// Pure volume (multiplicative scale) float benchmark for zk-Location FloatVar.
// Proves output[i] = input[i] * gain in IEEE-754 Float32 or Float64.
// No MiMC preimage binding — isolates the cost of the FP multiply so it's
// comparable to the Noir and zk-float-compiler volume benches.
//
// Usage: go run main.go [--plonk] [--f64] <size> [n_samples] [gain]
package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	floatlib "gnark-float/float"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type Audio struct {
	BitDepth uint8     `json:"bit_depth"`
	Left     []float64 `json:"left"`
}

// AudioVolumeCircuit proves: output[i] = input[i] * gain in Float32/64.
type AudioVolumeCircuit struct {
	Inputs  []frontend.Variable `gnark:",secret"`
	Gain    frontend.Variable   `gnark:",public"`
	Outputs []frontend.Variable `gnark:",public"`
	expBits uint8
	manBits uint8
}

func (c *AudioVolumeCircuit) Define(api frontend.API) error {
	ctx := floatlib.NewContext(api, 0, uint(c.expBits), uint(c.manBits))
	gain := ctx.NewFloat(c.Gain)
	for i := range c.Inputs {
		in := ctx.NewFloat(c.Inputs[i])
		out := ctx.NewFloat(c.Outputs[i])
		res := ctx.Mul(in, gain)
		ctx.AssertIsEqual(res, out)
	}
	return nil
}

func parseArgs() (bool, bool, string, []string) {
	usePlonk, useF64, backend := false, false, "groth16"
	var pos []string
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--plonk":
			usePlonk, backend = true, "plonk"
		case "--groth16":
		case "--f64":
			useF64 = true
		default:
			pos = append(pos, arg)
		}
	}
	return usePlonk, useF64, backend, pos
}

func loadAudio(size int) Audio {
	for _, c := range []string{"hyperveritas_impl/audio", "../hyperveritas_impl/audio", "../../hyperveritas_impl/audio", "../../../hyperveritas_impl/audio", "../../../hyperveritas-audio/hyperveritas_impl/audio"} {
		if info, _ := os.Stat(c); info != nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			p := filepath.Join(abs, fmt.Sprintf("Audio%d.json", size))
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var aud Audio
			_ = json.Unmarshal(data, &aud)
			return aud
		}
	}
	fmt.Fprintln(os.Stderr, "audio directory not found; run benchmark/common/gen_audio.py first")
	os.Exit(1)
	return Audio{}
}

func main() {
	usePlonk, useF64, backend, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: volume [--plonk] [--f64] <size> [n_samples] [gain]")
		os.Exit(1)
	}

	size, _ := strconv.Atoi(positional[0])
	nSamples := -1
	if len(positional) >= 2 {
		nSamples, _ = strconv.Atoi(positional[1])
	}
	gain32 := float32(0.5)
	gain64 := 0.5
	if len(positional) >= 3 {
		g, _ := strconv.ParseFloat(positional[2], 64)
		gain32 = float32(g)
		gain64 = g
	}

	aud := loadAudio(size)
	samples := aud.Left
	if nSamples > 0 && nSamples < len(samples) {
		samples = samples[:nSamples]
	}
	n := len(samples)

	precision := "f32"
	var expBits, manBits uint8 = 8, 23
	if useF64 {
		precision = "f64"
		expBits, manBits = 11, 52
	}
	fmt.Printf("Backend: %s, Precision: %s, Gain: %v, Samples: %d\n", backend, precision, gain64, n)

	inputVars := make([]frontend.Variable, n)
	outputVars := make([]frontend.Variable, n)
	for i, s := range samples {
		if useF64 {
			var in float64
			if aud.BitDepth == 64 || aud.BitDepth == 32 {
				in = s
			} else {
				in = float64(int64(s))
			}
			out := in * gain64
			inputVars[i] = math.Float64bits(in)
			outputVars[i] = math.Float64bits(out)
		} else {
			var in float32
			if aud.BitDepth == 32 {
				in = float32(s)
			} else {
				in = float32(int32(s))
			}
			out := in * gain32
			inputVars[i] = math.Float32bits(in)
			outputVars[i] = math.Float32bits(out)
		}
	}

	var gainVar frontend.Variable
	if useF64 {
		gainVar = math.Float64bits(gain64)
	} else {
		gainVar = math.Float32bits(gain32)
	}

	circuit := &AudioVolumeCircuit{
		Inputs:  make([]frontend.Variable, n),
		Outputs: make([]frontend.Variable, n),
		expBits: expBits,
		manBits: manBits,
	}

	fmt.Printf("Compiling AudioVolumeCircuit (N=%d, %s, %s)... ", n, backend, precision)
	t0 := time.Now()

	var nbConstraints int
	var compileTime, setupTime, proveTime, verifyTime time.Duration
	var valid bool
	var proofSize int

	if usePlonk {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		if err != nil { fmt.Fprintf(os.Stderr, "compile failed: %v\n", err); os.Exit(1) }
		compileTime = time.Since(t0)
		nbConstraints = cs.GetNbConstraints()
		fmt.Printf("%v (%d constraints)\n", compileTime, nbConstraints)

		t0 = time.Now()
		srs, srsL, _ := unsafekzg.NewSRS(cs)
		pk, vk, _ := plonk.Setup(cs, srs, srsL)
		setupTime = time.Since(t0)

		assignment := &AudioVolumeCircuit{Inputs: inputVars, Gain: gainVar, Outputs: outputVars, expBits: expBits, manBits: manBits}
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

		t0 = time.Now()
		proof, err := plonk.Prove(cs, pk, witness)
		proveTime = time.Since(t0)
		if err != nil { fmt.Fprintf(os.Stderr, "prove failed: %v\n", err); os.Exit(1) }

		var buf bytes.Buffer
		_, _ = proof.WriteTo(&buf)
		proofSize = buf.Len()

		pubWitness, _ := witness.Public()
		t0 = time.Now()
		valid = plonk.Verify(proof, vk, pubWitness) == nil
		verifyTime = time.Since(t0)
	} else {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil { fmt.Fprintf(os.Stderr, "compile failed: %v\n", err); os.Exit(1) }
		compileTime = time.Since(t0)
		nbConstraints = cs.GetNbConstraints()
		fmt.Printf("%v (%d constraints)\n", compileTime, nbConstraints)

		t0 = time.Now()
		pk, vk, _ := groth16.Setup(cs)
		setupTime = time.Since(t0)

		assignment := &AudioVolumeCircuit{Inputs: inputVars, Gain: gainVar, Outputs: outputVars, expBits: expBits, manBits: manBits}
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

		t0 = time.Now()
		proof, err := groth16.Prove(cs, pk, witness)
		proveTime = time.Since(t0)
		if err != nil { fmt.Fprintf(os.Stderr, "prove failed: %v\n", err); os.Exit(1) }

		var buf bytes.Buffer
		_, _ = proof.WriteTo(&buf)
		proofSize = buf.Len()

		pubWitness, _ := witness.Public()
		t0 = time.Now()
		valid = groth16.Verify(proof, vk, pubWitness) == nil
		verifyTime = time.Since(t0)
	}
	if !valid { fmt.Fprintln(os.Stderr, "VERIFICATION FAILED"); os.Exit(1) }

	writeCSV("pure_volume", backend, precision, size, n, nbConstraints, compileTime, setupTime, proveTime, verifyTime, proofSize)
	fmt.Printf("\nSummary (%s, %s)\n", backend, precision)
	fmt.Printf("  Samples:     %d\n", n)
	fmt.Printf("  Constraints: %d\n", nbConstraints)
	fmt.Printf("  Prove:       %v\n", proveTime)
	fmt.Printf("  Verify:      %v\n", verifyTime)
	fmt.Printf("  Proof size:  %d bytes\n", proofSize)
}

func writeCSV(name, backend, precision string, size, n, constraints int, compile, setup, prove, verify time.Duration, proofBytes int) {
	_ = os.MkdirAll("output", 0755)
	csvPath := fmt.Sprintf("output/%s_%s_%s_%d_n%d.csv", name, backend, precision, size, n)
	f, err := os.Create(csvPath); if err != nil { return }
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"Backend", "Precision", "BatchSize", "NbConstraints", "CompileTime_ms", "SetupTime_ms", "ProveTime_ms", "VerifyTime_ms", "ProofSize_bytes"})
	_ = w.Write([]string{
		backend, precision, strconv.Itoa(n), strconv.Itoa(constraints),
		strconv.FormatInt(compile.Milliseconds(), 10),
		strconv.FormatInt(setup.Milliseconds(), 10),
		strconv.FormatInt(prove.Milliseconds(), 10),
		strconv.FormatInt(verify.Milliseconds(), 10),
		strconv.Itoa(proofBytes),
	})
	w.Flush()
	fmt.Printf("  CSV:         %s\n", csvPath)
}
