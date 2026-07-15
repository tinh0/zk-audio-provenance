// Pure-addition float32 benchmark for zk-Location FloatVar.
// Proves output[i] = inputs_a[i] + inputs_b[i] in IEEE-754 Float32
// without any MiMC preimage binding — isolates the cost of the add op
// so it's comparable to the Noir and zk-float-compiler addition benches.
//
// Usage: go run main.go [--plonk] <size> [n_samples]
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

func f32Bits(v float32) uint32 { return math.Float32bits(v) }

// AudioAdditionCircuit proves: output[i] = inputs_a[i] + inputs_b[i] in Float32/64.
type AudioAdditionCircuit struct {
	InputsA []frontend.Variable `gnark:",secret"`
	InputsB []frontend.Variable `gnark:",secret"`
	Outputs []frontend.Variable `gnark:",public"`
	expBits uint8
	manBits uint8
}

func (c *AudioAdditionCircuit) Define(api frontend.API) error {
	ctx := floatlib.NewContext(api, 0, uint(c.expBits), uint(c.manBits))
	for i := range c.InputsA {
		a := ctx.NewFloat(c.InputsA[i])
		b := ctx.NewFloat(c.InputsB[i])
		out := ctx.NewFloat(c.Outputs[i])
		sum := ctx.Add(a, b)
		ctx.AssertIsEqual(sum, out)
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

func loadAudio(size int, name string) Audio {
	for _, c := range []string{"hyperveritas_impl/audio", "../hyperveritas_impl/audio", "../../hyperveritas_impl/audio", "../../../hyperveritas_impl/audio", "../../../hyperveritas-audio/hyperveritas_impl/audio"} {
		if info, _ := os.Stat(c); info != nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			p := filepath.Join(abs, fmt.Sprintf("%s%d.json", name, size))
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
		fmt.Fprintln(os.Stderr, "Usage: addition [--plonk] [--f64] <size> [n_samples]")
		os.Exit(1)
	}

	size, _ := strconv.Atoi(positional[0])
	nSamples := -1
	if len(positional) >= 2 {
		nSamples, _ = strconv.Atoi(positional[1])
	}

	audA := loadAudio(size, "Audio")
	audB := loadAudio(size, "Audio2_")
	if len(audA.Left) == 0 || len(audB.Left) == 0 {
		fmt.Fprintln(os.Stderr, "missing Audio/Audio2 input; run benchmark/common/gen_audio.py first")
		os.Exit(1)
	}
	samplesA, samplesB := audA.Left, audB.Left
	if nSamples > 0 && nSamples < len(samplesA) {
		samplesA = samplesA[:nSamples]
		samplesB = samplesB[:nSamples]
	}
	n := len(samplesA)

	precision := "f32"
	var expBits, manBits uint8 = 8, 23
	if useF64 {
		precision = "f64"
		expBits, manBits = 11, 52
	}
	fmt.Printf("Backend: %s, Precision: %s, Samples: %d (pure addition)\n", backend, precision, n)

	// Convert samples and compute expected outputs
	inputVarsA := make([]frontend.Variable, n)
	inputVarsB := make([]frontend.Variable, n)
	outputVars := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		if useF64 {
			var a, b float64
			if audA.BitDepth == 64 || audA.BitDepth == 32 {
				a = samplesA[i]
				b = samplesB[i]
			} else {
				a = float64(int64(samplesA[i]))
				b = float64(int64(samplesB[i]))
			}
			out := a + b
			inputVarsA[i] = math.Float64bits(a)
			inputVarsB[i] = math.Float64bits(b)
			outputVars[i] = math.Float64bits(out)
		} else {
			var a, b float32
			if audA.BitDepth == 32 {
				a = float32(samplesA[i])
				b = float32(samplesB[i])
			} else {
				a = float32(int32(samplesA[i]))
				b = float32(int32(samplesB[i]))
			}
			out := a + b
			inputVarsA[i] = f32Bits(a)
			inputVarsB[i] = f32Bits(b)
			outputVars[i] = f32Bits(out)
		}
	}

	circuit := &AudioAdditionCircuit{
		InputsA: make([]frontend.Variable, n),
		InputsB: make([]frontend.Variable, n),
		Outputs: make([]frontend.Variable, n),
		expBits: expBits,
		manBits: manBits,
	}

	fmt.Printf("Compiling AudioAdditionCircuit (N=%d, %s, %s)... ", n, backend, precision)
	t0 := time.Now()

	var nbConstraints int
	var compileTime, setupTime, proveTime, verifyTime time.Duration
	var valid bool
	var proofSize int

	if usePlonk {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compile failed: %v\n", err)
			os.Exit(1)
		}
		compileTime = time.Since(t0)
		nbConstraints = cs.GetNbConstraints()
		fmt.Printf("%v (%d constraints, %.1f/sample)\n", compileTime, nbConstraints, float64(nbConstraints)/float64(n))

		fmt.Print("Setup... ")
		t0 = time.Now()
		srs, srsLagrange, _ := unsafekzg.NewSRS(cs)
		pk, vk, _ := plonk.Setup(cs, srs, srsLagrange)
		setupTime = time.Since(t0)
		fmt.Printf("%v\n", setupTime)

		assignment := &AudioAdditionCircuit{InputsA: inputVarsA, InputsB: inputVarsB, Outputs: outputVars, expBits: expBits, manBits: manBits}
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

		fmt.Print("Proving... ")
		t0 = time.Now()
		proof, err := plonk.Prove(cs, pk, witness)
		proveTime = time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "prove failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v\n", proveTime)

		var buf bytes.Buffer
		_, _ = proof.WriteTo(&buf)
		proofSize = buf.Len()

		pubWitness, _ := witness.Public()
		fmt.Print("Verifying... ")
		t0 = time.Now()
		valid = plonk.Verify(proof, vk, pubWitness) == nil
		verifyTime = time.Since(t0)
		fmt.Printf("%v  valid=%v\n", verifyTime, valid)
	} else {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compile failed: %v\n", err)
			os.Exit(1)
		}
		compileTime = time.Since(t0)
		nbConstraints = cs.GetNbConstraints()
		fmt.Printf("%v (%d constraints, %.1f/sample)\n", compileTime, nbConstraints, float64(nbConstraints)/float64(n))

		fmt.Print("Setup... ")
		t0 = time.Now()
		pk, vk, _ := groth16.Setup(cs)
		setupTime = time.Since(t0)
		fmt.Printf("%v\n", setupTime)

		assignment := &AudioAdditionCircuit{InputsA: inputVarsA, InputsB: inputVarsB, Outputs: outputVars, expBits: expBits, manBits: manBits}
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

		fmt.Print("Proving... ")
		t0 = time.Now()
		proof, err := groth16.Prove(cs, pk, witness)
		proveTime = time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "prove failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v\n", proveTime)

		var buf bytes.Buffer
		_, _ = proof.WriteTo(&buf)
		proofSize = buf.Len()

		pubWitness, _ := witness.Public()
		fmt.Print("Verifying... ")
		t0 = time.Now()
		valid = groth16.Verify(proof, vk, pubWitness) == nil
		verifyTime = time.Since(t0)
		fmt.Printf("%v  valid=%v\n", verifyTime, valid)
	}

	if !valid {
		fmt.Fprintln(os.Stderr, "VERIFICATION FAILED")
		os.Exit(1)
	}

	writeCSV(fmt.Sprintf("pure_addition_%s", precision), backend, size, n, nbConstraints, compileTime, setupTime, proveTime, verifyTime, proofSize)

	fmt.Printf("\nSummary (%s)\n", backend)
	fmt.Printf("  Samples:     %d\n", n)
	fmt.Printf("  Constraints: %d (%.1f/sample)\n", nbConstraints, float64(nbConstraints)/float64(n))
	fmt.Printf("  Compile:     %v\n", compileTime)
	fmt.Printf("  Setup:       %v\n", setupTime)
	fmt.Printf("  Prove:       %v\n", proveTime)
	fmt.Printf("  Verify:      %v\n", verifyTime)
	fmt.Printf("  Proof size:  %d bytes\n", proofSize)
}

func writeCSV(name, backend string, size, n, constraints int, compile, setup, prove, verify time.Duration, proofBytes int) {
	_ = os.MkdirAll("output", 0755)
	csvPath := fmt.Sprintf("output/%s_%s_%d_n%d.csv", name, backend, size, n)
	f, err := os.Create(csvPath)
	if err != nil {
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"Backend", "BatchSize", "NbConstraints", "ConstraintsPerSample",
		"CompileTime_ms", "SetupTime_ms", "ProveTime_ms", "VerifyTime_ms",
		"ProofSize_bytes", "ProveTimePerSample_us"})
	_ = w.Write([]string{
		backend, strconv.Itoa(n), strconv.Itoa(constraints),
		fmt.Sprintf("%.2f", float64(constraints)/float64(n)),
		strconv.FormatInt(compile.Milliseconds(), 10),
		strconv.FormatInt(setup.Milliseconds(), 10),
		strconv.FormatInt(prove.Milliseconds(), 10),
		strconv.FormatInt(verify.Milliseconds(), 10),
		strconv.Itoa(proofBytes),
		fmt.Sprintf("%.2f", float64(prove.Microseconds())/float64(n)),
	})
	w.Flush()
	fmt.Printf("  CSV:         %s\n", csvPath)
}
