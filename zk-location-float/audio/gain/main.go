// authentic_gain proves gain with MiMC hash preimage binding.
// Usage: go run main.go [--plonk] <size> [n_samples] [gain]
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

	zkAudio "gnark-float/audio"

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

func main() {
	usePlonk, backend, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: authentic_gain [--plonk] <size> [n_samples] [gain]")
		os.Exit(1)
	}

	size, _ := strconv.Atoi(positional[0])
	n := -1
	if len(positional) >= 2 {
		n, _ = strconv.Atoi(positional[1])
	}
	gain := float32(0.75)
	if len(positional) >= 3 {
		g, _ := strconv.ParseFloat(positional[2], 32)
		gain = float32(g)
	}

	aud := loadAudio(size)
	samples := aud.Left
	if n > 0 && n < len(samples) {
		samples = samples[:n]
	}
	n = len(samples)

	fmt.Printf("Backend: %s, Gain: %.2f, Samples: %d (authentic)\n", backend, gain, n)

	// Convert samples to float32 bit patterns and compute outputs
	inputBits := make([]uint32, n)
	inputVars := make([]frontend.Variable, n)
	outputVars := make([]frontend.Variable, n)
	for i, s := range samples {
		var inF float32
		if aud.BitDepth == 32 {
			inF = float32(s)
		} else {
			inF = float32(int32(s))
		}
		outF := inF * gain
		inputBits[i] = f32Bits(inF)
		inputVars[i] = inputBits[i]
		outputVars[i] = f32Bits(outF)
	}

	// Compute MiMC digest of inputs
	fmt.Print("Computing MiMC input digest... ")
	t0 := time.Now()
	digest := zkAudio.ComputeInputDigest(inputBits)
	fmt.Printf("%v\n", time.Since(t0))

	// Compile
	circuit := &zkAudio.AudioGainCircuit{
		Inputs:  make([]frontend.Variable, n),
		Outputs: make([]frontend.Variable, n),
	}

	fmt.Printf("Compiling AudioGainCircuit (N=%d, %s)... ", n, backend)
	t0 = time.Now()

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

		assignment := &zkAudio.AudioGainCircuit{
			Inputs: inputVars, InputDigest: digest, Gain: f32Bits(gain), Outputs: outputVars,
		}
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

		fmt.Printf("Proving... ")
		t0 = time.Now()
		proof, err := plonk.Prove(cs, pk, witness)
		proveTime = time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "prove failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v (%.1f μs/sample)\n", proveTime, float64(proveTime.Microseconds())/float64(n))

		var pbuf bytes.Buffer
		_, _ = proof.WriteTo(&pbuf)
		proofSize = pbuf.Len()

		pubWitness, _ := witness.Public()
		fmt.Print("Verifying... ")
		t0 = time.Now()
		valid = plonk.Verify(proof, vk, pubWitness) == nil
		verifyTime = time.Since(t0)
		fmt.Printf("%v  valid=%v\n\n", verifyTime, valid)
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

		assignment := &zkAudio.AudioGainCircuit{
			Inputs: inputVars, InputDigest: digest, Gain: f32Bits(gain), Outputs: outputVars,
		}
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

		fmt.Printf("Proving... ")
		t0 = time.Now()
		proof, err := groth16.Prove(cs, pk, witness)
		proveTime = time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "prove failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v (%.1f μs/sample)\n", proveTime, float64(proveTime.Microseconds())/float64(n))

		var pbuf bytes.Buffer
		_, _ = proof.WriteTo(&pbuf)
		proofSize = pbuf.Len()

		pubWitness, _ := witness.Public()
		fmt.Print("Verifying... ")
		t0 = time.Now()
		valid = groth16.Verify(proof, vk, pubWitness) == nil
		verifyTime = time.Since(t0)
		fmt.Printf("%v  valid=%v\n\n", verifyTime, valid)
	}

	if !valid {
		fmt.Fprintln(os.Stderr, "VERIFICATION FAILED")
		os.Exit(1)
	}

	writeCSV("authentic_gain", backend, size, n, nbConstraints, compileTime, setupTime, proveTime, verifyTime, proofSize)

	fmt.Printf("Summary (%s)\n", backend)
	fmt.Printf("  Samples:       %d\n", n)
	fmt.Printf("  Constraints:   %d (%.1f/sample)\n", nbConstraints, float64(nbConstraints)/float64(n))
	fmt.Printf("  Compile:       %v\n", compileTime)
	fmt.Printf("  Setup:         %v\n", setupTime)
	fmt.Printf("  Prove:         %v\n", proveTime)
	fmt.Printf("  Verify:        %v\n", verifyTime)
	fmt.Printf("  Proof size:    %d bytes\n", proofSize)
}

func parseArgs() (bool, string, []string) {
	usePlonk, backend := false, "groth16"
	var pos []string
	for _, arg := range os.Args[1:] {
		if arg == "--plonk" {
			usePlonk, backend = true, "plonk"
		} else if arg != "--groth16" {
			pos = append(pos, arg)
		}
	}
	return usePlonk, backend, pos
}

func loadAudio(size int) Audio {
	for _, c := range []string{"hyperveritas_impl/audio", "../hyperveritas_impl/audio", "../../hyperveritas_impl/audio", "../../../hyperveritas_impl/audio", "../../../hyperveritas-audio/hyperveritas_impl/audio"} {
		if info, _ := os.Stat(c); info != nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			path := filepath.Join(abs, fmt.Sprintf("Audio%d.json", size))
			data, _ := os.ReadFile(path)
			var aud Audio
			json.Unmarshal(data, &aud)
			return aud
		}
	}
	fmt.Fprintln(os.Stderr, "audio directory not found")
	os.Exit(1)
	return Audio{}
}

func writeCSV(name, backend string, size, n, constraints int, compile, setup, prove, verify time.Duration, proofBytes int) {
	os.MkdirAll("output", 0755)
	csvPath := fmt.Sprintf("output/%s_%s_%d_n%d.csv", name, backend, size, n)
	f, _ := os.Create(csvPath)
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"Backend", "BatchSize", "NbConstraints", "ConstraintsPerSample",
		"CompileTime_ms", "SetupTime_ms", "ProveTime_ms", "VerifyTime_ms",
		"ProofSize_bytes", "ProveTimePerSample_us"})
	w.Write([]string{backend, strconv.Itoa(n), strconv.Itoa(constraints),
		fmt.Sprintf("%.2f", float64(constraints)/float64(n)),
		strconv.FormatInt(compile.Milliseconds(), 10),
		strconv.FormatInt(setup.Milliseconds(), 10),
		strconv.FormatInt(prove.Milliseconds(), 10),
		strconv.FormatInt(verify.Milliseconds(), 10),
		strconv.Itoa(proofBytes),
		fmt.Sprintf("%.2f", float64(prove.Microseconds())/float64(n))})
	w.Flush()
	fmt.Printf("  CSV:           %s\n", csvPath)
}
