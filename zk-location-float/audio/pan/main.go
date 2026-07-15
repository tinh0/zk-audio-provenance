// authentic_pan proves stereo panning with MiMC hash preimage binding.
// Usage: go run main.go [--plonk] <size> [n_samples] [pan]
package main

import (
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
	BitDepth    uint8      `json:"bit_depth"`
	NumChannels uint8      `json:"num_channels"`
	Left        []float64  `json:"left"`
	Right       *[]float64 `json:"right"`
}

func f32Bits(v float32) uint32 { return math.Float32bits(v) }

func main() {
	usePlonk, backend, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: authentic_pan [--plonk] <size> [n_samples] [pan]")
		fmt.Fprintln(os.Stderr, "  pan: [-1.0 to 1.0], default 0.5 (right)")
		os.Exit(1)
	}

	size, _ := strconv.Atoi(positional[0])
	nSamples := -1
	if len(positional) >= 2 {
		nSamples, _ = strconv.Atoi(positional[1])
	}
	pan := float32(0.5)
	if len(positional) >= 3 {
		p, _ := strconv.ParseFloat(positional[2], 32)
		pan = float32(p)
	}

	aud := loadStereoAudio(size)
	if aud.NumChannels != 2 || aud.Right == nil {
		fmt.Fprintln(os.Stderr, "Error: Need stereo audio. Use StereoAudio*.json")
		os.Exit(1)
	}

	left := aud.Left
	right := *aud.Right
	if nSamples > 0 && nSamples < len(left) {
		left = left[:nSamples]
		right = right[:nSamples]
	}
	n := len(left)

	fmt.Printf("Backend: %s, Pan: %.2f, Samples: %d (authentic pan)\n", backend, pan, n)

	// Convert samples and compute outputs
	leftBits := make([]uint32, n)
	rightBits := make([]uint32, n)
	inputsL := make([]frontend.Variable, n)
	inputsR := make([]frontend.Variable, n)
	outputsL := make([]frontend.Variable, n)
	outputsR := make([]frontend.Variable, n)
	leftGain := 1 - pan
	rightGain := 1 + pan
	for i := 0; i < n; i++ {
		var inL, inR float32
		if aud.BitDepth == 32 {
			inL = float32(left[i])
			inR = float32(right[i])
		} else {
			inL = float32(int32(left[i]))
			inR = float32(int32(right[i]))
		}
		outL := inL * leftGain
		outR := inR * rightGain
		leftBits[i] = f32Bits(inL)
		rightBits[i] = f32Bits(inR)
		inputsL[i] = leftBits[i]
		inputsR[i] = rightBits[i]
		outputsL[i] = f32Bits(outL)
		outputsR[i] = f32Bits(outR)
	}

	// Compute MiMC digest over both channels
	fmt.Print("Computing MiMC input digest... ")
	t0 := time.Now()
	digest := zkAudio.ComputeInputDigest(leftBits, rightBits)
	fmt.Printf("%v\n", time.Since(t0))

	circuit := &zkAudio.AudioPanCircuit{
		InputsLeft:   make([]frontend.Variable, n),
		InputsRight:  make([]frontend.Variable, n),
		OutputsLeft:  make([]frontend.Variable, n),
		OutputsRight: make([]frontend.Variable, n),
	}

	fmt.Printf("Compiling AudioPanCircuit (N=%d, %s)... ", n, backend)
	t0 = time.Now()

	var nbConstraints int
	var compileTime, setupTime, proveTime, verifyTime time.Duration
	var valid bool

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

		assignment := &zkAudio.AudioPanCircuit{
			InputsLeft: inputsL, InputsRight: inputsR, InputDigest: digest,
			Pan: f32Bits(pan), OutputsLeft: outputsL, OutputsRight: outputsR,
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

		assignment := &zkAudio.AudioPanCircuit{
			InputsLeft: inputsL, InputsRight: inputsR, InputDigest: digest,
			Pan: f32Bits(pan), OutputsLeft: outputsL, OutputsRight: outputsR,
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

	writeCSV("authentic_pan", backend, size, n, nbConstraints, compileTime, setupTime, proveTime, verifyTime)

	fmt.Printf("Summary (%s)\n", backend)
	fmt.Printf("  Samples:       %d\n", n)
	fmt.Printf("  Constraints:   %d (%.1f/sample)\n", nbConstraints, float64(nbConstraints)/float64(n))
	fmt.Printf("  Compile:       %v\n", compileTime)
	fmt.Printf("  Setup:         %v\n", setupTime)
	fmt.Printf("  Prove:         %v\n", proveTime)
	fmt.Printf("  Verify:        %v\n", verifyTime)
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

func loadStereoAudio(size int) Audio {
	audioDir := "hyperveritas_impl/audio"
	for _, c := range []string{audioDir, "../" + audioDir, "../../" + audioDir, "../../../" + audioDir, "../../../hyperveritas-audio/" + audioDir} {
		if info, _ := os.Stat(c); info != nil && info.IsDir() {
			audioDir, _ = filepath.Abs(c)
			break
		}
	}
	path := filepath.Join(audioDir, fmt.Sprintf("StereoAudio%d.json", size))
	data, _ := os.ReadFile(path)
	var aud Audio
	json.Unmarshal(data, &aud)
	return aud
}

func writeCSV(name, backend string, size, n, constraints int, compile, setup, prove, verify time.Duration) {
	os.MkdirAll("output", 0755)
	csvPath := fmt.Sprintf("output/%s_%s_%d_n%d.csv", name, backend, size, n)
	f, _ := os.Create(csvPath)
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"Backend", "BatchSize", "NbConstraints", "ConstraintsPerSample",
		"CompileTime_ms", "SetupTime_ms", "ProveTime_ms", "VerifyTime_ms", "ProveTimePerSample_us"})
	w.Write([]string{backend, strconv.Itoa(n), strconv.Itoa(constraints),
		fmt.Sprintf("%.2f", float64(constraints)/float64(n)),
		strconv.FormatInt(compile.Milliseconds(), 10),
		strconv.FormatInt(setup.Milliseconds(), 10),
		strconv.FormatInt(prove.Milliseconds(), 10),
		strconv.FormatInt(verify.Milliseconds(), 10),
		fmt.Sprintf("%.2f", float64(prove.Microseconds())/float64(n))})
	w.Flush()
	fmt.Printf("  CSV:           %s\n", csvPath)
}
