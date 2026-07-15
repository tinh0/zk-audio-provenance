// Beep / tone-injection benchmark for zk-Location FloatVar.
// Proves output[i] = input[i] + sin(rate * 2π * i / sampleRate) for N samples
// in IEEE-754 Float32. The beep frequency `rate` is a private witness so the
// in-circuit SinTaylor32 gadget must actually run — this benchmarks the cost
// of the sin gadget per sample, isolated from envelope / depth multiplication
// (vs the existing tremolo bench which adds a depth + 1+x envelope on top).
//
// No MiMC binding — keeps the per-sample cost a clean (1 mul + sin + 1 add).
//
// Usage: go run main.go [--plonk] <size> [n_samples] [rate_hz]
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
	zkMath "gnark-float/math"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type Audio struct {
	SampleRate uint32    `json:"sample_rate"`
	BitDepth   uint8     `json:"bit_depth"`
	Left       []float64 `json:"left"`
}

func f32Bits(v float32) uint32 { return math.Float32bits(v) }

// AudioBeepCircuit proves: output[i] = input[i] + sin(rate * timeConst[i])
// where timeConst[i] = 2π * i / sampleRate is a public per-sample constant
// baked in at circuit-build time, and `rate` is a private witness (Hz).
type AudioBeepCircuit struct {
	Inputs     []frontend.Variable `gnark:",secret"`
	Rate       frontend.Variable   `gnark:",secret"` // beep frequency in Hz (private)
	Outputs    []frontend.Variable `gnark:",public"`
	SampleRate float32
}

func (c *AudioBeepCircuit) Define(api frontend.API) error {
	ctx := floatlib.NewContext(api, 0, 8, 23)
	rate := ctx.NewFloat(c.Rate)
	pi := ctx.NewF32Constant(float32(math.Pi))
	twoPi := ctx.NewF32Constant(float32(2.0 * math.Pi))

	for i := range c.Inputs {
		// Per-sample compile-time constant: 2π * i / sampleRate
		timeConst := ctx.NewF32Constant(float32(2.0 * math.Pi * float64(i) / float64(c.SampleRate)))
		// phase = rate * timeConst   (one float multiplication in-circuit)
		phase := ctx.Mul(rate, timeConst)

		// Reduce phase to [0, 2π) then fold into [0, π] for SinTaylor32
		periods := ctx.Floor(ctx.Div(phase, twoPi))
		reduced := ctx.Sub(phase, ctx.Mul(periods, twoPi))
		greaterPi := ctx.IsGt(reduced, pi)
		phaseSub := ctx.Sub(reduced, pi)
		adjustedPhase := ctx.Select(greaterPi, phaseSub, reduced)

		// In-circuit sin via 15-term Taylor series (the expensive part)
		sinVal := zkMath.SinTaylor32(&ctx, adjustedPhase)
		sinNeg := ctx.Neg(sinVal)
		sinFinal := ctx.Select(greaterPi, sinNeg, sinVal)

		// output = input + sin(phase)
		input := ctx.NewFloat(c.Inputs[i])
		output := ctx.NewFloat(c.Outputs[i])
		result := ctx.Add(input, sinFinal)
		// Allow up to 4 ULPs of slack to absorb SinTaylor approximation error
		ctx.AssertIsEqualOrCustomULP32(result, output, 4.0)
	}
	return nil
}

func parseArgs() (bool, string, []string) {
	usePlonk, backend := false, "groth16"
	var pos []string
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--plonk":
			usePlonk, backend = true, "plonk"
		case "--groth16":
		default:
			pos = append(pos, arg)
		}
	}
	return usePlonk, backend, pos
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
	usePlonk, backend, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: beep [--plonk] <size> [n_samples] [rate_hz]")
		os.Exit(1)
	}

	size, _ := strconv.Atoi(positional[0])
	nSamples := -1
	if len(positional) >= 2 {
		nSamples, _ = strconv.Atoi(positional[1])
	}
	rate := float32(1000.0) // censoring beep ≈ 1 kHz
	if len(positional) >= 3 {
		r, _ := strconv.ParseFloat(positional[2], 32)
		rate = float32(r)
	}

	aud := loadAudio(size)
	samples := aud.Left
	if nSamples > 0 && nSamples < len(samples) {
		samples = samples[:nSamples]
	}
	n := len(samples)
	sr := float32(aud.SampleRate)
	if sr == 0 {
		sr = 44100
	}

	fmt.Printf("Backend: %s, Beep: %.0f Hz, SampleRate: %.0f, Samples: %d\n", backend, rate, sr, n)

	inputVars := make([]frontend.Variable, n)
	outputVars := make([]frontend.Variable, n)
	for i, s := range samples {
		var inF float32
		if aud.BitDepth == 32 {
			inF = float32(s)
		} else {
			inF = float32(int32(s))
		}
		phase := float32(2.0*math.Pi*float64(rate)*float64(i)) / sr
		sinVal := float32(math.Sin(float64(phase)))
		outF := inF + sinVal
		inputVars[i] = f32Bits(inF)
		outputVars[i] = f32Bits(outF)
	}

	circuit := &AudioBeepCircuit{
		Inputs:     make([]frontend.Variable, n),
		Outputs:    make([]frontend.Variable, n),
		SampleRate: sr,
	}

	fmt.Printf("Compiling AudioBeepCircuit (N=%d, %s)... ", n, backend)
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
		srs, srsL, _ := unsafekzg.NewSRS(cs)
		pk, vk, _ := plonk.Setup(cs, srs, srsL)
		setupTime = time.Since(t0)
		fmt.Printf("%v\n", setupTime)

		assignment := &AudioBeepCircuit{Inputs: inputVars, Rate: f32Bits(rate), Outputs: outputVars, SampleRate: sr}
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

		assignment := &AudioBeepCircuit{Inputs: inputVars, Rate: f32Bits(rate), Outputs: outputVars, SampleRate: sr}
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

	writeCSV("beep", backend, size, n, nbConstraints, compileTime, setupTime, proveTime, verifyTime, proofSize)
	fmt.Printf("\nSummary (%s)\n", backend)
	fmt.Printf("  Samples:     %d\n", n)
	fmt.Printf("  Constraints: %d (%.1f/sample)\n", nbConstraints, float64(nbConstraints)/float64(n))
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
