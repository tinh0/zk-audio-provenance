package audio

import (
	"math"

	float "gnark-float/float"
	zkMath "gnark-float/math"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// AudioTremoloCircuit proves that:
//  1. MiMC(Inputs) == InputDigest
//  2. Output[i] = Input[i] * (1 + Depth * sin(2π * Rate * i / SampleRate)) for all i
type AudioTremoloCircuit struct {
	Inputs      []frontend.Variable `gnark:",secret"`
	InputDigest frontend.Variable   `gnark:",public"`
	Rate        frontend.Variable   `gnark:",public"`
	Depth       frontend.Variable   `gnark:",public"`
	Outputs     []frontend.Variable `gnark:",public"`
	SampleRate  float32             `gnark:"-"`
}

func (c *AudioTremoloCircuit) Define(api frontend.API) error {
	// Stage 1: Hash preimage binding
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := range c.Inputs {
		h.Write(c.Inputs[i])
	}
	api.AssertIsEqual(h.Sum(), c.InputDigest)

	// Stages 2+3: Range check (implicit in NewFloat) + transformation
	ctx := float.NewContext(api, 0, 8, 23)
	return defineTremolo(&ctx, api, c.Inputs, c.Rate, c.Depth, c.Outputs, c.SampleRate)
}

// defineTremolo is the shared tremolo logic.
func defineTremolo(
	ctx *float.Context,
	api frontend.API,
	inputs []frontend.Variable,
	rateVar frontend.Variable,
	depthVar frontend.Variable,
	outputs []frontend.Variable,
	sampleRate float32,
) error {
	rate := ctx.NewFloat(rateVar)
	depth := ctx.NewFloat(depthVar)
	one := ctx.NewF32Constant(1.0)
	pi := ctx.NewF32Constant(math.Pi)
	twoPi := ctx.NewF32Constant(2.0 * math.Pi)

	for i := range inputs {
		input := ctx.NewFloat(inputs[i])
		output := ctx.NewFloat(outputs[i])

		// phase = (2π * i / sampleRate) * rate
		// The first part is a compile-time constant.
		timeConst := ctx.NewF32Constant(float32(2.0 * math.Pi * float64(i) / float64(sampleRate)))
		phase := ctx.Mul(timeConst, rate)

		// Reduce phase to [0, 2π)
		periods := ctx.Floor(ctx.Div(phase, twoPi))
		reduced := ctx.Sub(phase, ctx.Mul(periods, twoPi))

		// Map to [0, π] for SinTaylor32.
		// sin(x) for x in [π, 2π) equals -sin(x - π).
		greaterPi := ctx.IsGt(reduced, pi)
		phaseSub := ctx.Sub(reduced, pi)
		adjustedPhase := ctx.Select(greaterPi, phaseSub, reduced)

		sinVal := zkMath.SinTaylor32(ctx, adjustedPhase)
		sinNeg := ctx.Neg(sinVal)
		sinFinal := ctx.Select(greaterPi, sinNeg, sinVal)

		// modulation = 1 + depth * sin(phase)
		modulation := ctx.Add(one, ctx.Mul(depth, sinFinal))

		// result = input * modulation
		result := ctx.Mul(input, modulation)

		ctx.AssertIsEqualOrCustomULP32(result, output, 4.0)
	}
	return nil
}
