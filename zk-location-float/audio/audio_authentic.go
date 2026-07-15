package audio

import (
	"math"

	float "gnark-float/float"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// AudioGainCircuit proves that:
//  1. The prover knows secret Inputs whose MiMC hash equals InputDigest
//  2. Output[i] = Input[i] * Gain for all i in IEEE-754 Float32
//
// This combines hash preimage binding (HyperVerITAS stage 1),
// range checking (implicit in NewFloat, stage 2), and
// transformation correctness (stage 3) in a single proof.
type AudioGainCircuit struct {
	Inputs      []frontend.Variable `gnark:",secret"`
	InputDigest frontend.Variable   `gnark:",public"`
	Gain        frontend.Variable   `gnark:",public"`
	Outputs     []frontend.Variable `gnark:",public"`
}

func (c *AudioGainCircuit) Define(api frontend.API) error {
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
	gain := ctx.NewFloat(c.Gain)
	for i := range c.Inputs {
		input := ctx.NewFloat(c.Inputs[i])
		output := ctx.NewFloat(c.Outputs[i])
		result := ctx.Mul(input, gain)
		ctx.AssertIsEqual(result, output)
	}
	return nil
}

// AudioFadeInCircuit proves that:
//  1. MiMC(Inputs) == InputDigest
//  2. Output[i] = Input[i] * (i / N) for all i
type AudioFadeInCircuit struct {
	Inputs      []frontend.Variable `gnark:",secret"`
	InputDigest frontend.Variable   `gnark:",public"`
	Outputs     []frontend.Variable `gnark:",public"`
}

func (c *AudioFadeInCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := range c.Inputs {
		h.Write(c.Inputs[i])
	}
	api.AssertIsEqual(h.Sum(), c.InputDigest)

	ctx := float.NewContext(api, 0, 8, 23)
	n := len(c.Inputs)
	nFloat := ctx.NewFloat(math.Float32bits(float32(n)))
	for i := range c.Inputs {
		input := ctx.NewFloat(c.Inputs[i])
		output := ctx.NewFloat(c.Outputs[i])
		iFloat := ctx.NewFloat(math.Float32bits(float32(i)))
		factor := ctx.Div(iFloat, nFloat)
		result := ctx.Mul(input, factor)
		ctx.AssertIsEqual(result, output)
	}
	return nil
}

// AudioFadeOutCircuit proves that:
//  1. MiMC(Inputs) == InputDigest
//  2. Output[i] = Input[i] * (1 - i/N) for all i
type AudioFadeOutCircuit struct {
	Inputs      []frontend.Variable `gnark:",secret"`
	InputDigest frontend.Variable   `gnark:",public"`
	Outputs     []frontend.Variable `gnark:",public"`
}

func (c *AudioFadeOutCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := range c.Inputs {
		h.Write(c.Inputs[i])
	}
	api.AssertIsEqual(h.Sum(), c.InputDigest)

	ctx := float.NewContext(api, 0, 8, 23)
	n := len(c.Inputs)
	nFloat := ctx.NewFloat(math.Float32bits(float32(n)))
	one := ctx.NewFloat(math.Float32bits(float32(1.0)))
	for i := range c.Inputs {
		input := ctx.NewFloat(c.Inputs[i])
		output := ctx.NewFloat(c.Outputs[i])
		iFloat := ctx.NewFloat(math.Float32bits(float32(i)))
		ratio := ctx.Div(iFloat, nFloat)
		factor := ctx.Sub(one, ratio)
		result := ctx.Mul(input, factor)
		ctx.AssertIsEqual(result, output)
	}
	return nil
}

// AudioCombineCircuit proves that:
//  1. MiMC(Inputs1 || Inputs2) == InputDigest
//  2. Output[i] = Alpha * Input1[i] + (1-Alpha) * Input2[i] for all i
type AudioCombineCircuit struct {
	Inputs1     []frontend.Variable `gnark:",secret"`
	Inputs2     []frontend.Variable `gnark:",secret"`
	InputDigest frontend.Variable   `gnark:",public"`
	Alpha       frontend.Variable   `gnark:",public"`
	Outputs     []frontend.Variable `gnark:",public"`
}

func (c *AudioCombineCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := range c.Inputs1 {
		h.Write(c.Inputs1[i])
	}
	for i := range c.Inputs2 {
		h.Write(c.Inputs2[i])
	}
	api.AssertIsEqual(h.Sum(), c.InputDigest)

	ctx := float.NewContext(api, 0, 8, 23)
	alpha := ctx.NewFloat(c.Alpha)
	one := ctx.NewFloat(math.Float32bits(float32(1.0)))
	beta := ctx.Sub(one, alpha)
	for i := range c.Inputs1 {
		input1 := ctx.NewFloat(c.Inputs1[i])
		input2 := ctx.NewFloat(c.Inputs2[i])
		output := ctx.NewFloat(c.Outputs[i])
		term1 := ctx.Mul(alpha, input1)
		term2 := ctx.Mul(beta, input2)
		result := ctx.Add(term1, term2)
		ctx.AssertIsEqual(result, output)
	}
	return nil
}

// AudioPanCircuit proves that:
//  1. MiMC(InputsLeft || InputsRight) == InputDigest
//  2. OutputLeft[i] = InputLeft[i] * (1-Pan)
//  3. OutputRight[i] = InputRight[i] * (1+Pan)
type AudioPanCircuit struct {
	InputsLeft   []frontend.Variable `gnark:",secret"`
	InputsRight  []frontend.Variable `gnark:",secret"`
	InputDigest  frontend.Variable   `gnark:",public"`
	Pan          frontend.Variable   `gnark:",public"`
	OutputsLeft  []frontend.Variable `gnark:",public"`
	OutputsRight []frontend.Variable `gnark:",public"`
}

func (c *AudioPanCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := range c.InputsLeft {
		h.Write(c.InputsLeft[i])
	}
	for i := range c.InputsRight {
		h.Write(c.InputsRight[i])
	}
	api.AssertIsEqual(h.Sum(), c.InputDigest)

	ctx := float.NewContext(api, 0, 8, 23)
	pan := ctx.NewFloat(c.Pan)
	one := ctx.NewFloat(math.Float32bits(float32(1.0)))
	leftGain := ctx.Sub(one, pan)
	rightGain := ctx.Add(one, pan)
	for i := range c.InputsLeft {
		inputLeft := ctx.NewFloat(c.InputsLeft[i])
		outputLeft := ctx.NewFloat(c.OutputsLeft[i])
		resultLeft := ctx.Mul(inputLeft, leftGain)
		ctx.AssertIsEqual(resultLeft, outputLeft)

		inputRight := ctx.NewFloat(c.InputsRight[i])
		outputRight := ctx.NewFloat(c.OutputsRight[i])
		resultRight := ctx.Mul(inputRight, rightGain)
		ctx.AssertIsEqual(resultRight, outputRight)
	}
	return nil
}
