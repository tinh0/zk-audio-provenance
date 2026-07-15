package audio

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// AudioTrimCircuit proves that:
//  1. MiMC(Inputs) == InputDigest  (hash preimage binding)
//  2. Outputs[i] == Inputs[i]       for all i in [0, len(Outputs))
//
// The start offset is applied at witness construction time.
// Inputs are secret (full original audio), Outputs are public (trimmed segment).
type AudioTrimCircuit struct {
	Inputs      []frontend.Variable `gnark:",secret"`
	InputDigest frontend.Variable   `gnark:",public"`
	Outputs     []frontend.Variable `gnark:",public"`
}

func (c *AudioTrimCircuit) Define(api frontend.API) error {
	// Stage 1: Hash preimage binding
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := range c.Inputs {
		h.Write(c.Inputs[i])
	}
	api.AssertIsEqual(h.Sum(), c.InputDigest)

	// Stage 2: Trim equality
	for i := range c.Outputs {
		api.AssertIsEqual(c.Inputs[i], c.Outputs[i])
	}
	return nil
}
