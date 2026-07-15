package audio

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// ComputeInputDigest computes the MiMC hash of audio sample IEEE-754 bit patterns
// over the BN254 scalar field. The result matches the in-circuit MiMC digest.
//
// Pass one slice for mono audio, two for stereo or multi-track mixing.
// Channels are hashed in order: all of channel 0, then all of channel 1, etc.
func ComputeInputDigest(channels ...[]uint32) *big.Int {
	h := mimc.NewMiMC()
	for _, ch := range channels {
		for _, bits := range ch {
			var e fr.Element
			e.SetUint64(uint64(bits))
			b := e.Bytes()
			h.Write(b[:])
		}
	}
	digest := h.Sum(nil)
	return new(big.Int).SetBytes(digest)
}
