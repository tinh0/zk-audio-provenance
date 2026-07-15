# zk-Location Float — Audio Circuits

Audio transformation circuits over **exact IEEE-754 float32 samples**, built on [zk-Location](https://github.com/tumberger/zk-Location)'s floating-point gadgets in [gnark](https://github.com/Consensys/gnark) (Go). Each circuit proves an edit was applied correctly to a committed original (MiMC digest binds the input).

The float gadgets are from Ernstberger, Zhang, Ciprian, Jovanovic, Steinhorst. *Zero-Knowledge Location Privacy via Accurate Floating-Point SNARKs* ([arXiv:2404.14983](https://arxiv.org/abs/2404.14983)).

Circuits: `gain/`, `fade_in/`, `fade_out/`, `combine/` (mix), `pan/`, `tremolo/`, `trim/`, plus `volume/`, `addition/`, and `beep/` micro-benchmarks. Shared circuit definitions live in `audio_authentic.go`, `audio_tremolo.go`, `audio_trim.go`, and `mimc_helper.go`.

## Setup

Requires Go ≥ 1.21. Generate float32 test audio first (from the repo root):

```bash
cd hyperveritas-audio/hyperveritas_impl
python -c "from audio.helper_float32 import generate_all_float32; generate_all_float32(19, 25, stereo=True)"
```

Then run any circuit (size 19–25 = 2^n samples; `--plonk` switches Groth16 → PLONK):

```bash
cd zk-location-float/audio/gain
go run main.go 19
go run main.go --plonk 19
```

Full command list: [../../audio_commands.md](../../audio_commands.md).
