# HyperVerITAS — Audio

The [HyperVerITAS](https://github.com/glgreiner/HyperVerITAS) proof system (Greiner, Mowery, Soni — *HyperVerITAS: Verifying Image Transformations at Scale on Boolean Hypercubes*, [IACR ePrint 2026/641](https://eprint.iacr.org/2026/641)) extended with **audio transformation proofs** over integer PCM samples: volume/gain, stereo-to-mono, and trim, each with PST, Brakedown, and Basefold PCS backends.

New in this fork: `hyperveritas_impl/src/audio.rs`, `src/audio_prover.rs`, the `hv_volume_*`, `hv_mono_*`, `hv_trim_*` examples, prove/verify split examples used by the web demo, and audio test-data generators in `hyperveritas_impl/audio/`.

## Layout

- `hyperveritas_impl/` — the prover/verifier implementation and all examples
- `hyperplonk/` — submodule: the [HyperPlonk](https://github.com/EspressoSystems/hyperplonk) library (Espresso Systems), via glgreiner's fork
- `plonkish_basefold/` — vendored @ `45a16ea` with small Brakedown fixes: the [BaseFold](https://github.com/hadasz/plonkish_basefold) artifact (Zeilberger et al.), via glgreiner's fork
- `comparisons/` — upstream comparison harnesses (VerITAS, VIMz, TilesProof; image ops)

## Setup

Requires Rust nightly and Python 3 with `numpy`. (On Linux, `./install.sh` and `./hyperveritas_setup.sh` install everything, including the image-comparison systems.)

Generate audio test data, then run any example (sizes 19–25, i.e. 2^n samples):

```bash
cd hyperveritas_impl
python -c "from audio.helper import generate_all_audio; generate_all_audio(19, 25, bit_depth=16, stereo=True)"
cargo run --release --example hv_volume_brakedown 19
```

All audio commands are collected in [../audio_commands.md](../audio_commands.md). The original upstream artifact instructions (image benchmarks, comparison systems, reviewer notes) are in [ARTIFACT-APPENDIX.md](ARTIFACT-APPENDIX.md).

Each run prints **Prover Runtime**, **Verifier Runtime**, and **Proof Size**; peak prover memory is available via `/usr/bin/time -v` (Linux).
