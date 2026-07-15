# zk-audio-provenance

**Zero-Knowledge Proofs for Floating-Point and Audio Provenance**

**MS Project by Tinh Nguyen**  
**Advisor:** Prof. Pratik Soni  
**Mentors:** Garrett Greiner, Caleb Geren

Verifying the authenticity and provenance of media has become increasingly important, as media routinely undergoes many transformations before reaching the end user. This project extends the C2PA trust model — in which the original source (camera, microphone, ML server) is trusted but editing software is not — and applies zero-knowledge proofs to verify the provenance of audio transformed by an untrusted party, without revealing the original recording.

The repository provides three proof-system baselines for audio transformations (volume/gain, stereo-to-mono, trim, fades, pan, mix, tremolo), together with a browser-based demonstration. An overview is given in the [project presentation](<Zero Knowledge Audio Presentation.pdf>).

## Components

| Directory | What it is |
|---|---|
| [`hyperveritas-audio/`](hyperveritas-audio/) | The [HyperVerITAS](https://github.com/glgreiner/HyperVerITAS) proof system extended with audio transformation proofs over integer PCM samples. |
| [`zk-float-compiler/`](https://github.com/tinh0/zk-float-compiler) | A compiler for succinct ZK proofs of floating-point computation via relative error bounds (Garg et al., CCS 2022), with audio benchmarks. |
| [`zk-location-float/`](zk-location-float/) | [zk-Location](https://github.com/tumberger/zk-Location)'s exact IEEE-754 floating-point gadgets (gnark/Go), extended with audio transformation circuits in `audio/`. |
| [`web/`](web/) | Browser demo: WASM verifier + React frontend + prover backend for end-to-end audio provenance verification. |

## Quick start

```bash
git clone --recurse-submodules <this-repo-url>
```

Each component's README covers its own setup: [hyperveritas-audio](hyperveritas-audio/README.md), [zk-location-float/audio](zk-location-float/audio/README.md), [web](web/README.md), and the zk-float-compiler submodule. [audio_commands.md](audio_commands.md) lists every benchmark command.

## References

The three baselines build on:

- **HyperVerITAS**: Garrett Greiner, Toshi Mowery, Pratik Soni. *HyperVerITAS: Verifying Image Transformations at Scale on Boolean Hypercubes.* [IACR ePrint 2026/641](https://eprint.iacr.org/2026/641) — code at [glgreiner/HyperVerITAS](https://github.com/glgreiner/HyperVerITAS).
- **Floating-point ZK (relative error)**: Sanjam Garg, Abhishek Jain, Zhengzhong Jin, Yinuo Zhang. *Succinct Zero Knowledge for Floating Point Computations.* ACM CCS 2022. [doi:10.1145/3548606.3560653](https://doi.org/10.1145/3548606.3560653)
- **Floating-point ZK (exact IEEE-754)**: Jens Ernstberger, Chengru Zhang, Luca Ciprian, Philipp Jovanovic, Sebastian Steinhorst. *Zero-Knowledge Location Privacy via Accurate Floating-Point SNARKs.* [arXiv:2404.14983](https://arxiv.org/abs/2404.14983) — code at [tumberger/zk-Location](https://github.com/tumberger/zk-Location).
- **Related**: Daniel Kang. [*Fighting AI-generated audio with attested microphones and zk-SNARKs*](https://medium.com/@danieldkang/fighting-ai-generated-audio-with-attested-microphones-and-zk-snarks-the-attested-audio-experiment-d6ea0fc296ac) (blog, 2023).

## Attribution

- **HyperVerITAS** — the proof system and the `comparisons/` suite, by Greiner, Mowery, Soni ([ePrint 2026/641](https://eprint.iacr.org/2026/641), [repo](https://github.com/glgreiner/HyperVerITAS)).
- **`hyperplonk`** — the HyperPlonk library, by Chen, Bünz, Boneh, Zhang ([ePrint 2022/1355](https://eprint.iacr.org/2022/1355), [repo](https://github.com/EspressoSystems/hyperplonk)); included as a submodule of glgreiner's fork.
- **`plonkish_basefold`** — the BaseFold artifact, by Zeilberger, Chen, Fisch ([ePrint 2023/1705](https://eprint.iacr.org/2023/1705), [repo](https://github.com/hadasz/plonkish_basefold)); vendored from glgreiner's fork at `45a16ea`, with small local Brakedown fixes.
- **`zk-location-float`** — the floating-point gadget library, by Ernstberger, Zhang, Ciprian, Jovanovic, Steinhorst ([arXiv:2404.14983](https://arxiv.org/abs/2404.14983), [repo](https://github.com/tumberger/zk-Location)); vendored at `4afebb8`.
- The **audio transformation extensions** in all three baselines, the zk-float-compiler implementation, the WASM verifier, and the web demo are the contributions of this repository.

## AI-assistance disclosure

Portions of the code and documentation in this repository (in particular the audio extensions, WASM bindings, web demo, and benchmarking scripts) were developed with the assistance of Claude (Anthropic). All AI-assisted code was reviewed, tested, and validated by the author.
