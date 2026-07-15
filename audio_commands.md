# HyperVerITAS Audio Commands

## Generate Test Audio Data

```powershell
cd hyperveritas-audio/hyperveritas_impl

# 8-bit audio (default)
python -c "from audio.helper import generate_all_audio; generate_all_audio(19, 25, bit_depth=8, stereo=True)"

# 16-bit audio
python -c "from audio.helper import generate_all_audio; generate_all_audio(19, 25, bit_depth=16, stereo=True)"

# 24-bit audio
python -c "from audio.helper import generate_all_audio; generate_all_audio(19, 25, bit_depth=24, stereo=True)"
```

## Build

```powershell
cd hyperveritas-audio/hyperveritas_impl
cargo build --release
```

## Volume Examples

```powershell
cd hyperveritas-audio/hyperveritas_impl
cargo run --release --example hv_volume_pst 19
cargo run --release --example hv_volume_brakedown 19
cargo run --release --example hv_volume_basefold 19
```

## Mono Examples

```powershell
cd hyperveritas-audio/hyperveritas_impl
cargo run --release --example hv_mono_pst 19
cargo run --release --example hv_mono_brakedown 19
cargo run --release --example hv_mono_basefold 19
```

## Trim Examples

```powershell
cd hyperveritas-audio/hyperveritas_impl
cargo run --release --example hv_trim_pst 19
cargo run --release --example hv_trim_brakedown 19
cargo run --release --example hv_trim_basefold 19
```

## Generate Float32 Test Audio Data

```powershell
cd hyperveritas-audio/hyperveritas_impl

# Float32 audio (IEEE-754, values in [-1.0, 1.0])
python -c "from audio.helper_float32 import generate_all_float32; generate_all_float32(19, 25, stereo=True)"
```

# zk-Location Float Audio Commands

## Gain / Volume
# 2^15 ~1 second of audio 3.8M constraints
```powershell
cd zk-location-float/audio/gain
go run main.go 19
go run main.go 19 1024 0.5
go run main.go --plonk 19
```

## Fade In

```powershell
cd zk-location-float/audio/fade_in
go run main.go 19
go run main.go 19 2048
go run main.go --plonk 19
```

## Fade Out

```powershell
cd zk-location-float/audio/fade_out
go run main.go 19
go run main.go 19 2048
go run main.go --plonk 19
```

## Combine / Mix

```powershell
cd zk-location-float/audio/combine
go run main.go 19
go run main.go 19 1024 0.7
go run main.go --plonk 19
```

## Pan

```powershell
cd zk-location-float/audio/pan
go run main.go 19
go run main.go 19 1024 0.0
go run main.go --plonk 19 512 -0.5
```

## Tremolo
# sin operations for each sample, 2^10 3.5M constraints
```powershell
cd zk-location-float/audio/tremolo
go run main.go 19
```

## Trim

```powershell
cd zk-location-float/audio/trim
go run main.go 19
```

## Volume (float benchmark)

```powershell
cd zk-location-float/audio/volume
go run main.go 19
```

## Addition / Beep (benchmark circuits)

```powershell
cd zk-location-float/audio/addition
go run main.go 19

cd zk-location-float/audio/beep
go run main.go 19
```
