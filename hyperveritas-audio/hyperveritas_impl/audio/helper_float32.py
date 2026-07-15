"""
32-bit float audio test data generation for HyperVerITAS audio extension.

Generates test audio data in JSON format with 32-bit float samples
(IEEE 754 float32 in [-1.0, 1.0]) for sizes 2^8 through 2^25.

Produces the same transformation variants as helper.py:
  - Audio{size}.json:        Original mono audio
  - StereoAudio{size}.json:  Original stereo audio
  - Trim{size}.json:         First half trimmed
  - Mono{size}.json:         Stereo to mono mix
  - Volume{size}.json:       50% volume
  - Gain{size}.json:         87.5% (7/8) gain

No external dependencies - uses only the Python standard library.
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
import struct
import random


def float_to_u32(f):
    """Convert a Python float to its IEEE 754 float32 u32 bit representation."""
    return struct.unpack('<I', struct.pack('<f', f))[0]


def u32_to_float(u):
    """Convert a u32 bit representation back to a Python float (via float32)."""
    return struct.unpack('<f', struct.pack('<I', u))[0]


def to_float32(f):
    """Round a Python float to float32 precision."""
    return struct.unpack('<f', struct.pack('<f', f))[0]


def float32_audio_to_json(path, samples, sample_rate, num_channels, right_samples=None):
    """
    Save 32-bit float audio data to JSON format.

    Samples are stored as float values in [-1.0, 1.0], rounded to
    float32 precision.

    Args:
        path: Output JSON file path
        samples: Left/mono channel samples (list of floats)
        sample_rate: Sample rate in Hz
        num_channels: 1 (mono) or 2 (stereo)
        right_samples: Right channel samples for stereo (optional)
    """
    audio_json = {
        "sample_rate": sample_rate,
        "bit_depth": 32,
        "num_channels": num_channels,
        "num_samples": len(samples),
        "left": samples,
        "right": None,
    }

    if right_samples is not None:
        audio_json["right"] = right_samples

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(audio_json, f, ensure_ascii=False, indent=4)


def rand_float32():
    """Generate a random float32 in [-1.0, 1.0]."""
    return to_float32(random.uniform(-1.0, 1.0))


def generate_float32_audio(size, sample_rate=44100, stereo=True):
    """
    Generate 32-bit float test audio of 2^size samples with transformation variants.

    Args:
        size: Power of 2 for number of samples (e.g., 12 -> 2^12 = 4096 samples)
        sample_rate: Sample rate in Hz
        stereo: Whether to generate stereo audio
    """
    print(f"Generating 32-bit float audio for size 2^{size} ({2**size} samples)")

    num_samples = 2 ** size

    # Generate random float32 samples in [-1.0, 1.0]
    left_samples = [rand_float32() for _ in range(num_samples)]

    # Save original mono audio
    float32_audio_to_json(os.path.join(_HERE, f"Audio{size}.json"), left_samples, sample_rate, 1)

    if stereo:
        right_samples = [rand_float32() for _ in range(num_samples)]

        # Save stereo audio
        float32_audio_to_json(
            os.path.join(_HERE, f"StereoAudio{size}.json"),
            left_samples,
            sample_rate,
            2,
            right_samples
        )

        # Mono mix: (left + right) / 2, rounded to float32
        mono_samples = [to_float32((l + r) / 2.0) for l, r in zip(left_samples, right_samples)]
        float32_audio_to_json(os.path.join(_HERE, f"Mono{size}.json"), mono_samples, sample_rate, 1)

    # Trimmed audio (first half)
    trim_length = num_samples // 2
    trimmed_samples = left_samples[:trim_length]
    float32_audio_to_json(os.path.join(_HERE, f"Trim{size}.json"), trimmed_samples, sample_rate, 1)

    # Volume-scaled audio (50%)
    volume_samples = [to_float32(s * 0.5) for s in left_samples]
    float32_audio_to_json(os.path.join(_HERE, f"Volume{size}.json"), volume_samples, sample_rate, 1)

    # Gain-scaled audio (87.5% = 7/8)
    gain_samples = [to_float32(s * 0.875) for s in left_samples]
    float32_audio_to_json(f"Gain{size}.json", gain_samples, sample_rate, 1)

    print(f"  Done! Generated:")
    print(f"    Audio{size}.json        ({num_samples} samples, mono)")
    if stereo:
        print(f"    StereoAudio{size}.json  ({num_samples} samples, stereo)")
        print(f"    Mono{size}.json         ({num_samples} samples, mono mix)")
    print(f"    Trim{size}.json         ({trim_length} samples, trimmed)")
    print(f"    Volume{size}.json       ({num_samples} samples, 50% volume)")
    print(f"    Gain{size}.json         ({num_samples} samples, 87.5% gain)")


def generate_all_float32(start_size=8, end_size=25, stereo=True):
    """
    Generate 32-bit float test audio for sizes 2^start_size through 2^end_size.

    Args:
        start_size: Starting power of 2 (default 8)
        end_size: Ending power of 2 inclusive (default 25)
        stereo: Whether to generate stereo audio
    """
    print("=" * 60)
    print("Generating 32-bit Float Audio Test Data")
    print(f"Sizes: 2^{start_size} to 2^{end_size}")
    print(f"Stereo: {stereo}")
    print("=" * 60)
    print()

    for size in range(start_size, end_size + 1):
        generate_float32_audio(size, stereo=stereo)
        print()

    print("All 32-bit float audio generated!")


if __name__ == "__main__":
    generate_all_float32(8, 25, stereo=True)
