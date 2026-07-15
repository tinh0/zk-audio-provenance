"""
Audio test data generation for HyperVerITAS audio extension.

This module generates test audio data in JSON format for benchmarking the
audio transformation proofs (trim, mono mix, volume scaling).
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
import numpy as np
import math
import wave
import struct


def audio_to_json(path, samples, sample_rate, bit_depth, num_channels, right_samples=None):
    """
    Save audio data to JSON format matching the Rust Audio struct.

    Args:
        path: Output JSON file path
        samples: Left/mono channel samples (list of integers)
        sample_rate: Sample rate in Hz (e.g., 44100)
        bit_depth: Bit depth (8, 16, or 24)
        num_channels: Number of channels (1 for mono, 2 for stereo)
        right_samples: Right channel samples for stereo (optional)
    """
    audio_json = {
        "sample_rate": sample_rate,
        "bit_depth": bit_depth,
        "num_channels": num_channels,
        "num_samples": len(samples),
        "left": samples if isinstance(samples, list) else samples.tolist(),
        "right": right_samples if right_samples is None else (
            right_samples if isinstance(right_samples, list) else right_samples.tolist()
        )
    }

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(audio_json, f, ensure_ascii=False, indent=4)


def json_to_audio(path):
    """
    Load audio data from JSON format.

    Args:
        path: Input JSON file path

    Returns:
        Dictionary with audio data
    """
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def generate_test_audio(size, sample_rate=44100, bit_depth=8, stereo=False):
    """
    Generate test audio of 2^size samples with transformation variants.

    Creates:
    - Audio{size}.json: Original mono audio
    - StereoAudio{size}.json: Original stereo audio (if stereo=True)
    - Trim{size}.json: First half trimmed
    - Mono{size}.json: Stereo to mono mix (if stereo=True)
    - Volume{size}.json: 50% volume

    Args:
        size: Power of 2 for number of samples (e.g., 19 -> 2^19 samples)
        sample_rate: Sample rate in Hz
        bit_depth: Bit depth (8, 16, or 24)
        stereo: Whether to generate stereo audio
    """
    print(f"Generating audio data for size 2^{size}")

    num_samples = 2 ** size

    # Determine value range based on bit depth
    if bit_depth == 8:
        # 8-bit WAV is unsigned [0, 255]
        min_val, max_val = 0, 255
    elif bit_depth == 16:
        # 16-bit WAV is signed [-32768, 32767]
        min_val, max_val = -32768, 32767
    elif bit_depth == 24:
        # 24-bit WAV is signed [-8388608, 8388607]
        min_val, max_val = -8388608, 8388607
    else:
        raise ValueError(f"Unsupported bit depth: {bit_depth}")

    # Generate random audio samples
    left_samples = np.random.randint(min_val, max_val + 1, size=num_samples, dtype=np.int32)

    # Save original mono audio
    audio_to_json(os.path.join(_HERE, f"Audio{size}.json"), left_samples.tolist(), sample_rate, bit_depth, 1)

    if stereo:
        right_samples = np.random.randint(min_val, max_val + 1, size=num_samples, dtype=np.int32)

        # Save original stereo audio
        audio_to_json(
            os.path.join(_HERE, f"StereoAudio{size}.json"),
            left_samples.tolist(),
            sample_rate,
            bit_depth,
            2,
            right_samples.tolist()
        )

        # Generate mono mix: floor((left + right) / 2)
        mono_samples = ((left_samples.astype(np.int64) + right_samples.astype(np.int64)) // 2).astype(np.int32)
        audio_to_json(os.path.join(_HERE, f"Mono{size}.json"), mono_samples.tolist(), sample_rate, bit_depth, 1)

    # Generate trimmed audio (first half)
    trim_length = num_samples // 2
    trimmed_samples = left_samples[:trim_length]
    audio_to_json(os.path.join(_HERE, f"Trim{size}.json"), trimmed_samples.tolist(), sample_rate, bit_depth, 1)

    # Generate volume-scaled audio (50% volume)
    # For unsigned 8-bit: scaled = original / 2
    # For signed: scaled = original / 2 (preserving sign)
    volume_samples = (left_samples // 2).astype(np.int32)
    audio_to_json(os.path.join(_HERE, f"Volume{size}.json"), volume_samples.tolist(), sample_rate, bit_depth, 1)

    print(f"Generation complete for size 2^{size}!")
    print(f"  - Audio{size}.json: {num_samples} samples (mono)")
    if stereo:
        print(f"  - StereoAudio{size}.json: {num_samples} samples (stereo)")
        print(f"  - Mono{size}.json: {num_samples} samples (mono mix)")
    print(f"  - Trim{size}.json: {trim_length} samples (trimmed)")
    print(f"  - Volume{size}.json: {num_samples} samples (50% volume)")
    print()


def generate_all_audio(start_size=19, end_size=25, bit_depth=8, stereo=True):
    """
    Generate test audio for a range of sizes.

    Args:
        start_size: Starting power of 2
        end_size: Ending power of 2 (inclusive)
        bit_depth: Bit depth (8, 16, or 24)
        stereo: Whether to generate stereo audio
    """
    print("Generating Audio Test Data...")
    print(f"Bit depth: {bit_depth}")
    print(f"Stereo: {stereo}")
    print()

    for size in range(start_size, end_size + 1):
        generate_test_audio(size, bit_depth=bit_depth, stereo=stereo)

    print("All audio generated!")


def wav_to_json(wav_path, json_path):
    """
    Convert a WAV file to JSON format.

    Args:
        wav_path: Path to input WAV file
        json_path: Path to output JSON file
    """
    with wave.open(wav_path, 'rb') as wav_file:
        num_channels = wav_file.getnchannels()
        sample_width = wav_file.getsampwidth()
        sample_rate = wav_file.getframerate()
        num_frames = wav_file.getnframes()

        bit_depth = sample_width * 8

        # Read all frames
        raw_data = wav_file.readframes(num_frames)

        # Determine format string based on sample width
        if sample_width == 1:
            # 8-bit is unsigned
            fmt = f'{num_frames * num_channels}B'
            samples = list(struct.unpack(fmt, raw_data))
        elif sample_width == 2:
            # 16-bit is signed
            fmt = f'{num_frames * num_channels}h'
            samples = list(struct.unpack(fmt, raw_data))
        elif sample_width == 3:
            # 24-bit needs special handling
            samples = []
            for i in range(0, len(raw_data), 3):
                # Little-endian 24-bit to signed int
                val = raw_data[i] | (raw_data[i+1] << 8) | (raw_data[i+2] << 16)
                if val >= 0x800000:
                    val -= 0x1000000
                samples.append(val)
        else:
            raise ValueError(f"Unsupported sample width: {sample_width}")

        # Deinterleave channels
        if num_channels == 1:
            left_samples = samples
            right_samples = None
        else:
            left_samples = samples[0::2]
            right_samples = samples[1::2]

        audio_to_json(json_path, left_samples, sample_rate, bit_depth, num_channels, right_samples)

        print(f"Converted {wav_path} to {json_path}")
        print(f"  Sample rate: {sample_rate} Hz")
        print(f"  Bit depth: {bit_depth}")
        print(f"  Channels: {num_channels}")
        print(f"  Samples: {len(left_samples)}")


def json_to_wav(json_path, wav_path):
    """
    Convert a JSON audio file back to WAV format.

    Args:
        json_path: Path to input JSON file
        wav_path: Path to output WAV file
    """
    audio = json_to_audio(json_path)

    sample_rate = audio['sample_rate']
    bit_depth = audio['bit_depth']
    num_channels = audio['num_channels']
    left_samples = audio['left']
    right_samples = audio.get('right')

    sample_width = bit_depth // 8

    with wave.open(wav_path, 'wb') as wav_file:
        wav_file.setnchannels(num_channels)
        wav_file.setsampwidth(sample_width)
        wav_file.setframerate(sample_rate)

        # Interleave channels if stereo
        if num_channels == 2 and right_samples:
            samples = []
            for l, r in zip(left_samples, right_samples):
                samples.append(l)
                samples.append(r)
        else:
            samples = left_samples

        # Pack samples
        if sample_width == 1:
            raw_data = struct.pack(f'{len(samples)}B', *samples)
        elif sample_width == 2:
            raw_data = struct.pack(f'{len(samples)}h', *samples)
        elif sample_width == 3:
            raw_data = b''
            for s in samples:
                if s < 0:
                    s += 0x1000000
                raw_data += bytes([s & 0xFF, (s >> 8) & 0xFF, (s >> 16) & 0xFF])
        else:
            raise ValueError(f"Unsupported sample width: {sample_width}")

        wav_file.writeframes(raw_data)

        print(f"Converted {json_path} to {wav_path}")


if __name__ == "__main__":
    # Generate test audio for sizes 2^19 to 2^25
    # Using 8-bit depth initially, with both mono and stereo variants
    generate_all_audio(19, 25, bit_depth=8, stereo=True)
