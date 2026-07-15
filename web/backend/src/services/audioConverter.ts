import { HVAudioJson } from '@hyperveritas-web/shared/types';

/**
 * Convert a WAV buffer to HyperVerITAS Audio JSON format.
 * Matches: hyperveritas_impl/src/audio.rs Audio struct
 *
 * WAV format: RIFF header + PCM data
 * We parse the WAV manually to handle 8/16/24 bit depths.
 */
export function wavToHVJson(buffer: Buffer): HVAudioJson {
  // Parse WAV header
  const riff = buffer.toString('ascii', 0, 4);
  if (riff !== 'RIFF') throw new Error('Not a valid WAV file');

  const wave = buffer.toString('ascii', 8, 12);
  if (wave !== 'WAVE') throw new Error('Not a valid WAV file');

  // Find fmt chunk
  let offset = 12;
  let fmtOffset = -1;
  let dataOffset = -1;
  let dataSize = 0;

  while (offset < buffer.length - 8) {
    const chunkId = buffer.toString('ascii', offset, offset + 4);
    const chunkSize = buffer.readUInt32LE(offset + 4);

    if (chunkId === 'fmt ') {
      fmtOffset = offset + 8;
    } else if (chunkId === 'data') {
      dataOffset = offset + 8;
      dataSize = chunkSize;
    }

    offset += 8 + chunkSize;
    // Align to even boundary
    if (chunkSize % 2 !== 0) offset++;
  }

  if (fmtOffset === -1 || dataOffset === -1) {
    throw new Error('Invalid WAV: missing fmt or data chunk');
  }

  const audioFormat = buffer.readUInt16LE(fmtOffset);
  // Format 1 = PCM integer, Format 3 = IEEE float
  if (audioFormat !== 1 && audioFormat !== 3) {
    throw new Error('Only PCM (format 1) and IEEE float (format 3) WAV are supported');
  }

  const numChannels = buffer.readUInt16LE(fmtOffset + 2) as 1 | 2;
  const sampleRate = buffer.readUInt32LE(fmtOffset + 4);
  const bitsPerSample = buffer.readUInt16LE(fmtOffset + 14);

  if (audioFormat === 3 && bitsPerSample !== 32) {
    throw new Error(`IEEE float WAV must be 32-bit, got ${bitsPerSample}-bit`);
  }
  if (audioFormat === 1 && bitsPerSample !== 8 && bitsPerSample !== 16 && bitsPerSample !== 24) {
    throw new Error(`Unsupported PCM bit depth: ${bitsPerSample}. Only 8, 16, 24 supported.`);
  }

  const isFloat32 = audioFormat === 3;

  const bytesPerSample = bitsPerSample / 8;
  const totalSamples = Math.floor(dataSize / (bytesPerSample * numChannels));

  // Truncate to nearest power of 2
  let numSamples = 1;
  while (numSamples * 2 <= totalSamples) numSamples *= 2;

  const left: number[] = [];
  const right: number[] = [];

  for (let i = 0; i < numSamples; i++) {
    const sampleOffset = dataOffset + i * numChannels * bytesPerSample;

    if (isFloat32) {
      // IEEE float32: read as float directly
      left.push(buffer.readFloatLE(sampleOffset));
      if (numChannels === 2) {
        right.push(buffer.readFloatLE(sampleOffset + bytesPerSample));
      }
    } else {
      // PCM integer
      left.push(readSample(buffer, sampleOffset, bitsPerSample));
      if (numChannels === 2) {
        right.push(readSample(buffer, sampleOffset + bytesPerSample, bitsPerSample));
      }
    }
  }

  return {
    sample_rate: sampleRate,
    bit_depth: bitsPerSample as 8 | 16 | 24 | 32,
    num_channels: numChannels,
    num_samples: numSamples,
    left,
    right: numChannels === 2 ? right : undefined,
  };
}

function readSample(buffer: Buffer, offset: number, bitDepth: number): number {
  switch (bitDepth) {
    case 8:
      // 8-bit is unsigned [0, 255]
      return buffer.readUInt8(offset);
    case 16:
      // 16-bit is signed [-32768, 32767]
      return buffer.readInt16LE(offset);
    case 24: {
      // 24-bit is signed [-8388608, 8388607]
      const val = buffer.readUInt8(offset) |
        (buffer.readUInt8(offset + 1) << 8) |
        (buffer.readUInt8(offset + 2) << 16);
      // Sign extend
      return val >= 0x800000 ? val - 0x1000000 : val;
    }
    default:
      throw new Error(`Unsupported bit depth: ${bitDepth}`);
  }
}

/**
 * Convert HyperVerITAS Audio JSON back to a WAV buffer.
 */
export function hvJsonToWav(json: HVAudioJson): Buffer {
  const bytesPerSample = json.bit_depth / 8;
  const dataSize = json.num_samples * json.num_channels * bytesPerSample;
  const headerSize = 44;
  const buffer = Buffer.alloc(headerSize + dataSize);

  // RIFF header
  buffer.write('RIFF', 0);
  buffer.writeUInt32LE(36 + dataSize, 4);
  buffer.write('WAVE', 8);

  // fmt chunk
  buffer.write('fmt ', 12);
  buffer.writeUInt32LE(16, 16);          // chunk size
  buffer.writeUInt16LE(1, 20);           // PCM format
  buffer.writeUInt16LE(json.num_channels, 22);
  buffer.writeUInt32LE(json.sample_rate, 24);
  buffer.writeUInt32LE(json.sample_rate * json.num_channels * bytesPerSample, 28); // byte rate
  buffer.writeUInt16LE(json.num_channels * bytesPerSample, 32); // block align
  buffer.writeUInt16LE(json.bit_depth, 34);

  // data chunk
  buffer.write('data', 36);
  buffer.writeUInt32LE(dataSize, 40);

  let offset = 44;
  for (let i = 0; i < json.num_samples; i++) {
    writeSample(buffer, offset, json.left[i], json.bit_depth);
    offset += bytesPerSample;

    if (json.num_channels === 2 && json.right) {
      writeSample(buffer, offset, json.right[i], json.bit_depth);
      offset += bytesPerSample;
    }
  }

  return buffer;
}

function writeSample(buffer: Buffer, offset: number, value: number, bitDepth: number): void {
  switch (bitDepth) {
    case 8:
      buffer.writeUInt8(Math.max(0, Math.min(255, value)), offset);
      break;
    case 16:
      buffer.writeInt16LE(Math.max(-32768, Math.min(32767, value)), offset);
      break;
    case 24: {
      const clamped = Math.max(-8388608, Math.min(8388607, value));
      const unsigned = clamped < 0 ? clamped + 0x1000000 : clamped;
      buffer.writeUInt8(unsigned & 0xFF, offset);
      buffer.writeUInt8((unsigned >> 8) & 0xFF, offset + 1);
      buffer.writeUInt8((unsigned >> 16) & 0xFF, offset + 2);
      break;
    }
  }
}

/** Get the size parameter (log2 of total samples) */
export function getAudioSizeParam(json: HVAudioJson): number {
  return Math.round(Math.log2(json.num_samples));
}
