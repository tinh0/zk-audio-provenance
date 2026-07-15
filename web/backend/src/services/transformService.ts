import {
  HVImageJson,
  HVAudioJson,
  CropParams,
  VolumeParams,
  TrimParams,
} from '@hyperveritas-web/shared/types';

// ============================================================
// Image Transformations
// Matching logic from hyperveritas_impl/images/helper.py
// ============================================================

/**
 * Crop an image from the top-left corner.
 *
 * The Rust prover (hv_crop_brakedown.rs lines 469-470) hardcodes:
 *   cropStartX = 0, cropStartY = 0
 *   cropEndX = cropImg.rows, cropEndY = cropImg.cols
 * And requires nvCrop = input_size - 1, so crop total = 2^(N-1).
 *
 * We halve one dimension (the larger one) to get half the total pixels,
 * preserving aspect ratio as much as possible.
 *
 * JSON convention: rows = width, cols = height (swapped from normal).
 * Pixel layout: R[h * rows + w] where h in 0..cols-1, w in 0..rows-1.
 */
export function applyCrop(img: HVImageJson, _params: CropParams): HVImageJson {
  // JSON rows = width, cols = height
  const origWidth = img.rows;
  const origHeight = img.cols;

  // Halve the larger dimension to get half total pixels
  let cropWidth: number;
  let cropHeight: number;

  if (origHeight >= origWidth) {
    cropHeight = origHeight / 2;
    cropWidth = origWidth;
  } else {
    cropHeight = origHeight;
    cropWidth = origWidth / 2;
  }

  const totalPixels = cropWidth * cropHeight;
  const R: number[] = new Array(totalPixels);
  const G: number[] = new Array(totalPixels);
  const B: number[] = new Array(totalPixels);

  // Extract top-left cropHeight x cropWidth block
  // Pixel layout: R[h * width + w]
  for (let h = 0; h < cropHeight; h++) {
    for (let w = 0; w < cropWidth; w++) {
      const srcIdx = h * origWidth + w;
      const dstIdx = h * cropWidth + w;
      R[dstIdx] = img.R[srcIdx];
      G[dstIdx] = img.G[srcIdx];
      B[dstIdx] = img.B[srcIdx];
    }
  }

  return { rows: cropWidth, cols: cropHeight, R, G, B };
}

/**
 * Convert image to grayscale.
 * Reference: helper.py makeGray() lines 31-43
 * Formula: val = round(0.3*R + 0.59*G + 0.11*B)
 */
export function applyGrayscale(img: HVImageJson): HVImageJson {
  const totalPixels = img.rows * img.cols;
  const R: number[] = new Array(totalPixels);
  const G: number[] = new Array(totalPixels);
  const B: number[] = new Array(totalPixels);

  for (let i = 0; i < totalPixels; i++) {
    const val = Math.round(0.3 * img.R[i] + 0.59 * img.G[i] + 0.11 * img.B[i]);
    const clamped = Math.min(255, Math.max(0, val));
    R[i] = clamped;
    G[i] = clamped;
    B[i] = clamped;
  }

  return { rows: img.rows, cols: img.cols, R, G, B };
}

// ============================================================
// Audio Transformations
// Matching logic from hyperveritas_impl/audio/helper.py
// ============================================================

/**
 * Convert stereo to mono by averaging channels.
 * Reference: audio/helper.py line ~110
 */
export function applyMono(audio: HVAudioJson): HVAudioJson {
  if (audio.num_channels !== 2 || !audio.right) {
    throw new Error('Mono transformation requires stereo input');
  }

  const left: number[] = new Array(audio.num_samples);
  for (let i = 0; i < audio.num_samples; i++) {
    left[i] = Math.floor((audio.left[i] + audio.right[i]) / 2);
  }

  return {
    sample_rate: audio.sample_rate,
    bit_depth: audio.bit_depth,
    num_channels: 1,
    num_samples: audio.num_samples,
    left,
  };
}

/**
 * Adjust volume by a multiplication factor.
 * Reference: audio/helper.py line ~121
 */
export function applyVolume(audio: HVAudioJson, params: VolumeParams): HVAudioJson {
  if (audio.bit_depth === 32) {
    throw new Error('float32 volume is handled by the gnark prover, not integer transforms');
  }
  const maxVal = getMaxVal(audio.bit_depth);
  const minVal = getMinVal(audio.bit_depth);

  const left = audio.left.map(s =>
    Math.max(minVal, Math.min(maxVal, Math.floor(s * params.factor)))
  );

  const right = audio.right
    ? audio.right.map(s =>
        Math.max(minVal, Math.min(maxVal, Math.floor(s * params.factor)))
      )
    : undefined;

  return { ...audio, left, right };
}

/**
 * Trim audio to a sample range.
 * Reference: audio/helper.py line ~113-116
 */
export function applyTrim(audio: HVAudioJson, params: TrimParams): HVAudioJson {
  const { startSample, endSample } = params;

  if (startSample < 0 || endSample > audio.num_samples || startSample >= endSample) {
    throw new Error('Invalid trim range');
  }

  const newLength = endSample - startSample;
  // Pad to power of 2
  const paddedLength = nextPow2(newLength);

  const left = new Array(paddedLength).fill(0);
  const right = audio.right ? new Array(paddedLength).fill(0) : undefined;

  for (let i = 0; i < newLength; i++) {
    left[i] = audio.left[startSample + i];
    if (right && audio.right) {
      right[i] = audio.right[startSample + i];
    }
  }

  return {
    sample_rate: audio.sample_rate,
    bit_depth: audio.bit_depth,
    num_channels: audio.num_channels,
    num_samples: paddedLength,
    left,
    right,
  };
}

// ============================================================
// Helpers
// ============================================================

function nextPow2(n: number): number {
  let p = 1;
  while (p < n) p *= 2;
  return p;
}

function getMaxVal(bitDepth: 8 | 16 | 24): number {
  switch (bitDepth) {
    case 8: return 255;
    case 16: return 32767;
    case 24: return 8388607;
  }
}

function getMinVal(bitDepth: 8 | 16 | 24): number {
  switch (bitDepth) {
    case 8: return 0;
    case 16: return -32768;
    case 24: return -8388608;
  }
}
