import sharp from 'sharp';
import { HVImageJson } from '@hyperveritas-web/shared/types';

/**
 * Convert a PNG/JPG buffer to HyperVerITAS Image JSON format for the prover.
 *
 * The Python helper (imgToJSON) uses SWAPPED dimension labels:
 *   JSON "rows" = numpy width (W), JSON "cols" = numpy height (H)
 *   R array is flattened row-major: R[h * W + w]
 *
 * We resize to power-of-2 dimensions. The image will look padded/squished
 * but that's only for the prover - the original file is shown in the UI.
 */
export async function imageToHVJson(buffer: Buffer): Promise<HVImageJson> {
  const metadata = await sharp(buffer).metadata();
  if (!metadata.width || !metadata.height) {
    throw new Error('Could not read image dimensions');
  }

  // Round each dimension down to nearest power of 2
  let imgWidth = nearestPow2(metadata.width);
  let imgHeight = nearestPow2(metadata.height);

  // Ensure minimum 4x4
  imgWidth = Math.max(imgWidth, 4);
  imgHeight = Math.max(imgHeight, 4);

  // Resize and extract raw RGB pixels
  const rawPixels = await sharp(buffer)
    .resize(imgWidth, imgHeight, { fit: 'fill' })
    .removeAlpha()
    .raw()
    .toBuffer();

  const totalPixels = imgHeight * imgWidth;
  const R: number[] = new Array(totalPixels);
  const G: number[] = new Array(totalPixels);
  const B: number[] = new Array(totalPixels);

  for (let i = 0; i < totalPixels; i++) {
    R[i] = rawPixels[i * 3];
    G[i] = rawPixels[i * 3 + 1];
    B[i] = rawPixels[i * 3 + 2];
  }

  // Match Python convention: rows = width, cols = height
  return { rows: imgWidth, cols: imgHeight, R, G, B };
}

/**
 * Convert HyperVerITAS Image JSON back to a PNG buffer.
 */
export async function hvJsonToImage(json: HVImageJson): Promise<Buffer> {
  // JSON rows = width, cols = height (swapped)
  const imgWidth = json.rows;
  const imgHeight = json.cols;
  const totalPixels = imgWidth * imgHeight;
  const rawPixels = Buffer.alloc(totalPixels * 3);

  for (let i = 0; i < totalPixels; i++) {
    rawPixels[i * 3] = json.R[i];
    rawPixels[i * 3 + 1] = json.G[i];
    rawPixels[i * 3 + 2] = json.B[i];
  }

  return sharp(rawPixels, {
    raw: { width: imgWidth, height: imgHeight, channels: 3 },
  })
    .png()
    .toBuffer();
}

/** Round down to nearest power of 2 */
function nearestPow2(n: number): number {
  let p = 1;
  while (p * 2 <= n) p *= 2;
  return p;
}

/** Get the size parameter (log2 of total pixels) */
export function getImageSizeParam(json: HVImageJson): number {
  return Math.round(Math.log2(json.rows * json.cols));
}
