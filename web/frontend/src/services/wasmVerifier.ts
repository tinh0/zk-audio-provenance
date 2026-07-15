import { init, verify_crop_brakedown } from '../wasm-pkg/hyperveritas_wasm';

let initialized = false;

function ensureInit(): void {
  if (!initialized) {
    init();
    initialized = true;
  }
}

export interface WasmVerifyResult {
  verified: boolean;
  message: string;
}

/**
 * Verify a HyperVerITAS crop proof (Brakedown PCS) client-side using WASM.
 *
 * @param inputSize - log2 size parameter (e.g., 14, 15)
 * @param proofBytes - raw proof bytes (contents of proof.bin)
 * @param publicInputsJson - JSON string with origWidth, origHeight, startX, startY, endX, endY
 * @param cameraHashJson - JSON string of the camera hash (digestRGB) - public attestation
 * @param cropImageJson - JSON string of cropped image {rows, cols, R, G, B}
 */
export async function verifyCropBrakedown(
  inputSize: number,
  proofBytes: Uint8Array,
  publicInputsJson: string,
  cameraHashJson: string,
  cropImageJson: string,
): Promise<WasmVerifyResult> {
  await ensureInit();
  return verify_crop_brakedown(
    inputSize,
    proofBytes,
    publicInputsJson,
    cameraHashJson,
    cropImageJson,
  ) as WasmVerifyResult;
}
