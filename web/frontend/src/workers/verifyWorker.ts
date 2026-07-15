import { init, verify_crop_brakedown } from '../wasm-pkg/hyperveritas_wasm';

export interface VerifyWorkerRequest {
  inputSize: number;
  proofBytes: Uint8Array;
  publicInputsJson: string;
  cameraHashJson: string;
  cropImageJson: string;
}

export interface VerifyWorkerResponse {
  success: boolean;
  result?: { verified: boolean; message: string };
  error?: string;
  timeMs?: number;
}

self.onmessage = async (e: MessageEvent<VerifyWorkerRequest>) => {
  const { inputSize, proofBytes, publicInputsJson, cameraHashJson, cropImageJson } = e.data;
  try {
    await init();
    const start = performance.now();
    const result = verify_crop_brakedown(
      inputSize,
      proofBytes,
      publicInputsJson,
      cameraHashJson,
      cropImageJson,
    );
    const timeMs = performance.now() - start;
    self.postMessage({ success: true, result, timeMs } as VerifyWorkerResponse);
  } catch (err) {
    self.postMessage({ success: false, error: String(err) } as VerifyWorkerResponse);
  }
};
