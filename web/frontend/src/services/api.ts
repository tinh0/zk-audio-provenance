const API_BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options?.headers || {}),
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error.error || `Request failed: ${res.status}`);
  }

  return res.json();
}

export async function uploadFile(file: File): Promise<{ fileId: string; fileName: string }> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error.error || 'Upload failed');
  }

  return res.json();
}

export async function startTransform(params: {
  fileId: string;
  mediaType: string;
  transformation: string;
  proverEngine: string;
  pcs?: string;
  gnarkBackend?: string;
  params: Record<string, any>;
}): Promise<{ jobId: string }> {
  return request('/transform', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

export async function getJobStatus(jobId: string): Promise<{ job: any }> {
  return request(`/status/${jobId}`);
}

export async function getJobResult(jobId: string): Promise<any> {
  return request(`/result/${jobId}`);
}

export interface VerifyResponse {
  verified: boolean;
  verifierTimeSec: number;
  message: string;
}

export async function verifyProof(jobId: string): Promise<VerifyResponse> {
  return request(`/verify/${jobId}`, { method: 'POST' });
}

export function getFileUrl(jobId: string, type: 'original' | 'output'): string {
  return `${API_BASE}/files/${jobId}/${type}`;
}

/** Fetch proof bytes for client-side WASM verification. */
export async function fetchProofBytes(jobId: string): Promise<Uint8Array> {
  const res = await fetch(`${API_BASE}/files/${jobId}/proof`);
  if (!res.ok) throw new Error('Failed to fetch proof');
  return new Uint8Array(await res.arrayBuffer());
}

/** Fetch public inputs JSON for client-side WASM verification. */
export async function fetchPublicInputs(jobId: string): Promise<string> {
  const res = await fetch(`${API_BASE}/files/${jobId}/public-inputs`);
  if (!res.ok) throw new Error('Failed to fetch public inputs');
  return res.text();
}

/** Fetch crop image JSON for client-side WASM verification. */
export async function fetchCropImageJson(jobId: string): Promise<string> {
  const res = await fetch(`${API_BASE}/files/${jobId}/crop-image-json`);
  if (!res.ok) throw new Error('Failed to fetch crop image JSON');
  return res.text();
}

/** Fetch the pre-computed camera hash (digestRGB) for client-side WASM verification. */
export async function fetchCameraHash(jobId: string): Promise<string> {
  const res = await fetch(`${API_BASE}/files/${jobId}/camera-hash`);
  if (!res.ok) throw new Error('Failed to fetch camera hash');
  return res.text();
}

/** Fetch the camera attestation (ECDSA signature + public key). */
export interface CameraAttestation {
  publicKey: string;
  signature: string;
  algorithm: string;
}

export async function fetchCameraAttestation(jobId: string): Promise<CameraAttestation> {
  const res = await fetch(`${API_BASE}/files/${jobId}/camera-attestation`);
  if (!res.ok) throw new Error('Failed to fetch camera attestation');
  return res.json();
}
