import { useState, useEffect } from 'react';
import { Download, ShieldCheck, ShieldX, Clock, HardDrive, Cpu } from 'lucide-react';
import { getFileUrl, verifyProof, fetchProofBytes, fetchPublicInputs, fetchCropImageJson, fetchCameraHash, fetchCameraAttestation } from '../../services/api';
import type { VerifyResponse, CameraAttestation } from '../../services/api';
import type { Job } from '../../types';
import { VerifiedMedia } from './VerifiedMedia';
import type { VerifyWorkerResponse } from '../../workers/verifyWorker';

type VerificationStatus = 'pending' | 'checking' | 'verified' | 'failed';

interface ResultsDisplayProps {
  job: Job;
}

export function ResultsDisplay({ job }: ResultsDisplayProps) {
  const [verifyStatus, setVerifyStatus] = useState<VerificationStatus>('pending');
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);

  const originalUrl = getFileUrl(job.jobId, 'original');
  const transformedUrl = getFileUrl(job.jobId, 'output');
  const isImage = job.mediaType === 'image';

  // Determine if this job supports real verification (split prover)
  const hasSplitVerifier = !!job.proofFilePath;
  // Determine if this job supports client-side WASM verification
  const supportsWasmVerify = hasSplitVerifier && job.transformation === 'crop' && job.pcs === 'brakedown';

  /**
   * Convert a DER-encoded ECDSA signature to IEEE P1363 format (r || s).
   * Node.js crypto produces DER; Web Crypto API expects P1363.
   */
  const derToP1363 = (derSig: Uint8Array, curveSize: number = 32): Uint8Array => {
    let offset = 2;
    if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const rLen = derSig[offset++];
    const rBytes = derSig.slice(offset, offset + rLen);
    offset += rLen;
    if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const sLen = derSig[offset++];
    const sBytes = derSig.slice(offset, offset + sLen);
    const result = new Uint8Array(curveSize * 2);
    const rStart = rBytes[0] === 0 ? 1 : 0;
    const rActual = rBytes.slice(rStart);
    result.set(rActual, curveSize - rActual.length);
    const sStart = sBytes[0] === 0 ? 1 : 0;
    const sActual = sBytes.slice(sStart);
    result.set(sActual, curveSize * 2 - sActual.length);
    return result;
  };

  // Verify ECDSA signature on camera hash using Web Crypto API
  const verifyEcdsaSignature = async (
    cameraHashJson: string,
    attestation: CameraAttestation,
  ): Promise<boolean> => {
    // Import camera public key from PEM
    const pemBody = attestation.publicKey
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '');
    const keyBuffer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

    const publicKey = await crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );

    // Convert DER signature (from Node.js) to P1363 format (for Web Crypto)
    const derSig = Uint8Array.from(atob(attestation.signature), c => c.charCodeAt(0));
    const sigBuffer = derToP1363(derSig);
    const dataBuffer = new TextEncoder().encode(cameraHashJson);

    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBuffer.buffer as ArrayBuffer,
      dataBuffer,
    );
  };

  // Client-side verification: ECDSA signature check + ZK proof verification via Web Worker
  const verifyClientSide = async (): Promise<VerifyResponse> => {
    // Fetch all artifacts in parallel - no original image needed!
    const [proofBytes, publicInputsJson, cameraHashJson, cropImageJson, attestation] = await Promise.all([
      fetchProofBytes(job.jobId),
      fetchPublicInputs(job.jobId),
      fetchCameraHash(job.jobId),
      fetchCropImageJson(job.jobId),
      fetchCameraAttestation(job.jobId),
    ]);

    // Step 1: Verify ECDSA signature on the camera hash
    const sigValid = await verifyEcdsaSignature(cameraHashJson, attestation);
    if (!sigValid) {
      return {
        verified: false,
        verifierTimeSec: 0,
        message: 'Camera signature verification failed - the image hash may have been tampered with.',
      };
    }

    // Step 2: Verify ZK proof against the camera hash via Web Worker
    return new Promise((resolve, reject) => {
      const worker = new Worker(
        new URL('../../workers/verifyWorker.ts', import.meta.url),
        { type: 'module' }
      );

      worker.onmessage = (e: MessageEvent<VerifyWorkerResponse>) => {
        worker.terminate();
        if (e.data.success && e.data.result) {
          resolve({
            verified: e.data.result.verified,
            verifierTimeSec: (e.data.timeMs ?? 0) / 1000,
            message: e.data.result.message + ' (verified client-side: ECDSA signature + ZK proof)',
          });
        } else {
          reject(new Error(e.data.error || 'WASM verification failed'));
        }
      };

      worker.onerror = (err) => {
        worker.terminate();
        reject(err);
      };

      worker.postMessage({
        inputSize: job.sizeParam,
        proofBytes,
        publicInputsJson,
        cameraHashJson,
        cropImageJson,
      });
    });
  };

  // Auto-verify on mount for split prover jobs
  useEffect(() => {
    if (!hasSplitVerifier) return;

    let cancelled = false;
    setVerifyStatus('checking');

    const verifyFn = supportsWasmVerify ? verifyClientSide() : verifyProof(job.jobId);

    verifyFn.then((result) => {
      if (cancelled) return;
      setVerifyResult(result);
      setVerifyStatus(result.verified ? 'verified' : 'failed');
    }).catch(() => {
      if (cancelled) return;
      setVerifyStatus('failed');
    });

    return () => { cancelled = true; };
  }, [job.jobId, hasSplitVerifier]);

  // Manual verify for non-split jobs
  const handleManualVerify = async () => {
    setVerifyStatus('checking');
    try {
      const result = supportsWasmVerify ? await verifyClientSide() : await verifyProof(job.jobId);
      setVerifyResult(result);
      setVerifyStatus(result.verified ? 'verified' : 'failed');
    } catch {
      setVerifyStatus('failed');
    }
  };

  // Show verifier time from either the auto-verify result or the pre-computed job metric
  const verifierTimeSec = verifyResult?.verifierTimeSec ?? job.verifierTimeSec;

  return (
    <div className="space-y-6">
      {/* Metrics Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="stat bg-base-200 rounded-xl p-4">
          <div className="stat-figure text-primary">
            <Clock className="w-6 h-6" />
          </div>
          <div className="stat-title text-xs">Prover Time</div>
          <div className="stat-value text-lg">{job.proverTimeSec?.toFixed(3)}s</div>
        </div>
        <div className="stat bg-base-200 rounded-xl p-4">
          <div className="stat-figure text-secondary">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div className="stat-title text-xs">Verifier Time</div>
          <div className="stat-value text-lg">
            {verifierTimeSec != null ? `${verifierTimeSec.toFixed(3)}s` : (
              verifyStatus === 'checking' ? '...' : 'N/A'
            )}
          </div>
        </div>
        <div className="stat bg-base-200 rounded-xl p-4">
          <div className="stat-figure text-accent">
            <HardDrive className="w-6 h-6" />
          </div>
          <div className="stat-title text-xs">Proof Size</div>
          <div className="stat-value text-lg">{formatBytes(job.proofSizeBytes || 0)}</div>
        </div>
        <div className="stat bg-base-200 rounded-xl p-4">
          <div className="stat-figure text-info">
            <Cpu className="w-6 h-6" />
          </div>
          <div className="stat-title text-xs">
            {job.nbConstraints ? 'Constraints' : 'Size Param'}
          </div>
          <div className="stat-value text-lg">
            {job.nbConstraints ? job.nbConstraints.toLocaleString() : `2^${job.sizeParam}`}
          </div>
        </div>
      </div>

      {/* Side-by-side comparison with verification overlays */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h3 className="card-title text-sm">Original</h3>
            {hasSplitVerifier ? (
              <VerifiedMedia
                src={originalUrl}
                mediaType={job.mediaType}
                status={verifyStatus}
                alt="Original"
              />
            ) : isImage ? (
              <img src={originalUrl} alt="Original" className="rounded-lg max-h-64 mx-auto" />
            ) : (
              <audio controls className="w-full">
                <source src={originalUrl} type="audio/wav" />
              </audio>
            )}
          </div>
        </div>
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h3 className="card-title text-sm">
              Transformed ({job.transformation})
            </h3>
            {hasSplitVerifier ? (
              <VerifiedMedia
                src={transformedUrl}
                mediaType={job.mediaType}
                status={verifyStatus}
                alt="Transformed"
              />
            ) : isImage ? (
              <img src={transformedUrl} alt="Transformed" className="rounded-lg max-h-64 mx-auto" />
            ) : (
              <audio controls className="w-full">
                <source src={transformedUrl} type="audio/wav" />
              </audio>
            )}
          </div>
        </div>
      </div>

      {/* Info badge */}
      <div className="text-center flex flex-wrap gap-2 justify-center">
        <div className="badge badge-lg badge-outline">
          Engine: <span className="font-semibold ml-1">{job.proverEngine === 'gnark' ? 'gnark (Go)' : 'HyperVerITAS (Rust)'}</span>
        </div>
        <div className="badge badge-lg badge-outline">
          {job.proverEngine === 'gnark'
            ? <>Backend: <span className="font-semibold ml-1 uppercase">{job.gnarkBackend}</span></>
            : <>PCS: <span className="font-semibold ml-1 capitalize">{job.pcs}</span></>
          }
        </div>
        <div className="badge badge-lg badge-outline">
          Transform: <span className="font-semibold ml-1 capitalize">{job.transformation.replace('_', ' ')}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-wrap gap-3 justify-center">
        {!hasSplitVerifier && (
          <button
            className={`btn ${verifyStatus === 'verified' ? 'btn-success' : 'btn-primary'} gap-2`}
            onClick={handleManualVerify}
            disabled={verifyStatus === 'checking' || verifyStatus === 'verified'}
          >
            {verifyStatus === 'checking' ? (
              <span className="loading loading-spinner loading-sm"></span>
            ) : (
              <ShieldCheck className="w-4 h-4" />
            )}
            {verifyStatus === 'verified' ? 'Verified!' : 'Verify Proof'}
          </button>
        )}

        <a href={transformedUrl} download className="btn btn-outline gap-2">
          <Download className="w-4 h-4" />
          Download {isImage ? 'Image' : 'Audio'}
        </a>
      </div>

      {/* Verification result banner */}
      {verifyStatus === 'verified' && supportsWasmVerify && (
        <div className="alert alert-success">
          <ShieldCheck className="w-5 h-5" />
          <div>
            <div className="font-medium">Client-Side Verification Passed</div>
            <div className="text-sm space-y-1">
              <div>1. Camera signature (ECDSA P-256) - valid</div>
              <div>2. ZK proof ({job.transformation} transformation) - valid ({verifyResult?.verifierTimeSec?.toFixed(2)}s)</div>
              <div className="opacity-70 mt-1">Verified entirely in your browser. No server trust required.</div>
            </div>
          </div>
        </div>
      )}

      {verifyStatus === 'verified' && !supportsWasmVerify && (
        <div className="alert alert-success">
          <ShieldCheck className="w-5 h-5" />
          <div>
            <div className="font-medium">Proof Verified Successfully</div>
            <div className="text-sm">
              {verifyResult?.message || `The transformed ${job.mediaType} is a valid ${job.transformation} of the original.`}
              {hasSplitVerifier && ' Verified by independent verifier binary.'}
            </div>
          </div>
        </div>
      )}

      {verifyStatus === 'failed' && (
        <div className="alert alert-error">
          <ShieldX className="w-5 h-5" />
          <div>
            <div className="font-medium">Verification Failed</div>
            <div className="text-sm">
              {verifyResult?.message || 'The proof could not be verified. The media may have been tampered with.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
