import { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, ShieldX, Loader2, XCircle } from 'lucide-react';
import { verifyCropBrakedown } from '../services/wasmVerifier';

const IMG_API = '/api/integrity-demo';
const AUDIO_API = '/api/audio-integrity-demo';

interface CameraAttestation {
  publicKey: string;
  signature: string;
  algorithm: string;
}

type VerifyStage = 'idle' | 'ecdsa-checking' | 'ecdsa-failed' | 'zk-checking' | 'verified' | 'zk-failed';
type AudioVerifyState = 'idle' | 'checking' | 'verified' | 'failed';

export function IntegrityDemoPage() {
  const [imgStatus, setImgStatus] = useState<any>(null);
  const [audioStatus, setAudioStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Image verification state
  const [authStage, setAuthStage] = useState<VerifyStage>('idle');
  const [authTime, setAuthTime] = useState<number | null>(null);
  const [tampStage, setTampStage] = useState<VerifyStage>('idle');
  const [tampTime, setTampTime] = useState<number | null>(null);

  // Audio verification state
  const [audioAuthState, setAudioAuthState] = useState<AudioVerifyState>('idle');
  const [audioAuthTime, setAudioAuthTime] = useState<number | null>(null);
  const [audioTampState, setAudioTampState] = useState<AudioVerifyState>('idle');
  const [audioTampTime, setAudioTampTime] = useState<number | null>(null);

  // Load both demos
  useEffect(() => {
    let imgReady = false, audioReady = false;
    const checkDone = () => { if (imgReady && audioReady) setLoading(false); };

    fetchOrSetup(IMG_API, (s: any) => { setImgStatus(s); imgReady = true; checkDone(); }, setError);
    fetchOrSetup(AUDIO_API, (s: any) => { setAudioStatus(s); audioReady = true; checkDone(); }, setError);
  }, []);

  // Image WASM verification
  const derToP1363 = (derSig: Uint8Array, curveSize = 32): Uint8Array => {
    let offset = 2;
    if (derSig[offset] !== 0x02) throw new Error('Invalid DER');
    offset++;
    const rLen = derSig[offset++];
    const rBytes = derSig.slice(offset, offset + rLen);
    offset += rLen;
    if (derSig[offset] !== 0x02) throw new Error('Invalid DER');
    offset++;
    const sLen = derSig[offset++];
    const sBytes = derSig.slice(offset, offset + sLen);
    const result = new Uint8Array(curveSize * 2);
    const rStart = rBytes[0] === 0 ? 1 : 0;
    result.set(rBytes.slice(rStart), curveSize - (rLen - rStart));
    const sStart = sBytes[0] === 0 ? 1 : 0;
    result.set(sBytes.slice(sStart), curveSize * 2 - (sLen - sStart));
    return result;
  };

  const verifyImage = useCallback(async (
    cropJsonFile: string,
    setStage: (s: VerifyStage) => void,
    setTime: (t: number) => void,
  ) => {
    if (!imgStatus) return;
    const sizeParam = imgStatus.sizeParam ?? 16;
    try {
      setStage('ecdsa-checking');
      const [proofRes, piRes, hashRes, cropRes, attRes] = await Promise.all([
        fetch(`${IMG_API}/files/proof`), fetch(`${IMG_API}/files/public-inputs`),
        fetch(`${IMG_API}/files/camera-hash`), fetch(`${IMG_API}/files/${cropJsonFile}`),
        fetch(`${IMG_API}/files/camera-attestation`),
      ]);
      const proofBytes = new Uint8Array(await proofRes.arrayBuffer());
      const piJson = await piRes.text();
      const hashJson = await hashRes.text();
      const cropJson = await cropRes.text();
      const att: CameraAttestation = await attRes.json();

      const pemBody = att.publicKey.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
      const pk = await crypto.subtle.importKey('spki',
        Uint8Array.from(atob(pemBody), c => c.charCodeAt(0)),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const sig = derToP1363(Uint8Array.from(atob(att.signature), c => c.charCodeAt(0)));
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, pk,
        sig.buffer as ArrayBuffer, new TextEncoder().encode(hashJson));
      if (!valid) { setStage('ecdsa-failed'); return; }

      setStage('zk-checking');
      await new Promise(r => setTimeout(r, 50));
      const start = performance.now();
      const result = await verifyCropBrakedown(sizeParam, proofBytes, piJson, hashJson, cropJson);
      setTime(performance.now() - start);
      setStage(result.verified ? 'verified' : 'zk-failed');
    } catch (err) {
      console.error('Image verification error:', err);
      setStage('zk-failed');
    }
  }, [imgStatus]);

  // Audio server-side verification
  const verifyAudio = async (
    which: 'authentic' | 'tampered',
    setState: (s: AudioVerifyState) => void,
    setTime: (t: number) => void,
  ) => {
    setState('checking');
    try {
      const res = await fetch(`${AUDIO_API}/verify/${which}`, { method: 'POST' });
      const result = await res.json();
      setTime(result.verifierTimeSec);
      setState(result.verified ? 'verified' : 'failed');
    } catch {
      setState('failed');
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col justify-center items-center min-h-[60vh] gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-base-content/60">Preparing demos...</p>
      </div>
    );
  }

  if (error) {
    return <div className="max-w-3xl mx-auto p-6"><div className="alert alert-error">{error}</div></div>;
  }

  return (
    <div className="max-w-5xl mx-auto py-8 px-4 space-y-8">
      <div className="text-center mb-4">
        <h1 className="text-3xl font-bold">End-to-End Demo</h1>
      </div>

      {/* Image: Crop */}
      {imgStatus?.ready && (
        <>
          <div className="divider text-lg font-semibold">Image Crop</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <ImageCard
              label="Verified"
              src={imgStatus.authenticImageUrl}
              stage={authStage}
              verifyTimeMs={authTime}
              onVerify={() => verifyImage('crop-json', setAuthStage, setAuthTime)}
            />
            <ImageCard
              label="Unverified"
              src={imgStatus.tamperedImageUrl}
              stage={tampStage}
              verifyTimeMs={tampTime}
              onVerify={() => verifyImage('tampered-crop-json', setTampStage, setTampTime)}
            />
          </div>
        </>
      )}

      {/* Audio: Volume */}
      {audioStatus?.ready && (
        <>
          <div className="divider text-lg font-semibold">Audio Volume</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <AudioCard
              label="Verified"
              audioUrl={audioStatus.authenticAudioUrl}
              state={audioAuthState}
              verifyTimeSec={audioAuthTime}
              onVerify={() => verifyAudio('authentic', setAudioAuthState, setAudioAuthTime)}
            />
            <AudioCard
              label="Unverified"
              audioUrl={audioStatus.tamperedAudioUrl}
              state={audioTampState}
              verifyTimeSec={audioTampTime}
              onVerify={() => verifyAudio('tampered', setAudioTampState, setAudioTampTime)}
            />
          </div>
        </>
      )}
    </div>
  );
}

// ─── Image Card ──────────────────────────────────────────────────────────────

function ImageCard({ label, src, stage, verifyTimeMs, onVerify }: {
  label: string;
  src: string;
  stage: VerifyStage;
  verifyTimeMs: number | null;
  onVerify: () => void;
}) {
  const isVerified = stage === 'verified';
  const isFailed = stage === 'ecdsa-failed' || stage === 'zk-failed';
  const isChecking = stage === 'ecdsa-checking' || stage === 'zk-checking';

  return (
    <div className={`card bg-base-200 overflow-hidden transition-all duration-300 ${isVerified ? 'ring-2 ring-success' : ''} ${isFailed ? 'ring-2 ring-error' : ''}`}>
      <div className="card-body p-4">
        <div className="flex justify-between items-center mb-2">
          <h3 className="font-bold">{label}</h3>
          <Badge state={isVerified ? 'verified' : isFailed ? 'failed' : null} />
        </div>

        <div className="relative">
          {isFailed ? (
            <div className="relative">
              <img src={src} alt={label} className="rounded-lg w-full opacity-20" style={{ imageRendering: 'pixelated' }} />
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <XCircle className="w-14 h-14 text-error mb-1" />
                <span className="font-bold text-error">PROVENANCE FAILED</span>
              </div>
            </div>
          ) : (
            <div className={isChecking ? 'opacity-70' : ''}>
              <img src={src} alt={label} className="rounded-lg w-full" style={{ imageRendering: 'pixelated' }} />
            </div>
          )}
        </div>

        {stage !== 'idle' && (
          <div className="mt-3 space-y-1.5 text-sm">
            <Step
              label={`Verification${verifyTimeMs != null ? ` (${(verifyTimeMs / 1000).toFixed(2)}s)` : ''}`}
              status={
                stage === 'ecdsa-checking' || stage === 'ecdsa-failed' ? 'pending' :
                stage === 'zk-checking' ? 'checking' :
                stage === 'verified' ? 'done' : 'failed'
              } />
          </div>
        )}

        {stage === 'idle' && (
          <button className="btn btn-primary btn-sm mt-3 w-full gap-2" onClick={onVerify}>
            <ShieldCheck className="w-4 h-4" /> Verify
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Audio Card ──────────────────────────────────────────────────────────────

function AudioCard({ label, audioUrl, state, verifyTimeSec, onVerify }: {
  label: string;
  audioUrl: string;
  state: AudioVerifyState;
  verifyTimeSec: number | null;
  onVerify: () => void;
}) {
  return (
    <div className={`card bg-base-200 overflow-hidden transition-all duration-300 ${state === 'verified' ? 'ring-2 ring-success' : ''} ${state === 'failed' ? 'ring-2 ring-error' : ''}`}>
      <div className="card-body p-4">
        <div className="flex justify-between items-center mb-2">
          <h3 className="font-bold">{label}</h3>
          <Badge state={state === 'verified' ? 'verified' : state === 'failed' ? 'failed' : null} />
        </div>

        <audio controls className="w-full"><source src={audioUrl} type="audio/wav" /></audio>

        {state === 'idle' && (
          <button className="btn btn-primary btn-sm mt-3 w-full gap-2" onClick={onVerify}>
            <ShieldCheck className="w-4 h-4" /> Verify
          </button>
        )}
        {state === 'checking' && (
          <div className="flex items-center justify-center gap-2 mt-3">
            <Loader2 className="w-4 h-4 animate-spin text-primary" />
            <span className="text-sm">Verifying...</span>
          </div>
        )}
        {state === 'verified' && (
          <div className="alert alert-success mt-3 py-2 text-sm">
            <ShieldCheck className="w-4 h-4" />
            <span>Verified{verifyTimeSec != null ? ` (${verifyTimeSec.toFixed(3)}s)` : ''}</span>
          </div>
        )}
        {state === 'failed' && (
          <div className="alert alert-error mt-3 py-2 text-sm">
            <ShieldX className="w-4 h-4" />
            <span>Verification failed</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Shared ──────────────────────────────────────────────────────────────────

function Badge({ state }: { state: 'verified' | 'failed' | null }) {
  if (state === 'verified') return <div className="badge badge-success gap-1"><ShieldCheck className="w-3 h-3" /> Verified</div>;
  if (state === 'failed') return <div className="badge badge-error gap-1"><ShieldX className="w-3 h-3" /> Failed</div>;
  return null;
}

function Step({ label, status }: { label: string; status: 'pending' | 'checking' | 'done' | 'failed' }) {
  return (
    <div className="flex items-center gap-2">
      {status === 'checking' && <Loader2 className="w-4 h-4 animate-spin text-primary" />}
      {status === 'done' && <ShieldCheck className="w-4 h-4 text-success" />}
      {status === 'failed' && <XCircle className="w-4 h-4 text-error" />}
      {status === 'pending' && <div className="w-4 h-4 rounded-full border border-base-content/20" />}
      <span className={status === 'checking' ? 'text-primary' : status === 'done' ? 'text-success' : status === 'failed' ? 'text-error' : 'text-base-content/40'}>
        {label}{status === 'checking' ? ' ...' : status === 'done' ? ' - valid' : status === 'failed' ? ' - failed' : ''}
      </span>
    </div>
  );
}

function fetchOrSetup(apiBase: string, onReady: (s: any) => void, onError: (e: string) => void) {
  fetch(apiBase).then(r => r.json()).then(s => {
    if (s.ready) { onReady(s); }
    else {
      fetch(`${apiBase}/setup`, { method: 'POST' })
        .then(async r => { if (!r.ok) throw new Error((await r.json()).error); return r.json(); })
        .then(() => fetch(apiBase)).then(r => r.json()).then(onReady)
        .catch(e => onError(e instanceof Error ? e.message : 'Setup failed'));
    }
  }).catch(() => {
    fetch(`${apiBase}/setup`, { method: 'POST' })
      .then(async r => { if (!r.ok) throw new Error((await r.json()).error); return r.json(); })
      .then(() => fetch(apiBase)).then(r => r.json()).then(onReady)
      .catch(e => onError(e instanceof Error ? e.message : 'Setup failed'));
  });
}
