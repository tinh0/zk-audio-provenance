import { useState, useCallback } from 'react';
import { FileUpload } from '../components/demo/FileUpload';
import { TransformationSelector } from '../components/demo/TransformationSelector';
import { ProofStatus } from '../components/demo/ProofStatus';
import { ResultsDisplay } from '../components/demo/ResultsDisplay';
import { uploadFile, startTransform, getJobStatus } from '../services/api';
import type { MediaType, Transformation, PCSType, GnarkBackend, ProverEngine, TransformParams, Job } from '../types';

type DemoState = 'idle' | 'uploaded' | 'configuring' | 'submitting' | 'proving' | 'completed';

export function DemoPage() {
  const [state, setState] = useState<DemoState>('idle');
  const [mediaType, setMediaType] = useState<MediaType | null>(null);
  const [isFloat32, setIsFloat32] = useState(false);
  const [isStereo, setIsStereo] = useState(false);
  const [fileId, setFileId] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [completedJob, setCompletedJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileInfo, setFileInfo] = useState<{ name: string; totalElements: number; sizeParam: number } | null>(null);

  const handleFileSelected = useCallback(async (file: File, type: MediaType) => {
    setMediaType(type);
    setError(null);
    setState('submitting');

    // Detect format info from file header
    if (type === 'audio') {
      try {
        const header = await readWavHeader(file);
        setIsFloat32(header.isFloat32);
        setIsStereo(header.isStereo);
        const sizeParam = Math.floor(Math.log2(header.totalSamples));
        setFileInfo({ name: file.name, totalElements: 1 << sizeParam, sizeParam });
      } catch {
        setIsFloat32(false);
        setIsStereo(false);
        setFileInfo(null);
      }
    } else {
      setIsFloat32(false);
      setIsStereo(false);
      try {
        const dims = await readImageDimensions(file);
        const totalPixels = dims.width * dims.height;
        const sizeParam = Math.floor(Math.log2(totalPixels));
        setFileInfo({ name: file.name, totalElements: 1 << sizeParam, sizeParam });
      } catch {
        setFileInfo(null);
      }
    }

    try {
      const result = await uploadFile(file);
      setFileId(result.fileId);
      setState('configuring');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
      setState('idle');
    }
  }, []);

  const handleTransformSubmit = useCallback(async (
    transformation: Transformation,
    engine: ProverEngine,
    pcs?: PCSType,
    gnarkBackend?: GnarkBackend,
    params?: TransformParams,
  ) => {
    if (!fileId || !mediaType) return;
    setError(null);
    setState('submitting');

    try {
      const result = await startTransform({
        fileId,
        mediaType,
        transformation,
        proverEngine: engine,
        pcs,
        gnarkBackend,
        params: params || {},
      });
      setJobId(result.jobId);
      setState('proving');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start transform');
      setState('configuring');
    }
  }, [fileId, mediaType]);

  const handleProofComplete = useCallback(async () => {
    if (!jobId) return;
    try {
      const result = await getJobStatus(jobId);
      setCompletedJob(result.job);
      setState('completed');
    } catch {
      // Status hook will handle errors
    }
  }, [jobId]);

  const handleReset = () => {
    setState('idle');
    setMediaType(null);
    setIsFloat32(false);
    setIsStereo(false);
    setFileId(null);
    setFileInfo(null);
    setJobId(null);
    setCompletedJob(null);
    setError(null);
  };

  return (
    <div className="max-w-3xl mx-auto py-8 px-4">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold mb-2">Interactive Demo</h1>
        <p className="text-base-content/70">
          Upload a file, choose a transformation, and watch HyperVerITAS generate a zero-knowledge proof.
        </p>
      </div>

      {error && (
        <div className="alert alert-error mb-4">
          <span>{error}</span>
          <button className="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {/* Step 1: Upload */}
      <div className="collapse collapse-open bg-base-100 border border-base-300 mb-4">
        <div className="collapse-title font-semibold flex items-center gap-2">
          <span className={`badge ${state !== 'idle' ? 'badge-primary' : 'badge-outline'} badge-sm`}>1</span>
          Upload File
        </div>
        <div className="collapse-content">
          <FileUpload
            onFileSelected={handleFileSelected}
            disabled={state !== 'idle'}
          />
          {fileInfo && (
            <div className="mt-3 text-sm text-base-content/70">
              <span className="font-medium">{fileInfo.name}</span>
              {' - '}
              {fileInfo.totalElements.toLocaleString()} {mediaType === 'image' ? 'pixels' : 'samples'}
              {' (2'}
              <sup>{fileInfo.sizeParam}</sup>
              {')'}
            </div>
          )}
        </div>
      </div>

      {/* Step 2: Configure */}
      {(state === 'configuring' || state === 'submitting' || state === 'proving' || state === 'completed') && mediaType && (
        <div className="collapse collapse-open bg-base-100 border border-base-300 mb-4">
          <div className="collapse-title font-semibold flex items-center gap-2">
            <span className={`badge ${state !== 'configuring' ? 'badge-primary' : 'badge-outline'} badge-sm`}>2</span>
            Configure Transformation
          </div>
          <div className="collapse-content">
            <TransformationSelector
              mediaType={mediaType}
              isFloat32={isFloat32}
              isStereo={isStereo}
              onSubmit={handleTransformSubmit}
              disabled={state !== 'configuring'}
            />
          </div>
        </div>
      )}

      {/* Step 3: Proving */}
      {(state === 'proving' || state === 'completed') && jobId && (
        <div className="collapse collapse-open bg-base-100 border border-base-300 mb-4">
          <div className="collapse-title font-semibold flex items-center gap-2">
            <span className={`badge ${state === 'completed' ? 'badge-primary' : 'badge-outline'} badge-sm`}>3</span>
            Proof Generation
          </div>
          <div className="collapse-content">
            {state === 'proving' && (
              <ProofStatus jobId={jobId} onComplete={handleProofComplete} />
            )}
          </div>
        </div>
      )}

      {/* Step 4: Results */}
      {state === 'completed' && completedJob && (
        <div className="collapse collapse-open bg-base-100 border border-base-300 mb-4">
          <div className="collapse-title font-semibold flex items-center gap-2">
            <span className="badge badge-primary badge-sm">4</span>
            Results
          </div>
          <div className="collapse-content">
            <ResultsDisplay job={completedJob} />
          </div>
        </div>
      )}

      {/* Reset button */}
      {state !== 'idle' && (
        <div className="text-center mt-6">
          <button className="btn btn-outline" onClick={handleReset}>
            Start Over
          </button>
        </div>
      )}
    </div>
  );
}

/** Read WAV header from a File to detect format, channels, and total samples */
async function readWavHeader(file: File): Promise<{ isFloat32: boolean; isStereo: boolean; totalSamples: number }> {
  // Read enough bytes to find chunks (most headers are under 1KB)
  const buffer = await file.slice(0, Math.min(file.size, 4096)).arrayBuffer();
  const view = new DataView(buffer);

  const riff = String.fromCharCode(view.getUint8(0), view.getUint8(1), view.getUint8(2), view.getUint8(3));
  if (riff !== 'RIFF') throw new Error('Not a WAV file');

  // Scan for fmt and data chunks
  let audioFormat = 1;
  let numChannels = 1;
  let bitsPerSample = 16;
  let dataSize = 0;
  let offset = 12;

  while (offset < view.byteLength - 8) {
    const chunkId = String.fromCharCode(
      view.getUint8(offset), view.getUint8(offset + 1),
      view.getUint8(offset + 2), view.getUint8(offset + 3),
    );
    const chunkSize = view.getUint32(offset + 4, true);

    if (chunkId === 'fmt ') {
      audioFormat = view.getUint16(offset + 8, true);
      numChannels = view.getUint16(offset + 10, true);
      bitsPerSample = view.getUint16(offset + 22, true);
    } else if (chunkId === 'data') {
      dataSize = chunkSize;
      break;
    }

    offset += 8 + chunkSize;
    if (chunkSize % 2 !== 0) offset++; // align to even boundary
  }

  const bytesPerSample = bitsPerSample / 8;
  const totalSamples = Math.floor(dataSize / (bytesPerSample * numChannels));

  return {
    isFloat32: audioFormat === 3,
    isStereo: numChannels === 2,
    totalSamples,
  };
}

/** Read image dimensions by loading it into an HTMLImageElement */
function readImageDimensions(file: File): Promise<{ width: number; height: number }> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve({ width: img.naturalWidth, height: img.naturalHeight });
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Failed to read image'));
    };
    img.src = url;
  });
}
