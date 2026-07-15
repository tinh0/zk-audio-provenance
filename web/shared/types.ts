// ============================================================
// Shared types for HyperVerITAS-Web
// ============================================================

// --- Transformation Types ---

export type ImageTransformation = 'crop' | 'grayscale';
export type AudioTransformation = 'mono' | 'volume' | 'trim';
// Float32 audio transformations (Go/gnark via zk-Location)
export type Float32AudioTransformation = 'gain' | 'fade_in' | 'fade_out' | 'combine' | 'pan' | 'tremolo';
export type Transformation = ImageTransformation | AudioTransformation | Float32AudioTransformation;
export type MediaType = 'image' | 'audio';

// Proving engine: Rust (HyperVerITAS) or Go (zk-Location/gnark)
export type ProverEngine = 'hyperveritas' | 'gnark';

// Polynomial Commitment Schemes available in the Rust implementation
export type PCSType = 'pst' | 'brakedown' | 'basefold';
// Backends available in the Go implementation
export type GnarkBackend = 'groth16' | 'plonk';

// --- Job Types ---

export type JobStatus = 'pending' | 'converting' | 'proving' | 'completed' | 'failed';

export interface Job {
  jobId: string;
  status: JobStatus;
  mediaType: MediaType;
  transformation: Transformation;
  proverEngine: ProverEngine;
  pcs?: PCSType;             // for hyperveritas (Rust)
  gnarkBackend?: GnarkBackend; // for gnark (Go)
  sizeParam: number; // log2 of total pixels or samples
  originalFileName: string;
  transformParams: TransformParams;
  // Metrics (populated after proving)
  proverTimeSec?: number;
  verifierTimeSec?: number;
  proofSizeBytes?: number;
  peakMemoryKb?: number;
  nbConstraints?: number;    // gnark-specific
  // File paths (local storage keys or S3 keys)
  inputJsonPath?: string;
  transformedJsonPath?: string;
  outputFilePath?: string;
  proofFilePath?: string;       // path to proof.bin artifact (for split prover/verifier)
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

// --- Transformation Parameters ---

export interface CropParams {
  startX: number;
  startY: number;
  endX: number;
  endY: number;
}

export interface VolumeParams {
  factor: number; // multiplier, e.g. 0.5 for half volume
}

export interface TrimParams {
  startSample: number;
  endSample: number;
}

export interface GainParams {
  factor: number; // float32 gain multiplier, e.g. 0.75
}

export interface CombineParams {
  alpha: number; // blend factor 0.0-1.0 (1.0 = 100% input1, 0.0 = 100% input2)
}

export interface PanParams {
  pan: number; // -1.0 (full left) to 1.0 (full right)
}

export interface TremoloParams {
  rateHz: number; // LFO frequency in Hz
  depth: number;  // modulation depth 0.0-1.0
}

export type TransformParams =
  | CropParams | VolumeParams | TrimParams
  | GainParams | CombineParams | PanParams | TremoloParams
  | Record<string, never>;

// --- HyperVerITAS Data Formats ---
// These match the Rust structs in hyperveritas_impl/src/image.rs and audio.rs

export interface HVImageJson {
  rows: number;
  cols: number;
  R: number[]; // u8 values [0, 255]
  G: number[];
  B: number[];
}

export interface HVAudioJson {
  sample_rate: number;
  bit_depth: 8 | 16 | 24 | 32;
  num_channels: 1 | 2;
  num_samples: number;
  left: number[];       // i32 values (8/16/24-bit) or float32 values (32-bit)
  right?: number[];     // present if stereo
}

// --- API Request/Response Types ---

export interface UploadResponse {
  fileId: string;
  fileName: string;
}

export interface TransformRequest {
  fileId: string;
  mediaType: MediaType;
  transformation: Transformation;
  proverEngine: ProverEngine;
  pcs?: PCSType;
  gnarkBackend?: GnarkBackend;
  params: TransformParams;
}

export interface TransformResponse {
  jobId: string;
}

export interface StatusResponse {
  job: Job;
}

export interface ResultResponse {
  job: Job;
  originalFileUrl: string;
  transformedFileUrl: string;
}

// --- Constants ---

export const IMAGE_TRANSFORMATIONS: ImageTransformation[] = ['crop', 'grayscale'];
export const AUDIO_TRANSFORMATIONS: AudioTransformation[] = ['mono', 'volume', 'trim'];
export const FLOAT32_AUDIO_TRANSFORMATIONS: Float32AudioTransformation[] = [
  'gain', 'fade_in', 'fade_out', 'combine', 'pan', 'tremolo',
];

export const PCS_OPTIONS: { value: PCSType; label: string; description: string }[] = [
  { value: 'brakedown', label: 'Brakedown', description: 'No trusted setup, fast for small sizes' },
  { value: 'basefold', label: 'Basefold', description: 'FRI-based, good balance of speed and proof size' },
  { value: 'pst', label: 'PST (KZG)', description: 'Smallest proofs, requires trusted setup' },
];

export const GNARK_BACKEND_OPTIONS: { value: GnarkBackend; label: string; description: string }[] = [
  { value: 'groth16', label: 'Groth16', description: 'Smaller proofs, higher prover time' },
  { value: 'plonk', label: 'PLONK', description: 'Lower peak memory' },
];

// Maps transformation + pcs to the Rust binary name (HyperVerITAS)
export function getProverBinaryName(transformation: Transformation, pcs: PCSType): string {
  const transformMap: Record<string, string> = {
    crop: 'crop',
    grayscale: 'gray',
    mono: 'mono',
    volume: 'volume',
    trim: 'trim',
  };
  return `hv_${transformMap[transformation]}_${pcs}`;
}

// Maps float32 transformation to the Go directory name (zk-Location)
export function getGnarkTransformDir(transformation: Float32AudioTransformation): string {
  const dirMap: Record<Float32AudioTransformation, string> = {
    gain: 'gain_batch',
    fade_in: 'fade_in',
    fade_out: 'fade_out',
    combine: 'combine',
    pan: 'pan',
    tremolo: 'tremolo',
  };
  return dirMap[transformation];
}

// Which float32 transformations require stereo input
export function requiresStereoInput(transformation: Float32AudioTransformation): boolean {
  return transformation === 'pan' || transformation === 'combine';
}
