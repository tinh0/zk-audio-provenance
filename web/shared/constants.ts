// Max file sizes for web demo uploads
export const MAX_IMAGE_FILE_SIZE = 10 * 1024 * 1024; // 10MB
export const MAX_AUDIO_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Demo size constraints (log2)
export const MIN_SIZE_PARAM = 10; // 2^10 = 1024 pixels/samples
export const MAX_SIZE_PARAM = 14; // 2^14 = 16384 pixels/samples

// Max image dimensions for demo (must be power of 2)
export const MAX_IMAGE_DIM = 128; // 128x128 = 16384 pixels = size 14

// Accepted file types
export const ACCEPTED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/jpg'];
export const ACCEPTED_AUDIO_TYPES = ['audio/wav', 'audio/wave', 'audio/x-wav'];

// Path to HyperVerITAS Rust implementation (relative to project root)
export const HYPERVERITAS_IMPL_PATH = '../../hyperveritas-audio/hyperveritas_impl';

// Polling interval for job status (ms)
export const STATUS_POLL_INTERVAL = 2000;
