import path from 'path';

export const config = {
  port: parseInt(process.env.PORT || '3006', 10),
  env: process.env.NODE_ENV || 'development',

  // Local storage paths (used in dev, replaced by S3 in prod)
  storagePath: path.resolve(__dirname, '../../storage'),
  uploadsPath: path.resolve(__dirname, '../../storage/uploads'),
  jobsPath: path.resolve(__dirname, '../../storage/jobs'),

  // Path to the HyperVerITAS Rust implementation (repo root is 4 levels up
  // from backend/src/config; web/ and hyperveritas-audio/ are siblings)
  hyperveritasPath: process.env.HYPERVERITAS_PATH ||
    path.resolve(__dirname, '../../../../hyperveritas-audio/hyperveritas_impl'),

  // Max upload size
  maxFileSize: 10 * 1024 * 1024, // 10MB
};
