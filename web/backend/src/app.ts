import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { config } from './config';
import { corsMiddleware } from './middleware/cors';
import { errorHandler } from './middleware/errorHandler';
import { healthHandler } from './handlers/health';
import { uploadHandler } from './handlers/upload';
import { transformHandler } from './handlers/transform';
import { statusHandler } from './handlers/status';
import { resultHandler, fileHandler } from './handlers/result';
import { verifyHandler } from './handlers/verify';
import {
  integrityDemoSetupHandler,
  integrityDemoStatusHandler,
  integrityDemoVerifyHandler,
  integrityDemoFileHandler,
} from './handlers/integrityDemo';
import {
  audioIntegrityDemoSetupHandler,
  audioIntegrityDemoStatusHandler,
  audioIntegrityDemoVerifyHandler,
  audioIntegrityDemoFileHandler,
} from './handlers/audioIntegrityDemo';

// Ensure storage directories exist
fs.mkdirSync(config.uploadsPath, { recursive: true });
fs.mkdirSync(config.jobsPath, { recursive: true });

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxFileSize },
});

// Middleware
app.use(corsMiddleware);
app.use(express.json());

// Demo article pages (the extension calls the API on the page's origin,
// so articles must be served from the backend, not file://)
app.use('/demo', express.static(path.join(__dirname, '../../demo/articles')));

// Routes
app.get('/api/health', healthHandler);
app.post('/api/upload', upload.single('file'), uploadHandler);
app.post('/api/transform', transformHandler);
app.get('/api/status/:jobId', statusHandler);
app.get('/api/result/:jobId', resultHandler);
app.get('/api/files/:jobId/:filename', fileHandler);
app.post('/api/verify/:jobId', verifyHandler);

// Integrity demo routes
app.post('/api/integrity-demo/setup', integrityDemoSetupHandler);
app.get('/api/integrity-demo', integrityDemoStatusHandler);
app.post('/api/integrity-demo/verify/:which', integrityDemoVerifyHandler);
app.get('/api/integrity-demo/files/:which', integrityDemoFileHandler);

// Audio integrity demo routes
app.post('/api/audio-integrity-demo/setup', audioIntegrityDemoSetupHandler);
app.get('/api/audio-integrity-demo', audioIntegrityDemoStatusHandler);
app.post('/api/audio-integrity-demo/verify/:which', audioIntegrityDemoVerifyHandler);
app.get('/api/audio-integrity-demo/files/:which', audioIntegrityDemoFileHandler);

// Error handling
app.use(errorHandler);

// Start server (local dev only, not used when deployed to Lambda)
if (config.env !== 'production') {
  app.listen(config.port, () => {
    console.log(`HyperVerITAS-Web API running at http://localhost:${config.port}`);
    console.log(`HyperVerITAS impl path: ${config.hyperveritasPath}`);
  });
}

export default app;
