import { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import { config } from '../config';
import * as jobService from '../services/jobService';

/**
 * GET /api/result/:jobId
 * Get job results and file download URLs.
 */
export function resultHandler(req: Request, res: Response) {
  const jobId = String(req.params.jobId);
  const job = jobService.getJob(jobId);

  if (!job) {
    res.status(404).json({ error: 'Job not found' });
    return;
  }

  res.json({
    job,
    originalFileUrl: `/api/files/${jobId}/original`,
    transformedFileUrl: `/api/files/${jobId}/output`,
  });
}

/**
 * GET /api/files/:jobId/:filename
 * Serve a file from the job directory.
 */
export function fileHandler(req: Request, res: Response) {
  const jobId = String(req.params.jobId);
  const filename = String(req.params.filename);
  const job = jobService.getJob(jobId);

  if (!job) {
    res.status(404).json({ error: 'Job not found' });
    return;
  }

  const jobDir = path.join(config.jobsPath, jobId);

  // Map logical names to actual files
  let actualFile: string;
  if (filename === 'original') {
    // Find the original file (could be .png, .jpg, .jpeg, .wav)
    const jobFiles = fs.readdirSync(jobDir);
    const origFile = jobFiles.find(f => f.startsWith('original'));
    actualFile = origFile || (job.mediaType === 'image' ? 'original.png' : 'original.wav');
  } else if (filename === 'output') {
    actualFile = job.outputFilePath || (job.mediaType === 'image' ? 'output.png' : 'output.wav');
  } else if (filename === 'proof') {
    actualFile = 'proof.bin';
  } else if (filename === 'public-inputs') {
    actualFile = 'public_inputs.json';
  } else if (filename === 'original-image-json') {
    // The HV image JSON used for proving (e.g., Timings14.json)
    const jobFiles = fs.readdirSync(jobDir);
    const jsonFile = jobFiles.find(f => f.startsWith('Timings') && f.endsWith('.json'));
    actualFile = jsonFile || 'original_image.json';
  } else if (filename === 'crop-image-json') {
    // The HV crop image JSON used for proving (e.g., Crop14.json)
    const jobFiles = fs.readdirSync(jobDir);
    const jsonFile = jobFiles.find(f => f.startsWith('Crop') && f.endsWith('.json'));
    actualFile = jsonFile || 'crop_image.json';
  } else if (filename === 'camera-hash') {
    actualFile = 'camera_hash.json';
  } else if (filename === 'camera-attestation') {
    actualFile = 'camera_attestation.json';
  } else {
    res.status(400).json({ error: 'Invalid filename' });
    return;
  }

  const filePath = path.join(jobDir, actualFile);

  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'File not found' });
    return;
  }

  res.sendFile(filePath);
}
