import { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import { config } from '../config';
import {
  TransformRequest,
  Job,
  CropParams,
  VolumeParams,
  TrimParams,
  FLOAT32_AUDIO_TRANSFORMATIONS,
  Float32AudioTransformation,
  requiresStereoInput,
} from '@hyperveritas-web/shared/types';
import { imageToHVJson, hvJsonToImage, getImageSizeParam } from '../services/imageConverter';
import { wavToHVJson, hvJsonToWav, getAudioSizeParam } from '../services/audioConverter';
import {
  applyCrop,
  applyGrayscale,
  applyMono,
  applyVolume,
  applyTrim,
} from '../services/transformService';
import * as jobService from '../services/jobService';
import { runProver } from '../services/proverService';
import { runGnarkProver } from '../services/gnarkProverService';

/**
 * POST /api/transform
 * Start a transformation + proving job.
 */
export async function transformHandler(req: Request, res: Response) {
  try {
    const body = req.body as TransformRequest;
    const { fileId, mediaType, transformation, proverEngine, pcs, gnarkBackend, params } = body;

    if (!fileId || !mediaType || !transformation || !proverEngine) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    // Validate engine-specific fields
    if (proverEngine === 'hyperveritas' && !pcs) {
      res.status(400).json({ error: 'PCS is required for HyperVerITAS engine' });
      return;
    }

    const isFloat32Transform = FLOAT32_AUDIO_TRANSFORMATIONS.includes(
      transformation as Float32AudioTransformation
    );

    // Find the uploaded file
    const uploadDir = path.join(config.uploadsPath, fileId);
    const files = fs.readdirSync(uploadDir);
    const originalFile = files.find(f => f.startsWith('original'));
    if (!originalFile) {
      res.status(404).json({ error: 'Uploaded file not found' });
      return;
    }

    const filePath = path.join(uploadDir, originalFile);
    const fileBuffer = fs.readFileSync(filePath);

    // Create job
    const jobId = uuidv4();
    const jobDir = path.join(config.jobsPath, jobId);
    fs.mkdirSync(jobDir, { recursive: true });

    const job: Job = {
      jobId,
      status: 'converting',
      mediaType,
      transformation,
      proverEngine,
      pcs: pcs || undefined,
      gnarkBackend: gnarkBackend || 'groth16',
      sizeParam: 0,
      originalFileName: originalFile,
      transformParams: params,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    jobService.createJob(job);

    if (mediaType === 'image') {
      // --- IMAGE TRANSFORMATIONS (HyperVerITAS/Rust) ---
      const inputJson = await imageToHVJson(fileBuffer);
      const sizeParam = getImageSizeParam(inputJson);

      let transformedJson;
      if (transformation === 'crop') {
        transformedJson = applyCrop(inputJson, params as CropParams);
      } else {
        transformedJson = applyGrayscale(inputJson);
      }

      fs.writeFileSync(path.join(jobDir, 'input.json'), JSON.stringify(inputJson));
      fs.writeFileSync(path.join(jobDir, 'transformed.json'), JSON.stringify(transformedJson));

      // Generate output preview from original file at full resolution
      let outputBuffer: Buffer;
      if (transformation === 'grayscale') {
        outputBuffer = await sharp(fileBuffer).grayscale().png().toBuffer();
      } else {
        const meta = await sharp(fileBuffer).metadata();
        const origW = meta.width!;
        const origH = meta.height!;
        const cropW = origH >= origW ? origW : Math.floor(origW / 2);
        const cropH = origH >= origW ? Math.floor(origH / 2) : origH;
        outputBuffer = await sharp(fileBuffer)
          .extract({ left: 0, top: 0, width: cropW, height: cropH })
          .png()
          .toBuffer();
      }
      fs.writeFileSync(path.join(jobDir, 'output.png'), outputBuffer);

      const origExt = path.extname(originalFile) || '.png';
      fs.copyFileSync(filePath, path.join(jobDir, `original${origExt}`));

      jobService.updateJob(jobId, {
        sizeParam,
        inputJsonPath: 'input.json',
        transformedJsonPath: 'transformed.json',
        outputFilePath: 'output.png',
      });

      // Run Rust prover
      runProver(jobService.getJob(jobId)!).catch(err => {
        console.error(`Prover failed for job ${jobId}:`, err);
      });

    } else if (isFloat32Transform) {
      // --- FLOAT32 AUDIO TRANSFORMATIONS (zk-Location/gnark/Go) ---
      const inputJson = wavToHVJson(fileBuffer);
      const sizeParam = getAudioSizeParam(inputJson);

      // Validate: float32 transforms require 32-bit float WAV
      if (inputJson.bit_depth !== 32) {
        jobService.updateJob(jobId, {
          status: 'failed',
          errorMessage: `Float32 transformations require a 32-bit float WAV file. Got ${inputJson.bit_depth}-bit.`,
        });
        res.json({ jobId });
        return;
      }

      // Validate stereo requirement
      const f32Transform = transformation as Float32AudioTransformation;
      if (requiresStereoInput(f32Transform) && inputJson.num_channels !== 2) {
        jobService.updateJob(jobId, {
          status: 'failed',
          errorMessage: `${transformation} requires stereo (2-channel) input. Got ${inputJson.num_channels} channel(s).`,
        });
        res.json({ jobId });
        return;
      }

      // Save input JSON for the Go prover
      fs.writeFileSync(path.join(jobDir, 'input.json'), JSON.stringify(inputJson));

      // Save original WAV for preview
      fs.copyFileSync(filePath, path.join(jobDir, 'original.wav'));

      // For float32 transforms, we don't generate a transformed preview WAV
      // (the Go prover handles the math in ZK circuits, not in JS)
      // Just copy the original as a placeholder
      fs.copyFileSync(filePath, path.join(jobDir, 'output.wav'));

      jobService.updateJob(jobId, {
        sizeParam,
        inputJsonPath: 'input.json',
        outputFilePath: 'output.wav',
      });

      // Run Go/gnark prover
      runGnarkProver(jobService.getJob(jobId)!).catch(err => {
        console.error(`Gnark prover failed for job ${jobId}:`, err);
      });

    } else {
      // --- INTEGER AUDIO TRANSFORMATIONS (HyperVerITAS/Rust) ---
      const inputJson = wavToHVJson(fileBuffer);
      const sizeParam = getAudioSizeParam(inputJson);

      // Validate: integer transforms require PCM (8/16/24-bit)
      if (inputJson.bit_depth === 32) {
        jobService.updateJob(jobId, {
          status: 'failed',
          errorMessage: `Integer audio transformations (mono/volume/trim) require PCM WAV (8/16/24-bit). Got 32-bit float. Use the Float32 engine for float audio.`,
        });
        res.json({ jobId });
        return;
      }

      let transformedJson;
      if (transformation === 'mono') {
        transformedJson = applyMono(inputJson);
      } else if (transformation === 'volume') {
        transformedJson = applyVolume(inputJson, params as VolumeParams);
      } else {
        transformedJson = applyTrim(inputJson, params as TrimParams);
      }

      fs.writeFileSync(path.join(jobDir, 'input.json'), JSON.stringify(inputJson));
      fs.writeFileSync(path.join(jobDir, 'transformed.json'), JSON.stringify(transformedJson));

      const outputBuffer = hvJsonToWav(transformedJson);
      fs.writeFileSync(path.join(jobDir, 'output.wav'), outputBuffer);
      fs.copyFileSync(filePath, path.join(jobDir, 'original.wav'));

      jobService.updateJob(jobId, {
        sizeParam,
        inputJsonPath: 'input.json',
        transformedJsonPath: 'transformed.json',
        outputFilePath: 'output.wav',
      });

      // Run Rust prover
      runProver(jobService.getJob(jobId)!).catch(err => {
        console.error(`Prover failed for job ${jobId}:`, err);
      });
    }

    res.json({ jobId });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    res.status(500).json({ error: message });
  }
}
