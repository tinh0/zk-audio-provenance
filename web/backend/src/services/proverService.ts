import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import { config } from '../config';
import { Job, Transformation, PCSType, getProverBinaryName } from '@hyperveritas-web/shared/types';
import * as jobService from './jobService';
import { attestCameraHash } from './cameraService';

interface ProverMetrics {
  proverTimeSec: number;
  verifierTimeSec?: number;
  proofSizeBytes: number;
}

/**
 * Run the HyperVerITAS prover locally via child_process.
 * In production, this would kick off an ECS Fargate task instead.
 *
 * The Rust examples expect input files at specific paths relative to CWD:
 * - Images: images/Timings{size}.json (original), images/Crop{size}.json (transformed)
 * - Audio: various JSON files based on transformation
 */
/**
 * Check if this job should use the split prover (prover-only binary that serializes proof to disk).
 * Currently only crop+brakedown POC is supported.
 */
function useSplitProver(job: Job): boolean {
  return job.mediaType === 'image' && job.transformation === 'crop' && job.pcs === 'brakedown';
}

export async function runProver(job: Job): Promise<void> {
  const hvPath = config.hyperveritasPath;
  const jobDir = path.join(config.jobsPath, job.jobId);

  // Update job status
  jobService.updateJobStatus(job.jobId, 'proving');

  try {
    // Set up the working directory with symlinks/copies of input files
    await setupProverInputs(job, jobDir, hvPath);

    if (useSplitProver(job)) {
      // Use split prover binary - proof artifacts saved to jobDir
      const metrics = await executeSplitProver(job.sizeParam, jobDir, hvPath);

      // Sign the camera hash with ECDSA (simulated attested camera)
      try {
        attestCameraHash(jobDir);
        console.log(`[Camera] Signed camera_hash.json for job ${job.jobId}`);
      } catch (err) {
        console.warn(`[Camera] Failed to attest camera hash: ${err}`);
      }

      jobService.updateJob(job.jobId, {
        status: 'completed',
        proverTimeSec: metrics.proverTimeSec,
        proofSizeBytes: metrics.proofSizeBytes,
        proofFilePath: 'proof.bin',
      });
    } else {
      // Use original monolithic binary (transform handler guarantees pcs is set)
      if (!job.pcs) throw new Error('PCS is required for the HyperVerITAS prover');
      const binaryName = getProverBinaryName(job.transformation, job.pcs);
      const metrics = await executeProver(binaryName, job.sizeParam, hvPath);
      jobService.updateJob(job.jobId, {
        status: 'completed',
        proverTimeSec: metrics.proverTimeSec,
        verifierTimeSec: metrics.verifierTimeSec,
        proofSizeBytes: metrics.proofSizeBytes,
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    jobService.updateJob(job.jobId, {
      status: 'failed',
      errorMessage: message,
    });
  }
}

async function setupProverInputs(job: Job, jobDir: string, hvPath: string): Promise<void> {
  const size = job.sizeParam;

  if (job.mediaType === 'image') {
    const imagesDir = path.join(hvPath, 'images');
    if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });

    // Copy input JSON to the expected location
    if (job.inputJsonPath) {
      const src = path.join(jobDir, 'input.json');
      const dest = path.join(imagesDir, `Timings${size}.json`);
      if (fs.existsSync(src)) fs.copyFileSync(src, dest);
    }

    // Copy transformed JSON to expected location
    if (job.transformedJsonPath) {
      const src = path.join(jobDir, 'transformed.json');
      const transformName = job.transformation === 'crop' ? 'Crop' : 'Gray';
      const dest = path.join(imagesDir, `${transformName}${size}.json`);
      if (fs.existsSync(src)) fs.copyFileSync(src, dest);
    }
  } else {
    // Audio files go in the hyperveritas_impl root or audio/ directory
    const audioDir = path.join(hvPath);
    if (job.inputJsonPath) {
      const src = path.join(jobDir, 'input.json');
      const audioName = getAudioInputFileName(job.transformation, size);
      const dest = path.join(audioDir, audioName);
      if (fs.existsSync(src)) fs.copyFileSync(src, dest);
    }
    if (job.transformedJsonPath) {
      const src = path.join(jobDir, 'transformed.json');
      const audioName = getAudioOutputFileName(job.transformation, size);
      const dest = path.join(audioDir, audioName);
      if (fs.existsSync(src)) fs.copyFileSync(src, dest);
    }
  }
}

function getAudioInputFileName(transformation: string, size: number): string {
  switch (transformation) {
    case 'mono': return `StereoAudio${size}.json`;
    case 'volume': return `Audio${size}.json`;
    case 'trim': return `Audio${size}.json`;
    default: return `Audio${size}.json`;
  }
}

function getAudioOutputFileName(transformation: string, size: number): string {
  switch (transformation) {
    case 'mono': return `Mono${size}.json`;
    case 'volume': return `Volume${size}.json`;
    case 'trim': return `Trim${size}.json`;
    default: return `${transformation}${size}.json`;
  }
}

/**
 * Execute the split prover binary (prover-only, writes proof artifacts to outputDir).
 */
function executeSplitProver(sizeParam: number, outputDir: string, cwd: string): Promise<ProverMetrics> {
  return new Promise((resolve, reject) => {
    const cmd = `cargo run --release --example hv_crop_brakedown_prove ${sizeParam} "${outputDir}"`;
    console.log(`[SplitProver] Running: ${cmd}`);
    console.log(`[SplitProver] CWD: ${cwd}`);

    const child = exec(cmd, {
      cwd,
      maxBuffer: 50 * 1024 * 1024,
      timeout: 10 * 60 * 1000,
    }, (error, stdout, stderr) => {
      if (error) {
        console.error(`[SplitProver] Error: ${error.message}`);
        console.error(`[SplitProver] stderr: ${stderr}`);
        reject(new Error(`Split prover failed: ${error.message}\n${stderr}`));
        return;
      }

      console.log(`[SplitProver] stdout:\n${stdout}`);

      try {
        const proverMatch = stdout.match(/PROVER TIME:\s*([\d.]+)\s*seconds/);
        const proofSizeMatch = stdout.match(/PROOF SIZE:\s*(\d+)\s*bytes/);

        if (!proverMatch || !proofSizeMatch) {
          throw new Error('Could not parse split prover output');
        }

        resolve({
          proverTimeSec: parseFloat(proverMatch[1]),
          proofSizeBytes: parseInt(proofSizeMatch[1], 10),
        });
      } catch (parseErr) {
        reject(new Error(`Failed to parse split prover output: ${parseErr}`));
      }
    });
  });
}

function executeProver(binaryName: string, sizeParam: number, cwd: string): Promise<ProverMetrics> {
  return new Promise((resolve, reject) => {
    const cmd = `cargo run --release --example ${binaryName} ${sizeParam}`;
    console.log(`[Prover] Running: ${cmd}`);
    console.log(`[Prover] CWD: ${cwd}`);

    const child = exec(cmd, {
      cwd,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer
      timeout: 10 * 60 * 1000, // 10 minute timeout
    }, (error, stdout, stderr) => {
      if (error) {
        console.error(`[Prover] Error: ${error.message}`);
        console.error(`[Prover] stderr: ${stderr}`);
        reject(new Error(`Prover failed: ${error.message}\n${stderr}`));
        return;
      }

      console.log(`[Prover] stdout:\n${stdout}`);

      try {
        const metrics = parseProverOutput(stdout);
        resolve(metrics);
      } catch (parseErr) {
        reject(new Error(`Failed to parse prover output: ${parseErr}`));
      }
    });
  });
}

/**
 * Parse the stdout from a HyperVerITAS example binary.
 * Expected format:
 *   PROVER TIME: X.XXX seconds
 *   PROOF SIZE: XXXXX bytes
 *   VERIFIER TIME: X.XXX seconds
 */
function parseProverOutput(stdout: string): ProverMetrics {
  const proverMatch = stdout.match(/PROVER TIME:\s*([\d.]+)\s*seconds/);
  const proofSizeMatch = stdout.match(/PROOF SIZE:\s*(\d+)\s*bytes/);
  const verifierMatch = stdout.match(/VERIFIER TIME:\s*([\d.]+)\s*seconds/);

  if (!proverMatch || !proofSizeMatch || !verifierMatch) {
    throw new Error(
      `Could not parse metrics from output. ` +
      `Prover: ${!!proverMatch}, ProofSize: ${!!proofSizeMatch}, Verifier: ${!!verifierMatch}`
    );
  }

  return {
    proverTimeSec: parseFloat(proverMatch[1]),
    proofSizeBytes: parseInt(proofSizeMatch[1], 10),
    verifierTimeSec: parseFloat(verifierMatch[1]),
  };
}
