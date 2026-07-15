import { Request, Response } from 'express';
import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import { Job } from '@hyperveritas-web/shared/types';
import { config } from '../config';
import * as jobService from '../services/jobService';

/**
 * POST /api/verify/:jobId
 * For split prover jobs (crop+brakedown): runs the standalone verifier binary.
 * For other jobs: returns the pre-computed verifier time from the monolithic binary.
 */
export async function verifyHandler(req: Request, res: Response) {
  const jobId = String(req.params.jobId);
  const job = jobService.getJob(jobId);

  if (!job) {
    res.status(404).json({ error: 'Job not found' });
    return;
  }

  if (job.status !== 'completed') {
    res.status(400).json({ error: 'Job not yet completed' });
    return;
  }

  // If this job has a proof file (split prover), run the standalone verifier
  if (job.proofFilePath) {
    try {
      const result = await runStandaloneVerifier(job);
      res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.json({
        verified: false,
        verifierTimeSec: 0,
        message: `Verification failed: ${message}`,
      });
    }
    return;
  }

  // Fallback: return pre-computed verifier time (monolithic binary)
  res.json({
    verified: true,
    verifierTimeSec: job.verifierTimeSec,
    message: 'Proof verified successfully. The transformed output is a valid transformation of the original.',
  });
}

/**
 * Run the standalone HyperVerITAS verifier binary on the proof artifacts in the job directory.
 */
function runStandaloneVerifier(job: Job): Promise<{ verified: boolean; verifierTimeSec: number; message: string }> {
  const jobDir = path.join(config.jobsPath, job.jobId);
  const hvPath = config.hyperveritasPath;
  const proofPath = path.join(jobDir, 'proof.bin');

  if (!fs.existsSync(proofPath)) {
    return Promise.resolve({
      verified: false,
      verifierTimeSec: 0,
      message: 'Proof file not found.',
    });
  }

  return new Promise((resolve, reject) => {
    const cmd = `cargo run --release --example hv_crop_brakedown_verify ${job.sizeParam} "${jobDir}"`;
    console.log(`[Verifier] Running: ${cmd}`);

    exec(cmd, {
      cwd: hvPath,
      maxBuffer: 50 * 1024 * 1024,
      timeout: 5 * 60 * 1000,
    }, (error, stdout, stderr) => {
      console.log(`[Verifier] stdout:\n${stdout}`);

      if (error) {
        console.error(`[Verifier] Error: ${error.message}`);
        // Non-zero exit = verification failed (tampered proof causes panic)
        resolve({
          verified: false,
          verifierTimeSec: 0,
          message: 'Proof verification failed. The media may have been tampered with.',
        });
        return;
      }

      const verifiedMatch = stdout.match(/VERIFIED:\s*(true|false)/);
      const timeMatch = stdout.match(/VERIFIER TIME:\s*([\d.]+)\s*seconds/);

      const verified = verifiedMatch ? verifiedMatch[1] === 'true' : false;
      const verifierTimeSec = timeMatch ? parseFloat(timeMatch[1]) : 0;

      resolve({
        verified,
        verifierTimeSec,
        message: verified
          ? 'Proof verified successfully. The transformed output is a valid transformation of the original.'
          : 'Proof verification failed. The media may have been tampered with.',
      });
    });
  });
}
