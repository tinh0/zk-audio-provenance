import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import { config } from '../config';
import {
  Job,
  Float32AudioTransformation,
  GnarkBackend,
  getGnarkTransformDir,
} from '@hyperveritas-web/shared/types';
import * as jobService from './jobService';

interface GnarkMetrics {
  proverTimeSec: number;
  verifierTimeSec: number;
  nbConstraints: number;
}

/**
 * Run a zk-Location (gnark) float32 audio prover locally via `go run`.
 * In production, this would run on ECS.
 *
 * The Go programs read audio JSON files from the hyperveritas_impl directory
 * and output CSV results to an output/ directory.
 */
export async function runGnarkProver(job: Job): Promise<void> {
  const transformation = job.transformation as Float32AudioTransformation;
  const backend = job.gnarkBackend || 'groth16';
  const transformDir = getGnarkTransformDir(transformation);
  const zkLocationPath = path.resolve(config.hyperveritasPath, '../../zk-location-float');
  const audioDir = transformDir;
  const cwd = path.join(zkLocationPath, 'audio', audioDir);

  jobService.updateJobStatus(job.jobId, 'proving');

  try {
    // Copy input JSON files to where the Go program expects them
    await setupGnarkInputs(job, zkLocationPath);

    const metrics = await executeGnarkProver(
      cwd,
      backend,
      job.sizeParam,
      job,
    );

    jobService.updateJob(job.jobId, {
      status: 'completed',
      proverTimeSec: metrics.proverTimeSec,
      verifierTimeSec: metrics.verifierTimeSec,
      nbConstraints: metrics.nbConstraints,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    jobService.updateJob(job.jobId, {
      status: 'failed',
      errorMessage: message,
    });
  }
}

async function setupGnarkInputs(job: Job, zkLocationPath: string): Promise<void> {
  const size = job.sizeParam;
  const jobDir = path.join(config.jobsPath, job.jobId);
  const hvImplPath = config.hyperveritasPath;

  // The Go programs look for Audio{size}.json or StereoAudio{size}.json
  // in the hyperveritas_impl directory (one level up from zk-Location/audio/*)
  const inputSrc = path.join(jobDir, 'input.json');

  if (fs.existsSync(inputSrc)) {
    const inputJson = JSON.parse(fs.readFileSync(inputSrc, 'utf-8'));
    const isStereo = inputJson.num_channels === 2;

    if (isStereo) {
      const dest = path.join(hvImplPath, `StereoAudio${size}.json`);
      fs.copyFileSync(inputSrc, dest);
    }
    // Always write the mono/general version too
    const dest = path.join(hvImplPath, `Audio${size}.json`);
    fs.copyFileSync(inputSrc, dest);
  }
}

function buildGnarkCommand(
  backend: GnarkBackend,
  sizeParam: number,
  job: Job,
): string {
  const args: string[] = [];

  if (backend === 'plonk') {
    args.push('--plonk');
  }

  args.push(String(sizeParam));

  // Add transformation-specific parameters
  const params = job.transformParams;
  const transformation = job.transformation as Float32AudioTransformation;

  // Number of samples (use all by default)
  const nSamples = 1 << sizeParam;

  switch (transformation) {
    case 'gain':
      args.push(String(nSamples));
      args.push(String((params as any).factor ?? 0.75));
      break;
    case 'fade_in':
    case 'fade_out':
      args.push(String(nSamples));
      break;
    case 'combine':
      args.push(String(nSamples));
      args.push(String((params as any).alpha ?? 0.5));
      break;
    case 'pan':
      args.push(String(nSamples));
      args.push(String((params as any).pan ?? 0.5));
      break;
    case 'tremolo':
      args.push(String(nSamples));
      args.push(String((params as any).rateHz ?? 5.0));
      args.push(String((params as any).depth ?? 0.5));
      break;
  }

  return `go run main.go ${args.join(' ')}`;
}

function executeGnarkProver(
  cwd: string,
  backend: GnarkBackend,
  sizeParam: number,
  job: Job,
): Promise<GnarkMetrics> {
  return new Promise((resolve, reject) => {
    const cmd = buildGnarkCommand(backend, sizeParam, job);
    console.log(`[GnarkProver] Running: ${cmd}`);
    console.log(`[GnarkProver] CWD: ${cwd}`);

    exec(cmd, {
      cwd,
      shell: process.env.ComSpec || 'C:\\WINDOWS\\system32\\cmd.exe',
      maxBuffer: 50 * 1024 * 1024,
      timeout: 10 * 60 * 1000,
    }, (error, stdout, stderr) => {
      if (error) {
        console.error(`[GnarkProver] Error: ${error.message}`);
        console.error(`[GnarkProver] stderr: ${stderr}`);
        reject(new Error(`Gnark prover failed: ${error.message}\n${stderr}`));
        return;
      }

      console.log(`[GnarkProver] stdout:\n${stdout}`);

      try {
        const metrics = parseGnarkOutput(cwd, backend, sizeParam, stdout, job);
        resolve(metrics);
      } catch (parseErr) {
        reject(new Error(`Failed to parse gnark output: ${parseErr}`));
      }
    });
  });
}

/**
 * Parse gnark output. The Go programs write CSV files to output/ directory.
 * CSV columns include ProveTime_ms, VerifyTime_ms, NbConstraints, etc.
 * We also try to parse timing from stdout as a fallback.
 */
function parseGnarkOutput(
  cwd: string,
  backend: GnarkBackend,
  sizeParam: number,
  stdout: string,
  job: Job,
): GnarkMetrics {
  const transformation = job.transformation as Float32AudioTransformation;
  const transformDir = getGnarkTransformDir(transformation);
  const nSamples = 1 << sizeParam;

  // Try to find the CSV output file
  const outputDir = path.resolve(cwd, '..', '..', 'output');
  const csvName = `${transformDir}_${backend}_${sizeParam}_n${nSamples}.csv`;
  const csvPath = path.join(outputDir, csvName);

  if (fs.existsSync(csvPath)) {
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    const lines = csvContent.trim().split('\n');
    if (lines.length >= 2) {
      const headers = lines[0].split(',');
      const values = lines[lines.length - 1].split(','); // last row

      const getCol = (name: string): string => {
        const idx = headers.indexOf(name);
        return idx >= 0 ? values[idx] : '';
      };

      const proveMs = parseFloat(getCol('ProveTime_ms')) || 0;
      const verifyMs = parseFloat(getCol('VerifyTime_ms')) || 0;
      const nbConstraints = parseInt(getCol('NbConstraints'), 10) || 0;

      return {
        proverTimeSec: proveMs / 1000,
        verifierTimeSec: verifyMs / 1000,
        nbConstraints,
      };
    }
  }

  // Fallback: try to parse from stdout
  const proveMatch = stdout.match(/prove.*?(\d+(?:\.\d+)?)\s*ms/i);
  const verifyMatch = stdout.match(/verify.*?(\d+(?:\.\d+)?)\s*ms/i);

  return {
    proverTimeSec: proveMatch ? parseFloat(proveMatch[1]) / 1000 : 0,
    verifierTimeSec: verifyMatch ? parseFloat(verifyMatch[1]) / 1000 : 0,
    nbConstraints: 0,
  };
}
