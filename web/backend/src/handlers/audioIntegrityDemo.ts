import { Request, Response } from 'express';
import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import { config } from '../config';
import { HVAudioJson } from '@hyperveritas-web/shared/types';
import { hvJsonToWav } from '../services/audioConverter';
import { attestCameraHash, verifyCameraAttestation } from '../services/cameraService';

const DEMO_SIZE = 18;
const DEMO_DIR = path.join(config.storagePath, 'audio-integrity-demo');
const META_FILE = path.join(DEMO_DIR, 'demo_meta.json');

interface DemoMeta {
  ready: boolean;
  proofSizeBytes: number;
  proverTimeSec: number;
  setupTime: string;
}

function getDemoMeta(): DemoMeta | null {
  if (!fs.existsSync(META_FILE)) return null;
  return JSON.parse(fs.readFileSync(META_FILE, 'utf-8'));
}

/**
 * POST /api/audio-integrity-demo/setup
 * Runs the audio volume prover and generates demo artifacts.
 */
export async function audioIntegrityDemoSetupHandler(_req: Request, res: Response) {
  try {
    fs.mkdirSync(DEMO_DIR, { recursive: true });

    const hvPath = config.hyperveritasPath;

    // Step 1: Run the split audio volume prover
    console.log('[AudioIntegrityDemo] Running prover...');
    const proofResult = await new Promise<{ proverTimeSec: number; proofSizeBytes: number }>((resolve, reject) => {
      const cmd = `cargo run --release --example hv_volume_brakedown_prove ${DEMO_SIZE} "${DEMO_DIR}"`;
      exec(cmd, { cwd: hvPath, maxBuffer: 50 * 1024 * 1024, timeout: 5 * 60 * 1000 }, (error, stdout, stderr) => {
        if (error) {
          console.error('[AudioIntegrityDemo] Prover error:', stderr);
          reject(new Error(`Prover failed: ${error.message}`));
          return;
        }
        console.log('[AudioIntegrityDemo] Prover stdout:', stdout);
        const proverMatch = stdout.match(/PROVER TIME:\s*([\d.]+)\s*seconds/);
        const proofSizeMatch = stdout.match(/PROOF SIZE:\s*(\d+)\s*bytes/);
        resolve({
          proverTimeSec: proverMatch ? parseFloat(proverMatch[1]) : 0,
          proofSizeBytes: proofSizeMatch ? parseInt(proofSizeMatch[1], 10) : 0,
        });
      });
    });

    // Step 2: Save the prover's Volume JSON (the ground truth for verification)
    const volumeJsonPath = path.join(hvPath, 'audio', `Volume${DEMO_SIZE}.json`);
    const volumeJson: HVAudioJson = JSON.parse(fs.readFileSync(volumeJsonPath, 'utf-8'));
    fs.writeFileSync(path.join(DEMO_DIR, 'authentic.json'), JSON.stringify(volumeJson));

    // Step 3: Generate WAV files — trim to real audio length (before padding)
    const REAL_SAMPLES = 192000; // clipC.wav original length before power-of-2 padding
    const audioJsonPath = path.join(hvPath, 'audio', `Audio${DEMO_SIZE}.json`);
    const audioJson: HVAudioJson = JSON.parse(fs.readFileSync(audioJsonPath, 'utf-8'));
    const trimmedOriginal = { ...audioJson, left: audioJson.left.slice(0, REAL_SAMPLES), num_samples: REAL_SAMPLES };
    const originalWav = hvJsonToWav(trimmedOriginal);
    fs.writeFileSync(path.join(DEMO_DIR, 'original.wav'), originalWav);

    const trimmedAuthentic = { ...volumeJson, left: volumeJson.left.slice(0, REAL_SAMPLES), num_samples: REAL_SAMPLES };
    const authenticWav = hvJsonToWav(trimmedAuthentic);
    fs.writeFileSync(path.join(DEMO_DIR, 'authentic.wav'), authenticWav);

    // Step 4: Create tampered version — obvious: reverse the entire second half
    const tamperedJson: HVAudioJson = JSON.parse(JSON.stringify(volumeJson));
    const halfway = Math.floor(tamperedJson.left.length / 2);
    const secondHalf = tamperedJson.left.slice(halfway);
    secondHalf.reverse();
    for (let i = 0; i < secondHalf.length; i++) {
      tamperedJson.left[halfway + i] = secondHalf[i];
    }
    const trimmedTampered = { ...tamperedJson, left: tamperedJson.left.slice(0, REAL_SAMPLES), num_samples: REAL_SAMPLES };
    const tamperedWav = hvJsonToWav(trimmedTampered);
    fs.writeFileSync(path.join(DEMO_DIR, 'tampered.wav'), tamperedWav);
    fs.writeFileSync(path.join(DEMO_DIR, 'tampered.json'), JSON.stringify(tamperedJson));

    // Step 5: Sign camera hash with ECDSA
    try {
      attestCameraHash(DEMO_DIR);
      console.log('[AudioIntegrityDemo] Camera hash signed');
    } catch (err) {
      console.warn('[AudioIntegrityDemo] Failed to attest camera hash:', err);
    }

    // Step 6: Save metadata
    const meta: DemoMeta = {
      ready: true,
      proofSizeBytes: proofResult.proofSizeBytes,
      proverTimeSec: proofResult.proverTimeSec,
      setupTime: new Date().toISOString(),
    };
    fs.writeFileSync(META_FILE, JSON.stringify(meta, null, 2));

    console.log('[AudioIntegrityDemo] Setup complete');
    res.json({ ready: true, proofSizeBytes: proofResult.proofSizeBytes, proverTimeSec: proofResult.proverTimeSec });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    console.error('[AudioIntegrityDemo] Setup failed:', message);
    res.status(500).json({ error: message });
  }
}

/**
 * GET /api/audio-integrity-demo
 */
export function audioIntegrityDemoStatusHandler(_req: Request, res: Response) {
  const meta = getDemoMeta();
  if (!meta || !meta.ready) {
    res.json({ ready: false });
    return;
  }

  res.json({
    ready: true,
    proofSizeBytes: meta.proofSizeBytes,
    proverTimeSec: meta.proverTimeSec,
    sizeParam: DEMO_SIZE,
    originalAudioUrl: '/api/audio-integrity-demo/files/original',
    authenticAudioUrl: '/api/audio-integrity-demo/files/authentic',
    tamperedAudioUrl: '/api/audio-integrity-demo/files/tampered',
  });
}

/**
 * POST /api/audio-integrity-demo/verify/:which
 * Runs the standalone verifier against authentic or tampered volume adjustment.
 */
export async function audioIntegrityDemoVerifyHandler(req: Request, res: Response) {
  const which = req.params.which as string;
  if (which !== 'authentic' && which !== 'tampered') {
    res.status(400).json({ error: 'Invalid: must be "authentic" or "tampered"' });
    return;
  }

  const meta = getDemoMeta();
  if (!meta || !meta.ready) {
    res.status(400).json({ error: 'Demo not set up.' });
    return;
  }

  const hvPath = config.hyperveritasPath;

  // Step 1: Verify the camera's ECDSA signature on the hash (Vrfy(pk, h, σ)).
  // This binds h to a trusted capture device before we even run the SNARK.
  const sigCheck = verifyCameraAttestation(DEMO_DIR);
  if (!sigCheck.valid) {
    res.json({
      which,
      verified: false,
      verifierTimeSec: 0,
      message: `Camera attestation failed: ${sigCheck.message}`,
    });
    return;
  }
  console.log(`[AudioIntegrityDemo] ${sigCheck.message}`);

  // For tampered verification, swap the Volume JSON with the tampered version
  const volumeJsonPath = path.join(hvPath, 'audio', `Volume${DEMO_SIZE}.json`);
  const sourceJson = which === 'authentic'
    ? path.join(DEMO_DIR, 'authentic.json')
    : path.join(DEMO_DIR, 'tampered.json');

  // Backup the original Volume JSON, copy the test version, restore after
  const backupPath = volumeJsonPath + '.bak';
  if (fs.existsSync(volumeJsonPath)) {
    fs.copyFileSync(volumeJsonPath, backupPath);
  }
  fs.copyFileSync(sourceJson, volumeJsonPath);

  try {
    const result = await new Promise<{ verified: boolean; verifierTimeSec: number }>((resolve, reject) => {
      const cmd = `cargo run --release --example hv_volume_brakedown_verify ${DEMO_SIZE} "${DEMO_DIR}"`;
      console.log(`[AudioIntegrityDemo] Verifying ${which}: ${cmd}`);

      exec(cmd, { cwd: hvPath, maxBuffer: 50 * 1024 * 1024, timeout: 5 * 60 * 1000 }, (error, stdout) => {
        console.log(`[AudioIntegrityDemo] Verifier stdout:\n${stdout}`);
        if (error) {
          const timeMatch = stdout.match(/VERIFIER TIME:\s*([\d.]+)\s*seconds/);
          resolve({ verified: false, verifierTimeSec: timeMatch ? parseFloat(timeMatch[1]) : 0 });
          return;
        }

        const verifiedMatch = stdout.match(/VERIFIED:\s*(true|false)/);
        const timeMatch = stdout.match(/VERIFIER TIME:\s*([\d.]+)\s*seconds/);
        resolve({
          verified: verifiedMatch ? verifiedMatch[1] === 'true' : false,
          verifierTimeSec: timeMatch ? parseFloat(timeMatch[1]) : 0,
        });
      });
    });

    // Restore original Volume JSON
    if (fs.existsSync(backupPath)) {
      fs.copyFileSync(backupPath, volumeJsonPath);
      fs.unlinkSync(backupPath);
    }

    res.json({
      which,
      verified: result.verified,
      verifierTimeSec: result.verifierTimeSec,
      message: result.verified
        ? 'Proof verified. This audio is an authentic volume adjustment of the original recording.'
        : 'Verification FAILED. This audio has been tampered with.',
    });
  } catch (err) {
    // Restore on error too
    if (fs.existsSync(backupPath)) {
      fs.copyFileSync(backupPath, volumeJsonPath);
      fs.unlinkSync(backupPath);
    }
    const message = err instanceof Error ? err.message : 'Unknown error';
    res.json({ which, verified: false, verifierTimeSec: 0, message: `Verification error: ${message}` });
  }
}

/**
 * GET /api/audio-integrity-demo/files/:which
 */
export function audioIntegrityDemoFileHandler(req: Request, res: Response) {
  const which = req.params.which as string;
  const fileMap: Record<string, string> = {
    original: 'original.wav',
    authentic: 'authentic.wav',
    tampered: 'tampered.wav',
  };

  const fileName = fileMap[which];
  if (!fileName) {
    res.status(400).json({ error: 'Invalid file' });
    return;
  }

  const filePath = path.join(DEMO_DIR, fileName);
  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'File not found. Run setup first.' });
    return;
  }

  res.sendFile(filePath);
}
