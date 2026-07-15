import { Request, Response } from 'express';
import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import sharp from 'sharp';
import { config } from '../config';
import { HVImageJson } from '@hyperveritas-web/shared/types';
import { attestCameraHash, verifyCameraAttestation } from '../services/cameraService';

const DEMO_SIZE = 16;
const DEMO_DIR = path.join(config.storagePath, 'integrity-demo');
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
 * Convert HVImageJson to a PNG buffer.
 */
async function hvJsonToPng(json: HVImageJson): Promise<Buffer> {
  const imgWidth = json.rows;
  const imgHeight = json.cols;
  const totalPixels = imgWidth * imgHeight;
  const rawPixels = Buffer.alloc(totalPixels * 3);
  for (let i = 0; i < totalPixels; i++) {
    rawPixels[i * 3] = json.R[i];
    rawPixels[i * 3 + 1] = json.G[i];
    rawPixels[i * 3 + 2] = json.B[i];
  }
  return sharp(rawPixels, {
    raw: { width: imgWidth, height: imgHeight, channels: 3 },
  }).png().toBuffer();
}

/**
 * POST /api/integrity-demo/setup
 * Runs the prover and generates demo artifacts.
 */
export async function integrityDemoSetupHandler(_req: Request, res: Response) {
  try {
    fs.mkdirSync(DEMO_DIR, { recursive: true });

    const hvPath = config.hyperveritasPath;
    const imagesDir = path.join(hvPath, 'images');

    // Step 1: Run the split prover
    console.log('[IntegrityDemo] Running prover...');
    const proofResult = await new Promise<{ proverTimeSec: number; proofSizeBytes: number }>((resolve, reject) => {
      const cmd = `cargo run --release --example hv_crop_brakedown_prove ${DEMO_SIZE} "${DEMO_DIR}"`;
      exec(cmd, { cwd: hvPath, maxBuffer: 50 * 1024 * 1024, timeout: 5 * 60 * 1000 }, (error, stdout, stderr) => {
        if (error) {
          console.error('[IntegrityDemo] Prover error:', stderr);
          reject(new Error(`Prover failed: ${error.message}`));
          return;
        }
        const proverMatch = stdout.match(/PROVER TIME:\s*([\d.]+)\s*seconds/);
        const proofSizeMatch = stdout.match(/PROOF SIZE:\s*(\d+)\s*bytes/);
        resolve({
          proverTimeSec: proverMatch ? parseFloat(proverMatch[1]) : 0,
          proofSizeBytes: proofSizeMatch ? parseInt(proofSizeMatch[1], 10) : 0,
        });
      });
    });

    // Step 2: Generate original full image PNG from Timings JSON
    const timingsJsonPath = path.join(imagesDir, `Timings${DEMO_SIZE}.json`);
    const timingsJson: HVImageJson = JSON.parse(fs.readFileSync(timingsJsonPath, 'utf-8'));
    const originalPng = await hvJsonToPng(timingsJson);
    fs.writeFileSync(path.join(DEMO_DIR, 'original_full.png'), originalPng);
    // Scale up for display
    const origW = timingsJson.rows;
    const origH = timingsJson.cols;
    const displayScale = Math.max(1, Math.floor(512 / Math.max(origW, origH)));
    const originalDisplay = await sharp(originalPng).resize(origW * displayScale, origH * displayScale, { kernel: 'nearest' }).png().toBuffer();
    fs.writeFileSync(path.join(DEMO_DIR, 'original_full_display.png'), originalDisplay);

    // Step 3: Generate authentic crop PNG from the prover's Crop JSON
    const cropJsonPath = path.join(imagesDir, `Crop${DEMO_SIZE}.json`);
    const cropJson: HVImageJson = JSON.parse(fs.readFileSync(cropJsonPath, 'utf-8'));
    const authenticPng = await hvJsonToPng(cropJson);
    fs.writeFileSync(path.join(DEMO_DIR, 'authentic_crop.png'), authenticPng);

    // Step 4: Load the real tampered image (photoshopped version with flipped text)
    const tamperedCropPath = path.join(imagesDir, `TamperedCrop${DEMO_SIZE}.json`);
    const tamperedJson: HVImageJson = JSON.parse(fs.readFileSync(tamperedCropPath, 'utf-8'));
    const tamperedPng = await hvJsonToPng(tamperedJson);
    fs.writeFileSync(path.join(DEMO_DIR, 'tampered_crop.png'), tamperedPng);
    // Save tampered JSON for verifier
    fs.writeFileSync(path.join(DEMO_DIR, 'tampered_crop.json'), JSON.stringify(tamperedJson));
    // Save authentic crop JSON too
    fs.copyFileSync(cropJsonPath, path.join(DEMO_DIR, 'authentic_crop.json'));

    // Scale up crop images for display
    const cropW = cropJson.rows;
    const cropH = cropJson.cols;
    const cropScale = Math.max(1, Math.floor(512 / Math.max(cropW, cropH)));
    const authenticDisplay = await sharp(authenticPng).resize(cropW * cropScale, cropH * cropScale, { kernel: 'nearest' }).png().toBuffer();
    const tamperedDisplay = await sharp(tamperedPng).resize(cropW * cropScale, cropH * cropScale, { kernel: 'nearest' }).png().toBuffer();
    fs.writeFileSync(path.join(DEMO_DIR, 'authentic_display.png'), authenticDisplay);
    fs.writeFileSync(path.join(DEMO_DIR, 'tampered_display.png'), tamperedDisplay);

    // Step 5: Sign camera hash with ECDSA (simulated attested camera)
    try {
      attestCameraHash(DEMO_DIR);
      console.log('[IntegrityDemo] Camera hash signed');
    } catch (err) {
      console.warn('[IntegrityDemo] Failed to attest camera hash:', err);
    }

    // Step 6: Save metadata
    const meta: DemoMeta = {
      ready: true,
      proofSizeBytes: proofResult.proofSizeBytes,
      proverTimeSec: proofResult.proverTimeSec,
      setupTime: new Date().toISOString(),
    };
    fs.writeFileSync(META_FILE, JSON.stringify(meta, null, 2));

    console.log('[IntegrityDemo] Setup complete');
    res.json({ ready: true, proofSizeBytes: proofResult.proofSizeBytes, proverTimeSec: proofResult.proverTimeSec });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    console.error('[IntegrityDemo] Setup failed:', message);
    res.status(500).json({ error: message });
  }
}

/**
 * GET /api/integrity-demo
 * Returns demo status and metadata.
 */
export function integrityDemoStatusHandler(_req: Request, res: Response) {
  const meta = getDemoMeta();
  if (!meta || !meta.ready) {
    res.json({ ready: false });
    return;
  }

  // Read first 128 bytes of proof as hex preview
  const proofPath = path.join(DEMO_DIR, 'proof.bin');
  let proofPreview = '';
  if (fs.existsSync(proofPath)) {
    const proofBytes = Buffer.alloc(128);
    const fd = fs.openSync(proofPath, 'r');
    fs.readSync(fd, proofBytes, 0, 128, 0);
    fs.closeSync(fd);
    proofPreview = proofBytes.toString('hex');
  }

  res.json({
    ready: true,
    proofSizeBytes: meta.proofSizeBytes,
    proverTimeSec: meta.proverTimeSec,
    sizeParam: DEMO_SIZE,
    originalImageUrl: '/api/integrity-demo/files/original-full',
    authenticImageUrl: '/api/integrity-demo/files/authentic',
    tamperedImageUrl: '/api/integrity-demo/files/tampered',
    proofPreview,
  });
}

/**
 * POST /api/integrity-demo/verify/:which
 * Runs the standalone verifier against authentic or tampered crop.
 */
export async function integrityDemoVerifyHandler(req: Request, res: Response) {
  const which = req.params.which as string;
  if (which !== 'authentic' && which !== 'tampered') {
    res.status(400).json({ error: 'Invalid: must be "authentic" or "tampered"' });
    return;
  }

  const meta = getDemoMeta();
  if (!meta || !meta.ready) {
    res.status(400).json({ error: 'Demo not set up. Call POST /api/integrity-demo/setup first.' });
    return;
  }

  const hvPath = config.hyperveritasPath;
  const cropJsonPath = which === 'authentic'
    ? path.join(DEMO_DIR, 'authentic_crop.json')
    : path.join(DEMO_DIR, 'tampered_crop.json');

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
  console.log(`[IntegrityDemo] ${sigCheck.message}`);

  try {
    const result = await new Promise<{ verified: boolean; verifierTimeSec: number }>((resolve, reject) => {
      const cmd = `cargo run --release --example hv_crop_brakedown_verify ${DEMO_SIZE} "${DEMO_DIR}" "${cropJsonPath}"`;
      console.log(`[IntegrityDemo] Verifying ${which}: ${cmd}`);

      exec(cmd, { cwd: hvPath, maxBuffer: 50 * 1024 * 1024, timeout: 5 * 60 * 1000 }, (error, stdout) => {
        console.log(`[IntegrityDemo] Verifier stdout:\n${stdout}`);

        if (error) {
          // Non-zero exit = verification failed (tampered proof causes panic or returns false)
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

    res.json({
      which,
      verified: result.verified,
      verifierTimeSec: result.verifierTimeSec,
      message: result.verified
        ? 'Proof verified. This image is an authentic, unmodified crop of the original.'
        : 'Verification FAILED. This image has been tampered with and does not match the original proof.',
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    res.json({ which, verified: false, verifierTimeSec: 0, message: `Verification error: ${message}` });
  }
}

/**
 * GET /api/integrity-demo/files/:which
 * Serves the demo image files.
 */
export function integrityDemoFileHandler(req: Request, res: Response) {
  const which = req.params.which as string;
  const fileMap: Record<string, string> = {
    authentic: 'authentic_display.png',
    tampered: 'tampered_display.png',
    'authentic-raw': 'authentic_crop.png',
    'tampered-raw': 'tampered_crop.png',
    'original-full': 'original_full_display.png',
    'proof': 'proof.bin',
    'camera-hash': 'camera_hash.json',
    'public-inputs': 'public_inputs.json',
    'crop-json': 'authentic_crop.json',
    'tampered-crop-json': 'tampered_crop.json',
    'camera-attestation': 'camera_attestation.json',
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
