import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * Simulated "attested camera" using ECDSA P-256.
 *
 * In the real threat model, the camera has a secure enclave with an ECDSA
 * private key that signs the image hash (digestRGB) at capture time.
 * Here we simulate this with a server-side keypair.
 */

// Camera keypair — generated once at server startup.
// In production, this would be burned into camera hardware.
let cameraKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };

function ensureKeyPair() {
  if (cameraKeyPair) return;

  const keysDir = path.join(__dirname, '../../storage');
  const privPath = path.join(keysDir, 'camera_private.pem');
  const pubPath = path.join(keysDir, 'camera_public.pem');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    // Load existing keypair
    cameraKeyPair = {
      privateKey: crypto.createPrivateKey(fs.readFileSync(privPath, 'utf-8')),
      publicKey: crypto.createPublicKey(fs.readFileSync(pubPath, 'utf-8')),
    };
  } else {
    // Generate new keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    cameraKeyPair = { publicKey, privateKey };

    // Persist for consistency across restarts
    fs.mkdirSync(keysDir, { recursive: true });
    fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
    fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }) as string);
  }
}

/**
 * Sign the camera hash (digestRGB) with ECDSA P-256.
 * Returns the signature as a base64 string.
 */
export function signCameraHash(cameraHashJson: string): string {
  ensureKeyPair();
  const sign = crypto.createSign('SHA256');
  sign.update(cameraHashJson);
  sign.end();
  return sign.sign(cameraKeyPair.privateKey, 'base64');
}

/**
 * Get the camera's public key in PEM format.
 */
export function getCameraPublicKey(): string {
  ensureKeyPair();
  return cameraKeyPair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
}

/**
 * Sign the camera hash file in a job directory and write the attestation.
 * Called after the prover writes camera_hash.json.
 */
export function attestCameraHash(jobDir: string): void {
  const hashPath = path.join(jobDir, 'camera_hash.json');
  if (!fs.existsSync(hashPath)) {
    throw new Error('camera_hash.json not found in job directory');
  }

  const cameraHashJson = fs.readFileSync(hashPath, 'utf-8');
  const signature = signCameraHash(cameraHashJson);
  const publicKeyPem = getCameraPublicKey();

  // Write attestation file — contains the signature and public key
  const attestation = {
    publicKey: publicKeyPem,
    signature,
    algorithm: 'ECDSA-P256-SHA256',
  };

  fs.writeFileSync(
    path.join(jobDir, 'camera_attestation.json'),
    JSON.stringify(attestation, null, 2),
  );
}

/**
 * Verify the ECDSA signature on camera_hash.json using the public key
 * in camera_attestation.json. This is the client-side signature check
 * that binds h to the trusted capture device (Vrfy(pk, h, σ) in the paper).
 *
 * Returns { valid, message } — valid=true iff the signature is well-formed
 * and matches the hash file.
 */
export function verifyCameraAttestation(jobDir: string): { valid: boolean; message: string } {
  const hashPath = path.join(jobDir, 'camera_hash.json');
  const attestationPath = path.join(jobDir, 'camera_attestation.json');

  if (!fs.existsSync(hashPath)) {
    return { valid: false, message: 'camera_hash.json missing from job directory' };
  }
  if (!fs.existsSync(attestationPath)) {
    return { valid: false, message: 'camera_attestation.json missing — no source attestation' };
  }

  const cameraHashJson = fs.readFileSync(hashPath, 'utf-8');
  const attestation = JSON.parse(fs.readFileSync(attestationPath, 'utf-8')) as {
    publicKey: string;
    signature: string;
    algorithm: string;
  };

  const verifier = crypto.createVerify('SHA256');
  verifier.update(cameraHashJson);
  verifier.end();

  const valid = verifier.verify(attestation.publicKey, attestation.signature, 'base64');

  return {
    valid,
    message: valid
      ? 'Camera signature valid — hash attested by trusted source'
      : 'Camera signature INVALID — hash does not match the source attestation',
  };
}
