#![allow(warnings)]

mod helpers;
mod verifier;

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use hyperveritas_impl::image::Image;

use plonkish_backend::util::new_fields::Mersenne127 as F;

#[derive(Serialize, Deserialize)]
struct VerifyResult {
    verified: bool,
    message: String,
}

#[derive(Deserialize)]
struct PublicInputs {
    #[serde(alias = "origWidth")]
    orig_width: usize,
    #[serde(alias = "origHeight")]
    orig_height: usize,
    #[serde(alias = "startX")]
    start_x: usize,
    #[serde(alias = "startY")]
    start_y: usize,
    #[serde(alias = "endX")]
    end_x: usize,
    #[serde(alias = "endY")]
    end_y: usize,
}

/// Initialize panic hook for better error messages in browser console.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Verify a HyperVerITAS crop proof (Brakedown PCS).
///
/// # Arguments
/// * `input_size` - the log2 size parameter (e.g., 14, 15, etc.)
/// * `proof_bytes` - the serialized proof (contents of proof.bin)
/// * `public_inputs_json` - JSON string with origWidth, origHeight, startX, startY, endX, endY
/// * `camera_hash_json` - JSON string of the camera hash (digestRGB): [[u64,u64]...] × 3 channels
/// * `crop_image_json` - JSON string of cropped image {rows, cols, R, G, B}
///
/// # Returns
/// A JsValue containing {verified: bool, message: string}
#[wasm_bindgen]
pub fn verify_crop_brakedown(
    input_size: usize,
    proof_bytes: &[u8],
    public_inputs_json: &str,
    camera_hash_json: &str,
    crop_image_json: &str,
) -> Result<JsValue, JsValue> {
    let public_inputs: PublicInputs = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse public inputs: {}", e)))?;

    // Parse the camera hash (digestRGB) — this is the public attestation from the camera
    let digest_rgb: Vec<Vec<F>> = serde_json::from_str(camera_hash_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse camera hash: {}", e)))?;

    let crop_img: Image = serde_json::from_str(crop_image_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse crop image: {}", e)))?;

    let num_cols = input_size;
    let nv_crop = input_size - 1;
    let num_rows = 7;

    // PCS param setup only — no camera hash recomputation
    let (_pp, vp) = verifier::setup_params(input_size);

    // Run verification with the pre-computed camera hash
    let success = verifier::verify_from_bytes(
        vp,
        num_rows,
        num_cols,
        nv_crop,
        public_inputs.orig_width,
        public_inputs.orig_height,
        public_inputs.start_x,
        public_inputs.start_y,
        public_inputs.end_x,
        public_inputs.end_y,
        digest_rgb,
        proof_bytes,
        &crop_img,
    );

    let result = VerifyResult {
        verified: success,
        message: if success {
            "Proof verified successfully".to_string()
        } else {
            "Proof verification failed".to_string()
        },
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}
