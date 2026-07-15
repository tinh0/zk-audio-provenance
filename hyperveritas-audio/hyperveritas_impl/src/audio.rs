#![allow(warnings)]

//! Audio data structures and loading for zero-knowledge proof systems.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Audio data structure for storing audio samples.
/// Supports mono (single channel) and stereo (two channels) audio.
/// Sample values are stored as i32 to handle all bit depths uniformly.
#[derive(Serialize, Deserialize, Clone)]
pub struct Audio {
    pub sample_rate: u32,
    pub bit_depth: u8,
    pub num_channels: u8,
    pub num_samples: usize,
    pub left: Vec<i32>,
    pub right: Option<Vec<i32>>,
}

/// Load audio data from a JSON file.
pub fn load_audio(path: impl AsRef<Path> + std::fmt::Debug) -> Audio {
    let result: Audio = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

    assert!(result.num_samples == result.left.len(),
            "Left channel length {} does not match num_samples {}",
            result.left.len(), result.num_samples);

    if result.num_channels == 2 {
        assert!(result.right.is_some(), "Stereo audio must have right channel");
        assert!(result.right.as_ref().unwrap().len() == result.num_samples,
                "Right channel length does not match num_samples");
    }

    assert!(result.bit_depth == 8 || result.bit_depth == 16 || result.bit_depth == 24,
            "Unsupported bit depth: {}", result.bit_depth);

    result
}
