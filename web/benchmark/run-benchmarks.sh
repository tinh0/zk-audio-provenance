#!/bin/bash
# HyperVerITAS Benchmark Runner
# Runs all transformation x PCS x size combinations and collects results.
#
# Usage: bash run-benchmarks.sh [MIN_SIZE] [MAX_SIZE]
#   Default: sizes 19 to 25
set -euo pipefail

MIN_SIZE="${1:-19}"
MAX_SIZE="${2:-25}"
RESULTS_DIR="$HOME/benchmark-results/$(date +%Y%m%d_%H%M%S)"
HV_DIR="$HOME/HyperVerITAS/hyperveritas_impl"

mkdir -p "$RESULTS_DIR"

echo "=== HyperVerITAS Benchmarks ==="
echo "Sizes: 2^${MIN_SIZE} to 2^${MAX_SIZE}"
echo "Results: ${RESULTS_DIR}"
echo ""

# Image transformations x PCS combinations
IMAGE_TRANSFORMS=("crop" "gray")
# Audio transformations x PCS combinations
AUDIO_TRANSFORMS=("mono" "volume" "trim")
# PCS backends
PCS_TYPES=("pst" "brakedown" "basefold")

# Write CSV header
RESULTS_CSV="${RESULTS_DIR}/results.csv"
echo "transformation,pcs,size,prover_time_sec,verifier_time_sec,proof_size_bytes,peak_memory_kb" > "$RESULTS_CSV"

run_benchmark() {
  local transform="$1"
  local pcs="$2"
  local size="$3"
  local binary="hv_${transform}_${pcs}"
  local log_file="${RESULTS_DIR}/${binary}_${size}.log"

  echo "--- Running: ${binary} size=${size} ---"

  cd "$HV_DIR"

  # Run with /usr/bin/time to capture peak memory
  /usr/bin/time -v cargo run --release --example "$binary" "$size" \
    > "$log_file" 2>&1 || {
    echo "  FAILED (see ${log_file})"
    echo "${transform},${pcs},${size},FAILED,FAILED,FAILED,FAILED" >> "$RESULTS_CSV"
    return
  }

  # Parse metrics from output
  local prover_time=$(grep -oP 'PROVER TIME:\s*\K[\d.]+' "$log_file" || echo "N/A")
  local proof_size=$(grep -oP 'PROOF SIZE:\s*\K\d+' "$log_file" || echo "N/A")
  local verifier_time=$(grep -oP 'VERIFIER TIME:\s*\K[\d.]+' "$log_file" || echo "N/A")
  local peak_memory=$(grep -oP 'Maximum resident set size.*?:\s*\K\d+' "$log_file" || echo "N/A")

  echo "  Prover: ${prover_time}s | Verifier: ${verifier_time}s | Proof: ${proof_size}B | Memory: ${peak_memory}kB"
  echo "${transform},${pcs},${size},${prover_time},${verifier_time},${proof_size},${peak_memory}" >> "$RESULTS_CSV"
}

# Run image benchmarks
echo "=== Image Transformations ==="
for transform in "${IMAGE_TRANSFORMS[@]}"; do
  for pcs in "${PCS_TYPES[@]}"; do
    for ((size=MIN_SIZE; size<=MAX_SIZE; size++)); do
      run_benchmark "$transform" "$pcs" "$size"
    done
  done
done

# Run audio benchmarks
echo ""
echo "=== Audio Transformations ==="
for transform in "${AUDIO_TRANSFORMS[@]}"; do
  for pcs in "${PCS_TYPES[@]}"; do
    for ((size=MIN_SIZE; size<=MAX_SIZE; size++)); do
      run_benchmark "$transform" "$pcs" "$size"
    done
  done
done

echo ""
echo "=== Benchmarks Complete ==="
echo "Results saved to: ${RESULTS_CSV}"
echo "Individual logs in: ${RESULTS_DIR}/"
