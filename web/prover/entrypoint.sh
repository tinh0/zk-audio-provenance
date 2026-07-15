#!/bin/bash
set -euo pipefail

# HyperVerITAS Prover Entrypoint
# This script runs inside the ECS Fargate container.
#
# Expected environment variables:
#   S3_BUCKET           - S3 bucket name
#   JOB_ID              - Unique job identifier
#   TRANSFORMATION      - crop, grayscale, mono, volume, trim
#   PCS_TYPE            - pst, brakedown, basefold
#   SIZE_PARAM          - log2 of total pixels/samples (e.g., 10, 12, 14)
#   MEDIA_TYPE          - image or audio
#   INPUT_S3_KEY        - S3 key for original JSON
#   TRANSFORMED_S3_KEY  - S3 key for transformed JSON
#   DYNAMODB_TABLE      - DynamoDB table name (optional, for status updates)

echo "=== HyperVerITAS Prover ==="
echo "Job ID: ${JOB_ID}"
echo "Transformation: ${TRANSFORMATION}"
echo "PCS: ${PCS_TYPE}"
echo "Size: 2^${SIZE_PARAM}"
echo "Media: ${MEDIA_TYPE}"

# --------------------------------------------------
# 1. Download input files from S3
# --------------------------------------------------
echo "Downloading input files from S3..."

if [ "${MEDIA_TYPE}" = "image" ]; then
  # Image files go in images/ directory
  mkdir -p images
  aws s3 cp "s3://${S3_BUCKET}/${INPUT_S3_KEY}" "images/Timings${SIZE_PARAM}.json"

  if [ "${TRANSFORMATION}" = "crop" ]; then
    aws s3 cp "s3://${S3_BUCKET}/${TRANSFORMED_S3_KEY}" "images/Crop${SIZE_PARAM}.json"
  elif [ "${TRANSFORMATION}" = "grayscale" ]; then
    aws s3 cp "s3://${S3_BUCKET}/${TRANSFORMED_S3_KEY}" "images/Gray${SIZE_PARAM}.json"
  fi
else
  # Audio files
  case "${TRANSFORMATION}" in
    mono)
      aws s3 cp "s3://${S3_BUCKET}/${INPUT_S3_KEY}" "StereoAudio${SIZE_PARAM}.json"
      aws s3 cp "s3://${S3_BUCKET}/${TRANSFORMED_S3_KEY}" "Mono${SIZE_PARAM}.json"
      ;;
    volume)
      aws s3 cp "s3://${S3_BUCKET}/${INPUT_S3_KEY}" "Audio${SIZE_PARAM}.json"
      aws s3 cp "s3://${S3_BUCKET}/${TRANSFORMED_S3_KEY}" "Volume${SIZE_PARAM}.json"
      ;;
    trim)
      aws s3 cp "s3://${S3_BUCKET}/${INPUT_S3_KEY}" "Audio${SIZE_PARAM}.json"
      aws s3 cp "s3://${S3_BUCKET}/${TRANSFORMED_S3_KEY}" "Trim${SIZE_PARAM}.json"
      ;;
  esac
fi

# --------------------------------------------------
# 2. Map transformation + PCS to binary name
# --------------------------------------------------
case "${TRANSFORMATION}" in
  crop)      TRANSFORM_CODE="crop" ;;
  grayscale) TRANSFORM_CODE="gray" ;;
  mono)      TRANSFORM_CODE="mono" ;;
  volume)    TRANSFORM_CODE="volume" ;;
  trim)      TRANSFORM_CODE="trim" ;;
  *)         echo "Unknown transformation: ${TRANSFORMATION}"; exit 1 ;;
esac

BINARY="hv_${TRANSFORM_CODE}_${PCS_TYPE}"
echo "Running binary: ${BINARY} ${SIZE_PARAM}"

# --------------------------------------------------
# 3. Run the prover
# --------------------------------------------------
OUTPUT=$("${BINARY}" "${SIZE_PARAM}" 2>&1) || {
  echo "Prover failed!"
  echo "${OUTPUT}"

  # Upload error to S3
  echo "{\"error\": \"Prover binary failed\", \"output\": \"${OUTPUT}\"}" | \
    aws s3 cp - "s3://${S3_BUCKET}/jobs/${JOB_ID}/error.json"
  exit 1
}

echo "=== Prover Output ==="
echo "${OUTPUT}"

# --------------------------------------------------
# 4. Parse metrics from stdout
# --------------------------------------------------
PROVER_TIME=$(echo "${OUTPUT}" | grep -oP 'PROVER TIME:\s*\K[\d.]+')
PROOF_SIZE=$(echo "${OUTPUT}" | grep -oP 'PROOF SIZE:\s*\K\d+')
VERIFIER_TIME=$(echo "${OUTPUT}" | grep -oP 'VERIFIER TIME:\s*\K[\d.]+')

echo "=== Parsed Metrics ==="
echo "Prover Time: ${PROVER_TIME}s"
echo "Proof Size: ${PROOF_SIZE} bytes"
echo "Verifier Time: ${VERIFIER_TIME}s"

# --------------------------------------------------
# 5. Upload metrics to S3
# --------------------------------------------------
METRICS_JSON=$(cat <<EOF
{
  "jobId": "${JOB_ID}",
  "proverTimeSec": ${PROVER_TIME},
  "verifierTimeSec": ${VERIFIER_TIME},
  "proofSizeBytes": ${PROOF_SIZE},
  "status": "completed"
}
EOF
)

echo "${METRICS_JSON}" | aws s3 cp - "s3://${S3_BUCKET}/jobs/${JOB_ID}/metrics.json"

echo "=== Done ==="
