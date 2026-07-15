#!/bin/bash
# EC2 User Data script for automated benchmark VM provisioning.
# Paste this into the EC2 launch wizard "User data" field.
# The VM will set up, build, and be ready for benchmarks on login.

set -euo pipefail
exec > /var/log/hyperveritas-setup.log 2>&1

REPO_URL="https://github.com/your-org/HyperVerITAS.git"

# Run setup as ubuntu user
su - ubuntu -c "
  cd /home/ubuntu
  # Download and run setup script
  git clone --recurse-submodules ${REPO_URL} HyperVerITAS
  cd HyperVerITAS
  bash benchmark/setup-ec2.sh local
"

echo "HyperVerITAS benchmark VM setup complete at $(date)"
