#!/bin/bash
# HyperVerITAS Benchmark VM Setup
# Run on a fresh Ubuntu 24.04 EC2 instance (recommended: r6i.8xlarge, 256GB RAM)
#
# Usage: bash setup-ec2.sh [REPO_URL]
set -euo pipefail

REPO_URL="${1:-https://github.com/your-org/HyperVerITAS.git}"

echo "=== HyperVerITAS Benchmark VM Setup ==="

# System updates
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
  build-essential gcc g++ cmake \
  python3 python3-pip python3-venv \
  git curl wget time jq \
  pkg-config libssl-dev

# Install Rust nightly
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup default nightly

# Install Go (for zk-Location audio proofs)
GO_VERSION="1.22.5"
wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"
echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
export PATH=$PATH:/usr/local/go/bin

# Clone the repository
cd "$HOME"
git clone --recurse-submodules "$REPO_URL" HyperVerITAS
cd HyperVerITAS

# Build HyperVerITAS Rust implementation
cd hyperveritas_impl
cargo build --release --examples
echo "Rust build complete."

# Set up Python environment for test data generation
python3 -m venv venv
source venv/bin/activate
pip install numpy scipy

# Generate test images (sizes 19-25)
python3 -c "
import sys
sys.path.insert(0, 'images')
from helper import generate_all_images
generate_all_images(19, 25)
"

# Generate test audio (sizes 19-25, 16-bit stereo)
python3 -c "
import sys
sys.path.insert(0, 'audio')
from helper import generate_all_audio
generate_all_audio(19, 25, bit_depth=16, stereo=True)
"

deactivate
cd "$HOME/HyperVerITAS"

# Build Go implementation
cd zk-location-float
go build ./...
cd "$HOME/HyperVerITAS"

echo ""
echo "=== Setup Complete ==="
echo "Run benchmarks with: bash benchmark/run-benchmarks.sh"
