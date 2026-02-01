#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# 1. Use Rust (nightly)
echo "Use Rust nightly..."
rustup default nightly

# 2. Initialize Python environment
echo "Setting up Python virtual environment..."
cd hyperveritas_impl
python3 -m venv hyperveritas
source hyperveritas/bin/activate

# 3. Install Python dependencies
cd images
pip install -r requirements.txt

# 4. Run helper.py
echo "Running helper.py to generate images..."
python helper.py

echo "All done! HyperVerITAS is setup. Images should be generated."
