#!/bin/bash
#
# setup.sh
# Sets up the environment for IR Lifting Benchmark.
# Installs system dependencies, Python virtual environment, and analysis tools.
#

set -e  # Exit on error

echo "=========================================="
echo "IR Lifting Benchmark - Environment Setup"
echo "=========================================="

# 1. System Dependencies
echo "[*] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y time python3-venv python3-pip wget llvm opam build-essential

# 2. Python Virtual Environment (angr)
echo ""
echo "[*] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "    Created .venv"
else
    echo "    .venv already exists"
fi

# Activate and install angr
source .venv/bin/activate
echo "    Installing angr (this may take a while)..."
pip install --upgrade pip
pip install angr

# 3. BAP Installation (via opam)
echo ""
echo "[*] Checking BAP installation..."
if ! command -v bap &> /dev/null; then
    echo "    BAP not found. Installing via opam..."
    
    # Initialize opam if not already initialized
    if [ ! -d "$HOME/.opam" ]; then
        opam init -y --disable-sandboxing
    fi
    
    eval $(opam env)
    
    # Install BAP
    # Note: conf-bap-llvm might fail on some systems depending on LLVM version, 
    # but core BAP often installs successfully. We use || true to continue if non-critical components fail.
    opam install bap -y || echo "WARNING: BAP installation encountered errors. Please verify 'bap' command works."
else
    echo "    BAP is already installed."
fi

# 4. LLVM Lifters (Optional)
echo ""
echo "[*] Setting up LLVM lifters..."
./scripts/install_llvm_lifter.sh || echo "WARNING: LLVM lifter setup failed. You can retry manually."

# 5. Script Permissions
echo ""
echo "[*] Making scripts executable..."
chmod +x scripts/*.sh

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo "To run the benchmark:"
echo "  1. Activate venv: source .venv/bin/activate"
echo "  2. Configure Ghidra: export GHIDRA_INSTALL_DIR=/path/to/ghidra"
echo "  3. Run: ./scripts/run_all.sh"
echo ""
