# IR Lifting Benchmark

A comprehensive benchmarking suite to evaluate the performance and reliability of Intermediate Representation (IR) lifting tools for security research.

## Supported Tools

| Tool       | IR Type | Analysis Type                                  |
| ---------- | ------- | ---------------------------------------------- |
| **Ghidra** | P-code  | Static Analysis (Headless)                     |
| **angr**   | VEX     | Static Analysis (CFG Recovery)                 |
| **BAP**    | BIL     | Static Analysis (Lifting)                      |
| **LLVM**   | LLVM IR | Lifting (RetDec/mctoll) or Disassembly (Proxy) |

## Prerequisites

- **OS**: Ubuntu 20.04/22.04 LTS (Recommended)
- **Ghidra**: Version 10.x or 11.x (Installed separately)
- **Python**: 3.8+

## Quick Start

### 1. Setup Environment

Run the automated setup script to install system dependencies, Python venv, and tools (angr, BAP):

```bash
./setup.sh
```

### 2. Configure Ghidra

Set the path to your Ghidra installation:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.0.1_PUBLIC
```

### 3. Populate Dataset

Place your malware samples in the `samples/malware/<arch>/` directories.
(Benign samples are provided in `samples/benign/` for testing).

### 4. Run Benchmark

Activate the virtual environment and run the benchmark:

```bash
source .venv/bin/activate
./scripts/run_all.sh
```

To enable optional tools (BAP and LLVM):

```bash
ENABLE_BAP=true ENABLE_LLVM=true ./scripts/run_all.sh
```

### 5. Generate Report

After the benchmark completes, generate a summary report:

```bash
python3 scripts/report_generator.py
```

This creates `results/benchmark_report.md`.

## Directory Structure

- `scripts/`: Analysis and orchestration scripts.
- `samples/`: Dataset directory (benign and malware).
- `results/`: Output logs and CSV summaries.

## Advanced Configuration

### LLVM Lifting

To enable true binary-to-LLVM IR lifting, you need **RetDec** or **llvm-mctoll**.
Run the helper script to attempt installation:

```bash
./scripts/install_llvm_lifter.sh
```

- Missing Ghidra? Verify the install path and that `ghidraRun` is executable.
- Python import errors? Reactivate itialized and BAP is installed: `opam install bap && eval $(opam env)`.venv and reinstall angr.
- BAP not found? Ensure opam is in
- LLVM not found? Install LLVM toolchain: `sudo apt install llvm` or download from <https://releases.llvm.org/>.
- Parsing failures? Confirm GNU time output is English and scripts still redirect stdout/stderr to the expected temp files.

### Customization

- **Timeout**: Set `TIMEOUT_SECONDS` (default: 60s).
- **Paths**: Override `SAMPLES_DIR`, `RESULTS_DIR` via environment variables.

## License

[MIT License](LICENSE)
