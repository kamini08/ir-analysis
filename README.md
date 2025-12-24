## IR Analysis / IR Lifting Benchmark

This repository provides an analysis and benchmarking framework for evaluating Intermediate Representation (IR) lifting and disassembly tools against binary samples. It orchestrates multiple lifters/analysers (Ghidra, angr, BAP, LLVM) and collects runtime, memory and IR-statistics into CSV and human-readable reports.

The project is intended for security researchers and tool developers who want to compare lifting quality and resource usage across different toolchains.

## Key features

- Batch orchestration for multiple analyzers: Ghidra (P-code), angr (VEX), BAP (BIL), and LLVM-based tooling.
- Per-sample timing and memory measurement using GNU time.
- CSV summary output with counts for functions, basic blocks and IR statements.
- Scripts to run each tool headless and helper scripts for installation and reporting.

## Repository layout

- `scripts/` - orchestration and analysis scripts (see details below).
- `samples/` - dataset of binaries (organized by benign/ malware and optionally by architecture).
- `results/` - output logs, CSV summaries and generated reports.
- `ghidra_projects/` - (optional) project data produced by Ghidra headless runs.
- `validation/` - helper utilities used for semantic validation and test harnesses.

## Quick start

1. Install prerequisites. On Debian/Ubuntu based systems this typically includes:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip time file
```

2. Run the repository setup script (this creates a virtualenv and installs Python requirements where applicable):

```bash
./setup.sh
```

3. Configure external tools (examples):

- Ghidra: set the `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation directory.
- BAP: optional, installed via `opam` (enable with `ENABLE_BAP=true`).
- LLVM: optional; enable with `ENABLE_LLVM=true`.

Example environment variables (set inline or export in your shell):

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
SAMPLES_DIR=/absolute/path/to/samples RESULTS_DIR=/absolute/path/to/results ./scripts/run_all.sh
```

4. Activate your Python virtualenv (if created by `setup.sh`) and run the full benchmark:

```bash
source venv/bin/activate
./scripts/run_all.sh
```

Notes:
- The orchestrator script is `scripts/run_all.sh`. It detects missing dependencies and will print guidance when something is absent.
- Use `ENABLE_BAP` and `ENABLE_LLVM` environment variables to toggle optional analyses.

## Producing reports

- After a run, a CSV summary `results/summary.csv` and detailed logs are produced.
- Generate a human-readable report with:

```bash
python3 scripts/report_generator.py
```

The generated report(s) are placed under `results/` (for example `results/benchmark_report.md`).

## Development notes

- Scripts are a mix of Bash and Python. Keep shell scripts POSIX-friendly where possible and prefer `bash` for complex logic.
- The `scripts/validation/` folder contains utilities for semantic differencing and validation between IRs.

## Contributing

See `CONTRIBUTING.md` for contribution guidelines, test instructions, and the project workflow.

## License

This project is open source under the MIT License - see the bundled `LICENSE` file.

----
If something in this README is incorrect (paths, script names, or behavior), please open an issue or submit a pull request with the fix.
