## Contributing to IR Analysis

Thanks for your interest in contributing! This project aims to be welcoming and collaborative. The following guidelines will help your contribution land quickly.

### Where to start

- Find an issue or open a new one describing a bug, feature request or improvement.
- If the change is non-trivial, open an issue first to discuss the approach and API.

### Branches and Pull Requests

1. Fork the repository and create a branch named `topic/short-description` (e.g. `fix/ghidra-timeout`).
2. Commit logically and use clear commit messages; one change per commit where practical.
3. Push your branch and open a pull request against `main`.
4. Describe what you changed and why; link to any open issues.

Suggested PR checklist:

- [ ] Runs without errors locally (see local setup below).
- [ ] Follows existing code style (Bash/Python).
- [ ] Includes tests or a brief manual test plan, if applicable.
- [ ] Updated README or docs when public behavior changes.

### Local development / testing

1. Install system prerequisites (Ubuntu/Debian example):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip time file
```

2. Run the repository setup script (creates a `venv` and installs Python deps):

```bash
./setup.sh
source venv/bin/activate
```

3. Verify scripts and checks before committing:

- Run `./verify_before_commit.sh` to run project-specific pre-commit checks.
- Run `./verify_cfg_implementation.sh` if you changed or added CFG-related logic.

4. Linting and formatting

- Python: follow standard formatting (Black/Flake8 recommended). If adding a new Python dependency, include it in `setup.sh` or requirements used by the project.
- Shell scripts: run `shellcheck` where possible; keep scripts POSIX-friendly unless `bash` features are required.

### Tests

This repository includes validation utilities in `scripts/validation/`. If you add tests, try to keep them self-contained and fast. Include a short `README` in `validation/` if a new test harness is non-trivial.

### Code style notes

- Prefer clear, small functions in Python.
- For bash: prefer functions, defensive checks for required tools, and explicit `set -euo pipefail` when appropriate.

### Security & Responsible Disclosure

This repository may process malware samples. Never upload sensitive or private data when opening an issue or PR. Follow your organization's malware-handling policies.

### Contact

If you need help, open an issue or reach out in the PR comments. Thank you for contributing!
