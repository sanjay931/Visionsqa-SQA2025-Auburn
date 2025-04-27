## CI/CD Pipeline

VisionSQA implements a comprehensive CI/CD pipeline using GitHub Actions and pre-commit hooks to ensure code quality and security at every stage of development.

### GitHub Workflow (fuzz.yml)

The project uses a GitHub workflow defined in `.github/workflows/fuzz.yml` that automatically runs security and quality checks:

```yaml
name: Enhanced Fuzzing Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Run weekly on Sundays

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
    - name: Checkout repo
      uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install atheris pyyaml ruamel.yaml

    - name: Create directories
      run: |
        mkdir -p fuzz_corpus
        touch fuzz_errors.log

    - name: Cache fuzzing corpus
      uses: actions/cache@v3
      with:
        path: fuzz_corpus
        key: ${{ runner.os }}-fuzz-corpus-${{ github.sha }}
        restore-keys: |
          ${{ runner.os }}-fuzz-corpus-

    - name: Run fuzzing script
      run: |
        export FUZZ_ITERATIONS=50000
        export MAX_EXECUTION_TIME=30
        
        timeout 45m python3 fuzz.py || true

    - name: Upload fuzz artifacts
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: fuzz-results
        path: |
          fuzz_errors.log
          fuzz_stats.json
          fuzz_corpus/
        if-no-files-found: warn
```

#### How the Workflow is Triggered

The GitHub workflow is automatically triggered by:

1. **Push Events**: Any push to the `main` branch
2. **Pull Requests**: Any pull request targeting the `main` branch
3. **Scheduled Runs**: Weekly runs on Sundays to ensure continuous testing

#### What the Workflow Does

1. Sets up the Python environment
2. Installs necessary dependencies
3. Configures the fuzzing environment
4. Runs the fuzzing script with a time limit
5. Uploads fuzzing results as artifacts for review
6. Caches the fuzzing corpus for future runs

### Pre-commit Hooks Integration

Pre-commit hooks work alongside the GitHub workflow to ensure code quality before code is even committed:

#### Pre-commit Hook Workflow

1. When you run `git commit`, the pre-commit hook in `.git/hooks/pre-commit` is automatically executed
2. The hook runs a series of checks on your code:
   - Code formatting checks
   - Static code analysis
   - Security scans
   - Custom VisionSQA checks
3. If any check fails, the commit is blocked, and you must fix the issues
4. Once all checks pass, the commit proceeds normally

#### Integration with CI/CD

The pre-commit hooks act as the first line of defense in the CI/CD pipeline:

```
Developer Workflow:
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │    │                 │
│  Code Changes   │───▶│  Pre-commit     │───▶│  GitHub         │───▶│  Review &       │
│                 │    │  Hooks          │    │  Workflow       │    │  Deployment     │
│                 │    │                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Adding Custom Checks

You can modify the pre-commit hook to add custom checks by editing the `.githooks/pre-commit` file before running `./install-hooks.sh`:

```bash
# Example of adding a custom check to the pre-commit hook
echo '#!/bin/bash

# Run standard linting
flake8 .

# Run custom VisionSQA check
python slikube.py --self-check

# Exit with error if any check failed
if [ $? -ne 0 ]; then
  echo "Pre-commit checks failed!"
  exit 1
fi' > .githooks/pre-commit

# Install the updated hook
./install-hooks.sh
```

### Complete Pipeline Flow

The complete CI/CD pipeline works as follows:

1. **Local Development**:
   - Developer makes code changes
   - Pre-commit hooks run automatically when committing
   - Immediate feedback on code quality issues

2. **GitHub Integration**:
   - Code is pushed to GitHub
   - GitHub workflow (fuzz.yml) is triggered
   - Fuzzing tests run in the GitHub Actions environment
   - Results are stored as artifacts

3. **Continuous Monitoring**:
   - Weekly scheduled runs catch regressions
   - Cached corpus builds up over time, improving test coverage
   - Artifacts provide historical data for trend analysis

This integrated approach ensures that code quality and security are maintained throughout the development lifecycle, with multiple layers of protection against potential issues.# VisionSQA - Security, Quality, and Forensics Assessment Tool

VisionSQA is a comprehensive security, quality, and forensics assessment tool specifically designed for Kubernetes environments. It helps identify misconfigurations, vulnerabilities, quality issues, and provides forensic capabilities for your Kubernetes YAML files.

[![Run Fuzz Tests](https://github.com/sanjay931/Visionsqa-SQA2025-Auburn/actions/workflows/fuzz.yml/badge.svg)](https://github.com/sanjay931/Visionsqa-SQA2025-Auburn/actions/workflows/fuzz.yml)

## Features

- Static analysis of Kubernetes YAML files
- Detection of common security misconfigurations
- Quality assessment for Kubernetes resources
- JSON/YAML parsing and validation
- Fuzzing capability for robust testing
- Forensic analysis for incident investigation

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Docker](#docker)
- [Pre-commit Hooks](#pre-commit-hooks)
- [Fuzzing](#fuzzing)
- [Forensics](#forensics)
- [CI/CD Pipeline](#cicd-pipeline)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Python 3.8+
- Docker (optional, for containerized usage)
- Git (for pre-commit hooks)

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/sanjay931/Visionsqa-SQA2025-Auburn.git
cd Visionsqa-SQA2025-Auburn

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage
python slikube.py -i <path-to-your-kubernetes-yaml>

# Help
python slikube.py --help
```

## Docker

Using VisionSQA with Docker is the recommended way to ensure consistent behavior across different environments.

### Building the Docker Image

```bash
# Build the Docker image
docker build -t slikube .
```

### Running VisionSQA in Docker

```bash
# Run VisionSQA with Docker, mounting the output directory
docker run --rm -v "$(pwd)/output:/results" docker.io/library/slikube
```

### Custom Flags with Docker

```bash
# Example of running with custom flags
docker run --rm -v "$(pwd)/output:/results" -v "$(pwd)/your-yamls:/input" docker.io/library/slikube -i /input

# Run forensic analysis with Docker
docker run --rm -v "$(pwd)/output:/results" -v "$(pwd)/your-yamls:/input" docker.io/library/slikube -f -i /input
```

## Pre-commit Hooks

VisionSQA provides pre-commit hooks to ensure your code meets quality standards before commits.

### Installing Pre-commit Hooks

```bash
# Make the install script executable (if needed)
chmod +x install-hooks.sh

# On macOS, you might need to remove quarantine attribute
xattr -d com.apple.quarantine install-hooks.sh

# Install the pre-commit hooks
./install-hooks.sh

# Ensure the pre-commit hook is executable
chmod +x .git/hooks/pre-commit
```

### Troubleshooting Pre-commit Hooks

If you're having issues with pre-commit hooks:

```bash
# Make sure the pre-commit hook is executable
chmod +x .git/hooks/pre-commit

# On macOS, you might need to remove quarantine attribute
xattr -d com.apple.quarantine .git/hooks/pre-commit
```

## Fuzzing

VisionSQA includes a comprehensive fuzzing framework to ensure the robustness of its parsing and analysis functions.

### Installing Fuzzing Dependencies

```bash
# Install Atheris for fuzzing
pip install atheris

# Alternative installation method using pipx
brew install pipx  # On macOS
pipx install atheris
```

### Running the Fuzzer

```bash
# Basic fuzzing run
python fuzz.py

# Run with specific iterations
FUZZ_ITERATIONS=100000 python fuzz.py

# Run with a different timeout value (in seconds)
MAX_EXECUTION_TIME=60 python fuzz.py
```

### Fuzzing Results

Fuzzing results are stored in the following files:

- `fuzz_errors.log`: Detailed log of all errors encountered during fuzzing
- `fuzz_stats.json`: Statistics about the fuzzing run
- `fuzz_corpus/`: Directory containing interesting inputs that triggered bugs

### CI/CD Integration

The GitHub workflow automatically runs fuzzing tests on every push and pull request to the main branch. You can view the results in the GitHub Actions tab.

## Forensics

VisionSQA includes powerful forensics capabilities to help investigate security incidents and compliance violations in Kubernetes environments.

### Running Forensic Analysis

```bash
# Basic forensic analysis
python slikube.py -f -i <path-to-your-kubernetes-yaml>

# Generate detailed forensic report
python slikube.py -f --report-format=full -i <path-to-your-kubernetes-yaml>

# Extract specific forensic artifacts
python slikube.py -f --extract-artifacts -i <path-to-your-kubernetes-yaml>
```

### Forensic Capabilities

- **Historical Analysis**: Examine changes to Kubernetes resources over time
- **Incident Response**: Identify potential breach indicators and vulnerable configurations
- **Compliance Verification**: Validate resources against compliance frameworks (CIS, NIST, PCI-DSS)
- **Artifact Extraction**: Extract and preserve key artifacts for further investigation
- **Chain of Custody**: Maintain proper forensic documentation for findings

### Forensic Reports

Forensic reports are generated in the `output/forensics/` directory and include:

- `summary_report.json`: Overview of key findings
- `detailed_analysis.json`: In-depth analysis of each resource
- `compliance_report.json`: Compliance status for relevant frameworks
- `artifacts/`: Directory containing extracted forensic artifacts
- `timeline.json`: Chronological sequence of events (if available)

## Development

### Project Structure

```
.
├── slikube.py              # Main application
├── parser.py               # YAML/JSON parsing utilities
├── fuzz.py                 # Fuzzing framework
├── forensics/              # Forensics analysis modules
│   ├── analyzer.py         # Core forensics functionality
│   ├── artifacts.py        # Artifact extraction utilities
│   └── report.py           # Report generation utilities
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker configuration
├── install-hooks.sh        # Pre-commit hook installer
├── .githooks/              # Git hooks templates
│   └── pre-commit          # Pre-commit hook template
├── .github/workflows/      # GitHub Actions workflows
│   └── fuzz.yml            # Fuzzing workflow configuration
└── output/                 # Default output directory
    ├── reports/            # Analysis reports
    └── forensics/          # Forensic analysis results
```

### Adding New Features

1. Create a new branch for your feature
2. Implement your changes
3. Add tests (including fuzz tests if appropriate)
4. Submit a pull request

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.