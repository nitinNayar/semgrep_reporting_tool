# Semgrep Reporter

A powerful Python utility that transforms Semgrep security findings into customizable, visually appealing PDF and CSV reports. Streamline your security reporting workflow by connecting directly to the Semgrep API to generate professional, presentation-ready security documentation for both SAST (Static Application Security Testing) and SCA (Software Composition Analysis) findings.

## Features

- 🔍 Direct integration with Semgrep API
- 📊 Beautiful visualization charts
- 📑 Multiple output formats (PDF, CSV, Excel)
- 🎨 Customizable report appearance
- 🏷️ Filtering by repositories, tags, and severity levels
- 🎯 Company logo integration
- 📈 Summary statistics and trends
- 🔐 Separate reports for SAST and SCA findings
- 📦 Detailed dependency vulnerability information

## Installation

### Using pip

```bash
pip install semgrep-reporter
```

### Using Poetry (for development)

```bash
# Clone the repository
git clone https://github.com/nitinNayar/semgrep_reporting_tool.git
cd semgrep-reporter

# Install dependencies
poetry install
```

## Usage

### Basic Usage

```bash
# Set your Semgrep API token and deployment slug
export SEMGREP_API_TOKEN="your-api-token"
export SEMGREP_DEPLOYMENT_SLUG="your-deployment-slug"

# Generate SAST (Code Analysis) report
semgrep-reporter sast

# Generate SCA (Software Composition Analysis) report
semgrep-reporter sca

# Generate both reports with specific formats
semgrep-reporter sast --format pdf --format csv
semgrep-reporter sca --format pdf --format csv
```

### Advanced Options

```bash
# Generate SAST report with filters
semgrep-reporter sast \
    --api-token "your-api-token" \
    --deployment-slug "your-deployment-slug" \
    --repository myorg/repo1 \
    --repository myorg/repo2 \
    --severity ERROR

# Generate SCA report with customization
semgrep-reporter sca \
    --deployment-slug "your-deployment-slug" \
    --company-logo path/to/logo.png \
    --report-title "Dependency Vulnerabilities Report - Q1 2024" \
    --output-dir ./reports/q1_2024

# Filter by tags (works for both SAST and SCA)
semgrep-reporter sast --tag production --tag critical
semgrep-reporter sca --tag production --tag critical
```

### All Available Options

```bash
# View SAST command options
semgrep-reporter sast --help

# View SCA command options
semgrep-reporter sca --help
```

## Configuration

The tool can be configured using command-line options or environment variables:

| Environment Variable | Description |
|---------------------|-------------|
| SEMGREP_API_TOKEN | Your Semgrep API token |
| SEMGREP_DEPLOYMENT_SLUG | Your Semgrep deployment slug |
| SEMGREP_REPORTER_OUTPUT_DIR | Default output directory |

## Report Types

### SAST Reports (Code Analysis)
Generated using `semgrep-reporter sast`:
- Static code analysis findings
- Code snippets with syntax highlighting
- Rule-based security issues
- Custom code vulnerabilities

### SCA Reports (Dependency Analysis)
Generated using `semgrep-reporter sca`:
- Dependency vulnerability findings
- Package ecosystem information
- CVE details and references
- Reachability analysis
- Fixed version recommendations

## Report Formats

### PDF Report
- Executive summary
- Severity distribution charts
- Detailed findings with syntax highlighting
- Company branding integration
- Type-specific information (SAST/SCA)

### CSV Report
- Complete findings data in tabular format
- Easy to import into spreadsheet software
- Ideal for further analysis
- Type-specific fields (SAST/SCA)

### Excel Report
- Multiple worksheets for findings and summaries
- Pivot tables for quick analysis
- Charts and graphs
- Separate sheets for SAST and SCA data

## Output Directory Structure

Reports are organized by type in separate directories:

```
reports/
├── sast/
│   ├── semgrep_report.pdf
│   ├── semgrep_findings.csv
│   └── semgrep_findings.xlsx
└── sca/
    ├── semgrep_report.pdf
    ├── semgrep_findings.csv
    └── semgrep_findings.xlsx
```

## Development

### Running Tests

```bash
poetry run pytest
```

### Code Style

This project uses:
- Black for code formatting
- isort for import sorting
- mypy for type checking

To run all checks:

```bash
poetry run black .
poetry run isort .
poetry run mypy .
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
