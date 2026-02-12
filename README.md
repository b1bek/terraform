# TFC Enum

A Python script to enumerate Terraform Cloud (TFC) resources using a list of API tokens. It gathers information about organizations, workspaces, variables, and runs, and attempts to download state files to extract sensitive outputs.

## Features

- **Enumeration**: Lists Organizations, Teams, Policy Sets, Agent Pools, and Workspaces.
- **Variable Inspection**: Displays workspace variables, including values (even for sensitive variables if available in state outputs).
- **State Downloading**: Automatically attempts to download the latest state file for each workspace.
- **Sensitive Data Extraction**: Parses downloaded state files to find root module outputs that might contain secrets.
- **Resume Capability**: Tracks processed tokens to allow resuming interrupted scans.
- **Logging**: Outputs results to both console and `tfc_enum_output.txt`.

## Prerequisites

- Python 3.x
- `uv` (recommended for dependency management)

## Installation & Usage

1. **Prepare your tokens file**:
   Create a file named `tokens.txt` with one TFC API token per line.

2. **Run with `uv`**:
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install requests
   python tfc_enum.py tokens.txt
   ```

## Output

- **Console/Log**: Detailed enumeration results.
- **`states/` directory**: Downloaded JSON state files (e.g., `states/workspace-name_sv-xxxx.json`).
- **`tfc_enum_output.txt`**: Full log of the enumeration session.
- **`tfc_enum_resume.log`**: Tracks hashes of processed tokens to support resuming.

## Security Note

This tool is intended for security assessment and authorized auditing purposes only. Ensure you have permission to scan the target Terraform Cloud accounts.
