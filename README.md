# dns-record-resolution-check.py

Bulk DNS validation tool for F5 XC nameserver. Reads expected DNS records from Excel, queries both `ns1.f5clouddns.com` and `ns2.f5clouddns.com` via `dig`, and writes pass/fail results back to an output spreadsheet.

## Prerequisites

- Python 3.7+, `dig` in PATH
- `pip install pandas openpyxl requests`

## Configuration

Edit the constants at the top of the script:

| Variable | Description |
|---|---|
| `API_TOKEN` | F5 XC API token |
| `TENANT` | Your XC tenant name |
| `ZONE_NAME` | Target DNS zone |

## Input

Place `dns_records_f5_input.xlsx` in the working directory with columns: `SUBDOMAIN`, `RECORD TYPE`, `VALUE`.

## Usage

```bash
python dns-record-resolution-check.py
```

When prompted, enter a namespace to filter results or press Enter for all. Output is saved as `output_<namespace>.xlsx` with `RESULT_NS1` and `RESULT_NS2` columns showing `SUCCESS` or `FAILURE` per record.
