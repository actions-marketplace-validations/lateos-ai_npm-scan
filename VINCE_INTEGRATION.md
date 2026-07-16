# VINCE Integration

npm-scan now supports submitting vulnerability findings to [VINCE](https://www.cisa.gov/vince/) (Vulnerability Information and Coordination Environment), CISA's vulnerability coordination platform.

## Setup

### Prerequisites

1. **VINCE Membership**: You must be registered with VINCE at https://www.cisa.gov/vince/
2. **API Key**: Obtain your VINCE API key from your VINCE account settings

### Configuration

Set your VINCE API key as an environment variable:

```bash
# macOS/Linux
export VINCE_API_KEY=your_api_key_here

# Windows PowerShell
[Environment]::SetEnvironmentVariable('VINCE_API_KEY', 'your_api_key_here', 'User')

# Verify
echo $env:VINCE_API_KEY
```

## Usage

### Workflow: Manual Review with Claude

The VINCE integration requires manual review via Claude before submission. This prevents accidental disclosure of sensitive vulnerability information.

#### Step 1: Scan and Generate Report

```bash
npm-scan scan lodash > scan_result.json
```

#### Step 2: Review with Claude

In Claude Code, review the scan results and the VINCE summary:

```bash
npm-scan submit-vince scan_result.json
```

This will output:
- A detailed summary of all findings
- Package count and severity breakdown
- Individual findings with evidence

#### Step 3: Approve and Submit

Once Claude reviews the findings and you approve (either in the conversation or by confirming here), submit with:

```bash
npm-scan submit-vince scan_result.json --auto-approve
```

### Example Flow

```bash
# 1. Scan multiple packages
npm-scan scan axios > axios.json
npm-scan scan lodash > lodash.json

# 2. Combine results (optional, for batch submission)
jq -s '.' axios.json lodash.json > combined.json

# 3. Review with Claude
npm-scan submit-vince combined.json

# 4. After Claude approval, submit
npm-scan submit-vince combined.json --auto-approve
```

## Features

### Report Format

VINCE submissions include:

- **Timestamp**: When the report was generated
- **Scanner Info**: npm-scan v1.5.0
- **Findings Count**: Total number of findings
- **Severity Summary**: Breakdown by critical/high/medium/low
- **Package Details**: Affected packages and versions
- **Full Findings**: Complete details with evidence

### Submission Status

After successful submission, you'll receive:

```json
{
  "success": true,
  "submission_id": "VINCE-2026-12345",
  "message": "Report submitted successfully to VINCE"
}
```

Use the submission ID to track your report in VINCE.

## Security Considerations

1. **API Key Protection**: Never commit your API key to version control
2. **Manual Review**: All submissions require Claude review before submission
3. **Selective Reporting**: Only submit high-confidence findings
4. **Sensitive Data**: Ensure evidence doesn't leak proprietary code
5. **Coordination**: VINCE handles vendor coordination, so you don't submit directly to affected parties

## Troubleshooting

### "VINCE_API_KEY environment variable not set"

Ensure your API key is set:

```bash
# Check if set
echo $VINCE_API_KEY

# Set it
export VINCE_API_KEY=your_key_here
```

### "VINCE submission failed (401)"

Your API key is invalid or expired:

1. Check your VINCE account settings
2. Regenerate the API key if needed
3. Update your environment variable

### "No findings to report"

The scan found no security issues. Only meaningful findings are submitted.

## Integration with CI/CD

For automated scanning without VINCE submission:

```bash
npm-scan scan <package> --fail-on high
```

For manual VINCE submission in CI/CD:

```bash
# Store scan results
npm-scan scan <package> > results.json

# Later, with human approval:
npm-scan submit-vince results.json --auto-approve
```

## References

- [VINCE Official Site](https://www.cisa.gov/vince/)
- [npm-scan GitHub](https://github.com/lateos-ai/npm-scan)
- [CISA Vulnerability Coordination](https://www.cisa.gov/coordinate-vulnerability-reports)
