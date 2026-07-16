import https from 'https';
import http from 'http';

export function formatFindingsForVince(scans) {
  const findings = [];
  for (const scan of scans) {
    for (const finding of scan.findings || []) {
      findings.push({
        package_name: scan.package_name,
        version: scan.version,
        severity: finding.severity,
        atk_id: finding.atk_id || finding.id,
        title: finding.title,
        description: finding.description,
        evidence: finding.evidence,
      });
    }
  }
  return findings;
}

export function generateVinceReport(scans) {
  const findings = formatFindingsForVince(scans);
  const timestamp = new Date().toISOString();

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (severityCounts.hasOwnProperty(finding.severity)) {
      severityCounts[finding.severity]++;
    }
  }

  return {
    timestamp,
    scanner: 'npm-scan',
    scanner_version: '1.5.0',
    findings_count: findings.length,
    severity_summary: severityCounts,
    findings,
    packages_affected: new Set(findings.map((f) => f.package_name)).size,
  };
}

function makeRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const apiKey = process.env.VINCE_API_KEY;
    if (!apiKey) {
      reject(new Error('VINCE_API_KEY environment variable not set'));
      return;
    }

    const options = {
      hostname: 'vince.cisa.gov',
      port: 443,
      path,
      method,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'npm-scan/1.5.0',
      },
    };

    const request = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, body: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    request.on('error', reject);

    if (body) {
      request.write(JSON.stringify(body));
    }
    request.end();
  });
}

export async function submitToVince(report) {
  if (!report.findings || report.findings.length === 0) {
    return {
      success: true,
      message: 'No findings to report',
      submission_id: null,
    };
  }

  const payload = {
    submission_type: 'vulnerability_report',
    timestamp: report.timestamp,
    findings: report.findings,
    metadata: {
      scanner: report.scanner,
      scanner_version: report.scanner_version,
      packages_affected: report.packages_affected,
    },
  };

  const response = await makeRequest('POST', '/api/v1/submissions', payload);

  if (response.status >= 200 && response.status < 300) {
    return {
      success: true,
      submission_id: response.body.submission_id,
      message: `Report submitted successfully to VINCE`,
    };
  } else {
    throw new Error(
      `VINCE submission failed (${response.status}): ${
        typeof response.body === 'string' ? response.body : JSON.stringify(response.body)
      }`
    );
  }
}

export async function getVinceSubmissionStatus(submissionId) {
  const response = await makeRequest('GET', `/api/v1/submissions/${submissionId}`);

  if (response.status >= 200 && response.status < 300) {
    return response.body;
  } else {
    throw new Error(
      `Failed to fetch submission status (${response.status}): ${
        typeof response.body === 'string' ? response.body : JSON.stringify(response.body)
      }`
    );
  }
}

export function generateVinceReviewSummary(report) {
  const lines = [];
  lines.push('=== VINCE SUBMISSION SUMMARY ===\n');
  lines.push(`Timestamp: ${report.timestamp}`);
  lines.push(`Packages Affected: ${report.packages_affected}`);
  lines.push(`Total Findings: ${report.findings_count}`);
  lines.push(`Critical: ${report.severity_summary.critical}`);
  lines.push(`High: ${report.severity_summary.high}`);
  lines.push(`Medium: ${report.severity_summary.medium}`);
  lines.push(`Low: ${report.severity_summary.low}`);
  lines.push('');
  lines.push('=== FINDINGS ===\n');

  for (const finding of report.findings || []) {
    lines.push(`Package: ${finding.package_name}@${finding.version}`);
    lines.push(`Severity: ${finding.severity.toUpperCase()}`);
    lines.push(`ATK ID: ${finding.atk_id}`);
    lines.push(`Title: ${finding.title}`);
    lines.push(`Description: ${finding.description}`);
    if (finding.evidence) {
      lines.push(`Evidence: ${finding.evidence.substring(0, 200)}...`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
