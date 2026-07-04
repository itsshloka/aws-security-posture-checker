# AWS Security Posture Checker

A Python tool that scans an AWS account for common, high-impact security misconfigurations and produces a prioritized, machine-readable report — the kind of check a security analyst would run before an audit or as part of routine hygiene.

This project grew out of a cloud security lab where I identified exposed S3 buckets and overly permissive IAM policies through manual review; this tool automates that same review so it can run repeatably and be extended over time.

## What it checks

| Check | Severity | Why it matters |
|---|---|---|
| Public S3 bucket ACLs / policies | HIGH | Publicly accessible buckets are one of the most common cloud data-leak causes |
| S3 Block Public Access not fully enabled | MEDIUM | Leaves a bucket one misconfigured policy away from public exposure |
| IAM policies granting `Action:"*"` on `Resource:"*"` | HIGH | Effectively grants admin access; violates least-privilege |
| Stale IAM access keys (90+ days old) | MEDIUM | Old, unrotated keys increase blast radius if leaked |
| Security groups open to `0.0.0.0/0` on sensitive ports (SSH, RDP, DB ports) | HIGH/MEDIUM | Direct internet exposure of admin or database ports |

## How it works

`scanner.py` uses `boto3` to query S3, IAM, and EC2 APIs, evaluates each resource against a defined security baseline, and writes results to a JSON report sorted by severity (HIGH → MEDIUM → LOW).

## Getting started

```bash
# 1. Clone and install dependencies
git clone https://github.com/<your-username>/aws-security-posture-checker.git
cd aws-security-posture-checker
pip install -r requirements.txt

# 2. Configure AWS credentials (read-only IAM user recommended)
aws configure --profile security-audit

# 3. Run the scan
python scanner.py --profile security-audit --region us-east-1 --output reports/scan_result.json
```

### Required IAM permissions (read-only)

The scanning user/role needs at minimum:
- `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`
- `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:ListUsers`, `iam:ListAccessKeys`
- `ec2:DescribeSecurityGroups`

No write permissions are required — this tool only reads configuration, it does not remediate.

## Sample output

See [`reports/sample_scan_result.json`](reports/sample_scan_result.json) for an example report against a demo account. Console output looks like:

```
[*] Checking S3 buckets for public access...
[*] Checking IAM policies for over-permissive grants...
[*] Checking IAM access keys for staleness...
[*] Checking security groups for open access...

=== Scan Summary ===
  HIGH: 2
  MEDIUM: 3
  LOW: 0
  ERROR: 0

Full report written to: reports/scan_result.json
```

## Running tests

Tests use mocked AWS clients (`unittest.mock`), so no real AWS account or credentials are needed:

```bash
pip install pytest
pytest tests/ -v
```

## Roadmap / planned improvements

- [ ] Add checks for RDS publicly accessible instances and unencrypted volumes
- [ ] Add CloudTrail logging-enabled check
- [ ] Support multi-account scanning via AWS Organizations
- [ ] Add a `--remediate` flag with dry-run output for safe auto-fixes (e.g., enabling Block Public Access)
- [ ] Export report as HTML for non-technical stakeholders
- [ ] Add GitHub Actions workflow to run the scanner on a schedule against a sandbox account

## Disclaimer

This tool only performs read-only checks and is intended for accounts you own or have explicit authorization to scan.
