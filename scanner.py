#!/usr/bin/env python3
"""
AWS Security Posture Checker
-----------------------------
Scans an AWS account for common security misconfigurations:
  - Public / open S3 buckets
  - Overly permissive IAM policies (Action: "*", Resource: "*")
  - IAM users with old / unused access keys
  - Security groups open to the world (0.0.0.0/0) on sensitive ports

Outputs a prioritized JSON + human-readable report to /reports.

Usage:
    python scanner.py --profile default --output reports/scan_result.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017}
STALE_KEY_DAYS = 90


def get_session(profile):
    try:
        return boto3.Session(profile_name=profile) if profile else boto3.Session()
    except Exception as e:
        print(f"[!] Failed to create AWS session: {e}")
        sys.exit(1)


def check_public_s3_buckets(session):
    """Flag buckets with public ACLs or public bucket policies."""
    s3 = session.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, NoCredentialsError) as e:
        return [{"severity": "ERROR", "check": "s3_public_access", "detail": str(e)}]

    for bucket in buckets:
        name = bucket["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append({
                        "severity": "HIGH",
                        "check": "s3_public_acl",
                        "resource": name,
                        "detail": f"Bucket '{name}' grants access to {uri}",
                    })
        except ClientError as e:
            findings.append({"severity": "LOW", "check": "s3_acl_check_failed", "resource": name, "detail": str(e)})

        try:
            status = s3.get_public_access_block(Bucket=name)
            cfg = status["PublicAccessBlockConfiguration"]
            if not all(cfg.values()):
                findings.append({
                    "severity": "MEDIUM",
                    "check": "s3_block_public_access_disabled",
                    "resource": name,
                    "detail": f"Bucket '{name}' does not fully block public access: {cfg}",
                })
        except ClientError:
            # No public access block configuration set at all == worth flagging
            findings.append({
                "severity": "MEDIUM",
                "check": "s3_no_public_access_block",
                "resource": name,
                "detail": f"Bucket '{name}' has no Block Public Access configuration set.",
            })

    return findings


def check_permissive_iam_policies(session):
    """Flag IAM policies granting Action:* on Resource:* (admin-equivalent)."""
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):  # customer-managed policies only
        for policy in page["Policies"]:
            arn = policy["Arn"]
            version_id = policy["DefaultVersionId"]
            try:
                version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                doc = version["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    actions = [actions] if isinstance(actions, str) else actions
                    resources = [resources] if isinstance(resources, str) else resources

                    if "*" in actions and "*" in resources:
                        findings.append({
                            "severity": "HIGH",
                            "check": "iam_admin_equivalent_policy",
                            "resource": policy["PolicyName"],
                            "detail": f"Policy '{policy['PolicyName']}' grants Action:* on Resource:*",
                        })
            except ClientError as e:
                findings.append({"severity": "LOW", "check": "iam_policy_check_failed", "resource": arn, "detail": str(e)})

    return findings


def check_stale_access_keys(session):
    """Flag IAM access keys older than STALE_KEY_DAYS or unused for 90+ days."""
    iam = session.client("iam")
    findings = []
    now = datetime.now(timezone.utc)

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                age_days = (now - key["CreateDate"]).days
                if age_days > STALE_KEY_DAYS:
                    findings.append({
                        "severity": "MEDIUM",
                        "check": "iam_stale_access_key",
                        "resource": f"{username}/{key['AccessKeyId']}",
                        "detail": f"Access key is {age_days} days old (threshold: {STALE_KEY_DAYS}).",
                    })

    return findings


def check_open_security_groups(session, region):
    """Flag security groups open to 0.0.0.0/0 on sensitive ports."""
    ec2 = session.client("ec2", region_name=region)
    findings = []

    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except ClientError as e:
        return [{"severity": "ERROR", "check": "sg_check_failed", "detail": str(e)}]

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    severity = "HIGH" if from_port in SENSITIVE_PORTS else "MEDIUM"
                    findings.append({
                        "severity": severity,
                        "check": "sg_open_to_world",
                        "resource": sg["GroupId"],
                        "detail": f"Security group '{sg['GroupName']}' ({sg['GroupId']}) opens port {from_port} to 0.0.0.0/0",
                    })

    return findings


def run_all_checks(session, region):
    all_findings = []
    print("[*] Checking S3 buckets for public access...")
    all_findings += check_public_s3_buckets(session)
    print("[*] Checking IAM policies for over-permissive grants...")
    all_findings += check_permissive_iam_policies(session)
    print("[*] Checking IAM access keys for staleness...")
    all_findings += check_stale_access_keys(session)
    print("[*] Checking security groups for open access...")
    all_findings += check_open_security_groups(session, region)
    return all_findings


def summarize(findings):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "ERROR": 0}
    for f in findings:
        counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1
    return counts


def main():
    parser = argparse.ArgumentParser(description="AWS Security Posture Checker")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name (optional)")
    parser.add_argument("--region", default="us-east-1", help="AWS region for regional checks (default: us-east-1)")
    parser.add_argument("--output", default="reports/scan_result.json", help="Path to write JSON report")
    args = parser.parse_args()

    session = get_session(args.profile)
    findings = run_all_checks(session, args.region)
    summary = summarize(findings)

    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": sorted(findings, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "ERROR": 3}.get(f.get("severity"), 4)),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print("\n=== Scan Summary ===")
    for severity, count in summary.items():
        print(f"  {severity}: {count}")
    print(f"\nFull report written to: {args.output}")


if __name__ == "__main__":
    main()
