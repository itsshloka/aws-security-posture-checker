"""
Unit tests for scanner.py using unittest.mock to avoid needing real AWS credentials.
Run with: pytest tests/
"""

import sys
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner


def test_check_public_s3_buckets_flags_all_users_grant():
    session = MagicMock()
    s3_client = MagicMock()
    session.client.return_value = s3_client

    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "my-public-bucket"}]}
    s3_client.get_bucket_acl.return_value = {
        "Grants": [
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}
        ]
    }
    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }

    findings = scanner.check_public_s3_buckets(session)
    checks = [f["check"] for f in findings]

    assert "s3_public_acl" in checks
    assert "s3_block_public_access_disabled" in checks


def test_check_permissive_iam_policies_flags_admin_equivalent():
    session = MagicMock()
    iam_client = MagicMock()
    session.client.return_value = iam_client

    paginator = MagicMock()
    iam_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"Policies": [{"Arn": "arn:aws:iam::123:policy/TooOpen", "DefaultVersionId": "v1", "PolicyName": "TooOpen"}]}
    ]
    iam_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        }
    }

    findings = scanner.check_permissive_iam_policies(session)
    assert len(findings) == 1
    assert findings[0]["check"] == "iam_admin_equivalent_policy"


def test_check_stale_access_keys_flags_old_key():
    session = MagicMock()
    iam_client = MagicMock()
    session.client.return_value = iam_client

    paginator = MagicMock()
    iam_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"Users": [{"UserName": "alice"}]}]

    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    iam_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIA123", "CreateDate": old_date}]
    }

    findings = scanner.check_stale_access_keys(session)
    assert len(findings) == 1
    assert findings[0]["check"] == "iam_stale_access_key"


def test_check_open_security_groups_flags_world_open_ssh():
    session = MagicMock()
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "IpPermissions": [
                    {"FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        ]
    }

    findings = scanner.check_open_security_groups(session, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_summarize_counts_severities():
    findings = [
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
    ]
    summary = scanner.summarize(findings)
    assert summary["HIGH"] == 2
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1
