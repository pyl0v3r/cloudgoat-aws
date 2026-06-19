
# CloudGoat AWS — Consolidated Pentest Summaries

| Report | File |
|---|---|
| SNS Topic Secrets Disclosure | [sns_secrets.md](sns_secrets.md) |
| Beanstalk Secrets & IAM Priv Escalation | [beanstalks_secrets_exposure_iam_privesc.md](beanstalks_secrets_exposure_iam_privesc.md) |
| Lambda Privilege Escalation | [lambda_privesc.md](lambda_privesc.md) |
| EC2 SSRF & IAM Priv Escalation | [ec2_ssrf_iam_privsec.md](ec2_ssrf_iam_privsec.md) |
| S3 Misconfiguration & Leaked Credentials | [aws_s3_misconfig.md](aws_s3_misconfig.md) |

This repository contains five CloudGoat AWS lab writeups. This README consolidates what was tested, the single worst finding from each lab, and executive actions leadership should take to remediate and reduce risk.

Reports included:
- sns_secrets.md — SNS topic disclosure and API Gateway key exposure
- beanstalks_secrets_exposure_iam_privesc.md — Elastic Beanstalk secrets exposure and IAM escalation
- lambda_privesc.md — Lambda-based IAM privilege escalation
- ec2_ssrf_iam_privsec.md — EC2 SSRF, IMDS, and chained escalation
- aws_s3_misconfig.md — Public S3 misconfiguration and leaked credentials

For each report below: a short description of what was tested, the worst thing found, and recommended actions for leadership.

**SNS Secrets (sns_secrets.md)**
- What was tested: SNS topic access policy, ability to subscribe endpoints, and API Gateway exposure. Also used Pacu and AWS CLI to enumerate resources.
- Worst finding: A publicly-subscribable SNS topic leaked a live API Gateway key in plaintext, allowing any subscriber to call a sensitive `/user-data` endpoint.
- Leadership actions:
	- Immediately rotate exposed API keys and revoke subscriptions to the topic.
	- Audit all SNS topic policies for `Principal: "*"` and restrict to explicit principals or account IDs.
	- Stop publishing secrets to notification channels; use AWS Secrets Manager or encrypted messages with restricted KMS keys.

**Elastic Beanstalk Secrets & IAM Privilege Escalation (beanstalks_secrets_exposure_iam_privesc.md)**
- What was tested: Beanstalk environment configuration retrieval and IAM policy review; used discovered credentials to test IAM actions.
- Worst finding: IAM access keys were present in Beanstalk environment variables; the recovered secondary user could call `iam:CreateAccessKey` with `Resource: "*"`, enabling creation of an admin user's keys and full account takeover.
- Leadership actions:
	- Rotate and remove any IAM keys stored in environment variables; migrate to IAM instance profiles or Secrets Manager.
	- Restrict `iam:CreateAccessKey` to the caller's own user ARN and apply permission boundaries.
	- Audit policies for wildcard `CreateAccessKey` or similar escalation primitives and remediate immediately.

**Lambda Privilege Escalation (lambda_privesc.md)**
- What was tested: IAM permissions for `sts:AssumeRole`, role trust relationships, and Lambda `iam:PassRole`/`lambda:*` capabilities.
- Worst finding: A low-privilege user could assume a `lambdaManager` role with `lambda:*` and unrestricted `iam:PassRole`, then create a Lambda using a role that had `AdministratorAccess`, resulting in complete account compromise.
- Leadership actions:
	- Scope `sts:AssumeRole` to specific role ARNs and remove wildcard assume permissions.
	- Scope `iam:PassRole` by resource and use `iam:PassedToService` conditions.
	- Replace broad `lambda:*` with least-privilege action sets and audit roles that trust AWS services.

**EC2 SSRF & IAM Privilege Escalation (ec2_ssrf_iam_privsec.md)**
- What was tested: Lambda and EC2 enumeration, SSRF against web app to access IMDS, S3 bucket inspection using retrieved credentials.
- Worst finding: SSRF to an IMDSv1-enabled EC2 instance allowed theft of instance-role credentials; those credentials led to S3 objects containing plaintext IAM keys, enabling final escalation.
- Leadership actions:
	- Enforce IMDSv2 (`HttpTokens: required`) on all EC2 instances immediately.
	- Harden web applications to validate/whitelist outbound fetch targets and block link-local ranges.
	- Remove any long-lived keys found in S3 and adopt Secrets Manager; enable S3 access logging and scan buckets for credentials.

**S3 Misconfiguration (aws_s3_misconfig.md)**
- What was tested: Public S3 bucket enumeration and retrieval of archived project files; inspection of archive contents for credentials.
- Worst finding: A publicly listable S3 prefix contained an archive with `migrate_secrets.ps1` embedding long-lived AWS credentials, which were used to access restricted data and escalate privileges.
- Leadership actions:
	- Enable S3 Block Public Access at account level; remediate any public prefixes and tighten bucket policies.
	- Rotate any credentials found in artifacts and implement pre-commit/CI scanning to prevent secrets in archives.
	- Move secrets to a managed secrets store and enforce encryption and least privilege on bucket access.

**Overall Highest-Risk Finding (cross-report)**
- Across these labs the single most critical misconfiguration class repeatedly enabling full account compromise was the presence of long-lived credentials (hardcoded or stored in environment/config) combined with overly permissive IAM actions (`iam:CreateAccessKey`, `iam:PassRole`, wildcard `AssumeRole`) or publicly-exposed channels that leak secrets.

**Top Recommendations (prioritized)**
1. Rotate and revoke any exposed or long-lived credentials discovered; treat them as compromised.
2. Audit and remediate IAM policies that use wildcards for sensitive actions (`iam:CreateAccessKey`, `iam:PassRole`, `sts:AssumeRole`) and apply permission boundaries.
3. Enforce secure secret management: use AWS Secrets Manager or SSM Parameter Store (SecureString); remove credentials from code, archives, environment variables, and S3 objects.
4. Enforce IMDSv2 on EC2 and harden web app controls to prevent SSRF (allow-list external fetch targets, block link-local ranges).
5. Audit SNS and S3 resource policies for public or overly broad principals; restrict `Principal: "*"` and enable S3 Block Public Access and access logging.
6. Implement automated checks: pre-commit secret detection, CI scanning for leaked credentials, and CloudTrail/Config rules to detect risky policies.
