# AWS S3 Misconfiguration — Penetration Test Report

## Objective and Scope

The objective of this assessment was to evaluate the security posture of the **Huge Logistics** development environment hosted on AWS, focusing on S3 bucket access controls, credential management practices, and the potential for privilege escalation via exposed AWS IAM credentials.

## Scope of Work

**In-Scope Assets:**
- **Target:** `http://dev.huge-logistics.com/`
- **Infrastructure:** AWS S3 (static site hosting), AWS IAM
- **Testing Perspective:** Unauthenticated external attacker with no prior knowledge of the environment

---

## Enumeration

### Infrastructure Identification

Initial inspection of `dev.huge-logistics.com` revealed the site is hosted on **AWS S3**, and the S3 bucket name was identified directly from the domain:

```
dev.huge-logistics.com
```

### Unauthenticated S3 Bucket Enumeration

Using the AWS CLI without credentials (`--no-sign-request`), the bucket's top-level contents were listed:

```bash
aws s3 ls s3://dev.huge-logistics.com --no-sign-request
```

```
PRE admin/
PRE migration-files/
PRE shared/
PRE static/
    index.html
```

Access attempts against `admin/` and `migration-files/` returned `AccessDenied`. However, the `shared/` prefix was publicly listable and contained a downloadable file:

```bash
aws s3 ls s3://dev.huge-logistics.com/shared/ --no-sign-request
```

```
hl_migration_project.zip
```

### Tools Used
- AWS CLI
- `aws sts get-caller-identity`

---

## Vulnerabilities

| Vulnerability | Severity | Impact |
|---|---|---|
| Publicly Accessible S3 Bucket Prefix Exposing Sensitive Archive | High | Credential disclosure enabling authenticated AWS access |
| Hardcoded AWS IAM Credentials in Migration Script | Critical | Authenticated access to restricted S3 content |
| Credentials Export File Containing Plaintext Multi-System Credentials | Critical | Full compromise of AWS production account and multiple downstream services |
| Sensitive Customer PII and Payment Data Accessible via Escalated IAM Credentials | Critical | Mass disclosure of customer financial data |

---

### Publicly Accessible S3 Bucket Prefix Exposing Sensitive Archive

#### Severity
High

#### CWE
CWE-732: Incorrect Permission Assignment for Critical Resource

#### OWASP Category
OWASP Top 10 2021 – A05: Security Misconfiguration

#### Description
The `shared/` prefix of the `dev.huge-logistics.com` S3 bucket was configured with public read access, allowing unauthenticated users to list its contents and download files without any credentials. This prefix contained `hl_migration_project.zip`, a migration project archive that included a PowerShell script with hardcoded AWS credentials.

#### Affected Functionality
- `s3://dev.huge-logistics.com/shared/`

#### Steps to Reproduce
1. Identify the S3 bucket name from the target domain.
2. List the bucket contents without credentials:
   ```bash
   aws s3 ls s3://dev.huge-logistics.com --no-sign-request
   ```
3. Identify the accessible `shared/` prefix and list its contents:
   ```bash
   aws s3 ls s3://dev.huge-logistics.com/shared/ --no-sign-request
   ```
4. Download the exposed archive:
   ```bash
   aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip . --no-sign-request
   ```

#### Proof of Concept
The archive was successfully downloaded without authentication. Extracting it revealed `migrate_secrets.ps1`, containing hardcoded AWS IAM credentials (see next finding).

#### Impact
- Unauthenticated access to a sensitive file containing AWS credentials
- Provides the initial foothold for all subsequent findings in this report

#### Root Cause
The `shared/` S3 prefix was configured with a public bucket policy or ACL granting `s3:ListBucket` and `s3:GetObject` to unauthenticated principals, likely as a convenience during development without consideration of the sensitivity of files stored there.

#### Recommendation
- Set all S3 bucket prefixes to private by default; enable public access only where explicitly required for static assets
- Enable **S3 Block Public Access** at the account level to prevent accidental public exposure
- Audit existing bucket policies and ACLs regularly to identify unintended public access
- Avoid storing credential material, configuration files, or migration scripts in any S3 prefix that is or could become publicly accessible

#### References
- OWASP Top 10 2021 – A05: Security Misconfiguration
- CWE-732
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)

---

### Hardcoded AWS IAM Credentials in Migration Script

#### Severity
Critical

#### CWE
- CWE-798: Use of Hard-coded Credentials
- CWE-522: Insufficiently Protected Credentials

#### OWASP Category
OWASP Top 10 2021 – A07: Identification and Authentication Failures

#### Description
The `migrate_secrets.ps1` script contained hardcoded AWS IAM access key and secret key in plaintext. These credentials belonged to the IAM user `pam-test` and granted authenticated access to the AWS environment, including the ability to read the previously inaccessible `migration-files/` S3 prefix.

#### Affected Functionality
- `migrate_secrets.ps1` (within `hl_migration_project.zip`)
- IAM user: `pam-test`

#### Steps to Reproduce
1. Extract `hl_migration_project.zip` and open `migrate_secrets.ps1`.
2. Locate the hardcoded credentials:
   ```
   Access Key ID:     AKIA3SFMDAPO7WLZVRVE
   Secret Access Key: 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
   ```
3. Configure the AWS CLI with these credentials:
   ```bash
   aws configure --profile pwnedlabss3
   ```
4. Confirm identity:
   ```bash
   aws sts get-caller-identity --profile pwnedlabss3
   ```

#### Proof of Concept
`aws sts get-caller-identity` confirmed successful authentication as:
```json
{
    "UserId": "AIDA3SFMDAPOYPM3X2TB7",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/pam-test"
}
```
Using these credentials, the previously access-denied `migration-files/` prefix was accessible, and `test-export.xml` was downloaded — containing further credentials for multiple systems (see next finding).

#### Impact
- Authenticated access to the AWS environment as `pam-test`
- Access to restricted S3 content containing multi-system credential exports
- Credential compromise persists until the key is rotated, regardless of whether the script is removed

#### Root Cause
AWS credentials were embedded directly in a script file as plaintext, which was then committed to a project archive and stored in a publicly accessible S3 location. This is a common pattern when developers use static credentials during development and fail to rotate or remove them before sharing project files.

#### Recommendation
- Never hardcode AWS credentials in scripts, configuration files, or code — use IAM roles, AWS Secrets Manager, or environment variables instead
- Immediately rotate any credentials that may have been exposed in a file accessible to unauthorized parties
- Implement pre-commit hooks (e.g. `git-secrets`, `truffleHog`) to detect credential patterns before they enter source control or project archives
- Apply least-privilege IAM policies to service/migration accounts — `pam-test` should have access only to the specific resources required for its migration task

#### References
- OWASP Top 10 2021 – A07: Identification and Authentication Failures
- CWE-798, CWE-522
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

---

### Credentials Export File Containing Plaintext Multi-System Credentials

#### Severity
Critical

#### CWE
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-284: Improper Access Control

#### OWASP Category
OWASP Top 10 2021 – A02: Cryptographic Failures

#### Description
The `migration-files/test-export.xml` file, accessible using the `pam-test` credentials, contained plaintext credentials for multiple critical systems across the organization. Among these was a second, higher-privileged set of AWS IAM credentials belonging to the `it-admin` user, enabling full escalation of AWS access.

#### Affected Functionality
- `s3://dev.huge-logistics.com/migration-files/test-export.xml`

#### Steps to Reproduce
1. Using the `pam-test` profile, download the credentials export:
   ```bash
   aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml . --profile pwnedlabss3
   ```
2. Review the file contents for embedded credentials.

#### Proof of Concept
`test-export.xml` contained plaintext credentials for the following systems:

| System | Username | Notes |
|---|---|---|
| Oracle Database | admin | Primary financial application DB |
| HP Server Cluster | root | Batch job infrastructure |
| AWS IT Admin | it-admin (IAM) | Production AWS workloads |
| Iron Mountain Backup | hladmin | Tape backup portal |
| Office 365 | admin@company.onmicrosoft.com | Global admin account |
| Jira | jira_admin | Atlassian admin account |

The AWS IT Admin credentials (`AKIA3SFMDAPO6DGDLJAG`) were configured as a second CLI profile and verified:
```bash
aws sts get-caller-identity --profile pwnedlabss3_2
```
```json
{
    "UserId": "AIDA3SFMDAPOWKM6ICH4K",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/it-admin"
}
```

#### Impact
- Complete credential exposure for six critical organizational systems
- Escalation to `it-admin` IAM user with access to production AWS workloads and the restricted `admin/` S3 prefix
- Potential for full AWS account compromise, database access, and takeover of Office 365 global admin — effectively full organizational compromise

#### Root Cause
Credentials for multiple systems were consolidated into a single plaintext XML file and stored in an S3 bucket accessible to a low-privilege IAM user. Credential exports of this kind should never be stored in cloud object storage, and certainly not in plaintext.

#### Recommendation
- Never store credential exports in plaintext — use a secrets management solution (AWS Secrets Manager, HashiCorp Vault) for all system credentials
- Immediately rotate all credentials present in the exposed file
- Apply strict least-privilege IAM policies — `pam-test` should not have had access to a file containing `it-admin` credentials
- Enforce S3 bucket policies that restrict access to credential-containing files to only the specific principals that require them
- Treat credential exports as highly sensitive artifacts — encrypt them at rest and in transit, and delete them immediately after use

#### References
- OWASP Top 10 2021 – A02: Cryptographic Failures
- CWE-312, CWE-284
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)

---

### Sensitive Customer PII and Payment Data Accessible via Escalated IAM Credentials

#### Severity
Critical

#### CWE
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- CWE-284: Improper Access Control

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
Using the `it-admin` IAM credentials recovered from the credentials export, the previously inaccessible `admin/` S3 prefix became fully readable. This prefix contained `website_transactions_export.csv`, a file holding sensitive customer transaction data including full payment card details and account credentials for 29 customers.

#### Affected Functionality
- `s3://dev.huge-logistics.com/admin/`
- `website_transactions_export.csv`

#### Steps to Reproduce
1. Using the `it-admin` profile, list and download the contents of the `admin/` prefix:
   ```bash
   aws s3 cp s3://dev.huge-logistics.com/admin/flag.txt . --profile pwnedlabss3_2
   aws s3 cp s3://dev.huge-logistics.com/admin/website_transactions_export.csv . --profile pwnedlabss3_2
   ```
2. Review the CSV file contents.

#### Proof of Concept
`website_transactions_export.csv` contained 29 rows of customer data including:

- Full Visa credit card numbers (PAN)
- CVV codes
- Card expiry dates
- Cardholder names
- Application usernames and plaintext passwords
- Customer IP addresses

A sample row:
```
Visa, 4055497191304, 386, 5/2021, Hunter Miller, hunter_m, password123, 34.56.78.90
```

Additionally, the flag confirming full compromise was retrieved:
```
flag.txt: a49f18145568e4d001414ef1415086b8
```

#### Impact
- Mass exposure of customer PII, full payment card data (PAN + CVV + expiry), and plaintext passwords for 29 customers
- In a real environment this would constitute a **PCI DSS breach** and likely a **GDPR reportable incident**
- Plaintext customer passwords enable credential stuffing against other services
- Represents the terminal step in a complete attack chain from unauthenticated S3 access to full data breach

#### Root Cause
Customer payment and credential data was stored in an S3 bucket without encryption controls sufficient to prevent access by any IAM user with `s3:GetObject` on the `admin/` prefix. The broader root cause is the chain of misconfigurations and credential exposures that allowed an unauthenticated attacker to escalate to `it-admin` in the first place.

#### Recommendation
- Never store raw payment card data (PAN, CVV, expiry) in plaintext in any storage system — this violates PCI DSS requirements regardless of access controls
- Never store user passwords in plaintext — hash using a strong, salted algorithm (bcrypt, argon2)
- Apply strict IAM policies limiting access to customer data to only the specific roles and services that require it
- Enable S3 server-side encryption (SSE-S3 or SSE-KMS) for all buckets containing sensitive data
- Implement S3 access logging and CloudTrail to detect unauthorized access to sensitive prefixes
- Conduct a PCI DSS and GDPR impact assessment for any environment where this configuration has been in place

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-359, CWE-284
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [AWS S3 Encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html)

---

## Attack Chain Summary

1. Identified the target as an AWS S3-hosted site and derived the bucket name from the domain
2. Enumerated the bucket without credentials — found `shared/` prefix publicly accessible
3. Downloaded `hl_migration_project.zip` and extracted `migrate_secrets.ps1` containing hardcoded IAM credentials for `pam-test`
4. Authenticated to AWS as `pam-test` and accessed the restricted `migration-files/` prefix
5. Retrieved `test-export.xml` — a plaintext credentials export containing keys for six organizational systems including an `it-admin` IAM user
6. Authenticated as `it-admin` using the escalated credentials
7. Accessed the restricted `admin/` prefix and retrieved `website_transactions_export.csv` — 29 rows of customer PAN, CVV, expiry, and plaintext password data

## Key Takeaways

- S3 bucket names derived from domain names are trivially discoverable — never rely on obscurity for access control
- A single publicly accessible prefix containing a credential file is sufficient to compromise an entire AWS environment
- Hardcoded credentials in migration scripts are a systemic risk — secrets management tooling must be a prerequisite for any cloud migration project
- Consolidating credentials for multiple systems into a single exportable file dramatically increases blast radius if that file is exposed
- Customer PAN and CVV data must never be stored in plaintext — the moment an attacker reaches storage-layer access, the breach is complete
- Each step in this chain (public bucket → hardcoded creds → credential export → escalated IAM → customer data) was preventable independently; fixing any one of them would have broken the attack chain