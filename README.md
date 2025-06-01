# iam-lens

[![NPM Version](https://img.shields.io/npm/v/@cloud-copilot/iam-lens.svg?logo=nodedotjs)](https://www.npmjs.com/package/@cloud-copilot/iam-lens) [![License: AGPL v3](https://img.shields.io/github/license/cloud-copilot/iam-lens)](LICENSE.txt) [![GuardDog](https://github.com/cloud-copilot/iam-lens/actions/workflows/guarddog.yml/badge.svg)](https://github.com/cloud-copilot/iam-lens/actions/workflows/guarddog.yml) [![Known Vulnerabilities](https://snyk.io/test/github/cloud-copilot/iam-lens/badge.svg?targetFile=package.json&style=flat-square)](https://snyk.io/test/github/cloud-copilot/iam-lens?targetFile=package.json)

## iam-lens

Get visibility into the actual IAM permissions in your AWS organizations and accounts. Use your actual AWS IAM policies (downloaded via [iam-collect](https://github.com/cloud-copilot/iam-collect)) and evaluate the effective permissions.

## Quick Start

```bash
# Install
npm install -g @cloud-copilot/iam-collect @cloud-copilot/iam-lens

# Download all IAM policies in your account using default credentials, run download once per account
iam-collect init
iam-collect download

# Simulate a request
iam-lens simulate --principal arn:aws:iam::123456789012:role/ExampleRole --resource arn:aws:s3:::example-bucket/secret-file.txt --action s3:GetObject

# Find out who can do something
iam-lens who-can --resource arn:aws:s3:::example-bucket --actions s3:ListBucket

# Find out who can do all actions on a resource
iam-lens who-can --resource arn:aws:s3:::example-bucket
```

## What is iam-lens?

iam-lens uses real IAM data from your AWS accounts (collected via [iam-collect](https://github.com/cloud-copilot/iam-collect)) to quickly simulate requests and discover the real effective permissions that apply to a principal or resource.

## Why use it?

1. **Understand** what permissions are actually in place and why. See the policies that determine the outcome of a request.
2. **Verify** what's allowed or not after everything is deployed.
3. **Discover** who can take action on a sensitive resource with a single command.
4. **Audit** your IAM policies and ensure they are configured correctly.
5. **Debug** permissions by simulating requests locally and iterate quickly without needing to deploy changes to your AWS environment.

## Getting Started

1. **Download Your Policies** with [iam-collect](https://github.com/cloud-copilot/iam-collect) to get all your policies from all your AWS accounts. iam-collect is highly configurable and can be customized to collect the policies you need. It only downloads information to your file system or an S3 bucket, so you're in full control of your data.

```bash
npm install -g @cloud-copilot/iam-collect
iam-collect init
iam-collect download
```

To see the effect of SCPs and RCPs, you should download data from your management account; or an account with permissions to download organization information. Download data for member accounts you want to analyze. `iam-lens` will analyze cross-account and cross-organization requests if you have the data available.

You can download information for as many accounts, organizations, and regions as you like. The more data you have, the more accurate your simulations will be.

2. **Install iam-lens**

```bash
npm install -g @cloud-copilot/iam-lens
```

3. **Execute Commands** with `iam-lens` to simulate requests, discover permissions, and audit your IAM policies.

Simulate a request:

```bash
iam-lens simulate --principal arn:aws:iam::123456789012:role/ExampleRole --resource arn:aws:s3:::example-bucket/secret-file.txt --action s3:GetObject
```

or

Discover who can perform an action on a resource:

```bash
iam-lens who-can --resource arn:aws:iam::111111111111:role/ImportantRole --actions sts:AssumeRole iam:PassRole
```

## Commands

### `simulate` - Simulate an IAM request

```bash
iam-lens simulate [options]
```

Evaluates whether a principal can perform a specified action on a resource (or wildcard). Returns a decision (Allowed/ImplicitlyDenied/ExplicitlyDenied), and exits nonzero if you provided an `--expect` that doesn’t match the result.

**Options:**

| Flag                        | Description                                                                                                                                                                                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--principal <arn>`         | The principal the request is from. Can be a user, role, session, or AWS service.                                                                                                                                                                                     |
| `--resource <arn>`          | The ARN of the resource to simulate access to. Ignore for wildcard-only actions such as `s3:ListAllMyBuckets`.                                                                                                                                                       |
| `--resource-account <id>`   | The account ID of the resource, only required if it cannot be determined from the resource ARN.                                                                                                                                                                      |
| `--action <service:action>` | The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`.                                                                                                                                                                              |
| `--context <key=value>`     | One or more context keys to use for the simulation. Keys are formatted as `keyA=value1,value2 keyB=value1,value2`. Multiple keys are separated by spaces. Multiple values separated by commas. See [Context Keys](#context-keys) for what keys are set automatically |
| `-v, --verbose`             | Enable verbose output for the simulation (exactly what statements applied or not and why).                                                                                                                                                                           |
| `--expect <result>`         | Optional expected outcome of the simulation. Valid values are `Allowed`, `ImplicitlyDenied`, `ExplicitlyDenied`, `AnyDeny`. If the result does not match the expected value, a non-zero exit code is returned                                                        |

**Examples:**

```bash
# Simple simulate: can this role list objects in the bucket?
iam-lens simulate \
  --principal arn:aws:iam::111111111111:role/MyRole \
  --resource arn:aws:s3:::my-bucket \
  --action s3:ListBucket

# Simulate a wildcard action (ListAllMyBuckets) – this will assume the principals account
iam-lens simulate \
  --principal arn:aws:iam::222222222222:user/Alice \
  --action s3:ListAllMyBuckets \

# Include custom context keys
iam-lens simulate \
  --principal arn:aws:iam::333333333333:role/DevRole \
  --resource arn:aws:sqs:us-east-1:333333333333:my-queue \
  --action sqs:SendMessage \
  --context aws:SourceVpc=vpc-1234567890abcdef0 \
  --verbose

# Assert the result must be “Allowed”; exit code will be nonzero if not
iam-lens simulate \
  --principal arn:aws:iam::444444444444:role/ReadOnly \
  --resource arn:aws:dynamodb:us-east-1:444444444444:table/Books \
  --action dynamodb:Query \
  --expect Allowed
```

### `who-can` - Find who can perform an action on a resource

```bash
iam-lens who-can [options]
```

Lists all principals in your IAM data who are allowed to perform one or more specified actions on a resource (or wildcard). If applicable it will check the resource policy to find cross-account permissions and AWS service principals.

**Options:**

| Flag                         | Description                                                                                                                                                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--resource <arn>`           | The ARN of the resource to check permissions for. Ignore for wildcard-only actions such as `iam:ListRoles`                                                                                                             |
| `--resource-account <id>`    | The account ID of the resource, only required if it cannot be determined from the resource ARN. Required for wildcard actions such as `ec2:DescribeInstances`                                                          |
| `--actions <service:action>` | One or more actions to check such as `s3:GetObject`. Specify as many actions as you want. If omitted it will analyze all valid actions for the resource. If no `--resource` is specified then actions must be entered. |

**Examples:**

```bash
# Who can get this object?
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket/secret-file.txt \
  --actions s3:GetObject

# Who can list all IAM roles in any account? (wildcard action – no resource)
iam-lens who-can \
  --resource-account 555555555555 \
  --actions iam:ListRoles

# Check multiple actions at once
iam-lens who-can \
  --resource arn:aws:dynamodb:us-east-1:555555555555:table/Books \
  --actions dynamodb:Query dynamodb:UpdateItem
```

### Global Options:

These options are available for all commands:

| Flag                       | Description                                                           | Default             |
| -------------------------- | --------------------------------------------------------------------- | ------------------- |
| `--collectConfigs <files>` | One or more `iam-collect` config files to use for fetching IAM data.  | `iam-collect.jsonc` |
| `--partition <partition>`  | The AWS partition (`aws`, `aws-cn`, `aws-us-gov`). Defaults to `aws`. | `aws`               |

## Context Keys

Below are the context keys that iam-lens populates by default during simulation. These keys are set based on your principal, resource, and organization data. Any keys provided via `--context` will override the defaults.

### Default Context Keys

- **`aws:SecureTransport`**
  Always set to `true` to indicate the request is using a secure channel.

- **`aws:CurrentTime`**
  ISO 8601 timestamp of when the simulation is run (e.g., `2025-06-01T12:34:56.789Z`).

- **`aws:EpochTime`**
  Unix epoch time in seconds (e.g., `1717290896`).

#### IAM Principal Context

- **`aws:PrincipalArn`**
  The full ARN of the principal (user, role, role session, or federated user) being simulated.

- **`aws:PrincipalAccount`**
  The AWS account ID extracted from the principal ARN.

- **`aws:PrincipalOrgId`** _(if the account is in an organization)_
  The Organization ID that owns the principal’s account.

- **`aws:PrincipalOrgPaths`** _(if the account is in an organization)_
  A list containing a single string of the form `<OrgId>/<OU1>/<OU2>/…/` indicating the account’s path in the OU hierarchy.

- **`aws:PrincipalTag/<TagKey>`**
  For each tag on the IAM principal, a context key of the form `aws:PrincipalTag/<TagKey>` with its tag value.

- **`aws:PrincipalIsAWSService`**
  Set to `false` for all IAM principals (users, roles, federated users).

- **`aws:PrincipalType`**
  One of: `Account`, `User`, `FederatedUser`, `AssumedRole`, indicating the type of principal.

- **`aws:userid`**
  The unique identifier for the principal session:

  - For a root principal: the account ID
  - For a user: the IAM user’s unique ID (or `UNKNOWN` if not found)
  - For a federated user: `<AccountId>:<FederatedName>`
  - For an assumed role: `<RoleUniqueId>:<SessionName>`

  Setting `role-id:ec2-instance-id` for EC2 instances is not supported at this time.

- **`aws:username`** _(only for IAM users)_
  The IAM username portion of the principal ARN (e.g. `Alice`).

#### Service Principal Context

The following context keys are set when the principal is an AWS service (e.g., `lambda.amazonaws.com`, `ec2.amazonaws.com`):

- **`aws:PrincipalServiceName`**
  The service principal string (e.g. `lambda.amazonaws.com`).

- **`aws:SourceAccount`**
  The account ID of the resource.

- **`aws:SourceOrgID`**
  The organization ID of the resource’s account (if part of an organization).

- **`aws:SourceOrgPaths`**
  The OU hierarchy path for the resource’s account (if part of an organization).

- **`aws:PrincipalIsAWSService`**
  Set to `true` for all service principals. Set to `false` for all IAM principals (users, roles, federated users).

#### Resource Context ([unless action is excluded](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-resourceaccount))

- **`aws:ResourceAccount`**
  The AWS account ID of the resource.

- **`aws:ResourceOrgID`**
  The Organization ID for the resource’s account (if part of an organization).

- **`aws:ResourceOrgPaths`** _(if the resource account is in an organization)_
  A list containing a single string of the form `<OrgId>/<OU1>/<OU2>/…/` for the resource’s account (if part of an organization).

- **`aws:ResourceTag/<TagKey>`**
  For each tag on the resource ARN, a context key `aws:ResourceTag/TagKey` with its tag value. **This is only for resources that are stored in your `iam-collect` data**, such as Roles, S3 Buckets, DynamoDB Tables, etc. For resources not stored in `iam-collect`, this key should be set manually.

### Overriding Default Context Keys

Any context keys supplied via the `--context key=value[,value2,…]` option will override the defaults described above. For example:

```bash
iam-lens simulate \
  --principal arn:aws:iam::123456789012:user/Alice \
  --resource arn:aws:s3:::my-bucket \
  --action s3:GetObject \
  --context aws:CurrentTime=2025-01-01T00:00:00Z aws:PrincipalTag/Env=staging
```

In this case, `aws:CurrentTime` and `aws:PrincipalTag/Env` will use the provided values instead of what iam-lens would normally derive.
