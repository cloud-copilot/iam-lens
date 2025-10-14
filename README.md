# iam-lens

[![NPM Version](https://img.shields.io/npm/v/@cloud-copilot/iam-lens.svg?logo=nodedotjs)](https://www.npmjs.com/package/@cloud-copilot/iam-lens) [![License: AGPL v3](https://img.shields.io/github/license/cloud-copilot/iam-lens)](LICENSE.txt) [![GuardDog](https://github.com/cloud-copilot/iam-lens/actions/workflows/guarddog.yml/badge.svg)](https://github.com/cloud-copilot/iam-lens/actions/workflows/guarddog.yml) [![Known Vulnerabilities](https://snyk.io/test/github/cloud-copilot/iam-lens/badge.svg?targetFile=package.json&style=flat-square)](https://snyk.io/test/github/cloud-copilot/iam-lens?targetFile=package.json)

Get visibility into the IAM permissions in your AWS organizations and accounts. Use your actual AWS IAM policies (downloaded via [iam-collect](https://github.com/cloud-copilot/iam-collect)) and evaluate the effective permissions.

## Table of Contents

1. [Quick Start](#quick-start)
2. [What is iam-lens?](#what-is-iam-lens)
3. [Why use it?](#why-use-it)
4. [Getting Started](#getting-started)
5. [Commands](#commands)
   - [simulate - Simulate a request](docs/Simulate.md)
   - [who-can - Find who can perform an action on a resource](docs/WhoCan.md)
   - [principal-can - Get a consolidated policy of all permissions for a principal](docs/PrincipalCan.md)
   - [Global CLI Options](docs/GlobalCliOptions.md)
6. [Contributing & Support](#contributing--support)
7. [Acknowledgements](#acknowledgements)

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

**iam-lens** lets you **simulate** and **audit** real IAM requests against your collected IAM data from your AWS accounts (collected via [iam-collect](https://github.com/cloud-copilot/iam-collect)) and understand the effective permissions that apply to a principal or resource.

## Why use it?

- **Understand** the permissions that are actually in place.
- **Verify** allowed and denied outcomes after all policies are deployed.
- **Discover** every principal that can access a given resource.
- **Audit** complex policy combinations across all your AWS accounts and orgs.
- **Debug** complex conditions locally without deployment or network calls.

## Getting Started

1. **Download Your Policies** with [iam-collect](https://github.com/cloud-copilot/iam-collect) to get all policies from your AWS accounts. iam-collect is highly configurable and can be customized to collect the policies you need. It only downloads information to your file system or an S3 bucket, so you're in full control of your data.

```bash
npm install -g @cloud-copilot/iam-collect
iam-collect init
iam-collect download
```

To see the effect of SCPs and RCPs, you should download data from your management account; or an account with permission to download organization information. Download data for member accounts you want to analyze. `iam-lens` will analyze cross-account and cross-organization requests if the data is available.

You can download information for as many accounts, organizations, and regions as you like. The more data you have, the more accurate your answers will be.

2. **Install iam-lens**

```bash
npm install -g @cloud-copilot/iam-lens
```

3. **Execute Commands** with `iam-lens` to simulate requests, discover permissions, and audit your IAM policies.

Simulate a request:

```bash
iam-lens simulate \
  --principal arn:aws:iam::123456789012:role/ExampleRole \
  --resource arn:aws:s3:::example-bucket/secret-file.txt \
  --action s3:GetObject
```

or

Discover who can perform an action on a resource:

```bash
iam-lens who-can \
  --resource arn:aws:iam::111111111111:role/ImportantRole \
  --actions sts:AssumeRole iam:PassRole
```

## Commands

### `simulate` - Simulate a request

Evaluates whether a principal can perform a specified action on a resource (or account for wildcard only actions). Returns a decision: `Allowed`, `ImplicitlyDenied`, or `ExplicitlyDenied`. All [condition keys](docs/Simulate.md#context-keys) are supported and [many context keys are set automatically](docs/Simulate.md#default-context-keys).

[Full simulate documentation](docs/Simulate.md)

```bash
# Simple simulate: can this role list objects in the bucket?
iam-lens simulate \
  --principal arn:aws:iam::111111111111:role/MyRole \
  --resource arn:aws:s3:::my-bucket \
  --action s3:ListBucket

# Simulate a wildcard action (ListAllMyBuckets) – this will assume the principals account
iam-lens simulate \
  --principal arn:aws:iam::222222222222:user/Alice \
  --action s3:ListAllMyBuckets

# Include custom context keys
iam-lens simulate \
  --principal arn:aws:iam::333333333333:role/DevRole \
  --resource arn:aws:sqs:us-east-1:333333333333:my-queue \
  --action sqs:SendMessage \
  --context aws:SourceVpc vpc-1234567890abcdef0 \
  --verbose

# Assert the result must be “Allowed”; exit code will be nonzero if not
iam-lens simulate \
  --principal arn:aws:iam::444444444444:role/ReadOnly \
  --resource arn:aws:dynamodb:us-east-1:444444444444:table/Books \
  --action dynamodb:Query \
  --expect Allowed
```

[Full simulate documentation](docs/Simulate.md)

### `who-can` - Find who can perform an action on a resource

```bash
iam-lens who-can [options]
```

Lists all principals in your IAM data who are allowed to perform one or more specified actions on a resource (or account for wildcard only actions). If applicable it will check the resource policy to find cross-account permissions and AWS service principals.

[Full who-can documentation](docs/WhoCan.md)

**Examples:**

```bash
# Who can get this object?
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket/secret-file.txt \
  --actions s3:GetObject

# Who can list all IAM roles in this account? (wildcard action – no resource)
iam-lens who-can \
  --resource-account 555555555555 \
  --actions iam:ListRoles

# Check multiple actions at once
iam-lens who-can \
  --resource arn:aws:dynamodb:us-east-1:555555555555:table/Books \
  --actions dynamodb:Query dynamodb:UpdateItem

# Check all actions for a bucket
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket
```

[Full who-can documentation](docs/WhoCan.md)

### `principal-can` - Get a consolidated policy of all permissions for a principal

```bash
iam-lens principal-can --principal <arn> [--shrink-action-lists]
```

Creates a consolidated policy document showing all permissions that a principal can perform based on their identity policies, permission boundaries, SCPs, RCPs, and resource policies. The output is a synthesized IAM policy representing the effective permissions after all policy evaluations.

[Full principal-can documentation](docs/PrincipalCan.md)

**Examples:**

```bash
# Get all permissions for a user or role
iam-lens principal-can \
  --principal arn:aws:iam::123456789012:user/Alice

# Get permissions for a role with shrunk action lists
iam-lens principal-can \
  --principal arn:aws:iam::123456789012:role/MyRole \
  --shrink-action-lists
```

[Full principal-can documentation](docs/PrincipalCan.md)

## Contributing & Support

The best way to support is to [open an issue](https://github.com/cloud-copilot/iam-lens/issues) and let us know of any bugs, feature requests, or questions you have. We're always looking for ways to improve the project and make it more useful for everyone.

## Acknowledgements

Special thanks to [Ziyad Almbasher](https://www.linkedin.com/in/ziadmo/) for testing, validating, providing feedback, and for not letting up when the author thinks "this is fine".
