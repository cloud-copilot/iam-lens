# `simulate` - Simulate an IAM request

```bash
iam-lens simulate [options]
```

Evaluates whether a principal can perform a specified action on a resource (or account for wildcard only actions). Returns a decision: `Allowed`, `ImplicitlyDenied`, or `ExplicitlyDenied`.

Simulations can be run for any principal type (user, role, assumed role, federated user, or AWS service) and any resource type (S3 bucket, DynamoDB table, etc.). The simulation will evaluate all policies that apply to the principal and resource, including:

- Identity policies (inline and managed)
- Resource policies ([supported resource types](https://github.com/cloud-copilot/iam-collect?tab=readme-ov-file#supported-services-and-data))
- Resource Access Manager (RAM) Shares
- Service control policies (SCPs)
- Resource control policies (RCPs)
- Permission boundaries

Simulations support both inclusive and exclusive statement fields such as `Principal`, `NotPrincipal`, `Action`, `NotAction`, `Resource`, `NotResource`, `Condition`, and `Effect`. [All condition operators are supported](#supported-condition-keys).

## Cross Account and Organization Requests

When simulating requests, iam-lens will detect the account for the principal and resource. If the accounts are different accounts, cross-account permissions will be evaluated. If the accounts are in different organizations or different organizational units in the same organization, iam-lens will use the correct SCPs for the principal and RCPs for the resource.

## Options

| Flag                               | Description                                                                                                                                                                                                                                                          |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--principal <arn>`                | The principal the request is from. Can be a user, role, session, or AWS service.                                                                                                                                                                                     |
| `--resource <arn>`                 | The ARN of the resource to simulate access to. Ignore for wildcard-only actions such as `s3:ListAllMyBuckets`.                                                                                                                                                       |
| `--resource-account <id>`          | The account ID of the resource. Only required if it cannot be determined from the resource ARN or the principal ARN for wildcard only actions.                                                                                                                       |
| `--action <service:action>`        | The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`.                                                                                                                                                                              |
| `--context <key=value>`            | One or more context keys to use for the simulation. Keys are formatted as `keyA=value1,value2 keyB=value1,value2`. Multiple keys are separated by spaces. Multiple values separated by commas. See [Context Keys](#context-keys) for what keys are set automatically |
| `-v`, `--verbose`                  | Enable verbose output for the simulation to see exactly what statements applied or not and why.                                                                                                                                                                      |
| `--expect <result>`                | Optional expected outcome of the simulation. Valid values are `Allowed`, `ImplicitlyDenied`, `ExplicitlyDenied`, `AnyDeny`. If the result does not match the expected value, a non-zero exit code is returned                                                        |
| `-i`, `--ignore-missing-principal` | Ignore if the principal is not found in the data. By default a simulation will fail if the principal is not in your iam-collect data. Use this flag if you want to simulate a request for a principal that may not exist in the downloaded data.                     |

You can also include any [Global CLI Options](GlobalCliOptions.md).

## Examples

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
  --context aws:SourceVpc=vpc-1234567890abcdef0 \
  --verbose

# Assert the result must be “Allowed”; exit code will be nonzero if not
iam-lens simulate \
  --principal arn:aws:iam::444444444444:role/ReadOnly \
  --resource arn:aws:dynamodb:us-east-1:444444444444:table/Books \
  --action dynamodb:Query \
  --expect Allowed
```

## Supported Condition Keys

iam-lens supports [all IAM condition operators](https://iam.cloudcopilot.io/resources/operators) when simulating policy evaluation. This is for all policy types including identity policies, permission boundaries, resource policies, service control policies (SCPs), and resource control policies (RCPs). This allows you to fully simulate all policy conditions for all policy types.

## Context Keys

iam-lens will automatically populate context keys (see below) and allows you to override them with the `--context` argument. Context keys are automatically verified against the [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) and invalid context keys are not included in the simulation.

iam-lens automatically populates the context keys below when simulating requests. These keys are set based on your principal, resource, and organization data. Any keys provided via `--context` will override the defaults.

## Using VPC Endpoint Policies

To simulate requests through VPC endpoints you can specify either the VPC id or the VPC endpoint id as part of the context. For example:

```bash
iam-lens simulate \
  --principal arn:aws:iam::222222222222:user/Alice \
  --action s3:GetObject
  --resource arn:aws:s3:::my-bucket/my-object.txt \
  --context aws:SourceVpc=vpc-myvpcid
```

Will automatically look up the VPC endpoint for S3 within VPC `vpc-myvpcid` and include the endpoint policy in the simulation. It will also automatically set the context key `aws:SourceVpce` to the VPC endpoint id.

If you know the VPC endpoint id you can specify it directly. For example:

```bash
iam-lens simulate \
  --principal arn:aws:iam::222222222222:user/Alice \
  --action s3:GetObject
  --resource arn:aws:s3:::my-bucket/my-object.txt \
  --context aws:SourceVpce=vpce-myvpcendpointid
```

Will lookup the VPC endpoint and include the endpoint policy in the simulation. It will also automatically set the context key for `aws:SourceVpc` to the VPC id that endpoint is in.

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
  Set to `true` for all service principals.

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

Any context keys supplied via the `--context key=value[,value2,…]` argument will override the defaults described above. For example:

```bash
iam-lens simulate \
  --principal arn:aws:iam::123456789012:user/Alice \
  --resource arn:aws:s3:::my-bucket \
  --action s3:GetObject \
  --context aws:CurrentTime=2025-01-01T00:00:00Z aws:PrincipalTag/Env=staging
```

In this case, `aws:CurrentTime` and `aws:PrincipalTag/Env` will use the provided values instead of what iam-lens would normally derive.
