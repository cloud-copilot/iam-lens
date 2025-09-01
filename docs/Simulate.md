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

| Flag                               | Description                                                                                                                                                                                                                                                                                                             |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--principal <arn>`                | The principal the request is from. Can be a user, role, session, or AWS service.                                                                                                                                                                                                                                        |
| `--resource <arn>`                 | The ARN of the resource to simulate access to. Ignore for wildcard-only actions such as `s3:ListAllMyBuckets`.                                                                                                                                                                                                          |
| `--resource-account <id>`          | The account ID of the resource. Only required if it cannot be determined from the resource ARN or the principal ARN for wildcard only actions.                                                                                                                                                                          |
| `--action <service:action>`        | The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`.                                                                                                                                                                                                                                 |
| `--context <key value1 value2>`    | One or more context keys to use for the simulation. Keys are formatted as `keyA value1 value2`. To specify multiple keys simply provide the argument more than once. For instance `--context keyA valueA1 valueA2 --context keyB valueB1 valueB2` See [Context Keys](#context-keys) for what keys are set automatically |
| `-v`, `--verbose`                  | Enable verbose output for the simulation to see exactly what statements applied or not and why.                                                                                                                                                                                                                         |
| `--expect <result>`                | Optional expected outcome of the simulation. Valid values are `Allowed`, `ImplicitlyDenied`, `ExplicitlyDenied`, `AnyDeny`. If the result does not match the expected value, a non-zero exit code is returned                                                                                                           |
| `-i`, `--ignore-missing-principal` | Ignore if the principal is not found in the data. By default a simulation will fail if the principal is not in your iam-collect data. Use this flag if you want to simulate a request for a principal that may not exist in the downloaded data.                                                                        |

You can also include any [Global CLI Options](GlobalCliOptions.md).

## Using VPC Endpoint Policies

When simulating requests through VPC endpoints, iam-lens can automatically include VPC endpoint policies in the evaluation and set relevant context keys. You can specify either the VPC ID or VPC endpoint ID:

**Option 1: Specify VPC ID** (iam-lens will lookup the appropriate endpoint)

```bash
iam-lens simulate \
  --principal arn:aws:iam::222222222222:user/Alice \
  --action s3:GetObject
  --resource arn:aws:s3:::my-bucket/my-object.txt \
  --context aws:SourceVpc vpc-myvpcid
```

This will:

- Look up the VPC endpoint for S3 within the specified VPC
- Include the VPC endpoint policy in the simulation
- Set `aws:SourceVpce` to the VPC endpoint ID
- Set additional VPC endpoint context keys (see [VPC Endpoint Context Keys](#vpc-endpoint-context-keys))

**Option 2: Specify VPC Endpoint ID directly**

```bash
iam-lens simulate \
  --principal arn:aws:iam::222222222222:user/Alice \
  --action s3:GetObject
  --resource arn:aws:s3:::my-bucket/my-object.txt \
  --context aws:SourceVpce vpce-myvpcendpointid
```

This will:

- Include the VPC endpoint policy in the simulation
- Set `aws:SourceVpc` to the VPC ID that contains the endpoint
- Set additional VPC endpoint context keys (see [VPC Endpoint Context Keys](#vpc-endpoint-context-keys))

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
  --context aws:SourceVpc vpc-1234567890abcdef0 \
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

iam-lens automatically populates the context keys below when simulating requests. These keys are set based on your principal, resource, VPC, and organization data. Any keys provided via `--context` will override the automatically provided values.

Context keys are automatically verified against the [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) and invalid context keys are not included in the simulation.

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

### VPC Endpoint Context Keys

When using VPC endpoints in simulations, iam-lens manages VPC-related context keys and includes VPC endpoint policies in the evaluation:

**Automatic VPC Context Key Population:**

- If you set `aws:SourceVpce` (VPC endpoint ID), iam-lens sets `aws:SourceVpc` to the ID of the VPC containing that endpoint.
- If you set `aws:SourceVpc` (VPC ID), iam-lens sets `aws:SourceVpce` to the VPC endpoint ID (if one exists in the VPC) of the service being simulated.

**VPC Endpoint Policy Inclusion:**

- If `aws:SourceVpce` is set (directly or through `aws:SourceVpc`), [the corresponding VPC endpoint policy is included in the simulation evaluation](#using-vpc-endpoint-policies).

**Additional VPC Endpoint Context Keys:**

For services that support [enhanced VPC endpoint context keys](https://aws.amazon.com/blogs/security/use-scalable-controls-to-help-prevent-access-from-unexpected-networks/) (such as S3), these context keys are set when `aws:SourceVpce` is present:

- **`aws:VpceAccount`** - The account ID that owns the VPC endpoint; e.g., `"123456789012"`
- **`aws:VpceOrgID`** - The organization ID of the VPC endpoint's account (if part of an organization); e.g., `"o-45j328rnf"`
- **`aws:VpceOrgPaths`** - The organizational unit hierarchy path for the VPC endpoint's account (if part of an organization); e.g., `[ "o-45j328rnf/r-483b9/ou-383f84/ou-28fmnf8/" ]`

**Note:** This data may not be available in your iam-collect dataset. For example, if you didn't download it or you are testing VPCs outside your accounts.

### Overriding Default Context Keys

Any context keys supplied via the `--context key value [value2] [value3]` argument will override the defaults described above. For example:

```bash
iam-lens simulate \
  --principal arn:aws:iam::123456789012:user/Alice \
  --resource arn:aws:s3:::my-bucket \
  --action s3:GetObject \
  --context aws:CurrentTime 2025-01-01T00:00:00Z \
  --context aws:PrincipalTag/Env staging
```

In this case, `aws:CurrentTime` and `aws:PrincipalTag/Env` will use the provided values instead of what iam-lens would normally derive.
