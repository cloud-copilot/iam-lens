# `principal-can` - Analyze all permissions for a principal

```bash
iam-lens principal-can --principal <arn> [--shrink-action-lists]
```

Creates a consolidated policy of all permissions that a principal can perform based on their identity policies, permission boundaries, SCPs, RCPs, and [some resource policies](#supported-policies). The output is a policy document showing allowed permissions that result from the evaluation of all applicable policies.

The result is a synthesized policy document that represents the effective permissions the principal has after all policy evaluations.

You can use this:

- As a pen tester or auditor to quickly understand what a principal can do
- As a developer to understand what permissions a role has been granted
- As a security engineer to check for dangerous permissions

## Options

| Flag                          | Description                                                             |
| ----------------------------- | ----------------------------------------------------------------------- |
| `--principal <arn>`           | The principal to check permissions for. Can be a user or role ARN.      |
| `-s`, `--shrink-action-lists` | Shrink action lists to reduce policy size using wildcard consolidation. |

You can also use any of the [Global CLI Options](GlobalCliOptions.md).

## Output Format

The output is ideally a valid IAM policy document that contains only `Allow` statements. There are some complex scenarios where only Allow statements are not possible. In that case Deny statements will be included to accurately represent the effective permissions.

The command returns a standard JSON policy document, such as:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["*"]
    }
  ]
}
```

### Actions List

Only `Action` is included in the output. Any `NotAction` statements are converted to `Action` statements for clarity. The data for this comes from [`@cloud-copilot/iam-data`](https://github.com/cloud-copilot/iam-data) which is updated daily.

All `Action`s in the output are explicit lists without wildcards. This makes it easy for any searching or automation. If you prefer shorter policies, use the `--shrink-action-lists` flag to consolidate actions using wildcards.

## Examples

```bash
# Get all permissions for a user
iam-lens principal-can \
  --principal arn:aws:iam::123456789012:user/Alice

# Get permissions for a role with shrunk action lists
iam-lens principal-can \
  --principal arn:aws:iam::123456789012:role/MyRole \
  --shrink-action-lists

# Analyze permissions across accounts (if cross-account policies exist)
iam-lens principal-can \
  --principal arn:aws:iam::111111111111:role/CrossAccountRole
```

## Supported Policies

This command currently supports the following policy types:

- Identity-based policies (user, role, group)
- Service Control Policies (SCPs)
- Resource Control Policies (RCPs)
- Permission Boundaries

Support for resource-based policies is being added incrementally. The currently supported types are:
| Resource Type | Same Account | Cross Account |
| ------------- | :-----------: | :-----------: |
| S3 Bucket Policies | ✅ | ❌ |

## Limitations

### Permission Boundaries

There is an [edge case when evaluating implicit denies from permission boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html#access_policies_boundaries-eval-logic). If a resource policy grants access directly to a Role session ARN or a Federated user ARN, it can override the implicit deny from a permission boundary. This behavior is not currently supported in `principal-can`, but `simulate` and `who-can` do incorporate this behavior.

## Principal Not Found

```bash
Error: Principal must be provided for principal-can command
```

Ensure you provide a valid principal ARN using the `--principal` flag.
