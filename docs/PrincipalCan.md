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

## How Permissions are Combined

Different policy statements may have overlapping or duplicate permissions. For instance, you may have two `Allow` statements for the same action but with different resources.

### Combining Statements

For instance, this:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"]
}
```

and:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::another-bucket/*"]
}
```

Would be combined into:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::another-bucket/*"]
}
```

### Overlapping Statements

It's possible for one statement to completely include another. For instance:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"]
}
```

and

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"]
}
```

These statements would be simplified to:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"]
}
```

Because the `"Resource": ["*"]` statement already includes all resources, including `arn:aws:s3:::my-bucket/*`.

These transformations ensure the resulting policy accurately expresses the principal's effective permissions with the fewest statements possible.

### Combining Conditions

When combining `Allow` statements with conditions, `principal-can` attempts to merge them when possible. For instance, if you have:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "true"
    }
  }
}
```

and

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::another-bucket/*"],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "true"
    }
  }
}
```

These would be combined into:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::another-bucket/*"],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "true"
    }
  }
}
```

If it's not possible to combine conditions safely, `principal-can` keeps them separate to ensure the resulting policy accurately represents the intended permissions.

In this example, the conditions can't be combined because they apply to different VPC endpoints and resources. For instance, if you have:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-111111111111"
    }
  }
}
```

and

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::another-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-222222222222"
    }
  }
}
```

These would be kept separate because the conditions can't be combined:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-111111111111"
    }
  }
},
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::another-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-222222222222"
    }
  }
}
```

If two conditions differ only by multiple allowed values for the same key (for example, several `aws:SourceVpce` values in an array), `principal-can` will merge them into a single condition with multiple values. However, conditions using different keys or operators are always kept separate.

For instance, if you have:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-111111111111"
    }
  }
}
```

and

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-222222222222"
    }
  }
}
```

These would be combined into:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"],
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": ["vpce-111111111111", "vpce-222222222222"]
    }
  }
}
```

These would be combined into a single statement because the `Action` and `Resource` are the same, and the conditions differ only by multiple allowed values for the same key.

These rules for merging and separating conditions ensure that the resulting policy remains both accurate and minimal, without changing its effective permissions.

### Merging Allow and Deny Statements

If there is no overlap between `Allow` and `Deny` statements, the `Deny` statements are simply dropped. Since `principal-can` is focused on creating a policy of what the principal can do, any explicit denies that do not overlap with allows are irrelevant.

If there is overlap, the `principal-can` attempts to convert them to `Allow` statements.

#### Allow minus a Deny

For instance, if you have:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"]
}
```

and

```json
{
  "Effect": "Deny",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::special-bucket/*"]
}
```

The result would be:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "NotResource": ["arn:aws:s3:::special-bucket/*"]
}
```

### Allow with Deny Permissions

If there is a `Deny` statement that adds conditions to an `Allow` statement, `principal-can` will invert the deny conditions and attach them to the `Allow` statement to accurately represent the effective permissions.
For instance, if you have:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"]
}
```

and

```json
{
  "Effect": "Deny",
  "Action": ["s3:GetObject"],
  "Resource": ["*"],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```

The result would be:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "true"
    }
  }
}
```

### Keeping Deny Statements

In some scenarios, it is not possible to merge a `Deny` statement with the existing `Allow` statements. If that happens the deny statement is kept in the output to accurately represent the effective permissions.

For instance, if you have:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"]
}
```

and

```json
{
  "Effect": "Deny",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/secret-folder/*"]
}
```

It's impossible to create an allow statement that includes only the allowed objects in the bucket so both statements are kept in the output:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/*"]
},
{
  "Effect": "Deny",
  "Action": ["s3:GetObject"],
  "Resource": ["arn:aws:s3:::my-bucket/secret-folder/*"]
}
```
