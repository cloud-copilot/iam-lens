# `principal-can` - Get a consolidated policy of all permissions for a principal

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

| Resource Type           | Same Account | Cross Account |
| ----------------------- | :----------: | :-----------: |
| S3 Bucket Policies      |      ✅      |      ✅       |
| KMS Key Policies        |      ✅      |      ❌       |
| IAM Role Trust Policies |      ✅      |      ❌       |

## Limitations

### Permission Boundaries

There is an [edge case when evaluating implicit denies from permission boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html#access_policies_boundaries-eval-logic). If a resource policy grants access directly to a Role session ARN or a Federated user ARN, it can override the implicit deny from a permission boundary. This behavior is not currently supported in `principal-can`, but `simulate` and `who-can` do incorporate this behavior.

## Cross-Account Evaluation

When evaluating cross-account access, `principal-can` checks resource policies in other accounts that grant access to the principal. For cross-account access to be effective:

1. The resource policy in the resource account must grant access to the principal (either directly or via the account `arn:aws:iam::123456789012:root`)
2. The principal must have corresponding permissions in their identity policies.
3. A permission boundary attached to the principal must allow the action.
4. Any RCPs in the resource account must allow the action.
5. Any SCPs in the principal's account must allow the action.

Cross-account permissions are combined with same-account permissions in the final output.

## IAM Role Trust Policies (`sts:AssumeRole`)

Assuming roles uses a specific permission model. Regardless of what’s in a principal’s identity policies, permission must be explicitly allowed by the role's trust policy. Access can be granted in two ways:

1. Directly to the principal, such as `arn:aws:iam::111222333444:role/MyRole` or `arn:aws:sts::111222333444:assumed-role/MyRole/MySession`.
2. To the principal’s AWS account, such as `arn:aws:iam::111222333444:root`. In this case, the principal must also have permissions in their own identity policies.

Because of this, `principal-can` lists only specific roles that the principal can assume, and it will not show wildcard permissions such as `"Resource": "*"`. For wildcard only role actions (e.g., `iam:ListRoles`), `"Resource": "*"` is expected.

If a role grants access directly to the principal, those assume role permissions are included. If access is granted only to the account, the permissions appear only if the principal’s identity policies also allow assuming the role.

- `principal-can` also includes the **permission-only** STS actions that can be included in a trust policy:
  - `sts:SetContext`
  - `sts:SetSourceIdentity`
  - `sts:TagSession`

- Only `sts:AssumeRole` is considered for role trust evaluation. `sts:AssumeRoleWithSAML` and `sts:AssumeRoleWithWebIdentity` are **not** returned, because IAM users and roles do not call those APIs directly; they are used by federation flows (SAML and OIDC identity providers), not by IAM principals. Support for these may be added in the future.

### Trust policies do **not** grant other role actions

Trust policies are used to determine who can assume a role (plus the permission-only session actions reported alongside it). Other permissions are determined by the regular identity policies, permission boundaries, and SCPs.

- **IAM management actions on the role are unaffected by the trust policy.**
  Examples: `iam:GetRole`, `iam:UpdateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:DeleteRole`, `iam:PassRole`.
  These require corresponding **identity-based** permissions on the caller. Whether the role can be assumed (via the trust policy) does not affect management rights over the role itself.

- **`iam:PassRole` is separate from assuming the role.**
  A caller needs `iam:PassRole` on the role resource in their **own** identity policies to pass it to a service. The target role’s trust policy does not affect `iam:PassRole`.

## KMS Specific Behavior

KMS keys use a different permission model than most AWS services. Regardless of what’s in a principal’s identity policies, access must also be explicitly allowed by the KMS key policy. Access can be granted in two ways:

1. Directly to the principal, such as `arn:aws:iam::111222333444:role/MyRole` or `arn:aws:sts::111222333444:assumed-role/MyRole/MySession`.
2. To the principal’s AWS account, such as `arn:aws:iam::111222333444:root`. In this case, the principal must also have permissions in their own identity policies.

Because of this, `principal-can` lists only specific KMS keys that the principal can access, and it will not show wildcard permissions such as `"Resource": "*"`. For non key–scoped KMS actions (e.g., `CreateKey`, `ListKeys`, `ListAliases`), `"Resource": "*"` is expected.

If a key grants access directly to the principal, those permissions are included. If access is granted only to the account, the permissions appear only if the principal’s identity policies also allow the action.

### Grants

KMS grants provide a third way to authorize use of a key, independent of IAM policies or key policies. A grant can allow a principal to use a key even if their identity policy does not.

Currently, `iam-lens` does **not** enumerate or evaluate KMS grants. If your organization uses grants extensively, use the AWS CLI or console to inspect active grants on a key and validate effective permissions.

### Multi-Region Keys

KMS Multi-Region Keys (MRKs) are evaluated per-replica ARN. Access to a primary key does not automatically grant access to its replicas. Each key in a multi-region pair has its own resource policy and permissions, and `iam-lens` treats them as distinct resources when evaluating access.

### `kms:ViaService` Condition Key

To prevent noisy output, `principal-can` does not include any permissions in key policies that have the `kms:ViaService` condition key.

A common pattern in KMS key policies is to use the `kms:ViaService` condition key to allow a key to be used only when accessed through a specific service. To leverage that permission, the principal must also have access to that service.

For example, this key policy grants **indirect** access to the KMS key **only if the principal is using DynamoDB and has the required DynamoDB permissions**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow access through Amazon DynamoDB for all principals in the account that are authorized to use Amazon DynamoDB",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:CreateGrant",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount": "111122223333"
        },
        "StringLike": {
          "kms:ViaService": "dynamodb.*.amazonaws.com"
        }
      }
    }
  ]
}
```

To prevent noisy output, `principal-can` does not include any permissions in key policies that have the `kms:ViaService` condition key.

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

#### Deny Statements with Multiple Conditions

When a `Deny` statement includes multiple conditions, the logic is a little confusing. It means the request is denied if **all** of the conditions are true, inversely this means the request is allowed if **any** of the conditions are false.

Take this policy for example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["*"]
    },
    {
      "Effect": "Deny",
      "Action": ["s3:GetObject"],
      "Resource": ["*"],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "192.0.2.0/32"
        },
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

This table shows the possible outcomes:

| `aws:SourceIp`          | `aws:SecureTransport` | Result     |
| ----------------------- | --------------------- | ---------- |
| `192.0.2.0` (match)     | `false` (match)       | ❌ Denied  |
| `192.0.2.0` (match)     | `true` (no match)     | ✅ Allowed |
| `172.16.0.0` (no match) | `false` (match)       | ✅ Allowed |
| `172.16.0.0` (no match) | `true` (no match)     | ✅ Allowed |

`principal-can` creates separate `Allow` statements for each condition to accurately represent the resulting permissions. This approach ensures that each conditional deny is properly accounted for in the synthesized policy.

So to start the policy above in a positive way, you can say the principal is allowed to `s3:GetObject` if either:

- The request does not come from the `192.0.2.0/32` IP OR
- The request uses secure transport (HTTPS)

To represent this using only allow statements you can write:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"],
  "Condition": {
    "NotIpAddress": {
      "aws:SourceIp": "192.0.2.0/32"
    }
  }
},
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

So this is exactly what `principal-can` does. It inverts each condition in the `Deny` statement and creates separate `Allow` statements for each condition.

For example, given this `Deny` statement with two different conditions:

```json
{
  "Effect": "Deny",
  "Action": ["s3:GetObject"],
  "Resource": ["*"],
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "192.0.2.0/32"
    },
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```

`principal-can` will create two separate `Allow` statements, one for each condition inverted appropriately:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": ["*"],
  "Condition": {
    "NotIpAddress": {
      "aws:SourceIp": "192.0.2.0/32"
    }
  }
},
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
