# Agent Instructions for iam-lens

This document provides comprehensive instructions for LLMs to help customers effectively use iam-lens, a powerful AWS IAM policy analysis tool.

## Overview

**iam-lens** is a command-line tool that helps users understand AWS IAM permissions by analyzing real IAM policies downloaded from their AWS accounts. It provides simulation, auditing, and discovery capabilities to understand effective permissions across complex policy combinations.

## Prerequisites and Setup

### 1. Data Collection with iam-collect

Before using iam-lens, customers MUST first collect their IAM data using `iam-collect`:

```bash
# Install both tools
npm install -g @cloud-copilot/iam-collect @cloud-copilot/iam-lens

# Initialize and download IAM data (run once per account)
iam-collect init
iam-collect download
```

**Important**: For comprehensive analysis, recommend downloading from:

- Management account (for SCPs and RCPs)
- All member accounts they want to analyze
- Multiple regions if they use region-specific resources

### 2. Configuration Files

By default, iam-lens looks for `./iam-collect.jsonc` configuration file. Users can specify different config files using `--collectConfigs`.

## Core Commands

### 1. simulate - Policy Simulation

**Purpose**: Test if a specific principal can perform a specific action on a specific resource.

**Syntax**:

```bash
iam-lens simulate --principal <arn> --action <service:action> [--resource <arn>] [options]
```

**Key Options**:

- `--principal <arn>`: The principal making the request (user, role, session, or AWS service)
- `--action <service:action>`: The action to test (e.g., `s3:GetObject`)
- `--resource <arn>`: The target resource (omit for wildcard actions like `s3:ListAllMyBuckets`)
- `--resource-account <id>`: Required for wildcard actions or when resource account cannot be determined
- `--context <key value1 value2>`: Add context keys for condition evaluation
- `--verbose`: Show detailed JSON analysis of how the result was determined, including which specific policies and statements allowed or denied the request. Also includes the context that was automatically populated in the request.
- `--expect <result>`: Assert expected outcome (`Allowed`, `ImplicitlyDenied`, `ExplicitlyDenied`)
- `--ignore-missing-principal`: Continue if principal not found in data

**Returns**:

- Simple mode: `Allowed`, `ImplicitlyDenied`, or `ExplicitlyDenied`
- Verbose mode: Detailed JSON analysis showing exactly which policies, statements, and conditions led to the decision

**Common Use Cases**:

- Troubleshooting access issues
- Validating policy changes
- Security testing scenarios
- Compliance auditing

**Examples**:

```bash
# Basic simulation
iam-lens simulate \
  --principal arn:aws:iam::123456789012:role/MyRole \
  --resource arn:aws:s3:::my-bucket/file.txt \
  --action s3:GetObject

# Wildcard action (no resource)
iam-lens simulate \
  --principal arn:aws:iam::123456789012:user/Alice \
  --action s3:ListAllMyBuckets

# With context keys and verbose output
iam-lens simulate \
  --principal arn:aws:iam::123456789012:role/DevRole \
  --resource arn:aws:sqs:us-east-1:123456789012:my-queue \
  --action sqs:SendMessage \
  --context aws:SourceVpc vpc-1234567890abcdef0 \
  --verbose

# Assert expected result
iam-lens simulate \
  --principal arn:aws:iam::123456789012:role/ReadOnly \
  --resource arn:aws:dynamodb:us-east-1:123456789012:table/Books \
  --action dynamodb:Query \
  --expect Allowed
```

### 2. who-can - Permission Discovery

**Purpose**: Find all principals who can perform specified actions on a resource.

**Syntax**:

```bash
iam-lens who-can [--resource <arn>] [--actions <service:action>] [options]
```

**Key Options**:

- `--resource <arn>`: The target resource to check permissions for
- `--resource-account <id>`: Required for wildcard actions or when resource account cannot be determined
- `--actions <service:action>`: One or more actions to check (if omitted, checks all valid actions for the resource)

**Returns**: List of principals with their effective permissions AND the specific conditions under which access is allowed or denied. If access depends on specific context keys or conditions, those details are included in the output.

**Common Use Cases**:

- Security auditing ("who has access to this sensitive resource?")
- Access reviews and cleanup
- Understanding resource exposure
- Compliance reporting
- Incident response investigations

**Examples**:

```bash
# Who can access a specific S3 object?
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket/secret-file.txt \
  --actions s3:GetObject

# Who can perform wildcard actions in an account?
iam-lens who-can \
  --resource-account 555555555555 \
  --actions iam:ListRoles

# Multiple actions at once
iam-lens who-can \
  --resource arn:aws:dynamodb:us-east-1:555555555555:table/Books \
  --actions dynamodb:Query dynamodb:UpdateItem

# All possible actions on a resource
iam-lens who-can \
  --resource arn:aws:s3:::my-bucket
```

### 3. principal-can - Permission Analysis

**Purpose**: Generate a comprehensive policy document showing all permissions a principal has.

**Syntax**:

```bash
iam-lens principal-can --principal <arn> [--shrink-action-lists]
```

**Key Options**:

- `--principal <arn>`: The principal to analyze
- `--shrink-action-lists`: Use wildcards to consolidate actions and reduce policy size

**Returns**: JSON policy document with effective permissions

**Current Limitations**:

- Only supports S3 bucket policies for resource policies
- Limited cross-account resource policy evaluation

**Common Use Cases**:

- Security assessments and penetration testing
- Role capability analysis
- Permission auditing and cleanup
- Understanding effective permissions after policy changes

**Examples**:

```bash
# Analyze all permissions for a user
iam-lens principal-can \
  --principal arn:aws:iam::123456789012:user/Alice

# Get consolidated permissions with wildcards
iam-lens principal-can \
  --principal arn:aws:iam::123456789012:role/MyRole \
  --shrink-action-lists
```

## Global Options

All commands support these global options:

- `--collectConfigs <files>`: Specify alternative iam-collect config files (default: `iam-collect.jsonc`)
- `--partition <partition>`: AWS partition (`aws`, `aws-cn`, `aws-us-gov`) (default: `aws`)

## Advanced Features

### Context Keys and Conditions

The `simulate` command supports comprehensive condition evaluation:

**Automatic Context Population**: iam-lens automatically populates many AWS context keys based on the principal, resource, and request details. Use `--verbose` to see exactly which context variables are automatically set for any simulation.

**Custom Context Keys**: Use `--context` to specify additional context for condition evaluation or override automatically set values.

**VPC Endpoints**: Automatic VPC endpoint policy evaluation when VPC context is provided

### Cross-Account Analysis

iam-lens can analyze cross-account permissions when data is available:

- Requires iam-collect data from both source and target accounts
- Evaluates cross-account resource policies
- Considers organizational policies (SCPs/RCPs) across account boundaries

### Policy Types Analyzed

iam-lens evaluates all major AWS policy types:

- **Identity Policies**: User/role attached policies and group memberships
- **Resource Policies**: S3 buckets, and other resource-based policies (expanding)
- **Permission Boundaries**: Maximum permission constraints
- **Service Control Policies (SCPs)**: Organizational restrictions
- **Resource Control Policies (RCPs)**: Resource-based organizational restrictions
- **Session Policies**: For assumed roles and federated sessions

## Understanding Command Output

### Verbose Simulation Analysis

When using `simulate --verbose`, the output provides detailed JSON analysis that shows:

**Policy Evaluation Details**:

- Which specific policies were evaluated (identity, resource, SCPs, etc.)
- Which statements within each policy matched or didn't match
- How conditions were evaluated and which context keys were used
- The exact decision path that led to Allow/Deny

**Context Variables**:

- All automatically populated context keys based on the principal and resource
- Custom context keys you provided
- How each context key was used in condition evaluation

**Step-by-Step Decision Process**:

- Policy precedence and evaluation order
- Which statements granted permissions vs. which denied them
- Final decision logic and reasoning

**Analyzing who-can Results**:
When `who-can` returns principals with conditional access, you can:

1. Take the principal, action, and resource from the who-can output
2. Run `simulate --verbose` with those parameters
3. See exactly which policies and conditions enable that access
4. Understand the complete decision chain

### Context Variable Management

**Automatic Population**: iam-lens sets many context variables automatically:

- Principal-based keys (account, user ID, etc.)
- Resource-based keys (region, service, etc.)
- Request-based keys (date/time, etc.)

**Viewing Auto-Populated Variables**: Always use `--verbose` to see which context variables are automatically set before adding custom ones.

**Custom Overrides**: You can override automatic values using `--context` if you need to test specific scenarios.

## Best Practices for Agent Assistance

### 1. Data Freshness

- Always remind users that results are based on collected IAM data
- Suggest running `iam-collect download` if data seems outdated
- Note that recent policy changes may not be reflected

### 2. Use Case Identification

Help customers choose the right command:

- **simulate**: "Can X do Y to Z?" (specific test)
- **who-can**: "Who can do Y to Z?" (discovery)
- **principal-can**: "What can X do?" (comprehensive analysis)

### 3. Progressive Complexity

Start with simple examples and add complexity:

1. Basic simulation without context
2. Add context keys for conditions
3. Use verbose mode for troubleshooting
4. Combine with other commands for comprehensive analysis

### 4. Troubleshooting Common Issues

**Principal Not Found**:

- Check if principal exists in collected data
- Verify ARN format and account ID
- Consider using `--ignore-missing-principal` for hypothetical scenarios

**Unexpected Results**:

- Use `--verbose` to see detailed JSON analysis showing exactly which policies and statements were evaluated
- Check what context variables are automatically populated (visible in verbose output)
- Check for typos in ARNs and action names
- Verify resource-account specification for wildcard actions
- If `who-can` shows unexpected access, use `simulate --verbose` to understand the exact policy logic

**Performance Issues**:

- Large datasets may cause slow responses
- Consider analyzing specific accounts vs. entire organizations
- Use specific actions rather than checking all actions

### 5. Security Considerations

- Results show what COULD happen based on policies, not what HAS happened
- Always consider condition context in real-world scenarios
- Remember that resource policies and cross-account trusts expand access beyond identity policies

## Common Workflows

### Security Audit Workflow

1. Use `who-can` to identify all principals with access to sensitive resources
2. Use `simulate` to test specific scenarios with various context keys
3. Use `principal-can` to understand full capabilities of high-privilege principals

### Access Troubleshooting Workflow

1. Use `simulate` with the exact principal, action, and resource that's failing
2. Add `--verbose` to see detailed policy evaluation and understand exactly which statements are being evaluated
3. Add relevant context keys that match the real request
4. Compare with `who-can` results to see if access should be possible

### Understanding who-can Results

When `who-can` shows that a principal has access to a resource:

- The output includes the specific conditions under which access is granted
- If you need to understand HOW that access was determined, use `simulate --verbose` with the same principal, action, and resource and if necessary, context keys returned by `who-can`
- The verbose simulate output will show exactly which policies and statements granted the access

### Policy Development Workflow

1. Use `simulate` to test new policies before deployment
2. Use `who-can` to verify intended access patterns
3. Use `principal-can` to ensure roles don't have excessive permissions

## Limitations and Considerations

- **Real-time Data**: Results based on collected data, not live AWS state
- **Context Dependency**: Many real-world conditions cannot be fully simulated
- **Resource Policy Coverage**: Not all AWS services support resource policies in analysis
- **Temporary Credentials**: Session policies and temporary credential constraints may not be fully represented
- **Regional Variations**: Some resources and policies are region-specific

## Error Handling

Common error scenarios and solutions:

- **Configuration Issues**: Verify iam-collect.jsonc exists and is valid
- **ARN Format Errors**: Check ARN syntax and component validity
- **Missing Data**: Ensure required accounts/regions have been collected
- **Permission Issues**: Verify iam-collect had sufficient permissions to gather data

Always encourage users to start with simple examples and build complexity incrementally to isolate issues.
