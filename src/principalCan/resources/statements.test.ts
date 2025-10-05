import { loadPolicy } from '@cloud-copilot/iam-policy'
import { describe, expect, it } from 'vitest'
import { makePrincipalOnlyPolicyFromStatement } from './statements.js'

describe('makePrincipalOnlyPolicyFromStatement', () => {
  it('should create a principal-only policy from a statement with Principal', () => {
    // Given a statement with Principal
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Deny',
        Principal: { AWS: 'arn:aws:iam::123456789012:user/testuser' },
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::my-bucket/*'
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    //Then it should return a policy with only Principal, Resource *, and Action *
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:user/testuser' },
        Action: '*',
        Resource: '*'
      }
    })
  })

  it('should create a principal-only policy from a statement with NotPrincipal', () => {
    // Given a statement with NotPrincipal
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        NotPrincipal: { AWS: 'arn:aws:iam::123456789012:root' },
        Action: 'ec2:DescribeInstances',
        Resource: '*'
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should return a policy with only NotPrincipal, Resource *, and Action *
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        NotPrincipal: { AWS: 'arn:aws:iam::123456789012:root' },
        Action: '*',
        Resource: '*'
      }
    })
  })

  it('should preserve principal-related conditions and remove non-principal conditions', () => {
    // Given a statement with mixed conditions (principal and non-principal)
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: 's3:*',
        Resource: 'arn:aws:s3:::example-bucket/*',
        Condition: {
          StringEquals: {
            'aws:PrincipalArn': 'arn:aws:iam::123456789012:user/allowed-user',
            's3:x-amz-server-side-encryption': 'AES256'
          },
          StringLike: {
            'aws:username': 'test-*',
            'aws:RequestedRegion': 'us-east-*'
          },
          IpAddress: {
            'aws:SourceIp': '203.0.113.0/24'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should preserve only principal-related conditions
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringEquals: {
            'aws:PrincipalArn': 'arn:aws:iam::123456789012:user/allowed-user'
          },
          StringLike: {
            'aws:username': 'test-*'
          }
        }
      }
    })
  })

  it('should remove conditions entirely when no principal-related keys remain', () => {
    // Given a statement with only non-principal conditions
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: 'sts:AssumeRole',
        Resource: '*',
        Condition: {
          StringEquals: {
            's3:x-amz-server-side-encryption': 'AES256'
          },
          IpAddress: {
            'aws:SourceIp': '203.0.113.0/24'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should remove the conditions entirely
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: '*',
        Resource: '*'
      }
    })
  })

  it('should handle statements with aws:PrincipalAccount condition', () => {
    // Given a statement with aws:PrincipalAccount condition
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: 's3:GetObject',
        Resource: '*',
        Condition: {
          StringEquals: {
            'aws:PrincipalAccount': '123456789012'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should preserve the aws:PrincipalAccount condition
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringEquals: {
            'aws:PrincipalAccount': '123456789012'
          }
        }
      }
    })
  })

  it('should handle statements with aws:PrincipalAccount condition ignoring case', () => {
    // Given a statement with aws:PrincipalAccount condition
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: 's3:GetObject',
        Resource: '*',
        Condition: {
          StringEquals: {
            'aws:principalaccount': '123456789012'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should preserve the aws:PrincipalAccount condition
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringEquals: {
            'aws:principalaccount': '123456789012'
          }
        }
      }
    })
  })

  it('should handle statements with aws:PrincipalOrgId condition', () => {
    // Given a statement with aws:PrincipalOrgId condition
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Deny',
        Principal: { AWS: '*' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringNotEquals: {
            'aws:PrincipalOrgId': 'o-1234567890'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should preserve the aws:PrincipalOrgId condition
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringNotEquals: {
            'aws:PrincipalOrgId': 'o-1234567890'
          }
        }
      }
    })
  })

  it('should handle statements with aws:userid condition', () => {
    // Given a statement with aws:userid condition
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:root' },
        Action: 'iam:GetRole',
        Resource: '*',
        Condition: {
          StringLike: {
            'aws:userid': 'AIDAI*'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should preserve the aws:userid condition
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:root' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringLike: {
            'aws:userid': 'AIDAI*'
          }
        }
      }
    })
  })

  it('should remove empty condition operators', () => {
    // Given a statement where all keys in a condition operator are non-principal
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { Service: 'ec2.amazonaws.com' },
        Action: 'sts:AssumeRole',
        Resource: '*',
        Condition: {
          StringEquals: {
            'ec2:InstanceType': 't2.micro',
            'aws:RequestedRegion': 'us-east-1'
          },
          StringLike: {
            'aws:username': 'admin-*'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should remove the empty StringEquals operator but keep StringLike
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Principal: { Service: 'ec2.amazonaws.com' },
        Action: '*',
        Resource: '*',
        Condition: {
          StringLike: {
            'aws:username': 'admin-*'
          }
        }
      }
    })
  })

  it('should handle statements without Principal or NotPrincipal', () => {
    // Given a statement without Principal or NotPrincipal
    const policy = loadPolicy({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::my-bucket/*',
        Condition: {
          StringEquals: {
            'aws:PrincipalArn': 'arn:aws:iam::123456789012:user/testuser'
          }
        }
      }
    })
    const statement = policy.statements()[0]

    // When calling makePrincipalOnlyPolicyFromStatement
    const result = makePrincipalOnlyPolicyFromStatement(statement)

    // Then it should create a policy with no Principal/NotPrincipal but preserve principal conditions
    expect(result.toJSON()).toEqual({
      Version: '2012-10-17',
      Statement: {
        Effect: 'Allow',
        Action: '*',
        Resource: '*',
        Condition: {
          StringEquals: {
            'aws:PrincipalArn': 'arn:aws:iam::123456789012:user/testuser'
          }
        }
      }
    })
  })
})
