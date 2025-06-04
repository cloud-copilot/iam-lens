import { describe, it, expect, afterEach, vi } from 'vitest'
import {
  actionPatternMatches,
  arnPatternMatches,
  calculateEffectivePolicy,
  SingleActionStatement,
  EffectivePolicyDocument
} from './effectivePolicy.js'
import * as principals from './principals.js'

describe('pattern matching helpers', () => {
  it('matches action when wildcard pattern covers it', () => {
    expect(actionPatternMatches('s3:*', 's3:GetObject')).toBe(true)
  })

  it('does not match when candidate is broader than pattern', () => {
    expect(actionPatternMatches('s3:GetObject', 's3:*')).toBe(false)
  })

  it('matches arn patterns correctly', () => {
    expect(arnPatternMatches('arn:aws:s3:::bucket/*', 'arn:aws:s3:::bucket/path/*')).toBe(true)
    expect(arnPatternMatches('arn:aws:s3:::bucket/path/*', 'arn:aws:s3:::bucket/*')).toBe(false)
  })
})

describe('condition merging from boundaries', () => {
  const principal = 'arn:aws:iam::123456789012:user/Bob'

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('applies permission boundary conditions to allows', async () => {
    const principalPolicies = {
      managedPolicies: [],
      inlinePolicies: [
        {
          name: 'inline',
          policy: {
            Version: '2012-10-17',
            Statement: [
              { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }
            ]
          }
        }
      ],
      permissionBoundary: {
        name: 'pb',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: '*',
              Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } }
            }
          ]
        }
      },
      scps: [],
      rcps: [],
      groupPolicies: []
    }

    vi.spyOn(principals, 'getAllPoliciesForPrincipal').mockResolvedValue(principalPolicies as any)

    const result = await calculateEffectivePolicy({} as any, principal)
    const allow = result.Statement.find(
      (s: SingleActionStatement) => s.Effect === 'Allow'
    ) as SingleActionStatement
    expect(allow.Condition).toEqual({ Bool: { 'aws:MultiFactorAuthPresent': 'true' } })
  })
})

describe('calculateEffectivePolicy scp gating', () => {
  const principal = 'arn:aws:iam::123456789012:user/Bob'

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('keeps allows permitted by every scp level', async () => {
    const principalPolicies = {
      managedPolicies: [],
      inlinePolicies: [
        {
          name: 'inline',
          policy: {
            Version: '2012-10-17',
            Statement: [
              { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*' }
            ]
          }
        }
      ],
      permissionBoundary: undefined,
      scps: [
        {
          orgIdentifier: 'root',
          policies: [
            {
              name: 'root-allow',
              policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }
            }
          ]
        },
        {
          orgIdentifier: 'ou',
          policies: [
            {
              name: 'ou-allow',
              policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*' }] }
            }
          ]
        }
      ],
      rcps: [],
      groupPolicies: []
    }

    vi.spyOn(principals, 'getAllPoliciesForPrincipal').mockResolvedValue(principalPolicies as any)

    const result = await calculateEffectivePolicy({} as any, principal)
    expect(result.Statement.length).toBe(1)
    expect((result.Statement[0] as SingleActionStatement).Action).toBe('s3:GetObject')
  })

  it('drops allows not covered by all scp levels', async () => {
    const principalPolicies = {
      managedPolicies: [],
      inlinePolicies: [
        {
          name: 'inline',
          policy: {
            Version: '2012-10-17',
            Statement: [
              { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*' }
            ]
          }
        }
      ],
      permissionBoundary: undefined,
      scps: [
        {
          orgIdentifier: 'root',
          policies: [
            {
              name: 'root-allow',
              policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }
            }
          ]
        },
        {
          orgIdentifier: 'ou',
          policies: [
            {
              name: 'ou-deny-only',
              policy: { Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: 's3:*', Resource: '*' }] }
            }
          ]
        }
      ],
      rcps: [],
      groupPolicies: []
    }

    vi.spyOn(principals, 'getAllPoliciesForPrincipal').mockResolvedValue(principalPolicies as any)

    const result = await calculateEffectivePolicy({} as any, principal)
    const allows = result.Statement.filter(
      (s: SingleActionStatement) => s.Effect === 'Allow'
    )
    expect(allows.length).toBe(0)
  })
})
