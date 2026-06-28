import { describe, expect, it } from 'vitest'
import {
  intersectPrincipalConstraints,
  normalizePrincipalConstraint,
  normalizePermissionPrincipals,
  principalIncludes,
  subtractPrincipalConstraint,
  unionPrincipalConstraints
} from './principalConstraints.js'

describe('normalizePermissionPrincipals', () => {
  it('should reject wildcard mixed with typed principals', () => {
    //Given a principal set with a wildcard and typed AWS principal
    const principals = { wildcard: true as const, AWS: ['arn:aws:iam::111122223333:role/Admin'] }

    //When we normalize the principal set
    const normalize = () => normalizePermissionPrincipals(principals)

    //Then it should reject the ambiguous input
    expect(normalize).toThrow('wildcard')
  })

  it('should normalize STS assumed-role session ARNs to IAM role ARNs', () => {
    //Given an STS assumed-role session principal
    const principals = {
      AWS: ['arn:aws:sts::111122223333:assumed-role/path/to/Admin/session-1']
    }

    //When the principal set is normalized
    const result = normalizePermissionPrincipals(principals)

    //Then the principal should be the corresponding IAM role ARN
    expect(result).toEqual({ AWS: ['arn:aws:iam::111122223333:role/path/to/Admin'] })
  })
})

describe('principalIncludes', () => {
  it('should treat wildcard principals as including service and AWS principals', () => {
    //Given a wildcard principal constraint and a service principal constraint
    const wildcard = normalizePrincipalConstraint({ wildcard: true }, undefined)
    const service = normalizePrincipalConstraint({ Service: ['lambda.amazonaws.com'] }, undefined)

    //When checking inclusion
    const result = principalIncludes(wildcard, service)

    //Then the wildcard should include the service principal
    expect(result).toBe(true)
  })

  it('should treat typed AWS wildcard principals as including service principals', () => {
    //Given a typed AWS wildcard principal and a service principal
    const typedWildcard = normalizePrincipalConstraint({ AWS: ['*'] }, undefined)
    const service = normalizePrincipalConstraint({ Service: ['lambda.amazonaws.com'] }, undefined)

    //When checking inclusion
    const result = principalIncludes(typedWildcard, service)

    //Then the typed AWS wildcard should include the service principal for this analysis
    expect(result).toBe(true)
  })

  it('should treat account principals as including role principals in the same account', () => {
    //Given an account principal and a role principal in that account
    const account = normalizePrincipalConstraint({ AWS: ['111122223333'] }, undefined)
    const role = normalizePrincipalConstraint(
      { AWS: ['arn:aws:iam::111122223333:role/Admin'] },
      undefined
    )

    //When checking inclusion
    const result = principalIncludes(account, role)

    //Then the account principal should include the role principal
    expect(result).toBe(true)
  })

  it('should not include a principal excluded by NotPrincipal', () => {
    //Given a NotPrincipal exclusion and the excluded role principal
    const notRole = normalizePrincipalConstraint(undefined, {
      AWS: ['arn:aws:iam::111122223333:role/Blocked']
    })
    const blockedRole = normalizePrincipalConstraint(
      { AWS: ['arn:aws:iam::111122223333:role/Blocked'] },
      undefined
    )

    //When checking inclusion
    const result = principalIncludes(notRole, blockedRole)

    //Then the NotPrincipal constraint should not include the excluded role
    expect(result).toBe(false)
  })
})

describe('principal set operations', () => {
  it('should union positive principal sets by principal type', () => {
    //Given two positive principal constraints
    const first = normalizePrincipalConstraint({ AWS: ['111122223333'] }, undefined)
    const second = normalizePrincipalConstraint({ Service: ['lambda.amazonaws.com'] }, undefined)

    //When the constraints are unioned
    const result = unionPrincipalConstraints(first, second)

    //Then the resulting principal constraint should contain both entries
    expect(result).toEqual([
      {
        kind: 'principal',
        principals: { AWS: ['111122223333'], Service: ['lambda.amazonaws.com'] }
      }
    ])
  })

  it('should intersect an account principal with a role principal to the role principal', () => {
    //Given an account principal and a role principal in the account
    const account = normalizePrincipalConstraint({ AWS: ['111122223333'] }, undefined)
    const role = normalizePrincipalConstraint(
      { AWS: ['arn:aws:iam::111122223333:role/Admin'] },
      undefined
    )

    //When the constraints are intersected
    const result = intersectPrincipalConstraints(account, role)

    //Then the role principal should remain as the narrower intersection
    expect(result).toEqual([
      { kind: 'principal', principals: { AWS: ['arn:aws:iam::111122223333:role/Admin'] } }
    ])
  })

  it('should intersect typed AWS wildcard with a specific role to the role principal', () => {
    //Given a typed AWS wildcard and a specific role principal
    const typedWildcard = normalizePrincipalConstraint({ AWS: ['*'] }, undefined)
    const role = normalizePrincipalConstraint(
      { AWS: ['arn:aws:iam::111122223333:role/Admin'] },
      undefined
    )

    //When the constraints are intersected
    const result = intersectPrincipalConstraints(typedWildcard, role)

    //Then the specific role should remain as the narrower intersection
    expect(result).toEqual([
      { kind: 'principal', principals: { AWS: ['arn:aws:iam::111122223333:role/Admin'] } }
    ])
  })

  it('should subtract a specific principal from wildcard as NotPrincipal', () => {
    //Given wildcard access and a denied role principal
    const wildcard = normalizePrincipalConstraint({ wildcard: true }, undefined)
    const role = normalizePrincipalConstraint(
      { AWS: ['arn:aws:iam::111122223333:role/Blocked'] },
      undefined
    )

    //When the role is subtracted
    const result = subtractPrincipalConstraint(wildcard, role)

    //Then the residual should be everyone except the denied role
    expect(result).toEqual([
      {
        kind: 'notPrincipal',
        principals: { AWS: ['arn:aws:iam::111122223333:role/Blocked'] }
      }
    ])
  })

  it('should subtract a specific principal from typed AWS wildcard as NotPrincipal', () => {
    //Given typed AWS wildcard access and a denied role principal
    const typedWildcard = normalizePrincipalConstraint({ AWS: ['*'] }, undefined)
    const role = normalizePrincipalConstraint(
      { AWS: ['arn:aws:iam::111122223333:role/Blocked'] },
      undefined
    )

    //When the role is subtracted
    const result = subtractPrincipalConstraint(typedWildcard, role)

    //Then the residual should be everyone except the denied role
    expect(result).toEqual([
      {
        kind: 'notPrincipal',
        principals: { AWS: ['arn:aws:iam::111122223333:role/Blocked'] }
      }
    ])
  })

  it('should subtract NotPrincipal from NotPrincipal as the remaining positive principals', () => {
    //Given an allow for everyone except role A and a deny for everyone except role B
    const allow = normalizePrincipalConstraint(undefined, {
      AWS: ['arn:aws:iam::111122223333:role/A']
    })
    const deny = normalizePrincipalConstraint(undefined, {
      AWS: ['arn:aws:iam::111122223333:role/B']
    })

    //When the deny is subtracted from the allow
    const result = subtractPrincipalConstraint(allow, deny)

    //Then only role B remains allowed
    expect(result).toEqual([
      { kind: 'principal', principals: { AWS: ['arn:aws:iam::111122223333:role/B'] } }
    ])
  })
})
