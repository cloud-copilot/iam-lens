import { loadPolicy } from '@cloud-copilot/iam-policy'
import { describe, expect, it } from 'vitest'
import {
  Permission,
  type PermissionConditions,
  type PermissionEffect,
  type PermissionPrincipals
} from './permission.js'
import {
  PermissionSet,
  addPoliciesToPermissionSet,
  addStatementToPermissionSet,
  buildPermissionSetFromPolicies,
  toPolicyStatements,
  type AddStatementToPermissionSetOptions
} from './permissionSet.js'
import {
  expectPermissionsToMatch,
  expectPermissionSetToMatch,
  type TestPermission
} from './permissionSetTestUtils.js'

interface TestPermissionInput {
  effect?: PermissionEffect
  action?: string
  resource?: string[]
  notResource?: string[]
  conditions?: PermissionConditions
  principal?: PermissionPrincipals
  notPrincipal?: PermissionPrincipals
}

interface PrincipalOperationTest {
  only?: true
  name: string
  permission: TestPermissionInput
  otherPermission: TestPermissionInput
}

interface PrincipalIncludesTest extends PrincipalOperationTest {
  included: boolean
}

interface PrincipalResultTest extends PrincipalOperationTest {
  expected: TestPermission[]
}

interface StatementConversionTest {
  only?: true
  name: string
  rawStatement: Record<string, unknown>
  permissionSetEffect: PermissionEffect
  options?: AddStatementToPermissionSetOptions
  expected: TestPermission[]
}

interface PolicyConversionTest {
  only?: true
  name: string
  conversionType: 'buildPermissionSetFromPolicies' | 'addPoliciesToPermissionSet'
  rawStatement: Record<string, unknown>
  permissionSetEffect: PermissionEffect
  options?: AddStatementToPermissionSetOptions
  expected: TestPermission[]
}

interface ToPolicyStatementsTest {
  only?: true
  name: string
  permissionSetEffect: PermissionEffect
  permissions: TestPermission[]
  expectedStatements: unknown[]
}

const accountId = '111122223333'
const otherAccountId = '999988887777'
const roleAdmin = `arn:aws:iam::${accountId}:role/Admin`
const roleBlocked = `arn:aws:iam::${accountId}:role/Blocked`
const roleA = `arn:aws:iam::${accountId}:role/A`
const roleB = `arn:aws:iam::${accountId}:role/B`
const otherAccountRole = `arn:aws:iam::${otherAccountId}:role/Admin`
const lambdaService = 'lambda.amazonaws.com'
const ec2Service = 'ec2.amazonaws.com'
const federatedProvider = 'arn:aws:iam::111122223333:saml-provider/Corp'
const otherFederatedProvider = 'arn:aws:iam::111122223333:saml-provider/Other'
const canonicalUser = '79a59df900b949e55d96a1e698f0example'
const otherCanonicalUser = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaexample'

const principalIncludesTests: PrincipalIncludesTest[] = [
  {
    name: 'legacy unconstrained principal includes a specific AWS role',
    permission: {},
    otherPermission: { principal: { AWS: [roleAdmin] } },
    included: true
  },
  {
    name: 'explicit wildcard Principal includes a service principal',
    permission: { principal: { wildcard: true } },
    otherPermission: { principal: { Service: [lambdaService] } },
    included: true
  },
  {
    name: 'typed AWS wildcard principal includes a service principal for this analysis',
    permission: { principal: { AWS: ['*'] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    included: true
  },
  {
    name: 'account principal includes role principal in the same account',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    included: true
  },
  {
    name: 'account root principal includes role principal in the same account',
    permission: { principal: { AWS: [`arn:aws:iam::${accountId}:root`] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    included: true
  },
  {
    name: 'role principal does not include account principal',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: { principal: { AWS: [accountId] } },
    included: false
  },
  {
    name: 'account principal does not include role in a different account',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [otherAccountRole] } },
    included: false
  },
  {
    name: 'service principal includes the same service principal',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    included: true
  },
  {
    name: 'service principal does not include a different service principal',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { principal: { Service: [ec2Service] } },
    included: false
  },
  {
    name: 'service principal does not include AWS principal',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    included: false
  },
  {
    name: 'federated principal includes the same federated provider',
    permission: { principal: { Federated: [federatedProvider] } },
    otherPermission: { principal: { Federated: [federatedProvider] } },
    included: true
  },
  {
    name: 'federated principal does not include a different federated provider',
    permission: { principal: { Federated: [federatedProvider] } },
    otherPermission: { principal: { Federated: [otherFederatedProvider] } },
    included: false
  },
  {
    name: 'canonical user principal includes the same canonical user',
    permission: { principal: { CanonicalUser: [canonicalUser] } },
    otherPermission: { principal: { CanonicalUser: [canonicalUser] } },
    included: true
  },
  {
    name: 'canonical user principal does not include a different canonical user',
    permission: { principal: { CanonicalUser: [canonicalUser] } },
    otherPermission: { principal: { CanonicalUser: [otherCanonicalUser] } },
    included: false
  },
  {
    name: 'specific principal does not include legacy unconstrained principal',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: {},
    included: false
  },
  {
    name: 'NotPrincipal includes a non-excluded AWS role',
    permission: { notPrincipal: { AWS: [roleBlocked] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    included: true
  },
  {
    name: 'NotPrincipal does not include its excluded AWS role',
    permission: { notPrincipal: { AWS: [roleBlocked] } },
    otherPermission: { principal: { AWS: [roleBlocked] } },
    included: false
  },
  {
    name: 'NotPrincipal account does not include a role in the excluded account',
    permission: { notPrincipal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    included: false
  },
  {
    name: 'NotPrincipal AWS role includes a service principal',
    permission: { notPrincipal: { AWS: [roleBlocked] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    included: true
  },
  {
    name: 'specific principal generally does not include NotPrincipal',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: { notPrincipal: { AWS: [roleBlocked] } },
    included: false
  },
  {
    name: 'typed AWS wildcard includes NotPrincipal',
    permission: { principal: { AWS: ['*'] } },
    otherPermission: { notPrincipal: { AWS: [roleBlocked] } },
    included: true
  },
  {
    name: 'NotPrincipal includes an equally excluded NotPrincipal',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleA] } },
    included: true
  },
  {
    name: 'NotPrincipal with fewer exclusions includes NotPrincipal with more exclusions',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleA, roleB] } },
    included: true
  },
  {
    name: 'NotPrincipal with more exclusions does not include NotPrincipal with fewer exclusions',
    permission: { notPrincipal: { AWS: [roleA, roleB] } },
    otherPermission: { notPrincipal: { AWS: [roleA] } },
    included: false
  },
  {
    name: 'NotPrincipal role includes NotPrincipal account when the role is inside the account exclusion',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [accountId] } },
    included: true
  },
  {
    name: 'NotPrincipal account does not include NotPrincipal role in that account',
    permission: { notPrincipal: { AWS: [accountId] } },
    otherPermission: { notPrincipal: { AWS: [roleA] } },
    included: false
  }
]

const principalUnionTests: PrincipalResultTest[] = [
  {
    name: 'keeps legacy unconstrained principal when unioned with a specific principal',
    permission: {},
    otherPermission: { principal: { AWS: [roleAdmin] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*']
      }
    ]
  },
  {
    name: 'keeps explicit wildcard principal when unioned with a service principal',
    permission: { principal: { wildcard: true } },
    otherPermission: { principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { wildcard: true }
      }
    ]
  },
  {
    name: 'keeps account principal when unioned with a role in the same account',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [accountId] }
      }
    ]
  },
  {
    name: 'unions account principal with a role in a different account',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [otherAccountRole] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [accountId, otherAccountRole] }
      }
    ]
  },
  {
    name: 'unions permissions with different positive principal types',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [accountId], Service: [lambdaService] }
      }
    ]
  },
  {
    name: 'unions federated and canonical user principal types',
    permission: { principal: { Federated: [federatedProvider] } },
    otherPermission: { principal: { CanonicalUser: [canonicalUser] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Federated: [federatedProvider], CanonicalUser: [canonicalUser] }
      }
    ]
  },
  {
    name: 'unions two service principals into one service principal list',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { principal: { Service: [ec2Service] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Service: [lambdaService, ec2Service] }
      }
    ]
  },
  {
    name: 'keeps a NotPrincipal permission when unioned with an already-included positive principal',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: { notPrincipal: { AWS: [roleBlocked] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleBlocked] }
      }
    ]
  },
  {
    name: 'unions positive principal with NotPrincipal that excludes that principal into wildcard',
    permission: { principal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleA] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { wildcard: true }
      }
    ]
  },
  {
    name: 'unions positive principal with NotPrincipal by removing that exclusion',
    permission: { principal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleA, roleB] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleB] }
      }
    ]
  },
  {
    name: 'unions NotPrincipal constraints by intersecting overlapping exclusions',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleA, roleB] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleA] }
      }
    ]
  },
  {
    name: 'unions NotPrincipal role and account exclusions to the narrower shared exclusion',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [accountId] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleA] }
      }
    ]
  },
  {
    name: 'unions disjoint NotPrincipal exclusions into wildcard access',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleB] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { wildcard: true }
      }
    ]
  }
]

const principalIntersectionTests: PrincipalResultTest[] = [
  {
    name: 'intersects legacy unconstrained principal with a specific principal',
    permission: {},
    otherPermission: { principal: { AWS: [roleAdmin] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'intersects explicit wildcard principal with a service principal',
    permission: { principal: { wildcard: true } },
    otherPermission: { principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Service: [lambdaService] }
      }
    ]
  },
  {
    name: 'intersects typed AWS wildcard principal with a service principal',
    permission: { principal: { AWS: ['*'] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Service: [lambdaService] }
      }
    ]
  },
  {
    name: 'intersects account and role permissions to the role principal',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'intersects account root principal with role principal to the role',
    permission: { principal: { AWS: [`arn:aws:iam::${accountId}:root`] } },
    otherPermission: { principal: { AWS: [roleAdmin] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'intersects account principal with different account role to no permissions',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { principal: { AWS: [otherAccountRole] } },
    expected: []
  },
  {
    name: 'intersects same service principal to itself',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Service: [lambdaService] }
      }
    ]
  },
  {
    name: 'intersects different service principals to no permissions',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { principal: { Service: [ec2Service] } },
    expected: []
  },
  {
    name: 'intersects same federated principal to itself',
    permission: { principal: { Federated: [federatedProvider] } },
    otherPermission: { principal: { Federated: [federatedProvider] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Federated: [federatedProvider] }
      }
    ]
  },
  {
    name: 'intersects different canonical users to no permissions',
    permission: { principal: { CanonicalUser: [canonicalUser] } },
    otherPermission: { principal: { CanonicalUser: [otherCanonicalUser] } },
    expected: []
  },
  {
    name: 'intersects disjoint positive principal types to no permissions',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: { principal: { Service: [lambdaService] } },
    expected: []
  },
  {
    name: 'intersects positive principal with NotPrincipal when the principal is not excluded',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: { notPrincipal: { AWS: [roleBlocked] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'intersects positive principal with NotPrincipal to no permissions when excluded',
    permission: { principal: { AWS: [roleBlocked] } },
    otherPermission: { notPrincipal: { AWS: [roleBlocked] } },
    expected: []
  },
  {
    name: 'intersects mixed positive principals with NotPrincipal by removing one type',
    permission: { principal: { AWS: [roleAdmin], Service: [lambdaService] } },
    otherPermission: { notPrincipal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'intersects NotPrincipal constraints by unioning exclusions',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [roleB] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleA, roleB] }
      }
    ]
  },
  {
    name: 'intersects NotPrincipal role and account exclusions by keeping the broader account exclusion',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { notPrincipal: { AWS: [accountId] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [accountId] }
      }
    ]
  }
]

const principalSubtractTests: PrincipalResultTest[] = [
  {
    name: 'subtracts a specific principal from wildcard access',
    permission: { principal: { wildcard: true } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleBlocked] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleBlocked] }
      }
    ]
  },
  {
    name: 'subtracts a specific principal from typed AWS wildcard access',
    permission: { principal: { AWS: ['*'] } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleBlocked] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleBlocked] }
      }
    ]
  },
  {
    name: 'subtracts a matching specific principal to no permissions',
    permission: { principal: { AWS: [roleBlocked] } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleBlocked] } },
    expected: []
  },
  {
    name: 'leaves a different specific principal unchanged',
    permission: { principal: { AWS: [roleAdmin] } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleBlocked] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'subtracts NotPrincipal from wildcard access as the excluded principal set',
    permission: { principal: { wildcard: true } },
    otherPermission: { effect: 'Deny', notPrincipal: { AWS: [roleA] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleA] }
      }
    ]
  },
  {
    name: 'falls back to Allow plus Deny residual for account minus role in same account',
    permission: { principal: { AWS: [accountId] } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleBlocked] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [accountId] }
      },
      {
        effect: 'Deny',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleBlocked] }
      }
    ]
  },
  {
    name: 'subtracts one principal type from a mixed positive principal set',
    permission: { principal: { AWS: [accountId], Service: [lambdaService] } },
    otherPermission: { effect: 'Deny', principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [accountId] }
      }
    ]
  },
  {
    name: 'inverts deny conditions while preserving matched principal constraints',
    permission: { principal: { AWS: [roleBlocked] } },
    otherPermission: {
      effect: 'Deny',
      principal: { AWS: [roleBlocked] },
      conditions: { Bool: { 'aws:MultiFactorAuthPresent': ['true'] } }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleBlocked] },
        conditions: { bool: { 'aws:multifactorauthpresent': ['false'] } }
      }
    ]
  },
  {
    name: 'subtracts a service principal from wildcard access',
    permission: { principal: { wildcard: true } },
    otherPermission: { effect: 'Deny', principal: { Service: [lambdaService] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { Service: [lambdaService] }
      }
    ]
  },
  {
    name: 'subtracts a matching service principal to no permissions',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { effect: 'Deny', principal: { Service: [lambdaService] } },
    expected: []
  },
  {
    name: 'leaves a different service principal unchanged',
    permission: { principal: { Service: [lambdaService] } },
    otherPermission: { effect: 'Deny', principal: { Service: [ec2Service] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { Service: [lambdaService] }
      }
    ]
  },
  {
    name: 'subtracts a matching federated principal to no permissions',
    permission: { principal: { Federated: [federatedProvider] } },
    otherPermission: { effect: 'Deny', principal: { Federated: [federatedProvider] } },
    expected: []
  },
  {
    name: 'leaves a different canonical user principal unchanged',
    permission: { principal: { CanonicalUser: [canonicalUser] } },
    otherPermission: { effect: 'Deny', principal: { CanonicalUser: [otherCanonicalUser] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { CanonicalUser: [canonicalUser] }
      }
    ]
  },
  {
    name: 'adds a denied positive principal to NotPrincipal exclusions',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleB] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleA, roleB] }
      }
    ]
  },
  {
    name: 'leaves NotPrincipal unchanged when denied positive principal is already excluded',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { effect: 'Deny', principal: { AWS: [roleA] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { AWS: [roleA] }
      }
    ]
  },
  {
    name: 'subtracts NotPrincipal from typed AWS wildcard access as the excluded principal set',
    permission: { principal: { AWS: ['*'] } },
    otherPermission: { effect: 'Deny', notPrincipal: { AWS: [roleA] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleA] }
      }
    ]
  },
  {
    name: 'subtracts NotPrincipal from NotPrincipal',
    permission: { notPrincipal: { AWS: [roleA] } },
    otherPermission: { effect: 'Deny', notPrincipal: { AWS: [roleB] } },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleB] }
      }
    ]
  }
]

const statementConversionTests: StatementConversionTest[] = [
  {
    name: 'ignores principals by default for compatibility',
    rawStatement: {
      Effect: 'Allow',
      Principal: { AWS: roleAdmin },
      Action: 's3:GetObject',
      Resource: '*'
    },
    permissionSetEffect: 'Allow',
    expected: [{ effect: 'Allow', action: 's3:GetObject', resource: ['*'] }]
  },
  {
    name: 'preserves Principal when statement conversion opts in',
    rawStatement: {
      Effect: 'Allow',
      Principal: { AWS: roleAdmin },
      Action: 's3:GetObject',
      Resource: '*'
    },
    permissionSetEffect: 'Allow',
    options: { includePrincipals: true },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'preserves single wildcard Principal distinctly',
    rawStatement: {
      Effect: 'Allow',
      Principal: '*',
      Action: 's3:GetObject',
      Resource: '*'
    },
    permissionSetEffect: 'Allow',
    options: { includePrincipals: true },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { wildcard: true }
      }
    ]
  },
  {
    name: 'preserves NotPrincipal when statement conversion opts in',
    rawStatement: {
      Effect: 'Deny',
      NotPrincipal: { Service: 'lambda.amazonaws.com' },
      Action: 's3:GetObject',
      Resource: '*'
    },
    permissionSetEffect: 'Deny',
    options: { includePrincipals: true },
    expected: [
      {
        effect: 'Deny',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { Service: ['lambda.amazonaws.com'] }
      }
    ]
  }
]

const policyConversionTests: PolicyConversionTest[] = [
  {
    name: 'buildPermissionSetFromPolicies passes principal opt-in to statements',
    conversionType: 'buildPermissionSetFromPolicies',
    rawStatement: {
      Effect: 'Allow',
      Principal: { AWS: roleAdmin },
      Action: 's3:GetObject',
      Resource: '*'
    },
    permissionSetEffect: 'Allow',
    options: { includePrincipals: true },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ]
  },
  {
    name: 'addPoliciesToPermissionSet passes principal opt-in to statements',
    conversionType: 'addPoliciesToPermissionSet',
    rawStatement: {
      Effect: 'Deny',
      NotPrincipal: { Service: lambdaService },
      Action: 's3:GetObject',
      Resource: '*'
    },
    permissionSetEffect: 'Deny',
    options: { includePrincipals: true },
    expected: [
      {
        effect: 'Deny',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { Service: [lambdaService] }
      }
    ]
  }
]

const toPolicyStatementTests: ToPolicyStatementsTest[] = [
  {
    name: 'omits Principal and NotPrincipal for legacy permissions',
    permissionSetEffect: 'Allow',
    permissions: [{ effect: 'Allow', action: 's3:GetObject', resource: ['*'] }],
    expectedStatements: [
      {
        Effect: 'Allow',
        Action: 's3:GetObject',
        Resource: ['*']
      }
    ]
  },
  {
    name: 'emits Principal in policy statements',
    permissionSetEffect: 'Allow',
    permissions: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        principal: { AWS: [roleAdmin] }
      }
    ],
    expectedStatements: [
      {
        Effect: 'Allow',
        Action: 's3:GetObject',
        Principal: { AWS: roleAdmin },
        Resource: ['*']
      }
    ]
  },
  {
    name: 'emits NotPrincipal in policy statements',
    permissionSetEffect: 'Deny',
    permissions: [
      {
        effect: 'Deny',
        action: 's3:GetObject',
        resource: ['*'],
        notPrincipal: { Service: ['lambda.amazonaws.com'] }
      }
    ],
    expectedStatements: [
      {
        Effect: 'Deny',
        Action: 's3:GetObject',
        NotPrincipal: { Service: 'lambda.amazonaws.com' },
        Resource: ['*']
      }
    ]
  }
]

describe('Permission principal dimension includes', () => {
  for (const test of principalIncludesTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given two permissions with principal constraints
      const permission = testPermissionInputToPermission(test.permission)
      const otherPermission = testPermissionInputToPermission(test.otherPermission)

      //When checking whether one permission includes the other
      const result = permission.includes(otherPermission)

      //Then the result should match the expected principal inclusion
      expect(result).toBe(test.included)
    })
  }
})

describe('Permission principal dimension union', () => {
  for (const test of principalUnionTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given two permissions with principal constraints
      const permission = testPermissionInputToPermission(test.permission)
      const otherPermission = testPermissionInputToPermission(test.otherPermission)

      //When the permissions are unioned
      const result = permission.union(otherPermission)

      //Then the resulting permissions should match the expected principal constraints
      expectPermissionsToMatch(result, test.expected)
    })
  }
})

describe('Permission principal dimension intersections', () => {
  for (const test of principalIntersectionTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given two permissions with principal constraints
      const permission = testPermissionInputToPermission(test.permission)
      const otherPermission = testPermissionInputToPermission(test.otherPermission)

      //When the permissions are intersected
      const result = permission.intersections(otherPermission)

      //Then the resulting permissions should match the expected principal overlap
      expectPermissionsToMatch(result, test.expected)
    })
  }
})

describe('Permission principal dimension subtract', () => {
  for (const test of principalSubtractTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given an Allow permission and a Deny permission with principal constraints
      const permission = testPermissionInputToPermission(test.permission)
      const otherPermission = testPermissionInputToPermission(test.otherPermission)

      //When the Deny permission is subtracted
      const result = permission.subtract(otherPermission)

      //Then the resulting permissions should match the expected principal residuals
      expectPermissionsToMatch(result, test.expected)
    })
  }
})

describe('PermissionSet principal-aware statement conversion', () => {
  for (const test of statementConversionTests) {
    const func = test.only ? it.only : it
    func(test.name, async () => {
      //Given a resource policy statement and a permission set
      const statement = loadPolicy({
        Version: '2012-10-17',
        Statement: test.rawStatement
      }).statements()[0]
      const permissionSet = new PermissionSet(test.permissionSetEffect)

      //When the statement is added to the permission set
      await addStatementToPermissionSet(statement, permissionSet, test.options)

      //Then the permission set should match the expected principal conversion behavior
      expectPermissionSetToMatch(permissionSet, test.expected)
    })
  }
})

describe('PermissionSet policy-level principal-aware conversion', () => {
  for (const test of policyConversionTests) {
    const func = test.only ? it.only : it
    func(test.name, async () => {
      //Given a policy and conversion options
      const policy = loadPolicy({
        Version: '2012-10-17',
        Statement: test.rawStatement
      })

      //When the policy is converted through the requested PermissionSet API
      const permissionSet =
        test.conversionType === 'buildPermissionSetFromPolicies'
          ? await buildPermissionSetFromPolicies(test.permissionSetEffect, [policy], test.options)
          : new PermissionSet(test.permissionSetEffect)
      if (test.conversionType === 'addPoliciesToPermissionSet') {
        await addPoliciesToPermissionSet(
          permissionSet,
          test.permissionSetEffect,
          [policy],
          test.options
        )
      }

      //Then the permission set should preserve principals according to the options
      expectPermissionSetToMatch(permissionSet, test.expected)
    })
  }
})

describe('PermissionSet principal policy statement output', () => {
  for (const test of toPolicyStatementTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given a permission set with the test permissions
      const permissionSet = new PermissionSet(test.permissionSetEffect)
      for (const permission of test.permissions) {
        permissionSet.addPermission(testPermissionInputToPermission(permission))
      }

      //When the permission set is converted to policy statements
      const statements = toPolicyStatements(permissionSet)

      //Then the statements should match the expected principal output
      expect(statements).toEqual(test.expectedStatements)
    })
  }
})

/**
 * Convert a test permission input into a Permission with defaults for principal-specific tests.
 *
 * @param input - The test input to convert.
 * @returns A Permission for the test case.
 */
function testPermissionInputToPermission(input: TestPermissionInput): Permission {
  const [service, action] = (input.action ?? 's3:GetObject').split(':')
  return new Permission(
    input.effect ?? 'Allow',
    service,
    action,
    input.resource ?? ['*'],
    input.notResource,
    input.conditions,
    input.principal,
    input.notPrincipal
  )
}
