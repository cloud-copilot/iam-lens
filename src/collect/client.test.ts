import { createInMemoryStorageClient } from '@cloud-copilot/iam-collect'
import { describe, expect, it } from 'vitest'
import { IamCollectClient } from './client.js'

const newStore = () => {
  const store = createInMemoryStorageClient()
  const client = new IamCollectClient(store)
  return { store, client }
}

const fullAccessPolicy = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: '*',
      Resource: '*'
    }
  ]
}

const s3Scp = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: 's3:*',
      Resource: '*'
    }
  ]
}

const extraSCPs = [1, 2, 3, 4, 5].map((i) => ({
  Version: '2012-10-17',
  Statement: {
    Sid: `ExtraSCP${i}`,
    Effect: 'Allow',
    Action: 's3:*',
    Resource: '*'
  }
}))

describe('IamCollectClient', () => {
  describe('accountExists', () => {
    it('should return true if account exists', async () => {
      // Given an account that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When checking if the account exists
      const exists = await client.accountExists(accountId)

      // Then it should return true
      expect(exists).toBe(true)
    })
    it('should return false if the account does not exist', async () => {
      // Given an account that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'

      // When checking if the account exists
      const exists = await client.accountExists(accountId)

      // Then it should return false
      expect(exists).toBe(false)
    })
  })

  describe('principalExists', () => {
    it('should return true if principal exists', async () => {
      // Given a principal that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const principalArn = `arn:aws:iam::${accountId}:user/test-user`
      await store.saveResourceMetadata(accountId, principalArn, 'metadata', {
        accountId,
        resourceType: 'user'
      })

      // When checking if the principal exists
      const exists = await client.principalExists(principalArn)

      // Then it should return true
      expect(exists).toBe(true)
    })

    it('should return false if the principal does not exist', async () => {
      // Given a principal that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const principalArn = `arn:aws:iam::${accountId}:user/test-user`

      // When checking if the principal exists
      const exists = await client.principalExists(principalArn)

      // Then it should return false
      expect(exists).toBe(false)
    })
  })

  describe('getScpHierarchyForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = newStore()
      const accountId = '123456789012'
      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When getting the SCP hierarchy for the account
      const hierarchy = await client.getScpHierarchyForAccount(accountId)

      // Then it should return an empty array
      expect(hierarchy).toEqual([])
    })

    it('should return an empty array for the root account in an org', async () => {
      // Given an account that is the root account of an org
      const { store, client } = newStore()
      const accountId = '123456789012'
      const orgId = 'o-12345678'
      await store.saveOrganizationMetadata(orgId, 'metadata', {
        rootAccountId: accountId
      })

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // And the account is part of an org
      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      // When getting the SCP hierarchy for the account
      const hierarchy = await client.getScpHierarchyForAccount(accountId)

      // Then it should return an empty array
      expect(hierarchy).toEqual([])
    })

    it('should return the SCP hierarchy for an account', async () => {
      // Given an account that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'
      const orgUnit2Id = 'ou-4fkd-87654321'
      // And the account is part of an org
      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      await store.saveOrganizationMetadata(orgId, 'metadata', {
        rootAccountId: 'different-account-id'
      })

      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      //And the account is in an OU and those OUs have SCPs
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7'
          ]
        },
        [orgUnit1Id]: {
          parent: rootOu,
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38'
          ]
        },
        [orgUnit2Id]: {
          parent: orgUnit1Id,
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-tj39dy7'
          ]
        }
      })

      // And the account has SCPS
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId]: {
          ou: orgUnit2Id,
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-12345678'
          ]
        }
      })

      //And the SCPs exist

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-FullAWSAccess', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
        name: 'FullAWSAccess'
      })
      await store.saveOrganizationPolicyMetadata(
        orgId,
        'scps',
        'p-FullAWSAccess',
        'policy',
        fullAccessPolicy
      )

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-12345678', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
        name: 'TestPolicy1'
      })

      for (const [i, policyId] of ['p-r7dber7', 'p-j48dn38', 'p-tj39dy7'].entries()) {
        // Now you can use both i (the index) and policyId (the value)
        await store.saveOrganizationPolicyMetadata(orgId, 'scps', policyId, 'metadata', {
          arn: `arn:aws:organizations::aws:policy/service_control_policy/${policyId}`,
          name: policyId
        })
        await store.saveOrganizationPolicyMetadata(orgId, 'scps', policyId, 'policy', extraSCPs[i])
      }

      //arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7
      //arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38
      //arn:aws:organizations::aws:policy/service_control_policy/p-tj39dy7

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-12345678', 'policy', s3Scp)

      // When getting the SCPs for the account
      const scps = await client.getScpHierarchyForAccount(accountId)

      // Then it should return the SCPs
      expect(scps).toEqual([
        {
          orgIdentifier: rootOu,
          policies: [
            {
              // name: 'FullAWSAccess',
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7',
              policy: extraSCPs[0]
            }
          ]
        },
        {
          orgIdentifier: orgUnit1Id,
          policies: [
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38',
              policy: extraSCPs[1]
            }
          ]
        },
        {
          orgIdentifier: orgUnit2Id,
          policies: [
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-tj39dy7',
              policy: extraSCPs[2]
            }
          ]
        },
        {
          orgIdentifier: accountId,
          policies: [
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
              policy: s3Scp
            }
          ]
        }
      ])
    })
  })

  describe('getOrgUnitHierarchyForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = newStore()
      const accountId = '123456789012'

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When getting the OU hierarchy for the account
      const hierarchy = await client.getOrgUnitHierarchyForAccount(accountId)

      // Then it should return an empty array
      expect(hierarchy).toEqual([])
    })

    it('should return the OU hierarchy for an account', async () => {
      // Given an account that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'
      const orgUnit2Id = 'ou-4fkd-87654321'

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // And the account is part of an org
      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      // And the account in an OU
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId]: {
          ou: orgUnit2Id
        }
      })

      // And the org has OUs
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [orgUnit1Id]: {
          parent: rootOu
        },
        [orgUnit2Id]: {
          parent: orgUnit1Id
        }
      })

      // When getting the OU hierarchy for the account
      const hierarchy = await client.getOrgUnitHierarchyForAccount(accountId)

      // Then it should return the OU hierarchy
      expect(hierarchy).toEqual([rootOu, orgUnit1Id, orgUnit2Id])
    })
  })

  describe('getOrgUnitIdForAccount', () => {
    it('should return undefined for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = newStore()
      const accountId = '123456789012'

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When getting the OU ID for the account
      const ouId = await client.getOrgUnitIdForAccount(accountId)

      // Then it should return undefined
      expect(ouId).toBeUndefined()
    })
  })

  describe('getScpsForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = newStore()
      const accountId = '123456789012'

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When getting the SCPs for the account
      const scps = await client.getScpsForAccount(accountId)

      // Then it should return an empty array
      expect(scps).toEqual([])
    })

    it('should return the SCPs for an account', async () => {
      // Given an account that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'
      const orgUnit2Id = 'ou-4fkd-87654321'
      // And the account is part of an org
      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      // And the account has SCPS
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId]: {
          ou: orgUnit2Id,
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-12345678'
          ]
        }
      })

      //And the SCPs exist

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-FullAWSAccess', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
        name: 'FullAWSAccess'
      })
      await store.saveOrganizationPolicyMetadata(
        orgId,
        'scps',
        'p-FullAWSAccess',
        'policy',
        fullAccessPolicy
      )

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-12345678', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
        name: 'TestPolicy1'
      })

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-12345678', 'policy', s3Scp)

      // When getting the SCPs for the account
      const scps = await client.getScpsForAccount(accountId)

      // Then it should return the SCPs
      expect(scps).toEqual([
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
          name: 'FullAWSAccess',
          policy: fullAccessPolicy
        },
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
          name: 'TestPolicy1',
          policy: s3Scp
        }
      ])
    })
  })

  describe('getRcpsForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = newStore()
      const accountId = '123456789012'

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When getting the SCPs for the account
      const scps = await client.getRcpsForAccount(accountId)

      // Then it should return an empty array
      expect(scps).toEqual([])
    })

    it('should return the RCPs for an account', async () => {
      // Given an account that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'
      const orgUnit2Id = 'ou-4fkd-87654321'
      // And the account is part of an org
      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      await store.saveOrganizationMetadata(orgId, 'metadata', {
        rootAccountId: 'different-account-id'
      })

      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      // And the account has SCPS
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId]: {
          ou: orgUnit2Id,
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-12345678'
          ]
        }
      })

      //And the SCPs exist

      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-RcpFullAWSAccess', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
        name: 'FullAWSAccess'
      })
      await store.saveOrganizationPolicyMetadata(
        orgId,
        'rcps',
        'p-RcpFullAWSAccess',
        'policy',
        fullAccessPolicy
      )

      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-12345678', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
        name: 'TestPolicy1'
      })

      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-12345678', 'policy', s3Scp)

      // When getting the SCPs for the account
      const rcps = await client.getRcpsForAccount(accountId)

      // Then it should return the SCPs
      expect(rcps).toEqual([
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
          name: 'FullAWSAccess',
          policy: fullAccessPolicy
        },
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
          name: 'TestPolicy1',
          policy: s3Scp
        }
      ])
    })
  })

  describe('getRcpHierarchyForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = newStore()
      const accountId = '123456789012'

      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      // When getting the SCPs for the account
      const scps = await client.getRcpHierarchyForAccount(accountId)

      // Then it should return an empty array
      expect(scps).toEqual([])
    })

    it('should return the RCP hierarchy for an account', async () => {
      // Given an account that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'
      const orgUnit2Id = 'ou-4fkd-87654321'
      // And the account is part of an org
      await store.saveAccountMetadata(accountId, 'metadata', {
        accountId
      })

      await store.saveOrganizationMetadata(orgId, 'metadata', {
        rootAccountId: 'different-account-id'
      })

      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      //And the account is in an OU and those OUs have RCPs
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7'
          ]
        },
        [orgUnit1Id]: {
          parent: rootOu,
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38'
          ]
        },
        [orgUnit2Id]: {
          parent: orgUnit1Id,
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-tj39dy7'
          ]
        }
      })

      // And the account has RCPs
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId]: {
          ou: orgUnit2Id,
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-12345678'
          ]
        }
      })

      //And the SCPs exist

      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-RcpFullAWSAccess', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
        name: 'FullAWSAccess'
      })
      await store.saveOrganizationPolicyMetadata(
        orgId,
        'rcps',
        'p-RcpFullAWSAccess',
        'policy',
        fullAccessPolicy
      )

      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-12345678', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
        name: 'TestPolicy1'
      })

      for (const [i, policyId] of ['p-r7dber7', 'p-j48dn38', 'p-tj39dy7'].entries()) {
        // Now you can use both i (the index) and policyId (the value)
        await store.saveOrganizationPolicyMetadata(orgId, 'rcps', policyId, 'metadata', {
          arn: `arn:aws:organizations::aws:policy/service_control_policy/${policyId}`,
          name: policyId
        })
        await store.saveOrganizationPolicyMetadata(orgId, 'rcps', policyId, 'policy', extraSCPs[i])
      }

      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-12345678', 'policy', s3Scp)

      // When getting the SCPs for the account
      const scps = await client.getRcpHierarchyForAccount(accountId)

      // Then it should return the SCPs
      expect(scps).toEqual([
        {
          orgIdentifier: rootOu,
          policies: [
            {
              // name: 'FullAWSAccess',
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7',
              policy: extraSCPs[0]
            }
          ]
        },
        {
          orgIdentifier: orgUnit1Id,
          policies: [
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38',
              policy: extraSCPs[1]
            }
          ]
        },
        {
          orgIdentifier: orgUnit2Id,
          policies: [
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-tj39dy7',
              policy: extraSCPs[2]
            }
          ]
        },
        {
          orgIdentifier: accountId,
          policies: [
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
              policy: fullAccessPolicy
            },
            {
              name: 'arn:aws:organizations::aws:policy/service_control_policy/p-12345678',
              policy: s3Scp
            }
          ]
        }
      ])
    })
  })

  describe('getScpsForOrgUnit', () => {
    it('should return the SCPs for an OrgUnit', async () => {
      //Given an OU that exists
      const { store, client } = newStore()
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'

      // And the OU has SCPs
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7'
          ]
        },
        [orgUnit1Id]: {
          parent: rootOu,
          scps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38'
          ]
        }
      })

      // And the SCPs exist
      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-FullAWSAccess', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
        name: 'FullAWSAccess'
      })
      await store.saveOrganizationPolicyMetadata(
        orgId,
        'scps',
        'p-FullAWSAccess',
        'policy',
        fullAccessPolicy
      )
      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-j48dn38', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38',
        name: 'TestPolicy1'
      })
      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-j48dn38', 'policy', s3Scp)

      // When getting the SCPs for the OU
      const scps = await client.getScpsForOrgUnit(orgId, orgUnit1Id)

      // Then it should return the SCPs
      expect(scps).toEqual([
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
          name: 'FullAWSAccess',
          policy: fullAccessPolicy
        },
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38',
          name: 'TestPolicy1',
          policy: s3Scp
        }
      ])
    })
  })

  describe('getRcpsForOrgUnit', () => {
    it('should return the RCPs for an OrgUnit', async () => {
      //Given an OU that exists
      const { store, client } = newStore()
      const orgId = 'o-12345678'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'

      // And the OU has RCPs
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-r7dber7'
          ]
        },
        [orgUnit1Id]: {
          parent: rootOu,
          rcps: [
            'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
            'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38'
          ]
        }
      })

      // And the SCPs exist
      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-RcpFullAWSAccess', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
        name: 'FullAWSAccess'
      })
      await store.saveOrganizationPolicyMetadata(
        orgId,
        'rcps',
        'p-RcpFullAWSAccess',
        'policy',
        fullAccessPolicy
      )
      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-j48dn38', 'metadata', {
        arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38',
        name: 'TestPolicy1'
      })
      await store.saveOrganizationPolicyMetadata(orgId, 'rcps', 'p-j48dn38', 'policy', s3Scp)

      // When getting the RCPs for the OU
      const rcps = await client.getRcpsForOrgUnit(orgId, orgUnit1Id)

      // Then it should return the SCPs
      expect(rcps).toEqual([
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-RcpFullAWSAccess',
          name: 'FullAWSAccess',
          policy: fullAccessPolicy
        },
        {
          arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-j48dn38',
          name: 'TestPolicy1',
          policy: s3Scp
        }
      ])
    })
  })

  describe('getAccountIdForBucket', () => {
    it('should return the account ID for a bucket ARN', async () => {
      // Given a bucket ARN
      const { store, client } = newStore()
      const bucketName = 'my-bucket'
      const accountId = '123456789012'
      // And the bucket exists in the account
      await store.saveIndex(
        'buckets-to-accounts',
        {
          [bucketName]: {
            accountId
          }
        },
        ''
      )
      // When getting the account ID for the bucket
      const result = await client.getAccountIdForBucket(bucketName)
      // Then it should return the account ID
      expect(result).toEqual(accountId)
    })

    it('should return undefined if the bucket name does not exist', async () => {
      // Given a bucket name that does not exist
      const { store, client } = newStore()
      const bucketName = 'non-existent-bucket'
      // When getting the account ID for the bucket
      const result = await client.getAccountIdForBucket(bucketName)
      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getAccountIdForRestApi', () => {
    it('should return the account ID for a RestApi ARN', async () => {
      // Given a RestApi ARN
      const { store, client } = newStore()
      const restApiId = 'arn:aws:apigateway:us-east-1::/restapis/rkyvy56npi'

      const accountId = '123456789012'

      // And the RestApi exists in the account
      await store.saveIndex(
        'apigateways-to-accounts',
        {
          [restApiId]: accountId
        },
        ''
      )

      // When getting the account ID for the RestApi
      const result = await client.getAccountIdForRestApi(restApiId)

      // Then it should return the account ID
      expect(result).toEqual(accountId)
    })

    it('should return undefined if the RestApi ID does not exist', async () => {
      // Given a RestApi ID that does not exist
      const { store, client } = newStore()
      const restApiId = 'arn:aws:apigateway:us-east-1::/restapis/non-existent-restapi'

      // When getting the account ID for the RestApi
      const result = await client.getAccountIdForRestApi(restApiId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getManagedPoliciesForUser', () => {
    it('should return an empty array if the user does not exist', async () => {
      // Given a user that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the managed policies for the user
      const policies = await client.getManagedPoliciesForUser(userArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the manged policies for the user', async () => {
      // Given a user with managed policies
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      const managedPolicyArn1 = `arn:aws:iam::${accountId}:policy/Policy1`
      const managedPolicyArn2 = `arn:aws:iam::${accountId}:policy/Policy2`
      const managedPolicy1 = {
        arn: managedPolicyArn1,
        name: 'Policy1',
        policy: { Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }
      }
      const managedPolicy2 = {
        arn: managedPolicyArn2,
        name: 'Policy2',
        policy: { Statement: [{ Effect: 'Deny', Action: 'ec2:*', Resource: '*' }] }
      }

      // Save user with managed policies
      await store.saveResourceMetadata(accountId, userArn, 'managed-policies', [
        managedPolicyArn1,
        managedPolicyArn2
      ])

      // Save managed policy metadata and policy documents
      await store.saveResourceMetadata(accountId, managedPolicyArn1, 'metadata', {
        arn: managedPolicyArn1,
        name: 'Policy1'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn1,
        'policy',
        managedPolicy1.policy
      )

      await store.saveResourceMetadata(accountId, managedPolicyArn2, 'metadata', {
        arn: managedPolicyArn2,
        name: 'Policy2'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn2,
        'policy',
        managedPolicy2.policy
      )

      // When getting the managed policies for the user
      const policies = await client.getManagedPoliciesForUser(userArn)

      // Then it should return the managed policies
      expect(policies).toEqual([
        {
          arn: managedPolicyArn1,
          name: 'Policy1',
          policy: managedPolicy1.policy
        },
        {
          arn: managedPolicyArn2,
          name: 'Policy2',
          policy: managedPolicy2.policy
        }
      ])
    })
  })

  describe('getManagedPolicy', () => {
    it('should return the managed policy ', async () => {
      // Given a managed policy stored in the account
      const { store, client } = newStore()
      const accountId = '123456789012'
      const managedPolicyArn = `arn:aws:iam::${accountId}:policy/Policy1`
      const managedPolicy = {
        arn: managedPolicyArn,
        name: 'Policy1',
        policy: { Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }
      }

      // Save managed policy metadata and policy document
      await store.saveResourceMetadata(accountId, managedPolicyArn, 'metadata', {
        arn: managedPolicyArn,
        name: 'Policy1'
      })
      await store.saveResourceMetadata(accountId, managedPolicyArn, 'policy', managedPolicy.policy)

      // When getting the managed policy
      const result = await client.getManagedPolicy(accountId, managedPolicyArn)

      // Then it should return the managed policy
      expect(result).toEqual(managedPolicy)
    })
  })

  describe('getInlinePoliciesForUser', () => {
    it('should return an empty array if the user does not exist', async () => {
      // Given a user that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the inline policies for the user
      const policies = await client.getInlinePoliciesForUser(userArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the inline policies for the user', async () => {
      // Given a user with inline policies
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      const inlinePolicies = [
        {
          PolicyName: 'InlinePolicy1',
          PolicyDocument: { Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }
        },
        {
          PolicyName: 'InlinePolicy2',
          PolicyDocument: { Statement: [{ Effect: 'Deny', Action: 'ec2:*', Resource: '*' }] }
        }
      ]

      // Save inline policies for the user
      await store.saveResourceMetadata(accountId, userArn, 'inline-policies', inlinePolicies)

      // When getting the inline policies for the user
      const policies = await client.getInlinePoliciesForUser(userArn)

      // Then it should return the inline policies
      expect(policies).toEqual([
        {
          name: 'InlinePolicy1',
          policy: inlinePolicies[0].PolicyDocument
        },
        {
          name: 'InlinePolicy2',
          policy: inlinePolicies[1].PolicyDocument
        }
      ])
    })
  })

  describe('getIamUserMetadata', () => {
    it('should return undefined if the user does not exist', async () => {
      // Given a user that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the IAM user metadata
      const metadata = await client.getIamUserMetadata(userArn)

      // Then it should return undefined
      expect(metadata).toBeUndefined()
    })
    it('should return the IAM user metadata', async () => {
      // Given a user that exists
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      const userMetadata = {
        arn: userArn,
        path: '/',
        permissionBoundary: 'arn:aws:iam::aws:policy/PowerUserAccess',
        id: 'AIDAEXAMPLE',
        name: 'test-user',
        created: '2024-01-01T00:00:00Z'
      }

      // Save the user metadata
      await store.saveResourceMetadata(accountId, userArn, 'metadata', userMetadata)

      // When getting the IAM user metadata
      const metadata = await client.getIamUserMetadata(userArn)

      // Then it should return the user metadata
      expect(metadata).toEqual(userMetadata)
    })
  })

  describe('getGroupsForUser', () => {
    it('should return an empty array if the user does not exist', async () => {
      // Given a user that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the groups for the user
      const groups = await client.getGroupsForUser(userArn)

      // Then it should return an empty array
      expect(groups).toEqual([])
    })

    it('should return the groups for the user', async () => {
      // Given a user that exists and is a member of groups
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      const groupArns = [
        `arn:aws:iam::${accountId}:group/Group1`,
        `arn:aws:iam::${accountId}:group/Group2`
      ]

      // Save the groups metadata for the user
      await store.saveResourceMetadata(accountId, userArn, 'groups', groupArns)

      // When getting the groups for the user
      const groups = await client.getGroupsForUser(userArn)

      // Then it should return the group ARNs
      expect(groups).toEqual(groupArns)
    })
  })

  describe('getManagedPoliciesForGroup', () => {
    it('should return an empty array if the group does not exist', async () => {
      // Given a group that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`

      // When getting the managed policies for the group
      const policies = await client.getManagedPoliciesForGroup(groupArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the managed policies for the group', async () => {
      // Given a group with managed policies
      const { store, client } = newStore()
      const accountId = '123456789012'
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`
      const managedPolicyArn1 = `arn:aws:iam::${accountId}:policy/GroupPolicy1`
      const managedPolicyArn2 = `arn:aws:iam::${accountId}:policy/GroupPolicy2`
      const managedPolicy1 = {
        arn: managedPolicyArn1,
        name: 'GroupPolicy1',
        policy: { Statement: [{ Effect: 'Allow', Action: 'sqs:*', Resource: '*' }] }
      }
      const managedPolicy2 = {
        arn: managedPolicyArn2,
        name: 'GroupPolicy2',
        policy: { Statement: [{ Effect: 'Deny', Action: 'sns:*', Resource: '*' }] }
      }

      // Save group with managed policies
      await store.saveResourceMetadata(accountId, groupArn, 'managed-policies', [
        managedPolicyArn1,
        managedPolicyArn2
      ])

      // Save managed policy metadata and policy documents
      await store.saveResourceMetadata(accountId, managedPolicyArn1, 'metadata', {
        arn: managedPolicyArn1,
        name: 'GroupPolicy1'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn1,
        'policy',
        managedPolicy1.policy
      )

      await store.saveResourceMetadata(accountId, managedPolicyArn2, 'metadata', {
        arn: managedPolicyArn2,
        name: 'GroupPolicy2'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn2,
        'policy',
        managedPolicy2.policy
      )

      // When getting the managed policies for the group
      const policies = await client.getManagedPoliciesForGroup(groupArn)

      // Then it should return the managed policies
      expect(policies).toEqual([
        {
          arn: managedPolicyArn1,
          name: 'GroupPolicy1',
          policy: managedPolicy1.policy
        },
        {
          arn: managedPolicyArn2,
          name: 'GroupPolicy2',
          policy: managedPolicy2.policy
        }
      ])
    })
  })

  describe('getInlinePoliciesForGroup', () => {
    it('should return an empty array if the group does not exist', async () => {
      // Given a group that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`

      // When getting the inline policies for the group
      const policies = await client.getInlinePoliciesForGroup(groupArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })

    it('should return the inline policies for the group', async () => {
      // Given a group with inline policies
      const { store, client } = newStore()
      const accountId = '123456789012'
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`
      const inlinePolicies = [
        {
          PolicyName: 'GroupInlinePolicy1',
          PolicyDocument: {
            Statement: { Sid: 'Policy1', Effect: 'Allow', Action: 'sqs:*', Resource: '*' }
          }
        },
        {
          PolicyName: 'GroupInlinePolicy2',
          PolicyDocument: {
            Statement: { Sid: 'Policy2', Effect: 'Deny', Action: 'sns:*', Resource: '*' }
          }
        }
      ]

      // Save inline policies for the group
      await store.saveResourceMetadata(accountId, groupArn, 'inline-policies', inlinePolicies)

      // When getting the inline policies for the group
      const policies = await client.getInlinePoliciesForGroup(groupArn)

      // Then it should return the inline policies
      expect(policies).toEqual([
        {
          name: 'GroupInlinePolicy1',
          policy: inlinePolicies[0].PolicyDocument
        },
        {
          name: 'GroupInlinePolicy2',
          policy: inlinePolicies[1].PolicyDocument
        }
      ])
    })
  })

  describe('getPermissionsBoundaryForUser', () => {
    it('should return undefined if no permissions boundary is set', async () => {
      // Given a user that does not have a permissions boundary
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      store.saveResourceMetadata(accountId, userArn, 'metadata', {
        arn: userArn
      })

      // When getting the permissions boundary for the user
      const permissionsBoundary = await client.getPermissionsBoundaryForUser(userArn)

      // Then it should return undefined
      expect(permissionsBoundary).toBeUndefined()
    })

    it('should return undefined if the user does not exist', async () => {
      // Given a user that does not have a permissions boundary
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the permissions boundary for the user
      const permissionsBoundary = await client.getPermissionsBoundaryForUser(userArn)

      // Then it should return undefined
      expect(permissionsBoundary).toBeUndefined()
    })
    it('should return the permission boundary if set', async () => {
      // Given a user with a permissions boundary set
      const { store, client } = newStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      const permissionsBoundaryArn = `arn:aws:iam::${accountId}:policy/BoundaryPolicy`
      const boundaryPolicy = {
        arn: permissionsBoundaryArn,
        name: 'BoundaryPolicy',
        policy: { Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }
      }

      // Save user metadata with permissions boundary
      await store.saveResourceMetadata(accountId, userArn, 'metadata', {
        arn: userArn,
        permissionBoundary: permissionsBoundaryArn
      })

      // Save the boundary policy metadata and document
      await store.saveResourceMetadata(accountId, permissionsBoundaryArn, 'metadata', {
        arn: permissionsBoundaryArn,
        name: 'BoundaryPolicy'
      })
      await store.saveResourceMetadata(
        accountId,
        permissionsBoundaryArn,
        'policy',
        boundaryPolicy.policy
      )

      // When getting the permissions boundary for the user
      const permissionsBoundary = await client.getPermissionsBoundaryForUser(userArn)

      // Then it should return the permissions boundary policy
      expect(permissionsBoundary).toEqual(boundaryPolicy)
    })
  })

  describe('getManagedPoliciesForRole', () => {
    it('should return an empty array if the role does not exist', async () => {
      // Given a role that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      // When getting the managed policies for the role
      const policies = await client.getManagedPoliciesForRole(roleArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the managed policies for the role', async () => {
      // Given a role with managed policies
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`
      const managedPolicyArn1 = `arn:aws:iam::${accountId}:policy/RolePolicy1`
      const managedPolicyArn2 = `arn:aws:iam::${accountId}:policy/RolePolicy2`
      const managedPolicy1 = {
        arn: managedPolicyArn1,
        name: 'RolePolicy1',
        policy: { Statement: [{ Effect: 'Allow', Action: 'lambda:*', Resource: '*' }] }
      }
      const managedPolicy2 = {
        arn: managedPolicyArn2,
        name: 'RolePolicy2',
        policy: { Statement: [{ Effect: 'Deny', Action: 'dynamodb:*', Resource: '*' }] }
      }

      // Save role with managed policies
      await store.saveResourceMetadata(accountId, roleArn, 'managed-policies', [
        managedPolicyArn1,
        managedPolicyArn2
      ])

      // Save managed policy metadata and policy documents
      await store.saveResourceMetadata(accountId, managedPolicyArn1, 'metadata', {
        arn: managedPolicyArn1,
        name: 'RolePolicy1'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn1,
        'policy',
        managedPolicy1.policy
      )

      await store.saveResourceMetadata(accountId, managedPolicyArn2, 'metadata', {
        arn: managedPolicyArn2,
        name: 'RolePolicy2'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn2,
        'policy',
        managedPolicy2.policy
      )

      // When getting the managed policies for the role
      const policies = await client.getManagedPoliciesForRole(roleArn)

      // Then it should return the managed policies
      expect(policies).toEqual([
        {
          arn: managedPolicyArn1,
          name: 'RolePolicy1',
          policy: managedPolicy1.policy
        },
        {
          arn: managedPolicyArn2,
          name: 'RolePolicy2',
          policy: managedPolicy2.policy
        }
      ])
    })
  })

  describe('getInlinePoliciesForRole', () => {
    it('should return an empty array if the role does not exist', async () => {
      // Given a role that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      // When getting the inline policies for the role
      const policies = await client.getInlinePoliciesForRole(roleArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the inline policies for the role', async () => {
      // Given a role with inline policies
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`
      const inlinePolicies = [
        {
          PolicyName: 'RoleInlinePolicy1',
          PolicyDocument: {
            Statement: { Sid: 'Policy1', Effect: 'Allow', Action: 'lambda:*', Resource: '*' }
          }
        },
        {
          PolicyName: 'RoleInlinePolicy2',
          PolicyDocument: {
            Statement: { Sid: 'Policy2', Effect: 'Deny', Action: 'dynamodb:*', Resource: '*' }
          }
        }
      ]

      // Save inline policies for the role
      await store.saveResourceMetadata(accountId, roleArn, 'inline-policies', inlinePolicies)

      // When getting the inline policies for the role
      const policies = await client.getInlinePoliciesForRole(roleArn)

      // Then it should return the inline policies
      expect(policies).toEqual([
        {
          name: 'RoleInlinePolicy1',
          policy: inlinePolicies[0].PolicyDocument
        },
        {
          name: 'RoleInlinePolicy2',
          policy: inlinePolicies[1].PolicyDocument
        }
      ])
    })
  })

  describe('getPermissionsBoundaryForRole', () => {
    it('should return undefined if the role does not exist', async () => {
      // Given a role that does not exist
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      // When getting the permissions boundary for the role
      const permissionsBoundary = await client.getPermissionsBoundaryForRole(roleArn)

      // Then it should return undefined
      expect(permissionsBoundary).toBeUndefined()
    })

    it('should return undefined if the role does not have a permissions boundary', async () => {
      // Given a role that does not have a permissions boundary
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      await store.saveResourceMetadata(accountId, roleArn, 'metadata', {
        arn: roleArn
      })

      // When getting the permissions boundary for the role
      const permissionsBoundary = await client.getPermissionsBoundaryForRole(roleArn)

      // Then it should return undefined
      expect(permissionsBoundary).toBeUndefined()
    })
    it('should return the permissions boundary if set', async () => {
      // Given a role with a permissions boundary set
      const { store, client } = newStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`
      const permissionsBoundaryArn = `arn:aws:iam::${accountId}:policy/BoundaryPolicy`
      const boundaryPolicy = {
        arn: permissionsBoundaryArn,
        name: 'BoundaryPolicy',
        policy: { Statement: { Sid: 'PB', Effect: 'Allow', Action: 's3:*', Resource: '*' } }
      }

      // Save role metadata with permissions boundary
      await store.saveResourceMetadata(accountId, roleArn, 'metadata', {
        arn: roleArn,
        permissionBoundary: permissionsBoundaryArn
      })

      // Save the boundary policy metadata and document
      await store.saveResourceMetadata(accountId, permissionsBoundaryArn, 'metadata', {
        arn: permissionsBoundaryArn,
        name: 'BoundaryPolicy'
      })
      await store.saveResourceMetadata(
        accountId,
        permissionsBoundaryArn,
        'policy',
        boundaryPolicy.policy
      )

      // When getting the permissions boundary for the role
      const permissionsBoundary = await client.getPermissionsBoundaryForRole(roleArn)

      // Then it should return the permissions boundary policy
      expect(permissionsBoundary).toEqual(boundaryPolicy)
    })
  })
})
