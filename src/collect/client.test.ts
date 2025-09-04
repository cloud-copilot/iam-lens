import { describe, expect, it } from 'vitest'
import { makePrincipalIndex } from '../principalIndex/makePrincipalIndex.js'
import { saveGroup, saveManagedPolicy, saveRole, saveUser } from '../utils/testUtils.js'
import { testStore } from './inMemoryClient.js'

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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-12345678', 'policy', {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 's3:*',
            Resource: '*'
          }
        ]
      })

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
              policy: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: 's3:*',
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      ])
    })
  })

  describe('getOrgUnitHierarchyForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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

      await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-12345678', 'policy', {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 's3:*',
            Resource: '*'
          }
        ]
      })

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
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ])
    })
  })

  describe('getRcpsForAccount', () => {
    it('should return an empty array for a standalone account', async () => {
      // Given an account that doesn't exist in an org
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
      const restApiId = 'arn:aws:apigateway:us-east-1::/restapis/non-existent-restapi'

      // When getting the account ID for the RestApi
      const result = await client.getAccountIdForRestApi(restApiId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getAccountIdForVpcEndpointId', () => {
    it('should return the account ID for a VPC endpoint ID', async () => {
      // Given a VPC endpoint ID
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-12345678'
      const accountId = '123456789012'
      const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

      // And the VPC endpoint exists in the account
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {
            [vpcEndpointId]: {
              arn: vpcEndpointArn,
              vpc: 'vpc-12345678'
            }
          }
        },
        ''
      )

      // When getting the account ID for the VPC endpoint
      const result = await client.getAccountIdForVpcEndpointId(vpcEndpointId)

      // Then it should return the account ID
      expect(result).toEqual(accountId)
    })

    it('should return undefined if the VPC endpoint ID does not exist', async () => {
      // Given a VPC endpoint ID that does not exist
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-nonexistent'

      // And the VPC index exists but without the endpoint
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {}
        },
        ''
      )

      // When getting the account ID for the VPC endpoint
      const result = await client.getAccountIdForVpcEndpointId(vpcEndpointId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getOrgIdForVpcEndpointId', () => {
    it('should return the organization ID for a VPC endpoint ID', async () => {
      // Given a VPC endpoint ID in an account that belongs to an organization
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-12345678'
      const accountId = '123456789012'
      const orgId = 'o-87654321'
      const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

      // And the VPC endpoint exists in the account
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {
            [vpcEndpointId]: {
              arn: vpcEndpointArn,
              vpc: 'vpc-12345678'
            }
          }
        },
        ''
      )

      // And the account is part of an organization
      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      // When getting the organization ID for the VPC endpoint
      const result = await client.getOrgIdForVpcEndpointId(vpcEndpointId)

      // Then it should return the organization ID
      expect(result).toEqual(orgId)
    })

    it('should return undefined if the VPC endpoint ID does not exist', async () => {
      // Given a VPC endpoint ID that does not exist
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-nonexistent'

      // And the VPC index exists but without the endpoint
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {}
        },
        ''
      )

      // When getting the organization ID for the VPC endpoint
      const result = await client.getOrgIdForVpcEndpointId(vpcEndpointId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })

    it('should return undefined if the account is not part of an organization', async () => {
      // Given a VPC endpoint ID in an account that is not part of an organization
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-12345678'
      const accountId = '123456789012'
      const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

      // And the VPC endpoint exists in the account
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {
            [vpcEndpointId]: {
              arn: vpcEndpointArn,
              vpc: 'vpc-12345678'
            }
          }
        },
        ''
      )

      // And the account is not mapped to any organization
      await store.saveIndex('accounts-to-orgs', {}, '')

      // When getting the organization ID for the VPC endpoint
      const result = await client.getOrgIdForVpcEndpointId(vpcEndpointId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getOrgUnitHierarchyForVpcEndpointId', () => {
    it('should return the organization unit hierarchy for a VPC endpoint ID', async () => {
      // Given a VPC endpoint ID in an account that belongs to an organization
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-12345678'
      const accountId = '123456789012'
      const orgId = 'o-87654321'
      const rootOu = 'r-4fkd'
      const orgUnit1Id = 'ou-4fkd-12345678'
      const orgUnit2Id = 'ou-4fkd-87654321'
      const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

      // And the VPC endpoint exists in the account
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {
            [vpcEndpointId]: {
              arn: vpcEndpointArn,
              vpc: 'vpc-12345678'
            }
          }
        },
        ''
      )

      // And the account is part of an organization
      await store.saveIndex(
        'accounts-to-orgs',
        {
          [accountId]: orgId
        },
        ''
      )

      // And the account is in an OU
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId]: {
          ou: orgUnit2Id
        }
      })

      // And the org has OUs with hierarchy
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [orgUnit1Id]: {
          parent: rootOu
        },
        [orgUnit2Id]: {
          parent: orgUnit1Id
        }
      })

      // When getting the organization unit hierarchy for the VPC endpoint
      const result = await client.getOrgUnitHierarchyForVpcEndpointId(vpcEndpointId)

      // Then it should return the organization unit hierarchy
      expect(result).toEqual([rootOu, orgUnit1Id, orgUnit2Id])
    })

    it('should return undefined if the VPC endpoint ID does not exist', async () => {
      // Given a VPC endpoint ID that does not exist
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-nonexistent'

      // And the VPC index exists but without the endpoint
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {}
        },
        ''
      )

      // When getting the organization unit hierarchy for the VPC endpoint
      const result = await client.getOrgUnitHierarchyForVpcEndpointId(vpcEndpointId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })

    it('should return undefined if the account is not part of an organization', async () => {
      // Given a VPC endpoint ID in an account that is not part of an organization
      const { store, client } = testStore()
      const vpcEndpointId = 'vpce-12345678'
      const accountId = '123456789012'
      const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

      // And the VPC endpoint exists in the account
      await store.saveIndex(
        'vpcs',
        {
          vpcs: {},
          endpoints: {
            [vpcEndpointId]: {
              arn: vpcEndpointArn,
              vpc: 'vpc-12345678'
            }
          }
        },
        ''
      )

      // And the account is not mapped to any organization
      await store.saveIndex('accounts-to-orgs', {}, '')

      // When getting the organization unit hierarchy for the VPC endpoint
      const result = await client.getOrgUnitHierarchyForVpcEndpointId(vpcEndpointId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getManagedPoliciesForUser', () => {
    it('should return an empty array if the user does not exist', async () => {
      // Given a user that does not exist
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the managed policies for the user
      const policies = await client.getManagedPoliciesForUser(userArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the manged policies for the user', async () => {
      // Given a user with managed policies
      const { store, client } = testStore()
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
        'current-policy',
        managedPolicy1.policy
      )

      await store.saveResourceMetadata(accountId, managedPolicyArn2, 'metadata', {
        arn: managedPolicyArn2,
        name: 'Policy2'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn2,
        'current-policy',
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
      const { store, client } = testStore()
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
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn,
        'current-policy',
        managedPolicy.policy
      )

      // When getting the managed policy
      const result = await client.getManagedPolicy(accountId, managedPolicyArn)

      // Then it should return the managed policy
      expect(result).toEqual(managedPolicy)
    })
  })

  describe('getInlinePoliciesForUser', () => {
    it('should return an empty array if the user does not exist', async () => {
      // Given a user that does not exist
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the inline policies for the user
      const policies = await client.getInlinePoliciesForUser(userArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the inline policies for the user', async () => {
      // Given a user with inline policies
      const { store, client } = testStore()
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the IAM user metadata
      const metadata = await client.getIamUserMetadata(userArn)

      // Then it should return undefined
      expect(metadata).toBeUndefined()
    })
    it('should return the IAM user metadata', async () => {
      // Given a user that exists
      const { store, client } = testStore()
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the groups for the user
      const groups = await client.getGroupsForUser(userArn)

      // Then it should return an empty array
      expect(groups).toEqual([])
    })

    it('should return the groups for the user', async () => {
      // Given a user that exists and is a member of groups
      const { store, client } = testStore()
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`

      // When getting the managed policies for the group
      const policies = await client.getManagedPoliciesForGroup(groupArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the managed policies for the group', async () => {
      // Given a group with managed policies
      const { store, client } = testStore()
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
        'current-policy',
        managedPolicy1.policy
      )

      await store.saveResourceMetadata(accountId, managedPolicyArn2, 'metadata', {
        arn: managedPolicyArn2,
        name: 'GroupPolicy2'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn2,
        'current-policy',
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`

      // When getting the inline policies for the group
      const policies = await client.getInlinePoliciesForGroup(groupArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })

    it('should return the inline policies for the group', async () => {
      // Given a group with inline policies
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the permissions boundary for the user
      const permissionsBoundary = await client.getPermissionsBoundaryForUser(userArn)

      // Then it should return undefined
      expect(permissionsBoundary).toBeUndefined()
    })
    it('should return the permission boundary if set', async () => {
      // Given a user with a permissions boundary set
      const { store, client } = testStore()
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
        'current-policy',
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      // When getting the managed policies for the role
      const policies = await client.getManagedPoliciesForRole(roleArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the managed policies for the role', async () => {
      // Given a role with managed policies
      const { store, client } = testStore()
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
        'current-policy',
        managedPolicy1.policy
      )

      await store.saveResourceMetadata(accountId, managedPolicyArn2, 'metadata', {
        arn: managedPolicyArn2,
        name: 'RolePolicy2'
      })
      await store.saveResourceMetadata(
        accountId,
        managedPolicyArn2,
        'current-policy',
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      // When getting the inline policies for the role
      const policies = await client.getInlinePoliciesForRole(roleArn)

      // Then it should return an empty array
      expect(policies).toEqual([])
    })
    it('should return the inline policies for the role', async () => {
      // Given a role with inline policies
      const { store, client } = testStore()
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
      const { store, client } = testStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`

      // When getting the permissions boundary for the role
      const permissionsBoundary = await client.getPermissionsBoundaryForRole(roleArn)

      // Then it should return undefined
      expect(permissionsBoundary).toBeUndefined()
    })

    it('should return undefined if the role does not have a permissions boundary', async () => {
      // Given a role that does not have a permissions boundary
      const { store, client } = testStore()
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
      const { store, client } = testStore()
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
        'current-policy',
        boundaryPolicy.policy
      )

      // When getting the permissions boundary for the role
      const permissionsBoundary = await client.getPermissionsBoundaryForRole(roleArn)

      // Then it should return the permissions boundary policy
      expect(permissionsBoundary).toEqual(boundaryPolicy)
    })
  })

  describe('getResourcePolicyForArn', () => {
    it('should return the resource policy for a given ARN', async () => {
      // Given a resource with a policy
      const { store, client } = testStore()
      const accountId = '123456789012'
      const resourceArn = `arn:aws:s3:::my-bucket`
      const policy = { Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }

      await store.saveResourceMetadata(accountId, resourceArn, 'policy', policy)

      // When getting the resource policy for the ARN
      const result = await client.getResourcePolicyForArn(resourceArn, accountId)

      // Then it should return the policy
      expect(result).toEqual(policy)
    })
    it('should return undefined if no policy exists for the ARN', async () => {
      // Given a resource with no policy
      const { store, client } = testStore()
      const accountId = '123456789012'
      const resourceArn = `arn:aws:s3:::my-bucket`

      // When getting the resource policy for the ARN
      const result = await client.getResourcePolicyForArn(resourceArn, accountId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })

    it('should get the trust-policy for a role ARN', async () => {
      // Given a role with a trust policy
      const { store, client } = testStore()
      const accountId = '123456789012'
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`
      const trustPolicy = {
        Statement: [
          { Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }
        ]
      }
      await store.saveResourceMetadata(accountId, roleArn, 'trust-policy', trustPolicy)

      // When getting the trust policy for the role ARN
      const result = await client.getResourcePolicyForArn(roleArn, accountId)

      // Then it should return the trust policy
      expect(result).toEqual(trustPolicy)
    })

    it('should return a bucket policy for an S3 object ARN', async () => {
      // Given a bucket with a bucket policy
      const { store, client } = testStore()
      const accountId = '123456789012'
      const bucketArn = 'arn:aws:s3:::my-bucket'
      const bucketPolicy = {
        Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: `${bucketArn}/*` }]
      }
      await store.saveResourceMetadata(accountId, bucketArn, 'policy', bucketPolicy)

      // When getting the resource policy for the S3 object ARN
      const result = await client.getResourcePolicyForArn(`${bucketArn}/my-object`, accountId)

      // Then it should return the bucket policy
      expect(result).toEqual(bucketPolicy)
    })
  })

  describe('getRamSharePolicyForArn', () => {
    it('should return the RAM share policy for a given ARN', async () => {
      // Given a resource with a RAM share policy
      const { store, client } = testStore()
      const accountId = '123456789012'
      const resourceArn = `arn:aws:ram::${accountId}:resource-share/my-share`
      const ramSharePolicy = {
        Statement: [{ Effect: 'Allow', Action: 'ram:ShareResource', Resource: '*' }]
      }

      await store.saveRamResource(accountId, resourceArn, {
        arn: resourceArn,
        shares: ['share1', 'share2'],
        policy: ramSharePolicy
      })

      // When getting the RAM share policy for the ARN
      const result = await client.getRamSharePolicyForArn(resourceArn, accountId)

      // Then it should return the RAM share policy
      expect(result).toEqual(ramSharePolicy)
    })
    it('should return undefined if no RAM share policy exists for the ARN', async () => {
      // Given a resource with no RAM share policy
      const { store, client } = testStore()
      const accountId = '123456789012'
      const resourceArn = `arn:aws:ram::${accountId}:resource-share/my-share`

      // When getting the RAM share policy for the ARN
      const result = await client.getRamSharePolicyForArn(resourceArn, accountId)

      // Then it should return undefined
      expect(result).toBeUndefined()
    })
  })

  describe('getTagsForResource', () => {
    it('should return the tags for a given resource ARN', async () => {
      // Given a resource with tags
      const { store, client } = testStore()
      const accountId = '123456789012'
      const resourceArn = `arn:aws:s3:::my-bucket`
      const tags = { Environment: 'prod', Owner: 'alice' }

      await store.saveResourceMetadata(accountId, resourceArn, 'tags', tags)

      // When getting the tags for the resource ARN
      const result = await client.getTagsForResource(resourceArn, accountId)

      // Then it should return the tags
      expect(result).toEqual(tags)
    })
    it('should return an empty object if no tags exist for the resource ARN', async () => {
      // Given a resource with no tags
      const { store, client } = testStore()
      const accountId = '123456789012'
      const resourceArn = `arn:aws:s3:::my-bucket`

      // When getting the tags for the resource ARN
      const result = await client.getTagsForResource(resourceArn, accountId)

      // Then it should return undefined
      expect(result).toEqual({})
    })
  })

  describe('getUniqueIdForIamResource', () => {
    it('should return the unique ID for an IAM resource', async () => {
      // Given an IAM user with a unique ID
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      await store.saveResourceMetadata(accountId, userArn, 'metadata', {
        arn: userArn,
        id: 'AIDAEXAMPLE',
        name: 'test-user',
        path: '/',
        created: '2024-01-01T00:00:00Z'
      })

      // When getting the unique ID for the IAM resource
      // Assume the client has a method getUniqueIdForIamResource
      const uniqueId = await client.getUniqueIdForIamResource(userArn)

      // Then it should return the unique ID
      expect(uniqueId).toBe('AIDAEXAMPLE')
    })
    it('should return undefined if the IAM resource does not exist', async () => {
      // Given a non-existent IAM user
      const { client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`

      // When getting the unique ID for the IAM resource
      const uniqueId = await client.getUniqueIdForIamResource(userArn)

      // Then it should return undefined
      expect(uniqueId).toBeUndefined()
    })
  })

  describe('getAccountsForOrganization', () => {
    it('should return the accounts for an organization', async () => {
      // Given an organization with accounts
      const { store, client } = testStore()
      const orgId = 'o-12345678'
      const accountId1 = '100000000001'
      const accountId2 = '100000000002'
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        [accountId1]: { ou: 'ou-1' },
        [accountId2]: { ou: 'ou-2' }
      })

      // When getting the accounts for the organization
      const [exists, accounts] = await client.getAccountsForOrganization(orgId)

      // Then it should return true and the account IDs
      expect(exists).toBe(true)
      expect(accounts).toContain(accountId1)
      expect(accounts).toContain(accountId2)
      expect(accounts.length).toBe(2)
    })

    it('should return false and an empty array if the organization does not exist', async () => {
      // Given an organization that does not exist
      const { client } = testStore()
      const orgId = 'o-nonexistent'

      // When getting the accounts for the organization
      const [exists, accounts] = await client.getAccountsForOrganization(orgId)

      // Then it should return false and an empty array
      expect(exists).toBe(false)
      expect(accounts).toEqual([])
    })
  })

  describe('getAccountsForOrgPath', () => {
    it('should return false and empty if the org does not exist', async () => {
      // Given a non-existent org
      const { client } = testStore()
      const orgId = 'o-nonexistent'
      const orgPath = ['r-root']

      // When getting accounts for the org path
      const [exists, accounts] = await client.getAccountsForOrgPath(orgId, orgPath)

      // Then it should return false and empty array
      expect(exists).toBe(false)
      expect(accounts).toEqual([])
    })

    it('should return false and empty if the org path is empty', async () => {
      // Given an org with an empty path
      const { store, client } = testStore()
      const orgId = 'o-12345678'
      // Save some org structure
      await store.saveOrganizationMetadata(orgId, 'structure', {
        'r-root': {
          accounts: ['arn:aws:organizations::o-12345678:account/o-12345678/100000000001']
        }
      })

      // When getting accounts for the org path
      const [exists, accounts] = await client.getAccountsForOrgPath(orgId, [])

      // Then it should return false and empty array
      expect(exists).toBe(false)
      expect(accounts).toEqual([])
    })

    it('should return false and empty if the org path does not exist', async () => {
      // Given an org with a structure, but the path does not exist
      const { store, client } = testStore()
      const orgId = 'o-12345678'
      await store.saveOrganizationMetadata(orgId, 'structure', {
        'r-root': {
          accounts: ['arn:aws:organizations::o-12345678:account/o-12345678/100000000001']
        }
      })

      // When getting accounts for a non-existent path
      const [exists, accounts] = await client.getAccountsForOrgPath(orgId, [
        'r-root',
        'ou-nonexistent'
      ])

      // Then it should return false and empty array
      expect(exists).toBe(false)
      expect(accounts).toEqual([])
    })

    it('should return the accounts for the org path recursively', async () => {
      // Given an org structure as in the example
      const { store, client } = testStore()
      const orgId = 'o-uch56v3mmz'
      const orgStructure = {
        'r-dh2e': {
          children: {
            'ou-dh2e-aps19rip': {
              accounts: [
                'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000001',
                'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000002'
              ]
            },
            'ou-dh2e-bm9olc5a': {
              accounts: ['arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000003']
            },
            'ou-dh2e-hib9i2fv': {},
            'ou-dh2e-kxtfc3s3': {
              accounts: ['arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000004']
            },
            'ou-dh2e-lvgwe3dc': {
              children: {
                'ou-dh2e-1t6b0r7y': {
                  accounts: [
                    'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000005'
                  ]
                },
                'ou-dh2e-434nky50': {
                  accounts: [
                    'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000006',
                    'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000007',
                    'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000008'
                  ]
                }
              }
            },
            'ou-dh2e-s1150ym3': {
              accounts: [
                'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000009',
                'arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000010'
              ]
            }
          },
          accounts: ['arn:aws:organizations::100000000011:account/o-uch56v3mmz/100000000011']
        }
      }

      await store.saveOrganizationMetadata(orgId, 'structure', orgStructure)

      // When getting accounts for a deep org path
      const [exists, accounts] = await client.getAccountsForOrgPath(orgId, [
        'r-dh2e',
        'ou-dh2e-lvgwe3dc'
      ])

      // Then it should return all accounts under ou-dh2e-lvgwe3dc recursively
      expect(exists).toBe(true)
      expect(accounts).toEqual(['100000000005', '100000000006', '100000000007', '100000000008'])
    })
  })

  describe('getAllPrincipalsInAccount', () => {
    it('should return all principals in the account', async () => {
      // Given an account with multiple principals
      const { store, client } = testStore()
      const accountId = '123456789012'
      const userArn = `arn:aws:iam::${accountId}:user/test-user`
      const roleArn = `arn:aws:iam::${accountId}:role/test-role`
      const groupArn = `arn:aws:iam::${accountId}:group/test-group`

      await store.saveResourceMetadata(accountId, userArn, 'metadata', { arn: userArn })
      await store.saveResourceMetadata(accountId, roleArn, 'metadata', { arn: roleArn })
      await store.saveResourceMetadata(accountId, groupArn, 'metadata', { arn: groupArn })

      // When getting all principals in the account
      const principals = await client.getAllPrincipalsInAccount(accountId)

      // Then it should return all principal ARNs
      expect(principals).toEqual([userArn, roleArn])
    })
  })

  describe('getPrincipalsWithActionAllowed', () => {
    it('should return undefined when principal index does not exist', async () => {
      // Given a store without a principal index
      const { client } = testStore()

      // When getting principals with action allowed
      const result = await client.getPrincipalsWithActionAllowed(
        '123456789012',
        ['123456789012'],
        's3:GetObject'
      )

      // Then it should return undefined
      expect(result).toBeUndefined()
    })

    it('should return principals with wildcard actions', async () => {
      // Given a store with principals and a built index
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userArn = `arn:aws:iam::${searchAccountId}:user/test-user`
      const roleArn = `arn:aws:iam::${searchAccountId}:role/test-role`

      // Set up user with full access policy (*) in allFromAccount
      await saveUser(store, {
        arn: userArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/full-access-policy`]
      })
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/full-access-policy`,
        policy: fullAccessPolicy
      })

      // Set up role with no policies in searchAccount (should not have access)
      await saveRole(store, { arn: roleArn })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount
      const result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the user from allFromAccount (not the role from searchAccount)
      expect(result).toEqual([userArn])
    })

    it('should return principals with specific service actions', async () => {
      // Given a store with principals and a built index
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userArn = `arn:aws:iam::${searchAccountId}:user/s3-user`
      const roleArn = `arn:aws:iam::${searchAccountId}:role/ec2-role`

      // Set up user with S3 access policy in allFromAccount
      await saveUser(store, {
        arn: userArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/s3-access-policy`]
      })
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/s3-access-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::example-bucket/*'
            }
          ]
        }
      })

      // Set up role with EC2 access policy in allFromAccount
      await saveRole(store, {
        arn: roleArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/ec2-access-policy`]
      })
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/ec2-access-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'ec2:*',
              Resource: '*'
            }
          ]
        }
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount
      const s3Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return only the S3 user from allFromAccount
      expect(s3Result).toEqual([userArn])

      // When getting principals with ec2:DescribeInstances action allowed from allFromAccount, searching in searchAccount
      const ec2Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        'ec2:DescribeInstances'
      )

      // Then it should return only the EC2 role from allFromAccount
      expect(ec2Result).toEqual([roleArn])
    })

    it('should return principals with specific action patterns', async () => {
      // Given a store with principals and policies with specific actions
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userArn = `arn:aws:iam::${searchAccountId}:user/specific-user`

      // Set up user with specific S3 actions in allFromAccount
      await saveUser(store, {
        arn: userArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/specific-s3-policy`]
      })

      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/specific-s3-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: '*'
            }
          ]
        }
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount
      const getResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the user from allFromAccount
      expect(getResult).toEqual([userArn])

      // When getting principals with s3:PutObject action allowed from allFromAccount, searching in searchAccount
      const putResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:PutObject'
      )

      // Then it should return the user from allFromAccount
      expect(putResult).toEqual([userArn])

      // When getting principals with s3:DeleteObject action allowed from allFromAccount, searching in searchAccount
      const deleteResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:DeleteObject'
      )

      // Then it should return empty array (user doesn't have delete access)
      expect(deleteResult).toEqual([])
    })

    it('should handle NotAction statements correctly', async () => {
      // Given a store with principals that have NotAction policies
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userArn = `arn:aws:iam::${searchAccountId}:user/not-action-user`

      // Set up user with NotAction policy (allow everything except s3:DeleteObject) in allFromAccount
      const notActionPolicy = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            NotAction: 's3:DeleteObject',
            Resource: '*'
          }
        ]
      }
      await saveUser(store, {
        arn: userArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/not-action-policy`]
      })
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/not-action-policy`,
        policy: notActionPolicy
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount (should be allowed)
      const getResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the user from allFromAccount
      expect(getResult).toEqual([userArn])

      // When getting principals with ec2:DescribeInstances action allowed from allFromAccount, searching in searchAccount (should be allowed)
      const ec2Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        'ec2:DescribeInstances'
      )

      // Then it should return the user from allFromAccount
      expect(ec2Result).toEqual([userArn])

      // When getting principals with s3:DeleteObject action allowed from allFromAccount, searching in searchAccount (should NOT be allowed)
      const deleteResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:DeleteObject'
      )

      // Then it should return empty array
      expect(deleteResult).toEqual([])
    })

    it('should handle multiple accounts and return principals from specified accounts', async () => {
      // Given multiple accounts with principals
      const { store, client } = testStore()
      const account1 = '111111111111'
      const account2 = '222222222222'
      const account3 = '333333333333'

      const user1Arn = `arn:aws:iam::${account1}:user/user1`
      const user2Arn = `arn:aws:iam::${account2}:user/user2`
      const user3Arn = `arn:aws:iam::${account3}:user/user3`

      // Set up users in different accounts with S3 access
      for (const [accountId, userArn] of [
        [account1, user1Arn],
        [account2, user2Arn],
        [account3, user3Arn]
      ]) {
        await saveUser(store, {
          arn: userArn,
          managedPolicies: [`arn:aws:iam::${accountId}:policy/s3-policy`]
        })
        await saveManagedPolicy(store, {
          arn: `arn:aws:iam::${accountId}:policy/s3-policy`,
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:ListBucket',
                Resource: 'arn:aws:s3:::example-bucket'
              }
            ]
          }
        })
      }

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:ListBucket action allowed from accounts 1 and 2 only
      const result = await client.getPrincipalsWithActionAllowed(
        '999999999999',
        [account1, account2],
        's3:ListBucket'
      )

      // Then it should return users from accounts 1 and 2, but not account 3
      expect(result).toEqual(expect.arrayContaining([user1Arn, user2Arn]))
      expect(result).not.toContain(user3Arn)
    })

    it('should include principals all principals from allFromAccount even if not in accountIds list', async () => {
      // Given multiple accounts with multiple principals each
      const { store, client } = testStore()
      const allFromAccount = '111111111111'
      const otherAccount = '222222222222'
      const searchAccount = '333333333333'

      // Multiple principals in allFromAccount (all should be returned)
      const user1FromAllArn = `arn:aws:iam::${allFromAccount}:user/user1-all`
      const user2FromAllArn = `arn:aws:iam::${allFromAccount}:user/user2-all`
      const role1FromAllArn = `arn:aws:iam::${allFromAccount}:role/role1-all`
      const role2FromAllArn = `arn:aws:iam::${allFromAccount}:role/role2-all`

      // Multiple principals in otherAccount (none should be returned)
      const user1FromOtherArn = `arn:aws:iam::${otherAccount}:user/user1-other`
      const user2FromOtherArn = `arn:aws:iam::${otherAccount}:user/user2-other`
      const role1FromOtherArn = `arn:aws:iam::${otherAccount}:role/role1-other`

      // Multiple principals in searchAccount (only those with S3 access should be returned)
      const user1FromSearchArn = `arn:aws:iam::${searchAccount}:user/user1-search` // has S3 access
      const user2FromSearchArn = `arn:aws:iam::${searchAccount}:user/user2-search` // no S3 access
      const role1FromSearchArn = `arn:aws:iam::${searchAccount}:role/role1-search` // has S3 access

      // Set up all principals in allFromAccount with S3 access
      const allFromPrincipals = [
        { arn: user1FromAllArn, type: 'user' },
        { arn: user2FromAllArn, type: 'user' },
        { arn: role1FromAllArn, type: 'role' },
        { arn: role2FromAllArn, type: 'role' }
      ]

      for (const principal of allFromPrincipals) {
        if (principal.type === 'user') {
          await saveUser(store, {
            arn: principal.arn,
            managedPolicies: [`arn:aws:iam::${allFromAccount}:policy/s3-policy`]
          })
        } else {
          await saveRole(store, {
            arn: principal.arn,
            managedPolicies: [`arn:aws:iam::${allFromAccount}:policy/s3-policy`]
          })
        }
      }

      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${allFromAccount}:policy/s3-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 's3:PutObject',
              Resource: 'arn:aws:s3:::test-bucket/*'
            }
          ]
        }
      })

      // Set up principals in otherAccount with S3 access (should not be returned)
      const otherAccountPrincipals = [
        { arn: user1FromOtherArn, type: 'user' },
        { arn: user2FromOtherArn, type: 'user' },
        { arn: role1FromOtherArn, type: 'role' }
      ]

      for (const principal of otherAccountPrincipals) {
        if (principal.type === 'user') {
          await saveUser(store, {
            arn: principal.arn,
            managedPolicies: [`arn:aws:iam::${otherAccount}:policy/s3-policy`]
          })
        } else {
          await saveRole(store, {
            arn: principal.arn,
            managedPolicies: [`arn:aws:iam::${otherAccount}:policy/s3-policy`]
          })
        }
      }

      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${otherAccount}:policy/s3-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 's3:PutObject',
              Resource: 'arn:aws:s3:::test-bucket/*'
            }
          ]
        }
      })

      // Set up principals in searchAccount - some with S3 access, some without
      await saveUser(store, {
        arn: user1FromSearchArn,
        managedPolicies: [`arn:aws:iam::${searchAccount}:policy/s3-policy`]
      })

      await saveUser(store, {
        arn: user2FromSearchArn,
        managedPolicies: [`arn:aws:iam::${searchAccount}:policy/ec2-policy`] // no S3 access
      })

      await saveRole(store, {
        arn: role1FromSearchArn,
        managedPolicies: [`arn:aws:iam::${searchAccount}:policy/s3-policy`]
      })

      // S3 policy for searchAccount
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccount}:policy/s3-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 's3:PutObject',
              Resource: 'arn:aws:s3:::test-bucket/*'
            }
          ]
        }
      })

      // EC2 policy for searchAccount (no S3 access)
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccount}:policy/ec2-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'ec2:*',
              Resource: '*'
            }
          ]
        }
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:PutObject action allowed from allFromAccount, searching in searchAccount
      const result = await client.getPrincipalsWithActionAllowed(
        allFromAccount,
        [searchAccount],
        's3:PutObject'
      )

      // Then it should return ALL principals from allFromAccount (even though not in search list)
      expect(result).toEqual(
        expect.arrayContaining([user1FromAllArn, user2FromAllArn, role1FromAllArn, role2FromAllArn])
      )

      // And it should return only the principals with S3 access from searchAccount
      expect(result).toEqual(expect.arrayContaining([user1FromSearchArn, role1FromSearchArn]))

      // But it should NOT return principals without S3 access from searchAccount
      expect(result).not.toContain(user2FromSearchArn)

      // And it should NOT return any principals from otherAccount
      expect(result).not.toContain(user1FromOtherArn)
      expect(result).not.toContain(user2FromOtherArn)
      expect(result).not.toContain(role1FromOtherArn)

      // Verify the total count is correct (4 from allFromAccount + 2 from searchAccount)
      expect(result).toHaveLength(6)
    })

    it('should handle inline policies correctly', async () => {
      // Given a principal with inline policies
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const roleArn = `arn:aws:iam::${searchAccountId}:role/inline-role`

      // Set up role with inline S3 policy in allFromAccount
      await saveRole(store, {
        arn: roleArn,
        inlinePolicies: [
          {
            PolicyName: 'InlineS3Policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::private-files/*'
                }
              ]
            }
          }
        ]
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount
      const result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the role with inline policy from allFromAccount
      expect(result).toEqual([roleArn])
    })

    it('should handle group policies for users', async () => {
      // Given a user that belongs to a group with policies
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userArn = `arn:aws:iam::${searchAccountId}:user/group-user`
      const groupArn = `arn:aws:iam::${searchAccountId}:group/s3-group`

      // Set up user in allFromAccount
      await saveUser(store, {
        arn: userArn,
        groups: [groupArn]
      })

      // Set up group with S3 policy in allFromAccount
      await saveGroup(store, {
        arn: groupArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/group-s3-policy`]
      })
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/group-s3-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::company-data/*'
            }
          ]
        }
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount
      const result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the user from allFromAccount (who gets access via group membership)
      expect(result).toEqual([userArn])
    })

    it('should handle inline policies on groups for users', async () => {
      // Given a user that belongs to a group with inline policies
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userArn = `arn:aws:iam::${searchAccountId}:user/inline-group-user`
      const groupArn = `arn:aws:iam::${searchAccountId}:group/inline-group`

      // Set up user in allFromAccount
      await saveUser(store, {
        arn: userArn,
        groups: [groupArn]
      })

      // Set up group with inline policy in allFromAccount
      await saveGroup(store, {
        arn: groupArn,
        inlinePolicies: [
          {
            PolicyName: 'InlineGroupS3Policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: ['s3:GetObject', 's3:ListBucket'],
                  Resource: ['arn:aws:s3:::shared-bucket/*', 'arn:aws:s3:::shared-bucket']
                }
              ]
            }
          },
          {
            PolicyName: 'InlineGroupEC2Policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: 'ec2:DescribeInstances',
                  Resource: '*'
                }
              ]
            }
          }
        ]
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with s3:GetObject action allowed from allFromAccount, searching in searchAccount
      const s3Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the user from allFromAccount (who gets access via group's inline policy)
      expect(s3Result).toEqual([userArn])

      // When getting principals with s3:ListBucket action allowed from allFromAccount, searching in searchAccount
      const listResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:ListBucket'
      )

      // Then it should return the user from allFromAccount (who gets access via group's inline policy)
      expect(listResult).toEqual([userArn])

      // When getting principals with ec2:DescribeInstances action allowed from allFromAccount, searching in searchAccount
      const ec2Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        'ec2:DescribeInstances'
      )

      // Then it should return the user from allFromAccount (who gets access via group's inline policy)
      expect(ec2Result).toEqual([userArn])

      // When getting principals with an action not granted by the inline policies
      const denyResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:DeleteObject'
      )

      // Then it should return empty array (user doesn't have delete access)
      expect(denyResult).toEqual([])
    })

    it('should match Action "*" wildcard against any action from different accounts', async () => {
      // Given users in searchAccount with wildcard action and no permissions
      const { store, client } = testStore()
      const allFromAccountId = '123456789012'
      const searchAccountId = '111111111111'
      const userWithWildcardArn = `arn:aws:iam::${searchAccountId}:user/wildcard-user`
      const userWithoutPermissionsArn = `arn:aws:iam::${searchAccountId}:user/no-permissions-user`

      // Set up user in searchAccount with global wildcard action
      await saveUser(store, {
        arn: userWithWildcardArn,
        managedPolicies: [`arn:aws:iam::${searchAccountId}:policy/global-wildcard-policy`]
      })
      await saveManagedPolicy(store, {
        arn: `arn:aws:iam::${searchAccountId}:policy/global-wildcard-policy`,
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: '*',
              Resource: '*'
            }
          ]
        }
      })

      // Set up user in searchAccount with no permissions
      await saveUser(store, {
        arn: userWithoutPermissionsArn
        // No policies attached - should have no permissions
      })

      // Build the principal index
      await makePrincipalIndex(client)

      // When getting principals with various specific actions from allFromAccount, searching in searchAccount
      const s3Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        's3:GetObject'
      )

      // Then it should return the user with wildcard access from searchAccount
      expect(s3Result).toEqual([userWithWildcardArn])
      expect(s3Result).not.toContain(userWithoutPermissionsArn)

      // Test with completely different service actions
      const ec2Result = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        'ec2:DescribeInstances'
      )

      // Should still return the wildcard user from searchAccount
      expect(ec2Result).toEqual([userWithWildcardArn])
      expect(ec2Result).not.toContain(userWithoutPermissionsArn)

      // Test with IAM actions
      const iamResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        'iam:CreateUser'
      )

      // Should still return the wildcard user from searchAccount
      expect(iamResult).toEqual([userWithWildcardArn])
      expect(iamResult).not.toContain(userWithoutPermissionsArn)

      // Test with completely arbitrary service:action combination
      const customResult = await client.getPrincipalsWithActionAllowed(
        allFromAccountId,
        [searchAccountId],
        'customservice:SomeRandomAction'
      )

      // Should still return the wildcard user from searchAccount
      expect(customResult).toEqual([userWithWildcardArn])
      expect(customResult).not.toContain(userWithoutPermissionsArn)
    })
  })
})
