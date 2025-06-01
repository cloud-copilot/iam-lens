import { AwsIamStore } from '@cloud-copilot/iam-collect'
import { splitArnParts } from '@cloud-copilot/iam-utils'

//TODO: Import this from iam-simulate
export interface SimulationOrgPolicies {
  orgIdentifier: string
  policies: { name: string; policy: any }[]
}

interface IamUserMetadata {
  arn: string
  path: string
  permissionBoundary: string
  id: string
  name: string
  created: string
}

interface ResourceMetadata {
  arn: string
}

interface InlinePolicyMetadata {
  PolicyName: string
  PolicyDocument: any
}

export interface OrgPolicy {
  arn: string
  name: string
  policy: any
}

interface ManagedPolicyMetadata {
  arn: string
  name: string
}

export interface ManagedPolicy {
  arn: string
  name: string
  policy: any
}

export interface InlinePolicy {
  name: string
  policy: any
}

interface OrgAccount {
  ou: string
  rcps: string[]
  scps: string[]
}

type OrgAccounts = Record<string, OrgAccount>

interface StoredOrgPolicyMetadata {
  arn: string
  name: string
  awsManaged: boolean
}

interface OrgUnitDetails {
  parent: string | undefined
  scps: string[]
  rcps: string[]
}

type OrgUnits = Record<string, OrgUnitDetails>

type OrgPolicyType = 'scps' | 'rcps'

interface OrganizationMetadata {
  id: string
  arn: string
  rootOu: string
  rootAccountArn: string
  rootAccountId: string
  features: {
    AISERVICES_OPT_OUT_POLICY?: boolean
    BACKUP_POLICY?: boolean
    RESOURCE_CONTROL_POLICY?: boolean
    SERVICE_CONTROL_POLICY?: boolean
    TAG_POLICY?: boolean
  }
}

interface RAMShare {
  arn: string
  shares: string[]
  policy: any
}

interface OrgStructureNode {
  children?: OrgStructure | undefined
  accounts?: string[] | undefined
}

interface OrgStructure {
  [key: string]: OrgStructureNode
}

export interface IamCollectClientOptions {
  enableCaching?: boolean
}

export class IamCollectClient {
  private _cache: Record<string, any> = {}
  private _enableCaching: boolean

  constructor(
    private storageClient: AwsIamStore,
    clientOptions?: IamCollectClientOptions
  ) {
    this._enableCaching = clientOptions?.enableCaching !== false
  }

  // Generic cache helper
  private async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    if (this._enableCaching && cacheKey in this._cache) {
      return this._cache[cacheKey]
    }
    const value = await fetcher()
    if (this._enableCaching) {
      this._cache[cacheKey] = value
    }
    return value
  }

  /**
   * Checks if an account exists in the store.
   * @param accountId The ID of the account to check.
   * @returns True if the account exists, false otherwise.
   */
  async accountExists(accountId: string): Promise<boolean> {
    const accounts = await this.storageClient.listAccountIds()
    return accounts.includes(accountId)
  }

  /**
   * Get all account IDs in the store.
   *
   * @returns all account IDs in the store
   */
  async allAccounts(): Promise<string[]> {
    return this.storageClient.listAccountIds()
  }

  /**
   * Checks if a principal exists in the store.
   * @param principalArn The ARN of the principal to check.
   * @returns True if the principal exists, false otherwise.
   */
  async principalExists(principalArn: string): Promise<boolean> {
    const accountId = splitArnParts(principalArn).accountId!
    const principalData = await this.storageClient.getResourceMetadata(
      accountId,
      principalArn,
      'metadata'
    )
    return !!principalData
  }

  /**
   * Gets the SCP Hierarchy for an account. The first element is the root, the last element is the account itself.
   * @param accountId The ID of the account to get the SCP Hierarchy for.
   * @returns The SCP Hierarchy for the account.
   */
  async getScpHierarchyForAccount(accountId: string): Promise<SimulationOrgPolicies[]> {
    return this.getOrgPolicyHierarchyForAccount(accountId, 'scps')
  }

  /**
   * Gets the policy hierarchy for an account for a given policy type.
   * @param accountId The ID of the account.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @returns The policy hierarchy for the account.
   */
  async getOrgPolicyHierarchyForAccount(
    accountId: string,
    policyType: OrgPolicyType
  ): Promise<SimulationOrgPolicies[]> {
    const cacheKey = `orgPolicyHierarchy:${accountId}:${policyType}`
    return this.withCache(cacheKey, async () => {
      const orgId = await this.getOrgIdForAccount(accountId)
      if (!orgId) {
        return []
      }
      // SCPs and RCPs do not apply to the root account
      const orgMetadata = await this.getOrganizationMetadata(orgId)
      if (orgMetadata.rootAccountId === accountId) {
        return []
      }

      const policyHierarchy: SimulationOrgPolicies[] = []
      const orgHierarchy = await this.getOrgUnitHierarchyForAccount(accountId)

      for (const ouId of orgHierarchy) {
        const policies = await this.getOrgPoliciesForOrgUnit(orgId, ouId, policyType)

        policyHierarchy.push({
          orgIdentifier: ouId,
          policies: policies.map((p) => ({
            name: p.arn,
            policy: p.policy
          }))
        })
      }

      const accountPolicies = await this.getOrgPoliciesForAccount(accountId, policyType)
      policyHierarchy.push({
        orgIdentifier: accountId,
        policies: accountPolicies.map((p) => ({
          name: p.arn,
          policy: p.policy
        }))
      })

      return policyHierarchy
    })
  }

  /**
   * Gets the OUs for an account. The first element is the root,
   * the last element is the parent OU of the account.
   * @param accountId The ID of the account to get the OUs for.
   * @returns The OUs for the account.
   */
  async getOrgUnitHierarchyForAccount(accountId: string): Promise<string[]> {
    const orgId = await this.getOrgIdForAccount(accountId)
    if (!orgId) {
      return []
    }
    const ouIds: string[] = []
    let ouId = await this.getOrgUnitIdForAccount(accountId)
    ouIds.push(ouId!)
    while (ouId) {
      const parentOuId = await this.getParentOrgUnitIdForOrgUnit(orgId, ouId)
      if (parentOuId) {
        ouIds.unshift(parentOuId)
      }
      ouId = parentOuId
    }
    return ouIds
  }

  /**
   * Gets the org unit ID for an account.
   * @param accountId The ID of the account.
   * @returns The org unit ID for the account, or undefined if not found.
   */
  async getOrgUnitIdForAccount(accountId: string): Promise<string | undefined> {
    const orgId = await this.getOrgIdForAccount(accountId)
    if (!orgId) {
      return undefined
    }

    const accounts = (await this.getAccountDataForOrg(orgId))!
    return accounts[accountId].ou
  }

  /**
   * Gets the parent org unit ID for a given org unit.
   * @param orgId The ID of the organization.
   * @param ouId The ID of the org unit.
   * @returns The parent org unit ID, or undefined if not found.
   */
  async getParentOrgUnitIdForOrgUnit(orgId: string, ouId: string): Promise<string | undefined> {
    const ouData = await this.getOrgUnitsDataForOrg(orgId)
    const ou = ouData[ouId]
    return ou.parent
  }

  /**
   * Gets the SCPs for an account.
   * @param accountId The ID of the account.
   * @returns The SCPs for the account.
   */
  async getScpsForAccount(accountId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForAccount(accountId, 'scps')
  }

  /**
   * Gets the org policies for an account for a given policy type.
   * @param accountId The ID of the account.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @returns The org policies for the account.
   */
  async getOrgPoliciesForAccount(
    accountId: string,
    policyType: OrgPolicyType
  ): Promise<OrgPolicy[]> {
    const orgId = await this.getOrgIdForAccount(accountId)
    if (!orgId) {
      return []
    }

    const accounts = (await this.getAccountDataForOrg(orgId))!
    const orgInformation = accounts[accountId]
    const policyArns = orgInformation[policyType]
    const policies: OrgPolicy[] = []
    for (const policyArn of policyArns) {
      const policyInfo = await this.getOrgPolicy(orgId, policyType, policyArn)
      policies.push(policyInfo)
    }

    return policies
  }

  /**
   * Gets the account data for an organization.
   * @param orgId The ID of the organization.
   * @returns The account data for the organization.
   */
  async getAccountDataForOrg(orgId: string): Promise<OrgAccounts | undefined> {
    return this.storageClient.getOrganizationMetadata<OrgAccounts, OrgAccounts>(orgId, 'accounts')
  }

  /**
   * Gets the org units data for an organization.
   * @param orgId The ID of the organization.
   * @returns The org units data for the organization.
   */
  async getOrgUnitsDataForOrg(orgId: string): Promise<OrgUnits> {
    return this.storageClient.getOrganizationMetadata<OrgUnits, OrgUnits>(orgId, 'ous')
  }

  /**
   * Gets a specific org policy.
   * @param orgId The ID of the organization.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @param policyArn The ARN of the policy.
   * @returns The org policy.
   */
  async getOrgPolicy(
    orgId: string,
    policyType: OrgPolicyType,
    policyArn: string
  ): Promise<OrgPolicy> {
    const policyId = policyArn.split('/').at(-1)!
    const policyData = await this.storageClient.getOrganizationPolicyMetadata<
      StoredOrgPolicyMetadata,
      StoredOrgPolicyMetadata
    >(orgId, policyType, policyId, 'metadata')
    const policyDocument = await this.storageClient.getOrganizationPolicyMetadata(
      orgId,
      policyType,
      policyId,
      'policy'
    )
    if (!policyDocument) {
      console.error(`Policy document not found for ${policyArn} in org ${orgId}`)
    }

    return {
      arn: policyData.arn,
      name: policyData.name,
      policy: policyDocument
    }
  }

  /**
   * Gets the RCPs for an account.
   * @param accountId The ID of the account.
   * @returns The RCPs for the account.
   */
  async getRcpsForAccount(accountId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForAccount(accountId, 'rcps')
  }

  /**
   * Gets the RCP hierarchy for an account.
   * @param accountId The ID of the account.
   * @returns The RCP hierarchy for the account.
   */
  async getRcpHierarchyForAccount(accountId: string): Promise<SimulationOrgPolicies[]> {
    return this.getOrgPolicyHierarchyForAccount(accountId, 'rcps')
  }

  /**
   * Gets the SCPs for an org unit.
   * @param orgId The ID of the organization.
   * @param orgUnitId The ID of the org unit.
   * @returns The SCPs for the org unit.
   */
  async getScpsForOrgUnit(orgId: string, orgUnitId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForOrgUnit(orgId, orgUnitId, 'scps')
  }

  /**
   * Gets the org policies for an org unit for a given policy type.
   * @param orgId The ID of the organization.
   * @param orgUnitId The ID of the org unit.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @returns The org policies for the org unit.
   */
  async getOrgPoliciesForOrgUnit(
    orgId: string,
    orgUnitId: string,
    policyType: OrgPolicyType
  ): Promise<OrgPolicy[]> {
    const orgUnitInformation = await this.getOrgUnitsDataForOrg(orgId)
    const orgUnit = orgUnitInformation[orgUnitId]
    const orgPolicies = orgUnit[policyType]
    const policies: OrgPolicy[] = []
    for (const policyArn of orgPolicies) {
      const policyInfo = await this.getOrgPolicy(orgId, policyType, policyArn)
      policies.push(policyInfo)
    }

    return policies
  }

  /**
   * Gets the RCPs for an org unit.
   * @param orgId The ID of the organization.
   * @param orgUnitId The ID of the org unit.
   * @returns The RCPs for the org unit.
   */
  async getRcpsForOrgUnit(orgId: string, orgUnitId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForOrgUnit(orgId, orgUnitId, 'rcps')
  }

  /**
   * Gets the org ID for an account.
   * @param accountId The ID of the account.
   * @returns The org ID for the account, or undefined if not found.
   */
  async getOrgIdForAccount(accountId: string): Promise<string | undefined> {
    const index = await this.storageClient.getIndex<Record<string, string>>('accounts-to-orgs', {})
    const accountToOrgMap = index.data
    return accountToOrgMap[accountId]
  }

  /**
   * Gets the account ID for a given S3 bucket name.
   * @param bucketName The name of the bucket.
   * @returns The account ID for the bucket, or undefined if not found.
   */
  async getAccountIdForBucket(bucketName: string): Promise<string | undefined> {
    const index = await this.storageClient.getIndex<Record<string, { accountId: string }>>(
      'buckets-to-accounts',
      {}
    )
    const bucketToAccountMap = index.data
    return bucketToAccountMap[bucketName]?.accountId
  }

  /**
   * Gets the account ID for a given API Gateway ARN.
   * @param apiArn The ARN of the API Gateway.
   * @returns The account ID for the API Gateway, or undefined if not found.
   */
  async getAccountIdForRestApi(apiArn: string): Promise<string | undefined> {
    const index = await this.storageClient.getIndex<Record<string, string>>(
      'apigateways-to-accounts',
      {}
    )
    const bucketToAccountMap = index.data
    return bucketToAccountMap[apiArn]
  }

  /**
   * Gets the managed policies attached to a user.
   * @param userArn The ARN of the user.
   * @returns The managed policies for the user.
   */
  async getManagedPoliciesForUser(userArn: string): Promise<ManagedPolicy[]> {
    const accountId = splitArnParts(userArn).accountId!
    const managedPolicies = await this.storageClient.getResourceMetadata<string[], string[]>(
      accountId,
      userArn,
      'managed-policies',
      []
    )

    const results: ManagedPolicy[] = []

    for (const policyArn of managedPolicies) {
      results.push(await this.getManagedPolicy(accountId, policyArn))
    }

    return results
  }

  async getManagedPolicy(accountId: string, policyArn: string): Promise<ManagedPolicy> {
    const policyMetadata = await this.storageClient.getResourceMetadata<
      ManagedPolicyMetadata,
      ManagedPolicyMetadata
    >(accountId, policyArn, 'metadata')
    const policyDocument = await this.storageClient.getResourceMetadata(
      accountId,
      policyArn,
      'policy'
    )
    if (!policyDocument) {
      console.error(`Policy document not found for ${policyArn} in account ${accountId}`)
    }
    return {
      arn: policyMetadata.arn,
      name: policyMetadata.name,
      policy: policyDocument
    }
  }

  /**
   * Gets the inline policies attached to a user.
   * @param userArn The ARN of the user.
   * @returns The inline policies for the user.
   */
  async getInlinePoliciesForUser(userArn: string): Promise<InlinePolicy[]> {
    const accountId = splitArnParts(userArn).accountId!
    const inlinePolicies = await this.storageClient.getResourceMetadata<
      InlinePolicyMetadata[],
      InlinePolicyMetadata[]
    >(accountId, userArn, 'inline-policies', [])

    return inlinePolicies.map((p) => ({
      name: p.PolicyName,
      policy: p.PolicyDocument
    }))
  }

  async getIamUserMetadata(userArn: string): Promise<IamUserMetadata | undefined> {
    const accountId = splitArnParts(userArn).accountId!
    // The permissions boundary is stored as a policy ARN on the user resource metadata
    return this.storageClient.getResourceMetadata<IamUserMetadata, IamUserMetadata>(
      accountId,
      userArn,
      'metadata'
    )
  }

  /**
   * Gets the permissions boundary policy attached to a user, if any.
   *
   * @param userArn The ARN of the user.
   * @returns The permissions boundary policy as an OrgPolicy, or undefined if none is set.
   */
  async getPermissionsBoundaryForUser(userArn: string): Promise<ManagedPolicy | undefined> {
    const accountId = splitArnParts(userArn).accountId!
    // The permissions boundary is stored as a policy ARN on the user resource metadata
    const userMetadata = await this.getIamUserMetadata(userArn)
    if (!userMetadata) {
      return undefined
    }

    const permissionsBoundaryArn = userMetadata.permissionBoundary
    if (!permissionsBoundaryArn) {
      return undefined
    }

    return this.getManagedPolicy(accountId, permissionsBoundaryArn)
  }

  /**
   * Gets the group ARNs that the user is a member of.
   * @param userArn The ARN of the user.
   * @returns An array of group ARNs the user belongs to.
   */
  async getGroupsForUser(userArn: string): Promise<string[]> {
    const accountId = splitArnParts(userArn).accountId!
    const groups = await this.storageClient.getResourceMetadata<string[], string[]>(
      accountId,
      userArn,
      'groups',
      []
    )
    return groups
  }

  /**
   * Gets the managed policies attached to a group.
   *
   * @param groupArn The ARN of the group.
   * @returns The managed policies for the group.
   */
  async getManagedPoliciesForGroup(groupArn: string): Promise<ManagedPolicy[]> {
    const accountId = splitArnParts(groupArn).accountId!
    const managedPolicies = await this.storageClient.getResourceMetadata<string[], string[]>(
      accountId,
      groupArn,
      'managed-policies',
      []
    )

    const results: ManagedPolicy[] = []

    for (const policyArn of managedPolicies) {
      results.push(await this.getManagedPolicy(accountId, policyArn))
    }

    return results
  }

  async getInlinePoliciesForGroup(groupArn: string): Promise<InlinePolicy[]> {
    const accountId = splitArnParts(groupArn).accountId!
    const inlinePolicies = await this.storageClient.getResourceMetadata<
      InlinePolicyMetadata[],
      InlinePolicyMetadata[]
    >(accountId, groupArn, 'inline-policies', [])

    return inlinePolicies.map((p) => ({
      name: p.PolicyName,
      policy: p.PolicyDocument
    }))
  }

  async getManagedPoliciesForRole(roleArn: string): Promise<ManagedPolicy[]> {
    const accountId = splitArnParts(roleArn).accountId!
    const managedPolicies = await this.storageClient.getResourceMetadata<string[], string[]>(
      accountId,
      roleArn,
      'managed-policies',
      []
    )

    const results: ManagedPolicy[] = []

    for (const policyArn of managedPolicies) {
      results.push(await this.getManagedPolicy(accountId, policyArn))
    }

    return results
  }

  async getInlinePoliciesForRole(roleArn: string): Promise<InlinePolicy[]> {
    const accountId = splitArnParts(roleArn).accountId!
    const inlinePolicies = await this.storageClient.getResourceMetadata<
      InlinePolicyMetadata[],
      InlinePolicyMetadata[]
    >(accountId, roleArn, 'inline-policies', [])

    return inlinePolicies.map((p) => ({
      name: p.PolicyName,
      policy: p.PolicyDocument
    }))
  }

  async getPermissionsBoundaryForRole(roleArn: string): Promise<ManagedPolicy | undefined> {
    const accountId = splitArnParts(roleArn).accountId!
    // The permissions boundary is stored as a policy ARN on the user resource metadata
    const roleMetadata = await this.getIamUserMetadata(roleArn)
    if (!roleMetadata) {
      return undefined
    }

    const permissionsBoundaryArn = roleMetadata.permissionBoundary
    if (!permissionsBoundaryArn) {
      return undefined
    }

    return this.getManagedPolicy(accountId, permissionsBoundaryArn)
  }

  /**
   * Get the metadata for an organization.
   *
   * @param organizationId the id of the organization
   * @returns the metadata for the organization
   */
  async getOrganizationMetadata(organizationId: string): Promise<OrganizationMetadata> {
    return this.storageClient.getOrganizationMetadata<OrganizationMetadata, OrganizationMetadata>(
      organizationId,
      'metadata'
    )
  }

  /**
   * Gets the resource policy for a given resource ARN and account.
   *
   * @param resourceArn The ARN of the resource.
   * @param accountId The ID of the account.
   * @returns The resource policy, or undefined if not found.
   */
  async getResourcePolicyForArn(resourceArn: string, accountId: string): Promise<any | undefined> {
    const arnParts = splitArnParts(resourceArn)
    let metadataKey = 'policy'

    if (arnParts.service === 'iam' && arnParts.resourceType === 'role') {
      metadataKey = 'trust-policy'
    }

    const resourcePolicy = await this.storageClient.getResourceMetadata<string, string>(
      accountId,
      resourceArn,
      metadataKey
    )
    return resourcePolicy
  }

  /**
   * Gets the RAM share policy for a given resource ARN and account.
   *
   * @param resourceArn The ARN of the resource.
   * @param accountId The ID of the account.
   * @returns The RAM share policy, or undefined if not found.
   */
  async getRamSharePolicyForArn(resourceArn: string, accountId: string): Promise<any | undefined> {
    const armSharePolicy = await this.storageClient.getRamResource<RAMShare, RAMShare>(
      accountId,
      resourceArn
    )
    return armSharePolicy?.policy
  }

  /**
   * Gets the tags for a given resource ARN and account.
   *
   * @param resourceArn The ARN of the resource.
   * @param accountId The ID of the account.
   * @returns The tags as a record, or undefined if not found.
   */
  async getTagsForResource(
    resourceArn: string,
    accountId: string
  ): Promise<Record<string, string>> {
    const tags = await this.storageClient.getResourceMetadata<
      Record<string, string>,
      Record<string, string>
    >(accountId, resourceArn, 'tags')
    return tags || {}
  }

  /**
   * Gets a unique ID for an IAM resource based on its ARN and account ID.
   * Used specifically for IAM Users and Roles
   *
   * @param resourceArn the ARN of the IAM resource
   * @param accountId the ID of the account the resource belongs to
   * @returns a unique ID for the resource, or undefined if not found
   */
  async getUniqueIdForIamResource(resourceArn: string): Promise<string | undefined> {
    const accountId = splitArnParts(resourceArn).accountId!
    const resourceMetadata = await this.storageClient.getResourceMetadata<
      IamUserMetadata,
      IamUserMetadata
    >(accountId, resourceArn, 'metadata')

    return resourceMetadata?.id
  }

  /**
   * Get the account IDs for an organization.
   *
   * @param organizationId the ID of the organization
   * @returns a tuple containing a boolean indicating success and an array of account IDs
   */
  async getAccountsForOrganization(organizationId: string): Promise<[boolean, string[]]> {
    const organizationAccounts = await this.getAccountDataForOrg(organizationId)
    if (!organizationAccounts) {
      return [false, []]
    }
    const accountIds = Object.keys(organizationAccounts)
    return [true, accountIds]
  }

  /**
   * Get the organization structure or an organization.
   *
   * @param orgId the ID of the organization
   * @returns returns the organization structure or undefined if not found
   */
  async getOrganizationStructure(orgId: string): Promise<OrgStructure | undefined> {
    return this.storageClient.getOrganizationMetadata<OrgStructure, OrgStructure>(
      orgId,
      'structure'
    )
  }

  async getAccountsForOrgPath(orgId: string, ouIds: string[]): Promise<[boolean, string[]]> {
    const orgUnits = await this.getOrganizationStructure(orgId)
    if (!orgUnits || ouIds.length === 0) {
      return [false, []]
    }

    const rootOu = orgUnits[ouIds[0]]

    // Now look through the structure to find the OU
    let currentStructure: OrgStructureNode | undefined = rootOu
    for (const ou of ouIds.slice(1)) {
      currentStructure = currentStructure.children?.[ou]
      if (!currentStructure) {
        return [false, []] // OU not found in the structure
      }
    }

    const getAccountId = (a: string) => a.split('/').at(-1)!

    const accounts = []
    if (currentStructure.accounts) {
      accounts.push(...currentStructure.accounts?.map(getAccountId))
    }

    const children = Object.values(currentStructure.children || {})

    // Traverse the children to collect all accounts
    while (children.length > 0) {
      const child = children.shift()
      if (child?.accounts) {
        accounts.push(...child.accounts.map(getAccountId))
      }
      if (child?.children) {
        children.push(...Object.values(child.children))
      }
    }

    return [true, accounts]
  }

  async getAllPrincipalsInAccount(accountId: string): Promise<string[]> {
    const iamUsers = await this.storageClient.findResourceMetadata<ResourceMetadata>(accountId, {
      service: 'iam',
      resourceType: 'user',
      account: accountId
    })

    const iamRoles = await this.storageClient.findResourceMetadata<ResourceMetadata>(accountId, {
      service: 'iam',
      resourceType: 'role',
      account: accountId
    })

    return [...iamUsers.map((user) => user.arn), ...iamRoles.map((role) => role.arn)]
  }
}
