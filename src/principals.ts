import { AwsIamStore } from '@cloud-copilot/iam-collect'
import {
  convertAssumedRoleArnToRoleArn,
  isAssumedRoleArn,
  isIamRoleArn,
  isIamUserArn,
  splitArnParts
} from '@cloud-copilot/iam-utils'
import {
  IamCollectClient,
  InlinePolicy,
  ManagedPolicy,
  SimulationOrgPolicies
} from './collect/client.js'

/**
 * Check if a principal exists in the specified AWS IAM store.
 */
export async function principalExists(
  storageClient: AwsIamStore,
  principalArn: string
): Promise<boolean> {
  const accountId = splitArnParts(principalArn).accountId!
  const principalData = await storageClient.getResourceMetadata(accountId, principalArn, 'metadata')
  return !!principalData
}

export interface PrincipalPolicies {
  managedPolicies: ManagedPolicy[]
  inlinePolicies: InlinePolicy[]
  permissionBoundary: ManagedPolicy | undefined
  scps: SimulationOrgPolicies[]
  rcps: SimulationOrgPolicies[]
  groupPolicies?: {
    group: string
    managedPolicies: ManagedPolicy[]
    inlinePolicies: InlinePolicy[]
  }[]
}

/**
 * Get all the IAM policies for a user, including managed and inline policies, permission boundaries, and group policies.
 *
 * @param collectClient the IAM collect client to use for retrieving policies
 * @param principalArn the ARN of the user to get policies for
 * @returns an object containing the managed policies, inline policies, permission boundary, and group policies
 */
export async function getAllPoliciesForUser(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<PrincipalPolicies> {
  const accountId = splitArnParts(principalArn).accountId!

  const managedPolicies = await collectClient.getManagedPoliciesForUser(principalArn)
  const inlinePolicies = await collectClient.getInlinePoliciesForUser(principalArn)
  const permissionBoundary = await collectClient.getPermissionsBoundaryForUser(principalArn)
  const groups = await collectClient.getGroupsForUser(principalArn)
  const scps = await collectClient.getScpHierarchyForAccount(accountId)
  const rcps = await collectClient.getRcpHierarchyForAccount(accountId)
  const groupPolicies = []
  for (const group of groups) {
    const groupManagedPolicies = await collectClient.getManagedPoliciesForGroup(group)
    const groupInlinePolicies = await collectClient.getInlinePoliciesForGroup(group)
    groupPolicies.push({
      group,
      managedPolicies: groupManagedPolicies,
      inlinePolicies: groupInlinePolicies
    })
  }
  return {
    scps,
    rcps,
    managedPolicies,
    inlinePolicies,
    permissionBoundary,
    groupPolicies
  }
}

/**
 * Get all the IAM policies for a role, including managed and inline policies and permission boundaries.
 *
 * @param collectClient the IAM collect client to use for retrieving policies
 * @param principalArn the ARN of the role to get policies for
 * @returns an object containing the managed policies, inline policies, and permission boundary
 */
export async function getAllPoliciesForRole(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<PrincipalPolicies> {
  const accountId = splitArnParts(principalArn).accountId!

  const managedPolicies = await collectClient.getManagedPoliciesForRole(principalArn)
  const inlinePolicies = await collectClient.getInlinePoliciesForRole(principalArn)
  const permissionBoundary = await collectClient.getPermissionsBoundaryForRole(principalArn)
  const scps = await collectClient.getScpHierarchyForAccount(accountId)
  const rcps = await collectClient.getRcpHierarchyForAccount(accountId)

  return {
    scps,
    rcps,
    managedPolicies,
    inlinePolicies,
    permissionBoundary
  }
}

export async function getAllPoliciesForPrincipal(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<PrincipalPolicies> {
  if (isServicePrincipal(principalArn)) {
    return {
      scps: [],
      rcps: [],
      managedPolicies: [],
      inlinePolicies: [],
      permissionBoundary: undefined,
      groupPolicies: []
    }
  }

  if (isIamUserArn(principalArn)) {
    return getAllPoliciesForUser(collectClient, principalArn)
  } else if (isIamRoleArn(principalArn)) {
    return getAllPoliciesForRole(collectClient, principalArn)
  } else if (isAssumedRoleArn(principalArn)) {
    const roleArn = convertAssumedRoleArnToRoleArn(principalArn)
    return getAllPoliciesForRole(collectClient, roleArn)
  }
  throw new Error(`Unsupported principal type: ${principalArn}`)
}

export function isArnPrincipal(principal: string): boolean {
  return principal.startsWith('arn:')
}

export function isServicePrincipal(principal: string): boolean {
  return !isArnPrincipal(principal) && principal.endsWith('amazonaws.com')
}

export function isServiceLinkedRole(principal: string): boolean {
  const arnParts = splitArnParts(principal)
  return isArnPrincipal(principal) && !!arnParts.resourcePath?.startsWith('aws-service-role/')
}
