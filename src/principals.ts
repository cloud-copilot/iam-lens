import { AwsIamStore } from '@cloud-copilot/iam-collect'
import { IamCollectClient } from './collect/client.js'
import { splitArnParts } from './util/arn.js'

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

interface SimulationIdentityPolicy {
  name: string
  policy: any
}

/**
 * Get all the IAM policies for a user, including managed and inline policies, permission boundaries, and group policies.
 *
 * @param collectClient the IAM collect client to use for retrieving policies
 * @param principalArn the ARN of the user to get policies for
 * @returns an object containing the managed policies, inline policies, permission boundary, and group policies
 */
export async function getAllPoliciesForUser(collectClient: IamCollectClient, principalArn: string) {
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
      managedPolices: groupManagedPolicies,
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
export async function getAllPoliciesForRole(collectClient: IamCollectClient, principalArn: string) {
  const accountId = splitArnParts(principalArn).accountId!

  const managedPolices = await collectClient.getManagedPoliciesForRole(principalArn)
  const inlinePolicies = await collectClient.getInlinePoliciesForRole(principalArn)
  const permissionBoundary = await collectClient.getPermissionsBoundaryForRole(principalArn)
  const scps = await collectClient.getScpHierarchyForAccount(accountId)
  const rcps = await collectClient.getRcpHierarchyForAccount(accountId)

  return {
    scps,
    rcps,
    managedPolices,
    inlinePolicies,
    permissionBoundary
  }
}
