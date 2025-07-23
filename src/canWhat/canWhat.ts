import { loadPolicy } from '@cloud-copilot/iam-policy'
import { shrinkJsonDocument } from '@cloud-copilot/iam-shrink'
import { IamCollectClient } from '../collect/client.js'
import { getAllPoliciesForPrincipal } from '../principals.js'
import {
  addPoliciesToPermissionSet,
  buildPermissionSetFromPolicies,
  PermissionSet,
  toPolicyStatements
} from './permissionSet.js'

/**
 * Input for the can-what command.
 */
export interface CanWhatInput {
  /**
   * The ARN of the principal to check permissions for.
   */
  principal: string

  /**
   * Whether to shrink action lists in the resulting policy document.
   */
  shrinkActionLists: boolean
}

/**
 * Get what actions a principal can perform based on their policies.
 *
 * @param collectClient the IAM collect client to use for retrieving policies.
 * @param input the input containing the principal and options.
 * @returns A promise that resolves to the permissions the principal can perform, or void if the implementation is incomplete.
 */
export async function canWhat(collectClient: IamCollectClient, input: CanWhatInput) {
  const { principal } = input

  if (!principal) {
    throw new Error('Principal must be provided for can-what command')
  }

  const principalPolicies = await getAllPoliciesForPrincipal(collectClient, principal)

  const identityPolicies = [
    ...principalPolicies.managedPolicies,
    ...principalPolicies.inlinePolicies,
    ...(principalPolicies.groupPolicies?.map((group) => group.managedPolicies).flat() || []),
    ...(principalPolicies.groupPolicies?.map((group) => group.inlinePolicies).flat() || [])
  ].map((policy) => loadPolicy(policy.policy))

  const allowedPermissions = await buildPermissionSetFromPolicies('Allow', identityPolicies)
  const identityDenyPermissions = await buildPermissionSetFromPolicies('Deny', identityPolicies)

  let finalPermissions = allowedPermissions

  if (principalPolicies.permissionBoundary) {
    const boundaryPolicy = loadPolicy(principalPolicies.permissionBoundary.policy)
    const boundaryPermissions = await buildPermissionSetFromPolicies('Allow', [boundaryPolicy])
    finalPermissions = allowedPermissions.intersection(boundaryPermissions)
  }

  const scpAllowsByLevel: PermissionSet[] = []
  const rcpAllowsByLevel: PermissionSet[] = []

  for (const level of principalPolicies.scps) {
    const scpPolicies = level.policies.map((scp) => loadPolicy(scp.policy))
    scpAllowsByLevel.push(await buildPermissionSetFromPolicies('Allow', scpPolicies))
    await addPoliciesToPermissionSet(identityDenyPermissions, 'Deny', scpPolicies)
  }

  const principalAccountDenyPermissions = identityDenyPermissions.clone()
  for (const level of principalPolicies.rcps) {
    const rcpPolicies = level.policies.map((rcp) => loadPolicy(rcp.policy))
    rcpAllowsByLevel.push(await buildPermissionSetFromPolicies('Allow', rcpPolicies))
    await addPoliciesToPermissionSet(principalAccountDenyPermissions, 'Deny', rcpPolicies)
  }

  for (const scpAllow of scpAllowsByLevel) {
    finalPermissions = finalPermissions.intersection(scpAllow)
  }

  for (const rcpAllow of rcpAllowsByLevel) {
    finalPermissions = finalPermissions.intersection(rcpAllow)
  }

  const permissionsAfterDeny = finalPermissions.subtract(principalAccountDenyPermissions)
  finalPermissions = permissionsAfterDeny.allow
  const deniedPermissions = permissionsAfterDeny.deny

  const allowStatements = toPolicyStatements(finalPermissions)
  const denyStatements = toPolicyStatements(deniedPermissions)

  const policyDocument = {
    Version: '2012-10-17',
    Statement: [...allowStatements, ...denyStatements]
  }

  if (input.shrinkActionLists) {
    await shrinkJsonDocument({ iterations: 0 }, policyDocument)
  }

  return policyDocument
}
