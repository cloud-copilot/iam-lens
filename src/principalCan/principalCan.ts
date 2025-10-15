import { loadPolicy } from '@cloud-copilot/iam-policy'
import { shrinkJsonDocument } from '@cloud-copilot/iam-shrink'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../collect/client.js'
import { getAllPoliciesForPrincipal } from '../principals.js'
import {
  addPoliciesToPermissionSet,
  buildPermissionSetFromPolicies,
  PermissionSet,
  toPolicyStatements
} from './permissionSet.js'
import {
  allIamRolesAssumeRolePermissionSets,
  iamRolesSameAccount
} from './resources/resourceTypes/iamRoles.js'
import {
  allKmsKeysAllActionsPermissionSets,
  kmsKeysSameAccount
} from './resources/resourceTypes/kmsKeys.js'
import { s3BucketsSameAccount } from './resources/resourceTypes/s3Buckets.js'

/**
 * Input for the can-what command.
 */
export interface PrincipalCanInput {
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
export async function principalCan(collectClient: IamCollectClient, input: PrincipalCanInput) {
  const { principal } = input

  if (!principal) {
    throw new Error('Principal must be provided for can-what command')
  }

  const principalArnParts = splitArnParts(principal)

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

  const resourceDenyPermissions = new PermissionSet('Deny')

  /*********** Start KMS Keys *************/
  const { keyAllows: allKeysAllow, keyDenies: allKeysDeny } =
    await allKmsKeysAllActionsPermissionSets()

  const identityKeyPermissions = allKeysAllow.intersection(allowedPermissions)

  // Remove all the KMS permissions from the identityAllows, add them back later
  finalPermissions = finalPermissions.subtract(allKeysDeny).allow

  // Get all the KMS permission for the same account
  const {
    accountAllows: keyAccountAllows,
    principalAllows: keyPrincipalAllows,
    denies: keyDenies
  } = await kmsKeysSameAccount(collectClient, principal)

  // Add in the principal allows
  finalPermissions.addAll(keyPrincipalAllows)

  // Add the account allows intersected with the identity allows
  for (const keyAcctAllow of keyAccountAllows) {
    finalPermissions.addAll(keyAcctAllow.intersection(identityKeyPermissions))
  }

  // Add the denies for later
  resourceDenyPermissions.addAll(keyDenies)
  /*********** End KMS Keys *************/

  /*********** Start Role Trust Policies *************/
  const { roleAllows: allRolesAllow, roleDenies: allRolesDeny } =
    await allIamRolesAssumeRolePermissionSets()

  const identityAssumeRolePermissions = allRolesAllow.intersection(allowedPermissions)

  // Remove all the KMS permissions from the identityAllows, add them back later
  finalPermissions = finalPermissions.subtract(allRolesDeny).allow

  // Get all the KMS permission for the same account
  const {
    accountAllows: roleAccountAllows,
    principalAllows: rolePrincipalAllows,
    denies: roleDenies
  } = await iamRolesSameAccount(collectClient, principal)

  // Add in the principal allows
  finalPermissions.addAll(rolePrincipalAllows)

  // Add the account allows intersected with the identity allows
  for (const roleAcctAllow of roleAccountAllows) {
    finalPermissions.addAll(roleAcctAllow.intersection(identityAssumeRolePermissions))
  }

  // Add the denies for later
  resourceDenyPermissions.addAll(roleDenies)
  /*********** End Role Trust Policies *************/

  /*********** Start Buckets *************/
  const { allows: bucketAllows, denies: bucketDenies } = await s3BucketsSameAccount(
    collectClient,
    principal
  )

  finalPermissions.addAll(bucketAllows)
  resourceDenyPermissions.addAll(bucketDenies)
  /*********** End Buckets *************/

  // TODO: There is a slight wrinkle where same account resource policies can override implicit denies from Permission Boundaries.
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

  //Put together all the denies
  principalAccountDenyPermissions.addAll(resourceDenyPermissions)

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
