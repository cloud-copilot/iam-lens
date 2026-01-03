import { loadPolicy } from '@cloud-copilot/iam-policy'
import { shrinkJsonDocument } from '@cloud-copilot/iam-shrink'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../collect/client.js'
import { getAllPoliciesForPrincipal } from '../principals.js'
import {
  addStatementToPermissionSet,
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
import { s3BucketsCrossAccount, s3BucketsSameAccount } from './resources/resourceTypes/s3Buckets.js'
import { statementAppliesToPrincipal } from './resources/statements.js'

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
    throw new Error('Principal must be provided for principal-can command')
  }

  const principalAccountId = splitArnParts(principal).accountId!

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
  //📋 Get all current permissions
  const { keyAllows: allKeysAllow, keyDenies: allKeysDeny } =
    await allKmsKeysAllActionsPermissionSets()

  //📋 Capture what is currently allowed by identity policies
  const identityKeyPermissions = allKeysAllow.intersection(allowedPermissions)

  //📋 Do any subtractions first
  // Remove all the KMS permissions from the identityAllows, add them back later
  finalPermissions = finalPermissions.subtract(allKeysDeny).allow

  //📋 Get the permissions for the account
  // Get all the KMS permission for the same account
  const {
    accountAllows: keyAccountAllows,
    principalAllows: keyPrincipalAllows,
    denies: keyDenies
  } = await kmsKeysSameAccount(collectClient, principal)

  //📋 Add direct permissions for the principal
  // Add in the principal allows
  finalPermissions.addAll(keyPrincipalAllows)

  //📋 Intersect account allows with identity allows
  // Add the account allows intersected with the identity allows
  for (const keyAcctAllow of keyAccountAllows) {
    finalPermissions.addAll(keyAcctAllow.intersection(identityKeyPermissions))
  }

  //📋 Add the denies.
  // Add the denies for later
  resourceDenyPermissions.addAll(keyDenies)
  /*********** End KMS Keys *************/

  /*********** Start Role Trust Policies *************/
  const { roleAllows: allRolesAllow, roleDenies: allRolesDeny } =
    await allIamRolesAssumeRolePermissionSets()

  const identityAssumeRolePermissions = allRolesAllow.intersection(allowedPermissions)

  // Remove all the IAM role permissions from the identityAllows, add them back later
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
    const boundaryDenies = await buildPermissionSetFromPolicies('Deny', [boundaryPolicy])
    identityDenyPermissions.addAll(boundaryDenies)
    finalPermissions = finalPermissions.intersection(boundaryPermissions)
  }

  /*********** Start Cross Account Checks *************/
  // 📋 List the accounts
  // 📋 Get the RCPs, if any
  // 📋 Get the bucket permission sets for the account
  // 📋 Intersect with identity permissions and Permission boundary by using `finalPermissions`
  // 📋 Subtract denies from identity permissions, SCPs, and Permission Boundary

  const allAccounts = await collectClient.allAccounts()
  const otherAccountAllows: PermissionSet = new PermissionSet('Allow')
  const otherAccountDenies: PermissionSet = new PermissionSet('Deny')

  for (const otherAccountId of allAccounts) {
    if (otherAccountId === principalAccountId) {
      continue
    }

    const rcpPolicies = await collectClient.getRcpHierarchyForAccount(otherAccountId)
    const otherAccountRcpDenies = new PermissionSet('Deny')

    for (const level of rcpPolicies) {
      const rcpPolicies = level.policies.map((rcp) => loadPolicy(rcp.policy))
      for (const policy of rcpPolicies) {
        for (const statement of policy.statements()) {
          if (statement.isDeny()) {
            // Only Add RCP denies that apply to the principal
            const applies = await statementAppliesToPrincipal(statement, principal, collectClient)
            if (applies === 'PrincipalMatch' || applies === 'AccountMatch') {
              await addStatementToPermissionSet(statement, otherAccountRcpDenies)
            }
          }
        }
      }
    }

    const { allows: otherAccountBucketAllows, denies: otherAccountBucketDenies } =
      await s3BucketsCrossAccount(collectClient, otherAccountId, otherAccountRcpDenies, principal)
    otherAccountAllows.addAll(otherAccountBucketAllows)
    otherAccountDenies.addAll(otherAccountBucketDenies)
  }

  let effectiveOtherAccountAllows = otherAccountAllows.intersection(finalPermissions)
  /*********** End Cross Account Checks *************/

  const scpAllowsByLevel: PermissionSet[] = []
  const rcpAllowsByLevel: PermissionSet[] = []

  for (const level of principalPolicies.scps) {
    const scpPolicies = level.policies.map((scp) => loadPolicy(scp.policy))
    scpAllowsByLevel.push(await buildPermissionSetFromPolicies('Allow', scpPolicies))
    for (const policy of scpPolicies) {
      for (const statement of policy.statements()) {
        if (statement.isDeny()) {
          // Only Add SCP denies that apply to the principal
          const applies = await statementAppliesToPrincipal(statement, principal, collectClient)
          if (applies === 'PrincipalMatch' || applies === 'AccountMatch') {
            await addStatementToPermissionSet(statement, identityDenyPermissions)
          }
        }
      }
    }
  }

  const principalAccountDenyPermissions = identityDenyPermissions.clone()
  for (const level of principalPolicies.rcps) {
    const rcpPolicies = level.policies.map((rcp) => loadPolicy(rcp.policy))
    rcpAllowsByLevel.push(await buildPermissionSetFromPolicies('Allow', rcpPolicies))
    for (const policy of rcpPolicies) {
      for (const statement of policy.statements()) {
        if (statement.isDeny()) {
          // Only Add RCPs denies that apply to the principal
          const applies = await statementAppliesToPrincipal(statement, principal, collectClient)
          if (applies === 'PrincipalMatch' || applies === 'AccountMatch') {
            await addStatementToPermissionSet(statement, principalAccountDenyPermissions)
          }
        }
      }
    }
  }

  for (const scpAllow of scpAllowsByLevel) {
    finalPermissions = finalPermissions.intersection(scpAllow)
    effectiveOtherAccountAllows = effectiveOtherAccountAllows.intersection(scpAllow)
  }

  for (const rcpAllow of rcpAllowsByLevel) {
    finalPermissions = finalPermissions.intersection(rcpAllow)
  }

  //Put together all the denies
  principalAccountDenyPermissions.addAll(resourceDenyPermissions)

  /* Same account final permissions after denies */
  const sameAccountPermissionsAfterDeny = finalPermissions.subtract(principalAccountDenyPermissions)
  finalPermissions = sameAccountPermissionsAfterDeny.allow
  const deniedPermissions = sameAccountPermissionsAfterDeny.deny

  const allowStatements = toPolicyStatements(finalPermissions)
  const denyStatements = toPolicyStatements(deniedPermissions)

  /* Cross account final permissions */
  // Combine all the denies that apply to cross account
  const allCrossAccountDenies = principalAccountDenyPermissions.clone()
  allCrossAccountDenies.addAll(otherAccountDenies)
  // Subtract the denies from the cross account allows
  const crossAccountPermissionsAfterDeny =
    effectiveOtherAccountAllows.subtract(allCrossAccountDenies)
  const crossAccountAllowStatements = toPolicyStatements(crossAccountPermissionsAfterDeny.allow)
  const crossAccountDenyStatements = toPolicyStatements(crossAccountPermissionsAfterDeny.deny)

  /* Create a policy document for everything */
  const policyDocument = {
    Version: '2012-10-17',
    Statement: [
      ...allowStatements,
      ...denyStatements,
      ...crossAccountAllowStatements,
      ...crossAccountDenyStatements
    ]
  }

  if (input.shrinkActionLists) {
    await shrinkJsonDocument({ iterations: 0 }, policyDocument)
  }

  return policyDocument
}
