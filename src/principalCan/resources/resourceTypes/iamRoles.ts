import { expandIamActions } from '@cloud-copilot/iam-expand'
import { loadPolicy } from '@cloud-copilot/iam-policy'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../../../collect/client.js'
import { Permission } from '../../permission.js'
import { addStatementToPermissionSet, PermissionSet } from '../../permissionSet.js'
import { statementAppliesToPrincipal } from '../statements.js'

/**
 * Get the list of IAM Actions to assume a role.
 *
 * @returns the list of IAM Actions to assume a role
 */
export async function stsRoleActions(): Promise<string[]> {
  const serviceActions = await expandIamActions('sts:AssumeRole*')
  const actions = serviceActions.map((a) => a.split(':').at(1)!)
  return [...actions, 'SetContext', 'TagSession', 'SetSourceIdentity']
}

/**
 * Get the permission sets for all IAM roles to assume a role.
 *
 * @returns the permission sets for all IAM roles to assume a role
 */
export async function allIamRolesAssumeRolePermissionSets(): Promise<{
  roleAllows: PermissionSet
  roleDenies: PermissionSet
}> {
  const assumeRoleActions = await stsRoleActions()
  const allowPerimeter = new PermissionSet('Allow')
  const denyPerimeter = new PermissionSet('Deny')
  for (const action of assumeRoleActions) {
    allowPerimeter.addPermission(
      new Permission('Allow', 'sts', action, ['*'], undefined, undefined)
    )
    denyPerimeter.addPermission(new Permission('Deny', 'sts', action, ['*'], undefined, undefined))
  }

  return { roleAllows: allowPerimeter, roleDenies: denyPerimeter }
}

/**
 * Get the permissions a principal has to assume roles in the same account.
 * This will only return permissions for sts:AssumeRole and not other assume role actions.
 *
 * @param collectClient the client to use to collect IAM information
 * @param principal the principal to check permissions for
 * @returns the permissions the principal has to assume roles in the same account
 */
export async function iamRolesSameAccount(
  collectClient: IamCollectClient,
  principal: string
): Promise<{
  accountAllows: PermissionSet[]
  principalAllows: PermissionSet[]
  denies: PermissionSet[]
}> {
  const principalArnParts = splitArnParts(principal)
  const principalAccountId = principalArnParts.accountId!

  const assumeRoleActions = ['AssumeRole', 'SetContext', 'TagSession', 'SetSourceIdentity']
  const allRoles = await collectClient.listResources(principalAccountId, 'iam', 'role', undefined)

  const accountAllows: PermissionSet[] = []
  const principalAllows: PermissionSet[] = []
  const denies: PermissionSet[] = []

  for (const roleArn of allRoles) {
    const rawPolicy = await collectClient.getResourcePolicyForArn(roleArn, principalAccountId)
    if (!rawPolicy) {
      continue
    }

    const allowPerimeter = new PermissionSet('Allow')
    const denyPerimeter = new PermissionSet('Deny')
    for (const action of assumeRoleActions) {
      allowPerimeter.addPermission(
        new Permission('Allow', 'sts', action, [roleArn], undefined, undefined)
      )
      denyPerimeter.addPermission(
        new Permission('Deny', 'sts', action, [roleArn], undefined, undefined)
      )
    }

    const roleAcctAllow = new PermissionSet('Allow')
    const rolePrincipalAllow = new PermissionSet('Allow')
    const roleDeny = new PermissionSet('Deny')

    addRoleArnToStatements(rawPolicy, roleArn)
    const trustPolicy = loadPolicy(rawPolicy)

    for (const statement of trustPolicy.statements()) {
      const applies = await statementAppliesToPrincipal(statement, principal, collectClient)
      if (applies === 'PrincipalMatch') {
        if (statement.isAllow()) {
          await addStatementToPermissionSet(statement, rolePrincipalAllow)
        } else {
          await addStatementToPermissionSet(statement, roleDeny)
        }
      } else if (applies === 'AccountMatch' && statement.isAllow()) {
        await addStatementToPermissionSet(statement, roleAcctAllow)
      }
    }

    const effectivePrincipalAllow = rolePrincipalAllow.intersection(allowPerimeter)
    const effectiveAccountAllow = roleAcctAllow.intersection(allowPerimeter)
    const effectiveDeny = roleDeny.intersection(denyPerimeter)

    if (!effectivePrincipalAllow.isEmpty()) {
      principalAllows.push(effectivePrincipalAllow)
    }
    if (!effectiveAccountAllow.isEmpty()) {
      accountAllows.push(effectiveAccountAllow)
    }
    if (!effectiveDeny.isEmpty()) {
      denies.push(effectiveDeny)
    }
  }

  return {
    accountAllows,
    principalAllows,
    denies
  }
}

function addRoleArnToStatements(policy: any, roleArn: string) {
  const statement = policy.Statement
  if (Array.isArray(statement)) {
    for (const statement of policy.Statement) {
      statement.Resource = [roleArn]
    }
  } else if (statement) {
    statement.Resource = [roleArn]
  }
}
