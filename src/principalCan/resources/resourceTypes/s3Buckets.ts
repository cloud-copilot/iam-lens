import { loadPolicy } from '@cloud-copilot/iam-policy'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../../../collect/client.js'
import { Permission } from '../../permission.js'
import { addStatementToPermissionSet, PermissionSet } from '../../permissionSet.js'
import { actionsForResourceType } from '../actions.js'
import { statementAppliesToPrincipal } from '../statements.js'

/**
 * Get the permission sets for S3 buckets in the same account as the principal.
 *
 * @param collectClient the IAM collect client to use for retrieving policies and resources
 * @param principal the ARN of the principal to check
 * @returns the Allow and Deny permission sets for S3 buckets in the same account as the principal
 */
export async function s3BucketsSameAccount(
  collectClient: IamCollectClient,
  principal: string
): Promise<{ allows: PermissionSet[]; denies: PermissionSet[] }> {
  const principalArnParts = splitArnParts(principal)
  const principalAccountId = principalArnParts.accountId!

  const allBuckets = await collectClient.listResources(
    principalAccountId,
    's3',
    'bucket',
    undefined
  )

  const bucketActions = await actionsForResourceType('s3', 'bucket')
  const objectActions = await actionsForResourceType('s3', 'object')

  const s3Actions = [...bucketActions, ...objectActions]

  const bucketAllowPermissionSets: PermissionSet[] = []
  const bucketDenyPermissionSets: PermissionSet[] = []

  for (const bucket of allBuckets) {
    const bucketPolicy = await collectClient.getResourcePolicyForArn(bucket, principalAccountId)
    if (bucketPolicy) {
      const loadedPolicy = loadPolicy(bucketPolicy)
      if (loadedPolicy) {
        const bucketArns = [bucket, `${bucket}/*`]
        const bucketAllowPerimeter = new PermissionSet('Allow')
        const bucketDenyPerimeter = new PermissionSet('Deny')
        for (const action of s3Actions) {
          bucketAllowPerimeter.addPermission(
            new Permission('Allow', 's3', action, bucketArns, undefined, undefined)
          )
          bucketDenyPerimeter.addPermission(
            new Permission('Deny', 's3', action, bucketArns, undefined, undefined)
          )
        }

        const allowPermissionSet = new PermissionSet('Allow')
        const denyPermissionSet = new PermissionSet('Deny')

        for (const statement of loadedPolicy.statements()) {
          const applies = await statementAppliesToPrincipal(statement, principal, collectClient)
          if (applies === 'PrincipalMatch') {
            if (statement.isAllow()) {
              await addStatementToPermissionSet(statement, allowPermissionSet)
            } else {
              await addStatementToPermissionSet(statement, denyPermissionSet)
            }
          }
        }

        const effectiveAllows = allowPermissionSet.intersection(bucketAllowPerimeter)
        const effectiveDenies = denyPermissionSet.intersection(bucketDenyPerimeter)
        if (!effectiveAllows.isEmpty()) {
          bucketAllowPermissionSets.push(effectiveAllows)
        }
        if (!effectiveDenies.isEmpty()) {
          bucketDenyPermissionSets.push(effectiveDenies)
        }
      }
    }
  }

  return { allows: bucketAllowPermissionSets, denies: bucketDenyPermissionSets }
}
