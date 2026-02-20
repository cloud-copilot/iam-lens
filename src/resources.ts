import { Simulation } from '@cloud-copilot/iam-simulate'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from './collect/client.js'

/**
 * Get the account ID for a given resource ARN. Lookup index if necessary to find the account ID.
 *
 * @param collectClient the IAM collect client to use for retrieving the account ID
 * @param resourceArn the ARN of the resource to get the account ID for
 * @returns the account ID for the specified resource, or undefined if not found
 */
export async function getAccountIdForResource(
  collectClient: IamCollectClient,
  resourceArn: string
): Promise<string | undefined> {
  if (!resourceArn.startsWith('arn')) {
    return undefined
  }
  const arnParts = splitArnParts(resourceArn)
  let accountId = arnParts.accountId
  if (accountId && accountId !== 'aws') {
    return accountId
  }
  if (arnParts.service === 's3' && arnParts.resourceType === '') {
    const bucketName = arnParts.resourcePath!.split('/')[0]
    return collectClient.getAccountIdForBucket(bucketName)
  } else if (arnParts.service === 'apigateway' && arnParts.resourceType === 'restapis') {
    return collectClient.getAccountIdForRestApi(resourceArn)
  }
  return undefined
}

/**
 * Get the resource control policies (RCPs) for a given resource ARN.
 *
 * @param collectClient the IAM collect client to use for retrieving RCPs
 * @param resourceArn the ARN of the resource to get RCPs for
 * @param resourceAccount the account ID of the resource, if known
 * @returns an array of resource control policies for the specified resource
 */
export async function getRcpsForResource(
  collectClient: IamCollectClient,
  resourceArn: string,
  resourceAccount: string | undefined
): Promise<Simulation['resourceControlPolicies']> {
  const accountId = resourceAccount || (await getAccountIdForResource(collectClient, resourceArn))
  if (!accountId) {
    throw new Error(`Unable to determine account ID for resource ARN: ${resourceArn}`)
  }
  return collectClient.getRcpHierarchyForAccount(accountId)
}

/**
 * Get the resource policy for a resource, if any.
 *
 * @param collectClient the IAM collect client to use for retrieving the resource policy
 * @param resourceArn the ARN of the resource to get the policy for
 * @param resourceAccount the account ID of the resource, if known
 * @returns  the resource policy for the specified resource, or undefined if not found
 */
export async function getResourcePolicyForResource(
  collectClient: IamCollectClient,
  resourceArn: string,
  resourceAccount: string | undefined
): Promise<any | undefined> {
  //TODO: Should this return a policy object?
  const accountId = resourceAccount || (await getAccountIdForResource(collectClient, resourceArn))
  if (!accountId) {
    throw new Error(`Unable to determine account ID for resource ARN: ${resourceArn}`)
  }
  const resourcePolicy = await collectClient.getResourcePolicyForArn(resourceArn, accountId)
  if (resourcePolicy) {
    return resourcePolicy
  }

  const ramPolicy = await collectClient.getRamSharePolicyForArn(resourceArn, accountId)
  if (ramPolicy) {
    return ramPolicy
  }

  //TODO: there should be more here for things like glue resources
  return undefined
}
