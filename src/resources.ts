import { Simulation } from '@cloud-copilot/iam-simulate'
import { IamCollectClient } from './collect/client.js'
import { splitArnParts } from './util/arn.js'

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
  const arnParts = splitArnParts(resourceArn)
  let accountId = arnParts.accountId
  if (accountId) {
    return accountId
  }
  if (arnParts.service === 's3' && arnParts.resourceType === '') {
    const bucketName = arnParts.resourcePath!
    console.log(`S3 bucket name: ${bucketName}`)
    return collectClient.getAccountIdForBucket(bucketName)
  } else if (arnParts.service === 'apigateway' && arnParts.resourceType === 'restapis') {
    const apiId = arnParts.resourcePath!
    return collectClient.getAccountIdForRestApi(apiId)
  }
  return undefined
}

/**
 * Get the resource control policies (RCPs) for a given resource ARN.
 *
 * @param collectClient the IAM collect client to use for retrieving RCPs
 * @param resourceArn the ARN of the resource to get RCPs for
 * @returns an array of resource control policies for the specified resource
 */
export async function getRcpsForResource(
  collectClient: IamCollectClient,
  resourceArn: string
): Promise<Simulation['resourceControlPolicies']> {
  const accountId = await getAccountIdForResource(collectClient, resourceArn)
  if (!accountId) {
    throw new Error(`Unable to determine account ID for resource ARN: ${resourceArn}`)
  }
  return collectClient.getRcpHierarchyForAccount(accountId)
}
