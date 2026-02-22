import { type AwsIamStore } from '@cloud-copilot/iam-collect'
import { splitArnParts } from '@cloud-copilot/iam-utils'

/**
 * Useful functions for unit tests.
 */

/**
 * Save a managed policy
 *
 * @param store the AWS IAM store
 * @param details the details of the managed policy
 */
export async function saveManagedPolicy(
  store: AwsIamStore,
  details: {
    arn: string
    description?: string
    policy: any
  }
) {
  const name = details.arn.split('/').pop()
  const accountId = splitArnParts(details.arn).accountId!

  await store.saveResourceMetadata(accountId, details.arn, 'metadata', {
    arn: details.arn,
    name,
    description: details.description
  })

  await store.saveResourceMetadata(accountId, details.arn, 'current-policy', details.policy)
}

/**
 * Save a user for testing
 *
 * @param store the AWS IAM store
 * @param details the details of the user
 */
export async function saveUser(
  store: AwsIamStore,
  details: {
    arn: string
    description?: string
    inlinePolicies?: any[]
    managedPolicies?: string[]
    groups?: string[]
    permissionBoundary?: string
  }
) {
  const name = details.arn.split('/').pop()
  const accountId = splitArnParts(details.arn).accountId!

  const metadata: any = {
    arn: details.arn,
    id: `AIDAEXAMPLE${accountId}`,
    name,
    path: '/',
    created: '2024-01-01T00:00:00Z'
  }

  if (details.permissionBoundary) {
    metadata.permissionBoundary = details.permissionBoundary
  }

  await store.saveResourceMetadata(accountId, details.arn, 'metadata', metadata)

  await store.saveResourceMetadata(
    accountId,
    details.arn,
    'managed-policies',
    details.managedPolicies
  )

  await store.saveResourceMetadata(
    accountId,
    details.arn,
    'inline-policies',
    details.inlinePolicies
  )

  await store.saveResourceMetadata(accountId, details.arn, 'groups', details.groups)
}

/**
 * Save a role for testing
 *
 * @param store the AWS IAM store
 * @param details the details of the role
 */
export async function saveRole(
  store: AwsIamStore,
  details: {
    arn: string
    description?: string
    inlinePolicies?: any[]
    managedPolicies?: string[]
    permissionBoundary?: string
    trustPolicy?: any
  }
) {
  const name = details.arn.split('/').pop()
  const accountId = splitArnParts(details.arn).accountId!

  const metadata: any = {
    arn: details.arn,
    id: `AROAEXAMPLE${accountId}`,
    name,
    path: '/',
    created: '2024-01-01T00:00:00Z'
  }

  if (details.permissionBoundary) {
    metadata.permissionBoundary = details.permissionBoundary
  }

  await store.saveResourceMetadata(accountId, details.arn, 'metadata', metadata)

  await store.saveResourceMetadata(
    accountId,
    details.arn,
    'managed-policies',
    details.managedPolicies
  )

  await store.saveResourceMetadata(
    accountId,
    details.arn,
    'inline-policies',
    details.inlinePolicies
  )

  await store.saveResourceMetadata(accountId, details.arn, 'trust-policy', details.trustPolicy)
}

/**
 * Save a group for testing
 *
 * @param store the AWS IAM store
 * @param details the details of the group
 */
export async function saveGroup(
  store: AwsIamStore,
  details: {
    arn: string
    description?: string
    inlinePolicies?: any[]
    managedPolicies?: string[]
  }
) {
  const name = details.arn.split('/').pop()
  const accountId = splitArnParts(details.arn).accountId!

  const metadata: any = {
    arn: details.arn,
    id: `AGPAEXAMPLE${accountId}`,
    name,
    path: '/',
    created: '2024-01-01T00:00:00Z'
  }

  await store.saveResourceMetadata(accountId, details.arn, 'metadata', metadata)

  await store.saveResourceMetadata(
    accountId,
    details.arn,
    'managed-policies',
    details.managedPolicies
  )

  await store.saveResourceMetadata(
    accountId,
    details.arn,
    'inline-policies',
    details.inlinePolicies
  )
}
