import { describe, expect, it } from 'vitest'
import { testStore } from './collect/inMemoryClient.js'
import { getAccountIdForResource } from './resources.js'

describe('getAccountIdForResource', () => {
  it('should return the account ID for a given resource ARN', async () => {
    // Given a resource ARN
    const resourceArn = 'arn:aws:dynamodb:us-east-1:123456789012:table/MyTable'

    // When calling getAccountIdForResource
    const { client } = testStore()
    const accountId = await getAccountIdForResource(client, resourceArn)

    // Then the account ID should be returned
    expect(accountId).toBe('123456789012')
  })

  it('should return undefined if the account ID is AWS', async () => {
    // Given an AWS managed policy ARN
    const resourceArn = 'arn:aws:iam::aws:policy/AWSLambda_FullAccess'
    const { client } = testStore()

    // When calling getAccountIdForResource
    const accountId = await getAccountIdForResource(client, resourceArn)

    // Then the account ID should be undefined
    expect(accountId).toBeUndefined()
  })

  it('should return the account ID for an S3 bucket ARN', async () => {
    // Given an S3 bucket ARN
    const resourceArn = 'arn:aws:s3:::my-bucket'

    // And an index for S3 buckets
    const { client, store } = testStore()
    await store.saveIndex(
      'buckets-to-accounts',
      {
        'my-bucket': {
          accountId: '999999999999',
          region: 'us-east-1'
        }
      },
      ''
    )

    // When calling getAccountIdForResource
    const accountId = await getAccountIdForResource(client, resourceArn)

    // Then the account ID should be returned
    expect(accountId).toEqual('999999999999') // Assuming the bucket is in this account
  })

  it('should return the account ID for an API Gateway REST API ARN', async () => {
    // Given an API Gateway REST API ARN
    const resourceArn = 'arn:aws:apigateway:us-east-1::/restapis/abc123'

    // And an index for API Gateway REST APIs
    const { client, store } = testStore()
    await store.saveIndex(
      'apigateways-to-accounts',
      {
        [resourceArn]: '888888888888'
      },
      ''
    )

    // When calling getAccountIdForResource
    const accountId = await getAccountIdForResource(client, resourceArn)

    // Then the account ID should be returned
    expect(accountId).toEqual('888888888888') // Assuming the API is in this account
  })

  it('should return undefined if the ARN is invalid', async () => {
    // Given an invalid ARN
    const resourceArn = '*'

    // When calling getAccountIdForResource
    const { client } = testStore()
    const accountId = await getAccountIdForResource(client, resourceArn)

    // Then the account ID should be undefined
    expect(accountId).toBeUndefined()
  })
})
