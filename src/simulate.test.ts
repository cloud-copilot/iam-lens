import { describe, expect, it } from 'vitest'
import { testStore } from './collect/inMemoryClient.js'
import { simulateRequest } from './simulate.js'

describe('simulateRequest', () => {
  it('should throw an error if the resource account id cannot be determined', async () => {
    const { client } = testStore()
    const req = {
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:s3:::unknown-bucket',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {}
    }
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find account ID for resource/
    )
  })

  it('should throw an error if the action service cannot be found', async () => {
    const { client } = testStore()
    const req = {
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:iam::123456789012:test-bucket',
      resourceAccount: '123456789012',
      action: 'unknown:action',
      customContextKeys: {}
    }
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find action details for unknown:action/
    )
  })

  it('should throw an error if the action details cannot be found', async () => {
    const { client } = testStore()
    const req = {
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:iam::123456789012:test-bucket',
      resourceAccount: '123456789012',
      action: 's3:fakeaction',
      customContextKeys: {}
    }
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find action details for s3:fakeaction/
    )
  })
})
