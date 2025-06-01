import { EvaluationResult } from '@cloud-copilot/iam-simulate'
import { describe, expect, it } from 'vitest'
import { testStore } from '../collect/inMemoryClient.js'
import { resultMatchesExpectation, simulateRequest } from './simulate.js'

describe('simulateRequest', () => {
  it('should throw an error if the resource account id cannot be determined', async () => {
    const { client } = testStore()
    // Given a request with an unknown resource ARN
    const req = {
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:s3:::unknown-bucket',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {}
    }
    //When simulating the request
    // Then it should throw an error indicating the account ID cannot be found
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find account ID for resource/
    )
  })

  it('should throw an error if the action service cannot be found', async () => {
    const { client } = testStore()
    // Given a request with an unknown action service
    const req = {
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:iam::123456789012:test-bucket',
      resourceAccount: '123456789012',
      action: 'unknown:action',
      customContextKeys: {}
    }

    // When simulating the request
    // Then it should throw an error indicating the action service cannot be found
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

describe('resultMatchesExpectation', () => {
  it('should return true if the expected result is undefined', () => {
    //Given an expected result of undefined
    const expected = undefined

    //When checking against any actual result
    const result = resultMatchesExpectation(expected, 'Allowed')

    //Then it should return true
    expect(result).toBe(true)
  })
  it('should return true if the expected result matches the actual result', () => {
    //Given a set of expected values
    const expectedValues = ['Allowed', 'ExplicitlyDeny', 'ImplicitlyDeny'] as EvaluationResult[]

    //When checking against each expected value
    const actualValues = expectedValues.map((expected) => {
      return resultMatchesExpectation(expected, expected)
    })

    //Then it should return true for each match
    expect(actualValues).toEqual(expectedValues.map(() => true))
  })
  it('should return true if AnyDeny is expected and the actual result is ImplicitlyDeny', () => {
    // Given AnyDeny as the expected result
    const expected = 'AnyDeny'

    // When checking against ImplicitlyDeny
    const result = resultMatchesExpectation(expected, 'ImplicitlyDenied')

    // Then it should return true
    expect(result).toBe(true)
  })

  it('should return true if AnyDeny is expected and the actual result is ExplicitlyDeny', () => {
    // Given AnyDeny as the expected result
    const expected = 'AnyDeny'

    // When checking against ExplicitlyDenied
    const result = resultMatchesExpectation(expected, 'ExplicitlyDenied')

    // Then it should return true
    expect(result).toBe(true)
  })
})
