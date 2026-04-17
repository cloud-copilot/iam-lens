import { type EvaluationResult } from '@cloud-copilot/iam-simulate'
import { assert, describe, expect, it } from 'vitest'
import { testStore } from '../collect/inMemoryClient.js'
import { saveRole, saveUser } from '../utils/testUtils.js'
import { resultMatchesExpectation, simulateRequest, type SimulationRequest } from './simulate.js'

describe('simulateRequest', () => {
  it('should throw an error if the resource account id cannot be determined', async () => {
    const { client } = testStore()
    // Given a request with an unknown resource ARN
    const req: SimulationRequest = {
      simulationMode: 'Strict',
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
    const req: SimulationRequest = {
      simulationMode: 'Strict',
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
    const req: SimulationRequest = {
      simulationMode: 'Strict',
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

describe('aws:userid strict context key behavior', () => {
  const useridConditionPolicy = [
    {
      PolicyName: 'ConditionalAccess',
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'dynamodb:GetItem',
            Resource: '*',
            Condition: {
              StringLike: { 'aws:userid': '*:expected-session' }
            }
          }
        ]
      }
    }
  ]

  it('should not treat aws:userid as strict for role principals in Discovery mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, {
      arn: roleArn,
      inlinePolicies: useridConditionPolicy
    })

    //When simulating in Discovery mode as the role
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: roleArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {}
      },
      client
    )

    //Then access should be allowed because aws:userid is not strict for roles
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    expect(result.overallResult).toBe('Allowed')

    //And aws:userid should be reported as an ignored condition on the identity allow
    if (result.resultType === 'single') {
      const ignoredConditions = result.result.analysis.ignoredConditions
      expect(ignoredConditions?.identity?.allow).toEqual(
        expect.arrayContaining([expect.objectContaining({ key: 'aws:userid' })])
      )
    } else {
      assert.fail(`Expected single result type, got ${result.resultType}`)
    }
  })

  it('should treat aws:userid as strict for user principals in Discovery mode', async () => {
    //Given a user whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const userArn = 'arn:aws:iam::123456789012:user/TestUser'
    await saveUser(store, {
      arn: userArn,
      inlinePolicies: useridConditionPolicy
    })

    //When simulating in Discovery mode as the user
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: userArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {}
      },
      client
    )

    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be denied because aws:userid is strict and the value doesn't match
    expect(result.overallResult).toBe('ImplicitlyDenied')
  })

  it('should treat aws:userid as strict for assumed-role session principals in Discovery mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, { arn: roleArn, inlinePolicies: useridConditionPolicy })

    //And an assumed-role session ARN whose session name does not match the condition
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/wrong-session'

    //When simulating in Discovery mode as the session
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: sessionArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {},
        ignoreMissingPrincipal: true
      },
      client
    )
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be denied because aws:userid is strict for sessions and the value doesn't match
    expect(result.overallResult).toBe('ImplicitlyDenied')
  })

  it('should allow assumed-role session when aws:userid condition matches in Discovery mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, { arn: roleArn, inlinePolicies: useridConditionPolicy })

    //And an assumed-role session ARN whose session name matches the condition
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/expected-session'

    //When simulating in Discovery mode as the session
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: sessionArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {},
        ignoreMissingPrincipal: true
      },
      client
    )
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be allowed because the userid matches
    expect(result.overallResult).toBe('Allowed')
  })

  it('should allow assumed-role session when aws:userid condition matches in Strict mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, { arn: roleArn, inlinePolicies: useridConditionPolicy })

    //And an assumed-role session ARN whose session name matches the condition
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/expected-session'

    //When simulating in Strict mode as the session
    const { result } = await simulateRequest(
      {
        simulationMode: 'Strict',
        principal: sessionArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {},
        ignoreMissingPrincipal: true
      },
      client
    )
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be allowed because the userid matches the condition
    expect(result.overallResult).toBe('Allowed')
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
