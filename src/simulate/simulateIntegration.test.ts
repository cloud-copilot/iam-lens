import { EvaluationResult } from '@cloud-copilot/iam-simulate'
import { join, resolve } from 'path'
import { describe, expect, it } from 'vitest'
import { getCollectClient } from '../collect/collect.js'
import { simulateRequest, SimulationRequest } from './simulate.js'

const simulateIntegrationTest: {
  name: string
  only?: boolean

  data: string
  request: SimulationRequest

  expected: EvaluationResult
  expectedError?: string
}[] = [
  {
    name: 'same account resource request with resource policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'Allowed'
  },
  {
    name: 'request blocked by SCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:PutBucketPolicy',
      principal:
        'arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'request blocked by RCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::restricted-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  }
]

describe('simulateIntegrationTest', () => {
  for (const test of simulateIntegrationTest) {
    const { name, only, data, request, expected } = test
    const testFn = only ? it.only : it

    testFn(name, async () => {
      // Given a client
      const collectClient = getCollectClient(
        [
          {
            iamCollectVersion: '0.0.0',
            storage: {
              type: 'file',
              path: resolve(join('./src', 'test-datasets', `iam-data-${test.data}`))
            }
          }
        ],
        'aws'
      )

      if (test.expectedError) {
        //If an error is expected
        // Then it should match the expected error
        await expect(simulateRequest(request, collectClient)).rejects.toThrow(
          new RegExp('/' + test.expectedError + '/')
        )
      } else {
        // When we run the simulation
        const result = await simulateRequest(request, collectClient)

        // Then the result should not have errors
        expect(result.errors).toBeUndefined()

        // And the result should match the expected result
        expect(result.analysis?.result).toEqual(test.expected)
      }
    })
  }
})
