import { describe, expect, it } from 'vitest'
import { isServiceLinkedRole } from './principals.js'

describe('isServiceLinkedRole', () => {
  it('should return true for service-linked role ARNs', () => {
    //Given a service-linked role ARN
    const serviceLinkedRoleArn =
      'arn:aws:iam::123456789012:role/aws-service-role/some-service.amazonaws.com/AWSServiceRoleForSomeService'

    //When checking if it is a service-linked role
    const result = isServiceLinkedRole(serviceLinkedRoleArn)

    //Then it should return true
    expect(result).toBe(true)
  })

  it('should return false for non-service-linked role ARNs', () => {
    //Given a non-service-linked role ARN
    const nonServiceLinkedRoleArn = 'arn:aws:iam::123456789012:role/some-other-role'

    //When checking if it is a service-linked role
    const result = isServiceLinkedRole(nonServiceLinkedRoleArn)

    //Then it should return false
    expect(result).toBe(false)
  })

  it('should return false for non-ARN principals', () => {
    //Given a non-ARN principal
    const nonArnPrincipal = 'some-principal.amazonaws.com'

    //When checking if it is a service-linked role
    const result = isServiceLinkedRole(nonArnPrincipal)

    //Then it should return false
    expect(result).toBe(false)
  })
})
