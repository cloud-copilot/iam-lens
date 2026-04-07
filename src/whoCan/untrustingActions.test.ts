import { describe, it, expect } from 'vitest'
import { actionsThatDoNotAutomaticallyTrustTheCurrentAccount } from './untrustingActions.js'

describe('actionsThatDoNotAutomaticallyTrustTheCurrentAccount', () => {
  it('should include sts:assumerole', async () => {
    //Given the set of untrusting actions
    const actions = await actionsThatDoNotAutomaticallyTrustTheCurrentAccount()

    //Then sts:assumerole should be in the set
    expect(actions.has('sts:assumerole')).toBe(true)
  })

  it('should include kms key actions like kms:encrypt and kms:decrypt', async () => {
    //Given the set of untrusting actions
    const actions = await actionsThatDoNotAutomaticallyTrustTheCurrentAccount()

    //Then KMS key-targeted actions should be in the set
    expect(actions.has('kms:encrypt')).toBe(true)
    expect(actions.has('kms:decrypt')).toBe(true)
  })

  it('should not include wildcard-only kms actions like kms:listkeys', async () => {
    //Given the set of untrusting actions
    const actions = await actionsThatDoNotAutomaticallyTrustTheCurrentAccount()

    //Then wildcard-only KMS actions should NOT be in the set
    expect(actions.has('kms:listkeys')).toBe(false)
  })
})
