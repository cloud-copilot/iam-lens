import { type Policy, type Action as PolicyAction } from '@cloud-copilot/iam-policy'
import BitSet from 'bitset'
import { type IamActionCache, IamCollectClient } from '../collect/client.js'
import { compressPrincipalString, encodeBitSet } from '../utils/bitset.js'

/**
 * Make a principal index for all principals in the collect client
 *
 * @param collectClient the collect client to use
 */
export async function makePrincipalIndex(collectClient: IamCollectClient) {
  const principalIndex: IamActionCache = {
    prefix: 'arn:aws:iam::',
    principals: [],
    accounts: {},
    action: {},
    notAction: {}
  }

  const allAccounts = await collectClient.allAccounts()
  let globalIndex = 0

  for (const accountId of allAccounts) {
    const accountBitSet = new BitSet()
    const principals = await collectClient.getAllPrincipalsInAccount(accountId)
    const accountStart = globalIndex
    for (const principalArn of principals) {
      principalIndex.principals.push(compressPrincipalString(principalArn))
      accountBitSet.set(globalIndex, 1)
      const allowPolicies = await collectClient.getAllowPoliciesForPrincipal(principalArn)
      addPoliciesToCache(allowPolicies, principalIndex, globalIndex)
      globalIndex++
    }
    const accountEnd = globalIndex - 1

    principalIndex.accounts[accountId] = [accountStart, accountEnd]
  }

  for (const type of ['action', 'notAction'] as const) {
    for (const [, actions] of Object.entries(principalIndex[type])) {
      for (const [action, bitset] of Object.entries(actions)) {
        actions[action] = encodeBitSet(bitset) as any
      }
    }
  }

  delete principalIndex.notAction['*']

  await collectClient.savePrincipalIndex('principals', {
    principals: principalIndex.principals,
    prefix: principalIndex.prefix
  })
  await collectClient.savePrincipalIndex('accounts', principalIndex.accounts)
  await collectClient.savePrincipalIndex('not-actions', principalIndex.notAction)
  for (const [service, serviceIndex] of Object.entries(principalIndex.action)) {
    const serviceKey = service === '*' ? 'wildcard' : service
    await collectClient.savePrincipalIndex(`actions-${serviceKey}`, serviceIndex)
  }
}

/**
 * Add policies to the existing cache
 *
 * @param policies the policies to add
 * @param existingCache the existing cache
 * @param principalIndex the index of the principal to add
 */

function addPoliciesToCache(
  policies: Policy[],
  existingCache: IamActionCache,
  principalIndex: number
) {
  for (const policy of policies) {
    for (const statement of policy.statements()) {
      if (statement.isAllow()) {
        if (statement.isActionStatement()) {
          for (const action of statement.actions()) {
            setCacheAction(existingCache.action, action, principalIndex)
          }
        } else if (statement.isNotActionStatement()) {
          for (const action of statement.notActions()) {
            setCacheAction(existingCache.notAction, action, principalIndex)
          }
        }
      }
    }
  }
}

/**
 * Sets an action for a principal in a cache.
 *
 * @param cache The cache to update.
 * @param action The action to set.
 * @param principalIndex The index of the principal.
 */
function setCacheAction(
  cache: IamActionCache['action'] | IamActionCache['notAction'],
  action: PolicyAction,
  principalIndex: number
) {
  if (action.isWildcardAction()) {
    if (!cache['*']) {
      cache['*'] = { '*': new BitSet() }
    }
    cache['*']['*'].set(principalIndex, 1)
  } else if (action.isServiceAction()) {
    const service = action.service().toLowerCase()
    const serviceAction = action.action().toLowerCase()
    if (!cache[service]) {
      cache[service] = {}
    }
    if (!cache[service][serviceAction]) {
      cache[service][serviceAction] = new BitSet()
    }
    cache[service][serviceAction].set(principalIndex, 1)
  }
}
