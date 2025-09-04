import { Policy, Action as PolicyAction } from '@cloud-copilot/iam-policy'
import BitSet from 'bitset'
import { IamActionCache, IamCollectClient } from '../collect/client.js'

export async function makePrincipalIndex(collectClient: IamCollectClient) {
  const principalIndex: IamActionCache = {
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
    for (const principalArn of principals) {
      principalIndex.principals.push(principalArn)
      accountBitSet.set(globalIndex, 1)
      const allowPolicies = await collectClient.getAllowPoliciesForPrincipal(principalArn)
      addPoliciesToCache(allowPolicies, principalIndex, globalIndex)

      globalIndex++
    }
    principalIndex.accounts[accountId] = accountBitSet.toString(16) as any
  }

  for (const [service, actions] of Object.entries(principalIndex.action)) {
    for (const [action, bitset] of Object.entries(actions)) {
      principalIndex.action[service][action] = bitset.toString(16) as any
    }
  }
  for (const [service, notActions] of Object.entries(principalIndex.notAction)) {
    for (const [action, bitset] of Object.entries(notActions)) {
      principalIndex.notAction[service][action] = bitset.toString(16) as any
    }
  }

  delete principalIndex.notAction['*']

  await collectClient.savePrincipalIndex(principalIndex)
}

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
