import { iamActionDetails, iamActionsForService } from '@cloud-copilot/iam-data'

const kms = 'kms'
const kmsKey = 'key'
const stsAssumeRole = 'sts:AssumeRole'

let cachedActions: Set<string> | undefined = undefined

/**
 * Get a set of actions that do not automatically trust the current account, in all lower case.
 *
 * @returns the set of actions that do not automatically trust the current account in all lower case
 */
export async function actionsThatDoNotAutomaticallyTrustTheCurrentAccount(): Promise<Set<string>> {
  if (cachedActions) {
    return cachedActions
  }

  const kmsActions = await iamActionsForService(kms)
  const allActions = new Set<string>([stsAssumeRole.toLowerCase()])
  for (const action of kmsActions) {
    const details = await iamActionDetails(kms, action)
    if (
      details.resourceTypes.length === 1 &&
      details.resourceTypes.some((rt) => rt.name === kmsKey)
    ) {
      allActions.add(`${kms}:${action.toLowerCase()}`)
    }
  }

  cachedActions = allActions
  return allActions
}
