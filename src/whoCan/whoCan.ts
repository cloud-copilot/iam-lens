import { TopLevelConfig } from '@cloud-copilot/iam-collect'
import {
  iamActionDetails,
  iamActionExists,
  iamActionsForService,
  iamResourceTypeDetails,
  iamResourceTypesForService,
  iamServiceExists,
  ResourceType
} from '@cloud-copilot/iam-data'
import { loadPolicy } from '@cloud-copilot/iam-policy'
import { RequestDenial } from '@cloud-copilot/iam-simulate'
import {
  isAssumedRoleArn,
  isIamRoleArn,
  isIamUserArn,
  isServicePrincipal,
  splitArnParts
} from '@cloud-copilot/iam-utils'
import { JobResult, numberOfCpus, StreamingJobQueue } from '@cloud-copilot/job'
import { Worker } from 'worker_threads'
import { IamCollectClient } from '../collect/client.js'
import { getCollectClient } from '../collect/collect.js'
import { getAccountIdForResource, getResourcePolicyForResource } from '../resources.js'
import { Arn } from '../utils/arn.js'
import { S3AbacOverride } from '../utils/s3Abac.js'
import { AssumeRoleActions } from '../utils/sts.js'
import { getWorkerScriptPath } from '../utils/workerScript.js'
import { ArrayStreamingWorkQueue } from '../workers/ArrayStreamingWorkQueue.js'
import { SharedArrayBufferMainCache } from '../workers/SharedArrayBufferMainCache.js'
import { StreamingWorkQueue } from '../workers/StreamingWorkQueue.js'
import { createMainThreadStreamingWorkQueue } from './WhoCanMainThreadWorker.js'
import { WhoCanWorkItem } from './WhoCanWorker.js'
import { LightRequestAnalysis } from './requestAnalysis.js'

export interface ResourceAccessRequest {
  /**
   * The ARN of the resource to check access for. If not provided, actions must be specified.
   */
  resource?: string

  /**
   * The account ID the resource belongs to.
   * By default this will be looked up based on the resource ARN, but that may
   * not be possible for all actions, such as wildcard actions like `s3:ListAllMyBuckets`.
   */
  resourceAccount?: string

  /**
   * The actions to check access for. If not provided, actions will be looked up based on the resource ARN.
   */
  actions: string[]

  /**
   * Whether to sort the results for consistent output.
   */
  sort?: boolean

  /**
   * An override for S3 ABAC being enabled when checking access to S3 Bucket resources.
   */
  s3AbacOverride?: S3AbacOverride

  /**
   * The number of worker threads to use for simulations beyond the main thread.
   * If not provided, defaults to number of CPUs - 1.
   */
  workerThreads?: number

  /**
   * Deny details callback for simulations. If the callback returns true, deny details will be included for that simulation.
   */
  denyDetailsCallback?: (details: LightRequestAnalysis) => boolean
}

export interface WhoCanAllowed {
  principal: string
  service: string
  action: string
  level: string
  conditions?: any
  dependsOnSessionName?: boolean
}

export interface WhoCanDenyDetail {
  principal: string
  service: string
  action: string
  details: RequestDenial[]
}

export interface WhoCanResponse {
  simulationCount: number
  allowed: WhoCanAllowed[]
  allAccountsChecked: boolean
  accountsNotFound: string[]
  organizationsNotFound: string[]
  organizationalUnitsNotFound: string[]
  principalsNotFound: string[]
  denyDetails?: WhoCanDenyDetail[] | undefined
}

/**
 * Get the number of worker threads to use, defaulting to number of CPUs - 1
 *
 * @param overrideValue the override value, if any
 * @returns the override value if provided, otherwise number of CPUs - 1
 */
function getNumberOfWorkers(overrideValue: number | undefined): number {
  if (typeof overrideValue === 'number' && overrideValue >= 0) {
    return Math.floor(overrideValue)
  }
  return Math.max(0, numberOfCpus() - 1)
}

export async function whoCan(
  collectConfigs: TopLevelConfig[],
  partition: string,
  request: ResourceAccessRequest
): Promise<WhoCanResponse> {
  const { resource } = request

  // Get the number of workers and the worker script path.
  // It's possible in bundled environments that the worker script path may not be found, so handle that gracefully.
  const numWorkers = getNumberOfWorkers(request.workerThreads)
  const workerPath = getWorkerScriptPath('whoCan/WhoCanWorkerThreadWorker.js')
  const collectDenyDetails = !!request.denyDetailsCallback
  const workers = !workerPath
    ? []
    : new Array(numWorkers).fill(undefined).map((val) => {
        return new Worker(workerPath, {
          workerData: {
            collectConfigs: collectConfigs,
            partition,
            concurrency: 50,
            s3AbacOverride: request.s3AbacOverride,
            collectDenyDetails
          }
        })
      })

  const collectClient = getCollectClient(collectConfigs, partition, {
    cacheProvider: new SharedArrayBufferMainCache(workers)
  })

  if (!request.resourceAccount && !request.resource) {
    throw new Error('Either resourceAccount or resource must be provided in the request.')
  }

  if (resource && !resource.startsWith('arn:')) {
    throw new Error(`Invalid resource ARN: ${resource}. It must start with 'arn:'.`)
  }

  const resourceAccount =
    request.resourceAccount || (await getAccountIdForResource(collectClient, resource!))

  if (!resourceAccount) {
    throw new Error(`Could not determine account ID for resource ${resource}`)
  }

  const actions = await actionsForWhoCan(request)
  if (!actions || actions.length === 0) {
    throw new Error('No valid actions provided or found for the resource.')
  }

  let resourcePolicy: any = undefined
  if (resource) {
    resourcePolicy = await getResourcePolicyForResource(collectClient, resource, resourceAccount)
    const resourceArn = new Arn(resource)
    if (
      (resourceArn.matches({ service: 'iam', resourceType: 'role' }) ||
        resourceArn.matches({ service: 'kms', resourceType: 'key' })) &&
      !resourcePolicy
    ) {
      throw new Error(
        `Unable to find resource policy for ${resource}. Cannot determine who can access the resource.`
      )
    }
  }

  const accountsToCheck = await accountsToCheckBasedOnResourcePolicy(
    resourcePolicy,
    resourceAccount
  )

  const uniqueAccounts = await uniqueAccountsToCheck(collectClient, accountsToCheck)

  const whoCanResults: WhoCanAllowed[] = []

  const concurrency = Math.min(50, Math.max(1, numberOfCpus() * 2))

  let simulationCount = 0
  const simulateQueue = new StreamingWorkQueue<WhoCanWorkItem>()

  const simulationErrors: any[] = []
  const denyDetails: WhoCanDenyDetail[] = []

  const onComplete = (result: JobResult<WhoCanAllowed | undefined, Record<string, unknown>>) => {
    simulationCount++
    if (result.status === 'fulfilled' && result.value) {
      whoCanResults.push(result.value)
    } else if (result.status === 'rejected') {
      console.error('Error running simulation:', result.reason)
      simulationErrors.push(result)
    }
  }

  const mainThreadWorker = createMainThreadStreamingWorkQueue(
    simulateQueue,
    collectClient,
    request.s3AbacOverride,
    onComplete,
    request.denyDetailsCallback,
    (detail) => denyDetails.push(detail)
  )

  workers.forEach((worker) => {
    worker.on('message', (msg) => {
      if (msg.type === 'requestTask') {
        const task = simulateQueue.dequeue()
        worker.postMessage({ type: 'task', workerId: msg.workerId, task })
      }
      if (msg.type === 'result') {
        onComplete(msg.result)
      }
      if (msg.type === 'checkDenyDetails') {
        // Run the callback on main thread to check if we should include deny details
        const shouldInclude = request.denyDetailsCallback?.(msg.lightAnalysis) ?? false
        worker.postMessage({
          type: 'denyDetailsCheckResult',
          checkId: msg.checkId,
          shouldInclude
        })
      }
      if (msg.type === 'denyDetailsResult') {
        denyDetails.push(msg.denyDetail)
      }
    })
  })

  simulateQueue.setWorkAvailableCallback(() => {
    mainThreadWorker.notifyWorkAvailable()
    workers.forEach((w) => w.postMessage({ type: 'workAvailable' }))
  })

  const accountQueue = new StreamingJobQueue<void, Record<string, unknown>>(
    concurrency,
    console,
    async (response) => {}
  )

  const principalIndexExists = await collectClient.principalIndexExists()
  if (principalIndexExists) {
    for (const action of actions) {
      const indexedPrincipals = await collectClient.getPrincipalsWithActionAllowed(
        resourceAccount,
        uniqueAccounts.accounts,
        action
      )
      for (const principal of indexedPrincipals || []) {
        simulateQueue.enqueue({
          resource,
          action,
          principal,
          resourceAccount
        })
      }
    }
  } else {
    for (const account of uniqueAccounts.accounts) {
      accountQueue.enqueue({
        properties: {},
        execute: async () => {
          const principals = await collectClient.getAllPrincipalsInAccount(account)
          for (const principal of principals) {
            await runPrincipalForActions(
              collectClient,
              simulateQueue,
              principal,
              resource,
              resourceAccount,
              actions
            )
          }
        }
      })
    }
  }

  const principalsNotFound: string[] = []
  for (const principal of accountsToCheck.specificPrincipals) {
    accountQueue.enqueue({
      properties: {},
      execute: async () => {
        if (isServicePrincipal(principal)) {
          await runPrincipalForActions(
            collectClient,
            simulateQueue,
            principal,
            resource,
            resourceAccount,
            actions
          )
        } else if (
          isIamUserArn(principal) ||
          isIamRoleArn(principal) ||
          isAssumedRoleArn(principal)
        ) {
          const principalExists = await collectClient.principalExists(principal)
          if (!principalExists) {
            principalsNotFound.push(principal)
          } else {
            await runPrincipalForActions(
              collectClient,
              simulateQueue,
              principal,
              resource,
              resourceAccount,
              actions
            )
          }
        } else {
          // TODO: Add a check for OIDC and SAML providers here
          principalsNotFound.push(principal)
        }
      }
    })
  }

  await accountQueue.finishAllWork()
  // await simulateQueue.finishAllWork()

  const workerPromises = workers.map((worker) => {
    return new Promise<void>((resolve, reject) => {
      worker.on('message', (msg) => {
        if (msg.type === 'finished') {
          worker.terminate().then(() => resolve())
        }
      })
      worker.on('error', (err) => {
        console.error('Worker error:', err)
        reject(err)
      })
      worker.postMessage({ type: 'finishWork' })
    })
  })

  await Promise.all([mainThreadWorker.finishAllWork(), ...workerPromises])

  if (simulationErrors.length > 0) {
    console.error(`Completed with ${simulationErrors.length} simulation errors.`)
    throw new Error(
      `Completed with ${simulationErrors.length} simulation errors. See previous logs.`
    )
  }

  const results = {
    simulationCount,
    allowed: whoCanResults,
    allAccountsChecked: accountsToCheck.allAccounts,
    accountsNotFound: uniqueAccounts.accountsNotFound,
    organizationsNotFound: uniqueAccounts.organizationsNotFound,
    organizationalUnitsNotFound: uniqueAccounts.organizationalUnitsNotFound,
    principalsNotFound: principalsNotFound,
    denyDetails: request.denyDetailsCallback ? denyDetails : undefined
  }

  if (request.sort) {
    sortWhoCanResults(results)
  }

  return results
}

async function runPrincipalForActions(
  collectClient: IamCollectClient,
  simulationQueue: StreamingWorkQueue<WhoCanWorkItem> | ArrayStreamingWorkQueue<WhoCanWorkItem>,
  principal: string,
  resource: string | undefined,
  resourceAccount: string,
  actions: string[]
): Promise<void> {
  for (const action of actions) {
    simulationQueue.enqueue({
      resource,
      action,
      principal,
      resourceAccount
    })
  }
}

export async function uniqueAccountsToCheck(
  collectClient: IamCollectClient,
  accountsToCheck: AccountsToCheck
): Promise<{
  accountsNotFound: string[]
  organizationsNotFound: string[]
  organizationalUnitsNotFound: string[]
  accounts: string[]
}> {
  const returnValue = {
    accountsNotFound: [] as string[],
    organizationsNotFound: [] as string[],
    organizationalUnitsNotFound: [] as string[],
    accounts: [] as string[]
  }

  if (accountsToCheck.allAccounts) {
    returnValue.accounts = await collectClient.allAccounts()
    return returnValue
  }

  const uniqueAccounts = new Set<string>()
  for (const account of accountsToCheck.specificAccounts || []) {
    const accountExists = await collectClient.accountExists(account)
    if (accountExists) {
      uniqueAccounts.add(account)
    } else {
      returnValue.accountsNotFound.push(account)
    }
  }

  for (const ouPath of accountsToCheck.specificOrganizationalUnits || []) {
    const parts = ouPath.split('/')
    const orgId = parts[0]
    const pathParts = parts.slice(1)

    const [found, accounts] = await collectClient.getAccountsForOrgPath(orgId, pathParts)
    for (const account of accounts) {
      uniqueAccounts.add(account)
    }
    if (!found) {
      returnValue.organizationalUnitsNotFound.push(ouPath)
    }
  }

  for (const orgId of accountsToCheck.specificOrganizations || []) {
    const [found, accounts] = await collectClient.getAccountsForOrganization(orgId)
    for (const account of accounts) {
      uniqueAccounts.add(account)
    }
    if (!found) {
      returnValue.organizationsNotFound.push(orgId)
    }
  }

  returnValue.accounts = Array.from(uniqueAccounts)
  return returnValue
}

export interface AccountsToCheck {
  allAccounts: boolean
  specificAccounts: string[]
  specificPrincipals: string[]
  specificOrganizations: string[]
  specificOrganizationalUnits: string[]
}

export async function accountsToCheckBasedOnResourcePolicy(
  resourcePolicy: any,
  resourceAccount: string | undefined
): Promise<AccountsToCheck> {
  const accountsToCheck: AccountsToCheck = {
    allAccounts: false,
    specificAccounts: [],
    specificPrincipals: [],
    specificOrganizations: [],
    specificOrganizationalUnits: []
  }
  if (resourceAccount) {
    accountsToCheck.specificAccounts.push(resourceAccount)
  }
  if (!resourcePolicy) {
    return accountsToCheck
  }

  const policy = loadPolicy(resourcePolicy)
  for (const statement of policy.statements()) {
    if (statement.isAllow() && statement.isNotPrincipalStatement()) {
      accountsToCheck.allAccounts = true
    }
    if (statement.isAllow() && statement.isPrincipalStatement()) {
      const principals = statement.principals()
      let hasWildcardPrincipal = false
      for (const principal of principals) {
        if (principal.isWildcardPrincipal()) {
          hasWildcardPrincipal = true
        } else if (principal.isAccountPrincipal()) {
          accountsToCheck.specificAccounts.push(principal.accountId())
        } else {
          accountsToCheck.specificPrincipals.push(principal.value())
        }
      }

      if (hasWildcardPrincipal) {
        const specificOrgs = []
        const specificOus = []
        const specificAccounts = []

        const conditions = statement.conditions()
        for (const cond of conditions) {
          if (
            cond.conditionKey().toLowerCase() === 'aws:principalorgid' &&
            cond.operation().value().toLowerCase().startsWith('stringequals') &&
            !cond.conditionValues().some((v: string) => v.includes('$')) // Ignore dynamic values for now
          ) {
            specificOrgs.push(...cond.conditionValues())
          }
          if (
            cond.conditionKey().toLowerCase() === 'aws:principalorgpaths' &&
            cond.operation().baseOperator().toLowerCase().startsWith('stringequals') &&
            !cond.conditionValues().some((v: string) => v.includes('$')) // Ignore dynamic values for now
          ) {
            specificOus.push(...cond.conditionValues())
          }
          if (
            cond.conditionKey().toLowerCase() === 'aws:principalaccount' &&
            cond.operation().value().toLowerCase().startsWith('stringequals') &&
            !cond.conditionValues().some((v: string) => v.includes('$')) // Ignore dynamic values for now
          ) {
            specificAccounts.push(...cond.conditionValues())
          }
        }
        if (specificAccounts.length > 0) {
          accountsToCheck.specificAccounts.push(...specificAccounts)
        } else if (specificOus.length > 0) {
          accountsToCheck.specificOrganizationalUnits.push(...specificOus)
        } else if (specificOrgs.length > 0) {
          accountsToCheck.specificOrganizations.push(...specificOrgs)
        } else {
          accountsToCheck.allAccounts = true
        }
      }
    }
  }
  return accountsToCheck
}

export async function actionsForWhoCan(request: ResourceAccessRequest): Promise<string[]> {
  const { actions } = request

  if (actions && actions.length > 0) {
    const validActions: string[] = []
    for (const action of actions) {
      const parts = action.split(':')
      if (parts.length !== 2) {
        continue
      }
      const [service, actionName] = parts
      const serviceExists = await iamServiceExists(service)
      if (!serviceExists) {
        continue
      }
      const actionExists = await iamActionExists(service, actionName)
      if (!actionExists) {
        continue
      }

      validActions.push(action)
    }
    return validActions
  }
  if (!request.resource) {
    return []
  }
  return lookupActionsForResourceArn(request.resource)
}

/**
 * Get the the possible resource types for an action and resource
 *
 * @param service the service the action belongs to
 * @param action the action to get the resource type for
 * @param resourceArn the resource type matching the action, if any
 * @throws an error if the service or action does not exist, or if the action is a wildcard only action
 */
export async function lookupActionsForResourceArn(resourceArn: string): Promise<string[]> {
  const [service, resourceType] = await findResourceTypeForArn(resourceArn)
  const resourceTypeKey = resourceType.key

  const selectedActions: string[] = []
  const serviceActions = await iamActionsForService(service)
  for (const action of serviceActions) {
    const actionDetails = await iamActionDetails(service, action)
    for (const rt of actionDetails.resourceTypes) {
      if (rt.name == resourceTypeKey) {
        selectedActions.push(`${service}:${action}`)
        break // No need to check other resource types for this action
      }
    }
  }

  const isRole = new Arn(resourceArn).matches({ service: 'iam', resourceType: 'role' })
  if (isRole) {
    selectedActions.push(...AssumeRoleActions.values())
  }

  return selectedActions
}

export async function findResourceTypeForArn(resourceArn: string): Promise<[string, ResourceType]> {
  const arnParts = splitArnParts(resourceArn)
  const service = arnParts.service!.toLowerCase()

  const serviceExists = await iamServiceExists(service)
  if (!serviceExists) {
    throw new Error(`Unable to find service ${service} for resource ${resourceArn}`)
  }

  const sortedResourceTypes = await allResourceTypesByArnLength(service)
  for (const rt of sortedResourceTypes) {
    const pattern = convertResourcePatternToRegex(rt.arn)
    const match = resourceArn.match(new RegExp(pattern))
    if (match) {
      return [service, rt]
    }
  }

  throw new Error(
    `Unable to find resource type for service ${service} and resource ${resourceArn}.`
  )
}

/**
 * Convert a resource pattern from iam-data to a regex pattern
 *
 * @param pattern the pattern to convert to a regex
 * @returns the regex pattern
 */
export function convertResourcePatternToRegex(pattern: string): string {
  const regex = pattern.replace(/\$\{.*?\}/g, (match, position) => {
    const name = match.substring(2, match.length - 1)
    const camelName = name.at(0)?.toLowerCase() + name.substring(1)
    return `(?<${camelName}>(.+?))`
  })
  return `^${regex}$`
}

async function allResourceTypesByArnLength(service: string): Promise<ResourceType[]> {
  const resourceTypeKeys = await iamResourceTypesForService(service)
  const sortedResourceTypes: ResourceType[] = []
  for (const key of resourceTypeKeys) {
    const details = await iamResourceTypeDetails(service, key)
    sortedResourceTypes.push(details)
  }
  return sortedResourceTypes.sort((a, b) => {
    return b.arn.length - a.arn.length
  })
}

/**
 * Sort the results in a WhoCanResponse in place for consistent output
 *
 * @param whoCanResponse the WhoCanResponse to sort
 */
export function sortWhoCanResults(whoCanResponse: WhoCanResponse) {
  whoCanResponse.allowed.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })

  whoCanResponse.denyDetails?.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })

  whoCanResponse.accountsNotFound.sort()
  whoCanResponse.organizationsNotFound.sort()
  whoCanResponse.organizationalUnitsNotFound.sort()
  whoCanResponse.principalsNotFound.sort()
}
