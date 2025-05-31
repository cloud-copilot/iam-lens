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
import {
  isAssumedRoleArn,
  isIamRoleArn,
  isIamUserArn,
  isServicePrincipal,
  splitArnParts
} from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../collect/client.js'
import { getAccountIdForResource, getResourcePolicyForResource } from '../resources.js'
import { simulateRequest } from '../simulate/simulate.js'
import { Arn } from '../utils/arn.js'
import { AssumeRoleActions } from '../utils/sts.js'

export interface ResourceAccessRequest {
  resource?: string
  resourceAccount?: string
  actions: string[]
}

export interface WhoCanAllowed {
  principal: string
  service: string
  action: string
}

export interface WhoCanResponse {
  allowed: WhoCanAllowed[]
  allAccountsChecked: boolean
  accountsNotFound: string[]
  organizationsNotFound: string[]
  organizationalUnitsNotFound: string[]
  principalsNotFound: string[]
}

export async function whoCan(
  collectClient: IamCollectClient,
  request: ResourceAccessRequest
): Promise<WhoCanResponse> {
  const { resource } = request

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
    resourcePolicy = await getResourcePolicyForResource(collectClient, resource)
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

  for (const account of uniqueAccounts.accounts) {
    const principals = await collectClient.getAllPrincipalsInAccount(account)
    for (const principal of principals) {
      const principalResults = await runPrincipalForActions(
        collectClient,
        principal,
        resource,
        resourceAccount,
        actions
      )
      whoCanResults.push(...principalResults)
    }
  }

  const principalsNotFound: string[] = []
  for (const principal of accountsToCheck.specificPrincipals) {
    if (isServicePrincipal(principal)) {
      const principalResults = await runPrincipalForActions(
        collectClient,
        principal,
        resource,
        resourceAccount,
        actions
      )
      whoCanResults.push(...principalResults)
    } else if (isIamUserArn(principal) || isIamRoleArn(principal) || isAssumedRoleArn(principal)) {
      const principalExists = await collectClient.principalExists(principal)
      if (!principalExists) {
        principalsNotFound.push(principal)
      } else {
        const principalResults = await runPrincipalForActions(
          collectClient,
          principal,
          resource,
          resourceAccount,
          actions
        )
        whoCanResults.push(...principalResults)
      }
    } else {
      principalsNotFound.push(principal)
    }
  }

  return {
    allowed: whoCanResults,
    allAccountsChecked: accountsToCheck.allAccounts,
    accountsNotFound: uniqueAccounts.accountsNotFound,
    organizationsNotFound: uniqueAccounts.organizationsNotFound,
    organizationalUnitsNotFound: uniqueAccounts.organizationalUnitsNotFound,
    principalsNotFound: principalsNotFound
  }
}

async function runPrincipalForActions(
  collectClient: IamCollectClient,
  principal: string,
  resource: string | undefined,
  resourceAccount: string,
  actions: string[]
): Promise<WhoCanAllowed[]> {
  const results: WhoCanAllowed[] = []
  for (const action of actions) {
    const result = await simulateRequest(
      {
        principal: principal,
        resourceArn: resource,
        resourceAccount,
        action,
        customContextKeys: {}
      },
      collectClient
    )
    if (result.analysis?.result === 'Allowed') {
      const [service, serviceAction] = action.split(':')
      results.push({
        principal,
        service: service,
        action: serviceAction
      })
    }
  }

  return results
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
