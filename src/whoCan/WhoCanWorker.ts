import { iamActionDetails } from '@actsecurity/iam-data'
import {
  type AllowedConditionExpression,
  type EvaluationResult,
  getGrantReasons,
  type IgnoredConditions,
  type RequestAnalysis,
  type SuccessfulRunSimulationResults
} from '@actsecurity/iam-simulate'
import type { Job } from '@actsecurity/job'
import { IamCollectClient } from '../collect/client.js'
import { simulateRequest } from '../simulate/simulate.js'
import type { S3AbacOverride } from '../utils/s3Abac.js'
import type { WhoCanAllowed, WhoCanAllowedResourcePattern } from './whoCan.js'
import { log } from '@actsecurity/log'

export interface WhoCanWorkItem {
  resource: string | undefined
  resourceAccount: string | undefined
  action: string
  principal: string
  resultPrincipal?: string | undefined
  strictContextKeys: string[] | undefined
  collectDenyDetails: boolean
}

/**
 * Execution result when the principal is allowed access.
 */
export interface AllowedWhoCanExecutionResult {
  type: 'allowed'
  workItem: WhoCanWorkItem
  allowed: WhoCanAllowed
}

/**
 * Execution result when the principal is denied access, without detailed analysis.
 */
export interface DeniedWhoCanExecutionResult {
  type: 'denied'
  workItem: WhoCanWorkItem
}

/**
 * Execution result when the principal is denied access for a single resource pattern,
 * with detailed analysis included.
 */
export interface DeniedSingleWhoCanExecutionResult {
  type: 'denied_single'
  workItem: WhoCanWorkItem
  analysis: RequestAnalysis
}

/**
 * Details about a denied resource pattern, including the analysis for why it was denied.
 */
export interface WhoCanDenyResourceDetails {
  /**
   * The resource pattern that was tested.
   */
  pattern: string
  /**
   * The type of resource for the pattern.
   */
  resourceType: string
  /**
   * The analysis explaining why the request was denied.
   */
  analysis: RequestAnalysis
}

/**
 * Execution result when the principal is denied access for a wildcard resource,
 * with detailed analysis for each denied pattern.
 */
export interface DeniedWildcardWhoCanExecutionResult {
  type: 'denied_wildcard'
  workItem: WhoCanWorkItem
  overallResult: EvaluationResult
  deniedPatterns: WhoCanDenyResourceDetails[]
}

/**
 * The result of executing a whoCan work item.
 * Contains either the allowed result or the deny analysis (but not both).
 */
export type WhoCanExecutionResult =
  | AllowedWhoCanExecutionResult
  | DeniedWhoCanExecutionResult
  | DeniedSingleWhoCanExecutionResult
  | DeniedWildcardWhoCanExecutionResult

/**
 * Union type for denied execution results that include detailed analysis.
 */
export type DeniedWhoCanExecutionResultWithDetails =
  DeniedSingleWhoCanExecutionResult | DeniedWildcardWhoCanExecutionResult

/**
 * The possible values for the `type` discriminator of a WhoCanExecutionResult.
 */
export type WhoCanExecutionResultType = WhoCanExecutionResult['type']

export function createJobForWhoCanWorkItem(
  workItem: WhoCanWorkItem,
  collectClient: IamCollectClient,
  whoCanOptions: WhoCanOptions
): Job<WhoCanExecutionResult, Record<string, unknown>> {
  return {
    properties: {},
    execute: async (context) => {
      return executeWhoCan(workItem, collectClient, whoCanOptions)
    }
  }
}

export interface WhoCanOptions {
  s3AbacOverride?: S3AbacOverride
  collectDenyDetails?: boolean
  collectGrantDetails?: boolean
  strictContextKeys?: string[]
}

export async function executeWhoCan(
  workItem: WhoCanWorkItem,
  collectClient: IamCollectClient,
  whoCanOptions: WhoCanOptions
): Promise<WhoCanExecutionResult> {
  const { principal, resource, resourceAccount, action } = workItem
  const [service, serviceAction] = action.split(':')
  const discoveryResult = await simulateRequest(
    {
      principal,
      resourceArn: resource,
      resourceAccount: resourceAccount,
      action,
      customContextKeys: {},
      simulationMode: 'Discovery',
      s3AbacOverride: whoCanOptions.s3AbacOverride,
      additionalStrictContextKeys: whoCanOptions.strictContextKeys
    },
    collectClient
  )

  if (discoveryResult.result.resultType === 'error') {
    log.error({
      mode: 'discovery',
      simulationErrors: true,
      errors: discoveryResult.result.errors,
      resource
    })
    throw new Error('Discovery simulation failed: ' + JSON.stringify(discoveryResult.result.errors))
  }

  const actionType = await getActionLevel(service, serviceAction)
  if (discoveryResult?.result.overallResult === 'Allowed') {
    const strictResult = await simulateRequest(
      {
        principal,
        resourceArn: resource,
        resourceAccount,
        action,
        customContextKeys: {},
        simulationMode: 'Strict',
        s3AbacOverride: whoCanOptions.s3AbacOverride,
        additionalStrictContextKeys: whoCanOptions.strictContextKeys
      },
      collectClient
    )

    if (strictResult.result.resultType === 'error') {
      log.error({
        mode: 'strict',
        simulationErrors: true,
        errors: strictResult.result.errors,
        resource
      })
      throw new Error('Strict simulation failed: ' + JSON.stringify(strictResult.result.errors))
    }

    if (strictResult?.result.overallResult === 'Allowed') {
      return mapSimulationResultToWhoCanExecutionResult(
        workItem,
        service,
        serviceAction,
        actionType,
        strictResult.result,
        !!whoCanOptions.collectDenyDetails,
        !!whoCanOptions.collectGrantDetails
      )
    }
  } else {
    return mapSimulationResultToWhoCanExecutionResult(
      workItem,
      service,
      serviceAction,
      actionType,
      discoveryResult.result,
      !!whoCanOptions.collectDenyDetails,
      !!whoCanOptions.collectGrantDetails
    )
  }

  return mapSimulationResultToWhoCanExecutionResult(
    workItem,
    service,
    serviceAction,
    actionType,
    discoveryResult.result,
    !!whoCanOptions.collectDenyDetails,
    !!whoCanOptions.collectGrantDetails
  )
}

/**
 * Get the action level for a specific service action, will fail if the service or action does not exist.
 *
 * @param service the service the action belongs to
 * @param action the action to get the level for
 * @returns the access level of the action, e.g. 'Read', 'Write', 'List', 'Tagging', 'Permissions management', 'Other'
 */
async function getActionLevel(service: string, action: string): Promise<string> {
  const details = await iamActionDetails(service, action)
  return details.accessLevel
}

/**
 * Return an allowed-condition expression only when it represents a meaningful
 * access constraint for whoCan output.
 *
 * @param conditions the allowed-condition expression returned by iam-simulate
 * @returns the expression when it is meaningful, otherwise undefined
 */
function meaningfulAllowedConditions(
  conditions: AllowedConditionExpression | undefined
): AllowedConditionExpression | undefined {
  if (!conditions || conditions.conditionType === 'always') {
    return undefined
  }
  return conditions
}

/**
 * Return ignored discovery-condition diagnostics only when at least one policy
 * bucket contains ignored allow or deny condition entries.
 *
 * @param ignoredConditions the ignored-condition diagnostics returned by iam-simulate
 * @returns the diagnostics when non-empty, otherwise undefined
 */
function nonEmptyIgnoredConditions(
  ignoredConditions: IgnoredConditions | undefined
): IgnoredConditions | undefined {
  if (!ignoredConditions) {
    return undefined
  }

  for (const conditionBucket of Object.values(ignoredConditions)) {
    // IgnoredConditions buckets are shaped as optional allow/deny arrays per policy type.
    if ((conditionBucket.allow?.length ?? 0) > 0 || (conditionBucket.deny?.length ?? 0) > 0) {
      return ignoredConditions
    }
  }

  return undefined
}

function mapSimulationResultToWhoCanExecutionResult(
  workItem: WhoCanWorkItem,
  service: string,
  action: string,
  actionType: string,
  simulationResponse: SuccessfulRunSimulationResults,
  collectDenyDetails: boolean,
  collectGrantDetails: boolean
): WhoCanExecutionResult {
  const { principal, resultPrincipal } = workItem

  if (simulationResponse.overallResult === 'Allowed') {
    // Build allowed result
    const allowed: WhoCanAllowed = {
      principal: resultPrincipal ?? principal,
      service,
      action,
      level: actionType.toLowerCase()
    }

    if (simulationResponse.resultType === 'single') {
      const analysis = simulationResponse.result.analysis
      const conditions = meaningfulAllowedConditions(analysis.conditions)
      if (conditions) {
        allowed.conditions = conditions
      }

      const ignoredConditions = nonEmptyIgnoredConditions(analysis.ignoredConditions)
      if (ignoredConditions) {
        allowed.ignoredConditions = ignoredConditions
      }

      if (analysis.ignoredRoleSessionName) {
        allowed.dependsOnSessionName = true
      }
      if (simulationResponse.result.resourceType) {
        allowed.resourceType = simulationResponse.result.resourceType
      }

      if (collectGrantDetails) {
        allowed.details = getGrantReasons(analysis)
      }
    } else {
      // Wildcard result - collect allowed patterns with per-pattern grant details
      const allowedPatterns: WhoCanAllowedResourcePattern[] = []
      for (const r of simulationResponse.results) {
        if (r.analysis.result === 'Allowed') {
          const conditions = meaningfulAllowedConditions(r.analysis.conditions)
          const ignoredConditions = nonEmptyIgnoredConditions(r.analysis.ignoredConditions)
          allowedPatterns.push({
            pattern: r.resourcePattern,
            resourceType: r.resourceType,
            ...(conditions && { conditions }),
            ...(ignoredConditions && { ignoredConditions }),
            dependsOnSessionName: r.analysis.ignoredRoleSessionName ? true : undefined,
            ...(collectGrantDetails && { details: getGrantReasons(r.analysis) })
          })
        }
      }
      if (allowedPatterns.length > 0) {
        allowed.allowedPatterns = allowedPatterns
      }
    }

    return {
      type: 'allowed',
      workItem,
      allowed
    }
  }

  // Denied result
  if (!collectDenyDetails) {
    // If we don't need to collect deny details, we can return a simple denied result without analysis
    return {
      type: 'denied',
      workItem
    }
  }

  if (simulationResponse.resultType === 'single') {
    return {
      type: 'denied_single',
      workItem,
      analysis: simulationResponse.result.analysis
    }
  } else {
    // Wildcard denial - collect denied patterns
    const deniedPatterns: WhoCanDenyResourceDetails[] = simulationResponse.results
      .filter((r) => r.analysis.result !== 'Allowed')
      .map((r) => ({
        pattern: r.resourcePattern,
        resourceType: r.resourceType,
        analysis: r.analysis
      }))

    return {
      type: 'denied_wildcard',
      overallResult: simulationResponse.overallResult,
      workItem,
      deniedPatterns
    }
  }
}
