import { iamActionDetails } from '@cloud-copilot/iam-data'
import {
  type EvaluationResult,
  type RequestAnalysis,
  type SuccessfulRunSimulationResults
} from '@cloud-copilot/iam-simulate'
import type { Job } from '@cloud-copilot/job'
import { IamCollectClient } from '../collect/client.js'
import { simulateRequest } from '../simulate/simulate.js'
import type { S3AbacOverride } from '../utils/s3Abac.js'
import type { WhoCanAllowed, WhoCanAllowedResourcePattern } from './whoCan.js'

export interface WhoCanWorkItem {
  resource: string | undefined
  resourceAccount: string | undefined
  action: string
  principal: string
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
  | DeniedSingleWhoCanExecutionResult
  | DeniedWildcardWhoCanExecutionResult

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
      s3AbacOverride: whoCanOptions.s3AbacOverride
    },
    collectClient
  )

  if (discoveryResult.result.resultType === 'error') {
    // If discovery fails, we treat it as a denial without details (since we don't have analysis to share)
    throw new Error('Discovery simulation failed: ' + discoveryResult.result.errors)
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
        s3AbacOverride: whoCanOptions.s3AbacOverride
      },
      collectClient
    )

    if (strictResult.result.resultType === 'error') {
      // If discovery fails, we treat it as a denial without details (since we don't have analysis to share)
      throw new Error('Discovery simulation failed: ' + strictResult.result.errors)
    }

    if (strictResult?.result.overallResult === 'Allowed') {
      return mapSimulationResultToWhoCanExecutionResult(
        workItem,
        service,
        serviceAction,
        actionType,
        strictResult.result,
        !!whoCanOptions.collectDenyDetails
      )
    }
  } else {
    return mapSimulationResultToWhoCanExecutionResult(
      workItem,
      service,
      serviceAction,
      actionType,
      discoveryResult.result,
      !!whoCanOptions.collectDenyDetails
    )
  }

  return mapSimulationResultToWhoCanExecutionResult(
    workItem,
    service,
    serviceAction,
    actionType,
    discoveryResult.result,
    !!whoCanOptions.collectDenyDetails
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

function mapSimulationResultToWhoCanExecutionResult(
  workItem: WhoCanWorkItem,
  service: string,
  action: string,
  actionType: string,
  simulationResponse: SuccessfulRunSimulationResults,
  collectDenyDetails: boolean
): WhoCanExecutionResult {
  const { principal } = workItem

  if (simulationResponse.overallResult === 'Allowed') {
    // Build allowed result
    const allowed: WhoCanAllowed = {
      principal,
      service,
      action,
      level: actionType.toLowerCase()
    }

    if (simulationResponse.resultType === 'single') {
      const analysis = simulationResponse.result.analysis
      allowed.conditions = analysis.ignoredConditions
      allowed.dependsOnSessionName = analysis.ignoredRoleSessionName ? true : undefined
    } else {
      // Wildcard result - collect allowed patterns
      const allowedPatterns: WhoCanAllowedResourcePattern[] = []
      for (const r of simulationResponse.results) {
        if (r.analysis.result === 'Allowed') {
          allowedPatterns.push({
            pattern: r.resourcePattern,
            resourceType: r.resourceType,
            conditions: r.analysis.ignoredConditions,
            dependsOnSessionName: r.analysis.ignoredRoleSessionName ? true : undefined
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
