import { iamActionDetails } from '@cloud-copilot/iam-data'
import { RequestAnalysis } from '@cloud-copilot/iam-simulate'
import { Job } from '@cloud-copilot/job'
import { IamCollectClient } from '../collect/client.js'
import { simulateRequest } from '../simulate/simulate.js'
import { S3AbacOverride } from '../utils/s3Abac.js'
import { WhoCanAllowed } from './whoCan.js'

export interface WhoCanWorkItem {
  resource: string | undefined
  resourceAccount: string | undefined
  action: string
  principal: string
}

/**
 * The result of executing a whoCan work item.
 * Contains either the allowed result or the deny analysis (but not both).
 */
export interface WhoCanExecutionResult {
  /**
   * The allowed result if the simulation was successful
   */
  allowed?: WhoCanAllowed

  /**
   * The deny analysis if the simulation was not allowed.
   * Only populated when collectDenyDetails is true.
   */
  denyAnalysis?: RequestAnalysis

  /**
   * The work item that was executed, for context in deny details
   */
  workItem: WhoCanWorkItem
}

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

  if (discoveryResult?.result.analysis?.result === 'Allowed') {
    const result = await simulateRequest(
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
    if (result?.result.analysis?.result === 'Allowed') {
      const actionType = await getActionLevel(service, serviceAction)
      return {
        workItem,
        allowed: {
          principal,
          service,
          action: serviceAction,
          level: actionType.toLowerCase()
        }
      }
    } else {
      const actionType = await getActionLevel(service, serviceAction)
      return {
        workItem,
        allowed: {
          principal,
          service: service,
          action: serviceAction,
          level: actionType.toLowerCase(),
          conditions: discoveryResult?.result.analysis.ignoredConditions,
          dependsOnSessionName: discoveryResult?.result.analysis.ignoredRoleSessionName
            ? true
            : undefined
        }
      }
    }
  }

  // Not allowed - return deny analysis if requested
  return {
    workItem,
    denyAnalysis: whoCanOptions.collectDenyDetails ? discoveryResult?.result.analysis : undefined
  }
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
