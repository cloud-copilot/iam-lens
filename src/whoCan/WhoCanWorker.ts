import { iamActionDetails } from '@cloud-copilot/iam-data'
import { Job } from '@cloud-copilot/job'
import { IamCollectClient } from '../collect/client.js'
import { simulateRequest } from '../simulate/simulate.js'
import { WhoCanAllowed } from './whoCan.js'

export interface WhoCanWorkItem {
  resource: string | undefined
  resourceAccount: string | undefined
  action: string
  principal: string
}

export function createJobForWhoCanWorkItem(
  workItem: WhoCanWorkItem,
  collectClient: IamCollectClient
): Job<WhoCanAllowed | undefined, Record<string, unknown>> {
  return {
    properties: {},
    execute: async (context) => {
      return executeWhoCan(workItem, collectClient)
    }
  }
}

export async function executeWhoCan(
  workItem: WhoCanWorkItem,
  collectClient: IamCollectClient
): Promise<WhoCanAllowed | undefined> {
  const { principal, resource, resourceAccount, action } = workItem
  const [service, serviceAction] = action.split(':')
  const discoveryResult = await simulateRequest(
    {
      principal,
      resourceArn: resource,
      resourceAccount: resourceAccount,
      action,
      customContextKeys: {},
      simulationMode: 'Discovery'
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
        simulationMode: 'Strict'
      },
      collectClient
    )
    if (result?.result.analysis?.result === 'Allowed') {
      const actionType = await getActionLevel(service, serviceAction)
      return {
        principal,
        service,
        action: serviceAction,
        level: actionType.toLowerCase()
      }
    } else {
      const actionType = await getActionLevel(service, serviceAction)
      return {
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

  return undefined
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
