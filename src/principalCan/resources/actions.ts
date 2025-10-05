import {
  iamActionDetails,
  iamActionsForService,
  iamResourceTypeExists
} from '@cloud-copilot/iam-data'

/**
 * Get the actions for a resource type in a service.
 *
 * @param service the service to get actions for
 * @param resourceType the resource type to get the actions for
 * @returns the actions that can be performed on the resource type
 */
export async function actionsForResourceType(service: string, resourceType: string) {
  const resourceTypeExists = await iamResourceTypeExists(service, resourceType)
  if (!resourceTypeExists) {
    throw new Error(`Resource type ${resourceType} does not exist in service ${service}`)
  }
  const actions = await iamActionsForService(service)

  const matchingAction: string[] = []
  for (const action of actions) {
    const actionDetails = await iamActionDetails(service, action)
    if (actionDetails?.resourceTypes?.some((rt) => rt.name === resourceType)) {
      matchingAction.push(action)
    }
  }

  return matchingAction
}
