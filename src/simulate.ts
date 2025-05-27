import { iamActionDetails } from '@cloud-copilot/iam-data'
import { runSimulation, Simulation } from '@cloud-copilot/iam-simulate'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient, SimulationOrgPolicies } from './collect/client.js'
import { ContextKeys, createContextKeys } from './contextKeys.js'
import { getAllPoliciesForPrincipal, isServiceLinkedRole, PrincipalPolicies } from './principals.js'
import {
  getAccountIdForResource,
  getRcpsForResource,
  getResourcePolicyForResource
} from './resources.js'

export interface SimulationRequest {
  resourceArn: string
  resourceAccount: string | undefined
  action: string
  principal: string
  // anonymous?: boolean
  customContextKeys: ContextKeys
}

const assumeRoleActions = new Set([
  'sts:assumerole',
  'sts:assumerolewithwebidentity',
  'sts:assumerolewithsaml'
])

export async function simulateRequest(
  simulationRequest: SimulationRequest,
  collectClient: IamCollectClient
) {
  simulationRequest.resourceAccount =
    simulationRequest.resourceAccount ||
    (await getAccountIdForResource(collectClient, simulationRequest.resourceArn))

  if (!simulationRequest.resourceAccount) {
    throw new Error(`Unable to find account ID for resource ${simulationRequest.resourceArn}`)
  }

  const actionParts = simulationRequest.action.split(':')
  const service = actionParts[0]
  const serviceAction = actionParts[1]
  const actionDetails = await iamActionDetails(service, serviceAction)
  if (!actionDetails) {
    throw new Error(`Unable to find action details for ${simulationRequest.action}`)
  }

  if (actionDetails.isWildcardOnly) {
    simulationRequest.resourceAccount = splitArnParts(simulationRequest.principal).accountId!
  }

  //Lookup the principal policies
  const principalPolicies = await getAllPoliciesForPrincipal(
    collectClient,
    simulationRequest.principal
  )

  const resourcePolicy = await getResourcePolicyForResource(
    collectClient,
    simulationRequest.resourceArn
  )

  if (assumeRoleActions.has(simulationRequest.action.toLowerCase()) && !resourcePolicy) {
    throw new Error(
      `Trust policy not found for resource ${simulationRequest.resourceArn}. sts:AssumeRole requires a trust policy.`
    )
  }

  const resourceRcps = await getRcpsForResource(collectClient, simulationRequest.resourceArn)

  const context = await createContextKeys(
    collectClient,
    simulationRequest,
    simulationRequest.customContextKeys
  )

  const applicableScps = isServiceLinkedRole(simulationRequest.principal)
    ? []
    : principalPolicies.scps

  const simulation: Simulation = {
    request: {
      action: simulationRequest.action,
      resource: {
        resource: simulationRequest.resourceArn,
        accountId: simulationRequest.resourceAccount
      },
      principal: simulationRequest.principal,
      contextVariables: context
    },
    identityPolicies: prepareIdentityPolicies(simulationRequest.principal, principalPolicies),
    serviceControlPolicies: applicableScps,
    resourceControlPolicies: rcpsForRequest(
      simulationRequest.principal,
      actionDetails.isWildcardOnly,
      resourceRcps,
      principalPolicies.scps
    ),
    resourcePolicy: resourcePolicy,
    permissionBoundaryPolicies: preparePermissionBoundary(principalPolicies)
  }

  const result = await runSimulation(simulation, {})

  return result
}

function rcpsForRequest(
  principalArn: string,
  actionIsWildcard: boolean,
  resourceRcps: SimulationOrgPolicies[],
  principalRcps: SimulationOrgPolicies[]
): SimulationOrgPolicies[] {
  if (isServiceLinkedRole(principalArn)) {
    return []
  }

  let theRcps = resourceRcps

  if (actionIsWildcard) {
    theRcps = principalRcps
  }

  return theRcps.map((rcp) => {
    rcp.orgIdentifier
    return {
      orgIdentifier: rcp.orgIdentifier,
      policies: rcp.policies.filter((policy) => {
        return !policy.name.toLowerCase().endsWith('rcpfullawsaccess')
      })
    }
  })
}

function prepareIdentityPolicies(
  principalArn: string,
  principalPolicies: PrincipalPolicies
): { name: string; policy: any }[] {
  //Collect unique managed policies
  const uniqueIdentityPolicies: Record<string, { name: string; policy: any }> = {}
  principalPolicies.managedPolicies.forEach((policy) => {
    if (!uniqueIdentityPolicies[policy.arn]) {
      uniqueIdentityPolicies[policy.arn] = {
        name: policy.arn,
        policy: policy.policy
      }
    }
  })
  principalPolicies.groupPolicies?.forEach((groupPolicy) => {
    groupPolicy.managedPolicies.forEach((policy) => {
      if (!uniqueIdentityPolicies[policy.arn]) {
        uniqueIdentityPolicies[policy.arn] = {
          name: policy.arn,
          policy: policy.policy
        }
      }
    })
  })

  const identityPolicies = Object.values(uniqueIdentityPolicies)

  principalPolicies.inlinePolicies.forEach((policy) => {
    identityPolicies.push({
      name: `${principalArn}#${policy.name}`,
      policy: policy.policy
    })
  })

  principalPolicies.groupPolicies?.forEach((groupPolicy) => {
    groupPolicy.inlinePolicies.forEach((policy) => {
      identityPolicies.push({
        name: `${groupPolicy.group}#${policy.name}`,
        policy: policy.policy
      })
    })
  })

  return identityPolicies
}

function preparePermissionBoundary(
  principalPolicies: PrincipalPolicies
): { name: string; policy: any }[] | undefined {
  if (principalPolicies.permissionBoundary) {
    return [
      {
        name: principalPolicies.permissionBoundary.arn,
        policy: principalPolicies.permissionBoundary.policy
      }
    ]
  }
  return undefined
}
