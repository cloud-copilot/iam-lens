import { iamActionDetails, iamActionExists, iamServiceExists } from '@cloud-copilot/iam-data'
import { EvaluationResult, runSimulation, Simulation } from '@cloud-copilot/iam-simulate'
import { isIamRoleArn, splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient, SimulationOrgPolicies } from '../collect/client.js'
import {
  getAllPoliciesForPrincipal,
  isServiceLinkedRole,
  PrincipalPolicies
} from '../principals.js'
import {
  getAccountIdForResource,
  getRcpsForResource,
  getResourcePolicyForResource
} from '../resources.js'
import { AssumeRoleActions } from '../utils/sts.js'
import { ContextKeys, createContextKeys } from './contextKeys.js'

export interface SimulationRequest {
  resourceArn: string
  resourceAccount: string | undefined
  action: string
  principal: string
  // anonymous?: boolean
  customContextKeys: ContextKeys
}

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
  const serviceExists = await iamServiceExists(service)
  const actionExists = serviceExists && (await iamActionExists(service, serviceAction))
  if (!serviceExists || !actionExists) {
    throw new Error(`Unable to find action details for ${simulationRequest.action}`)
  }
  const actionDetails = await iamActionDetails(service, serviceAction)

  if (actionDetails.isWildcardOnly) {
    simulationRequest.resourceAccount = splitArnParts(simulationRequest.principal).accountId!
  }

  //Lookup the principal policies
  const principalPolicies = await getAllPoliciesForPrincipal(
    collectClient,
    simulationRequest.principal
  )

  const { resourcePolicy, resourceRcps } = await getResourcePolicies(
    collectClient,
    simulationRequest.resourceArn
  )

  const useResourcePolicy =
    simulationRequest.resourceArn &&
    !(isIamRoleArn(simulationRequest.resourceArn) && service.toLowerCase() === 'iam')

  if (AssumeRoleActions.has(simulationRequest.action.toLowerCase()) && !resourcePolicy) {
    throw new Error(
      `Trust policy not found for resource ${simulationRequest.resourceArn}. sts assume role actions require a trust policy.`
    )
  }

  const context = await createContextKeys(
    collectClient,
    simulationRequest,
    simulationRequest.customContextKeys
  )

  const applicableScps = isServiceLinkedRole(simulationRequest.principal)
    ? []
    : principalPolicies.scps

  console.log(principalPolicies)
  console.log(resourcePolicy)

  const simulation: Simulation = {
    request: {
      action: simulationRequest.action,
      resource: {
        resource: simulationRequest.resourceArn || '*',
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
      principalPolicies.rcps
    ),
    resourcePolicy: useResourcePolicy ? resourcePolicy : undefined,
    permissionBoundaryPolicies: preparePermissionBoundary(principalPolicies)
  }

  const result = await runSimulation(simulation, {})

  return result
}

async function getResourcePolicies(
  collectClient: IamCollectClient,
  resourceArn: string
): Promise<{
  resourcePolicy: any | undefined
  resourceRcps: SimulationOrgPolicies[]
}> {
  if (!resourceArn) {
    return { resourcePolicy: undefined, resourceRcps: [] }
  }

  const resourcePolicy = await getResourcePolicyForResource(collectClient, resourceArn)
  const resourceRcps = await getRcpsForResource(collectClient, resourceArn)

  return { resourcePolicy, resourceRcps }
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

export function resultMatchesExpectation(
  expected: EvaluationResult | 'AnyDeny' | undefined,
  result: EvaluationResult
): boolean {
  if (!expected) {
    return true
  }
  if (expected === 'AnyDeny') {
    return result.includes('Denied')
  }
  return expected === result
}
