import { iamActionDetails, iamActionExists, iamServiceExists } from '@cloud-copilot/iam-data'
import {
  type EvaluationResult,
  runSimulation,
  type Simulation,
  type SimulationMode
} from '@cloud-copilot/iam-simulate'
import { isIamRoleArn, isS3BucketOrObjectArn, splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient, type SimulationOrgPolicies } from '../collect/client.js'
import {
  getAllPoliciesForPrincipal,
  isServiceLinkedRole,
  principalExists,
  type PrincipalPolicies
} from '../principals.js'
import {
  getAccountIdForResource,
  getRcpsForResource,
  getResourcePolicyForResource
} from '../resources.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { AssumeRoleActions } from '../utils/sts.js'
import {
  CONTEXT_KEYS,
  type ContextKeys,
  contextValue,
  createContextKeys,
  knownContextKeys
} from './contextKeys.js'

/**
 * The request details for simulating an IAM request.
 */
export interface SimulationRequest {
  /**
   * The ARN of the resource to simulate access to. Can be undefined for wildcard actions.
   */
  resourceArn: string | undefined

  /**
   * The account ID of the resource, only required if it cannot be determined from the resource ARN.
   */
  resourceAccount: string | undefined

  /**
   * The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`.
   */
  action: string

  /**
   * The ARN of the principal to simulate. Can be a user, role, session, or AWS service.
   */
  principal: string
  // anonymous?: boolean

  /**
   * Any custom context keys to use for the simulation.
   */
  customContextKeys: ContextKeys

  /**
   * The simulation mode to use for the request.
   */
  simulationMode: SimulationMode

  /**
   * Whether to ignore missing principal errors.
   */
  ignoreMissingPrincipal?: boolean

  /**
   * Override for S3 ABAC settings for the simulation.
   */
  s3AbacOverride?: S3AbacOverride

  /**
   * The session policy to use for the simulation, if the principal type supports it.
   */
  sessionPolicy?: any
}

/**
 * Simulate an IAM request against the collected IAM data.
 *
 * @param simulationRequest the simulation request details.
 * @param collectClient the IAM collect client to use for data access.
 * @returns the simulation result, including the request and the evaluation result.
 */
export async function simulateRequest(
  simulationRequest: SimulationRequest,
  collectClient: IamCollectClient
) {
  const actionParts = simulationRequest.action.split(':')
  const service = actionParts[0]
  const serviceAction = actionParts[1]
  const serviceExists = await iamServiceExists(service)
  const actionExists = serviceExists && (await iamActionExists(service, serviceAction))
  if (!serviceExists || !actionExists) {
    throw new Error(`Unable to find action details for ${simulationRequest.action}`)
  }
  const actionDetails = await iamActionDetails(service, serviceAction)

  // If it is a wildcard action, the resource account is always the principal account
  if (actionDetails.isWildcardOnly) {
    simulationRequest.resourceAccount = splitArnParts(simulationRequest.principal).accountId!
  }

  if (!simulationRequest.resourceAccount && !simulationRequest.resourceArn) {
    throw new Error(
      'Non wildcard actions require a resource ARN or resource account to be specified.'
    )
  }
  simulationRequest.resourceAccount =
    simulationRequest.resourceAccount ||
    (await getAccountIdForResource(collectClient, simulationRequest.resourceArn!))

  if (!simulationRequest.resourceAccount) {
    throw new Error(`Unable to find account ID for resource ${simulationRequest.resourceArn}`)
  }

  const principalFound = await principalExists(simulationRequest.principal, collectClient)
  if (!principalFound && !simulationRequest.ignoreMissingPrincipal) {
    throw new Error(
      `Principal ${simulationRequest.principal} does not exist. Use --ignore-missing-principal to ignore this.`
    )
  }

  //Lookup the principal policies
  const principalPolicies = await getAllPoliciesForPrincipal(
    collectClient,
    simulationRequest.principal
  )

  const { resourcePolicy, resourceRcps } = await getResourcePolicies(
    collectClient,
    simulationRequest.resourceArn,
    simulationRequest.resourceAccount
  )

  const useResourcePolicy =
    simulationRequest.resourceArn &&
    !(isIamRoleArn(simulationRequest.resourceArn) && service.toLowerCase() === 'iam')

  if (AssumeRoleActions.has(simulationRequest.action.toLowerCase()) && !resourcePolicy) {
    throw new Error(
      `Trust policy not found for resource ${simulationRequest.resourceArn}. sts assume role actions require a trust policy.`
    )
  }

  const { contextKeys, resourceTagsAreKnown } = await createContextKeys(
    collectClient,
    simulationRequest,
    service,
    simulationRequest.customContextKeys
  )

  const vpcEndpointId = contextValue(contextKeys, CONTEXT_KEYS.vpcEndpointId)
  let vpcEndpointPolicy: { name: string; policy: any } | undefined = undefined
  if (vpcEndpointId && typeof vpcEndpointId === 'string') {
    const vpcEndpointArn = await collectClient.getVpcEndpointArnForVpcEndpointId(vpcEndpointId)
    if (vpcEndpointArn) {
      const vpcPolicy = await collectClient.getVpcEndpointPolicyForArn(vpcEndpointArn)
      if (vpcPolicy) {
        vpcEndpointPolicy = { name: vpcEndpointArn, policy: vpcPolicy }
      }
    }
  }

  const applicableScps = isServiceLinkedRole(simulationRequest.principal)
    ? []
    : principalPolicies.scps

  const request: Simulation['request'] = {
    action: simulationRequest.action,
    resource: {
      resource: simulationRequest.resourceArn || '*',
      accountId: simulationRequest.resourceAccount
    },
    principal: simulationRequest.principal,
    contextVariables: contextKeys
  }

  const simulation: Simulation = {
    request,
    sessionPolicy: simulationRequest.sessionPolicy,
    identityPolicies: prepareIdentityPolicies(simulationRequest.principal, principalPolicies),
    serviceControlPolicies: applicableScps,
    resourceControlPolicies: rcpsForRequest(
      simulationRequest.principal,
      actionDetails.isWildcardOnly,
      resourceRcps,
      principalPolicies.rcps
    ),
    resourcePolicy: useResourcePolicy ? resourcePolicy : undefined,
    permissionBoundaryPolicies: preparePermissionBoundary(principalPolicies),
    vpcEndpointPolicies: vpcEndpointPolicy ? [vpcEndpointPolicy] : undefined
  }

  const s3BucketOrObjectRequest =
    simulationRequest.resourceArn && isS3BucketOrObjectArn(simulationRequest.resourceArn)
  if (s3BucketOrObjectRequest) {
    const bucketAbacEnabled = await evaluateAbacForBucket(
      simulationRequest.s3AbacOverride,
      collectClient,
      simulationRequest.resourceAccount!,
      simulationRequest.resourceArn!
    )
    simulation.additionalSettings = {
      s3: {
        bucketAbacEnabled
      }
    }
  }

  // Assemble the strict context keys for the simulation
  // Start with the default known context keys
  const strictContextKeys = [...knownContextKeys]

  if (!simulationRequest.principal.endsWith(':root')) {
    // Treat this as strict unless it is a root principal
    strictContextKeys.push(CONTEXT_KEYS.assumedRoot)
  }

  // S3 Access Points are Not Supported Right Now, Don't Add Noise
  if (simulationRequest.action.startsWith('s3:')) {
    strictContextKeys.push('s3:DataAccessPointAccount')
    strictContextKeys.push('s3:DataAccessPointArn')
  }

  // Add the custom context keys from the simulation request
  for (const key of Object.keys(simulationRequest.customContextKeys)) {
    strictContextKeys.push(key)
  }

  //If we know the tag keys, just make all tag keys strict
  if (resourceTagsAreKnown) {
    strictContextKeys.push('/^aws:ResourceTag\/.*/')
    if (s3BucketOrObjectRequest) {
      strictContextKeys.push('/^s3:BucketTag\/.*/')
    }
  }

  // There also may be other tag context keys, so add those too
  for (const key of Object.keys(contextKeys)) {
    if (key.toLowerCase().includes('tag/')) {
      strictContextKeys.push(key)
    }
  }

  const result = await runSimulation(simulation, {
    simulationMode: simulationRequest.simulationMode,
    strictConditionKeys: strictContextKeys
  })

  return { request, result }
}

async function getResourcePolicies(
  collectClient: IamCollectClient,
  resourceArn: string | undefined,
  resourceAccount: string | undefined
): Promise<{
  resourcePolicy: any | undefined
  resourceRcps: SimulationOrgPolicies[]
}> {
  if (!resourceArn) {
    return { resourcePolicy: undefined, resourceRcps: [] }
  }

  const resourcePolicy = await getResourcePolicyForResource(
    collectClient,
    resourceArn,
    resourceAccount
  )
  const resourceRcps = await getRcpsForResource(collectClient, resourceArn, resourceAccount)

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

/**
 * Evaluates whether ABAC (Attribute-Based Access Control) is enabled for a given S3 bucket or object.
 * The evaluation can be overridden by the `s3AbacOverride` parameter.
 *
 * @param s3AbacOverride the override setting for S3 ABAC or undefined to auto-detect
 * @param collectClient the IAM collect client to use for data access
 * @param bucketAccountId the account ID the bucket belongs to
 * @param bucketOrObjectArn the ARN of the bucket or bucket object
 * @returns whether ABAC should be used to evaluate access for the bucket or object
 */
async function evaluateAbacForBucket(
  s3AbacOverride: S3AbacOverride | undefined,
  collectClient: IamCollectClient,
  bucketAccountId: string,
  bucketOrObjectArn: string
): Promise<boolean> {
  if (s3AbacOverride === 'enabled') {
    return true
  }
  if (s3AbacOverride === 'disabled') {
    return false
  }
  return collectClient.getAbacEnabledForBucket(bucketAccountId, bucketOrObjectArn)
}
