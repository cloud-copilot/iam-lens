import { convertAssumedRoleArnToRoleArn, splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../collect/client.js'
import { isArnPrincipal, isServicePrincipal } from '../principals.js'
import { SimulationRequest } from './simulate.js'

/**
 * Context keys for IAM simulation requests.
 *
 * These keys are used to provide additional context for the simulation, such as
 * the principal making the request, the resource being accessed, and any additional
 * context keys that may be required for the simulation.
 */
export type ContextKeys = Record<string, string | string[]>

export const knownContextKeys: readonly string[] = [
  'aws:SecureTransport',
  'aws:CurrentTime',
  'aws:EpochTime',

  'aws:PrincipalArn',
  'aws:PrincipalAccount',
  'aws:PrincipalOrgId',
  'aws:PrincipalOrgPaths',
  'aws:PrincipalType',
  'aws:userid',
  'aws:username',

  'aws:ResourceAccount',
  'aws:ResourceOrgID',
  'aws:ResourceOrgPaths',

  'aws:PrincipalIsAWSService',
  'aws:PrincipalServiceName',
  'aws:SourceAccount',
  'aws:SourceOrgID',
  'aws:SourceOrgPaths',
  'aws:SourceOwner'
]

export const CONTEXT_KEYS = {
  assumedRoot: 'aws:AssumedRoot',
  vpc: 'aws:SourceVpc',
  vpcEndpointId: 'aws:SourceVpce',
  vpcEndpointAccount: 'aws:VpceAccount',
  vpcEndpointOrgId: 'aws:VpceOrgID',
  vpcEndpointOrgPaths: 'aws:VpceOrgPaths'
}

/**
 * Checks if a context has a specific key (case-insensitive).
 *
 * @param context - The context to check.
 * @param key - The key to check for.
 * @returns True if the context has the key, false otherwise.
 */
export function contextHasKey(context: ContextKeys, key: string): boolean {
  return !!contextValue(context, key)
}

/**
 * Get the value of a context key (case-insensitive).
 *
 * @param context - The context to check.
 * @param key - The key to get the value for.
 * @returns The value of the context key, or undefined if it doesn't exist.
 */
export function contextValue(context: ContextKeys, key: string): string | string[] | undefined {
  const matchingKey = Object.keys(context).find(
    (contextKey) => contextKey.toLowerCase() === key.toLowerCase()
  )
  return matchingKey ? context[matchingKey] : undefined
}

/**
 * Get the context keys for a simulation request.
 *
 * @param collectClient the collect client to use for fetching data
 * @param simulationRequest the simulation request to create context keys for
 * @param service the service the request is for
 * @param contextKeyOverrides the context key overrides to apply
 * @returns a promise that resolves to the context keys for the simulation request
 */
export async function createContextKeys(
  collectClient: IamCollectClient,
  simulationRequest: SimulationRequest,
  service: string,
  contextKeyOverrides: ContextKeys
): Promise<ContextKeys> {
  const result: ContextKeys = {
    'aws:SecureTransport': 'true',
    'aws:CurrentTime': new Date().toISOString(),
    'aws:EpochTime': Math.floor(Date.now() / 1000).toString()
  }

  if (isArnPrincipal(simulationRequest.principal)) {
    result['aws:PrincipalArn'] = simulationRequest.principal
    const arnParts = splitArnParts(simulationRequest.principal)
    const principalAccountId = arnParts.accountId!
    result['aws:PrincipalAccount'] = arnParts.accountId || ''

    const orgId = await collectClient.getOrgIdForAccount(principalAccountId)
    if (orgId) {
      result['aws:PrincipalOrgId'] = orgId

      const orgStructure = await collectClient.getOrgUnitHierarchyForAccount(principalAccountId)
      result['aws:PrincipalOrgPaths'] = makeOrgPaths(orgId, orgStructure)
    }

    const tags = await collectClient.getTagsForResource(
      simulationRequest.principal,
      principalAccountId
    )

    for (const [key, value] of Object.entries(tags)) {
      result[`aws:PrincipalTag/${key}`] = value
    }

    result['aws:PrincipalIsAWSService'] = 'false'

    if (simulationRequest.principal.endsWith(':root')) {
      result['aws:PrincipalType'] = 'Account'
      result['aws:userid'] = principalAccountId
    } else if (arnParts.resourceType === 'user') {
      result['aws:PrincipalType'] = 'User'
      const userUniqueId = await collectClient.getUniqueIdForIamResource(
        simulationRequest.principal
      )
      result['aws:userid'] = userUniqueId || 'UNKNOWN'
      const userName = arnParts.resourcePath?.split('/').at(-1)!
      result['aws:username'] = userName
    } else if (arnParts.resourceType === 'federated-user') {
      result['aws:PrincipalType'] = 'FederatedUser'
      result['aws:userid'] = `${arnParts.accountId}:${arnParts.resourcePath}`
    } else if (arnParts.resourceType === 'assumed-role') {
      result['aws:PrincipalType'] = 'AssumedRole'

      //TODO: Set aws:userId for role principals
      const sessionName = arnParts.resourcePath?.split('/').at(-1)!
      const roleArn = convertAssumedRoleArnToRoleArn(simulationRequest.principal)
      const roleUniqueId = await collectClient.getUniqueIdForIamResource(roleArn)
      result['aws:userid'] = `${roleUniqueId || 'UNKNOWN'}:${sessionName}`
    }
  }

  //Resource context keys
  if (!isAwsResourceInfoExcludedAction(simulationRequest.action)) {
    result['aws:ResourceAccount'] = simulationRequest.resourceAccount!

    const resourceOrgId = await collectClient.getOrgIdForAccount(simulationRequest.resourceAccount!)
    if (resourceOrgId) {
      result['aws:ResourceOrgID'] = resourceOrgId

      const orgStructure = await collectClient.getOrgUnitHierarchyForAccount(
        simulationRequest.resourceAccount!
      )

      result['aws:ResourceOrgPaths'] = makeOrgPaths(resourceOrgId, orgStructure)
    }
  }

  if (simulationRequest.resourceArn) {
    const resourceTags = await collectClient.getTagsForResource(
      simulationRequest.resourceArn,
      simulationRequest.resourceAccount!
    )

    for (const [key, value] of Object.entries(resourceTags)) {
      result[`aws:ResourceTag/${key}`] = value
    }
  }

  //Service Principal context keys
  if (isServicePrincipal(simulationRequest.principal)) {
    result['aws:PrincipalIsAWSService'] = 'true'
    result['aws:PrincipalServiceName'] = simulationRequest.principal
    result['aws:SourceAccount'] = simulationRequest.resourceAccount!
    result['aws:SourceOwner'] = simulationRequest.resourceAccount!
    result['aws:SourceOrgID'] = result['aws:ResourceOrgID']
    result['aws:SourceOrgPaths'] = result['aws:ResourceOrgPaths']
  }

  //Apply any custom context key overrides
  for (const [key, value] of Object.entries(contextKeyOverrides)) {
    result[key] = value
  }

  //Add VPC context keys
  const vpcKeys = await getVpcKeys(result, service, collectClient)
  for (const [key, value] of Object.entries(vpcKeys)) {
    result[key] = value
  }

  return result
}

/**
 * Get the VPC keys that should be added to the context for a simulation.
 *
 * @param context the existing context
 * @param service the service the request is for
 * @param collectClient the IAM collect client
 * @returns a record of VPC context keys
 */
export async function getVpcKeys(
  context: ContextKeys,
  service: string,
  collectClient: IamCollectClient
): Promise<ContextKeys> {
  const vpcKeys: ContextKeys = {}

  let vpcEndpointId = contextValue(context, CONTEXT_KEYS.vpcEndpointId)
  const hasVpcEndpoint = !!vpcEndpointId
  let vpcId = contextValue(context, CONTEXT_KEYS.vpc)

  //If we know the VPC but not the endpoint, lookup the endpoint
  if (!vpcEndpointId && vpcId && typeof vpcId === 'string') {
    vpcEndpointId = await collectClient.getVpcEndpointIdForVpcService(vpcId, service)
  }

  if (vpcEndpointId && !vpcId) {
    if (typeof vpcEndpointId == 'string') {
      const vpcId = await collectClient.getVpcIdForVpcEndpointId(vpcEndpointId)
      if (vpcId) {
        vpcKeys[CONTEXT_KEYS.vpc] = vpcId
      }
    }
  }

  if (vpcEndpointId && !hasVpcEndpoint) {
    vpcKeys[CONTEXT_KEYS.vpcEndpointId] = vpcEndpointId
  }

  if (
    vpcEndpointId &&
    typeof vpcEndpointId === 'string' &&
    serviceSupportsExtraVpcEndpointData(service)
  ) {
    const vpcEndpointAccount = await collectClient.getAccountIdForVpcEndpointId(vpcEndpointId)
    const vpcEndpointOrgId = await collectClient.getOrgIdForVpcEndpointId(vpcEndpointId)
    const vpcEndpointOrgStructure =
      await collectClient.getOrgUnitHierarchyForVpcEndpointId(vpcEndpointId)

    if (vpcEndpointAccount && !contextHasKey(context, CONTEXT_KEYS.vpcEndpointAccount)) {
      vpcKeys[CONTEXT_KEYS.vpcEndpointAccount] = vpcEndpointAccount
    }
    if (vpcEndpointOrgId && !contextHasKey(context, CONTEXT_KEYS.vpcEndpointOrgId)) {
      vpcKeys[CONTEXT_KEYS.vpcEndpointOrgId] = vpcEndpointOrgId
    }
    if (
      vpcEndpointOrgId &&
      vpcEndpointOrgStructure &&
      !contextHasKey(context, CONTEXT_KEYS.vpcEndpointOrgPaths)
    ) {
      vpcKeys[CONTEXT_KEYS.vpcEndpointOrgPaths] = makeOrgPaths(
        vpcEndpointOrgId,
        vpcEndpointOrgStructure
      )
    }
  }

  return vpcKeys
}

const awsResourceInfoExcludedActions = new Set([
  'auditmanager:updateassessmentframeworkshare',
  'detective:acceptinvitation',
  'ds:acceptshareddirectory',
  'ec2:accepttransitgatewaypeeringattachment',
  'ec2:acceptvpcendpointconnections',
  'ec2:acceptvpcpeeringconnection',
  'ec2:copysnapshot',
  'ec2:createtransitgatewaypeeringattachment',
  'ec2:createvpcendpoint',
  'ec2:createvpcpeeringconnection',
  'ec2:deletetransitgatewaypeeringattachment',
  'ec2:deletevpcpeeringconnection',
  'ec2:rejecttransitgatewaypeeringattachment',
  'ec2:rejectvpcendpointconnections',
  'ec2:rejectvpcpeeringconnection',
  'guardduty:acceptadministratorinvitation',
  'macie2:acceptinvitation',
  'es:acceptinboundconnection',
  'route53:associatevpcwithhostedzone',
  'route53:createvpcassociationauthorization',
  'route53:deletevpcassociationauthorization',
  'route53:disassociatevpcfromhostedzone',
  'route53:listhostedzonesbyvpc',
  'securityhub:acceptadministratorinvitation'
])

function isAwsResourceInfoExcludedAction(action: string): boolean {
  const lowerCaseAction = action.toLowerCase()
  return lowerCaseAction.startsWith('ebs:') || awsResourceInfoExcludedActions.has(lowerCaseAction)
}

const servicesThatSupportExtraVpcEndpointData = new Set([
  'apprunner',
  'discovery',
  'athena',
  'servicediscovery',
  'applicationinsights',
  'cloudformation',
  'comprehendmedical',
  'compute-optimizer',
  'datasync',
  'ebs',
  'scheduler',
  'firehose',
  'medical-imaging',
  'healthlake',
  'omics',
  'iam',
  'iotfleetwise',
  'iotwireless',
  'kms',
  'lambda',
  'payment-cryptography',
  'polly',
  'acm-pca',
  'rbin',
  'rekognition',
  'servicequotas',
  's3',
  'storagegateway',
  'ssm-contacts',
  'textract',
  'transcribe',
  'transfer'
])

/**
 * Check if a service supports extra VPC endpoint data.
 *
 * @param service the service to check
 * @returns true if the service supports extra VPC endpoint data, false otherwise
 */
export function serviceSupportsExtraVpcEndpointData(service: string): boolean {
  return servicesThatSupportExtraVpcEndpointData.has(service.toLowerCase())
}

/**
 * Create a string array for an aws:xxOrgPaths context key value.
 *
 * @param orgId the organization ID
 * @param hierarchy the organizational hierarchy
 * @returns a string array representing the organizational paths
 */
function makeOrgPaths(orgId: string, hierarchy: string[]): string[] {
  return [`${orgId}/${hierarchy.join('/')}/`]
}
