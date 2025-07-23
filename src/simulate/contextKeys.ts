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

/**
 * Get the context keys for a simulation request.
 *
 * @param collectClient the collect client to use for fetching data
 * @param simulationRequest the simulation request to create context keys for
 * @param contextKeyOverrides the context key overrides to apply
 * @returns a promise that resolves to the context keys for the simulation request
 */
export async function createContextKeys(
  collectClient: IamCollectClient,
  simulationRequest: SimulationRequest,
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
      result['aws:PrincipalOrgPaths'] = [`${orgId}/${orgStructure.join('/')}/`]
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

      result['aws:ResourceOrgPaths'] = [`${resourceOrgId}/${orgStructure.join('/')}/`]
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

  return result
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
