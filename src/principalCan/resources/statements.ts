import { loadPolicy, Policy, Statement } from '@cloud-copilot/iam-policy'
import { runSimulation, Simulation } from '@cloud-copilot/iam-simulate'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { IamCollectClient } from '../../collect/client.js'
import { createContextKeys } from '../../simulate/contextKeys.js'
import { SimulationRequest } from '../../simulate/simulate.js'

export type StatementPrincipalMatchType = 'PrincipalMatch' | 'AccountMatch' | 'NoMatch'

/**
 * Checks to see if a statement applies to a principal by running a simulation.
 *
 * If the principal is a match return 'PrincipalMatch'
 * If the account is a match return 'AccountMatch'
 * Otherwise return 'NoMatch'
 *
 * @param statement the statement to check
 * @param principalArn the arn of the principal to check
 * @param client the IAM collect client to use for retrieving principal information
 * @returns Whether the statement applies to the principal
 */
export async function statementAppliesToPrincipal(
  statement: Statement,
  principalArn: string,
  client: IamCollectClient
): Promise<StatementPrincipalMatchType> {
  const principalAccount = splitArnParts(principalArn).accountId!
  const resourcePolicy = makePrincipalOnlyPolicyFromStatement(statement)
  const simulationRequest: SimulationRequest = {
    principal: principalArn,
    action: 's3:ListBucket',
    resourceAccount: principalAccount,
    resourceArn: undefined,
    customContextKeys: {},
    simulationMode: 'Strict'
  }

  const contextKeys = await createContextKeys(client, simulationRequest, 's3', {})

  const request: Simulation['request'] = {
    action: 's3:ListBucket',
    resource: {
      resource: 'arn:aws:s3:::example-bucket',
      accountId: principalAccount
    },
    principal: principalArn,
    contextVariables: contextKeys
  }

  const simulation: Simulation = {
    request,
    identityPolicies: [],
    resourcePolicy: resourcePolicy.toJSON(),
    serviceControlPolicies: [],
    resourceControlPolicies: []
  }

  const result = await runSimulation(simulation, {
    simulationMode: simulationRequest.simulationMode
  })

  if (result.analysis?.result === 'Allowed') {
    return 'PrincipalMatch'
  }
  if (result.analysis?.resourceAnalysis?.result === 'AllowedForAccount') {
    return 'AccountMatch'
  }
  return 'NoMatch'
}

const principalKeys = new Set(
  [
    'aws:PrincipalArn',
    'aws:PrincipalAccount',
    'aws:PrincipalOrgId',
    'aws:PrincipalOrgPaths',
    'aws:PrincipalType',
    'aws:userid',
    'aws:username',
    'aws:PrincipalIsAWSService'
  ].map((k) => k.toLowerCase())
)

/**
 * Makes a policy that captures the principal and principal conditions from a statement
 * and allows all actions on all resources.
 *
 * The conditions returned are only those that relate to the principal.
 *
 * @param statement the statement to extract the principal from
 * @returns
 */
export function makePrincipalOnlyPolicyFromStatement(statement: Statement): Policy {
  const rawStatement = structuredClone(statement.toJSON())
  const rawStatementValues: any = {}
  if (statement.isPrincipalStatement()) {
    rawStatementValues.Principal = rawStatement.Principal
  } else if (statement.isNotPrincipalStatement()) {
    rawStatementValues.NotPrincipal = rawStatement.NotPrincipal
  }
  if (rawStatement.Condition) {
    for (const operator of Object.keys(rawStatement.Condition)) {
      for (const key of Object.keys(rawStatement.Condition[operator])) {
        if (!principalKeys.has(key.toLowerCase())) {
          delete rawStatement.Condition[operator][key]
        }
      }
      if (Object.keys(rawStatement.Condition[operator]).length === 0) {
        delete rawStatement.Condition[operator]
      }
    }
    if (Object.keys(rawStatement.Condition).length > 0) {
      rawStatementValues.Condition = rawStatement.Condition
    }
  }

  return loadPolicy({
    Version: '2012-10-17',
    Statement: {
      Effect: 'Allow',
      Resource: '*',
      Action: '*',
      ...rawStatementValues
    }
  })
}
