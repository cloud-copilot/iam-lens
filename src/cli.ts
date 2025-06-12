#!/usr/bin/env node

import { parseCliArguments } from '@cloud-copilot/cli'
import { canWhat } from './canWhat/canWhat.js'
import { getCollectClient, loadCollectConfigs } from './collect/collect.js'
import { ContextKeys } from './simulate/contextKeys.js'
import { resultMatchesExpectation, simulateRequest } from './simulate/simulate.js'
import { iamLensVersion } from './utils/packageVersion.js'
import { whoCan } from './whoCan/whoCan.js'

const main = async () => {
  const version = await iamLensVersion()
  const cli = parseCliArguments(
    'iam-lens',
    {
      simulate: {
        description: 'Simulate an IAM request',
        options: {
          principal: {
            type: 'string',
            values: 'single',
            description: 'The principal to simulate. Can be a user, role, session, or AWS service'
          },
          resource: {
            type: 'string',
            values: 'single',
            description:
              'The ARN of the resource to simulate access to. Ignore for wildcard actions'
          },
          resourceAccount: {
            type: 'string',
            values: 'single',
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN.'
          },
          action: {
            type: 'string',
            values: 'single',
            description:
              'The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`'
          },
          context: {
            type: 'string',
            values: 'multiple',
            description:
              'The context keys to use for the simulation. Keys are formatted as key=value. Multiple values can be separated by commas (key=value1,value2,value3)'
          },
          verbose: {
            type: 'boolean',
            description: 'Enable verbose output for the simulation',
            character: 'v'
          },
          expect: {
            type: 'enum',
            values: 'single',
            validValues: ['Allowed', 'ImplicitlyDenied', 'ExplicitlyDenied', 'AnyDeny'],
            description:
              'The expected result of the simulation, if the result does not match the expected response a non-zero exit code will be returned'
          }
        }
      },
      'who-can': {
        description: 'Find who can perform an action on a resource',
        options: {
          resource: {
            type: 'string',
            values: 'single',
            description:
              'The ARN of the resource to check permissions for. Ignore for wildcard actions'
          },
          resourceAccount: {
            type: 'string',
            values: 'single',
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN. Required for wildcard actions'
          },
          actions: {
            type: 'string',
            values: 'multiple',
            description:
              'The action to check permissions for; must be a valid IAM service and action such as `s3:GetObject`'
          }
        }
      },
      'can-what': {
        description: 'ALPHA: Find what actions a principal can perform',
        options: {
          principal: {
            type: 'string',
            values: 'single',
            description: 'The principal to check permissions for. Can be a user or role'
          },
          shrinkActionLists: {
            type: 'boolean',
            character: 's',
            description: 'Shrink action lists to reduce policy size'
          }
        }
      }
    },
    {
      collectConfigs: {
        type: 'string',
        description: 'The iam-collect configuration files to use',
        values: 'multiple'
      },
      partition: {
        type: 'string',
        description: 'The AWS partition to use (aws, aws-cn, aws-us-gov). Defaults to aws.',
        values: 'single'
      }
    },
    {
      envPrefix: 'IAM_LENS',
      showHelpIfNoArgs: true,
      requireSubcommand: true,
      version
    }
  )

  if (cli.args.collectConfigs.length === 0) {
    cli.args.collectConfigs.push('./iam-collect.jsonc')
  }
  const thePartition = cli.args.partition || 'aws'
  const collectConfigs = await loadCollectConfigs(cli.args.collectConfigs)
  const collectClient = getCollectClient(collectConfigs, thePartition)

  if (cli.subcommand === 'simulate') {
    const { principal, resource, resourceAccount, action, context } = cli.args
    const contextKeys = convertContextKeysToMap(context)

    const result = await simulateRequest(
      {
        principal: principal!,
        resourceArn: resource,
        resourceAccount: resourceAccount,
        action: action!,
        customContextKeys: contextKeys
      },
      collectClient
    )

    if (result.errors) {
      console.error('Simulation Errors:')
      console.log(JSON.stringify(result.errors, null, 2))
      process.exit(1)
    }

    console.log(`Simulation Result: ${result.analysis?.result}`)
    if (cli.args.verbose) {
      console.log(JSON.stringify(result, null, 2))
    }

    if (!resultMatchesExpectation(cli.args.expect, result.analysis?.result!)) {
      process.exit(1)
    }
  } else if (cli.subcommand === 'who-can') {
    const { resource, resourceAccount, actions } = cli.args
    if (!resourceAccount && !resource && actions.length === 0) {
      console.error(
        'Error: At least 1) resource or 2) resource-account and actions must be provided for who-can command'
      )
      process.exit(1)
    }

    const results = await whoCan(collectClient, {
      resource: cli.args.resource!,
      actions: cli.args.actions!,
      resourceAccount: cli.args.resourceAccount
    })

    console.log(JSON.stringify(results, null, 2))
  } else if (cli.subcommand === 'can-what') {
    const { principal, shrinkActionLists } = cli.args
    if (!principal) {
      console.error('Error: Principal must be provided for can-what command')
      process.exit(1)
    }

    const results = await canWhat(collectClient, {
      principal: principal!,
      shrinkActionLists
    })

    console.log(JSON.stringify(results, null, 2))
  }
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .then(() => {})
  .finally(() => {})

/**
 * Convert the context keys from the CLI arguments into a map.
 *
 * @param contextKeys the context keys from the CLI arguments, formatted as key=value1,value2,...
 * @returns a map of context keys where each key is associated with a single value or an array of values
 */
function convertContextKeysToMap(contextKeys: string[]): ContextKeys {
  const contextMap: Record<string, string | string[]> = {}
  for (const key of contextKeys) {
    const [keyName, value] = key.split('=')
    if (value) {
      const values = value.split(',')
      if (values.length > 1) {
        contextMap[keyName] = values
      } else {
        contextMap[keyName] = values[0]
      }
    }
  }
  return contextMap
}
