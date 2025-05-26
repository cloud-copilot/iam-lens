#!/usr/bin/env node

import { parseCliArguments } from '@cloud-copilot/cli'
import { getCollectClient, loadCollectConfigs } from './collect/collect.js'
import { ContextKeys } from './contextKeys.js'
import { simulateRequest } from './simulate.js'

const main = async () => {
  // const version = await iamLensVersion()
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
          resourceAccountId: {
            type: 'string',
            values: 'single',
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN. Ignore for wildcard actions'
          },
          action: {
            type: 'string',
            values: 'single',
            description:
              'The action to simulate; must be a valid IAM service and action such as `s3:GetObject`'
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
      requireSubcommand: true
      // version: version
    }
  )

  if (cli.args.collectConfigs.length === 0) {
    cli.args.collectConfigs.push('./iam-collect.jsonc')
  }
  const thePartition = cli.args.partition || 'aws'

  if (cli.subcommand === 'simulate') {
    const collectConfigs = await loadCollectConfigs(cli.args.collectConfigs)
    const collectClient = getCollectClient(collectConfigs, thePartition)

    const { principal, resource, resourceAccountId, action, context } = cli.args
    const contextKeys = convertContextKeysToMap(context)

    const result = await simulateRequest(
      {
        principal: principal!,
        resourceArn: resource!,
        resourceAccount: resourceAccountId,
        action: action!,
        customContextKeys: contextKeys
      },
      collectClient
    )

    console.log(`Simulation Result: ${result.analysis?.result}`)
    if (cli.args.verbose) {
      console.log(JSON.stringify(result, null, 2))
    }
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
