#!/usr/bin/env node

import {
  booleanArgument,
  enumArgument,
  mapArgument,
  parseCliArguments,
  stringArgument,
  stringArrayArgument
} from '@cloud-copilot/cli'
import { canWhat } from './canWhat/canWhat.js'
import { getCollectClient, loadCollectConfigs } from './collect/collect.js'
import { resultMatchesExpectation, simulateRequest } from './simulate/simulate.js'
import { iamLensVersion } from './utils/packageVersion.js'
import { whoCan } from './whoCan/whoCan.js'

const main = async () => {
  const cli = await parseCliArguments(
    'iam-lens',
    {
      simulate: {
        description: 'Simulate an IAM request',
        arguments: {
          principal: stringArgument({
            description: 'The principal to simulate. Can be a user, role, session, or AWS service'
          }),
          resource: stringArgument({
            description:
              'The ARN of the resource to simulate access to. Ignore for wildcard actions'
          }),
          resourceAccount: stringArgument({
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN.'
          }),
          action: stringArgument({
            description:
              'The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`'
          }),
          context: mapArgument({
            description:
              'The context keys to use for the simulation. Keys are formatted as key=value. Multiple values can be separated by commas (key=value1,value2,value3)',
            defaultValue: {}
          }),
          verbose: booleanArgument({
            description: 'Enable verbose output for the simulation',
            character: 'v'
          }),
          expect: enumArgument({
            description:
              'The expected result of the simulation, if the result does not match the expected response a non-zero exit code will be returned',
            validValues: ['Allowed', 'ImplicitlyDenied', 'ExplicitlyDenied', 'AnyDeny']
          }),
          ignoreMissingPrincipal: booleanArgument({
            description:
              'Ignore if the principal does not exist. Useful for simulating actions from principals that may not exist or are outside your data set',
            character: 'i'
          })
        }
      },
      'who-can': {
        description: 'Find who can perform an action on a resource',
        arguments: {
          resource: stringArgument({
            description:
              'The ARN of the resource to check permissions for. Ignore for wildcard actions'
          }),
          resourceAccount: stringArgument({
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN. Required for wildcard actions'
          }),
          actions: stringArrayArgument({
            description:
              'The actions to check permissions for; must be a valid IAM service and action such as `s3:GetObject`',
            defaultValue: []
          })
        }
      },
      'principal-can': {
        description: 'ALPHA: Create a consolidated view of all permissions for a principal',
        arguments: {
          principal: stringArgument({
            description: 'The principal to check permissions for. Can be a user or role'
          }),
          shrinkActionLists: booleanArgument({
            description: 'Shrink action lists to reduce policy size',
            character: 's'
          })
        }
      }
    },
    {
      collectConfigs: stringArrayArgument({
        description: 'The iam-collect configuration files to use',
        defaultValue: []
      }),
      partition: stringArgument({
        description: 'The AWS partition to use (aws, aws-cn, aws-us-gov).',
        defaultValue: 'aws'
      })
    },
    {
      envPrefix: 'IAM_LENS',
      showHelpIfNoArgs: true,
      requireSubcommand: true,
      expectOperands: false,
      version: {
        currentVersion: iamLensVersion,
        checkForUpdates: '@cloud-copilot/iam-lens'
      }
    }
  )

  if (cli.args.collectConfigs.length === 0) {
    cli.args.collectConfigs.push('./iam-collect.jsonc')
  }
  const collectConfigs = await loadCollectConfigs(cli.args.collectConfigs)
  const collectClient = getCollectClient(collectConfigs, cli.args.partition)

  if (cli.subcommand === 'simulate') {
    const { principal, resource, resourceAccount, action, context, ignoreMissingPrincipal } =
      cli.args

    const { request, result } = await simulateRequest(
      {
        principal: principal!,
        resourceArn: resource,
        resourceAccount: resourceAccount,
        action: action!,
        customContextKeys: context,
        simulationMode: 'Strict',
        ignoreMissingPrincipal
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
      console.log(JSON.stringify({ request, result }, null, 2))
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

    const results = await whoCan(collectConfigs, cli.args.partition, {
      resource: cli.args.resource!,
      actions: cli.args.actions!,
      resourceAccount: cli.args.resourceAccount
    })

    console.log(JSON.stringify(results, null, 2))
  } else if (cli.subcommand === 'principal-can') {
    const { principal, shrinkActionLists } = cli.args
    if (!principal) {
      console.error('Error: Principal must be provided for principal-can command')
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
