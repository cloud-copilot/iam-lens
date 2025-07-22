import { TopLevelConfig, createStorageClient, loadConfigFiles } from '@cloud-copilot/iam-collect'
import { IamCollectClient, IamCollectClientOptions } from './client.js'

/**
 * Load IAM collect configs from the specified paths.
 *
 * @param configPaths the paths to the config files
 * @returns the top-level configs
 */
export async function loadCollectConfigs(configPaths: string[]): Promise<TopLevelConfig[]> {
  return loadConfigFiles(configPaths)
}

/**
 * Get a collect client for the specified partition using the provided configs.
 *
 * @param configs the top-level configs to use for storage
 * @param partition which partition to use (aws, aws-cn, aws-us-gov)
 * @returns the iam-collect client to use for retrieving IAM resources
 */
export function getCollectClient(
  configs: TopLevelConfig[],
  partition: string,
  clientOptions?: IamCollectClientOptions
): IamCollectClient {
  return new IamCollectClient(createStorageClient(configs, partition), clientOptions)
}
