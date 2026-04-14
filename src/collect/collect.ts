import {
  type TopLevelConfig,
  createStorageClient,
  loadConfigFiles
} from '@cloud-copilot/iam-collect'
import { createRequire } from 'module'
import { IamCollectClient, type IamCollectClientOptions } from './client.js'
import { dynamicImport } from '../utils/dynamicImport.js'

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
 * Configuration for a plugin that wraps the default `IamCollectClient` with a
 * custom implementation.
 *
 * The factory function referenced by `factoryExport` is called with
 * `(store: AwsIamStore, options: IamCollectClientOptions | undefined, data: unknown)`
 * and must return an `IamCollectClient` (or subclass).
 */
export interface ClientFactoryPlugin {
  /** Package name (e.g. '@my-org/my-factory') or absolute path — resolved via require() */
  module: string
  /** Name of the exported factory function */
  factoryExport: string
  /** JSON-serializable data passed as the third argument to the factory */
  data: unknown
}

export interface CollectClientOptions extends IamCollectClientOptions {
  clientFactoryPlugin?: ClientFactoryPlugin
}

/**
 * Get a collect client for the specified partition using the provided configs.
 *
 * If a `clientFactoryPlugin` is provided, the factory function is called with
 * `(store, clientOptions, data)` — i.e. the raw `AwsIamStore` and
 * `IamCollectClientOptions` rather than a pre-built client — so the factory
 * can construct whatever client subclass it needs without discarding an
 * intermediate instance.
 *
 * @param configs - The top-level configs to use for storage.
 * @param partition - Which partition to use (aws, aws-cn, aws-us-gov).
 * @param options - Optional client options including a `clientFactoryPlugin`.
 * @returns The iam-collect client to use for retrieving IAM resources.
 */
export async function getCollectClient(
  configs: TopLevelConfig[],
  partition: string,
  options?: CollectClientOptions
): Promise<IamCollectClient> {
  const { clientFactoryPlugin, ...clientOptions } = options ?? {}
  const store = createStorageClient(configs, partition, true)
  if (!clientFactoryPlugin) return new IamCollectClient(store, clientOptions)
  const mod = await dynamicImport(clientFactoryPlugin.module)
  let factory = mod[clientFactoryPlugin.factoryExport]
  // Some environments (e.g. vitest SSR) wrap import() results in a Proxy where
  // Object.keys() returns the correct keys but property access returns undefined.
  // When this happens, fall back to createRequire which bypasses the proxy.
  if (!factory && Object.keys(mod).includes(clientFactoryPlugin.factoryExport)) {
    const _require = createRequire(process.cwd() + '/')
    const fallback = _require(clientFactoryPlugin.module) as Record<string, unknown>
    factory = fallback[clientFactoryPlugin.factoryExport]
  }
  if (!factory) {
    throw new Error(
      `Factory export '${clientFactoryPlugin.factoryExport}' not found in module '${clientFactoryPlugin.module}'`
    )
  } else if (typeof factory !== 'function') {
    throw new Error(
      `Factory export '${clientFactoryPlugin.factoryExport}' in module '${clientFactoryPlugin.module}' is not a function`
    )
  }
  return factory(store, clientOptions, clientFactoryPlugin.data) as IamCollectClient
}
