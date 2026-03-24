import {
  type TopLevelConfig,
  createStorageClient,
  loadConfigFiles
} from '@cloud-copilot/iam-collect'
import { createRequire } from 'module'
import { IamCollectClient, type IamCollectClientOptions } from './client.js'

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
  /** Package name (e.g. '@cloud-copilot/iam-scenario') or absolute path — resolved via require() */
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
 * Normalize a module namespace object so that named exports are accessible as
 * top-level properties regardless of whether the underlying module is ESM or
 * CJS. When `import()` loads a CJS module the entire `module.exports` object
 * is placed on the `default` property of the namespace, so this helper merges
 * `default` back into the top level.
 *
 * @param mod - The raw module namespace returned by `import()` or `require()`.
 * @returns A flat record with all named exports accessible as top-level keys.
 */
function normalizeModule(mod: Record<string, unknown>): Record<string, unknown> {
  if (mod.default && typeof mod.default === 'object' && !Array.isArray(mod.default)) {
    return { ...mod, ...(mod.default as Record<string, unknown>) }
  }
  return mod
}

/**
 * Dynamically load a module by name or path, handling both ESM and CJS
 * runtime contexts and both ESM and CJS target modules.
 *
 * Resolution strategy:
 * 1. Try a bare `import()` first — this works when the module is resolvable
 *    from the current file (e.g. it is a direct dependency) or when a bundler /
 *    test runner (vitest, etc.) intercepts module resolution.
 * 2. If that fails with a "not found" error, fall back to `createRequire`
 *    rooted at `process.cwd()`. This handles the case where the plugin package
 *    lives in the consuming project's `node_modules` rather than iam-lens's
 *    own. `createRequire` works in both ESM and CJS contexts and always uses
 *    the CJS resolution algorithm, which reliably finds packages regardless of
 *    the caller's module type.
 *
 * @param modulePath - Package name or absolute path to import.
 * @returns The exports object of the imported module with normalised keys.
 */
async function dynamicImport(modulePath: string): Promise<Record<string, unknown>> {
  try {
    const mod = (await import(modulePath)) as Record<string, unknown>
    return normalizeModule(mod)
  } catch (err: unknown) {
    const code = (err as { code?: string }).code
    if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') {
      throw err
    }
  }
  // Bare import failed — use createRequire to load from cwd's node_modules.
  // createRequire works in both ESM and CJS contexts and handles both CJS and
  // ESM target modules (for ESM targets it will load the CJS entry when one
  // exists, which is acceptable for plugin loading).
  const _require = createRequire(process.cwd() + '/')
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = _require(modulePath) as Record<string, unknown>
  // Some environments (e.g. vitest SSR) wrap require() results in a Proxy with
  // lazy getters where property access returns undefined despite keys being
  // visible. Spreading into a plain object materialises all values.
  const plain = { ...mod }
  return normalizeModule(plain)
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
