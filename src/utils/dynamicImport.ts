import { createRequire } from 'module'

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
export function normalizeModule(mod: Record<string, unknown>): Record<string, unknown> {
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
export async function dynamicImport(modulePath: string): Promise<Record<string, unknown>> {
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
