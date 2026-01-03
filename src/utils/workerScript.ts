import { existsSync } from 'fs'
import { join, resolve } from 'path'

let root = resolve(__dirname, '../')
if (process.env.NODE_ENV === 'test') {
  root = resolve(root, '..', 'dist', 'esm')
}

/**
 * Get the path to a worker script, adjusted for the build output location.
 *
 * @param path the relative path to the worker script from the project src directory and with a .js extension
 * @returns the absolute path to the worker script, or undefined if the worker script path does not exist
 */
export function getWorkerScriptPath(path: string): string | undefined {
  const fullPath = join(root, path)
  if (!existsSync(fullPath)) {
    return undefined
  }
  return fullPath
}
