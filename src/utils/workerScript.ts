import { join, resolve } from 'path'

let root = resolve(__dirname, '../')
if (process.env.NODE_ENV === 'test') {
  root = resolve(root, '..', 'dist', 'esm')
}

/**
 * Get the path to a worker script, adjusted for the build output location.
 *
 * @param path the relative path to the worker script from the project src directory and with a .js extension
 * @returns the absolute path to the worker script
 */
export function getWorkerScriptPath(path: string): string {
  return join(root, path)
}
