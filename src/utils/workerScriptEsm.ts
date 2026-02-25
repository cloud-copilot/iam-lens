import { join, resolve } from 'path'

//@ts-ignore
let root = resolve(import.meta.url.replace('file://', ''), '../../')
if (process.env.IAM_LENS_WORKER_ROOT) {
  root = process.env.IAM_LENS_WORKER_ROOT
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
