import { readRelativeFile } from '@cloud-copilot/cli'

let levels = 3
if (__filename.includes('src')) {
  levels = 2
}

export async function readPackageFile(pathParts: string[]): Promise<string> {
  const packageFile = await readRelativeFile(__filename, levels, pathParts)
  return packageFile
}
