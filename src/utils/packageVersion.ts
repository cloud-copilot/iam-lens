import { getPackageFileReader } from './readPackageFile.js'

interface PackageInfo {
  version: string
}

let packageCache: PackageInfo | undefined = undefined

/**
 * Get the package data version
 *
 * @returns the package data version
 */
async function getPackageData(): Promise<PackageInfo> {
  if (!packageCache) {
    const packageJson = await getPackageFileReader().readFile(['package.json'])
    packageCache = JSON.parse(packageJson)
  }
  return packageCache!
}

/**
 * Get the version of the package
 */
export async function iamLensVersion(): Promise<string> {
  const data = await getPackageData()
  return data.version
}
