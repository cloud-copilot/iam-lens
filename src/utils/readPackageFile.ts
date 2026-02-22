import { createPackageFileReader, type PackageFileReader } from '@cloud-copilot/cli'

let levels = 3
if (__filename.includes('src')) {
  levels = 2
}

let fileReader: PackageFileReader | undefined = undefined

export function getPackageFileReader(): PackageFileReader {
  if (!fileReader) {
    fileReader = createPackageFileReader(__filename, levels)
  }
  return fileReader
}
