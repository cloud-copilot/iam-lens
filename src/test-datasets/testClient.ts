import { type TopLevelConfig } from '@cloud-copilot/iam-collect'
import { existsSync } from 'fs'
import { dirname, join, resolve } from 'path'
import { fileURLToPath } from 'url'
import { IamCollectClient } from '../collect/client.js'
import { getCollectClient } from '../collect/collect.js'

// @ts-ignore
const __dirname = dirname(fileURLToPath(import.meta.url))

/**
 * Resolves the absolute path for a test dataset directory.
 *
 * @param dataSetId - The numeric ID suffix of the dataset (e.g. "1" for iam-data-1)
 * @returns Absolute path to the dataset directory
 */
function datasetPath(dataSetId: string): string {
  return resolve(join(__dirname, `iam-data-${dataSetId}`))
}

/**
 * Get an IAMCollectClient for a test database
 *
 * @param dataSetId the ID of the test dataset to use
 * @returns IamCollectClient instance configured for the specified dataset
 */
export async function getTestDatasetClient(dataSetId: string): Promise<IamCollectClient> {
  const path = datasetPath(dataSetId)
  if (!existsSync(path)) {
    throw new Error(
      `Test dataset with ID ${dataSetId} does not exist at path ${path}. Someone messed up.`
    )
  }

  return getCollectClient(
    [
      {
        iamCollectVersion: '0.0.0',
        storage: {
          type: 'file',
          path
        }
      }
    ],
    'aws'
  )
}

/**
 * Get TopLevelConfig array for a test dataset.
 *
 * @param dataSetId - The numeric ID suffix of the dataset
 * @returns Configuration array pointing to the dataset's file storage
 */
export function getTestDatasetConfigs(dataSetId: string): TopLevelConfig[] {
  return [
    {
      iamCollectVersion: '0.0.0',
      storage: {
        type: 'file',
        path: datasetPath(dataSetId)
      }
    }
  ]
}
