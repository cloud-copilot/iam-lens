import { TopLevelConfig } from '@cloud-copilot/iam-collect'
import { existsSync } from 'fs'
import { join, resolve } from 'path'
import { IamCollectClient } from '../collect/client.js'
import { getCollectClient } from '../collect/collect.js'

/**
 * Get an IAMCollectClient for a test database
 *
 * @param dataSetId the ID of the test dataset to use
 * @returns IamCollectClient instance configured for the specified dataset
 */
export function getTestDatasetClient(dataSetId: string): IamCollectClient {
  const path = resolve(join('./src', 'test-datasets', `iam-data-${dataSetId}`))
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
          path: resolve(join('./src', 'test-datasets', `iam-data-${dataSetId}`))
        }
      }
    ],
    'aws'
  )
}

export function getTestDatasetConfigs(dataSetId: string): TopLevelConfig[] {
  return [
    {
      iamCollectVersion: '0.0.0',
      storage: {
        type: 'file',
        path: resolve(join('./src', 'test-datasets', `iam-data-${dataSetId}`))
      }
    }
  ]
}
