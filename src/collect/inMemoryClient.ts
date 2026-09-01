import { createInMemoryStorageClient } from '@actsecurity/iam-collect'
import { IamCollectClient } from './client.js'

export function testStore() {
  const store = createInMemoryStorageClient()
  const client = new IamCollectClient(store)
  return { store, client }
}
