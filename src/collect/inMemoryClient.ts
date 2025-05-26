import { createInMemoryStorageClient } from '@cloud-copilot/iam-collect'
import { IamCollectClient } from './client.js'

export function testStore() {
  const store = createInMemoryStorageClient()
  const client = new IamCollectClient(store)
  return { store, client }
}
