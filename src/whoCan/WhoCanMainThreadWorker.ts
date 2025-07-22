import { JobResult } from '@cloud-copilot/job'
import { IamCollectClient } from '../collect/client.js'
import { ArrayStreamingWorkQueue } from '../workers/ArrayStreamingWorkQueue.js'
import { PullBasedJobRunner } from '../workers/JobRunner.js'
import { StreamingWorkQueue } from '../workers/StreamingWorkQueue.js'
import { WhoCanAllowed } from './whoCan.js'
import { createJobForWhoCanWorkItem, WhoCanWorkItem } from './WhoCanWorker.js'

export function createMainThreadStreamingWorkQueue(
  queue: StreamingWorkQueue<WhoCanWorkItem> | ArrayStreamingWorkQueue<WhoCanWorkItem>,
  collectClient: IamCollectClient,
  onComplete: (result: JobResult<WhoCanAllowed | undefined, Record<string, unknown>>) => void
) {
  return new PullBasedJobRunner<WhoCanAllowed | undefined, Record<string, unknown>, WhoCanWorkItem>(
    50,
    async () => {
      return queue.dequeue()
    },
    (workItem) => {
      return createJobForWhoCanWorkItem(workItem, collectClient)
    },
    async (result) => {
      // no-op for now, results are handled by the caller of execute
      return onComplete(result)
    }
  )
}

export class WhoCanMainThreadWorker {
  constructor(private collectClient: IamCollectClient) {}

  public async execute(workItem: WhoCanWorkItem): Promise<WhoCanAllowed | undefined> {
    const { principal, resource, resourceAccount, action } = workItem
    if (!principal || !resource || !resourceAccount || !action) {
      throw new Error(`Invalid work item: ${JSON.stringify(workItem)}`)
    } else {
      const { executeWhoCan } = await import('./WhoCanWorker.js')
      return executeWhoCan(workItem, this.collectClient)
    }
  }
}
