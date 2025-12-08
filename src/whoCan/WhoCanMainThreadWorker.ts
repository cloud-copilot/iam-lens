import { JobResult } from '@cloud-copilot/job'
import { IamCollectClient } from '../collect/client.js'
import { S3AbacOverride } from '../utils/s3Abac.js'
import { ArrayStreamingWorkQueue } from '../workers/ArrayStreamingWorkQueue.js'
import { PullBasedJobRunner } from '../workers/JobRunner.js'
import { StreamingWorkQueue } from '../workers/StreamingWorkQueue.js'
import { WhoCanAllowed } from './whoCan.js'
import { createJobForWhoCanWorkItem, WhoCanWorkItem } from './WhoCanWorker.js'

export function createMainThreadStreamingWorkQueue(
  queue: StreamingWorkQueue<WhoCanWorkItem> | ArrayStreamingWorkQueue<WhoCanWorkItem>,
  collectClient: IamCollectClient,
  s3AbacOverride: S3AbacOverride | undefined,
  onComplete: (result: JobResult<WhoCanAllowed | undefined, Record<string, unknown>>) => void
) {
  return new PullBasedJobRunner<WhoCanAllowed | undefined, Record<string, unknown>, WhoCanWorkItem>(
    50,
    async () => {
      return queue.dequeue()
    },
    (workItem) => {
      return createJobForWhoCanWorkItem(workItem, collectClient, {
        s3AbacOverride
      })
    },
    async (result) => {
      // no-op for now, results are handled by the caller of execute
      return onComplete(result)
    }
  )
}
