import { type JobResult } from '@cloud-copilot/job'
import { IamCollectClient } from '../collect/client.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { ArrayStreamingWorkQueue } from '../workers/ArrayStreamingWorkQueue.js'
import { PullBasedJobRunner } from '../workers/JobRunner.js'
import { StreamingWorkQueue } from '../workers/StreamingWorkQueue.js'
import {
  convertToDenialDetails,
  type LightRequestAnalysis,
  toLightRequestAnalysis
} from './requestAnalysis.js'
import { type WhoCanAllowed, type WhoCanDenyDetail } from './whoCan.js'
import {
  createJobForWhoCanWorkItem,
  type WhoCanExecutionResult,
  type WhoCanWorkItem
} from './WhoCanWorker.js'

export function createMainThreadStreamingWorkQueue(
  queue: StreamingWorkQueue<WhoCanWorkItem> | ArrayStreamingWorkQueue<WhoCanWorkItem>,
  collectClient: IamCollectClient,
  s3AbacOverride: S3AbacOverride | undefined,
  onComplete: (result: JobResult<WhoCanAllowed | undefined, Record<string, unknown>>) => void,
  denyDetailsCallback?: (details: LightRequestAnalysis) => boolean,
  onDenyDetail?: (detail: WhoCanDenyDetail) => void,
  collectGrantDetails?: boolean
) {
  const collectDenyDetails = !!denyDetailsCallback

  return new PullBasedJobRunner<WhoCanExecutionResult, Record<string, unknown>, WhoCanWorkItem>(
    50,
    async () => {
      return queue.dequeue()
    },
    (workItem) => {
      return createJobForWhoCanWorkItem(workItem, collectClient, {
        s3AbacOverride,
        collectDenyDetails,
        collectGrantDetails
      })
    },
    async (result) => {
      if (result.status === 'fulfilled') {
        const executionResult = result.value
        if (executionResult.type === 'allowed') {
          // Simulation was allowed - pass through to onComplete
          onComplete({
            status: 'fulfilled',
            value: executionResult.allowed,
            properties: result.properties
          })
        } else {
          // Simulation was denied
          onComplete({
            status: 'fulfilled',
            value: undefined,
            properties: result.properties
          })

          // Check if we should include deny details
          if (denyDetailsCallback && onDenyDetail) {
            const hasDetails =
              executionResult.type === 'denied_single' || executionResult.type === 'denied_wildcard'

            if (hasDetails) {
              const lightAnalysis = toLightRequestAnalysis(executionResult)
              const shouldInclude = denyDetailsCallback(lightAnalysis)

              if (shouldInclude) {
                onDenyDetail(convertToDenialDetails(executionResult))
              }
            }
          }
        }
      } else {
        // Error case - pass through as rejected
        onComplete({
          status: 'rejected',
          reason: result.reason,
          properties: result.properties
        })
      }
    }
  )
}
