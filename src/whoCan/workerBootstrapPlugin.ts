/**
 * Configuration for a consumer-provided module that runs once per worker thread
 * at startup, before any work is processed. Intended for loading instrumentation
 * (e.g. dd-trace), initializing logging context, or similar worker-lifetime setup.
 *
 * The referenced export must be a function matching
 * `(context: { data: unknown; threadId: number; isMainThread: false }) => void | Promise<void>`.
 */
export interface WorkerBootstrapPlugin {
  /** Package name (e.g. '@my-app/worker-bootstrap') or absolute path — resolved via dynamic import. */
  module: string
  /** Name of the exported bootstrap function. */
  factoryExport: string
  /** JSON-serializable data passed to the bootstrap function. */
  data: unknown
}
