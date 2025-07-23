export interface ArrayStreamingWorkQueueOptions {
  ringCapacity?: number
}

export class ArrayStreamingWorkQueue<T> {
  private onWorkAvailable?: () => void
  private notifyScheduled = false
  private work = [] as T[]

  constructor(options: ArrayStreamingWorkQueueOptions = {}) {}

  public setWorkAvailableCallback(callback: () => void): void {
    this.onWorkAvailable = callback
  }

  public enqueue(item: T): void {
    this.work.push(item)
    this.scheduleNotify()
  }

  public dequeue(): T | undefined {
    return this.work.shift()
  }

  public length(): number {
    return this.work.length
  }

  private scheduleNotify(): void {
    if (this.notifyScheduled || !this.onWorkAvailable) {
      return
    }

    this.notifyScheduled = true

    // Use a microtask to debounce notifications
    queueMicrotask(() => {
      this.notifyScheduled = false
      this.onWorkAvailable?.()
    })
  }
}
