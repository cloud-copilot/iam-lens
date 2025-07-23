export function convertArrayBufferToString(buffer: SharedArrayBuffer): string {
  const view = new Uint8Array(buffer)
  return new TextDecoder().decode(view)
}

export function convertArrayBufferToObject<T>(buffer: SharedArrayBuffer): T {
  if (!buffer || buffer.byteLength === 0) {
    return undefined as unknown as T
  }
  const jsonString = convertArrayBufferToString(buffer)
  return JSON.parse(jsonString) as T
}

export function convertObjectToArrayBuffer<T>(obj: T): SharedArrayBuffer {
  const jsonString = JSON.stringify(obj)
  const encoder = new TextEncoder()
  const byteArray = encoder.encode(jsonString)
  const buffer = new SharedArrayBuffer(byteArray.length)
  const view = new Uint8Array(buffer)
  view.set(byteArray)
  return buffer
}
