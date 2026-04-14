// Test bootstrap module that always throws, for testing error handling.

/**
 * Bootstrap function that always throws an error.
 */
export async function failingBootstrap() {
  throw new Error('Bootstrap intentionally failed')
}
