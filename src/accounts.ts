import { AwsIamStore } from '@cloud-copilot/iam-collect'

export async function accountExists(
  storageClient: AwsIamStore,
  accountId: string
): Promise<boolean> {
  const accounts = await storageClient.listAccountIds()
  return accounts.includes(accountId)
}
