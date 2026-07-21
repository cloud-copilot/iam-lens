# S3 Block Public Access Integration for Simulate and WhoCan

## Feature Brief

- Problem statement: `iam-lens` currently passes S3 bucket ABAC settings into `iam-simulate`, but it does not pass effective S3 Block Public Access (BPA) settings. Newer `iam-collect` stores bucket-level and account-level S3 BPA metadata, and newer `iam-simulate` can use an effective BPA boolean for S3 authorization.
- Goals:
  - Upgrade `@cloud-copilot/iam-simulate` to `0.1.157` and `@cloud-copilot/iam-collect` to `0.1.205`.
  - Auto-detect S3 BPA metadata for bucket/object simulations.
  - Combine bucket-level and account-level `RestrictPublicBuckets` settings into the effective `additionalSettings.s3.blockPublicAccess` value passed to `iam-simulate`.
  - Cover behavior in both `simulate` and `whoCan` integration tests.
- Non-goals:
  - Add a CLI override for S3 BPA.
  - Reimplement S3 BPA policy classification in `iam-lens`.
  - Change non-S3 simulation behavior.
  - Change existing S3 ABAC override behavior.
- Target package/API: `@cloud-copilot/iam-lens`; `simulateRequest`, `whoCan` (through its existing `simulateRequest` path), and `IamCollectClient` metadata access.
- User-facing behavior: For S3 bucket/object requests, `iam-lens` automatically looks up S3 BPA data from the collected bucket metadata and account metadata and passes the effective setting to `iam-simulate`. Users should see simulations and who-can results that account for S3 public bucket policy restrictions when the collected metadata says `RestrictPublicBuckets` is enabled.
- Inputs:
  - Existing `SimulationRequest` and `ResourceAccessRequest` inputs.
  - Bucket/object resource ARNs with a discoverable resource account.
  - iam-collect metadata: bucket metadata `bpa` and account metadata key `s3-bpa`.
- Outputs:
  - Existing simulation and whoCan outputs, with authorization decisions affected by S3 BPA where `iam-simulate` applies it.
  - No public output shape changes.
- Errors/diagnostics:
  - Missing BPA metadata should not be fatal; it should behave as BPA disabled unless either bucket/account metadata has `RestrictPublicBuckets: true`.
  - Existing resource account/principal/action validation errors remain unchanged.
- Edge cases:
  - S3 object ARN should resolve to the containing bucket for bucket metadata lookup.
  - Account-level `RestrictPublicBuckets: true` should enable effective BPA even if bucket metadata is missing or false.
  - Bucket-level `RestrictPublicBuckets: true` should enable effective BPA even if account metadata is missing or false.
  - Non-S3 resources and wildcard-only actions should not fetch/pass S3 BPA settings.
  - Existing bucket ABAC settings should remain merged into `additionalSettings.s3`.
- Compatibility concerns:
  - Public TypeScript API remains backwards compatible.
  - `package-lock.json` will update for the dependency versions.
  - Existing datasets that lack new account-level BPA metadata should continue to work.
- Documentation/examples impact:
  - Update `docs/Simulate.md`, `docs/WhoCan.md`, and potentially README command description to mention automatic S3 BPA handling from iam-collect metadata.
- Open questions:
  - None currently; plan assumes only `RestrictPublicBuckets` is relevant because `iam-simulate@0.1.157` documents `blockPublicAccess` as the effective setting for `RestrictPublicBuckets`.

## Discovery Findings

- Current branch: `main` tracking `origin/main`; no changes at intake.
- `package.json` currently pins `@cloud-copilot/iam-collect` as `^0.1.181` and `@cloud-copilot/iam-simulate` as `^0.1.151`.
- `simulateRequest` already builds `Simulation.additionalSettings.s3.bucketAbacEnabled` when `isS3BucketOrObjectArn(resourceArn)` is true.
- `whoCan` flows through `WhoCanWorker.executeWhoCan`, which calls `simulateRequest` for Discovery and Strict modes. Implementing BPA in `simulateRequest` automatically covers `whoCan` worker paths.
- `iam-simulate@0.1.157` adds `additionalSettings.s3.blockPublicAccess?: boolean`, documented as caller-supplied effective S3 Block Public Access setting for `RestrictPublicBuckets`.
- `iam-collect@0.1.205` stores:
  - account-level BPA metadata via `saveAccountMetadata(accountId, 's3-bpa', bpa)`
  - bucket-level BPA as a separate bucket resource metadata key `bpa` (`bpa.json`), not nested inside the bucket `metadata` key.
- The existing test dataset already has bucket-level `bpa.json` files with S3 BPA fields; focused account-level fixtures can be added as `accounts/{accountId}/s3-bpa.json`.

## Implementation Plan

### Files/functions/types likely to change

- `package.json` and `package-lock.json`
  - Upgrade `@cloud-copilot/iam-collect` to `^0.1.205` or exact `0.1.205` consistent with current dependency style.
  - Upgrade `@cloud-copilot/iam-simulate` to `^0.1.157` or exact `0.1.157` consistent with current dependency style.
- `src/collect/client.ts`
  - Add a small typed metadata shape for S3 BPA fields.
  - Add `getBlockPublicAccessEnabledForBucket(accountId, bucketOrObjectArn): Promise<boolean>` or similar.
  - Read bucket resource metadata key `bpa` via `getResourceMetadata(accountId, bucketArn, 'bpa', {})` and account metadata key `s3-bpa` via `getAccountMetadata(accountId, 's3-bpa', {})`.
  - Return `true` if either source has `RestrictPublicBuckets === true`; otherwise `false`.
- `src/simulate/simulate.ts`
  - Rename/refactor the S3 additional settings assembly so ABAC and BPA are both populated for S3 bucket/object requests.
  - Preserve `bucketAbacEnabled` behavior and add `blockPublicAccess` from the new collect-client method.
- Tests/fixtures:
  - `src/collect/client.test.ts`: unit coverage for bucket-level, account-level, object ARN normalization, false/missing defaults.
  - `src/simulate/simulateIntegration.test.ts`: add focused S3 public-policy/BPA cases proving simulated decisions differ with effective BPA enabled vs disabled/missing.
  - `src/whoCan/whoCanIntegration.test.ts`: add focused S3 public-policy/BPA cases proving whoCan excludes/includes cross-account principals according to effective BPA.
  - `src/test-datasets/iam-data-1/...`: add sanitized synthetic bucket/account metadata and policies only as needed.
- Docs:
  - `docs/Simulate.md` and `docs/WhoCan.md` mention automatic S3 BPA detection from iam-collect data.

### Primary input types

- Existing `SimulationRequest` and `ResourceAccessRequest` remain unchanged.
- Internal metadata type:
  - `{ BlockPublicAcls?: boolean; IgnorePublicAcls?: boolean; BlockPublicPolicy?: boolean; RestrictPublicBuckets?: boolean }`
  - Bucket metadata shape extends current ad hoc metadata with optional `bpa?: S3PublicAccessBlockMetadata`.

### Primary output/result types

- Existing `SimulateRequestResult` and `WhoCanResponse` remain unchanged.
- New internal collect-client method returns `boolean`.

### Error/diagnostic types

- No new public errors.
- Missing malformed/partial BPA metadata resolves to `false` unless a strict `true` is found on bucket or account metadata.

### Option/configuration types

- No new CLI or API options.
- Existing `s3AbacOverride` remains independent.

### Exported vs internal types

- Keep BPA metadata types internal to `collect/client.ts` unless tests require exported types (not expected).
- Do not export a new public API unless necessary.

### Exact behavior change

For S3 bucket/object simulations only:

1. Normalize object ARNs to the bucket ARN for bucket metadata lookup.
2. Read bucket resource metadata key `bpa` and inspect `RestrictPublicBuckets`.
3. Read account metadata key `s3-bpa` and inspect `RestrictPublicBuckets`.
4. Pass `additionalSettings.s3.blockPublicAccess = bucketRestrictPublicBuckets === true || accountRestrictPublicBuckets === true` into `iam-simulate`.
5. Continue passing `additionalSettings.s3.bucketAbacEnabled` as today.

### Docs/examples changes

- Update Simulate and WhoCan option/details text to note that S3 Block Public Access is automatically applied from iam-collect bucket/account metadata when available.
- No new examples required unless tests reveal a useful concise sample.

### Backwards compatibility impact

- No public API or CLI input change.
- Results for S3 public bucket-policy simulations may become more accurate and therefore may change when collected BPA metadata has `RestrictPublicBuckets: true`.
- Missing metadata remains non-fatal to preserve compatibility with old iam-collect datasets.

### Test strategy

- Unit tests for the collect-client metadata lookup:
  - bucket-level `bpa` metadata with RestrictPublicBuckets true -> true
  - account-level `s3-bpa` metadata with RestrictPublicBuckets true -> true
  - both absent/false -> false
  - object ARN normalizes to bucket ARN
- Simulate integration tests:
  - A cross-account S3 bucket policy that would otherwise grant access is denied when bucket-level BPA has `RestrictPublicBuckets: true`.
  - The same/similar case is denied when account-level BPA has `RestrictPublicBuckets: true`.
  - A control case with BPA false/missing remains allowed.
- WhoCan integration tests:
  - For a public/cross-account S3 bucket policy, whoCan excludes cross-account principals when effective BPA is true.
  - Control case verifies expected principals remain when BPA is false/missing.
- Existing ABAC integration tests should continue passing to prove `additionalSettings.s3` merging did not regress.

### Risk areas and edge cases

- The exact `iam-simulate` semantics for `blockPublicAccess` are delegated to version `0.1.157`; tests must assert user-visible results rather than internal call shape.
- Worker-thread whoCan paths must receive the same behavior; centralizing in `simulateRequest` avoids duplicated logic.
- Avoid interpreting other BPA flags as `blockPublicAccess`; the new simulate setting is specifically documented for `RestrictPublicBuckets`.
- Test fixture changes may affect broad whoCan integration expected results/simulation counts; focused new buckets should minimize disturbance.
- Fetching ABAC and BPA sequentially is simple but could add repeated I/O in whoCan; prefer `Promise.all` in S3 settings assembly and cache BPA lookups in `IamCollectClient`.

### Alternatives considered

- Add a CLI override for BPA: rejected as out of scope and not requested.
- Pass the full BPA object to `iam-simulate`: rejected because `iam-simulate@0.1.157` exposes a boolean `blockPublicAccess` setting.
- Implement BPA policy classification in `iam-lens`: rejected because `iam-simulate` owns authorization semantics.

### Commands/checks to run

```bash
npm install @cloud-copilot/iam-simulate@0.1.157 @cloud-copilot/iam-collect@0.1.205
npx vitest --run src/collect/client.test.ts src/simulate/simulateIntegration.test.ts src/whoCan/whoCanIntegration.test.ts
npm run build
npm test
npm run format-check
```

If formatting changes are needed:

```bash
npm run format
```

### Rollback/follow-up considerations

- Roll back dependency and code changes together if `iam-simulate@0.1.157` introduces incompatible result semantics.
- Follow-up could add a CLI/API override for BPA only if users need to model prospective settings not present in collected metadata.

## Pre-Implementation Confidence Gate

- [x] Discovery findings recorded
- [x] Product behavior is explicit
- [x] Inputs are final enough to implement
- [x] Outputs are final enough to implement
- [x] Exported types/APIs are final enough to implement
- [x] Error/diagnostic behavior is explicit
- [x] Test strategy is explicit
- [x] Docs/examples impact is explicit
- [x] Backwards compatibility impact is explicit
- [ ] Claude plan review concerns resolved
- [ ] Codex/current-model plan review concerns resolved
- [ ] User approved implementation
