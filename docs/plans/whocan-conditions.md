# whoCan Conditions Output Plan

## Feature Brief

- Problem statement: `iam-simulate` now returns a structured `analysis.conditions` expression describing the conditions under which a Discovery-mode allowed request is allowed, but `iam-lens` `whoCan` still places the older `analysis.ignoredConditions` diagnostic object in the public `conditions` field.
- Goals: For `WhoCanAllowed` and `WhoCanAllowedResourcePattern`, return the new `iam-simulate` allowed-condition expression in `conditions`, and preserve the prior ignored-condition diagnostic in a new `ignoredConditions` field.
- Non-goals: Do not change simulation behavior, condition evaluation, deny details, CLI flags, or principal/resource discovery.
- Target package/API: `@cloud-copilot/iam-lens` `whoCan` API and CLI JSON output; types in `src/whoCan/whoCan.ts`; mapping in `src/whoCan/WhoCanWorker.ts`.
- User-facing behavior: Allowed `whoCan` results expose `conditions` as the new structured allowed-condition expression when present and meaningful. Existing ignored discovery-condition details move to `ignoredConditions`. Unconditional allows continue to omit `conditions` rather than emitting `{ conditionType: 'always' }`.
- Inputs: Existing `whoCan` requests and `iam-simulate` `SuccessfulRunSimulationResults`.
- Outputs: `WhoCanAllowed.conditions?: AllowedConditionExpression`; `WhoCanAllowed.ignoredConditions?: IgnoredConditions`; same for `WhoCanAllowedResourcePattern`.
- Errors/diagnostics: No new errors. Existing ignored-condition diagnostics remain available under `ignoredConditions`.
- Edge cases: Omit `conditions` when undefined or `{ conditionType: 'always' }`; omit `ignoredConditions` when undefined/empty; preserve `dependsOnSessionName`, `details`, `resourceType`, and wildcard `allowedPatterns`; handle both single-resource and wildcard-resource simulation result shapes.
- Compatibility concerns: This changes the meaning/shape of the existing public `conditions` field and preserves old data under `ignoredConditions`. Downstream callers reading `conditions` as ignored conditions must migrate.
- Documentation/examples impact: Update `docs/WhoCan.md` to describe `conditions` vs `ignoredConditions` and adjust examples if tests/docs include conditional output.
- Open questions: None currently; the requested field names and target result types are explicit.

## Repository Reconnaissance

- Current branch/status: `main...origin/main`, working tree clean at intake.
- Package: `@cloud-copilot/iam-lens`; `@cloud-copilot/iam-simulate` dependency is `^0.1.163` and its declarations include `RequestAnalysis.conditions?: AllowedConditionExpression` and `RequestAnalysis.ignoredConditions?: IgnoredConditions`.
- Public API entry point: `src/index.ts` exports `whoCan`, `ResourceAccessRequest`, `WhoCanAllowed`, and `WhoCanResponse`. `WhoCanAllowedResourcePattern` is exported from `src/whoCan/whoCan.ts` but not re-exported from `src/index.ts`; this change should re-export it for typed access to `allowedPatterns` entries.
- Current mapping: `src/whoCan/WhoCanWorker.ts` maps single allowed result `analysis.ignoredConditions` into `allowed.conditions`; wildcard allowed patterns map `r.analysis.ignoredConditions` into each pattern's `conditions`.
- Current public types: `WhoCanAllowed.conditions?: any` and `WhoCanAllowedResourcePattern.conditions?: any` with comments describing conditions under which access is allowed. No `ignoredConditions` field exists.
- Tests: `src/whoCan/whoCanIntegration.test.ts` expects old ignored-condition objects in `conditions` for conditional cases; `src/whoCan/whoCan.test.ts` sorting preservation test uses `conditions` generically.
- Docs: `docs/WhoCan.md` documents wildcard output but not the conditional fields in detail.

## Implementation Plan

1. Update imports in `src/whoCan/whoCan.ts` to import `AllowedConditionExpression` and `IgnoredConditions` types from `@cloud-copilot/iam-simulate` along with `RequestDenial`/`RequestGrant`.
2. Update `WhoCanAllowedResourcePattern`:
   - Change `conditions?: any` to `conditions?: AllowedConditionExpression` and JSDoc to describe the new allowed-condition expression.
   - Add `ignoredConditions?: IgnoredConditions` with JSDoc explaining this is the previous ignored discovery-condition diagnostic data.
3. Update `WhoCanAllowed` similarly: `conditions?: AllowedConditionExpression`; add `ignoredConditions?: IgnoredConditions`; update JSDoc and compatibility note.
4. Add small internal mapping helpers in `src/whoCan/WhoCanWorker.ts` (or equivalent pure local functions) to keep output omission rules consistent:
   - `meaningfulAllowedConditions(conditions)` returns `undefined` for `undefined` or `{ conditionType: 'always' }`, otherwise returns the `AllowedConditionExpression` unchanged.
   - `nonEmptyIgnoredConditions(ignoredConditions)` returns `undefined` for `undefined` or structurally empty ignored-condition containers, otherwise returns the `IgnoredConditions` unchanged. Treat the object as non-empty only when at least one policy-type bucket has an `allow` or `deny` array with one or more entries.
5. Update `src/whoCan/WhoCanWorker.ts` mapping:
   - For single allowed results: set `allowed.conditions` from `meaningfulAllowedConditions(analysis.conditions)`; set `allowed.ignoredConditions` from `nonEmptyIgnoredConditions(analysis.ignoredConditions)`.
   - For wildcard allowed patterns: include `conditions` from `meaningfulAllowedConditions(r.analysis.conditions)` only when meaningful; include `ignoredConditions` from `nonEmptyIgnoredConditions(r.analysis.ignoredConditions)` only when non-empty. Do not emit either field as `undefined` in the object literal.
   - Preserve existing session-name, grant-details, resource-type behavior.
6. Update `src/index.ts` to re-export `WhoCanAllowedResourcePattern`. Do not add separate upstream type re-exports unless TypeScript build/tests reveal they are needed; callers can use the typed fields without importing the upstream types directly.
7. Update `src/whoCan/whoCanIntegration.test.ts` expected conditional outputs so old condition objects move to `ignoredConditions`; add assertions for new `conditions` objects using the `AllowedConditionExpression` shape where deterministic. Cover at least one single-resource `WhoCanAllowed` and one wildcard `WhoCanAllowedResourcePattern` with non-trivial `conditions`.
8. Update `src/whoCan/whoCan.test.ts` sorting preservation case to include both `conditions` and `ignoredConditions` so it verifies both fields survive sorting.
9. Update `docs/WhoCan.md` with a concise explanation of `conditions` and `ignoredConditions`, including that unconditional allows omit `conditions`.

## Test Strategy

- Focused tests:
  - `npx vitest --run src/whoCan/whoCan.test.ts src/whoCan/whoCanIntegration.test.ts`
- Package checks after implementation:
  - `npm run build`
  - `npm test`
  - `npm run format-check`
- Meaningful assertions:
  - Single-resource `WhoCanAllowed` includes `conditions` as `conditionType: 'condition'` or appropriate expression and includes old diagnostic under `ignoredConditions`.
  - Wildcard `WhoCanAllowedResourcePattern` includes `conditions` from each allowed pattern and old diagnostic under `ignoredConditions`.
  - Unconditional allowed results omit `conditions` rather than returning `{ conditionType: 'always' }`.
  - Sorting preserves both fields.

## Risks and Edge Cases

- Existing tests may need multiple expected expression shapes if `iam-simulate` combines identity/resource/SCP/RCP conditions into groups. Use precise assertions from current deterministic fixture outputs rather than broad snapshots.
- Public API compatibility is intentionally changed for `conditions`; preserving `ignoredConditions` mitigates data loss but not type/shape compatibility. Document this as a migration note in `docs/WhoCan.md` and use a `feat:` commit/PR title per repo workflow; package release semantics are managed by the repository's semantic-release config.
- Avoid emitting empty ignored-condition objects or trivial `{ conditionType: 'always' }` conditions.

## Alternatives Considered

- Add only `ignoredConditions` and leave `conditions` unchanged: rejected because the requested user-visible behavior is to put the new `iam-simulate` object in `conditions`.
- Add `allowedConditions` instead of reusing `conditions`: rejected because user explicitly requested the new conditions object in `conditions`.
- Keep `any` types: rejected because `iam-simulate` now exports semantic types and this is a public API contract change.

## Commands/Checks to Run

```bash
npx vitest --run src/whoCan/whoCan.test.ts src/whoCan/whoCanIntegration.test.ts
npm run build
npm test
npm run format-check
```

## Rollback/Follow-up Considerations

- `docs/WhoCan.md` will include the migration note for `conditions` vs `ignoredConditions` as part of this change.
- If downstream callers later need to import `AllowedConditionExpression`/`IgnoredConditions` directly from `iam-lens`, consider a follow-up explicit type re-export. This plan only requires typed fields and `WhoCanAllowedResourcePattern` re-export.

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
- [x] Claude plan review concerns resolved
- [x] Codex/current-model plan review concerns resolved
- [ ] User approved implementation
