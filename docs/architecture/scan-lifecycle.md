# Scan lifecycle and orchestration

## Scan states

The normal path is:

`queued -> preparing -> running -> completed`

From `running`, a cancellation request moves to `cancellation_requested`, then to `cancelled` only
after confirmed cleanup. `partial` records at least one successful planned check and at least one
unsuccessful check. `failed` records no useful completed coverage or unconfirmed cleanup. Terminal
states do not transition.

## Finding states

`open -> investigating -> remediating -> verification_pending -> resolved`

Analysts may also end review as `accepted_risk` or `ignored`. Invalid shortcuts are rejected.
`resolved -> open` is not a general transition: callers must record it using the explicit
regression operation.

## Pure job model

A `ScanPlan` contains 1..64 unique `(engine, target)` tasks. Each task has a bounded timeout;
an adapter result whose elapsed time exceeds that bound is classified as failed coverage even if
the adapter labels it completed.
`ScanJob` executes through `EngineTaskRunner`; the in-memory model is sequential to make ordering,
progress and fake tests deterministic. A future concurrent scheduler must preserve these observable
contracts:

- monotonic progress sequence and elapsed duration;
- percentage always in `0..=100` and derived only from completed tasks;
- no fabricated ETA (`eta_ms` remains absent until measured historical data exists);
- one coverage result for every planned `(engine, target)` pair;
- explicit provider availability; any unavailable planned provider makes coverage incomplete;
- invalid engine observations fail closed;
- timeouts are unsuccessful coverage;
- cancellation without cleanup confirmation is a failure, never a clean cancellation.

The core cannot prove that an OS process tree was terminated. The Engine Manager adapter must use
its process containment primitive, perform bounded termination/wait, and return
`cleanup_confirmed=true` only when that check succeeds.

## Events

The event contract includes scan creation/start/completion/partial/failure, engine start/progress/
completion/failure, finding observation/status change, remediation request and verification
completion. Engine events carry both engine and target IDs so multi-target plans remain unambiguous.
Events carry typed IDs and timestamps and use a tagged serialized representation.
They are facts for persistence/reporting; replay policy and delivery guarantees belong to the
storage/integration layer.

## Failure and retry policy

The pure core does not retry engines, infer retry safety or resume partial process output. An outer
policy may create a new scan linked by its own audit metadata. It must not overwrite prior coverage
or findings. Provider unavailability is explicit and reduces confidence; it is not a clean result.
