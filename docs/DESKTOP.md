# Desktop usage

DWI Desktop is a native Tkinter presentation/orchestration shell for Windows.
It uses the same scan, policy, application and recovery services as the CLI.
Launching Desktop performs no filesystem mutation.

```powershell
dwi desktop
```

The interface provides Overview/Scan, Findings, Cleanup Review, Recovery/Undo
and Settings. English and Vietnamese resources are packaged together. The
version label is sourced from `dwi.version.__version__`.

The cleanup workflow is deliberately explicit:

1. scan and inspect evidence;
2. select engine-eligible findings;
3. review the immutable plan;
4. provide exact human confirmation;
5. let the engine revalidate immediately before mutation;
6. inspect per-item Quarantine and recovery results;
7. use recovery identity for Undo.

Cancel is enabled only during safely cancellable phases. After authorized
mutation or restore begins, the UI disables cancellation and communicates that
it is finishing safely. Closing the window requests cooperative cancellation
when safe and otherwise waits for reconciliation; active mutation does not
continue invisibly after the window disappears.

Desktop does not manufacture `RiskLabel`, `ActionEligibility`,
`PlanValidation`, `ExecutionAuthorization`, trusted snapshots or mutation
capabilities. It does not accept arbitrary cleanup or restore paths.
