# Detection Modules

Detection modules analyze normalized `SecurityEvent` values and return bounded, structured signals. They do not mutate IIS configuration or deny lists. The built-in HTTP heuristic remains enabled and contributes to risk scoring by default; every other module defaults to observe-only.

## Contract

Implement `IDetectionModule` and provide a stable descriptor ID, display name, and configuration section. IDs are lowercase and limited to 32 letters, digits, dots, and hyphens. `ConfigurationSection` is descriptive metadata: the engine does not bind module-specific options automatically.

Each `DetectionSignal` must include:

- A stable signal `Key` and, when useful, a stable `CorrelationKey` shared by equivalent signals across detectors.
- An existing `DetectionEvidenceFamily`, an indicator, a plain-language explanation, and a reason.
- A non-negative weight. Keep signal data bounded; keys are at most 64 characters, indicators and reasons 256, and explanations 512.

Use `DetectionSignalCode.Custom` for module-specific signals. A module may return at most 128 signals per event and 64 distinct stable signal keys over its lifetime. Invalid output or an exception isolates that module for the event; its other modules continue. Keep mutable correlation state bounded and thread-safe, and make decisions deterministic for equivalent inputs and state.

The engine deduplicates contributing signals by correlation key, then selects one contributor per evidence family using deterministic tie-breaking. Observe-only signals remain in event evidence but never affect score, severity, or the detection reason. Structured evidence is persisted and returned with events, and the dashboard distinguishes contributing, unselected, and observe-only signals.

## Add a Module

Define module options and validate them at startup using the normal options pipeline:

```csharp
public sealed class ExampleDetectorOptions
{
    public const string SectionName = "ExampleDetection";

    [Range(0, 100)]
    public int Weight { get; set; } = 5;
}
```

Implement the module with its validated options. This abbreviated example emits one signal when a local rule matches:

```csharp
public sealed class ExampleDetector(IOptions<ExampleDetectorOptions> options) : IDetectionModule
{
    public DetectionModuleDescriptor Descriptor { get; } = new(
        "example",
        "Example detector",
        ExampleDetectorOptions.SectionName);

    public IReadOnlyList<DetectionSignal> Detect(SecurityEvent webEvent)
    {
        if (!Matches(webEvent)) return [];

        return
        [
            new DetectionSignal(
                DetectionSignalCode.Custom,
                "example.path.pattern",
                "http.path.example-pattern",
                DetectionEvidenceFamily.PathContent,
                "example pattern",
                "The request path matched the example pattern.",
                "example path pattern",
                options.Value.Weight)
        ];
    }

    private static bool Matches(SecurityEvent webEvent)
      => webEvent.Path.EndsWith(".example", StringComparison.OrdinalIgnoreCase);
}
```

Register both the validated options and the detector in `Program.cs` or the relevant service-registration extension:

```csharp
services.AddOptions<ExampleDetectorOptions>()
    .BindConfiguration(ExampleDetectorOptions.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();
services.AddSingleton<IDetectionModule, ExampleDetector>();
```

Add the module configuration and explicitly set its operating mode:

```json
{
  "ExampleDetection": { "Weight": 5 },
  "DetectionModules": {
    "Modules": {
      "example": { "Enabled": true, "Mode": "Observe" }
    }
  }
}
```

Keep `Observe` while evaluating the module. Change to `Contribute` only after reviewing its evidence and measured false-positive and false-negative behavior. Disabled modules are not evaluated. A configuration entry for an unregistered module is a startup error.

## Tests and Evaluation

Add focused tests for matching and non-matching inputs, signal bounds and stable keys, deterministic output, state/window boundaries, and failure behavior. Add engine tests when changing deduplication, family selection, or mode semantics. Verify that observation-only evidence is persisted without changing suspicious status or score.

For behavioral changes, add labeled scenarios to `Tests/DetectionEvaluation/Fixtures/baseline-v1.json` and run the evaluation report:

```powershell
dotnet run --project Tests/DetectionEvaluation -- --fixture Tests/DetectionEvaluation/Fixtures/baseline-v1.json --output artifacts/detection-evaluation.json
```

Review precision, recall, false-positive and false-negative examples, detection latency, and per-event evidence before enabling contribution. Update the baseline intentionally when expected behavior changes.

## Boundaries

Modules return evidence only. Keep IIS mutation in the existing enforcement services and do not call those services from a detector. Detection modules must remain local and deterministic: do not add machine-learning, cloud, or external model dependencies.