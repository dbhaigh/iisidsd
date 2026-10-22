# iisidsd Performance Baseline 0.2.3+d94bee47178b0f2ae22233ee25d465344fff90bc

Run: 2026-10-22T19:13:15.9785086+00:00 | source: `d94bee4` | working tree dirty: True
Host: AMD64 Family 26 Model 36 Stepping 0, AuthenticAMD, 24 logical CPUs, 93.6 GiB available; Microsoft Windows 10.0.26300; .NET 10.0.13
Dataset: seed 424242; 50,000 sustained requests; 26,243 client IPs, 16,736 paths, 32 domains/sites; repeated-404 detections 4,999/5,000.

## Release Comparison
No previous report was supplied. This is the first baseline; no release comparison or performance target is asserted.

## Measurements
- Sustained ingestion: 50,000 processed at 917.95 events/s; received 50,000, dropped 0, queue high-water 135; end-to-end detection latency n=50000; p50=39.83 ms; p95=85.70 ms; p99=101.53 ms.
- Burst ingestion: 10,000 processed at 1,564.81 events/s; dropped 0, queue high-water 6,115; end-to-end latency n=10000; p50=1,785.58 ms; p95=4,038.84 ms; p99=4,229.76 ms.
- Resource use during sustained ingestion: CPU 25.70s (47.2% of one logical core); managed allocation 1,007.5 MiB; working set 56.4 -> 84.1 MiB, peak 131.6 MiB.
- SQLite: 66,146,304 bytes final size; retained 60,514 rows; growth 61,393,024 bytes (1,227.9 bytes/event, 1,127,118 bytes/s).
- Dashboard concurrent filtered queries: 200 requests at 962.52 requests/s; n=200; p50=2.51 ms; p95=17.73 ms; p99=114.17 ms.
- Dashboard concurrent SSE clients: 8; event delivery n=8; p50=16.03 ms; p95=16.04 ms; p99=16.04 ms.
- Event JSON export: 99.59 ms, 2,945,646 bytes; event CSV export: 69.49 ms, 2,258,521 bytes; findings export: 39.25 ms, 22,475 bytes.
- Queue saturation: offered 4,000, accepted 257, dropped 3,743, high-water 256; drain recovery 127.19 ms.
- SQLite lock contention: held writer lock 250.00 ms; persisted 256/256; lock-release recovery 140.56 ms; batch-write p95 269.12 ms.

## Method and Limits
Synthetic IIS-shaped ETW payloads use a fixed seed and pass through the production normalizer, detector, bounded ingestion queue, SQLite event/finding stores, and mapped dashboard endpoints. TestServer API timings are in-process and exclude network/TLS/Windows Authentication. SSE clients are in-process streams; no live IIS ETW provider or production traffic is used. CPU and memory are process-wide snapshots around sustained ingestion. SQLite lock contention is injected with a held write transaction. The first run establishes a baseline only: no regression thresholds are configured; compare only runs with matched hardware, runtime, dataset, and settings.
