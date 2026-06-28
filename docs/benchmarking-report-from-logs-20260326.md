# Benchmarking Report From `docs/logs`

## Scope

This report summarizes the benchmark and load-generation data captured in:

- `docs/logs/details_collector_20260326T065306Z_conc1-lvl3.log`
- `docs/logs/details_collector_20260326T070601Z_conc2-lvl3.log`
- `docs/logs/details_collector_20260326T074948Z_conc8-lvl3.log`
- `docs/logs/details_collector_20260326T075306Z_conc12-lvl3.log`
- `docs/logs/details_collector_20260326T114644Z_conc16-lvl3.log`
- `docs/logs/details_collector_20260326T115413Z_conc1-lvl5.log`
- `docs/logs/details_collector_20260326T120610Z_conc2-lvl5.log`
- `docs/logs/details_collector_20260326T121556Z_conc8-lvl5.log`
- `docs/logs/details_collector_20260326T121951Z_conc12-lvl5.log`
- `docs/logs/details_collector_20260326T122857Z_conc16-lvl5.log`

Dataset size:

- `10` log files
- `180` loadgen result rows
- `380` Go benchmark rows

Test matrix reconstructed from the logs:

- Security levels: `3` and `5`
- Concurrency: `1`, `2`, `8`, `12`, `16`
- Schemes in loadgen: `a`, `b`, `c`, `d`, `e`, `f`
- Modes in loadgen: `parse-only`, `decrypt-only`, `end-to-end`
- Host runtime in every log: `NumCPU=12`, `GOMAXPROCS=12`
- Loadgen volume in every run: `n=100000`, `warmup=1000`

Important caveats:

- `security-level` only affects PQC and hybrid schemes `c` to `f`. For `a` and `b`, any Level 3 vs Level 5 differences are run-to-run noise because the tool ignores the flag there.
- `loadgen` for scheme `d` covers the baseline Profile D wire format only. `add17` and `add19` are represented in the Go benchmark section, not in the loadgen latency/throughput section.
- The logs do not contain direct CPU utilization percentages. CPU comparison in this report therefore uses:
  - throughput (`ops/s`)
  - latency (`p50`, `p95`, `p99`)
  - `ns/op`
  - allocation and bytes-per-op data
- `Peak RSS` is process-level memory and is somewhat noisy across runs, especially at higher concurrency. Use it directionally, not as a byte-accurate memory model.

## Executive Summary

The strongest overall pattern is the clear separation between the classical profiles (`A`, `B`), the pure PQC profile (`C`), and the hybrid profiles (`D`, `E`, `F`). In end-to-end throughput, `A` and `B` are fastest, `C` is the best-performing PQC-capable option, and `D/E/F` are materially slower due to dual-stack or nested/wrapper crypto composition.

For PQC-sensitive comparisons, `security-level 5` consistently imposes a measurable cost for schemes `C-F`. Across all tested concurrencies, the average end-to-end throughput drop versus Level 3 was:

- Profile `C`: `-29.11%`
- Profile `D`: `-19.42%`
- Profile `E`: `-19.26%`
- Profile `F`: `-16.89%`

The same Level 5 move also tends to worsen latency, especially tail latency:

- Profile `C`: average `p50 +47.46%`, average `p99 +28.66%`
- Profile `D`: average `p50 +24.45%`, average `p99 +35.15%`
- Profile `E`: average `p50 +23.18%`, average `p99 +15.37%`
- Profile `F`: average `p50 +21.66%`, average `p99 +13.66%`

On concurrency scaling, schemes `A/B` scale the best, while `C-F` saturate earlier:

- `A/B` reach about `7x` to `8.7x` end-to-end throughput at higher concurrency versus concurrency `1`
- `C` reaches about `4x`
- `D/E/F` typically reach about `5x` to `6x`

From a security/performance tradeoff perspective:

- Use `Level 3` when 3GPP-default ML-KEM-768 is acceptable and throughput or latency matter.
- Use `Level 5` when the higher PQ margin is worth a roughly `17%` to `29%` throughput penalty on `C-F`, plus higher median and tail latency.
- If a PQ-capable option is needed with the best performance, `Profile C` is the most efficient among the PQC-enabled schemes.

## Key Findings

### 1. Fastest end-to-end options

At high concurrency (`16`), end-to-end throughput ranks as follows:

| Rank | Scheme | Level | Throughput (ops/s) | p99 (us) | Peak RSS (kB) |
|---|---|---:|---:|---:|---:|
| 1 | A | 5 | 56637.19 | 754.82 | 12484 |
| 2 | A | 3 | 44434.64 | 1531.85 | 17672 |
| 3 | B | 3 | 41685.88 | 6289.47 | 15616 |
| 4 | B | 5 | 31996.06 | 11242.77 | 14716 |
| 5 | C | 3 | 25765.53 | 10832.59 | 20292 |
| 6 | C | 5 | 18761.15 | 10840.10 | 14592 |
| 7 | D | 3 | 15881.71 | 15192.13 | 19436 |
| 8 | E | 3 | 15648.53 | 14124.70 | 20592 |
| 9 | F | 3 | 15346.81 | 16458.81 | 18912 |
| 10 | D | 5 | 13368.15 | 13773.16 | 14088 |
| 11 | F | 5 | 12495.64 | 17764.20 | 18112 |
| 12 | E | 5 | 12214.43 | 14571.80 | 13912 |

Interpretation:

- `A` and `B` dominate raw throughput.
- `C` is clearly the best-performing PQC-bearing profile.
- `D/E/F` are in the same broad performance band, with `D` and `E` slightly ahead of `F` at Level 3 in some runs, but close enough that tail latency and security posture matter more than raw median speed.

### 2. Profile C is the most performance-efficient PQC option

At end-to-end Level 3:

- `C` at concurrency `1`: `6327.09 ops/s`
- `D` at concurrency `1`: `2987.10 ops/s`
- `E` at concurrency `1`: `2934.12 ops/s`
- `F` at concurrency `1`: `3031.38 ops/s`

That makes `C` roughly `2.1x` faster than the hybrid profiles at low concurrency. The same pattern holds at higher concurrency.

### 3. Level 5 cost is highest for pure PQC Profile C

Average end-to-end penalty from Level 3 to Level 5:

| Scheme | Avg throughput delta | Avg p50 delta | Avg p99 delta |
|---|---:|---:|---:|
| C | -29.11% | +47.46% | +28.66% |
| D | -19.42% | +24.45% | +35.15% |
| E | -19.26% | +23.18% | +15.37% |
| F | -16.89% | +21.66% | +13.66% |

Interpretation:

- `C` exposes the ML-KEM size/cost increase most directly.
- `D/E/F` still slow down at Level 5, but the relative penalty is smaller because their total cost is shared with the classical/hybrid layers.

### 4. Tail latency deteriorates faster than median latency

At moderate to high concurrency, Level 5 often impacts `p99` more than throughput alone suggests.

Examples:

- `D`, concurrency `8`: throughput `-25.73%`, but `p99 +125.80%`
- `C`, concurrency `8`: throughput `-32.27%`, `p99 +66.90%`
- `E`, concurrency `12`: throughput `-29.51%`, `p99 +48.83%`
- `F`, concurrency `12`: throughput `-27.54%`, `p99 +59.13%`

This matters for production-like workloads where worst-case or near-worst-case latencies matter more than average latency.

### 5. Scaling saturates around or before CPU count for the heavier schemes

The host reports `NumCPU=12`, and the scaling data reflects that:

- `A/B` still benefit at `16`, though not always cleanly
- `C` saturates earlier and shows weaker scaling
- `D/E/F` improve substantially from `1` to `12`, but gains from `12` to `16` are modest or negative

That suggests the heavier PQC/hybrid paths are compute-bound and/or memory-allocation sensitive before the lighter classical paths.

### 6. Memory differences are real, but RSS is noisy

At concurrency `16`, end-to-end Peak RSS is:

| Scheme | Level | Peak RSS (kB) | p50 (us) | Throughput (ops/s) |
|---|---:|---:|---:|---:|
| A | 3 | 17672 | 153.58 | 44434.64 |
| A | 5 | 12484 | 151.09 | 56637.19 |
| B | 3 | 15616 | 162.32 | 41685.88 |
| B | 5 | 14716 | 179.06 | 31996.06 |
| C | 3 | 20292 | 168.84 | 25765.53 |
| C | 5 | 14592 | 260.63 | 18761.15 |
| D | 3 | 19436 | 345.56 | 15881.71 |
| D | 5 | 14088 | 461.19 | 13368.15 |
| E | 3 | 20592 | 361.44 | 15648.53 |
| E | 5 | 13912 | 485.65 | 12214.43 |
| F | 3 | 18912 | 353.36 | 15346.81 |
| F | 5 | 18112 | 431.53 | 12495.64 |

Interpretation:

- The heavier PQC/hybrid profiles generally occupy the highest RSS band.
- However, Level 5 does not always show higher RSS in these process-level measurements.
- For more stable memory comparisons, the Go microbenchmarks are more trustworthy than Peak RSS.

## End-to-End Throughput Matrix

These are the cleanest tables for graphing the top-line throughput story.

### Level 3

| Scheme | Concurrency 1 | Concurrency 2 | Concurrency 8 | Concurrency 12 | Concurrency 16 |
|---|---:|---:|---:|---:|---:|
| A | 5872.63 | 12668.87 | 46663.32 | 40613.32 | 44434.64 |
| B | 5661.85 | 11563.90 | 37568.40 | 41177.68 | 41685.88 |
| C | 6327.09 | 12698.46 | 30654.09 | 27701.87 | 25765.53 |
| D | 2987.10 | 6013.81 | 17603.09 | 18034.17 | 15881.71 |
| E | 2934.12 | 5790.44 | 15043.26 | 16398.27 | 15648.53 |
| F | 3031.38 | 5902.34 | 14316.36 | 17383.56 | 15346.81 |

### Level 5

| Scheme | Concurrency 1 | Concurrency 2 | Concurrency 8 | Concurrency 12 | Concurrency 16 |
|---|---:|---:|---:|---:|---:|
| A | 6493.73 | 12671.05 | 46800.97 | 50427.15 | 56637.19 |
| B | 6142.57 | 11780.17 | 39450.68 | 44258.03 | 31996.06 |
| C | 4638.59 | 9020.25 | 20762.54 | 19273.48 | 18761.15 |
| D | 2570.13 | 5033.15 | 13073.00 | 13477.27 | 13368.15 |
| E | 2495.33 | 4794.95 | 13130.07 | 11558.74 | 12214.43 |
| F | 2548.82 | 4958.06 | 13399.99 | 12596.68 | 12495.64 |

Notes:

- For `A/B`, Level 3 vs Level 5 is not a real security-level comparison; those differences are only measurement noise.
- For `C-F`, the Level 5 drop is meaningful and consistent.

## Concurrency Scaling

End-to-end throughput scaling factor relative to concurrency `1`.

| Scheme | Level | x12 vs c1 | x16 vs c1 |
|---|---:|---:|---:|
| A | 3 | 6.92 | 7.57 |
| A | 5 | 7.77 | 8.72 |
| B | 3 | 7.27 | 7.36 |
| B | 5 | 7.21 | 5.21 |
| C | 3 | 4.38 | 4.07 |
| C | 5 | 4.16 | 4.04 |
| D | 3 | 6.04 | 5.32 |
| D | 5 | 5.24 | 5.20 |
| E | 3 | 5.59 | 5.33 |
| E | 5 | 4.63 | 4.89 |
| F | 3 | 5.73 | 5.06 |
| F | 5 | 4.94 | 4.90 |

Interpretation:

- `A/B` are the most scalable.
- `C` is the least scalable among the encrypted profiles.
- `D/E/F` scale better than `C`, but not nearly as well as `A/B`.
- `16` threads does not guarantee better results than `12`; some profiles are already saturated by then.

## Security-Level Delta Table For `C-F`

This table is directly useful for a Level 3 vs Level 5 penalty chart.

| Scheme | Concurrency | Throughput delta | p99 delta | RSS delta |
|---|---:|---:|---:|---:|
| C | 1 | -26.69% | +23.80% | +21.40% |
| C | 2 | -28.97% | +35.39% | -4.21% |
| C | 8 | -32.27% | +66.90% | +12.61% |
| C | 12 | -30.43% | +17.12% | -9.51% |
| C | 16 | -27.19% | +0.07% | -28.09% |
| D | 1 | -13.96% | +9.87% | +1.10% |
| D | 2 | -16.31% | +18.20% | +1.84% |
| D | 8 | -25.73% | +125.80% | +34.18% |
| D | 12 | -25.27% | +31.22% | +10.47% |
| D | 16 | -15.83% | -9.34% | -27.52% |
| E | 1 | -14.95% | +12.19% | -1.27% |
| E | 2 | -17.19% | +21.48% | +1.85% |
| E | 8 | -12.72% | -8.83% | +3.21% |
| E | 12 | -29.51% | +48.83% | +28.72% |
| E | 16 | -21.95% | +3.17% | -32.44% |
| F | 1 | -15.92% | +18.08% | -16.30% |
| F | 2 | -16.00% | +18.46% | +17.66% |
| F | 8 | -6.40% | -35.29% | -1.66% |
| F | 12 | -27.54% | +59.13% | +0.60% |
| F | 16 | -18.58% | +7.93% | -4.23% |

Interpretation:

- Throughput impact is stable enough to trust.
- `p99` and RSS are noisier at high concurrency; use them to show trends, not exact deterministic penalties.

## Go Benchmark Medians

These medians are taken across all repeated benchmark outputs in the logs. They are best treated as code-path cost proxies rather than direct reflections of the loadgen concurrency/security matrix.

### End-to-End CPU/Allocation Cost

| Benchmark | Median ns/op | Median B/op | Median allocs/op |
|---|---:|---:|---:|
| NullScheme EndToEnd | 1733.50 | 448 | 11 |
| ProfileA EndToEnd | 153525.50 | 2770 | 41 |
| ProfileB EndToEnd | 164801.00 | 6890 | 173 |
| ProfileC EndToEnd | 148232.00 | 13407 | 43 |
| ProfileD EndToEnd | 324048.00 | 15024 | 54 |
| ProfileD Add17 EndToEnd | 320897.50 | 15040 | 55 |
| ProfileD Add19 EndToEnd | 321968.50 | 15352 | 41 |
| ProfileE EndToEnd | 336430.00 | 17444 | 76 |
| ProfileF EndToEnd | 327489.50 | 15706 | 70 |

What this says:

- `Profile C` has the best end-to-end cost among the PQC-enabled options.
- `Profile D/E/F` roughly double the end-to-end cost of `C`.
- `Profile E` is the heaviest by allocation footprint in end-to-end mode.

### Encrypt Cost

| Benchmark | Median ns/op | Median B/op | Median allocs/op |
|---|---:|---:|---:|
| Encrypt ProfileA | 297932.00 | 2621 | 36 |
| Encrypt ProfileB | 108169.50 | 3470 | 45 |
| Encrypt ProfileC | 63480.00 | 11360 | 28 |
| Encrypt ProfileD | 403206.50 | 13152 | 43 |
| Encrypt ProfileD Add17 | 406606.00 | 13152 | 43 |
| Encrypt ProfileD Add19 | 400203.00 | 13448 | 28 |
| Encrypt ProfileE | 415442.00 | 15592 | 65 |
| Encrypt ProfileF | 407284.50 | 13888 | 60 |

Interesting point:

- `Encrypt_ProfileC` is notably efficient in `ns/op`, even if its payload size and parse cost are much larger than `A/B`.
- `add19` is slightly better than `add17` on `ns/op` and materially better on allocations.

### Decrypt Cost

| Benchmark | Median ns/op | Median B/op | Median allocs/op |
|---|---:|---:|---:|
| Decrypt ProfileA | 149844.50 | 2064 | 23 |
| Decrypt ProfileB | 156124.00 | 5851 | 147 |
| Decrypt ProfileC | 72466.50 | 10536 | 27 |
| Decrypt ProfileD | 244381.00 | 12072 | 37 |
| Decrypt ProfileD Add17 | 247168.50 | 12072 | 37 |
| Decrypt ProfileD Add19 | 241140.50 | 12248 | 23 |

Interesting point:

- `Profile C` decrypt-only is cheaper than `A` and `B` in the microbenchmarks.
- `add19` again shows better allocation behavior than `add17`.

### Parse Cost

| Benchmark | Median ns/op | Median B/op | Median allocs/op |
|---|---:|---:|---:|
| ParseSUCI ProfileA | 3418.00 | 400 | 4 |
| ParseSUCI ProfileB | 3489.50 | 400 | 4 |
| ParseSUCI ProfileC | 62050.50 | 1504 | 4 |
| ParseSUCI ProfileD | 64335.00 | 1504 | 4 |

Interpretation:

- Parsing PQC/hybrid SUCI strings is an order of magnitude more expensive than parsing classical `A/B` SUCI strings.
- That overhead helps explain why `parse-only` throughput for `C/D/E/F` is lower than `A/B`, even though parsing is still much cheaper than encryption/decryption.

## Security And Solution Comparison

### If you optimize for raw throughput

Recommended order:

1. `A`
2. `B`
3. `C`
4. `D/E/F`

### If you optimize for post-quantum protection with least cost

Recommended order:

1. `C` at Level 3
2. `C` at Level 5 if the stronger PQ margin is required
3. `D/F/E` depending on desired hybrid construction properties

### If you need hybrid security with better benchmark efficiency

Within the hybrid family:

- `D` is generally the best balance
- `F` is often close behind
- `E` is usually the heaviest, especially in allocations and memory footprint

### If you care about tail latency at concurrency

Avoid assuming throughput tells the whole story:

- `D/E/F` can show large `p99` inflation at `8+` concurrency
- Level 5 amplifies the tail-latency risk more than it amplifies the median-latency risk

## Recommended Graphs

The following graphs will present the dataset well:

1. End-to-end throughput by scheme
   - X-axis: concurrency
   - Y-axis: throughput (`ops/s`)
   - Series: `A`, `B`, `C`, `D`, `E`, `F`
   - Split into separate charts for Level `3` and Level `5`

2. Security-level penalty for `C-F`
   - X-axis: concurrency
   - Y-axis: throughput delta `%` from Level 3 to Level 5
   - One line each for `C`, `D`, `E`, `F`

3. Tail latency comparison
   - X-axis: concurrency
   - Y-axis: `p99 us`
   - Series by scheme and level

4. CPU-cost proxy scatter
   - X-axis: `ns/op`
   - Y-axis: `B/op`
   - Label points by benchmark name

5. Scaling efficiency
   - X-axis: scheme
   - Y-axis: `throughput(concN) / throughput(conc1)`
   - Separate bars for `12` and `16`

6. Memory footprint comparison
   - X-axis: scheme
   - Y-axis: Peak RSS (`kB`) or benchmark `B/op`
   - Separate series for levels `3` and `5`

## Chart-Ready CSV Blocks

### `end_to_end_throughput.csv`

```csv
scheme,level,conc1,conc2,conc8,conc12,conc16
a,lvl3,5872.63,12668.87,46663.32,40613.32,44434.64
a,lvl5,6493.73,12671.05,46800.97,50427.15,56637.19
b,lvl3,5661.85,11563.90,37568.40,41177.68,41685.88
b,lvl5,6142.57,11780.17,39450.68,44258.03,31996.06
c,lvl3,6327.09,12698.46,30654.09,27701.87,25765.53
c,lvl5,4638.59,9020.25,20762.54,19273.48,18761.15
d,lvl3,2987.10,6013.81,17603.09,18034.17,15881.71
d,lvl5,2570.13,5033.15,13073.00,13477.27,13368.15
e,lvl3,2934.12,5790.44,15043.26,16398.27,15648.53
e,lvl5,2495.33,4794.95,13130.07,11558.74,12214.43
f,lvl3,3031.38,5902.34,14316.36,17383.56,15346.81
f,lvl5,2548.82,4958.06,13399.99,12596.68,12495.64
```

### `security_level_delta_c_to_f.csv`

```csv
scheme,concurrency,throughput_delta_pct,p99_delta_pct,rss_delta_pct
c,1,-26.69,23.80,21.40
c,2,-28.97,35.39,-4.21
c,8,-32.27,66.90,12.61
c,12,-30.43,17.12,-9.51
c,16,-27.19,0.07,-28.09
d,1,-13.96,9.87,1.10
d,2,-16.31,18.20,1.84
d,8,-25.73,125.80,34.18
d,12,-25.27,31.22,10.47
d,16,-15.83,-9.34,-27.52
e,1,-14.95,12.19,-1.27
e,2,-17.19,21.48,1.85
e,8,-12.72,-8.83,3.21
e,12,-29.51,48.83,28.72
e,16,-21.95,3.17,-32.44
f,1,-15.92,18.08,-16.30
f,2,-16.00,18.46,17.66
f,8,-6.40,-35.29,-1.66
f,12,-27.54,59.13,0.60
f,16,-18.58,7.93,-4.23
```

### `scaling_end_to_end.csv`

```csv
scheme,level,x12_vs_c1,x16_vs_c1
a,3,6.92,7.57
a,5,7.77,8.72
b,3,7.27,7.36
b,5,7.21,5.21
c,3,4.38,4.07
c,5,4.16,4.04
d,3,6.04,5.32
d,5,5.24,5.20
e,3,5.59,5.33
e,5,4.63,4.89
f,3,5.73,5.06
f,5,4.94,4.90
```

### `benchmark_medians.csv`

```csv
benchmark,median_ns_op,median_B_op,median_allocs_op
BenchmarkConvertSUCItoSUPI_NullScheme_EndToEnd-12,1733.50,448,11
BenchmarkConvertSUCItoSUPI_ProfileA_EndToEnd-12,153525.50,2770,41
BenchmarkConvertSUCItoSUPI_ProfileB_EndToEnd-12,164801.00,6890,173
BenchmarkConvertSUCItoSUPI_ProfileC_EndToEnd-12,148232.00,13407,43
BenchmarkConvertSUCItoSUPI_ProfileD_EndToEnd-12,324048.00,15024,54
BenchmarkConvertSUCItoSUPI_ProfileD_Add17_EndToEnd-12,320897.50,15040,55
BenchmarkConvertSUCItoSUPI_ProfileD_Add19_EndToEnd-12,321968.50,15352,41
BenchmarkConvertSUCItoSUPI_ProfileE_EndToEnd-12,336430.00,17444,76
BenchmarkConvertSUCItoSUPI_ProfileF_EndToEnd-12,327489.50,15706,70
BenchmarkEncrypt_ProfileA-12,297932.00,2621,36
BenchmarkEncrypt_ProfileB-12,108169.50,3470,45
BenchmarkEncrypt_ProfileC-12,63480.00,11360,28
BenchmarkEncrypt_ProfileD-12,403206.50,13152,43
BenchmarkEncrypt_ProfileD_Add17-12,406606.00,13152,43
BenchmarkEncrypt_ProfileD_Add19-12,400203.00,13448,28
BenchmarkEncrypt_ProfileE-12,415442.00,15592,65
BenchmarkEncrypt_ProfileF-12,407284.50,13888,60
BenchmarkDeconceal_ProfileA_DecryptOnly-12,149844.50,2064,23
BenchmarkDeconceal_ProfileB_DecryptOnly-12,156124.00,5851,147
BenchmarkDeconceal_ProfileC_DecryptOnly-12,72466.50,10536,27
BenchmarkDeconceal_ProfileD_DecryptOnly-12,244381.00,12072,37
BenchmarkDeconceal_ProfileD_Add17_DecryptOnly-12,247168.50,12072,37
BenchmarkDeconceal_ProfileD_Add19_DecryptOnly-12,241140.50,12248,23
BenchmarkParseSUCI_ProfileA-12,3418.00,400,4
BenchmarkParseSUCI_ProfileB-12,3489.50,400,4
BenchmarkParseSUCI_ProfileC-12,62050.50,1504,4
BenchmarkParseSUCI_ProfileD-12,64335.00,1504,4
```

## Final Takeaways

- `Profile C` is the strongest performance/security compromise when PQ protection is required.
- `Profiles D/E/F` add meaningful hybrid-security properties, but they do so at a large latency and throughput cost.
- `Level 5` is clearly more expensive than `Level 3` for `C-F`, with the strongest penalty on `C`.
- If this dataset is presented visually, the most persuasive plots will be:
  - end-to-end throughput vs concurrency
  - Level 5 penalty vs concurrency
  - p99 latency vs concurrency
  - benchmark `ns/op` vs `B/op`

If you want, I can next generate:

- a second markdown report focused only on graph captions and presentation narrative
- a long-form raw table for all `180` loadgen rows in CSV format
- a PowerPoint-friendly executive-summary version with shorter bullets and ready-to-use chart titles
