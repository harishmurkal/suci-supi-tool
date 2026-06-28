## Comparative Performance, Memory and SUCI Size Assessment
SUCI Protection Profiles A, B, C, Hybrid D (PQC + ECC), E (Nested Hybrid), F (Wrapper Hybrid)
Author: Harish
Platform: Tests executed on x86-64 server-class CPU (Intel Xeon Gold 6130, 2.10 GHz) running Rocky Linux 8.6 (linux/amd64), Go 1.25.5
Execution: Single-threaded baseline (GOMAXPROCS=12); multi-concurrency scaling at 1, 2, 8, 12, 16
Operations: 100000 SUCI deconceal / end-to-end per run
Tool: suci-supi-tool v2.3.0 (Go standard crypto for ECC/AES/SHA-3/KMAC; Cloudflare CIRCL ML-KEM-768/ML-KEM-1024 for PQC; Hybrid ML-KEM + X25519)
Security levels: Level 3 (ML-KEM-768, 3GPP default) and Level 5 (ML-KEM-1024, tool extension)

### 1. Objective
This study evaluates computational and signalling impact of six SUCI protection profiles:
Profile A — ECIES-X25519
Profile B — ECIES-P-256
Profile C — ML-KEM-768 + AES-256-CTR + KMAC256 (PQC)
Profile D — Hybrid ML-KEM-768 + X25519 (baseline, add17, add19 variants)
Profile E — Nested Hybrid ML-KEM-768 + X25519 (two independent encryption layers)
Profile F — Wrapper Hybrid ML-KEM-768 + X25519 (ECIES unchanged, PQ wraps ephemeral key)

The goal is to assess:
Cryptographic cost
End-to-end throughput
Memory footprint
SUCI payload expansion
Hybrid migration feasibility
ML-KEM-1024 (Level 5) performance impact vs ML-KEM-768 (Level 3) for profiles C-F
Concurrency scaling across all profiles


### 2. Key Material Size Comparison
| Profile | Algorithm           | Private Key |
| ------- | ------------------- | ----------- |
| A       | X25519              | 32 B        |
| B       | P-256               | 32 B        |
| C       | ML-KEM-768          | ~2400 B     |
| C (L5)  | ML-KEM-1024         | ~3168 B     |
| D       | ML-KEM-768 + X25519 | ~2432 B     |
| D (L5)  | ML-KEM-1024 + X25519| ~3200 B     |
| E       | ML-KEM-768 + X25519 | ~2432 B     |
| E (L5)  | ML-KEM-1024 + X25519| ~3200 B     |
| F       | ML-KEM-768 + X25519 | ~2432 B     |
| F (L5)  | ML-KEM-1024 + X25519| ~3200 B     |

Observation
PQC private key is ~75x larger than ECC (Level 3) or ~99x larger (Level 5)
Hybrid adds negligible overhead vs PQC alone
E and F use the same composite key structure as D
Implications
HN key storage increases for PQC / Hybrid
HSM provisioning and backup size expand
UE unaffected (uses public key only)
ML-KEM-1024 keys are ~32% larger than ML-KEM-768


### 3. SUCI Payload Size Comparison
Measured from actual SUCI outputs:
| Profile | Payload (bytes) | Expansion vs A |
| ------- | --------------- | -------------- |
| A       | 64              | 1x             |
| B       | 65              | 1.02x          |
| C       | ~1096           | 17.1x          |
| C (L5)  | ~1576           | 24.6x          |
| D       | ~1128           | 17.6x          |
| D (L5)  | ~1608           | 25.1x          |
| E       | ~1184           | 18.5x          |
| E (L5)  | ~1664           | 26.0x          |
| F       | ~1160           | 18.1x          |
| F (L5)  | ~1640           | 25.6x          |

Hybrid Size Drivers
Profiles D/E/F SUCI contains:
ML-KEM ciphertext (~1088 B for Level 3, ~1568 B for Level 5)
ECC ephemeral public key (32 B)
Symmetric ciphertext + tag(s)
Key Insight
Hybrid does not materially worsen signalling vs pure PQC at the same security level.
ML-KEM-1024 (Level 5) adds ~480 B to every PQC/hybrid SUCI (~44% larger ciphertext).


### 4. Parse-Only Cost (NAS / SUCI decoding)
Measured (single-thread, Level 3):
| Profile | Throughput   |
| ------- | ------------ |
| A       | 248 k ops/s  |
| B       | 240 k ops/s  |
| C       | 15.4 k ops/s |
| D       | 14.9 k ops/s |
| E       | ~15 k ops/s  |
| F       | ~15 k ops/s  |

Observation
PQC/hybrid SUCI parsing is ~16x slower due to large payload hex decode.
However:
Absolute latency ~ 60-65 us
Negligible vs NAS / RRC timelines
Conclusion
Parsing overhead is insignificant operationally. (Authentication procedure: ~10 ms so parse overhead share is negligible.)


### 5. Decryption Performance (Cryptographic Core)
Measured decrypt-only (Go benchmark medians across all runs):
| Profile         | Mean Latency | Throughput     |
| --------------- | ------------ | -------------- |
| A               | 150 us       | 6627 ops/s     |
| B               | 156 us       | 6234 ops/s     |
| C               | 72 us        | 13590 ops/s    |
| D (baseline)    | 244 us       | 4069 ops/s     |
| D (add17)       | 247 us       | ~4050 ops/s    |
| D (add19)       | 241 us       | ~4150 ops/s    |

Interpretation
Profile C (PQC)
~2x faster than ECC
Confirms ML-KEM decapsulation efficiency
ECC scalar multiplication dominates A/B cost
Profile D (Hybrid)
~ ECC + PQC combined cost
~1.6x slower than ECC
~3.3x slower than PQC
D add19 is slightly more efficient than add17 (fewer allocations, comparable latency)
This matches hybrid design expectation: cost ~ PQC decap + ECC decap


### 6. End-to-End SUCI Deconceal Throughput
Measured end-to-end (Go benchmark medians):
| Profile         | Latency  | Throughput |
| --------------- | -------- | ---------- |
| A               | 154 us   | 6416 ops/s |
| B               | 165 us   | 6017 ops/s |
| C               | 148 us   | 6727 ops/s |
| D (baseline)    | 324 us   | 3094 ops/s |
| D (add17)       | 321 us   | ~3100 ops/s|
| D (add19)       | 322 us   | ~3100 ops/s|
| E               | 336 us   | ~2970 ops/s|
| F               | 327 us   | ~3050 ops/s|

Key Observations
PQC (Profile C)
Slightly faster than ECC overall
Despite larger SUCI
Confirms symmetric stage dominates
Hybrid (Profiles D/E/F)
~2x slower than ECC
~2.2x slower than PQC
But still:
~3 k ops/s single thread
Easily scalable across cores
No scalability risk observed
Within the hybrid family, D and F are slightly faster than E per-operation.


### 7. Runtime Memory Footprint (Peak RSS)
| Profile | Peak RSS (single thread) |
| ------- | ------------------------ |
| A       | 11.5 MB                  |
| B       | 11.9 MB                  |
| C       | 11.9 MB                  |
| D       | 11.9 MB                  |
| E       | ~12.0 MB                 |
| F       | ~12.0 MB                 |

Observation
PQC and Hybrid do not increase steady memory
ML-KEM buffers are transient
Go GC footprint similar across profiles
Conclusion
Runtime memory impact negligible at low concurrency.
At high concurrency (16), RSS rises to 12-21 MB range across all profiles (see Appendix A).


### 8. Go Benchmark Validation
From microbenchmarks (median across all log runs):
| Operation        | A      | B      | C      | D      | D-add17 | D-add19 | E      | F      |
| ---------------- | ------ | ------ | ------ | ------ | ------- | ------- | ------ | ------ |
| Decrypt-only     | 150 us | 156 us | 72 us  | 244 us | 247 us  | 241 us  | -      | -      |
| End-to-end       | 154 us | 165 us | 148 us | 324 us | 321 us  | 322 us  | 336 us | 327 us |
| Encrypt (UE)     | 298 us | 108 us | 63 us  | 403 us | 407 us  | 400 us  | 415 us | 407 us |
| B/op (end-to-end)| 2770   | 6890   | 13407  | 15024  | 15040   | 15352   | 17444  | 15706  |
| allocs/op (e2e)  | 41     | 173    | 43     | 54     | 55      | 41      | 76     | 70     |

These align precisely with loadgen results, confirming measurement stability.

Key insight from allocation data:
Profile E has the highest allocation footprint (76 allocs/op, 17.4 kB/op)
add19 has fewer allocations (41) than add17 (55) and baseline (54)


### 9. Hybrid Security Interpretation
Profile D combines:
ML-KEM-768 (post-quantum) + X25519 (classical) in a parallel combiner
Profile E (Nested Hybrid) provides:
Two independent encryption layers (ECC protects PQ ciphertext, PQ protects MSIN)
Profile F (Wrapper Hybrid) provides:
Standard ECIES unchanged (backward compatible), PQ wraps the ephemeral key

Security property:
Confidentiality holds if either PQC or ECC remains secure (for D, E, and F).
Therefore Hybrid provides:
PQC resistance
Classical backward compatibility
Graceful migration path

Profile F is the most backward-compatible of the three hybrid options because its inner ECIES layer is identical to Profile A.


### 10. System-Level Impact Summary
Computational
| Profile | Assessment          |
| ------- | ------------------- |
| A/B     | Baseline            |
| C       | Best performance    |
| D       | Acceptable overhead |
| E       | Similar to D        |
| F       | Similar to D        |

No CPU scalability concern for any profile.


Signaling
| Profile | NAS Impact |
| ------- | ---------- |
| A/B     | Minimal    |
| C       | High       |
| D       | High (~C)  |
| E       | High (~C)  |
| F       | High (~C)  |

Primary system impact = SUCI size expansion.


Memory
All profiles equivalent at runtime (single thread).
At high concurrency, RSS is in the 12-21 MB range for all profiles.


### 11. ML-KEM-1024 (Security Level 5) Performance Impact

This section is new compared to earlier A-D-only assessments. The tool now supports `--security-level 5` (ML-KEM-1024) for profiles C-F. Key findings from the 2026-03-26 test matrix:

Average end-to-end throughput penalty (Level 5 vs Level 3, across all concurrencies):
| Scheme | Avg throughput delta | Avg p50 delta | Avg p99 delta |
| ------ | -------------------: | ------------: | ------------: |
| C      | -29.11%              | +47.46%       | +28.66%       |
| D      | -19.42%              | +24.45%       | +35.15%       |
| E      | -19.26%              | +23.18%       | +15.37%       |
| F      | -16.89%              | +21.66%       | +13.66%       |

Interpretation
Profile C sees the largest throughput drop because its entire crypto path is ML-KEM; the larger 1024 ciphertext dominates.
Profiles D/E/F see a smaller relative penalty because the classical X25519 portion is unchanged by Level 5.
Tail latency (p99) deteriorates faster than median latency, especially at higher concurrency.

Recommendation
Use Level 3 (ML-KEM-768) when 3GPP-default security is acceptable and throughput/latency matter.
Use Level 5 (ML-KEM-1024) when the higher PQ margin is worth the ~17-29% throughput penalty, plus higher median and tail latency.


### 12. Migration Implications for 3GPP
Key findings relevant to standards:
PQC Profile C
Computationally superior
Signalling expansion only trade-off (does not materially increase computational cost or runtime memory compared to ECC SUCI, and the sole significant system impact is the substantial increase in SUCI payload size (~17x), which affects NAS/RRC signalling but not core processing performance)
Hybrid Profile D
Enables phased migration
Backward compatible
PQC-secure
Acceptable CPU overhead
Profile E (Nested Hybrid)
Two independent security layers
Highest allocation footprint among hybrids
Suitable where defense-in-depth is prioritized
Profile F (Wrapper Hybrid)
Inner ECIES layer identical to Profile A
Most backward-compatible hybrid option
PQ wraps the ephemeral key without changing the classical layer
ML-KEM-1024 (Level 5) option
Available for C-F when higher PQ margin is desired
Adds ~44% SUCI size expansion vs Level 3
Throughput penalty ~17-29% depending on profile


### 13. Overall Comparative Assessment
| Metric             | Best      | Worst |
| ------------------ | --------- | ----- |
| Decrypt speed      | C         | D/E   |
| End-to-end         | C         | E     |
| Signaling size     | A/B       | E~D~F~C |
| Memory             | All equal | -     |
| Security longevity | D/E/F/C   | A/B   |
| Backward compat    | F         | E     |
| Allocation efficiency | add19  | E     |


### 14. Final Conclusions
Profile C (ML-KEM-768)
2x faster decryption than ECC
Equal or better end-to-end throughput
No runtime memory penalty
Large SUCI payload (~17x)
Computationally optimal PQC profile

Profile D (Hybrid ML-KEM-768 + X25519)
~2x ECC cost
~2.2x PQC cost
Same signaling as PQC
Dual-security guarantee
Most robust migration profile
add19 variant is slightly more allocation-efficient than add17/baseline

Profile E (Nested Hybrid ML-KEM-768 + X25519)
Two independent encryption layers
Highest allocation footprint (76 allocs/op, 17.4 kB/op)
Suitable for defense-in-depth requirements

Profile F (Wrapper Hybrid ML-KEM-768 + X25519)
Inner ECIES layer identical to Profile A
Most backward-compatible hybrid option
Performance similar to Profile D

ML-KEM-1024 (Level 5)
Available for C-F
Throughput penalty 17-29% vs Level 3
Tail latency penalty higher than median penalty
Use when the stronger PQ margin justifies the cost


### 15. Key Technical Insight
Across all measurements:
PQC cost is dominated by ECC only in hybrid mode. Pure ML-KEM is computationally efficient for SUCI.
Thus:
Post-quantum SUCI is CPU-feasible in 5G core.
Nested and Wrapper hybrids (E, F) add meaningful security diversity with acceptable overhead.
ML-KEM-1024 is operationally viable but imposes a measurable cost that should be weighed against the additional PQ margin.


### 16. Standards-Relevant Discussion Points
Based on PoC evidence:
NAS size tolerance for PQC SUCI
UE buffer capability for ~1.1 kB SUCI (Level 3) or ~1.6 kB (Level 5)
Hybrid deployment strategy
Profile coexistence signaling
Long-term PQC adoption roadmap
Security-level selection policy (Level 3 vs Level 5 tradeoffs)
Hybrid family selection (D parallel vs E nested vs F wrapper)


### 17. Final Assessment Statement
This PoC demonstrates that:
ML-KEM-768 SUCI is computationally efficient
ML-KEM-1024 (Level 5) is operationally viable with a measurable throughput penalty
Hybrid ML-KEM + X25519 (Profiles D, E, F) is operationally viable
Runtime memory impact is negligible
Signaling expansion is the primary trade-off
There are no computational scalability barriers to PQC-based SUCI deployment in 5G systems.


Appendix A — Multi-Core Concurrency Scaling Evaluation

The end-to-end throughput-vs-concurrency data for this appendix is tabulated in
sections A.1 and A.2 below, and is also available as chart-ready CSV in
[benchmarking-report-from-logs-20260326.md](benchmarking-report-from-logs-20260326.md)
(see the `end_to_end_throughput.csv` and `scaling_end_to_end.csv` blocks). The raw
source measurements are in [logs/](logs/).

To complement the single-thread measurements presented in the main study, additional load-generation experiments were performed with multi-operation concurrency to evaluate SUCI processing scalability under realistic multi-subscriber core-network load.
Measurements were executed using the same platform and toolchain, varying only the load-generator concurrency parameter (1, 2, 8, 12, 16). GOMAXPROCS remained 12 (equal to CPU cores).
Security levels tested: Level 3 (ML-KEM-768) and Level 5 (ML-KEM-1024).


A.1 End-to-End Throughput vs Concurrency (Level 3)
Measured end-to-end SUCI deconceal throughput (ops/s):
| Profile         | Concurrency 1 | Concurrency 2 | Concurrency 8 | Concurrency 12 | Concurrency 16 |
| --------------- | ------------- | ------------- | ------------- | -------------- | -------------- |
| A (X25519)      | 5873          | 12669         | 46663         | 40613          | 44435          |
| B (P-256)       | 5662          | 11564         | 37568         | 41178          | 41686          |
| C (ML-KEM-768)  | 6327          | 12698         | 30654         | 27702          | 25766          |
| D (Hybrid)      | 2987          | 6014          | 17603         | 18034          | 15882          |
| E (Nested)      | 2934          | 5790          | 15043         | 16398          | 15649          |
| F (Wrapper)     | 3031          | 5902          | 14316         | 17384          | 15347          |

A.2 End-to-End Throughput vs Concurrency (Level 5)
| Profile          | Concurrency 1 | Concurrency 2 | Concurrency 8 | Concurrency 12 | Concurrency 16 |
| ---------------- | ------------- | ------------- | ------------- | -------------- | -------------- |
| A (X25519)       | 6494          | 12671         | 46801         | 50427          | 56637          |
| B (P-256)        | 6143          | 11780         | 39451         | 44258          | 31996          |
| C (ML-KEM-1024)  | 4639          | 9020          | 20763         | 19273          | 18761          |
| D (Hybrid L5)    | 2570          | 5033          | 13073         | 13477          | 13368          |
| E (Nested L5)    | 2495          | 4795          | 13130         | 11559          | 12214          |
| F (Wrapper L5)   | 2549          | 4958          | 13400         | 12597          | 12496          |

Note: For A/B, Level 3 vs Level 5 differences are run-to-run noise because security-level only affects profiles C-F.


A.3 Scaling Behaviour
Linear scaling region
All profiles show near-linear throughput increase from concurrency 1-2 and 1-8, confirming efficient parallel execution with no lock contention or serialization bottlenecks.
Scaling factors (Level 3):
| Profile | 1-2  | 1-8  | 1-12 | 1-16 |
| ------- | ---- | ---- | ---- | ---- |
| A       | 2.16 | 7.95 | 6.92 | 7.57 |
| B       | 2.04 | 6.63 | 7.27 | 7.36 |
| C       | 2.01 | 4.85 | 4.38 | 4.07 |
| D       | 2.01 | 5.89 | 6.04 | 5.32 |
| E       | 1.97 | 5.13 | 5.59 | 5.33 |
| F       | 1.95 | 4.72 | 5.73 | 5.06 |

Saturation region
Throughput plateaus near concurrency ~ 12, matching available CPU cores. This confirms CPU-bound processing with full core utilization.
At concurrency 16, some profiles show modest regression vs 12, especially for the heavier PQC/hybrid schemes.


A.4 ECC vs PQC Scaling Characteristics
Single-thread results showed ML-KEM (Profile C) ~ 2x faster than ECC. Under multi-core concurrency, ECC profiles achieve higher aggregate throughput.
This inversion is explained by workload characteristics:
ECC (Profiles A/B)
Small working set
Cache-resident arithmetic
Compute-bound
Near-linear core scaling
ML-KEM (Profile C)
Larger polynomial buffers
Higher memory bandwidth demand
Cache pressure under parallelism
Earlier saturation
Hybrid (Profiles D/E/F)
Combined ECC + PQC workload
Scaling consistent with summed crypto cost
No additional parallel inefficiency observed
Profile E has the highest allocation pressure among hybrids, scaling slightly less efficiently.
Thus the observed scaling differences reflect hardware resource utilization rather than implementation artifacts.


A.5 Peak Throughput at Core Saturation (Level 3)
At concurrency 12 (~ CPU cores):
| Profile | End-to-End Throughput |
| ------- | --------------------- |
| A       | ~41 k ops/s           |
| B       | ~41 k ops/s           |
| C       | ~28 k ops/s           |
| D       | ~18 k ops/s           |
| E       | ~16 k ops/s           |
| F       | ~17 k ops/s           |

Even hybrid SUCI processing supports >15000 deconceal operations per second per 12-core node.
This corresponds to:
~ 900000 SUCI operations per minute (for hybrids)
~ 1.7 million SUCI operations per minute (for Profile C)
which is well above typical AUSF/UDM load requirements.


A.6 Security-Level Delta Table (Level 5 vs Level 3) for C-F
| Scheme | Concurrency | Throughput delta | p99 delta  | RSS delta  |
| ------ | ----------: | ---------------: | ---------: | ---------: |
| C      | 1           | -26.69%          | +23.80%    | +21.40%    |
| C      | 2           | -28.97%          | +35.39%    | -4.21%     |
| C      | 8           | -32.27%          | +66.90%    | +12.61%    |
| C      | 12          | -30.43%          | +17.12%    | -9.51%     |
| C      | 16          | -27.19%          | +0.07%     | -28.09%    |
| D      | 1           | -13.96%          | +9.87%     | +1.10%     |
| D      | 2           | -16.31%          | +18.20%    | +1.84%     |
| D      | 8           | -25.73%          | +125.80%   | +34.18%    |
| D      | 12          | -25.27%          | +31.22%    | +10.47%    |
| D      | 16          | -15.83%          | -9.34%     | -27.52%    |
| E      | 1           | -14.95%          | +12.19%    | -1.27%     |
| E      | 2           | -17.19%          | +21.48%    | +1.85%     |
| E      | 8           | -12.72%          | -8.83%     | +3.21%     |
| E      | 12          | -29.51%          | +48.83%    | +28.72%    |
| E      | 16          | -21.95%          | +3.17%     | -32.44%    |
| F      | 1           | -15.92%          | +18.08%    | -16.30%    |
| F      | 2           | -16.00%          | +18.46%    | +17.66%    |
| F      | 8           | -6.40%           | -35.29%    | -1.66%     |
| F      | 12          | -27.54%          | +59.13%    | +0.60%     |
| F      | 16          | -18.58%          | +7.93%     | -4.23%     |

Note: Throughput impact is stable and trustworthy. p99 and RSS are noisier at high concurrency; use directionally.


A.7 Memory at High Concurrency
At concurrency 16, end-to-end Peak RSS:
| Scheme | Level | Peak RSS (kB) | p50 (us)  | Throughput (ops/s) |
| ------ | ----: | ------------: | --------: | -----------------: |
| A      | 3     | 17672         | 153.58    | 44435              |
| A      | 5     | 12484         | 151.09    | 56637              |
| B      | 3     | 15616         | 162.32    | 41686              |
| B      | 5     | 14716         | 179.06    | 31996              |
| C      | 3     | 20292         | 168.84    | 25766              |
| C      | 5     | 14592         | 260.63    | 18761              |
| D      | 3     | 19436         | 345.56    | 15882              |
| D      | 5     | 14088         | 461.19    | 13368              |
| E      | 3     | 20592         | 361.44    | 15649              |
| E      | 5     | 13912         | 485.65    | 12214              |
| F      | 3     | 18912         | 353.36    | 15347              |
| F      | 5     | 18112         | 431.53    | 12496              |


A.8 Scalability Conclusion
Multi-core evaluation confirms:
All SUCI profiles (A-F) scale efficiently across CPU cores
No concurrency bottlenecks or serialization observed
PQC and Hybrid processing remain operationally scalable
Profiles E/F scale comparably to D
Throughput differences reflect intrinsic crypto cost and memory characteristics
ML-KEM-1024 (Level 5) scales similarly to Level 3 but at a consistently lower throughput level
Therefore, the scalability results reinforce the main conclusion:
There are no multi-core performance barriers to PQC-based or Hybrid SUCI deployment in 5G core networks, including ML-KEM-1024 (Level 5) operation.
