# Security Policy

## Status of this project

This is a **research / proof-of-concept** tool for evaluating and benchmarking
classical, post-quantum, and hybrid SUCI protection schemes. It is **not** a
production component, is **not** part of any 3GPP-certified product, and must not
be used to protect real subscriber identities or in any production network.

Several profiles are **non-standard tool extensions** (Profiles E, F, and G, and
the ML-KEM-1024 / NIST Level 5 option for Profiles C-F) and exist only for
comparative study.

## Reporting a vulnerability

If you discover a security issue in this code, please report it privately via the
repository's GitHub Security Advisories ("Report a vulnerability") rather than
opening a public issue. Please include steps to reproduce and the affected
version/commit.

We aim to acknowledge reports within a reasonable time. As a research project,
there are no formal SLAs or guaranteed fixes.

## Scope notes

- Do not commit private keys or real subscriber data. The `.gitignore` excludes
  `*.pem`, `*.key`, and `test-keys/` directories.
- All example identifiers (IMSI/SUPI/SUCI) in the docs are synthetic test values.
