# SPHINCS+ FORS — corrected follow-up research (v2.0.0-rc1)

[Read the 2026 preprint (PDF)](paper/SPHINCS_FORS_Reassessment_Preprint.pdf)

**Research artifact — not production cryptographic software.** See the security limitations and third-party notices below.

This repository contains the corrected 2026 follow-up to my 2025 Master's research on SPHINCS+ FORS. It is maintained separately from the original thesis artifact, which contains earlier experimental methods and interpretations.

## Research background

### Master's thesis (2025)

This project builds upon research conducted for my Master's degree in Computer Science (Security) at the University of Passau, Germany.

The original work investigated side-channel analysis of SPHINCS+ SHA-256-128f-simple, focusing on FORS. It developed software instrumentation, a Hamming-weight leakage model, grouped correlation analysis, and fixed-versus-random leakage diagnostics.

The original implementation and experimental pipeline are preserved separately in the [2025 thesis artifact](https://github.com/frikhaeya/sphincs-fors-cpa-artifact), tag `v1.0`. Its earlier CPA interpretation should not be treated as demonstrated secret-key recovery.

### Follow-up research (2026)

After completing the thesis, I reassessed the code, mathematical assumptions, experimental results, and interpretation.

The follow-up work corrected the FORS logging layout, distinguished selected secret values exposed in public signatures from non-selected derived leaves, examined address-grouping limitations, and conducted restricted PRF hypothesis experiments.

The PRF experiments assume 14 known seed bytes and use noiseless software-derived Hamming weights to test hypotheses over a remaining two-byte suffix. They do not demonstrate physical side-channel extraction or recovery of a complete SPHINCS+ signing seed.

The accompanying preprint documents the corrected methods, experimental findings, and limitations.

## Parameter-set identification

The implementation uses the SPHINCS+-128f parameter configuration:
n=16, h=66, d=22, FORS height=6, FORS trees=33, and WOTS w=16.

These values match the official SPHINCS+ reference project's
SPHINCS+-128f parameter table, including its 17,088-byte
signature length.

The implementation is based on historical SHA-256 source code,
with research instrumentation and subsequent corrections.
Parameter agreement does not independently establish complete
cross-version implementation compatibility.

Reference: https://github.com/sphincs/sphincsplus

## Source-code provenance

The starting implementation was obtained from the [Gorachya SPHINCS+ SHA-256-128f-simple repository](https://github.com/Gorachya/sphincs-sha256-128f-simple), as referenced in the Master's thesis.

A comparison with the [official SPHINCS+ implementation](https://github.com/sphincs/sphincsplus) indicates substantial code similarity. This does not by itself establish exact version ancestry or the licensing status of intermediary modifications.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for documented upstream sources, relevant licensing information, and applicable licensing notices.

## What's corrected

- Native `SPX_N=16`, `SPX_FORS_TREES=33`: selected FORS logging was changed to one 16-byte block per tree (528 bytes per signature).
- Raw secret and exact-HW logging is **off by default**. `make` builds a library and produces no signatures or logging files. Explicit `-DENABLE_CPA_LOGGING` enables **dangerous research-only** logging. Never enable it for real signing keys.
- The old `log_sk_seed` call is inactive; deprecated 32-byte logging helpers and the KAT driver that wrote private key material to `.rsp` files were removed.
- Original `attack-code` and pre-correction result figures were excluded. The old zero-offset hypothesis is not secret-key recovery.

## Scientific scope

The preprint documents public-signature reconstruction of selected FORS byte HW, non-selected-leaf HW characterization, and restricted two-byte PRF-suffix hypothesis tests assuming 14 known seed bytes and noiseless software measurements. The latter tests are **not** drawn from the same signing observations. No full signing-seed recovery or measured physical side channel is claimed.

## Reproduce fresh trials on a *disposable* test-only machine or working directory

Requirements: Python 3.9+, C compiler, OpenSSL development headers/libraries; the source is provided for inspection. On macOS the scripts can detect Homebrew OpenSSL. `make` alone never logs secret values.

On macOS with Homebrew OpenSSL, if the compiler cannot find `openssl/conf.h`, build using:

```sh
make -C sphincs-sha256-128f-code CPPFLAGS="-I$(brew --prefix openssl@3)/include"
```


```sh
make -C sphincs-sha256-128f-code
sh run_test.sh 3
sh run_test.sh 4
sh run_test.sh 5
sh run_test.sh 6
sh run_test.sh 7
sh run_test.sh 8
sh run_test.sh 9
sh run_test.sh 10
sh run_test.sh 11
python3 evidence/verify_paper_aggregates.py
```

The Python scripts use fixed output directory names for experiment integrity and refuse overwriting existing runs. The generated directories include raw private derived leaves, private test seeds and known-address measurements. **Do not commit or upload any generated output**, even if it appears to be public inputs. The `.gitignore` is defense in depth, *not proof* that a file or Git history is safe.

### Reproducibility and randomized trials

The numerical results reported in the accompanying manuscript correspond to the original archived experiment aggregates provided in `evidence/`.

The reproduction scripts regenerate experimental observations using fresh synthetic test fixtures. Consequently, intermediate candidate counts and uniqueness frequencies may vary between runs. Reproduction should be evaluated against the stated experimental protocol, consistency checks, and successful validation against each run's withheld test fixture, rather than requiring identical intermediate statistics.

The archived aggregate verifier checks consistency of the published results; it does not independently reconstruct the original private fixtures. Generated seed files, secret-derived binary data, and private candidate outputs must not be committed or distributed.

The restricted PRF experiments assume 14 of 16 seed bytes are already known and use exact software-derived Hamming-weight observations. Their successful reproduction does not demonstrate physical side-channel exploitation or unrestricted signing-seed recovery.

## Security and Intended Use

This repository is a reproducible research artifact for the
methodological reassessment of SPHINCS+ FORS software leakage.
It is not a production-hardened cryptographic implementation
and must not be used to protect real-world signing keys.

### Research logging

Research instrumentation is disabled by default. The Makefile
does not define `ENABLE_CPA_LOGGING` unless explicitly requested.

When enabled, the research logger writes secret-derived bytes,
simulated Hamming-weight leakage, and FORS indices into local
binary files. These files are opened in append mode and are
not encrypted by the logger.

Use this instrumentation only with synthetic keys in an isolated
test environment. Never commit or distribute generated signing
keys, raw secret-derived logs, or private experiment fixtures.

### Evidence handling

The public evidence archive contains aggregate research records,
not the original private seed fixtures. Certain aggregate reports
include SHA-256 fingerprints of private experimental files.
These fingerprints are not the underlying raw files.

The aggregate verifier checks numerical consistency; it cannot
independently authenticate the original private fixtures.

### Release limitations

The research uses exact software-generated leakage observations,
not measured power or electromagnetic traces.

The experiments do not demonstrate unrestricted signing-seed
recovery, physical side-channel exploitation, or forgery.

Third-party licensing and attribution are documented in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).



## Public evidence

`evidence/step12_paper_evidence.zip` contains aggregate reports supplied by the author; these are numerical audit records, not the original private fixtures. `evidence/verify_paper_aggregates.py` checks aggregates only. `paper/` contains the reviewed IEEE-format preprint, not an IEEE-accepted paper.


## Licensing

The independently authored research components are provided
under the MIT License described in
[RESEARCH_CODE_LICENSE.md](RESEARCH_CODE_LICENSE.md).

The underlying SPHINCS+ implementation and NIST-origin
components retain their applicable third-party terms.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
