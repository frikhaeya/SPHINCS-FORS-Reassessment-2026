# Third-Party Attribution and Licensing

## SPHINCS+ Reference Implementation

The underlying SPHINCS+ cryptographic implementation is based on
the reference implementation developed by the SPHINCS+ team.

Official source:
https://github.com/sphincs/sphincsplus

The official project makes most implementation code available
under CC0-1.0, 0BSD, or MIT-0 licensing options, subject to
file-specific exceptions.

The CC0 notice is included in:
`THIRD_PARTY_LICENSES/CC0-1.0.txt`

The original SPHINCS+ implementation is not claimed as an
original contribution of this research.

## Historical Implementation Source

The historical starting implementation used in the author's
2025 Master's thesis was obtained from:

https://github.com/Gorachya/sphincs-sha256-128f-simple

This source is acknowledged as part of the implementation's
development history. No separate redistribution license from
that repository is asserted here.

## NIST Random Number Generation Code

The files `rng.c` and `rng.h` originate from NIST-provided
sample RNG software attributed to Lawrence E. Bassham (2017).

Their original source headers are preserved.

The included `rng.c` contains formatting differences relative
to the historical reference version; the origin and date of
those formatting changes are not established.

NIST is acknowledged as the source of the RNG implementation.
No NIST endorsement is implied.

The NIST software disclaimer and redistribution notice are
provided in:

`THIRD_PARTY_LICENSES/NIST-SOFTWARE-NOTICE.txt`

## SHA-256 Implementation

The `sha256.c` implementation retains its existing attribution
to the public-domain SHA-256 implementation associated with
D. J. Bernstein and SUPERCOP.

## Original Research Contributions

The FORS research instrumentation, Hamming-weight leakage
modeling, logging modifications, experimental scripts,
methodological corrections, and reproducibility workflows
were independently developed by Eya Frikha during her 2025
Master's research and subsequent 2026 reassessment.

The research methodology was informed by earlier academic
work acknowledged in the Master's thesis.

These original contributions are distinct from the underlying
third-party cryptographic implementation.

## Intended Use

This repository is provided for research and reproducibility,
not production cryptographic deployment.

Applicable third-party licensing and notice requirements
remain in effect. No blanket license for all third-party code
is asserted by this document.
