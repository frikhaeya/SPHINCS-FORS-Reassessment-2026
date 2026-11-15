#!/usr/bin/env python3
"""STEP 7: quantify information in the STEP 6 *simulated* HW channel.

Only uses the user's Step 6 output. No web, no new signatures, no new
cryptographic data, and no modification of the source code or existing logs.
Python 3.9+ standard library only.

Threat-model discipline:
  - The 'attacker' reads ONLY the logged HW byte to form candidate sets.
  - The logged original secret bytes are accessed only to VERIFY the logger
    and the exact-value conclusions for the two singleton weight classes.
  - This is *not* CPA, seed recovery, or a physical side-channel attack.
  - Theoretical entropy figures assume a uniformly sampled 8-bit value,
    not the signing seed, nor independence of derived FORS bytes.
"""
from pathlib import Path
from collections import Counter
import csv
import hashlib
import json
import math
import sys

ROOT = Path.cwd()
DATA_DIR = ROOT / 'step6_hidden_fors_probe_20261112'
SRC = DATA_DIR / 'step6_nonselected_leaves.bin'
MANIFEST = DATA_DIR / 'manifest.json'
OUT = ROOT / 'step7_leakage_information_20261112'
RECORD_LEN = 4 + 22 + 16 + 16  # index, 22-byte address, 16-byte secret, 16-byte HW
EXPECTED_RECORDS = 3 * 33 * 63
EXPECTED_SAMPLES = EXPECTED_RECORDS * 16


def fail(message):
    sys.exit('STEP 7 STOPPED: ' + str(message))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def hw(byte):
    return bin(byte).count('1')  # Python 3.9 compatible


def entropy(probs):
    return -sum(p * math.log(p, 2) for p in probs if p > 0)


def main():
    if not SRC.is_file() or not MANIFEST.is_file():
        fail('Step 6 output is missing; run from SPHINCS-FORS-CORRECTED root.')
    if OUT.exists():
        fail('Output folder already exists: ' + str(OUT) + ' (preserved, not overwritten).')
    try:
        metadata = json.loads(MANIFEST.read_text(encoding='utf-8'))
    except (ValueError, OSError) as ex:
        fail('Could not read Step 6 manifest: ' + str(ex))
    for field, value in [('signature_count', 3), ('keypair_count', 1),
                         ('SPX_N', 16), ('SPX_FORS_TREES', 33),
                         ('SPX_FORS_HEIGHT', 6),
                         ('hidden_leaf_records', EXPECTED_RECORDS)]:
        if metadata.get(field) != value:
            fail('Unexpected Step 6 metadata for {}: {}'.format(field, metadata.get(field)))
    raw = SRC.read_bytes()
    if len(raw) != EXPECTED_RECORDS * RECORD_LEN:
        fail('Unexpected Step 6 data size: {} (expected {})'.format(
            len(raw), EXPECTED_RECORDS * RECORD_LEN))
    expected_hash = metadata.get('output_sha256', {}).get(SRC.name)
    if expected_hash and sha256(raw) != expected_hash:
        fail('Step 6 file checksum differs from its manifest (do not continue).')
    observed = Counter()
    correct_leakage = 0
    unique_predictions = 0
    correct_unique_predictions = 0
    candidate_log_total = 0.0
    for start in range(0, len(raw), RECORD_LEN):
        record = raw[start:start + RECORD_LEN]
        # The address and ID identify a derivation, but are NOT used to guess secrets.
        secret = record[26:42]    # verification oracle only
        leak = record[42:58]      # the attacker-visible simulated measurement
        if len(secret) != 16 or len(leak) != 16:
            fail('Truncated record')
        for secret_byte, weight in zip(secret, leak):
            if weight > 8:
                fail('Invalid HW value {}'.format(weight))
            if hw(secret_byte) != weight:
                fail('Ground-truth validation failed in record {}'.format(start // RECORD_LEN))
            correct_leakage += 1
            observed[weight] += 1
            # Attacker-side candidate count uses ONLY the measurement weight.
            candidate_log_total += math.log(math.comb(8, weight), 2)
            # These are the ONLY two weights with exactly one compatible byte.
            if weight == 0 or weight == 8:
                prediction = 0x00 if weight == 0 else 0xFF
                unique_predictions += 1
                # Oracle check AFTER making the public-leakage-only prediction.
                if secret_byte == prediction:
                    correct_unique_predictions += 1
    if correct_leakage != EXPECTED_SAMPLES:
        fail('Unexpected number of bytes')
    if correct_unique_predictions != unique_predictions:
        fail('Singleton candidate verification failed')
    n = correct_leakage
    probs = [math.comb(8, w) / 256.0 for w in range(9)]
    theory_Hw = entropy(probs)
    theory_Hx_given_Hw = 8.0 - theory_Hw
    observed_probabilities = [observed[w] / n for w in range(9)]
    empirical_Hw = entropy(observed_probabilities)
    empirical_mean_log_candidates = candidate_log_total / n
    results = {
        'purpose': 'information characterization of the original HW-only software model on unselected FORS leaves',
        'status': 'descriptive leakage analysis; NOT CPA or key recovery',
        'provenance': {
            'input_file': str(SRC.relative_to(ROOT)),
            'sha256': sha256(raw),
            'step6_manifest_sha256': sha256(MANIFEST.read_bytes()),
            'signatures': 3,
            'nonselected_leaf_records': EXPECTED_RECORDS,
            'measurement_bytes': n
        },
        'measurement': 'one exact Hamming-weight number 0..8 per 8-bit secret-derived byte',
        'weight_histogram': {str(w): observed[w] for w in range(9)},
        'candidate_count_given_weight': {str(w): math.comb(8, w) for w in range(9)},
        'fully_determined_values_from_HW_only': {
            'weight_0_means_byte_0x00': observed[0],
            'weight_8_means_byte_0xFF': observed[8],
            'total_singleton_candidate_bytes': unique_predictions,
            'ground_truth_validation_matches': correct_unique_predictions,
            'fraction_of_measurement_bytes': unique_predictions / n,
        },
        'empirical_descriptive_metrics': {
            'observed_weight_histogram_shannon_entropy_bits': empirical_Hw,
            'mean_log2_number_of_compatible_bytes': empirical_mean_log_candidates,
        },
        'uniform_independent_byte_reference_ONLY': {
            'theoretical_entropy_of_HW_bits': theory_Hw,
            'theoretical_conditional_byte_entropy_given_HW_bits': theory_Hx_given_Hw,
            'theoretical_singleton_fraction': 2 / 256,
            'assumption': 'A uniformly random, standalone 8-bit secret byte; NOT an estimate of seed entropy or attack success.'
        },
        'limits': [
            'All measurement values are simulated as exact HW(secret), not physical leakage.',
            'Three signatures are a technical smoke test, not sufficient for population or key-security claims.',
            'The selected targets are non-selected FORS derived leaves, not the seed.',
            'Knowing a leaf byte weight does not imply recovering the signing seed or forging a signature.',
            'The ground-truth bytes are read only for validation, never for candidate creation.',
            'No CPA hypothesis or recoverability claim is made.'
        ]
    }
    OUT.mkdir()
    (OUT / 'step7_aggregate_results.json').write_text(
        json.dumps(results, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    with (OUT / 'step7_hw_histogram.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['hamming_weight','observed_count','observed_fraction',
                         'reference_fraction_uniform_byte','compatible_byte_values'])
        for w in range(9):
            writer.writerow([w, observed[w], '{:.9f}'.format(observed[w]/n),
                             '{:.9f}'.format(probs[w]), math.comb(8, w)])
    print('STEP 7: exact-HW channel analysis, using Step 6 data ONLY')
    print('Input checksums: PASS')
    print('Non-selected leaf derivations:', EXPECTED_RECORDS)
    print('8-bit measurement samples:', n)
    print('HW(secret) validation: {}/{}'.format(correct_leakage, n))
    print('\nHW value  Observed count  Compatible 8-bit bytes')
    for w in range(9):
        print('{:>4} {:>15} {:>21}'.format(w, observed[w], math.comb(8, w)))
    print('\nUniquely determined byte values by HW alone (w=0 or 8):', unique_predictions)
    print('Exact-value predictions verified against ground truth: {}/{}'.format(
        correct_unique_predictions, unique_predictions))
    print('Share of logged byte values uniquely determined: {:.4f}%'.format(
        100 * unique_predictions / n))
    print('Empirical Shannon entropy of the observed HW histogram: {:.6f} bits'.format(empirical_Hw))
    print('Uniform 8-bit reference: H(HW)={:.6f}, H(byte|HW)={:.6f} bits'.format(
        theory_Hw, theory_Hx_given_Hw))
    print('CAUTION: these are byte-level model properties, NOT seed entropy or CPA recovery.')
    print('STEP 7 PASS: saved aggregate-only CSV and JSON to', OUT)
    print('Do NOT share step6_nonselected_leaves.bin: it contains private ground truth.')


if __name__ == '__main__':
    main()
