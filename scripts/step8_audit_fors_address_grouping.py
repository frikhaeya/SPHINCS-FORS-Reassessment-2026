#!/usr/bin/env python3
"""Step 8: source-grounded grouping audit of Step 6 FORS leakage records.

Python 3.9+, standard library only. Read-only; no code modifications and no
new signatures. Uses only files produced by step6_hidden_fors_probe.py.

Scientific question: Does reusing a local/global leaf index identify the SAME
PRF input (key + full compressed address) across signatures? The signer uses
one keypair for all three signatures, per Step 6 manifest. This script reports
aggregate alignment counts only. It does NOT expose derived secrets/addresses,
perform CPA, or estimate seed entropy.
"""
from pathlib import Path
from collections import defaultdict
from itertools import combinations
import hashlib
import json
import sys

ROOT = Path.cwd()
DATA = ROOT / 'step6_hidden_fors_probe_20261112'
OUT = ROOT / 'step8_address_grouping_20261112'
SOURCE = DATA / 'step6_nonselected_leaves.bin'
MANIFEST = DATA / 'manifest.json'
TREES, HEIGHT, N, SIGS = 33, 6, 16, 3
RECORDS_PER_SIG = TREES * ((1 << HEIGHT) - 1)
RECORD_BYTES = 4 + 22 + N + N

def stop(msg):
    sys.exit('STEP 8 STOPPED: ' + str(msg))

def sha256(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    if not SOURCE.is_file() or not MANIFEST.is_file():
        stop('Step 6 data not found; run from your SPHINCS-FORS-CORRECTED root directory.')
    if OUT.exists():
        stop('Output folder exists: {}. Rename it to preserve the previous run.'.format(OUT))
    try:
        meta = json.loads(MANIFEST.read_text(encoding='utf-8'))
    except (OSError, ValueError) as ex:
        stop('Cannot read Step 6 manifest: {}'.format(ex))
    for name, value in [
        ('signature_count', SIGS), ('keypair_count', 1),
        ('SPX_N', N), ('SPX_FORS_TREES', TREES),
        ('SPX_FORS_HEIGHT', HEIGHT),
        ('hidden_leaf_records', SIGS * RECORDS_PER_SIG),
    ]:
        if meta.get(name) != value:
            stop('Unexpected manifest {}: {}'.format(name, meta.get(name)))
    raw = SOURCE.read_bytes()
    if len(raw) != SIGS * RECORDS_PER_SIG * RECORD_BYTES:
        stop('Data length mismatch: {}'.format(len(raw)))
    expected_sha = meta.get('output_sha256', {}).get(SOURCE.name)
    if not expected_sha:
        stop('Missing checksum in Step 6 manifest')
    if sha256(raw) != expected_sha:
        stop('Step 6 dataset checksum mismatch!')

    # A signing call has one selected leaf per tree. Each of the 63 other
    # leaf derivations has a record containing the PRF's 22-byte address.
    # Global leaf index identifies the local leaf plus tree within FORS only;
    # the full address also contains message-dependent hypertree location.
    by_global = defaultdict(list)
    by_address = defaultdict(list)
    per_sig_global = []
    per_sig_addr = []
    for sig in range(SIGS):
        seen_g, seen_a = set(), set()
        for item in range(RECORDS_PER_SIG):
            start = (sig * RECORDS_PER_SIG + item) * RECORD_BYTES
            record = raw[start:start + RECORD_BYTES]
            global_idx = int.from_bytes(record[:4], 'little')
            address = record[4:26]
            secret = record[26:42]  # oracle-only consistency check, never predicted
            leakage = record[42:58]
            if global_idx >= TREES * (1 << HEIGHT):
                stop('Out-of-range leaf index in record {}'.format(item))
            if global_idx in seen_g or address in seen_a:
                stop('Duplicate global index or full address within signature {}'.format(sig + 1))
            seen_g.add(global_idx)
            seen_a.add(address)
            by_global[global_idx].append((sig, address))
            by_address[address].append((sig, global_idx, secret, leakage))
        if len(seen_g) != RECORDS_PER_SIG or len(seen_a) != RECORDS_PER_SIG:
            stop('Unexpected per-signature record counts')
        per_sig_global.append(seen_g)
        per_sig_addr.append(seen_a)

    index_pairs = 0
    same_index_different_addr = 0
    same_index_same_addr = 0
    for observations in by_global.values():
        for (s1, a1), (s2, a2) in combinations(observations, 2):
            if s1 == s2:
                stop('Duplicate global index in same signature')
            index_pairs += 1
            if a1 == a2:
                same_index_same_addr += 1
            else:
                same_index_different_addr += 1
    repeated_full_groups = 0
    same_address_pairs = 0
    for a, observations in by_address.items():
        if len(observations) <= 1:
            continue
        repeated_full_groups += 1
        reference = observations[0]
        for s, g, sk, leak in observations[1:]:
            if g != reference[1]:
                stop('Same PRF address associated with different global leaf indices')
            if sk != reference[2] or leak != reference[3]:
                stop('Same PRF address under same key produced different secret/leakage')
        same_address_pairs += len(observations) * (len(observations) - 1) // 2

    pair_results = []
    for i, j in combinations(range(SIGS), 2):
        pair_results.append({
            'signature_pair': '{}-{}'.format(i+1, j+1),
            'global_indices_in_common': len(per_sig_global[i] & per_sig_global[j]),
            'full_prf_addresses_in_common': len(per_sig_addr[i] & per_sig_addr[j]),
        })
    findings = {
        'status': 'Step 8 grouping/alignment audit; NOT a key-recovery experiment',
        'source': 'Step 6 experimentally generated data only',
        'source_sha256': expected_sha,
        'signatures_same_keypair': SIGS,
        'records_per_signature': RECORDS_PER_SIG,
        'total_records': SIGS * RECORDS_PER_SIG,
        'distinct_global_leaf_indices': len(by_global),
        'global_index_groups_with_two_or_more_records': sum(len(v) >= 2 for v in by_global.values()),
        'cross_signature_pairs_sharing_global_leaf_index': index_pairs,
        'of_those_pairs_with_different_prf_addresses': same_index_different_addr,
        'of_those_pairs_with_same_prf_address': same_index_same_addr,
        'distinct_full_prf_addresses': len(by_address),
        'full_prf_address_groups_with_two_or_more_records': repeated_full_groups,
        'cross_signature_pairs_sharing_full_prf_address': same_address_pairs,
        'per_signature_pair': pair_results,
        'interpretation': [
            'If repeated global leaf indices carry different addresses, index-only grouping mixes distinct PRF inputs and distinct derived secret values.',
            'Identical full addresses under one fixed key yield identical PRF outputs and identical exact HW; repeated observations have no variation for Pearson correlation of those values.',
            'The audit does not show whether a real attacker can extract the seed or measure these values physically.',
            'These data come from three different messages signed by one keypair. Additional trials are required for broader claims.'
        ]
    }
    OUT.mkdir()
    (OUT / 'step8_aggregate_results.json').write_text(json.dumps(findings, indent=2) + '\n', encoding='utf-8')
    print('STEP 8: PRF-address grouping audit (Step 6 data only)')
    print('Input checksum: PASS')
    print('Signatures / keypairs: {} / 1'.format(SIGS))
    print('Non-selected leaf records: {} ({} per signature)'.format(SIGS*RECORDS_PER_SIG, RECORDS_PER_SIG))
    print('Distinct GLOBAL leaf indices:', len(by_global))
    print('Global-index groups seen in 2+ signatures:', findings['global_index_groups_with_two_or_more_records'])
    print('Cross-signature pairs sharing a GLOBAL leaf index:', index_pairs)
    print('  ...with DIFFERENT full PRF addresses:', same_index_different_addr)
    print('  ...with the SAME full PRF address:', same_index_same_addr)
    print('Distinct FULL 22-byte PRF addresses:', len(by_address))
    print('Full-address groups repeated in 2+ signatures:', repeated_full_groups)
    for pair in pair_results:
        print('Signature {}: shared global indices={}, shared full PRF addresses={}'.format(
            pair['signature_pair'], pair['global_indices_in_common'], pair['full_prf_addresses_in_common']))
    print('STEP 8 PASS: grouping checks completed. NOT CPA or secret-key recovery.')
    print('Aggregate-only results:', OUT / 'step8_aggregate_results.json')
    print('Do not share Step 6 private data.')

if __name__ == '__main__':
    main()
