#!/usr/bin/env python3
"""Step 10: repeat Step 9's restricted PRF hypothesis test on fresh fixtures.

Runs 20 independent 16-bit unknown-suffix trials, with 14 known seed bytes,
16 *fixed* public addresses, and exact software HW of first PRF-output byte.
Calls the two compiled C programs generated in Step 9; modifies no C sources.
The scoring executable receives only known-address/HW measurements and already
contains the 14 public seed bytes. Ground truth is checked afterwards by Python.

Scientific scope: diagnostic repeatability of a deliberately constrained test;
NOT unrestricted 128-bit seed recovery, a CPA experiment, or a physical attack.

Uses only Python standard library (Python 3.9+). Run from repository root.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys

ROOT = Path.cwd()
SOURCE = ROOT / 'step9_prf_partial_seed_20261112'
OUT = ROOT / 'step10_repeated_prf_20261112'
TRIALS = 20
CHECKPOINTS = (1, 2, 4, 6, 8, 12, 16)
KNOWN_PREFIX = bytes(range(14))  # MUST match the Step 9 scorer's built-in assumption


def stop(message):
    sys.exit('STEP 10 ERROR: ' + message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    return subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)


def private_file(path, data):
    with open(str(path), 'wb') as f:
        f.write(data)
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


def main():
    gen = SOURCE / 'step9_measurements'
    scorer = SOURCE / 'step9_hypothesis_search'
    report = SOURCE / 'step9_aggregate_results.json'
    required = [gen, scorer, report, SOURCE / 'step9_hypothesis_search.c',
                SOURCE / 'step9_measurements.c']
    missing = [p for p in required if not p.is_file()]
    if missing:
        stop('Missing Step 9 outputs: ' + ', '.join(str(p) for p in missing))
    info = json.loads(report.read_text())
    if info.get('status') != 'PASS' or info.get('unknown_seed_bits') != 16 or info.get('known_seed_bytes') != 14:
        stop('Unexpected Step 9 aggregate report; review it before proceeding')
    if digest(SOURCE / 'step9_hypothesis_search.c') != info.get('scorer_source_sha256'):
        stop('Step 9 scorer source changed since Step 9')
    if digest(SOURCE / 'step9_measurements.c') != info.get('generator_source_sha256'):
        stop('Step 9 generator source changed since Step 9')
    if OUT.exists():
        stop('{} already exists. Rename it before retrying; no prior results will be overwritten.'.format(OUT))
    OUT.mkdir()
    print('STEP 10: repeatability of restricted 16-bit PRF suffix test')
    print('20 independently generated 2-byte suffixes; 14 known seed bytes')
    print('16 identical public address positions and exact noiseless HW observations per trial')
    print('Using C generator and C hypothesis scorer compiled by Step 9')
    print('No original source modifications. No physical measurements. Not unrestricted seed recovery.')

    used_suffixes = set()
    records = []
    good = 0
    for t in range(1, TRIALS + 1):
        sub = OUT / ('trial_%02d' % t)
        sub.mkdir()
        suffix = os.urandom(2)
        while suffix in used_suffixes:
            suffix = os.urandom(2)
        used_suffixes.add(suffix)
        seed = KNOWN_PREFIX + suffix
        fixture = sub / 'private_test_seed.bin'
        private_file(fixture, seed)
        observations = sub / 'known_addresses_and_hw.bin'
        generated = run([gen, fixture, observations])
        if generated.returncode:
            stop('Trial %d generator failed (exit=%d): %s' % (t, generated.returncode, generated.stderr))
        if observations.stat().st_size != 368:
            stop('Trial %d measurement size incorrect' % t)
        obs = observations.read_bytes()
        if any(obs[j] > 8 for j in range(22, len(obs), 23)):
            stop('Trial %d contains a leakage value outside [0,8]' % t)
        if len({obs[j:j+22] for j in range(0, len(obs), 23)}) != 16:
            stop('Trial %d did not yield 16 distinct public addresses' % t)
        guess_file = sub / 'candidate_suffix_private.bin'
        attacked = run([scorer, observations, guess_file])
        counts = {int(a): int(b) for a, b in re.findall(r'SURVIVORS_(\d+)=(\d+)', attacked.stdout)}
        if set(counts) != set(CHECKPOINTS):
            stop('Trial %d scorer output incomplete: %s | %s' % (t, attacked.stdout, attacked.stderr))
        nums = [counts[k] for k in CHECKPOINTS]
        if not all(nums[i] >= nums[i+1] >= 1 for i in range(len(nums)-1)):
            stop('Trial %d inconsistent survivor counts: %s' % (t, nums))
        unique = counts[16] == 1
        if unique != (attacked.returncode == 0):
            stop('Trial %d scorer exit code disagrees with uniqueness' % t)
        match = False
        if unique:
            if not guess_file.is_file():
                stop('Trial %d unique candidate file missing' % t)
            try:
                os.chmod(str(guess_file), 0o600)
            except OSError:
                pass
            match = guess_file.read_bytes() == suffix
            if not match:
                stop('Trial %d recovered candidate does not match the fixture' % t)
            good += 1
        first_unique_checkpoint = next((k for k in CHECKPOINTS if counts[k] == 1), None)
        record = {
            'trial': t,
            'surviving_candidates': {str(k): counts[k] for k in CHECKPOINTS},
            'first_unique_checkpoint': first_unique_checkpoint,
            'unique_at_16': unique,
            'matches_private_fixture': match,
            'observation_file_sha256': digest(observations),
        }
        records.append(record)
        summary = ' '.join('%d:%d' % (k, counts[k]) for k in CHECKPOINTS)
        print('Trial %02d | survivors [%s] | unique@16=%s | fixture_match=%s' %
              (t, summary, 'YES' if unique else 'NO', 'YES' if match else 'NO'))

    checkpoints = {
        str(k): {
            'min': min(r['surviving_candidates'][str(k)] for r in records),
            'median': statistics.median(r['surviving_candidates'][str(k)] for r in records),
            'max': max(r['surviving_candidates'][str(k)] for r in records),
            'unique_trials': sum(r['surviving_candidates'][str(k)] == 1 for r in records),
        } for k in CHECKPOINTS
    }
    aggregate = {
        'status': 'PASS' if good == TRIALS else 'PARTIAL',
        'science_scope': ('20 independent restricted fixtures; fixed 14 known prefix bytes, '
                          '2 unknown suffix bytes; 16 fixed public PRF addresses; '
                          'noiseless simulated HW of first PRF output byte; exhaustive '
                          '16-bit search. Not full-key recovery, physical side channel, or CPA.'),
        'trials': TRIALS,
        'unique_and_correct_after_16': good,
        'checkpoints': checkpoints,
        'step9_generator_binary_sha256': digest(gen),
        'step9_scorer_binary_sha256': digest(scorer),
        'per_trial_aggregates': records,
    }
    result = OUT / 'step10_aggregate_results.json'
    result.write_text(json.dumps(aggregate, indent=2) + '\n')
    print('\nSUMMARY: uniquely and correctly inferred suffix after 16 observations: %d/%d trials' % (good, TRIALS))
    for k in CHECKPOINTS:
        e = checkpoints[str(k)]
        print('After %2d observations: unique in %2d/%d trials; survivor min/median/max = %s/%s/%s' %
              (k, e['unique_trials'], TRIALS, e['min'], e['median'], e['max']))
    print('Aggregate-only report:', result)
    print('PRIVATE: do not share any trial_*/private_test_seed.bin, candidate_suffix_private.bin, or known_addresses_and_hw.bin')
    print('STEP 10 %s: repeatability evaluated (still restricted-key simulation)' % aggregate['status'])


if __name__ == '__main__':
    main()
