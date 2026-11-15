#!/usr/bin/env python3
"""Step 3: build and run a three-signature smoke test of the user's patched SPHINCS+ code.

Sources: only repository's C implementation and the changes made in Step 2.
No external research or datasets. Runs in a dedicated output directory and never
modifies existing data or C source files. Compatible with Python 3.9+.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path.cwd()
CODE = ROOT / 'sphincs-sha256-128f-code'
OUT = ROOT / 'step3_smoke_20261112'
C_SRC = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "rng.h"

int main(void) {
    unsigned char entropy[48];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char signature[CRYPTO_BYTES];
    unsigned char message[32];
    size_t siglen = 0;
    int i, j;

    for (i = 0; i < 48; i++) entropy[i] = (unsigned char)i;
    randombytes_init(entropy, NULL, 256);
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }

    for (i = 0; i < 3; i++) {
        for (j = 0; j < 32; j++) message[j] = (unsigned char)(j + 17 * i);
        if (crypto_sign_signature(signature, &siglen, message, sizeof message, sk) != 0) {
            fprintf(stderr, "signing failed on message %d\n", i);
            return 2;
        }
        if (siglen != CRYPTO_BYTES) {
            fprintf(stderr, "unexpected signature size on message %d\n", i);
            return 3;
        }
        if (crypto_sign_verify(signature, siglen, message, sizeof message, pk) != 0) {
            fprintf(stderr, "verification failed on message %d\n", i);
            return 4;
        }
        printf("Signature %d: sign PASS; verify PASS; signature length %zu bytes\n", i + 1, siglen);
    }
    return 0;
}
'''

SOURCES = [
    'address.c', 'rng.c', 'wots.c', 'utils.c', 'fors.c', 'sign.c',
    'hash_sha256.c', 'thash_sha256_simple.c', 'logger.c', 'sha256.c'
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def openssl_flags():
    # No packages are installed by this script. Existing Homebrew or pkg-config
    # metadata are used only to locate headers/libraries on the user's Mac.
    pkg_config = shutil.which('pkg-config')
    if pkg_config:
        check = subprocess.run([pkg_config, '--exists', 'openssl'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check.returncode == 0:
            proc = subprocess.run([pkg_config, '--cflags', '--libs', 'openssl'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            if proc.returncode == 0:
                return proc.stdout.strip().split(), 'pkg-config openssl'
    brew = shutil.which('brew')
    if brew:
        for package in ('openssl@3', 'openssl'):
            proc = subprocess.run([brew, '--prefix', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            if proc.returncode == 0:
                prefix = Path(proc.stdout.strip())
                if (prefix / 'include' / 'openssl' / 'evp.h').is_file():
                    return ['-I' + str(prefix / 'include'), '-L' + str(prefix / 'lib'), '-lcrypto'], 'Homebrew ' + package
    return ['-lcrypto'], 'default compiler search path'


def main():
    if not CODE.is_dir() or any(not (CODE / s).is_file() for s in SOURCES):
        sys.exit('ERROR: Run from SPHINCS-FORS-CORRECTED repository root; expected sphincs-sha256-128f-code/*.c')
    fors = (CODE / 'fors.c').read_text(encoding='utf-8')
    logger = (CODE / 'logger.c').read_text(encoding='utf-8')
    params = (CODE / 'params.h').read_text(encoding='utf-8')
    if 'log_sk_and_leakage(sig, (uint16_t)indices[i]);' not in fors or 'log_sk_and_leakage(sig + SPX_N' in fors:
        sys.exit('ERROR: Expected Step 2 patched fors.c not found')
    if 'fwrite(sk,1,SPX_N,real_sk_file)' not in logger:
        sys.exit('ERROR: Expected Step 2 patched logger.c not found')
    if not re.search(r'^\s*#define\s+SPX_N\s+16\b', params, re.M) or not re.search(r'^\s*#define\s+SPX_FORS_TREES\s+33\b', params, re.M):
        sys.exit('ERROR: Unexpected params.h; expected SPX_N=16, SPX_FORS_TREES=33')
    if OUT.exists():
        sys.exit('ERROR: ' + str(OUT) + ' exists. Not overwriting any previous test. Rename it before retrying.')
    OUT.mkdir()
    smoke_c = OUT / 'step3_smoke.c'
    smoke_c.write_text(C_SRC, encoding='utf-8')
    compiler = shutil.which('clang') or shutil.which('cc')
    if compiler is None:
        sys.exit('ERROR: No C compiler found (clang or cc). Test output directory created; no sources modified.')
    openssl, source = openssl_flags()
    output_bin = OUT / 'step3_smoke'
    cmd = [compiler, '-std=c99', '-DENABLE_CPA_LOGGING', '-O2', '-Wall', '-Wextra', '-I' + str(CODE), '-o', str(output_bin)]
    cmd += [str(CODE / s) for s in SOURCES] + [str(smoke_c)] + openssl
    print('Working directory:', ROOT)
    print('Build output:', OUT.name)
    print('OpenSSL selection:', source)
    print('Compiling patched repository and 3-signature test harness...')
    build = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    (OUT / 'build.log').write_text('COMMAND: ' + ' '.join(cmd) + '\n\n' + build.stdout + build.stderr, encoding='utf-8')
    if build.returncode:
        print('COMPILATION FAILED. Last 30 lines of build.log:')
        print('\n'.join((build.stdout + build.stderr).splitlines()[-30:]))
        print('Send me this output; do not change source files yet.')
        sys.exit(build.returncode)
    print('Compilation: PASS')
    print('Running 3 signatures with ONE keypair and 3 distinct messages...')
    run = subprocess.run([str(output_bin)], cwd=str(OUT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    (OUT / 'run.log').write_text(run.stdout + run.stderr, encoding='utf-8')
    print(run.stdout.strip())
    if run.returncode:
        print('RUN FAILED:', run.stderr)
        sys.exit(run.returncode)
    expected = {'real_sk_FORS.bin': 3*33*16, 'leakage.bin': 3*33*16, 'sk_indices.bin': 3*33*2}
    for name, size in expected.items():
        file = OUT / name
        if not file.exists():
            sys.exit('ERROR: Missing log: ' + name)
        actual = file.stat().st_size
        print('{}: {} bytes (expected {})'.format(name, actual, size))
        if actual != size:
            sys.exit('ERROR: Incorrect size in ' + name)
    real = (OUT / 'real_sk_FORS.bin').read_bytes()
    leak = (OUT / 'leakage.bin').read_bytes()
    matches = sum(bin(b).count('1') == y for b,y in zip(real, leak))
    print('Leakage equals HW(secret): {}/{}'.format(matches, len(real)))
    if matches != len(real):
        sys.exit('ERROR: Leakage did not equal HW(secret)')
    idx = struct.unpack('<{}H'.format(3*33), (OUT / 'sk_indices.bin').read_bytes())
    print('FORS leaf indices: min={} max={} (expected range 0..63)'.format(min(idx), max(idx)))
    if not all(0 <= i <= 63 for i in idx):
        sys.exit('ERROR: FORS leaf index out of range')
    metadata = {
        'test': 'Step 3 smoke test (not a CPA or side-channel attack)',
        'source': 'user-provided repository with Step 2 logging patch',
        'keypair_count': 1,
        'signature_count': 3,
        'expected_secret_bytes_per_signature': 528,
        'expected_index_bytes_per_signature': 66,
        'platform': platform.platform(),
        'python': sys.version.split()[0],
        'sha256': {name: sha256(OUT / name) for name in expected},
        'source_sha256': {name: sha256(CODE / name) for name in ['fors.c','logger.c','params.h']}
    }
    (OUT / 'manifest.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print('STEP 3 PASS: signatures verify, log sizes and HW consistency match corrected layout.')
    print('Reproducibility manifest: ' + str(OUT / 'manifest.json'))
    print('Do not use this output as CPA recovery evidence.')

if __name__ == '__main__':
    main()
