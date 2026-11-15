#!/usr/bin/env python3
"""Step 4: Show which instrumented FORS bytes are already in public signatures.

Source: user's uploaded SPHINCS+ repository with the Step 2 correction applied.
No public web research, new algorithm, or fabricated values. Python 3.9+.
Run from the SPHINCS-FORS-CORRECTED repository root.

This is a controlled *format/attacker-observability test*, NOT a CPA attack.
It creates a new directory, never overwrites experiments, and does not edit C files.
"""
from pathlib import Path
import hashlib
import json
import platform
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path.cwd()
CODE = ROOT / 'sphincs-sha256-128f-code'
OUT = ROOT / 'step4_public_fors_check_20261112'
C_SRC = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "rng.h"

static int save_file(const char *name, const unsigned char *data, size_t len) {
    FILE *f = fopen(name, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    if (fclose(f)) return -1;
    return 0;
}

int main(void) {
    unsigned char entropy[48], pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char signature[CRYPTO_BYTES], message[32];
    size_t siglen = 0;
    char fname[64];
    int i, j;
    for (i = 0; i < 48; i++) entropy[i] = (unsigned char)i;
    randombytes_init(entropy, NULL, 256);
    if (crypto_sign_keypair(pk, sk) != 0) return 1;
    if (save_file("public_key.bin", pk, sizeof pk) != 0) return 2;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 32; j++) message[j] = (unsigned char)(j + 17 * i);
        if (crypto_sign_signature(signature, &siglen, message, sizeof message, sk) != 0) return 3;
        if (siglen != CRYPTO_BYTES) return 4;
        if (crypto_sign_verify(signature, siglen, message, sizeof message, pk) != 0) return 5;
        snprintf(fname, sizeof fname, "signature_%d.bin", i+1);
        if (save_file(fname, signature, siglen) != 0) return 6;
        printf("Signature %d verified, saved %zu public bytes\n", i + 1, siglen);
    }
    return 0;
}
'''
SOURCES = ['address.c','rng.c','wots.c','utils.c','fors.c','sign.c',
           'hash_sha256.c','thash_sha256_simple.c','logger.c','sha256.c']


def openssl_flags():
    # Mirror Step 3 library discovery; no software installed automatically.
    pkg = shutil.which('pkg-config')
    if pkg:
        ok = subprocess.run([pkg, '--exists', 'openssl'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ok.returncode == 0:
            result = subprocess.run([pkg, '--cflags', '--libs', 'openssl'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True)
            if result.returncode == 0:
                return result.stdout.strip().split(), 'pkg-config openssl'
    brew = shutil.which('brew')
    if brew:
        for package in ('openssl@3', 'openssl'):
            result = subprocess.run([brew, '--prefix', package],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True)
            if result.returncode == 0:
                prefix = Path(result.stdout.strip())
                if (prefix/'include'/'openssl'/'evp.h').is_file():
                    return ['-I'+str(prefix/'include'),'-L'+str(prefix/'lib'),'-lcrypto'], 'Homebrew '+package
    return ['-lcrypto'], 'default -lcrypto'


def fail(message):
    sys.exit('STEP 4 FAILED: ' + str(message))


def file_hash(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    params = (CODE/'params.h')
    if not params.is_file() or any(not (CODE/n).is_file() for n in SOURCES):
        fail('Open Terminal at the repository root; expected sphincs-sha256-128f-code/')
    p = params.read_text(encoding='utf-8')
    def define(name):
        m = re.search(r'^\s*#define\s+'+re.escape(name)+r'\s+(\d+)\b',p,re.M)
        if not m:
            fail('Could not read '+name+' from params.h')
        return int(m.group(1))
    n = define('SPX_N'); trees = define('SPX_FORS_TREES'); height = define('SPX_FORS_HEIGHT')
    if (n, trees, height) != (16,33,6):
        fail('Unexpected parameters: N=%d trees=%d height=%d; inspect source before continuing' % (n,trees,height))
    if OUT.exists():
        fail(str(OUT)+' already exists; preserve it and rename if a repeat is necessary')
    OUT.mkdir()
    harness = OUT/'step4_public_fors_check.c'
    harness.write_text(C_SRC,encoding='utf-8')
    cc = shutil.which('clang') or shutil.which('cc')
    if not cc:
        fail('clang or cc not found')
    flags, openssl_desc = openssl_flags()
    program = OUT/'step4_public_fors_check'
    cmd = [cc,'-std=c99','-DENABLE_CPA_LOGGING','-O2','-Wall','-Wextra','-I'+str(CODE),'-o',str(program)]
    cmd += [str(CODE/s) for s in SOURCES] + [str(harness)] + flags
    print('Compiling your corrected SPHINCS+ implementation...')
    print('OpenSSL:', openssl_desc)
    built = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    (OUT/'build.log').write_text('COMMAND: '+' '.join(cmd)+'\n'+built.stdout+built.stderr,encoding='utf-8')
    if built.returncode:
        fail('Compilation failed; send the last lines of '+str(OUT/'build.log')+'\n'+ '\n'.join(built.stderr.splitlines()[-20:]))
    run = subprocess.run([str(program)],cwd=str(OUT),stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, universal_newlines=True)
    (OUT/'run.log').write_text(run.stdout+run.stderr,encoding='utf-8')
    print(run.stdout.strip())
    if run.returncode:
        fail('Signing/verification failed. '+run.stderr)

    real = OUT/'real_sk_FORS.bin'; leak = OUT/'leakage.bin'; idx = OUT/'sk_indices.bin'
    for path, size in ((real,3*trees*n),(leak,3*trees*n),(idx,3*trees*2)):
        if not path.exists() or path.stat().st_size != size:
            fail('%s: missing or wrong size (expected %d)' % (path.name,size))
    real_data = real.read_bytes(); leak_data = leak.read_bytes()
    hwmatches = sum(bin(int(x)).count('1') == int(y) for x,y in zip(real_data,leak_data))
    if hwmatches != len(real_data):
        fail('The software leakage does not match HW(secret)')
    print('Logged leakage = HW(logged secret): {}/{}'.format(hwmatches,len(real_data)))

    per_tree_sig_bytes = (height+1)*n
    per_signature_secret_bytes = trees*n
    total_matches = 0
    for s in range(3):
        sig_path = OUT/('signature_%d.bin' % (s+1))
        sig = sig_path.read_bytes()
        if len(sig) != 17088:
            fail('Unexpected signature length %d: inspect layout' % len(sig))
        for j in range(trees):
            public_secret = sig[n + j*per_tree_sig_bytes:n + j*per_tree_sig_bytes + n]
            logged_secret = real_data[(s*trees+j)*n:(s*trees+j+1)*n]
            if len(public_secret) != n or public_secret != logged_secret:
                fail('Mismatch in signature %d, FORS tree %d' % (s+1,j))
            total_matches += len(public_secret)
        print('Signature {}: all {}/{} selected FORS bytes match the public signature'.format(
            s+1,per_signature_secret_bytes,per_signature_secret_bytes))
    print('Public-signature comparison: {}/{} logged FORS bytes matched'.format(total_matches,3*trees*n))

    # Diagnostic: check if the same local leaf index in the same FORS tree corresponds
    # to multiple secret values across the THREE different signatures.
    indices = struct.unpack('<{}H'.format(3*trees),idx.read_bytes())
    repeats=0; changed=0
    for j in range(trees):
        for a in range(3):
            for b in range(a+1,3):
                if indices[a*trees+j] == indices[b*trees+j]:
                    repeats += 1
                    if real_data[(a*trees+j)*n:(a*trees+j+1)*n] != real_data[(b*trees+j)*n:(b*trees+j+1)*n]:
                        changed += 1
    print('Same-tree repeated leaf indices among 3 signatures: {}'.format(repeats))
    print('Of those, different logged FORS secret values: {}'.format(changed))
    print('Note: same local leaf index alone does not fix the full FORS address.')

    paths = [real,leak,idx,OUT/'public_key.bin']+[OUT/('signature_%d.bin' % (k+1)) for k in range(3)]
    m = {
        'purpose':'attacker-observable FORS secret exposure check (NOT a CPA attack)',
        'keypair_count':1,'signature_count':3,
        'SPX_N':n,'SPX_FORS_TREES':trees,'SPX_FORS_HEIGHT':height,
        'signature_initial_randomizer_bytes':n,
        'FORS_secret_offset':'SPX_N + tree*(SPX_FORS_HEIGHT+1)*SPX_N',
        'match_bytes':total_matches,'total_comparable_bytes':3*trees*n,
        'same_tree_repeated_local_leaf_index_pairs':repeats,
        'such_pairs_with_different_secret_bytes':changed,
        'implementation_SHA256':{name:file_hash(CODE/name) for name in ['fors.c','sign.c','logger.c','params.h']},
        'output_SHA256':{x.name:file_hash(x) for x in paths},
        'platform':platform.platform(), 'python':sys.version.split()[0],
        'interpretation':'Selected FORS secret bytes are carried in ordinary public signatures.'
    }
    (OUT/'manifest.json').write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    print('STEP 4 PASS: selected FORS secret blocks are already publicly present in signatures.')
    print('Output:',OUT)
    print('This is not evidence of side-channel secret-key recovery.')

if __name__=='__main__':
    main()
