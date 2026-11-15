#!/usr/bin/env python3
"""Step 6: Controlled FORS hidden-leaf source and logging probe.

Research-only, based exclusively on the user's modified SPHINCS+ source.
Compiles a COPY of the source; does NOT change repository files.
Python >=3.9, clang and OpenSSL are needed. No NumPy required.

This is NOT a CPA attack or proof of seed recovery. It checks whether FORS
leaf secrets generated inside treehash but NOT selected for publication can
be logged, and validates software HW for those 16-byte secrets.
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
SRC = ROOT / 'sphincs-sha256-128f-code'
OUT = ROOT / 'step6_hidden_fors_probe_20261112'
CC_SOURCES = ['address.c','rng.c','wots.c','utils.c','fors.c','sign.c',
              'hash_sha256.c','thash_sha256_simple.c','logger.c','sha256.c']

HARNESS = r'''
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "api.h"
#include "rng.h"
static int write_file(const char *name, const unsigned char *p, size_t n) {
    FILE *f = fopen(name, "wb");
    if (!f) return 1;
    if (fwrite(p, 1, n, f) != n) { fclose(f); return 1; }
    return fclose(f) != 0;
}
int main(void) {
    unsigned char entropy[48], pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char signature[CRYPTO_BYTES], message[32];
    size_t siglen = 0;
    char sig_name[64], msg_name[64];
    int i, j;
    for (i = 0; i < 48; i++) entropy[i] = (unsigned char)i;
    randombytes_init(entropy, NULL, 256);
    if (crypto_sign_keypair(pk, sk) != 0) return 1;
    if (write_file("public_key.bin", pk, sizeof pk)) return 2;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 32; j++) message[j] = (unsigned char)(j + 17*i);
        if (crypto_sign_signature(signature, &siglen, message, sizeof message, sk)) return 3;
        if (siglen != CRYPTO_BYTES) return 4;
        if (crypto_sign_verify(signature, siglen, message, sizeof message, pk)) return 5;
        snprintf(sig_name, sizeof sig_name, "signature_%d.bin", i+1);
        snprintf(msg_name, sizeof msg_name, "message_%d.bin", i+1);
        if (write_file(sig_name, signature, siglen) ||
            write_file(msg_name, message, sizeof message)) return 6;
        printf("Signature %d: VERIFY PASS, %zu public bytes\n", i+1, siglen);
    }
    return 0;
}
'''

# Instrumentation: one 58-byte record [4B global leaf index][22B compressed
# address][16B secret][16B software HW] for each NON-SELECTED FORS leaf.
# This instrumentation is used ONLY in a private copied source tree.
INSTRUMENT_TOP = r'''
/* BEGIN Step 6 research-only hidden-leaf probe (temporary build copy) */
#include <stdio.h>
#include "sha256.h"
static FILE *step6_leaf_file = NULL;
static uint32_t step6_selected[SPX_FORS_TREES];
static int step6_error = 0;
static void step6_log_nonselected(uint32_t global_idx,
                                  const uint32_t addr[8],
                                  const unsigned char *sk) {
    unsigned int tree = global_idx >> SPX_FORS_HEIGHT;
    unsigned int local = global_idx & ((1U << SPX_FORS_HEIGHT)-1U);
    unsigned char id_le[4];
    unsigned char hw[SPX_N];
    unsigned int i;
    if (!step6_leaf_file || tree >= SPX_FORS_TREES ||
        local == step6_selected[tree]) return;
    for (i = 0; i < 4; ++i) id_le[i] = (unsigned char)(global_idx >> (8*i));
    for (i = 0; i < SPX_N; ++i) {
        unsigned char b = sk[i], n = 0;
        while (b) { n += b & 1U; b >>= 1U; }
        hw[i] = n;
    }
    if (fwrite(id_le, 1, 4, step6_leaf_file) != 4 ||
        fwrite(addr, 1, SPX_SHA256_ADDR_BYTES, step6_leaf_file) != SPX_SHA256_ADDR_BYTES ||
        fwrite(sk, 1, SPX_N, step6_leaf_file) != SPX_N ||
        fwrite(hw, 1, SPX_N, step6_leaf_file) != SPX_N) step6_error = 1;
}
/* END Step 6 research-only probe */
'''


def fail(s):
    raise SystemExit('STEP 6 FAILED: ' + str(s))

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def patch_fors(text):
    """Anchor-specific copy-only modifications; fail on unexpected source."""
    def insert_after(s, anchor, extra):
        if s.count(anchor) != 1:
            fail('Expected one anchor, got {}: {!r}'.format(s.count(anchor),anchor[:90]))
        return s.replace(anchor, anchor + extra, 1)
    params_include = '#include "logger.h"\n'
    text = insert_after(text, params_include, INSTRUMENT_TOP)
    text = insert_after(text,
        '    fors_gen_sk(leaf, sk_seed, fors_leaf_addr);\n',
        '    step6_log_nonselected(addr_idx, fors_leaf_addr, leaf);\n')
    # Set up for each signing. The selected leaf indices are derived
    # from message_to_indices (without reading the secret ground truth).
    sig_setup = '    message_to_indices(indices, m);\n\n#ifdef ENABLE_CPA_LOGGING'
    if text.count(sig_setup) != 1:
        fail('Unexpected fors_sign setup; not patching')
    replacement = ('''    message_to_indices(indices, m);
    /* Step 6 probe: record selected indices before treehash. */
    for (i = 0; i < SPX_FORS_TREES; ++i) step6_selected[i] = indices[i];
    step6_error = 0;
    step6_leaf_file = fopen("step6_nonselected_leaves.bin", "ab");
    if (!step6_leaf_file) { fprintf(stderr, "Step 6: cannot open probe log\\n"); exit(61); }
''')
    text = text.replace(sig_setup, replacement + '\n#ifdef ENABLE_CPA_LOGGING', 1)
    end_anchor = '#ifdef ENABLE_CPA_LOGGING\n    close_logger();\n#endif\n}'
    if text.count(end_anchor) != 1:
        fail('Unexpected fors_sign end; not patching')
    text = text.replace(end_anchor,
        '''#ifdef ENABLE_CPA_LOGGING
    close_logger();
#endif
    if (fclose(step6_leaf_file) != 0 || step6_error) {
        fprintf(stderr, "Step 6: probe write failed\\n"); exit(62);
    }
    step6_leaf_file = NULL;
}''',1)
    return text

def openssl_flags():
    pkg = shutil.which('pkg-config')
    if pkg and subprocess.run([pkg,'--exists','openssl'],stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE).returncode == 0:
        proc = subprocess.run([pkg,'--cflags','--libs','openssl'],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              universal_newlines=True)
        if proc.returncode == 0:
            return proc.stdout.strip().split(), 'pkg-config openssl'
    brew = shutil.which('brew')
    if brew:
        for name in ['openssl@3','openssl']:
            proc = subprocess.run([brew,'--prefix',name],stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,universal_newlines=True)
            if proc.returncode == 0:
                prefix = Path(proc.stdout.strip())
                if (prefix/'include'/'openssl'/'evp.h').exists():
                    return ['-I'+str(prefix/'include'),'-L'+str(prefix/'lib'),'-lcrypto'], 'Homebrew '+name
    return ['-lcrypto'], 'system -lcrypto'

def main():
    if not SRC.is_dir():
        fail('Run from repository root; missing sphincs-sha256-128f-code/')
    for file in CC_SOURCES + ['api.h','params.h','sha256.h']:
        if not (SRC/file).exists():
            fail('Missing expected source: '+file)
    paramtext = (SRC/'params.h').read_text()
    def value(name):
        r = re.search(r'^\s*#define\s+' + name + r'\s+(\d+)\b',paramtext,re.M)
        if not r: fail('Cannot read '+name)
        return int(r.group(1))
    n, trees, height = value('SPX_N'),value('SPX_FORS_TREES'),value('SPX_FORS_HEIGHT')
    if (n,trees,height) != (16,33,6):
        fail('Unexpected params: N={}, trees={}, height={}'.format(n,trees,height))
    if OUT.exists():
        fail('Output already exists; rename it to preserve earlier experiment: '+str(OUT))
    OUT.mkdir()
    code_copy = OUT/'instrumented_source_copy'
    shutil.copytree(str(SRC), str(code_copy))
    fpath = code_copy/'fors.c'
    fpath.write_text(patch_fors(fpath.read_text()))
    harness = OUT/'step6_harness.c'
    harness.write_text(HARNESS)
    cc = shutil.which('clang') or shutil.which('cc')
    if not cc: fail('C compiler not found')
    flags, openssl_info = openssl_flags()
    program = OUT/'step6_harness'
    cmd = ([cc,'-std=c99','-DENABLE_CPA_LOGGING','-O2','-Wall','-Wextra','-I'+str(code_copy),
            '-o',str(program)] + [str(code_copy/p) for p in CC_SOURCES]
            + [str(harness)] + flags)
    print('STEP 6: compiling temporary instrumented SOURCE COPY only')
    print('OpenSSL:',openssl_info)
    built = subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
    (OUT/'build.log').write_text('COMMAND: '+' '.join(cmd)+'\n'+built.stdout+built.stderr)
    if built.returncode:
        fail('Compilation error; send build.log or these lines:\n'+'\n'.join(built.stderr.splitlines()[-20:]))
    print('Compile: PASS')
    run = subprocess.run([str(program)],cwd=str(OUT),stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,universal_newlines=True)
    (OUT/'run.log').write_text(run.stdout+run.stderr)
    print(run.stdout.strip())
    if run.returncode:
        fail('Signing error: '+run.stderr)
    paths = [(OUT/'real_sk_FORS.bin',3*trees*n),
             (OUT/'leakage.bin',3*trees*n),
             (OUT/'sk_indices.bin',3*trees*2)]
    for p,sz in paths:
        if not p.exists() or p.stat().st_size!=sz:
            fail('Incorrect main log: {} (expected {} bytes)'.format(p,sz))
    raw_indices = (OUT/'sk_indices.bin').read_bytes()
    selected_by_signature = [struct.unpack('<{}H'.format(trees),
                             raw_indices[s*trees*2:(s+1)*trees*2]) for s in range(3)]
    record_size = 4+22+n+n
    expected_per_sig = trees*((1<<height)-1)
    total_records = 3*expected_per_sig
    probe = OUT/'step6_nonselected_leaves.bin'
    if not probe.exists() or probe.stat().st_size != total_records*record_size:
        fail('Incorrect hidden log size; expected {} bytes'.format(total_records*record_size))
    data = probe.read_bytes()
    leakage_consistent = 0
    in_public = 0
    address_uniqueness = []
    for s in range(3):
        sig = (OUT/'signature_{}.bin'.format(s+1)).read_bytes()
        if len(sig) != 17088: fail('Incorrect signature size')
        seen_indices = set()
        seen_addresses = set()
        for k in range(expected_per_sig):
            base = (s*expected_per_sig+k)*record_size
            idx = struct.unpack('<I',data[base:base+4])[0]
            addr = data[base+4:base+26]
            secret = data[base+26:base+26+n]
            leak = data[base+26+n:base+26+2*n]
            if idx >= trees*(1<<height) or idx in seen_indices:
                fail('Unexpected/duplicate global leaf index on signature {}'.format(s+1))
            seen_indices.add(idx)
            tree = idx >> height
            local = idx & ((1<<height)-1)
            if local == selected_by_signature[s][tree]:
                fail('Selected leaf found in hidden-leaf log (signature {}, tree {})'.format(s+1,tree))
            for a,b in zip(secret,leak):
                if bin(a).count('1') == b: leakage_consistent+=1
            if secret in sig: in_public+=1
            if addr in seen_addresses:
                fail('Duplicate PRF address within signature {}'.format(s+1))
            seen_addresses.add(addr)
        expected_idx = {x for x in range(trees*(1<<height))
                        if (x & ((1<<height)-1)) != selected_by_signature[s][x>>height]}
        if seen_indices != expected_idx:
            fail('Hidden-leaf index set differs from expected for signature '+str(s+1))
        address_uniqueness.append(len(seen_addresses))
        print('Signature {}: {} non-selected FORS leaf derivations; {} distinct PRF addresses'.format(
            s+1,len(seen_indices),len(seen_addresses)))
    total_bytes = total_records*n
    if leakage_consistent != total_bytes:
        fail('HW leakage disagrees with secretly logged bytes')
    print('NON-SELECTED FORS leaf records: {} total ({} per signature)'.format(total_records,expected_per_sig))
    print('HW(secret) consistency: {}/{}'.format(leakage_consistent,total_bytes))
    print('Exact 16-byte hidden secrets found verbatim in public signatures: {}'.format(in_public))
    print('Note: absence of exact bytes is NOT proof of cryptographic secrecy.')
    main_logs_ok = True
    files_to_hash = [probe,OUT/'public_key.bin'] + [p for p,_ in paths]
    files_to_hash += [OUT/('signature_{}.bin'.format(i)) for i in range(1,4)]
    manifest = {
        'purpose':'identify unrevealed FORS leaf derivations for future leakage study; not CPA or key recovery',
        'signature_count':3,'keypair_count':1,
        'SPX_N':n,'SPX_FORS_TREES':trees,'SPX_FORS_HEIGHT':height,
        'all_fors_treehash_leaf_derivations_per_sig':trees*(1<<height),
        'selected_leaf_derivations_per_sig':trees,
        'not_directly_published_leaf_derivations_per_sig':expected_per_sig,
        'hidden_leaf_records':total_records,
        'HW_matches':leakage_consistent,
        'HW_comparisons':total_bytes,
        'exact_hidden_secrets_present_verbatim_in_signatures':in_public,
        'code_sha256': {name:digest(SRC/name) for name in ['fors.c','logger.c','sign.c','params.h']},
        'instrumented_fors_sha256':digest(fpath),
        'output_sha256':{p.name:digest(p) for p in files_to_hash},
        'OS':platform.platform(),'python':sys.version.split()[0],
        'interpretation':'Ground-truth and HW values here are PRIVATE simulated measurement artifacts, not public data or an attack.'
    }
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('STEP 6 PASS: hidden-leaf logging is reproducible in an isolated source copy.')
    print('Output:',OUT)
    print('CAUTION: step6_nonselected_leaves.bin contains private derived secrets. Do not publish it.')

if __name__=='__main__':
    main()
