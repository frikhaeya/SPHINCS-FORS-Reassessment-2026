#!/usr/bin/env python3
"""Step 9: Controlled hypothesis-model validation against user's SPHINCS+ PRF.

This is a deliberately RESTRICTED test: 14 of 16 seed bytes known, 2 unknown;
exact, noiseless HW of only the first PRF output byte for 16 different PUBLIC
addresses. The scoring program reads neither the private fixture nor ground truth.
No physical traces, no unrestricted secret-seed recovery, no CPA claim.

Sources: local user's SPHINCS+ code only. Python >=3.9, clang/cc, OpenSSL.
Writes only inside a new step9_* folder; does not alter source or older data.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT=Path.cwd()
SRC=ROOT/'sphincs-sha256-128f-code'
OUT=ROOT/'step9_prf_partial_seed_20261112'
SOURCES=['address.c','rng.c','wots.c','utils.c','fors.c','sign.c',
         'hash_sha256.c','thash_sha256_simple.c','logger.c','sha256.c']

GENERATE_C=r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "address.h"
#include "params.h"
#include "sha256.h"

static unsigned char hw(unsigned char x) {
    unsigned char n=0;
    while (x) { n+=(unsigned char)(x&1u); x>>=1; }
    return n;
}
int main(int argc, char **argv) {
    unsigned char seed[SPX_N], value[SPX_N];
    uint32_t addr[8] = {0};
    FILE *s, *o;
    unsigned int i;
    if (argc!=3 || SPX_N!=16 || SPX_SHA256_ADDR_BYTES!=22) return 2;
    s=fopen(argv[1],"rb");
    if (!s) return 3;
    if (fread(seed,1,SPX_N,s)!=SPX_N || fgetc(s)!=EOF) { fclose(s); return 4; }
    fclose(s);
    o=fopen(argv[2],"wb");
    if (!o) return 5;
    set_layer_addr(addr,0);
    set_tree_addr(addr,0x1234567ULL);
    set_type(addr,SPX_ADDR_TYPE_FORSTREE);
    set_keypair_addr(addr,7);
    set_tree_height(addr,0);
    for (i=0;i<16;i++) {
        unsigned char y;
        set_tree_index(addr,i);
        prf_addr(value,seed,addr);
        y=hw(value[0]); /* exactly ONE 8-bit HW measurement per address */
        if (fwrite(addr,1,SPX_SHA256_ADDR_BYTES,o)!=SPX_SHA256_ADDR_BYTES ||
            fwrite(&y,1,1,o)!=1) { fclose(o); return 6; }
    }
    if (fclose(o)) return 7;
    return 0;
}
'''

SCORE_C=r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "params.h"
#include "sha256.h"

#define NOBS 16
#define ADDR_BYTES 22
static unsigned char hw(unsigned char x) {
    unsigned char n=0;
    while (x) { n+=(unsigned char)(x&1u); x>>=1; }
    return n;
}
int main(int argc, char **argv) {
    unsigned char adrs[NOBS][ADDR_BYTES], leaks[NOBS];
    const int stops[7]={1,2,4,6,8,12,16};
    uint32_t addr[8]={0};
    unsigned char seed[SPX_N],value[SPX_N];
    unsigned long counts[7]={0};
    unsigned int cand, i, j;
    int unique=-1;
    FILE *f;
    if (argc!=3 || SPX_N!=16 || SPX_SHA256_ADDR_BYTES!=ADDR_BYTES) return 2;
    f=fopen(argv[1],"rb");
    if (!f) return 3;
    for (i=0;i<NOBS;i++) {
        if (fread(adrs[i],1,ADDR_BYTES,f)!=ADDR_BYTES || fread(leaks+i,1,1,f)!=1 || leaks[i]>8) {
            fclose(f); return 4;
        }
        for (j=0;j<i;j++) if (!memcmp(adrs[i],adrs[j],ADDR_BYTES)) { fclose(f); return 5; }
    }
    if (fgetc(f)!=EOF) { fclose(f); return 6; }
    fclose(f);
    /* The attack model explicitly assumes 14 seed bytes are public. */
    for (i=0;i<14;i++) seed[i]=(unsigned char)i;
    for (cand=0;cand<65536u;cand++) {
        int matched=0;
        seed[14]=(unsigned char)(cand & 0xffu);
        seed[15]=(unsigned char)(cand >> 8);
        for (i=0;i<NOBS;i++) {
            memset(addr,0,sizeof(addr));
            memcpy(addr,adrs[i],ADDR_BYTES);
            prf_addr(value,seed,addr);
            if (hw(value[0])!=leaks[i]) break;
            matched++;
        }
        for (i=0;i<7;i++) if (matched>=stops[i]) counts[i]++;
        if (matched==NOBS) unique=(int)cand;
    }
    for (i=0;i<7;i++) printf("SURVIVORS_%d=%lu\n",stops[i],counts[i]);
    if (counts[6]==1) {
        unsigned char suffix[2];
        suffix[0]=(unsigned char)(unique & 0xff);
        suffix[1]=(unsigned char)(unique >> 8);
        f=fopen(argv[2],"wb");
        if (!f || fwrite(suffix,1,2,f)!=2 || fclose(f)) return 7;
    }
    return counts[6] == 1 ? 0 : 8;
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def openssl_flags():
    pkg=shutil.which('pkg-config')
    if pkg:
        proc=subprocess.run([pkg,'--exists','openssl'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if proc.returncode==0:
            p=subprocess.run([pkg,'--cflags','--libs','openssl'],stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,universal_newlines=True)
            if p.returncode==0: return p.stdout.strip().split(), 'pkg-config openssl'
    brew=shutil.which('brew')
    if brew:
        for name in ('openssl@3','openssl'):
            p=subprocess.run([brew,'--prefix',name],stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,universal_newlines=True)
            if p.returncode==0:
                prefix=Path(p.stdout.strip())
                if (prefix/'include'/'openssl'/'evp.h').is_file():
                    return ['-I'+str(prefix/'include'),'-L'+str(prefix/'lib'),'-lcrypto'],'Homebrew '+name
    return ['-lcrypto'],'system libcrypto'


def fail(s):
    sys.exit('STEP 9 ERROR: '+str(s))


def main():
    if not SRC.is_dir() or any(not (SRC/x).is_file() for x in SOURCES+['params.h','hash.h','sha256.h']):
        fail('Run from corrected repository root; missing local C sources')
    params=(SRC/'params.h').read_text()
    if not re.search(r'^\s*#define\s+SPX_N\s+16\b',params,re.M):
        fail('Unexpected seed length, expected SPX_N=16')
    if OUT.exists():
        fail('{} already exists. Rename it before rerunning; older results are never overwritten.'.format(OUT))
    cc=shutil.which('clang') or shutil.which('cc')
    if not cc: fail('clang/cc not available')
    OUT.mkdir()
    gen_source=OUT/'step9_measurements.c'
    score_source=OUT/'step9_hypothesis_search.c'
    gen_source.write_text(GENERATE_C)
    score_source.write_text(SCORE_C)
    openssl, otype = openssl_flags()
    print('STEP 9: controlled PRF hypothesis-model test')
    print('Source: your corrected SPHINCS+ code, no source modifications')
    print('OpenSSL:',otype)
    print('Threat model: 14 known seed bytes; 2 unknown bytes (16 bits); 16 known addresses')
    print('Measurement: exact Hamming weight of FIRST PRF-output byte per address')
    print('Caution: this artificial restricted-key test is NOT an unrestricted seed attack')
    for name, source in [('step9_measurements',gen_source),('step9_hypothesis_search',score_source)]:
        prog=OUT/name
        cmd=[cc,'-std=c99','-O2','-Wall','-Wextra','-I'+str(SRC),'-o',str(prog)]
        cmd += [str(SRC/x) for x in SOURCES]+[str(source)]+openssl
        proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
        (OUT/(name+'.build.log')).write_text('COMMAND: '+' '.join(cmd)+'\n'+proc.stdout+proc.stderr)
        if proc.returncode:
            fail('C compilation failed. Send {}.build.log, last lines:\n{}'.format(name,'\n'.join(proc.stderr.splitlines()[-15:])))
    print('Compilation: PASS (generator and independent hypothesis scorer)')
    # Only 2 unknown bytes, generated using real OS randomness. The secret never
    # appears in attacker data and is not passed to the hypothesis-search program.
    seed=bytes(range(14))+os.urandom(2)
    fixture=OUT/'private_test_seed.bin'
    fixture.write_bytes(seed)
    try: os.chmod(str(fixture),0o600)
    except OSError: pass
    public=OUT/'known_addresses_and_hw.bin'
    generated=subprocess.run([str(OUT/'step9_measurements'),str(fixture),str(public)],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
    if generated.returncode: fail('PRF data generation failed: '+generated.stderr)
    if public.stat().st_size!=16*(22+1): fail('Unexpected observation-file size')
    print('Generated 16 PUBLIC PRF-address/HW observation pairs using real C executions')
    print('Measurement file size: {} bytes (expected 368)'.format(public.stat().st_size))
    recovered_file=OUT/'candidate_suffix_private.bin'
    attack=subprocess.run([str(OUT/'step9_hypothesis_search'),str(public),str(recovered_file)],
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
    if attack.returncode: fail('Hypothesis search could not uniquely identify candidate: '+attack.stdout+' '+attack.stderr)
    print(attack.stdout.strip())
    counts={int(k):int(v) for k,v in re.findall(r'SURVIVORS_(\d+)=(\d+)',attack.stdout)}
    if set(counts)!={1,2,4,6,8,12,16}: fail('Missing hypothesis-search results')
    suffix=recovered_file.read_bytes()
    # Truth validation is OUTSIDE attack code and AFTER predictions are finalized.
    truth_ok = len(suffix)==2 and suffix==seed[14:]
    print('Unique inferred 2-byte suffix equals private test fixture:', 'PASS' if truth_ok else 'FAIL')
    if not truth_ok: fail('Candidate disagrees with private fixture')
    note=('STRICTLY CONTROLLED TEST: 14/16 seed bytes are given to the scorer. '
          'Perfect software HW observations, no physical measurement. '
          'Not 128-bit seed recovery, not Pearson CPA, not a deployment exploit.')
    report={
        'status':'PASS',
        'description':note,
        'source':'User SPHINCS+ C implementation: prf_addr() and address.c',
        'unknown_seed_bits':16,
        'known_seed_bytes':14,
        'num_observations':16,
        'observed_HW_bytes_per_address':1,
        'surviving_candidates_by_num_observations':{str(k):v for k,v in counts.items()},
        'one_candidate_matches_private_fixture':truth_ok,
        'observations_sha256':sha(public),
        'scorer_source_sha256':sha(score_source),
        'generator_source_sha256':sha(gen_source),
        'prf_source_sha256':sha(SRC/'hash_sha256.c'),
    }
    (OUT/'step9_aggregate_results.json').write_text(json.dumps(report,indent=2)+'\n')
    print('STEP 9 PASS: public-input hypotheses generated without using target suffix')
    print('Aggregate report:', OUT/'step9_aggregate_results.json')
    print('Keep private_test_seed.bin and candidate_suffix_private.bin PRIVATE.')

if __name__=='__main__': main()
