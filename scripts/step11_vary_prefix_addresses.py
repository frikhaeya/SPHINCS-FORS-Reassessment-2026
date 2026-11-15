#!/usr/bin/env python3
"""Step 11: controlled repeatability with a NEW known prefix and NEW valid PRF addresses per trial.

Only source is the user's existing SPHINCS+ C implementation. We compile two
independent test harnesses against prf_addr() from that implementation:
  - generator uses a full private 16-byte test seed to produce public HW(addr)
  - scorer uses only PUBLIC 14-byte prefix and public address/HW pairs to test
    all 65536 candidate two-byte suffixes.

Twenty synthetic/restricted-key validation trials, *not* an unrestricted key
recovery, Pearson CPA, or physical side-channel experiment. No claim of a
natural leakage source. Never publishes test seeds or guessed private suffix.

Python 3.9+, C compiler, OpenSSL. Run from SPHINCS-FORS-CORRECTED root.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import secrets
import shutil
import statistics
import subprocess
import sys

ROOT=Path.cwd()
SRC=ROOT/'sphincs-sha256-128f-code'
OUT=ROOT/'step11_varied_prf_20261112'
TRIALS=20
STOPS=(1,2,4,6,8,12,16)
SOURCES=['address.c','rng.c','wots.c','utils.c','fors.c','sign.c',
         'hash_sha256.c','thash_sha256_simple.c','logger.c','sha256.c']

GEN_C=r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hash.h"
#include "address.h"
#include "params.h"
#include "sha256.h"
#define NOBS 16
#define NADDR 22
static uint8_t hw(uint8_t x) { uint8_t n=0; while (x) { n+=(uint8_t)(x&1u); x>>=1; } return n; }
int main(int argc, char **argv) {
  uint8_t seed[SPX_N],ctx[8+1+2*NOBS],out[SPX_N];
  uint32_t addr[8]={0};
  uint64_t tree=0;
  FILE *f,*o;
  unsigned int i;
  if(argc!=4 || SPX_N!=16 || SPX_SHA256_ADDR_BYTES!=NADDR) return 2;
  f=fopen(argv[1],"rb"); if(!f) return 3;
  if(fread(seed,1,16,f)!=16 || fgetc(f)!=EOF) { fclose(f); return 4; }
  fclose(f);
  f=fopen(argv[2],"rb"); if(!f) return 5;
  if(fread(ctx,1,sizeof(ctx),f)!=sizeof(ctx) || fgetc(f)!=EOF) { fclose(f); return 6; }
  fclose(f);
  for(i=0;i<8;i++) tree |= ((uint64_t)ctx[i])<<(i*8);
  o=fopen(argv[3],"wb"); if(!o) return 7;
  for(i=0;i<NOBS;i++) {
    uint16_t index=(uint16_t)((unsigned int)ctx[9+2*i] | ((unsigned int)ctx[10+2*i]<<8));
    uint8_t leak;
    if (index>=2112u || ctx[8]>=8u) { fclose(o); return 8; }
    memset(addr,0,sizeof(addr));
    set_layer_addr(addr,0);
    set_tree_addr(addr,tree);
    set_type(addr,SPX_ADDR_TYPE_FORSTREE);
    set_keypair_addr(addr,ctx[8]);
    set_tree_height(addr,0);
    set_tree_index(addr,index);
    prf_addr(out,seed,addr);
    leak=hw(out[0]);
    if(fwrite(addr,1,NADDR,o)!=NADDR || fwrite(&leak,1,1,o)!=1) { fclose(o); return 9; }
  }
  if(fclose(o)) return 10;
  return 0;
}
'''

SCORE_C=r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hash.h"
#include "params.h"
#include "sha256.h"
#define NOBS 16
#define NADDR 22
static uint8_t hw(uint8_t x) { uint8_t n=0; while (x) { n+=(uint8_t)(x&1u); x>>=1; } return n; }
int main(int argc, char **argv) {
  uint8_t seed[SPX_N],adrs[NOBS][NADDR],leaks[NOBS],v[SPX_N];
  uint32_t addr[8];
  const int stops[7]={1,2,4,6,8,12,16};
  unsigned long counts[7]={0};
  unsigned int cand,i,j;
  int last=-1;
  FILE *f;
  if(argc!=4 || SPX_N!=16 || SPX_SHA256_ADDR_BYTES!=NADDR) return 2;
  f=fopen(argv[1],"rb"); if(!f) return 3;
  if(fread(seed,1,14,f)!=14 || fgetc(f)!=EOF) { fclose(f); return 4; }
  fclose(f);
  f=fopen(argv[2],"rb"); if(!f) return 5;
  for(i=0;i<NOBS;i++) {
    if(fread(adrs[i],1,NADDR,f)!=NADDR || fread(leaks+i,1,1,f)!=1 || leaks[i]>8) { fclose(f); return 6; }
    for(j=0;j<i;j++) if(!memcmp(adrs[j],adrs[i],NADDR)) { fclose(f); return 7; }
  }
  if(fgetc(f)!=EOF) { fclose(f); return 8; }
  fclose(f);
  for(cand=0;cand<65536u;cand++) {
    int matched=0;
    seed[14]=(uint8_t)(cand&0xffu);
    seed[15]=(uint8_t)(cand>>8);
    for(i=0;i<NOBS;i++) {
      memset(addr,0,sizeof(addr));
      memcpy(addr,adrs[i],NADDR);
      prf_addr(v,seed,addr);
      if(hw(v[0])!=leaks[i]) break;
      matched++;
    }
    for(i=0;i<7;i++) if(matched>=stops[i]) counts[i]++;
    if(matched==NOBS) last=(int)cand;
  }
  for(i=0;i<7;i++) printf("SURVIVORS_%d=%lu\n",stops[i],counts[i]);
  if(counts[6]==1) {
    uint8_t suffix[2]={ (uint8_t)(last&255),(uint8_t)(last>>8) };
    f=fopen(argv[3],"wb"); if(!f) return 9;
    if(fwrite(suffix,1,2,f)!=2 || fclose(f)) return 10;
  }
  return 0;
}
'''


def fail(msg): sys.exit('STEP 11 ERROR: '+msg)
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):
    return subprocess.run([str(a) for a in args],stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,universal_newlines=True)
def private_bytes(p,b):
    p.write_bytes(b)
    try: os.chmod(str(p),0o600)
    except OSError: pass

def openssl_flags():
    pc=shutil.which('pkg-config')
    if pc:
        proc=run([pc,'--exists','openssl'])
        if proc.returncode==0:
            proc=run([pc,'--cflags','--libs','openssl'])
            if proc.returncode==0:return proc.stdout.strip().split(),'pkg-config openssl'
    brew=shutil.which('brew')
    if brew:
        for n in ('openssl@3','openssl'):
            p=run([brew,'--prefix',n])
            if p.returncode==0:
                prefix=Path(p.stdout.strip())
                if (prefix/'include'/'openssl'/'evp.h').is_file():
                    return ['-I'+str(prefix/'include'),'-L'+str(prefix/'lib'),'-lcrypto'],'Homebrew '+n
    return ['-lcrypto'],'system libcrypto'

def main():
    if OUT.exists(): fail('{} already exists; do not overwrite, rename it first'.format(OUT))
    for x in SOURCES+['params.h','hash.h','sha256.h']:
        if not (SRC/x).is_file(): fail('Required original C source missing: '+x)
    if not re.search(r'^\s*#define\s+SPX_N\s+16\b',(SRC/'params.h').read_text(),re.M):
        fail('Unexpected SPX_N (expected 16)')
    cc=shutil.which('clang') or shutil.which('cc')
    if not cc: fail('No C compiler found')
    OUT.mkdir()
    openssl,backend=openssl_flags()
    print('STEP 11: varied-prefix and varied-address robustness check')
    print('Source: your PRF C implementation; no source modifications')
    print('OpenSSL:',backend)
    print('20 trials, new random 14-byte KNOWN prefix + 2-byte UNKNOWN suffix per trial')
    print('16 fresh valid FORS PRF addresses per trial, exact HW of first output byte')
    print('Restricted key-guess validation only: NOT CPA, full seed recovery, or physical leakage')
    for name,src in [('step11_generator',GEN_C),('step11_scorer',SCORE_C)]:
        srcpath=OUT/(name+'.c')
        srcpath.write_text(src)
        cmd=[cc,'-std=c99','-O2','-Wall','-Wextra','-I'+str(SRC),'-o',str(OUT/name)]+[str(SRC/s) for s in SOURCES]+[str(srcpath)]+openssl
        p=run(cmd)
        (OUT/(name+'.build.log')).write_text('COMMAND: '+' '.join(str(i) for i in cmd)+'\n'+p.stdout+p.stderr)
        if p.returncode: fail('{} compile failed:\n{}'.format(name,'\n'.join(p.stderr.splitlines()[-12:])))
    print('Compile generator and independent scorer: PASS')
    records=[]
    distinct_prefixes=set()
    distinct_contexts=set()
    for trial in range(1,TRIALS+1):
        d=OUT/('trial_%02d'%trial)
        d.mkdir()
        seed=secrets.token_bytes(16)
        prefix=seed[:14]
        while prefix in distinct_prefixes:
            seed=secrets.token_bytes(16)
            prefix=seed[:14]
        distinct_prefixes.add(prefix)
        seedfile=d/'private_test_seed.bin'; private_bytes(seedfile,seed)
        prefixfile=d/'known_prefix_public.bin'; prefixfile.write_bytes(prefix)
        # Address context selected independently from secret. Keep all indices
        # within the actual 33*64 FORS leaf positions and the keypair within 0..7.
        tree=secrets.randbits(48)
        kp=secrets.randbelow(8)
        indices=secrets.SystemRandom().sample(range(2112),16)
        context=tree.to_bytes(8,'little')+bytes([kp])+b''.join(i.to_bytes(2,'little') for i in indices)
        while context in distinct_contexts:
            tree=secrets.randbits(48); kp=secrets.randbelow(8)
            indices=secrets.SystemRandom().sample(range(2112),16)
            context=tree.to_bytes(8,'little')+bytes([kp])+b''.join(i.to_bytes(2,'little') for i in indices)
        distinct_contexts.add(context)
        ctxpath=d/'known_address_config.bin'; ctxpath.write_bytes(context)
        obs=d/'known_addresses_and_hw.bin'
        gp=run([OUT/'step11_generator',seedfile,ctxpath,obs])
        if gp.returncode: fail('Generator trial %02d exit %d: %s'%(trial,gp.returncode,gp.stderr))
        buf=obs.read_bytes()
        if len(buf)!=16*23 or len({buf[i:i+22] for i in range(0,len(buf),23)})!=16:
            fail('Invalid observations or addresses in trial %d'%trial)
        if any(buf[i]>8 for i in range(22,len(buf),23)):
            fail('Invalid HW byte in trial %d'%trial)
        guess=d/'candidate_suffix_private.bin'
        sp=run([OUT/'step11_scorer',prefixfile,obs,guess])
        if sp.returncode: fail('Scorer trial %02d failed: %s'%(trial,sp.stderr))
        counts={int(a):int(b) for a,b in re.findall(r'SURVIVORS_(\d+)=(\d+)',sp.stdout)}
        if set(counts)!=set(STOPS): fail('Scorer output incomplete in trial %d'%trial)
        ns=[counts[k] for k in STOPS]
        if not all(ns[i]>=ns[i+1]>=1 for i in range(len(ns)-1)):
            fail('Inconsistent counts trial %d'%trial)
        unique=(counts[16]==1)
        match=False
        if unique:
            if not guess.is_file(): fail('Unique prediction missing in trial %d'%trial)
            match=(guess.read_bytes()==seed[14:])
            if not match: fail('Unique prediction does NOT match private fixture (trial %d)'%trial)
            try: os.chmod(str(guess),0o600)
            except OSError:pass
        records.append({'trial':trial,'surviving_candidates':{str(k):counts[k] for k in STOPS},
                        'unique_at_16':unique,'matches_private_fixture':match,'observation_sha256':sha(obs),
                        'address_configuration_sha256':sha(ctxpath)})
        print('Trial %02d | unique@8=%s unique@12=%s unique@16=%s %s | survivors@16=%d'%(
            trial,'YES' if counts[8]==1 else 'NO', 'YES' if counts[12]==1 else 'NO',
            'YES' if unique else 'NO', 'fixture=PASS' if match else 'fixture=NOT_UNIQUE',counts[16]))
    summary={str(k):{'unique_trials':sum(r['surviving_candidates'][str(k)]==1 for r in records),
                     'min':min(r['surviving_candidates'][str(k)] for r in records),
                     'median':statistics.median(r['surviving_candidates'][str(k)] for r in records),
                     'max':max(r['surviving_candidates'][str(k)] for r in records)} for k in STOPS}
    aggregate={'status':'COMPLETED','scope':'Controlled noiseless, restricted 16-bit suffix only. 14 of 16 seed bytes known per trial. New independent known prefix and distinct address context per trial. Not a physical side-channel attack, Pearson CPA, or unrestricted 128-bit key recovery.',
               'trials':TRIALS,'distinct_known_prefixes':len(distinct_prefixes),
               'distinct_address_contexts':len(distinct_contexts),'survivors_by_observation_count':summary,
               'unique_and_correct_at_16':sum(r['matches_private_fixture'] for r in records),
               'source_hashes':{'hash_sha256.c':sha(SRC/'hash_sha256.c'),'params.h':sha(SRC/'params.h'),
                                'generator_c':sha(OUT/'step11_generator.c'),'scorer_c':sha(OUT/'step11_scorer.c')},
               'per_trial_aggregates':records}
    dest=OUT/'step11_aggregate_results.json'
    dest.write_text(json.dumps(aggregate,indent=2)+'\n')
    print('\nSUMMARY (unique and correct @16): %d/%d'%(aggregate['unique_and_correct_at_16'],TRIALS))
    for k in STOPS:
        e=summary[str(k)]
        print('After %2d observations: unique in %d/%d; survivor min/median/max %s/%s/%s'%(
              k,e['unique_trials'],TRIALS,e['min'],e['median'],e['max']))
    print('Distinct known prefixes:',len(distinct_prefixes),'; distinct address contexts:',len(distinct_contexts))
    print('Aggregate-only report:',dest)
    print('PRIVATE: do not upload trial_*/private_test_seed.bin or candidate_suffix_private.bin')
    print('STEP 11 COMPLETE: interpret as constrained hypothesis test only.')

if __name__=='__main__': main()
