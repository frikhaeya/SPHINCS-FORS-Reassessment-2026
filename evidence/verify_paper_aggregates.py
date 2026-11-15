#!/usr/bin/env python3
"""Verify the aggregate numerical claims in the paper using only the supplied Step 12 archive.
This checks aggregate consistency; it cannot authenticate private trial fixtures or rerun experiments.
Python 3.9+ standard library only.
"""
from pathlib import Path
import json, zipfile, math, statistics

archive = Path(__file__).with_name('step12_paper_evidence.zip')
assert archive.is_file(), 'Place supplied step12_paper_evidence.zip beside this script'
with zipfile.ZipFile(archive) as z:
    def load(path):
        return json.loads(z.read('step12_paper_evidence/' + path))
    step5=load('step5_audit.json');step7=load('step7/step7_aggregate_results.json')
    step8=load('step8.json');step9=load('step9.json');step10=load('step10.json');step11=load('step11.json')

assert step5['signatures']==3 and step5['samples']==1584
assert step5['public_FORS_matches']==1584 and step5['public_computed_HW_matches']==1584
print('Selected-secret public reconstruction: 1,584/1,584')
hist={int(k):int(v) for k,v in step7['weight_histogram'].items()}
assert sum(hist.values())==99792 and hist[0]==396 and hist[8]==415
single=hist[0]+hist[8]
assert single==811 and abs(100*single/sum(hist.values())-0.812690396)<1e-6
h=-sum(v/99792*math.log2(v/99792) for v in hist.values() if v)
m=sum(v/99792*math.log2(math.comb(8,k)) for k,v in hist.items())
assert abs(h-step7['empirical_descriptive_metrics']['observed_weight_histogram_shannon_entropy_bits'])<1e-10
assert abs(m-step7['empirical_descriptive_metrics']['mean_log2_number_of_compatible_bytes'])<1e-10
print('Non-selected leaf HW: 99,792 values, 811 singleton determinations, %.4f%%, H(W)=%.4f bits' % (100*single/99792,h))
assert step8['cross_signature_pairs_sharing_global_leaf_index']==6140
assert step8['of_those_pairs_with_different_prf_addresses']==6140
assert step8['of_those_pairs_with_same_prf_address']==0
assert step8['distinct_full_prf_addresses']==6237
print('Address audit: 6,140 matching-index pairs, no full-address matches')
assert step9['known_seed_bytes']==14 and step9['unknown_seed_bits']==16
assert step9['one_candidate_matches_private_fixture'] is True
assert step9['surviving_candidates_by_num_observations']['1']==17841
assert step9['surviving_candidates_by_num_observations']['6']==27
assert step9['surviving_candidates_by_num_observations']['8']==1
print('Initial PRF suffix test: candidate counts match reported checkpoints')
for name, obj, key in [('fixed',step10,'checkpoints'),('varied',step11,'survivors_by_observation_count')]:
    records=obj['per_trial_aggregates']
    assert len(records)==20
    for t in [1,2,4,6,8,12,16]:
        counts=[r['surviving_candidates'][str(t)] for r in records]
        expected=obj[key][str(t)]
        assert min(counts)==expected['min'] and max(counts)==expected['max']
        assert statistics.median(counts)==expected['median']
        assert sum(c==1 for c in counts)==expected['unique_trials']
    assert all(r['matches_private_fixture'] for r in records)
    assert [sum(r['surviving_candidates'][str(t)]==1 for r in records) for t in (6,8,12)] == ([10,19,20] if name=='fixed' else [1,19,20])
    print('%s contexts: 20 trial aggregates verified; unique @6/8/12 = %s' % (name,'10/19/20' if name=='fixed' else '1/19/20'))
print('ALL AGGREGATE-ONLY CHECKS PASS. This does not verify private seed fixtures.')
