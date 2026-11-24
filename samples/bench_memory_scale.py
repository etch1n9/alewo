#!/usr/bin/env python3
"""Memory scalability smoke: synthetic index workload, ISOLATED TEST DB.
No inference, no secrets, no claim that synthetic observations are true.
Uses actual alewo memory add/approve/search commands for each operation.
"""
from pathlib import Path
import os,json,subprocess,hashlib,time,statistics,random

root=Path('/workspace/alewo/data/benchmark/20261121-memory-scale')
root.mkdir(parents=True,exist_ok=True)
os.chmod(root,0o700)
db=root/'synthetic-memory.sqlite'
assert not db.exists(), "Refusing to reuse existing scalability database"
src=Path('/workspace/alewo/data/benchmark/20261121-blind-prefix/case01.php')
sha=hashlib.sha256(src.read_bytes()).hexdigest()
N=300
APPROVED=60
env=dict(os.environ,ALEWO_DB=str(db))
event_file=root/'candidate.json'
jsonl=root/'raw-events.jsonl'
samples=[]
def run(*argv):
    start=time.perf_counter()
    proc=subprocess.run(['alewo','memory',*argv],capture_output=True,text=True,env=env)
    elapsed=time.perf_counter()-start
    if proc.returncode!=0:
        raise RuntimeError(' '.join(argv[:2]) + " failed: " + proc.stderr[:280])
    return json.loads(proc.stdout),elapsed

add_lats=[]
approve_lats=[]
with open(jsonl,'w') as outfile:
    for i in range(N):
        # Intentionally synthetic: generated placeholder experiences.
        # Only proving memory store/index performance, NOT their truth.
        record={
          'scope':'synthetic-perf',
          'kind':'bug',
          'sig':f'php:prefix:synth{i:04}',
          'obs':['LANG:PHP','OP:LOOSE_EQ','RESULT:BOOL','FAMILY:FALSE_EQ_ZERO',f'SIGNATURE:synth{i:04}'],
          'actions':['TEST:ROUTE','CHECK:AUTH'],
          'outcomes':['FOUND:WRONG_COMPARISON',f'CASE:synth{i:04}'],
          'corrections':['PATCH:STRICT_COMPARE'],
          'tags':['php','prefix','authorization',f'synth{i:04}'],
          'evidence':[{'path':str(src),'sha256':sha}],
        }
        raw=json.dumps(record,sort_keys=True,separators=(',',':'))
        outfile.write(raw+'\n')
        event_file.write_text(raw)
        reply,lat=run('add','--file',str(event_file))
        assert reply['state']=='pending'
        add_lats.append(lat)
        if i<APPROVED:
            approval,lat=run('approve','--id',reply['id'])
            assert approval['status'].startswith('approved')
            approve_lats.append(lat)
random.seed(20261121)
queries=[f'synth{random.randrange(APPROVED):04}' for _ in range(40)]
search_lats=[]
hit_counts=[]
for q in queries:
    value,lat=run('search','--scope','synthetic-perf','--query',q,'--limit','3','--max-chars','600')
    search_lats.append(lat)
    hit_counts.append(len(value.get('records',[])))
    assert len(value.get('records',[]))==1,(q,value)
other,lat=run('search','--scope','other-project','--query','synth0009')
assert not other.get('records')
stats,_=run('stats')
raw_bytes=jsonl.stat().st_size
payload=sum(x['compressed_bytes'] for x in stats['states'])
disk_bytes=sum(p.stat().st_size for p in root.glob('synthetic-memory.sqlite*'))
def pct(l,q):
    s=sorted(l)
    return round(s[max(0,min(len(s)-1,int((len(s)-1)*q))) ]*1000,3)
report={
 'experiment':'Alewo memory CLI 300 synthetic episodes (not factual bug experiences)',
 'entries':N,'approved_entries':APPROVED,
 'memory_database':str(db),'evidence_file':str(src),
 'per_entry_jsonl_raw_bytes':raw_bytes/N,
 'raw_jsonl_bytes':raw_bytes,
 'zstd_cbor_payload_bytes':payload,
 'zstd_cbor_payload_saving_pct':round((1-payload/raw_bytes)*100,3),
 'sqlite_db_and_journal_bytes':disk_bytes,
 'sqlite_relative_to_jsonl':round(disk_bytes/raw_bytes,3),
 'add_ms_p50':pct(add_lats,.5),'add_ms_p95':pct(add_lats,.95),
 'approve_ms_p50':pct(approve_lats,.5),'approve_ms_p95':pct(approve_lats,.95),
 'fts_search_ms_p50':pct(search_lats,.5),'fts_search_ms_p95':pct(search_lats,.95),
 'fts_exact_hit_rate':sum(1 for n in hit_counts if n==1)/len(hit_counts),
 'fts_scope_isolation_passed':True,
 'note':'Runtime includes process startup and SQLite open/close for each operation. Source file reused as byte-bound proof but synthetic outcomes are not source-validated. No API inference made.'
}
(root/'result.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
