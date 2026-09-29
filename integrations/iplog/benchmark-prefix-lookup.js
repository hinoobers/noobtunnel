'use strict';
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { createDatabasePool } = require('/home/container/util/mysql');
const { parseIp } = require('/home/container/util/ip');
const { lookupIp } = require('/home/container/util/lookup.before-prefix-optimization');
const { lookupIp: optimizedLookupIp } = require('/home/container/util/lookup.optimized');
const { buildRouteLookup } = require('/home/container/util/prefix-lookup');
const addresses = ['1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222','89.144.8.232','90.191.235.189','79.76.44.220','185.199.108.153','4.2.2.1','45.33.32.156','104.16.132.229','193.0.6.139','2001:4860:4860::8888','2606:4700:4700::1111','2620:fe::fe','2a00:1450:4001:800::200e'];
function stats(values) { const s=[...values].sort((a,b)=>a-b); return { median_ms:+s[Math.floor(s.length/2)].toFixed(2), p90_ms:+s[Math.min(s.length-1,Math.floor(s.length*.9))].toFixed(2), mean_ms:+(s.reduce((a,b)=>a+b,0)/s.length).toFixed(2) }; }
async function main() {
 const db=createDatabasePool();
 try {
  const [version]=await db.query('SELECT VERSION() AS version');
  const [indexes]=await db.query('SHOW INDEX FROM bgp_prefixes');
  console.log(JSON.stringify({version:version[0].version,indexes:indexes.map(x=>({key:x.Key_name,column:x.Column_name,sequence:x.Seq_in_index}))}));
  const old=[], fast=[], records=[];
  for (let round=0;round<2;round++) for (const address of addresses) {
   const parsed=parseIp(address), phases={};
   let a,b;
   for (const mode of round===0?['old','fast']:['fast','old']) {
    const start=performance.now();
    const value=await (mode==='old'?lookupIp:optimizedLookupIp)(db,parsed,q=>{(phases[mode] ||= {})[q.stage]=q.durationMs});
    const elapsed=performance.now()-start;
    if(mode==='old'){a=value;old.push(elapsed)}else{b=value;fast.push(elapsed)}
   }
   assert.deepEqual(b,a,'Lookup changed for '+address);
   records.push({family:parsed.family,phases});
   console.log(JSON.stringify({address,phases,equal:true}));
  }
  console.log(JSON.stringify({summary:{cases:records.length,baseline:stats(old),optimized:stats(fast),mean_reduction_percent:+((1-fast.reduce((a,b)=>a+b,0)/old.reduce((a,b)=>a+b,0))*100).toFixed(1)}}));
  const p=parseIp('90.191.235.189'),q=buildRouteLookup(p);
  const [plan]=await db.query('EXPLAIN FORMAT=JSON '+q.sql,q.params);
  const planText=JSON.parse(plan[0].EXPLAIN);console.log(JSON.stringify({optimized_plan:planText.query_block.nested_loop.map(x=>{const t=x.table||x.read_sorted_file?.filesort?.table;return {table:t?.table_name,access:t?.access_type,index:t?.key,keyParts:t?.used_key_parts,rows:t?.rows}})}));
 } finally {await db.end()}
}
main().catch(error=>{console.error({name:error.name,message:error.message,code:error.code});process.exitCode=1});
