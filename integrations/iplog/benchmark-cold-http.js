'use strict';
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { loadConfig } = require('/home/container/util/config');
const { createDatabasePool } = require('/home/container/util/mysql');
const original = require('/home/container/util/lookup.before-prefix-optimization');
const optimized = require('/home/container/util/lookup.optimized');
const lookupPath = require.resolve('/home/container/util/lookup');
const appPath = require.resolve('/home/container/app');
require(lookupPath);
function loadApp(lookup) {
 require.cache[lookupPath].exports = lookup;
 delete require.cache[appPath];
 return require(appPath).createApp;
}
const originalApp = loadApp(original), optimizedApp = loadApp(optimized);
const addresses=['1.1.1.1','8.8.8.8','208.67.222.222','89.144.8.232','90.191.235.189','185.199.108.153','104.16.132.229','193.0.6.139','2001:4860:4860::8888','2606:4700:4700::1111','2620:fe::fe','2a00:1450:4001:800::200e'];
const coldCache=()=>({get:async()=>null,set:async()=>{}});
const core=data=>Object.fromEntries(['ip','family','is_tor','route','asns','allocation','sources'].map(k=>[k,data[k]]));
function stats(values){const s=[...values].sort((a,b)=>a-b);return {median_ms:+s[Math.floor(s.length/2)].toFixed(2),p90_ms:+s[Math.min(s.length-1,Math.floor(s.length*.9))].toFixed(2),mean_ms:+(s.reduce((a,b)=>a+b,0)/s.length).toFixed(2)}}
async function main(){
 const config=loadConfig(),db=createDatabasePool(config.database),servers=[];
 try{
  console.log(JSON.stringify({databaseHost:config.database.host,databasePort:config.database.port,poolSize:config.database.connectionLimit,redisConfigured:!!config.redis,mode:'core cache forced miss; real abuse provider; optional lookups off'}));
  for(const createApp of [originalApp,optimizedApp]){
   const app=createApp({database:db,cache:coldCache(),config});
   const server=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server))});servers.push(server);
  }
  const timings=[[],[]];
  for(let i=0;i<addresses.length;i++){
   const result=[];
   for(const mode of i%2?[1,0]:[0,1]){
    const url=new URL('/checkip','http://127.0.0.1:'+servers[mode].address().port);
    for(const [k,v] of Object.entries({ip:addresses[i],ports:'no',hostname:'no',registration:'no'}))url.searchParams.set(k,v);
    const start=performance.now(),response=await fetch(url),body=await response.json();
    const elapsed=performance.now()-start;
    assert.equal(response.status,200);assert.equal(body.cache,'miss');
    timings[mode].push(elapsed);result[mode]=body;
   }
   assert.deepEqual(core(result[1].data),core(result[0].data),'Core data changed for '+addresses[i]);
   console.log(JSON.stringify({address:addresses[i],baseline_ms:+timings[0].at(-1).toFixed(2),optimized_ms:+timings[1].at(-1).toFixed(2),baseline_abuse:!!result[0].data.abuse,optimized_abuse:!!result[1].data.abuse,core_equal:true}));
  }
  console.log(JSON.stringify({summary:{pairs:addresses.length,baseline:stats(timings[0]),optimized:stats(timings[1]),mean_reduction_percent:+((1-timings[1].reduce((a,b)=>a+b,0)/timings[0].reduce((a,b)=>a+b,0))*100).toFixed(1)}}));
 }finally{await Promise.all(servers.map(s=>new Promise(resolve=>s.close(resolve))));await db.end()}
}
main().catch(error=>{console.error({name:error.name,message:error.message,code:error.code});process.exitCode=1});
