'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { ancestorPrefixes, buildRouteLookup } = require('./prefix-lookup');
function ipv4(bytes) { const buffer=Buffer.alloc(16);Buffer.from(bytes).copy(buffer,12);return {family:4,buffer}; }
test('IPv4 ancestry preserves exact addresses and subnet boundaries',()=>{
 const parsed=ipv4([90,191,235,189]),original=Buffer.from(parsed.buffer),prefixes=ancestorPrefixes(parsed);
 assert.equal(prefixes.length,33);
 const start=length=>prefixes.find(p=>p.length===length).start.toString('hex');
 assert.equal(start(32),'0000000000000000000000005abfebbd');
 assert.equal(start(31),'0000000000000000000000005abfebbc');
 assert.equal(start(25),'0000000000000000000000005abfeb80');
 assert.equal(start(24),'0000000000000000000000005abfeb00');
 assert.equal(start(8),'0000000000000000000000005a000000');
 assert.equal(start(0),'00000000000000000000000000000000');
 assert.deepEqual(parsed.buffer,original);
});
test('IPv6 ancestry handles non-byte-aligned prefixes and /0',()=>{
 const parsed={family:6,buffer:Buffer.from('20010db8123456789abcdef012345678','hex')},prefixes=ancestorPrefixes(parsed);
 assert.equal(prefixes.length,129);
 const start=length=>prefixes.find(p=>p.length===length).start.toString('hex');
 assert.equal(start(128),parsed.buffer.toString('hex'));
 assert.equal(start(65),'20010db8123456788000000000000000');
 assert.equal(start(64),'20010db8123456780000000000000000');
 assert.equal(start(32),'20010db8000000000000000000000000');
 assert.equal(start(0),'00000000000000000000000000000000');
});
test('Every candidate exactly matches the mathematical CIDR mask',()=>{
 for(const family of [4,6])for(let sample=0;sample<20;sample++){
  const width=family===4?32:128,buffer=Buffer.alloc(16);
  for(let i=family===4?12:0;i<16;i++)buffer[i]=(sample*79+i*131)&255;
  const value=BigInt('0x'+buffer.toString('hex'));
  for(const prefix of ancestorPrefixes({family,buffer})){
   const hostBits=BigInt(width-prefix.length);
   const expected=(value>>hostBits)<<hostBits;
   assert.equal(BigInt('0x'+prefix.start.toString('hex')),expected);
  }
 }
});
test('Route SQL binds primary-index prefixes and preserves visibility order and limit',()=>{
 const parsed=ipv4([255,255,255,255]),query=buildRouteLookup(parsed);
 assert.equal((query.sql.match(/\?/g)||[]).length,query.params.length);
 assert.equal(query.params[0],4);
 assert.deepEqual(query.params.at(-1),parsed.buffer);
 assert.match(query.sql,/route.start_ip = \? AND route.prefix_length = \?/);
 assert.match(query.sql,/ORDER BY route.prefix_length DESC, route.visibility DESC/);
 assert.match(query.sql,/LIMIT 16/);
});
