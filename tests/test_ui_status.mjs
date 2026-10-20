// UI contract: backend diagnostics stay out of library/status text.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const html=readFileSync(new URL('../web/ui.html',import.meta.url),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
assert(!html.slice(html.indexOf('<main'),html.indexOf('<section id="library"')).includes('id="status"'));
assert(html.slice(html.indexOf('<aside'),html.indexOf('</aside>')).includes('id="activity"'));
const nodes=new Map();
function $(id){if(!nodes.has(id))nodes.set(id,{hidden:true,textContent:'',value:0,removeAttribute(){}});return nodes.get(id);}
const errors=[],timers=[];
let nextState;
const context=vm.createContext({$,clearTimeout(){},setTimeout(fn){timers.push(fn);return timers.length;},activityTimer:null,
 scanning:false,busy:false,runtimeActive:false,jobKind:'',lastSerial:0,lastErrorId:0,requestedLaunch:false,
 api:async()=>nextState,lock(){},showError(e){errors.push(e);},scan:async()=>{}});
vm.runInContext(script.slice(script.indexOf('function status('),script.indexOf('function lock(')),context);
vm.runInContext(script.slice(script.indexOf('async function poll('),script.indexOf('(async()=>')),context);
const raw='RAW_DIAGNOSTIC: process observation, crash check, /internal/path';
const base={message:raw,job:'launch',serial:0,result:0,busy:false,runtime_active:false,runtime_phase:0,done:0,total:0};
function noRawStatus(){for(const id of ['status','activityLabel','extractStatus'])assert(!$(id).textContent.includes('RAW_DIAGNOSTIC'));}
async function poll(patch){nextState={...base,...patch};await vm.runInContext('poll()',context);noRawStatus();}
await poll({busy:true});assert.equal($('activityLabel').textContent,'Oyun açılıyor');
await poll({runtime_active:true,runtime_phase:2});assert.equal($('activityLabel').textContent,'Oyun açık');
await poll({runtime_active:true,runtime_phase:3});assert.equal($('activityLabel').textContent,'Oyun kapatılıyor');
await poll({});assert.equal($('activityLabel').textContent,'Oyun kapandı');
const expire=timers.at(-2);expire();assert.equal($('activity').hidden,true);
await poll({});assert.equal($('activity').hidden,true); // old idle backend message must not reappear
await poll({job:'extract',busy:true,done:100,total:200});assert.equal($('extractStatus').textContent,'Dosyalar çıkarılıyor…');assert.equal($('extractProgress').value,50);
context.requestedLaunch=true;await poll({serial:1,result:1});assert.equal(errors.length,0);assert.equal($('activityLabel').textContent,'Oyun kapandı');
context.requestedLaunch=true;await poll({serial:2,result:-1});assert.equal(errors.length,1);assert(!errors[0].message.includes(raw));assert.equal(errors[0].detail,raw);
console.log('PASS: no header status, simple operation labels, extraction-only progress, expired idle notices stay hidden, early exit is not a crash claim, diagnostics only in optional error details');
