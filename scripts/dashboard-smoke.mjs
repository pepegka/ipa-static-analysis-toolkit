import fs from 'node:fs';
import vm from 'node:vm';
const REPO=new URL('..',import.meta.url).pathname.replace(/\/$/,'');
const data=fs.readFileSync(process.argv[2]||`${REPO}/results-us150/dashboard.json`,'utf8');

const ids=new Set(); const drawn=[]; const errors=[];
function el(id){ return { id, style:{setProperty(){}}, classList:{add(){},remove(){},toggle(){}},
  getAttribute:()=>null, setAttribute(){}, querySelectorAll:()=>[], querySelector:()=>null, addEventListener(){}, hidden:false, title:"",
  appendChild(){}, closest:()=>null, textContent:'', firstChild:{textContent:id},
  tBodies:[], rows:[], cells:[], getBoundingClientRect:()=>({width:0,height:0}) }; }
const doc={
  getElementById(id){ ids.add(id); return el(id); },
  querySelectorAll(){ return []; },
  addEventListener(){}, createElement:(t)=>el(t),
  documentElement:{ getAttribute:()=>null, setAttribute(){}, removeAttribute(){} },
};
const echarts={ init(d){ drawn.push(d.id); return {
  setOption(o){ try{ JSON.stringify(o,(k,v)=>typeof v==='function'?undefined:v); }
                catch(e){ errors.push(d.id+': '+e.message); } },
  resize(){}, dispose(){}, on(){}, }; } };
const ctx={ console, echarts, document:doc, window:{ addEventListener(){}, matchMedia:()=>({matches:true,addEventListener(){}}) },
  localStorage:{ getItem:()=>null, setItem(){} }, requestAnimationFrame:(f)=>f(),
  getComputedStyle:()=>({ getPropertyValue:(n)=>'#123456' }), Math, JSON, Object, Array, String, Number, Date, RegExp, parseFloat, parseInt, isNaN, Set };
ctx.window.document=doc; ctx.globalThis=ctx;
vm.createContext(ctx);
doc.getElementById=(id)=>{ ids.add(id);
  if(id==='msdata') return { textContent:data };
  if(id==='msadvice') return { textContent:'{}' };
  return el(id); };
for(const f of ['charts.js','comparator.js','insight-toggle.js','chrome.js']){
  try { vm.runInContext(fs.readFileSync(`${REPO}/Sources/ScannerKit/Resources/dashboard/${f}`,'utf8'), ctx, {filename:f}); }
  catch(e){ errors.push(`${f} load: ${e.message}`); }
}
try { ctx.window.__drawDashboard(); } catch(e){ errors.push('__drawDashboard: '+e.message+'\n'+e.stack.split('\n').slice(0,4).join('\n')); }
console.log('charts initialised:', drawn.length);
console.log('ids:', drawn.join(', '));
console.log(errors.length ? 'ERRORS:\n' + errors.join('\n') : 'no errors');
