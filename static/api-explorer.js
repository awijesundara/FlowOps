const $=(s,r=document)=>r.querySelector(s);
function esc(v=''){return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
const tokenInput=$('#token');
tokenInput.value=localStorage.getItem('flowops_explorer_token')||'';
tokenInput.oninput=()=>localStorage.setItem('flowops_explorer_token',tokenInput.value);
let spec=null;
async function load(){
  const res=await fetch('/openapi.json');
  spec=await res.json();
  const list=$('#endpointList');
  const rows=[];
  for(const [path,methods] of Object.entries(spec.paths)){
    for(const [method,op] of Object.entries(methods)){
      rows.push({path,method:method.toUpperCase(),op});
    }
  }
  list.innerHTML=rows.map((r,i)=>`<button class="admin-cat-row" data-i="${i}" style="width:100%;text-align:left;border:0;border-bottom:1px solid var(--line);background:transparent;padding:12px 8px;cursor:pointer"><span class="chip" style="margin-right:8px">${r.method}</span><b style="font-size:12px">${esc(r.path)}</b><br><small class="muted">${esc(r.op.summary||'')}</small></button>`).join('');
  list.querySelectorAll('[data-i]').forEach(btn=>btn.onclick=()=>renderDetail(rows[Number(btn.dataset.i)]));
}
function paramFields(op){
  return (op.parameters||[]).filter(p=>p.in==='path'||p.in==='query').map(p=>`<label>${esc(p.name)} <span>(${p.in}${p.required?', required':''})</span><input data-param="${esc(p.name)}" data-in="${p.in}" placeholder="${esc(p.schema?.type||'string')}"></label>`).join('');
}
function bodyField(op){
  const schema=op.requestBody?.content?.['application/json']?.schema;
  if(!schema) return '';
  const example=JSON.stringify(Object.fromEntries((Object.entries(schema.properties||{})).map(([k,v])=>[k, v.type==='array'?[]:v.type==='integer'?0:''])),null,2);
  return `<label>Request body (JSON)<textarea id="bodyField" rows="8">${esc(example)}</textarea></label>`;
}
function renderDetail(row){
  const {path,method,op}=row;
  $('#endpointDetail').innerHTML=`<div class="panelhead"><div><h2>${method} ${esc(path)}</h2><p>${esc(op.summary||'')}</p></div></div><form id="tryForm">${paramFields(op)}${bodyField(op)}<div class="modalactions"><span></span><button class="primary" type="submit">▶ Try it</button></div></form><div id="responseView" style="margin-top:16px"></div>`;
  $('#tryForm').onsubmit=async e=>{
    e.preventDefault();
    let resolvedPath=path;
    const query=new URLSearchParams();
    $('#tryForm').querySelectorAll('[data-param]').forEach(input=>{
      if(!input.value) return;
      if(input.dataset.in==='path') resolvedPath=resolvedPath.replace(`{${input.dataset.param}}`,encodeURIComponent(input.value));
      else query.set(input.dataset.param,input.value);
    });
    const url=resolvedPath+(query.toString()?`?${query}`:'');
    const headers={};
    if(tokenInput.value) headers['Authorization']=`Bearer ${tokenInput.value}`;
    const opts={method,headers};
    const bodyEl=$('#bodyField');
    if(bodyEl){headers['Content-Type']='application/json';opts.body=bodyEl.value}
    const view=$('#responseView');
    view.innerHTML='<p class="muted">Sending…</p>';
    try{
      const res=await fetch(url,opts);
      const text=await res.text();
      let pretty=text;
      try{pretty=JSON.stringify(JSON.parse(text),null,2)}catch(_){}
      view.innerHTML=`<div class="chip ${res.ok?'complete':'live'}">Status ${res.status}</div><pre style="background:#17223b;color:#e8edff;padding:14px;border-radius:8px;overflow:auto;margin-top:10px;font-size:12px">${esc(pretty)}</pre>`;
    }catch(err){
      view.innerHTML=`<p style="color:var(--red)">${esc(err.message)}</p>`;
    }
  };
}
load();
