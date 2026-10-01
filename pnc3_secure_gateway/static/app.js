let token = localStorage.getItem('pnc3_token');
let me = null;
const GEMINI_KEY_STORAGE = 'gemini_api_key';
const pages = ['overview','chat','simulator','requests','approvals','policies','tools','agents','events'];
const scenarioNames = {
 normal:'Normal Tool Call', prompt_injection:'Prompt Injection', unauthorized_tool:'Unauthorized Tool', data_exfiltration:'Data Exfiltration', parameter_smuggling:'Parameter Smuggling', obfuscated_payload:'Obfuscated Payload', unsafe_destination:'Unsafe Destination', destructive_command:'Destructive Command', ssrf:'SSRF / Unsafe IP', approval:'High-Risk Approval', sanitization:'Sensitive Data Sanitization'
};
function $(id){return document.getElementById(id)}
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function api(path, opts={}){opts.headers=Object.assign({'Content-Type':'application/json'},opts.headers||{}); if(token) opts.headers.Authorization='Bearer '+token; const r=await fetch(path,opts); const data=await r.json().catch(()=>({})); if(!r.ok) throw new Error(data.detail||'Request failed'); return data;}
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200)}
function statusBadge(s){let c=s==='ALLOW'||s==='SUCCESS'||s==='APPROVED'?'allow':s==='BLOCK'||s==='DENIED'?'block':s==='REQUIRE_APPROVAL'||s==='PENDING'?'approval':'sanitize';return `<span class="status ${c}">${esc(s)}</span>`}
function navTo(page){pages.forEach(p=>{const el=$('page-'+p); if(el) el.classList.toggle('active-page',p===page)});document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b.dataset.page===page));$('pageTitle').textContent=page==='chat'?'Chat bot':page==='simulator'?'Adversarial Test Lab':page==='requests'?'Tool Requests':page==='events'?'Security Events':page[0].toUpperCase()+page.slice(1); if(page==='overview')loadOverview(); if(page==='chat')loadChat(); if(page==='simulator')loadSimulator(); if(page==='requests')loadRequests(); if(page==='approvals')loadApprovals(); if(page==='policies')loadPolicies(); if(page==='tools')loadTools(); if(page==='agents')loadAgents(); if(page==='events')loadEvents();}
document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>navTo(b.dataset.page)));

async function init(){
 try{me=await api('/api/me');showApp(); await loadAll();}catch(e){clearSession();showLogin();}
}
function clearSession(){localStorage.removeItem('pnc3_token'); token = null; me = null;}
function showLogin(){$('loginView').classList.remove('hidden');$('appView').classList.add('hidden')}
function showApp(){$('loginView').classList.add('hidden');$('appView').classList.remove('hidden');$('userInfo').textContent=`${me.username} • ${me.role}`;$('rolePill').textContent=me.role}
$('loginForm').addEventListener('submit',async e=>{e.preventDefault();$('loginError').textContent='';try{const d=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:$('username').value,password:$('password').value})});token=d.token;localStorage.setItem('pnc3_token',token);me=d.user;showApp();toast('Signed in');await loadAll()}catch(err){clearSession();$('loginError').textContent=err.message;showLogin();}});
$('logoutBtn').addEventListener('click',()=>{clearSession();location.reload()});$('refreshBtn').addEventListener('click',loadAll);
$('saveGeminiKeyBtn').addEventListener('click',()=>{const key=$('geminiKeyInput').value.trim(); if(!key){localStorage.removeItem(GEMINI_KEY_STORAGE); toast('API key cleared'); return;} localStorage.setItem(GEMINI_KEY_STORAGE,key); toast('API key saved');});
const storedGeminiKey = localStorage.getItem(GEMINI_KEY_STORAGE) || '';
if(storedGeminiKey){$('geminiKeyInput').value = storedGeminiKey;}

const scanTypePlaceholders = {
  prompt: 'Enter the prompt',
  chat: 'Enter the chat transcript',
  document: 'Enter the document',
  code: 'Enter the code'
};

function updateScanPlaceholder() {
  const type = $('scanType').value;
  $('scanContent').placeholder = scanTypePlaceholders[type] || 'Enter the prompt';
}

$('scanType').addEventListener('change', updateScanPlaceholder);
updateScanPlaceholder();

$('scanFile').addEventListener('change', async event => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    $('scanContent').value = text;
    toast(`Loaded ${file.name}`);
  } catch (err) {
    toast('Could not read file');
  }
});

$('scanBtn').addEventListener('click', async () => {
  const content = $('scanContent').value.trim();
  if (!content) {
    toast('Paste or upload content before scanning.');
    return;
  }
  try {
    const result = await api('/api/analyze-content', {
      method: 'POST',
      body: JSON.stringify({ source_type: $('scanType').value, content })
    });
    const riskClass = result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH' ? 'block' : result.risk_level === 'MEDIUM' ? 'approval' : 'allow';
    const issues = Array.isArray(result.issues) ? result.issues.map(i => `<li>${esc(i)}</li>`).join('') : '<li>None</li>';
    $('scanResult').innerHTML = `
      <div class="scan-header">
        <div class="scan-score ${riskClass}">${result.safe_score}%</div>
        <div>
          <div class="scan-title">${esc(result.source_type)} safety check</div>
          <div class="scan-summary">${esc(result.summary)}</div>
          <div class="scan-meta"><span>${statusBadge(result.risk_level)}</span> <span class="muted">${result.content_length} chars</span> <span class="muted">${result.rules_violated} rules violated · ${result.violation_score}% violation score</span></div>
        </div>
      </div>
      <ul class="scan-issues">${issues}</ul>
    `;
  } catch (err) {
    $('scanResult').innerHTML = `<div class="error">${esc(err.message)}</div>`;
  }
});

async function loadAll(){await Promise.allSettled([loadOverview(),loadChatAgents(),loadApprovalsBadge(),loadSimulator(),loadPolicies(),loadTools(),loadAgents(),loadRequests(),loadEvents()])}
async function loadOverview(){try{const s=await api('/api/dashboard/stats');$('metrics').innerHTML=[['Requests',s.total||0],['Allowed',s.allowed||0],['Blocked',s.blocked||0],['Approval',s.approval||0],['High Risk',s.high_risk||0],['Avg ms',Math.round(s.avg_latency||0)]].map(x=>`<div class="metric"><div class="label">${x[0]}</div><div class="value">${x[1]}</div></div>`).join(''); const rows=await api('/api/requests?limit=8');$('recentRequests').innerHTML=reqTable(rows);$('threatSummary').innerHTML=`<div class="sim-grid"><div class="sim-stat"><b>${s.injection_attempts||0}</b><div class="muted">Prompt injections</div></div><div class="sim-stat"><b>${s.dlp_attempts||0}</b><div class="muted">DLP detections</div></div><div class="sim-stat"><b>${s.events||0}</b><div class="muted">Security events</div></div><div class="sim-stat"><b>${Math.round(s.avg_latency||0)} ms</b><div class="muted">Avg gateway latency</div></div></div>`}catch(e){toast(e.message)}}
function reqTable(rows){if(!rows.length)return '<div class="muted">No requests yet.</div>';return `<table class="table"><thead><tr><th>Time</th><th>Agent</th><th>Tool</th><th>Risk</th><th>Decision</th><th>Latency</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(new Date(r.created_at).toLocaleTimeString())}</td><td>${esc(r.agent_id)}</td><td>${esc(r.tool)}</td><td>${esc(r.risk_level)} (${r.risk_score})</td><td>${statusBadge(r.decision)}</td><td>${r.latency_ms}ms</td></tr>`).join('')}</tbody></table>`}
async function loadRequests(){try{$('requestsTable').innerHTML=reqTable(await api('/api/requests?limit=100'))}catch(e){}}
async function loadEvents(){try{const rows=await api('/api/events?limit=100');$('eventsTable').innerHTML=rows.length?`<table class="table"><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Request</th><th>Details</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(new Date(r.created_at).toLocaleString())}</td><td>${esc(r.event_type)}</td><td>${statusBadge(r.severity==='CRITICAL'||r.severity==='HIGH'?'BLOCK':r.severity)}</td><td>${esc(r.request_id)}</td><td><code>${esc(r.details)}</code></td></tr>`).join('')}</tbody></table>`:'<div class="muted">No security events yet.</div>'}catch(e){}}
async function loadApprovals(){try{const rows=await api('/api/approvals');$('approvalsTable').innerHTML=rows.length?`<table class="table"><thead><tr><th>Status</th><th>Tool</th><th>Agent</th><th>Risk</th><th>Destination</th><th>Action</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${statusBadge(r.status)}</td><td>${esc(r.tool)}</td><td>${esc(r.agent_id)}</td><td>${r.risk_level} (${r.risk_score})</td><td>${esc(r.destination)}</td><td>${r.status==='PENDING'&&['ADMIN','SECURITY_ANALYST'].includes(me.role)?`<button class="btn small primary" onclick="approval('${r.id}','approve')">Approve</button> <button class="btn small" onclick="approval('${r.id}','deny')">Deny</button>`:'—'}</td></tr>`).join('')}</tbody></table>`:'<div class="muted">No approvals.</div>'}catch(e){}}
async function loadApprovalsBadge(){try{const rows=await api('/api/approvals');const n=rows.filter(x=>x.status==='PENDING').length;$('approvalBadge').textContent=n;$('approvalBadge').classList.toggle('hidden',!n)}catch(e){}}
async function approval(id,act){try{await api(`/api/approvals/${id}/${act}`,{method:'POST',body:JSON.stringify({note:'Reviewed in PNC3 dashboard'})});toast(`Approval ${act}ed`);await loadApprovals();await loadApprovalsBadge();await loadOverview()}catch(e){toast(e.message)}}

async function loadChatAgents(){try{const a=await api('/api/agents');$('chatAgent').innerHTML=a.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('')}catch(e){}}
function addMsg(kind,text,sec){const d=document.createElement('div');d.className='msg '+kind;d.innerHTML=`<div class="bubble">${esc(text)}${sec?`<div class="security-card">${sec}</div>`:''}</div>`;$('chatMessages').appendChild(d);$('chatMessages').scrollTop=$('chatMessages').scrollHeight}
function loadChat(){if(!$('chatMessages').children.length)addMsg('bot','Welcome to the Secure Agent Tool Gateway. I act like a chat bot and route every tool action through the secure gateway before execution.');}
$('chatForm').addEventListener('submit',async e=>{e.preventDefault();const text=$('chatText').value.trim();if(!text)return;addMsg('user',text);$('chatText').value='';try{const apiKey=$('geminiKeyInput').value.trim() || localStorage.getItem(GEMINI_KEY_STORAGE) || '';const d=await api('/api/chat',{method:'POST',body:JSON.stringify({agent_id:$('chatAgent').value,message:text,api_key:apiKey || null})});let sec='';if(d.tool_call||d.decision==='BLOCK'){const violations=(d.rule_violations||[d.reason]).filter(Boolean);sec=`<b>${esc(d.decision)}</b> • Safety ${d.safety_score ?? Math.max(0,100-(d.risk_score||0))}% • Risk ${d.risk_score||0} (${esc(d.risk_level||'LOW')})<br>${violations.map(esc).join('<br>')}<br>${d.execution_status?`<span class="muted">Latency: ${d.latency_ms} ms • ${esc(d.execution_status)}</span>`:''}`}addMsg('bot',d.message,sec);await loadOverview();await loadApprovalsBadge()}catch(err){addMsg('bot','Gateway error: '+err.message)}});

async function loadSimulator(){const grid=$('scenarioGrid');grid.innerHTML=Object.entries(scenarioNames).map(([k,v])=>`<div class="scenario"><h4>${esc(v)}</h4><p>Run a safe simulated ${esc(v.toLowerCase())} through the real gateway.</p><button class="btn primary small" onclick="simulate('${k}')">Run scenario</button></div>`).join('')}
async function simulate(k){$('simResult').classList.remove('hidden');$('simResult').innerHTML='<div class="muted">Running security pipeline…</div>';try{const d=await api('/api/simulation/run?scenario='+encodeURIComponent(k),{method:'POST'});const tone=d.decision==='BLOCK'?'block':d.decision==='REQUIRE_APPROVAL'?'approval':'allow';$('simResult').innerHTML=`<div class="panel-head"><h3>${esc(scenarioNames[k])}</h3>${statusBadge(d.decision)}</div><div class="sim-grid"><div class="sim-stat"><b>${d.risk_score}</b><div class="muted">Risk score</div></div><div class="sim-stat"><b>${esc(d.risk_level)}</b><div class="muted">Risk level</div></div><div class="sim-stat"><b>${d.latency_ms} ms</b><div class="muted">Gateway latency</div></div><div class="sim-stat"><b>${esc(d.execution_status)}</b><div class="muted">Execution</div></div></div><p><b>Reason:</b> ${esc(d.reason)}</p><p><b>Request ID:</b> ${esc(d.request_id)}</p>`;await loadAll()}catch(e){$('simResult').innerHTML=`<div class="error">${esc(e.message)}</div>`}}

async function loadPolicies(){try{const rows=await api('/api/policies');$('policiesTable').innerHTML=rows.length?`<table class="table"><thead><tr><th>Name</th><th>Agent</th><th>Tool</th><th>Action</th><th>Max Risk</th><th>Destinations</th><th></th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.name)}</td><td>${esc(r.agent_id)}</td><td>${esc(r.tool)}</td><td>${statusBadge(r.action)}</td><td>${r.max_risk}</td><td>${esc(r.destination_allowlist.join(', ')||'—')}</td><td>${me.role==='ADMIN'?`<button class="btn small" onclick="deletePolicy('${r.id}')">Delete</button>`:'—'}</td></tr>`).join('')}</tbody></table>`:'<div class="muted">No policies</div>';const agents=await api('/api/agents'),tools=await api('/api/tools');$('pAgent').innerHTML=agents.map(a=>`<option value="${a.id}">${esc(a.name)}</option>`).join('');$('pTool').innerHTML=tools.map(t=>`<option value="${t.tool}">${esc(t.tool)}</option>`).join('')}catch(e){}}
$('policyForm').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/policies',{method:'POST',body:JSON.stringify({name:$('pName').value,agent_id:$('pAgent').value,tool:$('pTool').value,action:$('pAction').value,max_risk:Number($('pRisk').value),destination_allowlist:$('pDest').value.split(',').map(x=>x.trim()).filter(Boolean)})});$('policyMsg').textContent='Policy saved.';e.target.reset();await loadPolicies();toast('Policy created')}catch(err){$('policyMsg').textContent=err.message}});
async function deletePolicy(id){if(!confirm('Delete this policy?'))return;try{await api('/api/policies/'+id,{method:'DELETE'});toast('Policy deleted');await loadPolicies()}catch(e){toast(e.message)}}
async function loadTools(){try{const rows=await api('/api/tools');$('toolsTable').innerHTML=`<table class="table"><thead><tr><th>Tool</th><th>Risk</th><th>Destructive</th><th>Sensitive</th><th>Schema</th><th>Authorized Agents</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.tool)}</td><td>${esc(r.risk)}</td><td>${r.destructive?'🚫 YES':'No'}</td><td>${r.sensitive?'Yes':'No'}</td><td><code>${esc(JSON.stringify(r.schema))}</code></td><td>${esc(r.allowed_agents.join(', ')||'None')}</td></tr>`).join('')}</tbody></table>`}catch(e){}}
async function loadAgents(){try{const rows=await api('/api/agents');$('agentsTable').innerHTML=`<table class="table"><thead><tr><th>Agent</th><th>Environment</th><th>Max Risk</th><th>Allowed Tools</th><th>Destinations</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.name)}</td><td>${esc(r.environment)}</td><td>${r.max_risk}</td><td>${esc(r.allowed_tools.join(', '))}</td><td>${esc(r.allowed_destinations.join(', '))}</td></tr>`).join('')}</tbody></table>`}catch(e){}}
$('newPolicyBtn').addEventListener('click',()=>{$('pName').focus()});
init();
