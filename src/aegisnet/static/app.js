const API = '/api/v1';
const $ = (id) => document.getElementById(id);
const state = { alerts: [], events: [], overview: null, currentAlert: null, view: 'overview', severity: '', search: '' };

const RULES = [
  ['AUTH-001', 'Authentication brute force', 'T1110 · Credential Access'],
  ['NET-001', 'Network port scan', 'T1046 · Discovery'],
  ['THREAT-001', 'Threat-intelligence match', 'T1105 / T1071 · C2'],
  ['EXFIL-001', 'Large outbound transfer', 'T1567 · Exfiltration'],
  ['EDR-001', 'Privileged endpoint execution', 'T1059 · Execution'],
  ['DNS-001', 'High-entropy DNS query', 'T1568.002 · C2'],
];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function shortTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit', second:'2-digit', timeZone:'UTC' }) + ' UTC';
}
function relativeTime(value) {
  if (!value) return '—';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
function toast(message, type='success') {
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.textContent = message;
  $('toast-region').append(item);
  setTimeout(() => item.remove(), 3600);
}
async function api(path, options={}) {
  const headers = { 'Content-Type':'application/json', ...(options.headers || {}) };
  const apiKey = sessionStorage.getItem('aegis-api-key');
  if (apiKey) headers['X-API-Key'] = apiKey;
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
function setApiStatus(online) {
  $('api-label').textContent = online ? 'API connected' : 'API unavailable';
  $('api-label').style.color = online ? '#a6b6c9' : '#ff9297';
}
function updateClock() {
  $('clock').textContent = new Date().toLocaleTimeString('en-GB', { hour12:false, timeZone:'UTC' }) + ' UTC';
}
function renderMetrics(data) {
  $('metric-events').textContent = Number(data.events_total || 0).toLocaleString();
  $('metric-alerts').textContent = data.alerts_active ?? 0;
  $('metric-critical').textContent = data.high_critical ?? 0;
  $('metric-assets').textContent = data.assets_observed ?? 0;
  $('nav-alert-count').textContent = data.alerts_active ?? 0;
  $('severity-total').textContent = data.alerts_active ?? 0;
  const severity = data.severity || {};
  const max = Math.max(1, ...Object.values(severity));
  $('severity-bars').innerHTML = ['critical','high','medium','low'].map(level => {
    const n = severity[level] || 0;
    return `<div class="severity-row"><span>${level[0].toUpperCase()+level.slice(1)}</span><div class="severity-track"><div class="severity-fill sev-${level}" style="width:${Math.max(0, n/max*100)}%"></div></div><em>${n}</em></div>`;
  }).join('');
  renderChart(data.trend || []);
}
function renderChart(points) {
  const canvas = $('trend-chart');
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(300, rect.width);
  const height = 122;
  canvas.width = width * dpr; canvas.height = height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const values = points.map(p => p.count || 0);
  const maxValue = Math.max(4, ...values);
  $('chart-max').textContent = maxValue;
  $('chart-mid').textContent = Math.round(maxValue / 2);
  const left=3, right=width-5, top=8, bottom=height-13;
  ctx.strokeStyle = '#25384e'; ctx.lineWidth=1; ctx.setLineDash([3,5]);
  for(let i=0;i<4;i++){const y=top+(bottom-top)*i/3;ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(right,y);ctx.stroke();}
  ctx.setLineDash([]);
  const step=(right-left)/Math.max(1,values.length-1);
  const coords=values.map((v,i)=>({x:left+i*step,y:bottom-(v/maxValue)*(bottom-top)}));
  if(coords.length){
    const gradient=ctx.createLinearGradient(0,top,0,bottom);gradient.addColorStop(0,'rgba(69,214,197,.28)');gradient.addColorStop(1,'rgba(69,214,197,0)');
    ctx.beginPath();ctx.moveTo(coords[0].x,bottom);coords.forEach(p=>ctx.lineTo(p.x,p.y));ctx.lineTo(coords.at(-1).x,bottom);ctx.closePath();ctx.fillStyle=gradient;ctx.fill();
    ctx.beginPath();coords.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.strokeStyle='#45d6c5';ctx.lineWidth=2;ctx.stroke();
    coords.forEach((p,i)=>{if(i%4===0||i===coords.length-1){ctx.beginPath();ctx.arc(p.x,p.y,2.2,0,Math.PI*2);ctx.fillStyle='#9bf2e6';ctx.fill();}});
  }
  ctx.fillStyle='#6f8299';ctx.font='9px DM Mono';ctx.textAlign='center';
  [0,5,11,17,23].forEach(i=>{if(points[i])ctx.fillText(points[i].label,coords[i].x,height-1);});
}
function severityClass(level){return `severity-${['critical','high','medium','low'].includes(level)?level:'low'}`;}
function statusClass(status){return `status-${['open','investigating','contained','resolved'].includes(status)?status:'open'}`;}
function renderAlerts() {
  let items = [...state.alerts];
  if(state.severity) items=items.filter(a=>a.severity===state.severity);
  if(state.search){const needle=state.search.toLowerCase();items=items.filter(a=>[a.title,a.rule_id,a.asset,a.src_ip,a.username,a.mitre_technique].join(' ').toLowerCase().includes(needle));}
  $('alert-count').textContent=items.length;
  if(!items.length){$('alerts-body').innerHTML='<tr><td colspan="8" class="empty-state">No alerts match this view. Run the demo simulation to generate evidence.</td></tr>';return;}
  $('alerts-body').innerHTML=items.map(a=>`<tr>
    <td><div class="detection-cell"><span class="detection-glyph">${a.rule_id.startsWith('AUTH')?'⌑':a.rule_id.startsWith('NET')?'⌁':a.rule_id.startsWith('THREAT')?'◈':a.rule_id.startsWith('EXFIL')?'⇧':a.rule_id.startsWith('EDR')?'⌘':'⌕'}</span><span class="detection-main"><b>${escapeHtml(a.title)}</b><small>${escapeHtml(a.rule_id)} · ${a.event_count} evidence event(s)</small></span></div></td>
    <td><span class="severity-pill ${severityClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
    <td><span class="asset-main"><b>${escapeHtml(a.asset || 'Unknown asset')}</b><small>${escapeHtml(a.src_ip || a.username || '—')}</small></span></td>
    <td><span class="mitre-code">${escapeHtml(a.mitre_technique || '—')}</span></td>
    <td><span class="status-pill ${statusClass(a.status)}">${escapeHtml(a.status)}</span></td>
    <td><span class="risk-cell"><i class="risk-track"><i class="risk-fill" style="display:block;width:${Math.min(100,a.risk_score)}%"></i></i><span class="risk-num">${a.risk_score}</span></span></td>
    <td class="time-cell">${escapeHtml(relativeTime(a.last_seen))}</td>
    <td><button class="row-open" data-alert-id="${a.id}" aria-label="Open alert details">↗</button></td>
  </tr>`).join('');
  $('table-foot').textContent=`Showing ${items.length} of ${state.alerts.length} alerts`;
}
function renderEvents() {
  if(!state.events.length){$('event-list').innerHTML='<div class="empty-state">No telemetry received yet. Run the demo simulation to populate this view.</div>';return;}
  $('event-list').innerHTML=state.events.slice(0,6).map(e=>`<div class="event-item"><span class="event-time">${escapeHtml(shortTime(e.timestamp))}</span><span class="event-desc"><b>${escapeHtml(e.action || e.event_type.replaceAll('_',' '))} ${e.outcome?`· ${escapeHtml(e.outcome)}`:''}</b><small>${escapeHtml(e.source)} · ${escapeHtml(e.asset || e.src_ip || e.domain || 'unknown source')}</small></span><span class="event-type">${escapeHtml(e.event_type)}</span></div>`).join('');
}
function renderRules(){ $('rule-list').innerHTML=RULES.map(([id,title,ref])=>`<div class="rule-item"><b>${id}</b><span>${title}</span><small>${ref}</small></div>`).join(''); }
function renderIocs(items){$('ioc-grid').innerHTML=items.map(i=>`<div class="ioc-card"><div class="ioc-top"><span class="ioc-kind">${escapeHtml(i.kind)} · ${escapeHtml(i.threat_type)}</span><span class="ioc-confidence">${i.confidence}% CONF.</span></div><div class="ioc-indicator">${escapeHtml(i.indicator)}</div><div class="ioc-meta">Source: ${escapeHtml(i.source)}</div></div>`).join('') || '<div class="empty-state">No indicators loaded.</div>';}
async function refresh() {
  try {
    const [overview, alerts, events, iocs] = await Promise.all([
      api('/overview'), api('/alerts?limit=200'), api('/events?limit=12'), api('/iocs')
    ]);
    setApiStatus(true); state.alerts=alerts.items; state.events=events.items; state.overview=overview;
    renderMetrics(overview);renderAlerts();renderEvents();renderIocs(iocs.items);
    $('last-refresh').textContent=new Date().toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  } catch (error) { setApiStatus(false); toast(error.message,'error'); }
}
function openDrawer(){ $('alert-drawer').classList.add('open');$('drawer-backdrop').classList.add('open');$('alert-drawer').setAttribute('aria-hidden','false'); }
function closeDrawer(){ $('alert-drawer').classList.remove('open');$('drawer-backdrop').classList.remove('open');$('alert-drawer').setAttribute('aria-hidden','true');state.currentAlert=null; }
async function showAlert(id){
  try{
    const a=await api(`/alerts/${id}`);state.currentAlert=a;
    $('drawer-title').textContent=a.title;
    const evidence=(a.evidence||[]).map(e=>`<div class="evidence-item"><b>${escapeHtml(e.event_type)} · ${escapeHtml(e.action||'event')} ${e.outcome?`(${escapeHtml(e.outcome)})`:''}</b><small>${escapeHtml(e.timestamp)} · ${escapeHtml(e.source)} · event #${e.id}</small><p>${escapeHtml([e.src_ip&&`src ${e.src_ip}`,e.dst_ip&&`dst ${e.dst_ip}`,e.dst_port&&`port ${e.dst_port}`,e.username&&`user ${e.username}`,e.domain&&`domain ${e.domain}`,e.bytes_out&&`${(e.bytes_out/1048576).toFixed(1)} MiB out`].filter(Boolean).join(' · ')||'No additional fields')}</p></div>`).join('') || '<div class="empty-state">No evidence attached.</div>';
    const audit=(a.audit||[]).map(x=>`<div class="audit-item"><b>${escapeHtml(x.action.replaceAll('-',' '))} · ${escapeHtml(x.actor)}</b><small>${escapeHtml(x.created_at)}</small><p>${escapeHtml(x.note)}</p></div>`).join('') || '<div class="empty-state">No audit entries.</div>';
    const transitions={open:['open','investigating'],investigating:['investigating','open','contained','resolved'],contained:['contained','investigating','resolved'],resolved:['resolved','investigating']};
    const statusOptions=transitions[a.status].map(status=>`<option value="${status}" ${a.status===status?'selected':''}>${status[0].toUpperCase()+status.slice(1)}</option>`).join('');
    $('drawer-content').innerHTML=`<div class="detail-tags"><span class="severity-pill ${severityClass(a.severity)}">${escapeHtml(a.severity)}</span><span class="status-pill ${statusClass(a.status)}">${escapeHtml(a.status)}</span><span class="panel-tag">${escapeHtml(a.rule_id)}</span></div>
      <p class="detail-description">${escapeHtml(a.description)}</p>
      <div class="detail-grid"><div class="detail-kv"><small>RISK SCORE</small><b>${a.risk_score} / 100</b></div><div class="detail-kv"><small>MITRE ATT&amp;CK</small><b>${escapeHtml(a.mitre_technique||'—')} · ${escapeHtml(a.mitre_tactic||'—')}</b></div><div class="detail-kv"><small>ASSET</small><b>${escapeHtml(a.asset||'Unknown')}</b></div><div class="detail-kv"><small>SOURCE IP</small><b>${escapeHtml(a.src_ip||'—')}</b></div><div class="detail-kv"><small>FIRST SEEN</small><b>${escapeHtml(a.first_seen||'—')}</b></div><div class="detail-kv"><small>LAST SEEN</small><b>${escapeHtml(a.last_seen||'—')}</b></div></div>
      <div class="drawer-section"><h3>EVIDENCE TIMELINE · ${a.event_count}</h3>${evidence}</div>
      <div class="drawer-section"><h3>ANALYST AUDIT TRAIL</h3>${audit}</div>
      <div class="drawer-form"><h3>ANALYST WORKFLOW</h3><label for="alert-status">UPDATE STATUS</label><select id="alert-status">${statusOptions}</select><label for="alert-assignee">ASSIGNEE</label><input id="alert-assignee" maxlength="100" placeholder="Analyst name" value="${escapeHtml(a.assignee||'')}"/><label for="alert-note">INVESTIGATION NOTE</label><textarea id="alert-note" maxlength="1000" placeholder="Record evidence reviewed, actions taken or resolution rationale..."></textarea><button class="btn btn-primary" id="save-alert">Save analyst update</button></div>`;
    $('save-alert').addEventListener('click',()=>saveAlert(a.id));
    openDrawer();
  }catch(error){toast(error.message,'error');}
}
async function saveAlert(id){
  const status=$('alert-status').value,note=$('alert-note').value,assignee=$('alert-assignee').value;
  try{await api(`/alerts/${id}`,{method:'PATCH',body:JSON.stringify({status,note,assignee})});toast('Analyst update saved.');await refresh();await showAlert(id);}catch(error){toast(error.message,'error');}
}
async function runDemo(){
  $('demo-replay').disabled=true;$('demo-replay').textContent='Running simulation…';
  try{const result=await api('/demo/replay',{method:'POST',body:'{}'});toast(`Simulation complete: ${result.accepted} events ingested, ${result.alerts_touched} detections updated.`);await refresh();}
  catch(error){toast(error.message,'error');}
  finally{$('demo-replay').disabled=false;$('demo-replay').innerHTML='<span class="btn-plus">＋</span> Run demo simulation';}
}
function setView(view){
  state.view=view;document.querySelectorAll('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.view===view));
  const labels={overview:['Overview','Operational overview','A unified view of telemetry, detections and incident response.'],alerts:['Alert queue','Alert management','Prioritise detections, inspect evidence and record analyst actions.'],telemetry:['Telemetry','Telemetry stream','Inspect recent signals from the connected event sources.'],intel:['Threat intelligence','Local threat intelligence','Review the offline IOC set used by the deterministic matching rule.']};
  const [crumb,title,sub]=labels[view];$('breadcrumb-current').textContent=crumb;$('page-title').textContent=title;$('page-subtitle').textContent=sub;$('view-kicker').textContent=view.toUpperCase();
  if(view==='alerts'){$('alert-panel').scrollIntoView({behavior:'smooth',block:'start'});}
  if(view==='telemetry'){$('telemetry-panel').scrollIntoView({behavior:'smooth',block:'start'});}
  if(view==='intel'){$('intel-panel').scrollIntoView({behavior:'smooth',block:'start'});}
  if(view==='overview')window.scrollTo({top:0,behavior:'smooth'});
}

document.addEventListener('click',(event)=>{
  const alertButton=event.target.closest('[data-alert-id]');if(alertButton)showAlert(alertButton.dataset.alertId);
  const nav=event.target.closest('[data-view]');if(nav)setView(nav.dataset.view);
});
$('drawer-close').addEventListener('click',closeDrawer);$('drawer-backdrop').addEventListener('click',closeDrawer);
$('demo-replay').addEventListener('click',runDemo);$('refresh-btn').addEventListener('click',refresh);
$('severity-filter').addEventListener('change',(event)=>{state.severity=event.target.value;renderAlerts();});
$('alert-search').addEventListener('input',(event)=>{state.search=event.target.value;renderAlerts();});
window.addEventListener('resize',()=>{if(state.overview)renderChart(state.overview.trend || []);});
$('api-key-btn').addEventListener('click',()=>{const current=sessionStorage.getItem('aegis-api-key')||'';const entered=prompt('Enter the AEGIS_API_KEY for this browser tab. Leave blank to clear it:',current);if(entered===null)return;if(entered.trim())sessionStorage.setItem('aegis-api-key',entered.trim());else sessionStorage.removeItem('aegis-api-key');toast(entered.trim()?'Session API key updated.':'Session API key cleared.');});
renderRules();updateClock();setInterval(updateClock,1000);refresh();setInterval(refresh,30000);
