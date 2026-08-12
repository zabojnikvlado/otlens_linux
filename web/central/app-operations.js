function renderAudit(){
  const tbody=document.querySelector('#table-audit tbody');if(!tbody)return;
  tbody.innerHTML=audit.map(a=>`<tr data-id="${esc(a.ID)}"><td>${time(a.CreatedAt)}</td><td>${esc(a.Actor||'—')}</td><td>${esc(a.Action)}</td><td class="${a.Success?'state-ok':'state-new'}">${a.Status}</td><td>${esc(a.SensorID||'—')}</td><td>${esc(a.SourceIP||'—')}</td></tr>`).join('');
  const count=document.getElementById('audit-result-count');if(count)count.textContent=`Showing ${audit.length} newest matching event(s)`;
}
async function loadAuditFiltered(){
  const q=new URLSearchParams();
  const actor=document.getElementById('audit-filter-actor')?.value.trim(),action=document.getElementById('audit-filter-action')?.value.trim(),sensor=document.getElementById('audit-filter-sensor')?.value.trim(),success=document.getElementById('audit-filter-result')?.value;
  if(actor)q.set('actor',actor);if(action)q.set('action',action);if(sensor)q.set('sensor_id',sensor);if(success)q.set('success',success);q.set('limit','500');
  try{audit=await api('/audit?'+q.toString());renderAudit()}catch(err){console.error('load filtered audit',err)}
}

function openAuditModal(id){
  const entry=audit.find(a=>String(a.ID)===String(id));
  if(!entry)return;
  const rows=[
    ['Time',time(entry.CreatedAt)],
    ['Actor',entry.Actor||'—'],
    ['Action',entry.Action||'—'],
    ['Method',entry.Method||'—'],
    ['Path',entry.Path||'—'],
    ['Status',String(entry.Status)],
    ['Success',entry.Success?'yes':'no'],
    ['Sensor',entry.SensorID||'—'],
    ['Source IP',entry.SourceIP||'—'],
  ];
  document.getElementById('audit-modal-body').innerHTML='<dl>'+rows.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')+'</dl>';
  document.getElementById('audit-modal').hidden=false;
}
document.querySelector('#table-audit tbody').addEventListener('click',e=>{
  const row=e.target.closest('tr[data-id]');
  if(row)openAuditModal(row.dataset.id);
});
document.getElementById('audit-modal-close').onclick=()=>{document.getElementById('audit-modal').hidden=true};
document.getElementById('audit-modal').addEventListener('click',e=>{if(e.target.id==='audit-modal')e.target.hidden=true});
document.getElementById('own-password-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const status=document.getElementById('own-password-status');status.textContent='';
  const current=document.getElementById('own-current-password').value,next=document.getElementById('own-new-password').value;
  try{
    await api('/change-password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});
    document.getElementById('own-password-form').reset();
    status.style.color='var(--ok)';status.textContent='Password updated.';
  }catch(err){status.style.color='';status.textContent=err.parsed?.error||err.message}
});

function renderIncidentPresence(list){const el=document.getElementById('incident-presence');if(!el)return;const others=(list||[]).filter(x=>x.username&&x.username!==currentUser?.username);el.innerHTML=others.length?`<strong>Collaborating now:</strong> ${others.map(x=>`<span>${esc(x.username)}</span>`).join('')}`:'<span>You are the only analyst viewing this incident.</span>'}
async function pingIncidentPresence(active=true){if(!activeIncidentID)return;try{const r=await api('/live/presence',{method:'POST',body:JSON.stringify({entity:'incident',entity_id:String(activeIncidentID),active})});renderIncidentPresence(r?.presence||[])}catch(e){console.warn('presence',e)}}
function startIncidentPresence(id){stopIncidentPresence(false);activeIncidentID=id;pingIncidentPresence(true);presenceTimer=setInterval(()=>pingIncidentPresence(true),15000)}
function stopIncidentPresence(clear=true){if(presenceTimer){clearInterval(presenceTimer);presenceTimer=null}if(activeIncidentID)pingIncidentPresence(false);if(clear)activeIncidentID=null}
window.addEventListener('beforeunload',()=>{if(activeIncidentID)navigator.sendBeacon?.('/v1/live/presence',new Blob([JSON.stringify({entity:'incident',entity_id:String(activeIncidentID),active:false})],{type:'application/json'}))});
const ASSET_ENRICHMENT_TTL_MS=30000;
let assetEnrichmentLoadedAt=0,assetEnrichmentPending=null;
function invalidateAssetEnrichment(){assetEnrichmentLoadedAt=0}
async function refreshAssetEnrichment(){
  if(!canView('assets'))return;
  if(assetEnrichmentPending)return assetEnrichmentPending;
  if(assetSecurityLoaded&&assetRiskLoaded&&behaviorOverviewLoaded&&Date.now()-assetEnrichmentLoadedAt<ASSET_ENRICHMENT_TTL_MS)return;
  const paths=['/asset-security-status','/asset-risk','/behavior-overview'];
  const run=(async()=>{
    const settled=await Promise.allSettled(paths.map(loadPath));
    const ok=i=>settled[i]?.status==='fulfilled';
    if(ok(0)){assetSecurity=Array.isArray(settled[0].value)?settled[0].value:[];assetSecurityLoaded=true}
    if(ok(1)){assetRiskData=Array.isArray(settled[1].value)?settled[1].value:[];assetRiskLoaded=true}
    if(ok(2)&&settled[2].value&&typeof settled[2].value==='object'){behaviorOverview=settled[2].value;behaviorOverviewLoaded=true}
    assetEnrichmentLoadedAt=Date.now();
    const failed=paths.filter((_,i)=>settled[i]?.status==='rejected');
    if(failed.length)console.warn('Asset enrichment refresh failed:',failed);
    // Enrichment is intentionally second paint. The inventory rows themselves
    // are already usable; only security/risk/behavior decorations update here.
    if(activeTab()==='assets'){
      try{renderAssets();OTDataTables.refresh('table-assets')}catch(error){console.error('asset enrichment render',error)}
    }
  })();
  assetEnrichmentPending=run.finally(()=>{assetEnrichmentPending=null});
  return assetEnrichmentPending;
}

async function refreshDomains(domains,force=false){
  domains=[...new Set((domains||[]).filter(Boolean))];
  const now=Date.now();
  const due=force?domains:domains.filter(d=>now-(domainLoadedAt.get(d)||0)>=DOMAIN_TTL_MS);
  if(!due.length)return;
  const topologyActive=due.includes('topology')&&canView('topology');
  const paths=[...new Set(due.flatMap(d=>DOMAIN_PATHS[d]||[]))].filter(path=>{
    const permission={dashboard:'dashboard',assets:'assets',devices:'devices',vulnerabilities:'vulnerabilities',tags:'tags',sensors:'sensors',alerts:'alerts',nba:'alerts',incidents:'incidents',rules:'rules',reports:'reports',analysis:'analysis',data:'data',settings:'settings',audit:'audit'};
    const owners=due.filter(d=>(DOMAIN_PATHS[d]||[]).includes(path));
    if(path==='/incidents/dashboard')return canView('incidents');
    return owners.some(d=>d==='data'&&path==='/sensors'?canView('data'):canView(permission[d]||d));
  });
  const topoPromise=topologyActive?fetchTopology().then(value=>({status:'fulfilled',value})).catch(reason=>({status:'rejected',reason})):Promise.resolve({status:'skipped'});
  const [settled,topo]=await Promise.all([Promise.allSettled(paths.map(loadPath)),topoPromise]);
  const results={};paths.forEach((path,i)=>results[path]=settled[i]);
  const ok=path=>results[path]?.status==='fulfilled';
  const list=path=>ok(path)&&Array.isArray(results[path].value)?results[path].value:[];
  if(topo.status==='fulfilled'&&topo.value&&!topo.value.unchanged){const v=topo.value.value;graph=(v&&Array.isArray(v.Nodes)&&Array.isArray(v.Edges))?v:{Nodes:[],Edges:[],HoneypotThreshold:100}}
  if(ok('/assets'))assets=list('/assets');if(ok('/asset-security-status')){assetSecurity=list('/asset-security-status');assetSecurityLoaded=true}if(ok('/devices'))devices=list('/devices');if(ok('/device-categories'))deviceCategories=list('/device-categories');
  if(ok('/vulnerabilities')&&results['/vulnerabilities'].value&&typeof results['/vulnerabilities'].value==='object')vulnerabilities=results['/vulnerabilities'].value.Advisories||[];
  if(ok('/tags'))tags=list('/tags');if(ok('/tags/changes'))changes=list('/tags/changes');if(ok('/tags/events'))events=list('/tags/events');
  if(ok('/sensors'))sensors=list('/sensors');if(ok('/sensors/metrics'))sensorMetrics=list('/sensors/metrics');if(ok('/alerts'))alerts=list('/alerts');if(ok('/alerts/stats')&&results['/alerts/stats'].value&&typeof results['/alerts/stats'].value==='object'){alertStats=results['/alerts/stats'].value;if(typeof renderAlertBadge==='function')renderAlertBadge();}
  if(ok('/correlation-rules'))correlationRules=list('/correlation-rules');if(ok('/asset-risk')){assetRiskData=list('/asset-risk');assetRiskLoaded=true}
  if(ok('/incidents/dashboard')&&results['/incidents/dashboard'].value&&typeof results['/incidents/dashboard'].value==='object')incidentDashboard=results['/incidents/dashboard'].value;
  if(ok('/behavior-findings'))behaviorFindings=list('/behavior-findings');
  if(ok('/behavior-overview')&&results['/behavior-overview'].value&&typeof results['/behavior-overview'].value==='object'){behaviorOverview=results['/behavior-overview'].value;behaviorOverviewLoaded=true}
  // Dashboard/topology UDP endpoints are fetched through DOMAIN_PATHS just like
  // every other domain, but they still need to be copied into the live UI
  // state before renderDashboard()/renderUDP() run. The legacy
  // views/operations.js had these assignments; the bundled app-operations.js
  // accidentally lost them during the split, leaving udpTelemetry at its
  // initial empty object even when /v1/udp-telemetry returned real counters.
  if(ok('/udp-conversations?active=true'))udpConversations=list('/udp-conversations?active=true');
  if(ok('/udp-telemetry')&&results['/udp-telemetry'].value&&typeof results['/udp-telemetry'].value==='object')udpTelemetry=results['/udp-telemetry'].value;
  if(ok('/dns-observations?limit=1000'))dnsObservations=list('/dns-observations?limit=1000');if(ok('/smb-stats')&&results['/smb-stats'].value&&typeof results['/smb-stats'].value==='object')smbStats=results['/smb-stats'].value;if(ok('/reports'))reports=list('/reports');
  if(ok('/rules'))rules=list('/rules').map(x=>({...x,ID:x.ID||x.id,Name:x.Name||x.name,Description:x.Description||x.description,Category:x.Category||x.category,Kind:x.Kind||x.kind,Enabled:x.Enabled??x.enabled,Severity:x.Severity||x.severity,SeverityOverride:x.SeverityOverride??x.severity_override??false,Priority:x.Priority||x.priority,Simulation:x.Simulation??x.simulation,SimulationHits:x.SimulationHits||x.simulation_hits||0,LastSimulationHit:x.LastSimulationHit||x.last_simulation_hit,Version:x.Version||x.version,Groups:x.Groups||x.groups,GroupOperator:x.GroupOperator||x.group_operator,Actions:x.Actions||x.actions,Suppression:x.Suppression||x.suppression,Schedule:x.Schedule||x.schedule||'always',Detector:x.Detector||x.detector,MITRETactics:x.MITRETactics||x.mitre_tactics||[],MITRETechniques:x.MITRETechniques||x.mitre_techniques||[],Prerequisites:x.Prerequisites||x.prerequisites||[],Protocols:x.Protocols||x.protocols||[],Parameters:x.Parameters||x.parameters||{},AlertType:x.AlertType||x.alert_type,Field:x.Field||x.field,Value:x.Value||x.value}));
  if(ok('/baseline'))baselines=list('/baseline');if(ok('/analysis/jobs'))analysisJobs=list('/analysis/jobs');if(ok('/data/backups'))backups=list('/data/backups');if(ok('/reconnaissance/jobs'))reconnaissanceJobs=list('/reconnaissance/jobs');
  if(ok('/settings')&&typeof results['/settings'].value==='object')settings=results['/settings'].value;if(ok('/dashboard/trends')&&typeof results['/dashboard/trends'].value==='object')trends=results['/dashboard/trends'].value;if(ok('/audit'))audit=list('/audit');
  try{if(topologyActive&&topo.status==='fulfilled'){if(topologyColourMode==='behavior')topologyNodeSigCache.clear();renderTopology()}}catch(e){console.error('render topology',e)}
  if(due.includes('assets')){try{renderAssets()}catch(e){console.error(e)}void refreshAssetEnrichment()}if(due.includes('devices'))try{renderDevices()}catch(e){console.error(e)}if(due.includes('vulnerabilities'))try{renderVulnerabilities()}catch(e){console.error(e)}
  if(due.includes('tags'))try{renderTags()}catch(e){console.error(e)}if(due.includes('sensors'))try{renderSensors()}catch(e){console.error(e)}if(due.includes('alerts')){try{await refreshAlertSearch();renderDNS();renderSMB()}catch(e){console.error(e)}}
  if(due.includes('incidents')){try{renderCorrelationRules();await refreshIncidentSearch(false)}catch(e){console.error(e)}}if(due.includes('reports'))try{renderReports()}catch(e){console.error(e)}if(due.includes('rules'))try{renderRules()}catch(e){console.error(e)}
  if(due.includes('nba'))try{renderBehaviorFindings()}catch(e){console.error(e)}
  if(due.includes('analysis'))try{renderAnalysis()}catch(e){console.error(e)}if(due.includes('data'))try{renderBackups()}catch(e){console.error(e)}if(due.includes('settings'))try{renderSettings()}catch(e){console.error(e)}if(due.includes('audit'))try{renderAudit()}catch(e){console.error(e)}
  if(due.includes('dashboard')){try{renderBaseline();renderDashboard()}catch(e){console.error(e)}}
  if(due.includes('users')&&can('users_roles_manage'))try{await refreshUsersAndRoles()}catch(e){console.error('refresh users/roles',e)}
  due.forEach(d=>domainLoadedAt.set(d,Date.now()));
  const rejected=paths.map(path=>results[path]?.status==='rejected'?{path,reason:results[path].reason}:null).filter(Boolean);if(topo.status==='rejected')rejected.push({path:'/topology',reason:topo.reason});
  if(!rejected.length)setAPIConnection(true);else{console.error('Central API refresh failures:',rejected);const unauthorized=rejected.every(x=>x.reason?.status===401);setAPIConnection(false,unauthorized?'authentication required':`partial: ${rejected.map(x=>x.path).join(', ')}`);if(unauthorized){showLogin();const el=document.getElementById('login-error');if(el)el.textContent='Your session expired. Please sign in again.'}}
}
async function refreshView(tab=activeTab(),force=false){await refreshDomains([tab],force);if(['communication','assettraffic','networktraffic','protocolanalytics'].includes(tab)&&typeof loadTrafficAnalyticsTab==='function')await loadTrafficAnalyticsTab(tab)}
async function refreshActiveView(force=false){return refreshView(activeTab(),force)}
// Compatibility entry point for older handlers: now refreshes only the active view.
async function refreshAll(){return refreshActiveView(true)}

// Non-authenticated UI must remain usable even if an optional table widget
// regresses. Authentication handlers are registered below regardless of a
// single table failing to initialise.
try{OTDataTables.init()}catch(error){console.error('Data table bootstrap failed:',error)}
const tableRenderBindings=[
  ['renderAssets','table-assets'],
  ['renderTags','table-tags'],
  ['renderAlerts','table-alerts'],
  ['renderRules','table-rules'],
  ['renderAnalysis','table-analysis'],
  ['renderSensors','table-sensors'],
  ['renderBackups','table-backups']
];
tableRenderBindings.forEach(([name,tableID])=>{
  const original=window[name];
  if(typeof original!=='function')return;
  window[name]=function(...args){
    const result=original.apply(this,args);
    OTDataTables.refresh(tableID);
    return result;
  };
});
// --- Auth boot sequence, login/logout, permission gating ---

function showLogin(){
  stopPolling();
  stopLiveEvents();
  document.getElementById('app-shell').hidden=true;
  document.getElementById('login-screen').hidden=false;
  document.getElementById('login-error').textContent='';
}
function showApp(){
  document.getElementById('login-screen').hidden=true;
  document.getElementById('app-shell').hidden=false;
}
function startPolling(){
  stopPolling();
  refreshAll();
  loadLiveHistory();
  startLiveEvents();
  // SSE drives near-real-time updates. This slower poll remains a recovery
  // net for dropped events, proxies that block streaming, and laptop sleep.
  pollTimer=setInterval(()=>refreshActiveView(true),60000);
}
function stopPolling(){
  if(pollTimer){clearInterval(pollTimer);pollTimer=null}
}

const TAB_LABELS={dashboard:'Dashboard',communication:'Communication Analysis',assettraffic:'Asset Traffic',networktraffic:'Network / Zone Traffic',protocolanalytics:'Protocol Analytics',threatintel:'Threat Intelligence',dns:'DNS Explorer',smb:'SMB Explorer',topology:'Topology',purdue:'Purdue',segmentation:'Segmentation',assets:'Assets',devices:'Devices',vulnerabilities:'Vulnerabilities',tags:'OT Tags',rules:'Rules',alerts:'Alerts',nba:'Behavior Findings',incidents:'Incidents',sensors:'Sensors',health:'Healthcheck',analysis:'Analysis',users:'Users',settings:'Settings',data:'Data Management',audit:'Audit log',reports:'Reports'};
const ACTION_LABELS={sensor_start_stop:'Start/stop sensors',asset_confirm_delete:'Confirm/delete assets',alert_confirm_approve:'Confirm/approve alerts',rule_manage:'Create/edit/delete rules',analysis_manage:'Upload/delete PCAP analysis',data_management:'Backups, resets & learning',users_roles_manage:'Manage users & roles'};

// applyNavFiltering hides tab buttons the current role can't view (server
// still enforces this on every request — see requireView — this is only
// so the UI doesn't dangle buttons that would just 403).
// The Users tab is a first-class view permission. Management controls inside
// it are separately gated by users_roles_manage, while self-service password
// change remains available to any role allowed to view the Users tab.
const TAB_PERMISSION_ALIAS={health:'sensors',threatintel:'alerts',dns:'alerts',udp:'alerts',smb:'alerts',nba:'alerts',communication:'dashboard',assettraffic:'dashboard',networktraffic:'dashboard',protocolanalytics:'dashboard'};
function applyNavFiltering(){
  document.querySelectorAll('.tab').forEach(btn=>{
    const tab=btn.dataset.tab;
    btn.hidden=!canView(TAB_PERMISSION_ALIAS[tab]||tab);
  });
  refreshNavigationGroups();
  const active=document.querySelector('.tab.active');
  if(!active||active.hidden){
    const firstVisible=document.querySelector('.tab:not([hidden]):not(.nav-filter-hidden)');
    if(firstVisible)firstVisible.click();
  }
}
// applyActionGating hides any element tagged data-requires-action that the
// current role's Actions grant doesn't include — same "server enforces it
// too" caveat as applyNavFiltering; requireAction is the real gate.
function applyActionGating(){
  document.querySelectorAll('[data-requires-action]').forEach(el=>{
    el.style.display=can(el.dataset.requiresAction)?'':'none';
  });
}

function applyIdentity(payload){
  permissions=payload.Permissions||{view:[],actions:[]};
  currentUser=payload.ViaToken?null:payload.User||null;
  currentRole=payload.Role||null;
  document.getElementById('current-user').textContent=payload.ViaToken?'management token':(currentUser?.Username||'');
  applyNavFiltering();
  applyActionGating();
  const mustChange=Boolean(payload.MustChangePassword);
  document.getElementById('force-password-modal').hidden=!mustChange;
  if(mustChange){
    document.getElementById('force-password-reason').textContent=currentUser&&currentUser.MustChangePassword===false
      ?'Your password has expired and must be changed before you can continue.'
      :'Your password must be changed before you can continue.';
  }
}

async function boot(){
  try{
    const me=await api('/me');
    applyIdentity(me);
    showApp();
    startPolling();
  }catch(err){
    console.warn('Not authenticated (this is expected on a fresh page load):',err.status||err.message);
    showLogin();
  }
}

document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const form=e.currentTarget;
  const errEl=document.getElementById('login-error');
  const submit=form.querySelector('button[type="submit"]');
  errEl.textContent='';
  const username=document.getElementById('login-username').value,password=document.getElementById('login-password').value;
  if(submit){submit.disabled=true;submit.dataset.originalText=submit.textContent;submit.textContent='Signing in…'}
  try{
    await api('/login',{method:'POST',body:JSON.stringify({username,password})});
    // Verify that the browser accepted the session cookie before hiding the
    // login screen. Without this check a valid password + rejected Secure
    // cookie looked exactly like a silent login failure.
    const me=await api('/me');
    applyIdentity(me);
    form.reset();
    showApp();
    startPolling();
  }catch(err){
    if(err.status===401&&err.parsed?.error==='unauthorized'){
      errEl.textContent=location.protocol==='https:'
        ?'Login succeeded but the session was not accepted. Clear the OTLens site cookies and try again.'
        :'Login session could not be established. Open Central over HTTPS or disable web TLS only for isolated development.';
    }else{
      errEl.textContent=err.parsed?.error||err.message||'Login failed';
    }
  }finally{
    if(submit){submit.disabled=false;submit.textContent=submit.dataset.originalText||'Sign in';delete submit.dataset.originalText}
  }
});
document.getElementById('logout-btn').onclick=async()=>{
  try{await api('/logout',{method:'POST'})}catch(_){}
  stopPolling();
  currentUser=null;currentRole=null;permissions={view:[],actions:[]};
  showLogin();
};
document.getElementById('force-password-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const errEl=document.getElementById('force-password-error');errEl.textContent='';
  const current=document.getElementById('force-current-password').value;
  const next=document.getElementById('force-new-password').value,confirmVal=document.getElementById('force-new-password-confirm').value;
  if(next!==confirmVal){errEl.textContent='New passwords do not match';return}
  try{
    await api('/change-password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});
    document.getElementById('force-password-form').reset();
    document.getElementById('force-password-modal').hidden=true;
    refreshAll();
  }catch(err){errEl.textContent=err.parsed?.error||err.message}
});

// --- Users & Roles (Settings tab, admin only) ---

async function refreshUsersAndRoles(){
  const [u,r]=await Promise.allSettled([api('/users'),api('/roles')]);
  if(u.status==='fulfilled')users=Array.isArray(u.value)?u.value:[];else console.error('GET /users failed:',u.reason?.status,u.reason?.message);
  if(r.status==='fulfilled')roles=Array.isArray(r.value)?r.value:[];else console.error('GET /roles failed:',r.reason?.status,r.reason?.message);
  try{renderUsers();OTDataTables.refresh('table-users')}catch(e){console.error('render users',e)}
  try{renderRoles();OTDataTables.refresh('table-roles')}catch(e){console.error('render roles',e)}
  try{populateRoleSelect()}catch(e){console.error('populate role select',e)}
  if(u.status==='rejected'||r.status==='rejected'){
    const failures=[u.status==='rejected'?`users: ${u.reason?.status||''} ${u.reason?.message||'request failed'}`:'',r.status==='rejected'?`roles: ${r.reason?.status||''} ${r.reason?.message||'request failed'}`:''].filter(Boolean);
    throw new Error(failures.join('; '));
  }
}
function populateRoleSelect(){
  const sel=document.getElementById('user-form-role');
  const current=sel.value;
  sel.innerHTML=roles.map(r=>`<option value="${esc(r.ID)}">${esc(r.Name)}</option>`).join('');
  if(current)sel.value=current;
}
