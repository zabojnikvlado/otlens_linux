function nbaEvidence(item){return item.Evidence||item.evidence||{}}
function nbaValue(item,name,fallback=''){const value=item[name]??item[name[0].toLowerCase()+name.slice(1)];return value??fallback}
function nbaID(item){return nbaValue(item,'AlertKey',nbaValue(item,'ID',''))}
function nbaPercent(value){const n=Number(value||0);return `${Math.round((n<=1?n*100:n)*10)/10}%`}
function nbaScore(value){const n=Number(value||0);return Number.isFinite(n)?n.toFixed(1):'—'}
function nbaReasons(value){return Array.isArray(value)?value.join(', '):String(value||'—')}
function behaviorProfile(sensor,ip){return (behaviorOverview.profiles||[]).find(x=>x.sensor_id===sensor&&x.asset_ip===ip)}
function behaviorState(profile){return profile?.state||((behaviorOverview.learning_complete&&Number(behaviorOverview.coverage)>=99.5)?'healthy':'learning')}
function behaviorBadge(profile){const state=behaviorState(profile),score=profile?Math.round(Number(profile.health_score||0)):'—';return `<span class="behavior-badge behavior-${esc(state)}" title="${esc(profile?.top_reason||state)}">${esc(score)}${score==='—'?'':' health'}</span>`}
function renderNetworkBehavior(){
  const overview=behaviorOverview||{},health=Math.max(0,Math.min(100,Number(overview.network_health||0))),state=overview.state||'learning',hero=document.getElementById('network-behavior-hero');if(!hero)return;
  hero.className=`network-behavior-hero behavior-${state}`;hero.dataset.dashboardTab=canView('alerts')?'nba':'assets';document.getElementById('network-health-score').textContent=state==='learning'?'Learning':`${Math.round(health)}%`;document.getElementById('network-health-bar').style.width=`${health}%`;
  document.getElementById('network-health-state').textContent=state==='healthy'?'Healthy network behavior':state==='degraded'?'Behavior degradation detected':state==='critical'?'Major behavior anomaly':'Building reliable baselines';
  document.getElementById('network-learning-state').textContent=overview.learning_complete?'Complete':`${Math.round(Number(overview.learning_readiness||0))}% ready`;document.getElementById('network-coverage').textContent=`${Math.round(Number(overview.coverage||0))}% mature-asset coverage`;
  document.getElementById('network-active-baselines').textContent=Number(overview.active_baselines||0).toLocaleString();document.getElementById('network-behavior-alerts').textContent=Number(overview.behavior_alerts||0).toLocaleString();document.getElementById('network-affected-assets').textContent=`${Number(overview.affected_assets||0)} affected assets`;
  const top=overview.top_anomaly;document.getElementById('network-top-anomaly').textContent=top?.asset_ip||'—';document.getElementById('network-top-anomaly-score').textContent=top?`Anomaly ${Number(top.anomaly_score||0).toFixed(1)} · ${nbaPercent(top.confidence)}`:'No active finding';
}

function renderBehaviorFindings(){
  const needle=(document.getElementById('nba-filter')?.value||'').trim().toLowerCase();
  const severity=(document.getElementById('nba-severity')?.value||'').toLowerCase();
  const rows=behaviorFindings.filter(item=>{
    const evidence=nbaEvidence(item);
    const hay=[nbaID(item),nbaValue(item,'SensorID'),nbaValue(item,'IP'),nbaValue(item,'Message'),nbaReasons(evidence.reasons)].join(' ').toLowerCase();
    return(!needle||hay.includes(needle))&&(!severity||String(nbaValue(item,'Severity')).toLowerCase()===severity);
  });
  const body=document.querySelector('#table-nba tbody');
  if(!body)return;
  body.innerHTML=rows.map(item=>{
    const evidence=nbaEvidence(item);
    const id=nbaID(item);
    return `<tr class="clickable-row nba-row" data-id="${esc(id)}"><td>${time(nbaValue(item,'LastSeen'))}</td><td>${esc(nbaValue(item,'SensorID','—'))}</td><td>${esc(nbaValue(item,'IP','—'))}</td><td><span class="severity ${esc(String(nbaValue(item,'Severity')).toLowerCase())}">${esc(nbaValue(item,'Severity','—'))}</span></td><td>${nbaScore(evidence.risk_score)}</td><td>${nbaPercent(evidence.confidence)}</td><td>${esc(evidence.assessment_count??nbaValue(item,'Count',0))}</td><td>${esc(nbaValue(item,'Status','—'))}</td><td>${esc(nbaReasons(evidence.reasons))}</td></tr>`;
  }).join('');
  document.getElementById('nba-count').textContent=`${rows.length} finding${rows.length===1?'':'s'}`;
  body.querySelectorAll('.nba-row').forEach(row=>row.onclick=()=>showBehaviorFinding(row.dataset.id));
}

async function showBehaviorFinding(id){
  let item=behaviorFindings.find(value=>String(nbaID(value))===String(id));
  try{item=await api(`/behavior-findings/${encodeURIComponent(id)}`)}catch(error){if(!item){alert(error.message);return}}
  const evidence=nbaEvidence(item);
  document.getElementById('nba-detail-body').innerHTML=`
    <div class="detail-grid">
      <div><strong>Finding ID</strong><span>${esc(evidence.finding_id||nbaID(item)||'—')}</span></div>
      <div><strong>Sensor</strong><span>${esc(nbaValue(item,'SensorID','—'))}</span></div>
      <div><strong>Asset</strong><span>${esc(nbaValue(item,'IP','—'))}</span></div>
      <div><strong>Severity</strong><span>${esc(nbaValue(item,'Severity','—'))}</span></div>
      <div><strong>Risk score</strong><span>${nbaScore(evidence.risk_score)}</span></div>
      <div><strong>Confidence</strong><span>${nbaPercent(evidence.confidence)}</span></div>
      <div><strong>Peer</strong><span>${esc(evidence.peer_id||'—')}</span></div>
      <div><strong>Assessments</strong><span>${esc(evidence.assessment_count??nbaValue(item,'Count',0))}</span></div>
      <div><strong>First seen</strong><span>${time(nbaValue(item,'FirstSeen'))}</span></div>
      <div><strong>Last seen</strong><span>${time(nbaValue(item,'LastSeen'))}</span></div>
    </div>
    <h3>Reasons</h3><p>${esc(nbaReasons(evidence.reasons))}</p>
    <h3>Detection message</h3><p>${esc(nbaValue(item,'Message','—'))}</p>`;
  document.getElementById('nba-detail-modal').hidden=false;
}

document.getElementById('nba-filter')?.addEventListener('input',renderBehaviorFindings);
document.getElementById('nba-severity')?.addEventListener('change',renderBehaviorFindings);
document.getElementById('nba-refresh')?.addEventListener('click',()=>refreshView('nba',true));

const originalRenderDashboard=renderDashboard;
renderDashboard=function(...args){const result=originalRenderDashboard.apply(this,args);renderNetworkBehavior();return result};

document.querySelector('#table-assets thead tr')?.insertAdjacentHTML('beforeend','<th>Behavior</th>');
const originalRenderAssets=renderAssets;
renderAssets=function(...args){const result=originalRenderAssets.apply(this,args);document.querySelectorAll('#table-assets tbody tr.asset-row').forEach(row=>row.insertAdjacentHTML('beforeend',`<td>${behaviorBadge(behaviorProfile(row.dataset.sensor,row.dataset.ip))}</td>`));return result};

document.querySelector('#table-alerts thead tr')?.insertAdjacentHTML('beforeend','<th>Behavior</th>');
const originalRenderAlerts=renderAlerts;
renderAlerts=function(...args){const result=originalRenderAlerts.apply(this,args);document.querySelectorAll('#table-alerts tbody tr.alert-row').forEach(row=>{const alert=alertTableRows[Number(row.dataset.index)];row.insertAdjacentHTML('beforeend',`<td>${behaviorBadge(behaviorProfile(alert?.SensorID,alert?.IP))}</td>`)});return result};

const behaviorTab=document.createElement('button');behaviorTab.dataset.assetPanel='behavior';behaviorTab.textContent='Behavior';document.querySelector('.asset-detail-tabs [data-asset-panel="timeline"]')?.before(behaviorTab);
const originalRenderAssetPanel=renderAssetPanel;
renderAssetPanel=async function(panel){
  if(panel!=='behavior')return originalRenderAssetPanel.apply(this,arguments);
  if(!activeAssetDetail)return;document.querySelectorAll('.asset-detail-tabs button').forEach(x=>x.classList.toggle('active',x.dataset.assetPanel===panel));
  const profile=behaviorProfile(activeAssetDetail.SensorID,activeAssetDetail.IP),body=document.getElementById('asset-detail-body');
  if(!profile){body.innerHTML=`<div class="empty-dashboard"><strong>${behaviorOverview.learning_complete?'No active anomaly':'Behavior learning in progress'}</strong><span>${Math.round(Number(behaviorOverview.coverage||0))}% behavior-profile coverage.</span></div>`;return}
  const related=alerts.filter(x=>String(nbaValue(x,'Type')).startsWith('behavior_')&&nbaValue(x,'SensorID')===activeAssetDetail.SensorID&&nbaValue(x,'IP')===activeAssetDetail.IP);
  body.innerHTML=`<div class="asset-security-kpis"><div><span>Behavior health</span><strong>${Number(profile.health_score).toFixed(1)}</strong></div><div><span>Anomaly score</span><strong>${Number(profile.anomaly_score).toFixed(1)}</strong></div><div><span>Confidence</span><strong>${nbaPercent(profile.confidence)}</strong></div><div><span>Active findings</span><strong>${Number(profile.active_findings||0)}</strong></div></div><div class="asset-360-columns"><section class="otl-panel"><h3>Current assessment</h3><dl class="status-list"><div><dt>State</dt><dd>${behaviorBadge(profile)}</dd></div><div><dt>Top reason</dt><dd>${esc(profile.top_reason||'—')}</dd></div><div><dt>Last evaluated</dt><dd>${time(profile.last_evaluated)}</dd></div></dl></section><section class="otl-panel"><h3>Behavior findings</h3><div class="asset-security-list">${related.map(x=>`<article><span class="severity ${esc(String(nbaValue(x,'Severity','info')).toLowerCase())}">${esc(nbaValue(x,'Severity','info'))}</span><div><strong>${esc(nbaValue(x,'Message','Behavior finding'))}</strong><small>${time(nbaValue(x,'LastSeen'))}</small></div></article>`).join('')||'<div class="empty-dashboard">No detailed finding retained.</div>'}</div></section></div>`;
};

document.querySelector('#topology-colour-mode')?.insertAdjacentHTML('beforeend','<option value="behavior">Behavior health</option>');
const originalTopologyNode=node;
node=function(value){const result=originalTopologyNode(value);if(topologyColourMode!=='behavior'||value.IsHoneypot===true||value.Confirmed===false)return result;const profile=behaviorProfile(value.SensorID,value.IP),state=behaviorState(profile),colors={healthy:{background:'#16a34a',border:'#4ade80'},anomalous:{background:'#d97706',border:'#fbbf24'},critical:{background:'#dc2626',border:'#fb7185'},learning:{background:'#64748b',border:'#94a3b8'}};result.color=colors[state]||colors.learning;result.title+=`\nBehavior: ${state}${profile?` · health ${Number(profile.health_score).toFixed(1)} · anomaly ${Number(profile.anomaly_score).toFixed(1)}`:' · insufficient baseline data'}`;return result};

function learningPercent(value){const n=Number(value||0);return `${Math.round(n*10)/10}%`}
function learningCandidateRows(){
  const rows=[];
  (baselines||[]).forEach(b=>{
    const sensor=b.SensorID||b.sensor_id||'—',behavior=b.behavior||{};
    (behavior.candidates||[]).forEach(c=>rows.push({sensor,c}));
  });
  return rows.sort((a,b)=>Number(b.c.observations||0)-Number(a.c.observations||0));
}
function renderLearningQuality(){
  const o=behaviorOverview||{},set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=value};
  const readiness=Number(o.learning_readiness||0),coverage=Number(o.time_coverage||0),rate=Number(o.new_pattern_rate||0);
  set('learning-readiness',learningPercent(readiness));
  set('learning-readiness-detail',o.learning_complete?'Trusted baseline is monitoring':'Minimum duration + maturity/stability gate');
  set('learning-mature-assets',Number(o.mature_assets||0).toLocaleString());
  set('learning-assets-detail',`${Number(o.learning_assets||0).toLocaleString()} still learning`);
  set('learning-time-coverage',learningPercent(coverage));
  set('learning-pattern-rate',learningPercent(rate*100));
  set('learning-candidate-count',Number(o.candidate_patterns||0).toLocaleString());
  set('learning-candidate-assets',`${Number(o.candidate_assets||0).toLocaleString()} candidate-only assets`);
  set('learning-excluded',Number(o.excluded_learning||0).toLocaleString());
  set('learning-preview-anomalies',Number(o.preview_anomalies||0).toLocaleString());
  set('learning-preview-detail',`${Number(o.preview_evaluated||0).toLocaleString()} preview evaluations`);
  set('learning-preview-score',Number(o.preview_top_score||0)>0?Number(o.preview_top_score).toFixed(1):'—');
  set('learning-preview-reason',o.preview_top_reason||'No preview anomaly');
  set('learning-quality-state',o.learning_complete?'Monitoring with mature trusted baseline':`${learningPercent(readiness)} ready`);

  const rows=learningCandidateRows(),body=document.querySelector('#table-learning-candidates tbody');
  set('learning-candidate-note',`${rows.length.toLocaleString()} candidate${rows.length===1?'':'s'} shown from current sensor telemetry`);
  if(!body)return;
  body.innerHTML=rows.map(({sensor,c})=>{
    const k=c.key||{},ready=Boolean(c.ready_for_promotion),eligible=c.eligible!==false;
    const baseStatus=!eligible?(c.reason||'security/policy excluded'):ready?'ready for review':'collecting evidence';
    const status=eligible&&c.reason?`${baseStatus} · ${c.reason}`:baseStatus;
    const service=[k.protocol||k.transport||'unknown',k.service_port||''].filter(Boolean).join('/');
    const disabled=!ready||!can('alert_confirm_approve');
    return `<tr><td>${esc(sensor)}</td><td>${esc(k.src_ip||'—')} → ${esc(k.dst_ip||'—')}</td><td>${esc(service||'—')}</td><td>${esc([k.day_class,k.shift,k.context].filter(Boolean).join(' · ')||'—')}</td><td>${Number(c.observations||0).toLocaleString()}</td><td>${Number(c.distinct_days||0)}</td><td>${esc(status)}</td><td><button class="secondary-btn learning-promote" data-sensor="${esc(sensor)}" data-id="${esc(c.id||'')}" ${disabled?'disabled':''}>Promote</button></td></tr>`;
  }).join('')||'<tr><td colspan="8">No shadow-baseline candidates.</td></tr>';
  body.querySelectorAll('.learning-promote').forEach(button=>button.onclick=async()=>{
    if(!confirm('Promote this reviewed relationship into the trusted behavior baseline?'))return;
    button.disabled=true;
    try{await api(`/sensors/${encodeURIComponent(button.dataset.sensor)}/baseline/candidates/promote`,{method:'POST',body:JSON.stringify({candidate_id:button.dataset.id})});button.textContent='Queued';setTimeout(()=>refreshView('nba',true),1500)}catch(error){alert(error.parsed?.error||error.message);button.disabled=false}
  });
}

const originalRenderBehaviorFindings=renderBehaviorFindings;
renderBehaviorFindings=function(...args){const result=originalRenderBehaviorFindings.apply(this,args);renderLearningQuality();return result};
