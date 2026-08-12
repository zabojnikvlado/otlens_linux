function nbaEvidence(item){return item.Evidence||item.evidence||{}}
function nbaValue(item,name,fallback=''){const value=item[name]??item[name[0].toLowerCase()+name.slice(1)];return value??fallback}
function nbaID(item){return nbaValue(item,'AlertKey',nbaValue(item,'ID',''))}
function nbaPercent(value){const n=Number(value||0);return `${Math.round((n<=1?n*100:n)*10)/10}%`}
function nbaScore(value){const n=Number(value||0);return Number.isFinite(n)?n.toFixed(1):'—'}
function nbaReasons(value){return Array.isArray(value)?value.map(v=>typeof v==='string'?v:(v?.kind||v?.message||JSON.stringify(v))).join(', '):String(value||'—')}
const behaviorFindingTypeLabels={
  'correlation:new_external_peer':'New external peer','correlation:new_peer_and_protocol':'New peer + protocol','correlation:unusual_time_and_port':'Unusual time + service','correlation:risky_direction_change':'Risky direction change',
  new_flow:'New communication',new_asset_behavior:'New asset behavior',new_peer:'New peer',new_protocol:'New protocol',new_port:'New service / port',unusual_time:'Unusual time',new_direction:'Direction change',packet_size_deviation:'Packet-size deviation',rtt_deviation:'RTT deviation',
  external_destination:'External destination',asset_criticality:'Critical asset context',purdue_level:'Purdue risk context',honeypot:'Honeypot interaction',inter_vlan:'Inter-VLAN behavior',low_baseline_confidence:'Low baseline confidence',
  maintenance_window:'Maintenance window',approved_peer:'Approved peer context'
};
const behaviorFindingTypePriority=['correlation:new_external_peer','correlation:new_peer_and_protocol','correlation:unusual_time_and_port','correlation:risky_direction_change','new_asset_behavior','new_flow','new_peer','new_protocol','new_port','unusual_time','new_direction','packet_size_deviation','rtt_deviation','external_destination','honeypot','inter_vlan','asset_criticality','purdue_level','low_baseline_confidence','maintenance_window','approved_peer'];
function behaviorFindingSignals(item){
  const evidence=nbaEvidence(item),raw=Array.isArray(evidence.reasons)?evidence.reasons:[];
  return [...new Set(raw.map(v=>{
    const value=String(typeof v==='string'?v:(v?.kind||v?.message||'')).trim();
    const normalized=value.toLowerCase().replace(/[\s-]+/g,'_');
    return behaviorFindingTypeLabels[normalized]?normalized:value;
  }).filter(Boolean))];
}
function behaviorFindingType(item){
  const signals=behaviorFindingSignals(item),primary=behaviorFindingTypePriority.find(kind=>signals.includes(kind))||signals[0]||'';
  let label=behaviorFindingTypeLabels[primary]||primary.replace(/^correlation:/,'').replaceAll('_',' ')||'Behavior anomaly';
  if(String(nbaValue(item,'Type','')).toLowerCase()==='behavior_incident_candidate')label=`Incident · ${label}`;
  const secondary=signals.filter(kind=>kind!==primary&&behaviorFindingTypeLabels[kind]);
  return {label,signals,secondaryCount:secondary.length};
}
let behaviorProfileIndexSource=null,behaviorProfileIndex=new Map();
function behaviorProfile(sensor,ip){const profiles=behaviorOverview?.profiles||[];if(behaviorProfileIndexSource!==profiles){behaviorProfileIndexSource=profiles;behaviorProfileIndex=new Map(profiles.map(x=>[`${x.sensor_id}\x00${x.asset_ip}`,x]))}return behaviorProfileIndex.get(`${sensor}\x00${ip}`)}
function behaviorState(profile){return profile?.state||((behaviorOverview.learning_complete&&Number(behaviorOverview.coverage)>=99.5)?'healthy':'learning')}
function behaviorBadge(profile){if(!behaviorOverviewLoaded)return '<span class="behavior-badge behavior-learning" title="Behavior enrichment is loading">…</span>';const state=behaviorState(profile),score=profile?Math.round(Number(profile.health_score||0)):'—';return `<span class="behavior-badge behavior-${esc(state)}" title="${esc(profile?.top_reason||state)}">${esc(score)}${score==='—'?'':' health'}</span>`}
function renderNetworkBehavior(){
  const overview=behaviorOverview||{},health=Math.max(0,Math.min(100,Number(overview.network_health||0))),readiness=Math.max(0,Math.min(100,Number(overview.learning_readiness||0))),state=overview.state||'learning',hero=document.getElementById('network-behavior-hero');if(!hero)return;
  const barValue=state==='learning'?readiness:health,bar=document.getElementById('network-health-bar');
  hero.className=`network-behavior-hero behavior-${state}`;hero.dataset.dashboardTab=canView('alerts')?'nba':'assets';document.getElementById('network-health-score').textContent=state==='learning'?'Learning':`${Math.round(health)}%`;bar.style.width=`${barValue}%`;bar.parentElement?.setAttribute('aria-label',state==='learning'?`Learning readiness ${Math.round(readiness)}%`:`Network health ${Math.round(health)}%`);
  document.getElementById('network-health-state').textContent=state==='healthy'?'Healthy network behavior':state==='degraded'?'Behavior degradation detected':state==='critical'?'Major behavior anomaly':'Building reliable baselines';
  const awaitingSensors=Math.max(0,Number(overview.awaiting_sensors||0)),reportingSensors=Math.max(0,Number(overview.reporting_sensors||0));
  document.getElementById('network-learning-state').textContent=overview.learning_complete?'Complete':awaitingSensors&&reportingSensors===0?'Awaiting telemetry':`${Math.round(Number(overview.learning_readiness||0))}% ready`;
  document.getElementById('network-coverage').textContent=awaitingSensors?`${awaitingSensors} sensor(s) awaiting baseline telemetry`:`${Math.round(Number(overview.coverage||0))}% mature-asset coverage`;
  document.getElementById('network-active-baselines').textContent=Number(overview.active_baselines||0).toLocaleString();document.getElementById('network-behavior-alerts').textContent=Number(overview.behavior_alerts||0).toLocaleString();document.getElementById('network-affected-assets').textContent=`${Number(overview.affected_assets||0)} affected assets`;
  const top=overview.top_anomaly;document.getElementById('network-top-anomaly').textContent=top?.asset_ip||'—';document.getElementById('network-top-anomaly-score').textContent=top?`Anomaly ${Number(top.anomaly_score||0).toFixed(1)} · ${nbaPercent(top.confidence)}`:'No active finding';
}

function renderBehaviorFindings(){
  const needle=(document.getElementById('nba-filter')?.value||'').trim().toLowerCase();
  const severity=(document.getElementById('nba-severity')?.value||'').toLowerCase();
  const rows=behaviorFindings.filter(item=>{
    const evidence=nbaEvidence(item),type=behaviorFindingType(item);
    const hay=[nbaID(item),nbaValue(item,'SensorID'),nbaValue(item,'IP'),nbaValue(item,'Message'),type.label,type.signals.join(' '),nbaReasons(evidence.reasons)].join(' ').toLowerCase();
    return(!needle||hay.includes(needle))&&(!severity||String(nbaValue(item,'Severity')).toLowerCase()===severity);
  });
  const body=document.querySelector('#table-nba tbody');
  if(!body)return;
  body.innerHTML=rows.map(item=>{
    const evidence=nbaEvidence(item);
    const id=nbaID(item),type=behaviorFindingType(item),typeSuffix=type.secondaryCount?` <small>+${type.secondaryCount}</small>`:'';
    return `<tr class="clickable-row nba-row" data-id="${esc(id)}" data-sensor="${esc(nbaValue(item,'SensorID',''))}"><td>${time(nbaValue(item,'LastSeen'))}</td><td>${esc(nbaValue(item,'SensorID','—'))}</td><td>${esc(nbaValue(item,'IP','—'))}</td><td><span class="behavior-type-badge" title="${esc(type.signals.map(x=>behaviorFindingTypeLabels[x]||x).join(' · '))}">${esc(type.label)}${typeSuffix}</span></td><td><span class="severity ${esc(String(nbaValue(item,'Severity')).toLowerCase())}">${esc(nbaValue(item,'Severity','—'))}</span></td><td>${nbaScore(evidence.risk_score)}</td><td>${esc(nbaValue(item,'Status','—'))}</td><td><button class="secondary-btn behavior-details" type="button">Details</button></td></tr>`;
  }).join('');
  document.getElementById('nba-count').textContent=`${rows.length} finding${rows.length===1?'':'s'}`;
  body.querySelectorAll('.nba-row').forEach(row=>row.onclick=e=>{if(e.target.closest('button'))return;showBehaviorFinding(row.dataset.id,row.dataset.sensor)});
  body.querySelectorAll('.behavior-details').forEach(button=>button.onclick=e=>{e.stopPropagation();const row=button.closest('.nba-row');if(row)showBehaviorFinding(row.dataset.id,row.dataset.sensor)});
  window.OTDataTables?.refresh('table-nba');
}

async function showBehaviorFinding(id,sensorID){
  let item=behaviorFindings.find(value=>String(nbaID(value))===String(id)&&String(nbaValue(value,'SensorID',''))===String(sensorID||''));
  try{item=await api(`/behavior-findings/${encodeURIComponent(id)}?sensor_id=${encodeURIComponent(sensorID||'')}`)}catch(error){if(!item){alert(error.message);return}}
  const evidence=nbaEvidence(item),findingType=behaviorFindingType(item);
  document.getElementById('nba-detail-body').innerHTML=`
    <div class="detail-grid">
      <div><strong>Finding ID</strong><span>${esc(evidence.finding_id||nbaID(item)||'—')}</span></div>
      <div><strong>Sensor</strong><span>${esc(nbaValue(item,'SensorID','—'))}</span></div>
      <div><strong>Asset</strong><span>${esc(nbaValue(item,'IP','—'))}</span></div>
      <div><strong>Finding type</strong><span>${esc(findingType.label)}</span></div>
      <div><strong>Severity</strong><span>${esc(nbaValue(item,'Severity','—'))}</span></div>
      <div><strong>State</strong><span>${esc(nbaValue(item,'Status','—'))}</span></div>
      <div><strong>Risk score</strong><span>${nbaScore(evidence.risk_score)}</span></div>
      <div><strong>Confidence</strong><span>${nbaPercent(evidence.confidence)}</span></div>
      <div><strong>Peer</strong><span>${esc(evidence.peer_id||'—')}</span></div>
      <div><strong>Assessments</strong><span>${esc(evidence.assessment_count??nbaValue(item,'Count',0))}</span></div>
      <div><strong>Alert candidate</strong><span>${evidence.alert_candidate===true?'Yes':evidence.alert_candidate===false?'No':'—'}</span></div>
      <div><strong>Incident candidate</strong><span>${evidence.incident_candidate===true?'Yes':evidence.incident_candidate===false?'No':'—'}</span></div>
      <div><strong>First seen</strong><span>${time(nbaValue(item,'FirstSeen'))}</span></div>
      <div><strong>Last seen</strong><span>${time(nbaValue(item,'LastSeen'))}</span></div>
    </div>
    <h3>Detection signals</h3><p>${esc(findingType.signals.map(x=>behaviorFindingTypeLabels[x]?`${behaviorFindingTypeLabels[x]} (${x})`:x).join(', ')||'—')}</p>
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
function learningSensorRows(){
  const validTime=value=>{const ms=Date.parse(value||'');return Number.isFinite(ms)&&ms>Date.parse('2000-01-01T00:00:00Z')?ms:0};
  const registered=new Map();
  (sensors||[]).forEach(s=>{
    const id=String(s.id??s.ID??'').trim();if(!id)return;
    const name=String(s.name??s.Name??'').trim(),site=String(s.site_id??s.SiteID??'').trim(),hostname=String(s.hostname??s.Hostname??'').trim();
    registered.set(id,{id,name,site,hostname});
  });
  const baselineBySensor=new Map();
  (baselines||[]).forEach(b=>{const id=String(b.SensorID||b.sensor_id||'').trim();if(id)baselineBySensor.set(id,b)});
  const ids=new Set([...registered.keys(),...baselineBySensor.keys()]);
  return [...ids].map(sensor=>{
    const b=baselineBySensor.get(sensor)||{},identity=registered.get(sensor)||{},behavior=b.behavior||{},legacyMode=String(b.mode||'').toLowerCase(),behaviorMode=String(behavior.mode||'').toLowerCase();
    const telemetryAvailable=b.telemetry_available!==false&&Boolean(b.mode||behavior.mode||b.manual_completion_supported||behavior.manual_completion_supported);
    const capabilityKnown=b.manual_completion_supported!==undefined||behavior.manual_completion_supported!==undefined;
    const capability=b.manual_completion_supported!==false&&behavior.manual_completion_supported!==false;
    const pending=b.learning_completion_pending===true;
    const legacyEnabled=b.enabled!==false,behaviorEnabled=behavior.enabled!==false;
    const legacyLearning=legacyEnabled&&legacyMode==='learning',behaviorLearning=behaviorEnabled&&behaviorMode==='learning';
    const legacyMonitoring=legacyEnabled&&legacyMode==='monitoring',behaviorMonitoring=behaviorEnabled&&behaviorMode==='monitoring';
    const legacyStart=legacyLearning?validTime(b.learning_started):0,behaviorStart=behaviorLearning?validTime(behavior.learning_started):0;
    const legacyEnd=legacyLearning?validTime(b.learning_ends_at):0,behaviorEnd=behaviorLearning?validTime(behavior.learning_ends_at):0;
    const deadline=Math.max(legacyEnd,behaviorEnd),active=legacyLearning||behaviorLearning;
    const started=active&&(!legacyLearning||legacyStart>0)&&(!behaviorLearning||behaviorStart>0);
    const state=active?'learning':(legacyMonitoring||behaviorMonitoring?'monitoring':'unavailable');
    const fallbackName=String(b.sensor_name||'').trim(),name=identity.name||fallbackName;
    const displayName=name&&name!==sensor?`${name} (${sensor})`:sensor;
    return {sensor,name,displayName,site:identity.site||'',hostname:identity.hostname||'',state,active,started,deadline,minElapsed:active&&deadline>0&&Date.now()>=deadline,readiness:Number(behavior.readiness??b.readiness??0),mature:Number(behavior.mature_assets??b.mature_assets??0),learning:Number(behavior.learning_assets??b.learning_assets??0),rate:Number(behavior.new_pattern_rate??b.new_pattern_rate??0),capability,capabilityKnown,pending,telemetryAvailable};
  }).filter(x=>x.sensor).sort((a,b)=>a.displayName.localeCompare(b.displayName));
}

async function waitForLearningCompletion(sensorID,timeoutMs=90000){
  const deadline=Date.now()+timeoutMs;
  while(Date.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,2000));
    try{
      const latest=await api('/baseline');
      if(Array.isArray(latest))baselines=latest;
      const row=learningSensorRows().find(x=>x.sensor===sensorID);
      if(row&&row.state==='monitoring'&&!row.pending)return true;
      if(row&&row.telemetryAvailable&&row.capabilityKnown&&!row.capability){
        const error=new Error('The sensor reports that manual learning completion is unsupported. Rebuild and deploy the patched sensor binary.');
        error.code='learning_completion_unsupported';
        throw error;
      }
    }catch(error){
      if(error?.code==='learning_completion_unsupported')throw error;
      console.warn('learning completion status poll failed',error);
    }
  }
  return false;
}

function renderLearningControls(){
  const select=document.getElementById('learning-finish-sensor'),finish=document.getElementById('learning-finish'),force=document.getElementById('learning-force-finish');
  if(!select||!finish||!force)return;
  const rows=learningSensorRows(),previous=select.value;
  const optionLabel=x=>`${x.displayName} · ${x.state}${x.pending?' · finishing…':''}`;
  select.innerHTML=rows.length?rows.map(x=>`<option value="${esc(x.sensor)}">${esc(optionLabel(x))}</option>`).join(''):'<option value="">No registered sensors</option>';
  if(rows.some(x=>x.sensor===previous))select.value=previous;
  else if(rows.some(x=>x.active))select.value=rows.find(x=>x.active).sensor;
  select.disabled=!rows.length;
  const current=()=>rows.find(x=>x.sensor===select.value)||null;
  const sync=()=>{
    const row=current(),allowed=can('data_management'),forceAllowed=allowed&&can('users_roles_manage');
    finish.disabled=!allowed||!row||!row.active||!row.started||!row.minElapsed||!row.capability||row.pending;
    force.hidden=!forceAllowed||!row||!row.active||row.minElapsed;
    force.disabled=!forceAllowed||!row||!row.active||!row.started||row.minElapsed||!row.capability||row.pending;
    finish.textContent=row?.pending?'Finishing…':'Finish learning now';
    force.textContent=row?.pending?'Finishing…':'Force finish';
    if(!row)finish.title='No registered sensor is available';
    else if(row.pending)finish.title=force.title='Command is pending until this sensor reports monitoring telemetry';
    else if(row.telemetryAvailable&&row.capabilityKnown&&!row.capability)finish.title=force.title='This sensor reports that manual learning completion is unsupported; rebuild and deploy the patched sensor';
    else if(row.telemetryAvailable&&!row.capabilityKnown)finish.title=force.title='Sensor capability is not advertised by this build; if completion does not confirm, deploy the updated sensor binary';
    else if(!row.active)finish.title=row.state==='monitoring'?'This sensor is already monitoring':'Learning state is not available for this sensor';
    else if(!row.started)finish.title=force.title='Learning starts after the first eligible traffic observation';
    else if(!row.minElapsed)finish.title='Available after the minimum learning duration';
    else finish.title='Freeze the current trusted baseline and activate monitoring';
  };
  select.onchange=sync;sync();

  const details=row=>{
    const total=row.mature+row.learning,minimum=row.minElapsed?'elapsed':'NOT elapsed';
    return `Readiness: ${Math.round(row.readiness*1000)/10}%\nMature assets: ${row.mature}/${total}\nNew-pattern rate: ${Math.round(row.rate*1000)/10}%\nMinimum learning duration: ${minimum}`;
  };
  const run=async(row,forceMode)=>{
    const button=forceMode?force:finish;
    finish.disabled=true;force.disabled=true;button.textContent='Waiting for sensor…';
    try{
      await api(`/sensors/${encodeURIComponent(row.sensor)}/learning/complete`,{method:'POST',body:JSON.stringify({force:forceMode})});
      const completed=await waitForLearningCompletion(row.sensor);
      await refreshView('nba',true);
      if(!completed){
        alert(`Central queued the command, but ${row.displayName} did not report monitoring within 90 seconds.\n\nVerify that the patched sensor binary is deployed and running, then check the sensor log for "OTLens sensor learning completed". The command remains pending and will be retried automatically.`);
      }
    }catch(error){
      alert(error.parsed?.error||error.message);
      await refreshView('nba',true);
    }
  };
  finish.onclick=async()=>{
    const row=current();if(!row||finish.disabled)return;
    if(!confirm(`Finish learning for ${row.displayName}?\n\n${details(row)}\n\nThe current trusted baseline will be frozen and behavioral detection will become active.`))return;
    await run(row,false);
  };
  force.onclick=async()=>{
    const row=current();if(!row||force.disabled)return;
    if(!confirm(`FORCE finish learning for ${row.displayName}?\n\n${details(row)}\n\nWarning: the minimum learning duration has not elapsed. This can freeze an incomplete trusted baseline and increase false positives.`))return;
    await run(row,true);
  };
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
  renderLearningControls();

  const rows=learningCandidateRows(),body=document.querySelector('#table-learning-candidates tbody');
  set('learning-candidate-note',`${rows.length.toLocaleString()} candidate${rows.length===1?'':'s'} shown from current sensor telemetry`);
  if(!body)return;
  body.innerHTML=rows.map(({sensor,c})=>{
    const k=c.key||{},ready=Boolean(c.ready_for_promotion),eligible=c.eligible!==false;
    const shortStatus=!eligible?'excluded':ready?'ready for review':'collecting';
    const service=[k.protocol||k.transport||'unknown',k.service_port||''].filter(Boolean).join('/');
    const disabled=!ready||!can('alert_confirm_approve');
    const evidence=`${Number(c.observations||0).toLocaleString()} obs · ${Number(c.distinct_days||0)} day${Number(c.distinct_days||0)===1?'':'s'}`;
    return `<tr class="clickable-row learning-candidate-row"><td>${esc(sensor)}</td><td>${esc(k.src_ip||'—')} → ${esc(k.dst_ip||'—')}</td><td>${esc(service||'—')}</td><td>${esc(evidence)}</td><td>${esc(shortStatus)}</td><td class="behavior-row-actions"><button class="secondary-btn learning-candidate-details" type="button">Details</button><button class="secondary-btn learning-promote" type="button" ${disabled?'disabled':''}>Promote</button></td></tr>`;
  }).join('')||'<tr><td colspan="6">No shadow-baseline candidates.</td></tr>';
  body.querySelectorAll('.learning-candidate-row').forEach((row,index)=>row.onclick=e=>{if(e.target.closest('button'))return;showLearningCandidate(rows[index])});
  body.querySelectorAll('.learning-candidate-details').forEach((button,index)=>button.onclick=e=>{e.stopPropagation();showLearningCandidate(rows[index])});
  body.querySelectorAll('.learning-promote').forEach((button,index)=>button.onclick=async e=>{
    e.stopPropagation();
    const row=rows[index];if(!row?.c?.id)return;
    if(!confirm('Promote this reviewed relationship into the trusted behavior baseline?'))return;
    button.disabled=true;
    try{await api(`/sensors/${encodeURIComponent(row.sensor)}/baseline/candidates/promote`,{method:'POST',body:JSON.stringify({candidate_id:row.c.id})});button.textContent='Queued';setTimeout(()=>refreshView('nba',true),1500)}catch(error){alert(error.parsed?.error||error.message);button.disabled=false}
  });
  window.OTDataTables?.refresh('table-learning-candidates');
}


function showLearningCandidate(row){
  if(!row?.c)return;
  const sensor=row.sensor||'—',c=row.c,k=c.key||{},ready=Boolean(c.ready_for_promotion),eligible=c.eligible!==false;
  const service=[k.protocol||k.transport||'unknown',k.service_port||''].filter(Boolean).join('/');
  const status=!eligible?'Excluded from promotion':ready?'Ready for review':'Collecting evidence';
  const reason=c.reason||(!eligible?'Security or policy evidence prevents promotion':ready?'Candidate meets the configured evidence thresholds':'Candidate has not yet met the configured promotion thresholds');
  const days=Array.isArray(c.observation_days)&&c.observation_days.length?c.observation_days.join(', '):'—';
  const body=document.getElementById('candidate-detail-body');if(!body)return;
  body.innerHTML=`
    <dl class="status-list detail-status-list candidate-detail-list">
      <div><dt>Sensor</dt><dd>${esc(sensor)}</dd></div>
      <div><dt>Candidate ID</dt><dd class="wrap-anywhere">${esc(c.id||'—')}</dd></div>
      <div><dt>Source</dt><dd>${esc(k.src_ip||'—')}</dd></div>
      <div><dt>Destination</dt><dd>${esc(k.dst_ip||'—')}</dd></div>
      <div><dt>Service</dt><dd>${esc(service||'—')}</dd></div>
      <div><dt>Transport</dt><dd>${esc(k.transport||'—')}</dd></div>
      <div><dt>Protocol</dt><dd>${esc(k.protocol||'—')}</dd></div>
      <div><dt>Service port</dt><dd>${esc(k.service_port??'—')}</dd></div>
      <div><dt>Scope</dt><dd>${esc(k.scope||'—')}</dd></div>
      <div><dt>Time bucket</dt><dd>${esc(k.time_bucket??'—')}</dd></div>
      <div><dt>Day class</dt><dd>${esc(k.day_class||'—')}</dd></div>
      <div><dt>Shift</dt><dd>${esc(k.shift||'—')}</dd></div>
      <div><dt>Context</dt><dd>${esc(k.context||'—')}</dd></div>
      <div><dt>Observations</dt><dd>${Number(c.observations||0).toLocaleString()}</dd></div>
      <div><dt>Distinct days</dt><dd>${Number(c.distinct_days||0).toLocaleString()}</dd></div>
      <div><dt>Observation days</dt><dd class="wrap-anywhere">${esc(days)}</dd></div>
      <div><dt>First seen</dt><dd>${time(c.first_seen)}</dd></div>
      <div><dt>Last seen</dt><dd>${time(c.last_seen)}</dd></div>
      <div><dt>Eligible</dt><dd>${eligible?'Yes':'No'}</dd></div>
      <div><dt>Ready for promotion</dt><dd>${ready?'Yes':'No'}</dd></div>
      <div><dt>Status</dt><dd>${esc(status)}</dd></div>
    </dl>
    <h3>Review reason</h3><div class="detail-message wrap-anywhere">${esc(reason)}</div>`;
  document.getElementById('candidate-detail-modal').hidden=false;
}

const originalRenderBehaviorFindings=renderBehaviorFindings;
renderBehaviorFindings=function(...args){const result=originalRenderBehaviorFindings.apply(this,args);renderLearningQuality();return result};
renderLearningControls();
