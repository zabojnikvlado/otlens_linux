function renderAssets(){const q=document.getElementById('assets-filter').value.toLowerCase(),life=document.getElementById('assets-lifecycle-filter')?.value||'all',data=assets.filter(a=>JSON.stringify(a).toLowerCase().includes(q)&&(life==='all'||(life==='active'&&a.IdentityActive!==false)||(life==='stale'&&a.IdentityActive===false)));document.getElementById('assets-count').textContent=data.length+' assets';document.querySelector('#table-assets tbody').innerHTML=data.map(a=>`<tr class="asset-row ${a.Confirmed===false?'row-unconfirmed':''}" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" data-vendor="${esc(a.Vendor||'')}" data-ip="${esc(a.IP||'')}"><td><input class="asset-check" type="checkbox" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" ${selected.has(a.SensorID+'::'+a.MAC)?'checked':''}></td><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Vendor)}</td><td>${esc(a.Hostname)}</td><td><span class="status-pill ${a.IdentityActive===false?'degraded':'healthy'}">${a.IdentityActive===false?'stale':'active'}</span></td><td class="${a.Confirmed===false?'state-new':'state-ok'}">${a.Confirmed===false?'NEW / UNCONFIRMED':'confirmed'}</td><td>${a.IsOT?'OT':'IT'}</td><td>${esc((a.Protocols||[]).join(', '))}</td><td>${esc(a.VLANID||'untagged')}</td><td>${esc(a.Score??1)}</td><td>${(a.IsHoneypot===true||Number(a.Score??1)>=Number(a.HoneypotThreshold??100))?'<span class="pill honeypot">HONEYPOT</span>':Number(a.Score??1)>=75?'<span class="pill severity-high">CRITICAL</span>':Number(a.Score??1)>=40?'<span class="pill severity-medium">ELEVATED</span>':'standard'}</td><td>${esc(a.PacketCount)}</td><td>${time(a.LastSeen)}</td><td>${(()=>{const x=assetSecurity.find(v=>v.sensor_id===a.SensorID&&v.asset_ip===a.IP);return x?`<span class="pill severity-${x.status==='infected'?'high':x.status==='suspected'?'medium':'low'}">${esc(x.status.toUpperCase())}</span>`:'clean/unknown'})()}</td><td>${can('asset_confirm_delete')?`<button class="danger-btn infect-one" data-sensor="${esc(a.SensorID)}" data-ip="${esc(a.IP)}">Tag infection</button> `:''}${a.Confirmed===false&&can('asset_confirm_delete')?`<button class="ack-btn confirm-one" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}">Confirm</button>`:a.Confirmed===false?'pending':'—'}</td></tr>`).join('');updateBulk()}
const deviceCategoryFilter=new Set();
function syncImportAndPurdueSensorLists(){for(const id of ['tags-import-sensor','purdue-sensor']){const sel=document.getElementById(id);if(!sel)continue;const current=sel.value;sel.innerHTML=sensors.map(x=>`<option value="${esc(x.ID||x.id)}">${esc(x.Name||x.name||x.ID||x.id)}</option>`).join('');if(current&&[...sel.options].some(o=>o.value===current))sel.value=current}}
function renderDevices(){
  syncImportAndPurdueSensorLists();
  const sel=document.getElementById('devices-import-sensor');
  if(sel&&sel.dataset.populated!==String(sensors.length)){
    sel.innerHTML=sensors.map(s=>`<option value="${esc(s.ID||s.id)}">${esc(s.Name||s.name||s.ID||s.id)}</option>`).join('');
    sel.dataset.populated=String(sensors.length);
  }
  const cats=[...new Set(devices.map(d=>d.Category||'IT'))].sort();
  document.getElementById('devices-category-chips').innerHTML=cats.map(cat=>{
    const off=deviceCategoryFilter.has(cat);
    return `<label class="vlan-chip ${off?'off':''}" data-cat="${esc(cat)}"><input type="checkbox" ${off?'':'checked'}> ${esc(cat)}</label>`;
  }).join('');
  const q=(document.getElementById('devices-filter').value||'').toLowerCase();
  const data=devices.filter(d=>!deviceCategoryFilter.has(d.Category||'IT')&&JSON.stringify(d).toLowerCase().includes(q));
  document.getElementById('devices-count').textContent=data.length+' devices';
  document.querySelector('#table-devices tbody').innerHTML=data.map(d=>`<tr><td>${esc(d.SensorID)}</td><td>${esc(d.IP)}</td><td>${esc(d.MAC)}</td><td>${esc(d.OverrideName||d.Hostname||'—')}</td><td>${esc(d.Vendor||'—')}</td><td class="device-category" data-sensor="${esc(d.SensorID)}" data-mac="${esc(d.MAC)}" title="Click to change">${esc(d.Category||'IT')}</td><td class="${d.Confirmed===false?'state-new':'state-ok'}">${d.Confirmed===false?'NEW / UNCONFIRMED':'confirmed'}</td><td>${time(d.LastSeen)}</td></tr>`).join('');
}
document.getElementById('devices-filter').addEventListener('input',renderDevices);
document.getElementById('devices-category-chips').addEventListener('click',e=>{
  const chip=e.target.closest('.vlan-chip');if(!chip)return;e.preventDefault();
  const cat=chip.dataset.cat;
  if(deviceCategoryFilter.has(cat))deviceCategoryFilter.delete(cat);else deviceCategoryFilter.add(cat);
  renderDevices();
});
const DEVICE_CATEGORIES=['IT','OT','Workstation','Server','Engineering Workstation','HMI/SCADA','PLC/RTU','Historian','Network','Security Appliance','Virtualization','Storage/NAS','Printer','Mobile','IoT','Rogue/Unknown'];
let categoryEditTarget=null;
function openDeviceCategoryEditor(cell){
  categoryEditTarget={sensor:cell.dataset.sensor,mac:cell.dataset.mac};
  const select=document.getElementById('device-category-select'),current=cell.textContent.trim();
  select.innerHTML=DEVICE_CATEGORIES.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');
  if(!DEVICE_CATEGORIES.includes(current))select.insertAdjacentHTML('beforeend',`<option value="${esc(current)}">${esc(current)}</option>`);
  select.value=current;document.getElementById('device-category-modal').hidden=false;select.focus();
}
document.querySelector('#table-devices tbody').addEventListener('click',e=>{const cell=e.target.closest('.device-category');if(cell&&can('asset_confirm_delete'))openDeviceCategoryEditor(cell)});
async function saveDeviceCategory(){
  if(!categoryEditTarget)return;const next=document.getElementById('device-category-select').value;if(!next)return;
  try{await api(`/sensors/${encodeURIComponent(categoryEditTarget.sensor)}/assets/${encodeURIComponent(categoryEditTarget.mac)}/category`,{method:'POST',body:JSON.stringify({category:next})});document.getElementById('device-category-modal').hidden=true;categoryEditTarget=null;refreshAll()}catch(err){document.getElementById('device-category-error').textContent=`Failed to set category: ${err.message}`}
}
document.getElementById('device-category-save').onclick=saveDeviceCategory;document.getElementById('device-category-cancel').onclick=()=>document.getElementById('device-category-modal').hidden=true;document.getElementById('device-category-modal-close').onclick=()=>document.getElementById('device-category-modal').hidden=true;
document.getElementById('devices-import-file').addEventListener('change',async e=>{
  const file=e.target.files[0];if(!file)return;
  const sensorID=document.getElementById('devices-import-sensor').value;
  if(!sensorID){alert('Select a sensor to import into first.');e.target.value='';return}
  const form=new FormData();form.append('file',file);
  try{
    const r=await api(`/sensors/${encodeURIComponent(sensorID)}/devices/import`,{method:'POST',body:form});
    alert(`Imported ${r.applied} row(s).`);
    refreshAll();
  }catch(err){alert(`Import failed: ${err.message}`)}
  finally{e.target.value=''}
});
let segmentationSensorID=null;
function renderSegmentationSensorList(){
  const sel=document.getElementById('segmentation-sensor');if(!sel)return;
  if(sel.dataset.populated===String(sensors.length))return;
  sel.innerHTML=sensors.map(s=>`<option value="${esc(s.ID||s.id)}">${esc(s.Name||s.name||s.ID||s.id)}</option>`).join('');
  sel.dataset.populated=String(sensors.length);
  if(!segmentationSensorID&&sensors.length){segmentationSensorID=sensors[0].ID||sensors[0].id;sel.value=segmentationSensorID;loadSegmentation()}
}
async function loadSegmentation(){
  if(!segmentationSensorID)return;
  const tbody=document.querySelector('#table-segmentation tbody');
  try{
    const vlans=await api(`/sensors/${encodeURIComponent(segmentationSensorID)}/vlans`);
    tbody.innerHTML=(vlans||[]).map(v=>`<tr><td>${v.VLANID===0?'Untagged':v.VLANID}</td><td>${esc(v.Name||'—')}</td><td>${v.PurdueLevel==null?'—':esc(v.PurdueLevel)}</td><td class="segmentation-assets" data-vlan="${v.VLANID}">${esc(v.AssetCount)} <span class="rules-help" style="display:inline">(view)</span></td><td><button class="secondary-btn segmentation-edit" data-vlan="${v.VLANID}" data-name="${esc(v.Name||'')}" data-level="${v.PurdueLevel==null?'':v.PurdueLevel}">Edit</button></td></tr>`).join('')||'<tr><td colspan="5">No VLANs observed yet for this sensor.</td></tr>';
  }catch(err){tbody.innerHTML=`<tr><td colspan="5">Failed to load: ${esc(err.message)}</td></tr>`}
  try{
    const r=await api(`/sensors/${encodeURIComponent(segmentationSensorID)}/segmentation-settings`);
    document.getElementById('segmentation-max-jump').value=r.max_level_jump;
  }catch(err){/* leave whatever was there before */}
}
document.getElementById('segmentation-max-jump-save').addEventListener('click',async()=>{
  const val=Number(document.getElementById('segmentation-max-jump').value);
  if(!val||val<=0){alert('Enter a positive number.');return}
  try{
    await api(`/sensors/${encodeURIComponent(segmentationSensorID)}/segmentation-settings`,{method:'PUT',body:JSON.stringify({max_level_jump:val})});
  }catch(err){alert(`Failed to save: ${err.message}`)}
});
document.getElementById('segmentation-sensor').addEventListener('change',e=>{segmentationSensorID=e.target.value;loadSegmentation()});
document.querySelector('#table-segmentation tbody').addEventListener('click',async e=>{
  const editBtn=e.target.closest('.segmentation-edit');
  if(editBtn){
    const name=prompt('VLAN name:',editBtn.dataset.name||'');
    if(name===null)return;
    const levelStr=prompt('Purdue level (0-5, blank to clear):',editBtn.dataset.level||'');
    if(levelStr===null)return;
    const purdue_level=levelStr.trim()===''?null:Number(levelStr);
    try{
      await api(`/sensors/${encodeURIComponent(segmentationSensorID)}/vlans/${editBtn.dataset.vlan}`,{method:'PUT',body:JSON.stringify({name,purdue_level})});
      loadSegmentation();
    }catch(err){alert(`Failed to save: ${err.message}`)}
    return;
  }
  const assetsCell=e.target.closest('.segmentation-assets');
  if(assetsCell){
    try{
      const assets=await api(`/sensors/${encodeURIComponent(segmentationSensorID)}/vlans/${assetsCell.dataset.vlan}/assets`);
      document.getElementById('vuln-modal-title').textContent=`VLAN ${assetsCell.dataset.vlan==='0'?'Untagged':assetsCell.dataset.vlan} — assets`;
      const rows=assets||[];
      document.getElementById('vuln-modal-body').innerHTML=rows.length?`<table class="data-table"><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th></tr></thead><tbody>${rows.map(a=>`<tr><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Hostname||'—')}</td><td>${esc(a.Vendor||'—')}</td></tr>`).join('')}</tbody></table>`:'<div class="empty-dashboard">No assets currently on this VLAN.</div>';
      document.getElementById('vuln-modal').hidden=false;
    }catch(err){alert(`Failed to load assets: ${err.message}`)}
  }
});
function renderVulnerabilities(){
  const q=(document.getElementById('vuln-mgmt-filter').value||'').toLowerCase();
  const data=vulnerabilities.filter(v=>JSON.stringify(v).toLowerCase().includes(q));
  document.getElementById('vuln-mgmt-count').textContent=data.length+' advisories';
  document.querySelector('#table-vulnerabilities tbody').innerHTML=data.map((v,i)=>{const c=v.StatusCounts||{};return `<tr class="vuln-row" data-index="${data.indexOf(v)}"><td>${esc(v.CVEID)}</td><td><span class="severity ${esc(String(v.Severity||'').toLowerCase())}">${esc(v.Severity||'—')}</span></td><td>${esc(v.Vendor)}</td><td>${esc(v.Product||'—')}</td><td>${esc(v.Title)}</td><td>${esc(v.PublishedDate||'—')}</td><td>${esc(v.AffectedCount||0)}</td><td><span class="vuln-life-summary">${esc(c.confirmed||0)} confirmed · ${esc(c.remediated||0)} remediated</span></td></tr>`}).join('');
  window.__vulnRows=data;
}
document.getElementById('vuln-mgmt-filter').addEventListener('input',renderVulnerabilities);
document.querySelector('#table-vulnerabilities tbody').addEventListener('click',e=>{
  const row=e.target.closest('.vuln-row');if(!row)return;
  const v=(window.__vulnRows||[])[Number(row.dataset.index)];if(!v)return;
  const assetsList=v.AffectedAssets||[];
  document.getElementById('vuln-modal-title').textContent=`${esc(v.CVEID)} — ${esc(v.Vendor)}`;
  document.getElementById('vuln-modal-body').innerHTML=`
    <div class="modal-history"><b>${esc(v.Title)}</b><br><span class="severity ${esc(String(v.Severity||'').toLowerCase())}">${esc(v.Severity||'—')}</span> · ${esc(v.Product||'—')} · ${esc(v.PublishedDate||'—')}${v.URL?` · <a href="${esc(v.URL)}" target="_blank" rel="noopener">advisory</a>`:''}</div>
    <h3>Affected assets (${assetsList.length})</h3>
    ${assetsList.length?`<table class="data-table vulnerability-findings-table"><thead><tr><th>Sensor</th><th>IP</th><th>MAC</th><th>Hostname</th><th>Status</th><th>Notes</th><th></th></tr></thead><tbody>${assetsList.map((a,i)=>`<tr data-finding-index="${i}"><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Hostname||'—')}</td><td><select class="otl-select vuln-finding-status"><option value="potential" ${a.FindingStatus==='potential'?'selected':''}>Potential</option><option value="confirmed" ${a.FindingStatus==='confirmed'?'selected':''}>Confirmed</option><option value="accepted_risk" ${a.FindingStatus==='accepted_risk'?'selected':''}>Accepted risk</option><option value="false_positive" ${a.FindingStatus==='false_positive'?'selected':''}>False positive</option><option value="remediated" ${a.FindingStatus==='remediated'?'selected':''}>Remediated</option></select></td><td><input class="otl-input vuln-finding-notes" value="${esc(a.FindingNotes||'')}" placeholder="Notes"></td><td><button class="secondary-btn vuln-finding-save">Save</button></td></tr>`).join('')}</tbody></table>`:'<div class="empty-dashboard">No currently-known assets from this vendor.</div>'}`;
  window.__activeVulnerability={v,assetsList};
  document.getElementById('vuln-modal').hidden=false;
});

document.getElementById('vuln-modal-body').addEventListener('click',async e=>{
  const btn=e.target.closest('.vuln-finding-save');if(!btn)return;
  const row=btn.closest('tr'),ctx=window.__activeVulnerability;if(!row||!ctx)return;
  const asset=ctx.assetsList[Number(row.dataset.findingIndex)];if(!asset)return;
  const status=row.querySelector('.vuln-finding-status').value,notes=row.querySelector('.vuln-finding-notes').value.trim();
  btn.disabled=true;
  try{await api('/vulnerabilities/findings',{method:'PUT',body:JSON.stringify({cve_id:ctx.v.CVEID,sensor_id:asset.SensorID,asset_identity:asset.AssetIdentity,asset_ip:asset.IP||'',asset_mac:asset.MAC||'',status,notes})});asset.FindingStatus=status;asset.FindingNotes=notes;btn.textContent='Saved';setTimeout(()=>btn.textContent='Save',1200);await refreshAll()}catch(err){alert(err.parsed?.error||err.message)}finally{btn.disabled=false}
});

function updateBulk(){const on=selected.size>0;document.querySelectorAll('.bulk').forEach(b=>b.hidden=!on)}

function selectedAssetsForDiscovery(){return (assets||[]).filter(a=>selected.has(a.SensorID+'::'+a.MAC)&&a.IP)}
function automaticDiscoveryProfile(asset){return (asset.IsOT||asset.Category==='OT'||(asset.Protocols||[]).some(p=>/modbus|s7|ethernet.?ip|opc|bacnet/i.test(p)))?'ot-conservative':'safe-discovery'}
function openBulkDiscovery(){const chosen=selectedAssetsForDiscovery();if(!chosen.length){alert('Select at least one asset with an IP address.');return}const sensorsCount=new Set(chosen.map(a=>a.SensorID)).size;document.getElementById('bulk-discovery-summary').textContent=`${chosen.length} assets selected across ${sensorsCount} sensor${sensorsCount===1?'':'s'}. Jobs are grouped per sensor and profile.`;document.getElementById('bulk-discovery-form').hidden=false;document.getElementById('bulk-discovery-progress').hidden=true;document.getElementById('bulk-discovery-modal').hidden=false}
function closeBulkDiscovery(){document.getElementById('bulk-discovery-modal').hidden=true}
function renderBulkDiscoveryJobs(batch){const current=reconnaissanceJobs||[],rows=batch.map(x=>{const job=current.find(j=>j.id===x.id)||x,status=job.status||x.status||'queued';return `<tr><td>${esc(x.sensor_id)}</td><td>${esc((x.targets||[]).length)}</td><td>${esc(x.profile)}</td><td><span class="bulk-discovery-status ${esc(status)}">${esc(status)}</span></td><td>${esc(job.error||x.error||'—')}</td></tr>`});document.getElementById('bulk-discovery-jobs').innerHTML=rows.join('');const done=batch.filter(x=>{const j=current.find(v=>v.id===x.id)||x;return ['completed','partially_completed','failed'].includes(j.status)}).length,failed=batch.filter(x=>{const j=current.find(v=>v.id===x.id)||x;return j.status==='failed'}).length,total=batch.length;document.getElementById('bulk-discovery-progress-bar').max=Math.max(1,total);document.getElementById('bulk-discovery-progress-bar').value=done;document.getElementById('bulk-discovery-progress-count').textContent=`${done} / ${total}`;document.getElementById('bulk-discovery-progress-title').textContent=done===total?'Discovery batch completed':'Discovery in progress';document.getElementById('bulk-discovery-progress-details').textContent=`${total-done} active or queued · ${failed} failed`;return done===total}
async function monitorBulkDiscovery(batch){for(let i=0;i<180;i++){await loadRecon();if(renderBulkDiscoveryJobs(batch)){await refreshAll();return}await new Promise(r=>setTimeout(r,2000))}document.getElementById('bulk-discovery-progress-details').textContent='Some jobs are still pending. They remain visible in Reconnaissance.'}
document.getElementById('assets-discover').onclick=openBulkDiscovery;document.getElementById('bulk-discovery-close').onclick=closeBulkDiscovery;document.getElementById('bulk-discovery-cancel').onclick=closeBulkDiscovery;
document.getElementById('bulk-discovery-form').onsubmit=async e=>{e.preventDefault();const chosen=selectedAssetsForDiscovery();if(!chosen.length)return closeBulkDiscovery();if(!document.getElementById('bulk-discovery-approval').checked){alert('Manual approval is required.');return}const selectedProfile=document.getElementById('bulk-discovery-profile').value,concurrency=Math.max(1,Math.min(10,Number(document.getElementById('bulk-discovery-concurrency').value||3))),rate=Math.max(1,Math.min(20,Number(document.getElementById('bulk-discovery-rate').value||5))),timeout=Math.max(1,Math.min(10,Number(document.getElementById('bulk-discovery-timeout').value||4))),groups=new Map();chosen.forEach(a=>{const profile=selectedProfile==='automatic'?automaticDiscoveryProfile(a):selectedProfile,key=a.SensorID+'::'+profile;if(!groups.has(key))groups.set(key,{sensor:a.SensorID,profile,targets:[]});groups.get(key).targets.push(a.IP)});document.getElementById('bulk-discovery-form').hidden=true;document.getElementById('bulk-discovery-progress').hidden=false;document.getElementById('bulk-discovery-jobs').innerHTML='';const batch=[];for(const g of groups.values()){try{const policy={allowed_networks:[],denied_targets:[],ports:[22,80,443,445,3389,502,102,44818,4840,47808],packets_per_second:rate,concurrent_targets:concurrency,timeout_seconds:timeout,require_manual_approval:g.profile==='ot-conservative',ot_protocols:g.profile==='ot-conservative'?['modbus','ethernet-ip','s7','opcua','bacnet']:[],credential_id:'',authenticated_methods:[]};const job=await api('/reconnaissance/jobs',{method:'POST',body:JSON.stringify({sensor_id:g.sensor,targets:[...new Set(g.targets)],profile:g.profile,policy})});batch.push(job)}catch(err){batch.push({id:'local-'+Math.random(),sensor_id:g.sensor,targets:g.targets,profile:g.profile,status:'failed',error:err.parsed?.error||err.message})}renderBulkDiscoveryJobs(batch)}monitorBulkDiscovery(batch)};

document.getElementById('assets-filter').oninput=renderAssets;document.getElementById('assets-lifecycle-filter').onchange=renderAssets;document.querySelector('#table-assets tbody').onclick=e=>{const c=e.target.closest('.asset-check');if(c){const k=c.dataset.sensor+'::'+c.dataset.mac;c.checked?selected.add(k):selected.delete(k);updateBulk();return}const inf=e.target.closest('.infect-one');if(inf){tagAssetInfected(inf.dataset.sensor,inf.dataset.ip);return}const b=e.target.closest('.confirm-one');if(b){sendAssetAction('confirm',[b.dataset.sensor+'::'+b.dataset.mac]);return}const row=e.target.closest('.asset-row');if(!row)return;const a=(assets||[]).find(x=>x.SensorID===row.dataset.sensor&&x.IP===row.dataset.ip);if(a)openAssetDetail(a)};document.getElementById('assets-all').onchange=e=>{assets.forEach(a=>e.target.checked?selected.add(a.SensorID+'::'+a.MAC):selected.delete(a.SensorID+'::'+a.MAC));renderAssets()};
async function openAssetVulnerabilities(sensor,vendor,mac,ip){
  const title=document.getElementById('vuln-modal-title'),body=document.getElementById('vuln-modal-body');
  title.textContent=`${vendor||'Unknown vendor'} — ${ip||mac||sensor}`;
  document.getElementById('vuln-modal').hidden=false;
  const sections=[];
  if(vendor){
    try{
      const r=await api('/assets/vulnerabilities?vendor='+encodeURIComponent(vendor));
      if(!r.Loaded){
        sections.push('<h3>Known vulnerabilities</h3><div class="empty-dashboard">No vulnerability snapshot loaded on Central — set vulnerability.csv_path in central.config.yaml.</div>');
      }else{
        const list=Array.isArray(r.Advisories)?r.Advisories:[];
        sections.push('<h3>Known vulnerabilities</h3>'+(list.length?list.map(v=>`<div class="modal-history"><b>${esc(v.CVEID)}</b> <span class="severity ${esc(String(v.Severity||'').toLowerCase())}">${esc(v.Severity||'—')}</span><br>${esc(v.Title)}<br><small>${esc(v.Product||'—')} · ${esc(v.PublishedDate||'—')}</small>${v.URL?` · <a href="${esc(v.URL)}" target="_blank" rel="noopener">advisory</a>`:''}</div>`).join(''):'<div class="empty-dashboard">No known advisories for this vendor in the loaded snapshot.</div>'));
      }
    }catch(err){sections.push(`<h3>Known vulnerabilities</h3><div class="empty-dashboard">Failed to load: ${esc(err.message)}</div>`)}
  }else{
    sections.push('<h3>Known vulnerabilities</h3><div class="empty-dashboard">No vendor identified for this device (OUI lookup found no match) — vendor-based vulnerability matching needs one.</div>');
  }
  sections.push('<h3>IP history</h3><div id="vuln-modal-ip-history" class="empty-dashboard">Loading…</div>');
  body.innerHTML=sections.join('');
  try{
    const hist=await api(`/sensors/${encodeURIComponent(sensor)}/assets/by-mac/${encodeURIComponent(mac)}/ip-history`);
    const rows=Array.isArray(hist)?hist:[];
    document.getElementById('vuln-modal-ip-history').outerHTML=rows.length?`<table class="data-table"><thead><tr><th>IP</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${rows.map(h=>`<tr><td>${esc(h.IP)}</td><td>${time(h.FirstSeen)}</td><td>${time(h.LastSeen)}</td></tr>`).join('')}</tbody></table>`:'<div class="empty-dashboard">No recorded IP history for this device yet.</div>';
  }catch(err){
    const el=document.getElementById('vuln-modal-ip-history');
    if(el)el.textContent=`Failed to load: ${err.message}`;
  }
}
document.getElementById('vuln-modal-close').onclick=()=>document.getElementById('vuln-modal').hidden=true;
async function sendAssetAction(action,keys=[...selected]){const groups={};keys.forEach(k=>{const i=k.indexOf('::'),s=k.slice(0,i),m=k.slice(i+2);(groups[s]??=[]).push(m)});for(const [s,targets] of Object.entries(groups))await api(`/sensors/${encodeURIComponent(s)}/assets/actions`,{method:'POST',body:JSON.stringify({action,targets})});selected.clear();updateBulk();setTimeout(refreshAll,1000)}document.getElementById('assets-confirm').onclick=()=>sendAssetAction('confirm');document.getElementById('assets-delete').onclick=()=>confirm('Delete selected assets?')&&sendAssetAction('delete');
function tagIdentity(t){return `${t.SensorID??''}::${t.Key||[t.DeviceIP,t.DevicePort,t.Protocol,t.AddressSpace,t.Address].join('|')}`}
function currentTags(){const byKey=new Map();for(const t of Array.isArray(tags)?tags:[])byKey.set(tagIdentity(t),t);return [...byKey.values()]}
function renderTags(){const q=document.getElementById('tags-filter').value.toLowerCase(),data=currentTags().filter(t=>JSON.stringify(t).toLowerCase().includes(q));document.getElementById('tags-count').textContent=data.length+' tags';document.querySelector('#table-tags tbody').innerHTML=data.map(t=>`<tr class="tag-row" data-sensor="${esc(t.SensorID)}" data-key="${esc(t.Key||[t.DeviceIP,t.DevicePort,t.Protocol,t.AddressSpace,t.Address].join('|'))}"><td>${esc(t.SensorID)}</td><td>${esc(t.DeviceIP)}:${esc(t.DevicePort)}</td><td>${esc(t.Protocol)}</td><td>${esc(t.AddressSpace)} ${esc(t.Address)}</td><td>${esc(t.Operation)}</td><td>${esc(val(t.LastValue))}</td><td>${esc(val(t.MinValue))}</td><td>${esc(val(t.MaxValue))}</td><td>${time(t.LastChangeAt)}</td><td>${esc(t.PollCount)}</td><td>${esc(t.ChangeCount)}</td></tr>`).join('')}
document.getElementById('tags-filter').oninput=renderTags;document.querySelector('#table-tags tbody').onclick=e=>{const r=e.target.closest('.tag-row');if(r)openTag(r.dataset.sensor,r.dataset.key)};document.getElementById('tags-import-file')?.addEventListener('change',async e=>{const file=e.target.files[0];if(!file)return;const sensorID=document.getElementById('tags-import-sensor').value;if(!sensorID){alert('Select a sensor first.');e.target.value='';return}const form=new FormData();form.append('file',file);try{const r=await api(`/sensors/${encodeURIComponent(sensorID)}/tags/import`,{method:'POST',body:form});alert(`Imported ${r.applied} tag(s).`);await refreshAll()}catch(err){alert(`Tag import failed: ${err.message}`)}finally{e.target.value=''}});
function formatTagValue(v){return Number.isInteger(v)?String(v):String(Number(v.toFixed(2)))}
function drawChart(rows){
  const c=document.getElementById('tag-chart'),x=c.getContext('2d');
  x.clearRect(0,0,c.width,c.height);
  const points=rows.map(r=>({v:Number(r.NewValue),t:r.Timestamp})).filter(p=>Number.isFinite(p.v));
  if(points.length<1){x.fillStyle='#8393ab';x.font='13px sans-serif';x.fillText('No numeric change history',20,c.height/2);return}
  const nums=points.map(p=>p.v),mn=Math.min(...nums),mx=Math.max(...nums),range=mx-mn||1;
  const padL=56,padR=14,padT=14,padB=26,plotW=c.width-padL-padR,plotH=c.height-padT-padB;
  const xAt=i=>padL+(points.length>1?i*plotW/(points.length-1):plotW/2);
  const yAt=v=>padT+plotH-(v-mn)*plotH/range;

  // axes
  x.strokeStyle='#2a3648';x.lineWidth=1;
  x.beginPath();x.moveTo(padL,padT);x.lineTo(padL,padT+plotH);x.lineTo(padL+plotW,padT+plotH);x.stroke();

  // horizontal gridlines + Y value labels (min / mid / max of the learned history)
  x.font='11px monospace';x.textAlign='right';x.textBaseline='middle';
  [mn,mn+range/2,mx].forEach(v=>{
    const py=yAt(v);
    x.strokeStyle='rgba(255,255,255,.06)';x.beginPath();x.moveTo(padL,py);x.lineTo(padL+plotW,py);x.stroke();
    x.fillStyle='#8393ab';x.fillText(formatTagValue(v),padL-8,py);
  });

  // X axis time labels — first, middle, last change in the visible window
  x.textAlign='center';x.textBaseline='top';
  const xIdxs=points.length>1?[0,Math.floor((points.length-1)/2),points.length-1]:[0];
  new Set(xIdxs).forEach(i=>{
    const label=points[i].t?new Date(points[i].t).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'';
    x.fillStyle='#8393ab';x.fillText(label,xAt(i),padT+plotH+6);
  });

  // value line + point markers
  x.strokeStyle='#3fbfb0';x.lineWidth=2;x.beginPath();
  points.forEach((p,i)=>{const px=xAt(i),py=yAt(p.v);i?x.lineTo(px,py):x.moveTo(px,py)});
  x.stroke();
  x.fillStyle='#3fbfb0';
  points.forEach((p,i)=>{const px=xAt(i),py=yAt(p.v);x.beginPath();x.arc(px,py,2.5,0,Math.PI*2);x.fill()});
}
// drawDailyBarChart renders a simple bar chart of one count per day —
// used for both dashboard trend panels. Zero-fills every day in the
// window (not just days that had data) so the x-axis stays continuous
// and a quiet stretch reads as "nothing happened," not as a gap.
function drawDailyBarChart(canvasId,dayCounts,days){
  const c=document.getElementById(canvasId);if(!c)return;
  const {x,w,h}=resizeCanvas(c,180);
  x.clearRect(0,0,w,h);
  const byDay=new Map((dayCounts||[]).map(d=>[new Date(d.Day).toDateString(),Number(d.Count)||0]));
  const series=[];
  const today=new Date();today.setHours(0,0,0,0);
  for(let i=days-1;i>=0;i--){
    const d=new Date(today);d.setDate(d.getDate()-i);
    series.push({date:d,count:byDay.get(d.toDateString())||0});
  }
  const mx=Math.max(1,...series.map(s=>s.count));
  const padL=38,padR=12,padT=12,padB=24,plotW=w-padL-padR,plotH=h-padT-padB;
  const barW=plotW/series.length;
  x.strokeStyle='#2a3648';x.lineWidth=1;
  x.beginPath();x.moveTo(padL,padT);x.lineTo(padL,padT+plotH);x.lineTo(padL+plotW,padT+plotH);x.stroke();
  x.font='10px monospace';x.textAlign='right';x.textBaseline='middle';x.fillStyle='#8393ab';
  x.fillText(String(mx),padL-6,padT+4);
  x.fillText('0',padL-6,padT+plotH);
  x.fillStyle='#3fbfb0';
  series.forEach((s,i)=>{
    const h=s.count/mx*plotH,bx=padL+i*barW+1,by=padT+plotH-h;
    x.fillRect(bx,by,Math.max(1,barW-2),h);
  });
  x.textAlign='center';x.textBaseline='top';x.fillStyle='#8393ab';
  [0,Math.floor(series.length/2),series.length-1].forEach(i=>{
    const label=series[i].date.toLocaleDateString([],{month:'short',day:'numeric'});
    x.fillText(label,padL+i*barW+barW/2,padT+plotH+4);
  });
}
function openTag(sensor,key){const t=currentTags().find(x=>x.SensorID===sensor&&(x.Key||[x.DeviceIP,x.DevicePort,x.Protocol,x.AddressSpace,x.Address].join('|'))===key);if(!t)return;const h=(Array.isArray(changes)?changes:[]).filter(x=>x.SensorID===sensor&&x.TagKey===key).sort((a,b)=>new Date(a.Timestamp)-new Date(b.Timestamp)),ev=(Array.isArray(events)?events:[]).filter(x=>x.SensorID===sensor&&x.TagKey===key);document.getElementById('tag-modal-title').textContent=`${t.Protocol} ${t.DeviceIP} — ${t.AddressSpace} ${t.Address}`;document.getElementById('tag-modal-details').innerHTML=`<p>Current: <b>${esc(val(t.LastValue))}</b> · Previous: ${esc(val(t.PreviousValue))} · learned range: ${esc(val(t.MinValue))} … ${esc(val(t.MaxValue))}</p>`;document.getElementById('tag-history').innerHTML=h.length?h.slice().reverse().map(x=>`<div>${time(x.Timestamp)}: ${esc(val(x.OldValue))} → <b>${esc(val(x.NewValue))}</b></div>`).join(''):'No changes';document.getElementById('tag-events').innerHTML=ev.length?ev.slice().reverse().map(x=>`<div>${time(x.Timestamp)}: ${esc(x.FunctionName)} ${esc(x.SrcIP)} → ${esc(x.DstIP)}</div>`).join(''):'No control events';document.getElementById('tag-modal').hidden=false;drawChart(h)}document.getElementById('tag-modal-close').onclick=()=>document.getElementById('tag-modal').hidden=true;
const selectedAlerts=new Set();
function updateAlertBulkBar(){const count=selectedAlerts.size;document.getElementById('alerts-approve').hidden=!count;document.getElementById('alerts-confirm').hidden=!count;document.getElementById('alerts-selection-count').textContent=count?`${count} selected`:'';const selectable=alerts.filter(a=>(a.Status||'new')==='new');const all=document.getElementById('alerts-all');all.checked=selectable.length>0&&selectable.every(a=>selectedAlerts.has(`${a.SensorID}::${a.ID}`));all.indeterminate=selectable.some(a=>selectedAlerts.has(`${a.SensorID}::${a.ID}`))&&!all.checked}
function renderAlerts(){const valid=new Set(alerts.filter(a=>(a.Status||'new')==='new').map(a=>`${a.SensorID}::${a.ID}`));for(const key of [...selectedAlerts])if(!valid.has(key))selectedAlerts.delete(key);document.querySelector('#table-alerts tbody').innerHTML=alerts.map((a,i)=>{const key=`${a.SensorID}::${a.ID}`,status=(a.Status||'new'),isNew=status==='new';return `<tr class="alert-row alert-status-${esc(status)}" data-index="${i}"><td>${isNew?`<input type="checkbox" class="alert-select" data-key="${esc(key)}" ${selectedAlerts.has(key)?'checked':''} aria-label="Select alert ${esc(a.ID)}">`:'—'}</td><td>${esc(a.SensorID)}</td><td><span class="severity ${esc(a.Severity)}">${esc(a.Severity)}</span></td><td>${esc(a.Type)}</td><td>${esc(a.Message)}</td><td>${esc(a.IP)}</td><td>${esc(a.Count)}</td><td>${esc(a.Status)}</td><td>${time(a.LastSeen)}</td></tr>`}).join('');const n=alerts.filter(a=>(a.Status||'new')==='new').length;document.getElementById('alert-badge').textContent=n?String(n):'';updateAlertBulkBar()}
function objectRows(obj){return Object.entries(obj||{}).filter(([,v])=>v!==undefined&&v!==null&&v!=='').map(([k,v])=>`<div><dt>${esc(k.replace(/_/g,' '))}</dt><dd>${esc(typeof v==='object'?JSON.stringify(v,null,2):v)}</dd></div>`).join('')}
function openAlertDetail(index){const a=alerts[index];if(!a)return;document.getElementById('alert-detail-title').textContent=`Alert · ${a.Type||'unknown'}`;document.getElementById('alert-detail-body').innerHTML=`<dl class="status-list detail-status-list"><div><dt>Sensor</dt><dd>${esc(a.SensorID)}</dd></div><div><dt>Alert key</dt><dd class="wrap-anywhere">${esc(a.AlertKey||a.ID||'—')}</dd></div><div><dt>Severity</dt><dd><span class="severity ${esc(a.Severity)}">${esc(a.Severity)}</span></dd></div><div><dt>Status</dt><dd>${esc(a.Status||'new')}</dd></div><div><dt>IP</dt><dd>${esc(a.IP||'—')}</dd></div><div><dt>Occurrences</dt><dd>${esc(a.Count||1)}</dd></div><div><dt>First seen</dt><dd>${time(a.FirstSeen)}</dd></div><div><dt>Last seen</dt><dd>${time(a.LastSeen)}</dd></div>${a.ApprovedBy?`<div><dt>Reviewed by</dt><dd>${esc(a.ApprovedBy)}</dd></div>`:''}</dl><h3>Message</h3><div class="detail-message">${esc(a.Message||'—')}</div>${a.Evidence&&Object.keys(a.Evidence).length?`<h3>Structured evidence</h3><dl class="status-list detail-status-list">${objectRows(a.Evidence)}</dl>`:''}`;document.getElementById('alert-detail-modal').hidden=false}
document.querySelector('#table-alerts tbody').addEventListener('click',e=>{if(e.target.closest('input,button'))return;const row=e.target.closest('.alert-row');if(row)openAlertDetail(Number(row.dataset.index))});document.getElementById('alert-detail-close').onclick=()=>document.getElementById('alert-detail-modal').hidden=true;
function splitCSV(v){return String(v||'').split(',').map(x=>x.trim()).filter(Boolean)}
