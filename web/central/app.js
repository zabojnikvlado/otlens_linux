const POLL=10000;let graph={Nodes:[],Edges:[]},assets=[],devices=[],vulnerabilities=[],tags=[],alerts=[],rules=[],sensors=[],baselines=[],changes=[],events=[],analysisJobs=[],backups=[],settings={},users=[],roles=[],audit=[],incidents=[],assetSecurity=[],dnsObservations=[],smbObservations=[],threatIntelSources=[],threatIntelIndicators=[],reports=[],sensorMetrics=[],healthcheckData=null,trends={AlertsByDay:[],NewAssetsByDay:[]};let network,nodesDS,edgesDS;let topologyColourMode='class',purdueTopologyData=null;const topologyPositionCache=new Map();const selected=new Set();
// Auth state — populated from GET /v1/me on boot and again right after
// login. permissions.view drives which nav tabs are shown (server-side
// requireView enforces the same thing, this just reflects it in the UI);
// permissions.actions drives which buttons render as active via can().
let currentUser=null,currentRole=null,permissions={view:[],actions:[]};
let pollTimer=null;
function can(action){return permissions.actions.includes(action)}
function canView(tab){return permissions.view.includes(tab)}
// Signature caches for the Topology tab: as long as a node/edge's visible
// properties are byte-identical to what's already drawn, we skip calling
// vis-network's update() on it entirely. Redrawing something that hasn't
// changed in the database is exactly the wasted work that made large
// graphs feel slow — this makes "unchanged" a no-op instead of a re-render.
const topologyNodeSigCache=new Map(),topologyEdgeSigCache=new Map();
const nodeSignature=n=>`${n.label}|${n.title}|${n.color.background}|${n.color.border}|${n.size}|${n.font.size}`;
const edgeSignature=e=>`${e.label}|${e.title}|${e.color.color}|${e.color.opacity}|${e.width}|${e.dashes}|${e.arrows||''}|${e.font.size}`;
let topologyETag=null;
async function fetchTopology(){
  const h={};if(topologyETag)h['If-None-Match']=topologyETag;
  let r;try{r=await fetch('/v1/topology',{headers:h,credentials:'include'})}catch(cause){const e=new Error('network error');e.kind='network';e.cause=cause;throw e}
  if(r.status===304)return{unchanged:true};
  if(!r.ok){const body=await r.text();const e=new Error(r.status+' '+body);e.status=r.status;e.body=body;throw e}
  topologyETag=r.headers.get('ETag')||topologyETag;
  const value=await r.json();
  console.log(`Topology fetch: ${(value.Nodes||[]).length} nodes, ${(value.Edges||[]).length} edges, ETag=${topologyETag}`);
  return{unchanged:false,value};
}
const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));const val=v=>typeof v==='object'?JSON.stringify(v):v??'—';const time=v=>v?new Date(v).toLocaleString():'—';
async function api(path,opt={}){const isFormData=typeof FormData!=='undefined'&&opt.body instanceof FormData;const h=isFormData?{...(opt.headers||{})}:{'Content-Type':'application/json',...(opt.headers||{})};let r;try{r=await fetch('/v1'+path,{...opt,headers:h,credentials:'include'})}catch(cause){const e=new Error('network error');e.kind='network';e.cause=cause;throw e}if(!r.ok){const body=await r.text();const e=new Error(r.status+' '+body);e.status=r.status;e.body=body;try{e.parsed=JSON.parse(body)}catch(_){}throw e}return r.status===204||r.status===202?null:r.json()}
function setConn(ok,t){document.getElementById('conn-dot').className='dot '+(ok?'ok':'down');document.getElementById('conn-text').textContent=t}
document.querySelector('.tabs').onclick=e=>{const b=e.target.closest('.tab');if(!b)return;const enteringTopology=b.dataset.tab==='topology'&&!document.getElementById('view-topology').classList.contains('active');const enteringSegmentation=b.dataset.tab==='segmentation'&&!document.getElementById('view-segmentation').classList.contains('active');const enteringPurdue=b.dataset.tab==='purdue'&&!document.getElementById('view-purdue').classList.contains('active');document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.getElementById('view-'+b.dataset.tab).classList.add('active');if(b.dataset.tab==='topology'&&network)setTimeout(()=>network.redraw(),30);if(enteringTopology)refreshAll();if(enteringPurdue)loadPurdueArchitecture();if(enteringSegmentation)loadSegmentation();if(b.dataset.tab==='dns')loadDNS();if(b.dataset.tab==='smb')loadSMB();if(b.dataset.tab==='threatintel')loadThreatIntelManagement();if(b.dataset.tab==='health')loadHealthcheck()};
const PURDUE_COLORS={'5':['#475569','#94a3b8'],'4':['#2563eb','#60a5fa'],'3.5':['#7c3aed','#a78bfa'],'3':['#0891b2','#22d3ee'],'2':['#d97706','#fbbf24'],'1':['#16a34a','#4ade80'],'0':['#dc2626','#fb7185'],'?':['#64748b','#94a3b8']};
function nodePurdueLevel(n){const v=n.PurdueLevel??n.purdue_level??n.PurdueOverride;return v==null?'?':String(v)}
function node(n){const threshold=Number(n.HoneypotThreshold??graph.HoneypotThreshold??100),score=Number(n.Score??1),honey=n.IsHoneypot===true||score>=threshold,bad=n.Confirmed===false,level=nodePurdueLevel(n),pc=PURDUE_COLORS[level]||PURDUE_COLORS['?'],base=topologyColourMode==='purdue'?{background:pc[0],border:pc[1]}:{background:n.IsOT?'#3fbfb0':'#64748b',border:n.IsOT?'#2a7d74':'#334155'};return{id:n.ID,label:n.Hostname||n.IP||n.MAC,title:`Sensor: ${n.SensorID}
IP: ${n.IP}
MAC: ${n.MAC}
Vendor: ${n.Vendor||'—'}
Purdue: ${level==='?'?'Unclassified':'Level '+level}
Deception score: ${score}/100${honey?' (honeypot)':''}
Protocols: ${(n.Protocols||[]).join(', ')||'—'}`,font:{color:'#ffffff',strokeWidth:2,strokeColor:'#0b1220'},color:honey?{background:'#a855f7',border:'#7c3aed'}:bad?{background:'#e85d4c',border:'#ff9f95'}:base,size:honey?24:n.IsOT?22:16,_search:`${n.IP} ${n.MAC} ${n.Hostname} ${n.SensorID}`.toLowerCase(),_vlan:Number(n.VLANID||0),_purdue:level}}
function topologyHash(value){
  let h=2166136261;
  for(const ch of String(value)){h^=ch.charCodeAt(0);h=Math.imul(h,16777619)}
  return h>>>0;
}
function rememberTopologyPositions(){
  if(!network||!nodesDS)return;
  const positions=network.getPositions(nodesDS.getIds());
  Object.entries(positions).forEach(([id,p])=>topologyPositionCache.set(id,{x:p.x,y:p.y}));
}
function positionNewTopologyNodes(newIds,edges){
  if(!network||!newIds.length)return;
  rememberTopologyPositions();
  const neighbours=new Map();
  for(const edge of edges){
    if(!neighbours.has(edge.from))neighbours.set(edge.from,[]);
    if(!neighbours.has(edge.to))neighbours.set(edge.to,[]);
    neighbours.get(edge.from).push(edge.to);
    neighbours.get(edge.to).push(edge.from);
  }
  const existingPositions=network.getPositions(nodesDS.getIds());
  const updates=[];
  const total=Math.max(nodesDS.length,1);
  const fallbackRadius=Math.max(260,Math.sqrt(total)*70);
  newIds.forEach((id,index)=>{
    const linked=(neighbours.get(id)||[]).map(n=>existingPositions[n]||topologyPositionCache.get(n)).filter(Boolean);
    const hash=topologyHash(id),angle=(hash%360)*Math.PI/180;
    let x,y;
    if(linked.length){
      const centre=linked.reduce((a,p)=>({x:a.x+p.x,y:a.y+p.y}),{x:0,y:0});
      centre.x/=linked.length;centre.y/=linked.length;
      const radius=90+(hash%70);
      x=centre.x+Math.cos(angle)*radius;
      y=centre.y+Math.sin(angle)*radius;
    }else{
      const ring=Math.floor(index/18)+1;
      const radius=fallbackRadius+ring*100;
      x=Math.cos(angle)*radius;y=Math.sin(angle)*radius;
    }
    topologyPositionCache.set(id,{x,y});
    updates.push({id,x,y,fixed:{x:false,y:false}});
  });
  nodesDS.update(updates);
  network.redraw();
}
function renderTopology(){
  const rawNodes=graph.Nodes||[],rawEdges=graph.Edges||[],dense=rawNodes.length>80||rawEdges.length>160;
  // vis.DataSet throws on any duplicate id rather than just ignoring the
  // repeat — one bad record would otherwise take the whole tab down. Central
  // shouldn't ever send duplicates (see buildTopologyResponse's own
  // dedup), but this is a cheap, harmless safety net either way: keeps
  // the first occurrence, drops the rest.
  const dedupeById=arr=>{const seen=new Set();return arr.filter(x=>seen.has(x.id)?false:(seen.add(x.id),true))};
  const ns=dedupeById(rawNodes.map(n=>{
    const item=node(n),cached=topologyPositionCache.get(item.id);
    if(cached){item.x=cached.x;item.y=cached.y}
    if(dense&&!n.IsHoneypot&&n.Confirmed!==false)item.font={...item.font,size:11};
    return item;
  })),
        ip=new Map(rawNodes.map(n=>[n.SensorID+'::'+n.IP,n.ID])),
        nodeByIP=new Map(rawNodes.map(n=>[n.SensorID+'::'+n.IP,n]));
  const mappedEdges=rawEdges.map(e=>{
    const src=nodeByIP.get(e.SensorID+'::'+e.SrcIP),dst=nodeByIP.get(e.SensorID+'::'+e.DstIP),
          interVlan=!!src&&!!dst&&Number(src.VLANID||0)!==Number(dst.VLANID||0),lateral=!!e.FromHoneypot,
          label=lateral?'POTENTIAL LATERAL MOVEMENT':interVlan?`VLAN ${src.VLANID||'untagged'} → ${dst.VLANID||'untagged'}`:(!dense&&e.IsOT?e.Protocol:'');
    const flowNote=e.FlowCount>1?` (${e.FlowCount} flows aggregated, ${e.Packets||0} pkts)`:'';
    return{id:e.ID,from:ip.get(e.SensorID+'::'+e.SrcIP),to:ip.get(e.SensorID+'::'+e.DstIP),_srcIP:e.SrcIP,_dstIP:e.DstIP,_sensorID:e.SensorID,label,title:(lateral?`Potential lateral movement: honeypot ${e.SrcIP} initiated communication to ${e.DstIP}`:interVlan?'Inter-VLAN communication':e.Protocol)+flowNote,font:{color:lateral?'#ff9f95':interVlan?'#fbbf24':'#d7e1ec',strokeWidth:2,strokeColor:'#0b1220',size:dense?10:14},color:{color:lateral?'#ef4444':interVlan?'#f59e0b':e.IsOT?'#5fd1c4':'#94a3b8',opacity:dense&&!lateral&&!interVlan?.55:1},dashes:lateral?false:interVlan?[10,6]:false,width:lateral?5:interVlan?3:e.IsOT?2:1,arrows:lateral?'to':undefined,smooth:false}
  });
  const unresolvedEdges=mappedEdges.filter(e=>e.from==null||e.to==null);
  if(unresolvedEdges.length)console.warn(`Topology: ${unresolvedEdges.length} edge(s) from Central couldn't be attached to a node this poll (endpoint asset missing from the response's node list) — these are what "flicker" if it's not consistent poll-to-poll:`,unresolvedEdges.map(e=>({id:e.id,sensor:e._sensorID,srcIP:e._srcIP,dstIP:e._dstIP,srcResolved:e.from!=null,dstResolved:e.to!=null})));
  const es=dedupeById(mappedEdges.filter(e=>e.from!=null&&e.to!=null));
  if(!network){
    ns.forEach(n=>topologyNodeSigCache.set(n.id,nodeSignature(n)));
    es.forEach(e=>topologyEdgeSigCache.set(e.id,edgeSignature(e)));
    nodesDS=new vis.DataSet(ns);edgesDS=new vis.DataSet(es);
    network=new vis.Network(document.getElementById('graph'),{nodes:nodesDS,edges:edgesDS},{
      nodes:{shape:'dot',borderWidth:2},edges:{smooth:false,selectionWidth:1.5,hoverWidth:1.5},
      physics:{enabled:true,solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:dense?-70:-115,centralGravity:.015,springLength:dense?115:155,springConstant:.055,damping:.72,avoidOverlap:1},minVelocity:.75,maxVelocity:22,timestep:.35,adaptiveTimestep:true,stabilization:{enabled:true,iterations:dense?500:320,updateInterval:40,fit:true}},
      interaction:{hover:true,hideEdgesOnDrag:true,hideEdgesOnZoom:dense,multiselect:true},layout:{improvedLayout:true}
    });
    network.once('stabilized',()=>{
      rememberTopologyPositions();
      network.setOptions({physics:{enabled:false}});
    });
    network.on('dragEnd',params=>{
      const ids=params.nodes&&params.nodes.length?params.nodes:nodesDS.getIds();
      const positions=network.getPositions(ids);
      Object.entries(positions).forEach(([id,p])=>topologyPositionCache.set(id,{x:p.x,y:p.y}));
    });
  }else{
    const oldIds=new Set(nodesDS.getIds()),nextIds=new Set(ns.map(n=>n.id));
    const newIds=ns.filter(n=>!oldIds.has(n.id)).map(n=>n.id);
    const removedNodeIds=nodesDS.getIds().filter(id=>!nextIds.has(id));
    if(removedNodeIds.length)console.warn(`Topology: removing ${removedNodeIds.length} node(s) no longer in the response:`,removedNodeIds);
    removedNodeIds.forEach(id=>{nodesDS.remove(id);topologyPositionCache.delete(id);topologyNodeSigCache.delete(id)});
    // Only push nodes whose visible properties actually changed (or are
    // brand new). An asset that's sitting there unchanged in the database
    // between polls costs nothing here — same principle as the edge diff
    // below, and the same reasoning as the backend's fingerprint cache.
    const changedNodes=ns.filter(n=>{const sig=nodeSignature(n),same=topologyNodeSigCache.get(n.id)===sig;topologyNodeSigCache.set(n.id,sig);return!same});
    if(changedNodes.length)nodesDS.update(changedNodes);
    const edgeIds=new Set(es.map(e=>e.id));
    const removedEdgeIds=edgesDS.getIds().filter(id=>!edgeIds.has(id));
    if(removedEdgeIds.length)console.warn(`Topology: removing ${removedEdgeIds.length} edge(s) no longer in the response (had ${edgesDS.length}, response now has ${es.length}):`,removedEdgeIds);
    removedEdgeIds.forEach(id=>{edgesDS.remove(id);topologyEdgeSigCache.delete(id)});
    // This is the "draw a connection once, then leave it alone while it's
    // unchanged in the database" behavior: a conversation between two
    // assets that Central already knows about, with the same OT/VLAN/
    // lateral-movement state as before, is never re-submitted to
    // vis-network — only genuinely new or changed edges are.
    const changedEdges=es.filter(e=>{const sig=edgeSignature(e),same=topologyEdgeSigCache.get(e.id)===sig;topologyEdgeSigCache.set(e.id,sig);return!same});
    if(changedEdges.length)edgesDS.update(changedEdges);
    network.setOptions({physics:{enabled:false},interaction:{hideEdgesOnZoom:dense}});
    positionNewTopologyNodes(newIds,es);
    rememberTopologyPositions();
  }
  renderVlanFilter();
  applyVlanFilter();
  applySearch();
}
function applySearch(){if(!network)return;const q=document.getElementById('topology-search-input').value.trim().toLowerCase();document.getElementById('topology-search-clear').hidden=!q;if(!q){network.unselectAll();document.getElementById('topology-search-status').textContent='';return}const ids=nodesDS.get().filter(n=>n._search.includes(q)).map(n=>n.id);network.selectNodes(ids);document.getElementById('topology-search-status').textContent=ids.length+' match(es)';if(ids.length===1)network.focus(ids[0],{scale:1.2,animation:true})}
// VLAN filter — hiddenVlans holds the VLAN ids currently toggled OFF.
// Empty set means "show everything" (the default). Persists across
// polls/re-renders the same way topologyPositionCache does, so a filter
// choice doesn't reset itself every 10s.
const hiddenVlans=new Set();
function vlanLabel(v){return v===0?'Untagged':'VLAN '+v}
function renderVlanFilter(){
  if(!nodesDS)return;
  const present=[...new Set(nodesDS.get().map(n=>n._vlan??0))].sort((a,b)=>a-b);
  const list=document.getElementById('vlan-filter-list');
  if(!present.length){list.innerHTML='';return}
  list.innerHTML=present.map(v=>{
    const off=hiddenVlans.has(v);
    return `<label class="vlan-chip ${off?'off':''}" data-vlan="${v}"><input type="checkbox" ${off?'':'checked'}> ${esc(vlanLabel(v))}</label>`;
  }).join('');
}
function applyVlanFilter(){
  if(!nodesDS)return;
  const updates=nodesDS.get().filter(n=>Boolean(n.hidden)!==hiddenVlans.has(n._vlan??0)).map(n=>({id:n.id,hidden:hiddenVlans.has(n._vlan??0)}));
  if(updates.length)nodesDS.update(updates);
}
document.getElementById('vlan-filter-list').addEventListener('click',e=>{
  const chip=e.target.closest('.vlan-chip');
  if(!chip)return;
  e.preventDefault();
  const v=Number(chip.dataset.vlan);
  if(hiddenVlans.has(v))hiddenVlans.delete(v);else hiddenVlans.add(v);
  chip.classList.toggle('off',hiddenVlans.has(v));
  chip.querySelector('input').checked=!hiddenVlans.has(v);
  applyVlanFilter();
});
document.getElementById('vlan-filter-all').onclick=()=>{hiddenVlans.clear();renderVlanFilter();applyVlanFilter()};
document.getElementById('vlan-filter-none').onclick=()=>{if(!nodesDS)return;nodesDS.get().forEach(n=>hiddenVlans.add(n._vlan??0));renderVlanFilter();applyVlanFilter()};
document.getElementById('topology-search-input').oninput=applySearch;document.getElementById('topology-search-clear').onclick=()=>{document.getElementById('topology-search-input').value='';applySearch()};
function renderAssets(){const q=document.getElementById('assets-filter').value.toLowerCase(),data=assets.filter(a=>JSON.stringify(a).toLowerCase().includes(q));document.getElementById('assets-count').textContent=data.length+' assets';document.querySelector('#table-assets tbody').innerHTML=data.map(a=>`<tr class="asset-row ${a.Confirmed===false?'row-unconfirmed':''}" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" data-vendor="${esc(a.Vendor||'')}" data-ip="${esc(a.IP||'')}"><td><input class="asset-check" type="checkbox" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" ${selected.has(a.SensorID+'::'+a.MAC)?'checked':''}></td><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Vendor)}</td><td>${esc(a.Hostname)}</td><td class="${a.Confirmed===false?'state-new':'state-ok'}">${a.Confirmed===false?'NEW / UNCONFIRMED':'confirmed'}</td><td>${a.IsOT?'OT':'IT'}</td><td>${esc((a.Protocols||[]).join(', '))}</td><td>${esc(a.VLANID||'untagged')}</td><td>${esc(a.Score??1)}</td><td>${(a.IsHoneypot===true||Number(a.Score??1)>=Number(a.HoneypotThreshold??100))?'<span class="pill honeypot">HONEYPOT</span>':Number(a.Score??1)>=75?'<span class="pill severity-high">CRITICAL</span>':Number(a.Score??1)>=40?'<span class="pill severity-medium">ELEVATED</span>':'standard'}</td><td>${esc(a.PacketCount)}</td><td>${time(a.LastSeen)}</td><td>${(()=>{const x=assetSecurity.find(v=>v.sensor_id===a.SensorID&&v.asset_ip===a.IP);return x?`<span class="pill severity-${x.status==='infected'?'high':x.status==='suspected'?'medium':'low'}">${esc(x.status.toUpperCase())}</span>`:'clean/unknown'})()}</td><td>${can('asset_confirm_delete')?`<button class="danger-btn infect-one" data-sensor="${esc(a.SensorID)}" data-ip="${esc(a.IP)}">Tag infection</button> `:''}${a.Confirmed===false&&can('asset_confirm_delete')?`<button class="ack-btn confirm-one" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}">Confirm</button>`:a.Confirmed===false?'pending':'—'}</td></tr>`).join('');updateBulk()}
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
  document.querySelector('#table-vulnerabilities tbody').innerHTML=data.map((v,i)=>`<tr class="vuln-row" data-index="${data.indexOf(v)}"><td>${esc(v.CVEID)}</td><td><span class="severity ${esc(String(v.Severity||'').toLowerCase())}">${esc(v.Severity||'—')}</span></td><td>${esc(v.Vendor)}</td><td>${esc(v.Product||'—')}</td><td>${esc(v.Title)}</td><td>${esc(v.PublishedDate||'—')}</td><td>${esc(v.AffectedCount||0)}</td></tr>`).join('');
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
    ${assetsList.length?`<table class="data-table"><thead><tr><th>Sensor</th><th>IP</th><th>MAC</th><th>Hostname</th></tr></thead><tbody>${assetsList.map(a=>`<tr><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Hostname||'—')}</td></tr>`).join('')}</tbody></table>`:'<div class="empty-dashboard">No currently-known assets from this vendor.</div>'}`;
  document.getElementById('vuln-modal').hidden=false;
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

document.getElementById('assets-filter').oninput=renderAssets;document.querySelector('#table-assets tbody').onclick=e=>{const c=e.target.closest('.asset-check');if(c){const k=c.dataset.sensor+'::'+c.dataset.mac;c.checked?selected.add(k):selected.delete(k);updateBulk();return}const inf=e.target.closest('.infect-one');if(inf){tagAssetInfected(inf.dataset.sensor,inf.dataset.ip);return}const b=e.target.closest('.confirm-one');if(b){sendAssetAction('confirm',[b.dataset.sensor+'::'+b.dataset.mac]);return}const row=e.target.closest('.asset-row');if(!row)return;const a=(assets||[]).find(x=>x.SensorID===row.dataset.sensor&&x.IP===row.dataset.ip);if(a)openAssetDetail(a)};document.getElementById('assets-all').onchange=e=>{assets.forEach(a=>e.target.checked?selected.add(a.SensorID+'::'+a.MAC):selected.delete(a.SensorID+'::'+a.MAC));renderAssets()};
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
    const hist=await api(`/sensors/${encodeURIComponent(sensor)}/assets/${encodeURIComponent(mac)}/ip-history`);
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
function renderIncidents(){
  const tbody=document.querySelector('#table-incidents tbody');if(!tbody)return;
  tbody.innerHTML=incidents.map((inc,i)=>`<tr class="incident-row" data-index="${i}"><td>${esc(inc.SensorID)}</td><td>${esc(inc.IP)}</td><td><span class="severity ${esc(inc.Severity)}">${esc(inc.Severity)}</span></td><td>${esc((inc.Types||[]).join(', '))}</td><td>${esc(inc.AlertCount)}</td><td>${time(inc.FirstSeen)}</td><td>${time(inc.LastSeen)}</td></tr>`).join('');
}
async function openIncident(index){
  const inc=incidents[index];if(!inc)return;
  const related=alerts.filter(a=>a.SensorID===inc.SensorID&&a.IP===inc.IP).sort((a,b)=>new Date(a.LastSeen)-new Date(b.LastSeen));
  let dns=[],smb=[];try{[dns,smb]=await Promise.all([api(`/dns-observations?sensor_id=${encodeURIComponent(inc.SensorID)}&client_ip=${encodeURIComponent(inc.IP)}&limit=100`),api(`/smb-observations?sensor_id=${encodeURIComponent(inc.SensorID)}&client_ip=${encodeURIComponent(inc.IP)}&limit=100`)])}catch(e){console.warn('incident evidence',e)}
  document.getElementById('incident-modal-title').textContent=`Incident · ${inc.IP}`;
  const timeline=[...related.map(a=>({at:a.LastSeen,kind:a.Type,text:a.Message,severity:a.Severity})),...dns.map(d=>({at:d.observed_at,kind:'DNS',text:`${d.query_name} → ${jsonList(d.answers).join(', ')||'no answer'}`,severity:threatForDNS(d)?'high':'info'})),...smb.map(x=>({at:x.Timestamp,kind:'SMB',text:`${x.Command} ${x.ShareName||''} ${x.FileName||x.NamedPipe||''}`.trim(),severity:smbRisk(x)?'high':'info'}))].sort((a,b)=>new Date(a.at)-new Date(b.at));
  document.getElementById('incident-modal-body').innerHTML=`<div class="detail-grid"><section><h3>Summary</h3><dl class="status-list"><div><dt>Sensor</dt><dd>${esc(inc.SensorID)}</dd></div><div><dt>Severity</dt><dd>${esc(inc.Severity)}</dd></div><div><dt>Alert types</dt><dd>${esc((inc.Types||[]).join(', '))}</dd></div><div><dt>Window</dt><dd>${time(inc.FirstSeen)} — ${time(inc.LastSeen)}</dd></div></dl></section><section><h3>Related evidence</h3><p>${related.length} alerts · ${dns.length} DNS observations · ${smb.length} SMB observations</p></section></div><h3>Timeline</h3><div class="incident-timeline">${timeline.length?timeline.map(x=>`<div class="timeline-item"><time>${time(x.at)}</time><span class="severity ${esc(x.severity)}">${esc(x.kind)}</span><div>${esc(x.text)}</div></div>`).join(''):'<div class="empty-dashboard">No related evidence found.</div>'}</div>`;
  document.getElementById('incident-modal').hidden=false;
}
document.querySelector('#table-incidents tbody').onclick=e=>{const r=e.target.closest('.incident-row');if(r)openIncident(Number(r.dataset.index))};
document.getElementById('incident-modal-close').onclick=()=>document.getElementById('incident-modal').hidden=true;
function jsonList(v){if(Array.isArray(v))return v;try{return JSON.parse(v||'[]')}catch(_){return[]}}
function threatForDNS(d){const q=String(d.query_name||'').toLowerCase();return alerts.some(a=>['malicious_domain','c2_correlated'].includes(String(a.Type))&&(String(a.Message||'').toLowerCase().includes(q)||a.IP===d.client_ip))}
function smbRisk(x){return !!(x.IsAdminShare||x.IsExecutable||x.IsScript||x.NamedPipe||x.is_admin_share||x.is_executable||x.is_script||x.named_pipe)}
async function loadDNS(){try{dnsObservations=await api('/dns-observations?limit=1000');renderDNS()}catch(e){console.error('dns observations',e)}}
const DNS_TYPES={1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',41:'OPT',64:'SVCB',65:'HTTPS'},DNS_RCODES={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'};
function dnsType(v){return DNS_TYPES[Number(v)]||String(v||'—')}function dnsRcode(v){return DNS_RCODES[Number(v)]||String(v??'—')}
function renderDNS(){const sel=document.getElementById('dns-sensor');if(sel){const current=sel.value,ids=[...new Set(dnsObservations.map(d=>d.sensor_id).filter(Boolean))].sort();sel.innerHTML='<option value="">All sensors</option>'+ids.map(id=>`<option value="${esc(id)}">${esc(id)}</option>`).join('');sel.value=ids.includes(current)?current:''}const q=(document.getElementById('dns-filter')?.value||'').toLowerCase(),sensor=sel?.value||'';const rows=dnsObservations.filter(d=>(!sensor||d.sensor_id===sensor)&&(!q||JSON.stringify(d).toLowerCase().includes(q)));document.getElementById('dns-count').textContent=`${rows.length} observations`;document.querySelector('#table-dns tbody').innerHTML=rows.map(d=>`<tr class="dns-row ${threatForDNS(d)?'row-threat':''}" data-id="${esc(d.id)}"><td>${time(d.observed_at)}</td><td>${esc(d.sensor_id)}</td><td>${esc(d.client_ip)}</td><td>${esc(d.server_ip)}</td><td>${esc(d.query_name)}</td><td>${esc(dnsType(d.query_type))}</td><td>${esc(dnsRcode(d.response_code))}</td><td>${esc(jsonList(d.answers).join(', ')||'—')}</td><td>${esc(d.ttl)}</td><td>${threatForDNS(d)?'<span class="pill severity-high">MATCH</span>':'—'}</td></tr>`).join('')}
function openDNSDetail(id){const d=dnsObservations.find(x=>String(x.id)===String(id));if(!d)return;const answers=jsonList(d.answers),cnames=jsonList(d.cnames),related=alerts.filter(a=>String(a.SensorID)===String(d.sensor_id)&&(String(a.IP||'')===String(d.client_ip)||String(a.Message||'').toLowerCase().includes(String(d.query_name||'').toLowerCase())));document.getElementById('dns-detail-title').textContent=`DNS · ${d.query_name}`;document.getElementById('dns-detail-body').innerHTML=`<dl class="status-list detail-status-list"><div><dt>Observed</dt><dd>${time(d.observed_at)}</dd></div><div><dt>Sensor</dt><dd>${esc(d.sensor_id)}</dd></div><div><dt>Direction</dt><dd>${d.is_response?'Response':'Query'}</dd></div><div><dt>Client</dt><dd>${esc(d.client_ip)}</dd></div><div><dt>Resolver</dt><dd>${esc(d.server_ip)}</dd></div><div><dt>Query</dt><dd class="wrap-anywhere">${esc(d.query_name)}</dd></div><div><dt>Record type</dt><dd>${esc(dnsType(d.query_type))} (${esc(d.query_type)})</dd></div><div><dt>Response code</dt><dd>${esc(dnsRcode(d.response_code))} (${esc(d.response_code)})</dd></div><div><dt>TTL</dt><dd>${esc(d.ttl)} seconds${Number(d.ttl)>0?` · expires approximately ${time(new Date(new Date(d.observed_at).getTime()+Number(d.ttl)*1000))}`:''}</dd></div><div><dt>Threat correlation</dt><dd>${threatForDNS(d)?'<span class="pill severity-high">MATCH</span>':'None'}</dd></div></dl><div class="detail-grid"><section><h3>Answers (${answers.length})</h3><div class="detail-list">${answers.map(esc).join('<br>')||'—'}</div></section><section><h3>CNAME chain (${cnames.length})</h3><div class="detail-list">${cnames.map(esc).join('<br>')||'—'}</div></section></div><h3>Related alerts (${related.length})</h3><div class="detail-list">${related.slice(0,20).map(a=>`${time(a.LastSeen)} · ${esc(a.Type)} · ${esc(a.Message)}`).join('<br>')||'No related alerts.'}</div>`;document.getElementById('dns-detail-modal').hidden=false}
document.querySelector('#table-dns tbody').addEventListener('click',e=>{const row=e.target.closest('.dns-row');if(row)openDNSDetail(row.dataset.id)});document.getElementById('dns-detail-close').onclick=()=>document.getElementById('dns-detail-modal').hidden=true;
async function loadSMB(){try{smbObservations=await api('/smb-observations?limit=1000');renderSMB()}catch(e){console.error('smb observations',e)}}
function renderSMB(){const q=(document.getElementById('smb-filter')?.value||'').toLowerCase(),mode=document.getElementById('smb-risk')?.value||'';const rows=smbObservations.filter(x=>(!q||JSON.stringify(x).toLowerCase().includes(q))&&(!mode||(mode==='risk'&&smbRisk(x))||(mode==='encrypted'&&(x.IsEncrypted||x.is_encrypted))));document.getElementById('smb-count').textContent=`${rows.length} observations`;document.querySelector('#table-smb tbody').innerHTML=rows.map(x=>{const flags=[(x.IsAdminShare||x.is_admin_share)?'ADMIN SHARE':'',(x.IsExecutable||x.is_executable)?'EXECUTABLE':'',(x.IsScript||x.is_script)?'SCRIPT':'',(x.IsEncrypted||x.is_encrypted)?'ENCRYPTED':''].filter(Boolean);return `<tr class="${smbRisk(x)?'row-threat':''}"><td>${time(x.Timestamp||x.timestamp)}</td><td>${esc(x.sensor_id)}</td><td>${esc(x.ClientIP||x.client_ip)} → ${esc(x.ServerIP||x.server_ip)}</td><td>${esc(x.Command||x.command)}</td><td>${esc(x.ShareName||x.share_name||'—')}</td><td>${esc(x.FileName||x.file_name||x.NamedPipe||x.named_pipe||'—')}</td><td>${esc(x.Bytes||x.bytes||0)}</td><td>${esc(x.Status||x.status||'—')}</td><td>${flags.map(f=>`<span class="pill severity-${f==='ENCRYPTED'?'medium':'high'}">${esc(f)}</span>`).join(' ')||'—'}</td></tr>`}).join('')}
async function loadThreatIntelManagement(){try{const [sources,indicators]=await Promise.all([api('/threat-intel/sources'),api('/threat-intel/indicators?limit=10000')]);threatIntelSources=Array.isArray(sources)?sources:[];threatIntelIndicators=Array.isArray(indicators)?indicators:[];renderThreatIntel()}catch(e){console.error('load threat intel management',e)}}
function renderThreatIntel(){
  const q=(document.getElementById('ti-filter')?.value||'').toLowerCase(),kind=document.getElementById('ti-type')?.value||'';
  const hitKind=kind.startsWith('malicious_')?kind:'';
  const hits=alerts.filter(a=>['malicious_ip','malicious_domain'].includes(String(a.Type))&&(!hitKind||a.Type===hitKind)&&(!q||JSON.stringify(a).toLowerCase().includes(q)));
  const indicators=threatIntelIndicators.filter(i=>(!kind||kind.startsWith('malicious_')||i.type===kind)&&(!q||JSON.stringify(i).toLowerCase().includes(q)));
  document.getElementById('ti-count').textContent=`${indicators.length} indicators · ${hits.length} observed hits`;
  const sourceBody=document.querySelector('#table-ti-sources tbody');if(sourceBody)sourceBody.innerHTML=threatIntelSources.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.source_type)}</td><td class="wrap-anywhere">${esc(x.url||'—')}</td><td>${esc(x.format)}</td><td>${x.enabled?'Yes':'No'}</td><td>${time(x.last_success_at)}</td><td>${esc(x.accepted_count)}</td><td>${esc(x.rejected_count)}</td><td class="wrap-anywhere">${esc(x.last_error||'—')}</td><td>${can('data_management')?`<button class="secondary-btn ti-refresh-source" data-id="${x.id}">Refresh</button> <button class="danger-btn ti-delete-source" data-id="${x.id}">Delete</button>`:'—'}</td></tr>`).join('');
  const indicatorBody=document.querySelector('#table-ti-indicators tbody');if(indicatorBody)indicatorBody.innerHTML=indicators.map(i=>`<tr><td class="wrap-anywhere">${esc(i.value)}</td><td>${esc(i.type)}</td><td>${esc(i.threat_type||'—')}</td><td>${esc(i.confidence)}%</td><td>${esc(i.source_name)}</td><td>${time(i.valid_until)}</td><td>${time(i.last_seen)}</td><td>${can('data_management')?`<button class="danger-btn ti-delete-indicator" data-id="${i.id}">Delete</button>`:'—'}</td></tr>`).join('');
  document.querySelector('#table-ti tbody').innerHTML=hits.map(a=>`<tr><td>${time(a.LastSeen)}</td><td>${esc(a.SensorID)}</td><td><span class="severity ${esc(a.Severity)}">${esc(a.Severity)}</span></td><td>${esc(a.Type)}</td><td>${esc(a.IP)}</td><td>${esc(a.Message)}</td><td>${esc(a.Count)}</td></tr>`).join('')
}


function renderReports(){
  const tbody=document.querySelector('#table-reports tbody');if(!tbody)return;
  tbody.innerHTML=reports.map(r=>{
    const status=r.EmailSent?'Sent':(r.Recipients&&r.Recipients.length?`Failed: ${esc(r.EmailError||'unknown error')}`:'Not emailed (no recipients configured)');
    return `<tr class="report-row" data-id="${esc(r.ID)}"><td>${time(r.GeneratedAt)}</td><td>${time(r.PeriodStart)} – ${time(r.PeriodEnd)}</td><td>${esc((r.Recipients||[]).join(', ')||'—')}</td><td class="${r.EmailSent?'state-ok':''}">${status}</td><td class="report-actions"><button class="secondary-btn report-pdf" data-id="${esc(r.ID)}">PDF</button>${can('data_management')?` <button class="danger-btn report-delete" data-id="${esc(r.ID)}">Delete</button>`:''}</td></tr>`;
  }).join('');
  document.getElementById('reports-generate').hidden=!can('data_management');
}
document.querySelector('#table-reports tbody').addEventListener('click',async e=>{
  const pdf=e.target.closest('.report-pdf');if(pdf){e.stopPropagation();window.location=`/v1/reports/${encodeURIComponent(pdf.dataset.id)}/pdf`;return}
  const del=e.target.closest('.report-delete');if(del){e.stopPropagation();if(!confirm('Delete this report permanently?'))return;try{await api(`/reports/${encodeURIComponent(del.dataset.id)}`,{method:'DELETE'});await refreshAll()}catch(err){alert(`Failed to delete report: ${err.message}`)}return}
  const row=e.target.closest('.report-row');if(!row)return;
  try{
    const rep=await api(`/reports/${encodeURIComponent(row.dataset.id)}`);
    document.getElementById('report-modal-frame').srcdoc=rep.HTML||'';
    document.getElementById('report-modal').hidden=false;
  }catch(err){alert(`Failed to load report: ${err.message}`)}
});
document.getElementById('report-modal-close').onclick=()=>document.getElementById('report-modal').hidden=true;
document.getElementById('reports-generate').onclick=async()=>{
  const btn=document.getElementById('reports-generate');btn.disabled=true;
  try{await api('/reports/generate',{method:'POST'});alert('Report generated.');refreshAll()}
  catch(err){alert(`Report generation failed: ${err.message}`)}
  finally{btn.disabled=false}
};
document.querySelector('#table-alerts tbody').onchange=e=>{const c=e.target.closest('.alert-select');if(!c)return;c.checked?selectedAlerts.add(c.dataset.key):selectedAlerts.delete(c.dataset.key);updateAlertBulkBar()};
document.getElementById('alerts-all').onchange=e=>{for(const a of alerts.filter(a=>(a.Status||'new')==='new')){const key=`${a.SensorID}::${a.ID}`;e.target.checked?selectedAlerts.add(key):selectedAlerts.delete(key)}renderAlerts()};
async function runAlertBulkAction(action){const grouped=new Map();for(const key of selectedAlerts){const split=key.indexOf('::'),sensor=key.slice(0,split),id=key.slice(split+2);if(!grouped.has(sensor))grouped.set(sensor,[]);grouped.get(sensor).push(id)}if(!grouped.size)return;const label=action==='approve'?'approve and remember':'confirm';if(!confirm(`Really ${label} ${selectedAlerts.size} selected alert(s)?`))return;await Promise.all([...grouped].map(([sensor,targets])=>api(`/sensors/${encodeURIComponent(sensor)}/alerts/actions`,{method:'POST',body:JSON.stringify({action,targets})})));selectedAlerts.clear();updateAlertBulkBar();setTimeout(refreshAll,1000)}
document.getElementById('alerts-approve').onclick=()=>runAlertBulkAction('approve');
document.getElementById('alerts-confirm').onclick=()=>runAlertBulkAction('confirm');
const RULE_FIELDS=[['src_ip','Source IP'],['dst_ip','Destination IP'],['either_ip','Source or destination IP'],['src_mac','Source MAC'],['dst_mac','Destination MAC'],['protocol','Protocol'],['src_port','Source port'],['dst_port','Destination port'],['port','Either port'],['vlan','VLAN'],['packet_size','Packet size'],['tcp_flags','TCP flags']];
const RULE_OPERATORS=[['eq','='],['neq','!='],['gt','>'],['gte','>='],['lt','<'],['lte','<='],['contains','contains'],['starts_with','starts with'],['ends_with','ends with'],['between','between'],['in','in list'],['not_in','not in list'],['regex','regex']];
function ruleGroupsOf(r){if(Array.isArray(r.Groups)&&r.Groups.length)return r.Groups;if(r.Field)return [{operator:'AND',conditions:[{field:r.Field,operator:'eq',value:r.Value}]}];return []}
function ruleSummary(r){return ruleGroupsOf(r).map(g=>'('+((g.Conditions||g.conditions||[]).map(c=>`${c.Field||c.field} ${c.Operator||c.operator} ${c.Value||c.value}`).join(` ${g.Operator||g.operator||'AND'} `))+')').join(` ${r.GroupOperator||'AND'} `)||'built-in detector'}
function renderRules(){document.querySelector('#table-rules tbody').innerHTML=rules.map(r=>{const custom=String(r.Kind).toLowerCase()==='custom',mode=r.Simulation?`simulation (${r.SimulationHits||0} matches)`:(r.Enabled?'enabled':'disabled'),toggleLabel=r.Enabled?'Disable rule':'Enable rule';return `<tr><td>${esc(r.SensorID)}</td><td>${esc(r.Name)}</td><td>${esc(r.Category||r.Kind)}</td><td class="rule-condition rule-condition-summary">${esc(ruleSummary(r))}</td><td>${esc(mode)}</td><td>${esc(r.Severity||'—')}</td><td>${esc(r.Priority||100)}</td><td>${esc(r.HitCount||0)}</td><td>${time(r.LastHit)}</td><td class="rule-actions"><button type="button" class="rule-state-toggle ${r.Enabled?'is-on':'is-off'}" data-sensor="${esc(r.SensorID)}" data-id="${esc(r.ID)}" data-enabled="${r.Enabled?'true':'false'}" aria-pressed="${r.Enabled?'true':'false'}" aria-label="${toggleLabel}" title="${toggleLabel}" ${can('rule_manage')?'':'disabled'}><span aria-hidden="true"></span></button>${custom&&can('rule_manage')?`<button class="secondary-btn rule-edit" data-sensor="${esc(r.SensorID)}" data-id="${esc(r.ID)}">Edit</button><button class="danger-btn rule-delete" data-sensor="${esc(r.SensorID)}" data-id="${esc(r.ID)}">Delete</button>`:custom?'<span class="builtin-lock">view only</span>':'<span class="builtin-lock">built-in</span>'}</td></tr>`}).join('')}
function populateRuleSensors(){const select=document.getElementById('rule-sensor'),current=select.value;select.innerHTML=sensors.map(s=>`<option value="${esc(s.id)}">${esc(s.name||s.id)} (${esc(s.id)})</option>`).join('');if(current)select.value=current}
function optionHtml(items,selected){return items.map(([v,l])=>`<option value="${v}" ${v===selected?'selected':''}>${l}</option>`).join('')}
function addCondition(group,condition={field:'src_ip',operator:'eq',value:''}){const row=document.createElement('div');row.className='rule-condition-row';row.innerHTML=`<select class="condition-field">${optionHtml(RULE_FIELDS,condition.field||condition.Field)}</select><select class="condition-operator">${optionHtml(RULE_OPERATORS,condition.operator||condition.Operator)}</select><input class="condition-value" value="${esc(condition.value||condition.Value||'')}" placeholder="Value or comma-separated list"><button type="button" class="danger-btn condition-remove">×</button>`;row.querySelector('.condition-remove').onclick=()=>row.remove();group.querySelector('.rule-conditions').appendChild(row)}
function addGroup(data={operator:'AND',conditions:[{field:'src_ip',operator:'eq',value:''}]}){const box=document.createElement('div');box.className='rule-group';box.innerHTML=`<div class="rule-group-head"><label>Inside group <select class="group-operator"><option value="AND">AND</option><option value="OR">OR</option></select></label><div><button type="button" class="secondary-btn condition-add">+ Condition</button> <button type="button" class="danger-btn group-remove">Remove group</button></div></div><div class="rule-conditions"></div>`;box.querySelector('.group-operator').value=data.operator||data.Operator||'AND';box.querySelector('.condition-add').onclick=()=>addCondition(box);box.querySelector('.group-remove').onclick=()=>box.remove();document.getElementById('rule-groups').appendChild(box);(data.conditions||data.Conditions||[]).forEach(c=>addCondition(box,c))}
function resetRuleForm(){document.getElementById('rule-form').reset();document.getElementById('rule-id').value='';document.getElementById('rule-priority').value='100';document.getElementById('rule-enabled').checked=true;document.getElementById('rule-groups').innerHTML='';addGroup();document.getElementById('rule-form-error').textContent='';document.getElementById('rule-test-result').textContent='';document.getElementById('rule-modal-title').textContent='Create detection rule'}
function openRuleModal(rule=null){populateRuleSensors();resetRuleForm();if(rule){document.getElementById('rule-modal-title').textContent='Edit detection rule';document.getElementById('rule-id').value=rule.ID;document.getElementById('rule-sensor').value=rule.SensorID;document.getElementById('rule-sensor').disabled=true;document.getElementById('rule-name').value=rule.Name||'';document.getElementById('rule-description').value=rule.Description||'';document.getElementById('rule-category').value=rule.Category||'custom';document.getElementById('rule-severity').value=rule.Severity||'medium';document.getElementById('rule-priority').value=rule.Priority||100;document.getElementById('rule-enabled').checked=!!rule.Enabled;document.getElementById('rule-simulation').checked=!!rule.Simulation;document.getElementById('rule-group-operator').value=rule.GroupOperator||'AND';document.getElementById('rule-suppression').value=(rule.Suppression&&rule.Suppression.Mode)||'aggregate';document.getElementById('rule-interval').value=(rule.Suppression&&rule.Suppression.IntervalSeconds)||600;document.getElementById('rule-groups').innerHTML='';ruleGroupsOf(rule).forEach(g=>addGroup({operator:g.Operator||g.operator,conditions:g.Conditions||g.conditions}))}else document.getElementById('rule-sensor').disabled=false;document.getElementById('rule-modal').hidden=false;toggleRuleInterval()}
function closeRuleModal(){document.getElementById('rule-modal').hidden=true;document.getElementById('rule-sensor').disabled=false}
function collectRule(){const groups=[...document.querySelectorAll('#rule-groups .rule-group')].map(g=>({operator:g.querySelector('.group-operator').value,conditions:[...g.querySelectorAll('.rule-condition-row')].map(r=>({field:r.querySelector('.condition-field').value,operator:r.querySelector('.condition-operator').value,value:r.querySelector('.condition-value').value.trim()}))}));return {id:document.getElementById('rule-id').value||undefined,name:document.getElementById('rule-name').value.trim(),description:document.getElementById('rule-description').value.trim(),category:document.getElementById('rule-category').value,kind:'custom',enabled:document.getElementById('rule-enabled').checked,severity:document.getElementById('rule-severity').value,priority:Number(document.getElementById('rule-priority').value)||100,simulation:document.getElementById('rule-simulation').checked,group_operator:document.getElementById('rule-group-operator').value,groups,actions:[{type:'alert'},{type:'siem'}],suppression:{mode:document.getElementById('rule-suppression').value,interval_seconds:Number(document.getElementById('rule-interval').value)||0},schedule:'always'}}
function toggleRuleInterval(){document.getElementById('rule-interval-label').hidden=document.getElementById('rule-suppression').value!=='interval'}
document.getElementById('rule-add-open').onclick=()=>openRuleModal();document.getElementById('rule-modal-close').onclick=closeRuleModal;document.getElementById('rule-cancel').onclick=closeRuleModal;document.getElementById('rule-add-group').onclick=()=>addGroup();document.getElementById('rule-suppression').onchange=toggleRuleInterval;
document.getElementById('rule-test').onclick=async()=>{const sensor=document.getElementById('rule-sensor').value;try{const result=await api(`/sensors/${encodeURIComponent(sensor)}/rules/test`,{method:'POST',body:JSON.stringify(collectRule())});document.getElementById('rule-test-result').textContent=result.message||'Rule is valid'}catch(err){document.getElementById('rule-form-error').textContent=err.message}};
document.getElementById('rule-form').onsubmit=async e=>{e.preventDefault();const sensor=document.getElementById('rule-sensor').value,body=collectRule(),id=document.getElementById('rule-id').value;try{await api(id?`/sensors/${encodeURIComponent(sensor)}/rules/${encodeURIComponent(id)}`:`/sensors/${encodeURIComponent(sensor)}/rules`,{method:id?'PUT':'POST',body:JSON.stringify(body)});closeRuleModal();setTimeout(refreshAll,1000)}catch(err){document.getElementById('rule-form-error').textContent=err.message}};
document.querySelector('#table-rules tbody').onclick=async e=>{const toggle=e.target.closest('.rule-state-toggle'),edit=e.target.closest('.rule-edit'),del=e.target.closest('.rule-delete');if(edit){openRuleModal(rules.find(r=>r.SensorID===edit.dataset.sensor&&r.ID===edit.dataset.id));return}if(toggle){const enabled=toggle.dataset.enabled!=='true';toggle.disabled=true;await api(`/sensors/${encodeURIComponent(toggle.dataset.sensor)}/rules/${encodeURIComponent(toggle.dataset.id)}`,{method:'PATCH',body:JSON.stringify({enabled})});setTimeout(refreshAll,1000)}else if(del&&confirm('Delete this custom rule?')){del.disabled=true;await api(`/sensors/${encodeURIComponent(del.dataset.sensor)}/rules/${encodeURIComponent(del.dataset.id)}`,{method:'DELETE'});setTimeout(refreshAll,1000)}};
document.getElementById('rule-export').onclick=async()=>{const data=await api('/rules/export');const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='otlens-rules.json';a.click();URL.revokeObjectURL(a.href)};
document.getElementById('rule-import-open').onclick=()=>document.getElementById('rule-import-file').click();document.getElementById('rule-import-file').onchange=async e=>{const f=e.target.files[0];if(!f)return;try{const data=JSON.parse(await f.text()),sensor=prompt('Target sensor ID',sensors[0]?.id||'');if(!sensor)return;const imported=(data.rules||[]).filter(r=>String(r.Kind||r.kind).toLowerCase()==='custom').map(r=>{const x={...r};delete x.SensorID;return x});await api('/rules/import',{method:'POST',body:JSON.stringify({sensor_id:sensor,rules:imported})});setTimeout(refreshAll,1000)}catch(err){alert('Import failed: '+err.message)}finally{e.target.value=''}};

function populateAnalysisSensors(){const sel=document.getElementById('analysis-sensor');if(!sel)return;const current=sel.value;sel.innerHTML=sensors.map(s=>`<option value="${esc(s.id??s.ID)}">${esc(s.name??s.Name??s.id??s.ID)} (${esc(s.id??s.ID)})</option>`).join('');if([...sel.options].some(o=>o.value===current))sel.value=current}
function renderAnalysis(){const tbody=document.querySelector('#table-analysis tbody');if(!tbody)return;tbody.innerHTML=(analysisJobs||[]).map(j=>`<tr><td>${time(j.created_at)}</td><td>${esc(j.sensor_id)}</td><td title="SHA-256: ${esc(j.sha256)}">${esc(j.filename)}<br><small>${Math.round((j.size_bytes||0)/1024)} KB</small></td><td class="analysis-status-${esc(j.status)}">${esc(j.status)}</td><td>${esc(j.packets||0)}</td><td>${esc(j.assets_discovered||0)}</td><td>${esc(j.flows_discovered||0)}</td><td>${esc(j.tags_discovered||0)}</td><td>${esc(j.alerts_generated||0)}</td><td>${esc((j.protocols||[]).join(', '))}</td><td>${esc(j.error||'')}</td><td>${can('analysis_manage')?`<button class="danger-btn analysis-delete" data-id="${esc(j.id)}">Delete</button>`:'—'}</td></tr>`).join('')}
async function uploadAnalysis(form){const fd=new FormData();fd.append('sensor_id',document.getElementById('analysis-sensor').value);const file=document.getElementById('analysis-file').files[0];if(!file)throw new Error('Select a PCAP file');fd.append('pcap',file,file.name);document.querySelectorAll('input[name=analysis-protocol]:checked').forEach(x=>fd.append('protocols',x.value));const r=await fetch('/v1/analysis/jobs',{method:'POST',body:fd,credentials:'include'});if(!r.ok)throw new Error(r.status+' '+await r.text());return r.json()}
document.getElementById('analysis-form').onsubmit=async e=>{e.preventDefault();const st=document.getElementById('analysis-upload-status');st.textContent='Uploading…';try{await uploadAnalysis(e.target);st.textContent='Queued for sensor analysis';e.target.reset();setTimeout(refreshAll,500)}catch(err){st.textContent='Upload failed: '+err.message}}
document.querySelector('#table-analysis tbody').onclick=async e=>{const b=e.target.closest('.analysis-delete');if(!b)return;if(!confirm('Delete this analysis job and stored PCAP?'))return;try{await api('/analysis/jobs/'+encodeURIComponent(b.dataset.id),{method:'DELETE'});refreshAll()}catch(err){alert(err.message)}};

function sensorSelection(){return [...document.querySelectorAll('.sensor-select:checked')].map(x=>x.dataset.id)}
function updateSensorBulk(){const ids=sensorSelection(),all=document.getElementById('sensors-all'),boxes=[...document.querySelectorAll('.sensor-select')];document.getElementById('sensors-start').hidden=!ids.length;document.getElementById('sensors-stop').hidden=!ids.length;document.getElementById('sensors-delete').hidden=!ids.length;document.getElementById('sensors-selection-count').textContent=ids.length?`${ids.length} selected`:'';if(all){all.checked=boxes.length>0&&ids.length===boxes.length;all.indeterminate=ids.length>0&&ids.length<boxes.length}}
function metric(obj,...path){let v=obj;for(const k of path){v=v?.[k]}return Number(v)||0}
function humanBytes(v){v=Number(v)||0;const u=['B','KB','MB','GB','TB'];let i=0;while(v>=1024&&i<u.length-1){v/=1024;i++}return `${v.toFixed(i?1:0)} ${u[i]}`}
function resizeCanvas(c,height=180){const dpr=Math.max(1,window.devicePixelRatio||1),w=Math.max(260,c.clientWidth||420);c.width=Math.round(w*dpr);c.height=Math.round(height*dpr);const x=c.getContext('2d');x.setTransform(dpr,0,0,dpr,0,0);return{x,w,h:height}}
function drawMetricLine(id,samples,series){const c=document.getElementById(id);if(!c)return;const {x,w,h}=resizeCanvas(c,180);x.clearRect(0,0,w,h);const pad={l:45,r:14,t:12,b:25},pw=w-pad.l-pad.r,ph=h-pad.t-pad.b;const vals=samples.flatMap(s=>series.map(q=>q.value(s)));const max=Math.max(1,...vals);x.strokeStyle='#2a3648';x.lineWidth=1;x.beginPath();x.moveTo(pad.l,pad.t);x.lineTo(pad.l,pad.t+ph);x.lineTo(pad.l+pw,pad.t+ph);x.stroke();x.font='11px ui-monospace,monospace';x.fillStyle='#8393ab';x.textAlign='right';x.fillText(series[0].format?series[0].format(max):Math.round(max),pad.l-6,pad.t+5);x.fillText('0',pad.l-6,pad.t+ph);series.forEach((q,si)=>{x.strokeStyle=si?'#e8a33d':'#3fbfb0';x.lineWidth=2;x.beginPath();samples.forEach((s,i)=>{const px=pad.l+(samples.length<2?0:i/(samples.length-1))*pw,py=pad.t+ph-(q.value(s)/max)*ph;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()});if(samples.length){x.textAlign='left';x.fillText(new Date(samples[0].recorded_at).toLocaleTimeString(),pad.l,pad.t+ph+17);x.textAlign='right';x.fillText(new Date(samples.at(-1).recorded_at).toLocaleTimeString(),pad.l+pw,pad.t+ph+17)}}
let selectedMetricSensor='';async function openSensorMetrics(id){selectedMetricSensor=id;const s=sensors.find(x=>(x.id??x.ID)===id);document.getElementById('sensor-metrics-title').textContent=`Sensor metrics · ${s?.name||id}`;document.getElementById('sensor-metrics-subtitle').textContent=`${s?.hostname||'—'} · ${s?.capture_interface||'—'} · ${s?.capture_backend||'—'}`;document.getElementById('sensor-metrics-modal').hidden=false;await loadSensorMetricHistory()}
async function loadSensorMetricHistory(){if(!selectedMetricSensor)return;const range=document.getElementById('sensor-metrics-range').value;const rows=await api(`/sensors/${encodeURIComponent(selectedMetricSensor)}/metrics?range=${range}`);const last=rows.at(-1)||{},tcp=last.metrics?.tcp_reassembly||{},cap=last.metrics?.capture||{},sys=last.metrics?.system||{};document.getElementById('sensor-metrics-kpis').innerHTML=[['Health',last.health_state||'unknown'],['Packets/s',Math.round(metric(last,'metrics','capture','packets_per_second')).toLocaleString()],['Traffic/s',humanBytes(metric(last,'metrics','capture','bytes_per_second'))],['TCP reassembly',tcp.enabled?(tcp.running?'running':'stopped'):'disabled'],['TCP packets/s',Math.round(metric(last,'metrics','tcp_reassembly','tcp_packets_per_second')).toLocaleString()],['TCP share',`${metric(last,'metrics','tcp_reassembly','tcp_packet_percent').toFixed(1)}%`],['Active streams',metric(last,'metrics','tcp_reassembly','active_connections').toLocaleString()],['Streams opened',metric(last,'metrics','tcp_reassembly','connections_opened_total').toLocaleString()],['Streams closed',metric(last,'metrics','tcp_reassembly','connections_closed_total').toLocaleString()],['TCP segments',metric(last,'metrics','tcp_reassembly','segments_seen').toLocaleString()],['Stream chunks',metric(last,'metrics','tcp_reassembly','chunks_emitted').toLocaleString()],['Buffered',humanBytes(metric(last,'metrics','tcp_reassembly','buffered_bytes'))],['Gap recoveries',metric(last,'metrics','tcp_reassembly','gap_recoveries').toLocaleString()],['Overlap conflicts',metric(last,'metrics','tcp_reassembly','overlap_conflicts').toLocaleString()],['Sync failures',last.sync?.consecutive_failures||0]].map(([a,b])=>`<div class="kpi-card"><span>${esc(a)}</span><strong>${esc(b)}</strong></div>`).join('');drawMetricLine('sensor-chart-pps',rows,[{value:s=>metric(s,'metrics','capture','packets_per_second')}]);drawMetricLine('sensor-chart-bps',rows,[{value:s=>metric(s,'metrics','capture','bytes_per_second'),format:humanBytes}]);drawMetricLine('sensor-chart-streams',rows,[{value:s=>metric(s,'metrics','tcp_reassembly','active_connections')}]);drawMetricLine('sensor-chart-buffered',rows,[{value:s=>metric(s,'metrics','tcp_reassembly','buffered_bytes'),format:humanBytes}]);drawMetricLine('sensor-chart-memory',rows,[{value:s=>metric(s,'metrics','system','memory_alloc_bytes'),format:humanBytes}]);drawMetricLine('sensor-chart-integrity',rows,[{value:s=>metric(s,'metrics','tcp_reassembly','gap_recoveries')},{value:s=>metric(s,'metrics','tcp_reassembly','overlap_conflicts')}]);document.getElementById('sensor-metrics-details').innerHTML=objectRows({uptime_seconds:last.uptime_seconds,capture:last.capture,tcp_reassembly:tcp,versions:last.versions,sync:last.sync,health_reasons:last.health_reasons})}
async function loadHealthcheck(){try{healthcheckData=await api('/healthcheck');renderHealthcheck()}catch(e){console.error('healthcheck',e)}}
function renderHealthcheck(){const h=healthcheckData?.central||{},rows=healthcheckData?.sensors||[];document.getElementById('health-central-kpis').innerHTML=[['Healthy sensors',h.sensors_healthy||0],['Warning',h.sensors_warning||0],['Critical',h.sensors_critical||0],['Offline',h.sensors_offline||0],['Database',h.database_ok?'Healthy':'Unavailable'],['DB latency',`${Number(h.database_latency_ms||0).toFixed(1)} ms`],['Central memory',humanBytes(h.memory_alloc_bytes)],['Goroutines',h.goroutines||0]].map(([a,b])=>`<div class="kpi-card"><span>${esc(a)}</span><strong>${esc(b)}</strong></div>`).join('');document.getElementById('health-central-status').innerHTML=objectRows({recorded_at:time(h.recorded_at),uptime_seconds:h.uptime_seconds,memory_system:humanBytes(h.memory_sys_bytes),heap_objects:h.heap_objects,database_latency_ms:Number(h.database_latency_ms||0).toFixed(2)});document.getElementById('health-sensor-summary').innerHTML=['healthy','warning','critical','offline'].map(k=>`<div class="health-summary-item health-${k}"><span>${k}</span><strong>${rows.filter(x=>x.health_state===k).length}</strong></div>`).join('');document.querySelector('#table-health tbody').innerHTML=rows.map(x=>`<tr class="health-row" data-id="${esc(x.sensor_id)}"><td>${esc(x.sensor_id)}</td><td><span class="sensor-state sensor-state-${esc(x.health_state)}">${esc(x.health_state)}</span></td><td>${esc((x.health_reasons||[]).join('; ')||'No active operational issue')}</td><td>${time(x.recorded_at)}</td><td>${Math.round(metric(x,'metrics','capture','packets_per_second')).toLocaleString()}</td><td>${humanBytes(metric(x,'metrics','capture','bytes_per_second'))}/s</td><td>${metric(x,'metrics','capture','drop_rate_percent').toFixed(2)}%</td><td>${metric(x,'metrics','system','cpu_percent').toFixed(1)}%</td><td>${humanBytes(metric(x,'metrics','system','memory_alloc_bytes'))}</td><td>${metric(x,'metrics','pipeline','event_queue_depth')}</td><td>${metric(x,'metrics','tcp_reassembly','active_connections')}</td><td>${esc(x.versions?.threat_intel||'—')}</td><td>${esc(x.versions?.config||'—')}</td></tr>`).join('')}
function renderSensors(){sensors=Array.isArray(sensors)?sensors:[];populateRuleSensors();populateAnalysisSensors();renderSegmentationSensorList();populateITOTSensorList();const metricsBySensor=new Map((sensorMetrics||[]).map(x=>[x.sensor_id,x]));document.querySelector('#table-sensors tbody').innerHTML=sensors.map(s=>{const id=s.id??s.ID,status=String(s.status??s.Status??'unknown').toLowerCase(),m=metricsBySensor.get(id),hs=m?.health_state||status;return `<tr class="sensor-row" data-id="${esc(id)}"><td><input type="checkbox" class="sensor-select" data-id="${esc(id)}" aria-label="Select sensor ${esc(id)}"></td><td>${esc(id)}</td><td>${esc(s.name??s.Name)}</td><td>${esc(s.site_id??s.SiteID)}</td><td><span class="sensor-state sensor-state-${esc(hs)}">${esc(hs)}</span></td><td>${esc(s.hostname??s.Hostname)}</td><td>${esc(s.version??s.Version)}</td><td>${esc(s.go_version??s.GoVersion??'—')}</td><td>${esc(s.libpcap_version??s.LibpcapVersion??'—')}</td><td>${esc(s.gopacket_version??s.GopacketVersion??'—')}</td><td>${esc(s.capture_backend??s.CaptureBackend??'—')}</td><td>${esc(s.capture_interface??s.CaptureInterface??'—')}</td><td>${esc(s.capture_snaplen??s.CaptureSnaplen??'—')}</td><td>${(s.capture_promiscuous??s.CapturePromiscuous)?'yes':'no'}</td><td>${time(s.last_heartbeat_at??s.LastHeartbeatAt??s.last_seen??s.LastSeen)}</td><td>${time(s.last_data_received_at??s.LastDataReceivedAt)}</td><td><span class="sensor-state sensor-state-${esc(String(s.sync_status??s.SyncStatus??'unknown').toLowerCase())}">${esc(s.sync_status??s.SyncStatus??'unknown')}</span></td><td>${esc(s.pending_records??s.PendingRecords??0)}</td><td title="${esc(s.last_sync_error??s.LastSyncError??'')}">${esc((s.last_sync_error??s.LastSyncError??'—').slice(0,60))}</td></tr>`}).join('');updateSensorBulk()}
async function sensorAction(action){const ids=sensorSelection();if(!ids.length)return;const verb=action==='stop'?'stop capture on':'start capture on';if(!confirm(`${verb} ${ids.length} selected sensor(s)?`))return;const start=document.getElementById('sensors-start'),stop=document.getElementById('sensors-stop');start.disabled=stop.disabled=true;try{await api('/sensors/actions',{method:'POST',body:JSON.stringify({action,sensor_ids:ids})});document.getElementById('sensors-selection-count').textContent=`${action} queued for ${ids.length} sensor(s)`;setTimeout(refreshAll,1200)}catch(err){alert(`Sensor ${action} failed: ${err.message}`)}finally{start.disabled=stop.disabled=false}}
async function deleteSensors(){
  const ids=sensorSelection();if(!ids.length)return;
  const confirmation=prompt(`This deletes ${ids.length} sensor(s) and ALL their history (topology, alerts, analysis jobs) permanently. A sensor that's still running will simply reappear (with fresh, empty history) the next time it connects — this does not block it. Type DELETE to continue.`);
  if(confirmation!=='DELETE')return;
  const btn=document.getElementById('sensors-delete');btn.disabled=true;
  try{
    await Promise.all(ids.map(id=>api(`/sensors/${encodeURIComponent(id)}`,{method:'DELETE'})));
    document.getElementById('sensors-selection-count').textContent=`Deleted ${ids.length} sensor(s)`;
    refreshAll();
  }catch(err){alert(`Sensor delete failed: ${err.message}`)}
  finally{btn.disabled=false}
}
document.querySelector('#table-sensors tbody').addEventListener('change',e=>{if(e.target.matches('.sensor-select'))updateSensorBulk()});document.getElementById('sensors-all').addEventListener('change',e=>{document.querySelectorAll('.sensor-select').forEach(x=>x.checked=e.target.checked);updateSensorBulk()});document.getElementById('sensors-start').onclick=()=>sensorAction('start');document.getElementById('sensors-stop').onclick=()=>sensorAction('stop');document.getElementById('sensors-delete').onclick=()=>deleteSensors();

function openDashboardTab(tab){
  if(!canView(tab))return;
  const button=document.querySelector(`.tab[data-tab="${tab}"]`);
  if(button)button.click();
}
function dashboardStatus(sensor){
  const status=String(sensor.status??sensor.Status??'offline').toLowerCase();
  if(status==='running'||status==='online'||status==='active')return 'running';
  if(status==='stopped'||status==='paused'||status==='disabled')return 'stopped';
  return 'offline';
}
function dashboardBars(target,items,total,severity=false){
  const el=document.getElementById(target);if(!el)return;
  if(!items.length||!total){el.innerHTML='<div class="empty-dashboard">No data available</div>';return}
  el.innerHTML=items.map(([name,count])=>`<div class="bar-row" ${severity?`data-severity="${esc(String(name).toLowerCase())}"`:''}><span class="bar-label" title="${esc(name)}">${esc(name)}</span><span class="bar-track"><span class="bar-fill" style="width:${Math.max(2,Math.round(count/total*100))}%"></span></span><span class="bar-value">${count}</span></div>`).join('');
}
function renderDashboard(){
  const sensorCounts={running:0,stopped:0,offline:0};
  (sensors||[]).forEach(s=>sensorCounts[dashboardStatus(s)]++);
  const openAlerts=(alerts||[]).filter(a=>String(a.Status??a.status??'new').toLowerCase()==='new');
  const activeRules=(rules||[]).filter(r=>Boolean(r.Enabled??r.enabled));
  const unconfirmedAssets=(assets||[]).filter(a=>(a.Confirmed??a.confirmed)===false).length;
  const pendingJobs=(analysisJobs||[]).filter(j=>['queued','pending','running','processing'].includes(String(j.status??j.Status??'').toLowerCase()));
  document.getElementById('dashboard-sensors-running').textContent=sensorCounts.running;
  document.getElementById('dashboard-sensors-stopped').textContent=sensorCounts.stopped;
  document.getElementById('dashboard-sensors-offline').textContent=sensorCounts.offline;
  document.getElementById('dashboard-alerts-open').textContent=openAlerts.length;
  document.getElementById('dashboard-assets').textContent=(assets||[]).length;
  document.getElementById('dashboard-assets-detail').textContent=`${unconfirmedAssets} unconfirmed`;
  document.getElementById('dashboard-rules').textContent=`${activeRules.length} / ${(rules||[]).length}`;
  document.getElementById('dashboard-tags').textContent=(tags||[]).length;
  document.getElementById('dashboard-analysis').textContent=pendingJobs.length;
  document.getElementById('dashboard-analysis-detail').textContent=pendingJobs.length?`${pendingJobs.filter(j=>String(j.status).toLowerCase()==='running').length} running · ${pendingJobs.length} pending`:'No pending jobs';
  document.getElementById('dashboard-unconfirmed-assets').textContent=unconfirmedAssets;
  const tiHits=openAlerts.filter(a=>['malicious_ip','malicious_domain'].includes(String(a.Type))).length;
  const c2lm=openAlerts.filter(a=>['c2_correlated','beacon','lateral_movement'].includes(String(a.Type))).length;
  const otAnomaly=openAlerts.filter(a=>['ot_value_anomaly','unexpected_write'].includes(String(a.Type))).length;
  const smbRiskCount=(smbObservations||[]).filter(smbRisk).length;
  document.getElementById('dashboard-ti').textContent=tiHits;
  document.getElementById('dashboard-c2lm').textContent=c2lm;
  document.getElementById('dashboard-ot-anomaly').textContent=otAnomaly;
  document.getElementById('dashboard-smb').textContent=smbRiskCount;
  document.getElementById('dashboard-refresh').textContent=new Date().toLocaleTimeString();
  const totalPPS=(sensorMetrics||[]).reduce((n,x)=>n+metric(x,'metrics','capture','packets_per_second'),0),totalStreams=(sensorMetrics||[]).reduce((n,x)=>n+metric(x,'metrics','tcp_reassembly','active_connections'),0),healthWarnings=(sensorMetrics||[]).filter(x=>['warning','critical','offline'].includes(x.health_state)).length;
  document.getElementById('dashboard-pps').textContent=Math.round(totalPPS).toLocaleString();document.getElementById('dashboard-streams').textContent=Math.round(totalStreams).toLocaleString();document.getElementById('dashboard-health-warnings').textContent=healthWarnings;
  const profiled=(assets||[]).filter(a=>a.LastProfiledAt||a.ReconHostname||a.ReconVendor||a.ReconOS).length, unknownIdentity=(assets||[]).filter(a=>!(a.Hostname||a.ReconHostname)||!(a.Vendor||a.ReconVendor)||!a.ReconOS).length, reconActive=(reconnaissanceJobs||[]).filter(j=>['queued','running'].includes(j.status)).length;
  const dp=document.getElementById('dashboard-profiled');if(dp)dp.textContent=profiled;const du=document.getElementById('dashboard-unknown-identity');if(du)du.textContent=unknownIdentity;const dj=document.getElementById('dashboard-recon-jobs');if(dj)dj.textContent=reconActive;

  const severityOrder=['critical','high','medium','low','info'];
  const severityCounts=new Map(severityOrder.map(x=>[x,0]));
  openAlerts.forEach(a=>{const key=String(a.Severity??a.severity??'info').toLowerCase();severityCounts.set(key,(severityCounts.get(key)||0)+1)});
  const severityItems=severityOrder.map(x=>[x[0].toUpperCase()+x.slice(1),severityCounts.get(x)||0]).filter(([,n])=>n>0);
  const severityMax=severityItems.reduce((m,[,n])=>Math.max(m,n),0);
  dashboardBars('dashboard-severity',severityItems,severityMax,true);

  const protocolCounts=new Map();
  (assets||[]).forEach(a=>(a.Protocols??a.protocols??[]).forEach(proto=>{const key=String(proto||'Unknown');protocolCounts.set(key,(protocolCounts.get(key)||0)+1)}));
  if(!protocolCounts.size)(tags||[]).forEach(t=>{const key=String(t.Protocol??t.protocol??'Unknown');protocolCounts.set(key,(protocolCounts.get(key)||0)+1)});
  const protocols=[...protocolCounts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,7);
  dashboardBars('dashboard-protocols',protocols,protocols.reduce((n,x)=>n+x[1],0));

  const recent=[...openAlerts].sort((a,b)=>new Date(b.LastSeen??b.last_seen??0)-new Date(a.LastSeen??a.last_seen??0)).slice(0,7);
  const recentEl=document.getElementById('dashboard-recent');
  recentEl.innerHTML=recent.length?recent.map(a=>`<div class="activity-item"><span class="activity-time">${time(a.LastSeen??a.last_seen)}</span><span class="activity-sensor">${esc(a.SensorID??a.sensor_id??'—')}</span><span class="activity-message"><span class="severity ${esc(String(a.Severity??a.severity??'info').toLowerCase())}">${esc(a.Severity??a.severity??'info')}</span>${esc(a.Message??a.message??a.Type??a.type??'Alert')}</span></div>`).join(''):'<div class="empty-dashboard">No open security alerts</div>';

  const learning=(baselines||[]).filter(b=>String(b.mode??b.Mode??'').toLowerCase()==='learning');
  document.getElementById('dashboard-baseline').textContent=learning.length?`Learning on ${learning.length} sensor(s)`:(baselines||[]).length?'Monitoring':'No data';
  const latest=[...(backups||[])].sort((a,b)=>new Date(b.created_at??b.CreatedAt??0)-new Date(a.created_at??a.CreatedAt??0))[0];
  document.getElementById('dashboard-backup').textContent=latest?time(latest.created_at??latest.CreatedAt):'Never';

  const criticalOpen=severityCounts.get('critical')||0;
  const health=document.getElementById('dashboard-health'),title=document.getElementById('dashboard-health-title'),detail=document.getElementById('dashboard-health-detail');
  health.className='health-banner '+(sensorCounts.offline||criticalOpen?'health-critical':sensorCounts.stopped||openAlerts.length?'health-warning':'health-healthy');
  if(sensorCounts.offline||criticalOpen){title.textContent='Critical';detail.textContent=[sensorCounts.offline?`${sensorCounts.offline} sensor(s) offline`:'',criticalOpen?`${criticalOpen} critical alert(s)`:'' ].filter(Boolean).join(' · ')}
  else if(sensorCounts.stopped||openAlerts.length){title.textContent='Warning';detail.textContent=[sensorCounts.stopped?`${sensorCounts.stopped} sensor(s) stopped`:'',openAlerts.length?`${openAlerts.length} open alert(s)`:'' ].filter(Boolean).join(' · ')}
  else{title.textContent='Healthy';detail.textContent='Sensors running and no open alerts'}
  drawDailyBarChart('dashboard-alerts-trend',trends.AlertsByDay,30);
  drawDailyBarChart('dashboard-assets-trend',trends.NewAssetsByDay,30);
}
document.getElementById('view-dashboard').addEventListener('click',e=>{const target=e.target.closest('[data-dashboard-tab]');if(target)openDashboardTab(target.dataset.dashboardTab)});

function renderBaseline(){const learning=baselines.filter(b=>b.mode==='learning'),d=document.getElementById('baseline-dot'),t=document.getElementById('baseline-text');if(learning.length){d.className='dot learning';const ends=learning.map(x=>new Date(x.learning_ends_at)).filter(x=>!isNaN(x)).sort((a,b)=>a-b)[0];t.textContent=`Learning ${learning.length}/${baselines.length}${ends?' · until '+ends.toLocaleTimeString():''} · alerts suppressed`}else{d.className='dot monitoring';t.textContent=baselines.length?'Monitoring':'No baseline data'}}
function renderSettings(){
  const onOff=v=>v?'Enabled':'Disabled';
  const days=n=>n>0?`${n} days`:'kept indefinitely';
  document.getElementById('settings-offline-after').textContent=settings.SensorOfflineAfterSeconds!=null?`${settings.SensorOfflineAfterSeconds}s of silence`:'—';
  document.getElementById('settings-check-interval').textContent=settings.SensorCheckIntervalSeconds!=null?`${settings.SensorCheckIntervalSeconds}s`:'—';
  document.getElementById('settings-session-duration').textContent=settings.SessionDurationSeconds!=null?`${Math.round(settings.SessionDurationSeconds/3600*10)/10}h`:'—';
  document.getElementById('settings-retention-enabled').textContent=onOff(settings.RetentionEnabled);
  document.getElementById('settings-retention-interval').textContent=settings.RetentionIntervalHours!=null?`${settings.RetentionIntervalHours}h`:'—';
  document.getElementById('settings-retention-telemetry').textContent=days(settings.TelemetryRetentionDays);
  document.getElementById('settings-retention-alerts').textContent=days(settings.AlertsRetentionDays);
  document.getElementById('settings-retention-audit').textContent=days(settings.AuditRetentionDays);
  document.getElementById('settings-retention-size').textContent=(settings.MaxDatabaseSizeGB!=null)?`${settings.MaxDatabaseSizeGB}GB → ${settings.TargetDatabaseSizeGB}GB`:'—';
  document.getElementById('settings-siem').textContent=onOff(settings.SIEMEnabled);
  document.getElementById('settings-analysis').textContent=onOff(settings.AnalysisEnabled);
  document.getElementById('settings-vuln').textContent=settings.VulnerabilityLoaded?`Loaded — ${settings.VulnerabilityCount} advisories`:'Not loaded';
  document.getElementById('settings-notifications').textContent=settings.NotificationsEnabled?`On (min. ${settings.NotificationsMinSeverity}) — email ${onOff(settings.NotificationsEmailEnabled)}, webhook ${onOff(settings.NotificationsWebhookEnabled)}`:'Off';
  document.getElementById('settings-web-tls').textContent=onOff(settings.WebTLSEnabled);
  document.getElementById('settings-sensor-tls').textContent=onOff(settings.SensorAPITLSEnabled);
  const extra=document.getElementById('settings-runtime-config');if(extra){const groups=settings.RuntimeConfig||{};extra.innerHTML=Object.entries(groups).map(([group,values])=>`<section class="settings-config-group"><h3>${esc(group)}</h3><dl class="status-list">${Object.entries(values||{}).map(([k,v])=>`<div><dt>${esc(k)}</dt><dd class="wrap-anywhere">${esc(Array.isArray(v)?v.join(', '):typeof v==='object'?JSON.stringify(v):v)}</dd></div>`).join('')}</dl></section>`).join('')}
}
function renderAudit(){
  const tbody=document.querySelector('#table-audit tbody');if(!tbody)return;
  tbody.innerHTML=audit.map(a=>`<tr data-id="${esc(a.ID)}"><td>${time(a.CreatedAt)}</td><td>${esc(a.Actor||'—')}</td><td>${esc(a.Action)}</td><td class="${a.Success?'state-ok':'state-new'}">${a.Status}</td><td>${esc(a.SensorID||'—')}</td><td>${esc(a.SourceIP||'—')}</td></tr>`).join('');
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
async function refreshAll(){
  setConn(false,'connecting');
  // /topology is fetched separately from the rest, and only while that tab
  // is actually visible: it's the one payload that can get genuinely large
  // on a big OT network, so there's no reason to pull and decode it every
  // 10s while the user is looking at Alerts or Sensors. fetchTopology also
  // sends If-None-Match, so even while the tab IS active, an unchanged
  // graph comes back as a bodyless 304 instead of a full re-send.
  const topologyActive=document.getElementById('view-topology').classList.contains('active')&&canView('topology');
  // Every poll path is tied to the view permission that gates it
  // server-side (see requireView in internal/central/server.go) — a role
  // that can't see a tab never even requests its data, instead of
  // spamming 403s into the "partial failure" indicator every 10s.
  const pathView={'/asset-security-status':'assets','/assets':'assets','/devices':'devices','/vulnerabilities':'vulnerabilities','/tags':'tags','/tags/changes':'tags','/tags/events':'tags','/sensors':'sensors','/sensors/metrics':'sensors','/alerts':'alerts','/incidents':'incidents','/dns-observations?limit=1000':'alerts','/smb-observations?limit=1000':'alerts','/rules':'rules','/baseline':'dashboard','/dashboard/trends':'dashboard','/reports':'dashboard','/analysis/jobs':'analysis','/data/backups':'data','/settings':'settings','/audit':'audit'};
  const paths=Object.keys(pathView).filter(p=>p==='/sensors'?(canView('sensors')||canView('data')):canView(pathView[p]));
  const topoPromise=topologyActive
    ?fetchTopology().then(v=>({status:'fulfilled',value:v})).catch(reason=>({status:'rejected',reason}))
    :Promise.resolve({status:'skipped'});
  const [settled,topo]=await Promise.all([Promise.allSettled(paths.map(api)),topoPromise]);
  const results={};paths.forEach((p,i)=>{results[p]=settled[i]});
  const ok=p=>results[p]&&results[p].status==='fulfilled';
  const list=p=>ok(p)&&Array.isArray(results[p].value)?results[p].value:[];
  if(topo.status==='fulfilled'&&topo.value&&!topo.value.unchanged){
    const v=topo.value.value;
    graph=(v&&Array.isArray(v.Nodes)&&Array.isArray(v.Edges))?v:{Nodes:[],Edges:[],HoneypotThreshold:100};
  }
  if(ok('/assets'))assets=list('/assets');
  if(ok('/asset-security-status'))assetSecurity=list('/asset-security-status');
  if(ok('/devices'))devices=list('/devices');
  if(ok('/vulnerabilities')&&results['/vulnerabilities'].value&&typeof results['/vulnerabilities'].value==='object')vulnerabilities=results['/vulnerabilities'].value.Advisories||[];
  if(ok('/tags'))tags=list('/tags');
  if(ok('/sensors'))sensors=list('/sensors');if(ok('/sensors/metrics'))sensorMetrics=list('/sensors/metrics');
  if(ok('/alerts'))alerts=list('/alerts');
  if(ok('/incidents'))incidents=list('/incidents');if(ok('/dns-observations?limit=1000'))dnsObservations=list('/dns-observations?limit=1000');if(ok('/smb-observations?limit=1000'))smbObservations=list('/smb-observations?limit=1000');
  if(ok('/reports'))reports=list('/reports');
  if(ok('/rules'))rules=list('/rules').map(x=>({...x,ID:x.ID||x.id,Name:x.Name||x.name,Description:x.Description||x.description,Category:x.Category||x.category,Kind:x.Kind||x.kind,Enabled:x.Enabled??x.enabled,Severity:x.Severity||x.severity,Priority:x.Priority||x.priority,Simulation:x.Simulation??x.simulation,SimulationHits:x.SimulationHits||x.simulation_hits||0,LastSimulationHit:x.LastSimulationHit||x.last_simulation_hit,Version:x.Version||x.version,Groups:x.Groups||x.groups,GroupOperator:x.GroupOperator||x.group_operator,Actions:x.Actions||x.actions,Suppression:x.Suppression||x.suppression,Field:x.Field||x.field,Value:x.Value||x.value}));
  if(ok('/baseline'))baselines=list('/baseline');
  if(ok('/tags/changes'))changes=list('/tags/changes');
  if(ok('/tags/events'))events=list('/tags/events');
  if(ok('/analysis/jobs'))analysisJobs=list('/analysis/jobs');
  if(ok('/data/backups'))backups=list('/data/backups');
  if(ok('/settings')&&results['/settings'].value&&typeof results['/settings'].value==='object')settings=results['/settings'].value;
  if(ok('/dashboard/trends')&&results['/dashboard/trends'].value&&typeof results['/dashboard/trends'].value==='object')trends=results['/dashboard/trends'].value;
  if(ok('/audit'))audit=list('/audit');
  // Render whenever the tab is active and the fetch didn't fail — including
  // the "unchanged" (304) case, since a freshly-opened tab or a
  // newly-arrived node still needs its first paint from whatever `graph`
  // already holds; renderTopology's own signature diff is what makes that
  // cheap when there's genuinely nothing new to draw.
  try{if(topologyActive&&topo.status==='fulfilled')renderTopology()}catch(e){console.error('render topology',e)}
  try{if(ok('/assets'))renderAssets()}catch(e){console.error('render assets',e)}
  try{if(ok('/devices'))renderDevices()}catch(e){console.error('render devices',e)}
  try{if(ok('/vulnerabilities'))renderVulnerabilities()}catch(e){console.error('render vulnerabilities',e)}
  try{if(ok('/tags'))renderTags()}catch(e){console.error('render tags',e)}
  try{if(ok('/sensors'))renderSensors()}catch(e){console.error('render sensors',e)}
  try{if(ok('/alerts'))renderAlerts()}catch(e){console.error('render alerts',e)}
  try{if(ok('/incidents'))renderIncidents()}catch(e){console.error('render incidents',e)}try{renderThreatIntel()}catch(e){console.error('render threat intel',e)}try{renderDNS()}catch(e){console.error('render dns',e)}try{renderSMB()}catch(e){console.error('render smb',e)}
  try{if(ok('/reports'))renderReports()}catch(e){console.error('render reports',e)}
  try{if(ok('/rules'))renderRules()}catch(e){console.error('render rules',e)}
  try{if(ok('/baseline'))renderBaseline()}catch(e){console.error('render baseline',e)}
  try{if(ok('/analysis/jobs'))renderAnalysis()}catch(e){console.error('render analysis',e)}try{renderBackups()}catch(e){console.error('render backups',e)}
  try{if(ok('/settings'))renderSettings()}catch(e){console.error('render settings',e)}
  try{if(ok('/audit'))renderAudit()}catch(e){console.error('render audit',e)}
  try{if(can('users_roles_manage'))await refreshUsersAndRoles()}catch(e){console.error('refresh users/roles',e)}
  try{renderDashboard()}catch(e){console.error('render dashboard',e)}
  const rejected=paths.map(p=>results[p].status==='rejected'?{path:p,reason:results[p].reason}:null).filter(Boolean);
  if(topo.status==='rejected')rejected.push({path:'/topology',reason:topo.reason});
  const attempted=paths.length+(topologyActive?1:0);
  if(!rejected.length){setConn(true,'live');document.getElementById('conn-text').title=''}
  else{
    console.error('Central API refresh failures:',rejected);
    const allUnauthorized=rejected.length===attempted&&rejected.every(x=>x.reason&&x.reason.status===401);
    const allForbidden=rejected.length===attempted&&rejected.every(x=>x.reason&&x.reason.status===403);
    const allNetwork=rejected.length===attempted&&rejected.every(x=>x.reason&&x.reason.kind==='network');
    let text;
    if(allUnauthorized)text='authentication required';
    else if(allForbidden)text='access forbidden';
    else if(allNetwork)text='backend unreachable';
    else text=`partial: ${rejected.map(x=>x.path).join(', ')}`;
    setConn(false,text);
    document.getElementById('conn-text').title=allUnauthorized?'Your session has expired — please log in again':'Failed endpoints: '+rejected.map(x=>x.path).join(', ');
    if(allUnauthorized){
      console.warn('All requests came back unauthorized — session cookie missing or invalid. Failing paths and status codes:',rejected.map(x=>({path:x.path,status:x.reason?.status})));
      showLogin();
    }
  }
}
OTDataTables.init();
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
  pollTimer=setInterval(refreshAll,POLL);
}
function stopPolling(){
  if(pollTimer){clearInterval(pollTimer);pollTimer=null}
}

const TAB_LABELS={dashboard:'Dashboard',threatintel:'Threat Intelligence',dns:'DNS Explorer',smb:'SMB Explorer',topology:'Topology',purdue:'Purdue',segmentation:'Segmentation',assets:'Assets',devices:'Devices',vulnerabilities:'Vulnerabilities',tags:'OT Tags',rules:'Rules',alerts:'Alerts',incidents:'Incidents',sensors:'Sensors',health:'Healthcheck',analysis:'Analysis',users:'Users',settings:'Settings',data:'Data Management',audit:'Audit log',reports:'Reports'};
const ACTION_LABELS={sensor_start_stop:'Start/stop sensors',asset_confirm_delete:'Confirm/delete assets',alert_confirm_approve:'Confirm/approve alerts',rule_manage:'Create/edit/delete rules',analysis_manage:'Upload/delete PCAP analysis',data_management:'Backups & resets',users_roles_manage:'Manage users & roles'};

// applyNavFiltering hides tab buttons the current role can't view (server
// still enforces this on every request — see requireView — this is only
// so the UI doesn't dangle buttons that would just 403).
// The Users tab holds content that used to live under Settings (self-
// service password change, Users, Roles) — it's gated by the same
// permission as Settings rather than a separate one, since splitting the
// page into two tabs didn't change who's supposed to see it.
const TAB_PERMISSION_ALIAS={health:'sensors',users:'settings',threatintel:'alerts',dns:'alerts',smb:'alerts'};
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
  const errEl=document.getElementById('login-error');errEl.textContent='';
  const username=document.getElementById('login-username').value,password=document.getElementById('login-password').value;
  try{
    const res=await api('/login',{method:'POST',body:JSON.stringify({username,password})});
    applyIdentity(res);
    document.getElementById('login-form').reset();
    showApp();
    startPolling();
  }catch(err){
    errEl.textContent=err.parsed?.error||'Login failed';
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
  if(u.status==='fulfilled')users=u.value||[];else console.error('GET /users failed:',u.reason?.status,u.reason?.message);
  if(r.status==='fulfilled')roles=r.value||[];else console.error('GET /roles failed:',r.reason?.status,r.reason?.message);
  try{renderUsers()}catch(e){console.error('render users',e)}
  try{renderRoles()}catch(e){console.error('render roles',e)}
  try{populateRoleSelect()}catch(e){console.error('populate role select',e)}
}
function populateRoleSelect(){
  const sel=document.getElementById('user-form-role');
  const current=sel.value;
  sel.innerHTML=roles.map(r=>`<option value="${esc(r.ID)}">${esc(r.Name)}</option>`).join('');
  if(current)sel.value=current;
}
function renderUsers(){
  const tbody=document.querySelector('#table-users tbody');if(!tbody)return;
  const roleName=id=>roles.find(r=>r.ID===id)?.Name||id;
  tbody.innerHTML=users.map(u=>{
    const expired=u.PasswordExpiresAt&&new Date(u.PasswordExpiresAt)<new Date();
    const pwStatus=u.MustChangePassword?'Must change at next login':expired?'Expired — must change at next login':u.PasswordExpiresAt?`Valid until ${time(u.PasswordExpiresAt)}`:'Never expires';
    return `<tr><td>${esc(u.Username)}</td><td>${esc(u.DisplayName)}</td><td>${esc(roleName(u.RoleID))}</td><td class="${u.Enabled?'state-ok':'state-new'}">${u.Enabled?'enabled':'disabled'}</td><td>${esc(pwStatus)}</td><td>${time(u.LastLoginAt)}</td><td>${can('users_roles_manage')?`<button class="secondary-btn user-edit" data-id="${esc(u.ID)}">Edit</button> <button class="secondary-btn user-reset" data-id="${esc(u.ID)}" data-username="${esc(u.Username)}">Reset password</button> <button class="danger-btn user-delete" data-id="${esc(u.ID)}">Delete</button>`:'—'}</td></tr>`;
  }).join('');
}
function renderRoles(){
  const tbody=document.querySelector('#table-roles tbody');if(!tbody)return;
  tbody.innerHTML=roles.map(r=>{
    const views=(r.Permissions?.view||[]).map(v=>TAB_LABELS[v]||v).join(', ')||'—';
    const acts=(r.Permissions?.actions||[]).map(a=>ACTION_LABELS[a]||a).join(', ')||'—';
    return `<tr><td>${esc(r.Name)}${r.BuiltIn?' <span class="pill">built-in</span>':''}</td><td>${esc(views)}</td><td>${esc(acts)}</td><td>${can('users_roles_manage')?`<button class="secondary-btn role-edit" data-id="${esc(r.ID)}">Edit</button> ${r.BuiltIn?'':`<button class="danger-btn role-delete" data-id="${esc(r.ID)}">Delete</button>`}`:'—'}</td></tr>`;
  }).join('');
}

function openUserModal(user){
  document.getElementById('user-form').reset();
  document.getElementById('user-form-error').textContent='';
  populateRoleSelect();
  const passwordLabel=document.getElementById('user-form-password-label');
  const forceRow=document.getElementById('user-form-force-change-row');
  if(user){
    document.getElementById('user-modal-title').textContent='Edit user';
    document.getElementById('user-form-id').value=user.ID;
    document.getElementById('user-form-username').value=user.Username;
    document.getElementById('user-form-username').disabled=true;
    document.getElementById('user-form-display-name').value=user.DisplayName||'';
    document.getElementById('user-form-role').value=user.RoleID;
    document.getElementById('user-form-validity').value=user.PasswordValidityDays||'';
    document.getElementById('user-form-enabled').checked=user.Enabled;
    passwordLabel.hidden=true;forceRow.hidden=true;
    document.getElementById('user-form-password').required=false;
  }else{
    document.getElementById('user-modal-title').textContent='Add user';
    document.getElementById('user-form-id').value='';
    document.getElementById('user-form-username').disabled=false;
    passwordLabel.hidden=false;forceRow.hidden=false;
    document.getElementById('user-form-password').required=true;
  }
  document.getElementById('user-modal').hidden=false;
}
document.getElementById('user-add-open').onclick=()=>openUserModal(null);
document.getElementById('user-modal-close').onclick=()=>document.getElementById('user-modal').hidden=true;
document.getElementById('user-form-cancel').onclick=()=>document.getElementById('user-modal').hidden=true;
document.getElementById('user-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const errEl=document.getElementById('user-form-error');errEl.textContent='';
  const id=document.getElementById('user-form-id').value;
  const validityRaw=document.getElementById('user-form-validity').value.trim();
  const validityDays=validityRaw?parseInt(validityRaw,10):null;
  try{
    if(id){
      await api(`/users/${encodeURIComponent(id)}`,{method:'PATCH',body:JSON.stringify({
        role_id:document.getElementById('user-form-role').value,
        display_name:document.getElementById('user-form-display-name').value,
        enabled:document.getElementById('user-form-enabled').checked,
        password_validity_days:validityDays,
      })});
    }else{
      await api('/users',{method:'POST',body:JSON.stringify({
        username:document.getElementById('user-form-username').value,
        password:document.getElementById('user-form-password').value,
        role_id:document.getElementById('user-form-role').value,
        display_name:document.getElementById('user-form-display-name').value,
        password_validity_days:validityDays,
        must_change_password:document.getElementById('user-form-force-change').checked,
      })});
    }
    document.getElementById('user-modal').hidden=true;
    refreshUsersAndRoles();
  }catch(err){errEl.textContent=err.parsed?.error||err.message}
});
document.querySelector('#table-users tbody').addEventListener('click',async e=>{
  const edit=e.target.closest('.user-edit'),reset=e.target.closest('.user-reset'),del=e.target.closest('.user-delete');
  if(edit){openUserModal(users.find(u=>u.ID===edit.dataset.id));return}
  if(reset){
    if(!confirm(`Generate a new temporary password for ${reset.dataset.username}? Any active session for this user will be signed out.`))return;
    try{
      const res=await api(`/users/${encodeURIComponent(reset.dataset.id)}/reset-password`,{method:'POST'});
      prompt(`Temporary password for ${reset.dataset.username} (shown once — copy it now, it cannot be retrieved again). The user must change it at next login.`,res.TemporaryPassword);
    }catch(err){alert(err.parsed?.error||err.message)}
    return;
  }
  if(del){
    if(!confirm('Delete this user? This cannot be undone.'))return;
    try{await api(`/users/${encodeURIComponent(del.dataset.id)}`,{method:'DELETE'});refreshUsersAndRoles()}catch(err){alert(err.parsed?.error||err.message)}
  }
});

function buildCheckGrid(containerId,labels,checkedList,namePrefix){
  const container=document.getElementById(containerId);
  container.innerHTML=Object.entries(labels).map(([key,label])=>
    `<label><input type="checkbox" data-${namePrefix}="${esc(key)}" ${checkedList.includes(key)?'checked':''}> ${esc(label)}</label>`
  ).join('');
}
function readCheckGrid(containerId,attr){
  return [...document.getElementById(containerId).querySelectorAll(`input[data-${attr}]`)].filter(i=>i.checked).map(i=>i.dataset[attr]);
}
function openRoleModal(role){
  document.getElementById('role-form').reset();
  document.getElementById('role-form-error').textContent='';
  buildCheckGrid('role-form-views',TAB_LABELS,role?.Permissions?.view||[],'view');
  buildCheckGrid('role-form-actions',ACTION_LABELS,role?.Permissions?.actions||[],'action');
  if(role){
    document.getElementById('role-modal-title').textContent='Edit role';
    document.getElementById('role-form-id').value=role.ID;
    document.getElementById('role-form-id').disabled=true;
    document.getElementById('role-form-name').value=role.Name;
  }else{
    document.getElementById('role-modal-title').textContent='Add role';
    document.getElementById('role-form-id').value='';
    document.getElementById('role-form-id').disabled=false;
  }
  document.getElementById('role-modal').hidden=false;
}
document.getElementById('role-add-open').onclick=()=>openRoleModal(null);
document.getElementById('role-modal-close').onclick=()=>document.getElementById('role-modal').hidden=true;
document.getElementById('role-form-cancel').onclick=()=>document.getElementById('role-modal').hidden=true;
document.getElementById('role-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const errEl=document.getElementById('role-form-error');errEl.textContent='';
  try{
    await api('/roles',{method:'PUT',body:JSON.stringify({
      id:document.getElementById('role-form-id').value.trim(),
      name:document.getElementById('role-form-name').value.trim(),
      permissions:{view:readCheckGrid('role-form-views','view'),actions:readCheckGrid('role-form-actions','action')},
    })});
    document.getElementById('role-modal').hidden=true;
    refreshUsersAndRoles();
  }catch(err){errEl.textContent=err.parsed?.error||err.message}
});
document.querySelector('#table-roles tbody').addEventListener('click',async e=>{
  const edit=e.target.closest('.role-edit'),del=e.target.closest('.role-delete');
  if(edit){openRoleModal(roles.find(r=>r.ID===edit.dataset.id));return}
  if(del){
    if(!confirm('Delete this role? Users must be reassigned first.'))return;
    try{await api(`/roles/${encodeURIComponent(del.dataset.id)}`,{method:'DELETE'});refreshUsersAndRoles()}catch(err){alert(err.parsed?.error||err.message)}
  }
});

boot();


function renderBackups(){const tbody=document.querySelector('#table-backups tbody');if(!tbody)return;tbody.innerHTML=(backups||[]).map(b=>`<tr><td>${time(b.created_at)}</td><td>${esc(b.name)}</td><td>${esc(b.kind)}</td><td>${Math.round((b.size_bytes||0)/1024)} KB</td><td title="${esc(b.sha256)}"><code>${esc((b.sha256||'').slice(0,16))}…</code></td><td><button class="secondary-btn backup-download" data-id="${esc(b.id)}" data-name="${esc(b.name)}">Download</button> <button class="danger-btn backup-delete" data-id="${esc(b.id)}">Delete</button></td></tr>`).join('')}
async function destructive(scope,operation,sensorIDs=[]){const confirmation=prompt(`This cannot be undone. Type RESET to continue with ${scope} ${operation}.`);if(confirmation!=='RESET')return;await api('/data/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope,operation,sensor_ids:sensorIDs,confirmation})});alert(scope==='sensors'?'Reset command queued':'Reset completed');refreshAll()}
document.getElementById('data-backup-central').onclick=async()=>{try{await api('/data/backups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:'central',name:document.getElementById('data-backup-name').value})});refreshAll()}catch(e){alert(e.message)}};
document.getElementById('data-backup-sensors').onclick=async()=>{const ids=sensorSelection();if(!ids.length){alert('Select sensors in the Sensors tab first');return}try{await api('/data/backups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:'sensors',sensor_ids:ids,name:document.getElementById('data-backup-name').value})});alert('Sensor backup commands queued')}catch(e){alert(e.message)}};
document.getElementById('data-reset-central').onclick=()=>destructive('central',document.getElementById('data-central-operation').value);
const sensorResetOperationLabels={database:'SQLite database',learning:'Learning state',assets:'Assets and flows',alerts:'Alerts',tags:'OT tags',analysis:'Analysis cache',factory:'Factory data reset'};const sensorResetSelection=new Set();
function sensorResetID(sensor){return String(sensor.id??sensor.ID??'')}
function sensorResetSelectedIDs(){return [...sensorResetSelection]}
function filteredResetSensors(){const q=document.getElementById('sensor-reset-search').value.trim().toLowerCase();return (sensors||[]).filter(sensor=>!q||[sensorResetID(sensor),sensor.name??sensor.Name,sensor.site_id??sensor.SiteID,sensor.hostname??sensor.Hostname].some(v=>String(v??'').toLowerCase().includes(q)))}
function updateSensorResetState(){const visible=filteredResetSensors(),visibleIDs=new Set(visible.map(sensorResetID)),selected=sensorResetSelectedIDs(),selectedVisible=selected.filter(id=>visibleIDs.has(id));const all=document.getElementById('sensor-reset-select-all'),confirmation=document.getElementById('sensor-reset-confirmation').value;all.checked=visible.length>0&&selectedVisible.length===visible.length;all.indeterminate=selectedVisible.length>0&&selectedVisible.length<visible.length;document.getElementById('sensor-reset-count').textContent=`${selected.length} sensor${selected.length===1?'':'s'} selected`;document.getElementById('sensor-reset-submit').disabled=!selected.length||confirmation!=='RESET'}
function renderSensorResetList(){const selected=sensorResetSelection,list=document.getElementById('sensor-reset-list'),rows=filteredResetSensors();list.innerHTML=rows.length?rows.map(sensor=>{const id=sensorResetID(sensor),name=sensor.name??sensor.Name??id,site=sensor.site_id??sensor.SiteID??'—',host=sensor.hostname??sensor.Hostname??'—',status=String(sensor.status??sensor.Status??'unknown').toLowerCase();return `<label class="sensor-reset-row"><input class="sensor-reset-check" type="checkbox" data-id="${esc(id)}" ${selected.has(id)?'checked':''}><span class="sensor-reset-row-name">${esc(name)}<br><small>${esc(id)}</small></span><span class="sensor-reset-row-meta sensor-reset-site">Site: ${esc(site)}</span><span class="sensor-reset-row-meta sensor-reset-host">${esc(host)}</span><span class="sensor-state sensor-state-${esc(status)}">${esc(status)}</span></label>`}).join(''):'<div class="sensor-reset-empty">No sensors match this filter.</div>';updateSensorResetState()}
function openSensorResetModal(){const operation=document.getElementById('data-sensor-operation').value;sensorResetSelection.clear();sensorSelection().forEach(id=>sensorResetSelection.add(id));document.getElementById('sensor-reset-operation-label').textContent=sensorResetOperationLabels[operation]||operation;document.getElementById('sensor-reset-search').value='';document.getElementById('sensor-reset-confirmation').value='';document.getElementById('sensor-reset-error').textContent='';document.getElementById('sensor-reset-modal').hidden=false;renderSensorResetList();document.getElementById('sensor-reset-search').focus()}
function closeSensorResetModal(){document.getElementById('sensor-reset-modal').hidden=true}
document.getElementById('data-reset-sensors').onclick=openSensorResetModal;
document.getElementById('sensor-reset-modal-close').onclick=closeSensorResetModal;
document.getElementById('sensor-reset-cancel').onclick=closeSensorResetModal;
document.getElementById('sensor-reset-search').oninput=()=>renderSensorResetList();
document.getElementById('sensor-reset-list').onchange=e=>{if(e.target.matches('.sensor-reset-check')){e.target.checked?sensorResetSelection.add(e.target.dataset.id):sensorResetSelection.delete(e.target.dataset.id);updateSensorResetState()}};
document.getElementById('sensor-reset-select-all').onchange=e=>{filteredResetSensors().map(sensorResetID).forEach(id=>e.target.checked?sensorResetSelection.add(id):sensorResetSelection.delete(id));renderSensorResetList()};
document.getElementById('sensor-reset-confirmation').oninput=updateSensorResetState;
document.getElementById('sensor-reset-submit').onclick=async()=>{const ids=sensorResetSelectedIDs(),operation=document.getElementById('data-sensor-operation').value,confirmation=document.getElementById('sensor-reset-confirmation').value,error=document.getElementById('sensor-reset-error'),button=document.getElementById('sensor-reset-submit');if(!ids.length||confirmation!=='RESET')return;button.disabled=true;error.textContent='';try{await api('/data/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:'sensors',operation,sensor_ids:ids,confirmation})});closeSensorResetModal();alert(`Reset command queued for ${ids.length} sensor${ids.length===1?'':'s'}`);refreshAll()}catch(err){error.textContent=err.message;updateSensorResetState()}};
document.getElementById('sensor-reset-modal').addEventListener('click',e=>{if(e.target.id==='sensor-reset-modal')closeSensorResetModal()});document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!document.getElementById('sensor-reset-modal').hidden)closeSensorResetModal()});
document.querySelector('#table-backups tbody').onclick=async e=>{const dl=e.target.closest('.backup-download'),b=e.target.closest('.backup-delete');if(dl){const r=await fetch('/v1/data/backups/'+encodeURIComponent(dl.dataset.id)+'/download',{credentials:'include'});if(!r.ok){alert(await r.text());return}const blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=(dl.dataset.name||'otlens-backup')+'.json';a.click();URL.revokeObjectURL(a.href);return}if(!b)return;if(!confirm('Delete this backup?'))return;try{await api('/data/backups/'+encodeURIComponent(b.dataset.id),{method:'DELETE'});refreshAll()}catch(err){alert(err.message)}};

async function tagAssetInfected(sensor,ip){
  const reason=prompt('Reason for infection/suspicion tag:','Analyst confirmed malware infection');if(reason===null)return;
  const status=confirm('Mark as confirmed INFECTED? Cancel marks it SUSPECTED.')?'infected':'suspected';
  try{const out=await api(`/sensors/${encodeURIComponent(sensor)}/assets/${encodeURIComponent(ip)}/security-status`,{method:'PUT',body:JSON.stringify({status,reason,source:'manual',detected_at:new Date().toISOString(),auto_trace:true,lookback_hours:24,max_hops:2})});const count=out&&out.incident&&out.incident.exposures?out.incident.exposures.length:0;alert(`Asset tagged ${status}. Contact trace created with ${count} exposed assets.`);await refreshAll()}catch(e){alert('Failed to tag asset: '+e.message)}
}

// Observed IT→OT attack paths and Purdue overlay. These use directional
// flow_observations only; they do not claim firewall/ACL reachability.
function populateITOTSensorList(){
  const sel=document.getElementById('itot-sensor');if(!sel)return;
  const previous=sel.value;sel.innerHTML=sensors.map(s=>{const id=s.id??s.ID;return `<option value="${esc(id)}">${esc(s.name??s.Name??id)} (${esc(id)})</option>`}).join('');
  if(previous&&[...sel.options].some(o=>o.value===previous))sel.value=previous;
}
function purdueLabel(level){const n=Number(level);return n===5?'External / cloud':n===4?'Enterprise IT':n===3.5?'Industrial DMZ':n===3?'Site operations':n===2?'Supervisory control':n===1?'Basic control':n===0?'Process':'Unclassified'}
function suggestedPurdue(n){const role=String(n.asset_role||'').toLowerCase(),p=(n.protocols||[]).join(' ').toLowerCase(),vendor=String(n.vendor||'').toLowerCase();if(/sensor|actuator|instrument/.test(role))return{level:0,confidence:86,reason:'field device role'};if(/plc|rtu|drive|controller/.test(role)||/s7|modbus|ethernet\/ip|dnp3/.test(p))return{level:1,confidence:92,reason:'controller or control protocol'};if(/hmi|scada|operator/.test(role))return{level:2,confidence:88,reason:'supervisory role'};if(/historian|engineering|opc/.test(role+' '+p))return{level:3,confidence:78,reason:'site operations service'};if(/firewall|proxy|jump/.test(role))return{level:3.5,confidence:70,reason:'boundary infrastructure'};if(/erp|domain|email|enterprise/.test(role))return{level:4,confidence:72,reason:'enterprise role'};if(/siemens|rockwell|schneider|abb|honeywell/.test(vendor))return{level:1,confidence:62,reason:'industrial vendor'};return null}
function renderPurdueArchitecture(){const r=purdueTopologyData||{nodes:[],edges:[]},nodes=r.nodes||[],groups=new Map(),showUnknown=document.getElementById('purdue-show-unclassified')?.checked;for(const n of nodes){const key=n.purdue_level==null?'unclassified':String(n.purdue_level);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(n)}const classified=nodes.filter(n=>n.purdue_level!=null).length,unknown=nodes.length-classified,suggestions=nodes.filter(n=>n.purdue_level==null).map(n=>({node:n,s:suggestedPurdue(n)})).filter(x=>x.s);document.getElementById('purdue-coverage').textContent=nodes.length?Math.round(classified/nodes.length*100)+'%':'0%';document.getElementById('purdue-classified').textContent=classified;document.getElementById('purdue-unclassified').textContent=unknown;document.getElementById('purdue-suggested').textContent=suggestions.length;const order=['5','4','3.5','3','2','1','0'];document.getElementById('purdue-levels').innerHTML=order.map(k=>{const list=groups.get(k)||[];return `<section class="purdue-band level-${k.replace('.','-')}"><header><span><b>Level ${k}</b> · ${purdueLabel(k)}</span><em>${list.length} assets</em></header><div class="purdue-band-assets">${list.map(n=>`<button class="purdue-node" data-ip="${esc(n.ip)}" title="${esc(n.asset_role||'unknown')} · ${esc(n.purdue_source||'unknown source')}"><b>${esc(n.hostname||n.ip)}</b><small>${esc(n.asset_role||n.vendor||'unknown')}</small></button>`).join('')||'<span class="purdue-empty">No classified assets</span>'}</div></section>`}).join('')+`<section class="purdue-band unclassified"><header><span><b>Unclassified</b> · classification backlog</span><em>${unknown} assets</em></header><div class="purdue-band-assets ${showUnknown?'':'collapsed'}">${showUnknown?(groups.get('unclassified')||[]).map(n=>`<button class="purdue-node" data-ip="${esc(n.ip)}"><b>${esc(n.hostname||n.ip)}</b><small>${esc(n.asset_role||n.vendor||'unknown')}</small></button>`).join(''):`<button id="purdue-expand-unknown" class="secondary-btn">Show ${unknown} assets</button>`}</div></section>`;document.getElementById('purdue-coverage-list').innerHTML=order.map(k=>`<div class="coverage-row"><span>L${k}</span><progress max="${Math.max(nodes.length,1)}" value="${(groups.get(k)||[]).length}"></progress><b>${(groups.get(k)||[]).length}</b></div>`).join('')+`<div class="coverage-row"><span>Unknown</span><progress max="${Math.max(nodes.length,1)}" value="${unknown}"></progress><b>${unknown}</b></div>`;document.getElementById('purdue-suggestions').innerHTML=suggestions.slice(0,20).map(x=>`<div class="purdue-suggestion"><b>${esc(x.node.hostname||x.node.ip)}</b><span>Suggested L${x.s.level} · ${x.s.confidence}%</span><small>${esc(x.s.reason)}</small><button class="secondary-btn purdue-accept" data-ip="${esc(x.node.ip)}" data-level="${x.s.level}">Accept</button></div>`).join('')||'<div class="placeholder">No automatic suggestions available.</div>';document.getElementById('purdue-status').textContent=`${nodes.length} assets · ${classified} classified`}
async function loadPurdueArchitecture(){const sensor=document.getElementById('purdue-sensor')?.value||document.getElementById('itot-sensor')?.value,status=document.getElementById('purdue-status');if(!sensor){if(status)status.textContent='Select a sensor';return}try{purdueTopologyData=await api(`/sensors/${encodeURIComponent(sensor)}/purdue-topology`);renderPurdueArchitecture()}catch(e){status.textContent='Failed: '+e.message}}
async function editAssetContext(sensor,ip,acceptedLevel){const role=prompt('Asset role (PLC, HMI, historian, engineering workstation, server, firewall, …):','');if(role===null)return;const criticality=prompt('Criticality (low, medium, high, critical):','medium');if(criticality===null)return;const zone=prompt('Zone / cell name:','');if(zone===null)return;let purdueRaw=acceptedLevel==null?prompt('Per-asset Purdue override (0, 1, 2, 3, 3.5, 4, 5). Leave empty to use VLAN mapping.',''):String(acceptedLevel);if(purdueRaw===null)return;const purdue_override=purdueRaw.trim()===''?null:Number(purdueRaw);if(purdue_override!==null&&!Number.isFinite(purdue_override)){alert('Invalid Purdue level');return}await api(`/sensors/${encodeURIComponent(sensor)}/assets/${encodeURIComponent(ip)}/context`,{method:'PUT',body:JSON.stringify({asset_role:role.trim(),criticality:criticality.trim(),zone:zone.trim(),purdue_override,is_attack_path_entry:false,is_attack_path_target:false})});await loadPurdueArchitecture();await refreshAll()}
async function runITOTPaths(){const sensor=document.getElementById('itot-sensor').value,source=document.getElementById('itot-source').value.trim(),hours=Number(document.getElementById('itot-lookback').value||24),hops=Number(document.getElementById('itot-hops').value||4),status=document.getElementById('itot-status'),box=document.getElementById('itot-results');if(!sensor||!source){status.textContent='Select a sensor and source asset';return}status.textContent='Searching…';try{const r=await api(`/sensors/${encodeURIComponent(sensor)}/itot-paths?source_ip=${encodeURIComponent(source)}&lookback_hours=${encodeURIComponent(hours)}&max_hops=${encodeURIComponent(hops)}`);box.innerHTML=(r.paths||[]).map((p,i)=>{const chain=[];(p.nodes||[]).forEach((n,idx)=>{if(idx)chain.push(` →[${esc(p.edges[idx-1]?.protocol||'IP')}/${esc(p.edges[idx-1]?.responder_port||0)}]→ `);chain.push(`<b>${esc(n.hostname||n.ip)}</b> (L${n.purdue_level==null?'?':esc(n.purdue_level)}, ${esc(n.asset_role||'unknown')})`)});return `<div class="itot-path"><div><b>Path ${i+1}</b>${p.bypasses_dmz?' <span class="severity critical">DMZ bypass</span>':''}</div><div class="itot-path-chain">${chain.join('')}</div><div class="itot-path-meta"><span>Path risk: <b>${esc(p.path_risk_score)}</b></span><span>Confidence: <b>${esc(p.path_confidence)}</b></span><span>${esc((p.reasons||[]).join(' · '))}</span></div></div>`}).join('')||'<div class="placeholder">No observed directional path from this asset to an OT target in the selected time window.</div>';status.textContent=`${(r.paths||[]).length} paths found`;}catch(e){status.textContent='Failed: '+e.message}}
async function applyTopologyColourMode(mode){topologyColourMode=mode;if(mode==='purdue'){const levelByAsset=new Map();await Promise.all(sensors.map(async x=>{const id=x.ID||x.id;try{const r=await api(`/sensors/${encodeURIComponent(id)}/purdue-topology`);for(const n of r.nodes||[])levelByAsset.set(id+'::'+n.ip,n.purdue_level)}catch(_){}}));for(const n of graph.Nodes||[])n.PurdueLevel=levelByAsset.get(n.SensorID+'::'+n.IP)??null}topologyNodeSigCache.clear();renderTopology()}
document.getElementById('itot-run')?.addEventListener('click',runITOTPaths);document.getElementById('topology-colour-mode')?.addEventListener('change',e=>applyTopologyColourMode(e.target.value));document.getElementById('purdue-refresh')?.addEventListener('click',loadPurdueArchitecture);document.getElementById('purdue-sensor')?.addEventListener('change',loadPurdueArchitecture);document.getElementById('purdue-show-unclassified')?.addEventListener('change',renderPurdueArchitecture);document.getElementById('purdue-levels')?.addEventListener('click',e=>{if(e.target.closest('#purdue-expand-unknown')){document.getElementById('purdue-show-unclassified').checked=true;renderPurdueArchitecture();return}const x=e.target.closest('.purdue-node');if(x)editAssetContext(document.getElementById('purdue-sensor').value,x.dataset.ip).catch(err=>alert(err.parsed?.error||err.message))});document.getElementById('purdue-suggestions')?.addEventListener('click',e=>{const x=e.target.closest('.purdue-accept');if(x)editAssetContext(document.getElementById('purdue-sensor').value,x.dataset.ip,x.dataset.level).catch(err=>alert(err.parsed?.error||err.message))});

document.getElementById('ti-filter')?.addEventListener('input',renderThreatIntel);document.getElementById('ti-type')?.addEventListener('change',renderThreatIntel);document.getElementById('ti-source-form')?.addEventListener('submit',async e=>{e.preventDefault();try{await api('/threat-intel/sources',{method:'POST',body:JSON.stringify({name:document.getElementById('ti-source-name').value,url:document.getElementById('ti-source-url').value,source_type:'url',format:document.getElementById('ti-source-format').value,indicator_type:document.getElementById('ti-source-indicator-type').value,default_confidence:Number(document.getElementById('ti-source-confidence').value||70),refresh_interval_seconds:Number(document.getElementById('ti-source-refresh').value||60)*60,enabled:true})});e.target.reset();document.getElementById('ti-source-confidence').value=70;document.getElementById('ti-source-refresh').value=60;await loadThreatIntelManagement()}catch(err){alert(err.message)}});
document.getElementById('ti-import-submit')?.addEventListener('click',async()=>{const f=document.getElementById('ti-import-file').files[0];if(!f){alert('Select a CSV or JSON file first.');return}const fd=new FormData();fd.append('file',f);fd.append('source',document.getElementById('ti-import-source').value||f.name);try{const out=await api('/threat-intel/import',{method:'POST',body:fd});document.getElementById('ti-source-status').textContent=`Imported ${out.accepted}, rejected ${out.rejected}`;await loadThreatIntelManagement()}catch(e){alert(e.message)}});
document.getElementById('ti-add-manual')?.addEventListener('click',async()=>{const value=prompt('Indicator value (IP or domain):');if(!value)return;const type=prompt('Type (ip or domain):',value.includes(':')||/^\d+\./.test(value)?'ip':'domain');if(!type)return;const threat=prompt('Threat type (c2, malware, phishing, ...):','malware')||'';const confidence=Number(prompt('Confidence 1-100:','80')||80);try{await api('/threat-intel/indicators',{method:'POST',body:JSON.stringify({type,value,threat_type:threat,confidence})});await loadThreatIntelManagement()}catch(e){alert(e.message)}});
document.getElementById('view-threatintel')?.addEventListener('click',async e=>{const refresh=e.target.closest('.ti-refresh-source'),delSource=e.target.closest('.ti-delete-source'),delIndicator=e.target.closest('.ti-delete-indicator');try{if(refresh){await api(`/threat-intel/sources/${refresh.dataset.id}/refresh`,{method:'POST'});await loadThreatIntelManagement()}else if(delSource&&confirm('Delete this feed and all indicators imported from it?')){await api(`/threat-intel/sources/${delSource.dataset.id}`,{method:'DELETE'});await loadThreatIntelManagement()}else if(delIndicator&&confirm('Delete this indicator?')){await api(`/threat-intel/indicators/${delIndicator.dataset.id}`,{method:'DELETE'});await loadThreatIntelManagement()}}catch(err){alert(err.message)}});
document.getElementById('dns-filter')?.addEventListener('input',renderDNS);document.getElementById('dns-sensor')?.addEventListener('change',renderDNS);document.getElementById('dns-refresh')?.addEventListener('click',loadDNS);document.getElementById('smb-filter')?.addEventListener('input',renderSMB);document.getElementById('smb-risk')?.addEventListener('change',renderSMB);document.getElementById('smb-refresh')?.addEventListener('click',loadSMB);

document.querySelector('#table-sensors tbody').addEventListener('click',e=>{if(e.target.closest('input,button'))return;const row=e.target.closest('.sensor-row');if(row)openSensorMetrics(row.dataset.id)});document.querySelector('#table-health tbody').addEventListener('click',e=>{const row=e.target.closest('.health-row');if(row)openSensorMetrics(row.dataset.id)});document.getElementById('sensor-metrics-close').onclick=()=>document.getElementById('sensor-metrics-modal').hidden=true;document.getElementById('sensor-metrics-range').onchange=loadSensorMetricHistory;document.getElementById('health-refresh').onclick=loadHealthcheck;window.addEventListener('resize',()=>{if(!document.getElementById('sensor-metrics-modal').hidden)loadSensorMetricHistory();renderDashboard()});

let reconnaissanceJobs=[];
let reconnaissanceCredentials=[];
let activeAssetDetail=null;
function reconValue(a,name){return a[name]??a['Recon'+name]??a[name[0].toUpperCase()+name.slice(1)]??''}
function renderRecon(){
  const jobs=reconnaissanceJobs||[], completed=jobs.filter(j=>['completed','partially_completed'].includes(j.status)).length, failed=jobs.filter(j=>j.status==='failed').length, active=jobs.filter(j=>['queued','running'].includes(j.status)).length;
  const profiled=(assets||[]).filter(a=>a.LastProfiledAt||a.ReconHostname||a.ReconVendor||a.ReconOS).length;
  const waiting=(assets||[]).filter(a=>!String(a.Hostname||a.ReconHostname||'').trim()||!String(a.Vendor||a.ReconVendor||'').trim()||!String(a.ReconOS||'').trim());
  const k=document.getElementById('recon-kpis');if(k)k.innerHTML=[['Profiled assets',profiled,'overview'],['Waiting for identity',waiting.length,'waiting'],['Queued / running',active,'jobs'],['Completed jobs',completed,'jobs'],['Failed jobs',failed,'jobs']].map(x=>`<button class="kpi-card" data-recon-open="${x[2]}"><span>${x[0]}</span><strong>${x[1]}</strong><small>Click to inspect</small></button>`).join('');
  const body=document.querySelector('#table-recon tbody');if(body)body.innerHTML=jobs.map(j=>{const rr=j.results||[];const identity=rr.map(x=>[x.hostname,x.vendor,x.model,x.os,x.firmware].filter(Boolean).join(' / ')).filter(Boolean);const services=rr.flatMap(x=>(x.services||[]).map(s=>`${x.target}:${s.port} ${s.service}${s.product?' '+s.product:''}`));return `<tr class="recon-job-row" data-job="${esc(j.id)}"><td>${time(j.created_at)}</td><td>${esc(j.profile)}</td><td>${esc(j.sensor_id)}</td><td><span class="sensor-state sensor-state-${esc(j.status)}">${esc(j.status)}</span></td><td>${esc((j.targets||[]).join(', '))}</td><td>${esc(identity.join(', ')||'—')}</td><td title="${esc(services.join('\n'))}">${esc(services.slice(0,5).join(', ')||'—')}${services.length>5?' …':''}</td><td>${esc(j.error||rr.map(x=>x.error).filter(Boolean).join('; ')||'—')}</td></tr>`}).join('');
  const wb=document.querySelector('#table-recon-waiting tbody');if(wb)wb.innerHTML=waiting.map(a=>{const h=a.Hostname||a.ReconHostname||'',v=a.Vendor||a.ReconVendor||'',o=a.ReconOS||'',miss=[!h&&'hostname',!v&&'vendor',!o&&'OS'].filter(Boolean);return `<tr><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(h||'Unknown')}</td><td>${esc(v||'Unknown')}</td><td>${esc(o||'Unknown')}</td><td>${miss.map(x=>`<span class="pill severity-medium">${x}</span>`).join(' ')}</td><td><button class="ack-btn recon-one" data-sensor="${esc(a.SensorID)}" data-ip="${esc(a.IP)}">Run safe discovery</button></td></tr>`}).join('');
  dashboardBars('recon-completeness',[['Hostname',(assets||[]).filter(a=>a.Hostname||a.ReconHostname).length],['Vendor',(assets||[]).filter(a=>a.Vendor||a.ReconVendor).length],['OS',(assets||[]).filter(a=>a.ReconOS).length],['Model',(assets||[]).filter(a=>a.ReconModel).length],['Firmware',(assets||[]).filter(a=>a.ReconFirmware).length]],Math.max(1,(assets||[]).length));
  const counts=new Map();jobs.forEach(j=>counts.set(j.status,(counts.get(j.status)||0)+1));dashboardBars('recon-job-status',[...counts.entries()],Math.max(1,...counts.values()));
  const recent=document.getElementById('recon-recent');if(recent)recent.innerHTML=jobs.slice(0,7).map(j=>`<div class="activity-item"><span class="activity-time">${time(j.created_at)}</span><span class="activity-sensor">${esc(j.sensor_id)}</span><span class="activity-message"><span class="sensor-state sensor-state-${esc(j.status)}">${esc(j.status)}</span> ${esc(j.profile)} · ${(j.targets||[]).length} target(s)</span></div>`).join('')||'<div class="empty-dashboard">No reconnaissance jobs</div>';
}
async function loadRecon(){try{[reconnaissanceJobs,reconnaissanceCredentials]=await Promise.all([api('/reconnaissance/jobs'),api('/reconnaissance/credentials')]);renderRecon();renderReconCredentials();renderDashboard()}catch(e){const x=document.getElementById('recon-status');if(x)x.textContent=e.parsed?.error||e.message}}
function populateReconSensors(){const el=document.getElementById('recon-sensor');if(el)el.innerHTML=(sensors||[]).map(s=>`<option value="${esc(s.id||s.ID)}">${esc(s.name||s.Name||s.id||s.ID)}</option>`).join('')}
async function queueRecon(sensor,targets,profile='safe-discovery',options={}){
 const split=v=>String(v||'').split(/[\s,;]+/).map(x=>x.trim()).filter(Boolean), ot=[...document.querySelectorAll('#recon-ot-protocols input:checked')].map(x=>x.value),standalone=Boolean(options.standalone);
 const policy=standalone?{allowed_networks:[],denied_targets:[],ports:[22,80,443,445,3389,502,102,44818,4840,47808],packets_per_second:5,concurrent_targets:1,timeout_seconds:4,require_manual_approval:profile==='ot-conservative',ot_protocols:profile==='ot-conservative'?['modbus','ethernet-ip','s7','opcua','bacnet']:[],credential_id:'',authenticated_methods:[]}:{allowed_networks:split(document.getElementById('recon-networks')?.value),denied_targets:split(document.getElementById('recon-denied')?.value),ports:split(document.getElementById('recon-ports')?.value||'22,80,443,445,3389,502,102,44818,4840').map(Number).filter(x=>x>0&&x<65536),packets_per_second:Number(document.getElementById('recon-rate')?.value||5),concurrent_targets:1,timeout_seconds:Number(document.getElementById('recon-timeout')?.value||3),require_manual_approval:Boolean(document.getElementById('recon-manual-approval')?.checked),ot_protocols:profile==='ot-conservative'?ot:[],credential_id:profile==='authenticated-inventory'?(document.getElementById('recon-credential')?.value||''):'',authenticated_methods:profile==='authenticated-inventory'&&document.getElementById('recon-auth-ssh')?.checked?['ssh']:[]};
 return api('/reconnaissance/jobs',{method:'POST',body:JSON.stringify({sensor_id:sensor,targets,profile,policy})});
}
document.getElementById('recon-form')?.addEventListener('submit',async e=>{e.preventDefault();const status=document.getElementById('recon-status'),profile=document.getElementById('recon-profile').value;status.textContent='Queueing…';try{await queueRecon(document.getElementById('recon-sensor').value,document.getElementById('recon-targets').value.split(/[\s,;]+/).filter(Boolean),profile);status.textContent='Job queued. The sensor will execute it on its next sync.';await loadRecon()}catch(err){status.textContent=err.parsed?.error||err.message}});
document.getElementById('view-reconnaissance')?.addEventListener('click',async e=>{const tab=e.target.closest('.recon-subtab,[data-recon-open]');if(tab){const name=tab.dataset.reconPanel||tab.dataset.reconOpen;document.querySelectorAll('.recon-subtab').forEach(x=>x.classList.toggle('active',x.dataset.reconPanel===name));document.querySelectorAll('.recon-panel').forEach(x=>x.classList.toggle('active',x.dataset.reconPanelBody===name));return}const one=e.target.closest('.recon-one');if(one){try{await queueRecon(one.dataset.sensor,[one.dataset.ip]);await loadRecon()}catch(err){alert(err.parsed?.error||err.message)}}});
document.querySelector('.tab[data-tab="reconnaissance"]')?.addEventListener('click',()=>{populateReconSensors();loadRecon()});


function openReconJob(id){
  const j=(reconnaissanceJobs||[]).find(x=>x.id===id);if(!j)return;
  document.getElementById('recon-job-title').textContent=`${j.id} · ${j.profile}`;
  const results=j.results||[];
  const resultCards=results.map(x=>{
    const services=(x.services||[]).map(s=>`<tr><td>${esc(s.port)}</td><td>${esc(s.transport||'tcp')}</td><td>${esc(s.service||'unknown')}</td><td>${esc(s.product||s.banner||'—')}</td><td>${esc(s.version||'—')}</td></tr>`).join('');
    const audit=(x.audit||[]).map(a=>`<tr><td>${time(a.observed_at)}</td><td><code>${esc(a.stage)}</code></td><td><span class="sensor-state sensor-state-${esc(a.status)}">${esc(a.status)}</span></td><td>${esc(a.detail||'—')}</td></tr>`).join('');
    const evidence=(x.evidence||[]).map(e=>`<tr><td>${esc(e.field)}</td><td>${esc(e.value)}</td><td>${esc(e.source)}</td><td>${esc(e.confidence)}%</td></tr>`).join('');
    return `<section class="panel"><h3>${esc(x.target)} · ${x.reachable?'reachable':'not reached'}</h3><div class="identity-grid">${[['Hostname',x.hostname||'—'],['Vendor',x.vendor||'—'],['Model',x.model||'—'],['OS',x.os||'—'],['Firmware',x.firmware||'—'],['Error',x.error||'—']].map(v=>`<div><span>${v[0]}</span><strong>${esc(v[1])}</strong></div>`).join('')}</div><h4>Pipeline audit</h4><div class="scrollable"><table class="data-table"><thead><tr><th>Time</th><th>Stage</th><th>Status</th><th>Detail</th></tr></thead><tbody>${audit||'<tr><td colspan="4">No audit data (legacy result)</td></tr>'}</tbody></table></div><h4>Services</h4><div class="scrollable"><table class="data-table"><thead><tr><th>Port</th><th>Transport</th><th>Service</th><th>Product / banner</th><th>Version</th></tr></thead><tbody>${services||'<tr><td colspan="5">No open configured ports</td></tr>'}</tbody></table></div><h4>Evidence</h4><div class="scrollable"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Source</th><th>Confidence</th></tr></thead><tbody>${evidence||'<tr><td colspan="4">No evidence collected</td></tr>'}</tbody></table></div></section>`;
  }).join('');
  document.getElementById('recon-job-body').innerHTML=`<div class="identity-grid">${[['Sensor',j.sensor_id],['Status',j.status],['Created',time(j.created_at)],['Started',j.started_at?time(j.started_at):'—'],['Completed',j.completed_at?time(j.completed_at):'—'],['Targets',(j.targets||[]).length],['Rate',`${j.policy?.packets_per_second||'—'} probes/s`],['Timeout',`${j.policy?.timeout_seconds||'—'} s`]].map(x=>`<div><span>${x[0]}</span><strong>${esc(x[1])}</strong></div>`).join('')}</div><h3>Discovery debug</h3>${resultCards||'<div class="empty-state">No result uploaded yet. Check that the sensor is online and polling Central commands.</div>'}`;
  document.getElementById('recon-job-modal').hidden=false;
}
document.querySelector('#table-recon tbody')?.addEventListener('click',e=>{const row=e.target.closest('.recon-job-row');if(row)openReconJob(row.dataset.job)});document.getElementById('recon-job-close').onclick=()=>document.getElementById('recon-job-modal').hidden=true;
function assetRecon(a){return {hostname:a.ReconHostname||a.Hostname||'',vendor:a.ReconVendor||a.Vendor||'',os:a.ReconOS||'',model:a.ReconModel||'',firmware:a.ReconFirmware||'',serial:a.ReconSerial||'',services:a.ReconServices||[],evidence:a.ReconEvidence||[],ot:a.ReconOTIdentity||{},last:a.LastProfiledAt||''}}
function openAssetDetail(a){activeAssetDetail=a;const r=assetRecon(a),m=document.getElementById('asset-detail-modal');document.getElementById('asset-detail-title').textContent=`${a.IP} asset profile`;document.getElementById('asset-detail-subtitle').textContent=`${a.SensorID} · ${a.MAC||'no MAC'} · last seen ${time(a.LastSeen)}`;m.hidden=false;renderAssetPanel('identity')}
function formatObservedDuration(seconds){const s=Math.max(0,Math.round(Number(seconds)||0));if(s<60)return `${s}s`;if(s<3600)return `${Math.floor(s/60)}m ${s%60}s`;if(s<86400)return `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;return `${Math.floor(s/86400)}d ${Math.floor((s%86400)/3600)}h`}
async function renderAssetPanel(panel){
  if(!activeAssetDetail)return;
  const a=activeAssetDetail,r=assetRecon(a),body=document.getElementById('asset-detail-body');
  document.querySelectorAll('.asset-detail-tabs button').forEach(x=>x.classList.toggle('active',x.dataset.assetPanel===panel));
  if(panel==='identity'){
    body.innerHTML=`<div class="identity-grid">${[['Hostname',r.hostname],['Vendor',r.vendor],['Model',r.model],['Operating system',r.os],['Firmware',r.firmware],['Serial',r.serial],['Classification',a.IsOT?'OT':'IT'],['Last profiled',r.last?time(r.last):'Never']].map(x=>`<div><span>${x[0]}</span><strong>${esc(x[1]||'Unknown')}</strong></div>`).join('')}</div><h3>OT identity</h3><dl class="status-list">${Object.entries(r.ot||{}).map(([k,v])=>`<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')||'<div><dt>Status</dt><dd>No OT identity evidence</dd></div>'}</dl>`;
  }else if(panel==='services'){
    body.innerHTML=`<div class="scrollable"><table class="data-table"><thead><tr><th>Port</th><th>Transport</th><th>Service</th><th>Product</th><th>Banner / TLS</th></tr></thead><tbody>${(r.services||[]).map(x=>`<tr><td>${x.port}</td><td>${esc(x.transport)}</td><td>${esc(x.service)}</td><td>${esc(x.product||x.version||'—')}</td><td>${esc(x.banner||x.tls_subject||'—')}</td></tr>`).join('')||'<tr><td colspan="5">No active service evidence</td></tr>'}</tbody></table></div>`;
  }else if(panel==='evidence'){
    body.innerHTML=`<div class="evidence-list">${(r.evidence||[]).map(x=>`<article><div><strong>${esc(x.field)}</strong><span>${esc(x.value)}</span></div><div><span>${esc(x.source)}</span><span class="confidence">${Number(x.confidence||0)}%</span><time>${time(x.observed_at)}</time></div></article>`).join('')||'<div class="empty-dashboard">No reconnaissance evidence</div>'}</div>`;
  }else if(panel==='ip-history'){
    if(!a.MAC){body.innerHTML='<div class="empty-dashboard">IP history is unavailable because this asset has no MAC address.</div>';return}
    const sensorID=a.SensorID,mac=a.MAC;
    body.innerHTML='<div class="empty-dashboard">Loading IP history…</div>';
    try{
      const history=await api(`/sensors/${encodeURIComponent(sensorID)}/assets/${encodeURIComponent(mac)}/ip-history`);
      if(activeAssetDetail?.SensorID!==sensorID||activeAssetDetail?.MAC!==mac||!document.querySelector('[data-asset-panel="ip-history"]')?.classList.contains('active'))return;
      const rows=Array.isArray(history)?history:[];
      body.innerHTML=rows.length?`<div class="scrollable"><table class="data-table"><thead><tr><th>IP address</th><th>First seen</th><th>Last seen</th><th>Observed duration</th></tr></thead><tbody>${rows.map(h=>{const first=new Date(h.FirstSeen),last=new Date(h.LastSeen),duration=Number.isFinite(first.getTime())&&Number.isFinite(last.getTime())?formatObservedDuration(Math.max(0,(last-first)/1000)):'—';return `<tr><td><strong>${esc(h.IP)}</strong>${h.IP===a.IP?' <span class="status-pill healthy">Current</span>':''}</td><td>${time(h.FirstSeen)}</td><td>${time(h.LastSeen)}</td><td>${esc(duration)}</td></tr>`}).join('')}</tbody></table></div>`:'<div class="empty-dashboard">No recorded IP history for this asset yet.</div>';
    }catch(err){body.innerHTML=`<div class="empty-dashboard">Failed to load IP history: ${esc(err.message)}</div>`}
  }else{
    const jobs=(reconnaissanceJobs||[]).filter(j=>j.sensor_id===a.SensorID&&(j.targets||[]).includes(a.IP));
    body.innerHTML=`<div class="scrollable"><table class="data-table"><thead><tr><th>Time</th><th>Profile</th><th>Status</th><th>Hostname</th><th>Vendor / model</th><th>OS / firmware</th></tr></thead><tbody>${jobs.map(j=>{const x=(j.results||[]).find(v=>v.target===a.IP)||{};return `<tr><td>${time(j.created_at)}</td><td>${esc(j.profile)}</td><td>${esc(j.status)}</td><td>${esc(x.hostname||'—')}</td><td>${esc([x.vendor,x.model].filter(Boolean).join(' / ')||'—')}</td><td>${esc([x.os,x.firmware].filter(Boolean).join(' / ')||'—')}</td></tr>`}).join('')||'<tr><td colspan="6">No active profiling history</td></tr>'}</tbody></table></div>`;
  }
}
document.getElementById('asset-detail-close').onclick=()=>document.getElementById('asset-detail-modal').hidden=true;document.querySelector('.asset-detail-tabs').onclick=e=>{const b=e.target.closest('[data-asset-panel]');if(b)renderAssetPanel(b.dataset.assetPanel)};
async function waitForReconJob(jobID,button){for(let i=0;i<90;i++){await new Promise(r=>setTimeout(r,2000));await loadRecon();const j=(reconnaissanceJobs||[]).find(x=>x.id===jobID);if(!j)continue;button.textContent=j.status==='queued'?'Waiting for sensor…':j.status==='running'?'Discovering…':'Refreshing asset…';if(['completed','partially_completed','failed'].includes(j.status)){await refreshAll();const fresh=(assets||[]).find(x=>x.SensorID===activeAssetDetail?.SensorID&&x.IP===activeAssetDetail?.IP);if(fresh){activeAssetDetail=fresh;renderAssetPanel('identity')}button.disabled=false;button.textContent=j.status==='failed'?'Discovery failed':'Run safe discovery';return}}button.disabled=false;button.textContent='Run safe discovery';alert('Discovery is still waiting for the sensor. Check sensor connectivity and the Reconnaissance jobs view.')}
document.getElementById('asset-run-discovery').onclick=async()=>{if(!activeAssetDetail)return;const button=document.getElementById('asset-run-discovery'),existing=(reconnaissanceJobs||[]).find(j=>j.sensor_id===activeAssetDetail.SensorID&&(j.targets||[]).includes(activeAssetDetail.IP)&&['queued','running'].includes(j.status));if(existing){button.disabled=true;button.textContent=existing.status==='running'?'Discovering…':'Waiting for sensor…';waitForReconJob(existing.id,button);return}button.disabled=true;button.textContent='Queueing…';try{const profile=(activeAssetDetail.IsOT||activeAssetDetail.Category==='OT')?'ot-conservative':'safe-discovery';const job=await queueRecon(activeAssetDetail.SensorID,[activeAssetDetail.IP],profile,{standalone:true});button.textContent='Waiting for sensor…';waitForReconJob(job.id,button)}catch(e){button.disabled=false;button.textContent='Run safe discovery';alert(e.parsed?.error||e.message)}};


document.getElementById('recon-credential-form')?.addEventListener('submit',async e=>{e.preventDefault();const st=document.getElementById('recon-cred-status');try{await api('/reconnaissance/credentials',{method:'POST',body:JSON.stringify({name:document.getElementById('recon-cred-name').value,type:'ssh',username:document.getElementById('recon-cred-user').value,password:document.getElementById('recon-cred-password').value,private_key:document.getElementById('recon-cred-key').value})});e.target.reset();st.textContent='Credential stored';await loadRecon()}catch(err){st.textContent=err.parsed?.error||err.message}});
document.getElementById('table-recon-credentials')?.addEventListener('click',async e=>{const b=e.target.closest('.recon-cred-delete');if(!b)return;if(!confirm('Delete this credential?'))return;try{await api('/reconnaissance/credentials/'+encodeURIComponent(b.dataset.id),{method:'DELETE'});await loadRecon()}catch(err){alert(err.parsed?.error||err.message)}});

// Task-oriented sidebar navigation. Group state is local UI preference only.
const NAV_SECTIONS={dashboard:'Overview',topology:'Network & architecture',purdue:'Network & architecture',segmentation:'Network & architecture',assets:'Assets & inventory',devices:'Assets & inventory',tags:'Assets & inventory',vulnerabilities:'Assets & inventory',reconnaissance:'Assets & inventory',alerts:'Detection & response',incidents:'Detection & response',rules:'Detection & response',threatintel:'Detection & response',dns:'Investigation',smb:'Investigation',analysis:'Investigation',reports:'Investigation',sensors:'Operations',health:'Operations',data:'Operations',users:'Administration',settings:'Administration',audit:'Administration'};
function updateNavigationContext(tab,button){
  document.getElementById('current-section').textContent=NAV_SECTIONS[tab]||'OTLens';
  document.getElementById('current-page').textContent=(button?.textContent||TAB_LABELS[tab]||tab).trim().replace(/\s+\d+$/,'');
  const group=button?.closest('.nav-group');
  if(group&&!group.classList.contains('open')){group.classList.add('open');group.querySelector('.nav-group-toggle')?.setAttribute('aria-expanded','true')}
  try{localStorage.setItem('otlens.lastTab',tab)}catch(_){ }
  document.body.classList.remove('sidebar-open');
}
function refreshNavigationGroups(){
  const query=(document.getElementById('nav-filter')?.value||'').trim().toLowerCase();let any=false;
  document.querySelectorAll('.nav-group').forEach(group=>{
    let visible=0;group.querySelectorAll('.tab').forEach(tab=>{const allowed=!tab.hidden,match=!query||tab.textContent.toLowerCase().includes(query);tab.classList.toggle('nav-filter-hidden',!(allowed&&match));if(allowed&&match)visible++});
    group.classList.toggle('nav-filter-hidden',visible===0);if(query&&visible){group.classList.add('open');group.querySelector('.nav-group-toggle')?.setAttribute('aria-expanded','true')}if(visible)any=true;
  });
  const home=document.querySelector('.nav-home');if(home){const show=!home.hidden&&(!query||home.textContent.toLowerCase().includes(query));home.classList.toggle('nav-filter-hidden',!show);if(show)any=true}
  const empty=document.getElementById('nav-empty');if(empty)empty.hidden=any;
}
document.querySelector('.tabs')?.addEventListener('click',e=>{
  const toggle=e.target.closest('.nav-group-toggle');if(toggle){const group=toggle.closest('.nav-group'),open=group.classList.toggle('open');toggle.setAttribute('aria-expanded',String(open));try{localStorage.setItem(`otlens.nav.${group.dataset.navGroup}`,open?'1':'0')}catch(_){ }return}
  const tab=e.target.closest('.tab');if(tab)updateNavigationContext(tab.dataset.tab,tab);
});
document.querySelectorAll('.nav-group').forEach(group=>{try{const saved=localStorage.getItem(`otlens.nav.${group.dataset.navGroup}`);if(saved!==null){group.classList.toggle('open',saved==='1');group.querySelector('.nav-group-toggle')?.setAttribute('aria-expanded',String(saved==='1'))}}catch(_){}});
document.getElementById('nav-filter')?.addEventListener('input',refreshNavigationGroups);
document.getElementById('sidebar-toggle')?.addEventListener('click',()=>document.body.classList.toggle('sidebar-open'));
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.body.classList.remove('sidebar-open');if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();document.getElementById('nav-filter')?.focus()}});

function downloadTextFile(name,text,type='text/csv'){
  const blob=new Blob([text],{type:`${type};charset=utf-8`}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0);
}
document.getElementById('devices-template')?.addEventListener('click',()=>downloadTextFile('otlens-assets-template.csv','mac,category,name\n00:11:22:33:44:55,PLC/RTU,PLC-Line-1\n'));
document.getElementById('tags-template')?.addEventListener('click',()=>downloadTextFile('otlens-tags-template.csv','device_ip,device_port,protocol,address_space,address,name,operation\n10.20.1.10,502,Modbus,holding_register,120,Tank level,read\n'));

// Restore the last page after authentication when the role still permits it.
window.addEventListener('load',()=>{setTimeout(()=>{refreshNavigationGroups();const active=document.querySelector('.tab.active');if(active)updateNavigationContext(active.dataset.tab,active)},0)});
