const POLL=10000;let graph={Nodes:[],Edges:[]},assets=[],tags=[],alerts=[],rules=[],sensors=[],baselines=[],changes=[],events=[],analysisJobs=[],backups=[],settings={},users=[],roles=[];let network,nodesDS,edgesDS;let topologySettling=false;const topologyPositionCache=new Map();const selected=new Set();
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
  return{unchanged:false,value:await r.json()};
}
const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));const val=v=>typeof v==='object'?JSON.stringify(v):v??'—';const time=v=>v?new Date(v).toLocaleString():'—';
async function api(path,opt={}){const h={'Content-Type':'application/json',...(opt.headers||{})};let r;try{r=await fetch('/v1'+path,{...opt,headers:h,credentials:'include'})}catch(cause){const e=new Error('network error');e.kind='network';e.cause=cause;throw e}if(!r.ok){const body=await r.text();const e=new Error(r.status+' '+body);e.status=r.status;e.body=body;try{e.parsed=JSON.parse(body)}catch(_){}throw e}return r.status===204||r.status===202?null:r.json()}
function setConn(ok,t){document.getElementById('conn-dot').className='dot '+(ok?'ok':'down');document.getElementById('conn-text').textContent=t}
document.querySelector('.tabs').onclick=e=>{const b=e.target.closest('.tab');if(!b)return;const enteringTopology=b.dataset.tab==='topology'&&!document.getElementById('view-topology').classList.contains('active');document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.getElementById('view-'+b.dataset.tab).classList.add('active');if(b.dataset.tab==='topology'&&network)setTimeout(()=>network.redraw(),30);if(enteringTopology)refreshAll()};
function node(n){const threshold=Number(n.HoneypotThreshold??graph.HoneypotThreshold??100),score=Number(n.Score??1),honey=n.IsHoneypot===true||score>=threshold,bad=n.Confirmed===false;return{id:n.ID,label:n.Hostname||n.IP||n.MAC,title:`Sensor: ${n.SensorID}\nIP: ${n.IP}\nMAC: ${n.MAC}\nVendor: ${n.Vendor||'—'}\nScore: ${score}/100${honey?' (honeypot)':''}\nProtocols: ${(n.Protocols||[]).join(', ')||'—'}`,font:{color:'#ffffff',strokeWidth:2,strokeColor:'#0b1220'},color:{background:honey?'#a855f7':bad?'#e85d4c':n.IsOT?'#3fbfb0':'#64748b',border:honey?'#7c3aed':bad?'#ff9f95':n.IsOT?'#2a7d74':'#334155'},size:honey?24:n.IsOT?22:16,_search:`${n.IP} ${n.MAC} ${n.Hostname} ${n.SensorID}`.toLowerCase()}}
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
  const ns=rawNodes.map(n=>{
    const item=node(n),cached=topologyPositionCache.get(item.id);
    if(cached){item.x=cached.x;item.y=cached.y}
    if(dense&&!n.IsHoneypot&&n.Confirmed!==false)item.font={...item.font,size:11};
    return item;
  }),
        ip=new Map(rawNodes.map(n=>[n.SensorID+'::'+n.IP,n.ID])),
        nodeByIP=new Map(rawNodes.map(n=>[n.SensorID+'::'+n.IP,n]));
  const es=rawEdges.map(e=>{
    const src=nodeByIP.get(e.SensorID+'::'+e.SrcIP),dst=nodeByIP.get(e.SensorID+'::'+e.DstIP),
          interVlan=!!src&&!!dst&&Number(src.VLANID||0)!==Number(dst.VLANID||0),lateral=!!e.FromHoneypot,
          label=lateral?'POTENTIAL LATERAL MOVEMENT':interVlan?`VLAN ${src.VLANID||'untagged'} → ${dst.VLANID||'untagged'}`:(!dense&&e.IsOT?e.Protocol:'');
    const flowNote=e.FlowCount>1?` (${e.FlowCount} flows aggregated, ${e.Packets||0} pkts)`:'';
    return{id:e.ID,from:ip.get(e.SensorID+'::'+e.SrcIP),to:ip.get(e.SensorID+'::'+e.DstIP),label,title:(lateral?`Potential lateral movement: honeypot ${e.SrcIP} initiated communication to ${e.DstIP}`:interVlan?'Inter-VLAN communication':e.Protocol)+flowNote,font:{color:lateral?'#ff9f95':interVlan?'#fbbf24':'#d7e1ec',strokeWidth:2,strokeColor:'#0b1220',size:dense?10:14},color:{color:lateral?'#ef4444':interVlan?'#f59e0b':e.IsOT?'#3fbfb0':'#64748b',opacity:dense&&!lateral&&!interVlan?.42:1},dashes:lateral?false:interVlan?[10,6]:false,width:lateral?5:interVlan?3:e.IsOT?2:1,arrows:lateral?'to':undefined,smooth:false}
  }).filter(e=>e.from!=null&&e.to!=null);
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
      topologySettling=false;
    });
    network.on('dragEnd',params=>{
      const ids=params.nodes&&params.nodes.length?params.nodes:nodesDS.getIds();
      const positions=network.getPositions(ids);
      Object.entries(positions).forEach(([id,p])=>topologyPositionCache.set(id,{x:p.x,y:p.y}));
    });
  }else{
    const oldIds=new Set(nodesDS.getIds()),nextIds=new Set(ns.map(n=>n.id));
    const newIds=ns.filter(n=>!oldIds.has(n.id)).map(n=>n.id);
    nodesDS.getIds().filter(id=>!nextIds.has(id)).forEach(id=>{nodesDS.remove(id);topologyPositionCache.delete(id);topologyNodeSigCache.delete(id)});
    // Only push nodes whose visible properties actually changed (or are
    // brand new). An asset that's sitting there unchanged in the database
    // between polls costs nothing here — same principle as the edge diff
    // below, and the same reasoning as the backend's fingerprint cache.
    const changedNodes=ns.filter(n=>{const sig=nodeSignature(n),same=topologyNodeSigCache.get(n.id)===sig;topologyNodeSigCache.set(n.id,sig);return!same});
    if(changedNodes.length)nodesDS.update(changedNodes);
    const edgeIds=new Set(es.map(e=>e.id));
    edgesDS.getIds().filter(id=>!edgeIds.has(id)).forEach(id=>{edgesDS.remove(id);topologyEdgeSigCache.delete(id)});
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
  applySearch();
}
function applySearch(){if(!network)return;const q=document.getElementById('topology-search-input').value.trim().toLowerCase();document.getElementById('topology-search-clear').hidden=!q;if(!q){network.unselectAll();document.getElementById('topology-search-status').textContent='';return}const ids=nodesDS.get().filter(n=>n._search.includes(q)).map(n=>n.id);network.selectNodes(ids);document.getElementById('topology-search-status').textContent=ids.length+' match(es)';if(ids.length===1)network.focus(ids[0],{scale:1.2,animation:true})}
document.getElementById('topology-search-input').oninput=applySearch;document.getElementById('topology-search-clear').onclick=()=>{document.getElementById('topology-search-input').value='';applySearch()};
function renderAssets(){const q=document.getElementById('assets-filter').value.toLowerCase(),data=assets.filter(a=>JSON.stringify(a).toLowerCase().includes(q));document.getElementById('assets-count').textContent=data.length+' assets';document.querySelector('#table-assets tbody').innerHTML=data.map(a=>`<tr class="asset-row ${a.Confirmed===false?'row-unconfirmed':''}" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" data-vendor="${esc(a.Vendor||'')}" data-ip="${esc(a.IP||'')}"><td><input class="asset-check" type="checkbox" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" ${selected.has(a.SensorID+'::'+a.MAC)?'checked':''}></td><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Vendor)}</td><td>${esc(a.Hostname)}</td><td class="${a.Confirmed===false?'state-new':'state-ok'}">${a.Confirmed===false?'NEW / UNCONFIRMED':'confirmed'}</td><td>${a.IsOT?'OT':'IT'}</td><td>${esc((a.Protocols||[]).join(', '))}</td><td>${esc(a.VLANID||'untagged')}</td><td>${esc(a.Score??1)}</td><td>${(a.IsHoneypot===true||Number(a.Score??1)>=Number(a.HoneypotThreshold??100))?'<span class="pill honeypot">HONEYPOT</span>':Number(a.Score??1)>=75?'<span class="pill severity-high">CRITICAL</span>':Number(a.Score??1)>=40?'<span class="pill severity-medium">ELEVATED</span>':'standard'}</td><td>${esc(a.PacketCount)}</td><td>${time(a.LastSeen)}</td><td>${a.Confirmed===false&&can('asset_confirm_delete')?`<button class="ack-btn confirm-one" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}">Confirm</button>`:a.Confirmed===false?'pending':'—'}</td></tr>`).join('');updateBulk()}
function updateBulk(){const on=selected.size>0;document.querySelectorAll('.bulk').forEach(b=>b.hidden=!on)}
document.getElementById('assets-filter').oninput=renderAssets;document.querySelector('#table-assets tbody').onclick=e=>{const c=e.target.closest('.asset-check');if(c){const k=c.dataset.sensor+'::'+c.dataset.mac;c.checked?selected.add(k):selected.delete(k);updateBulk();return}const b=e.target.closest('.confirm-one');if(b){sendAssetAction('confirm',[b.dataset.sensor+'::'+b.dataset.mac]);return}const row=e.target.closest('.asset-row');if(row)openAssetVulnerabilities(row.dataset.sensor,row.dataset.vendor,row.dataset.mac,row.dataset.ip)};document.getElementById('assets-all').onchange=e=>{assets.forEach(a=>e.target.checked?selected.add(a.SensorID+'::'+a.MAC):selected.delete(a.SensorID+'::'+a.MAC));renderAssets()};
async function openAssetVulnerabilities(sensor,vendor,mac,ip){
  const title=document.getElementById('vuln-modal-title'),body=document.getElementById('vuln-modal-body');
  title.textContent=`Known vulnerabilities — ${vendor||'Unknown vendor'} (${ip||mac||sensor})`;
  document.getElementById('vuln-modal').hidden=false;
  if(!vendor){body.innerHTML='<div class="empty-dashboard">No vendor identified for this device (OUI lookup found no match) — vendor-based vulnerability matching needs one.</div>';return}
  body.innerHTML='<div class="empty-dashboard">Loading…</div>';
  try{
    const r=await api('/assets/vulnerabilities?vendor='+encodeURIComponent(vendor));
    if(!r.Loaded){body.innerHTML='<div class="empty-dashboard">No vulnerability snapshot loaded on Central — set vulnerability.csv_path in central.config.yaml.</div>';return}
    const list=Array.isArray(r.Advisories)?r.Advisories:[];
    body.innerHTML=list.length?list.map(v=>`<div class="modal-history"><b>${esc(v.CVEID)}</b> <span class="severity ${esc(String(v.Severity||'').toLowerCase())}">${esc(v.Severity||'—')}</span><br>${esc(v.Title)}<br><small>${esc(v.Product||'—')} · ${esc(v.PublishedDate||'—')}</small>${v.URL?` · <a href="${esc(v.URL)}" target="_blank" rel="noopener">advisory</a>`:''}</div>`).join(''):'<div class="empty-dashboard">No known advisories for this vendor in the loaded snapshot.</div>';
  }catch(err){body.innerHTML=`<div class="empty-dashboard">Failed to load: ${esc(err.message)}</div>`}
}
document.getElementById('vuln-modal-close').onclick=()=>document.getElementById('vuln-modal').hidden=true;
async function sendAssetAction(action,keys=[...selected]){const groups={};keys.forEach(k=>{const i=k.indexOf('::'),s=k.slice(0,i),m=k.slice(i+2);(groups[s]??=[]).push(m)});for(const [s,targets] of Object.entries(groups))await api(`/sensors/${encodeURIComponent(s)}/assets/actions`,{method:'POST',body:JSON.stringify({action,targets})});selected.clear();updateBulk();setTimeout(refreshAll,1000)}document.getElementById('assets-confirm').onclick=()=>sendAssetAction('confirm');document.getElementById('assets-delete').onclick=()=>confirm('Delete selected assets?')&&sendAssetAction('delete');
function tagIdentity(t){return `${t.SensorID??''}::${t.Key||[t.DeviceIP,t.DevicePort,t.Protocol,t.AddressSpace,t.Address].join('|')}`}
function currentTags(){const byKey=new Map();for(const t of Array.isArray(tags)?tags:[])byKey.set(tagIdentity(t),t);return [...byKey.values()]}
function renderTags(){const q=document.getElementById('tags-filter').value.toLowerCase(),data=currentTags().filter(t=>JSON.stringify(t).toLowerCase().includes(q));document.getElementById('tags-count').textContent=data.length+' tags';document.querySelector('#table-tags tbody').innerHTML=data.map(t=>`<tr class="tag-row" data-sensor="${esc(t.SensorID)}" data-key="${esc(t.Key||[t.DeviceIP,t.DevicePort,t.Protocol,t.AddressSpace,t.Address].join('|'))}"><td>${esc(t.SensorID)}</td><td>${esc(t.DeviceIP)}:${esc(t.DevicePort)}</td><td>${esc(t.Protocol)}</td><td>${esc(t.AddressSpace)} ${esc(t.Address)}</td><td>${esc(t.Operation)}</td><td>${esc(val(t.LastValue))}</td><td>${esc(val(t.MinValue))}</td><td>${esc(val(t.MaxValue))}</td><td>${time(t.LastChangeAt)}</td><td>${esc(t.PollCount)}</td><td>${esc(t.ChangeCount)}</td></tr>`).join('')}
document.getElementById('tags-filter').oninput=renderTags;document.querySelector('#table-tags tbody').onclick=e=>{const r=e.target.closest('.tag-row');if(r)openTag(r.dataset.sensor,r.dataset.key)};
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
function openTag(sensor,key){const t=currentTags().find(x=>x.SensorID===sensor&&(x.Key||[x.DeviceIP,x.DevicePort,x.Protocol,x.AddressSpace,x.Address].join('|'))===key);if(!t)return;const h=(Array.isArray(changes)?changes:[]).filter(x=>x.SensorID===sensor&&x.TagKey===key).sort((a,b)=>new Date(a.Timestamp)-new Date(b.Timestamp)),ev=(Array.isArray(events)?events:[]).filter(x=>x.SensorID===sensor&&x.TagKey===key);document.getElementById('tag-modal-title').textContent=`${t.Protocol} ${t.DeviceIP} — ${t.AddressSpace} ${t.Address}`;document.getElementById('tag-modal-details').innerHTML=`<p>Current: <b>${esc(val(t.LastValue))}</b> · Previous: ${esc(val(t.PreviousValue))} · learned range: ${esc(val(t.MinValue))} … ${esc(val(t.MaxValue))}</p>`;document.getElementById('tag-history').innerHTML=h.length?h.slice().reverse().map(x=>`<div>${time(x.Timestamp)}: ${esc(val(x.OldValue))} → <b>${esc(val(x.NewValue))}</b></div>`).join(''):'No changes';document.getElementById('tag-events').innerHTML=ev.length?ev.slice().reverse().map(x=>`<div>${time(x.Timestamp)}: ${esc(x.FunctionName)} ${esc(x.SrcIP)} → ${esc(x.DstIP)}</div>`).join(''):'No control events';document.getElementById('tag-modal').hidden=false;drawChart(h)}document.getElementById('tag-modal-close').onclick=()=>document.getElementById('tag-modal').hidden=true;
const selectedAlerts=new Set();
function updateAlertBulkBar(){const count=selectedAlerts.size;document.getElementById('alerts-approve').hidden=!count;document.getElementById('alerts-confirm').hidden=!count;document.getElementById('alerts-selection-count').textContent=count?`${count} selected`:'';const selectable=alerts.filter(a=>(a.Status||'new')==='new');const all=document.getElementById('alerts-all');all.checked=selectable.length>0&&selectable.every(a=>selectedAlerts.has(`${a.SensorID}::${a.ID}`));all.indeterminate=selectable.some(a=>selectedAlerts.has(`${a.SensorID}::${a.ID}`))&&!all.checked}
function renderAlerts(){const valid=new Set(alerts.filter(a=>(a.Status||'new')==='new').map(a=>`${a.SensorID}::${a.ID}`));for(const key of [...selectedAlerts])if(!valid.has(key))selectedAlerts.delete(key);document.querySelector('#table-alerts tbody').innerHTML=alerts.map(a=>{const key=`${a.SensorID}::${a.ID}`,isNew=(a.Status||'new')==='new';return `<tr class="${isNew?'alert-new':'alert-reviewed'}"><td>${isNew?`<input type="checkbox" class="alert-select" data-key="${esc(key)}" ${selectedAlerts.has(key)?'checked':''} aria-label="Select alert ${esc(a.ID)}">`:'—'}</td><td>${esc(a.SensorID)}</td><td><span class="severity ${esc(a.Severity)}">${esc(a.Severity)}</span></td><td>${esc(a.Type)}</td><td>${esc(a.Message)}</td><td>${esc(a.IP)}</td><td>${esc(a.Count)}</td><td>${esc(a.Status)}</td><td>${time(a.LastSeen)}</td></tr>`}).join('');const n=alerts.filter(a=>(a.Status||'new')==='new').length;document.getElementById('alert-badge').textContent=n?String(n):'';updateAlertBulkBar()}
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
function updateSensorBulk(){const ids=sensorSelection(),all=document.getElementById('sensors-all'),boxes=[...document.querySelectorAll('.sensor-select')];document.getElementById('sensors-start').hidden=!ids.length;document.getElementById('sensors-stop').hidden=!ids.length;document.getElementById('sensors-selection-count').textContent=ids.length?`${ids.length} selected`:'';if(all){all.checked=boxes.length>0&&ids.length===boxes.length;all.indeterminate=ids.length>0&&ids.length<boxes.length}}
function renderSensors(){sensors=Array.isArray(sensors)?sensors:[];populateRuleSensors();populateAnalysisSensors();document.querySelector('#table-sensors tbody').innerHTML=sensors.map(s=>{const id=s.id??s.ID,status=String(s.status??s.Status??'unknown').toLowerCase();return `<tr><td><input type="checkbox" class="sensor-select" data-id="${esc(id)}" aria-label="Select sensor ${esc(id)}"></td><td>${esc(id)}</td><td>${esc(s.name??s.Name)}</td><td>${esc(s.site_id??s.SiteID)}</td><td><span class="sensor-state sensor-state-${esc(status)}">${esc(status)}</span></td><td>${esc(s.hostname??s.Hostname)}</td><td>${esc(s.version??s.Version)}</td><td>${esc(s.go_version??s.GoVersion??'—')}</td><td>${esc(s.libpcap_version??s.LibpcapVersion??'—')}</td><td>${esc(s.gopacket_version??s.GopacketVersion??'—')}</td><td>${esc(s.capture_backend??s.CaptureBackend??'—')}</td><td>${esc(s.capture_interface??s.CaptureInterface??'—')}</td><td>${esc(s.capture_snaplen??s.CaptureSnaplen??'—')}</td><td>${(s.capture_promiscuous??s.CapturePromiscuous)?'yes':'no'}</td><td>${time(s.last_heartbeat_at??s.LastHeartbeatAt??s.last_seen??s.LastSeen)}</td><td>${time(s.last_data_received_at??s.LastDataReceivedAt)}</td><td><span class="sensor-state sensor-state-${esc(String(s.sync_status??s.SyncStatus??'unknown').toLowerCase())}">${esc(s.sync_status??s.SyncStatus??'unknown')}</span></td><td>${esc(s.pending_records??s.PendingRecords??0)}</td><td title="${esc(s.last_sync_error??s.LastSyncError??'')}">${esc((s.last_sync_error??s.LastSyncError??'—').slice(0,60))}</td></tr>`}).join('');updateSensorBulk()}
async function sensorAction(action){const ids=sensorSelection();if(!ids.length)return;const verb=action==='stop'?'stop capture on':'start capture on';if(!confirm(`${verb} ${ids.length} selected sensor(s)?`))return;const start=document.getElementById('sensors-start'),stop=document.getElementById('sensors-stop');start.disabled=stop.disabled=true;try{await api('/sensors/actions',{method:'POST',body:JSON.stringify({action,sensor_ids:ids})});document.getElementById('sensors-selection-count').textContent=`${action} queued for ${ids.length} sensor(s)`;setTimeout(refreshAll,1200)}catch(err){alert(`Sensor ${action} failed: ${err.message}`)}finally{start.disabled=stop.disabled=false}}
document.querySelector('#table-sensors tbody').addEventListener('change',e=>{if(e.target.matches('.sensor-select'))updateSensorBulk()});document.getElementById('sensors-all').addEventListener('change',e=>{document.querySelectorAll('.sensor-select').forEach(x=>x.checked=e.target.checked);updateSensorBulk()});document.getElementById('sensors-start').onclick=()=>sensorAction('start');document.getElementById('sensors-stop').onclick=()=>sensorAction('stop');

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
  document.getElementById('dashboard-refresh').textContent=new Date().toLocaleTimeString();

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
}
document.getElementById('view-dashboard').addEventListener('click',e=>{const target=e.target.closest('[data-dashboard-tab]');if(target)openDashboardTab(target.dataset.dashboardTab)});

function renderBaseline(){const learning=baselines.filter(b=>b.mode==='learning'),d=document.getElementById('baseline-dot'),t=document.getElementById('baseline-text');if(learning.length){d.className='dot learning';const ends=learning.map(x=>new Date(x.learning_ends_at)).filter(x=>!isNaN(x)).sort((a,b)=>a-b)[0];t.textContent=`Learning ${learning.length}/${baselines.length}${ends?' · until '+ends.toLocaleTimeString():''} · alerts suppressed`}else{d.className='dot monitoring';t.textContent=baselines.length?'Monitoring':'No baseline data'}}
function renderSettings(){
  const onOff=v=>v?'Enabled':'Disabled';
  document.getElementById('settings-offline-after').textContent=settings.SensorOfflineAfterSeconds!=null?`${settings.SensorOfflineAfterSeconds}s of silence`:'—';
  document.getElementById('settings-check-interval').textContent=settings.SensorCheckIntervalSeconds!=null?`${settings.SensorCheckIntervalSeconds}s`:'—';
  document.getElementById('settings-siem').textContent=onOff(settings.SIEMEnabled);
  document.getElementById('settings-analysis').textContent=onOff(settings.AnalysisEnabled);
  document.getElementById('settings-vuln').textContent=settings.VulnerabilityLoaded?`Loaded — ${settings.VulnerabilityCount} advisories`:'Not loaded';
  document.getElementById('settings-web-tls').textContent=onOff(settings.WebTLSEnabled);
  document.getElementById('settings-sensor-tls').textContent=onOff(settings.SensorAPITLSEnabled);
}
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
  const pathView={'/assets':'assets','/tags':'tags','/tags/changes':'tags','/tags/events':'tags','/sensors':'sensors','/alerts':'alerts','/rules':'rules','/baseline':'dashboard','/analysis/jobs':'analysis','/data/backups':'data','/settings':'settings'};
  const paths=Object.keys(pathView).filter(p=>canView(pathView[p]));
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
  if(ok('/tags'))tags=list('/tags');
  if(ok('/sensors'))sensors=list('/sensors');
  if(ok('/alerts'))alerts=list('/alerts');
  if(ok('/rules'))rules=list('/rules').map(x=>({...x,ID:x.ID||x.id,Name:x.Name||x.name,Description:x.Description||x.description,Category:x.Category||x.category,Kind:x.Kind||x.kind,Enabled:x.Enabled??x.enabled,Severity:x.Severity||x.severity,Priority:x.Priority||x.priority,Simulation:x.Simulation??x.simulation,SimulationHits:x.SimulationHits||x.simulation_hits||0,LastSimulationHit:x.LastSimulationHit||x.last_simulation_hit,Version:x.Version||x.version,Groups:x.Groups||x.groups,GroupOperator:x.GroupOperator||x.group_operator,Actions:x.Actions||x.actions,Suppression:x.Suppression||x.suppression,Field:x.Field||x.field,Value:x.Value||x.value}));
  if(ok('/baseline'))baselines=list('/baseline');
  if(ok('/tags/changes'))changes=list('/tags/changes');
  if(ok('/tags/events'))events=list('/tags/events');
  if(ok('/analysis/jobs'))analysisJobs=list('/analysis/jobs');
  if(ok('/data/backups'))backups=list('/data/backups');
  if(ok('/settings')&&results['/settings'].value&&typeof results['/settings'].value==='object')settings=results['/settings'].value;
  // Render whenever the tab is active and the fetch didn't fail — including
  // the "unchanged" (304) case, since a freshly-opened tab or a
  // newly-arrived node still needs its first paint from whatever `graph`
  // already holds; renderTopology's own signature diff is what makes that
  // cheap when there's genuinely nothing new to draw.
  try{if(topologyActive&&topo.status==='fulfilled')renderTopology()}catch(e){console.error('render topology',e)}
  try{if(ok('/assets'))renderAssets()}catch(e){console.error('render assets',e)}
  try{if(ok('/tags'))renderTags()}catch(e){console.error('render tags',e)}
  try{if(ok('/sensors'))renderSensors()}catch(e){console.error('render sensors',e)}
  try{if(ok('/alerts'))renderAlerts()}catch(e){console.error('render alerts',e)}
  try{if(ok('/rules'))renderRules()}catch(e){console.error('render rules',e)}
  try{if(ok('/baseline'))renderBaseline()}catch(e){console.error('render baseline',e)}
  try{if(ok('/analysis/jobs'))renderAnalysis()}catch(e){console.error('render analysis',e)}try{renderBackups()}catch(e){console.error('render backups',e)}
  try{if(ok('/settings'))renderSettings()}catch(e){console.error('render settings',e)}
  try{if(canView('settings'))await refreshUsersAndRoles()}catch(e){console.error('refresh users/roles',e)}
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

const TAB_LABELS={dashboard:'Dashboard',topology:'Topology',assets:'Assets',tags:'OT Tags',rules:'Rules',alerts:'Alerts',sensors:'Sensors',analysis:'Analysis',settings:'Settings',data:'Data Management'};
const ACTION_LABELS={sensor_start_stop:'Start/stop sensors',asset_confirm_delete:'Confirm/delete assets',alert_confirm_approve:'Confirm/approve alerts',rule_manage:'Create/edit/delete rules',analysis_manage:'Upload/delete PCAP analysis',data_management:'Backups & resets',users_roles_manage:'Manage users & roles'};

// applyNavFiltering hides tab buttons the current role can't view (server
// still enforces this on every request — see requireView — this is only
// so the UI doesn't dangle buttons that would just 403).
function applyNavFiltering(){
  document.querySelectorAll('.tab').forEach(btn=>{
    btn.hidden=!canView(btn.dataset.tab);
  });
  const active=document.querySelector('.tab.active');
  if(!active||active.hidden){
    const firstVisible=document.querySelector('.tab:not([hidden])');
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
  if(u.status==='fulfilled')users=u.value||[];
  if(r.status==='fulfilled')roles=r.value||[];
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
document.getElementById('data-reset-sensors').onclick=()=>{const ids=sensorSelection();if(!ids.length){alert('Select sensors in the Sensors tab first');return}destructive('sensors',document.getElementById('data-sensor-operation').value,ids)};
document.querySelector('#table-backups tbody').onclick=async e=>{const dl=e.target.closest('.backup-download'),b=e.target.closest('.backup-delete');if(dl){const r=await fetch('/v1/data/backups/'+encodeURIComponent(dl.dataset.id)+'/download',{credentials:'include'});if(!r.ok){alert(await r.text());return}const blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=(dl.dataset.name||'otlens-backup')+'.json';a.click();URL.revokeObjectURL(a.href);return}if(!b)return;if(!confirm('Delete this backup?'))return;try{await api('/data/backups/'+encodeURIComponent(b.dataset.id),{method:'DELETE'});refreshAll()}catch(err){alert(err.message)}};
