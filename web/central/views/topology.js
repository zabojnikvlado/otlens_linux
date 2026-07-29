document.querySelector('.tabs').onclick=e=>{const b=e.target.closest('.tab');if(!b)return;const tab=b.dataset.tab;document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.getElementById('view-'+tab).classList.add('active');if(tab==='topology'&&network)setTimeout(()=>network.redraw(),30);refreshView(tab).catch(err=>console.error('view refresh',tab,err));if(tab==='purdue')loadPurdueArchitecture();if(tab==='segmentation')loadSegmentation();if(tab==='dns')loadDNS();if(tab==='smb')loadSMB();if(tab==='threatintel')loadThreatIntelManagement();if(tab==='health')loadHealthcheck()};
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
