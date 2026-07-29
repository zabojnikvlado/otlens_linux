const POLL=10000;let graph={Nodes:[],Edges:[]},assets=[],devices=[],vulnerabilities=[],tags=[],alerts=[],rules=[],sensors=[],baselines=[],changes=[],events=[],analysisJobs=[],backups=[],settings={},users=[],roles=[],audit=[],incidents=[],assetSecurity=[],dnsObservations=[],smbObservations=[],threatIntelSources=[],threatIntelIndicators=[],reports=[],sensorMetrics=[],healthcheckData=null,assetRiskData=[],correlationRules=[],udpConversations=[],udpTelemetry={totals:{},protocols:{},top_protocol:''},udpPacketRateState=null,trends={AlertsByDay:[],NewAssetsByDay:[]};let network,nodesDS,edgesDS;let topologyColourMode='class',purdueTopologyData=null;const topologyPositionCache=new Map();const selected=new Set();
// Auth state — populated from GET /v1/me on boot and again right after
// login. permissions.view drives which nav tabs are shown (server-side
// requireView enforces the same thing, this just reflects it in the UI);
// permissions.actions drives which buttons render as active via can().
let currentUser=null,currentRole=null,permissions={view:[],actions:[]};
let pollTimer=null,liveRefreshTimer=null;const livePendingTypes=new Set();let activeIncidentID=null,presenceTimer=null;const liveNotifications=[];let liveHistoryLoaded=false,assetContextsData=[],lastCreatedRuleSet=null;
const connectionState={api:'unknown',apiText:'',live:'idle',liveSince:0,lastEventAt:0};
// View-scoped data loading. The old UI refreshed every endpoint after nearly
// every action; these maps keep requests and rendering limited to the active
// data domain. Concurrent GETs are deduplicated and recently loaded views are
// reused for a short period when switching tabs.
const DOMAIN_TTL_MS=15000;
const domainLoadedAt=new Map(),pendingLoads=new Map();
const DOMAIN_PATHS={
  dashboard:['/baseline','/dashboard/trends','/reports','/sensors','/sensors/metrics','/alerts','/incidents','/asset-risk','/assets','/rules','/tags','/analysis/jobs','/data/backups','/vulnerabilities','/smb-observations?limit=1000','/reconnaissance/jobs','/udp-telemetry'],
  assets:['/assets','/asset-security-status','/asset-risk'],devices:['/devices'],
  vulnerabilities:['/vulnerabilities'],tags:['/tags','/tags/changes','/tags/events','/sensors'],
  sensors:['/sensors','/sensors/metrics'],alerts:['/alerts','/dns-observations?limit=1000','/smb-observations?limit=1000'],
  incidents:['/incidents','/correlation-rules'],rules:['/rules','/sensors'],reports:['/reports'],
  analysis:['/analysis/jobs','/sensors'],data:['/data/backups','/sensors'],settings:['/settings'],audit:['/audit'],
  topology:['/udp-conversations?active=true'],purdue:['/assets'],segmentation:['/sensors'],dns:['/dns-observations?limit=1000'],udp:[],smb:['/smb-observations?limit=1000'],threatintel:[]
};
function activeTab(){return document.querySelector('.tab.active')?.dataset.tab||'dashboard'}
function loadPath(path){if(pendingLoads.has(path))return pendingLoads.get(path);const q=api(path).finally(()=>pendingLoads.delete(path));pendingLoads.set(path,q);return q}
function invalidateDomains(...domains){domains.flat().forEach(d=>domainLoadedAt.delete(d))}

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
async function api(path,opt={}){const isFormData=typeof FormData!=='undefined'&&opt.body instanceof FormData;const h=isFormData?{...(opt.headers||{})}:{'Content-Type':'application/json',...(opt.headers||{})};let r;try{r=await fetch('/v1'+path,{...opt,headers:h,credentials:'include'})}catch(cause){const e=new Error('network error');e.kind='network';e.cause=cause;throw e}if(!r.ok){const body=await r.text();const e=new Error(r.status+' '+body);e.status=r.status;e.body=body;try{e.parsed=JSON.parse(body)}catch(_){}throw e}if((opt.method||'GET').toUpperCase()!=='GET')domainLoadedAt.clear();return r.status===204||r.status===202?null:r.json()}
function renderConnectionState(){
  const dot=document.getElementById('conn-dot'),text=document.getElementById('conn-text');if(!dot||!text)return;
  let cls='down',label='connecting',title='';
  if(connectionState.api==='error'){
    label=connectionState.apiText||'backend unavailable';title=label;
  }else if(connectionState.live==='open'){
    cls='ok';label='live';
    const since=connectionState.liveSince?new Date(connectionState.liveSince).toLocaleTimeString():'';
    const last=connectionState.lastEventAt?new Date(connectionState.lastEventAt).toLocaleTimeString():'';
    title=`Live stream connected${since?' since '+since:''}${last?' · last event '+last:''}`;
  }else if(connectionState.live==='reconnecting'){
    cls='connecting';label='reconnecting';title='Live stream temporarily disconnected; automatic reconnect is active.';
  }else if(connectionState.live==='unsupported'){
    cls=connectionState.api==='ok'?'ok':'down';label='polling';title='Browser does not support Server-Sent Events; using polling fallback.';
  }else{
    cls='connecting';label='connecting';title='Opening live event stream.';
  }
  dot.className='dot '+cls;text.textContent=label;text.title=title;
}
function setAPIConnection(ok,text=''){
  connectionState.api=ok?'ok':'error';connectionState.apiText=ok?'':text;renderConnectionState();
}
function markLiveEvent(){connectionState.lastEventAt=Date.now();renderConnectionState()}

function liveToast(event){
  const stack=document.getElementById('live-toast-stack');if(!stack)return;
  const quiet=new Set(['stream.ready','sensor.health','telemetry.updated','asset-risk.changed','incidents.changed']);
  if(quiet.has(event.type))return;
  const item=document.createElement('button');item.type='button';item.className='live-toast';
  const sev=String(event.severity||'info').toLowerCase();item.dataset.severity=sev;
  const title=event.type==='alert.created'?'New alert':event.type==='incident.updated'?'Incident updated':event.type==='incident.comment'?'Incident comment':event.type==='discovery.completed'?'Discovery finished':event.type==='sensor.registered'?'Sensor connected':'Live update';
  item.innerHTML=`<strong>${esc(title)}</strong><span>${esc(event.message||event.type)}</span><small>${esc(event.sensor_id||event.entity_id||'Central')}</small>`;
  item.onclick=()=>{if(event.type.startsWith('incident'))document.querySelector('[data-tab="incidents"]')?.click();else if(event.type==='alert.created')document.querySelector('[data-tab="alerts"]')?.click();else if(event.type==='discovery.completed')document.querySelector('[data-tab="assets"]')?.click();item.remove()};
  stack.prepend(item);while(stack.children.length>5)stack.lastElementChild.remove();setTimeout(()=>item.remove(),8000);
}
function liveEventDomains(type){
  if(type.startsWith('incident'))return['incidents','dashboard'];
  if(type.startsWith('alert'))return['alerts','dashboard'];
  if(type.startsWith('sensor')||type==='telemetry.updated')return['sensors','dashboard'];
  if(type.startsWith('asset-risk'))return['assets','dashboard'];
  if(type.startsWith('asset')||type.startsWith('discovery'))return['assets','topology','dashboard'];
  if(type.startsWith('report'))return['reports','dashboard'];
  return[activeTab()];
}
function scheduleLiveRefresh(type){
  liveEventDomains(type).forEach(d=>livePendingTypes.add(d));
  if(liveRefreshTimer)return;
  liveRefreshTimer=setTimeout(async()=>{const domains=[...livePendingTypes];liveRefreshTimer=null;livePendingTypes.clear();try{await refreshDomains(domains,true)}catch(e){console.error('live refresh',e)}},450);
}
function rememberLiveNotification(event){
  if(!event||event.type==='stream.ready'||event.type==='presence.changed')return;
  if(event.id&&liveNotifications.some(x=>String(x.id)===String(event.id)))return;
  liveNotifications.unshift({...event,acknowledged:false});if(liveNotifications.length>100)liveNotifications.length=100;renderNotificationCenter();
}
async function loadLiveHistory(){if(liveHistoryLoaded)return;try{const r=await api('/live/history?limit=100');const rows=Array.isArray(r?.events)?r.events:[];rows.forEach(e=>{if(e.type!=='stream.ready'&&e.type!=='presence.changed'&&!liveNotifications.some(x=>String(x.id)===String(e.id)))liveNotifications.push({...e,acknowledged:false})});liveNotifications.sort((a,b)=>new Date(b.time||0)-new Date(a.time||0));if(liveNotifications.length>100)liveNotifications.length=100;liveHistoryLoaded=true;renderNotificationCenter()}catch(e){console.warn('live history',e)}}
function ensureNotificationCenter(){
  if(document.getElementById('live-notification-center'))return;
  const host=document.createElement('div');host.id='live-notification-center';host.className='live-notification-center';host.hidden=true;host.innerHTML='<div class="notification-head"><strong>Live notifications</strong><button id="notifications-ack-all" class="secondary-btn">Acknowledge all</button></div><div id="live-notification-list"></div>';document.body.appendChild(host);
  const trigger=document.getElementById('conn-text');if(trigger){trigger.style.cursor='pointer';trigger.onclick=()=>{host.hidden=!host.hidden;renderNotificationCenter()}}
  host.querySelector('#notifications-ack-all').onclick=()=>{liveNotifications.forEach(x=>x.acknowledged=true);renderNotificationCenter()};
}
function renderNotificationCenter(){ensureNotificationCenter();const list=document.getElementById('live-notification-list');if(!list)return;list.innerHTML=liveNotifications.map((x,i)=>`<button class="notification-row ${x.acknowledged?'acknowledged':''}" data-index="${i}"><span class="severity ${esc(String(x.severity||'info').toLowerCase())}">${esc(x.severity||'info')}</span><strong>${esc(x.message||x.type)}</strong><small>${time(x.time)} · ${esc(x.sensor_id||x.entity_id||'Central')}</small></button>`).join('')||'<div class="empty-dashboard">No live notifications.</div>';list.querySelectorAll('.notification-row').forEach(b=>b.onclick=()=>{const x=liveNotifications[Number(b.dataset.index)];if(!x)return;x.acknowledged=true;if(x.type.startsWith('incident'))openDashboardTab('incidents');else if(x.type==='alert.created')openDashboardTab('alerts');else if(x.type.startsWith('sensor'))openDashboardTab('sensors');renderNotificationCenter()})}
function pulseTopology(event){if(!network||!event)return;const ip=event.data?.ip||event.entity_id;const node=(graph.Nodes||[]).find(n=>String(n.id||n.ID||n.label).includes(String(ip||'')));if(node){try{network.selectNodes([node.id||node.ID],false);setTimeout(()=>network.unselectAll(),1800)}catch(_){}}}
async function refreshIncidentWorkbench(){if(!activeIncidentID||document.getElementById('incident-modal')?.hidden)return;const idx=(incidents||[]).findIndex(x=>String(x.ID)===String(activeIncidentID));if(idx>=0)await openIncident(idx)}
function handlePresenceEvent(event){if(!activeIncidentID||String(event.entity_id)!==String(activeIncidentID)||event.data?.entity!=='incident')return;renderIncidentPresence(event.data.presence||[])}
function handleLiveEvent(event){
  if(!event||!event.type)return;
  markLiveEvent();
  if(event.type==='stream.ready')return;
  if(event.type==='presence.changed'){handlePresenceEvent(event);return}
  rememberLiveNotification(event);liveToast(event);pulseTopology(event);
  if(activeIncidentID&&event.type.startsWith('incident')&&String(event.entity_id)===String(activeIncidentID)){refreshIncidentWorkbench();return}
  scheduleLiveRefresh(event.type);
}
class LiveConnectionManager{
  constructor(){this.source=null;this.reconnectTimer=null;this.reconnectNoticeTimer=null;this.stabilityTimer=null;this.running=false;this.attempt=0;this.generation=0}
  start(){
    if(this.running)return;
    this.running=true;this.attempt=0;
    if(typeof EventSource==='undefined'){connectionState.live='unsupported';renderConnectionState();return}
    this.connect();
  }
  connect(){
    if(!this.running||this.source)return;
    const generation=++this.generation;
    connectionState.live=connectionState.live==='open'?'open':'connecting';renderConnectionState();
    const source=new EventSource('/v1/live/events',{withCredentials:true});this.source=source;
    source.onopen=()=>{
      if(!this.running||generation!==this.generation)return;
      this.clearReconnectNotice();connectionState.live='open';connectionState.liveSince=Date.now();renderConnectionState();
      clearTimeout(this.stabilityTimer);this.stabilityTimer=setTimeout(()=>{if(this.running&&this.source===source&&source.readyState===EventSource.OPEN)this.attempt=0},10000);
    };
    source.onmessage=e=>{
      if(generation!==this.generation)return;
      try{handleLiveEvent(JSON.parse(e.data))}catch(err){console.error('live event',err)}
    };
    source.onerror=()=>{
      if(!this.running||generation!==this.generation)return;
      source.close();if(this.source===source)this.source=null;
      clearTimeout(this.stabilityTimer);
      // Do not flash the badge for very short proxy/network interruptions.
      this.clearReconnectNotice();this.reconnectNoticeTimer=setTimeout(()=>{if(this.running&&connectionState.live!=='open'){connectionState.live='reconnecting';renderConnectionState()}},1500);
      const delays=[1000,2000,5000,10000,30000],delay=delays[Math.min(this.attempt,delays.length-1)];this.attempt++;
      clearTimeout(this.reconnectTimer);this.reconnectTimer=setTimeout(()=>{this.reconnectTimer=null;this.connect()},delay);
    };
  }
  clearReconnectNotice(){if(this.reconnectNoticeTimer){clearTimeout(this.reconnectNoticeTimer);this.reconnectNoticeTimer=null}}
  stop(){
    this.running=false;this.generation++;
    if(this.source){this.source.close();this.source=null}
    clearTimeout(this.reconnectTimer);clearTimeout(this.stabilityTimer);this.clearReconnectNotice();
    this.reconnectTimer=null;this.stabilityTimer=null;this.attempt=0;connectionState.live='idle';connectionState.liveSince=0;
    if(liveRefreshTimer){clearTimeout(liveRefreshTimer);liveRefreshTimer=null}
    livePendingTypes.clear();renderConnectionState();
  }
}
const liveConnection=new LiveConnectionManager();
function startLiveEvents(){liveConnection.start()}
function stopLiveEvents(){liveConnection.stop()}

