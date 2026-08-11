let udpRefreshTimer=null;
const UDP_PROTOCOLS={dns:['🟦','DNS'],dhcp:['🟩','DHCP'],ntp:['🟧','NTP'],snmp:['🟨','SNMP'],sip:['🟪','SIP'],dtls:['🔷','DTLS'],openvpn:['🟢','OpenVPN'],bittorrent:['🔵','BitTorrent']};

function udpProtocolBadge(protocol){
  const key=String(protocol||'udp').toLowerCase(),value=UDP_PROTOCOLS[key]||['⚪',key.toUpperCase()];
  return `<span class="udp-protocol-badge udp-protocol-${esc(key)}"><i>${value[0]}</i>${esc(value[1])}</span>`;
}
function udpStatusBadge(status){
  const key=String(status||'active').toLowerCase(),labels={active:'Active',idle:'Idle',expired:'Expired',timed_out:'Timed Out',closed:'Closed'};
  return `<span class="udp-status udp-status-${esc(key)}">${esc(labels[key]||status)}</span>`;
}
function udpDuration(ms){
  ms=Number(ms||0);if(ms<1000)return `${Math.round(ms)} ms`;if(ms<60000)return `${(ms/1000).toFixed(1)} s`;if(ms<3600000)return `${(ms/60000).toFixed(1)} min`;return `${(ms/3600000).toFixed(1)} h`;
}
function udpField(x,...keys){for(const key of keys)if(x?.[key]!==undefined&&x[key]!==null)return x[key];return null}
function udpDurationValue(x,...keys){const value=Number(udpField(x,...keys)||0);return value>0?value/1e6:0}
function udpEventTime(x){return udpField(x,'RespondedAt','responded_at','CompletedAt','EndedAt','LastSeenAt','RequestedAt','requested_at','StartedAt')||null}
function udpEventLabel(x){
  if(udpField(x,'TimedOut','timed_out'))return 'Timeout';
  return udpField(x,'Status','Operation','LastOpcode','QueryName','query_name')||((udpField(x,'RespondedAt','responded_at','CompletedAt','EndedAt'))?'Response':'Request');
}
function udpRTTValues(timeline){return (timeline||[]).map(x=>udpDurationValue(x,'RTT','rtt','ResponseTime','response_time','TimeToResponse')).filter(x=>x>0)}
function udpSparkline(values){
  if(!values.length)return '<div class="udp-no-chart">No RTT samples yet</div>';
  const width=340,height=90,pad=8,max=Math.max(1,...values),step=values.length>1?(width-pad*2)/(values.length-1):0;
  const points=values.map((v,i)=>`${pad+i*step},${height-pad-(v/max)*(height-pad*2)}`).join(' ');
  return `<svg class="udp-rtt-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="RTT samples"><polyline points="${points}"></polyline>${values.map((v,i)=>`<circle cx="${pad+i*step}" cy="${height-pad-(v/max)*(height-pad*2)}" r="3"><title>${v.toFixed(2)} ms</title></circle>`).join('')}</svg><div class="udp-rtt-values">${values.map(v=>`<span>${v.toFixed(1)}</span>`).join('')}</div>`;
}
function udpDirection(detail){
  const a=Number(detail.DirectionA||0),b=Number(detail.DirectionB||0),total=Math.max(1,a+b),ap=(a/total*100).toFixed(1);
  return `<div class="udp-directions"><div><span>A → B</span><strong>${a.toLocaleString()}</strong></div><div class="udp-direction-track"><i style="width:${ap}%"></i></div><div><span>B → A</span><strong>${b.toLocaleString()}</strong></div></div>`;
}
function udpProtocolPanel(detail){
  const p=String(detail.Protocol||'').toLowerCase(),t=detail.timeline||[];
  const metric=(name,value)=>`<div><span>${esc(name)}</span><strong>${esc(value??'—')}</strong></div>`;
  if(p==='dns'){
    const responses=t.filter(x=>udpField(x,'RespondedAt','responded_at')),nx=t.filter(x=>Number(udpField(x,'ResponseCode','response_code'))===3),answers=t.reduce((n,x)=>n+Number(udpField(x,'Answers','answers')||0),0);
    const ttl=Math.max(0,...t.map(x=>Number(udpField(x,'TTL','ttl')||0)));
    return `<h3>DNS exchange</h3><div class="asset-security-kpis">${metric('Queries',t.length)}${metric('Responses',responses.length)}${metric('NXDOMAIN',nx.length)}${metric('Answers',answers)}</div><dl class="status-list"><div><dt>TTL</dt><dd>${ttl?esc(ttl+' s'):'—'}</dd></div></dl>`;
  }
  if(p==='dhcp'){const x=t.at(-1)||{};return `<h3>DHCP lease</h3><div class="asset-security-kpis">${metric('Hostname',x.Hostname)}${metric('Vendor',x.VendorClass)}${metric('Assigned IP',x.AssignedIP)}${metric('Lease',udpDurationValue(x,'LeaseTime')?udpDuration(udpDurationValue(x,'LeaseTime')):'—')}</div><dl class="status-list"><div><dt>Gateway</dt><dd>${esc(x.Gateway||'—')}</dd></div><div><dt>DNS servers</dt><dd>${esc((x.DNSServers||[]).join(', ')||'—')}</dd></div><div><dt>Sequence</dt><dd>${esc((x.Sequence||[]).join(' → ')||'—')}</dd></div></dl>`}
  if(p==='snmp'){const ops={};t.forEach(x=>{const op=x.Operation||'UNKNOWN';ops[op]=(ops[op]||0)+1});return `<h3>SNMP operations</h3><div class="asset-security-kpis">${metric('GET',ops.GET||0)}${metric('SET',ops.SET||0)}${metric('GETNEXT',ops.GETNEXT||0)}${metric('Varbinds',t.reduce((n,x)=>n+Number(x.Varbinds||0),0))}</div>`}
  if(p==='sip'){const x=t.at(-1)||{};return `<h3>SIP dialog</h3><div class="asset-security-kpis">${metric('Status',x.Status)}${metric('Response',udpDuration(udpDurationValue(x,'TimeToResponse')))}${metric('Ringing',udpDuration(udpDurationValue(x,'RingingTime')))}${metric('Call duration',udpDuration(udpDurationValue(x,'Duration')))}</div><div class="udp-sequence">${(x.Sequence||[]).map(v=>`<span>${esc(v)}</span>`).join('<i>→</i>')||'No SIP states yet'}</div>`}
  if(p==='ntp'){const x=t.at(-1)||{};return `<h3>NTP exchange</h3><div class="asset-security-kpis">${metric('Stratum',x.ServerStratum)}${metric('Leap indicator',x.LeapIndicator)}${metric('Clock offset',x.OffsetValid?`${udpDurationValue(x,'ClockOffset').toFixed(2)} ms`:'unavailable')}${metric('KoD',x.KoD||'No')}</div>`}
  return `<h3>${esc((UDP_PROTOCOLS[p]?.[1]||p.toUpperCase()||'UDP'))} state</h3><div class="udp-sequence">${t.map(x=>`<span>${esc(udpEventLabel(x))}</span>`).join('<i>→</i>')||'No protocol exchange recorded yet'}</div>`;
}

async function loadUDPConversations(){
  const params=new URLSearchParams({active:'true'}),protocol=document.getElementById('udp-protocol')?.value,port=document.getElementById('udp-port')?.value;
  if(protocol)params.set('protocol',protocol);if(port)params.set('port',port);
  try{udpConversations=await api('/udp-conversations?'+params);renderUDPConversations()}catch(error){console.error('UDP conversations',error)}
}
function filteredUDPConversations(){
  const filter=(document.getElementById('udp-filter')?.value||'').toLowerCase();
  return (udpConversations||[]).filter(x=>{const k=x.Key||{};return !filter||[x.ID,k.EndpointAIP,k.EndpointBIP,x.SensorID,x.Protocol,x.Status].some(v=>String(v||'').toLowerCase().includes(filter))});
}
function renderUDPConversations(){
  const rows=filteredUDPConversations(),count=document.getElementById('udp-count'),body=document.querySelector('#table-udp tbody');if(!body)return;
  count.textContent=`${rows.length} conversation(s)`;
  body.innerHTML=rows.map(x=>{const key=x.Key||{},index=udpConversations.indexOf(x);return `<tr data-udp-index="${index}"><td>${time(x.StartedAt)}</td><td>${time(x.LastSeenAt)}</td><td>${udpDuration(x.duration_millis)}</td><td>${esc(x.SensorID)}</td><td>${udpProtocolBadge(x.Protocol)}</td><td>${esc(key.EndpointAIP)}:${esc(key.EndpointAPort)}</td><td>${esc(key.EndpointBIP)}:${esc(key.EndpointBPort)}</td><td>${Number(x.Packets||0).toLocaleString()}</td><td>${humanBytes(Number(x.Bytes||0))}</td><td>${udpStatusBadge(x.status)}</td></tr>`}).join('');
  window.OTDataTables?.refresh('table-udp');
}
async function openUDPConversation(index){
  const item=udpConversations[index];if(!item)return;let detail=item;
  try{detail=await api(`/udp-conversations/${encodeURIComponent(item.ID)}?sensor_id=${encodeURIComponent(item.SensorID)}`)}catch(_){}
  const key=detail.Key||{},events=[{label:'Conversation started',at:detail.StartedAt},...(detail.timeline||[]).map(x=>({label:udpEventLabel(x),at:udpEventTime(x),timeout:!!udpField(x,'TimedOut','timed_out'),detail:udpDurationValue(x,'RTT','rtt','ResponseTime','response_time')?`RTT ${udpDurationValue(x,'RTT','rtt','ResponseTime','response_time').toFixed(2)} ms`:''})),{label:'Last packet observed',at:detail.LastSeenAt}].sort((a,b)=>new Date(a.at||0)-new Date(b.at||0));
  document.getElementById('udp-detail-body').innerHTML=`<div class="asset-security-kpis"><div><span>Protocol</span><strong>${udpProtocolBadge(detail.Protocol)}</strong></div><div><span>Status</span><strong>${udpStatusBadge(detail.status)}</strong></div><div><span>Packets / bytes</span><strong>${Number(detail.Packets||0).toLocaleString()} / ${humanBytes(Number(detail.Bytes||0))}</strong></div><div><span>Average RTT</span><strong>${detail.rtt_millis?Number(detail.rtt_millis).toFixed(2)+' ms':'—'}</strong></div></div>
  <dl class="status-list"><div><dt>Conversation ID</dt><dd>${esc(detail.ID)}</dd></div><div><dt>Flow / sensor</dt><dd>${esc(detail.FlowID||'—')} · ${esc(detail.SensorID)}</dd></div><div><dt>Endpoint A</dt><dd>${esc(key.EndpointAIP)}:${esc(key.EndpointAPort)}</dd></div><div><dt>Endpoint B</dt><dd>${esc(key.EndpointBIP)}:${esc(key.EndpointBPort)}</dd></div><div><dt>Started</dt><dd>${time(detail.StartedAt)}</dd></div><div><dt>Last seen / duration</dt><dd>${time(detail.LastSeenAt)} · ${udpDuration(detail.duration_millis)}</dd></div></dl>
  <h3>Packet direction</h3>${udpDirection(detail)}<div class="udp-detail-columns"><section><h3>Timeline</h3><div class="udp-timeline">${events.map(e=>`<article class="${e.timeout?'timeout':''}"><i></i><div><strong>${esc(e.label)}</strong><span>${time(e.at)}${e.detail?' · '+esc(e.detail):''}</span></div></article>`).join('')}</div></section><section><h3>RTT</h3>${udpSparkline(udpRTTValues(detail.timeline))}</section></div>${udpProtocolPanel(detail)}`;
  document.getElementById('udp-detail-modal').hidden=false;
}
function exportUDP(format){
  const rows=filteredUDPConversations(),json=JSON.stringify(rows,null,2);
  let content=json,type='application/json',name='udp-conversations.json';
  if(format==='csv'){const headers=['ID','SensorID','Protocol','Status','StartedAt','LastSeenAt','DurationMillis','EndpointA','EndpointB','Packets','Bytes','DirectionA','DirectionB'];content=[headers.join(','),...rows.map(x=>{const k=x.Key||{},v=[x.ID,x.SensorID,x.Protocol,x.status,x.StartedAt,x.LastSeenAt,x.duration_millis,`${k.EndpointAIP}:${k.EndpointAPort}`,`${k.EndpointBIP}:${k.EndpointBPort}`,x.Packets,x.Bytes,x.DirectionA,x.DirectionB];return v.map(y=>`"${String(y??'').replaceAll('"','""')}"`).join(',')})].join('\n');type='text/csv';name='udp-conversations.csv'}
  const url=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);
}
function configureUDPRefresh(){
  clearInterval(udpRefreshTimer);udpRefreshTimer=null;
  if(document.getElementById('udp-live')?.checked){const seconds=Number(document.getElementById('udp-live-interval')?.value||10);udpRefreshTimer=setInterval(()=>{if(activeTab()==='udp')loadUDPConversations()},seconds*1000)}
}
document.querySelector('.tab[data-tab="udp"]')?.addEventListener('click',loadUDPConversations);
document.getElementById('udp-refresh')?.addEventListener('click',loadUDPConversations);
document.getElementById('udp-filter')?.addEventListener('input',renderUDPConversations);
document.getElementById('udp-protocol')?.addEventListener('change',loadUDPConversations);
document.getElementById('udp-port')?.addEventListener('change',loadUDPConversations);
document.getElementById('udp-export-json')?.addEventListener('click',()=>exportUDP('json'));
document.getElementById('udp-export-csv')?.addEventListener('click',()=>exportUDP('csv'));
document.getElementById('udp-live')?.addEventListener('change',configureUDPRefresh);
document.getElementById('udp-live-interval')?.addEventListener('change',configureUDPRefresh);
document.querySelector('#table-udp tbody')?.addEventListener('click',event=>{const row=event.target.closest('tr[data-udp-index]');if(row)openUDPConversation(Number(row.dataset.udpIndex))});
