let udpConversations=[];

async function loadUDPConversations(){
  const params=new URLSearchParams({active:'true'});
  const protocol=document.getElementById('udp-protocol')?.value;
  const port=document.getElementById('udp-port')?.value;
  if(protocol)params.set('protocol',protocol);
  if(port)params.set('port',port);
  try{
    udpConversations=await api('/udp-conversations?'+params);
    renderUDPConversations();
  }catch(error){console.error('UDP conversations',error)}
}

function renderUDPConversations(){
  const filter=(document.getElementById('udp-filter')?.value||'').toLowerCase();
  const rows=(udpConversations||[]).filter(x=>{
    const key=x.Key||{};
    return !filter||[x.ID,key.EndpointAIP,key.EndpointBIP,x.SensorID].some(v=>String(v||'').toLowerCase().includes(filter));
  });
  document.getElementById('udp-count').textContent=`${rows.length} active conversation(s)`;
  document.querySelector('#table-udp tbody').innerHTML=rows.map((x,index)=>{
    const key=x.Key||{};
    return `<tr data-udp-index="${index}"><td>${time(x.StartedAt)}</td><td>${time(x.LastSeenAt)}</td><td>${esc(x.SensorID)}</td><td>${esc(x.Protocol||'udp')}</td><td>${esc(key.EndpointAIP)}:${esc(key.EndpointAPort)}</td><td>${esc(key.EndpointBIP)}:${esc(key.EndpointBPort)}</td><td>${Number(x.Packets||0).toLocaleString()}</td><td>${humanBytes(Number(x.Bytes||0))}</td><td><span class="status-pill healthy">active</span></td></tr>`;
  }).join('')||'<tr><td colspan="9">No matching UDP conversations</td></tr>';
}

async function openUDPConversation(index){
  const item=udpConversations[index];if(!item)return;
  const key=item.Key||{};
  let detail=item;
  try{detail=await api(`/udp-conversations/${encodeURIComponent(item.ID)}?sensor_id=${encodeURIComponent(item.SensorID)}`)}catch(_){}
  document.getElementById('udp-detail-body').innerHTML=`
    <div class="asset-security-kpis"><div><span>Protocol state</span><strong>${esc(detail.Protocol||'udp')}</strong></div><div><span>Packets</span><strong>${Number(detail.Packets||0).toLocaleString()}</strong></div><div><span>Bytes</span><strong>${humanBytes(Number(detail.Bytes||0))}</strong></div><div><span>RTT</span><strong>${detail.RTTMillis?esc(detail.RTTMillis+' ms'):'—'}</strong></div></div>
    <dl><dt>Conversation ID</dt><dd>${esc(detail.ID)}</dd><dt>Endpoint A</dt><dd>${esc(key.EndpointAIP)}:${esc(key.EndpointAPort)}</dd><dt>Endpoint B</dt><dd>${esc(key.EndpointBIP)}:${esc(key.EndpointBPort)}</dd><dt>Direction A → B</dt><dd>${Number(detail.DirectionA||0).toLocaleString()} packets</dd><dt>Direction B → A</dt><dd>${Number(detail.DirectionB||0).toLocaleString()} packets</dd></dl>
    <h3>Timeline</h3><div class="activity-list"><article><strong>Conversation started</strong><small>${time(detail.StartedAt)}</small></article>${(detail.timeline||[]).map(x=>`<article><strong>${esc(x.Status||x.Operation||x.LastOpcode||'Protocol exchange')}</strong><small>${esc(x.TimedOut?'timeout / incomplete':x.RTT?`RTT ${Number(x.RTT)/1e6} ms`:'completed')}</small></article>`).join('')}<article><strong>Last packet observed</strong><small>${time(detail.LastSeenAt)}</small></article></div>`;
  document.getElementById('udp-detail-modal').hidden=false;
}

document.querySelector('.tab[data-tab="udp"]')?.addEventListener('click',loadUDPConversations);
document.getElementById('udp-refresh')?.addEventListener('click',loadUDPConversations);
document.getElementById('udp-filter')?.addEventListener('input',renderUDPConversations);
document.getElementById('udp-protocol')?.addEventListener('change',loadUDPConversations);
document.getElementById('udp-port')?.addEventListener('change',loadUDPConversations);
document.querySelector('#table-udp tbody')?.addEventListener('click',event=>{
  const row=event.target.closest('tr[data-udp-index]');
  if(row)openUDPConversation(Number(row.dataset.udpIndex));
});
