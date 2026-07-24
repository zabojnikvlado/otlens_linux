const POLL=10000;let token=localStorage.getItem('otlensCentralToken')||'';let graph={Nodes:[],Edges:[]},assets=[],tags=[],alerts=[],rules=[],sensors=[],baselines=[],changes=[],events=[],analysisJobs=[],backups=[];let network,nodesDS,edgesDS;let topologySettling=false;const selected=new Set();
const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));const val=v=>typeof v==='object'?JSON.stringify(v):v??'—';const time=v=>v?new Date(v).toLocaleString():'—';
async function api(path,opt={}){const h={'Content-Type':'application/json',...(opt.headers||{})};if(token)h.Authorization='Bearer '+token;let r;try{r=await fetch('/v1'+path,{...opt,headers:h})}catch(cause){const e=new Error('network error');e.kind='network';e.cause=cause;throw e}if(!r.ok){const body=await r.text();const e=new Error(r.status+' '+body);e.status=r.status;e.body=body;throw e}return r.status===204||r.status===202?null:r.json()}
function setConn(ok,t){document.getElementById('conn-dot').className='dot '+(ok?'ok':'down');document.getElementById('conn-text').textContent=t}
document.getElementById('token-btn').onclick=()=>{const v=prompt('Management token',token);if(v!==null){token=v.trim();localStorage.setItem('otlensCentralToken',token);refreshAll()}};
document.querySelector('.tabs').onclick=e=>{const b=e.target.closest('.tab');if(!b)return;document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.getElementById('view-'+b.dataset.tab).classList.add('active');if(b.dataset.tab==='topology'&&network)setTimeout(()=>network.redraw(),30)};
function node(n){const threshold=Number(n.HoneypotThreshold??graph.HoneypotThreshold??100),score=Number(n.Score??1),honey=n.IsHoneypot===true||score>=threshold,bad=n.Confirmed===false;return{id:n.ID,label:n.Hostname||n.IP||n.MAC,title:`Sensor: ${n.SensorID}\nIP: ${n.IP}\nMAC: ${n.MAC}\nVendor: ${n.Vendor||'—'}\nScore: ${score}/100${honey?' (honeypot)':''}\nProtocols: ${(n.Protocols||[]).join(', ')||'—'}`,font:{color:'#ffffff',strokeWidth:2,strokeColor:'#0b1220'},color:{background:honey?'#a855f7':bad?'#e85d4c':n.IsOT?'#3fbfb0':'#64748b',border:honey?'#7c3aed':bad?'#ff9f95':n.IsOT?'#2a7d74':'#334155'},size:honey?24:n.IsOT?22:16,_search:`${n.IP} ${n.MAC} ${n.Hostname} ${n.SensorID}`.toLowerCase()}}
function settleTopology(newNodeIds=[]){
  if(!network||topologySettling)return;
  topologySettling=true;
  const allIds=nodesDS.getIds();
  const moving=new Set(newNodeIds);
  // Existing nodes stay exactly where the operator left them. Only newly
  // discovered nodes participate in the short stabilization pass.
  if(moving.size){
    const pos=network.getPositions(allIds);
    nodesDS.update(allIds.map(id=>({id,fixed:moving.has(id)?{x:false,y:false}:{x:true,y:true},...(pos[id]?{x:pos[id].x,y:pos[id].y}:{})})));
  }
  network.setOptions({physics:{enabled:true}});
  network.stabilize(moving.size?90:250);
}
function renderTopology(){
  const ns=(graph.Nodes||[]).map(node),
        ip=new Map((graph.Nodes||[]).map(n=>[n.SensorID+'::'+n.IP,n.ID])),
        nodeByIP=new Map((graph.Nodes||[]).map(n=>[n.SensorID+'::'+n.IP,n]));
  const es=(graph.Edges||[]).map(e=>{
    const src=nodeByIP.get(e.SensorID+'::'+e.SrcIP),dst=nodeByIP.get(e.SensorID+'::'+e.DstIP),
          interVlan=!!src&&!!dst&&Number(src.VLANID||0)!==Number(dst.VLANID||0),lateral=!!e.FromHoneypot;
    return{id:e.ID,from:ip.get(e.SensorID+'::'+e.SrcIP),to:ip.get(e.SensorID+'::'+e.DstIP),label:lateral?'POTENTIAL LATERAL MOVEMENT':interVlan?`VLAN ${src.VLANID||'untagged'} → ${dst.VLANID||'untagged'}`:(e.IsOT?e.Protocol:''),title:lateral?`Potential lateral movement: honeypot ${e.SrcIP} initiated communication to ${e.DstIP}`:interVlan?'Inter-VLAN communication':e.Protocol,font:{color:lateral?'#ff9f95':interVlan?'#fbbf24':'#d7e1ec',strokeWidth:2,strokeColor:'#0b1220'},color:{color:lateral?'#ef4444':interVlan?'#f59e0b':e.IsOT?'#3fbfb0':'#64748b'},dashes:lateral?false:interVlan?[10,6]:false,width:lateral?5:interVlan?3:e.IsOT?2:1,arrows:lateral?'to':undefined}
  }).filter(e=>e.from!=null&&e.to!=null);
  if(!network){
    nodesDS=new vis.DataSet(ns);edgesDS=new vis.DataSet(es);
    network=new vis.Network(document.getElementById('graph'),{nodes:nodesDS,edges:edgesDS},{
      nodes:{shape:'dot',borderWidth:2},edges:{smooth:false},
      physics:{enabled:true,solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:-120,springLength:160,avoidOverlap:1},stabilization:{enabled:true,iterations:250,updateInterval:25,fit:true}},
      interaction:{hover:true}
    });
    network.once('stabilized',()=>{
      network.setOptions({physics:{enabled:false}});
      nodesDS.update(nodesDS.getIds().map(id=>({id,fixed:{x:false,y:false}})));
      topologySettling=false;
    });
  }else{
    const oldIds=new Set(nodesDS.getIds()),nextIds=new Set(ns.map(n=>n.id));
    const newIds=ns.filter(n=>!oldIds.has(n.id)).map(n=>n.id);
    nodesDS.getIds().filter(id=>!nextIds.has(id)).forEach(id=>nodesDS.remove(id));
    // Do not write x/y for existing nodes. vis-network retains both automatic
    // and manually dragged positions while physics is disabled.
    nodesDS.update(ns);
    const edgeIds=new Set(es.map(e=>e.id));
    edgesDS.getIds().filter(id=>!edgeIds.has(id)).forEach(id=>edgesDS.remove(id));
    edgesDS.update(es);
    if(newIds.length){
      network.once('stabilized',()=>{
        network.setOptions({physics:{enabled:false}});
        nodesDS.update(nodesDS.getIds().map(id=>({id,fixed:{x:false,y:false}})));
        topologySettling=false;
      });
      settleTopology(newIds);
    }
  }
  applySearch();
}
function applySearch(){if(!network)return;const q=document.getElementById('topology-search-input').value.trim().toLowerCase();document.getElementById('topology-search-clear').hidden=!q;if(!q){network.unselectAll();document.getElementById('topology-search-status').textContent='';return}const ids=nodesDS.get().filter(n=>n._search.includes(q)).map(n=>n.id);network.selectNodes(ids);document.getElementById('topology-search-status').textContent=ids.length+' match(es)';if(ids.length===1)network.focus(ids[0],{scale:1.2,animation:true})}
document.getElementById('topology-search-input').oninput=applySearch;document.getElementById('topology-search-clear').onclick=()=>{document.getElementById('topology-search-input').value='';applySearch()};
function renderAssets(){const q=document.getElementById('assets-filter').value.toLowerCase(),data=assets.filter(a=>JSON.stringify(a).toLowerCase().includes(q));document.getElementById('assets-count').textContent=data.length+' assets';document.querySelector('#table-assets tbody').innerHTML=data.map(a=>`<tr class="${a.Confirmed===false?'row-unconfirmed':''}"><td><input class="asset-check" type="checkbox" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}" ${selected.has(a.SensorID+'::'+a.MAC)?'checked':''}></td><td>${esc(a.SensorID)}</td><td>${esc(a.IP)}</td><td>${esc(a.MAC)}</td><td>${esc(a.Vendor)}</td><td>${esc(a.Hostname)}</td><td class="${a.Confirmed===false?'state-new':'state-ok'}">${a.Confirmed===false?'NEW / UNCONFIRMED':'confirmed'}</td><td>${a.IsOT?'OT':'IT'}</td><td>${esc((a.Protocols||[]).join(', '))}</td><td>${esc(a.VLANID||'untagged')}</td><td>${esc(a.Score??1)}</td><td>${(a.IsHoneypot===true||Number(a.Score??1)>=Number(a.HoneypotThreshold??100))?'<span class="pill honeypot">HONEYPOT</span>':Number(a.Score??1)>=75?'<span class="pill severity-high">CRITICAL</span>':Number(a.Score??1)>=40?'<span class="pill severity-medium">ELEVATED</span>':'standard'}</td><td>${esc(a.PacketCount)}</td><td>${time(a.LastSeen)}</td><td>${a.Confirmed===false?`<button class="ack-btn confirm-one" data-sensor="${esc(a.SensorID)}" data-mac="${esc(a.MAC)}">Confirm</button>`:'—'}</td></tr>`).join('');updateBulk()}
function updateBulk(){const on=selected.size>0;document.querySelectorAll('.bulk').forEach(b=>b.hidden=!on)}
document.getElementById('assets-filter').oninput=renderAssets;document.querySelector('#table-assets tbody').onclick=e=>{const c=e.target.closest('.asset-check');if(c){const k=c.dataset.sensor+'::'+c.dataset.mac;c.checked?selected.add(k):selected.delete(k);updateBulk();return}const b=e.target.closest('.confirm-one');if(b)sendAssetAction('confirm',[b.dataset.sensor+'::'+b.dataset.mac])};document.getElementById('assets-all').onchange=e=>{assets.forEach(a=>e.target.checked?selected.add(a.SensorID+'::'+a.MAC):selected.delete(a.SensorID+'::'+a.MAC));renderAssets()};
async function sendAssetAction(action,keys=[...selected]){const groups={};keys.forEach(k=>{const i=k.indexOf('::'),s=k.slice(0,i),m=k.slice(i+2);(groups[s]??=[]).push(m)});for(const [s,targets] of Object.entries(groups))await api(`/sensors/${encodeURIComponent(s)}/assets/actions`,{method:'POST',body:JSON.stringify({action,targets})});selected.clear();updateBulk();setTimeout(refreshAll,1000)}document.getElementById('assets-confirm').onclick=()=>sendAssetAction('confirm');document.getElementById('assets-delete').onclick=()=>confirm('Delete selected assets?')&&sendAssetAction('delete');
function tagIdentity(t){return `${t.SensorID??''}::${t.Key||[t.DeviceIP,t.DevicePort,t.Protocol,t.AddressSpace,t.Address].join('|')}`}
function currentTags(){const byKey=new Map();for(const t of Array.isArray(tags)?tags:[])byKey.set(tagIdentity(t),t);return [...byKey.values()]}
function renderTags(){const q=document.getElementById('tags-filter').value.toLowerCase(),data=currentTags().filter(t=>JSON.stringify(t).toLowerCase().includes(q));document.getElementById('tags-count').textContent=data.length+' tags';document.querySelector('#table-tags tbody').innerHTML=data.map(t=>`<tr class="tag-row" data-sensor="${esc(t.SensorID)}" data-key="${esc(t.Key||[t.DeviceIP,t.DevicePort,t.Protocol,t.AddressSpace,t.Address].join('|'))}"><td>${esc(t.SensorID)}</td><td>${esc(t.DeviceIP)}:${esc(t.DevicePort)}</td><td>${esc(t.Protocol)}</td><td>${esc(t.AddressSpace)} ${esc(t.Address)}</td><td>${esc(t.Operation)}</td><td>${esc(val(t.LastValue))}</td><td>${esc(val(t.MinValue))}</td><td>${esc(val(t.MaxValue))}</td><td>${time(t.LastChangeAt)}</td><td>${esc(t.PollCount)}</td><td>${esc(t.ChangeCount)}</td></tr>`).join('')}
document.getElementById('tags-filter').oninput=renderTags;document.querySelector('#table-tags tbody').onclick=e=>{const r=e.target.closest('.tag-row');if(r)openTag(r.dataset.sensor,r.dataset.key)};
function drawChart(rows){const c=document.getElementById('tag-chart'),x=c.getContext('2d');x.clearRect(0,0,c.width,c.height);const nums=rows.map(r=>Number(r.NewValue)).filter(Number.isFinite);if(nums.length<1){x.fillStyle='#8393ab';x.fillText('No numeric change history',20,30);return}const mn=Math.min(...nums),mx=Math.max(...nums),pad=25,range=mx-mn||1;x.strokeStyle='#3fbfb0';x.lineWidth=2;x.beginPath();nums.forEach((v,i)=>{const px=pad+i*(c.width-pad*2)/Math.max(1,nums.length-1),py=c.height-pad-(v-mn)*(c.height-pad*2)/range;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();x.fillStyle='#d7e1ec';x.fillText(`min ${mn}   max ${mx}`,pad,16)}
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
function renderRules(){document.querySelector('#table-rules tbody').innerHTML=rules.map(r=>{const custom=String(r.Kind).toLowerCase()==='custom',mode=r.Simulation?`simulation (${r.SimulationHits||0} matches)`:(r.Enabled?'enabled':'disabled'),toggleLabel=r.Enabled?'Disable rule':'Enable rule';return `<tr><td>${esc(r.SensorID)}</td><td>${esc(r.Name)}</td><td>${esc(r.Category||r.Kind)}</td><td class="rule-condition rule-condition-summary">${esc(ruleSummary(r))}</td><td>${esc(mode)}</td><td>${esc(r.Severity||'—')}</td><td>${esc(r.Priority||100)}</td><td>${esc(r.HitCount||0)}</td><td>${time(r.LastHit)}</td><td class="rule-actions"><button type="button" class="rule-state-toggle ${r.Enabled?'is-on':'is-off'}" data-sensor="${esc(r.SensorID)}" data-id="${esc(r.ID)}" data-enabled="${r.Enabled?'true':'false'}" aria-pressed="${r.Enabled?'true':'false'}" aria-label="${toggleLabel}" title="${toggleLabel}"><span aria-hidden="true"></span></button>${custom?`<button class="secondary-btn rule-edit" data-sensor="${esc(r.SensorID)}" data-id="${esc(r.ID)}">Edit</button><button class="danger-btn rule-delete" data-sensor="${esc(r.SensorID)}" data-id="${esc(r.ID)}">Delete</button>`:'<span class="builtin-lock">built-in</span>'}</td></tr>`}).join('')}
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
function renderAnalysis(){const tbody=document.querySelector('#table-analysis tbody');if(!tbody)return;tbody.innerHTML=(analysisJobs||[]).map(j=>`<tr><td>${time(j.created_at)}</td><td>${esc(j.sensor_id)}</td><td title="SHA-256: ${esc(j.sha256)}">${esc(j.filename)}<br><small>${Math.round((j.size_bytes||0)/1024)} KB</small></td><td class="analysis-status-${esc(j.status)}">${esc(j.status)}</td><td>${esc(j.packets||0)}</td><td>${esc(j.assets_discovered||0)}</td><td>${esc(j.flows_discovered||0)}</td><td>${esc(j.tags_discovered||0)}</td><td>${esc(j.alerts_generated||0)}</td><td>${esc((j.protocols||[]).join(', '))}</td><td>${esc(j.error||'')}</td><td><button class="danger-btn analysis-delete" data-id="${esc(j.id)}">Delete</button></td></tr>`).join('')}
async function uploadAnalysis(form){const fd=new FormData();fd.append('sensor_id',document.getElementById('analysis-sensor').value);const file=document.getElementById('analysis-file').files[0];if(!file)throw new Error('Select a PCAP file');fd.append('pcap',file,file.name);document.querySelectorAll('input[name=analysis-protocol]:checked').forEach(x=>fd.append('protocols',x.value));const headers={};if(token)headers.Authorization='Bearer '+token;const r=await fetch('/v1/analysis/jobs',{method:'POST',headers,body:fd});if(!r.ok)throw new Error(r.status+' '+await r.text());return r.json()}
document.getElementById('analysis-form').onsubmit=async e=>{e.preventDefault();const st=document.getElementById('analysis-upload-status');st.textContent='Uploading…';try{await uploadAnalysis(e.target);st.textContent='Queued for sensor analysis';e.target.reset();setTimeout(refreshAll,500)}catch(err){st.textContent='Upload failed: '+err.message}}
document.querySelector('#table-analysis tbody').onclick=async e=>{const b=e.target.closest('.analysis-delete');if(!b)return;if(!confirm('Delete this analysis job and stored PCAP?'))return;try{await api('/analysis/jobs/'+encodeURIComponent(b.dataset.id),{method:'DELETE'});refreshAll()}catch(err){alert(err.message)}};

function sensorSelection(){return [...document.querySelectorAll('.sensor-select:checked')].map(x=>x.dataset.id)}
function updateSensorBulk(){const ids=sensorSelection(),all=document.getElementById('sensors-all'),boxes=[...document.querySelectorAll('.sensor-select')];document.getElementById('sensors-start').hidden=!ids.length;document.getElementById('sensors-stop').hidden=!ids.length;document.getElementById('sensors-selection-count').textContent=ids.length?`${ids.length} selected`:'';if(all){all.checked=boxes.length>0&&ids.length===boxes.length;all.indeterminate=ids.length>0&&ids.length<boxes.length}}
function renderSensors(){sensors=Array.isArray(sensors)?sensors:[];populateRuleSensors();populateAnalysisSensors();document.querySelector('#table-sensors tbody').innerHTML=sensors.map(s=>{const id=s.id??s.ID,status=String(s.status??s.Status??'unknown').toLowerCase();return `<tr><td><input type="checkbox" class="sensor-select" data-id="${esc(id)}" aria-label="Select sensor ${esc(id)}"></td><td>${esc(id)}</td><td>${esc(s.name??s.Name)}</td><td>${esc(s.site_id??s.SiteID)}</td><td><span class="sensor-state sensor-state-${esc(status)}">${esc(status)}</span></td><td>${esc(s.hostname??s.Hostname)}</td><td>${esc(s.version??s.Version)}</td><td>${esc(s.go_version??s.GoVersion??'—')}</td><td>${esc(s.libpcap_version??s.LibpcapVersion??'—')}</td><td>${esc(s.gopacket_version??s.GopacketVersion??'—')}</td><td>${esc(s.capture_backend??s.CaptureBackend??'—')}</td><td>${esc(s.capture_interface??s.CaptureInterface??'—')}</td><td>${esc(s.capture_snaplen??s.CaptureSnaplen??'—')}</td><td>${(s.capture_promiscuous??s.CapturePromiscuous)?'yes':'no'}</td><td>${time(s.last_seen??s.LastSeen)}</td></tr>`}).join('');updateSensorBulk()}
async function sensorAction(action){const ids=sensorSelection();if(!ids.length)return;const verb=action==='stop'?'stop capture on':'start capture on';if(!confirm(`${verb} ${ids.length} selected sensor(s)?`))return;const start=document.getElementById('sensors-start'),stop=document.getElementById('sensors-stop');start.disabled=stop.disabled=true;try{await api('/sensors/actions',{method:'POST',body:JSON.stringify({action,sensor_ids:ids})});document.getElementById('sensors-selection-count').textContent=`${action} queued for ${ids.length} sensor(s)`;setTimeout(refreshAll,1200)}catch(err){alert(`Sensor ${action} failed: ${err.message}`)}finally{start.disabled=stop.disabled=false}}
document.querySelector('#table-sensors tbody').addEventListener('change',e=>{if(e.target.matches('.sensor-select'))updateSensorBulk()});document.getElementById('sensors-all').addEventListener('change',e=>{document.querySelectorAll('.sensor-select').forEach(x=>x.checked=e.target.checked);updateSensorBulk()});document.getElementById('sensors-start').onclick=()=>sensorAction('start');document.getElementById('sensors-stop').onclick=()=>sensorAction('stop');

function openDashboardTab(tab){
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
  dashboardBars('dashboard-severity',severityOrder.map(x=>[x[0].toUpperCase()+x.slice(1),severityCounts.get(x)||0]).filter(([,n])=>n>0),openAlerts.length,true);

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
async function refreshAll(){
  setConn(false,'connecting');
  const paths=['/topology','/assets','/tags','/sensors','/alerts','/rules','/baseline','/tags/changes','/tags/events','/analysis/jobs','/data/backups'];
  const r=await Promise.allSettled(paths.map(api));
  const list=(i)=>r[i].status==='fulfilled'&&Array.isArray(r[i].value)?r[i].value:[];
  if(r[0].status==='fulfilled')graph=(r[0].value&&Array.isArray(r[0].value.Nodes)&&Array.isArray(r[0].value.Edges))?r[0].value:{Nodes:[],Edges:[],HoneypotThreshold:100};
  if(r[1].status==='fulfilled')assets=list(1);
  if(r[2].status==='fulfilled')tags=list(2);
  if(r[3].status==='fulfilled')sensors=list(3);
  if(r[4].status==='fulfilled')alerts=list(4);
  if(r[5].status==='fulfilled')rules=list(5).map(x=>({...x,ID:x.ID||x.id,Name:x.Name||x.name,Description:x.Description||x.description,Category:x.Category||x.category,Kind:x.Kind||x.kind,Enabled:x.Enabled??x.enabled,Severity:x.Severity||x.severity,Priority:x.Priority||x.priority,Simulation:x.Simulation??x.simulation,SimulationHits:x.SimulationHits||x.simulation_hits||0,LastSimulationHit:x.LastSimulationHit||x.last_simulation_hit,Version:x.Version||x.version,Groups:x.Groups||x.groups,GroupOperator:x.GroupOperator||x.group_operator,Actions:x.Actions||x.actions,Suppression:x.Suppression||x.suppression,Field:x.Field||x.field,Value:x.Value||x.value}));
  if(r[6].status==='fulfilled')baselines=list(6);
  if(r[7].status==='fulfilled')changes=list(7);
  if(r[8].status==='fulfilled')events=list(8);
  if(r[9].status==='fulfilled')analysisJobs=list(9);if(r[10]&&r[10].status==='fulfilled')backups=list(10);
  try{if(r[0].status==='fulfilled')renderTopology()}catch(e){console.error('render topology',e)}
  try{if(r[1].status==='fulfilled')renderAssets()}catch(e){console.error('render assets',e)}
  try{if(r[2].status==='fulfilled')renderTags()}catch(e){console.error('render tags',e)}
  try{if(r[3].status==='fulfilled')renderSensors()}catch(e){console.error('render sensors',e)}
  try{if(r[4].status==='fulfilled')renderAlerts()}catch(e){console.error('render alerts',e)}
  try{if(r[5].status==='fulfilled')renderRules()}catch(e){console.error('render rules',e)}
  try{if(r[6].status==='fulfilled')renderBaseline()}catch(e){console.error('render baseline',e)}
  try{if(r[9].status==='fulfilled')renderAnalysis()}catch(e){console.error('render analysis',e)}try{renderBackups()}catch(e){console.error('render backups',e)}
  try{renderDashboard()}catch(e){console.error('render dashboard',e)}
  const rejected=r.map((x,i)=>x.status==='rejected'?{path:paths[i],reason:x.reason}:null).filter(Boolean);
  if(!rejected.length){setConn(true,'live');document.getElementById('conn-text').title=''}
  else{
    console.error('Central API refresh failures:',rejected);
    const allUnauthorized=rejected.length===paths.length&&rejected.every(x=>x.reason&&x.reason.status===401);
    const allForbidden=rejected.length===paths.length&&rejected.every(x=>x.reason&&x.reason.status===403);
    const allNetwork=rejected.length===paths.length&&rejected.every(x=>x.reason&&x.reason.kind==='network');
    let text;
    if(allUnauthorized)text='authentication required';
    else if(allForbidden)text='access forbidden';
    else if(allNetwork)text='backend unreachable';
    else text=`partial: ${rejected.map(x=>x.path).join(', ')}`;
    setConn(false,text);
    document.getElementById('conn-text').title=allUnauthorized?'Click Token and enter central.management_token':'Failed endpoints: '+rejected.map(x=>x.path).join(', ');
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
refreshAll();setInterval(refreshAll,POLL);


function renderBackups(){const tbody=document.querySelector('#table-backups tbody');if(!tbody)return;tbody.innerHTML=(backups||[]).map(b=>`<tr><td>${time(b.created_at)}</td><td>${esc(b.name)}</td><td>${esc(b.kind)}</td><td>${Math.round((b.size_bytes||0)/1024)} KB</td><td title="${esc(b.sha256)}"><code>${esc((b.sha256||'').slice(0,16))}…</code></td><td><button class="secondary-btn backup-download" data-id="${esc(b.id)}" data-name="${esc(b.name)}">Download</button> <button class="danger-btn backup-delete" data-id="${esc(b.id)}">Delete</button></td></tr>`).join('')}
async function destructive(scope,operation,sensorIDs=[]){const confirmation=prompt(`This cannot be undone. Type RESET to continue with ${scope} ${operation}.`);if(confirmation!=='RESET')return;await api('/data/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope,operation,sensor_ids:sensorIDs,confirmation})});alert(scope==='sensors'?'Reset command queued':'Reset completed');refreshAll()}
document.getElementById('data-backup-central').onclick=async()=>{try{await api('/data/backups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:'central',name:document.getElementById('data-backup-name').value})});refreshAll()}catch(e){alert(e.message)}};
document.getElementById('data-backup-sensors').onclick=async()=>{const ids=sensorSelection();if(!ids.length){alert('Select sensors in the Sensors tab first');return}try{await api('/data/backups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope:'sensors',sensor_ids:ids,name:document.getElementById('data-backup-name').value})});alert('Sensor backup commands queued')}catch(e){alert(e.message)}};
document.getElementById('data-reset-central').onclick=()=>destructive('central',document.getElementById('data-central-operation').value);
document.getElementById('data-reset-sensors').onclick=()=>{const ids=sensorSelection();if(!ids.length){alert('Select sensors in the Sensors tab first');return}destructive('sensors',document.getElementById('data-sensor-operation').value,ids)};
document.querySelector('#table-backups tbody').onclick=async e=>{const dl=e.target.closest('.backup-download'),b=e.target.closest('.backup-delete');if(dl){const h={};if(token)h.Authorization='Bearer '+token;const r=await fetch('/v1/data/backups/'+encodeURIComponent(dl.dataset.id)+'/download',{headers:h});if(!r.ok){alert(await r.text());return}const blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=(dl.dataset.name||'otlens-backup')+'.json';a.click();URL.revokeObjectURL(a.href);return}if(!b)return;if(!confirm('Delete this backup?'))return;try{await api('/data/backups/'+encodeURIComponent(b.dataset.id),{method:'DELETE'});refreshAll()}catch(err){alert(err.message)}};
