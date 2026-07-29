(function(){
  'use strict';

  const STORAGE_PREFIX='otlens.datatable.';
  const states=new Map();

  function loadState(id){
    const fallback={sortColumn:null,sortDirection:'asc',pageSize:'10',page:1};
    try{
      const saved=JSON.parse(localStorage.getItem(STORAGE_PREFIX+id)||'null');
      return {...fallback,...(saved&&typeof saved==='object'?saved:{})};
    }catch(_){return fallback}
  }

  function saveState(id,state){
    try{localStorage.setItem(STORAGE_PREFIX+id,JSON.stringify(state))}catch(_){}
  }

  function ipv4Value(value){
    const match=String(value).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?$/);
    if(!match)return null;
    const octets=match.slice(1).map(Number);
    if(octets.some(n=>n<0||n>255))return null;
    return octets.reduce((total,n)=>total*256+n,0);
  }

  function numericValue(value){
    const cleaned=String(value).trim().replace(/\s/g,'').replace(/,/g,'');
    if(!/^[+-]?(?:\d+\.?\d*|\.\d+)(?:KB|MB|GB|B|%)?$/i.test(cleaned))return null;
    const match=cleaned.match(/^([+-]?(?:\d+\.?\d*|\.\d+))(KB|MB|GB|B|%)?$/i);
    if(!match)return null;
    let number=Number(match[1]);
    const unit=(match[2]||'').toUpperCase();
    if(unit==='KB')number*=1024;
    else if(unit==='MB')number*=1024*1024;
    else if(unit==='GB')number*=1024*1024*1024;
    return Number.isFinite(number)?number:null;
  }

  function dateValue(value){
    const text=String(value).trim();
    if(!text||text==='—')return null;
    if(!/[/:\-]/.test(text))return null;
    const parsed=Date.parse(text);
    return Number.isNaN(parsed)?null:parsed;
  }

  function severityValue(value){
    const rank={info:0,low:1,medium:2,high:3,critical:4};
    const normalized=String(value).trim().toLowerCase();
    return Object.prototype.hasOwnProperty.call(rank,normalized)?rank[normalized]:null;
  }

  function cellValue(row,column){
    const cell=row.cells[column];
    if(!cell)return '';
    return cell.dataset.sortValue!==undefined?cell.dataset.sortValue:cell.textContent.trim();
  }

  function compareValues(a,b){
    const aBlank=a===''||a==='—',bBlank=b===''||b==='—';
    if(aBlank||bBlank)return aBlank===bBlank?0:(aBlank?1:-1);

    const aIP=ipv4Value(a),bIP=ipv4Value(b);
    if(aIP!==null&&bIP!==null)return aIP-bIP;

    const aSeverity=severityValue(a),bSeverity=severityValue(b);
    if(aSeverity!==null&&bSeverity!==null)return aSeverity-bSeverity;

    const aNumber=numericValue(a),bNumber=numericValue(b);
    if(aNumber!==null&&bNumber!==null)return aNumber-bNumber;

    const aDate=dateValue(a),bDate=dateValue(b);
    if(aDate!==null&&bDate!==null)return aDate-bDate;

    return String(a).localeCompare(String(b),undefined,{numeric:true,sensitivity:'base'});
  }

  function makePager(table,state){
    const pager=document.createElement('div');
    pager.className='table-pager';
    pager.dataset.table=table.id;
    pager.innerHTML=`<label class="table-page-size">Rows per page <select aria-label="Rows per page"><option value="10">10</option><option value="50">50</option><option value="100">100</option><option value="all">All</option></select></label><span class="table-page-info"></span><div class="table-page-actions"><button type="button" class="secondary-btn table-page-prev">Previous</button><span class="table-page-number"></span><button type="button" class="secondary-btn table-page-next">Next</button></div>`;
    table.closest('.scrollable').insertAdjacentElement('afterend',pager);
    const select=pager.querySelector('select');
    select.value=state.pageSize;
    select.addEventListener('change',()=>{
      state.pageSize=select.value;
      state.page=1;
      saveState(table.id,state);
      refresh(table.id);
    });
    pager.querySelector('.table-page-prev').addEventListener('click',()=>{
      if(state.page>1){state.page--;saveState(table.id,state);refresh(table.id)}
    });
    pager.querySelector('.table-page-next').addEventListener('click',()=>{
      state.page++;
      saveState(table.id,state);
      refresh(table.id);
    });
    return pager;
  }

  function initializeTable(table){
    if(!table.id||states.has(table.id))return;
    const state=loadState(table.id);
    const headers=[...table.querySelectorAll('thead th')];
    headers.forEach((header,index)=>{
      const title=header.textContent.trim().toLowerCase();
      const nonData=header.querySelector('input,button')||title==='action'||title==='actions'||!title;
      if(nonData)return;
      header.dataset.sort=String(index);
      header.tabIndex=0;
      header.setAttribute('role','button');
      header.setAttribute('aria-label',`Sort by ${header.textContent.trim()}`);
      const activate=()=>{
        if(state.sortColumn===index)state.sortDirection=state.sortDirection==='asc'?'desc':'asc';
        else{state.sortColumn=index;state.sortDirection='asc'}
        state.page=1;
        saveState(table.id,state);
        refresh(table.id);
      };
      header.addEventListener('click',activate);
      header.addEventListener('keydown',event=>{
        if(event.key==='Enter'||event.key===' '){event.preventDefault();activate()}
      });
    });
    const pager=makePager(table,state);
    states.set(table.id,{table,state,pager});
    refresh(table.id);
  }

  function refresh(id){
    const entry=states.get(id);
    if(!entry)return;
    const {table,state,pager}=entry;
    const body=table.tBodies[0];
    if(!body)return;
    const rows=[...body.rows];

    if(state.sortColumn!==null){
      rows.sort((left,right)=>{
        const result=compareValues(cellValue(left,state.sortColumn),cellValue(right,state.sortColumn));
        return state.sortDirection==='desc'?-result:result;
      });
      const fragment=document.createDocumentFragment();
      rows.forEach(row=>fragment.appendChild(row));
      body.appendChild(fragment);
    }

    table.querySelectorAll('thead th').forEach((header,index)=>{
      header.classList.toggle('sorted-asc',state.sortColumn===index&&state.sortDirection==='asc');
      header.classList.toggle('sorted-desc',state.sortColumn===index&&state.sortDirection==='desc');
      if(header.dataset.sort!==undefined)header.setAttribute('aria-sort',state.sortColumn===index?(state.sortDirection==='asc'?'ascending':'descending'):'none');
    });

    const total=rows.length;
    const pageSize=state.pageSize==='all'?Math.max(total,1):Number(state.pageSize)||10;
    const pages=state.pageSize==='all'?1:Math.max(1,Math.ceil(total/pageSize));
    state.page=Math.min(Math.max(1,state.page),pages);
    const start=state.pageSize==='all'?0:(state.page-1)*pageSize;
    const end=state.pageSize==='all'?total:Math.min(start+pageSize,total);
    rows.forEach((row,index)=>{row.hidden=index<start||index>=end});

    pager.querySelector('select').value=state.pageSize;
    pager.querySelector('.table-page-info').textContent=total?`${start+1}–${end} of ${total}`:'0 records';
    pager.querySelector('.table-page-number').textContent=`Page ${state.page} of ${pages}`;
    pager.querySelector('.table-page-prev').disabled=state.page<=1;
    pager.querySelector('.table-page-next').disabled=state.page>=pages;
    saveState(id,state);
  }

  function init(){document.querySelectorAll('table.data-table[id]').forEach(initializeTable)}

  window.OTDataTables={init,refresh};
})();
