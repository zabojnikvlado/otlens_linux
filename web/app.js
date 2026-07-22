// OTLens dashboard. Vanilla JS, no build step — fetches the REST API
// this same server exposes (see internal/api) and polls it on an
// interval. Field names below match the Go structs' JSON output
// exactly (encoding/json's default: exported field name, PascalCase)
// — the one exception is /baseline, which uses explicit snake_case
// json tags (see detect.BaselineStatus).

const POLL_INTERVAL_MS = 5000;

// ---------- tiny helpers ----------

function fmtTime(iso) {
  if (!iso || iso.startsWith('0001-01-01')) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { hour12: false });
}

function fmtValue(v) {
  if (v === null || v === undefined) return '—';
  if (Array.isArray(v)) {
    // Safety net: with per-address decomposition (see
    // internal/store's expandAddressRange) a Tag's value should
    // normally be a single scalar, not a long array — this just
    // keeps any edge case (old pre-decomposition data, an unusually
    // large single read) from rendering as an unreadable wall of
    // text instead of quietly truncating with a count.
    const maxItems = 20;
    if (v.length > maxItems) {
      return v.slice(0, maxItems).join(', ') + ` … (${v.length} total)`;
    }
    return v.join(', ');
  }
  return String(v);
}

// S7 addresses (see internal/store's extractS7Address) are stored as
// a raw wire bit-address (byte offset*8 + bit offset) — the same
// encoding S7comm itself uses on the wire, but not how any S7
// engineer actually writes an address. Modbus addresses are already
// plain register/coil numbers with no such encoding, so this only
// applies to the S7 address spaces.
const S7_AREAS = ['I', 'Q', 'M', 'C', 'T'];

function fmtTagAddress(addressSpace, address) {

  const isS7 = S7_AREAS.includes(addressSpace) || /^DB\d+$/.test(addressSpace);

  if (!isS7) {
    return `${addressSpace} ${address}`;
  }

  const byteAddr = Math.floor(address / 8);
  const bitAddr = address % 8;

  return bitAddr === 0
    ? `${addressSpace}.${byteAddr}`
    : `${addressSpace}.${byteAddr}.${bitAddr}`;
}

function fmtBytes(n) {
  if (n === undefined || n === null) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0, val = n;
  while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
  return `${val.toFixed(val < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  if (res.status === 204) return null;
  return res.json();
}

function setConn(ok) {
  const dot = document.getElementById('conn-dot');
  const text = document.getElementById('conn-text');
  dot.className = 'dot ' + (ok ? 'ok' : 'down');
  text.textContent = ok ? 'live' : 'backend unreachable';
}

// ---------- tabs ----------

document.getElementById('tabs').addEventListener('click', (e) => {
  const btn = e.target.closest('.tab');
  if (!btn) return;

  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');

  const target = btn.dataset.tab;
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + target).classList.add('active');

  if (target === 'topology' && network) {
    // vis-network needs a nudge to size correctly after being hidden
    setTimeout(() => network.redraw(), 50);
  }
});

// ---------- baseline badge ----------

async function refreshBaseline() {
  const status = await api('/baseline'); // snake_case keys — see header note
  const dot = document.getElementById('baseline-dot');
  const text = document.getElementById('baseline-text');

  if (status.mode === 'learning') {
    dot.className = 'dot learning';
    const ends = new Date(status.learning_ends_at);
    const remainingMs = ends.getTime() - Date.now();
    const remaining = remainingMs > 0 ? Math.ceil(remainingMs / 60000) : 0;
    text.textContent = `learning (${remaining}m left, ${status.learned_patterns} patterns)`;
  } else {
    dot.className = 'dot monitoring';
    text.textContent = `monitoring (${status.learned_patterns} known patterns)`;
  }
}

// ---------- assets ----------

// Default: most recently seen device on top. Without an explicit
// sort, Go's map iteration order (which /assets is built from) is
// randomized on every single request — rebuilding the table in
// whatever order came back made rows appear to "disappear" as they
// silently changed position on every 5s poll. Sorting here fixes
// that regardless of what order the API happens to return.
let assetSort = { column: 'last', direction: 'desc' };
let lastAssets = [];
let selectedAssetMACs = new Set();

function sortAssets(assets) {

  const dir = assetSort.direction === 'asc' ? 1 : -1;
  const col = assetSort.column;

  return assets.slice().sort((a, b) => {

    let av, bv;

    switch (col) {
      case 'ip':       av = a.IP || ''; bv = b.IP || ''; break;
      case 'mac':       av = a.MAC; bv = b.MAC; break;
      case 'vendor':    av = a.Vendor || ''; bv = b.Vendor || ''; break;
      case 'hostname':  av = a.Hostname || ''; bv = b.Hostname || ''; break;
      case 'class':     av = a.IsOT ? 1 : 0; bv = b.IsOT ? 1 : 0; break;
      case 'score':     av = a.Score || 1; bv = b.Score || 1; break;
      case 'packets':   av = a.PacketCount; bv = b.PacketCount; break;
      case 'first':     av = new Date(a.FirstSeen).getTime(); bv = new Date(b.FirstSeen).getTime(); break;
      case 'last':
      default:          av = new Date(a.LastSeen).getTime(); bv = new Date(b.LastSeen).getTime(); break;
    }

    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;

    // Tie-break with a stable, unique key — without this, equal
    // primary sort values (e.g. identical LastSeen, common right
    // after a batch pcap analysis) would silently reshuffle relative
    // order between polls, since the backend (a Go map, unordered)
    // can return tied records in a different order each time.
    return (a.MAC || '').localeCompare(b.MAC || '');
  });
}

function updateAssetSortIndicators() {

  document.querySelectorAll('#table-assets thead th[data-sort]').forEach(th => {

    th.classList.remove('sorted-asc', 'sorted-desc');

    if (th.dataset.sort === assetSort.column) {
      th.classList.add(assetSort.direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
    }
  });
}

function updateAssetsBulkBar() {

  const bar = document.getElementById('assets-bulk-bar');
  const count = document.getElementById('assets-bulk-count');

  bar.hidden = selectedAssetMACs.size === 0;
  count.textContent = `${selectedAssetMACs.size} selected`;
}

function renderAssets() {

  const tbody = document.querySelector('#table-assets tbody');
  const empty = document.querySelector('#view-assets .empty-state');
  const paginationEl = document.getElementById('assets-pagination');

  tbody.innerHTML = '';
  empty.hidden = lastAssets.length > 0;

  // Drop selection for any asset no longer present.
  const currentMACs = new Set(lastAssets.map(a => a.MAC));
  selectedAssetMACs.forEach(mac => { if (!currentMACs.has(mac)) selectedAssetMACs.delete(mac); });

  const sorted = sortAssets(lastAssets);

  const pageSize = assetPageSize === 'all' ? sorted.length : assetPageSize;
  const totalPages = pageSize > 0 ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1;

  if (assetPage > totalPages) assetPage = totalPages;
  if (assetPage < 1) assetPage = 1;

  const pageItems = assetPageSize === 'all'
    ? sorted
    : sorted.slice((assetPage - 1) * pageSize, assetPage * pageSize);

  for (const a of pageItems) {

    const tr = document.createElement('tr');
    const isHoneypot = (a.Score || 1) >= honeypotThreshold;

    if (isHoneypot) {
      tr.classList.add('row-honeypot');
    } else if (a.Confirmed === false) {
      tr.classList.add('row-unconfirmed');
    }

    tr.innerHTML = `
      <td></td>
      <td>${a.IP || '—'}</td>
      <td>${a.MAC}</td>
      <td>${a.Vendor || '—'}</td>
      <td>${a.Hostname || '—'}</td>
      <td><span class="pill ${a.IsOT ? 'ot' : 'it'}">${a.IsOT ? 'OT' : 'IT'}</span></td>
      <td>${fmtValue(a.Protocols)}</td>
      <td>${isHoneypot ? `<span class="pill honeypot">🍯 ${a.Score}</span>` : (a.Score || 1)}</td>
      <td>${a.PacketCount}</td>
      <td>${fmtTime(a.FirstSeen)}</td>
      <td>${fmtTime(a.LastSeen)}</td>
      <td></td>
    `;

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = selectedAssetMACs.has(a.MAC);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) selectedAssetMACs.add(a.MAC);
      else selectedAssetMACs.delete(a.MAC);
      updateAssetsBulkBar();
    });
    tr.firstElementChild.appendChild(checkbox);

    if (a.Confirmed === false) {

      const confirmBtn = document.createElement('button');
      confirmBtn.className = 'ack-btn';
      confirmBtn.textContent = 'Confirm';
      confirmBtn.addEventListener('click', () => confirmAsset(a.MAC, confirmBtn));

      tr.lastElementChild.appendChild(confirmBtn);
    }

    // Opens the vulnerabilities popup — excludes the checkbox/Confirm
    // button cells (both already have their own click handlers above;
    // without this check, clicking either would also pop the modal
    // open underneath whatever it was actually meant to do).
    tr.addEventListener('click', (e) => {
      if (e.target.closest('input, button')) return;
      openAssetVulnerabilities(a);
    });

    tbody.appendChild(tr);
  }

  renderPagination(paginationEl, assetPage, totalPages, (page) => {
    assetPage = page;
    renderAssets();
  });

  updateAssetsBulkBar();
}

async function confirmAsset(mac, btn) {

  btn.disabled = true;

  try {
    await api(`/assets/${encodeURIComponent(mac)}/confirm`, { method: 'POST' });
    refreshAssets();
  } catch (e) {
    console.error('Confirm failed for', mac, e);
    btn.disabled = false;
  }
}

async function bulkDeleteAssets() {

  const macs = Array.from(selectedAssetMACs);

  if (macs.length === 0) return;

  if (!confirm(`Delete ${macs.length} selected asset(s)? This cannot be undone (though a device reappears if seen again on the wire).`)) {
    return;
  }

  const btn = document.getElementById('bulk-delete-assets-btn');
  btn.disabled = true;

  for (const mac of macs) {

    try {
      await api(`/assets/${encodeURIComponent(mac)}`, { method: 'DELETE' });
    } catch (e) {
      console.error('Delete failed for', mac, e);
    }
  }

  selectedAssetMACs.clear();
  btn.disabled = false;

  refreshAssets();
}

function initAssetSort() {

  document.querySelectorAll('#table-assets thead th[data-sort]').forEach(th => {

    th.addEventListener('click', () => {

      const col = th.dataset.sort;

      if (assetSort.column === col) {
        assetSort.direction = assetSort.direction === 'asc' ? 'desc' : 'asc';
      } else {
        assetSort.column = col;
        assetSort.direction = 'desc';
      }

      updateAssetSortIndicators();
      assetPage = 1;
      renderAssets();
    });
  });

  updateAssetSortIndicators();

  document.getElementById('assets-page-size').addEventListener('change', (e) => {
    assetPageSize = e.target.value === 'all' ? 'all' : Number(e.target.value);
    assetPage = 1;
    renderAssets();
  });

  document.getElementById('assets-select-all').addEventListener('change', (e) => {

    document.querySelectorAll('#table-assets tbody input[type=checkbox]').forEach(cb => {
      cb.checked = e.target.checked;
      cb.dispatchEvent(new Event('change'));
    });
  });

  document.getElementById('bulk-delete-assets-btn').addEventListener('click', bulkDeleteAssets);
}

async function refreshAssets() {
  lastAssets = await api('/assets');
  renderAssets();
}

// ---------- flows ----------

// Default sort: most recently active conversation on top. Clicking a
// column header (see initFlowSort below) changes this; re-clicking
// the same column flips direction.
let flowSort = { column: 'last', direction: 'desc' };
let lastFlows = [];
let assetPageSize = 10; // number, or 'all'
let assetPage = 1;

let flowPageSize = 50; // number, or 'all'
let flowPage = 1;

function sortFlows(flows) {

  const dir = flowSort.direction === 'asc' ? 1 : -1;
  const col = flowSort.column;

  return flows.slice().sort((a, b) => {

    let av, bv;

    switch (col) {
      case 'src':      av = `${a.SrcIP}:${a.SrcPort}`; bv = `${b.SrcIP}:${b.SrcPort}`; break;
      case 'dst':      av = `${a.DstIP}:${a.DstPort}`; bv = `${b.DstIP}:${b.DstPort}`; break;
      case 'protocol': av = a.Protocol; bv = b.Protocol; break;
      case 'packets':  av = a.Packets; bv = b.Packets; break;
      case 'bytes':    av = a.Bytes; bv = b.Bytes; break;
      case 'first':    av = new Date(a.FirstSeen).getTime(); bv = new Date(b.FirstSeen).getTime(); break;
      case 'last':
      default:         av = new Date(a.LastSeen).getTime(); bv = new Date(b.LastSeen).getTime(); break;
    }

    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;

    // See sortAssets' identical comment above for why this matters.
    return (a.ID || '').localeCompare(b.ID || '');
  });
}

function updateFlowSortIndicators() {

  document.querySelectorAll('#table-flows thead th[data-sort]').forEach(th => {

    th.classList.remove('sorted-asc', 'sorted-desc');

    if (th.dataset.sort === flowSort.column) {
      th.classList.add(flowSort.direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
    }
  });
}

// renderPagination is generic (not flows-specific) so any other tab
// can reuse it later without duplicating the button-window logic.
// Renders: « prev, page numbers (with … gaps once there are more
// than a handful of pages), next ».
function renderPagination(container, currentPage, totalPages, onPageClick) {

  container.innerHTML = '';

  if (totalPages <= 1) return;

  const makeButton = (label, page, disabled, active) => {

    const btn = document.createElement('button');
    btn.className = 'page-btn' + (active ? ' active' : '');
    btn.textContent = label;
    btn.disabled = disabled;
    btn.addEventListener('click', () => onPageClick(page));

    return btn;
  };

  container.appendChild(makeButton('‹', currentPage - 1, currentPage === 1, false));

  const windowSize = 2;
  const pages = [];

  for (let p = 1; p <= totalPages; p++) {
    if (p === 1 || p === totalPages || (p >= currentPage - windowSize && p <= currentPage + windowSize)) {
      pages.push(p);
    }
  }

  let prevPage = null;

  for (const p of pages) {

    if (prevPage !== null && p - prevPage > 1) {

      const ellipsis = document.createElement('span');
      ellipsis.className = 'page-ellipsis';
      ellipsis.textContent = '…';
      container.appendChild(ellipsis);
    }

    container.appendChild(makeButton(String(p), p, false, p === currentPage));
    prevPage = p;
  }

  container.appendChild(makeButton('›', currentPage + 1, currentPage === totalPages, false));
}

function renderFlows() {

  const tbody = document.querySelector('#table-flows tbody');
  const empty = document.querySelector('#view-flows .empty-state');
  const paginationEl = document.getElementById('flows-pagination');

  tbody.innerHTML = '';
  empty.hidden = lastFlows.length > 0;

  const sorted = sortFlows(lastFlows);

  const pageSize = flowPageSize === 'all' ? sorted.length : flowPageSize;
  const totalPages = pageSize > 0 ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1;

  if (flowPage > totalPages) flowPage = totalPages;
  if (flowPage < 1) flowPage = 1;

  const pageItems = flowPageSize === 'all'
    ? sorted
    : sorted.slice((flowPage - 1) * pageSize, flowPage * pageSize);

  for (const f of pageItems) {

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${f.SrcIP}:${f.SrcPort}</td>
      <td>${f.DstIP}:${f.DstPort}</td>
      <td>${f.Protocol}</td>
      <td>${f.Packets}</td>
      <td>${fmtBytes(f.Bytes)}</td>
      <td>${fmtTime(f.FirstSeen)}</td>
      <td>${fmtTime(f.LastSeen)}</td>
    `;
    tbody.appendChild(tr);
  }

  renderPagination(paginationEl, flowPage, totalPages, (page) => {
    flowPage = page;
    renderFlows();
  });
}

// Click handlers are wired once at startup, not per-poll — they
// re-render from the last-fetched data (no need to re-hit the API
// just to change sort order).
function initFlowSort() {

  document.querySelectorAll('#table-flows thead th[data-sort]').forEach(th => {

    th.addEventListener('click', () => {

      const col = th.dataset.sort;

      if (flowSort.column === col) {
        flowSort.direction = flowSort.direction === 'asc' ? 'desc' : 'asc';
      } else {
        flowSort.column = col;
        flowSort.direction = 'desc';
      }

      flowPage = 1;
      updateFlowSortIndicators();
      renderFlows();
    });
  });

  updateFlowSortIndicators();

  document.getElementById('flows-page-size').addEventListener('change', (e) => {
    flowPageSize = e.target.value === 'all' ? 'all' : Number(e.target.value);
    flowPage = 1;
    renderFlows();
  });
}

async function refreshFlows() {
  lastFlows = await api('/flows');
  renderFlows();
}

// ---------- OT tags ----------

// Same instability fix as assets/flows: default to most recently
// active variable on top, sorted explicitly rather than however the
// API happens to return them.
let tagSort = { column: 'last', direction: 'desc' };
let lastTags = [];

function sortTags(tags) {

  const dir = tagSort.direction === 'asc' ? 1 : -1;
  const col = tagSort.column;

  return tags.slice().sort((a, b) => {

    let av, bv;

    switch (col) {
      case 'device':   av = `${a.DeviceIP}:${a.DevicePort}`; bv = `${b.DeviceIP}:${b.DevicePort}`; break;
      case 'protocol': av = a.Protocol; bv = b.Protocol; break;
      case 'address':  av = `${a.AddressSpace} ${a.Address}`; bv = `${b.AddressSpace} ${b.Address}`; break;
      case 'op':       av = a.Operation; bv = b.Operation; break;
      case 'value':    av = String(a.LastValue ?? ''); bv = String(b.LastValue ?? ''); break;
      case 'changed':  av = new Date(a.LastChangeAt).getTime(); bv = new Date(b.LastChangeAt).getTime(); break;
      case 'polls':    av = a.PollCount; bv = b.PollCount; break;
      case 'changes':  av = a.ChangeCount; bv = b.ChangeCount; break;
      case 'last':
      default:         av = new Date(a.LastSeen).getTime(); bv = new Date(b.LastSeen).getTime(); break;
    }

    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;

    // See sortAssets' identical comment above for why this matters.
    return (a.Key || '').localeCompare(b.Key || '');
  });
}

function updateTagSortIndicators() {

  document.querySelectorAll('#table-tags thead th[data-sort]').forEach(th => {

    th.classList.remove('sorted-asc', 'sorted-desc');

    if (th.dataset.sort === tagSort.column) {
      th.classList.add(tagSort.direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
    }
  });
}

function renderTags() {

  const tbody = document.querySelector('#table-tags tbody');
  const empty = document.querySelector('#view-tags .empty-state');

  tbody.innerHTML = '';
  empty.hidden = lastTags.length > 0;

  for (const t of sortTags(lastTags)) {

    const tr = document.createElement('tr');
    tr.classList.add('clickable-row');
    tr.innerHTML = `
      <td>${t.DeviceIP}:${t.DevicePort}</td>
      <td>${t.Protocol}</td>
      <td>${fmtTagAddress(t.AddressSpace, t.Address)}</td>
      <td>${t.Operation}</td>
      <td>${fmtValue(t.LastValue)}</td>
      <td>${fmtValue(t.PreviousValue)}</td>
      <td>${fmtTime(t.LastChangeAt)}</td>
      <td>${t.PollCount}</td>
      <td>${t.ChangeCount}</td>
    `;
    tr.addEventListener('click', () => openTagHistory(t));
    tbody.appendChild(tr);
  }
}

// ---------- tag history modal ----------

// Tracks the active Chart.js instance so it can be destroyed before
// a new one is created — reusing the same <canvas> across multiple
// openTagHistory calls without destroying the previous chart first
// leaks memory and, with Chart.js specifically, throws on the
// "Canvas is already in use" condition.
let tagHistoryChart = null;

// renderTagHistoryChart draws a trend line for one tag's value
// history into the popup's canvas. changes should be the same array
// openTagHistory already fetched from /tags/changes — this re-sorts
// it chronologically itself (the table above shows newest-first,
// which is backwards for a trend line).
function renderTagHistoryChart(changes) {

  const wrap = document.getElementById('tag-history-chart-wrap');
  const empty = document.getElementById('tag-history-chart-empty');

  if (tagHistoryChart) {
    tagHistoryChart.destroy();
    tagHistoryChart = null;
  }

  const chronological = changes.slice().sort((a, b) => new Date(a.Timestamp) - new Date(b.Timestamp));

  // A value that's an array is only possible from data recorded
  // before the per-address decomposition fix (see
  // store.expandAddressRange) — not something a line chart can show
  // meaningfully, so it's excluded rather than attempted.
  const plottable = chronological.filter(c => {
    const v = c.NewValue;
    return typeof v === 'number' || typeof v === 'boolean';
  });

  if (plottable.length < 2) {

    wrap.hidden = true;
    empty.hidden = false;
    empty.textContent = chronological.length > 0 && plottable.length === 0
      ? "This value type can't be charted."
      : 'Not enough history yet to chart a trend.';
    return;
  }

  wrap.hidden = false;
  empty.hidden = true;

  // A coil/bit alternates between exactly two states — a stepped,
  // filled ON/OFF chart reads much more naturally for that than a
  // sloped line implying values in between that never happened.
  const isBoolean = typeof plottable[0].NewValue === 'boolean';

  const labels = plottable.map(c => fmtTime(c.Timestamp));
  const values = plottable.map(c => isBoolean ? (c.NewValue ? 1 : 0) : c.NewValue);

  const axisFont = { family: 'IBM Plex Mono', size: 10 };
  const axisColor = '#7d8aa3';
  const gridColor = 'rgba(125, 138, 163, 0.12)';

  const ctx = document.getElementById('tag-history-chart').getContext('2d');

  tagHistoryChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: values,
        borderColor: '#3fbfb0',
        backgroundColor: 'rgba(63, 191, 176, 0.15)',
        borderWidth: 2,
        pointRadius: values.length > 60 ? 0 : 2,
        pointBackgroundColor: '#3fbfb0',
        stepped: isBoolean,
        fill: isBoolean,
        tension: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: {
          ticks: { color: axisColor, maxTicksLimit: 8, font: axisFont },
          grid: { color: gridColor },
        },
        y: isBoolean
          ? {
              min: -0.2,
              max: 1.2,
              ticks: {
                color: axisColor,
                stepSize: 1,
                font: axisFont,
                callback: (v) => v === 1 ? 'ON' : (v === 0 ? 'OFF' : ''),
              },
              grid: { color: gridColor },
            }
          : {
              ticks: { color: axisColor, font: axisFont },
              grid: { color: gridColor },
            },
      },
    },
  });
}

async function openTagHistory(tag) {

  const backdrop = document.getElementById('tag-history-backdrop');
  const title = document.getElementById('tag-history-title');
  const summary = document.getElementById('tag-history-summary');

  title.textContent = `${tag.DeviceIP}:${tag.DevicePort} — ${fmtTagAddress(tag.AddressSpace, tag.Address)}`;

  const rangeLine = (tag.MinValue !== null && tag.MinValue !== undefined)
    ? `<div><strong>Learned range:</strong> ${fmtValue(tag.MinValue)} – ${fmtValue(tag.MaxValue)}</div>`
    : '';

  summary.innerHTML = `
    <div><strong>Protocol:</strong> ${tag.Protocol}</div>
    <div><strong>Operation:</strong> ${tag.Operation}</div>
    <div><strong>Current value:</strong> ${fmtValue(tag.LastValue)}</div>
    ${rangeLine}
    <div><strong>Polls:</strong> ${tag.PollCount} · <strong>Changes:</strong> ${tag.ChangeCount}</div>
  `;

  backdrop.hidden = false;

  const changesTbody = document.querySelector('#tag-history-changes-table tbody');
  const changesEmpty = document.getElementById('tag-history-changes-empty');
  const eventsTbody = document.querySelector('#tag-history-events-table tbody');
  const eventsEmpty = document.getElementById('tag-history-events-empty');

  changesTbody.innerHTML = '';
  eventsTbody.innerHTML = '';
  changesEmpty.hidden = true;
  eventsEmpty.hidden = true;
  changesEmpty.textContent = 'No value changes recorded yet.';
  eventsEmpty.textContent = 'No control events recorded yet.';

  if (tagHistoryChart) {
    tagHistoryChart.destroy();
    tagHistoryChart = null;
  }
  document.getElementById('tag-history-chart-wrap').hidden = true;
  document.getElementById('tag-history-chart-empty').hidden = true;

  try {

    const [changes, events] = await Promise.all([
      api(`/tags/changes?key=${encodeURIComponent(tag.Key)}`),
      api(`/tags/events?key=${encodeURIComponent(tag.Key)}`),
    ]);

    // Newest first — most relevant for "what just happened to this
    // variable" at a glance.
    changes.sort((a, b) => new Date(b.Timestamp) - new Date(a.Timestamp));
    events.sort((a, b) => new Date(b.Timestamp) - new Date(a.Timestamp));

    renderTagHistoryChart(changes);

    changesEmpty.hidden = changes.length > 0;

    for (const c of changes) {

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${fmtTime(c.Timestamp)}</td>
        <td>${fmtValue(c.OldValue)}</td>
        <td>${fmtValue(c.NewValue)}</td>
      `;
      changesTbody.appendChild(tr);
    }

    eventsEmpty.hidden = events.length > 0;

    for (const e of events) {

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${fmtTime(e.Timestamp)}</td>
        <td>${e.FunctionName}</td>
        <td>${e.SrcIP}:${e.SrcPort} → ${e.DstIP}:${e.DstPort}</td>
        <td>${e.SecurityRelevant ? '⚠ yes' : '—'}</td>
      `;
      eventsTbody.appendChild(tr);
    }

  } catch (err) {

    console.error('Loading tag history failed:', err);
    changesEmpty.hidden = false;
    changesEmpty.textContent = 'Failed to load history — see browser console.';
  }
}

function closeTagHistory() {

  document.getElementById('tag-history-backdrop').hidden = true;

  if (tagHistoryChart) {
    tagHistoryChart.destroy();
    tagHistoryChart = null;
  }
}

// ---------- asset vulnerabilities modal ----------

// openAssetVulnerabilities fetches and shows known vulnerabilities
// for one asset's vendor (see GET /assets/:mac/vulnerabilities).
// Offline-only on the backend (internal/vuln) — this just displays
// whatever the backend already resolved, no separate network call
// of its own.
async function openAssetVulnerabilities(asset) {

  const backdrop = document.getElementById('asset-vuln-backdrop');
  const title = document.getElementById('asset-vuln-title');
  const summary = document.getElementById('asset-vuln-summary');
  const tbody = document.querySelector('#asset-vuln-table tbody');
  const empty = document.getElementById('asset-vuln-empty');

  title.textContent = `Known vulnerabilities — ${asset.IP || asset.MAC}`;
  summary.innerHTML = '';
  tbody.innerHTML = '';
  empty.hidden = true;

  backdrop.hidden = false;

  try {

    const data = await api(`/assets/${encodeURIComponent(asset.MAC)}/vulnerabilities`);

    summary.innerHTML = `<div><strong>Vendor:</strong> ${data.vendor || 'Unknown vendor'}</div>`;

    if (!data.enabled) {

      empty.hidden = false;
      empty.textContent = 'Vulnerability lookup is not enabled (vulnerability.enabled in config.yaml).';
      return;
    }

    if (!data.advisories || data.advisories.length === 0) {

      empty.hidden = false;
      empty.textContent = `No known advisories found for vendor "${data.vendor}" in the loaded snapshot. This checks the vendor name only — it can't confirm this specific device/firmware is unaffected, only that nothing in the current snapshot mentions this vendor.`;
      return;
    }

    for (const adv of data.advisories) {

      const tr = document.createElement('tr');

      tr.innerHTML = `
        <td>${adv.CVEID}</td>
        <td><span class="sev ${(adv.Severity || '').toLowerCase()}">${adv.Severity || '—'}</span></td>
        <td>${adv.Title || '—'}${adv.Product ? ` (${adv.Product})` : ''}</td>
        <td>${adv.PublishedDate || '—'}</td>
        <td></td>
      `;

      if (adv.URL) {

        const link = document.createElement('a');
        link.href = adv.URL;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = 'Details';
        link.className = 'ack-btn';
        tr.lastElementChild.appendChild(link);
      }

      tbody.appendChild(tr);
    }

  } catch (e) {

    console.error('Fetching vulnerabilities failed for', asset.MAC, e);
    empty.hidden = false;
    empty.textContent = 'Failed to load vulnerability data — see console for details.';
  }
}

function closeAssetVulnerabilities() {
  document.getElementById('asset-vuln-backdrop').hidden = true;
}

function initAssetVulnModal() {

  document.getElementById('asset-vuln-close').addEventListener('click', closeAssetVulnerabilities);

  document.getElementById('asset-vuln-backdrop').addEventListener('click', (e) => {
    if (e.target.id === 'asset-vuln-backdrop') closeAssetVulnerabilities();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAssetVulnerabilities();
  });
}

function initTagHistoryModal() {

  document.getElementById('tag-history-close').addEventListener('click', closeTagHistory);

  document.getElementById('tag-history-backdrop').addEventListener('click', (e) => {
    if (e.target.id === 'tag-history-backdrop') closeTagHistory();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeTagHistory();
  });
}

function initTagSort() {

  document.querySelectorAll('#table-tags thead th[data-sort]').forEach(th => {

    th.addEventListener('click', () => {

      const col = th.dataset.sort;

      if (tagSort.column === col) {
        tagSort.direction = tagSort.direction === 'asc' ? 'desc' : 'asc';
      } else {
        tagSort.column = col;
        tagSort.direction = 'desc';
      }

      updateTagSortIndicators();
      renderTags();
    });
  });

  updateTagSortIndicators();
}

async function refreshTags() {
  lastTags = await api('/tags');
  renderTags();
}

// ---------- alerts ----------

let alertSort = { column: 'last', direction: 'desc' };
let lastAlerts = [];
let lastRules = [];
let selectedAlertIds = new Set();

const sevRank = { critical: 0, high: 1, medium: 2, low: 3 };

function sortAlerts(alerts) {

  const dir = alertSort.direction === 'asc' ? 1 : -1;
  const col = alertSort.column;

  return alerts.slice().sort((a, b) => {

    let av, bv;

    switch (col) {
      case 'severity': av = sevRank[a.Severity] ?? 9; bv = sevRank[b.Severity] ?? 9; break;
      case 'status':   av = a.Status || 'new'; bv = b.Status || 'new'; break;
      case 'type':     av = a.Type; bv = b.Type; break;
      case 'message':  av = a.Message; bv = b.Message; break;
      case 'count':    av = a.Count; bv = b.Count; break;
      case 'first':    av = new Date(a.FirstSeen).getTime(); bv = new Date(b.FirstSeen).getTime(); break;
      case 'last':
      default:         av = new Date(a.LastSeen).getTime(); bv = new Date(b.LastSeen).getTime(); break;
    }

    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;

    // See sortAssets' identical comment above for why this matters.
    return (a.ID || '').localeCompare(b.ID || '');
  });
}

function updateAlertSortIndicators() {

  document.querySelectorAll('#table-alerts thead th[data-sort]').forEach(th => {

    th.classList.remove('sorted-asc', 'sorted-desc');

    if (th.dataset.sort === alertSort.column) {
      th.classList.add(alertSort.direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
    }
  });
}

function updateAlertsBulkBar() {

  const bar = document.getElementById('alerts-bulk-bar');
  const count = document.getElementById('alerts-bulk-count');

  bar.hidden = selectedAlertIds.size === 0;
  count.textContent = `${selectedAlertIds.size} selected`;
}

// Single-alert action (per-row Approve/Confirm buttons).
async function setAlertStatus(id, action, buttons) {

  buttons.forEach(b => b.disabled = true);

  try {
    await api(`/alerts/${encodeURIComponent(id)}/${action}`, { method: 'POST' });
    selectedAlertIds.delete(id);
    refreshAlerts();
  } catch (e) {
    console.error('Alert action failed:', e);
    buttons.forEach(b => b.disabled = false);
  }
}

// Bulk action across every currently checked alert (the bulk bar's
// Approve/Confirm buttons). Requests run one at a time rather than
// all at once — simpler to reason about than a burst of concurrent
// writes against the same in-memory alert map, and the alert count
// here is small enough that the sequential delay is not noticeable.
async function bulkSetAlertStatus(action) {

  const ids = Array.from(selectedAlertIds);

  const bulkBtns = [
    document.getElementById('bulk-approve-btn'),
    document.getElementById('bulk-confirm-btn'),
  ];

  bulkBtns.forEach(b => b.disabled = true);

  for (const id of ids) {

    try {
      await api(`/alerts/${encodeURIComponent(id)}/${action}`, { method: 'POST' });
    } catch (e) {
      console.error('Bulk alert action failed for', id, e);
    }
  }

  selectedAlertIds.clear();

  bulkBtns.forEach(b => b.disabled = false);

  refreshAlerts();
}

function renderAlerts() {

  const tbody = document.querySelector('#table-alerts tbody');
  const empty = document.querySelector('#view-alerts .empty-state');
  const badge = document.getElementById('alert-badge');

  tbody.innerHTML = '';

  const unreviewed = lastAlerts.filter(a => (a.Status || 'new') === 'new');
  badge.hidden = unreviewed.length === 0;
  badge.textContent = unreviewed.length;

  empty.hidden = lastAlerts.length > 0;

  // Drop selection for any alert no longer present (e.g. pruned).
  const currentIds = new Set(lastAlerts.map(a => a.ID));
  selectedAlertIds.forEach(id => { if (!currentIds.has(id)) selectedAlertIds.delete(id); });

  for (const a of sortAlerts(lastAlerts)) {

    const status = a.Status || 'new';

    const tr = document.createElement('tr');
    if (status !== 'new') tr.classList.add('row-acked');

    tr.innerHTML = `
      <td></td>
      <td><span class="sev ${a.Severity}">${a.Severity}</span></td>
      <td><span class="status-tag ${status}">${status}</span></td>
      <td>${a.Type}</td>
      <td>${a.Message}</td>
      <td>${a.Count}</td>
      <td>${fmtTime(a.FirstSeen)}</td>
      <td>${fmtTime(a.LastSeen)}</td>
      <td></td>
    `;

    const checkboxCell = tr.firstElementChild;
    const actionCell = tr.lastElementChild;

    if (status === 'new') {

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = selectedAlertIds.has(a.ID);
      checkbox.addEventListener('change', () => {
        if (checkbox.checked) selectedAlertIds.add(a.ID);
        else selectedAlertIds.delete(a.ID);
        updateAlertsBulkBar();
      });
      checkboxCell.appendChild(checkbox);

      const approveBtn = document.createElement('button');
      approveBtn.className = 'ack-btn';
      approveBtn.textContent = 'Approve';

      const confirmBtn = document.createElement('button');
      confirmBtn.className = 'ack-btn confirm-btn';
      confirmBtn.textContent = 'Confirm';

      const buttons = [approveBtn, confirmBtn];

      approveBtn.addEventListener('click', () => setAlertStatus(a.ID, 'approve', buttons));
      confirmBtn.addEventListener('click', () => setAlertStatus(a.ID, 'confirm', buttons));

      actionCell.appendChild(approveBtn);
      actionCell.appendChild(confirmBtn);
    }

    tbody.appendChild(tr);
  }

  updateAlertsBulkBar();
}

function initAlertSort() {

  document.querySelectorAll('#table-alerts thead th[data-sort]').forEach(th => {

    th.addEventListener('click', () => {

      const col = th.dataset.sort;

      if (alertSort.column === col) {
        alertSort.direction = alertSort.direction === 'asc' ? 'desc' : 'asc';
      } else {
        alertSort.column = col;
        alertSort.direction = 'desc';
      }

      updateAlertSortIndicators();
      renderAlerts();
    });
  });

  updateAlertSortIndicators();

  document.getElementById('alerts-select-all').addEventListener('change', (e) => {

    document.querySelectorAll('#table-alerts tbody input[type=checkbox]').forEach(cb => {
      cb.checked = e.target.checked;
      cb.dispatchEvent(new Event('change'));
    });
  });

  document.getElementById('bulk-approve-btn').addEventListener('click', () => bulkSetAlertStatus('approve'));
  document.getElementById('bulk-confirm-btn').addEventListener('click', () => bulkSetAlertStatus('confirm'));
}

async function refreshAlerts() {
  lastAlerts = await api('/alerts');
  renderAlerts();
}

// ---------- rules ----------

async function refreshRules() {
  lastRules = await api('/rules');
  renderRules();
}

function renderRules() {

  const tbody = document.querySelector('#table-rules tbody');
  const empty = document.querySelector('#view-rules .empty-state');

  tbody.innerHTML = '';
  empty.hidden = lastRules.length > 0;

  // Built-in rules first (stable, always-present set), then custom
  // rules newest-first — matches how a person would scan the list:
  // "what's always on" up top, "what I just added" near the top of
  // the part I actually control.
  const sorted = lastRules.slice().sort((a, b) => {
    if (a.Kind !== b.Kind) return a.Kind === 'builtin' ? -1 : 1;
    if (a.Kind === 'builtin') return a.Name.localeCompare(b.Name);
    return b.ID.localeCompare(a.ID);
  });

  for (const rule of sorted) {

    const tr = document.createElement('tr');

    const condition = rule.Kind === 'custom'
      ? `${fieldLabel(rule.Field)} = ${rule.Value}`
      : '—';

    const severity = rule.Kind === 'custom' ? rule.Severity : '—';

    tr.innerHTML = `
      <td></td>
      <td>${rule.Name}</td>
      <td><span class="pill ${rule.Kind === 'builtin' ? 'it' : 'ot'}">${rule.Kind}</span></td>
      <td>${condition}</td>
      <td>${severity !== '—' ? `<span class="sev ${severity}">${severity}</span>` : '—'}</td>
      <td>${rule.HitCount || 0}</td>
      <td>${rule.LastHit && rule.HitCount ? fmtTime(rule.LastHit) : '—'}</td>
      <td>${rule.LastHitIP || '—'}</td>
      <td></td>
    `;

    const toggleLabel = document.createElement('label');
    toggleLabel.className = 'rule-toggle';
    toggleLabel.title = rule.Enabled ? 'Enabled — click to disable' : 'Disabled — click to enable';

    const toggleInput = document.createElement('input');
    toggleInput.type = 'checkbox';
    toggleInput.checked = rule.Enabled;
    toggleInput.addEventListener('change', () => toggleRule(rule.ID, toggleInput.checked));

    const toggleTrack = document.createElement('span');
    toggleTrack.className = 'rule-toggle-track';

    toggleLabel.appendChild(toggleInput);
    toggleLabel.appendChild(toggleTrack);
    tr.firstElementChild.appendChild(toggleLabel);

    if (rule.Kind === 'custom') {

      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'ack-btn confirm-btn';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', () => deleteRule(rule.ID, rule.Name));

      tr.lastElementChild.appendChild(deleteBtn);
    }

    tbody.appendChild(tr);
  }
}

function fieldLabel(field) {
  const labels = {
    src_ip: 'Source IP',
    dst_ip: 'Destination IP',
    either_ip: 'Either IP',
    protocol: 'Protocol',
    port: 'Port',
  };
  return labels[field] || field;
}

async function toggleRule(id, enabled) {

  try {

    await api(`/rules/${encodeURIComponent(id)}/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });

    refreshRules();

  } catch (e) {
    console.error('Toggling rule failed for', id, e);
    refreshRules(); // revert the checkbox to the real server state
  }
}

async function deleteRule(id, name) {

  if (!confirm(`Delete rule "${name}"? This can't be undone.`)) {
    return;
  }

  try {
    await api(`/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
    refreshRules();
  } catch (e) {
    console.error('Deleting rule failed for', id, e);
  }
}

function initRulesTab() {

  const backdrop = document.getElementById('add-rule-backdrop');
  const form = document.getElementById('add-rule-form');
  const errorEl = document.getElementById('add-rule-error');

  document.getElementById('add-rule-btn').addEventListener('click', () => {
    form.reset();
    errorEl.hidden = true;
    backdrop.hidden = false;
  });

  document.getElementById('add-rule-close').addEventListener('click', () => {
    backdrop.hidden = true;
  });

  backdrop.addEventListener('click', (e) => {
    if (e.target.id === 'add-rule-backdrop') backdrop.hidden = true;
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !backdrop.hidden) backdrop.hidden = true;
  });

  form.addEventListener('submit', async (e) => {

    e.preventDefault();
    errorEl.hidden = true;

    const name = document.getElementById('add-rule-name').value.trim();
    const field = document.getElementById('add-rule-field').value;
    const value = document.getElementById('add-rule-value').value.trim();
    const severity = document.getElementById('add-rule-severity').value;

    try {

      await api('/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, field, value, severity }),
      });

      backdrop.hidden = true;
      refreshRules();

    } catch (err) {

      errorEl.hidden = false;
      errorEl.textContent = 'Failed to create rule — check the value matches the selected field (e.g. a valid port number).';
      console.error('Creating rule failed', err);
    }
  });
}

// ---------- topology graph ----------

// Two things were fighting each other in earlier attempts at this:
// wanting the layout to organically reflect live connections (which
// needs physics running), and not wanting visible trembling (which a
// naive "always-on" physics setup causes). The actual root cause of
// the trembling turned out to be the OT "breathing" pulse: it resized
// nodes every 1.2s, and node *size* directly feeds the physics
// engine's repulsion calculation — so every pulse frame nudged every
// neighboring (often IT) node, which read as constant vibration.
// Fixing that (pulse now animates color/opacity, never size — see
// nodeFromApi) removes the actual disturbance, so physics can stay
// on continuously: it settles quickly after a real change (a new
// device/flow) and then sits still, giving the organic
// connection-based clustering back without the shake.
let network = null;
let pulseTimer = null;
let nodesDataSet = null;
let edgesDataSet = null;

// Set fresh by renderGraph on every refresh — nodeFromApi/edgeFromApi
// need this to interpret Score/FromHoneypot, but graph.Nodes.map()
// only passes them the individual node/edge, not the whole Graph
// object that actually carries the threshold (see
// topology.Graph.HoneypotThreshold's doc comment for why it's there
// at all rather than hardcoded on the frontend).
let honeypotThreshold = 100;

function nodeId(apiNode) {
  return apiNode.IP || apiNode.ID;
}

function nodeFromApi(n) {

  // A device discovered after baseline learning ended shows red until
  // someone confirms it (Assets tab) — a genuinely new/unexpected
  // device is exactly the kind of thing worth being visually loud
  // about on the map, not blended in with everything already known.
  const unconfirmed = n.Confirmed === false;

  // A configured deception station (config.Deception) — distinct
  // violet, not the same red as "unconfirmed," since these are
  // different kinds of findings: unconfirmed means "wasn't in the
  // learned baseline," honeypot means "this is a deliberate decoy —
  // any traffic touching it is inherently suspicious." Takes visual
  // priority over unconfirmed/OT coloring since it's a persistent,
  // deliberate classification, not a transient review state.
  const isHoneypot = n.Score >= honeypotThreshold;

  return {
    id: nodeId(n),
    label: n.IP || n.MAC,
    title: `${n.Hostname || n.IP || n.MAC}\nMAC: ${n.MAC}\nVendor: ${n.Vendor || 'Unknown'}\n${n.IsOT ? 'OT device — ' + (n.Protocols || []).join(', ') : 'IT device'}${isHoneypot ? '\n🍯 DECEPTION STATION (honeypot)' : ''}${unconfirmed ? '\n⚠ UNCONFIRMED — new since baseline learning ended' : ''}`,
    color: isHoneypot
      ? { background: '#a855f7', border: '#7c3aed' }
      : unconfirmed
        ? { background: '#e85d4c', border: '#a83a2d' }
        : n.IsOT
          ? { background: '#3fbfb0', border: '#2a7d74' }
          : { background: '#6b7ea3', border: '#4d5c78' },
    size: isHoneypot ? 22 : (n.IsOT ? 20 : 14),
    font: { color: '#d7e1ec', face: 'IBM Plex Mono', size: 14 },
    _isOT: n.IsOT,
    _unconfirmed: unconfirmed,
    _isHoneypot: isHoneypot,
    _ip: (n.IP || '').toLowerCase(),
    _mac: (n.MAC || '').toLowerCase(),
  };
}

// edgeFromApi. vlanByIP maps IP -> VLANID for currently-visible
// nodes (see renderGraph) — used to detect a "cross-VLAN" edge,
// where the two endpoints report different VLAN tags. This is
// flagged visually (amber, dashed) rather than left to blend in with
// ordinary same-VLAN traffic, since a connection crossing between
// VLANs is usually routed through something (a firewall/router) and
// is exactly the kind of segmentation-relevant path worth noticing
// at a glance.
//
// Caveat worth knowing: this compares raw VLAN ID numbers. If
// traffic is ever captured from more than one broadcast domain that
// happens to reuse the same VLAN ID for two unrelated networks (VLAN
// tags are only guaranteed unique within a single trunk/broadcast
// domain, not globally), this can't tell those apart — two devices
// both showing "VLAN 10" are treated as the same VLAN even if they
// are, in reality, on two different physical networks that just
// happen to number a VLAN the same way. There's no separate site/
// segment identifier in the data to disambiguate that case.
function edgeFromApi(e, vlanByIP) {

  const srcVlan = vlanByIP ? vlanByIP.get(e.SrcIP) : undefined;
  const dstVlan = vlanByIP ? vlanByIP.get(e.DstIP) : undefined;

  const crossVlan = srcVlan !== undefined && dstVlan !== undefined && srcVlan !== dstVlan;

  return {
    id: e.ID,
    from: e.SrcIP,
    to: e.DstIP,
    // FromHoneypot — the honeypot itself initiated this conversation,
    // not just being talked to. This is exactly what
    // AlertHoneypotLateralMovement fires on: a decoy that exists
    // purely to be talked TO, talking FROM itself, means it's
    // compromised. Dashed + thick + red so a pivot out from a decoy
    // is obvious in the graph, not just buried in the Alerts tab.
    // Takes priority over the cross-VLAN styling below — an actual
    // compromise finding matters more than "this happens to cross a
    // VLAN boundary."
    color: e.FromHoneypot
      ? { color: '#e85d4c', opacity: 0.9 }
      : crossVlan
        ? { color: '#e8a33d', opacity: 0.85 }
        : e.IsOT ? { color: '#3fbfb0', opacity: 0.8 } : { color: '#4d5c78', opacity: 0.4 },
    width: e.FromHoneypot ? 3 : (crossVlan ? 2.5 : (e.IsOT ? 2 : 1)),
    dashes: e.FromHoneypot ? [6, 3] : (crossVlan ? [3, 3] : false),
    // A cross-VLAN edge is curved — everything else stays a straight
    // line (see the network-wide edges.smooth:false option). A
    // device often sits at the shared endpoint of both an ordinary
    // straight intra-VLAN edge (to its own VLAN's hub) *and* a
    // cross-VLAN edge going a completely different direction (to
    // whatever it's cross-talking to) — with VLAN clustering placing
    // distant VLANs on the far side of the layout, those two edges
    // can end up nearly collinear, making them look like one
    // continuous line straight through an unrelated node in between,
    // even though they're two separate edges that happen to share
    // just the one endpoint. Curving only the cross-VLAN edge breaks
    // that illusion — a curve can never visually align with a
    // straight line the way two straight lines can.
    smooth: crossVlan ? { type: 'curvedCW', roundness: 0.2 } : false,
    title: `${e.Protocol} — ${e.Packets} packets, ${e.Bytes} bytes`
      + (e.FromHoneypot ? '\n⚠ Traffic FROM a honeypot — possible lateral movement' : '')
      + (crossVlan ? `\n↔ Cross-VLAN: VLAN ${srcVlan} ↔ VLAN ${dstVlan}` : ''),
  };
}

// nodeVisualsEqual/edgeVisualsEqual compare only the fields that
// actually affect rendering/physics, ignoring incidental ones (e.g.
// a tooltip's exact packet count). Skipping DataSet.update() calls
// for items that haven't meaningfully changed means vis-network's
// simulation isn't repeatedly poked with no-op writes on every 5s
// poll — it only wakes up when something real changed.
function nodeVisualsEqual(a, b) {
  return a.label === b.label &&
    a.size === b.size &&
    JSON.stringify(a.color) === JSON.stringify(b.color);
}

function edgeVisualsEqual(a, b) {
  return a.width === b.width &&
    JSON.stringify(a.color) === JSON.stringify(b.color);
}

// dedupeById collapses items sharing the same id down to one,
// keeping the last occurrence. Node ids here are IP addresses (see
// nodeId) rather than MAC — a deliberate tradeoff so edges, which
// only carry IP addresses (flow.Flow has no MAC concept), can
// resolve from/to the right node. The cost of that tradeoff: if two
// different assets (different MACs) currently show the same IP —
// stale data from before an IP got correctly re-attributed, a DHCP
// reassignment, a device replaced without the old MAC aging out yet
// — the backend legitimately returns two Node entries with the same
// id, and vis.DataSet throws a hard "item already exists" error on
// the second one, taking down the whole graph instead of just that
// one node. Deduplicating here trades perfect accuracy (you won't
// see both devices at once) for the graph rendering at all; the
// underlying data-quality question (why two MACs currently share an
// IP) is real and worth investigating separately, not something to
// silently paper over forever — hence the warning.
function dedupeById(items) {

  const map = new Map();

  for (const item of items) {

    if (map.has(item.id)) {

      console.warn(
        `Topology: duplicate node/edge id "${item.id}" — two records currently share this identity; keeping the most recent one.`,
      );
    }

    map.set(item.id, item);
  }

  return Array.from(map.values());
}

// ---------- topology search ----------

// Set by initTopologySearch's input handler, read by renderGraph
// after every poll so the highlight stays in sync with fresh data
// without needing its own separate polling loop.
let topologySearchQuery = '';

// applyTopologySearch highlights (selects) the first node whose IP
// or MAC contains topologySearchQuery. refocus controls whether the
// view also pans/zooms to it — true for the user's own search
// action, false when this runs again after a routine data refresh
// (re-centering the view on every 5s poll while someone's looking
// around would be disruptive; keeping the selection border in sync
// is enough there).
function applyTopologySearch(refocus) {

  const status = document.getElementById('topology-search-status');
  const clearBtn = document.getElementById('topology-search-clear');

  if (!network || !nodesDataSet) {
    return;
  }

  if (!topologySearchQuery) {
    network.unselectAll();
    status.textContent = '';
    status.classList.remove('not-found');
    clearBtn.hidden = true;
    return;
  }

  clearBtn.hidden = false;

  const match = nodesDataSet.get().find(n =>
    (n._ip && n._ip.includes(topologySearchQuery)) ||
    (n._mac && n._mac.includes(topologySearchQuery))
  );

  if (!match) {
    network.unselectAll();
    status.textContent = 'No match found';
    status.classList.add('not-found');
    return;
  }

  status.classList.remove('not-found');
  status.textContent = `Found: ${match.label}`;

  network.selectNodes([match.id]);

  if (refocus) {

    network.focus(match.id, {
      scale: 1.3,
      animation: { duration: 400, easingFunction: 'easeInOutQuad' },
    });
  }
}

function initTopologySearch() {

  const input = document.getElementById('topology-search-input');
  const clearBtn = document.getElementById('topology-search-clear');

  input.addEventListener('input', () => {
    topologySearchQuery = input.value.trim().toLowerCase();
    applyTopologySearch(true);
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    topologySearchQuery = '';
    applyTopologySearch(true);
    input.focus();
  });
}

// ---------- VLAN filter ----------

// VLAN IDs currently toggled OFF — everything visible by default
// (empty set), matching the requirement that all VLANs show unless
// explicitly hidden. 0 stands for "untagged" (no 802.1Q tag).
let hiddenVLANs = new Set();

// Kept so toggling a checkbox can re-render immediately, using
// whatever was last fetched, without waiting for the next 5s poll.
let lastTopologyGraph = null;

// updateVLANFilterUI (re)builds the toggle row from whatever VLAN
// IDs actually appear in the current graph — no separate "list of
// known VLANs" endpoint needed. Existing toggle states are
// preserved (hiddenVLANs isn't reset here), so a VLAN a user hid
// stays hidden across polls even if it temporarily has no visible
// devices. Hidden entirely — not just skipped — when only one (or
// zero) VLAN is present, since a single always-on toggle is just
// clutter with nothing to filter.
function updateVLANFilterUI(graph) {

  const container = document.getElementById('topology-vlan-filter');

  const vlanIds = new Set();
  graph.Nodes.forEach(n => vlanIds.add(n.VLANID || 0));
  graph.Edges.forEach(e => vlanIds.add(e.VLANID || 0));

  const sorted = Array.from(vlanIds).sort((a, b) => a - b);

  container.innerHTML = '';

  if (sorted.length <= 1) {
    container.hidden = true;
    return;
  }

  container.hidden = false;

  for (const vid of sorted) {

    const label = document.createElement('label');
    label.className = 'vlan-toggle';

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = !hiddenVLANs.has(vid);

    checkbox.addEventListener('change', () => {

      if (checkbox.checked) {
        hiddenVLANs.delete(vid);
      } else {
        hiddenVLANs.add(vid);
      }

      if (lastTopologyGraph) {
        renderGraph(lastTopologyGraph);
      }
    });

    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(vid === 0 ? 'Untagged' : `VLAN ${vid}`));

    container.appendChild(label);
  }
}

// computeVisibleGraph applies the VLAN filter (hiddenVLANs) once —
// pulled out of renderGraph on its own since the filtering/dedup
// logic is reused by the VLAN checkbox handler above (re-rendering
// immediately on toggle) as well as the regular poll cycle. Also
// sets the module-level lastTopologyGraph/honeypotThreshold and
// refreshes the VLAN filter UI.
function computeVisibleGraph(graph) {

  lastTopologyGraph = graph;
  honeypotThreshold = graph.HoneypotThreshold || 100;

  updateVLANFilterUI(graph);

  // Filter by node visibility first, then only keep edges where
  // *both* endpoints are still visible — filtering edges directly by
  // their own VLANID instead could leave a "dangling" edge pointing
  // at a node that got hidden (an edge can, in principle, span two
  // different VLANs via routing), which vis-network doesn't handle
  // gracefully.
  const visibleNodeApis = graph.Nodes.filter(n => !hiddenVLANs.has(n.VLANID || 0));
  const visibleNodeIds = new Set(visibleNodeApis.map(nodeId));

  // IP -> VLANID, so edgeFromApi can tell whether an edge crosses
  // between two different VLANs (its two endpoints disagree) — see
  // edgeFromApi's doc comment on crossVlan for why this is flagged
  // visually rather than silently allowed to blend in.
  const vlanByIP = new Map(visibleNodeApis.map(n => [nodeId(n), n.VLANID || 0]));

  const visibleEdgeApis = graph.Edges.filter(e =>
    visibleNodeIds.has(e.SrcIP) && visibleNodeIds.has(e.DstIP)
  );

  return { visibleNodeApis, visibleEdgeApis, vlanByIP };
}

// computeVlanAnchors returns a Map from VLANID -> fixed {x, y} point,
// one per distinct VLAN present, evenly spaced around a circle sized
// to the number of VLANs. Paired with an invisible "anchor" node per
// VLAN and a short, hidden spring edge from each device to its
// VLAN's anchor (see renderGraph) — devices are pulled toward their
// own anchor without their position being *fixed*, so the graph
// keeps its normal organic, interactive feel (drag, physics,
// collision avoidance) within each VLAN's own region, instead of a
// single generic blob where devices from different VLANs sit
// wherever normal link/repulsion forces happen to settle them. A
// single VLAN (or none) has nothing to cluster against, so this
// returns an empty map in that case.
function computeVlanAnchors(nodeApis) {

  const vlanIds = Array.from(new Set(nodeApis.map(n => n.VLANID || 0))).sort((a, b) => a - b);

  const anchors = new Map();

  if (vlanIds.length <= 1) {
    return anchors;
  }

  const radius = Math.max(400, vlanIds.length * 150);

  vlanIds.forEach((vid, i) => {
    const angle = (2 * Math.PI * i) / vlanIds.length;
    anchors.set(vid, {
      x: radius * Math.cos(angle),
      y: radius * Math.sin(angle),
    });
  });

  return anchors;
}

function renderGraph(graph) {
  const container = document.getElementById('graph');

  const { visibleNodeApis, visibleEdgeApis, vlanByIP } = computeVisibleGraph(graph);

  const vlanAnchors = computeVlanAnchors(visibleNodeApis);

  // One invisible, unmoving node per VLAN anchor point. physics:
  // false means it never itself moves — the spring edges below still
  // pull *connected* (physics-enabled) device nodes toward it though,
  // which is the whole mechanism.
  const anchorNodes = Array.from(vlanAnchors.entries()).map(([vid, pos]) => ({
    id: `vlan-anchor-${vid}`,
    x: pos.x,
    y: pos.y,
    fixed: { x: true, y: true },
    physics: false,
    hidden: true,
  }));

  // One short, hidden spring edge per visible device, to its VLAN's
  // anchor — this is what actually pulls devices into their VLAN's
  // region. Skipped entirely when there's nothing to cluster against
  // (vlanAnchors empty).
  const anchorEdges = vlanAnchors.size > 0
    ? visibleNodeApis.map(n => ({
        id: `vlan-anchor-edge-${nodeId(n)}`,
        from: nodeId(n),
        to: `vlan-anchor-${n.VLANID || 0}`,
        hidden: true,
        length: 100,
        smooth: false,
      }))
    : [];

  const newNodes = dedupeById(visibleNodeApis.map(nodeFromApi).concat(anchorNodes));
  const newEdges = dedupeById(visibleEdgeApis.map(e => edgeFromApi(e, vlanByIP)).concat(anchorEdges));

  if (!network) {

    nodesDataSet = new vis.DataSet(newNodes);
    edgesDataSet = new vis.DataSet(newEdges);

    const options = {
      nodes: { shape: 'dot', borderWidth: 2 },
      // Straight lines rather than curved: a curve's control point
      // shifts with the two nodes' positions, which for a busy graph
      // makes edges visually swing through areas they don't actually
      // pass near — straight lines are easier to trace by eye and
      // don't add crossings that aren't really there.
      edges: { smooth: false },
      physics: {
        // forceAtlas2Based (the algorithm behind Gephi's default
        // layout) is built specifically for "who talks to whom"
        // graphs like this one.
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          // Balanced middle ground: strong enough repulsion that
          // connected clusters don't overlap each other, but not so
          // strong that a fully isolated node (nothing pulling it
          // anywhere except repulsion) drifts off to the horizon —
          // that was the previous problem: the layout technically
          // had no crossings anymore, but fitting the view to include
          // an isolated node halfway to infinity zoomed everything
          // else out to the point of being unreadable.
          gravitationalConstant: -180,
          springLength: 180,
          springConstant: 0.05,

          // A little central pull (not zero, not the too-strong
          // default either) keeps the whole graph — including
          // isolated nodes — within a bounded area, so the view never
          // has to zoom out further than necessary just to fit one
          // outlier. See minViewScale below for the other half of
          // this fix.
          centralGravity: 0.02,

          damping: 0.6,
          avoidOverlap: 1,
        },
        stabilization: { iterations: 400 },
      },
      interaction: { hover: true, tooltipDelay: 100 },
    };

    network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);

    // Belt-and-braces on top of the physics tuning above: whatever
    // the initial auto-fit zoom level ends up being once the layout
    // settles, never let it go below minViewScale — an outlier node
    // (or several, on a sparse network) is better off just outside
    // the visible area than making every label on screen too small
    // to read.
    const minViewScale = 0.6;

    network.once('stabilizationIterationsDone', () => {

      const scale = network.getScale();

      if (scale < minViewScale) {
        network.moveTo({ scale: minViewScale });
      }
    });

  } else {

    // Only push updates for nodes/edges that are new or actually
    // changed visually — see nodeVisualsEqual's doc comment above.
    const nodeUpdates = newNodes.filter(n => {
      const existing = nodesDataSet.get(n.id);
      return !existing || !nodeVisualsEqual(existing, n);
    });

    const edgeUpdates = newEdges.filter(e => {
      const existing = edgesDataSet.get(e.id);
      return !existing || !edgeVisualsEqual(existing, e);
    });

    if (nodeUpdates.length) nodesDataSet.update(nodeUpdates);
    if (edgeUpdates.length) edgesDataSet.update(edgeUpdates);

    const currentNodeIds = new Set(newNodes.map(n => n.id));
    const staleNodeIds = nodesDataSet.getIds().filter(id => !currentNodeIds.has(id));
    if (staleNodeIds.length) nodesDataSet.remove(staleNodeIds);

    const currentEdgeIds = new Set(newEdges.map(e => e.id));
    const staleEdgeIds = edgesDataSet.getIds().filter(id => !currentEdgeIds.has(id));
    if (staleEdgeIds.length) edgesDataSet.remove(staleEdgeIds);
  }

  // Signature: OT devices "breathe" — a subtle pulsing highlight, the
  // dashboard's one deliberate animated flourish, evoking a live
  // telemetry heartbeat and (functionally) drawing the eye straight
  // to the OT assets that matter most in this network. Pulses
  // *opacity*, deliberately never *size* — size feeds the physics
  // engine's repulsion calculation, which is what caused neighboring
  // nodes to visibly vibrate in an earlier version of this.
  // Opacity/color has no effect on physics at all.
  if (pulseTimer) clearInterval(pulseTimer);
  let phase = 0;
  pulseTimer = setInterval(() => {
    phase = (phase + 1) % 2;
    const updates = [];
    nodesDataSet.forEach(n => {
      if (n._isOT) {
        updates.push({
          id: n.id,
          color: n._isHoneypot
            ? {
                background: phase === 0 ? '#a855f7' : '#c084fc',
                border: '#7c3aed',
              }
            : n._unconfirmed
              ? {
                  background: phase === 0 ? '#e85d4c' : '#f28a7a',
                  border: '#a83a2d',
                }
              : {
                  background: phase === 0 ? '#3fbfb0' : '#7fe0d4',
                  border: '#2a7d74',
                },
        });
      }
    });
    if (updates.length) nodesDataSet.update(updates);
  }, 1200);

  // Keep the search highlight (if any) in sync with fresh data —
  // selection only, deliberately not re-focusing/re-zooming here,
  // since that would re-center the view out from under someone every
  // 5s poll while they're trying to look around. Focusing happens
  // only on the actual search action — see initTopologySearch.
  applyTopologySearch(false);
}

async function refreshTopology() {

  const graph = await api('/topology');

  try {
    renderGraph(graph);
  } catch (err) {

    // A rendering bug here (e.g. a vis-network data-shape issue)
    // shouldn't take down the whole poll cycle the way an uncaught
    // throw would — this at least gets the real error and the graph
    // payload that triggered it into the console for diagnosis,
    // instead of the Topology tab just silently staying blank with
    // no clue why.
    console.error('Rendering topology failed:', err, graph);
  }
}

// ---------- capture control (admin) ----------

async function refreshCaptureStatus() {

  const dot = document.getElementById('capture-status-dot');
  const text = document.getElementById('capture-status-text');
  const stopBtn = document.getElementById('capture-stop-btn');
  const startBtn = document.getElementById('capture-start-btn');
  const analyzeBtn = document.getElementById('capture-analyze-btn');
  const wipeBtn = document.getElementById('wipe-database-btn');
  const note = document.getElementById('capture-mode-note');

  let status;

  try {
    status = await api('/admin/capture/status');
  } catch (e) {
    dot.className = 'dot down';
    text.textContent = 'unreachable';
    return;
  }

  // Start/stop (and therefore wipe, which requires the data source to
  // be stopped first) work the same way in both npcap and ipfix
  // mode — see internal/api's dataSource interface. Manual pcap file
  // analysis is the one npcap-only piece: there's no ipfix
  // equivalent of "analyze a saved packet capture".
  const isNpcap = status.mode === 'npcap';

  dot.className = 'dot ' + (status.running ? 'monitoring' : 'learning');
  text.textContent = `${status.running ? 'running' : 'stopped'} (${status.mode})`;
  stopBtn.disabled = !status.running;
  startBtn.disabled = status.running;
  wipeBtn.disabled = status.running;

  analyzeBtn.disabled = !isNpcap || status.running;

  if (!isNpcap) {
    note.textContent = 'Manual pcap file analysis is only available in npcap mode. Start/stop and database wipe work the same as in npcap mode.';
  } else {
    note.textContent = status.running
      ? 'Stop capture before uploading a file to analyze.'
      : 'Capture is stopped — you can upload a .pcap/.pcapng file below to analyze it through the same pipeline as live traffic.';
  }
}

async function stopCapture() {
  try {
    await api('/admin/capture/stop', { method: 'POST' });
  } catch (e) {
    console.error('Stop capture failed:', e);
  }
  refreshCaptureStatus();
}

async function startCapture() {
  try {
    await api('/admin/capture/start', { method: 'POST' });
  } catch (e) {
    console.error('Start capture failed:', e);
  }
  refreshCaptureStatus();
}

async function analyzeUploadedFile() {

  const input = document.getElementById('capture-file-input');
  const statusEl = document.getElementById('capture-analyze-status');

  if (!input.files || input.files.length === 0) {
    statusEl.textContent = 'Choose a file first.';
    return;
  }

  const formData = new FormData();
  formData.append('file', input.files[0]);

  statusEl.textContent = 'Analyzing…';

  try {

    const res = await fetch('/admin/capture/analyze', { method: 'POST', body: formData });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      statusEl.textContent = `Failed: ${body.error || res.status}`;
      return;
    }

    const body = await res.json();
    statusEl.textContent = `Done — ${body.packets_processed} packets processed.`;

    // Uploaded traffic flows through the normal pipeline just like
    // live capture, so refresh everything to show what it found.
    refreshAll();

  } catch (e) {
    console.error('Analyze failed:', e);
    statusEl.textContent = 'Analyze failed — see browser console.';
  }
}

async function wipeDatabase() {

  if (!confirm('Wipe the entire database? This permanently erases ALL assets, flows, OT tags, and alerts from memory and disk. This cannot be undone.')) {
    return;
  }

  const btn = document.getElementById('wipe-database-btn');
  btn.disabled = true;
  btn.textContent = 'Wiping…';

  try {

    await api('/admin/wipe', { method: 'POST' });

    btn.textContent = 'Wipe database';
    btn.disabled = false;

    refreshAll();

  } catch (e) {

    console.error('Wipe failed:', e);
    alert('Wipe failed — see browser console for details (capture may still be running).');

    btn.textContent = 'Wipe database';
    btn.disabled = false;
  }
}

function initCaptureControl() {
  document.getElementById('capture-stop-btn').addEventListener('click', stopCapture);
  document.getElementById('capture-start-btn').addEventListener('click', startCapture);
  document.getElementById('capture-analyze-btn').addEventListener('click', analyzeUploadedFile);
  document.getElementById('wipe-database-btn').addEventListener('click', wipeDatabase);
}

function renderAdmin() {
  refreshCaptureStatus();
}

// ---------- polling loop ----------

async function refreshAll() {

  const results = await Promise.allSettled([
    refreshBaseline(),
    refreshAssets(),
    refreshFlows(),
    refreshTags(),
    refreshAlerts(),
    refreshTopology(),
    refreshRules(),
  ]);

  const labels = ['baseline', 'assets', 'flows', 'tags', 'alerts', 'topology', 'rules'];

  let anySucceeded = false;

  results.forEach((r, i) => {

    if (r.status === 'rejected') {

      // One tab's refresh failing (e.g. a rendering bug specific to
      // the topology graph) shouldn't be reported as "backend
      // unreachable" — the other tabs above already show the backend
      // is responding fine. Logging which one failed, and why, here
      // makes that distinction visible instead of a single opaque
      // "connection lost" indicator that isn't actually true.
      console.error(`refresh failed: ${labels[i]}`, r.reason);

    } else {
      anySucceeded = true;
    }
  });

  renderAdmin();

  // Only the true "nothing at all is responding" case should show as
  // unreachable — that's the situation the connection dot exists to
  // warn about.
  setConn(anySucceeded);
}

initAssetSort();
initFlowSort();
initTagSort();
initTagHistoryModal();
initAssetVulnModal();
initRulesTab();
initAlertSort();
initCaptureControl();
initTopologySearch();

refreshAll();
setInterval(refreshAll, POLL_INTERVAL_MS);
