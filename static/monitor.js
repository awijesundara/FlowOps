const rid = new URLSearchParams(location.search).get('rid');
const esc = s => (s ?? '').toString().replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const content = document.getElementById('content');

function gateBadge(t) {
  const n = (t.depends_on || []).length;
  if (n === 0) return '';
  if (n === 1) return '';
  return t.dependency_logic === 'or' ? ' · OR join' : ' · AND join';
}

function taskCard(t) {
  const flags = [];
  if (t.escalated) flags.push('<span class="flag escalated">⚠ Escalated</span>');
  if (t.incident) flags.push('<span class="flag incident">🔥 Incident</span>');
  const runningLong = t.status === 'running' && t.started_at && (Date.now() - new Date(t.started_at).getTime()) > t.duration * 60000;
  if (runningLong) flags.push('<span class="flag running-long">⏱ Running long</span>');
  const classes = ['card', `status-${t.status}`];
  if (t.escalated) classes.push('escalated');
  if (t.incident) classes.push('incident');
  if (runningLong) classes.push('running-long');
  if (t.blocked) classes.push('blocked');
  return `<div class="${classes.join(' ')}">
    <div class="card-top"><h3>${esc(t.title)}</h3><span class="badge ${esc(t.status)}">${esc(t.status)}</span></div>
    <small>${esc(t.stream)} · ${esc(t.owner_display || t.owner || 'Unassigned')} · ${t.duration} min${gateBadge(t)}</small>
    ${flags.length ? `<div class="flags">${flags.join('')}</div>` : ''}
  </div>`;
}

async function render() {
  let doc;
  try {
    const res = await fetch(`/api/runbooks/${rid}`);
    if (res.status === 401) {
      content.innerHTML = '<div class="signin">Sign in to FlowOps first, then reopen this monitor link. <a href="/">Go to FlowOps →</a></div>';
      return;
    }
    if (!res.ok) { content.innerHTML = '<div class="empty">Runbook not found.</div>'; return; }
    doc = (await res.json()).data;
  } catch (e) {
    content.innerHTML = '<div class="empty">Could not reach FlowOps.</div>';
    return;
  }
  document.title = `${doc.name} · FlowOps Monitor`;
  document.getElementById('rbName').textContent = doc.name;
  const statusChip = document.getElementById('rbStatus');
  statusChip.textContent = doc.status;
  statusChip.className = `chip ${esc(doc.status)}`;
  const complete = doc.tasks.filter(t => t.status === 'complete').length;
  content.innerHTML = `
    <div class="metrics">
      <div class="metric"><span>Progress</span><strong>${doc.progress}%</strong></div>
      <div class="metric"><span>Tasks</span><strong>${complete} / ${doc.tasks.length}</strong></div>
      <div class="metric"><span>Streams</span><strong>${new Set(doc.tasks.map(t => t.stream)).size}</strong></div>
      <div class="metric"><span>Escalated / Incidents</span><strong>${doc.tasks.filter(t=>t.escalated).length} / ${doc.tasks.filter(t=>t.incident).length}</strong></div>
    </div>
    <div class="grid">${doc.tasks.map(taskCard).join('') || '<div class="empty">No tasks yet.</div>'}</div>
  `;
}

function connectLive() {
  const liveLabel = document.getElementById('liveLabel');
  const source = new EventSource('/api/events');
  source.addEventListener('workspace', e => {
    try {
      const data = JSON.parse(e.data);
      if (String(data.runbook_id) === String(rid)) render();
    } catch (_) {}
  });
  source.onerror = () => { liveLabel.textContent = 'Reconnecting…'; };
  source.onopen = () => { liveLabel.textContent = 'Live'; };
}

if (!rid) {
  content.innerHTML = '<div class="empty">No runbook specified. Open this page as <code>/monitor.html?rid=&lt;id&gt;</code>.</div>';
} else {
  render();
  connectLive();
  setInterval(render, 20000);
}
