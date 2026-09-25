const state = {
  events: [],
  findings: [],
  sites: [],
  deniedIps: [],
  selectedDomain: '*',
  selectedView: 'events',
  selectedFindingIp: null,
  selectedSiteName: '',
  findingEvents: []
};

const allEvents = document.querySelector('#all-events');
const status = document.querySelector('#status');
const domains = document.querySelector('#domains');
const viewButtons = [...document.querySelectorAll('.view-tabs button')];
const eventBody = document.querySelector('#events');
const findingBody = document.querySelector('#findings');
const detailBody = document.querySelector('#finding-events');
const detailSummary = document.querySelector('#finding-summary');
const banCountValue = document.querySelector('#ban-count-value');
const banCountSave = document.querySelector('#ban-count-save');
const banCountStatus = document.querySelector('#ban-count-status');
const iisSiteSelect = document.querySelector('#iis-site-select');
const iisRefresh = document.querySelector('#iis-refresh');
const iisDenySelected = document.querySelector('#iis-deny-selected');
const iisStatus = document.querySelector('#iis-status');
const iisDenyListBody = document.querySelector('#iis-deny-list');
let findingsRefreshHandle = 0;

function text(value) {
  return document.createTextNode(value ?? '');
}

function escapeSegment(value) {
  return encodeURIComponent(value ?? '');
}

function getSeverityClass(value) {
  return String(value || 'Low').toLowerCase();
}

function normalizeDomain(value) {
  const trimmed = String(value || '').trim().replace(/\.+$/, '');
  const separatorIndex = trimmed.lastIndexOf(':');
  return separatorIndex > -1 && trimmed.indexOf(':') === separatorIndex ? trimmed.slice(0, separatorIndex) : trimmed;
}

function selectedFinding() {
  return state.findings.find(item => item.clientIp === state.selectedFindingIp) || null;
}

function setView(view) {
  state.selectedView = view;
  viewButtons.forEach(button => button.classList.toggle('active', button.dataset.view === view));
  document.querySelectorAll('.view').forEach(panel => panel.classList.toggle('active', panel.id === `${view}-view`));
}

function visibleEvent(webEvent) {
  return (allEvents.checked || webEvent.isSuspicious) && (state.selectedDomain === '*' || webEvent.domain === state.selectedDomain);
}

function visibleFinding(finding) {
  return state.selectedDomain === '*' || (finding.domains || []).includes(state.selectedDomain);
}

function ensureDomainButtons() {
  const domainNames = new Set();
  state.events.forEach(webEvent => webEvent.domain && domainNames.add(webEvent.domain));
  state.findings.forEach(finding => (finding.domains || []).forEach(domain => domain && domainNames.add(domain)));

  for (const domain of [...domainNames].sort((left, right) => left.localeCompare(right))) {
    if (!document.querySelector(`button[data-domain="${CSS.escape(domain)}"]`)) {
      const button = document.createElement('button');
      button.dataset.domain = domain;
      button.append(text(domain));
      button.onclick = async () => {
        await selectDomain(domain);
      };
      domains.append(button);
    }
  }
}

function renderEvents() {
  eventBody.replaceChildren();
  const visibleEvents = state.events.filter(visibleEvent).slice(-500).reverse();
  if (!visibleEvents.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.className = 'empty';
    cell.append(text(allEvents.checked ? 'No events received.' : 'No suspicious events received.'));
    row.append(cell);
    eventBody.append(row);
    return;
  }

  for (const webEvent of visibleEvents) {
    const row = document.createElement('tr');
    if (webEvent.isSuspicious) row.className = 'suspicious';
    [new Date(webEvent.timestamp).toLocaleString(), webEvent.domain, webEvent.clientIp, webEvent.method, webEvent.path, webEvent.statusCode, `${webEvent.riskScore ?? 0} (${webEvent.riskSeverity ?? 'Low'})`, webEvent.detectionReason || ''].forEach(value => {
      const cell = document.createElement('td');
      cell.append(text(String(value ?? '')));
      row.append(cell);
    });
    eventBody.append(row);
  }
}

function renderFindings() {
  findingBody.replaceChildren();
  const visibleFindings = state.findings.filter(visibleFinding);
  if (!visibleFindings.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.className = 'empty';
    cell.append(text('No suspicious IP findings available.'));
    row.append(cell);
    findingBody.append(row);
    return;
  }

  for (const finding of visibleFindings) {
    const row = document.createElement('tr');
    row.className = `clickable ${state.selectedFindingIp === finding.clientIp ? 'selected' : ''}`.trim();
    row.onclick = () => openFinding(finding.clientIp);

    const riskCell = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `badge ${getSeverityClass(finding.highestRiskSeverity)}`;
    badge.append(text(`${finding.highestRiskScore} ${finding.highestRiskSeverity}`));
    riskCell.append(badge);

    const values = [
      finding.clientIp,
      finding.requestCount,
      finding.suspiciousRequestCount,
      finding.banCount ?? 0,
      (finding.domains || []).join(', '),
      new Date(finding.lastSeen).toLocaleString(),
      (finding.detectionReasons || []).join('; ')
    ];

    values.forEach(value => {
      const cell = document.createElement('td');
      cell.append(text(String(value ?? '')));
      row.append(cell);
    });

    row.insertBefore(riskCell, row.children[3]);
    findingBody.append(row);
  }
}

function renderDetails() {
  detailBody.replaceChildren();
  const finding = state.findings.find(item => item.clientIp === state.selectedFindingIp) || null;

  if (!finding) {
    detailSummary.textContent = 'Select a finding to inspect its recent events.';
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 6;
    cell.className = 'empty';
    cell.append(text('No finding selected.'));
    row.append(cell);
    detailBody.append(row);
    return;
  }

  detailSummary.replaceChildren();
  const strong = document.createElement('strong');
  strong.append(text(finding.clientIp));
  detailSummary.append(strong, text(` · ${finding.requestCount} requests · ${finding.suspiciousRequestCount} suspicious · Ban count ${finding.banCount ?? 0} · Highest risk ${finding.highestRiskScore} (${finding.highestRiskSeverity})`));
  banCountValue.value = String(finding.banCount ?? 0);

  if (!state.findingEvents.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 6;
    cell.className = 'empty';
    cell.append(text('No recent events available for this IP.'));
    row.append(cell);
    detailBody.append(row);
    return;
  }

  for (const webEvent of state.findingEvents) {
    const row = document.createElement('tr');
    if (webEvent.isSuspicious) row.className = 'suspicious';
    [new Date(webEvent.timestamp).toLocaleString(), webEvent.domain, webEvent.method, webEvent.path, `${webEvent.riskScore ?? 0} (${webEvent.riskSeverity ?? 'Low'})`, webEvent.detectionReason || ''].forEach(value => {
      const cell = document.createElement('td');
      cell.append(text(String(value ?? '')));
      row.append(cell);
    });
    detailBody.append(row);
  }
}

function renderIis() {
  iisSiteSelect.replaceChildren();
  if (!state.sites.length) {
    const option = document.createElement('option');
    option.value = '';
    option.append(text('No IIS sites found'));
    iisSiteSelect.append(option);
    iisSiteSelect.disabled = true;
  } else {
    iisSiteSelect.disabled = false;
    for (const site of state.sites) {
      const option = document.createElement('option');
      option.value = site.name;
      option.selected = site.name === state.selectedSiteName;
      option.append(text(site.name));
      iisSiteSelect.append(option);
    }
  }

  iisDenyListBody.replaceChildren();
  if (!state.selectedSiteName) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 2;
    cell.className = 'empty';
    cell.append(text('Select or load an IIS site.'));
    row.append(cell);
    iisDenyListBody.append(row);
    return;
  }

  if (!state.deniedIps.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 2;
    cell.className = 'empty';
    cell.append(text('No deny-list entries for the selected site.'));
    row.append(cell);
    iisDenyListBody.append(row);
    return;
  }

  for (const clientIp of state.deniedIps) {
    const row = document.createElement('tr');
    const ipCell = document.createElement('td');
    ipCell.append(text(clientIp));
    const actionCell = document.createElement('td');
    const removeButton = document.createElement('button');
    removeButton.className = 'inline-button';
    removeButton.type = 'button';
    removeButton.append(text('Remove'));
    removeButton.onclick = () => {
      removeDeniedIp(clientIp).catch(() => {
        iisStatus.textContent = 'Removal failed.';
      });
    };
    actionCell.append(removeButton);
    row.append(ipCell, actionCell);
    iisDenyListBody.append(row);
  }
}

function render() {
  ensureDomainButtons();
  renderEvents();
  renderFindings();
  renderDetails();
  renderIis();
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function selectedDomainQuery() {
  return state.selectedDomain === '*' ? '' : `&domain=${escapeSegment(state.selectedDomain)}`;
}

function chooseSiteForSelectedFinding() {
  const finding = selectedFinding();
  if (!finding || !state.sites.length) {
    return false;
  }

  const matchingSite = state.sites.find(site =>
    (site.domains || []).some(domain =>
      (finding.domains || []).some(findingDomain => normalizeDomain(findingDomain).localeCompare(normalizeDomain(domain), undefined, { sensitivity: 'accent' }) === 0)));

  if (!matchingSite) {
    return false;
  }

  state.selectedSiteName = matchingSite.name;
  return true;
}

async function saveBanCount() {
  if (!state.selectedFindingIp) {
    banCountStatus.textContent = 'Select a finding first.';
    return;
  }

  const banCount = Number.parseInt(banCountValue.value, 10);
  if (!Number.isInteger(banCount) || banCount < 0) {
    banCountStatus.textContent = 'Enter a non-negative whole number.';
    return;
  }

  banCountStatus.textContent = 'Saving...';
  const response = await fetch(`/api/ban-counts/${escapeSegment(state.selectedFindingIp)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ banCount })
  });

  if (!response.ok) {
    banCountStatus.textContent = 'Save failed.';
    return;
  }

  const updated = await response.json();
  const finding = state.findings.find(item => item.clientIp === state.selectedFindingIp);
  if (finding) {
    finding.banCount = updated.banCount;
  }
  banCountValue.value = String(updated.banCount ?? 0);
  banCountStatus.textContent = 'Saved.';
  render();
}

async function selectDomain(domain) {
  state.selectedDomain = domain;
  document.querySelectorAll('#domains button').forEach(button => button.classList.toggle('active', button.dataset.domain === domain));
  await refreshFindings();
  if (state.selectedFindingIp) {
    const url = `/api/findings/${escapeSegment(state.selectedFindingIp)}/events?limit=250${selectedDomainQuery()}`;
    state.findingEvents = await fetchJson(url);
  }
  chooseSiteForSelectedFinding();
  if (state.selectedSiteName) {
    await refreshDeniedIps();
  }
  render();
}

async function refreshFindings() {
  const url = `/api/findings?limit=250${state.selectedDomain === '*' ? '' : `&domain=${escapeSegment(state.selectedDomain)}`}`;
  state.findings = await fetchJson(url);
  if (state.selectedFindingIp && !state.findings.some(item => item.clientIp === state.selectedFindingIp)) {
    state.selectedFindingIp = null;
    state.findingEvents = [];
  }
  render();
}

async function refreshSites() {
  state.sites = await fetchJson('/api/iis/sites');
  if (!state.selectedSiteName || !state.sites.some(site => site.name === state.selectedSiteName)) {
    if (!chooseSiteForSelectedFinding()) {
      state.selectedSiteName = state.sites[0]?.name || '';
    }
  }
  await refreshDeniedIps();
  render();
}

async function refreshDeniedIps() {
  if (!state.selectedSiteName) {
    state.deniedIps = [];
    return;
  }

  state.deniedIps = await fetchJson(`/api/iis/sites/${escapeSegment(state.selectedSiteName)}/deny-list`);
}

async function denySelectedFindingIp() {
  if (!state.selectedFindingIp) {
    iisStatus.textContent = 'Select a finding first.';
    return;
  }

  if (!state.selectedSiteName) {
    iisStatus.textContent = 'Select an IIS site first.';
    return;
  }

  iisStatus.textContent = 'Applying deny-list entry...';
  const response = await fetch(`/api/iis/sites/${escapeSegment(state.selectedSiteName)}/deny-list`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientIp: state.selectedFindingIp })
  });

  if (response.status === 403) {
    iisStatus.textContent = 'Enable IisAdmin:EnableDenyListChanges to modify deny lists.';
    return;
  }

  if (!response.ok) {
    iisStatus.textContent = 'Unable to add deny-list entry.';
    return;
  }

  await refreshDeniedIps();
  iisStatus.textContent = 'Deny-list entry added.';
  render();
}

async function removeDeniedIp(clientIp) {
  if (!state.selectedSiteName) {
    iisStatus.textContent = 'Select an IIS site first.';
    return;
  }

  iisStatus.textContent = 'Removing deny-list entry...';
  const response = await fetch(`/api/iis/sites/${escapeSegment(state.selectedSiteName)}/deny-list/${escapeSegment(clientIp)}`, {
    method: 'DELETE'
  });

  if (response.status === 403) {
    iisStatus.textContent = 'Enable IisAdmin:EnableDenyListChanges to modify deny lists.';
    return;
  }

  if (!response.ok) {
    iisStatus.textContent = 'Unable to remove deny-list entry.';
    return;
  }

  await refreshDeniedIps();
  iisStatus.textContent = 'Deny-list entry removed.';
  render();
}

function scheduleFindingsRefresh() {
  if (findingsRefreshHandle) return;
  findingsRefreshHandle = window.setTimeout(async () => {
    findingsRefreshHandle = 0;
    try {
      await refreshFindings();
    } catch {
    }
  }, 500);
}

async function openFinding(clientIp) {
  state.selectedFindingIp = clientIp;
  setView('details');
  const url = `/api/findings/${escapeSegment(clientIp)}/events?limit=250${selectedDomainQuery()}`;
  state.findingEvents = await fetchJson(url);
  chooseSiteForSelectedFinding();
  if (state.selectedSiteName) {
    await refreshDeniedIps();
  }
  render();
}

function addEvent(webEvent) {
  if (!state.events.some(existing => existing.id === webEvent.id)) {
    state.events.push(webEvent);
    scheduleFindingsRefresh();
  }
  render();
}

function initializeViewTabs() {
  viewButtons.forEach(button => {
    button.onclick = () => setView(button.dataset.view);
  });
}

allEvents.onchange = render;
banCountSave.onclick = () => {
  saveBanCount().catch(() => {
    banCountStatus.textContent = 'Save failed.';
  });
};
iisSiteSelect.onchange = () => {
  state.selectedSiteName = iisSiteSelect.value;
  refreshDeniedIps().then(render).catch(() => {
    iisStatus.textContent = 'Unable to load deny-list entries.';
  });
};
iisRefresh.onclick = () => {
  refreshSites().then(() => {
    iisStatus.textContent = 'IIS site data refreshed.';
  }).catch(() => {
    iisStatus.textContent = 'Unable to load IIS site data.';
  });
};
iisDenySelected.onclick = () => {
  denySelectedFindingIp().catch(() => {
    iisStatus.textContent = 'Unable to add deny-list entry.';
  });
};
document.querySelector('[data-domain="*"]').onclick = async () => {
  await selectDomain('*');
};

initializeViewTabs();
setView('events');
fetchJson('/api/events?limit=1000')
  .then(items => {
    items.reverse().forEach(addEvent);
    status.textContent = 'Connected';
    return refreshFindings();
  })
  .then(() => refreshSites().catch(() => {
    iisStatus.textContent = 'Unable to load IIS site data.';
  }))
  .catch(() => {
    status.textContent = 'API unavailable';
  });

const stream = new EventSource('/api/events/stream');
stream.addEventListener('etw', event => {
  status.textContent = 'Live';
  addEvent(JSON.parse(event.data));
});
stream.onerror = () => {
  status.textContent = 'Reconnecting...';
};
