const defaultColumnWidths = [170, 140, 100, 110, 110, 110, 220, 220, 280];

const state = {
  events: [],
  findings: [],
  sites: [],
  deniedIps: [],
  selectedDomain: '*',
  selectedView: 'events',
  selectedFindingIp: null,
  selectedSiteName: '',
  findingEvents: [],
  sortState: {
    events: { key: 'timestamp', direction: 'desc' },
    findings: { key: 'timestamp', direction: 'desc' },
    details: { key: 'timestamp', direction: 'desc' },
    iis: { key: 'client', direction: 'asc' }
  },
  columnWidths: {
    events: [...defaultColumnWidths],
    findings: [...defaultColumnWidths],
    details: [...defaultColumnWidths],
    iis: [...defaultColumnWidths]
  }
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
const denyTargetSites = document.querySelector('#deny-target-sites');
const denyTargetStatus = document.querySelector('#deny-target-status');
const iisSiteSelect = document.querySelector('#iis-site-select');
const iisRefresh = document.querySelector('#iis-refresh');
const iisDenySelected = document.querySelector('#iis-deny-selected');
const iisStatus = document.querySelector('#iis-status');
const iisDenyListBody = document.querySelector('#iis-deny-list');
const tableViews = {
  events: document.querySelector('#events-view table'),
  findings: document.querySelector('#findings-view table'),
  details: document.querySelector('#details-view table'),
  iis: document.querySelector('#iis-view table')
};
const tableColumns = [
  { key: 'timestamp', label: 'Time', type: 'date', defaultDirection: 'desc' },
  { key: 'client', label: 'Client', type: 'text', defaultDirection: 'asc' },
  { key: 'requests', label: 'Requests', type: 'number', defaultDirection: 'desc' },
  { key: 'suspicious', label: 'Suspicious', type: 'number', defaultDirection: 'desc' },
  { key: 'risk', label: 'Risk', type: 'number', defaultDirection: 'desc' },
  { key: 'banCount', label: 'Ban Count', type: 'number', defaultDirection: 'desc' },
  { key: 'domains', label: 'Domain(s)', type: 'text', defaultDirection: 'asc' },
  { key: 'path', label: 'Path', type: 'text', defaultDirection: 'asc' },
  { key: 'detection', label: 'Detection', type: 'text', defaultDirection: 'asc' }
];
const columnWidthLimits = { min: 80, max: 600 };
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

function createRiskBadge(score, severity) {
  const badge = document.createElement('span');
  badge.className = `badge ${getSeverityClass(severity)}`;
  badge.append(text(`${score ?? 0} ${severity || 'Low'}`));
  return badge;
}

function appendCell(row, value) {
  const cell = document.createElement('td');
  if (value instanceof Node) {
    cell.append(value);
  } else {
    cell.append(text(String(value ?? '')));
  }

  row.append(cell);
  return cell;
}

const tableColumnCount = 9;

function appendCells(row, values) {
  values.forEach(value => appendCell(row, value));
}

function createEmptyRow(message, colSpan = tableColumnCount) {
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = colSpan;
  cell.className = 'empty';
  cell.append(text(message));
  row.append(cell);
  return row;
}

function getViewSortState(view) {
  return state.sortState[view];
}

function getColumnDefinition(key) {
  return tableColumns.find(column => column.key === key) || tableColumns[0];
}

function defaultSortDirectionForKey(key) {
  return getColumnDefinition(key).defaultDirection;
}

function compareValues(left, right, type) {
  if (type === 'date') {
    const leftTime = left ? Date.parse(left) : Number.NEGATIVE_INFINITY;
    const rightTime = right ? Date.parse(right) : Number.NEGATIVE_INFINITY;
    return leftTime < rightTime ? -1 : leftTime > rightTime ? 1 : 0;
  }

  if (type === 'number') {
    const leftNumber = Number(left ?? Number.NEGATIVE_INFINITY);
    const rightNumber = Number(right ?? Number.NEGATIVE_INFINITY);
    return leftNumber < rightNumber ? -1 : leftNumber > rightNumber ? 1 : 0;
  }

  return String(left ?? '').localeCompare(String(right ?? ''), undefined, { numeric: true, sensitivity: 'base' });
}

function getColumnValue(view, item, key) {
  switch (view) {
    case 'events':
    case 'details':
      return {
        timestamp: item.timestamp,
        client: item.clientIp,
        requests: 1,
        suspicious: item.isSuspicious ? 1 : 0,
        risk: item.riskScore,
        banCount: state.findings.find(finding => finding.clientIp === item.clientIp)?.banCount ?? 0,
        domains: item.domain,
        path: item.path,
        detection: item.detectionReason || ''
      }[key];
    case 'findings':
      return {
        timestamp: item.lastSeen,
        client: item.clientIp,
        requests: item.requestCount,
        suspicious: item.suspiciousRequestCount,
        risk: item.highestRiskScore,
        banCount: item.banCount ?? 0,
        domains: (item.domains || []).join(', '),
        path: '',
        detection: (item.detectionReasons || []).join('; ')
      }[key];
    case 'iis':
      return {
        timestamp: '',
        client: item,
        requests: '',
        suspicious: '',
        risk: '',
        banCount: '',
        domains: state.selectedSiteName,
        path: '',
        detection: 'Deny-list entry'
      }[key];
    default:
      return item?.[key] ?? '';
  }
}

function sortItems(view, items) {
  const { key, direction } = getViewSortState(view);
  const column = getColumnDefinition(key);
  const multiplier = direction === 'desc' ? -1 : 1;
  return [...items].sort((left, right) => compareValues(getColumnValue(view, left, key), getColumnValue(view, right, key), column.type) * multiplier);
}

function setSort(view, key) {
  const current = getViewSortState(view);
  const nextDirection = current.key === key ? (current.direction === 'asc' ? 'desc' : 'asc') : defaultSortDirectionForKey(key);
  state.sortState[view] = { key, direction: nextDirection };
  applyTableUi(view);
  render();
}

function applyColumnWidths(view) {
  const table = tableViews[view];
  const widths = state.columnWidths[view];
  if (!table || !widths) {
    return;
  }

  widths.forEach((width, index) => {
    table.style.setProperty(`--col-${index + 1}`, `${width}px`);
  });
}

function updateHeaderIndicators(view) {
  const table = tableViews[view];
  if (!table) {
    return;
  }

  const sortState = getViewSortState(view);
  table.querySelectorAll('th').forEach((header, index) => {
    const column = tableColumns[index];
    const isActive = column.key === sortState.key;
    header.classList.toggle('active-sort', isActive);
    header.setAttribute('aria-sort', isActive ? (sortState.direction === 'asc' ? 'ascending' : 'descending') : 'none');
    const indicator = header.querySelector('.sort-indicator');
    if (indicator) {
      indicator.textContent = isActive ? (sortState.direction === 'asc' ? '▲' : '▼') : '';
    }
  });
}

function applyTableUi(view) {
  applyColumnWidths(view);
  updateHeaderIndicators(view);
}

function beginColumnResize(view, columnIndex, startX, startWidth) {
  const table = tableViews[view];
  const onMove = event => {
    const nextWidth = Math.max(columnWidthLimits.min, Math.min(columnWidthLimits.max, Math.round(startWidth + (event.clientX - startX))));
    state.columnWidths[view][columnIndex] = nextWidth;
    applyColumnWidths(view);
  };

  const onUp = () => {
    document.removeEventListener('pointermove', onMove);
    document.removeEventListener('pointerup', onUp);
    document.removeEventListener('pointercancel', onUp);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  };

  document.body.style.cursor = 'col-resize';
  document.body.style.userSelect = 'none';
  document.addEventListener('pointermove', onMove);
  document.addEventListener('pointerup', onUp);
  document.addEventListener('pointercancel', onUp);
  if (table) {
    table.focus?.();
  }
}

function initializeTableControls() {
  Object.entries(tableViews).forEach(([view, table]) => {
    if (!table) {
      return;
    }

    table.querySelectorAll('th').forEach((header, index) => {
      const column = tableColumns[index];
      header.classList.add('sortable');
      header.dataset.view = view;
      header.dataset.sortKey = column.key;
      if (!header.querySelector('.sort-indicator')) {
        const indicator = document.createElement('span');
        indicator.className = 'sort-indicator';
        header.append(indicator);
      }
      if (!header.querySelector('.resize-handle')) {
        const handle = document.createElement('span');
        handle.className = 'resize-handle';
        handle.addEventListener('pointerdown', event => {
          event.preventDefault();
          event.stopPropagation();
          beginColumnResize(view, index, event.clientX, state.columnWidths[view][index]);
        });
        handle.addEventListener('click', event => event.stopPropagation());
        header.append(handle);
      }
      header.onclick = event => {
        if (event.target instanceof Element && event.target.closest('.resize-handle')) {
          return;
        }
        setSort(view, column.key);
      };
      header.onkeydown = event => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          setSort(view, column.key);
        }
      };
      header.tabIndex = 0;
    });

    applyTableUi(view);
  });
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
  const visibleEvents = sortItems('events', state.events.filter(visibleEvent)).slice(0, 500);
  if (!visibleEvents.length) {
    eventBody.append(createEmptyRow(allEvents.checked ? 'No events received.' : 'No suspicious events received.'));
    return;
  }

  for (const webEvent of visibleEvents) {
    const row = document.createElement('tr');
    if (webEvent.isSuspicious) row.className = 'suspicious';

    const findingBanCount = state.findings.find(item => item.clientIp === webEvent.clientIp)?.banCount ?? 0;
    appendCells(row, [new Date(webEvent.timestamp).toLocaleString(), webEvent.clientIp, 1, webEvent.isSuspicious ? 'Yes' : 'No']);
    appendCell(row, createRiskBadge(webEvent.riskScore, webEvent.riskSeverity));
    appendCells(row, [findingBanCount, webEvent.domain, webEvent.path, String(webEvent.detectionReason || '')]);

    eventBody.append(row);
  }
}

function renderFindings() {
  findingBody.replaceChildren();
  const visibleFindings = sortItems('findings', state.findings.filter(visibleFinding));
  if (!visibleFindings.length) {
    findingBody.append(createEmptyRow('No suspicious IP findings available.'));
    return;
  }

  for (const finding of visibleFindings) {
    const row = document.createElement('tr');
    row.className = `clickable ${state.selectedFindingIp === finding.clientIp ? 'selected' : ''}`.trim();
    row.onclick = () => openFinding(finding.clientIp);

    appendCells(row, [
      new Date(finding.lastSeen).toLocaleString(),
      finding.clientIp,
      finding.requestCount,
      finding.suspiciousRequestCount
    ]);
    appendCell(row, createRiskBadge(finding.highestRiskScore, finding.highestRiskSeverity));
    appendCells(row, [finding.banCount ?? 0, (finding.domains || []).join(', '), '', (finding.detectionReasons || []).join('; ')]);

    findingBody.append(row);
  }
}

function updateTargetedDenyControls(finding) {
  denyTargetSites.disabled = !finding;
  if (!finding) {
    denyTargetStatus.textContent = '';
  }
}

function renderDetails() {
  detailBody.replaceChildren();
  const finding = state.findings.find(item => item.clientIp === state.selectedFindingIp) || null;
  updateTargetedDenyControls(finding);

  if (!finding) {
    detailSummary.textContent = 'Select a finding to inspect its recent events.';
    detailBody.append(createEmptyRow('No finding selected.'));
    return;
  }

  detailSummary.replaceChildren();
  const strong = document.createElement('strong');
  strong.append(text(finding.clientIp));
  detailSummary.append(strong, text(` · ${finding.requestCount} requests · ${finding.suspiciousRequestCount} suspicious · Ban count ${finding.banCount ?? 0} · Highest risk ${finding.highestRiskScore} (${finding.highestRiskSeverity})`));
  banCountValue.value = String(finding.banCount ?? 0);

  const visibleEvents = sortItems('details', state.findingEvents);
  if (!visibleEvents.length) {
    detailBody.append(createEmptyRow('No recent events available for this IP.'));
    return;
  }

  for (const webEvent of visibleEvents) {
    const row = document.createElement('tr');
    if (webEvent.isSuspicious) row.className = 'suspicious';

    appendCells(row, [new Date(webEvent.timestamp).toLocaleString(), webEvent.clientIp, 1, webEvent.isSuspicious ? 'Yes' : 'No']);
    appendCell(row, createRiskBadge(webEvent.riskScore, webEvent.riskSeverity));
    appendCells(row, [finding.banCount ?? 0, webEvent.domain, webEvent.path, String(webEvent.detectionReason || '')]);

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
    iisDenyListBody.append(createEmptyRow('Select or load an IIS site.'));
    return;
  }

  const visibleDeniedIps = sortItems('iis', state.deniedIps);
  if (!visibleDeniedIps.length) {
    iisDenyListBody.append(createEmptyRow('No deny-list entries for the selected site.'));
    return;
  }

  for (const clientIp of visibleDeniedIps) {
    const row = document.createElement('tr');
    appendCells(row, ['', clientIp, '', '', '', '', state.selectedSiteName, '']);

    const detectionCell = appendCell(row, 'Deny-list entry');
    const removeButton = document.createElement('button');
    removeButton.className = 'inline-button';
    removeButton.type = 'button';
    removeButton.append(text('Remove'));
    removeButton.onclick = () => {
      removeDeniedIp(clientIp).catch(() => {
        iisStatus.textContent = 'Removal failed.';
      });
    };
    detectionCell.append(text(' '), removeButton);
    iisDenyListBody.append(row);
  }
}

function render() {
  ensureDomainButtons();
  applyTableUi('events');
  applyTableUi('findings');
  applyTableUi('details');
  applyTableUi('iis');
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
  const domainQuery = state.selectedDomain === '*' ? '' : `?domain=${escapeSegment(state.selectedDomain)}`;
  const response = await fetch(`/api/ban-counts/${escapeSegment(state.selectedFindingIp)}${domainQuery}`, {
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

async function denyFindingOnMatchedSites() {
  const finding = selectedFinding();
  if (!finding) {
    denyTargetStatus.textContent = 'Select a finding first.';
    return;
  }

  denyTargetStatus.textContent = 'Applying deny-list entry...';
  const response = await fetch('/api/iis/deny-list', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientIp: finding.clientIp })
  });

  if (response.status === 403) {
    denyTargetStatus.textContent = 'Enable IisAdmin:EnableDenyListChanges to modify deny lists.';
    return;
  }

  if (response.status === 404) {
    denyTargetStatus.textContent = 'No matching IIS sites were found for the selected IP.';
    return;
  }

  if (!response.ok) {
    denyTargetStatus.textContent = 'Unable to add deny-list entry.';
    return;
  }

  const updated = await response.json();
  denyTargetStatus.textContent = `Added to ${updated.sites?.length ?? 0} site(s).`;
  if (state.selectedSiteName) {
    await refreshDeniedIps();
  }
  render();
}

async function selectDomain(domain) {
  state.selectedDomain = domain;
  denyTargetStatus.textContent = '';
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
  denyTargetStatus.textContent = '';
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
denyTargetSites.onclick = () => {
  denyFindingOnMatchedSites().catch(() => {
    denyTargetStatus.textContent = 'Unable to add deny-list entry.';
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
initializeTableControls();
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
