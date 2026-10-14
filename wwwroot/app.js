const defaultColumnWidths = [170, 140, 100, 110, 110, 110, 220, 220, 280];

const state = {
  events: [],
  findings: [],
  sites: [],
  deniedIps: [],
  iisStatusInfo: null,
  iisStatusError: '',
  iisStatusErrorStatus: 0,
  selectedDomain: '*',
  domainRequestId: 0,
  findingsRequestId: 0,
  iisStatusRequestId: 0,
  sitesRequestId: 0,
  deniedListRequestId: 0,
  selectedView: 'events',
  selectedFindingIp: null,
  selectedFindingIps: new Set(),
  selectedSiteName: '',
  findingEvents: [],
  searchQuery: '',
  livePaused: false,
  bulkDenyRunning: false,
  eventSource: null,
  reconnectTimer: 0,
  reconnectAttempts: 0,
  detailRequestId: 0,
  renderFrame: 0,
  accessStatusSignature: '',
  dismissedAccessWarnings: new Set(),
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
const streamHint = document.querySelector('#stream-hint');
const pauseEvents = document.querySelector('#pause-events');
const searchInput = document.querySelector('#search-input');
const themeToggle = document.querySelector('#theme-toggle');
const accessNotices = document.querySelector('#access-notices');
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
const iisConfigStatus = document.querySelector('#iis-config-status');
const iisAuditBody = document.querySelector('#iis-audit-list');
const iisDenyListBody = document.querySelector('#iis-deny-list');
const configurationEditor = document.querySelector('#configuration-editor');
const configurationReload = document.querySelector('#configuration-reload');
const configurationSave = document.querySelector('#configuration-save');
const configurationStatus = document.querySelector('#configuration-status');
const bulkDenySelected = document.querySelector('#bulk-deny-selected');
const bulkDenyStatus = document.querySelector('#bulk-deny-status');
const selectVisible = document.querySelector('#select-visible');
const selectionCount = document.querySelector('#selection-count');
const riskChart = document.querySelector('#risk-chart');
const ipChart = document.querySelector('#ip-chart');
const chartFootnote = document.querySelector('#chart-footnote');
const findingRiskIndicators = document.querySelector('#finding-risk-indicators');
const findingReasons = document.querySelector('#finding-reasons');
const tableViews = {
  events: document.querySelector('#events-view table'),
  findings: document.querySelector('#findings-view table'),
  details: document.querySelector('#details-view table'),
  iis: document.querySelector('#iis-deny-list')?.closest('table')
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
const maxEventsInMemory = 2000;
const initialEventLimit = 1000;
const dayInMilliseconds = 24 * 60 * 60 * 1000;
let configurationLoaded = false;

function text(value) {
  return document.createTextNode(value ?? '');
}

function setConnectionStatus(message, stateName) {
  status.dataset.state = stateName;
  const dot = document.createElement('span');
  dot.className = 'connection-dot';
  dot.setAttribute('aria-hidden', 'true');
  status.replaceChildren(dot, text(message));
}

function escapeSegment(value) {
  return encodeURIComponent(value ?? '');
}

function getSeverityClass(value) {
  const severity = String(value || 'Low').toLowerCase();
  return ['low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'low';
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

function matchesSearch(values) {
  const query = state.searchQuery.trim().toLocaleLowerCase();
  return !query || values.some(value => String(value ?? '').toLocaleLowerCase().includes(query));
}

function formatTimestamp(value) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function setView(view) {
  state.selectedView = view;
  viewButtons.forEach(button => button.classList.toggle('active', button.dataset.view === view));
  document.querySelectorAll('.view').forEach(panel => panel.classList.toggle('active', panel.id === `${view}-view`));
}

function visibleEvent(webEvent) {
  return (allEvents.checked || webEvent.isSuspicious) &&
    (state.selectedDomain === '*' || webEvent.domain === state.selectedDomain) &&
    matchesSearch([
      webEvent.clientIp,
      webEvent.domain,
      webEvent.path,
      webEvent.method,
      webEvent.detectionReason,
      ...(webEvent.riskIndicators || [])
    ]);
}

function visibleFinding(finding) {
  return (state.selectedDomain === '*' || (finding.domains || []).includes(state.selectedDomain)) &&
    matchesSearch([
      finding.clientIp,
      ...(finding.domains || []),
      ...(finding.detectionReasons || []),
      ...(finding.riskIndicators || []),
      finding.highestRiskSeverity,
      finding.highestRiskScore
    ]);
}

function ensureDomainButtons() {
  const domainNames = new Set();
  state.events.forEach(webEvent => webEvent.domain && domainNames.add(webEvent.domain));
  state.findings.forEach(finding => (finding.domains || []).forEach(domain => domain && domainNames.add(domain)));

  for (const domain of [...domainNames].sort((left, right) => left.localeCompare(right))) {
    if (!document.querySelector(`button[data-domain="${CSS.escape(domain)}"]`)) {
      const button = document.createElement('button');
      button.className = 'domain-chip';
      button.dataset.domain = domain;
      button.append(text(domain));
      button.onclick = () => {
        selectDomain(domain).catch(error => {
          streamHint.textContent = `Unable to change domain filter: ${error.message}`;
        });
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
    appendCells(row, [formatTimestamp(webEvent.timestamp), webEvent.clientIp, 1, webEvent.isSuspicious ? 'Yes' : 'No']);
    appendCell(row, createRiskBadge(webEvent.riskScore, webEvent.riskSeverity));
    appendCells(row, [findingBanCount, webEvent.domain, webEvent.path, String(webEvent.detectionReason || '')]);

    eventBody.append(row);
  }
}

function renderFindings() {
  findingBody.replaceChildren();
  const visibleFindings = sortItems('findings', state.findings.filter(visibleFinding));
  const allVisibleSelected = visibleFindings.length > 0 &&
    visibleFindings.every(finding => state.selectedFindingIps.has(finding.clientIp));
  selectVisible.textContent = allVisibleSelected ? 'Clear visible selection' : 'Select visible';
  selectionCount.textContent = `${state.selectedFindingIps.size} selected`;
  selectVisible.disabled = visibleFindings.length === 0 || state.bulkDenyRunning;
  bulkDenySelected.disabled = state.selectedFindingIps.size === 0 ||
    !state.iisStatusInfo?.enableDenyListChanges || state.bulkDenyRunning;
  if (!visibleFindings.length) {
    findingBody.append(createEmptyRow('No suspicious IP findings available.'));
    return;
  }

  for (const finding of visibleFindings) {
    const row = document.createElement('tr');
    row.className = `clickable ${state.selectedFindingIp === finding.clientIp ? 'selected' : ''}`.trim();
    row.onclick = () => openFinding(finding.clientIp);

    appendCell(row, formatTimestamp(finding.lastSeen));
    const clientCell = appendCell(row, '');
    const selector = document.createElement('input');
    selector.type = 'checkbox';
    selector.className = 'finding-select';
    selector.checked = state.selectedFindingIps.has(finding.clientIp);
    selector.disabled = state.bulkDenyRunning;
    selector.setAttribute('aria-label', `Select ${finding.clientIp}`);
    selector.onclick = event => event.stopPropagation();
    selector.onchange = () => {
      if (selector.checked) {
        state.selectedFindingIps.add(finding.clientIp);
      } else {
        state.selectedFindingIps.delete(finding.clientIp);
      }
      renderFindings();
    };
    clientCell.append(selector, text(finding.clientIp));
    appendCells(row, [finding.requestCount, finding.suspiciousRequestCount]);
    appendCell(row, createRiskBadge(finding.highestRiskScore, finding.highestRiskSeverity));
    appendCells(row, [finding.banCount ?? 0, (finding.domains || []).join(', '), '', (finding.detectionReasons || []).join('; ')]);

    findingBody.append(row);
  }
}

function appendChartRows(container, entries) {
  container.replaceChildren();
  if (!entries.length) {
    const empty = document.createElement('span');
    empty.className = 'muted';
    empty.append(text('No matching events in the loaded 24-hour sample.'));
    container.append(empty);
    return;
  }

  const maxValue = Math.max(...entries.map(entry => entry.value), 1);
  for (const entry of entries) {
    const row = document.createElement('div');
    row.className = 'chart-row';
    const label = document.createElement('span');
    label.className = 'chart-label';
    label.title = entry.label;
    label.append(text(entry.label));
    const track = document.createElement('span');
    track.className = 'bar-track';
    const bar = document.createElement('span');
    bar.className = `bar-fill ${getSeverityClass(entry.severity || 'low')}`;
    bar.style.setProperty('--bar-width', `${Math.max(2, (entry.value / maxValue) * 100)}%`);
    track.append(bar);
    const value = document.createElement('span');
    value.className = 'chart-value';
    value.append(text(entry.value));
    row.append(label, track, value);
    container.append(row);
  }
}

function renderCharts() {
  const cutoff = Date.now() - dayInMilliseconds;
  const events = state.events.filter(webEvent =>
    Date.parse(webEvent.timestamp) >= cutoff &&
    (state.selectedDomain === '*' || webEvent.domain === state.selectedDomain));
  const riskCounts = new Map([['Low (0)', 0], ['Medium (1–3)', 0], ['High (4–7)', 0], ['Critical (8+)', 0]]);
  const ipCounts = new Map();

  for (const webEvent of events) {
    const score = Number(webEvent.riskScore) || 0;
    const bucket = score >= 8 ? 'Critical (8+)'
      : score >= 4 ? 'High (4–7)'
        : score >= 1 ? 'Medium (1–3)'
          : 'Low (0)';
    riskCounts.set(bucket, riskCounts.get(bucket) + 1);
    if (webEvent.clientIp) {
      ipCounts.set(webEvent.clientIp, (ipCounts.get(webEvent.clientIp) || 0) + 1);
    }
  }

  appendChartRows(riskChart, [...riskCounts].map(([label, value]) => ({
    label,
    value,
    severity: label.startsWith('Critical') ? 'Critical'
      : label.startsWith('High') ? 'High'
        : label.startsWith('Medium') ? 'Medium'
          : 'Low'
  })));
  appendChartRows(ipChart, [...ipCounts]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))
    .slice(0, 6));
  chartFootnote.textContent = `${events.length} matching events from the last 24 hours in a rolling sample of ${state.events.length} recent events.`;
}

function renderFindingIndicators(finding) {
  const indicators = new Set(finding.riskIndicators || []);
  for (const webEvent of state.findingEvents) {
    for (const indicator of webEvent.riskIndicators || []) indicators.add(indicator);
  }

  for (const [container, values] of [
    [findingRiskIndicators, [...indicators]],
    [findingReasons, finding.detectionReasons || []]
  ]) {
    container.replaceChildren();
    if (!values.length) {
      const empty = document.createElement('span');
      empty.className = 'muted';
      empty.append(text('No indicators recorded.'));
      container.append(empty);
      continue;
    }

    for (const value of values) {
      const chip = document.createElement('span');
      chip.className = 'indicator-chip';
      chip.append(text(value));
      container.append(chip);
    }
  }
}

function updateTargetedDenyControls(finding) {
  const canChangeDenyList = Boolean(state.iisStatusInfo?.enableDenyListChanges);
  denyTargetSites.disabled = !finding || !canChangeDenyList;
  iisDenySelected.disabled = !state.selectedFindingIp || !state.selectedSiteName || !canChangeDenyList;
  banCountSave.disabled = !state.iisStatusInfo;
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
    findingRiskIndicators.replaceChildren(text('No finding selected.'));
    findingReasons.replaceChildren(text('No finding selected.'));
    return;
  }

  detailSummary.replaceChildren();
  const strong = document.createElement('strong');
  strong.append(text(finding.clientIp));
  detailSummary.append(
    strong,
    text(` · ${finding.requestCount} requests · ${finding.suspiciousRequestCount} suspicious · Ban count ${finding.banCount ?? 0} · Highest risk ${finding.highestRiskScore} (${finding.highestRiskSeverity}) · First seen ${formatTimestamp(finding.firstSeen)} · Last seen ${formatTimestamp(finding.lastSeen)}`)
  );
  renderFindingIndicators(finding);
  if (document.activeElement !== banCountValue) {
    banCountValue.value = String(finding.banCount ?? 0);
  }

  const visibleEvents = sortItems('details', state.findingEvents.filter(webEvent =>
    matchesSearch([
      webEvent.clientIp,
      webEvent.domain,
      webEvent.path,
      webEvent.method,
      webEvent.detectionReason,
      ...(webEvent.riskIndicators || [])
    ])));
  if (!visibleEvents.length) {
    detailBody.append(createEmptyRow('No recent events available for this IP.'));
    return;
  }

  for (const webEvent of visibleEvents) {
    const row = document.createElement('tr');
    if (webEvent.isSuspicious) row.className = 'suspicious';

    appendCells(row, [formatTimestamp(webEvent.timestamp), webEvent.clientIp, 1, webEvent.isSuspicious ? 'Yes' : 'No']);
    appendCell(row, createRiskBadge(webEvent.riskScore, webEvent.riskSeverity));
    appendCells(row, [finding.banCount ?? 0, webEvent.domain, webEvent.path, String(webEvent.detectionReason || '')]);

    detailBody.append(row);
  }
}

function renderIis() {
  renderIisConfiguration();
  renderIisAudit();

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

  function renderIisConfiguration() {
    if (!state.iisStatusInfo) {
      iisConfigStatus.textContent = state.iisStatusError || 'IIS safety settings are unavailable.';
      return;
    }

    const settings = state.iisStatusInfo;
    const temporaryBan = settings.temporaryBanMinutes > 0
      ? `${settings.temporaryBanMinutes} minute(s)`
      : 'permanent';
    iisConfigStatus.textContent =
      `Deny-list changes: ${settings.enableDenyListChanges ? 'enabled' : 'disabled'} · ` +
      `Dry run: ${settings.dryRun ? 'ON' : 'OFF'} · ` +
      `Ban duration: ${temporaryBan} · ` +
      `Multiple indicators: ${settings.requireMultipleIndicators ? 'required' : 'not required'}`;
  }

  function renderIisAudit() {
    iisAuditBody.replaceChildren();
    const entries = state.iisStatusInfo?.recentAuditEntries || [];
    if (!entries.length) {
      iisAuditBody.append(createEmptyRow(
        state.iisStatusInfo ? 'No deny-list audit entries.' : 'Audit history is unavailable.',
        8
      ));
      return;
    }

    for (const entry of entries) {
      const row = document.createElement('tr');
      const occurredAt = entry.occurredAt ? new Date(entry.occurredAt).toLocaleString() : '';
      const expiresAt = entry.expiresAt ? new Date(entry.expiresAt).toLocaleString() : '';
      appendCells(row, [
        occurredAt,
        entry.actor,
        entry.action,
        entry.clientIp,
        entry.siteName,
        expiresAt,
        entry.reason,
        entry.dryRun ? `Dry run (${entry.outcome})` : entry.outcome
      ]);
      iisAuditBody.append(row);
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
    removeButton.disabled = !state.iisStatusInfo?.enableDenyListChanges;
    removeButton.append(text('Remove'));
    removeButton.onclick = () => {
      removeDeniedIp(clientIp).catch(error => {
        iisStatus.textContent = `Removal failed: ${error.message}`;
      });
    };
    detectionCell.append(text(' '), removeButton);
    iisDenyListBody.append(row);
  }
}

function createNotice(tone, title, message) {
  const isWarning = tone === 'warning' || tone === 'danger';
  const warningKey = `${tone}|${title}|${message}`;
  if (isWarning) {
    const logWarning = tone === 'danger' ? console.error : console.warn;
    logWarning.call(console, `[iisidsd] ${title}: ${message}`);
    if (state.dismissedAccessWarnings.has(warningKey)) return null;
  }

  const notice = document.createElement('div');
  notice.className = `notice ${tone}`;
  const heading = document.createElement('strong');
  heading.append(text(`${title}: `));
  notice.append(heading, text(message));
  if (isWarning) {
    const dismissButton = document.createElement('button');
    dismissButton.className = 'notice-dismiss';
    dismissButton.type = 'button';
    dismissButton.setAttribute('aria-label', `Dismiss ${title}`);
    dismissButton.append(text('Dismiss'));
    dismissButton.onclick = () => {
      state.dismissedAccessWarnings.add(warningKey);
      console.info(`[iisidsd] Dismissed dashboard notice: ${title}.`);
      notice.remove();
    };
    notice.append(dismissButton);
  }
  return notice;
}

function appendAccessNotice(tone, title, message) {
  const notice = createNotice(tone, title, message);
  if (notice) accessNotices.append(notice);
}

function renderAccessStatus() {
  const host = location.hostname.toLowerCase();
  const localHost = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host);
  const signature = [
    host,
    state.iisStatusInfo
      ? `${state.iisStatusInfo.enableDenyListChanges}:${state.iisStatusInfo.dryRun}`
      : `error:${state.iisStatusErrorStatus}`
  ].join('|');
  if (signature === state.accessStatusSignature) return;
  state.accessStatusSignature = signature;
  accessNotices.replaceChildren();
  if (localHost) {
    appendAccessNotice(
      'warning',
      'Remote access',
      'The server setting is not exposed by the available API. Remote clients are blocked when Dashboard:RemoteAccessEnabled is false.'
    );
  } else {
    appendAccessNotice(
      'good',
      'Remote access',
      'This remote browser session reached the dashboard through the server access policy.'
    );
  }

  if (state.iisStatusInfo) {
    appendAccessNotice(
      'good',
      'Administrator access verified',
      'Administrator-only IIS settings are available for this session.'
    );
    if (state.iisStatusInfo.dryRun) {
      appendAccessNotice(
        'warning',
        'Dry run is ON',
        'Deny-list actions are logged as intended actions and will not change IIS.'
      );
    }

    if (!state.iisStatusInfo.enableDenyListChanges) {
      appendAccessNotice(
        'danger',
        'Deny-list changes are disabled',
        'IisAdmin:EnableDenyListChanges is the master switch; mutation controls are disabled.'
      );
    }
  } else if (state.iisStatusErrorStatus === 403) {
    appendAccessNotice(
      'danger',
      'Administrator access unavailable',
      'This account is not authorized for administrator-only dashboard actions, or the server access policy rejected the request.'
    );
  } else if (state.iisStatusErrorStatus === 401) {
    appendAccessNotice(
      'warning',
      'Administrator sign-in required',
      'Windows Authentication is only needed to verify administrator-only IIS features; viewing the dashboard does not require sign-in.'
    );
  } else {
    appendAccessNotice(
      'warning',
      'Administrator status unknown',
      'IIS safety settings and administrator-only actions are unavailable until status can be read.'
    );
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
  renderCharts();
  renderAccessStatus();
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.text();
    let detail = body.slice(0, 300);
    if (body) {
      try {
        const problem = JSON.parse(body);
        const validationErrors = Object.values(problem.errors || {}).flat().join(' ');
        detail = validationErrors || problem.detail || problem.title || detail;
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
      }
    }
    const error = new Error(`Request failed: ${response.status}${detail ? ` - ${detail}` : ''}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

async function loadBackendConfiguration() {
  configurationStatus.textContent = 'Loading saved settings...';
  configurationReload.disabled = true;
  try {
    const response = await fetchJson('/api/configuration');
    configurationEditor.value = JSON.stringify(response.settings, null, 2);
    configurationLoaded = true;
    configurationStatus.textContent = 'Loaded the supported settings from appsettings.json.';
  } catch (error) {
    configurationStatus.textContent = error.status === 401 || error.status === 403
      ? 'Backend configuration is available to authorized administrators only.'
      : `Unable to load backend configuration: ${error.message}`;
  } finally {
    configurationReload.disabled = false;
  }
}

async function saveBackendConfiguration() {
  let settings;
  try {
    settings = JSON.parse(configurationEditor.value);
  } catch (error) {
    configurationStatus.textContent = `Invalid JSON: ${error.message}`;
    return;
  }

  configurationSave.disabled = true;
  configurationStatus.textContent = 'Validating and saving settings...';
  try {
    const response = await fetchJson('/api/configuration', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings })
    });
    configurationEditor.value = JSON.stringify(response.settings, null, 2);
    configurationLoaded = true;
    configurationStatus.textContent = 'Settings saved to appsettings.json. Restart the iisidsd service to apply them.';
  } catch (error) {
    configurationStatus.textContent = error.status === 401 || error.status === 403
      ? 'Backend configuration changes are restricted to authorized administrators.'
      : `Unable to save backend configuration: ${error.message}`;
  } finally {
    configurationSave.disabled = false;
  }
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

  const clientIp = state.selectedFindingIp;
  const domain = state.selectedDomain;
  const banCount = Number.parseInt(banCountValue.value, 10);
  if (!Number.isInteger(banCount) || banCount < 0) {
    banCountStatus.textContent = 'Enter a non-negative whole number.';
    return;
  }

  banCountStatus.textContent = 'Saving...';
  const domainQuery = domain === '*' ? '' : `?domain=${escapeSegment(domain)}`;
  const response = await fetch(`/api/ban-counts/${escapeSegment(clientIp)}${domainQuery}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ banCount })
  });

  if (!response.ok) {
    banCountStatus.textContent = response.status === 401
      ? 'Windows Authentication is required.'
      : response.status === 403
        ? 'Administrator access or an enabled remote-access configuration is required.'
        : 'Save failed.';
    return;
  }

  const updated = await response.json();
  const finding = state.findings.find(item => item.clientIp === clientIp);
  if (finding) {
    finding.banCount = updated.banCount;
  }
  if (state.selectedFindingIp === clientIp) {
    banCountValue.value = String(updated.banCount ?? 0);
    banCountStatus.textContent = 'Saved.';
  } else {
    banCountStatus.textContent = `Saved the ban count for ${clientIp}.`;
  }
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
    body: JSON.stringify({ clientIp: finding.clientIp, reason: 'Manual dashboard deny-list action' })
  });

  if (response.status === 401) {
    denyTargetStatus.textContent = 'Windows Authentication is required.';
    return;
  }

  if (response.status === 403) {
    denyTargetStatus.textContent = 'Access denied. Check administrator access, IisAdmin:EnableDenyListChanges, and whether the IP is allow-listed.';
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
  denyTargetStatus.textContent = updated.dryRun
    ? `Dry run: would deny ${finding.clientIp} on sites matching ${updated.domains?.join(', ') || 'the finding domains'}.`
    : `Added to ${updated.sites?.length ?? 0} site(s).`;
  await refreshIisStatus();
  if (!updated.dryRun && state.selectedSiteName) {
    await refreshDeniedIps();
  }
  render();
}

async function selectDomain(domain) {
  const requestId = ++state.domainRequestId;
  const detailRequestId = state.detailRequestId;
  const selectedFindingIp = state.selectedFindingIp;
  state.selectedDomain = domain;
  denyTargetStatus.textContent = '';
  bulkDenyStatus.textContent = '';
  document.querySelectorAll('#domains button').forEach(button => button.classList.toggle('active', button.dataset.domain === domain));
  await refreshFindings();
  if (requestId !== state.domainRequestId) return;
  if (selectedFindingIp &&
      state.selectedFindingIp === selectedFindingIp &&
      state.detailRequestId === detailRequestId) {
    const url = `/api/findings/${escapeSegment(selectedFindingIp)}/events?limit=250${selectedDomainQuery()}`;
    const findingEvents = await fetchJson(url);
    if (requestId !== state.domainRequestId ||
        state.selectedFindingIp !== selectedFindingIp ||
        state.detailRequestId !== detailRequestId) return;
    state.findingEvents = findingEvents;
  }
  chooseSiteForSelectedFinding();
  if (state.selectedSiteName) {
    await refreshDeniedIps();
  }
  render();
}

async function refreshFindings() {
  const requestId = ++state.findingsRequestId;
  const url = `/api/findings?limit=250${state.selectedDomain === '*' ? '' : `&domain=${escapeSegment(state.selectedDomain)}`}`;
  const findings = await fetchJson(url);
  if (requestId !== state.findingsRequestId) return;
  state.findings = findings;
  const availableIps = new Set(findings.map(item => item.clientIp));
  state.selectedFindingIps = new Set([...state.selectedFindingIps].filter(ip => availableIps.has(ip)));
  if (state.selectedFindingIp && !state.findings.some(item => item.clientIp === state.selectedFindingIp)) {
    state.selectedFindingIp = null;
    state.findingEvents = [];
    state.detailRequestId++;
  }
  render();
}

async function refreshSites() {
  const requestId = ++state.sitesRequestId;
  await refreshIisStatus();
  const sites = await fetchJson('/api/iis/sites');
  if (requestId !== state.sitesRequestId) return;
  state.sites = sites;
  if (!state.selectedSiteName || !state.sites.some(site => site.name === state.selectedSiteName)) {
    if (!chooseSiteForSelectedFinding()) {
      state.selectedSiteName = state.sites[0]?.name || '';
    }
  }
  await refreshDeniedIps();
  if (requestId !== state.sitesRequestId) return;
  render();
}

async function refreshIisStatus() {
  const requestId = ++state.iisStatusRequestId;
  try {
    const statusInfo = await fetchJson('/api/iis/status');
    if (requestId !== state.iisStatusRequestId) return;
    state.iisStatusInfo = statusInfo;
    state.iisStatusError = '';
    state.iisStatusErrorStatus = 0;
  } catch (error) {
    if (requestId !== state.iisStatusRequestId) return;
    state.iisStatusInfo = null;
    state.iisStatusErrorStatus = error?.status || 0;
    state.iisStatusError = state.iisStatusErrorStatus === 401
      ? 'Windows Authentication is required to view administrator-only IIS settings.'
      : state.iisStatusErrorStatus === 403
        ? 'Administrator access is required to view IIS settings and audit history.'
        : 'Unable to read IIS settings and audit history.';
  }

  render();
}

async function refreshDeniedIps() {
  const requestId = ++state.deniedListRequestId;
  if (!state.selectedSiteName) {
    state.deniedIps = [];
    return;
  }

  const siteName = state.selectedSiteName;
  const deniedIps = await fetchJson(`/api/iis/sites/${escapeSegment(siteName)}/deny-list`);
  if (requestId === state.deniedListRequestId && state.selectedSiteName === siteName) {
    state.deniedIps = deniedIps;
  }
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

  const clientIp = state.selectedFindingIp;
  const siteName = state.selectedSiteName;
  iisStatus.textContent = 'Applying deny-list entry...';
  const response = await fetch(`/api/iis/sites/${escapeSegment(siteName)}/deny-list`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientIp, reason: 'Manual dashboard deny-list action' })
  });

  if (response.status === 401) {
    iisStatus.textContent = 'Windows Authentication is required.';
    return;
  }

  if (response.status === 403) {
    iisStatus.textContent = 'Access denied. Check administrator access, IisAdmin:EnableDenyListChanges, and whether the IP is allow-listed.';
    return;
  }

  if (!response.ok) {
    iisStatus.textContent = 'Unable to add deny-list entry.';
    return;
  }

  const updated = await response.json();
  if (!updated.dryRun && state.selectedSiteName === siteName) {
    await refreshDeniedIps();
  }
  iisStatus.textContent = updated.dryRun
    ? `Dry run: would deny ${clientIp} on ${siteName}.`
    : `Deny-list entry added for ${clientIp} on ${siteName}.`;
  await refreshIisStatus();
  render();
}

async function removeDeniedIp(clientIp) {
  if (!state.selectedSiteName) {
    iisStatus.textContent = 'Select an IIS site first.';
    return;
  }

  const siteName = state.selectedSiteName;
  iisStatus.textContent = 'Removing deny-list entry...';
  const response = await fetch(`/api/iis/sites/${escapeSegment(siteName)}/deny-list/${escapeSegment(clientIp)}?reason=${escapeSegment('Manual dashboard removal')}`, {
    method: 'DELETE'
  });

  if (response.status === 401) {
    iisStatus.textContent = 'Windows Authentication is required.';
    return;
  }

  if (response.status === 403) {
    iisStatus.textContent = 'Access denied. Check administrator access, HTTPS/remote-access settings, and IisAdmin:EnableDenyListChanges.';
    return;
  }

  if (!response.ok) {
    iisStatus.textContent = 'Unable to remove deny-list entry.';
    return;
  }

  const updated = await response.json();
  if (!updated.dryRun && state.selectedSiteName === siteName) {
    await refreshDeniedIps();
  }
  iisStatus.textContent = updated.dryRun
    ? `Dry run: would remove ${clientIp} from ${siteName}.`
    : `Deny-list entry removed for ${clientIp} from ${siteName}.`;
  await refreshIisStatus();
  render();
}

async function denySelectedFindings() {
  const clientIps = [...state.selectedFindingIps];
  if (!clientIps.length) {
    bulkDenyStatus.textContent = 'Select one or more findings first.';
    return;
  }
  if (!state.iisStatusInfo?.enableDenyListChanges) {
    bulkDenyStatus.textContent = 'Deny-list changes are disabled or administrator access is unavailable.';
    return;
  }

  const mode = state.iisStatusInfo.dryRun ? 'dry run' : 'apply';
  if (!window.confirm(`${mode === 'dry run' ? 'Simulate' : 'Deny'} ${clientIps.length} selected IP address(es)?`)) {
    return;
  }

  let applied = 0;
  let simulated = 0;
  const failed = [];
  const failedIps = [];
  bulkDenySelected.disabled = true;
  state.bulkDenyRunning = true;
  renderFindings();
  bulkDenyStatus.textContent = 'Processing selected IPs sequentially...';

  for (const clientIp of clientIps) {
    try {
      const response = await fetch('/api/iis/deny-list', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientIp, reason: 'Bulk dashboard deny-list action' })
      });
      if (!response.ok) {
        failed.push(`${clientIp} (HTTP ${response.status})`);
        failedIps.push(clientIp);
        continue;
      }

      const result = await response.json();
      if (result.dryRun) {
        simulated++;
      } else {
        applied++;
      }
    } catch (error) {
      failed.push(`${clientIp} (${error.message})`);
      failedIps.push(clientIp);
    }
  }

  state.selectedFindingIps = new Set(failedIps);
  state.bulkDenyRunning = false;
  renderFindings();
  const resultSummary = [
    applied ? `${applied} applied` : '',
    simulated ? `${simulated} simulated` : '',
    failed.length ? `${failed.length} failed: ${failed.join(', ')}` : ''
  ].filter(Boolean).join(' · ');
  bulkDenyStatus.textContent = resultSummary || 'No deny-list actions were completed.';

  try {
    await refreshIisStatus();
    await refreshFindings();
  } catch (error) {
    bulkDenyStatus.textContent += ` Refresh failed: ${error.message}`;
  }
}

function selectVisibleFindings() {
  const visibleFindings = state.findings.filter(visibleFinding);
  const allVisibleSelected = visibleFindings.length > 0 &&
    visibleFindings.every(finding => state.selectedFindingIps.has(finding.clientIp));

  for (const finding of visibleFindings) {
    if (allVisibleSelected) {
      state.selectedFindingIps.delete(finding.clientIp);
    } else {
      state.selectedFindingIps.add(finding.clientIp);
    }
  }

  selectVisible.textContent = allVisibleSelected ? 'Select visible' : 'Clear visible selection';
  renderFindings();
}

function scheduleFindingsRefresh() {
  if (findingsRefreshHandle) return;
  findingsRefreshHandle = window.setTimeout(async () => {
    findingsRefreshHandle = 0;
    try {
      await refreshFindings();
      if (state.selectedSiteName) {
        await refreshDeniedIps();
        render();
      }
    } catch (error) {
      streamHint.textContent = `Unable to refresh findings after a recent event: ${error.message}`;
    }
  }, 500);
}

async function openFinding(clientIp) {
  const requestId = ++state.detailRequestId;
  state.selectedFindingIp = clientIp;
  state.findingEvents = [];
  denyTargetStatus.textContent = '';
  setView('details');
  render();

  let findingEvents;
  try {
    const url = `/api/findings/${escapeSegment(clientIp)}/events?limit=250${selectedDomainQuery()}`;
    findingEvents = await fetchJson(url);
  } catch (error) {
    if (requestId === state.detailRequestId) {
      detailSummary.textContent = `Unable to load events for ${clientIp}: ${error.message}`;
    }
    return;
  }

  if (requestId !== state.detailRequestId) return;
  state.findingEvents = findingEvents;
  chooseSiteForSelectedFinding();
  if (state.selectedSiteName) {
    try {
      await refreshDeniedIps();
    } catch (error) {
      iisStatus.textContent = `Unable to load deny-list entries: ${error.message}`;
    }
  }

  if (requestId === state.detailRequestId) render();
}

function addEvent(webEvent) {
  if (!state.events.some(existing => existing.id === webEvent.id)) {
    state.events.push(webEvent);
    if (state.events.length > maxEventsInMemory) {
      state.events.splice(0, state.events.length - maxEventsInMemory);
    }
    scheduleFindingsRefresh();
  }
  queueRender();
}

function queueRender() {
  if (state.renderFrame) return;
  state.renderFrame = window.requestAnimationFrame(() => {
    state.renderFrame = 0;
    ensureDomainButtons();
    applyTableUi('events');
    renderEvents();
    renderCharts();
    renderAccessStatus();
  });
}

function initializeViewTabs() {
  viewButtons.forEach(button => {
    button.onclick = () => {
      setView(button.dataset.view);
      if (button.dataset.view === 'configuration' && !configurationLoaded) {
        loadBackendConfiguration();
      }
    };
  });
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const dark = theme === 'dark';
  themeToggle.textContent = dark ? 'Use light theme' : 'Use dark theme';
  themeToggle.setAttribute('aria-pressed', String(dark));
}

function mergeEvents(events) {
  const byId = new Map(state.events.map(webEvent => [webEvent.id, webEvent]));
  const previousCount = byId.size;
  for (const webEvent of events) {
    byId.set(webEvent.id, webEvent);
  }

  state.events = [...byId.values()]
    .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp))
    .slice(-maxEventsInMemory);
  if (byId.size > previousCount) {
    scheduleFindingsRefresh();
  }
  render();
}

async function refreshEvents() {
  const events = await fetchJson(`/api/events?limit=${initialEventLimit}`);
  mergeEvents(events);
}

function connectEventStream() {
  if (state.livePaused || state.eventSource) return;
  const source = new EventSource('/api/events/stream');
  state.eventSource = source;

  source.onopen = () => {
    if (state.eventSource !== source || state.livePaused) return;
    state.reconnectAttempts = 0;
    setConnectionStatus('Live', 'live');
    streamHint.textContent = 'Connected. Stream recovery loads recent events after reconnects.';
    refreshEvents().catch(error => {
      streamHint.textContent = `Live stream is connected, but event recovery failed: ${error.message}`;
    });
  };

  source.addEventListener('etw', event => {
    if (state.eventSource !== source || state.livePaused) return;
    try {
      addEvent(JSON.parse(event.data));
    } catch (error) {
      streamHint.textContent = `An event could not be read: ${error.message}`;
    }
  });

  source.onerror = () => {
    if (state.eventSource !== source || state.livePaused) return;
    setConnectionStatus('Reconnecting', 'reconnecting');
    streamHint.textContent = 'The browser will retry the event stream automatically.';
    if (source.readyState === EventSource.CLOSED && !state.reconnectTimer) {
      const delay = Math.min(30000, 1000 * (2 ** Math.min(state.reconnectAttempts, 5)));
      state.reconnectAttempts++;
      state.reconnectTimer = window.setTimeout(() => {
        state.reconnectTimer = 0;
        state.eventSource = null;
        connectEventStream();
      }, delay);
    }
  };
}

function setLivePaused(paused) {
  state.livePaused = paused;
  pauseEvents.textContent = paused ? 'Resume live updates' : 'Pause live updates';
  pauseEvents.setAttribute('aria-pressed', String(paused));

  if (paused) {
    if (state.reconnectTimer) {
      window.clearTimeout(state.reconnectTimer);
      state.reconnectTimer = 0;
    }
    state.eventSource?.close();
    state.eventSource = null;
    setConnectionStatus('Paused', 'paused');
    streamHint.textContent = 'Live updates are paused. Resume to load recent events and reconnect.';
    return;
  }

  setConnectionStatus('Catching up', 'reconnecting');
  streamHint.textContent = 'Reconnecting; recent events will be loaded when the stream opens.';
  connectEventStream();
}

function initializeControls() {
  initializeViewTabs();
  initializeTableControls();
  configurationReload.onclick = () => loadBackendConfiguration();
  configurationSave.onclick = () => saveBackendConfiguration();
  setView('events');
  applyTheme(document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');

  themeToggle.onclick = () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  searchInput.oninput = () => {
    state.searchQuery = searchInput.value;
    render();
  };
  allEvents.onchange = render;
  pauseEvents.onclick = () => setLivePaused(!state.livePaused);
  selectVisible.onclick = selectVisibleFindings;
  bulkDenySelected.onclick = () => {
    denySelectedFindings().catch(error => {
      bulkDenyStatus.textContent = `Bulk deny failed: ${error.message}`;
    });
  };
  banCountSave.onclick = () => {
    saveBanCount().catch(error => {
      banCountStatus.textContent = `Save failed: ${error.message}`;
    });
  };
  denyTargetSites.onclick = () => {
    denyFindingOnMatchedSites().catch(error => {
      denyTargetStatus.textContent = `Unable to add deny-list entry: ${error.message}`;
    });
  };
  iisSiteSelect.onchange = () => {
    state.sitesRequestId++;
    state.selectedSiteName = iisSiteSelect.value;
    state.deniedIps = [];
    refreshDeniedIps().then(render).catch(error => {
      iisStatus.textContent = `Unable to load deny-list entries: ${error.message}`;
    });
  };
  iisRefresh.onclick = () => {
    refreshSites().then(() => {
      iisStatus.textContent = 'IIS site data refreshed.';
    }).catch(error => {
      iisStatus.textContent = `Unable to load IIS site data: ${error.message}`;
    });
  };
  iisDenySelected.onclick = () => {
    denySelectedFindingIp().catch(error => {
      iisStatus.textContent = `Unable to add deny-list entry: ${error.message}`;
    });
  };
  document.querySelector('[data-domain="*"]').onclick = () => {
    selectDomain('*').catch(error => {
      streamHint.textContent = `Unable to change domain filter: ${error.message}`;
    });
  };
}

async function initializeDashboard() {
  initializeControls();
  render();

  try {
    await refreshEvents();
    await refreshFindings();
  } catch (error) {
    setConnectionStatus('API unavailable', 'error');
    streamHint.textContent = `Unable to load dashboard data: ${error.message}`;
  }

  try {
    await refreshSites();
  } catch (error) {
    iisStatus.textContent = `Unable to load IIS site data: ${error.message}`;
  }

  connectEventStream();
}

initializeDashboard();
