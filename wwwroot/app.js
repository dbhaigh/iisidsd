const defaultColumnWidths = [170, 140, 100, 110, 110, 110, 220, 220, 280];
const dashboardModel = window.IisidsdDashboardModel;

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
  incidents: {},
  notifications: [],
  notificationQueueStatus: null,
  incidentAccessStatus: 'loading',
  incidentAccessError: '',
  searchQuery: '',
  incidentStatusFilter: 'all',
  eventStatusFilter: 'all',
  eventTimeFilter: 'all',
  lastEventAt: 0,
  eventRows: new Map(),
  serviceReadiness: 'checking',
  etwState: 'unknown',
  databaseHealth: 'checking',
  ingestionHealth: 'checking',
  droppedEventCount: null,
  processingFailureCount: null,
  metricsAccess: 'unknown',
  metricsRefreshRunning: false,
  livePaused: false,
  bulkDenyRunning: false,
  eventSource: null,
  eventCursor: 0,
  recoveryWarning: '',
  reconnectTimer: 0,
  reconnectAttempts: 0,
  detailRequestId: 0,
  renderFrame: 0,
  accessStatusSignature: '',
  dismissedAccessWarnings: new Set(),
  sortState: {
    events: { key: 'timestamp', direction: 'desc' },
    findings: { key: 'risk', direction: 'desc' },
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
const eventStatusFilter = document.querySelector('#event-status-filter');
const eventTimeFilter = document.querySelector('#event-time-filter');
const incidentStatusFilter = document.querySelector('#incident-status-filter');
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
const bulkDenyDialog = document.querySelector('#bulk-deny-dialog');
const bulkDenyPreview = document.querySelector('#bulk-deny-preview');
const bulkDenyMode = document.querySelector('#bulk-deny-mode');
const bulkDenyConfirm = document.querySelector('#bulk-deny-confirm');
const selectVisible = document.querySelector('#select-visible');
const selectionCount = document.querySelector('#selection-count');
const riskChart = document.querySelector('#risk-chart');
const ipChart = document.querySelector('#ip-chart');
const chartFootnote = document.querySelector('#chart-footnote');
const findingRiskIndicators = document.querySelector('#finding-risk-indicators');
const findingReasons = document.querySelector('#finding-reasons');
const findingObservedFacts = document.querySelector('#finding-observed-facts');
const incidentState = document.querySelector('#incident-state');
const analystNote = document.querySelector('#analyst-note');
const incidentStateSave = document.querySelector('#incident-state-save');
const incidentStateStatus = document.querySelector('#incident-state-status');
const notificationQueueBody = document.querySelector('#notification-queue');
const notificationQueueStatus = document.querySelector('#notification-queue-status');
const notificationsRefresh = document.querySelector('#notifications-refresh');
const relatedFindingsList = document.querySelector('#related-findings-list');
const databaseHealth = document.querySelector('#database-health');
const serviceHealth = document.querySelector('#service-health');
const ingestionHealth = document.querySelector('#ingestion-health');
const dataFreshness = document.querySelector('#data-freshness');
let healthRefreshRunning = false;
let healthRefreshHandle = 0;
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
let chartRefreshHandle = 0;
const maxEventsInMemory = 2000;
const initialEventLimit = 1000;
const dayInMilliseconds = 24 * 60 * 60 * 1000;
let configurationLoaded = false;
let configurationRevision = null;

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

function renderHealthIndicators() {
  serviceHealth.dataset.state = state.serviceReadiness === 'ready'
    ? 'ok'
    : state.serviceReadiness === 'not-ready' ? 'warning' : 'checking';
  serviceHealth.textContent = state.serviceReadiness === 'ready'
    ? 'Service: ready'
    : state.serviceReadiness === 'not-ready'
      ? `Service: not ready · ETW ${state.etwState}`
      : 'Service readiness: checking';

  databaseHealth.dataset.state = state.databaseHealth;
  databaseHealth.textContent = state.databaseHealth === 'ok'
    ? 'Database: healthy'
    : state.databaseHealth === 'degraded'
      ? 'Database: degraded'
      : 'Database: checking';

  ingestionHealth.dataset.state = state.metricsAccess === 'ready'
    ? (state.droppedEventCount > 0 || state.processingFailureCount > 0 ? 'warning' : 'ok')
    : state.metricsAccess === 'forbidden' ? 'restricted' : state.metricsAccess === 'error' ? 'degraded' : 'checking';
  ingestionHealth.textContent = state.metricsAccess === 'ready'
    ? `Ingestion: ${state.droppedEventCount} dropped · ${state.processingFailureCount} processing failures · queue ${state.queueDepth ?? 0}/${state.queueHighWaterMark ?? 0} high-water`
    : state.metricsAccess === 'forbidden'
      ? 'Ingestion loss counters: administrator access required'
      : state.metricsAccess === 'error'
        ? 'Ingestion counters: unavailable'
        : 'Ingestion: checking';

  if (!state.lastEventAt) {
    dataFreshness.dataset.state = 'unknown';
    dataFreshness.textContent = 'Event data: none received';
    return;
  }

  const ageMilliseconds = Math.max(0, Date.now() - state.lastEventAt);
  const stale = ageMilliseconds > 5 * 60 * 1000;
  dataFreshness.dataset.state = stale ? 'warning' : 'ok';
  dataFreshness.textContent = `Latest event: ${stale ? 'stale · ' : ''}${Math.floor(ageMilliseconds / 1000)}s ago`;
}

function parsePrometheusMetric(metricsText, metricName) {
  const line = metricsText.split(/\r?\n/).find(candidate => candidate.startsWith(`${metricName} `));
  const value = line ? Number(line.slice(metricName.length).trim()) : NaN;
  return Number.isFinite(value) ? value : 0;
}

async function refreshDashboardHealth() {
  if (healthRefreshRunning) return;
  healthRefreshRunning = true;
  const healthRequest = fetch('/health').then(async response => {
    const result = await response.json();
    state.serviceReadiness = result.readiness ?? 'unknown';
    state.etwState = result.checks?.etw?.state ?? 'unknown';
    state.databaseHealth = result.checks?.sqlite?.status === 'ok' ? 'ok' : 'degraded';
  }).catch(() => {
    state.serviceReadiness = 'unknown';
    state.databaseHealth = 'degraded';
  });
  const metricsRequest = fetch('/metrics').then(async response => {
    if (!response.ok) {
      const error = new Error(`HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    const metricsText = await response.text();
    state.droppedEventCount = parsePrometheusMetric(metricsText, 'etw_events_dropped');
    state.processingFailureCount = parsePrometheusMetric(metricsText, 'event_processing_failures');
    state.queueDepth = parsePrometheusMetric(metricsText, 'queue_depth');
    state.queueHighWaterMark = parsePrometheusMetric(metricsText, 'queue_high_water_mark');
    state.metricsAccess = 'ready';
    const lastEventSeconds = parsePrometheusMetric(metricsText, 'last_event_timestamp_seconds');
    if (lastEventSeconds > 0) state.lastEventAt = Math.max(state.lastEventAt, lastEventSeconds * 1000);
  }).catch(error => {
    state.metricsAccess = error.status === 401 || error.status === 403 ? 'forbidden' : 'error';
  });
  await Promise.all([healthRequest, metricsRequest]);
  healthRefreshRunning = false;
  renderHealthIndicators();
  if (!healthRefreshHandle) {
    healthRefreshHandle = window.setInterval(refreshDashboardHealth, 60_000);
  }
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
        path: (item.riskIndicators || []).join('; '),
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
  viewButtons.forEach(button => {
    const isSelected = button.dataset.view === view;
    button.classList.toggle('active', isSelected);
    button.setAttribute('aria-selected', String(isSelected));
    button.tabIndex = isSelected ? 0 : -1;
  });
  document.querySelectorAll('.view').forEach(panel => {
    const isSelected = panel.id === `${view}-view`;
    panel.classList.toggle('active', isSelected);
    panel.hidden = !isSelected;
  });
  if (view === 'notifications') refreshNotifications();
}

function visibleEvent(webEvent) {
  return (allEvents.checked || webEvent.isSuspicious) && dashboardModel.filterEvents([webEvent], {
    query: state.searchQuery,
    status: state.eventStatusFilter,
    range: state.eventTimeFilter,
    domain: state.selectedDomain
  }).length > 0;
}

function visibleFinding(finding) {
  return dashboardModel.filterFindings([finding], {
    query: state.searchQuery,
    domain: state.selectedDomain,
    incidentStatus: state.incidentStatusFilter,
    incidents: state.incidents
  }).length > 0;
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

function createEventRow(webEvent) {
  const row = document.createElement('tr');
  row.dataset.eventId = webEvent.id;
  if (webEvent.isSuspicious) row.className = 'suspicious';

  const findingBanCount = state.findings.find(item => item.clientIp === webEvent.clientIp)?.banCount ?? 0;
  appendCells(row, [formatTimestamp(webEvent.timestamp), webEvent.clientIp, 1, webEvent.isSuspicious ? 'Yes' : 'No']);
  appendCell(row, createRiskBadge(webEvent.riskScore, webEvent.riskSeverity));
  appendCells(row, [findingBanCount, webEvent.domain, webEvent.path, String(webEvent.detectionReason || '')]);
  return row;
}

function renderEvents() {
  const visibleEvents = sortItems('events', state.events.filter(visibleEvent)).slice(0, 500);
  const visibleIds = new Set(visibleEvents.map(webEvent => webEvent.id));
  const recentIds = new Set(state.events.map(webEvent => webEvent.id));
  for (const [eventId, row] of state.eventRows) {
    if (!recentIds.has(eventId)) state.eventRows.delete(eventId);
    if (!visibleIds.has(eventId)) row.remove();
  }

  if (!visibleEvents.length) {
    if (!eventBody.querySelector('.empty')) {
      eventBody.replaceChildren(createEmptyRow(allEvents.checked ? 'No matching events in the selected window.' : 'No suspicious events in the selected window.'));
    }
    return;
  }

  eventBody.querySelector('.empty')?.remove();
  visibleEvents.forEach((webEvent, index) => {
    let row = state.eventRows.get(webEvent.id);
    if (!row) {
      row = createEventRow(webEvent);
      state.eventRows.set(webEvent.id, row);
    }

    if (eventBody.children[index] !== row) {
      eventBody.insertBefore(row, eventBody.children[index] || null);
    }
  });
  while (eventBody.children.length > visibleEvents.length) {
    eventBody.lastElementChild.remove();
  }
}

function renderFindings() {
  findingBody.replaceChildren();
  const filteredFindings = state.findings.filter(visibleFinding);
  const visibleFindings = state.sortState.findings.key === 'risk' && state.sortState.findings.direction === 'desc'
    ? dashboardModel.prioritizeFindings(filteredFindings)
    : sortItems('findings', filteredFindings);
  const allVisibleSelected = visibleFindings.length > 0 &&
    visibleFindings.every(finding => state.selectedFindingIps.has(finding.clientIp));
  selectVisible.textContent = allVisibleSelected ? 'Clear visible selection' : 'Select visible';
  selectionCount.textContent = `${state.selectedFindingIps.size} selected`;
  selectVisible.disabled = visibleFindings.length === 0 || state.bulkDenyRunning;
  bulkDenySelected.disabled = state.selectedFindingIps.size === 0 ||
    !state.iisStatusInfo?.enableDenyListChanges || state.bulkDenyRunning;
  const enforcementMode = state.iisStatusInfo?.enforcementMode;
  bulkDenySelected.textContent = enforcementMode === 'Enforce' ? 'Review and deny selected'
    : enforcementMode === 'Simulate' ? 'Review simulation'
      : enforcementMode === 'Observe' ? 'Review observed action'
        : 'Review selected action';
  if (!visibleFindings.length) {
    findingBody.append(createEmptyRow('No suspicious IP findings available.'));
    return;
  }

  for (const finding of visibleFindings) {
    const row = document.createElement('tr');
    row.className = state.selectedFindingIp === finding.clientIp ? 'selected' : '';

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
    const openButton = document.createElement('button');
    openButton.type = 'button';
    openButton.className = 'finding-open';
    openButton.setAttribute('aria-label', `Investigate source ${finding.clientIp}`);
    openButton.append(text(finding.clientIp));
    openButton.onclick = () => openFinding(finding.clientIp);
    const analystStatus = dashboardModel.normalizeIncidentRecord(state.incidents[finding.clientIp]).status;
    const statusBadge = document.createElement('span');
    statusBadge.className = `incident-badge ${analystStatus}`;
    statusBadge.append(text(analystStatus));
    clientCell.append(selector, openButton, statusBadge);
    appendCells(row, [finding.requestCount, finding.suspiciousRequestCount]);
    appendCell(row, createRiskBadge(finding.highestRiskScore, finding.highestRiskSeverity));
    appendCells(row, [
      finding.banCount ?? 0,
      (finding.domains || []).join(', '),
      (finding.riskIndicators || []).join('; '),
      (finding.detectionReasons || []).join('; ')
    ]);

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

function renderFindingFacts(finding) {
  findingObservedFacts.replaceChildren();
  const statusCodes = [...new Set(state.findingEvents.map(webEvent => webEvent.statusCode).filter(Number.isFinite))].sort((left, right) => left - right);
  const facts = [
    ['Source address', finding.clientIp],
    ['Requests retained', finding.requestCount],
    ['Suspicious requests', finding.suspiciousRequestCount],
    ['Observed domains', (finding.domains || []).join(', ') || 'Not recorded'],
    ['HTTP responses', statusCodes.join(', ') || 'Not loaded'],
    ['Activity window', `${formatTimestamp(finding.firstSeen)} to ${formatTimestamp(finding.lastSeen)}`]
  ];
  for (const [label, value] of facts) {
    const item = document.createElement('div');
    item.className = 'fact-item';
    const term = document.createElement('span');
    term.className = 'fact-label';
    term.append(text(label));
    const detail = document.createElement('strong');
    detail.append(text(value));
    item.append(term, detail);
    findingObservedFacts.append(item);
  }
}

function renderAnalystState(finding) {
  const incident = dashboardModel.normalizeIncidentRecord(state.incidents[finding.clientIp]);
  const canEdit = state.incidentAccessStatus === 'ready';
  if (document.activeElement !== incidentState) incidentState.value = incident.status;
  if (document.activeElement !== analystNote) analystNote.value = incident.note;
  incidentState.disabled = !canEdit;
  analystNote.disabled = !canEdit;
  incidentStateSave.disabled = !canEdit;
  if (state.incidentAccessStatus === 'loading') {
    incidentStateStatus.textContent = 'Loading shared analyst state...';
  } else if (state.incidentAccessStatus !== 'ready') {
    incidentStateStatus.textContent = state.incidentAccessError || 'Shared analyst state is unavailable.';
  } else if (incident.updatedBy) {
    incidentStateStatus.textContent = `Last updated by ${incident.updatedBy}${incident.updatedAtUtc ? ` at ${formatTimestamp(incident.updatedAtUtc)}` : ''}.`;
  }
}

function renderRelatedFindings(finding) {
  relatedFindingsList.replaceChildren();
  const domainsForFinding = new Set(finding.domains || []);
  const related = dashboardModel.prioritizeFindings(state.findings
    .filter(candidate => candidate.clientIp !== finding.clientIp && (candidate.domains || []).some(domain => domainsForFinding.has(domain)))
    .slice(0, 8));
  if (!related.length) {
    relatedFindingsList.append(text('No other findings share the affected sites in the loaded queue.'));
    return;
  }

  for (const candidate of related) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'related-finding-link';
    button.append(
      text(`${candidate.clientIp} · ${candidate.highestRiskSeverity} ${candidate.highestRiskScore} · ${(candidate.domains || []).join(', ')}`)
    );
    button.onclick = () => openFinding(candidate.clientIp);
    relatedFindingsList.append(button);
  }
}

async function refreshIncidents() {
  try {
    const records = await fetchJson('/api/incidents?limit=500');
    state.incidents = Object.fromEntries(records.map(record => [record.clientIp, record]));
    state.incidentAccessStatus = 'ready';
    state.incidentAccessError = '';
  } catch (error) {
    state.incidents = {};
    state.incidentAccessStatus = error.status === 401 || error.status === 403 ? 'forbidden' : 'error';
    state.incidentAccessError = error.status === 401
      ? 'Administrator sign-in is required to load shared analyst notes.'
      : error.status === 403
        ? 'Administrator access is required to load or edit shared analyst state.'
        : `Unable to load shared analyst state: ${error.message}`;
  }
  renderFindings();
  if (state.selectedFindingIp) renderDetails();
}

async function refreshNotifications() {
  notificationQueueStatus.textContent = 'Loading notification queue...';
  notificationsRefresh.disabled = true;
  try {
    const [notifications, status] = await Promise.all([
      fetchJson('/api/notifications?limit=250'),
      fetchJson('/api/notifications/status')
    ]);
    state.notifications = notifications;
    state.notificationQueueStatus = status;
    notificationQueueStatus.textContent =
      `Pending ${status.pending} · Retrying ${status.retrying} · Delivered ${status.delivered} · ` +
      `Failed ${status.failed} · Acknowledged ${status.acknowledged} · Dropped ${status.dropped}`;
    renderNotifications();
  } catch (error) {
    state.notifications = [];
    state.notificationQueueStatus = null;
    notificationQueueStatus.textContent = error.status === 401 || error.status === 403
      ? 'Administrator access is required to inspect or acknowledge notifications.'
      : `Unable to load notification queue: ${error.message}`;
    notificationQueueBody.replaceChildren(createEmptyRow('Notification queue is unavailable.', 8));
  } finally {
    notificationsRefresh.disabled = false;
  }
}

function renderNotifications() {
  notificationQueueBody.replaceChildren();
  if (!state.notifications.length) {
    notificationQueueBody.append(createEmptyRow('No notification incidents recorded.', 8));
    return;
  }

  for (const incident of state.notifications) {
    const row = document.createElement('tr');
    appendCells(row, [
      `${incident.riskSeverity} (${incident.riskScore})`,
      incident.status,
      incident.clientIp,
      incident.targetSite,
      `${incident.summary} ${(incident.evidence || []).map(item => item.explanation).join('; ')}`,
      incident.attemptCount,
      formatTimestamp(incident.lastSeenUtc)
    ]);
    const actionCell = document.createElement('td');
    if (incident.status !== 'acknowledged') {
      const acknowledgeButton = document.createElement('button');
      acknowledgeButton.className = 'button button-secondary';
      acknowledgeButton.type = 'button';
      acknowledgeButton.append(text('Acknowledge'));
      acknowledgeButton.onclick = async () => {
        acknowledgeButton.disabled = true;
        try {
          await fetchJson(`/api/notifications/${escapeSegment(incident.id)}/acknowledge`, { method: 'POST' });
          await refreshNotifications();
        } catch (error) {
          notificationQueueStatus.textContent = `Unable to acknowledge notification: ${error.message}`;
          acknowledgeButton.disabled = false;
        }
      };
      actionCell.append(acknowledgeButton);
    }
    row.append(actionCell);
    notificationQueueBody.append(row);
  }
}

async function saveIncidentAnalysis() {
  const finding = selectedFinding();
  if (!finding) {
    incidentStateStatus.textContent = 'Select a finding before saving analyst state.';
    return;
  }

  try {
    const updated = await fetchJson(`/api/incidents/${escapeSegment(finding.clientIp)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: incidentState.value, note: analystNote.value })
    });
    state.incidents = { ...state.incidents, [finding.clientIp]: updated };
    incidentStateStatus.textContent = `Saved shared ${updated.status} state.`;
    renderFindings();
    renderDetails();
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      state.incidentAccessStatus = 'forbidden';
      state.incidentAccessError = 'Administrator access is required to save shared analyst state.';
      incidentStateSave.disabled = true;
    }
    incidentStateStatus.textContent = `Unable to save analyst state: ${error.message}`;
  }
}

function renderFindingIndicators(finding) {
  const indicators = new Set(finding.riskIndicators || []);
  const moduleEvidence = new Map();
  for (const webEvent of state.findingEvents) {
    for (const indicator of webEvent.riskIndicators || []) indicators.add(indicator);
    for (const evidence of webEvent.detectionEvidence || []) {
      const key = `${evidence.detectorId}|${evidence.signalKey || evidence.indicator}|${evidence.explanation}`;
      moduleEvidence.set(key, evidence);
    }
  }

  for (const [container, values] of [
    [findingRiskIndicators, [...indicators]],
    [findingReasons, finding.detectionReasons || []]
  ]) {
    container.replaceChildren();
    const hasModuleEvidence = container === findingRiskIndicators && moduleEvidence.size > 0;
    if (!values.length && !hasModuleEvidence) {
      const empty = document.createElement('span');
      empty.className = 'muted';
      empty.append(text('No indicators recorded.'));
      container.append(empty);
      continue;
    }

    for (const value of values) {
      if (container === findingReasons) {
        const chip = document.createElement('span');
        chip.className = 'indicator-chip';
        chip.append(text(value));
        container.append(chip);
        continue;
      }

      const explanation = dashboardModel.getRiskExplanation(value);
      const card = document.createElement('div');
      card.className = 'indicator-explanation';
      const title = document.createElement('strong');
      title.append(text(value));
      const description = document.createElement('span');
      description.append(text(explanation.description));
      const weight = document.createElement('span');
      weight.className = 'indicator-weight';
      weight.append(text(explanation.defaultWeight === null
        ? 'Configured contribution unavailable'
        : `Default contribution +${explanation.defaultWeight}; configured weight unavailable`));
      card.append(title, description, weight);
      container.append(card);
    }

    if (container === findingRiskIndicators) {
      for (const evidence of moduleEvidence.values()) {
        const card = document.createElement('div');
        card.className = 'indicator-explanation';
        const title = document.createElement('strong');
        title.append(text(`${evidence.detectorId} · ${evidence.signalKey || evidence.indicator}`));
        const description = document.createElement('span');
        description.append(text(evidence.explanation || evidence.indicator));
        const weight = document.createElement('span');
        weight.className = 'indicator-weight';
        weight.append(text(evidence.observeOnly
          ? 'Observe only; does not affect the risk score'
          : evidence.contributed
            ? `Contributed ${evidence.scoreContribution} points`
            : 'Evidence recorded; not selected for scoring'));
        card.append(title, description, weight);
        container.append(card);
      }
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
    findingObservedFacts.replaceChildren(text('No finding selected.'));
    relatedFindingsList.replaceChildren(text('No finding selected.'));
    incidentStateStatus.textContent = '';
    return;
  }

  detailSummary.replaceChildren();
  const strong = document.createElement('strong');
  strong.append(text(finding.clientIp));
  detailSummary.append(
    strong,
    text(` · ${finding.requestCount} requests · ${finding.suspiciousRequestCount} detector-flagged · highest heuristic score ${finding.highestRiskScore} (${finding.highestRiskSeverity}) · first ${formatTimestamp(finding.firstSeen)} · last ${formatTimestamp(finding.lastSeen)}`)
  );
  renderFindingFacts(finding);
  renderFindingIndicators(finding);
  renderAnalystState(finding);
  renderRelatedFindings(finding);
  if (document.activeElement !== banCountValue) {
    banCountValue.value = String(finding.banCount ?? 0);
  }

  const visibleEvents = sortItems('details', dashboardModel.filterEvents(state.findingEvents, {
    query: state.searchQuery,
    status: state.eventStatusFilter,
    range: state.eventTimeFilter,
    domain: state.selectedDomain
  }));
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
      `Enforcement: ${settings.enforcementMode} · ` +
      `Deny-list writes: ${settings.canEnforce ? 'enabled' : 'disabled'} · ` +
      `Legacy dry run: ${settings.dryRun ? 'ON' : 'OFF'} · ` +
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
      ? `${state.iisStatusInfo.enableDenyListChanges}:${state.iisStatusInfo.dryRun}:${state.iisStatusInfo.enforcementMode}`
      : `error:${state.iisStatusErrorStatus}`
  ].join('|');
  if (signature === state.accessStatusSignature) return;
  state.accessStatusSignature = signature;
  accessNotices.replaceChildren();
  if (localHost) {
    appendAccessNotice(
      'warning',
      'Remote access',
      'Local dashboard viewing is available, but management APIs still require an authenticated Windows Administrator. Loopback and service elevation do not grant administrator access.'
    );
  } else {
    appendAccessNotice(
      'warning',
      'Remote access',
      'Remote dashboard requests require HTTPS and Windows Authentication. Management APIs require a Windows Administrator.'
    );
  }

  if (state.iisStatusInfo) {
    appendAccessNotice(
      'good',
      'Administrator access verified',
      'Administrator-only IIS settings are available for this session.'
    );
    if (state.iisStatusInfo.enforcementMode === 'Simulate') {
      appendAccessNotice(
        'warning',
        'Simulation mode',
        'Deny-list actions are recorded as simulated and will not change IIS or ban counts.'
      );
    }

    if (state.iisStatusInfo.enforcementMode === 'Observe') {
      appendAccessNotice('warning', 'Observe mode', 'Deny-list requests are audited but do not change IIS.');
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
  const response = await fetch(url, { ...options, credentials: 'same-origin' });
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
    configurationRevision = response.revision;
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
  if (!configurationRevision) {
    configurationStatus.textContent = 'Reload the saved configuration before making changes.';
    configurationSave.disabled = false;
    return;
  }

  configurationStatus.textContent = 'Validating and saving settings...';
  try {
    const response = await fetchJson('/api/configuration', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings, expectedRevision: configurationRevision })
    });
    configurationEditor.value = JSON.stringify(response.settings, null, 2);
    configurationRevision = response.revision;
    configurationLoaded = true;
    configurationStatus.textContent = 'Settings saved to appsettings.json. Restart the iisidsd service to apply them.';
  } catch (error) {
    configurationStatus.textContent = error.status === 401 || error.status === 403
      ? 'Backend configuration changes are restricted to authorized administrators.'
      : error.status === 409
        ? 'Configuration changed since it was loaded. Reload before saving to avoid overwriting another administrator’s changes.'
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
  const didNotEnforce = updated.simulated || updated.observed;
  denyTargetStatus.textContent = updated.simulated
    ? `Simulated: would deny ${finding.clientIp} on sites matching ${updated.domains?.join(', ') || 'the finding domains'}.`
    : updated.observed
      ? `Observed a deny request for ${finding.clientIp}; IIS was not changed.`
      : `Added to ${updated.sites?.length ?? 0} site(s).`;
  await refreshIisStatus();
  if (!didNotEnforce && state.selectedSiteName) {
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
  if (state.iisStatusErrorStatus === 401 || state.iisStatusErrorStatus === 403) {
    state.sites = [];
    state.deniedIps = [];
    state.selectedSiteName = '';
    render();
    return;
  }

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

async function confirmDenyPreview(siteName, clientIp, reason) {
  const finding = state.findings.find(item => item.clientIp === clientIp);
  const response = await fetch('/api/iis/deny-list/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      siteName,
      clientIp,
      reason,
      evidence: finding?.riskIndicators || []
    })
  });
  if (!response.ok) {
    throw new Error(`Preview failed (HTTP ${response.status}).`);
  }

  const preview = await response.json();
  if (preview.allowListed) {
    iisStatus.textContent = 'This address matches the configured allow-list and cannot be denied.';
    return false;
  }

  const expires = preview.expiresAt ? new Date(preview.expiresAt).toLocaleString() : 'permanent';
  const sharedSites = preview.otherSitesSharingPools.length
    ? `Shared application pools affect: ${preview.otherSitesSharingPools.join(', ')}`
    : 'No other sites share the target application pools.';
  const evidence = preview.evidence.length ? preview.evidence.join('\n') : 'No risk evidence supplied.';
  const warnings = preview.warnings.length ? `\n\nWarnings:\n${preview.warnings.join('\n')}` : '';
  return window.confirm(
    `${preview.enforcementMode} ${preview.rule} on ${preview.siteName}\nExpiry: ${expires}\nRule state: ${preview.existingRuleState}\nEvidence:\n${evidence}\n${sharedSites}${warnings}\n\nContinue?`
  );
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
  if (!await confirmDenyPreview(siteName, clientIp, 'Manual dashboard deny-list action')) return;
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
  const didNotEnforce = updated.simulated || updated.observed;
  if (!didNotEnforce && state.selectedSiteName === siteName) {
    await refreshDeniedIps();
  }
  iisStatus.textContent = updated.simulated
    ? `Simulated: would deny ${clientIp} on ${siteName}.`
    : updated.observed
      ? `Observed a deny request for ${clientIp} on ${siteName}; IIS was not changed.`
      : updated.alreadyPresent
        ? `The deny rule for ${clientIp} on ${siteName} is already present.`
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
  if (!window.confirm(`Remove the service-owned deny rule for ${clientIp} from ${siteName}? Unmanaged administrator rules are preserved.`)) {
    return;
  }
  iisStatus.textContent = 'Removing deny-list entry...';
  const response = await fetch(`/api/iis/sites/${escapeSegment(siteName)}/deny-list/${escapeSegment(clientIp)}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'Manual dashboard removal' })
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
  const didNotEnforce = updated.simulated || updated.observed;
  if (!didNotEnforce && state.selectedSiteName === siteName) {
    await refreshDeniedIps();
  }
  iisStatus.textContent = updated.simulated
    ? `Simulated: would remove ${clientIp} from ${siteName}.`
    : updated.observed
      ? `Observed a removal request for ${clientIp} from ${siteName}; IIS was not changed.`
      : `Deny-list entry removed for ${clientIp} from ${siteName}.`;
  await refreshIisStatus();
  render();
}

function openBulkDenyPreview() {
  const clientIps = [...state.selectedFindingIps];
  if (!clientIps.length) {
    bulkDenyStatus.textContent = 'Select one or more findings first.';
    return;
  }
  if (!state.iisStatusInfo?.enableDenyListChanges) {
    bulkDenyStatus.textContent = 'Deny-list changes are disabled or administrator access is unavailable.';
    return;
  }

  const mode = state.iisStatusInfo.enforcementMode;
  const modeDescription = mode === 'Enforce'
    ? 'ENFORCE: IIS deny rules may be written for these sources.'
    : mode === 'Simulate'
      ? 'SIMULATE: intended actions are recorded; IIS will not be changed.'
      : 'OBSERVE: requests are audited; IIS will not be changed.';
  bulkDenyMode.textContent = `${modeDescription} ${clientIps.length} source address(es) selected.`;
  bulkDenyMode.dataset.mode = String(mode || 'Unavailable').toLowerCase();
  bulkDenyPreview.replaceChildren();
  for (const item of dashboardModel.createBulkPreview(state.findings, state.incidents, clientIps)) {
    const row = document.createElement('li');
    const source = document.createElement('strong');
    source.append(text(`${item.clientIp} · ${item.severity} heuristic score ${item.score}`));
    const scope = document.createElement('span');
    scope.append(text(`Observed domains: ${item.domains.join(', ') || 'not recorded'}`));
    const evidence = document.createElement('span');
    evidence.append(text(`Detector evidence: ${item.evidence.join('; ') || 'none recorded'}`));
    const analyst = document.createElement('span');
    analyst.append(text(`Analyst state: ${item.analystStatus}`));
    row.append(source, scope, evidence, analyst);
    bulkDenyPreview.append(row);
  }

  bulkDenyConfirm.textContent = mode === 'Enforce' ? 'Confirm enforced action'
    : mode === 'Simulate' ? 'Confirm simulation'
      : 'Confirm observed action';
  bulkDenyDialog.showModal();
}

async function executeBulkDeny() {
  const clientIps = [...state.selectedFindingIps];
  const reviewedMode = bulkDenyMode.dataset.mode;
  bulkDenyDialog.close();
  if (!clientIps.length) return;

  await refreshIisStatus();
  if (!state.iisStatusInfo?.enableDenyListChanges) {
    bulkDenyStatus.textContent = 'Deny-list changes are disabled or administrator access is unavailable.';
    return;
  }
  if (String(state.iisStatusInfo.enforcementMode || 'Unavailable').toLowerCase() !== reviewedMode) {
    bulkDenyStatus.textContent = 'Enforcement mode changed since the review. Confirm the updated mode before continuing.';
    openBulkDenyPreview();
    return;
  }

  let applied = 0;
  let simulated = 0;
  let observed = 0;
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
      if (result.simulated) {
        simulated++;
      } else if (result.observed) {
        observed++;
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
    observed ? `${observed} observed` : '',
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
    const timestamp = Date.parse(webEvent.timestamp);
    if (Number.isFinite(timestamp)) state.lastEventAt = Math.max(state.lastEventAt, timestamp);
    if (state.events.length > maxEventsInMemory) {
      state.events.splice(0, state.events.length - maxEventsInMemory);
    }
    scheduleFindingsRefresh();
  }
  renderHealthIndicators();
  queueRender();
}

function queueRender() {
  if (state.renderFrame) return;
  state.renderFrame = window.requestAnimationFrame(() => {
    state.renderFrame = 0;
    ensureDomainButtons();
    renderEvents();
    scheduleChartRefresh();
  });
}

function scheduleChartRefresh() {
  if (chartRefreshHandle) return;
  chartRefreshHandle = window.setTimeout(() => {
    chartRefreshHandle = 0;
    renderCharts();
  }, 5000);
}

function initializeViewTabs() {
  viewButtons.forEach(button => {
    button.onclick = () => {
      setView(button.dataset.view);
      if (button.dataset.view === 'configuration' && !configurationLoaded) {
        loadBackendConfiguration();
      }
    };
    button.onkeydown = event => {
      const currentIndex = viewButtons.indexOf(button);
      const nextIndex = event.key === 'ArrowRight' ? (currentIndex + 1) % viewButtons.length
        : event.key === 'ArrowLeft' ? (currentIndex - 1 + viewButtons.length) % viewButtons.length
          : event.key === 'Home' ? 0
            : event.key === 'End' ? viewButtons.length - 1
              : -1;
      if (nextIndex < 0) return;
      event.preventDefault();
      viewButtons[nextIndex].focus();
      viewButtons[nextIndex].click();
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
  state.eventRows.clear();
  eventBody.replaceChildren();
  const latestTimestamp = state.events.reduce((latest, webEvent) => Math.max(latest, Date.parse(webEvent.timestamp) || 0), 0);
  state.lastEventAt = Math.max(state.lastEventAt, latestTimestamp);
  if (byId.size > previousCount) {
    scheduleFindingsRefresh();
  }
  render();
  renderHealthIndicators();
}

async function refreshEvents(advanceCursor = true) {
  const page = await fetchJson(`/api/v2/events?limit=${initialEventLimit}`);
  mergeEvents(page.items.map(envelope => envelope.payload));
  const latestCursor = Number(page.lastCursor ?? page.latestCursor ?? 0);
  if (advanceCursor && Number.isSafeInteger(latestCursor) && latestCursor >= 0) {
    state.eventCursor = Math.max(state.eventCursor, latestCursor);
  }
  return page;
}

function updateEventCursor(value) {
  const cursor = Number(value);
  if (Number.isSafeInteger(cursor) && cursor >= 0) {
    state.eventCursor = Math.max(state.eventCursor, cursor);
  }
}

function connectEventStream() {
  if (state.livePaused || state.eventSource) return;
  const source = new EventSource(`/api/v2/events/stream?afterSequence=${encodeURIComponent(state.eventCursor)}`);
  state.eventSource = source;

  source.onopen = () => {
    if (state.eventSource !== source || state.livePaused) return;
    state.reconnectAttempts = 0;
    setConnectionStatus('Live', 'live');
    streamHint.textContent = state.recoveryWarning || 'Connected. Retained events replay from the last received cursor.';
    refreshFindings().catch(error => {
      streamHint.textContent = `Live stream is connected, but finding recovery failed: ${error.message}`;
    });
    refreshIncidents();
    refreshDashboardHealth();
  };

  source.addEventListener('iis.event.v1', event => {
    if (state.eventSource !== source || state.livePaused) return;
    try {
      const envelope = JSON.parse(event.data);
      updateEventCursor(envelope.cursor ?? event.lastEventId);
      addEvent(envelope.payload);
    } catch (error) {
      streamHint.textContent = `An event could not be read: ${error.message}`;
    }
  });

  source.addEventListener('checkpoint', event => updateEventCursor(event.lastEventId));

  source.addEventListener('recovery', event => {
    if (state.eventSource !== source || state.livePaused) return;
    try {
      const recovery = JSON.parse(event.data);
      updateEventCursor(event.lastEventId);
      state.recoveryWarning = recovery.reason === 'retention_gap'
        ? 'History gap: some events after this cursor expired from retention. Showing retained events and continuing live.'
        : 'Stream recovery: the subscriber fell behind. Replaying retained events from the last received cursor.';
      streamHint.textContent = state.recoveryWarning;
      if (recovery.reason === 'retention_gap') {
        refreshEvents(false).catch(error => {
          streamHint.textContent = `${state.recoveryWarning} Bounded refresh failed: ${error.message}`;
        });
      }
    } catch (error) {
      streamHint.textContent = `Stream recovery details could not be read: ${error.message}`;
    }
  });

  source.onerror = () => {
    if (state.eventSource !== source || state.livePaused) return;
    setConnectionStatus('Reconnecting', 'reconnecting');
    streamHint.textContent = state.recoveryWarning || 'Reconnecting. Retained events will replay from the last received cursor.';
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
  notificationsRefresh.onclick = () => refreshNotifications();
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
  eventStatusFilter.onchange = () => {
    state.eventStatusFilter = eventStatusFilter.value;
    renderEvents();
    renderDetails();
  };
  eventTimeFilter.onchange = () => {
    state.eventTimeFilter = eventTimeFilter.value;
    renderEvents();
    renderDetails();
  };
  incidentStatusFilter.onchange = () => {
    state.incidentStatusFilter = incidentStatusFilter.value;
    renderFindings();
  };
  incidentStateSave.onclick = () => {
    saveIncidentAnalysis().catch(error => {
      incidentStateStatus.textContent = `Unable to save analyst state: ${error.message}`;
    });
  };
  selectVisible.onclick = selectVisibleFindings;
  bulkDenySelected.onclick = openBulkDenyPreview;
  bulkDenyConfirm.onclick = () => {
    executeBulkDeny().catch(error => {
      bulkDenyStatus.textContent = `Bulk deny failed: ${error.message}`;
    });
  };
  document.querySelector('#bulk-deny-cancel').onclick = () => bulkDenyDialog.close();
  document.querySelector('#bulk-deny-close').onclick = () => bulkDenyDialog.close();
  bulkDenyDialog.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      event.preventDefault();
      bulkDenyDialog.close();
    }
  });
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

  await Promise.all([refreshIncidents(), refreshNotifications(), refreshDashboardHealth()]);

  try {
    await refreshSites();
  } catch (error) {
    iisStatus.textContent = `Unable to load IIS site data: ${error.message}`;
  }

  connectEventStream();
}

initializeDashboard();
