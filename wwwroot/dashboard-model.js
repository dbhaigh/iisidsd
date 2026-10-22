(function (root, factory) {
  const model = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = model;
  }
  root.IisidsdDashboardModel = model;
})(globalThis, function () {
  const maximumIncidentRecords = 500;
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const riskExplanations = [
    ['multiple 404 responses', 'Repeated not-found responses from this client and IIS site within the detection window.', 3],
    ['repeated authentication failures', 'Repeated 401/403 responses from this client and IIS site within the detection window.', 1],
    ['status code meets', 'An HTTP response met the configured suspicious-status threshold.', 1],
    ['request path exceeds', 'The request path met the configured long-path threshold.', 2],
    ['unusual http method', 'The request used TRACE, CONNECT, or DEBUG.', 3],
    ['suspicious request uri', 'The request URI matched a configured suspicious path fragment.', 5],
    ['request targets file type', 'An unsuccessful request targeted a file extension not learned for this site.', 2],
    ['request rate exceeded', 'The client request rate exceeded the configured threshold for this site.', 2],
    ['many unique request paths', 'The client reached the unique-path threshold for this site.', 2],
    ['known security scanner', 'The user-agent matched a configured scanner signature.', 6]
  ];

  function normalizeIncidentRecord(record) {
    if (!record || typeof record !== 'object') {
      return { status: 'open', note: '', updatedAt: '', updatedBy: '' };
    }
    return {
      status: ['open', 'acknowledged', 'suppressed', 'resolved'].includes(record.status) ? record.status : 'open',
      note: typeof record.note === 'string' ? record.note.slice(0, 4000) : '',
      updatedAt: typeof record.updatedAt === 'string' ? record.updatedAt : record.updatedAtUtc || '',
      updatedBy: typeof record.updatedBy === 'string' ? record.updatedBy : ''
    };
  }

  function updateIncidentRecord(records, clientIp, patch, now = new Date().toISOString()) {
    const next = { ...(records || {}) };
    next[clientIp] = {
      ...normalizeIncidentRecord(next[clientIp]),
      ...patch,
      updatedAt: now
    };
    const keys = Object.keys(next);
    while (keys.length > maximumIncidentRecords) {
      const oldest = keys.shift();
      delete next[oldest];
    }
    return next;
  }

  function filterEvents(events, filters = {}) {
    const query = String(filters.query || '').trim().toLocaleLowerCase();
    const status = filters.status || 'all';
    const domain = filters.domain || '*';
    const now = Number.isFinite(filters.now) ? filters.now : Date.now();
    const rangeMilliseconds = filters.range === '1h' ? 60 * 60 * 1000
      : filters.range === '24h' ? 24 * 60 * 60 * 1000
        : 0;
    return events.filter(event => {
      const timestamp = Date.parse(event.timestamp);
      if (domain !== '*' && event.domain !== domain) return false;
      if (status === 'suspicious' && !event.isSuspicious) return false;
      if (status === 'not-found' && event.statusCode !== 404) return false;
      if (status === 'errors' && Number(event.statusCode) < 400) return false;
      if (rangeMilliseconds && (!Number.isFinite(timestamp) || now - timestamp > rangeMilliseconds)) return false;
      if (!query) return true;
      return [event.clientIp, event.domain, event.path, event.method, event.detectionReason, ...(event.riskIndicators || [])]
        .some(value => String(value ?? '').toLocaleLowerCase().includes(query));
    });
  }

  function filterFindings(findings, filters = {}) {
    const query = String(filters.query || '').trim().toLocaleLowerCase();
    const domain = filters.domain || '*';
    const incidentStatus = filters.incidentStatus || 'all';
    return findings.filter(finding => {
      if (domain !== '*' && !(finding.domains || []).includes(domain)) return false;
      if (incidentStatus !== 'all' && normalizeIncidentRecord(filters.incidents?.[finding.clientIp]).status !== incidentStatus) return false;
      if (!query) return true;
      return [finding.clientIp, finding.highestRiskSeverity, finding.highestRiskScore, ...(finding.domains || []), ...(finding.detectionReasons || []), ...(finding.riskIndicators || [])]
        .some(value => String(value ?? '').toLocaleLowerCase().includes(query));
    });
  }

  function prioritizeFindings(findings) {
    return [...findings].sort((left, right) => {
      const leftSeverity = severityOrder[String(left.highestRiskSeverity || 'low').toLowerCase()] || 0;
      const rightSeverity = severityOrder[String(right.highestRiskSeverity || 'low').toLowerCase()] || 0;
      return rightSeverity - leftSeverity ||
        (Number(right.highestRiskScore) || 0) - (Number(left.highestRiskScore) || 0) ||
        (Date.parse(right.lastSeen) || 0) - (Date.parse(left.lastSeen) || 0);
    });
  }

  function getRiskExplanation(indicator) {
    const normalized = String(indicator || '').toLocaleLowerCase();
    const explanation = riskExplanations.find(([phrase]) => normalized.includes(phrase));
    return explanation
      ? { description: explanation[1], defaultWeight: explanation[2], configuredWeightKnown: false }
      : { description: 'The detector recorded this as contributing evidence. Its configured weight is not included in the existing event API.', defaultWeight: null, configuredWeightKnown: false };
  }

  function getReconnectDelay(attempt) {
    return Math.min(30000, 1000 * (2 ** Math.min(Math.max(0, attempt), 5)));
  }

  function classifyRequestError(statusCode) {
    if (statusCode === 401) return 'authentication-required';
    if (statusCode === 403) return 'administrator-required';
    if (statusCode >= 500) return 'service-error';
    if (statusCode >= 400) return 'request-error';
    return 'unknown-error';
  }

  function canUseAdministratorActions(statusCode) {
    return statusCode === 200;
  }

  function createBulkPreview(findings, incidents, clientIps) {
    return clientIps.map(clientIp => {
      const finding = findings.find(item => item.clientIp === clientIp);
      return {
        clientIp,
        severity: finding?.highestRiskSeverity || 'Unknown',
        score: finding?.highestRiskScore ?? 0,
        domains: [...(finding?.domains || [])],
        evidence: [...(finding?.riskIndicators || [])],
        analystStatus: normalizeIncidentRecord(incidents?.[clientIp]).status
      };
    });
  }

  return {
    canUseAdministratorActions,
    classifyRequestError,
    createBulkPreview,
    filterEvents,
    filterFindings,
    getReconnectDelay,
    getRiskExplanation,
    normalizeIncidentRecord,
    prioritizeFindings,
    updateIncidentRecord
  };
});