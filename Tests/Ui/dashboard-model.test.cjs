const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../../wwwroot/dashboard-model.js');

const now = Date.parse('2026-10-22T12:00:00Z');

test('timeline filters combine search, status, site, and time range', () => {
  const events = [
    { clientIp: '203.0.113.7', domain: 'alpha.example', path: '/missing', statusCode: 404, isSuspicious: true, timestamp: new Date(now - 10_000).toISOString() },
    { clientIp: '203.0.113.8', domain: 'alpha.example', path: '/health', statusCode: 200, isSuspicious: false, timestamp: new Date(now - 2 * 60 * 60 * 1000).toISOString() },
    { clientIp: '203.0.113.9', domain: 'beta.example', path: '/missing', statusCode: 404, isSuspicious: true, timestamp: new Date(now - 10_000).toISOString() }
  ];

  const filtered = model.filterEvents(events, { query: 'missing', status: 'not-found', domain: 'alpha.example', range: '1h', now });
  assert.deepEqual(filtered.map(event => event.clientIp), ['203.0.113.7']);
});

test('incident actions persist bounded analyst state without changing detector fields', () => {
  const finding = { clientIp: '203.0.113.7', highestRiskScore: 3, riskIndicators: ['multiple 404 responses'] };
  let incidents = model.updateIncidentRecord({}, finding.clientIp, { status: 'acknowledged' }, '2026-10-22T12:00:00Z');
  incidents = model.updateIncidentRecord(incidents, finding.clientIp, { note: 'Reviewed request sequence.' }, '2026-10-22T12:01:00Z');
  incidents = model.updateIncidentRecord(incidents, finding.clientIp, { status: 'suppressed' }, '2026-10-22T12:02:00Z');
  incidents = model.updateIncidentRecord(incidents, finding.clientIp, { status: 'resolved' }, '2026-10-22T12:03:00Z');

  assert.equal(incidents[finding.clientIp].status, 'resolved');
  assert.equal(incidents[finding.clientIp].note, 'Reviewed request sequence.');
  assert.equal(finding.highestRiskScore, 3);
  assert.deepEqual(finding.riskIndicators, ['multiple 404 responses']);
});

test('finding queue prioritizes severity then score and activity', () => {
  const findings = [
    { clientIp: 'low', highestRiskSeverity: 'Low', highestRiskScore: 0, lastSeen: '2026-10-22T12:00:00Z' },
    { clientIp: 'critical-older', highestRiskSeverity: 'Critical', highestRiskScore: 8, lastSeen: '2026-10-22T11:00:00Z' },
    { clientIp: 'critical-newer', highestRiskSeverity: 'Critical', highestRiskScore: 8, lastSeen: '2026-10-22T11:30:00Z' }
  ];
  assert.deepEqual(model.prioritizeFindings(findings).map(finding => finding.clientIp), ['critical-newer', 'critical-older', 'low']);
});

test('reconnect delay backs off and caps at thirty seconds', () => {
  assert.equal(model.getReconnectDelay(0), 1000);
  assert.equal(model.getReconnectDelay(3), 8000);
  assert.equal(model.getReconnectDelay(9), 30000);
});

test('administrator actions remain disabled for anonymous and forbidden responses', () => {
  assert.equal(model.canUseAdministratorActions(200), true);
  assert.equal(model.canUseAdministratorActions(401), false);
  assert.equal(model.canUseAdministratorActions(403), false);
  assert.equal(model.classifyRequestError(401), 'authentication-required');
  assert.equal(model.classifyRequestError(403), 'administrator-required');
  assert.equal(model.classifyRequestError(503), 'service-error');
});

test('risk explanations call configured weights defaults, not measured contributions', () => {
  const explanation = model.getRiskExplanation('multiple 404 responses from the same client IP');
  assert.equal(explanation.defaultWeight, 3);
  assert.equal(explanation.configuredWeightKnown, false);
  assert.match(explanation.description, /not-found responses/i);
});

test('bulk preview includes severity, scope, evidence, and analyst status', () => {
  const findings = [{
    clientIp: '203.0.113.7',
    highestRiskSeverity: 'High',
    highestRiskScore: 5,
    domains: ['alpha.example'],
    riskIndicators: ['suspicious request URI pattern']
  }];
  const preview = model.createBulkPreview(findings, { '203.0.113.7': { status: 'acknowledged' } }, ['203.0.113.7']);
  assert.deepEqual(preview[0], {
    clientIp: '203.0.113.7',
    severity: 'High',
    score: 5,
    domains: ['alpha.example'],
    evidence: ['suspicious request URI pattern'],
    analystStatus: 'acknowledged'
  });
});

test('findings without a saved analyst record default to open', () => {
  assert.deepEqual(model.normalizeIncidentRecord(undefined), {
    status: 'open',
    note: '',
    updatedAt: '',
    updatedBy: ''
  });
});