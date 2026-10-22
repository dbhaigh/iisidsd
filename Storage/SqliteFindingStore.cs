using System.Globalization;
using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteFindingStore(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment) : IFindingStore
{
    private const int PruneBatchSize = 1_000;
    private const int BackfillBatchSize = 1_000;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly Lock _sync = new();
    private readonly Lock _writeSync = SqliteDatabaseLock.For(
        GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));

    public void Upsert(SecurityEvent webEvent)
    {
        ValidateEvent(webEvent);
        if (string.IsNullOrWhiteSpace(webEvent.ClientIp))
        {
            return;
        }

        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            UpsertCore(webEvent, connection, transaction);
            transaction.Commit();
        }
    }

    public void Upsert(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction)
    {
        ValidateEvent(webEvent);
        if (string.IsNullOrWhiteSpace(webEvent.ClientIp))
        {
            return;
        }

        UpsertCore(webEvent, connection, transaction);
    }

    public void UpsertBatch(
        IReadOnlyList<SecurityEvent> webEvents,
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(webEvents);
        var findings = new Dictionary<string, FindingAggregate>(StringComparer.OrdinalIgnoreCase);
        foreach (var webEvent in webEvents)
        {
            ValidateEvent(webEvent);
            if (string.IsNullOrWhiteSpace(webEvent.ClientIp))
            {
                continue;
            }

            if (!findings.TryGetValue(webEvent.ClientIp, out var finding))
            {
                finding = new FindingAggregate(webEvent.ClientIp);
                findings.Add(webEvent.ClientIp, finding);
            }

            finding.Add(webEvent);
        }

        foreach (var finding in findings.Values)
        {
            UpsertAggregate(finding, connection, transaction);
            foreach (var domain in finding.DomainsByName.Values)
            {
                UpsertDomainAggregate(finding.ClientIp, domain, connection, transaction);
            }
        }
    }

    public int BackfillFromExistingEvents()
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using (var existingFindingsCommand = connection.CreateCommand())
            {
                existingFindingsCommand.Transaction = transaction;
                existingFindingsCommand.CommandText = "SELECT 1 FROM ip_findings LIMIT 1;";
                if (existingFindingsCommand.ExecuteScalar() is not null)
                {
                    transaction.Rollback();
                    return 0;
                }
            }

            var totalBackfilled = 0;
            long lastSequenceId = 0;
            while (true)
            {
                var events = new List<SecurityEvent>(BackfillBatchSize);
                using (var eventsCommand = connection.CreateCommand())
                {
                    eventsCommand.Transaction = transaction;
                    eventsCommand.CommandText = """
                        SELECT
                            sequence_id,
                            event_id,
                            timestamp_utc,
                            server,
                            domain,
                            method,
                            path,
                            client_ip,
                            status_code,
                            user_agent,
                            properties_json,
                            is_suspicious,
                            detection_reason,
                            risk_score,
                            risk_severity,
                            risk_indicators_json
                        FROM events
                        WHERE sequence_id > $afterSequenceId
                        ORDER BY sequence_id
                        LIMIT $limit;
                        """;
                    eventsCommand.Parameters.AddWithValue("$afterSequenceId", lastSequenceId);
                    eventsCommand.Parameters.AddWithValue("$limit", BackfillBatchSize);
                    using var reader = eventsCommand.ExecuteReader();
                    while (reader.Read())
                    {
                        lastSequenceId = reader.GetInt64(0);
                        events.Add(SqliteEventStore.ReadEvent(reader, sequenceIdColumnOffset: 1));
                    }
                }

                if (events.Count == 0)
                {
                    break;
                }

                UpsertBatch(events, connection, transaction);
                totalBackfilled += events.Count;
                if (events.Count < BackfillBatchSize)
                {
                    break;
                }
            }

            transaction.Commit();
            return totalBackfilled;
        }
    }

    private static void UpsertCore(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction)
    {
        var timestamp = webEvent.Timestamp.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var suspiciousCount = webEvent.IsSuspicious || webEvent.RiskScore > 0 ? 1 : 0;
        var domains = string.IsNullOrWhiteSpace(webEvent.Domain) ? [] : new[] { webEvent.Domain };
        var reasons = suspiciousCount > 0 && !string.IsNullOrWhiteSpace(webEvent.DetectionReason)
            ? new[] { webEvent.DetectionReason }
            : [];
        var indicators = suspiciousCount > 0 ? webEvent.RiskIndicators ?? [] : [];
        var updatedUtc = DateTimeOffset.UtcNow.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
                INSERT INTO ip_findings (
                    client_ip,
                    first_seen,
                    last_seen,
                    request_count,
                    suspicious_count,
                    highest_risk_score,
                    highest_risk_severity,
                    domains_json,
                    reasons_json,
                    indicators_json,
                    ban_count,
                    updated_utc)
                VALUES (
                    $clientIp,
                    $timestamp,
                    $timestamp,
                    1,
                    $suspiciousCount,
                    $riskScore,
                    $riskSeverity,
                    $domains,
                    $reasons,
                    $indicators,
                    COALESCE((SELECT SUM(ban_count) FROM ban_counts WHERE client_ip = $clientIp), 0),
                    $updatedUtc)
                ON CONFLICT(client_ip) DO UPDATE SET
                    first_seen = MIN(ip_findings.first_seen, excluded.first_seen),
                    last_seen = MAX(ip_findings.last_seen, excluded.last_seen),
                    request_count = ip_findings.request_count + 1,
                    suspicious_count = ip_findings.suspicious_count + excluded.suspicious_count,
                    highest_risk_severity = CASE
                        WHEN excluded.highest_risk_score > ip_findings.highest_risk_score
                          OR (excluded.highest_risk_score = ip_findings.highest_risk_score
                              AND excluded.last_seen >= ip_findings.last_seen)
                        THEN excluded.highest_risk_severity
                        ELSE ip_findings.highest_risk_severity
                    END,
                    highest_risk_score = MAX(ip_findings.highest_risk_score, excluded.highest_risk_score),
                    domains_json = (
                        SELECT json_group_array(value)
                        FROM (
                            SELECT value COLLATE NOCASE AS value FROM json_each(ip_findings.domains_json)
                            UNION
                            SELECT value COLLATE NOCASE FROM json_each(excluded.domains_json)
                        )),
                    reasons_json = (
                        SELECT json_group_array(value)
                        FROM (
                            SELECT value FROM json_each(ip_findings.reasons_json)
                            UNION
                            SELECT value FROM json_each(excluded.reasons_json)
                        )),
                    indicators_json = (
                        SELECT json_group_array(value)
                        FROM (
                            SELECT value FROM json_each(ip_findings.indicators_json)
                            UNION
                            SELECT value FROM json_each(excluded.indicators_json)
                        )),
                    ban_count = COALESCE((SELECT SUM(ban_count) FROM ban_counts WHERE client_ip = excluded.client_ip), 0),
                    updated_utc = excluded.updated_utc;
                """;
            command.Parameters.AddWithValue("$clientIp", webEvent.ClientIp);
            command.Parameters.AddWithValue("$timestamp", timestamp);
            command.Parameters.AddWithValue("$suspiciousCount", suspiciousCount);
            command.Parameters.AddWithValue("$riskScore", webEvent.RiskScore);
            command.Parameters.AddWithValue("$riskSeverity", webEvent.RiskSeverity);
            command.Parameters.AddWithValue("$domains", JsonSerializer.Serialize(domains, SerializerOptions));
            command.Parameters.AddWithValue("$reasons", JsonSerializer.Serialize(reasons, SerializerOptions));
            command.Parameters.AddWithValue("$indicators", JsonSerializer.Serialize(indicators, SerializerOptions));
            command.Parameters.AddWithValue("$updatedUtc", updatedUtc);
            command.ExecuteNonQuery();

        if (webEvent.Domain is not null)
        {
            UpsertDomainFinding(connection, transaction, webEvent, timestamp, suspiciousCount, reasons, indicators);
        }
    }

    private static void UpsertAggregate(
        FindingAggregate finding,
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO ip_findings (
                client_ip, first_seen, last_seen, request_count, suspicious_count,
                highest_risk_score, highest_risk_severity, domains_json, reasons_json,
                indicators_json, ban_count, updated_utc)
            VALUES (
                $clientIp, $firstSeen, $lastSeen, $requestCount, $suspiciousCount,
                $riskScore, $riskSeverity, $domains, $reasons, $indicators,
                COALESCE((SELECT SUM(ban_count) FROM ban_counts WHERE client_ip = $clientIp), 0), $updatedUtc)
            ON CONFLICT(client_ip) DO UPDATE SET
                first_seen = MIN(ip_findings.first_seen, excluded.first_seen),
                last_seen = MAX(ip_findings.last_seen, excluded.last_seen),
                request_count = ip_findings.request_count + excluded.request_count,
                suspicious_count = ip_findings.suspicious_count + excluded.suspicious_count,
                highest_risk_severity = CASE
                    WHEN excluded.highest_risk_score > ip_findings.highest_risk_score
                      OR (excluded.highest_risk_score = ip_findings.highest_risk_score
                          AND $severityTimestamp >= ip_findings.last_seen)
                    THEN excluded.highest_risk_severity
                    ELSE ip_findings.highest_risk_severity
                END,
                highest_risk_score = MAX(ip_findings.highest_risk_score, excluded.highest_risk_score),
                domains_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value COLLATE NOCASE AS value FROM json_each(ip_findings.domains_json)
                        UNION
                        SELECT value COLLATE NOCASE FROM json_each(excluded.domains_json)
                    )),
                reasons_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value FROM json_each(ip_findings.reasons_json)
                        UNION
                        SELECT value FROM json_each(excluded.reasons_json)
                    )),
                indicators_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value FROM json_each(ip_findings.indicators_json)
                        UNION
                        SELECT value FROM json_each(excluded.indicators_json)
                    )),
                ban_count = COALESCE((SELECT SUM(ban_count) FROM ban_counts WHERE client_ip = excluded.client_ip), 0),
                updated_utc = excluded.updated_utc;
            """;
        command.Parameters.AddWithValue("$clientIp", finding.ClientIp);
        command.Parameters.AddWithValue("$firstSeen", FormatTimestamp(finding.FirstSeen));
        command.Parameters.AddWithValue("$lastSeen", FormatTimestamp(finding.LastSeen));
        command.Parameters.AddWithValue("$requestCount", finding.RequestCount);
        command.Parameters.AddWithValue("$suspiciousCount", finding.SuspiciousCount);
        command.Parameters.AddWithValue("$riskScore", finding.HighestRiskScore);
        command.Parameters.AddWithValue("$riskSeverity", finding.HighestRiskSeverity);
        command.Parameters.AddWithValue("$severityTimestamp", FormatTimestamp(finding.SeverityTimestamp));
        command.Parameters.AddWithValue("$domains", JsonSerializer.Serialize(finding.Domains, SerializerOptions));
        command.Parameters.AddWithValue("$reasons", JsonSerializer.Serialize(finding.Reasons, SerializerOptions));
        command.Parameters.AddWithValue("$indicators", JsonSerializer.Serialize(finding.Indicators, SerializerOptions));
        command.Parameters.AddWithValue("$updatedUtc", DateTimeOffset.UtcNow.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
        command.ExecuteNonQuery();
    }

    private static void UpsertDomainAggregate(
        string clientIp,
        FindingAggregate domain,
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO ip_finding_domains (
                client_ip, domain, first_seen, last_seen, request_count, suspicious_count,
                highest_risk_score, highest_risk_severity, reasons_json, indicators_json)
            VALUES (
                $clientIp, $domain, $firstSeen, $lastSeen, $requestCount, $suspiciousCount,
                $riskScore, $riskSeverity, $reasons, $indicators)
            ON CONFLICT(client_ip, domain) DO UPDATE SET
                first_seen = MIN(ip_finding_domains.first_seen, excluded.first_seen),
                last_seen = MAX(ip_finding_domains.last_seen, excluded.last_seen),
                request_count = ip_finding_domains.request_count + excluded.request_count,
                suspicious_count = ip_finding_domains.suspicious_count + excluded.suspicious_count,
                highest_risk_severity = CASE
                    WHEN excluded.highest_risk_score > ip_finding_domains.highest_risk_score
                      OR (excluded.highest_risk_score = ip_finding_domains.highest_risk_score
                          AND $severityTimestamp >= ip_finding_domains.last_seen)
                    THEN excluded.highest_risk_severity
                    ELSE ip_finding_domains.highest_risk_severity
                END,
                highest_risk_score = MAX(ip_finding_domains.highest_risk_score, excluded.highest_risk_score),
                reasons_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value FROM json_each(ip_finding_domains.reasons_json)
                        UNION
                        SELECT value FROM json_each(excluded.reasons_json)
                    )),
                indicators_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value FROM json_each(ip_finding_domains.indicators_json)
                        UNION
                        SELECT value FROM json_each(excluded.indicators_json)
                    ));
            """;
        command.Parameters.AddWithValue("$clientIp", clientIp);
        command.Parameters.AddWithValue("$domain", domain.Domain);
        command.Parameters.AddWithValue("$firstSeen", FormatTimestamp(domain.FirstSeen));
        command.Parameters.AddWithValue("$lastSeen", FormatTimestamp(domain.LastSeen));
        command.Parameters.AddWithValue("$requestCount", domain.RequestCount);
        command.Parameters.AddWithValue("$suspiciousCount", domain.SuspiciousCount);
        command.Parameters.AddWithValue("$riskScore", domain.HighestRiskScore);
        command.Parameters.AddWithValue("$riskSeverity", domain.HighestRiskSeverity);
        command.Parameters.AddWithValue("$severityTimestamp", FormatTimestamp(domain.SeverityTimestamp));
        command.Parameters.AddWithValue("$reasons", JsonSerializer.Serialize(domain.Reasons, SerializerOptions));
        command.Parameters.AddWithValue("$indicators", JsonSerializer.Serialize(domain.Indicators, SerializerOptions));
        command.ExecuteNonQuery();
    }

    private static string FormatTimestamp(DateTimeOffset value)
        => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private sealed class FindingAggregate(string clientIp)
    {
        public string ClientIp { get; } = clientIp;
        public string Domain { get; private init; } = string.Empty;
        public int RequestCount { get; private set; }
        public int SuspiciousCount { get; private set; }
        public int HighestRiskScore { get; private set; } = int.MinValue;
        public string HighestRiskSeverity { get; private set; } = "Low";
        public DateTimeOffset FirstSeen { get; private set; }
        public DateTimeOffset LastSeen { get; private set; }
        public DateTimeOffset SeverityTimestamp { get; private set; }
        public HashSet<string> Domains { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Reasons { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Indicators { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, FindingAggregate> DomainsByName { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void Add(SecurityEvent webEvent)
        {
            var isFirst = RequestCount == 0;
            var priorLastSeen = LastSeen;
            if (isFirst || webEvent.Timestamp < FirstSeen)
            {
                FirstSeen = webEvent.Timestamp;
            }

            if (isFirst || webEvent.RiskScore > HighestRiskScore ||
                (webEvent.RiskScore == HighestRiskScore && webEvent.Timestamp >= priorLastSeen))
            {
                HighestRiskScore = webEvent.RiskScore;
                HighestRiskSeverity = webEvent.RiskSeverity;
                SeverityTimestamp = webEvent.Timestamp;
            }

            if (isFirst || webEvent.Timestamp > LastSeen)
            {
                LastSeen = webEvent.Timestamp;
            }

            RequestCount++;
            var suspicious = webEvent.IsSuspicious || webEvent.RiskScore > 0;
            if (suspicious)
            {
                SuspiciousCount++;
                if (!string.IsNullOrWhiteSpace(webEvent.DetectionReason))
                {
                    Reasons.Add(webEvent.DetectionReason);
                }

                foreach (var indicator in webEvent.RiskIndicators ?? [])
                {
                    Indicators.Add(indicator);
                }
            }

            if (!string.IsNullOrWhiteSpace(webEvent.Domain))
            {
                Domains.Add(webEvent.Domain);
            }

            if (webEvent.Domain is not null)
            {
                if (!DomainsByName.TryGetValue(webEvent.Domain, out var domain))
                {
                    domain = new FindingAggregate(ClientIp) { Domain = webEvent.Domain };
                    DomainsByName.Add(webEvent.Domain, domain);
                }

                domain.AddEventOnly(webEvent);
            }
        }

        private void AddEventOnly(SecurityEvent webEvent)
        {
            var isFirst = RequestCount == 0;
            var priorLastSeen = LastSeen;
            if (isFirst || webEvent.Timestamp < FirstSeen)
            {
                FirstSeen = webEvent.Timestamp;
            }

            if (isFirst || webEvent.RiskScore > HighestRiskScore ||
                (webEvent.RiskScore == HighestRiskScore && webEvent.Timestamp >= priorLastSeen))
            {
                HighestRiskScore = webEvent.RiskScore;
                HighestRiskSeverity = webEvent.RiskSeverity;
                SeverityTimestamp = webEvent.Timestamp;
            }

            if (isFirst || webEvent.Timestamp > LastSeen)
            {
                LastSeen = webEvent.Timestamp;
            }

            RequestCount++;
            if (webEvent.IsSuspicious || webEvent.RiskScore > 0)
            {
                SuspiciousCount++;
                if (!string.IsNullOrWhiteSpace(webEvent.DetectionReason))
                {
                    Reasons.Add(webEvent.DetectionReason);
                }

                foreach (var indicator in webEvent.RiskIndicators ?? [])
                {
                    Indicators.Add(indicator);
                }
            }
        }
    }

    private static void ValidateEvent(SecurityEvent webEvent)
        => ArgumentNullException.ThrowIfNull(webEvent);

    public IpFinding? Get(string clientIp, string? domain = null)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            return null;
        }

        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = domain is null
                ? """
                    SELECT client_ip, request_count, suspicious_count, highest_risk_score, highest_risk_severity,
                           first_seen, last_seen, domains_json, reasons_json, indicators_json, ban_count
                    FROM ip_findings
                    WHERE client_ip = $clientIp;
                    """
                : """
                    SELECT f.client_ip, d.request_count, d.suspicious_count, d.highest_risk_score, d.highest_risk_severity,
                           d.first_seen, d.last_seen,
                           CASE WHEN TRIM(d.domain) = '' THEN '[]' ELSE json_array(d.domain) END,
                           d.reasons_json, d.indicators_json, f.ban_count
                    FROM ip_findings f
                    INNER JOIN ip_finding_domains d ON d.client_ip = f.client_ip
                    WHERE f.client_ip = $clientIp AND d.domain = $domain;
                    """;
            command.Parameters.AddWithValue("$clientIp", clientIp);
            if (domain is not null)
            {
                command.Parameters.AddWithValue("$domain", domain);
            }

            using var reader = command.ExecuteReader();
            return reader.Read() ? ReadFinding(reader) : null;
        }
    }

    public IReadOnlyList<IpFinding> List(int limit, string? domain = null)
    {
        limit = Math.Clamp(limit, 1, FindingStoreLimits.MaximumListLimit);
        var findings = new List<IpFinding>();
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = domain is null
                ? """
                    SELECT client_ip, request_count, suspicious_count, highest_risk_score, highest_risk_severity,
                           first_seen, last_seen, domains_json, reasons_json, indicators_json, ban_count
                    FROM ip_findings
                    WHERE suspicious_count > 0 OR highest_risk_score > 0
                    ORDER BY highest_risk_score DESC, suspicious_count DESC, last_seen DESC
                    LIMIT $limit;
                    """
                : """
                    SELECT f.client_ip, d.request_count, d.suspicious_count, d.highest_risk_score, d.highest_risk_severity,
                           d.first_seen, d.last_seen,
                           CASE WHEN TRIM(d.domain) = '' THEN '[]' ELSE json_array(d.domain) END,
                           d.reasons_json, d.indicators_json, f.ban_count
                    FROM ip_findings f
                    INNER JOIN ip_finding_domains d ON d.client_ip = f.client_ip
                    WHERE d.domain = $domain AND (d.suspicious_count > 0 OR d.highest_risk_score > 0)
                    ORDER BY d.highest_risk_score DESC, d.suspicious_count DESC, d.last_seen DESC
                    LIMIT $limit;
                    """;
            command.Parameters.AddWithValue("$limit", limit);
            if (domain is not null)
            {
                command.Parameters.AddWithValue("$domain", domain);
            }

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                findings.Add(ReadFinding(reader));
            }
        }

        return findings;
    }

    public int Prune(DateTimeOffset olderThan)
    {
        var cutoff = olderThan.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var prunedFindings = 0;
        while (true)
        {
            int expiredDomainCount;
            int prunedInBatch;
            lock (_writeSync)
            {
                using var connection = OpenConnection();
                using var transaction = connection.BeginTransaction();
                using (var expiredDomainsCommand = connection.CreateCommand())
                {
                    expiredDomainsCommand.Transaction = transaction;
                    expiredDomainsCommand.CommandText = """
                        CREATE TEMP TABLE IF NOT EXISTS expired_ip_finding_domains (
                            client_ip TEXT NOT NULL COLLATE NOCASE,
                            domain TEXT NOT NULL COLLATE NOCASE,
                            PRIMARY KEY (client_ip, domain));
                        DELETE FROM expired_ip_finding_domains;
                        INSERT INTO expired_ip_finding_domains (client_ip, domain)
                        SELECT client_ip, domain
                        FROM ip_finding_domains
                        WHERE last_seen < $cutoff
                        ORDER BY last_seen
                        LIMIT $limit;
                        """;
                    expiredDomainsCommand.Parameters.AddWithValue("$cutoff", cutoff);
                    expiredDomainsCommand.Parameters.AddWithValue("$limit", PruneBatchSize);
                    expiredDomainsCommand.ExecuteNonQuery();
                }

                using (var countDomainsCommand = connection.CreateCommand())
                {
                    countDomainsCommand.Transaction = transaction;
                    countDomainsCommand.CommandText = "SELECT COUNT(*) FROM expired_ip_finding_domains;";
                    expiredDomainCount = Convert.ToInt32(countDomainsCommand.ExecuteScalar(), CultureInfo.InvariantCulture);
                }

                using (var domainCommand = connection.CreateCommand())
                {
                    domainCommand.Transaction = transaction;
                    domainCommand.CommandText = """
                        DELETE FROM ip_finding_domains
                        WHERE (client_ip, domain) IN (
                            SELECT client_ip, domain FROM expired_ip_finding_domains);
                        """;
                    domainCommand.ExecuteNonQuery();
                }

                using (var domainsCommand = connection.CreateCommand())
                {
                    domainsCommand.Transaction = transaction;
                    domainsCommand.CommandText = """
                        UPDATE ip_findings
                        SET domains_json = COALESCE((
                            SELECT json_group_array(domain)
                            FROM (
                                SELECT domain
                                FROM ip_finding_domains
                                WHERE client_ip = ip_findings.client_ip AND TRIM(domain) <> ''
                                ORDER BY domain COLLATE NOCASE
                            )), '[]')
                        WHERE client_ip IN (SELECT client_ip FROM expired_ip_finding_domains);
                        """;
                    domainsCommand.ExecuteNonQuery();
                }

                using (var findingCommand = connection.CreateCommand())
                {
                    findingCommand.Transaction = transaction;
                    findingCommand.CommandText = """
                        DELETE FROM ip_findings
                        WHERE client_ip IN (
                            SELECT finding.client_ip
                            FROM ip_findings AS finding
                            WHERE finding.last_seen < $cutoff
                              AND NOT EXISTS (
                                  SELECT 1
                                  FROM ip_finding_domains AS domain
                                  WHERE domain.client_ip = finding.client_ip)
                            ORDER BY finding.last_seen
                            LIMIT $limit);
                        """;
                    findingCommand.Parameters.AddWithValue("$cutoff", cutoff);
                    findingCommand.Parameters.AddWithValue("$limit", PruneBatchSize);
                    prunedInBatch = findingCommand.ExecuteNonQuery();
                }

                transaction.Commit();
            }

            prunedFindings += prunedInBatch;
            if (expiredDomainCount < PruneBatchSize && prunedInBatch < PruneBatchSize)
            {
                return prunedFindings;
            }
        }
    }

    private static void UpsertDomainFinding(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SecurityEvent webEvent,
        string timestamp,
        int suspiciousCount,
        IReadOnlyList<string?> reasons,
        IReadOnlyList<string> indicators)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO ip_finding_domains (
                client_ip, domain, first_seen, last_seen, request_count, suspicious_count,
                highest_risk_score, highest_risk_severity, reasons_json, indicators_json)
            VALUES (
                $clientIp, $domain, $timestamp, $timestamp, 1, $suspiciousCount,
                $riskScore, $riskSeverity, $reasons, $indicators)
            ON CONFLICT(client_ip, domain) DO UPDATE SET
                first_seen = MIN(ip_finding_domains.first_seen, excluded.first_seen),
                last_seen = MAX(ip_finding_domains.last_seen, excluded.last_seen),
                request_count = ip_finding_domains.request_count + 1,
                suspicious_count = ip_finding_domains.suspicious_count + excluded.suspicious_count,
                highest_risk_severity = CASE
                    WHEN excluded.highest_risk_score > ip_finding_domains.highest_risk_score
                      OR (excluded.highest_risk_score = ip_finding_domains.highest_risk_score
                          AND excluded.last_seen >= ip_finding_domains.last_seen)
                    THEN excluded.highest_risk_severity
                    ELSE ip_finding_domains.highest_risk_severity
                END,
                highest_risk_score = MAX(ip_finding_domains.highest_risk_score, excluded.highest_risk_score),
                reasons_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value FROM json_each(ip_finding_domains.reasons_json)
                        UNION
                        SELECT value FROM json_each(excluded.reasons_json)
                    )),
                indicators_json = (
                    SELECT json_group_array(value)
                    FROM (
                        SELECT value FROM json_each(ip_finding_domains.indicators_json)
                        UNION
                        SELECT value FROM json_each(excluded.indicators_json)
                    ));
            """;
        command.Parameters.AddWithValue("$clientIp", webEvent.ClientIp);
        command.Parameters.AddWithValue("$domain", webEvent.Domain);
        command.Parameters.AddWithValue("$timestamp", timestamp);
        command.Parameters.AddWithValue("$suspiciousCount", suspiciousCount);
        command.Parameters.AddWithValue("$riskScore", webEvent.RiskScore);
        command.Parameters.AddWithValue("$riskSeverity", webEvent.RiskSeverity);
        command.Parameters.AddWithValue("$reasons", JsonSerializer.Serialize(reasons, SerializerOptions));
        command.Parameters.AddWithValue("$indicators", JsonSerializer.Serialize(indicators, SerializerOptions));
        command.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
        => SqliteConnectionFactory.Open(_databasePath, storageOptions.Value);

    private static IpFinding ReadFinding(SqliteDataReader reader)
    {
        var domains = JsonSerializer.Deserialize<List<string>>(reader.GetString(7), SerializerOptions) ?? [];
        var reasons = JsonSerializer.Deserialize<List<string>>(reader.GetString(8), SerializerOptions) ?? [];
        var indicators = JsonSerializer.Deserialize<List<string>>(reader.GetString(9), SerializerOptions) ?? [];
        return new IpFinding(
            reader.GetString(0),
            reader.GetInt32(1),
            reader.GetInt32(2),
            reader.GetInt32(3),
            reader.GetString(4),
            DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            DateTimeOffset.Parse(reader.GetString(6), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            domains.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            reasons,
            indicators.Order(StringComparer.Ordinal).ToArray(),
            BanCount: reader.GetInt32(10));
    }

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}
