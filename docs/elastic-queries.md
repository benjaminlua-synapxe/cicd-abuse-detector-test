# ES|QL Detection Queries

Example queries for the `logs-cicd.abuse-default` data stream. These assume the Elastic shipping step is configured with `ES_URL` and `ES_API_KEY` secrets.

Data stream: `logs-cicd.abuse-default` (auto-creates `.ds-logs-cicd.abuse-default-*`).

*In Kibana Discover you can show malicious verdicts shipped from GitHub, Azure DevOps, and GitLab in one data stream; use the queries below for views and filters.*

## Cross-platform incident timeline

The single most useful query — shows all alerts across GitHub, GitLab, and Azure DevOps in chronological order with direct links to the pipeline runs.

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict IN ("malicious", "suspicious") AND @timestamp > NOW() - 7 days
| EVAL platform = cicd.platform, repo = cicd.repository, actor = cicd.actor,
       severity = verdict.severity, run = cicd.run_url
| KEEP @timestamp, platform, repo, actor, severity, run
| SORT @timestamp DESC
```

## All malicious verdicts (cross-platform)

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict == "malicious"
| SORT @timestamp DESC
| KEEP @timestamp, cicd.platform, cicd.repository, cicd.actor, verdict.severity, verdict.summary, cicd.run_url
```

## Critical/high severity alerts in the last 7 days

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.severity IN ("critical", "high") AND @timestamp > NOW() - 7 days
| SORT @timestamp DESC
| KEEP @timestamp, cicd.platform, cicd.repository, cicd.actor, verdict.verdict, verdict.severity, verdict.summary
```

## Repeat offenders — actors with multiple alerts

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict IN ("malicious", "suspicious")
| STATS alert_count = COUNT(*), platforms = VALUES(cicd.platform), repos = VALUES(cicd.repository), latest = MAX(@timestamp) BY cicd.actor
| WHERE alert_count > 1
| SORT alert_count DESC
```

## Cross-platform correlation — same actor flagged on multiple platforms

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict IN ("malicious", "suspicious")
| STATS platform_count = COUNT_DISTINCT(cicd.platform), platforms = VALUES(cicd.platform), alert_count = COUNT(*) BY cicd.actor
| WHERE platform_count > 1
| SORT alert_count DESC
```

## Credential harvesting pattern detection

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict == "malicious" AND verdict.severity == "critical"
| SORT @timestamp DESC
| KEEP @timestamp, cicd.platform, cicd.repository, cicd.actor, verdict.summary, verdict.evidence, cicd.run_url
```

## Alert volume by repository

```esql
FROM logs-cicd.abuse-*
| STATS total = COUNT(*),
        malicious = COUNT(CASE(verdict.verdict == "malicious", 1)),
        suspicious = COUNT(CASE(verdict.verdict == "suspicious", 1))
  BY cicd.repository
| SORT malicious DESC, suspicious DESC
```

## Platform coverage — alerts per CI platform

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict IN ("malicious", "suspicious")
| STATS alert_count = COUNT(*),
        repos = VALUES(cicd.repository),
        actors = VALUES(cicd.actor),
        critical = COUNT(CASE(verdict.severity == "critical", 1))
  BY cicd.platform
| SORT alert_count DESC
```

## Coordinated campaign detection — burst of alerts within a time window

Detects a credential harvesting campaign that hits multiple repos/platforms in quick succession.

```esql
FROM logs-cicd.abuse-*
| WHERE verdict.verdict == "malicious" AND @timestamp > NOW() - 1 hour
| STATS platform_count = COUNT_DISTINCT(cicd.platform),
        repo_count = COUNT_DISTINCT(cicd.repository),
        total = COUNT(*)
| WHERE total > 2
```
