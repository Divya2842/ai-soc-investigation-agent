# Future Microsoft Sentinel Integration

This project does not require a Sentinel subscription. The `LogSource`
abstraction (`backend/app/services/logs/base.py`) exists so a
`SentinelLogSource` can be added later without changing the agent, API, or
database schema.

## What's in place today

```python
class LogSource(ABC):
    @abstractmethod
    def search_logs(self, query: LogQuery) -> list[LogEvent]: ...

    @abstractmethod
    def get_user_activity(self, user: str, window: TimeWindow) -> list[LogEvent]: ...

    @abstractmethod
    def get_host_activity(self, hostname: str, window: TimeWindow) -> list[LogEvent]: ...
```

`LocalLogSource` implements this fully against the SQLite `raw_log_events`
table seeded from `data/logs/*.jsonl`.

`SentinelLogSource` is a documented placeholder (raises
`NotImplementedError`) — no fake Sentinel API responses are implemented, per
the project's engineering requirements.

## How it would be connected later

1. **Authentication** — register an Azure AD application with
   `Log Analytics Reader` (or narrower, custom) role on the Sentinel
   workspace. Use client-credentials OAuth2 flow (`MSAL` or
   `azure-identity`) to obtain a token for the Log Analytics Query API.
2. **KQL query execution** — `SentinelLogSource.search_logs()` would
   translate the generic `LogQuery` (log type, time window, filters) into a
   KQL query against the appropriate table (`SecurityEvent`,
   `SigninLogs`, `DeviceProcessEvents`, etc.) and execute it via the
   `azure-monitor-query` SDK's `LogsQueryClient`.
3. **Alert/incident retrieval** — `SentinelLogSource` would additionally
   implement an `IncidentSource` interface pulling from the Sentinel
   `SecurityIncident` / Microsoft Graph Security API, mapped into the same
   `AlertRecord` shape `LocalLogSource`-backed alerts already use, so the
   ingestion pipeline and downstream agent don't need to know which source
   produced the alert.
4. **Configuration** — switching sources is `LOG_SOURCE=sentinel` in
   `.env`, plus `SENTINEL_TENANT_ID`, `SENTINEL_CLIENT_ID`,
   `SENTINEL_CLIENT_SECRET`, `SENTINEL_WORKSPACE_ID` (all placeholders in
   `.env.example`, unused while `LOG_SOURCE=local`).

## Why it's not implemented now

Building a fake Sentinel client that returns canned data would misrepresent
what the project actually demonstrates and could be misleading in an
interview setting. The placeholder documents the integration surface
precisely so it's clear what real work remains.
