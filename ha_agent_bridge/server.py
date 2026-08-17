import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx
import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings


OPTIONS_PATH = "/data/options.json"
HA_API_BASE_URL = "http://supervisor/core/api"
MCP_PORT = 8099


def load_options() -> dict[str, Any]:
    with open(OPTIONS_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


OPTIONS = load_options()

MCP_TOKEN = OPTIONS["mcp_token"]
MAX_HISTORY_HOURS = int(OPTIONS.get("max_history_hours", 168))
MAX_RESULTS = int(OPTIONS.get("max_results", 50))
REDACT_SENSITIVE_DATA = bool(OPTIONS.get("redact_sensitive_data", True))

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN")

if not SUPERVISOR_TOKEN:
    raise RuntimeError("SUPERVISOR_TOKEN is not available")

if not MCP_TOKEN:
    raise RuntimeError("mcp_token must be configured")


SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "token",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "client_secret",
    "authorization",
    "private_key",
}


def redact_string(value: str) -> str:
    if not REDACT_SENSITIVE_DATA:
        return value

    value = re.sub(
        r"(?i)(access_token|refresh_token|token|api[_-]?key|password|passwd|client_secret)"
        r"([=:]\s*)[^&\s\"']+",
        r"\1\2<redacted>",
        value,
    )

    value = re.sub(
        r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+",
        r"\1<redacted>",
        value,
    )

    value = re.sub(
        r"(?i)([?&](?:access_token|token|api_key)=)[^&\s]+",
        r"\1<redacted>",
        value,
    )

    return value


def redact(value: Any) -> Any:
    if not REDACT_SENSITIVE_DATA:
        return value

    if isinstance(value, dict):
        result = {}

        for key, item in value.items():
            if key.lower() in SENSITIVE_KEYS:
                result[key] = "<redacted>"
            else:
                result[key] = redact(item)

        return result

    if isinstance(value, list):
        return [redact(item) for item in value]

    if isinstance(value, str):
        return redact_string(value)

    return value


def validate_entity_id(entity_id: str) -> str:
    if not re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", entity_id):
        raise ValueError(f"Invalid entity_id: {entity_id}")

    return entity_id


def parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None

    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        raise ValueError(
            "Timestamp must include timezone information, "
            "for example 2026-08-17T20:00:00+02:00"
        )

    return parsed


def resolve_period(
    start_time: str | None,
    end_time: str | None,
    hours: int,
) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)

    end = parse_timestamp(end_time) or now
    start = parse_timestamp(start_time) or (end - timedelta(hours=hours))

    if start >= end:
        raise ValueError("start_time must be before end_time")

    duration_hours = (end - start).total_seconds() / 3600

    if duration_hours > MAX_HISTORY_HOURS:
        raise ValueError(
            f"Requested period is {duration_hours:.1f} hours, "
            f"maximum allowed is {MAX_HISTORY_HOURS}"
        )

    return start, end


async def ha_get(
    path: str,
    params: dict[str, Any] | None = None,
    *,
    text: bool = False,
) -> Any:
    headers = {
        "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(
        base_url=HA_API_BASE_URL,
        headers=headers,
        timeout=30.0,
    ) as client:
        response = await client.get(path, params=params)

    if response.status_code == 404:
        raise ValueError(f"Home Assistant resource not found: {path}")

    response.raise_for_status()

    if text:
        return redact_string(response.text)

    return redact(response.json())


mcp = MCPServer(
    "Home Assistant Agent Bridge",
    version="0.1.0",
    instructions=(
        "Read-only access to Home Assistant runtime information. "
        "Use these tools to inspect actual Home Assistant state, history, "
        "logbook and errors. Never assume runtime state from Git configuration "
        "when a runtime tool can answer the question. "
        "Sensitive values may be redacted."
    ),
)


@mcp.tool()
async def ha_get_state(entity_id: str) -> dict[str, Any]:
    """
    Get the current runtime state and attributes of one Home Assistant entity.

    Use this when the exact entity_id is already known.
    """

    validate_entity_id(entity_id)
    return await ha_get(f"/states/{entity_id}")


@mcp.tool()
async def ha_search_entities(
    query: str,
    domain: str | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """
    Search current Home Assistant entities by entity_id or friendly name.

    Use this before ha_get_state when the exact entity_id is unknown.
    """

    states = await ha_get("/states")

    query_lower = query.lower().strip()
    domain_lower = domain.lower().strip() if domain else None

    limit = min(max(limit, 1), MAX_RESULTS)

    matches = []

    for state in states:
        entity_id = state.get("entity_id", "")
        attributes = state.get("attributes", {})
        friendly_name = str(attributes.get("friendly_name", ""))

        if domain_lower and not entity_id.startswith(f"{domain_lower}."):
            continue

        if (
            query_lower not in entity_id.lower()
            and query_lower not in friendly_name.lower()
        ):
            continue

        matches.append(
            {
                "entity_id": entity_id,
                "friendly_name": friendly_name or None,
                "state": state.get("state"),
                "last_changed": state.get("last_changed"),
                "last_updated": state.get("last_updated"),
                "unit_of_measurement": attributes.get("unit_of_measurement"),
                "device_class": attributes.get("device_class"),
            }
        )

        if len(matches) >= limit:
            break

    return matches


@mcp.tool()
async def ha_get_history(
    entity_ids: list[str],
    start_time: str | None = None,
    end_time: str | None = None,
    hours: int = 24,
) -> Any:
    """
    Get Home Assistant state history for one or more entities.

    start_time and end_time must be ISO 8601 timestamps with timezone.
    If omitted, the previous `hours` hours are returned.
    """

    if not entity_ids:
        raise ValueError("At least one entity_id is required")

    if len(entity_ids) > 10:
        raise ValueError("A maximum of 10 entities can be queried at once")

    for entity_id in entity_ids:
        validate_entity_id(entity_id)

    start, end = resolve_period(start_time, end_time, hours)

    start_value = start.isoformat()
    end_value = end.isoformat()

    params = {
        "filter_entity_id": ",".join(entity_ids),
        "end_time": end_value,
        "minimal_response": "",
        "no_attributes": "",
    }

    encoded_start = quote(start_value, safe="")

    return await ha_get(
        f"/history/period/{encoded_start}",
        params=params,
    )


@mcp.tool()
async def ha_get_logbook(
    start_time: str | None = None,
    end_time: str | None = None,
    hours: int = 24,
    entity_id: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Get Home Assistant logbook events.

    Optionally filter the result to a single entity.
    """

    if entity_id:
        validate_entity_id(entity_id)

    start, end = resolve_period(start_time, end_time, hours)

    params: dict[str, Any] = {
        "end_time": end.isoformat(),
    }

    if entity_id:
        params["entity"] = entity_id

    encoded_start = quote(start.isoformat(), safe="")

    result = await ha_get(
        f"/logbook/{encoded_start}",
        params=params,
    )

    limit = min(max(limit, 1), MAX_RESULTS * 10)

    return result[-limit:]


@mcp.tool()
async def ha_get_error_log(
    query: str | None = None,
    limit: int = 200,
) -> list[str]:
    """
    Get recent Home Assistant Core error log lines.

    Optionally filter lines using a case-insensitive text query.
    """

    log = await ha_get("/error_log", text=True)

    lines = log.splitlines()

    if query:
        query_lower = query.lower()
        lines = [line for line in lines if query_lower in line.lower()]

    limit = min(max(limit, 1), MAX_RESULTS * 10)

    return lines[-limit:]


class BearerAuthMiddleware:
    def __init__(self, app: Any, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }

        authorization = headers.get("authorization", "")
        expected = f"Bearer {self.token}"

        if not secrets.compare_digest(authorization, expected):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (
                            b"www-authenticate",
                            b'Bearer realm="home-assistant-agent-bridge"',
                        ),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"Unauthorized",
                }
            )
            return

        await self.app(scope, receive, send)


security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False,
)

mcp_app = mcp.streamable_http_app(
    transport_security=security,
)

app = BearerAuthMiddleware(
    mcp_app,
    MCP_TOKEN,
)


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=MCP_PORT,
        log_level="info",
    )