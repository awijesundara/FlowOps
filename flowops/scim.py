"""SCIM 2.0 filter parsing and resource documents."""
from __future__ import annotations

import re
from typing import Any

from flowops.config import SCIM_FILTER_ATTRIBUTES, SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA


def scim_parse_filter(expr: str) -> list[tuple[str,str,str]]:
    """Minimal hand-rolled SCIM filter parser -- supports `eq`/`co`/`sw`
    against SCIM_FILTER_ATTRIBUTES, joined with `and`. Not the full SCIM
    filter grammar (no `or`, no parentheses, no `pr`) -- a deliberate,
    documented scope call matching what real IdP SCIM connectors actually
    send for user/group lookup in practice. Raises ValueError on anything
    outside that narrow grammar."""
    clauses=[]
    for part in re.split(r"\s+and\s+", expr.strip(), flags=re.IGNORECASE):
        match=re.match(r'^(\w+(?:\.\w+)?)\s+(eq|co|sw)\s+"([^"]*)"$', part.strip(), re.IGNORECASE)
        if not match: raise ValueError(f"Unsupported SCIM filter expression: {part}")
        attr=match.group(1).lower()
        if attr not in SCIM_FILTER_ATTRIBUTES: raise ValueError(f"Unsupported SCIM filter attribute: {attr}")
        clauses.append((attr, match.group(2).lower(), match.group(3)))
    return clauses

def scim_filter_matches(clauses: list[tuple[str,str,str]], user_row: dict[str,Any]) -> bool:
    for attr, op, value in clauses:
        field=SCIM_FILTER_ATTRIBUTES[attr]
        actual="true" if field=="active" and user_row["active"] else "false" if field=="active" else str(user_row.get(field) or "")
        if op=="eq" and actual.lower()!=value.lower(): return False
        if op=="co" and value.lower() not in actual.lower(): return False
        if op=="sw" and not actual.lower().startswith(value.lower()): return False
    return True

def scim_user_document(user_row: dict[str,Any]) -> dict[str,Any]:
    return {
        "schemas":[SCIM_USER_SCHEMA], "id":str(user_row["id"]), "userName":user_row["username"],
        "name":{"formatted":user_row["display_name"]}, "displayName":user_row["display_name"],
        "emails":([{"value":user_row["email"],"primary":True}] if user_row["email"] else []),
        "active":bool(user_row["active"]),
        "meta":{"resourceType":"User","created":user_row["created_at"],"location":f"/scim/v2/Users/{user_row['id']}"},
    }

def scim_group_document(team_row: dict[str,Any], members: list[dict[str,Any]]) -> dict[str,Any]:
    return {
        "schemas":[SCIM_GROUP_SCHEMA], "id":str(team_row["id"]), "displayName":team_row["name"],
        "members":[{"value":str(m["id"]),"display":m["display_name"]} for m in members],
        "meta":{"resourceType":"Group","created":team_row["created_at"],"location":f"/scim/v2/Groups/{team_row['id']}"},
    }
