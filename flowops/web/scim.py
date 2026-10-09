"""SCIM 2.0 provisioning endpoints."""
from __future__ import annotations

import json
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from flowops.audit import append_audit
from flowops.config import SCIM_ERROR_SCHEMA, SCIM_LIST_SCHEMA
from flowops.crypto import password_hash
from flowops.db import connect, now, rows
from flowops.ratelimit import check_rate_limit
from flowops.scim import scim_filter_matches, scim_group_document, scim_parse_filter, scim_user_document
from flowops.web.base import BaseHandler, NOT_HANDLED


class ScimRoutes(BaseHandler):
    def scim_error(self, status: int, detail: str):
        self.send_json({"schemas":[SCIM_ERROR_SCHEMA],"status":str(status),"detail":detail}, status)

    def scim_actor(self, db: sqlite3.Connection) -> dict[str,Any] | None:
        """SCIM clients authenticate with a bearer token only (no session
        cookie -- there's no browser involved), reusing the exact same
        api_tokens mechanism and current_user() already used for the
        regular REST API, gated by a new scim:provision scope."""
        user=self.current_user(db)
        if not user or user.get("auth_method")!="token":
            self.scim_error(401,"SCIM requires a bearer token with the scim:provision scope"); return None
        retry_after=check_rate_limit(f"token:{user['username']}")
        if retry_after:
            self.scim_error(429,"Rate limit exceeded"); return None
        if "scim:provision" not in user["permissions"]:
            self.scim_error(403,"This token does not have the scim:provision scope"); return None
        return user

    # --- SCIM 2.0 provisioning --------------------------------------------
    # /scim/v2/Users and /scim/v2/Groups, bearer-token auth reusing the
    # exact existing api_tokens mechanism (scim_actor() above) gated by a
    # new scim:provision scope -- no new auth mechanism. SCIM Users map to
    # the users table; SCIM Groups map to central_teams/central_team_members
    # (the cross-runbook membership model, not per-runbook runbook_teams).
    def scim_dispatch(self):
        path=urllib.parse.urlparse(self.path).path
        parts=path.strip("/").split("/")
        if len(parts)<3 or parts[:2]!=["scim","v2"] or parts[2] not in ("Users","Groups"):
            return self.scim_error(404,"Not found")
        resource=parts[2]; resource_id=parts[3] if len(parts)>3 else None
        with connect() as db:
            actor=self.scim_actor(db)
            if not actor: return
            if resource=="Users":
                if self.command=="GET" and resource_id is None:
                    query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                    return self.scim_list_users(db,actor,query)
                if self.command=="GET": return self.scim_get_user(db,actor,resource_id)
                if self.command=="POST" and resource_id is None: return self.scim_create_user(db,actor)
                if self.command=="PATCH" and resource_id is not None: return self.scim_patch_user(db,actor,resource_id)
                if self.command=="DELETE" and resource_id is not None: return self.scim_delete_user(db,actor,resource_id)
            if resource=="Groups":
                if self.command=="GET" and resource_id is None:
                    query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                    return self.scim_list_groups(db,actor,query)
                if self.command=="GET": return self.scim_get_group(db,actor,resource_id)
                if self.command=="POST" and resource_id is None: return self.scim_create_group(db,actor)
                if self.command=="PATCH" and resource_id is not None: return self.scim_patch_group(db,actor,resource_id)
                if self.command=="DELETE" and resource_id is not None: return self.scim_delete_group(db,actor,resource_id)
            return self.scim_error(404,"Not found")

    def scim_paginate(self, query: dict, total: int) -> tuple[int,int]:
        try: start_index=max(1,int((query.get("startIndex") or ["1"])[0]))
        except ValueError: start_index=1
        try: count=max(0,min(200,int((query.get("count") or ["100"])[0])))
        except ValueError: count=100
        return start_index,count

    def scim_list_users(self, db, actor, query):
        rows_=[dict(r) for r in db.execute("SELECT * FROM users WHERE instance_id=? ORDER BY id",(actor["instance_id"],))]
        filter_expr=(query.get("filter") or [""])[0]
        if filter_expr:
            try: clauses=scim_parse_filter(filter_expr)
            except ValueError as exc: return self.scim_error(400,str(exc))
            rows_=[r for r in rows_ if scim_filter_matches(clauses,r)]
        start_index,count=self.scim_paginate(query,len(rows_))
        page=rows_[start_index-1:start_index-1+count] if count else []
        return self.send_json({"schemas":[SCIM_LIST_SCHEMA],"totalResults":len(rows_),"startIndex":start_index,"itemsPerPage":len(page),"Resources":[scim_user_document(r) for r in page]})

    def scim_get_user(self, db, actor, resource_id):
        try: uid=int(resource_id)
        except ValueError: return self.scim_error(404,"Not found")
        row=db.execute("SELECT * FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
        if not row: return self.scim_error(404,"User not found")
        return self.send_json(scim_user_document(dict(row)))

    def scim_create_user(self, db, actor):
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.scim_error(400,str(exc))
        username=str(payload.get("userName","")).strip()
        if not username: return self.scim_error(400,"userName is required")
        name=payload.get("name") or {}
        display=str(payload.get("displayName") or name.get("formatted") or username).strip()[:160]
        emails=payload.get("emails") or []
        email=str((emails[0].get("value") if emails and isinstance(emails[0],dict) else "") or "")[:180]
        active=bool(payload.get("active",True))
        # SSO-first provisioned users authenticate via OIDC, never a local
        # password -- still need *some* password_hash to satisfy the
        # column's NOT NULL constraint, so generate an unusable random one
        # via the same PBKDF2 helper used everywhere else (cosmetic use only).
        try:
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,active,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?,?)",
                (username,display,email,"Member","",password_hash(secrets.token_urlsafe(48)),1 if active else 0,now(),actor["instance_id"]))
        except sqlite3.IntegrityError:
            return self.scim_error(409,"A user with that userName already exists")
        row=db.execute("SELECT * FROM users WHERE username=? AND instance_id=?",(username,actor["instance_id"])).fetchone()
        append_audit(db,None,"admin.user_created",f"{username} via SCIM",actor["display_name"],actor["instance_id"]); db.commit()
        return self.send_json(scim_user_document(dict(row)),201)

    def scim_patch_user(self, db, actor, resource_id):
        try: uid=int(resource_id)
        except ValueError: return self.scim_error(404,"Not found")
        row=db.execute("SELECT * FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
        if not row: return self.scim_error(404,"User not found")
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.scim_error(400,str(exc))
        sets={}
        for operation in payload.get("Operations",[]):
            op=str(operation.get("op","replace")).lower()
            path_attr=str(operation.get("path") or "").lower()
            value=operation.get("value")
            attrs={}
            if path_attr and value is not None: attrs={path_attr:value}
            elif isinstance(value,dict): attrs={k.lower():v for k,v in value.items()}
            for attr,attr_value in attrs.items():
                if attr=="active": sets["active"]=1 if (attr_value if op!="remove" else False) else 0
                elif attr in ("displayname","name.formatted"): sets["display_name"]=str(attr_value)[:160]
                elif attr in ("emails","emails[type eq \"work\"].value"):
                    if isinstance(attr_value,list) and attr_value: sets["email"]=str(attr_value[0].get("value",""))[:180]
                    elif isinstance(attr_value,str): sets["email"]=attr_value[:180]
        if sets:
            sets_sql=",".join(f"{k}=?" for k in sets); values=list(sets.values())+[uid]
            db.execute(f"UPDATE users SET {sets_sql} WHERE id=?",values)
            append_audit(db,None,"admin.user_updated",f"{row['username']} via SCIM",actor["display_name"],actor["instance_id"]); db.commit()
        updated=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        return self.send_json(scim_user_document(dict(updated)))

    def scim_delete_user(self, db, actor, resource_id):
        try: uid=int(resource_id)
        except ValueError: return self.scim_error(404,"Not found")
        row=db.execute("SELECT * FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
        if not row: return self.scim_error(404,"User not found")
        # FlowOps never hard-deletes users anywhere else in the app (audit
        # rows, task ownership, etc. all reference user ids) -- SCIM DELETE
        # is implemented as deprovisioning (active=0), consistent with that
        # existing soft-delete convention, not a literal row deletion.
        db.execute("UPDATE users SET active=0 WHERE id=?",(uid,))
        db.execute("DELETE FROM sessions WHERE user_id=?",(uid,))
        append_audit(db,None,"admin.user_deleted",f"{row['username']} deprovisioned via SCIM",actor["display_name"],actor["instance_id"]); db.commit()
        self.send_response(204); self.end_headers()

    def scim_default_workspace_id(self, db, instance_id):
        row=db.execute("SELECT id FROM workspaces WHERE instance_id=? ORDER BY id LIMIT 1",(instance_id,)).fetchone()
        return row["id"] if row else None

    def scim_list_groups(self, db, actor, query):
        teams=[dict(r) for r in db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE w.instance_id=? ORDER BY ct.id",(actor["instance_id"],))]
        start_index,count=self.scim_paginate(query,len(teams))
        page=teams[start_index-1:start_index-1+count] if count else []
        docs=[]
        for team in page:
            members=rows(db.execute("SELECT u.id,u.display_name FROM users u JOIN central_team_members ctm ON ctm.user_id=u.id WHERE ctm.team_id=?",(team["id"],)))
            docs.append(scim_group_document(team,members))
        return self.send_json({"schemas":[SCIM_LIST_SCHEMA],"totalResults":len(teams),"startIndex":start_index,"itemsPerPage":len(docs),"Resources":docs})

    def scim_get_group(self, db, actor, resource_id):
        try: tid=int(resource_id)
        except ValueError: return self.scim_error(404,"Not found")
        team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(tid,actor["instance_id"])).fetchone()
        if not team: return self.scim_error(404,"Group not found")
        members=rows(db.execute("SELECT u.id,u.display_name FROM users u JOIN central_team_members ctm ON ctm.user_id=u.id WHERE ctm.team_id=?",(tid,)))
        return self.send_json(scim_group_document(dict(team),members))

    def scim_create_group(self, db, actor):
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.scim_error(400,str(exc))
        name=str(payload.get("displayName","")).strip()[:160]
        if not name: return self.scim_error(400,"displayName is required")
        workspace_id=self.scim_default_workspace_id(db,actor["instance_id"])
        if not workspace_id: return self.scim_error(409,"No workspace exists yet to provision this group into")
        try: cur=db.execute("INSERT INTO central_teams(workspace_id,name,created_at) VALUES(?,?,?)",(workspace_id,name,now()))
        except sqlite3.IntegrityError: return self.scim_error(409,"A group with that displayName already exists")
        tid=cur.lastrowid
        for member in payload.get("members") or []:
            try: uid=int(member.get("value"))
            except (TypeError,ValueError): continue
            if db.execute("SELECT 1 FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone():
                db.execute("INSERT OR IGNORE INTO central_team_members(team_id,user_id) VALUES(?,?)",(tid,uid))
        append_audit(db,None,"central_team.created",f"{name} via SCIM",actor["display_name"],actor["instance_id"]); db.commit()
        team=db.execute("SELECT * FROM central_teams WHERE id=?",(tid,)).fetchone()
        members=rows(db.execute("SELECT u.id,u.display_name FROM users u JOIN central_team_members ctm ON ctm.user_id=u.id WHERE ctm.team_id=?",(tid,)))
        return self.send_json(scim_group_document(dict(team),members),201)

    def scim_patch_group(self, db, actor, resource_id):
        try: tid=int(resource_id)
        except ValueError: return self.scim_error(404,"Not found")
        team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(tid,actor["instance_id"])).fetchone()
        if not team: return self.scim_error(404,"Group not found")
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.scim_error(400,str(exc))
        for operation in payload.get("Operations",[]):
            op=str(operation.get("op","add")).lower()
            path_attr=str(operation.get("path") or "").lower()
            value=operation.get("value")
            if path_attr not in ("members","") : continue
            if op in ("add","replace") and isinstance(value,list):
                if op=="replace": db.execute("DELETE FROM central_team_members WHERE team_id=?",(tid,))
                for member in value:
                    try: uid=int(member.get("value"))
                    except (TypeError,ValueError): continue
                    if db.execute("SELECT 1 FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone():
                        db.execute("INSERT OR IGNORE INTO central_team_members(team_id,user_id) VALUES(?,?)",(tid,uid))
            elif op=="remove" and isinstance(value,list):
                for member in value:
                    try: uid=int(member.get("value"))
                    except (TypeError,ValueError): continue
                    db.execute("DELETE FROM central_team_members WHERE team_id=? AND user_id=?",(tid,uid))
            elif op=="remove" and not value:
                db.execute("DELETE FROM central_team_members WHERE team_id=?",(tid,))
        if "displayName" in payload:
            name=str(payload["displayName"]).strip()[:160]
            if name: db.execute("UPDATE central_teams SET name=? WHERE id=?",(name,tid))
        append_audit(db,None,"central_team.member_added",f"{team['name']} via SCIM",actor["display_name"],actor["instance_id"]); db.commit()
        updated=db.execute("SELECT * FROM central_teams WHERE id=?",(tid,)).fetchone()
        members=rows(db.execute("SELECT u.id,u.display_name FROM users u JOIN central_team_members ctm ON ctm.user_id=u.id WHERE ctm.team_id=?",(tid,)))
        return self.send_json(scim_group_document(dict(updated),members))

    def scim_delete_group(self, db, actor, resource_id):
        try: tid=int(resource_id)
        except ValueError: return self.scim_error(404,"Not found")
        team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(tid,actor["instance_id"])).fetchone()
        if not team: return self.scim_error(404,"Group not found")
        if db.execute("SELECT COUNT(*) FROM runbook_teams WHERE central_team_id=?",(tid,)).fetchone()[0]:
            return self.scim_error(409,"This group is linked to a runbook team and cannot be removed via SCIM. Unlink it in FlowOps first.")
        db.execute("DELETE FROM central_teams WHERE id=?",(tid,))
        append_audit(db,None,"central_team.deleted",f"{team['name']} via SCIM",actor["display_name"],actor["instance_id"]); db.commit()
        self.send_response(204); self.end_headers()

    def _get_scim(self, path):
        if path.startswith("/scim/v2/"): return self.scim_dispatch()
        return NOT_HANDLED

    def _post_scim(self, path):
        if path.startswith("/scim/v2/"): return self.scim_dispatch()
        return NOT_HANDLED

    def _patch_scim(self, path, parts):
        if path.startswith("/scim/v2/"): return self.scim_dispatch()
        return NOT_HANDLED

    def _delete_scim(self, path, parts, parsed):
        if path.startswith("/scim/v2/"): return self.scim_dispatch()
        return NOT_HANDLED
