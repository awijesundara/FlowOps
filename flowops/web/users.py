"""Administration of users, invitations and scoped role grants."""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

import flowops.mail
from flowops.audit import append_audit
from flowops.config import ROLE_PERMISSIONS
from flowops.crypto import password_hash
from flowops.db import connect, now, rows
from flowops.mail import mail_configuration
from flowops.runbooks import owns_runbook
from flowops.web.base import BaseHandler, NOT_HANDLED


class UserAdminRoutes(BaseHandler):
    def _get_users_db(self, db, path):
        if path=="/api/admin/users":
            actor=self.require(db,"admin:users")
            if not actor: return
            data=rows(db.execute("SELECT id,username,display_name,email,role,team,active,last_login_at,created_at FROM users WHERE instance_id=? ORDER BY display_name",(actor["instance_id"],)))
            return self.send_json({"data":data})
        if path=="/api/admin/scoped-role-grants":
            actor=self.require(db,"admin:users")
            if not actor: return
            workspace_managers=rows(db.execute("SELECT wm.user_id,u.display_name,wm.workspace_id,w.name workspace_name FROM workspace_managers wm JOIN users u ON u.id=wm.user_id JOIN workspaces w ON w.id=wm.workspace_id WHERE u.instance_id=? ORDER BY u.display_name",(actor["instance_id"],)))
            folder_creators=rows(db.execute("SELECT fc.user_id,u.display_name,fc.folder_id,f.name folder_name FROM folder_creator_grants fc JOIN users u ON u.id=fc.user_id JOIN folders f ON f.id=fc.folder_id WHERE u.instance_id=? ORDER BY u.display_name",(actor["instance_id"],)))
            stream_editors=rows(db.execute("SELECT se.user_id,u.display_name,se.runbook_id,r.name runbook_name FROM stream_editor_grants se JOIN users u ON u.id=se.user_id JOIN runbooks r ON r.id=se.runbook_id WHERE u.instance_id=? ORDER BY u.display_name",(actor["instance_id"],)))
            return self.send_json({"data":{"workspace_managers":workspace_managers,"folder_creators":folder_creators,"stream_editors":stream_editors}})
        return NOT_HANDLED

    def _post_users_db(self, db, path, payload):
        if path=="/api/admin/users":
            actor=self.require(db,"admin:users")
            if not actor:return
            username=str(payload.get("username","")).strip(); display=str(payload.get("display_name","")).strip(); role=str(payload.get("role","Member")); password=str(payload.get("password", ""))
            if not username or not display or role not in ROLE_PERMISSIONS or len(password)<12:return self.send_json({"error":"Username, display name, valid role, and password of at least 12 characters are required"},400)
            try: db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,str(payload.get("email",""))[:180],role,str(payload.get("team",""))[:120],password_hash(password),now(),actor["instance_id"]))
            except sqlite3.IntegrityError:return self.send_json({"error":"That username already exists"},409)
            append_audit(db,None,"admin.user_created",f"{username} as {role}",actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}},201)
        if path=="/api/admin/workspace-managers":
            actor=self.require(db,"admin:users")
            if not actor:return
            user_id=int(payload.get("user_id") or 0); workspace_id=int(payload.get("workspace_id") or 0)
            target=db.execute("SELECT display_name FROM users WHERE id=? AND instance_id=?",(user_id,actor["instance_id"])).fetchone()
            workspace=db.execute("SELECT name FROM workspaces WHERE id=? AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone()
            if not target or not workspace:return self.send_json({"error":"Invalid user or workspace"},400)
            db.execute("INSERT OR IGNORE INTO workspace_managers(user_id,workspace_id) VALUES(?,?)",(user_id,workspace_id))
            append_audit(db,None,"admin.workspace_manager_granted",f"{target['display_name']} → {workspace['name']}",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"ok":True}},201)
        if path=="/api/admin/folder-creators":
            actor=self.require(db,"admin:users")
            if not actor:return
            user_id=int(payload.get("user_id") or 0); folder_id=int(payload.get("folder_id") or 0)
            target=db.execute("SELECT display_name FROM users WHERE id=? AND instance_id=?",(user_id,actor["instance_id"])).fetchone()
            folder=db.execute("SELECT f.name FROM folders f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.instance_id=?",(folder_id,actor["instance_id"])).fetchone()
            if not target or not folder:return self.send_json({"error":"Invalid user or folder"},400)
            db.execute("INSERT OR IGNORE INTO folder_creator_grants(user_id,folder_id) VALUES(?,?)",(user_id,folder_id))
            append_audit(db,None,"admin.folder_creator_granted",f"{target['display_name']} → {folder['name']}",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"ok":True}},201)
        if path=="/api/admin/stream-editors":
            actor=self.require(db,"admin:users")
            if not actor:return
            user_id=int(payload.get("user_id") or 0); runbook_id=int(payload.get("runbook_id") or 0)
            target=db.execute("SELECT display_name FROM users WHERE id=? AND instance_id=?",(user_id,actor["instance_id"])).fetchone()
            if not target or not owns_runbook(db,runbook_id,actor["instance_id"]):return self.send_json({"error":"Invalid user or runbook"},400)
            db.execute("INSERT OR IGNORE INTO stream_editor_grants(user_id,runbook_id) VALUES(?,?)",(user_id,runbook_id))
            append_audit(db,runbook_id,"admin.stream_editor_granted",f"{target['display_name']}",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"ok":True}},201)
        if path=="/api/admin/invitations":
            actor=self.require(db,"admin:users")
            if not actor:return
            email=str(payload.get("email","")).strip().lower(); role=str(payload.get("role","Member"))
            if "@" not in email or role not in ROLE_PERMISSIONS:return self.send_json({"error":"A valid email and role are required"},400)
            preview=os.getenv("FLOWOPS_PREVIEW_TOKENS","false").lower()=="true";mail=mail_configuration()
            if not preview and not mail["configured"]:return self.send_json({"error":"Email delivery is not configured. Configure server-side SMTP before inviting users."},503)
            raw=secrets.token_urlsafe(28); db.execute("INSERT INTO invitations(email,role,token_hash,expires_at,created_by,created_at,instance_id) VALUES(?,?,?,?,?,?,?)",(email,role,hashlib.sha256(raw.encode()).hexdigest(),int(time.time())+7*86400,actor["id"],now(),actor["instance_id"])); append_audit(db,None,"admin.user_invited",f"{email} as {role}",actor["display_name"],actor["instance_id"])
            if not preview:
                try: flowops.mail.send_mail(email,"You are invited to FlowOps",f"You have been invited to FlowOps as {role}.\n\nAccept this invitation within seven days:\n{mail['public_url']}/?invite={urllib.parse.quote(raw)}\n\nIf you were not expecting this invitation, ignore this email.")
                except RuntimeError as exc: db.rollback();return self.send_json({"error":str(exc)},502)
            db.commit();response={"email":email,"role":role,"expires_in_days":7,"delivery":"preview" if preview else "email"}
            if preview:response["invite_token"]=raw
            return self.send_json({"data":response},201)
        return NOT_HANDLED

    def _patch_users(self, path, parts, payload):
        if len(parts)==4 and parts[:3]==["api","admin","users"]:
            try: uid=int(parts[3])
            except ValueError:return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                user=db.execute("SELECT * FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
                if not user:return self.send_json({"error":"User not found"},404)
                role=str(payload.get("role",user["role"])); active=1 if payload.get("active",bool(user["active"])) else 0
                if role not in ROLE_PERMISSIONS:return self.send_json({"error":"Invalid role"},400)
                if uid==actor["id"] and (role!="Admin" or not active):return self.send_json({"error":"You cannot remove your own administrator access"},409)
                password=payload.get("password")
                if password is not None and len(str(password))<12:return self.send_json({"error":"Password must be at least 12 characters"},400)
                db.execute("UPDATE users SET display_name=?,email=?,role=?,team=?,active=? WHERE id=?",(str(payload.get("display_name",user["display_name"]))[:120],str(payload.get("email",user["email"]))[:180],role,str(payload.get("team",user["team"]))[:120],active,uid))
                if password is not None: db.execute("UPDATE users SET password_hash=? WHERE id=?",(password_hash(str(password)),uid)); db.execute("DELETE FROM sessions WHERE user_id=?",(uid,))
                append_audit(db,None,"admin.user_updated",f"{user['username']}: role={role}, active={bool(active)}",actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}})
        return NOT_HANDLED

    def _delete_users(self, path, parts, parsed):
        if len(parts)==5 and parts[:3]==["api","admin","workspace-managers"]:
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                try: user_id,workspace_id=int(parts[3]),int(parts[4])
                except ValueError: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM workspace_managers WHERE user_id=? AND workspace_id=? AND EXISTS(SELECT 1 FROM workspaces w WHERE w.id=? AND w.instance_id=?)",(user_id,workspace_id,workspace_id,actor["instance_id"]))
                append_audit(db,None,"admin.workspace_manager_revoked",f"user {user_id} × workspace {workspace_id}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==5 and parts[:3]==["api","admin","folder-creators"]:
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                try: user_id,folder_id=int(parts[3]),int(parts[4])
                except ValueError: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM folder_creator_grants WHERE user_id=? AND folder_id=? AND EXISTS(SELECT 1 FROM folders f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.instance_id=?)",(user_id,folder_id,folder_id,actor["instance_id"]))
                append_audit(db,None,"admin.folder_creator_revoked",f"user {user_id} × folder {folder_id}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==5 and parts[:3]==["api","admin","stream-editors"]:
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                try: user_id,runbook_id=int(parts[3]),int(parts[4])
                except ValueError: return self.send_json({"error":"Not found"},404)
                if not owns_runbook(db,runbook_id,actor["instance_id"]):return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM stream_editor_grants WHERE user_id=? AND runbook_id=?",(user_id,runbook_id))
                append_audit(db,runbook_id,"admin.stream_editor_revoked",f"user {user_id}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        return NOT_HANDLED

    def _delete_users_tail(self, path, parts, parsed):
        if len(parts)!=4 or parts[:3]!=["api","admin","users"]:return self.send_json({"error":"Not found"},404)
        try:uid=int(parts[3])
        except ValueError:return self.send_json({"error":"Not found"},404)
        with connect() as db:
            actor=self.require(db,"admin:users")
            if not actor:return
            if uid==actor["id"]:return self.send_json({"error":"You cannot delete your own account"},409)
            user=db.execute("SELECT username FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
            if not user:return self.send_json({"error":"User not found"},404)
            db.execute("DELETE FROM users WHERE id=?",(uid,)); append_audit(db,None,"admin.user_deleted",user["username"],actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}})
