"""Workspaces, folders, templates, snippets, saved views, types, custom fields and central teams."""
from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request

import flowops.runbooks
from flowops.audit import append_audit
from flowops.db import connect, now, rows
from flowops.web.base import BaseHandler, NOT_HANDLED


class CatalogRoutes(BaseHandler):
    def _get_catalog_db(self, db, path):
        if path=="/api/saved-views":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            items=rows(db.execute("SELECT id,name,filters_json,created_at FROM saved_views WHERE user_id=? ORDER BY name",(actor["id"],)))
            for item in items: item["filters"]=json.loads(item.pop("filters_json") or "{}")
            return self.send_json({"data":items})
        if path=="/api/workspaces":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            return self.send_json({"data":rows(db.execute("SELECT id,name,description,color FROM workspaces WHERE active=1 AND instance_id=? ORDER BY name",(actor["instance_id"],)))})
        if path=="/api/folders":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            items=rows(db.execute("SELECT f.*,COUNT(r.id) runbook_count FROM folders f JOIN workspaces w ON w.id=f.workspace_id LEFT JOIN runbooks r ON r.folder_id=f.id WHERE w.instance_id=? GROUP BY f.id ORDER BY f.sort_order,f.name",(actor["instance_id"],)))
            return self.send_json({"data":items})
        if path=="/api/runbook-types":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            items=rows(db.execute("SELECT rt.*,COUNT(r.id) runbook_count FROM runbook_types rt JOIN workspaces w ON w.id=rt.workspace_id LEFT JOIN runbooks r ON r.runbook_type_id=rt.id WHERE w.instance_id=? GROUP BY rt.id ORDER BY rt.name",(actor["instance_id"],)))
            return self.send_json({"data":items})
        if path=="/api/central-teams":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            teams=rows(db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE w.instance_id=? ORDER BY ct.name",(actor["instance_id"],)))
            for team in teams:
                team["members"]=rows(db.execute("SELECT u.id,u.display_name,u.email FROM users u JOIN central_team_members ctm ON ctm.user_id=u.id WHERE ctm.team_id=? ORDER BY u.display_name",(team["id"],)))
                team["linked_runbooks"]=db.execute("SELECT COUNT(*) FROM runbook_teams WHERE central_team_id=?",(team["id"],)).fetchone()[0]
            return self.send_json({"data":teams})
        if path=="/api/custom-fields":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            entity_type=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("entity_type",[None])[0]
            clause="AND cfd.entity_type=?" if entity_type else ""
            params=[actor["instance_id"]]+([entity_type] if entity_type else [])
            items=rows(db.execute(f"SELECT cfd.* FROM custom_field_definitions cfd JOIN workspaces w ON w.id=cfd.workspace_id WHERE w.instance_id=? {clause} ORDER BY cfd.entity_type,cfd.sort_order",params))
            for item in items: item["options"]=json.loads(item.pop("options_json") or "[]")
            return self.send_json({"data":items})
        if path=="/api/templates":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            workspace_id=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("workspace_id",[None])[0]
            clause="AND t.workspace_id=?" if workspace_id else ""
            params=[actor["instance_id"]]+([int(workspace_id)] if workspace_id else [])
            items=rows(db.execute(f"SELECT t.*,COUNT(tt.id) task_count FROM templates t JOIN workspaces w ON w.id=t.workspace_id LEFT JOIN template_tasks tt ON tt.template_id=t.id WHERE w.instance_id=? {clause} GROUP BY t.id ORDER BY t.category,t.name",params))
            return self.send_json({"data":items})
        if path=="/api/snippets":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            workspace_id=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("workspace_id",[None])[0]
            clause="AND s.workspace_id=?" if workspace_id else ""
            params=[actor["instance_id"]]+([int(workspace_id)] if workspace_id else [])
            items=rows(db.execute(f"SELECT s.*,COUNT(st.id) task_count FROM snippets s JOIN workspaces w ON w.id=s.workspace_id LEFT JOIN snippet_tasks st ON st.snippet_id=s.id WHERE w.instance_id=? {clause} GROUP BY s.id ORDER BY s.name",params))
            return self.send_json({"data":items})
        return NOT_HANDLED

    def _post_catalog_db(self, db, path, payload):
        parts_central=path.strip("/").split("/")
        parts=path.strip("/").split("/")
        if path=="/api/folders":
            actor=self.require(db,"runbooks:edit")
            if not actor:return
            name=str(payload.get("name","")).strip()
            if not name or len(name)>120: return self.send_json({"error":"Folder name is required (maximum 120 characters)"},400)
            workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
            if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                return self.send_json({"error":"Select an active workspace"},400)
            parent_folder_id=int(payload["parent_folder_id"]) if payload.get("parent_folder_id") else None
            if parent_folder_id and not db.execute("SELECT 1 FROM folders WHERE id=? AND workspace_id=?",(parent_folder_id,workspace_id)).fetchone():
                return self.send_json({"error":"Invalid parent folder"},400)
            order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM folders WHERE workspace_id=?",(workspace_id,)).fetchone()[0]
            try: cur=db.execute("INSERT INTO folders(workspace_id,name,sort_order,created_at,parent_folder_id) VALUES(?,?,?,?,?)",(workspace_id,name,order,now(),parent_folder_id))
            except sqlite3.IntegrityError: return self.send_json({"error":"That folder already exists"},409)
            append_audit(db,None,"folder.created",name,actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"id":cur.lastrowid,"name":name,"parent_folder_id":parent_folder_id}},201)
        if path=="/api/saved-views":
            actor=self.require(db,"runbooks:view")
            if not actor:return
            name=str(payload.get("name","")).strip()
            if not name or len(name)>120: return self.send_json({"error":"View name is required (maximum 120 characters)"},400)
            filters=payload.get("filters") if isinstance(payload.get("filters"),dict) else {}
            try: cur=db.execute("INSERT INTO saved_views(user_id,name,filters_json,created_at) VALUES(?,?,?,?)",(actor["id"],name,json.dumps(filters),now()))
            except sqlite3.IntegrityError: return self.send_json({"error":"You already have a saved view with that name"},409)
            db.commit()
            return self.send_json({"data":{"id":cur.lastrowid,"name":name,"filters":filters}},201)
        if path=="/api/runbook-types":
            actor=self.require(db,"runbooks:edit")
            if not actor:return
            name=str(payload.get("name","")).strip()
            if not name or len(name)>80: return self.send_json({"error":"Runbook type name is required (maximum 80 characters)"},400)
            workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
            if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                return self.send_json({"error":"Select an active workspace"},400)
            icon=str(payload.get("icon","◇")).strip()[:4] or "◇"
            color=str(payload.get("color","#7557e8")).strip()[:20] or "#7557e8"
            requires_approval=1 if payload.get("requires_approval") else 0
            try: cur=db.execute("INSERT INTO runbook_types(workspace_id,name,icon,color,default_description,requires_approval,created_at) VALUES(?,?,?,?,?,?,?)",(workspace_id,name,icon,color,str(payload.get("default_description",""))[:2000],requires_approval,now()))
            except sqlite3.IntegrityError: return self.send_json({"error":"That runbook type already exists"},409)
            append_audit(db,None,"runbook_type.created",name,actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
        if path=="/api/central-teams":
            actor=self.require(db,"admin:users")
            if not actor:return
            name=str(payload.get("name","")).strip()
            if not name or len(name)>120: return self.send_json({"error":"Team name is required (maximum 120 characters)"},400)
            workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
            if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                return self.send_json({"error":"Select an active workspace"},400)
            try: cur=db.execute("INSERT INTO central_teams(workspace_id,name,created_at) VALUES(?,?,?)",(workspace_id,name,now()))
            except sqlite3.IntegrityError: return self.send_json({"error":"That central team already exists"},409)
            append_audit(db,None,"central_team.created",name,actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
        if path=="/api/custom-fields":
            actor=self.require(db,"admin:users")
            if not actor:return
            name=str(payload.get("name","")).strip()
            entity_type=str(payload.get("entity_type",""))
            field_type=str(payload.get("field_type","text"))
            if not name or len(name)>80: return self.send_json({"error":"Field name is required (maximum 80 characters)"},400)
            if entity_type not in {"runbook","task"}: return self.send_json({"error":"entity_type must be 'runbook' or 'task'"},400)
            if field_type not in {"text","number","date","boolean","select"}: return self.send_json({"error":"Invalid field type"},400)
            options=[str(o)[:80] for o in payload.get("options",[]) if isinstance(o,str)][:30] if field_type=="select" else []
            workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
            if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                return self.send_json({"error":"Select an active workspace"},400)
            order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM custom_field_definitions WHERE workspace_id=? AND entity_type=?",(workspace_id,entity_type)).fetchone()[0]
            try: cur=db.execute("INSERT INTO custom_field_definitions(workspace_id,entity_type,name,field_type,options_json,required,sort_order,created_at) VALUES(?,?,?,?,?,?,?,?)",(workspace_id,entity_type,name,field_type,json.dumps(options),1 if payload.get("required") else 0,order,now()))
            except sqlite3.IntegrityError: return self.send_json({"error":"That field already exists for this entity type"},409)
            append_audit(db,None,"custom_field.created",f"{entity_type}: {name} ({field_type})",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
        if len(parts_central)==4 and parts_central[:2]==["api","central-teams"] and parts_central[3]=="members":
            actor=self.require(db,"admin:users")
            if not actor:return
            try: central_team_id=int(parts_central[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
            if not team: return self.send_json({"error":"Not found"},404)
            user_id=int(payload.get("user_id",0))
            if not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(user_id,actor["instance_id"])).fetchone():
                return self.send_json({"error":"User is invalid"},400)
            db.execute("INSERT OR IGNORE INTO central_team_members(team_id,user_id) VALUES(?,?)",(central_team_id,user_id))
            append_audit(db,None,"central_team.member_added",team["name"],actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"ok":True}},201)
        if len(parts)==4 and parts[:2]==["api","templates"] and parts[3]=="use":
            actor=self.require(db,"runbooks:edit")
            if not actor:return
            try: template_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            template=db.execute("SELECT t.* FROM templates t JOIN workspaces w ON w.id=t.workspace_id WHERE t.id=? AND w.instance_id=?",(template_id,actor["instance_id"])).fetchone()
            if not template: return self.send_json({"error":"Not found"},404)
            name=str(payload.get("name","")).strip() or template["name"]
            workspace_id=template["workspace_id"]
            stamp=now()
            cur=db.execute("INSERT INTO runbooks(name,description,owner,scheduled_at,workspace_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(name[:160],template["description"],str(payload.get("owner",""))[:120],payload.get("scheduled_at") or None,workspace_id,stamp,stamp))
            new_rid=cur.lastrowid
            for s in db.execute("SELECT DISTINCT stream FROM template_tasks WHERE template_id=? ORDER BY sort_order",(template_id,)):
                order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(new_rid,)).fetchone()[0]
                db.execute("INSERT OR IGNORE INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(new_rid,s["stream"],order,stamp))
            id_map={}
            for t in db.execute("SELECT * FROM template_tasks WHERE template_id=? ORDER BY sort_order",(template_id,)):
                new_tid=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset) VALUES(?,?,?,?,?,?,?,?,?,?)",(new_rid,t["title"],t["description"],t["stream"],"",t["duration"],t["sort_order"],t["automation_url"],t["task_type"],t["scheduled_offset"])).lastrowid
                id_map[t["id"]]=new_tid
            for dep in db.execute("SELECT template_task_id,depends_on_template_task_id FROM template_dependencies td JOIN template_tasks tt ON tt.id=td.template_task_id WHERE tt.template_id=?",(template_id,)):
                if dep["template_task_id"] in id_map and dep["depends_on_template_task_id"] in id_map:
                    db.execute("INSERT INTO dependencies VALUES(?,?)",(id_map[dep["template_task_id"]],id_map[dep["depends_on_template_task_id"]]))
            append_audit(db,new_rid,"runbook.created",f"Created from template: {template['name']}",actor["display_name"]); doc=flowops.runbooks.runbook_document(db,new_rid,actor); db.commit()
            return self.send_json({"data":doc},201)
        return NOT_HANDLED

    def _delete_catalog(self, path, parts, parsed):
        if len(parts)==3 and parts[:2]==["api","saved-views"]:
            with connect() as db:
                actor=self.require(db,"runbooks:view")
                if not actor:return
                try: view_id=int(parts[2])
                except ValueError: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM saved_views WHERE id=? AND user_id=?",(view_id,actor["id"])); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","templates"]:
            try: template_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                template=db.execute("SELECT t.* FROM templates t JOIN workspaces w ON w.id=t.workspace_id WHERE t.id=? AND w.instance_id=?",(template_id,actor["instance_id"])).fetchone()
                if not template: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM templates WHERE id=?",(template_id,)); append_audit(db,None,"template.deleted",template["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","folders"]:
            try: folder_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                folder=db.execute("SELECT f.* FROM folders f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.instance_id=?",(folder_id,actor["instance_id"])).fetchone()
                if not folder: return self.send_json({"error":"Not found"},404)
                if db.execute("SELECT COUNT(*) FROM runbooks WHERE folder_id=?",(folder_id,)).fetchone()[0]:
                    return self.send_json({"error":"Move or remove this folder's runbooks before deleting it"},409)
                db.execute("DELETE FROM folders WHERE id=?",(folder_id,)); append_audit(db,None,"folder.deleted",folder["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","snippets"]:
            try: snippet_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                snippet=db.execute("SELECT s.* FROM snippets s JOIN workspaces w ON w.id=s.workspace_id WHERE s.id=? AND w.instance_id=?",(snippet_id,actor["instance_id"])).fetchone()
                if not snippet: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM snippets WHERE id=?",(snippet_id,)); append_audit(db,None,"snippet.deleted",snippet["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","runbook-types"]:
            try: type_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                rtype=db.execute("SELECT rt.* FROM runbook_types rt JOIN workspaces w ON w.id=rt.workspace_id WHERE rt.id=? AND w.instance_id=?",(type_id,actor["instance_id"])).fetchone()
                if not rtype: return self.send_json({"error":"Not found"},404)
                if db.execute("SELECT COUNT(*) FROM runbooks WHERE runbook_type_id=?",(type_id,)).fetchone()[0]:
                    return self.send_json({"error":"Reassign this type's runbooks before deleting it"},409)
                db.execute("DELETE FROM runbook_types WHERE id=?",(type_id,)); append_audit(db,None,"runbook_type.deleted",rtype["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","custom-fields"]:
            try: definition_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                definition=db.execute("SELECT cfd.* FROM custom_field_definitions cfd JOIN workspaces w ON w.id=cfd.workspace_id WHERE cfd.id=? AND w.instance_id=?",(definition_id,actor["instance_id"])).fetchone()
                if not definition: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM custom_field_definitions WHERE id=?",(definition_id,)); append_audit(db,None,"custom_field.deleted",f"{definition['entity_type']}: {definition['name']}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==5 and parts[:2]==["api","central-teams"] and parts[3]=="members":
            try: central_team_id=int(parts[2]); user_id=int(parts[4])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
                if not team: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM central_team_members WHERE team_id=? AND user_id=?",(central_team_id,user_id))
                append_audit(db,None,"central_team.member_removed",team["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","central-teams"]:
            try: central_team_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
                if not team: return self.send_json({"error":"Not found"},404)
                if db.execute("SELECT COUNT(*) FROM runbook_teams WHERE central_team_id=?",(central_team_id,)).fetchone()[0]:
                    return self.send_json({"error":"Unlink this team from every runbook before deleting it"},409)
                db.execute("DELETE FROM central_teams WHERE id=?",(central_team_id,)); append_audit(db,None,"central_team.deleted",team["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        return NOT_HANDLED
