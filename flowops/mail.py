"""SMTP delivery."""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any



def mail_configuration() -> dict[str,Any]:
    host=os.getenv("FLOWOPS_SMTP_HOST","").strip(); sender=os.getenv("FLOWOPS_MAIL_FROM","").strip(); public_url=os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")
    return {"configured":bool(host and sender and public_url),"host":host,"port":int(os.getenv("FLOWOPS_SMTP_PORT","587")),"sender":sender,"public_url":public_url,"security":os.getenv("FLOWOPS_SMTP_SECURITY","starttls").strip().lower(),"username":os.getenv("FLOWOPS_SMTP_USERNAME","")}

def send_mail(recipient: str, subject: str, body: str) -> None:
    config=mail_configuration()
    if not config["configured"]: raise RuntimeError("Email delivery is not configured")
    message=EmailMessage();message["From"]=config["sender"];message["To"]=recipient;message["Subject"]=subject;message.set_content(body)
    password=os.getenv("FLOWOPS_SMTP_PASSWORD",""); security=config["security"]
    if security not in {"starttls","tls","none"}: raise RuntimeError("FLOWOPS_SMTP_SECURITY must be starttls, tls, or none")
    client_type=smtplib.SMTP_SSL if security=="tls" else smtplib.SMTP
    try:
        with client_type(config["host"],config["port"],timeout=10) as client:
            if security=="starttls": client.starttls(context=ssl.create_default_context())
            if config["username"]: client.login(config["username"],password)
            client.send_message(message)
    except (OSError,smtplib.SMTPException) as exc:
        raise RuntimeError("Email delivery failed") from exc
