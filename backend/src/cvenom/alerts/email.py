"""Plain-text email sink (aiosmtplib). Content comes from the Cve/AlertRule rows only."""

from __future__ import annotations

import asyncio
import re
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import getaddresses

import aiosmtplib

from cvenom.alerts.sinks import SinkError, SinkNotConfigured, clean_summary
from cvenom.config import get_settings
from cvenom.models import AlertDelivery, AlertRecipient, AlertRule, Cve

SUBJECT_MAX = 200
SEND_TIMEOUT_S = 30  # overall bound (connect + TLS + auth + DATA)
_HEADER_BAD = re.compile(r"[\x00-\x1f\x7f\x85  ]")


def _na(value) -> str:
    return "n/a" if value is None else str(value)


class EmailSink:
    def __init__(self, settings=None):
        self._settings = settings

    def _cfg(self):
        return self._settings if self._settings is not None else get_settings()

    def send(self, delivery: AlertDelivery, cve: Cve, rule: AlertRule,
             recipient: AlertRecipient) -> None:
        try:
            asyncio.run(asyncio.wait_for(self._send(cve, rule, recipient), SEND_TIMEOUT_S))
        except SinkError:
            raise
        except Exception as exc:
            raise SinkError(f"smtp error: {type(exc).__name__}") from None

    async def _send(self, cve: Cve, rule: AlertRule, recipient: AlertRecipient) -> None:
        st = self._cfg()
        if not st.smtp_host or not st.smtp_from_addr or not recipient.email:
            raise SinkNotConfigured("smtp not configured")
        # Exactly one plain address: never let a stored value fan out to others.
        addr = recipient.email.strip()
        parsed = getaddresses([recipient.email])
        if len(parsed) != 1 or parsed[0][1] != addr or "@" not in addr:
            raise SinkError("smtp error: invalid recipient")
        try:
            msg = EmailMessage(policy=SMTP)
            subject = _HEADER_BAD.sub("", f"[CVEnom] {cve.cve_id} exploited in the wild")
            msg["Subject"] = subject[:SUBJECT_MAX]
            msg["From"] = st.smtp_from_addr
            msg["To"] = addr
            kev_added = cve.kev_added.isoformat() if cve.kev_added else "n/a"
            msg.set_content(
                "\n".join([
                    f"CVE: {cve.cve_id}",
                    f"Rule: {rule.name}",
                    f"CVSS: {_na(cve.cvss)}",
                    f"EPSS percentile: {_na(cve.epss_percentile)}",
                    f"KEV source: {_na(cve.kev_source)}",
                    f"Added to KEV: {kev_added}",
                    "",
                    clean_summary(cve.summary),
                    "",
                    f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
                    "",
                ])
            )
            kwargs: dict = {"hostname": st.smtp_host, "port": st.smtp_port, "timeout": 15}
            if st.smtp_port == 465:
                kwargs["use_tls"] = True
            else:
                kwargs["start_tls"] = st.smtp_starttls
            if st.smtp_username:
                kwargs["username"] = st.smtp_username
            if st.smtp_password is not None:
                kwargs["password"] = st.smtp_password.get_secret_value()
            await aiosmtplib.send(msg, recipients=[addr], **kwargs)
        except Exception as exc:
            # Never include str(exc): SMTP errors can echo usernames and server banners.
            raise SinkError(f"smtp error: {type(exc).__name__}") from None
