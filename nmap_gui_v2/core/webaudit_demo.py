"""Resultados de auditoría web de EJEMPLO para la red de demostración.

La demostración usa direcciones ficticias que podrían coincidir con equipos
reales de quien la use, así que nunca se conecta a ellas: muestra estos datos.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .webaudit import HttpInfo, TlsInfo, WebResult, WebTarget, evaluate

_ALL_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def _tls(version, days, self_signed=True, subject="CN=equipo.local", issuer=None, legacy=()):
    return TlsInfo(version=version, cipher="TLS_AES_128_GCM_SHA256" if version == "TLSv1.3" else
                   "ECDHE-RSA-AES128-GCM-SHA256", subject=subject, issuer=issuer or subject,
                   not_after=datetime.now(timezone.utc) + timedelta(days=days), days_left=days,
                   self_signed=self_signed, key_bits=2048, signature="sha256",
                   legacy=list(legacy), legacy_checked=True)


_EXAMPLES = {
    ("192.168.1.1", 80): (HttpInfo(200, {"server": "lighttpd/1.4.59"}), None),
    ("192.168.1.1", 443): (HttpInfo(200, {"server": "lighttpd/1.4.59", "x-frame-options": "SAMEORIGIN"}),
                           _tls("TLSv1.3", 2400, subject="CN=router.local")),
    ("192.168.1.20", 80): (HttpInfo(301, {"server": "nginx", "location": "https://192.168.1.20/"},
                                    location="https://192.168.1.20/"), None),
    ("192.168.1.20", 443): (HttpInfo(200, {"server": "nginx", "strict-transport-security": "max-age=15768000",
                                           "x-frame-options": "SAMEORIGIN", "x-content-type-options": "nosniff"}),
                            _tls("TLSv1.2", 18, subject="CN=synology", legacy=("TLS 1.0",))),
    ("192.168.1.33", 80): (HttpInfo(401, {"server": "Hikvision-Webs",
                                          "www-authenticate": 'Basic realm="IP Camera"'}), None),
    ("192.168.1.33", 8080): (HttpInfo(200, {"server": "Hikvision-Webs"}, cookies=["WebSession=7f3a9c; path=/"]), None),
    ("192.168.1.40", 80): (HttpInfo(200, {"server": "HP HTTP Server"}), None),
    ("10.20.0.5", 443): (HttpInfo(200, {"server": "nginx", **_ALL_HEADERS}),
                         _tls("TLSv1.3", 61, self_signed=False, subject="CN=servicio.ejemplo",
                              issuer="CN=R11,O=Let's Encrypt,C=US")),
}


def demo_results(targets: list[WebTarget]) -> list[WebResult]:
    tls_hosts = {t.host for t in targets if t.tls}
    out = []
    for t in targets:
        http_info, tls = _EXAMPLES.get((t.host, t.port), (HttpInfo(200, {}), None))
        res = WebResult(t, http_info, tls, evaluate(t, http_info, tls, t.host in tls_hosts), example=True)
        out.append(res)
    return out
