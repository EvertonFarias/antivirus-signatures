"""Monta a base de ameaças (sha256.txt) a partir de fontes públicas. Roda no GitHub Actions.

Fontes:
- MalwareBazaar (abuse.ch): hashes SHA-256 de APKs maliciosos recentes. Precisa da variável
  MB_AUTH_KEY (chave gratuita em https://auth.abuse.ch/). Sem ela, mantém os hashes que já existem.
- Echap stalkerware-indicators (CC BY 4.0): nomes de pacote e certificados (SHA-1) de apps espiões.
  https://github.com/AssoEchap/stalkerware-indicators

Formato das linhas:
    <sha256>;<nome>            hash do APK
    pkg:<pacote>;<nome>        nome do pacote
    cert1:<sha1>;<nome>        certificado de assinatura
O SignDb.java recria a linha "#version=" ao assinar.

Escreve changed=true|false em $GITHUB_OUTPUT (informativo: o workflow assina todo dia).
"""

import json
import os
import re
import sys
import urllib.parse
import urllib.request

DB_PATH = "sha256.txt"
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
STALKERWARE_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
USER_AGENT = "signature-feed-updater"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")

HEADER = [
    "# Base de ameacas do MeowGuard: <sha256>;<nome> | pkg:<pacote>;<nome> | cert1:<sha1>;<nome>",
    "# Fontes: MalwareBazaar (abuse.ch); Echap stalkerware-indicators (CC BY 4.0)",
]


def load_hashes(path):
    """Hashes já existentes (acumulam ao longo do tempo)."""
    hashes = {}
    if not os.path.exists(path):
        return hashes
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, name = line.partition(";")
            key = key.strip().lower()
            if SHA256_RE.match(key):
                hashes[key] = name.strip() or "Android.Malware.Generic"
    return hashes


def fetch(url, data=None, headers=None, timeout=60):
    request = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_recent_apks(auth_key):
    body = urllib.parse.urlencode({"query": "get_file_type", "file_type": "apk", "limit": "1000"}).encode()
    payload = json.loads(fetch(MB_API_URL, data=body, headers={"Auth-Key": auth_key}))
    status = payload.get("query_status")
    if status != "ok":
        print(f"MalwareBazaar respondeu: {status}")
        return []
    return payload.get("data") or []


def threat_name(signature):
    family = re.sub(r"[^A-Za-z0-9._-]", "", signature or "")
    return f"Android.{family}" if family else "Android.Malware.Generic"


def parse_stalkerware(text):
    """Lê o ioc.yaml sem depender de bibliotecas (o formato é uma lista simples)."""
    apps, current, section = [], None, None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("- name:"):
            current = {"name": raw.split(":", 1)[1].strip(), "type": "", "packages": [], "certificates": []}
            apps.append(current)
            section = None
            continue
        if current is None:
            continue
        stripped = raw.strip()
        is_item = raw.startswith("  - ")
        if not is_item and stripped.startswith("type:"):
            current["type"] = stripped.split(":", 1)[1].strip()
            section = None
        elif not is_item and stripped.endswith(":"):
            section = stripped[:-1]
        elif is_item and section in ("packages", "certificates"):
            current[section].append(stripped[2:].strip().strip("'\""))
        elif not is_item:
            section = None
    return apps


def stalkerware_lines():
    try:
        apps = parse_stalkerware(fetch(STALKERWARE_URL).decode("utf-8"))
    except Exception as e:  # sem a lista hoje: o app continua com a da véspera
        print(f"Nao foi possivel baixar a lista de stalkerware: {e}")
        return None
    lines = []
    for app in apps:
        if app["type"] != "stalkerware":
            continue
        name = "Stalkerware." + (re.sub(r"[^A-Za-z0-9._-]", "", app["name"]) or "Generic")
        for package in app["packages"]:
            if PACKAGE_RE.match(package):
                lines.append(f"pkg:{package};{name}")
        for cert in app["certificates"]:
            cert = cert.lower()
            if SHA1_RE.match(cert):
                lines.append(f"cert1:{cert};{name}")
    lines = sorted(set(lines))
    print(f"Stalkerware: {len(lines)} indicador(es).")
    return lines


def previous_ioc_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.startswith(("pkg:", "cert1:"))]


def write_output(changed):
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")


def main():
    before = open(DB_PATH, encoding="utf-8").read() if os.path.exists(DB_PATH) else ""
    hashes = load_hashes(DB_PATH)

    auth_key = os.environ.get("MB_AUTH_KEY", "").strip()
    if auth_key:
        added = 0
        for sample in fetch_recent_apks(auth_key):
            sha = (sample.get("sha256_hash") or "").lower()
            if SHA256_RE.match(sha) and sha not in hashes:
                hashes[sha] = threat_name(sample.get("signature"))
                added += 1
        print(f"MalwareBazaar: {added} hash(es) novo(s); total {len(hashes)}.")
    else:
        print("MB_AUTH_KEY nao configurada: hashes do MalwareBazaar nao atualizados.")

    iocs = stalkerware_lines()
    if iocs is None:
        iocs = previous_ioc_lines(DB_PATH)

    version = [l for l in before.splitlines() if l.startswith("#version=")]
    lines = version + HEADER + [f"{sha};{name}" for sha, name in hashes.items()] + iocs
    content = "\n".join(lines) + "\n"
    with open(DB_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    write_output(content != before)
    return 0


if __name__ == "__main__":
    sys.exit(main())
