"""Monta a base de ameaças (sha256.txt) a partir de fontes públicas que permitem uso comercial.
Roda no GitHub Actions, todo dia.

Fontes:
- ESET malware-ioc (BSD-2-Clause, Copyright (c) 2014-2018 ESET spol. s r.o.): SHA-256 das amostras
  de cada investigação publicada pela ESET (Android e outras plataformas).
  https://github.com/eset/malware-ioc
- Echap stalkerware-indicators (CC BY 4.0): nomes de pacote e certificados (SHA-1) de apps espiões.
  https://github.com/AssoEchap/stalkerware-indicators

(O MalwareBazaar/abuse.ch não é usado: pelos termos de uso de nov/2025, uso comercial exige
assinatura paga pela Spamhaus.)

Formato das linhas:
    <sha256>;<nome>            hash do arquivo
    pkg:<pacote>;<nome>        nome do pacote
    cert1:<sha1>;<nome>        certificado de assinatura
O SignDb.java recria a linha "#version=" ao assinar. Se uma fonte falhar num dia, mantém as
linhas dela da véspera.

Escreve changed=true|false em $GITHUB_OUTPUT (informativo: o workflow assina todo dia).
"""

import io
import os
import re
import sys
import tarfile
import urllib.request

DB_PATH = "sha256.txt"
ESET_TARBALL = "https://codeload.github.com/eset/malware-ioc/tar.gz/refs/heads/master"
STALKERWARE_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
USER_AGENT = "signature-feed-updater"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")

HEADER = [
    "# Base de ameacas do MeowGuard: <sha256>;<nome> | pkg:<pacote>;<nome> | cert1:<sha1>;<nome>",
    "# Fontes: ESET malware-ioc (BSD-2-Clause, (c) ESET spol. s r.o.); Echap stalkerware-indicators (CC BY 4.0)",
]


def fetch(url, timeout=120):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def eset_lines():
    """SHA-256 de cada pasta (investigação) do repositório da ESET: <pasta>/samples.sha256."""
    try:
        archive = tarfile.open(fileobj=io.BytesIO(fetch(ESET_TARBALL)), mode="r:gz")
    except Exception as e:
        print(f"Nao foi possivel baixar a ESET malware-ioc: {e}")
        return None
    lines = {}
    for member in archive.getmembers():
        parts = member.name.split("/")
        # malware-ioc-master/<campanha>/samples.sha256
        if not member.isfile() or len(parts) != 3 or parts[2].lower() != "samples.sha256":
            continue
        campaign = re.sub(r"[^A-Za-z0-9_-]", "", parts[1]) or "Generic"
        content = archive.extractfile(member).read().decode("utf-8", errors="ignore")
        for raw in content.splitlines():
            sha = raw.strip().split()[0].lower() if raw.strip() else ""
            if SHA256_RE.match(sha):
                lines.setdefault(sha, f"ESET.{campaign}")
    print(f"ESET: {len(lines)} hash(es).")
    return sorted(f"{sha};{name}" for sha, name in lines.items())


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
    except Exception as e:
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


def previous(before, kind):
    """Linhas da véspera de uma fonte (para quando ela falhar hoje)."""
    out = []
    for line in before.splitlines():
        if kind == "eset" and ";ESET." in line and SHA256_RE.match(line.split(";")[0]):
            out.append(line)
        if kind == "stalkerware" and line.startswith(("pkg:", "cert1:")):
            out.append(line)
    return out


def write_output(changed):
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")


def main():
    before = open(DB_PATH, encoding="utf-8").read() if os.path.exists(DB_PATH) else ""

    eset = eset_lines()
    if eset is None:
        eset = previous(before, "eset")
    stalkerware = stalkerware_lines()
    if stalkerware is None:
        stalkerware = previous(before, "stalkerware")

    version = [l for l in before.splitlines() if l.startswith("#version=")]
    content = "\n".join(version + HEADER + eset + stalkerware) + "\n"
    with open(DB_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    write_output(content != before)
    return 0


if __name__ == "__main__":
    sys.exit(main())
