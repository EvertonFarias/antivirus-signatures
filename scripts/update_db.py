"""Adiciona à base os hashes de APKs maliciosos recentes do MalwareBazaar (abuse.ch).

Precisa da variável MB_AUTH_KEY (chave gratuita em https://auth.abuse.ch/).
Sem a chave, não faz nada e sai com sucesso.

Escreve changed=true|false em $GITHUB_OUTPUT para o workflow decidir se assina e publica.
"""

import json
import os
import re
import sys
import urllib.parse
import urllib.request

DB_PATH = "sha256.txt"
API_URL = "https://mb-api.abuse.ch/api/v1/"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def load_db(path):
    header, entries = [], {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("#version="):
                continue  # o SignDb.java recria essa linha ao assinar
            if not line or line.startswith("#"):
                if not entries:
                    header.append(raw.rstrip("\n"))
                continue
            sha, _, name = line.partition(";")
            sha = sha.strip().lower()
            if SHA256_RE.match(sha):
                entries[sha] = name.strip() or "Android.Malware.Generic"
    return header, entries


def fetch_recent_apks(auth_key):
    body = urllib.parse.urlencode(
        {"query": "get_file_type", "file_type": "apk", "limit": "1000"}
    ).encode()
    request = urllib.request.Request(
        API_URL,
        data=body,
        headers={"Auth-Key": auth_key, "User-Agent": "signature-feed-updater"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.load(response)

    status = payload.get("query_status")
    if status != "ok":
        print(f"MalwareBazaar respondeu: {status}")
        return []
    return payload.get("data") or []


def threat_name(signature):
    family = re.sub(r"[^A-Za-z0-9._-]", "", signature or "")
    return f"Android.{family}" if family else "Android.Malware.Generic"


def write_output(changed):
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")


def main():
    auth_key = os.environ.get("MB_AUTH_KEY", "").strip()
    if not auth_key:
        print("MB_AUTH_KEY não configurada: nada a fazer.")
        write_output(False)
        return 0

    header, entries = load_db(DB_PATH)
    added = 0
    for sample in fetch_recent_apks(auth_key):
        sha = (sample.get("sha256_hash") or "").lower()
        if SHA256_RE.match(sha) and sha not in entries:
            entries[sha] = threat_name(sample.get("signature"))
            added += 1

    if added:
        lines = header + [f"{sha};{name}" for sha, name in entries.items()]
        with open(DB_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    print(f"{added} hash(es) novo(s); total {len(entries)}.")
    write_output(added > 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
