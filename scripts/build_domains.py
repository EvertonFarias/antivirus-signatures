"""Monta domains.bin: a lista de domínios de golpe/malware que o MeowGuard bloqueia na navegação.

Fontes (uso comercial permitido):
- Phishing.Database (MIT): https://github.com/Phishing-Database/Phishing.Database
- Echap stalkerware-indicators (CC BY 4.0): sites dos fornecedores de apps espiões.

Formato compacto (big-endian), para caber na memória do celular:
    8 bytes  "MGDOM001"
    8 bytes  versão (AAAAMMDDHHMM, UTC)
    4 bytes  quantidade N
    N x 8 bytes: os 8 primeiros bytes do SHA-256 de cada domínio (minúsculo), como inteiro com
    sinal, em ordem crescente (o app faz busca binária).
Depois é assinado com `java tools/SignDb.java signfile domains.bin`.

Proteção contra falso positivo: domínios essenciais e raízes de plataformas de hospedagem
(PROTECTED) nunca entram inteiros. Golpes em subdomínios (golpe.pages.dev) continuam bloqueados.
"""

import datetime
import hashlib
import re
import struct
import sys
import urllib.request

PHISHING_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
STALKERWARE_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
OUT = "domains.bin"
USER_AGENT = "signature-feed-updater"

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")

# Nunca bloquear estes domínios nem nada ACIMA deles (o domínio-pai). Subdomínios específicos
# de golpe (ex.: golpe.pages.dev) continuam valendo.
PROTECTED = {
    # Google
    "google.com", "docs.google.com", "sites.google.com", "drive.google.com", "forms.google.com", "mail.google.com",
    "accounts.google.com", "play.google.com", "storage.googleapis.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "youtu.be", "goo.gl", "forms.gle", "g.co", "google.com.br", "google.co.uk", "blogspot.com", "appspot.com",
    "firebaseapp.com", "web.app", "firebaseio.com", "firebasestorage.googleapis.com", "page.link", "script.google.com",
    # Microsoft
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com",
    "onedrive.live.com", "1drv.ms", "azurewebsites.net", "windows.net", "blob.core.windows.net", "azureedge.net",
    "github.com", "github.io", "githubusercontent.com", "forms.office.com", "linkedin.com", "bing.com",
    # Apple, Amazon, Meta e afins
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "amazon.com.br",
    "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net", "wa.me", "messenger.com",
    "twitter.com", "x.com", "t.co", "tiktok.com", "telegram.org", "t.me", "discord.com", "discord.gg", "reddit.com",
    "netflix.com", "spotify.com", "paypal.com", "ebay.com", "dropbox.com", "box.com", "wetransfer.com", "zoom.us",
    # CDNs e plataformas de hospedagem (só os subdomínios de golpe são bloqueados)
    "cloudflare.com", "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app", "herokuapp.com", "webflow.io",
    "weebly.com", "weeblysite.com", "wixsite.com", "wix.com", "square.site", "000webhostapp.com", "glitch.me",
    "duckdns.org", "ngrok.io", "ngrok-free.app", "replit.app", "repl.co", "surge.sh", "framer.app", "notion.site",
    "godaddysites.com", "myshopify.com", "wordpress.com", "blogger.com", "medium.com", "canva.site", "my.canva.site",
    "ipfs.io", "dweb.link", "linktr.ee", "bit.ly", "tinyurl.com", "akamaihd.net", "akamaized.net", "fastly.net",
    # Governo e bancos muito usados (o app já reconhece os oficiais; aqui é só garantia)
    "gov.br", "gov.uk", "usa.gov", "irs.gov", "caixa.gov.br", "bb.com.br", "itau.com.br", "bradesco.com.br",
    "nubank.com.br", "santander.com.br", "mercadopago.com", "mercadolivre.com.br", "mercadolibre.com",
}


def fetch(url, timeout=180):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def is_protected(domain):
    # O próprio domínio essencial ou um "pai" dele (ex.: "google.com" bloquearia docs.google.com).
    return any(p == domain or p.endswith("." + domain) for p in PROTECTED)


def stalkerware_websites(text):
    domains, in_websites = [], False
    for raw in text.splitlines():
        if raw.startswith("- name:"):
            in_websites = False
        elif raw.startswith("  websites:"):
            in_websites = True
        elif raw.startswith("  - ") and in_websites:
            domains.append(raw[4:].strip().strip("'\""))
        elif raw.startswith("  ") and not raw.startswith("  - "):
            in_websites = False
    return domains


def domain_hash(domain):
    return struct.unpack(">q", hashlib.sha256(domain.encode("ascii")).digest()[:8])[0]


def main():
    domains = set()
    phishing = fetch(PHISHING_URL).splitlines()
    for line in phishing:
        d = line.strip().lower().rstrip(".")
        if d.startswith("www."):
            domains.add(d[4:])
        domains.add(d)
    print(f"Phishing.Database: {len(phishing)} linha(s)")

    stalker = [d.lower() for d in stalkerware_websites(fetch(STALKERWARE_URL))]
    domains.update(stalker)
    print(f"Stalkerware: {len(stalker)} site(s)")

    valid = sorted(d for d in domains if DOMAIN_RE.match(d) and not is_protected(d))
    removed = len([d for d in domains if DOMAIN_RE.match(d)]) - len(valid)
    print(f"Domínios: {len(valid)} (protegidos removidos: {removed})")
    if len(valid) < 1000:
        print("Lista pequena demais: provavelmente a fonte falhou. Mantendo a versão anterior.")
        return 1

    hashes = sorted(set(domain_hash(d) for d in valid))
    version = int(datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M"))
    with open(OUT, "wb") as f:
        f.write(b"MGDOM001")
        f.write(struct.pack(">qi", version, len(hashes)))
        f.write(b"".join(struct.pack(">q", h) for h in hashes))
    print(f"{OUT}: versão {version}, {len(hashes)} hash(es)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
