# Base de assinaturas

Hashes SHA-256 de APKs Android maliciosos conhecidos, publicados via GitHub Pages.

- `sha256.txt`: uma entrada por linha, `<sha256>;<nome da ameaça>`. A linha `#version=` traz a data/hora UTC da assinatura.
- `sha256.txt.sig`: assinatura ECDSA P-256 (SHA-256), em Base64, sobre os bytes exatos de `sha256.txt`.

O workflow `.github/workflows/update.yml` roda todo dia: busca hashes novos no
[MalwareBazaar](https://bazaar.abuse.ch/), assina a base e publica.

Secrets usados:
- `SIGNING_PRIVATE_KEY`: chave privada gerada por `java tools/SignDb.java keygen`
- `MB_AUTH_KEY`: chave da API do abuse.ch (opcional; sem ela o workflow não busca nada)
