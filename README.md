# Base de assinaturas

Hashes SHA-256 de APKs Android maliciosos conhecidos, publicados via GitHub Pages.

- `sha256.txt`: uma entrada por linha, `<sha256>;<nome da ameaça>`. A linha `#version=` traz a data/hora UTC da assinatura.
- `sha256.txt.sig`: assinatura ECDSA P-256 (SHA-256), em Base64, sobre os bytes exatos de `sha256.txt`.

O workflow `.github/workflows/update.yml` roda todo dia: monta a base com as fontes abaixo,
assina e publica. Ele assina **todo dia**, mesmo
sem hashes novos: o app usa a data de `#version=` para avisar quando a base passa de 7 dias
(sinal de que as atualizações estão sendo bloqueadas).

## Fontes e créditos

- **ESET malware-ioc** (https://github.com/eset/malware-ioc), licença BSD-2-Clause,
  Copyright (c) 2014-2018 ESET spol. s r.o.: SHA-256 das amostras de cada investigação publicada.
- **Echap stalkerware-indicators** (https://github.com/AssoEchap/stalkerware-indicators), licença
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): nomes de pacote e certificados (SHA-1)
  de apps espiões, convertidos para as linhas `pkg:` e `cert1:`. O app mostra o crédito em
  Ajustes → Fontes de dados de ameaças.

O **MalwareBazaar/abuse.ch não é usado**: pelos termos de uso em vigor desde novembro de 2025,
o uso comercial exige assinatura paga pela Spamhaus (https://abuse.ch/terms-of-use/).

## Segredos

- `SIGNING_PRIVATE_KEY`: chave privada, no **Environment `assinatura`** (Settings → Environments),
  liberado só para o branch `main`. Outros branches, forks e PRs não conseguem lê-la.

As Actions estão fixadas por commit (uma tag pode ser movida para código malicioso, um commit não).
O Dependabot abre PR semanal quando sai versão nova: confira o changelog antes de aceitar.

## Troca de chave (se a principal vazar)

O app aceita duas chaves públicas: a principal e uma reserva, cuja privada fica guardada offline
(`keys/signing-backup.key` no computador do desenvolvedor, com backup fora dele).

1. Troque o secret `SIGNING_PRIVATE_KEY` do Environment `assinatura` pelo conteúdo da chave reserva.
2. Rode o workflow manualmente (Actions → Atualizar base de assinaturas → Run workflow).
   Os apps instalados passam a aceitar a base nova na hora, sem atualização.
3. No app, troque a chave vazada por uma reserva nova (`java tools/SignDb.java keygen keys/nova-reserva.key`)
   em `SIGNATURES_PUBLIC_KEYS` e publique uma versão. Enquanto ela não chega a todos, a chave vazada
   continua aceita pelos apps antigos; por isso a troca é urgente.
