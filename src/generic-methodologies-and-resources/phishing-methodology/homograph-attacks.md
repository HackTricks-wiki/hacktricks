# Ataques de Homógrafos / Homoglifos em Phishing

{{#include ../../banners/hacktricks-training.md}}

## Visão Geral

Um ataque homógrafo (também conhecido como homoglyph) explora o fato de que muitos **pontos de código Unicode de scripts não latinos são visualmente idênticos ou extremamente semelhantes a caracteres ASCII**. Ao substituir um ou mais caracteres latinos por seus equivalentes visualmente semelhantes, um atacante pode criar:

* Nomes de exibição, assuntos ou corpos de mensagem que parecem legítimos para o olho humano, mas contornam detecções baseadas em palavras-chave.
* Domínios, subdomínios ou caminhos de URL que enganam as vítimas, fazendo-as acreditar que estão visitando um site confiável.

Como cada glifo é identificado internamente pelo seu **ponto de código Unicode**, um único caractere substituído é suficiente para derrotar comparações de strings ingênuas (por exemplo, `"Παypal.com"` vs. `"Paypal.com"`).

## Fluxo de Trabalho Típico de Phishing

1. **Criar conteúdo da mensagem** – Substituir letras latinas específicas na marca / palavra-chave impersonada por caracteres visualmente indistinguíveis de outro script (grego, cirílico, armênio, cherokee, etc.).
2. **Registrar infraestrutura de suporte** – Opcionalmente, registrar um domínio homoglyph e obter um certificado TLS (a maioria das CAs não faz verificações de similaridade visual).
3. **Enviar e-mail / SMS** – A mensagem contém homógrafos em uma ou mais das seguintes localizações:
* Nome de exibição do remetente (por exemplo, `Ηеlрdеѕk`)
* Linha de assunto (`Urgеnt Аctіon Rеquіrеd`)
* Texto do hyperlink ou nome de domínio totalmente qualificado
4. **Cadeia de redirecionamento** – A vítima é redirecionada através de sites aparentemente benignos ou encurtadores de URL antes de aterrissar no host malicioso que coleta credenciais / entrega malware.

## Faixas de Unicode Comumente Abusadas

| Script | Faixa | Glifo de exemplo | Parece com |
|--------|-------|------------------|------------|
| Grego  | U+0370-03FF | `Η` (U+0397) | Latino `H` |
| Grego  | U+0370-03FF | `ρ` (U+03C1) | Latino `p` |
| Cirílico | U+0400-04FF | `а` (U+0430) | Latino `a` |
| Cirílico | U+0400-04FF | `е` (U+0435) | Latino `e` |
| Armênio | U+0530-058F | `օ` (U+0585) | Latino `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latino `T` |

> Dica: Gráficos completos de Unicode estão disponíveis em [unicode.org](https://home.unicode.org/).

## Técnicas de Detecção

### 1. Inspeção de Script Misto

E-mails de phishing direcionados a uma organização de língua inglesa raramente devem misturar caracteres de múltiplos scripts. Uma heurística simples, mas eficaz, é:

1. Iterar cada caractere da string inspecionada.
2. Mapear o ponto de código para seu bloco Unicode.
3. Emitir um alerta se mais de um script estiver presente **ou** se scripts não latinos aparecerem onde não são esperados (nome de exibição, domínio, assunto, URL, etc.).

Prova de conceito em Python:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Normalização Punycode (Domínios)

Nomes de Domínio Internacionalizados (IDNs) são codificados com **punycode** (`xn--`). Converter cada nome de host para punycode e depois de volta para Unicode permite a correspondência contra uma lista de permissões ou a realização de verificações de similaridade (por exemplo, distância de Levenshtein) **após** a string ter sido normalizada.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Dicionários / Algoritmos de Homógrafos

Ferramentas como **dnstwist** (`--homoglyph`) ou **urlcrazy** podem enumerar permutações de domínios visualmente semelhantes e são úteis para remoção / monitoramento proativo.

## Prevenção & Mitigação

* Aplique políticas rigorosas de DMARC/DKIM/SPF – previna spoofing de domínios não autorizados.
* Implemente a lógica de detecção acima em **Secure Email Gateways** e **SIEM/XSOAR** playbooks.
* Marque ou coloque em quarentena mensagens onde o domínio do nome exibido ≠ domínio do remetente.
* Eduque os usuários: copie e cole texto suspeito em um inspetor de Unicode, passe o mouse sobre links, nunca confie em encurtadores de URL.

## Exemplos do Mundo Real

* Nome exibido: `Сonfidеntiаl Ꭲiꮯkеt` (Cirílico `С`, `е`, `а`; Cherokee `Ꭲ`; letra minúscula latina `ꮯ`).
* Cadeia de domínio: `bestseoservices.com` ➜ diretório municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ login falso da Microsoft em `mlcorsftpsswddprotcct.approaches.it.com` protegido por CAPTCHA OTP personalizado.
* Impersonação do Spotify: remetente `Sρօtifւ` com link oculto atrás de `redirects.ca`.

Esses exemplos originam-se da pesquisa da Unit 42 (julho de 2025) e ilustram como o abuso de homógrafos é combinado com redirecionamento de URL e evasão de CAPTCHA para contornar a análise automatizada.

## Referências

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
