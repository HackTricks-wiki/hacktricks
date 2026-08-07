# Homograph / Homoglyph Attacks em Phishing

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Um ataque de homograph (também conhecido como homoglyph) explora o fato de que muitos **code points Unicode de scripts não latinos são visualmente idênticos ou extremamente semelhantes a caracteres ASCII**. Ao substituir um ou mais caracteres latinos por equivalentes visualmente semelhantes, um atacante pode criar:

* Nomes de exibição, assuntos ou corpos de mensagens que parecem legítimos ao olho humano, mas contornam detecções baseadas em palavras-chave.
* Domínios, subdomínios ou caminhos de URL que levam as vítimas a acreditar que estão acessando um site confiável.

Como cada glyph é identificado internamente pelo seu **code point Unicode**, um único caractere substituído é suficiente para derrotar comparações de strings ingênuas (por exemplo, `"Παypal.com"` vs. `"Paypal.com"`).

## Fluxo de Phishing típico

1. **Criar o conteúdo da mensagem** – Substituir letras latinas específicas na marca / palavra-chave imitada por caracteres visualmente indistinguíveis de outro script (Grego, Cirílico, Armênio, Cherokee etc.).
2. **Registrar a infraestrutura de suporte** – Opcionalmente, registrar um domínio homoglyph e obter um certificado TLS (a maioria das CAs não realiza verificações de similaridade visual).
3. **Enviar e-mail / SMS** – A mensagem contém homoglyphs em um ou mais dos seguintes locais:
* Nome de exibição do remetente (por exemplo, `Ηеlрdеѕk`)
* Linha de assunto (`Urgеnt Аctіon Rеquіrеd`)
* Texto do hyperlink ou fully qualified domain name
4. **Cadeia de redirecionamento** – A vítima é encaminhada por sites aparentemente benignos ou encurtadores de URL antes de chegar ao host malicioso que coleta credenciais / entrega malware.

## Intervalos Unicode comumente abusados

| Script | Intervalo | Glyph de exemplo | Parece com |
|--------|-------|---------------|------------|
| Grego  | U+0370-03FF | `Η` (U+0397) | Latino `H` |
| Grego  | U+0370-03FF | `ρ` (U+03C1) | Latino `p` |
| Cirílico | U+0400-04FF | `а` (U+0430) | Latino `a` |
| Cirílico | U+0400-04FF | `е` (U+0435) | Latino `e` |
| Armênio | U+0530-058F | `օ` (U+0585) | Latino `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latino `T` |

> Dica: Os gráficos Unicode completos estão disponíveis em [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Técnicas de detecção

### 1. Inspeção de scripts mistos

E-mails de Phishing direcionados a uma organização de língua inglesa raramente deveriam misturar caracteres de vários scripts. Uma heurística simples, mas eficaz, consiste em:

1. Iterar por cada caractere da string inspecionada.
2. Mapear o code point para o bloco Unicode correspondente.
3. Gerar um alerta se mais de um script estiver presente **ou** se scripts não latinos aparecerem onde não são esperados (nome de exibição, domínio, assunto, URL etc.).

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
### 2. Normalização de Punycode (Domínios)

Os Internationalised Domain Names (IDNs) são codificados com **punycode** (`xn--`). Converter cada hostname para punycode e depois de volta para Unicode permite fazer correspondências com uma whitelist ou realizar verificações de similaridade (por exemplo, distância de Levenshtein) **após** a string ter sido normalizada.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Dicionários / Algoritmos de Homoglyph

Ferramentas como **dnstwist** (`--homoglyph`) ou **urlcrazy** podem enumerar permutações de domínios visualmente semelhantes e são úteis para takedown / monitoramento proativo.<sup>[[3]](#references)</sup>

## Prevenção e Mitigação

* Imponha políticas rigorosas de DMARC/DKIM/SPF – evite spoofing a partir de domínios não autorizados.
* Implemente a lógica de detecção acima em **Secure Email Gateways** e playbooks de **SIEM/XSOAR**.
* Sinalize ou coloque em quarentena mensagens nas quais o domínio do nome de exibição ≠ domínio do remetente.
* Eduque os usuários: copie e cole textos suspeitos em um inspetor de Unicode, passe o cursor sobre os links e nunca confie em encurtadores de URL.

## Exemplos do Mundo Real

* Nome de exibição: `Сonfidеntiаl Ꭲiꮯkеt` (`С`, `е`, `а` em cirílico; `Ꭲ` em Cherokee; `ꮯ` em Latin small capital).
* Cadeia de domínios: `bestseoservices.com` ➜ diretório municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ login falso da Microsoft em `mlcorsftpsswddprotcct.approaches.it.com`, protegido por um CAPTCHA OTP personalizado.
* Impersonação do Spotify: remetente `Sρօtifս` com um link oculto atrás de `redirects.ca`.

Essas amostras são provenientes de uma pesquisa da Unit 42 (julho de 2025) e ilustram como o abuso de homograph é combinado com redirecionamento de URL e evasão de CAPTCHA para contornar análises automatizadas.<sup>[[1]](#references)</sup>

## Referências

- [1] [A Ilusão do Homograph: Nem Tudo É O Que Parece](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Banco de Dados de Caracteres Unicode](https://home.unicode.org/)
- [3] [dnstwist – mecanismo de permutação de domínios](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
