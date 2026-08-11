# Homograph / Homoglyph Attacks em Phishing

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Um ataque homograph (também conhecido como homoglyph) explora o fato de que muitos **pontos de código Unicode de scripts não latinos são visualmente idênticos ou extremamente semelhantes a caracteres ASCII**. Ao substituir um ou mais caracteres latinos por seus equivalentes visualmente semelhantes, um atacante pode criar:

* Nomes de exibição, assuntos ou corpos de mensagens que parecem legítimos para o olho humano, mas contornam detecções baseadas em palavras-chave.
* Domínios, subdomínios ou caminhos de URL que fazem as vítimas acreditarem que estão visitando um site confiável.<sup>[[1]](#references)</sup>

Como cada glyph é identificado internamente por seu **ponto de código Unicode**, um único caractere substituído é suficiente para derrotar comparações de strings ingênuas (por exemplo, `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Fluxo de Phishing Típico

1. **Criar o conteúdo da mensagem** – Substituir letras latinas específicas na marca / palavra-chave personificada por caracteres visualmente indistinguíveis de outro script (Grego, Cirílico, Armênio, Cherokee etc.).
2. **Registrar a infraestrutura de suporte** – Opcionalmente, registrar um domínio homoglyph e obter um certificado TLS (a maioria das CAs não realiza verificações de similaridade visual).
3. **Enviar email / SMS** – A mensagem contém homoglyphs em um ou mais dos seguintes locais:
* Nome de exibição do remetente (por exemplo, `Ηеlрdеѕk`)
* Linha de assunto (`Urgеnt Аctіon Rеquіrеd`)
* Texto do hyperlink ou fully qualified domain name
4. **Cadeia de redirecionamento** – A vítima é encaminhada por sites aparentemente benignos ou encurtadores de URL antes de chegar ao host malicioso que coleta credenciais / entrega malware.<sup>[[1]](#references)</sup>

## Intervalos Unicode Comumente Abusados

Os exemplos a seguir são blocos Unicode que contêm caracteres comumente usados para criar look-alikes entre scripts.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Intervalo | Glyph de exemplo | Parece com |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Dica: Use os Unicode code charts para consultar blocos e pontos de código.

## Técnicas de Detecção

### 1. Inspeção de Scripts Mistos

Emails de phishing direcionados a uma organização de língua inglesa raramente devem misturar caracteres de múltiplos scripts. Uma heuristic simples, mas eficaz, é:

1. Iterar por cada caractere da string inspecionada.
2. Mapear o ponto de código para seu nome de script ou bloco Unicode.
3. Gerar um alerta se mais de um script estiver presente **ou** se scripts não latinos aparecerem onde não são esperados (nome de exibição, domínio, assunto, URL etc.).<sup>[[3]](#references)</sup>

Proof-of-concept em Python:
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

Os Internationalised Domain Names (IDNs) têm uma forma Unicode e uma forma **Punycode** compatível com ASCII, prefixada com `xn--`. Converta os hostnames para a forma IDNA/Punycode antes de adicioná-los à lista de permissões ou compará-los, mantendo a forma Unicode para exibição.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Dicionários / Algoritmos de Homoglyph

Ferramentas como **dnstwist** (`--fuzzers homoglyph`) ou **urlcrazy** podem enumerar permutações de domínios visualmente semelhantes e são úteis para takedown / monitoramento proativos.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevenção e Mitigação

* Aplique políticas rigorosas de DMARC/DKIM/SPF – impeça spoofing proveniente de domínios não autorizados.
* Implemente a lógica de detecção acima em **Secure Email Gateways** e playbooks do **SIEM/XSOAR**.
* Sinalize ou coloque em quarentena mensagens nas quais o domínio do nome de exibição ≠ domínio do remetente.
* Eduque os usuários: cole textos suspeitos em um inspetor de Unicode, passe o mouse sobre os links e nunca confie em URL shorteners.

## Exemplos do Mundo Real

* Nome de exibição: `Сonfidеntiаl Ꭲiꮯkеt` (`С`, `е`, `а` cirílicos; `Ꭲ` Cherokee; `ꮯ` letra latina minúscula em caixa alta).
* Cadeia de domínios: `bestseoservices.com` ➜ diretório municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ login falso da Microsoft em `mlcorsftpsswddprotcct.approaches.it.com`, protegido por CAPTCHA OTP personalizado.
* Impersonação do Spotify: remetente `Sρօtifս` com link oculto atrás de `redirects.ca`.

Essas amostras têm origem em uma pesquisa da Unit 42 (julho de 2025) e ilustram como o abuso de homographs é combinado com redirecionamento de URL e evasão de CAPTCHA para contornar análises automatizadas.<sup>[[1]](#references)</sup>

## References

- [1] [A Ilusão do Homograph: nem tudo é o que parece](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tabelas de códigos de caracteres Unicode](https://www.unicode.org/charts/)
- [3] [Padrão Técnico Unicode #39: Mecanismos de segurança Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – mecanismo de permutação de domínios](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – gerador de typos e variações de domínios](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Nomes de domínio internacionalizados para aplicações (IDNA): definições e estrutura de documentos](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
