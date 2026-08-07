# Homograph / Homoglyph Attacks en Phishing

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Un ataque homograph (también conocido como homoglyph) abusa del hecho de que muchos **Unicode code points de scripts no latinos son visualmente idénticos o extremadamente similares a caracteres ASCII**. Al reemplazar uno o más caracteres latinos por sus equivalentes visuales, un atacante puede crear:

* Display names, subjects o message bodies que parecen legítimos al ojo humano, pero evaden las detecciones basadas en keywords.
* Domains, sub-domains o URL paths que engañan a las víctimas haciéndoles creer que están visitando un sitio de confianza.

Dado que cada glyph se identifica internamente mediante su **Unicode code point**, un solo carácter sustituido basta para evadir comparaciones de strings ingenuas (por ejemplo, `"Παypal.com"` frente a `"Paypal.com"`).

## Flujo de Phishing habitual

1. **Craft message content** – Reemplazar letras latinas específicas de la marca / keyword suplantada por caracteres visualmente indistinguibles de otro script (griego, cirílico, armenio, cheroqui, etc.).
2. **Register supporting infrastructure** – Registrar opcionalmente un dominio homoglyph y obtener un certificado TLS (la mayoría de las CAs no realizan comprobaciones de similitud visual).
3. **Send email / SMS** – El mensaje contiene homoglyphs en una o más de las siguientes ubicaciones:
* Sender display name (por ejemplo, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text o fully qualified domain name
4. **Redirect chain** – La víctima es redirigida a través de sitios aparentemente benignos o URL shorteners antes de llegar al host malicioso que roba credenciales / distribuye malware.

## Unicode Ranges comúnmente abusados

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Griego  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Griego  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cirílico | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cirílico | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenio | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cheroqui | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Consejo: Los gráficos completos de Unicode están disponibles en [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

Los phishing emails dirigidos a una organización angloparlante rara vez deberían mezclar caracteres de varios scripts. Una heurística sencilla pero eficaz consiste en:

1. Iterar sobre cada carácter del string inspeccionado.
2. Mapear el code point al Unicode block correspondiente.
3. Generar una alerta si hay más de un script presente **o** si aparecen scripts no latinos donde no se esperan (display name, domain, subject, URL, etc.).

Python proof-of-concept:
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
### 2. Normalización de Punycode (Dominios)

Los nombres de dominio internacionalizados (IDNs) se codifican con **punycode** (`xn--`). Convertir cada hostname a punycode y después de vuelta a Unicode permite realizar coincidencias con una whitelist o comprobaciones de similitud (por ejemplo, la distancia de Levenshtein) **después** de normalizar la cadena.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Dictionaries / Algorithms

Tools such as **dnstwist** (`--homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.<sup>[[3]](#references)</sup>

## Prevención y mitigación

* Enforce strict DMARC/DKIM/SPF policies – prevent spoofing from unauthorised domains.
* Implement the detection logic above in **Secure Email Gateways** and **SIEM/XSOAR** playbooks.
* Flag or quarantine messages where display name domain ≠ sender domain.
* Educa a los usuarios: copia y pega el texto sospechoso en un inspector de Unicode, pasa el cursor sobre los links y nunca confíes en los acortadores de URL.

## Ejemplos reales

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Spotify impersonation: `Sρօtifս` sender with link hidden behind `redirects.ca`.

These samples originate from Unit 42 research (July 2025) and illustrate how homograph abuse is combined with URL redirection and CAPTCHA evasion to bypass automated analysis.<sup>[[1]](#references)</sup>

## Referencias

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
