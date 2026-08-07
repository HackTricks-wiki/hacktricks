# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Un attacco homograph (noto anche come homoglyph) sfrutta il fatto che molti **Unicode code points appartenenti a script non latini sono visivamente identici o estremamente simili ai caratteri ASCII**. Sostituendo uno o più caratteri latini con le loro controparti graficamente simili, un attacker può creare:

* Nomi visualizzati, oggetti o corpi dei messaggi che sembrano legittimi all'occhio umano, ma aggirano i sistemi di rilevamento basati su keyword.
* Domini, sottodomini o percorsi URL che inducono le vittime a credere di visitare un sito trusted.

Poiché ogni glyph viene identificato internamente dal proprio **Unicode code point**, un singolo carattere sostituito è sufficiente per aggirare i naïve string comparisons (ad esempio, `"Παypal.com"` vs. `"Paypal.com"`).

## Flusso tipico di Phishing

1. **Creare il contenuto del messaggio** – Sostituire lettere latine specifiche nel brand / nella keyword impersonata con caratteri visivamente indistinguibili appartenenti a un altro script (Greek, Cyrillic, Armenian, Cherokee, ecc.).
2. **Registrare l'infrastruttura di supporto** – Facoltativamente, registrare un homoglyph domain e ottenere un certificato TLS (la maggior parte delle CA non esegue controlli sulla similarità visiva).
3. **Inviare email / SMS** – Il messaggio contiene homoglyph in una o più delle seguenti posizioni:
* Nome visualizzato del mittente (ad esempio, `Ηеlрdеѕk`)
* Oggetto (`Urgеnt Аctіon Rеquіrеd`)
* Testo del collegamento ipertestuale o fully qualified domain name
4. **Catena di redirect** – La vittima viene reindirizzata attraverso siti apparentemente innocui o URL shortener prima di arrivare sull'host malicious che raccoglie le credenziali / distribuisce malware.

## Unicode Ranges comunemente abusati

| Script | Range | Glyph di esempio | Sembra |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Suggerimento: i grafici Unicode completi sono disponibili su [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Tecniche di rilevamento

### 1. Ispezione degli script misti

Le email di Phishing rivolte a un'organizzazione anglofona dovrebbero raramente combinare caratteri appartenenti a più script. Una heuristic semplice ma efficace consiste nel:

1. Iterare ogni carattere della stringa esaminata.
2. Mappare il code point al relativo Unicode block.
3. Generare un alert se è presente più di uno script **oppure** se compaiono script non latini in posizioni in cui non sono previsti (nome visualizzato, dominio, oggetto, URL, ecc.).

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
### 2. Normalizzazione Punycode (domini)

Gli Internationalised Domain Names (IDN) sono codificati con **punycode** (`xn--`). Convertire ogni hostname in punycode e poi nuovamente in Unicode consente di effettuare il confronto con una whitelist o controlli di similarità (ad esempio, la distanza di Levenshtein) **dopo** che la stringa è stata normalizzata.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Dizionari / algoritmi Homoglyph

Strumenti come **dnstwist** (`--homoglyph`) o **urlcrazy** possono enumerare permutazioni di domini visivamente simili e sono utili per takedown / monitoring proattivi.<sup>[[3]](#references)</sup>

## Prevenzione e mitigazione

* Applicare policy DMARC/DKIM/SPF rigorose – impedire lo spoofing da domini non autorizzati.
* Implementare la logica di rilevamento precedente nei **Secure Email Gateways** e nei playbook **SIEM/XSOAR**.
* Segnalare o mettere in quarantena i messaggi in cui il dominio del display name ≠ il dominio del mittente.
* Educare gli utenti: copiare e incollare il testo sospetto in un Unicode inspector, passare il mouse sui link, non fidarsi mai degli URL shortener.

## Esempi reali

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cirillico `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Catena del dominio: `bestseoservices.com` ➜ directory municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ login Microsoft falso su `mlcorsftpsswddprotcct.approaches.it.com`, protetto da un CAPTCHA OTP personalizzato.
* Impersonificazione di Spotify: mittente `Sρօtifս` con link nascosto dietro `redirects.ca`.

Questi campioni provengono dalla ricerca di Unit 42 (luglio 2025) e illustrano come l'abuso degli homograph venga combinato con il reindirizzamento degli URL e l'elusione dei CAPTCHA per aggirare l'analisi automatizzata.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
