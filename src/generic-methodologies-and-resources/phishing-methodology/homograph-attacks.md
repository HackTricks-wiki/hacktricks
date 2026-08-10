# Homograph / Homoglyph Attacks nel Phishing

## Panoramica

Un homograph (detto anche homoglyph) attack sfrutta il fatto che molti **punti di codice Unicode di script non latini sono visivamente identici o estremamente simili ai caratteri ASCII**. Sostituendo uno o più caratteri latini con i loro equivalenti dall'aspetto simile, un attacker può creare:

* Nomi visualizzati, oggetti o corpi dei messaggi che sembrano legittimi all'occhio umano, ma aggirano i sistemi di rilevamento basati su keyword.
* Domini, sottodomini o percorsi URL che inducono le vittime a credere di visitare un sito attendibile.<sup>[[1]](#references)</sup>

Poiché ogni glyph è identificato internamente dal proprio **punto di codice Unicode**, è sufficiente un singolo carattere sostituito per eludere i confronti di stringhe ingenui (ad esempio, `"Παypal.com"` rispetto a `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Workflow tipico di Phishing

1. **Creare il contenuto del messaggio** – Sostituire specifiche lettere latine nel brand / keyword impersonato con caratteri visivamente indistinguibili appartenenti a un altro script (greco, cirillico, armeno, Cherokee, ecc.).
2. **Registrare l'infrastruttura di supporto** – Facoltativamente, registrare un dominio homoglyph e ottenere un certificato TLS (la maggior parte delle CA non esegue controlli sulla similarità visiva).
3. **Inviare email / SMS** – Il messaggio contiene homoglyph in una o più delle seguenti posizioni:
* Nome visualizzato del mittente (ad es., `Ηеlрdеѕk`)
* Oggetto (`Urgеnt Аctіon Rеquіrеd`)
* Testo del collegamento ipertestuale o fully qualified domain name
4. **Catena di redirect** – La vittima viene fatta passare attraverso siti apparentemente innocui o URL shortener prima di arrivare sull'host malevolo che raccoglie le credenziali / distribuisce malware.<sup>[[1]](#references)</sup>

## Intervalli Unicode comunemente abusati

Gli esempi seguenti sono blocchi Unicode che contengono caratteri comunemente utilizzati per creare look-alike tra script diversi.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Intervallo | Glyph di esempio | Sembra |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Suggerimento: utilizzare le tabelle dei codici Unicode per consultare blocchi e punti di codice.

## Tecniche di rilevamento

### 1. Ispezione degli script misti

Le email di Phishing rivolte a un'organizzazione anglofona dovrebbero raramente combinare caratteri appartenenti a più script. Una euristica semplice ma efficace consiste nel:

1. Iterare ogni carattere della stringa esaminata.
2. Mappare il punto di codice al nome dello script o al blocco Unicode.
3. Generare un alert se è presente più di uno script **oppure** se compaiono script non latini in posizioni in cui non sono attesi (nome visualizzato, dominio, oggetto, URL, ecc.).<sup>[[3]](#references)</sup>

Proof-of-concept in Python:
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
### 2. Normalizzazione Punycode (Domini)

I nomi di dominio internazionalizzati (IDN) hanno una forma Unicode e una forma **Punycode** compatibile con ASCII, preceduta da `xn--`. Converti i nomi host nel formato IDNA/Punycode prima di inserirli in una allow-list o confrontarli, mantenendo la forma Unicode per la visualizzazione.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Dizionari / Algoritmi di Homoglyph

Strumenti come **dnstwist** (`--fuzzers homoglyph`) o **urlcrazy** possono enumerare le permutazioni di domini visivamente simili e sono utili per il takedown / monitoring proattivo.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevenzione e Mitigazione

* Applicare policy DMARC/DKIM/SPF rigorose – impedire lo spoofing da domini non autorizzati.
* Implementare la logica di rilevamento descritta sopra nei **Secure Email Gateways** e nei playbook **SIEM/XSOAR**.
* Segnalare o mettere in quarantena i messaggi in cui il dominio del display name ≠ il dominio del mittente.
* Educare gli utenti: copiare e incollare il testo sospetto in un ispettore Unicode, passare il mouse sui link, non fidarsi mai degli URL shortener.

## Esempi reali

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cirillico `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Catena di domini: `bestseoservices.com` ➜ directory municipale `/templates` ➜ `kig.skyvaulyt.ru` ➜ falso login Microsoft su `mlcorsftpsswddprotcct.approaches.it.com`, protetto da un CAPTCHA OTP personalizzato.
* Impersonificazione di Spotify: mittente `Sρօtifս` con un link nascosto dietro `redirects.ca`.

Questi esempi provengono dalla ricerca di Unit 42 (luglio 2025) e illustrano come l'abuso di Homoglyph venga combinato con il reindirizzamento degli URL e l'elusione dei CAPTCHA per aggirare l'analisi automatizzata.<sup>[[1]](#references)</sup>

## References

- [1] [L'illusione Homograph: non tutto è come sembra](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Grafici dei codici dei caratteri Unicode](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: meccanismi di sicurezza Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – motore per la permutazione dei domini](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generatore di typo e variazioni dei domini](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): definizioni e struttura del documento](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
