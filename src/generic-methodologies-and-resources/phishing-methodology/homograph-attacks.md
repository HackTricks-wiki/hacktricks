# Attacchi Homograph / Homoglyph nel Phishing

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Un attacco homograph (noto anche come homoglyph) sfrutta il fatto che molti **punti di codice Unicode di script non latini sono visivamente identici o estremamente simili ai caratteri ASCII**. Sostituendo uno o più caratteri latini con i loro omologhi visivamente simili, un attaccante può creare:

* Nomi di visualizzazione, soggetti o corpi di messaggi che sembrano legittimi all'occhio umano ma eludono le rilevazioni basate su parole chiave.
* Domini, sottodomini o percorsi URL che ingannano le vittime facendole credere di visitare un sito fidato.

Poiché ogni glifo è identificato internamente dal suo **punto di codice Unicode**, un singolo carattere sostituito è sufficiente per sconfiggere confronti di stringhe naïve (ad es., `"Παypal.com"` vs. `"Paypal.com"`).

## Flusso di Lavoro Tipico del Phishing

1. **Creare il contenuto del messaggio** – Sostituire lettere latine specifiche nel marchio / parola chiave impersonata con caratteri visivamente indistinguibili di un altro script (greco, cirillico, armeno, cherokee, ecc.).
2. **Registrare l'infrastruttura di supporto** – Registrare facoltativamente un dominio homoglyph e ottenere un certificato TLS (la maggior parte delle CA non esegue controlli di somiglianza visiva).
3. **Inviare email / SMS** – Il messaggio contiene homoglyph in uno o più dei seguenti luoghi:
* Nome visualizzato del mittente (ad es., `Ηеlрdеѕk`)
* Oggetto (`Urgеnt Аctіon Rеquіrеd`)
* Testo del collegamento ipertestuale o nome di dominio completamente qualificato
4. **Catena di reindirizzamento** – La vittima viene reindirizzata attraverso siti web apparentemente benigni o accorciatori di URL prima di atterrare sull'host malevolo che raccoglie credenziali / distribuisce malware.

## Intervalli Unicode Comunemente Sfruttati

| Script | Intervallo | Glifo di esempio | Sembra |
|--------|-------|---------------|------------|
| Greco  | U+0370-03FF | `Η` (U+0397) | Latino `H` |
| Greco  | U+0370-03FF | `ρ` (U+03C1) | Latino `p` |
| Cirillico | U+0400-04FF | `а` (U+0430) | Latino `a` |
| Cirillico | U+0400-04FF | `е` (U+0435) | Latino `e` |
| Armeno | U+0530-058F | `օ` (U+0585) | Latino `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latino `T` |

> Suggerimento: Le tabelle Unicode complete sono disponibili su [unicode.org](https://home.unicode.org/).

## Tecniche di Rilevamento

### 1. Ispezione di Script Misti

Le email di phishing destinate a un'organizzazione di lingua inglese dovrebbero raramente mescolare caratteri di più script. Un'euristica semplice ma efficace è:

1. Iterare ogni carattere della stringa ispezionata.
2. Mappare il punto di codice al suo blocco Unicode.
3. Sollevare un avviso se è presente più di uno script **o** se appaiono script non latini dove non sono attesi (nome visualizzato, dominio, soggetto, URL, ecc.).

Prova di concetto in Python:
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

I nomi di dominio internazionalizzati (IDN) sono codificati con **punycode** (`xn--`). Convertire ogni nome host in punycode e poi tornare a Unicode consente di confrontare con una lista bianca o eseguire controlli di somiglianza (ad es., distanza di Levenshtein) **dopo** che la stringa è stata normalizzata.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Dizionari / Algoritmi di Omoglyph

Strumenti come **dnstwist** (`--homoglyph`) o **urlcrazy** possono enumerare permutazioni di dominio visivamente simili e sono utili per azioni proattive di rimozione / monitoraggio.

## Prevenzione e Mitigazione

* Applicare politiche DMARC/DKIM/SPF rigorose – prevenire lo spoofing da domini non autorizzati.
* Implementare la logica di rilevamento sopra in **Secure Email Gateways** e **SIEM/XSOAR** playbook.
* Segnalare o mettere in quarantena i messaggi in cui il dominio del nome visualizzato ≠ dominio del mittente.
* Educare gli utenti: copiare e incollare testo sospetto in un ispezionatore Unicode, passare il mouse sui link, non fidarsi mai degli accorciatori di URL.

## Esempi del Mondo Reale

* Nome visualizzato: `Сonfidеntiаl Ꭲiꮯkеt` (Cirillico `С`, `е`, `а`; Cherokee `Ꭲ`; maiuscolo latino `ꮯ`).
* Catena di dominio: `bestseoservices.com` ➜ directory municipale `/templates` ➜ `kig.skyvaulyt.ru` ➜ falso login Microsoft su `mlcorsftpsswddprotcct.approaches.it.com` protetto da CAPTCHA OTP personalizzato.
* Impersonificazione di Spotify: mittente `Sρօtifւ` con link nascosto dietro `redirects.ca`.

Questi campioni provengono dalla ricerca di Unit 42 (luglio 2025) e illustrano come l'abuso di omografi sia combinato con la redirezione URL e l'evasione CAPTCHA per bypassare l'analisi automatizzata.

## Riferimenti

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
