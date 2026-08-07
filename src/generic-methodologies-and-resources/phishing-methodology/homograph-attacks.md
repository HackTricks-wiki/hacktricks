# Homograph- / Homoglyph-Angriffe bei Phishing

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Ein Homograph- (auch Homoglyph-)Angriff missbraucht die Tatsache, dass viele **Unicode-Codepoints aus nichtlateinischen Schriftsystemen visuell identisch oder extrem ähnlich zu ASCII-Zeichen sind**. Indem ein oder mehrere lateinische Zeichen durch ihre ähnlich aussehenden Gegenstücke ersetzt werden, kann ein Angreifer Folgendes erstellen:

* Anzeigenamen, Betreffzeilen oder Nachrichtentexte, die für das menschliche Auge legitim aussehen, aber schlüsselwortbasierte Erkennungen umgehen.
* Domains, Subdomains oder URL-Pfade, die Opfer davon überzeugen, eine vertrauenswürdige Website zu besuchen.

Da jede Glyphe intern durch ihren **Unicode-Codepoint** identifiziert wird, genügt ein einziges ersetztes Zeichen, um naive Zeichenkettenvergleiche zu umgehen (z. B. `"Παypal.com"` gegenüber `"Paypal.com"`).

## Typischer Phishing-Ablauf

1. **Nachrichteninhalt erstellen** – Bestimmte lateinische Buchstaben in der imitierten Marke bzw. im Keyword durch visuell nicht unterscheidbare Zeichen aus einem anderen Schriftsystem ersetzen (Griechisch, Kyrillisch, Armenisch, Cherokee usw.).
2. **Unterstützende Infrastruktur registrieren** – Optional eine Homoglyph-Domain registrieren und ein TLS-Zertifikat erhalten (die meisten CAs führen keine Prüfungen auf visuelle Ähnlichkeit durch).
3. **E-Mail / SMS senden** – Die Nachricht enthält Homoglyphen an einer oder mehreren der folgenden Stellen:
* Absender-Anzeigename (z. B. `Ηеlрdеѕk`)
* Betreffzeile (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink-Text oder vollständig qualifizierter Domainname
4. **Weiterleitungskette** – Das Opfer wird über scheinbar harmlose Websites oder URL-Shortener weitergeleitet, bevor es beim bösartigen Host landet, der Zugangsdaten abgreift bzw. Malware ausliefert.

## Häufig missbrauchte Unicode-Bereiche

| Schriftsystem | Bereich | Beispielglyphe | Sieht aus wie |
|--------|-------|---------------|------------|
| Griechisch  | U+0370-03FF | `Η` (U+0397) | Lateinisches `H` |
| Griechisch  | U+0370-03FF | `ρ` (U+03C1) | Lateinisches `p` |
| Kyrillisch | U+0400-04FF | `а` (U+0430) | Lateinisches `a` |
| Kyrillisch | U+0400-04FF | `е` (U+0435) | Lateinisches `e` |
| Armenisch | U+0530-058F | `օ` (U+0585) | Lateinisches `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Lateinisches `T` |

> Tipp: Vollständige Unicode-Tabellen sind unter [unicode.org](https://home.unicode.org/)<sup>[[2]](#references)</sup> verfügbar.

## Detection-Techniken

### 1. Prüfung auf gemischte Schriftsysteme

Phishing-E-Mails, die sich an eine englischsprachige Organisation richten, sollten nur selten Zeichen aus mehreren Schriftsystemen mischen. Eine einfache, aber effektive Heuristik besteht darin:

1. Jedes Zeichen der untersuchten Zeichenkette durchlaufen.
2. Den Codepoint dem entsprechenden Unicode-Block zuordnen.
3. Einen Alarm auslösen, wenn mehr als ein Schriftsystem vorhanden ist **oder** wenn nichtlateinische Schriftsysteme an Stellen erscheinen, an denen sie nicht erwartet werden (Anzeigename, Domain, Betreff, URL usw.).

Python Proof-of-Concept:
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
### 2. Punycode-Normalisierung (Domains)

Internationalisierte Domainnamen (IDNs) werden mit **Punycode** (`xn--`) codiert. Die Umwandlung jedes Hostnamens in Punycode und anschließend zurück in Unicode ermöglicht den Abgleich mit einer Whitelist oder die Durchführung von Ähnlichkeitsprüfungen (z. B. der Levenshtein-Distanz), **nachdem** der String normalisiert wurde.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph-Wörterbücher / Algorithmen

Tools wie **dnstwist** (`--homoglyph`) oder **urlcrazy** können visuell ähnliche Domain-Permutationen auflisten und sind für proaktives Takedown / Monitoring nützlich.<sup>[[3]](#references)</sup>

## Prävention & Abwehrmaßnahmen

* Strenge DMARC/DKIM/SPF-Richtlinien durchsetzen – Spoofing von nicht autorisierten Domains verhindern.
* Die oben beschriebene Erkennungslogik in **Secure Email Gateways** und **SIEM/XSOAR**-Playbooks implementieren.
* Nachrichten markieren oder unter Quarantäne stellen, wenn die Domain des Anzeigenamens ≠ der Absenderdomain ist.
* Benutzer schulen: verdächtigen Text per Copy-and-paste in einen Unicode-Inspector einfügen, Links per Mouseover prüfen und URL-Shortener niemals vertrauen.

## Beispiele aus der Praxis

* Anzeigename: `Сonfidеntiаl Ꭲiꮯkеt` (kyrillisches `С`, `е`, `а`; Cherokee-`Ꭲ`; lateinisches Small-Capital-`ꮯ`).
* Domain-Kette: `bestseoservices.com` ➜ kommunales `/templates`-Verzeichnis ➜ `kig.skyvaulyt.ru` ➜ gefälschter Microsoft-Login unter `mlcorsftpsswddprotcct.approaches.it.com`, geschützt durch ein benutzerdefiniertes OTP-CAPTCHA.
* Spotify-Imitation: Absender `Sρօtifս` mit einem hinter `redirects.ca` verborgenen Link.

Diese Beispiele stammen aus einer Untersuchung von Unit 42 (Juli 2025) und veranschaulichen, wie Homograph-Missbrauch mit URL-Weiterleitung und CAPTCHA-Umgehung kombiniert wird, um automatisierte Analysen zu umgehen.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Die Homograph-Illusion: Nicht alles ist so, wie es scheint](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – Engine für Domain-Permutationen](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
