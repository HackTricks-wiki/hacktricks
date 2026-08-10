# Homograph-/Homoglyph-Angriffe beim Phishing

## Überblick

Ein Homograph- (auch Homoglyph-)Angriff nutzt die Tatsache aus, dass viele **Unicode-Codepoints aus nichtlateinischen Schriftsystemen visuell identisch oder ASCII-Zeichen extrem ähnlich sind**. Indem ein oder mehrere lateinische Zeichen durch ihre ähnlich aussehenden Gegenstücke ersetzt werden, kann ein Angreifer Folgendes erstellen:

* Anzeigenamen, Betreffzeilen oder Nachrichtentexte, die für das menschliche Auge legitim aussehen, aber keywordbasierte Erkennungen umgehen.
* Domains, Subdomains oder URL-Pfade, die Opfer davon überzeugen, eine vertrauenswürdige Website zu besuchen.<sup>[[1]](#references)</sup>

Da jedes Glyph intern durch seinen **Unicode-Codepoint** identifiziert wird, reicht ein einziges ersetztes Zeichen aus, um naive Stringvergleiche zu umgehen (z. B. `"Παypal.com"` gegenüber `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Typischer Phishing-Ablauf

1. **Nachrichteninhalt erstellen** – Bestimmte lateinische Buchstaben in der imitierten Marke bzw. im Keyword durch visuell nicht unterscheidbare Zeichen aus einem anderen Schriftsystem ersetzen (Griechisch, Kyrillisch, Armenisch, Cherokee usw.).
2. **Unterstützende Infrastruktur registrieren** – Optional eine Homoglyph-Domain registrieren und ein TLS-Zertifikat erhalten (die meisten CAs führen keine Prüfungen auf visuelle Ähnlichkeit durch).
3. **E-Mail / SMS senden** – Die Nachricht enthält Homoglyphen an einer oder mehreren der folgenden Stellen:
* Anzeigename des Absenders (z. B. `Ηеlрdеѕk`)
* Betreffzeile (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlinktext oder vollständig qualifizierter Domainname
4. **Weiterleitungskette** – Das Opfer wird über scheinbar harmlose Websites oder URL-Shortener weitergeleitet, bevor es beim schädlichen Host landet, der Anmeldedaten abgreift bzw. Malware ausliefert.<sup>[[1]](#references)</sup>

## Häufig missbrauchte Unicode-Bereiche

Die folgenden Beispiele sind Unicode-Blöcke, die Zeichen enthalten, die häufig zur Erstellung von skriptübergreifenden Look-alikes verwendet werden.<sup>[[2]](#references)[[3]](#references)</sup>

| Schriftsystem | Bereich | Beispielzeichen | Sieht aus wie |
|--------|-------|---------------|------------|
| Griechisch  | U+0370-03FF | `Η` (U+0397) | Lateinisches `H` |
| Griechisch  | U+0370-03FF | `ρ` (U+03C1) | Lateinisches `p` |
| Kyrillisch | U+0400-04FF | `а` (U+0430) | Lateinisches `a` |
| Kyrillisch | U+0400-04FF | `е` (U+0435) | Lateinisches `e` |
| Armenisch | U+0530-058F | `օ` (U+0585) | Lateinisches `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Lateinisches `T` |

> Tipp: Verwende die Unicode-Codecharts, um Blöcke und Codepoints nachzuschlagen.

## Erkennungstechniken

### 1. Untersuchung gemischter Schriftsysteme

Phishing-E-Mails, die auf eine englischsprachige Organisation abzielen, sollten nur selten Zeichen aus mehreren Schriftsystemen enthalten. Eine einfache, aber effektive Heuristik besteht darin:

1. Jedes Zeichen der untersuchten Zeichenkette durchlaufen.
2. Den Codepoint seinem Schriftsystem oder Unicode-Block zuzuordnen.
3. Eine Warnung auszulösen, wenn mehr als ein Schriftsystem vorhanden ist **oder** wenn nichtlateinische Schriftsysteme an Stellen erscheinen, an denen sie nicht erwartet werden (Anzeigename, Domain, Betreff, URL usw.).<sup>[[3]](#references)</sup>

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

Internationalisierte Domainnamen (IDNs) haben eine Unicode-Form und eine ASCII-kompatible **Punycode**-Form mit dem Präfix `xn--`. Konvertiere Hostnamen vor der Aufnahme in Allow-Lists oder ihrem Vergleich in die IDNA/Punycode-Form und behalte die Unicode-Form für die Anzeige bei.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph-Wörterbücher / Algorithmen

Tools wie **dnstwist** (`--fuzzers homoglyph`) oder **urlcrazy** können visuell ähnliche Domain-Variationen auflisten und sind für proaktives Takedown / Monitoring nützlich.<sup>[[4]](#references)[[5]](#references)</sup>

## Prävention & Gegenmaßnahmen

* Strenge DMARC/DKIM/SPF-Richtlinien durchsetzen – Spoofing von nicht autorisierten Domains verhindern.
* Die oben beschriebene Erkennungslogik in **Secure Email Gateways** und **SIEM/XSOAR**-Playbooks implementieren.
* Nachrichten markieren oder unter Quarantäne stellen, wenn die Domain des Anzeigenamens ≠ der Sender-Domain ist.
* Benutzer schulen: Verdächtigen Text per Copy-and-paste in einen Unicode-Inspector einfügen, Links per Mouseover prüfen und URL-Shortener niemals vertrauen.

## Beispiele aus der Praxis

* Anzeigename: `Сonfidеntiаl Ꭲiꮯkеt` (kyrillisches `С`, `е`, `а`; Cherokee `Ꭲ`; lateinischer Small Capital-Buchstabe `ꮯ`).
* Domain-Kette: `bestseoservices.com` ➜ kommunales `/templates`-Verzeichnis ➜ `kig.skyvaulyt.ru` ➜ gefälschte Microsoft-Anmeldeseite unter `mlcorsftpsswddprotcct.approaches.it.com`, geschützt durch ein benutzerdefiniertes OTP-CAPTCHA.
* Spotify-Imitation: Absender `Sρօtifս` mit einem hinter `redirects.ca` versteckten Link.

Diese Beispiele stammen aus der Forschung von Unit 42 (Juli 2025) und veranschaulichen, wie Homograph-Missbrauch mit URL-Weiterleitung und CAPTCHA-Umgehung kombiniert wird, um automatisierte Analysen zu umgehen.<sup>[[1]](#references)</sup>

## References

- [1] [Die Homograph-Illusion: Nicht alles ist so, wie es scheint](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode-Zeichencode-Tabellen](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard Nr. 39: Unicode-Sicherheitsmechanismen](https://unicode.org/reports/tr39/)
- [4] [dnstwist – Engine für Domain-Variationen](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – Generator für Domain-Tippfehler und -Variationen](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalisierte Domainnamen für Anwendungen (IDNA): Definitionen und Dokumentrahmen](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
