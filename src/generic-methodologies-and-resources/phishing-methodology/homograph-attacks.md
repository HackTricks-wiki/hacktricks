# Homograph- / Homoglyph-Angriffe beim Phishing

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Ein Homograph- (auch Homoglyph-)Angriff missbraucht die Tatsache, dass viele **Unicode code points aus nicht-lateinischen Schriften visuell identisch oder extrem ähnlich zu ASCII-Zeichen sind**. Durch das Ersetzen eines oder mehrerer lateinischer Zeichen durch ihre ähnlich aussehenden Gegenstücke kann ein Angreifer Folgendes erstellen:

* Anzeigenamen, Betreffzeilen oder Nachrichtentexte, die für das menschliche Auge legitim aussehen, aber keyword-basierte Erkennungen umgehen.
* Domains, Subdomains oder URL-Pfade, die Opfer davon überzeugen, eine vertrauenswürdige Website zu besuchen.<sup>[[1]](#references)</sup>

Da jedes Glyph intern durch seinen **Unicode code point** identifiziert wird, genügt ein einziges ersetztes Zeichen, um naive String-Vergleiche zu umgehen (z. B. `"Παypal.com"` gegenüber `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Typischer Phishing-Ablauf

1. **Nachrichteninhalt erstellen** – Bestimmte lateinische Buchstaben in der imitierten Marke / im Keyword durch visuell nicht unterscheidbare Zeichen aus einer anderen Schrift ersetzen (Griechisch, Kyrillisch, Armenisch, Cherokee usw.).
2. **Unterstützende Infrastruktur registrieren** – Optional eine Homoglyph-Domain registrieren und ein TLS-Zertifikat beschaffen (die meisten CAs führen keine Prüfungen auf visuelle Ähnlichkeit durch).
3. **E-Mail / SMS senden** – Die Nachricht enthält Homoglyphs an einer oder mehreren der folgenden Stellen:
* Absender-Anzeigename (z. B. `Ηеlрdеѕk`)
* Betreffzeile (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlinktext oder vollständig qualifizierter Domainname
4. **Weiterleitungskette** – Das Opfer wird über scheinbar harmlose Websites oder URL-Shortener weitergeleitet, bevor es auf dem bösartigen Host landet, der Zugangsdaten abgreift / Malware ausliefert.<sup>[[1]](#references)</sup>

## Häufig missbrauchte Unicode-Bereiche

Die folgenden Beispiele zeigen Unicode-Blöcke, die Zeichen enthalten, die häufig zum Erstellen von schriftübergreifenden Look-alikes verwendet werden.<sup>[[2]](#references)[[3]](#references)</sup>

| Schrift | Bereich | Beispiel-Glyph | Sieht aus wie |
|--------|-------|---------------|------------|
| Griechisch  | U+0370-03FF | `Η` (U+0397) | Lateinisches `H` |
| Griechisch  | U+0370-03FF | `ρ` (U+03C1) | Lateinisches `p` |
| Kyrillisch | U+0400-04FF | `а` (U+0430) | Lateinisches `a` |
| Kyrillisch | U+0400-04FF | `е` (U+0435) | Lateinisches `e` |
| Armenisch | U+0530-058F | `օ` (U+0585) | Lateinisches `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Lateinisches `T` |

> Tipp: Verwende die Unicode-Codecharts, um Blöcke und Codepoints nachzuschlagen.

## Erkennungstechniken

### 1. Überprüfung gemischter Schriften

Phishing-E-Mails, die sich an eine englischsprachige Organisation richten, sollten nur selten Zeichen aus mehreren Schriften mischen. Eine einfache, aber effektive Heuristik besteht darin:

1. Jedes Zeichen der untersuchten Zeichenkette durchlaufen.
2. Den Codepoint seinem Schriftnamen oder Unicode-Block zuzuordnen.
3. Einen Alarm auszulösen, wenn mehr als eine Schrift vorhanden ist **oder** wenn nicht-lateinische Schriften an Stellen auftauchen, an denen sie nicht erwartet werden (Anzeigename, Domain, Betreff, URL usw.).<sup>[[3]](#references)</sup>

Python-Proof-of-Concept:
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

Internationalisierte Domainnamen (IDNs) haben eine Unicode-Form und eine ASCII-kompatible **Punycode**-Form mit dem Präfix `xn--`. Konvertiere Hostnamen vor der Aufnahme in Allow-Listen oder dem Vergleich in die IDNA-/Punycode-Form und behalte die Unicode-Form für die Anzeige bei.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph-Wörterbücher / Algorithmen

Tools wie **dnstwist** (`--fuzzers homoglyph`) oder **urlcrazy** können visuell ähnliche Domain-Varianten enumerieren und sind für proaktives Takedown / Monitoring nützlich.<sup>[[4]](#references)[[5]](#references)</sup>

## Prävention & Maßnahmen

* Strenge DMARC/DKIM/SPF-Richtlinien durchsetzen – Spoofing von nicht autorisierten Domains verhindern.
* Die oben beschriebene Erkennungslogik in **Secure Email Gateways** sowie in **SIEM/XSOAR**-Playbooks implementieren.
* Nachrichten markieren oder in Quarantäne verschieben, wenn die Domain des Anzeigenamens ≠ der Absenderdomain ist.
* Benutzer sensibilisieren: verdächtigen Text per Copy & Paste in einen Unicode-Inspector einfügen, Links per Mouseover prüfen und URL-Shortener niemals vertrauen.

## Beispiele aus der Praxis

* Anzeigename: `Сonfidеntiаl Ꭲiꮯkеt` (kyrillisches `С`, `е`, `а`; Cherokee `Ꭲ`; lateinischer Kleinbuchstabe in Kapitälchen `ꮯ`).
* Domain-Kette: `bestseoservices.com` ➜ kommunales `/templates`-Verzeichnis ➜ `kig.skyvaulyt.ru` ➜ gefälschter Microsoft-Login unter `mlcorsftpsswddprotcct.approaches.it.com`, geschützt durch ein benutzerdefiniertes OTP-CAPTCHA.
* Spotify-Imitation: Absender `Sρօtifս` mit einem hinter `redirects.ca` verborgenen Link.

Diese Beispiele stammen aus einer Untersuchung von Unit 42 (Juli 2025) und veranschaulichen, wie Homograph-Missbrauch mit URL-Weiterleitung und CAPTCHA-Umgehung kombiniert wird, um automatisierte Analysen zu umgehen.<sup>[[1]](#references)</sup>

## References

- [1] [Die Homograph-Illusion: Nicht alles ist so, wie es scheint](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode-Zeichencode-Tabellen](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode-Sicherheitsmechanismen](https://unicode.org/reports/tr39/)
- [4] [dnstwist – Engine für Domain-Varianten](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – Generator für Domain-Tippfehler und -Varianten](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalisierte Domainnamen für Anwendungen (IDNA): Definitionen und Dokumentrahmen](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
