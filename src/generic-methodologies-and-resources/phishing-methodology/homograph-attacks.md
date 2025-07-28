# Homograph / Homoglyph Angriffe im Phishing

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Ein Homograph (auch Homoglyph) Angriff nutzt die Tatsache aus, dass viele **Unicode-Codepunkte aus nicht-lateinischen Schriften visuell identisch oder extrem ähnlich zu ASCII-Zeichen sind**. Durch das Ersetzen eines oder mehrerer lateinischer Zeichen durch ihre ähnlich aussehenden Gegenstücke kann ein Angreifer:

* Anzeigenamen, Betreffzeilen oder Nachrichteninhalte erstellen, die für das menschliche Auge legitim erscheinen, aber keyword-basierte Erkennungen umgehen.
* Domains, Subdomains oder URL-Pfade erstellen, die Opfer dazu bringen, zu glauben, sie besuchen eine vertrauenswürdige Seite.

Da jedes Glyph intern durch seinen **Unicode-Codepunkt** identifiziert wird, reicht ein einzelnes ersetztes Zeichen aus, um naive String-Vergleiche zu überwinden (z. B. `"Παypal.com"` vs. `"Paypal.com"`).

## Typischer Phishing-Workflow

1. **Nachrichteninhalt erstellen** – Ersetzen Sie spezifische lateinische Buchstaben in der impersonierten Marke / dem Schlüsselwort durch visuell nicht unterscheidbare Zeichen aus einer anderen Schrift (Griechisch, Kyrillisch, Armenisch, Cherokee usw.).
2. **Unterstützende Infrastruktur registrieren** – Optional eine Homoglyph-Domain registrieren und ein TLS-Zertifikat erhalten (die meisten CAs führen keine visuellen Ähnlichkeitsprüfungen durch).
3. **E-Mail / SMS senden** – Die Nachricht enthält Homoglyphen an einem oder mehreren der folgenden Orte:
* Absenderanzeige (z. B. `Ηеlрdеѕk`)
* Betreffzeile (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink-Text oder vollqualifizierter Domainname
4. **Umleitungs-Kette** – Das Opfer wird durch scheinbar harmlose Websites oder URL-Shortener geleitet, bevor es auf dem bösartigen Host landet, der Anmeldeinformationen erntet / Malware liefert.

## Häufig missbrauchte Unicode-Bereiche

| Schrift | Bereich | Beispiel-Glyph | Sieht aus wie |
|--------|-------|---------------|------------|
| Griechisch  | U+0370-03FF | `Η` (U+0397) | Latein `H` |
| Griechisch  | U+0370-03FF | `ρ` (U+03C1) | Latein `p` |
| Kyrillisch | U+0400-04FF | `а` (U+0430) | Latein `a` |
| Kyrillisch | U+0400-04FF | `е` (U+0435) | Latein `e` |
| Armenisch | U+0530-058F | `օ` (U+0585) | Latein `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latein `T` |

> Tipp: Vollständige Unicode-Diagramme sind verfügbar unter [unicode.org](https://home.unicode.org/).

## Erkennungstechniken

### 1. Mischschriftinspektion

Phishing-E-Mails, die sich an eine englischsprachige Organisation richten, sollten selten Zeichen aus mehreren Schriften mischen. Eine einfache, aber effektive Heuristik ist es,:

1. Jedes Zeichen des inspizierten Strings zu durchlaufen.
2. Den Codepunkt seinem Unicode-Block zuzuordnen.
3. Eine Warnung auszulösen, wenn mehr als eine Schrift vorhanden ist **oder** wenn nicht-lateinische Schriften an unerwarteten Stellen erscheinen (Anzeigename, Domain, Betreff, URL usw.).

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

Internationalisierte Domainnamen (IDNs) werden mit **punycode** (`xn--`) codiert. Die Umwandlung jedes Hostnamens in Punycode und dann zurück in Unicode ermöglicht das Abgleichen mit einer Whitelist oder das Durchführen von Ähnlichkeitsprüfungen (z. B. Levenshtein-Distanz) **nachdem** der String normalisiert wurde.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph-Wörterbücher / Algorithmen

Tools wie **dnstwist** (`--homoglyph`) oder **urlcrazy** können visuell ähnliche Domain-Permutationen auflisten und sind nützlich für proaktive Abschaltungen / Überwachung.

## Prävention & Minderung

* Strenge DMARC/DKIM/SPF-Richtlinien durchsetzen – Spoofing von unautorisierten Domains verhindern.
* Implementieren Sie die oben genannte Erkennungslogik in **Secure Email Gateways** und **SIEM/XSOAR**-Playbooks.
* Nachrichten kennzeichnen oder quarantänisieren, bei denen der Anzeigename-Domain ≠ Absender-Domain.
* Benutzer schulen: Verdächtigen Text in einen Unicode-Inspektor kopieren, Links überfahren, URL-Shortener niemals vertrauen.

## Beispiele aus der Praxis

* Anzeigename: `Сonfidеntiаl Ꭲiꮯkеt` (Kyrillisch `С`, `е`, `а`; Cherokee `Ꭲ`; lateinisches Kleinbuchstaben `ꮯ`).
* Domain-Kette: `bestseoservices.com` ➜ kommunales `/templates` Verzeichnis ➜ `kig.skyvaulyt.ru` ➜ gefälschte Microsoft-Anmeldung bei `mlcorsftpsswddprotcct.approaches.it.com`, geschützt durch benutzerdefinierte OTP CAPTCHA.
* Spotify-Imitation: `Sρօtifւ` Absender mit Link, der hinter `redirects.ca` verborgen ist.

Diese Beispiele stammen aus der Forschung von Unit 42 (Juli 2025) und veranschaulichen, wie Homographenmissbrauch mit URL-Umleitung und CAPTCHA-Umgehung kombiniert wird, um automatisierte Analysen zu umgehen.

## Referenzen

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
