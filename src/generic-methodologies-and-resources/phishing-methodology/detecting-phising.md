# Phishing erkennen

## Introduction

Um einen Phishing-Versuch zu erkennen, ist es wichtig, **die heutzutage verwendeten Phishing-Techniken zu verstehen**. Auf der übergeordneten Seite dieses Beitrags findest du diese Informationen. Wenn du also nicht weißt, welche Techniken heute verwendet werden, empfehle ich dir, zur übergeordneten Seite zu gehen und mindestens diesen Abschnitt zu lesen.

Dieser Beitrag basiert auf der Annahme, dass **die Angreifer versuchen werden, den Domainnamen des Opfers auf irgendeine Weise nachzuahmen oder zu verwenden**. Wenn deine Domain `example.com` heißt und du aus irgendeinem Grund über eine völlig andere Domain wie `youwonthelottery.com` gephished wirst, werden diese Techniken dies nicht aufdecken.

## Variationen von Domainnamen

Es ist relativ **einfach**, **Phishing**-Versuche **aufzudecken**, bei denen in der E-Mail ein **ähnlicher Domainname** verwendet wird.\
Es reicht aus, **eine Liste der wahrscheinlichsten Phishing-Namen zu erstellen**, die ein Angreifer verwenden könnte, und zu **prüfen**, ob sie **registriert** sind, oder einfach zu überprüfen, ob eine **IP** sie verwendet.

### Verdächtige Domains finden

Für diesen Zweck kannst du eines der folgenden Tools verwenden. Beide lösen mögliche Domains auf, um zu prüfen, ob sie verwendet werden.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tipp: Wenn du eine Liste möglicher Domains erstellst, speise sie auch in deine DNS-Resolver-Logs ein, um **NXDOMAIN-Abfragen aus deiner Organisation** zu erkennen (Benutzer versuchen, einen Tippfehler aufzurufen, bevor der Angreifer ihn tatsächlich registriert). Leite diese Domains in ein Sinkhole um oder blockiere sie vorab, sofern dies laut Richtlinie zulässig ist.

### Bitflipping

**Eine kurze Erklärung findest du auf der übergeordneten Seite. Primäre Forschung zu Bitsquatting auf Windows.com findest du in [Remy Hax' write-up](https://remyhax.xyz/posts/bitsquatting-windows/) und im [Bericht von BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Beispielsweise kann eine Änderung von 1 Bit in der Domain microsoft.com diese in _windnws.com_ umwandeln.\
**Angreifer können so viele mit dem Opfer verbundene Bit-Flipping-Domains wie möglich registrieren, um legitime Benutzer zu ihrer Infrastruktur umzuleiten**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle möglichen Bit-Flipping-Domainnamen sollten ebenfalls überwacht werden.**

Wenn du auch Homoglyph-/IDN-Lookalikes berücksichtigen musst (z. B. die Mischung von lateinischen und kyrillischen Zeichen), siehe:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Grundlegende Prüfungen

Sobald du eine Liste potenziell verdächtiger Domainnamen hast, solltest du sie **prüfen** (hauptsächlich die Ports HTTP und HTTPS), um **festzustellen, ob sie ein Login-Formular verwenden, das dem eines Opfers ähnelt**.\
Du könntest auch Port 3333 prüfen, um festzustellen, ob er geöffnet ist und eine Instanz von `gophish` ausgeführt wird.\
Außerdem ist es interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist**. Je jünger sie ist, desto höher ist das Risiko.\
Du kannst auch **Screenshots** der verdächtigen HTTP- und/oder HTTPS-Webseite erstellen, um zu prüfen, ob sie verdächtig ist, und sie in diesem Fall **aufrufen, um sie genauer zu untersuchen**.

### Erweiterte Prüfungen

Wenn du noch einen Schritt weitergehen möchtest, empfehle ich dir, **diese verdächtigen Domains zu überwachen und gelegentlich nach weiteren zu suchen** (jeden Tag? Das dauert nur wenige Sekunden/Minuten). Du solltest außerdem die offenen **Ports** der zugehörigen IPs **prüfen** und nach **Instanzen von `gophish` oder ähnlichen Tools suchen** (ja, auch Angreifer machen Fehler) sowie die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains **überwachen**, um festzustellen, ob sie Login-Formulare von den Webseiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste der Login-Formulare der Domains des Opfers zu erstellen, die verdächtigen Webseiten zu crawlen und jedes in den verdächtigen Domains gefundene Login-Formular mit jedem Login-Formular der Domain des Opfers zu vergleichen, beispielsweise mit `ssdeep`.\
Wenn du die Login-Formulare der verdächtigen Domains gefunden hast, kannst du versuchen, **ungültige Zugangsdaten zu senden** und **zu prüfen, ob du zur Domain des Opfers weitergeleitet wirst**.

---

### Suche anhand von Favicon und Web-Fingerprints (Shodan/Censys)

Viele Phishing-Kits verwenden Favicons der Marke wieder, die sie imitieren. Shodan hasht die Base64-kodierten Favicon-Daten mit MurmurHash3, während Censys eigene Favicon-Hash-Felder bereitstellt.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Du kannst einen mit Shodan kompatiblen Hash erstellen und darauf basierend pivotieren:

Python-Beispiel (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan abfragen: `http.favicon.hash:309020573`
- Mit Tools: Sieh dir Community-Tools wie favfreak an, um Hashes zu berechnen und Shodan-Dorks zu generieren.<sup>[[16]](#references)</sup>

Hinweise
- Favicons werden wiederverwendet. Behandle Treffer als Ansatzpunkte und überprüfe Inhalte und Zertifikate, bevor du tätig wirst.
- Kombiniere dies mit Heuristiken zu Domain-Alter und Schlüsselwörtern, um die Präzision zu erhöhen.

### URL-Telemetrie-Suche (urlscan.io)

`urlscan.io` speichert historische Screenshots, DOM, Requests und TLS-Metadaten übermittelte URLs. Damit kannst du Markenmissbrauch und Klone suchen:<sup>[[8]](#references)</sup>

Beispielabfragen (UI oder API):
- Ähnliche Domains finden und deine legitimen Domains ausschließen: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Websites finden, die deine Assets per Hotlink einbinden: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Auf aktuelle Ergebnisse beschränken: `AND date:>now-7d` anhängen

API-Beispiel:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Aus der JSON können Sie nach folgenden Feldern pivotieren:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, um sehr neue Zertifikate für Lookalikes zu erkennen
- `task.source`-Werte wie `certstream-suspicious`, um Findings mit der CT-Überwachung zu verknüpfen

### Domain-Alter über RDAP (skriptfähig)

RDAP gibt maschinenlesbare Registrierungsereignisse zurück. Dies ist nützlich, um **neu registrierte Domains (NRDs)** zu erkennen.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Reichere deine Pipeline an, indem du Domains mit Kategorien für das Registrierungsalter versiehst (z. B. <7 Tage, <30 Tage) und die Triage entsprechend priorisierst.

### TLS/JAx-Fingerprints zum Erkennen von AiTM-Infrastruktur

Credential-Phishing kann **Adversary-in-the-Middle (AiTM)**-Reverse-Proxies (z. B. Evilginx) verwenden, um Session-Tokens zu stehlen.<sup>[[11]](#references)</sup> Du kannst netzwerkseitige Erkennungen hinzufügen:

- Protokolliere TLS/HTTP-Fingerprints (JA3/JA4/JA4S/JA4H) am Egress. Bei einigen Evilginx-Builds wurden stabile JA4-Client-/Serverwerte beobachtet. Löse nur bei bekannten schädlichen Fingerprints einen Alarm aus, und das auch nur als schwaches Signal; bestätige dies immer anhand von Inhalten und Domain-Informationen.<sup>[[12]](#references)</sup>
- Erfasse proaktiv TLS-Zertifikatsmetadaten (Aussteller, SAN-Anzahl, Wildcard-Nutzung, Gültigkeit) für ähnlich aussehende Hosts, die über CT oder urlscan entdeckt wurden, und korreliere sie mit dem DNS-Alter und der Geolokalisierung.

> Hinweis: Behandle Fingerprints als Anreicherung und nicht als alleinige Blockierungsgrundlage; Frameworks entwickeln sich weiter und können Fingerprints randomisieren oder verschleiern.

### Domainnamen mit Keywords

Die übergeordnete Seite erwähnt außerdem eine Technik zur Variation von Domainnamen, bei der der **Domainname des Opfers in eine größere Domain eingefügt wird** (z. B. paypal-financial.com für paypal.com).

#### Certificate Transparency

Certificate-Transparency-(CT-)Logs legen Zertifikatsidentitäten offen. Daher kann die Suche nach Marken-Keywords in Subject- oder SAN-Namen ähnlich aussehende Domains aufdecken (beispielsweise legt ein Zertifikat für `paypal-financial.com` das Keyword `paypal` offen). Filtere Ergebnisse bei Bedarf nach Ausstellungsdatum und CA, und validiere die Kandidaten, da Keyword-Treffer False Positives sein können.<sup>[[13]](#references)</sup>

Patrik Hudaks ursprünglicher [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) demonstriert diesen Workflow in Censys, einschließlich Filtern für Zertifikatsdatum und Aussteller wie Let's Encrypt.<sup>[[13]](#references)</sup>

Du kannst auch den kostenlosen Service [**crt.sh**](https://crt.sh) verwenden, um nach einem Keyword zu suchen und Ergebnisse nach Datum und CA zu filtern.<sup>[[13]](#references)</sup>

Das Feld „Matching Identities“ kann dabei helfen, Identitäten der echten Domain mit verdächtigen Domains zu vergleichen. Behandle Übereinstimmungen jedoch als Hinweise und nicht als Beweis.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) streamt CT-Aktualisierungen nahezu in Echtzeit, und [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) nutzt diesen Stream, um verdächtige Zertifikatsnamen zu bewerten.<sup>[[14]](#references)[[15]](#references)</sup>

Praktischer Tipp: Priorisiere bei der Triage von CT-Treffern NRDs, nicht vertrauenswürdige/unbekannte Registrare, WHOIS mit Privacy-Proxy und Zertifikate mit sehr aktuellen `NotBefore`-Zeitpunkten. Pflege eine Allowlist deiner eigenen Domains/Marken, um Rauschen zu reduzieren.

#### **Neue Domains**

Eine zweite Möglichkeit besteht darin, neu registrierte Domains nach TLD zu sammeln (beispielsweise über [Whoxy](https://www.whoxy.com/newly-registered-domains/)) und nach Marken-Keywords zu filtern. Dadurch wird Phishing über Subdomains übersehen, wenn das Keyword in der registrierten Domain nicht vorkommt.<sup>[[13]](#references)</sup>

Zusätzliche Heuristik: Behandle bestimmte **Dateiendungs-TLDs** (z. B. `.zip`, `.mov`) bei der Alarmierung mit erhöhter Vorsicht. In Lures werden sie häufig mit Dateinamen verwechselt. Kombiniere das TLD-Signal mit Marken-Keywords und dem NRD-Alter, um eine höhere Präzision zu erzielen.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Übernahme des Datenverkehrs zu Microsofts windows.com durch Bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Tiefgehende Analyse: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-Dokumentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Datensatz zu Web-Properties von Plattformen](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referenz der Search API](https://urlscan.io/docs/search/)
- [9] [Hilfe zum Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-Antworten für das Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token-Taktiken: So verhinderst, erkennst und behandelst du den Diebstahl von Cloud-Tokens](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+-Netzwerk-Fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing finden: Tools und Techniken](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream vorgestellt](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
