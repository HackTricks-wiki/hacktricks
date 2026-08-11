# Phishing erkennen

{{#include ../../banners/hacktricks-training.md}}

## Einleitung

Um einen Phishing-Versuch zu erkennen, ist es wichtig, **die heutzutage verwendeten Phishing-Techniken zu verstehen**. Auf der übergeordneten Seite dieses Beitrags findest du diese Informationen. Wenn dir nicht bekannt ist, welche Techniken heute verwendet werden, empfehle ich dir, zur übergeordneten Seite zu gehen und mindestens diesen Abschnitt zu lesen.

Dieser Beitrag basiert auf der Annahme, dass die **Angreifer versuchen werden, den Domainnamen des Opfers irgendwie nachzuahmen oder zu verwenden**. Wenn deine Domain `example.com` heißt und du aus irgendeinem Grund mit einem völlig anderen Domainnamen wie `youwonthelottery.com` phished wirst, werden diese Techniken dies nicht aufdecken.

## Variationen von Domainnamen

Es ist relativ **einfach**, Phishing-Versuche **aufzudecken**, bei denen ein **ähnlicher Domainname** innerhalb der E-Mail verwendet wird.\
Es reicht aus, **eine Liste der wahrscheinlichsten Phishing-Namen zu erstellen**, die ein Angreifer verwenden könnte, und zu **prüfen**, ob sie **registriert** sind, oder einfach zu überprüfen, ob eine **IP** sie verwendet.

### Verdächtige Domains finden

Für diesen Zweck kannst du eines der folgenden Tools verwenden. Beide lösen Kandidatendomains auf, um zu prüfen, ob sie verwendet werden.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tipp: Wenn du eine Kandidatenliste erstellst, speise sie auch in deine DNS-Resolver-Logs ein, um **NXDOMAIN-Abfragen aus deinem internen Netzwerk** zu erkennen (Benutzer versuchen, einen Tippfehler aufzurufen, bevor der Angreifer die Domain tatsächlich registriert). Leite diese Domains in ein Sinkhole um oder blockiere sie vorab, sofern dies die Richtlinien erlauben.

### Bitflipping

**Eine kurze Erklärung findest du auf der übergeordneten Seite. Primärforschung zum Windows.com-Bitsquatting findest du im [Beitrag von Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) und im [Bericht von BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Beispielsweise kann eine Änderung von 1 Bit in der Domain microsoft.com diese in _windnws.com_ umwandeln.\
**Angreifer könnten so viele Bit-Flipping-Domains wie möglich registrieren, die mit dem Opfer in Verbindung stehen, um legitime Benutzer auf ihre Infrastruktur umzuleiten**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle möglichen Bit-Flipping-Domainnamen sollten ebenfalls überwacht werden.**

Wenn du auch Homoglyph-/IDN-Lookalikes berücksichtigen musst (z. B. eine Mischung aus lateinischen und kyrillischen Zeichen), siehe:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Grundlegende Prüfungen

Sobald du eine Liste potenziell verdächtiger Domainnamen hast, solltest du sie **prüfen** (hauptsächlich die Ports HTTP und HTTPS), um **zu sehen, ob sie ein Login-Formular verwenden, das einem Formular der Domain des Opfers ähnelt**.\
Du könntest auch Port 3333 prüfen, um festzustellen, ob er geöffnet ist und eine Instanz von `gophish` ausgeführt wird.\
Es ist ebenfalls interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist**. Je jünger sie ist, desto höher ist das Risiko.\
Du kannst außerdem **Screenshots** der verdächtigen HTTP- und/oder HTTPS-Webseite erstellen, um zu sehen, ob sie verdächtig ist, und sie in diesem Fall **aufrufen, um sie genauer zu untersuchen**.

### Erweiterte Prüfungen

Wenn du noch einen Schritt weitergehen möchtest, empfehle ich dir, **diese verdächtigen Domains zu überwachen und gelegentlich nach weiteren zu suchen** (jeden Tag? Das dauert nur wenige Sekunden/Minuten). Du solltest außerdem die offenen **Ports** der zugehörigen IPs **prüfen und nach Instanzen von `gophish` oder ähnlichen Tools suchen** (ja, auch Angreifer machen Fehler) und die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains **überwachen**, um festzustellen, ob sie Login-Formulare von den Webseiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste der Login-Formulare der Domains des Opfers zu erstellen, die verdächtigen Webseiten zu spideren und jedes innerhalb der verdächtigen Domains gefundene Login-Formular mit jedem Login-Formular der Domain des Opfers zu vergleichen, beispielsweise mit `ssdeep`.\
Wenn du die Login-Formulare der verdächtigen Domains gefunden hast, kannst du versuchen, **Dummy-Zugangsdaten zu senden und zu prüfen, ob du auf die Domain des Opfers weitergeleitet wirst**.

---

### Suche anhand von Favicon- und Web-Fingerprints (Shodan/Censys)

Viele Phishing-Kits verwenden Favicons der Marke wieder, die sie imitieren. Shodan hasht seine Base64-codierten Favicon-Daten mit MurmurHash3, während Censys eigene Favicon-Hash-Felder bereitstellt.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Du kannst einen mit Shodan kompatiblen Hash generieren und anhand dieses Hashes weitere Informationen suchen:

Python-Beispiel (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan abfragen: `http.favicon.hash:309020573`
- Mit Tools: Sieh dir Community-Tools wie favfreak an, um Hashes zu berechnen und Shodan dorks zu generieren.<sup>[[16]](#references)</sup>

Hinweise
- Favicons werden wiederverwendet; behandle Treffer als Ausgangspunkte und validiere Inhalte und Zertifikate, bevor du aktiv wirst.
- Kombiniere dies mit Heuristiken zum Domain-Alter und zu Keywords, um eine höhere Präzision zu erreichen.

### Jagd nach URL-Telemetrie (urlscan.io)

`urlscan.io` speichert historische Screenshots, DOM, Requests und TLS-Metadaten übermittelte URLs. Damit kannst du Markenmissbrauch und Klone aufspüren:<sup>[[8]](#references)</sup>

Beispielabfragen (UI oder API):
- Finde Lookalikes unter Ausschluss deiner legitimen Domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Finde Websites, die deine Assets hotlinken: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beschränke die Suche auf aktuelle Ergebnisse: Hänge `AND date:>now-7d` an

API-Beispiel:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Aus dem JSON pivotieren auf:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, um sehr neue Zertifikate für Lookalikes zu erkennen
- `task.source`-Werte wie `certstream-suspicious`, um Findings mit CT-Monitoring zu verknüpfen

### Domain-Alter via RDAP (skriptfähig)

RDAP gibt maschinenlesbare Registrierungsereignisse zurück. Nützlich, um **neu registrierte Domains (NRDs)** zu erkennen.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Ergänze deine Pipeline, indem du Domains mit Registrierungsalterskategorien versiehst (z. B. <7 Tage, <30 Tage), und priorisiere die Triage entsprechend.

### TLS/JAx-Fingerprints zum Erkennen von AiTM-Infrastruktur

Credential-Phishing kann **Adversary-in-the-Middle (AiTM)**-Reverse-Proxys (z. B. Evilginx) verwenden, um Sitzungstokens zu stehlen.<sup>[[11]](#references)</sup> Du kannst netzwerkseitige Erkennungen hinzufügen:

- Protokolliere TLS/HTTP-Fingerprints (JA3/JA4/JA4S/JA4H) am Egress. Bei einigen Evilginx-Builds wurden stabile JA4-Client-/Serverwerte beobachtet. Löse nur bei bekannten schädlichen Fingerprints einen Alert aus, und betätige diesen immer mit Inhalts- und Domain-Informationen.<sup>[[12]](#references)</sup>
- Erfasse proaktiv TLS-Zertifikatsmetadaten (Aussteller, SAN-Anzahl, Verwendung von Wildcards, Gültigkeit) für Lookalike-Hosts, die über CT oder urlscan entdeckt wurden, und korreliere sie mit dem DNS-Alter und der Geolokalisierung.

> Hinweis: Behandle Fingerprints als Anreicherung und nicht als alleinige Blockierkriterien; Frameworks entwickeln sich weiter und können Fingerprints randomisieren oder verschleiern.

### Domainnamen mit Schlüsselwörtern

Auf der übergeordneten Seite wird außerdem eine Technik zur Variation von Domainnamen erwähnt, bei der der **Domainname des Opfers in eine größere Domain eingebettet** wird (z. B. paypal-financial.com für paypal.com).

#### Certificate Transparency

Certificate-Transparency-(CT-)Logs legen Zertifikatsidentitäten offen. Die Suche nach Markenschlüsselwörtern in Subject- oder SAN-Namen kann daher Lookalike-Domains aufdecken (beispielsweise legt ein Zertifikat für `paypal-financial.com` das Schlüsselwort `paypal` offen). Filtere die Ergebnisse bei Bedarf nach Ausstellungsdatum und CA, und validiere die Kandidaten, da Übereinstimmungen mit Schlüsselwörtern False Positives sein können.<sup>[[13]](#references)</sup>

Patrik Hudaks ursprünglicher [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) demonstriert diesen Workflow in Censys, einschließlich Filtern für Zertifikatsdatum und Aussteller wie Let's Encrypt.<sup>[[13]](#references)</sup>

Du kannst auch den kostenlosen Service [**crt.sh**](https://crt.sh) verwenden, um nach einem Schlüsselwort zu suchen und die Ergebnisse nach Datum und CA zu filtern.<sup>[[13]](#references)</sup>

Das Feld „Matching Identities“ kann beim Vergleich von Identitäten der echten Domain mit verdächtigen Domains helfen. Betrachte Übereinstimmungen jedoch als Hinweise und nicht als Beweis.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) streamt CT-Aktualisierungen nahezu in Echtzeit, und [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) verarbeitet diesen Stream, um verdächtige Zertifikatsnamen zu bewerten.<sup>[[14]](#references)[[15]](#references)</sup>

Praktischer Tipp: Priorisiere bei der Triage von CT-Treffern NRDs, nicht vertrauenswürdige oder unbekannte Registrare, WHOIS-Datenschutz-Proxys und Zertifikate mit sehr aktuellen `NotBefore`-Zeitpunkten. Führe eine Allowlist deiner eigenen Domains und Marken, um das Rauschen zu reduzieren.

#### **Neue Domains**

Eine zweite Möglichkeit besteht darin, neu registrierte Domains nach TLD zu sammeln (beispielsweise über [Whoxy](https://www.whoxy.com/newly-registered-domains/)) und nach Markenschlüsselwörtern zu filtern. Dadurch wird Phishing über Subdomains übersehen, wenn das Schlüsselwort in der registrierten Domain nicht vorkommt.<sup>[[13]](#references)</sup>

Zusätzliche Heuristik: Behandle bestimmte **Dateiendungs-TLDs** (z. B. `.zip`, `.mov`) in Alerts mit besonderem Misstrauen. Sie werden in Lures häufig mit Dateinamen verwechselt. Kombiniere das TLD-Signal mit Markenschlüsselwörtern und dem NRD-Alter, um eine höhere Präzision zu erreichen.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Übernahme des Datenverkehrs zu Microsofts windows.com durch Bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Tiefenanalyse: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-Dokumentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Hilfe zum Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-Antworten für das Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token-Taktiken: So verhinderst, erkennst und beantwortest du den Diebstahl von Cloud-Tokens](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+-Netzwerk-Fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing finden: Tools und Techniken](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream vorgestellt](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
