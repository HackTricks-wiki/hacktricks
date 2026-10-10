# Phishing erkennen

{{#include ../../banners/hacktricks-training.md}}

## Einführung

Um einen Phishing-Versuch zu erkennen, ist es wichtig, **die heutzutage verwendeten Phishing-Techniken zu verstehen**. Auf der übergeordneten Seite dieses Beitrags findest du diese Informationen. Wenn du also nicht weißt, welche Techniken heute eingesetzt werden, empfehle ich dir, zur übergeordneten Seite zu gehen und mindestens diesen Abschnitt zu lesen.

Dieser Beitrag basiert auf der Annahme, dass **Angreifer versuchen werden, den Domainnamen des Opfers auf irgendeine Weise nachzuahmen oder zu verwenden**. Wenn deine Domain `example.com` heißt und du aus irgendeinem Grund mit einem völlig anderen Domainnamen wie `youwonthelottery.com` angegriffen wirst, werden diese Techniken ihn nicht aufdecken.

## Variationen von Domainnamen

Es ist ziemlich **einfach**, jene **Phishing**-Versuche **aufzudecken**, bei denen in der E-Mail ein **ähnlicher Domainname** verwendet wird.\
Es reicht aus, **eine Liste der wahrscheinlichsten Phishing-Namen zu erstellen**, die ein Angreifer verwenden könnte, und zu **prüfen**, ob sie **registriert** sind, oder einfach zu prüfen, ob eine **IP** sie verwendet.

### Verdächtige Domains finden

Zu diesem Zweck kannst du eines der folgenden Tools verwenden. Beide lösen mögliche Domains auf, um zu prüfen, ob sie verwendet werden.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tipp: Wenn du eine Liste möglicher Domains erstellst, speise sie auch in die Logs deines DNS-Resolvers ein, um **NXDOMAIN-Abfragen aus deinem Unternehmen** zu erkennen (Nutzer versuchen, eine falsch geschriebene Domain aufzurufen, bevor der Angreifer sie tatsächlich registriert). Leite diese Domains auf einen Sinkhole um oder blockiere sie vorab, sofern die Richtlinien dies zulassen.

### Bitflipping

**Eine kurze Erklärung findest du auf der übergeordneten Seite. Primärforschung zum Bitsquatting auf Windows.com findest du in [Remy Hax' Beitrag](https://remyhax.xyz/posts/bitsquatting-windows/) und im [Bericht von BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Zum Beispiel kann eine Änderung um 1 Bit in der Domain microsoft.com sie in _windnws.com_ verwandeln.\
**Angreifer könnten so viele Bitflipping-Domains wie möglich registrieren, die mit dem Opfer zusammenhängen, um legitime Nutzer auf ihre Infrastruktur umzuleiten**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle möglichen Bitflipping-Domainnamen sollten ebenfalls überwacht werden.**

Wenn du auch Homoglyphen-/IDN-Lookalikes berücksichtigen musst (z. B. eine Mischung aus lateinischen und kyrillischen Zeichen), siehe:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Grundlegende Prüfungen

Sobald du eine Liste potenziell verdächtiger Domainnamen hast, solltest du sie prüfen (vor allem die Ports HTTP und HTTPS), um **festzustellen, ob sie ein Login-Formular verwenden, das dem einer Domain des Opfers ähnelt**.\
Du könntest auch Port 3333 prüfen, um festzustellen, ob er offen ist und eine Instanz von `gophish` läuft.\
Außerdem ist es interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist**: Je jünger sie ist, desto riskanter ist sie.\
Du kannst auch **Screenshots** der verdächtigen HTTP- und/oder HTTPS-Webseite erstellen, um zu prüfen, ob sie verdächtig ist, und sie in diesem Fall **aufrufen, um sie genauer zu untersuchen**.

### Erweiterte Prüfungen

Wenn du noch einen Schritt weiter gehen möchtest, empfehle ich dir, **diese verdächtigen Domains zu überwachen und regelmäßig nach weiteren zu suchen** (jeden Tag? Das dauert nur ein paar Sekunden oder Minuten). Du solltest auch die offenen **Ports** der zugehörigen IPs **prüfen**, nach Instanzen von `gophish` oder ähnlichen Tools **suchen** (ja, auch Angreifer machen Fehler) und die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains **überwachen**, um zu sehen, ob sie Login-Formulare von den Webseiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste der Login-Formulare der Domains des Opfers zu erstellen, die verdächtigen Webseiten zu crawlen und jedes dort gefundene Login-Formular mit jedem Login-Formular der Domains des Opfers zu vergleichen, beispielsweise mit `ssdeep`.\
Wenn du die Login-Formulare der verdächtigen Domains gefunden hast, kannst du versuchen, **gefälschte Zugangsdaten zu senden** und **prüfen, ob du zur Domain des Opfers weitergeleitet wirst**.

---

### Suche anhand von Favicons und Web-Fingerprints (Shodan/Censys)

Viele Phishing-Kits verwenden Favicons der Marke, die sie imitieren. Shodan hasht die base64-kodierten Favicon-Daten mit MurmurHash3, während Censys eigene Favicon-Hash-Felder bereitstellt.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Du kannst einen mit Shodan kompatiblen Hash erzeugen und damit suchen:

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
- Favicons werden wiederverwendet; betrachte Treffer als Hinweise und überprüfe Inhalte und Zertifikate, bevor du handelst.
- Kombiniere dies mit Heuristiken zum Domain-Alter und zu Schlüsselwörtern, um die Präzision zu verbessern.

### URL-Telemetrie durchsuchen (urlscan.io)

`urlscan.io` speichert historische Screenshots, DOM, Anfragen und TLS-Metadaten eingereichter URLs. Damit kannst du nach Markenmissbrauch und Klonen suchen:<sup>[[8]](#references)</sup>

Beispielabfragen (UI oder API):
- Finde ähnlich aussehende Domains, wobei deine legitimen Domains ausgeschlossen werden: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Finde Websites, die deine Assets per Hotlink einbinden: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beschränke die Ergebnisse auf aktuelle Einträge: `AND date:>now-7d` anhängen

API-Beispiel:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Im JSON nach folgenden Feldern suchen:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, um sehr neue Zertifikate für Lookalikes zu erkennen
- Werte wie `certstream-suspicious` in `task.source`, um Funde dem CT-Monitoring zuzuordnen

### Domain-Alter via RDAP (skriptfähig)

RDAP gibt maschinenlesbare Registrierungsereignisse zurück. Nützlich, um **neu registrierte Domains (NRDs)** zu erkennen.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Reichern Sie Ihre Pipeline an, indem Sie Domains mit Registrierungsaltersklassen (z. B. <7 Tage, <30 Tage) kennzeichnen und die Triage entsprechend priorisieren.

### TLS-/JAx-Fingerprints zur Erkennung von AiTM-Infrastruktur

Credential-Phishing kann **Adversary-in-the-Middle (AiTM)**-Reverse-Proxys (z. B. Evilginx) einsetzen, um Sitzungstoken zu stehlen.<sup>[[11]](#references)</sup> Sie können netzwerkseitige Erkennungen ergänzen:

- Protokollieren Sie TLS-/HTTP-Fingerprints (JA3/JA4/JA4S/JA4H) am Egress. Bei einigen Evilginx-Builds wurden stabile JA4-Client-/Server-Werte beobachtet. Lösen Sie nur bei bekannten schädlichen Fingerprints einen Alarm aus, und zwar nur als schwaches Signal. Bestätigen Sie den Verdacht stets anhand von Inhalten und Domain-Informationen.<sup>[[12]](#references)</sup>
- Erfassen Sie proaktiv TLS-Zertifikatmetadaten (Aussteller, Anzahl der SANs, Wildcard-Nutzung, Gültigkeit) für Lookalike-Hosts, die über CT oder urlscan entdeckt wurden, und korrelieren Sie diese mit dem DNS-Alter und der Geolokalisierung.

> Hinweis: Verwenden Sie Fingerprints als Anreicherung, nicht als alleinige Blockierkriterien; Frameworks entwickeln sich weiter und können ihre Fingerprints randomisieren oder verschleiern.

### Domainnamen mit Schlüsselwörtern

Auf der übergeordneten Seite wird außerdem eine Domainnamen-Variationsmethode erwähnt, bei der der **Domainname des Opfers in eine größere Domain eingebettet** wird (z. B. paypal-financial.com für paypal.com).

#### Certificate Transparency

Certificate-Transparency-(CT-)Logs legen Zertifikatsidentitäten offen. Daher kann die Suche nach Marken-Schlüsselwörtern in Subject- oder SAN-Namen Lookalike-Domains aufdecken (beispielsweise enthält ein Zertifikat für `paypal-financial.com` das Schlüsselwort `paypal`). Filtern Sie die Ergebnisse bei Bedarf nach Ausstellungsdatum und CA und überprüfen Sie mögliche Treffer, da Schlüsselwortübereinstimmungen falsch positiv sein können.<sup>[[13]](#references)</sup>

Patrik Hudaks ursprünglicher [Bericht zur Suche nach Phishing-Domains](https://0xpatrik.com/phishing-domains/) demonstriert diesen Workflow in Censys, einschließlich Filtern nach Zertifikatsdatum und Aussteller wie Let's Encrypt.<sup>[[13]](#references)</sup>

![Censys-Zertifikat-Suchergebnisse zur Identifizierung von Lookalike-Domains](<../../images/image (1115).png>)

Sie können auch den kostenlosen Dienst [**crt.sh**](https://crt.sh) verwenden, um nach einem Schlüsselwort zu suchen und die Ergebnisse nach Datum und CA zu filtern.<sup>[[13]](#references)</sup>

![crt.sh-Schlüsselwortsuche nach verdächtigen Zertifikatsidentitäten](<../../images/image (519).png>)

Das Feld „Matching Identities“ kann beim Vergleich der Identitäten der echten Domain mit denen verdächtiger Domains helfen. Behandeln Sie Übereinstimmungen jedoch als Hinweise und nicht als Beweis.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) streamt CT-Aktualisierungen nahezu in Echtzeit. [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) verarbeitet diesen Stream, um verdächtige Zertifikatsnamen zu bewerten.<sup>[[14]](#references)[[15]](#references)</sup>

Praktischer Tipp: Priorisieren Sie bei der Triage von CT-Treffern NRDs, nicht vertrauenswürdige oder unbekannte Registrare, WHOIS-Datensätze mit Privacy-Proxy und Zertifikate mit sehr aktuellen `NotBefore`-Zeitstempeln. Führen Sie eine Zulassungsliste Ihrer eigenen Domains und Marken, um Fehlalarme zu reduzieren.

#### **Neue Domains**

Eine weitere Möglichkeit besteht darin, neu registrierte Domains nach TLD zu sammeln (beispielsweise über [Whoxy](https://www.whoxy.com/newly-registered-domains/)) und nach Marken-Schlüsselwörtern zu filtern. Dadurch wird Phishing über Subdomains übersehen, wenn das Schlüsselwort nicht in der registrierten Domain vorkommt.<sup>[[13]](#references)</sup>

Zusätzliche Heuristik: Behandeln Sie bestimmte **Dateiendungs-TLDs** (z. B. `.zip`, `.mov`) bei der Alarmierung mit besonderer Vorsicht. Sie werden in Ködern häufig mit Dateinamen verwechselt. Kombinieren Sie das TLD-Signal mit Marken-Schlüsselwörtern und dem NRD-Alter, um die Präzision zu erhöhen.

## References

- [1] [Remy Hax – Bitsquatting bei Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Datenverkehr zu Microsofts windows.com mit Bitflipping kapern](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Tiefenanalyse: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-Dokumentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform-Web-Property-Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referenz zur Search API](https://urlscan.io/docs/search/)
- [9] [Hilfe zum Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-Antworten für das Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token-Taktiken: So verhindern, erkennen und bewältigen Sie den Diebstahl von Cloud-Token](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+-Netzwerk-Fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing finden: Tools und Techniken](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream vorgestellt](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
