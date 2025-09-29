# Erkennen von Phishing

{{#include ../../banners/hacktricks-training.md}}

## Einleitung

Um einen Phishing-Versuch zu erkennen, ist es wichtig, die **Phishing-Techniken zu verstehen, die heutzutage verwendet werden**. Auf der übergeordneten Seite dieses Beitrags findest du diese Informationen; wenn du nicht weißt, welche Techniken heute verwendet werden, empfehle ich, die übergeordnete Seite zu lesen und zumindest diesen Abschnitt zu prüfen.

Dieser Beitrag basiert auf der Idee, dass die **Angreifer versuchen werden, irgendwie den Domainnamen des Opfers zu imitieren oder zu nutzen**. Wenn deine Domain `example.com` heißt und du mit einer völlig anderen Domain wie `youwonthelottery.com` gephisht wirst, werden diese Techniken das nicht aufdecken.

## Domain name variations

Es ist recht **einfach**, diese **Phishing**-Versuche aufzudecken, die einen **ähnlichen Domain**-Namen in der E-Mail verwenden.\
Es reicht aus, eine Liste der wahrscheinlichsten Phishing-Namen zu **generieren**, die ein Angreifer verwenden könnte, und zu **prüfen**, ob sie **registriert** sind oder ob irgendeine **IP** sie verwendet.

### Finding suspicious domains

Für diesen Zweck kannst du eines der folgenden Tools verwenden. Beachte, dass diese Tools automatisch DNS-Anfragen durchführen, um zu prüfen, ob der Domain eine IP zugewiesen ist:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tipp: Wenn du eine Kandidatenliste erzeugst, füttere sie auch in deine DNS-Resolver-Logs, um **NXDOMAIN-Abfragen aus deinem Unternehmen** zu erkennen (Benutzer, die versuchen, einen Tippfehler aufzurufen, bevor der Angreifer ihn tatsächlich registriert). Sinkhole oder blockiere diese Domains vorab, wenn die Richtlinie das erlaubt.

### Bitflipping

**Einer kurzen Erklärung dieser Technik findest du auf der übergeordneten Seite. Oder lies die Originalforschung unter** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Zum Beispiel kann eine 1-Bit-Änderung in der Domain microsoft.com sie in _windnws.com._ verwandeln.\
**Angreifer können so viele bit-flipping-Domains wie möglich im Zusammenhang mit dem Opfer registrieren, um legitime Benutzer auf ihre Infrastruktur umzuleiten.**

**Alle möglichen bit-flipping-Domainnamen sollten ebenfalls überwacht werden.**

Wenn du auch Homoglyph/IDN-Lookalikes (z. B. Mischung aus lateinischen/kyrillischen Zeichen) berücksichtigen musst, schau nach:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

Sobald du eine Liste potenziell verdächtiger Domainnamen hast, solltest du sie **prüfen** (hauptsächlich die Ports HTTP und HTTPS), um **zu sehen, ob sie ein Login-Formular verwenden, das dem einer Domain des Opfers ähnelt**.\
Du könntest auch Port 3333 prüfen, um zu sehen, ob er offen ist und eine Instanz von `gophish` läuft.\
Es ist außerdem interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist** — je jünger, desto riskanter.\
Du kannst auch **Screenshots** der HTTP- und/oder HTTPS-Seite der verdächtigen Domain erstellen, um zu prüfen, ob sie verdächtig ist, und in diesem Fall **diese Seite aufrufen, um sie genauer zu untersuchen**.

### Advanced checks

Wenn du einen Schritt weiter gehen willst, empfehle ich, diese verdächtigen Domains zu **überwachen und gelegentlich nach weiteren zu suchen** (täglich? es dauert nur ein paar Sekunden/Minuten). Du solltest auch die offenen **Ports** der zugehörigen IPs prüfen und **nach Instanzen von `gophish` oder ähnlichen Tools suchen** (ja, Angreifer machen auch Fehler) und die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains **überwachen**, um zu sehen, ob sie ein Login-Formular von den Seiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste der Login-Formulare der Domains des Opfers zu haben, die verdächtigen Webseiten zu crawlen und jedes gefundene Login-Formular auf den verdächtigen Domains mit jedem Login-Formular der Opfer-Domain mittels etwas wie `ssdeep` zu vergleichen.\
Wenn du die Login-Formulare der verdächtigen Domains gefunden hast, kannst du versuchen, **verfälschte Zugangsdaten zu senden** und **zu prüfen, ob sie dich auf die Domain des Opfers umleiten**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Viele Phishing-Kits verwenden Favicons der Marke, die sie imitieren, wieder. Internetweite Scanner berechnen einen MurmurHash3 des base64-encodierten Favicons. Du kannst den Hash erzeugen und darauf pivotieren:

Python-Beispiel (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan abfragen: `http.favicon.hash:309020573`
- Mit Tools: Schau dir Community-Tools wie favfreak an, um Hashes und Dorks für Shodan/ZoomEye/Censys zu generieren.

Hinweise
- Favicons werden wiederverwendet; behandle Treffer als Leads und validiere Inhalt und Zertifikate, bevor du handelst.
- Kombiniere mit domain-age und Keyword-Heuristiken für bessere Präzision.

### URL-Telemetrie-Suche (urlscan.io)

`urlscan.io` speichert historische Screenshots, DOM, Requests und TLS-Metadaten von übermittelten URLs. Du kannst nach Markenmissbrauch und Kopien suchen:

Beispielabfragen (UI oder API):
- Finde Lookalikes unter Ausschluss deiner legitimen Domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Finde Seiten, die deine Assets hotlinken: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Auf jüngste Ergebnisse beschränken: füge `AND date:>now-7d` hinzu

API-Beispiel:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Aus dem JSON, pivot auf:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` um sehr neue certs bei Lookalikes zu erkennen
- `task.source` Werte wie `certstream-suspicious` um Funde mit CT-Überwachung zu verknüpfen

### Domainalter via RDAP (skriptbar)

RDAP liefert maschinenlesbare Erstellungsereignisse. Nützlich, um **neu registrierte Domains (NRDs)** zu kennzeichnen.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Ergänzen Sie Ihre Pipeline, indem Sie Domains nach Registrierungsalter gruppieren (z. B. <7 days, <30 days) und die Triage entsprechend priorisieren.

### TLS/JAx fingerprints to spot AiTM infrastructure

Moderne Credential-Phishing-Kampagnen nutzen zunehmend **Adversary-in-the-Middle (AiTM)** Reverse-Proxies (z. B. Evilginx), um Session-Tokens zu stehlen. Sie können netzwerkseitige Erkennungen hinzufügen:

- Protokollieren Sie TLS/HTTP-Fingerprints (JA3/JA4/JA4S/JA4H) am Egress. Einige Evilginx-Builds wurden mit stabilen JA4-Client/Server-Werten beobachtet. Generieren Sie Alarme nur bei bekannten bösartigen Fingerprints als schwaches Signal und bestätigen Sie immer mit Content- und Domain-Intel.
- Zeichnen Sie proaktiv TLS-Zertifikat-Metadaten auf (Issuer, SAN-Anzahl, Wildcard-Nutzung, Gültigkeit) für Lookalike-Hosts, die über CT oder urlscan entdeckt wurden, und korrelieren Sie diese mit DNS-Alter und Geolocation.

> Hinweis: Behandeln Sie Fingerprints als Enrichment, nicht als alleinige Blocker; Frameworks entwickeln sich weiter und können randomisieren oder verschleiern.

### Domain names using keywords

Die übergeordnete Seite erwähnt außerdem eine Domain-Name-Variationstechnik, die darin besteht, den **Domainnamen des Opfers in eine größere Domain einzubetten** (z. B. paypal-financial.com statt paypal.com).

#### Certificate Transparency

Der vorherige "Brute-Force"-Ansatz ist nicht möglich, aber es ist tatsächlich **möglich, solche Phishing-Versuche aufzudecken**, und zwar dank Certificate Transparency. Jedes Mal, wenn ein Zertifikat von einer CA ausgestellt wird, werden die Details öffentlich gemacht. Das bedeutet, dass man durch das Lesen der Certificate Transparency oder sogar durch deren Überwachung **Domains finden kann, die ein Schlüsselwort in ihrem Namen verwenden**. Wenn ein Angreifer beispielsweise ein Zertifikat für [https://paypal-financial.com](https://paypal-financial.com) erzeugt, kann man beim Sichtbarmachen des Zertifikats das Schlüsselwort "paypal" erkennen und wissen, dass eine verdächtige E-Mail verwendet wird.

Der Beitrag [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) schlägt vor, Censys zu verwenden, um nach Zertifikaten mit einem bestimmten Schlüsselwort zu suchen und nach Datum (nur "neue" Zertifikate) und nach dem CA-Issuer "Let's Encrypt" zu filtern:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Sie können das Gleiche jedoch mit dem kostenlosen Webdienst [**crt.sh**](https://crt.sh) tun. Sie können **nach dem Schlüsselwort suchen** und die **Ergebnisse bei Bedarf nach Datum und CA filtern**.

![](<../../images/image (519).png>)

Mit dieser letzten Option können Sie sogar das Feld Matching Identities verwenden, um zu prüfen, ob eine Identity der echten Domain mit einer der verdächtigen Domains übereinstimmt (beachten Sie, dass eine verdächtige Domain ein False Positive sein kann).

**Eine weitere Alternative** ist das großartige Projekt [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream liefert einen Echtzeit-Stream neu erzeugter Zertifikate, den Sie verwenden können, um bestimmte Schlüsselwörter in (nahezu) Echtzeit zu erkennen. Tatsächlich gibt es ein Projekt namens [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), das genau das tut.

Praktischer Tipp: Wenn Sie CT-Treffer triagieren, priorisieren Sie NRDs, untrusted/unknown Registrare, privacy-proxy WHOIS und Zertifikate mit sehr aktuellen NotBefore-Zeiten. Führen Sie eine Allowlist Ihrer eigenen Domains/Marken, um Rauschen zu reduzieren.

#### **New domains**

**Eine letzte Alternative** ist, eine Liste neu registrierter Domains für einige TLDs zu sammeln ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bietet einen solchen Service) und **die Schlüsselwörter in diesen Domains zu prüfen**. Lange Domains verwenden jedoch oft ein oder mehrere Subdomains, daher erscheint das Schlüsselwort nicht im FLD und Sie können die Phishing-Subdomain nicht finden.

Zusätzliche Heuristik: Behandeln Sie bestimmte **file-extension TLDs** (z. B. `.zip`, `.mov`) bei Alarmierung mit zusätzlicher Vorsicht. Diese werden in Lures häufig mit Dateinamen verwechselt; kombinieren Sie das TLD-Signal mit Marken-Keywords und NRD-Alter für bessere Präzision.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
