# Phishing erkennen

{{#include ../../banners/hacktricks-training.md}}

## Einführung

Um einen Phishing-Versuch zu erkennen, ist es wichtig, **die heutzutage verwendeten Phishing-Techniken zu verstehen**. Auf der übergeordneten Seite dieses Beitrags findest du diese Informationen. Wenn dir nicht bewusst ist, welche Techniken heute verwendet werden, empfehle ich dir, zur übergeordneten Seite zu gehen und mindestens diesen Abschnitt zu lesen.

Dieser Beitrag basiert auf der Annahme, dass **die Angreifer versuchen werden, den Domainnamen des Opfers irgendwie nachzuahmen oder zu verwenden**. Wenn deine Domain `example.com` heißt und du aus irgendeinem Grund mit einem völlig anderen Domainnamen wie `youwonthelottery.com` gephisht wirst, werden diese Techniken dies nicht aufdecken.

## Variationen von Domainnamen

Es ist relativ **einfach**, Phishing-Versuche **aufzudecken**, bei denen innerhalb der E-Mail ein **ähnlicher Domainname** verwendet wird.\
Es reicht aus, **eine Liste der wahrscheinlichsten Phishing-Namen zu erstellen**, die ein Angreifer verwenden könnte, und zu **prüfen**, ob sie **registriert** sind, oder einfach zu prüfen, ob eine **IP** sie verwendet.

### Verdächtige Domains finden

Hierfür kannst du eines der folgenden Tools verwenden. Beachte, dass diese Tools automatisch DNS-Anfragen ausführen, um zu prüfen, ob der Domain eine IP zugewiesen ist:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tipp: Wenn du eine Kandidatenliste erstellst, speise sie auch in deine DNS-Resolver-Logs ein, um **NXDOMAIN-Abfragen aus deinem Unternehmen** zu erkennen (Benutzer versuchen, einen Tippfehler aufzurufen, bevor der Angreifer ihn tatsächlich registriert). Leite diese Domains in ein Sinkhole um oder blockiere sie vorab, sofern dies laut Richtlinie zulässig ist.

### Bitflipping

**Eine kurze Erklärung dieser Technik findest du auf der übergeordneten Seite. Alternativ kannst du die ursprüngliche Untersuchung unter** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup> **lesen.**

Beispielsweise kann eine Änderung von 1 Bit in der Domain microsoft.com diese in _windnws.com_ umwandeln.\
**Angreifer können so viele Bit-Flipping-Domains wie möglich registrieren, die mit dem Opfer in Zusammenhang stehen, um legitime Benutzer auf ihre Infrastruktur umzuleiten**.<sup>[[1]](#references)</sup>

**Alle möglichen Bit-Flipping-Domainnamen sollten ebenfalls überwacht werden.**

Wenn du auch Homoglyph-/IDN-Nachahmungen berücksichtigen musst (z. B. die Mischung lateinischer und kyrillischer Zeichen), siehe:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Grundlegende Prüfungen

Sobald du eine Liste potenziell verdächtiger Domainnamen hast, solltest du sie **prüfen** (hauptsächlich die Ports HTTP und HTTPS), um **zu sehen, ob sie ein Login-Formular verwenden, das einem Formular der Domain des Opfers ähnelt**.\
Du könntest auch Port 3333 prüfen, um zu sehen, ob er geöffnet ist und eine Instanz von `gophish` ausgeführt wird.\
Es ist außerdem interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist**: Je jünger sie ist, desto höher ist das Risiko.\
Du kannst auch **Screenshots** der verdächtigen HTTP- und/oder HTTPS-Webseite erstellen, um zu sehen, ob sie verdächtig ist, und sie in diesem Fall **aufrufen, um sie genauer zu untersuchen**.

### Erweiterte Prüfungen

Wenn du noch einen Schritt weitergehen möchtest, empfehle ich dir, **diese verdächtigen Domains zu überwachen und gelegentlich nach weiteren zu suchen** (jeden Tag? Das dauert nur wenige Sekunden/Minuten). Du solltest außerdem die offenen **Ports** der zugehörigen IPs **prüfen** und nach **Instanzen von `gophish` oder ähnlichen Tools suchen** (ja, auch Angreifer machen Fehler) sowie **die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains überwachen**, um zu sehen, ob sie Login-Formulare von den Webseiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste der Login-Formulare der Domains des Opfers zu erstellen, die verdächtigen Webseiten zu durchsuchen und jedes in den verdächtigen Domains gefundene Login-Formular mit jedem Login-Formular der Domain des Opfers zu vergleichen, beispielsweise mit `ssdeep`.\
Wenn du die Login-Formulare der verdächtigen Domains gefunden hast, kannst du versuchen, **Dummy-Zugangsdaten zu senden** und **zu prüfen, ob du zur Domain des Opfers weitergeleitet wirst**.

---

### Suche anhand von Favicon und Web-Fingerprints (Shodan/ZoomEye/Censys)

Viele Phishing-Kits verwenden Favicons der Marke, die sie imitieren, erneut. Scanner für das gesamte Internet berechnen einen MurmurHash3 des base64-codierten Favicons. Du kannst den Hash erstellen und darauf aufbauen:

Python-Beispiel (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan abfragen: `http.favicon.hash:309020573`
- Mit Tools: Sieh dir Community-Tools wie favfreak an, um Hashes und Dorks für Shodan/ZoomEye/Censys zu generieren.

Hinweise
- Favicons werden wiederverwendet; betrachte Treffer als Anhaltspunkte und validiere Inhalte und Zertifikate, bevor du aktiv wirst.
- Kombiniere dies mit Heuristiken zu Domain-Alter und Schlüsselwörtern, um die Präzision zu verbessern.

### URL-Telemetrie-Suche (urlscan.io)

`urlscan.io` speichert historische Screenshots, DOM, Requests und TLS-Metadaten von übermittelten URLs. Du kannst nach Markenmissbrauch und Klonen suchen:<sup>[[2]](#references)</sup>

Beispielabfragen (UI oder API):
- Finde Lookalikes und schließe deine legitimen Domains aus: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Finde Websites, die deine Assets per Hotlink einbinden: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beschränke die Ergebnisse auf aktuelle Treffer: Hänge `AND date:>now-7d` an

API-Beispiel:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Aus dem JSON heraus solltest du nach folgenden Feldern suchen:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, um sehr neue Zertifikate für Lookalike-Domains zu erkennen
- `task.source`-Werte wie `certstream-suspicious`, um Findings mit dem CT Monitoring zu verknüpfen

### Domain-Alter via RDAP (skriptfähig)

RDAP gibt maschinenlesbare Erstellungsereignisse zurück. Dies ist nützlich, um **neu registrierte Domains (NRDs)** zu erkennen.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enrichern Sie Ihre Pipeline, indem Sie Domains mit Altersgruppen für die Registrierung taggen (z. B. <7 Tage, <30 Tage), und priorisieren Sie die Triage entsprechend.

### TLS/JAx-Fingerprints zur Erkennung von AiTM-Infrastruktur

Moderne Credential-Phishing-Angriffe verwenden zunehmend **Adversary-in-the-Middle (AiTM)**-Reverse-Proxies (z. B. Evilginx), um Session-Tokens zu stehlen. Sie können Erkennungen auf Netzwerkebene hinzufügen:

- Protokollieren Sie TLS/HTTP-Fingerprints (JA3/JA4/JA4S/JA4H) am Egress. Bei einigen Evilginx-Builds wurden stabile JA4-Client-/Server-Werte beobachtet. Lösen Sie nur bei bekannten bösartigen Fingerprints einen Alert aus, und verwenden Sie dies ausschließlich als schwaches Signal. Bestätigen Sie die Ergebnisse immer anhand von Content- und Domain-Intelligence.<sup>[[3]](#references)</sup>
- Erfassen Sie proaktiv TLS-Zertifikatsmetadaten (Aussteller, SAN-Anzahl, Verwendung von Wildcards, Gültigkeit) für Lookalike-Hosts, die über CT oder urlscan entdeckt wurden, und korrelieren Sie diese mit dem DNS-Alter und der Geolokalisierung.

> Hinweis: Behandeln Sie Fingerprints als Enrichment und nicht als alleinige Blockierungsgrundlage; Frameworks entwickeln sich weiter und können Fingerprints randomisieren oder verschleiern.

### Domainnamen mit Keywords

Die übergeordnete Seite erwähnt außerdem eine Domainnamen-Variationstechnik, bei der der **Domainname des Opfers in eine größere Domain eingefügt wird** (z. B. paypal-financial.com für paypal.com).

#### Certificate Transparency

Der vorherige „Brute-Force“-Ansatz ist nicht möglich, aber dank Certificate Transparency ist es tatsächlich **möglich, solche Phishing-Versuche aufzudecken**. Jedes Mal, wenn eine CA ein Zertifikat ausstellt, werden dessen Details öffentlich gemacht. Das bedeutet, dass es durch das Auslesen oder sogar Überwachen von Certificate Transparency **möglich ist, Domains zu finden, die ein Keyword in ihrem Namen verwenden**. Wenn ein Angreifer beispielsweise ein Zertifikat für [https://paypal-financial.com](https://paypal-financial.com) erstellt, kann man durch das Betrachten des Zertifikats das Keyword „paypal“ finden und erkennen, dass eine verdächtige E-Mail verwendet wird.

Der Beitrag [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) schlägt vor, Censys zu verwenden, um nach Zertifikaten zu suchen, die ein bestimmtes Keyword betreffen, und nach Datum (nur „neue“ Zertifikate) sowie nach dem CA-Aussteller „Let's Encrypt“ zu filtern:<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Sie können dies jedoch „auf dieselbe Weise“ mit der kostenlosen Website [**crt.sh**](https://crt.sh) tun. Sie können nach dem **Keyword suchen** und die Ergebnisse bei Bedarf **nach Datum und CA filtern**.

![Domainnamen mit Keywords - Certificate Transparency: Sie können dies jedoch „auf dieselbe Weise“ mit der kostenlosen Website crt.sh tun. Sie können nach dem Keyword suchen und die Ergebnisse nach Datum und ... filtern.](<../../images/image (519).png>)

Mit dieser letzten Option können Sie sogar das Feld „Matching Identities“ verwenden, um zu prüfen, ob eine Identität der echten Domain mit einer der verdächtigen Domains übereinstimmt (beachten Sie, dass eine verdächtige Domain ein False Positive sein kann).

**Eine weitere Alternative** ist das hervorragende Projekt [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream stellt einen Echtzeit-Stream neu generierter Zertifikate bereit, den Sie verwenden können, um darin (nahezu) in Echtzeit nach bestimmten Keywords zu suchen. Tatsächlich gibt es ein Projekt namens [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), das genau dies tut.

Praktischer Tipp: Priorisieren Sie bei der Triage von CT-Treffern NRDs, nicht vertrauenswürdige/unbekannte Registrare, WHOIS-Datensätze mit Privacy-Proxy und Zertifikate mit sehr aktuellen `NotBefore`-Zeitpunkten. Führen Sie eine Allowlist Ihrer eigenen Domains/Marken, um das Rauschen zu reduzieren.

#### **Neue Domains**

**Eine letzte Alternative** besteht darin, eine Liste **neu registrierter Domains** für einige TLDs zu sammeln ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bietet einen solchen Dienst an) und die **Keywords in diesen Domains zu überprüfen**. Lange Domains verwenden jedoch häufig eine oder mehrere Subdomains. Daher erscheint das Keyword möglicherweise nicht innerhalb der FLD, und Sie können die Phishing-Subdomain nicht finden.

Zusätzliche Heuristik: Behandeln Sie bestimmte **Dateiendungs-TLDs** (z. B. `.zip`, `.mov`) bei Alerts mit besonderem Misstrauen. Diese werden in Lures häufig mit Dateinamen verwechselt. Kombinieren Sie das TLD-Signal mit Marken-Keywords und dem NRD-Alter, um eine höhere Präzision zu erreichen.

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
