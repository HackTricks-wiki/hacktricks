# Externe Recon-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Asset-Ermittlung

Eine kategorisierte Liste weiterer OSINT- und Web-Discovery-Projekte findest du unter [Tools und Ressourcen von Drittanbietern](../third-party-tools-and-resources.md#osint).

> Man hat dir also gesagt, dass alles, was zu einem Unternehmen gehört, im scope liegt, und du möchtest herausfinden, was dieses Unternehmen tatsächlich besitzt.

Ziel dieser Phase ist es, alle **Unternehmen zu ermitteln, die dem Hauptunternehmen gehören**, und anschließend alle **Assets** dieser Unternehmen. Dazu werden wir:<sup>[[1]](#references)</sup>

1. Die Übernahmen des Hauptunternehmens ermitteln; so finden wir die Unternehmen innerhalb des scope.
2. Den ASN jedes Unternehmens ermitteln (falls vorhanden); so erhalten wir die IP-Bereiche, die jedem Unternehmen gehören.
3. Reverse-Whois-Abfragen verwenden, um nach weiteren Einträgen (Organisationsnamen, Domains usw.) zu suchen, die mit dem ersten zusammenhängen (dies lässt sich rekursiv durchführen).
4. Andere Techniken wie die Shodan-Filter `org`und `ssl` verwenden, um nach weiteren Assets zu suchen (der `ssl`-Trick lässt sich rekursiv durchführen).

Für den schrittweisen Übergang von aufgelösten Subdomains zu HTTP-Crawling und Port-Discovery siehe die [Pentesting-Methodik](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Übernahmen**

Zunächst müssen wir wissen, **welche anderen Unternehmen dem Hauptunternehmen gehören**.\
Eine Möglichkeit ist, [https://www.crunchbase.com/](https://www.crunchbase.com) aufzurufen, nach dem **Hauptunternehmen zu suchen** und auf **„acquisitions“** zu klicken. Dort siehst du andere Unternehmen, die vom Hauptunternehmen übernommen wurden.\
Eine weitere Möglichkeit ist, die **Wikipedia**-Seite des Hauptunternehmens aufzurufen und nach **Übernahmen** zu suchen.\
Bei börsennotierten Unternehmen solltest du **SEC/EDGAR-Unterlagen**, **Investor-Relations**-Seiten oder lokale Unternehmensregister prüfen (z. B. **Companies House** im Vereinigten Königreich).\
Für globale Unternehmensstrukturen und Tochtergesellschaften kannst du **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF-LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)) verwenden.

> Gut, an diesem Punkt solltest du alle Unternehmen innerhalb des scope kennen. Sehen wir uns an, wie du ihre Assets findest.

### **ASNs**

Eine autonome Systemnummer (**ASN**) ist eine **eindeutige Nummer**, die einer **Autonomen System**-Instanz (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken von IP-Adressen**, für die eine eindeutig festgelegte Richtlinie für den Zugriff auf externe Netzwerke gilt. Es wird von einer einzelnen Organisation verwaltet, kann aber aus mehreren Betreibern bestehen.

Es ist sinnvoll herauszufinden, ob dem **Unternehmen ein ASN zugewiesen wurde**, um seine **IP-Bereiche** zu ermitteln. Es ist interessant, einen **Schwachstellentest** gegen alle **Hosts** innerhalb des **scope** durchzuführen und nach **Domains** innerhalb dieser IPs zu suchen.\
Du kannst auf [**https://bgp.he.net/**](https://bgp.he.net) **oder** [**https://ipinfo.io/**](https://ipinfo.io/) nach **Unternehmensname**, **IP** oder **Domain** suchen.\
**Je nach Region des Unternehmens können diese Links nützlich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Allerdings finden sich wahrscheinlich alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Außerdem aggregiert und fasst die Enumeration von [**BBOT**](https://github.com/blacklanternsecurity/bbot) am Ende des Scans automatisch ASNs zusammen.

```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```

Du kannst die IP-Bereiche einer Organisation auch mit [ASNLookup](https://asnlookup.com/) herausfinden. Der Dienst bietet eine eingeschränkte kostenlose API-Stufe.

### **Nach Schwachstellen suchen**

An diesem Punkt kennen wir **alle Assets innerhalb des Scopes**. Wenn es dir erlaubt ist, kannst du also einen **Schwachstellen-Scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) für alle Hosts starten.\
Außerdem könntest du [**Port-Scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) starten **oder Dienste wie** Shodan, Censys oder ZoomEye **nutzen, um** offene Ports **zu finden. Je nachdem, was du entdeckst, solltest du in diesem Buch nachsehen, wie du verschiedene möglicherweise laufende Dienste pentesten kannst.**\
**Erwähnenswert ist auch, dass du Listen mit** Standard-Benutzernamen **und** Passwörtern **vorbereiten und versuchen kannst, Dienste mit** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **zu bruteforcen.**

## Domains

> Wir kennen alle Unternehmen innerhalb des Scopes und ihre Assets. Jetzt ist es an der Zeit, die Domains innerhalb des Scopes zu finden.

_Bitte beachte, dass du mit den folgenden vorgeschlagenen Techniken auch Subdomains finden kannst und diese Informationen nicht unterschätzen solltest._

Zuerst solltest du nach der/den **Hauptdomain(s)** jedes Unternehmens suchen. Die Hauptdomain von _Tesla Inc._ ist zum Beispiel _tesla.com_.

### **Reverse DNS**

Da du alle IP-Bereiche der Domains gefunden hast, könntest du versuchen, für diese **IPs Reverse-DNS-Abfragen durchzuführen, um weitere Domains innerhalb des Scopes zu finden**. Verwende einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8).

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Damit das funktioniert, muss der Administrator PTR manuell aktivieren.\
Du kannst für diese Informationen auch [SecurityTrails](https://securitytrails.com/) verwenden, historische DNS-Daten erfordern jedoch einen kostenpflichtigen Tarif.\
Für große Bereiche eignen sich Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx), um Reverse Lookups und die Anreicherung von Daten zu automatisieren.

### **Reverse Whois (loop)**

In einem **whois** findest du viele interessante **Informationen**, wie den **Organisationsnamen**, die **Adresse**, **E-Mail-Adressen**, Telefonnummern ... Noch interessanter ist jedoch, dass du **weitere mit dem Unternehmen verbundene Assets** finden kannst, indem du anhand dieser Felder **Reverse-Whois-Lookups** durchführst (zum Beispiel andere Whois-Registrierungen, in denen dieselbe E-Mail-Adresse vorkommt).\
Du kannst Online-Tools verwenden wie:

- [https://ip.thc.org/](https://ip.thc.org/) - **Kostenlos** (Web und API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Kostenlose** Weboberfläche; kostenpflichtige API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Kostenpflichtig
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Suchanfragen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos
- [https://securitytrails.com/](https://securitytrails.com/) - Eingeschränkter kostenloser API-Zugriff auf aktuelle DNS-Daten und Subdomains; historische Daten und Reverse Lookups erfordern einen kostenpflichtigen Tarif.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 kostenlose API-Credits bei der Anmeldung; danach kostenpflichtig.

Du kannst diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (erfordert einen whoxy-API-Key).\
Mit [amass](https://github.com/owasp-amass/amass) kannst du auch automatisch Reverse-Whois-Suchen durchführen: `amass intel -d tesla.com -whois`

**Beachte, dass du mit dieser Technik jedes Mal weitere Domainnamen finden kannst, wenn du eine neue Domain entdeckst.**

### **Tracker**

Wenn du auf 2 verschiedenen Seiten dieselbe **ID desselben Trackers** findest, kannst du davon ausgehen, dass **beide Seiten** vom **gleichen Team verwaltet** werden.\
Wenn du zum Beispiel auf mehreren Seiten dieselbe **Google-Analytics-ID** oder dieselbe **Adsense-ID** siehst.

Es gibt einige Seiten und Tools, mit denen du nach diesen und weiteren Trackern suchen kannst:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Kostenpflichtiger** Web- und API-Dienst ([Preise](https://www.stackscan.com/pricing)); derzeit wird kein kostenloser Tarif angeboten. Suche anhand beliebiger bereitgestellter Assets, nicht nur anhand von Tracker-IDs: etwa anhand eines Script-Pfads, des Namens eines selbst gehosteten Bundles oder des Hosts, von dem ein Asset geladen wird. Das Tool gibt dann alle Websites zurück, auf denen es vorkommt.

Die API gibt den Stack einer einzelnen Domain zurück. Das ist nützlich, um zu bestätigen, dass ein infrage kommendes Asset zum selben Bestand gehört:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gibt jede erkannte Technologie zusammen mit ihrer Kategorie zurück. Asset Pivoting ist derzeit nur für das Web verfügbar; die API ermöglicht die Suche nach einzelnen Domains.

### **Favicon**

Wusstest du, dass wir verwandte Domains und Subdomains unseres Ziels finden können, indem wir nach demselben Favicon-Hash suchen? Genau das macht das von [@m4ll0k2](https://twitter.com/m4ll0k2) entwickelte Tool [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py). So verwendest du es:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-Ergebnisse zum Entdecken von Domains mit demselben Favicon-Hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt ermöglicht uns favihash, Domains zu entdecken, deren Favicon denselben Hash wie das unseres Ziels hat.

![favihash-Ausgabe zum Entdecken von Domains mit demselben Favicon-Hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Verwende einen bekannten Favicon-Hash als Shodan- oder FOFA-Pivot, um weitere exponierte Instanzen derselben Technologie zu finden.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

So kannst du den **Favicon-Hash** einer Website berechnen (MMH3 über die **base64-kodierten** Favicon-Bytes):

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url, timeout=10)
    favicon = codecs.encode(response.content, "base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

Du kannst favicon-Hashes auch in großem Umfang mit [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) abrufen und anschließend in Shodan/Censys pivotieren.

Betrachte favicon-Fingerprints als Hinweise und validiere sie anhand umliegender Signale.<sup>[[3]](#references)[[4]](#references)</sup>

- **Betrachte den Hash als Indikator, nicht als Beweis**: MMH3 ist kompakt; Kollisionen, wiederverwendete Icons und absichtliches Spoofing sind möglich.
- **Prüfe mehr als** `/favicon.ico`: Untersuche Framework-/Build-Pfade, Manifest-Dateien, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, Inline-Data-URLs und HTML-`<link rel="icon">`-Tags.
- **Statische Assets können hinter WAF-/SSO-/IdP-Kontrollen weiterhin erreichbar sein**: Rufe das Icon direkt ab und prüfe `ETag`, `Last-Modified`, Weiterleitungen und Cache-Header.
- **Validiere Treffer anhand umliegender Signale**: Vergleiche Titel, HTML-/Body-Hash, Header, TLS-Zertifikat-Subjects/SANs, Produktkomponenten und offene Ports.
- **Gruppiere nach HTML-/Body-Hash**: Eine einheitliche Vorlage stärkt den Fingerprint; gemischte Vorlagen deuten auf ein generisches oder gemeinsam genutztes Icon hin.
- **Betrachte einen Hash, der bei nicht zusammengehörigen Signaturen, Ports und Produkten auftritt, als möglichen Honeypot oder Platzhalter.**
- **Vergleiche bei mehrdeutigen Zielen eine echte Seite mit einem nicht existierenden Pfad**, etwa `/_favicon_probe_<8-hex>`; übereinstimmende Hosting- oder Parking-Antworten können das gemeinsam genutzte Icon erklären.
- **Beginne die Triage mit Nuclei-Erkennungsregeln oder öffentlichen Datensätzen**, die favicon-Hashes Produkten und CPEs zuordnen.
- **Beachte die IP-zentrierte Abdeckungslücke**: Oberflächen hinter CDNs, mit SNI-Routing, Anycast und nur per Domain erreichbare Oberflächen können in Shodan-ähnlichen Datensätzen fehlen.

### **Copyright / eindeutiger String**

Suche auf den Webseiten nach **Strings, die auf verschiedenen Websites derselben Organisation vorkommen könnten**. Ein **Copyright-String** ist ein gutes Beispiel. Suche anschließend in **Google**, anderen **Browsern** oder sogar in **Shodan** nach diesem String: `shodan search http.html:"Copyright string"`

### **CRT-Zeit**

Häufig gibt es einen Cron-Job wie diesen:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

um alle Zertifikate auf einem Server gleichzeitig zu erneuern. Ein Abgleich der Zeitstempel von Zertifikaten oder ihrer Positionen in Certificate-Transparency-Logs kann verwandte Domains offenlegen.<sup>[[6]](#references)</sup>

Nutze auch direkt **Certificate-Transparency**-Logs:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail-DMARC-Informationen

Du kannst eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen teilen**.\
Ein weiterer nützlicher Dienst ist [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ein verwaister A-Record kann erreichbar werden, wenn ein Cloud-Anbieter eine IP-Adresse neu zuweist. Die referenzierte Recherche zeigt einen opportunistischen Workflow, bei dem eine Instanz bereitgestellt und ihre Adresse mit passiven DNS-Daten abgeglichen wird. Teste Takeover-Szenarien nur innerhalb des autorisierten Umfangs.<sup>[[7]](#references)</sup>

### **Weitere Möglichkeiten**

Wiederhole die passenden Discovery-Pivots jedes Mal, wenn du eine neue Domain findest: Jedes Ergebnis kann zusätzliche Zertifikatsnamen, Passive-DNS-Beziehungen, Favicon-Übereinstimmungen und Organisationskennungen aufdecken, die vom ursprünglichen Ausgangspunkt aus nicht sichtbar waren.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Da du bereits den Namen der Organisation kennst, der der IP-Adressbereich gehört, kannst du mit diesen Daten in Shodan suchen: `org:"Tesla, Inc."` Prüfe die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Du kannst auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisationsnamen** ermitteln und anschließend mit diesem Namen in den **TLS-Zertifikaten** aller bei **Shodan** bekannten Webseiten suchen. Verwende dazu den Filter `ssl:"Tesla Motors"` oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **Domains sucht, die mit einer Hauptdomain verwandt sind**, sowie nach deren **Subdomains** – ziemlich beeindruckend.

**Passive DNS / Historisches DNS**

Passive DNS-Daten eignen sich hervorragend, um **alte und vergessene Einträge** zu finden, die noch aufgelöst werden oder übernommen werden können. Sieh dir Folgendes an:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Suche nach Schwachstellen**

Prüfe, ob ein [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) möglich ist. Vielleicht **verwendet ein Unternehmen eine Domain**, hat aber **die Eigentümerschaft verloren**. Registriere sie einfach (wenn sie günstig genug ist) und informiere das Unternehmen.

Wenn du eine **Domain mit einer anderen IP-Adresse** als denen findest, die du bei der Asset Discovery bereits gefunden hast, solltest du einen **grundlegenden Vulnerability Scan** (mit Nessus oder OpenVAS) und einen [**Port Scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste laufen, findest du in **diesem Buch einige Tricks, um sie „anzugreifen“**.\
_Beachte, dass die Domain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht zum Scope gehört. Sei vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen innerhalb des Scopes, alle Assets der einzelnen Unternehmen und alle Domains, die mit den Unternehmen zusammenhängen.

Jetzt ist es an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu ermitteln.

> [!TIP]
> Beachte, dass einige Tools und Techniken zum Finden von Domains auch dabei helfen können, Subdomains zu finden.

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Records zu ermitteln. Wir sollten auch einen **Zone Transfer** versuchen (falls er möglich ist, solltest du das melden).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

APIs und Plattformen für Infrastruktur, Reputation, Breach-Datensätze und Enrichment über die Subdomain-Erkennung hinaus findest du im [Katalog für Reconnaissance- und Threat-Intelligence-APIs](reconnaissance-and-threat-intelligence-apis.md).

Am schnellsten erhältst du viele Subdomains durch die Suche in externen Quellen. Die am häufigsten verwendeten **Tools** sind die folgenden (für bessere Ergebnisse solltest du die API-Keys konfigurieren):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

- [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

- [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```

- [**vita**](https://github.com/junnlikestea/vita)

```
vita -d tesla.com
```

- [**theHarvester**](https://github.com/laramies/theHarvester)

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```

Es gibt **weitere interessante Tools/APIs**, die zwar nicht direkt auf die Suche nach Subdomains spezialisiert sind, aber dennoch nützlich sein können, um Subdomains zu finden, wie zum Beispiel:

- [**IP.THC.ORG**](https://ip.thc.org) kostenlose API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB free API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) kostenlose API

```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```

- [**https://crt.sh/**](https://crt.sh)

```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

- [**gau**](https://github.com/lc/gau)**:** ruft bekannte URLs von AlienVault's Open Threat Exchange, der Wayback Machine und Common Crawl für eine angegebene Domain ab.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Sie durchsuchen das Web nach JS-Dateien und extrahieren daraus Subdomains.

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

- [**Shodan**](https://www.shodan.io/)

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

- [**Censys-Subdomain-Finder**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) bietet begrenzten kostenlosen API-Zugriff auf aktuelle DNS- und Subdomain-Daten; historische DNS-/IP-Daten erfordern einen kostenpflichtigen Plan.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Dieses Projekt bietet **kostenlos alle Subdomains zu Bug-Bounty-Programmen** an. Auf diese Daten kannst du auch mit [chaospy](https://github.com/Moaaz-0x/chaospy) zugreifen oder sogar den von diesem Projekt verwendeten Scope abrufen: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Einen **Vergleich** vieler dieser Tools findest du hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **Subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen brute-forcen.

Für diese Aktion benötigst du einige **gängige Wordlists für Subdomains**, zum Beispiel:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Außerdem benötigst du IPs guter DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, kannst du die Resolver von [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) herunterladen und sie mit [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) filtern. Alternativ kannst du diese Liste verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die am häufigsten empfohlenen Tools für DNS-Brute-Force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool für effektives DNS-Brute-Force. Es ist sehr schnell, erzeugt jedoch leicht False Positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Ich denke, dieses Tool verwendet nur einen Resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, mit dem sich gültige Subdomains durch aktives Brute-Forcing enumerieren sowie Subdomains mit Wildcard-Behandlung und einfacher Ein- und Ausgabe auflösen lassen.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet ebenfalls `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron per Brute-Force zu testen.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Zweite DNS-Brute-Force-Runde

Nachdem du mithilfe offener Quellen und Brute-Force Subdomains gefunden hast, kannst du Variationen der gefundenen Subdomains generieren, um weitere zu finden. Dafür sind mehrere Tools nützlich:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Generiert Permutationen aus Domains und Subdomains.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Erzeugt Permutationen aus Domains und Subdomains.
  - Die **wordlist** für goaltdns-Permutationen gibt es [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Erzeugt Permutationen aus den angegebenen Domains und Subdomains. Wenn keine Datei mit Permutationen angegeben ist, verwendet gotator eine eigene.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Neben dem Generieren von Subdomain-Permutationen kann es auch versuchen, diese aufzulösen (dafür verwendet man aber besser die zuvor erwähnten Tools).
  - Die altdns-Permutationen-**wordlist** findest du [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zum Erzeugen von Permutationen, Mutationen und Abwandlungen von Subdomains. Dieses Tool ermittelt das Ergebnis per brute force (unterstützt keine DNS-Wildcards).
  - Die Permutations-Wortliste für dmut findest du [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Auf Grundlage einer Domain generiert es anhand angegebener Muster neue mögliche Subdomain-Namen, um weitere Subdomains aufzuspüren.

#### Intelligente Permutationsgenerierung

- [**regulator**](https://github.com/cramppet/regulator): Lernt regexähnliche Muster aus entdeckten Subdomains und generiert auflösbare Kandidatennamen.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven DNS-Antwort-gesteuerten Algorithmus arbeitet. Er nutzt bereitgestellte Eingabedaten, etwa eine speziell zusammengestellte Wordlist oder historische DNS-/TLS-Einträge, um präzise weitere passende Domainnamen zu generieren und sie in einer Schleife auf Grundlage der während des DNS-Scans gewonnenen Informationen weiter zu erweitern.

```
echo www | subzuf facebook.com
```

### **Subdomain-Discovery-Workflow**

Trickest-Workflow-Beispiele kombinieren OSINT, DNS-Brute-Force und Permutation-Phasen für eine wiederholbare Subdomain-Aufzählung.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtuelle Hosts**

Wenn du eine IP-Adresse gefunden hast, auf der **eine oder mehrere Webseiten** von Subdomains gehostet werden, kannst du versuchen, **weitere Subdomains mit Websites auf dieser IP** zu finden, indem du in **OSINT-Quellen** nach Domains auf einer IP suchst oder **VHost-Domainnamen auf dieser IP per Brute-Force ermittelst**.

#### OSINT

Du kannst **VHosts auf IPs mithilfe von** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder anderen APIs finden**.

**Brute-Force**

Wenn du vermutest, dass ein Subdomain auf einem Webserver verborgen sein könnte, kannst du versuchen, sie per Brute-Force zu finden:

Für namensbasierte vhosts kannst du den `Host`-Header fuzzing und die Auto-Kalibrierung von ffuf verwenden, um die Standardantwort herauszufiltern.<sup>[[2]](#references)</sup>

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```

> [!TIP]
> Mit dieser Technik kannst du möglicherweise sogar auf interne/versteckte Endpoints zugreifen.

### **CORS Brute Force**

Manchmal findest du Seiten, die den Header _**Access-Control-Allow-Origin**_ nur dann zurückgeben, wenn im Header _**Origin**_ eine gültige Domain/Subdomain angegeben ist. In solchen Szenarien kannst du dieses Verhalten ausnutzen, um neue **Subdomains** zu **entdecken**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Achte bei der Suche nach **Subdomains** darauf, ob sie auf irgendeine Art von **Bucket** **verweisen**. Falls ja, [**prüfe die Berechtigungen**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Da du zu diesem Zeitpunkt alle Domains innerhalb des Scopes kennst, kannst du außerdem versuchen, [**mögliche Bucket-Namen per Brute Force zu ermitteln und die Berechtigungen zu prüfen**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Überwachung**

Mit [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) kannst du die **Certificate Transparency**-Logs überwachen, um festzustellen, ob **neue Subdomains** einer Domain erstellt werden.

### **Suche nach Schwachstellen**

Prüfe auf mögliche [**Subdomain Takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3-Bucket** verweist, [**prüfe die Berechtigungen**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Wenn du eine **Subdomain mit einer IP-Adresse findest, die sich von den bereits bei der Asset-Erkennung gefundenen unterscheidet**, solltest du einen **grundlegenden Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**Port-Scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste laufen, findest du in **diesem Buch möglicherweise einige Tricks, um sie „anzugreifen“**.\
_Beachte, dass eine Subdomain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird und somit nicht zum Scope gehört. Sei vorsichtig._

## IPs

In den ersten Schritten hast du möglicherweise **einige IP-Bereiche, Domains und Subdomains gefunden**.\
Jetzt ist es an der Zeit, **alle IPs aus diesen Bereichen sowie die IPs der Domains/Subdomains (über DNS-Abfragen) zusammenzutragen**.

Mit Diensten wie den folgenden kannst du außerdem **frühere IPs ermitteln, die von Domains und Subdomains verwendet wurden**. Diese IPs könnten dem Kunden immer noch gehören (und es dir ermöglichen, [**CloudFlare-Umgehungen**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

- [**SecurityTrails**](https://securitytrails.com/) (für historische DNS-/IP-Daten ist ein kostenpflichtiger Tarif erforderlich)

Mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) kannst du auch nach Domains suchen, die auf eine bestimmte IP-Adresse verweisen.

### **Suche nach Schwachstellen**

**Führe für alle IPs, die nicht zu CDNs gehören, einen Port-Scan durch** (da du dort höchstwahrscheinlich nichts Interessantes finden wirst). Bei den entdeckten laufenden Diensten kannst du möglicherweise **Schwachstellen finden**.

**Hier findest du einen** [**Leitfaden**](../pentesting-network/index.html) **zum Scannen von Hosts.**

## Suche nach Webservern

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen die IP-Bereiche, Domains und Subdomains innerhalb des Scopes. Jetzt ist es an der Zeit, nach Webservern zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits einige **Recon der entdeckten IPs und Domains** durchgeführt und möglicherweise **schon alle möglichen Webserver gefunden**. Falls nicht, sehen wir uns nun einige **schnelle Tricks an, um innerhalb des Scopes nach Webservern zu suchen**.

Beachte, dass dieser Schritt auf die **Erkennung von Webanwendungen** ausgerichtet ist. Daher solltest du auch einen **Schwachstellenscan** und einen **Port-Scan** durchführen (**sofern der Scope dies erlaubt**).

Eine **schnelle Methode**, um mit [**masscan** offene Ports von **Webservern** zu ermitteln, findest du hier](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres benutzerfreundliches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste mit Domains, und das Tool versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich kannst du angeben, dass weitere Ports ausprobiert werden sollen:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Nachdem du **alle Webserver** im Scope entdeckt hast (unter den **IPs** des Unternehmens sowie allen **Domains** und **Subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es also einfach und beginnen damit, von allen Screenshots zu erstellen. Schon ein **Blick** auf die **Startseite** kann **ungewöhnliche** Endpunkte aufdecken, die eher **anfällig** für **Schwachstellen** sind.

Für diesen Ansatz kannst du [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** verwenden.**

Anschließend kannst du [**eyeballer**](https://github.com/BishopFox/eyeballer) auf allen **Screenshots** ausführen, damit es dir sagt, **welche wahrscheinlich Schwachstellen enthalten** und welche nicht.

## Public Cloud Assets

Um potenzielle Cloud-Assets eines Unternehmens zu finden, solltest du **mit einer Liste von Schlüsselwörtern beginnen, die das Unternehmen identifizieren**. Bei einem Krypto-Unternehmen könntest du beispielsweise Wörter wie `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Du benötigst außerdem Wortlisten mit **häufig in Buckets verwendeten Wörtern**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Aus diesen Wörtern solltest du dann **Permutationen** erstellen (weitere Informationen findest du unter [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Mit den resultierenden Wortlisten kannst du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.**

Denk bei der Suche nach Cloud-Assets daran, **nicht nur nach Buckets in AWS zu suchen**.

### **Nach Schwachstellen suchen**

Wenn du Dinge wie **offene Buckets oder offengelegte Cloud-Funktionen** findest, solltest du **darauf zugreifen** und herausfinden, was sie bieten und ob du sie missbrauchen kannst.

## Emails

Mit den **Domains** und **Subdomains** im Scope hast du im Grunde alles, was du **für die Suche nach Emails benötigst**. Mit diesen **APIs** und **Tools** habe ich die besten Ergebnisse bei der Suche nach Emails eines Unternehmens erzielt:

- [**theHarvester**](https://github.com/laramies/theHarvester) – mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Nach Schwachstellen suchen**

Emails sind später beim **Brute-Force-Angriff auf Web-Logins und Authentifizierungsdienste** (wie SSH) nützlich. Außerdem brauchst du sie für **Phishing**. Darüber hinaus liefern dir diese APIs weitere **Informationen über die Person** hinter der Email, was für die Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains,** **Subdomains** und **Emails** kannst du nach Credentials suchen, die in der Vergangenheit geleakt wurden und zu diesen Emails gehören:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Nach Schwachstellen suchen**

Wenn du **gültige geleakte** Credentials findest, ist das ein sehr einfacher Erfolg.

## Secrets Leaks

Credential-Leaks stehen im Zusammenhang mit Hacks von Unternehmen, bei denen **sensible Informationen geleakt und verkauft wurden**. Unternehmen können jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken enthalten sind:

### Github-Leaks

Credentials und APIs können in den **öffentlichen Repositories** des **Unternehmens** oder der **Mitarbeiter** dieses Unternehmens auf Github geleakt werden.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** **herunterzuladen** und automatisch [**gitleaks**](https://github.com/gitleaks/gitleaks) darauf auszuführen.

**Leakos** kann auch verwendet werden, um **gitleaks** auf allen übergebenen **Text-URLs** auszuführen, da manchmal auch **Webseiten Secrets enthalten**.

#### Github Dorks

Auf der Seite [GitHub dorks and leaks](github-leaked-secrets.md) findest du mögliche **GitHub dorks**, mit denen du die Organisation durchsuchen kannst.

### Pastes-Leaks

Manchmal **veröffentlichen Angreifer oder einfach Mitarbeiter Inhalte eines Unternehmens auf Paste-Seiten**. Diese können **sensible Informationen enthalten oder auch nicht**, aber danach zu suchen, ist sehr interessant.\
Mit dem Tool [**Pastos**](https://github.com/carlospolop/Pastos) kannst du gleichzeitig auf mehr als 80 Paste-Seiten suchen.

### Google Dorks

Alt, aber bewährt: Google dorks sind immer nützlich, um **offengelegte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausend** mögliche Suchanfragen enthält, die du nicht manuell ausführen kannst. Du kannst also deine 10 Favoriten auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Hinweis: Tools, die versuchen, die gesamte Datenbank über den regulären Google-Browser abzufragen, werden nie fertig, da Google dich sehr, sehr schnell blockiert._

### **Nach Schwachstellen suchen**

Wenn du **gültige geleakte** Credentials oder API-Tokens findest, ist das ein sehr einfacher Erfolg.

## Schwachstellen in öffentlichem Code

Wenn du herausgefunden hast, dass das Unternehmen **Open-Source-Code** hat, kannst du ihn **analysieren** und nach **Schwachstellen** suchen.

**Je nach Sprache** kannst du unterschiedliche **Tools** verwenden; siehe die Liste der [Tools zur Überprüfung von Quellcode](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Es gibt auch kostenlose Dienste, mit denen du **öffentliche Repositories scannen** kannst, zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **meisten von Bug Hunters gefundenen Schwachstellen** befinden sich in **Webanwendungen**. Deshalb möchte ich an dieser Stelle eine **Methodik zum Testen von Webanwendungen** vorstellen. [**Hier findest du diese Informationen**](../../network-services-pentesting/pentesting-web/index.html).

Außerdem möchte ich besonders auf den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) hinweisen: Auch wenn du nicht erwarten solltest, dass sie sehr kritische Schwachstellen finden, sind sie nützlich, um sie in **Workflows einzubinden und erste Informationen über das Web zu erhalten**.

## Zusammenfassung

> Glückwunsch! Du hast nun bereits **die gesamte grundlegende Enumeration** durchgeführt. Ja, sie ist grundlegend, denn es lässt sich noch viel mehr enumerieren (weitere Tricks sehen wir später).

Du hast also bereits:

1. Alle **Unternehmen** im Scope gefunden
2. Alle **Assets** der Unternehmen gefunden (und, sofern im Scope, einige Schwachstellen-Scans durchgeführt)
3. Alle **Domains** der Unternehmen gefunden
4. Alle **Subdomains** der Domains gefunden (gibt es eine Subdomain-Übernahme?)
5. Alle **IPs** im Scope gefunden (sowohl **von CDNs als auch nicht von CDNs**).
6. Alle **Webserver** gefunden und von ihnen **Screenshots** erstellt (ist etwas Ungewöhnliches dabei, das genauer untersucht werden sollte?)
7. Alle **potenziellen Public-Cloud-Assets** des Unternehmens gefunden.
8. **Emails**, **Credential-Leaks** und **Secret-Leaks**, die dir sehr einfach einen **großen Erfolg** verschaffen könnten.
9. **Pentesting aller gefundenen Websites**

## **Automatische Tools für vollständige Recon**

Es gibt verschiedene Tools, die einen Teil der vorgeschlagenen Aktionen für einen vorgegebenen Scope ausführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) – Etwas veraltet und nicht aktualisiert



## References

- [1] [Jason Haddix – Die Methodik von Bug Hunters, Version 4.0: Recon-Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Zu Favicons: Von Browser-Icons zu Informationen über die Angriffsfläche](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.ico für Bug Bounties, OSINT und mehr als Waffe einsetzen](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Domains mithilfe eines Zeitkorrelationsangriffs auf Certificate Transparency entdecken](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Übernahme: Eine aufwendige Subdomain-Takeover-Kampagne aufdecken (und nachbilden)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Eine einzigartige Methode zur Subdomain-Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Vollständiger Workflow zur Subdomain-Ermittlung, Teil 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Vollständige automatisierte Ermittlung von Subdomains per Brute Force mit dem Trickest-Workflow, Teil 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot der favihash-Ausgabe](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
