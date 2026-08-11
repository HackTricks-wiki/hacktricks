# Externe Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Asset-Ermittlung

> Dir wurde also gesagt, dass alles, was einem bestimmten Unternehmen gehört, innerhalb des scope liegt, und du möchtest herausfinden, was dieses Unternehmen tatsächlich besitzt.

Das Ziel dieser Phase besteht darin, alle **Unternehmen im Besitz des Hauptunternehmens** und anschließend alle **Assets** dieser Unternehmen zu ermitteln. Dazu werden wir:

1. Die Übernahmen des Hauptunternehmens ermitteln; dadurch erhalten wir die Unternehmen innerhalb des scope.
2. Die ASN (falls vorhanden) jedes Unternehmens ermitteln; dadurch erhalten wir die IP-Bereiche, die jedem Unternehmen gehören.
3. Reverse-Whois-Lookups verwenden, um nach weiteren Einträgen (Organisationsnamen, Domains usw.) zu suchen, die mit dem ersten Eintrag zusammenhängen (dies kann rekursiv durchgeführt werden).
4. Andere Techniken wie die Shodan-Filter `org` und `ssl` verwenden, um nach weiteren Assets zu suchen (der `ssl`-Trick kann rekursiv durchgeführt werden).

### **Übernahmen**

Zunächst müssen wir wissen, welche **anderen Unternehmen im Besitz des Hauptunternehmens sind**.\
Eine Möglichkeit besteht darin, [https://www.crunchbase.com/](https://www.crunchbase.com) aufzurufen, nach dem **Hauptunternehmen** zu **suchen** und auf "**acquisitions**" zu **klicken**. Dort siehst du andere Unternehmen, die vom Hauptunternehmen übernommen wurden.\
Eine weitere Möglichkeit besteht darin, die **Wikipedia**-Seite des Hauptunternehmens aufzurufen und nach **acquisitions** zu suchen.\
Bei börsennotierten Unternehmen solltest du **SEC/EDGAR filings**, **Investor-Relations**-Seiten oder lokale Unternehmensregister (z. B. **Companies House** im Vereinigten Königreich) prüfen.\
Für globale Unternehmensstrukturen und Tochtergesellschaften kannst du **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)) verwenden.

> Zu diesem Zeitpunkt solltest du also alle Unternehmen innerhalb des scope kennen. Sehen wir uns nun an, wie wir ihre Assets finden.

### **ASNs**

Eine Autonomous System Number (**ASN**) ist eine **eindeutige Nummer**, die einem **autonomen System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, die über eine eindeutig festgelegte Richtlinie für den Zugriff auf externe Netzwerke verfügen und von einer einzigen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant herauszufinden, ob das **Unternehmen eine ASN zugewiesen bekommen hat**, um seine **IP-Bereiche** zu ermitteln. Es kann sinnvoll sein, einen **vulnerability test** gegen alle **Hosts** innerhalb des **scope** durchzuführen und in diesen IPs nach **Domains** zu suchen.\
Du kannst nach dem **Namen des Unternehmens**, nach einer **IP** oder nach einer **Domain** auf [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **oder** [**https://ipinfo.io/**](https://ipinfo.io/) suchen.\
**Je nach Region des Unternehmens können diese Links hilfreich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Wie auch immer, wahrscheinlich erscheinen alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link.
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
Die IP-Bereiche einer Organisation können Sie auch mit [http://asnlookup.com/](http://asnlookup.com) ermitteln (es verfügt über eine kostenlose API).\
Sie können die IP und den ASN einer Domain mit [http://ipv4info.com/](http://ipv4info.com) ermitteln.

### **Suche nach Schwachstellen**

Zu diesem Zeitpunkt kennen wir **alle Assets innerhalb des Scopes**. Wenn Sie dazu berechtigt sind, könnten Sie daher einen **Schwachstellen-Scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) für alle Hosts einsetzen.\
Außerdem könnten Sie einige [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) durchführen **oder Dienste wie** Shodan, Censys oder ZoomEye **verwenden, um** offene Ports **zu finden. Je nachdem, was Sie finden, sollten Sie** in diesem Buch nachsehen, wie verschiedene möglicherweise laufende Dienste pentestet werden.\
**Außerdem ist es erwähnenswert, dass Sie auch einige** Listen mit Standardbenutzernamen **und** Passwörtern **vorbereiten und versuchen können, Dienste mit** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) zu **bruteforce**.

## Domains

> Wir kennen alle Unternehmen innerhalb des Scopes und deren Assets. Nun ist es an der Zeit, die Domains innerhalb des Scopes zu ermitteln.

_Bitte beachten Sie, dass Sie mit den folgenden vorgeschlagenen Techniken auch Subdomains finden können und diese Informationen nicht unterschätzt werden sollten._

Zunächst sollten Sie nach der bzw. den **Hauptdomain(s)** jedes Unternehmens suchen. Für _Tesla Inc._ wäre dies beispielsweise _tesla.com_.

### **Reverse DNS**

Da Sie alle IP-Bereiche der Domains ermittelt haben, könnten Sie versuchen, **Reverse-DNS-Abfragen** für diese **IPs durchzuführen, um weitere Domains innerhalb des Scopes zu finden**. Versuchen Sie, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit dies funktioniert, muss der Administrator den PTR manuell aktivieren.\
Du kannst für diese Informationen auch ein Online-Tool verwenden: [http://ptrarchive.com/](http://ptrarchive.com).\
Für große Bereiche sind Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx) nützlich, um Reverse Lookups und die Anreicherung zu automatisieren.

### **Reverse Whois (loop)**

In einem **whois** kannst du viele interessante **Informationen** wie **Organisationsname**, **Adresse**, **E-Mail-Adressen**, Telefonnummern usw. finden. Noch interessanter ist jedoch, dass du **weitere mit dem Unternehmen verbundene Assets** finden kannst, wenn du anhand eines dieser Felder **Reverse-Whois-Lookups** durchführst (zum Beispiel andere Whois-Registrierungen, in denen dieselbe E-Mail-Adresse erscheint).\
Du kannst Online-Tools verwenden wie:

- [https://ip.thc.org/](https://ip.thc.org/) - **Kostenlos** (Web und API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Kostenlos** im Web, API nicht kostenlos.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht kostenlos
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Suchen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos
- [https://securitytrails.com/](https://securitytrails.com/) - Nicht kostenlos (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nicht kostenlos (API)

Du kannst diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (benötigt einen whoxy-API-Key).\
Du kannst mit [amass](https://github.com/OWASP/Amass) auch eine automatische Reverse-Whois-Erkennung durchführen: `amass intel -d tesla.com -whois`

**Beachte, dass du diese Technik verwenden kannst, um jedes Mal weitere Domainnamen zu entdecken, wenn du eine neue Domain findest.**

### **Trackers**

Wenn du die **gleiche ID desselben Trackers** auf 2 verschiedenen Seiten findest, kannst du annehmen, dass **beide Seiten** vom **gleichen Team verwaltet** werden.\
Wenn du beispielsweise auf mehreren Seiten dieselbe **Google-Analytics-ID** oder dieselbe **Adsense-ID** siehst.

Es gibt einige Seiten und Tools, mit denen du nach diesen Trackers und weiteren Informationen suchen kannst:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (findet verwandte Websites anhand gemeinsamer Analytics/Tracker)

### **Favicon**

Wusstest du, dass wir verwandte Domains und Subdomains unseres Ziels finden können, indem wir nach demselben Favicon-Icon-Hash suchen? Genau das macht das von [@m4ll0k2](https://twitter.com/m4ll0k2) erstellte Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py). So wird es verwendet:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Einfach gesagt ermöglicht uns favihash, Domains zu entdecken, die denselben Favicon-Icon-Hash wie unser Ziel haben.

Verwende einen bekannten Favicon-Hash als Shodan- oder FOFA-Pivot, um weitere exponierte Instanzen derselben Technologie zu finden.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
So kannst du den **Favicon-Hash** einer Website berechnen (MMH3 über die **Base64-codierten** Favicon-Bytes):
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
Favicon-Hashes können auch in großem Maßstab mit [**httpx**](https://github.com/projectdiscovery/httpx) abgerufen werden (`httpx -l targets.txt -favicon`), anschließend kann in Shodan/Censys pivotiert werden.

Behandle Favicon-Fingerprints als Hinweise und validiere sie anhand zusätzlicher Signale.<sup>[[3]](#references)[[4]](#references)</sup>

- **Behandle den Hash als Indikator, nicht als Beweis**: MMH3 ist kompakt; Kollisionen, wiederverwendete Icons und absichtliches Spoofing sind möglich.
- **Prüfe mehr als** `/favicon.ico`: Untersuche Framework-/Build-Pfade, Manifest-Dateien, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, Inline-Data-URLs und HTML-`<link rel="icon">`-Tags.
- **Statische Assets können hinter WAF-/SSO-/IdP-Kontrollen weiterhin erreichbar sein**: Fordere das Icon direkt an und prüfe `ETag`, `Last-Modified`, Redirects und Cache-Header.
- **Validiere Treffer anhand zusätzlicher Signale**: Vergleiche den Titel, den HTML-/Body-Hash, Header, TLS-Zertifikat-Subjects/SANs, Produktkomponenten und exponierte Ports.
- **Cluster nach HTML-/Body-Hash**: Ein konsistentes Template stärkt den Fingerprint; gemischte Templates weisen auf ein generisches oder gemeinsam genutztes Icon hin.
- **Behandle einen Hash, der über voneinander unabhängige Signaturen, Ports und Produkte hinweg erscheint, als potenziellen Honeypot oder Platzhalter.**
- **Vergleiche bei mehrdeutigen Zielen eine echte Seite mit einem nicht vorhandenen Pfad**, beispielsweise `/_favicon_probe_<8-hex>`; übereinstimmende Hosting- oder Parking-Antworten können das gemeinsame Icon erklären.
- **Starte die Triage anhand von Nuclei-Erkennungsregeln oder öffentlichen Datensätzen**, die Favicon-Hashes Produkten und CPEs zuordnen.
- **Denke an die IP-zentrierte Abdeckungslücke**: CDN-geschützte, SNI-geroutete, Anycast- und ausschließlich domainbasierte Oberflächen können in Shodan-ähnlichen Datensätzen fehlen.

### **Copyright / Eindeutige Zeichenkette**

Suche innerhalb der Webseiten nach **Zeichenketten, die über verschiedene Webseiten derselben Organisation hinweg gemeinsam verwendet werden könnten**. Die **Copyright-Zeichenkette** könnte ein gutes Beispiel sein. Suche anschließend in **google**, in anderen **Browsern** oder sogar in **shodan** nach dieser Zeichenkette: `shodan search http.html:"Copyright string"`

### **CRT-Zeit**

Es ist üblich, einen Cronjob zu haben, etwa
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
um alle Zertifikate auf einem Server gleichzeitig zu erneuern. Das Korrelieren von Zertifikat-Zeitstempeln oder Positionen in Certificate-Transparency-Logs kann verwandte Domains offenlegen.<sup>[[6]](#references)</sup>

Verwende außerdem **certificate transparency**-Logs direkt:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail-DMARC-Informationen

Du kannst eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen verwenden**.\
Weitere nützliche Tools sind [**spoofcheck**](https://github.com/BishopFox/spoofcheck) und [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ein verwaister A-Record kann erreichbar werden, wenn ein Cloud-Provider eine IP neu zuweist. Die referenzierte Recherche beschreibt einen opportunistischen Workflow, der eine Instanz bereitstellt und deren Adresse mit passiven DNS-Daten korreliert. Teste Takeover-Szenarien ausschließlich innerhalb des autorisierten Scopes.<sup>[[7]](#references)</sup>

### **Andere Methoden**

**Shodan**

Da du bereits den Namen der Organisation kennst, der der IP-Adressbereich gehört, kannst du in Shodan anhand dieser Daten suchen: `org:"Tesla, Inc."` Überprüfe die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Du könntest auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisationsnamen** ermitteln und anschließend nach diesem Namen in den **TLS-Zertifikaten** aller Shodan bekannten Webseiten suchen, und zwar mit dem Filter: `ssl:"Tesla Motors"` oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) verwenden.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ist ein Tool, das nach **Domains sucht, die mit einer Hauptdomain zusammenhängen**, sowie nach deren **Subdomains** – wirklich erstaunlich.

**Passive DNS / Historical DNS**

Passive DNS-Daten eignen sich hervorragend, um **alte und vergessene Records** zu finden, die noch aufgelöst werden oder übernommen werden können. Siehe:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Suche nach Schwachstellen**

Prüfe auf einen [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht **verwendet ein Unternehmen eine Domain**, hat aber **das Eigentum daran verloren**. Registriere sie einfach (falls sie günstig genug ist) und informiere das Unternehmen.

Wenn du eine **Domain mit einer IP-Adresse findest, die sich von den bereits bei der Asset-Erkennung gefundenen IPs unterscheidet**, solltest du einen **grundlegenden Vulnerability Scan** (mit Nessus oder OpenVAS) sowie einen [**Port Scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Abhängig davon, welche Services ausgeführt werden, kannst du in **diesem Buch einige Tricks finden, um sie zu „attackieren“**.\
_Beachte, dass die Domain manchmal innerhalb einer IP gehostet wird, die nicht vom Client kontrolliert wird und sich daher nicht im Scope befindet. Sei vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen innerhalb des Scopes, alle Assets jedes Unternehmens und alle mit den Unternehmen verbundenen Domains.

Es ist an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu ermitteln.

> [!TIP]
> Beachte, dass einige Tools und Techniken zum Finden von Domains auch beim Finden von Subdomains helfen können.

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Records zu ermitteln. Wir sollten auch einen **Zone Transfer** versuchen (falls verwundbar, solltest du dies melden).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Die schnellste Möglichkeit, viele Subdomains zu erhalten, besteht darin, in externen Quellen zu suchen. Die am häufigsten verwendeten **Tools** sind die folgenden (für bessere Ergebnisse die API-Schlüssel konfigurieren):

- [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
- [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
- [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
- [**findomain**](https://github.com/Edu4rdSHL/findomain/)
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
Es gibt **weitere interessante Tools/APIs**, die zwar nicht direkt auf das Finden von Subdomains spezialisiert sind, aber dennoch nützlich sein könnten, um Subdomains zu finden, wie etwa:

- [**IP.THC.ORG**](https://ip.thc.org) kostenlose API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um Subdomains zu ermitteln
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC kostenlose API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
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
- [**gau**](https://github.com/lc/gau)**:** Ruft bekannte URLs von AlienVaults Open Threat Exchange, der Wayback Machine und Common Crawl für eine beliebige Domain ab.
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
- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) bietet eine kostenlose API, um nach subdomains und IP history zu suchen
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle subdomains im Zusammenhang mit Bug-Bounty-Programmen** an. Du kannst auf diese Daten auch über [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder sogar den von diesem Projekt verwendeten Scope über [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) abrufen.

Hier findest du einen **Vergleich** vieler dieser Tools: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **subdomains** zu finden, indem wir DNS-Server mit möglichen subdomain-Namen per Brute force durchsuchen.

Für diese Aktion benötigst du einige **common subdomains wordlists wie**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Außerdem benötigst du IPs guter DNS resolver. Um eine Liste vertrauenswürdiger DNS resolver zu erstellen, kannst du die resolver von [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) herunterladen und mit [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) filtern. Alternativ kannst du Folgendes verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die am meisten empfohlenen Tools für DNS Brute force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das einen effektiven DNS Brute force durchführte. Es ist sehr schnell, neigt jedoch zu false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ich glaube, dieser verwendet nur einen Resolver.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, der es ermöglicht, gültige Subdomains mittels aktivem Brute-Force zu enumerieren sowie Subdomains mit Wildcard-Behandlung und einfacher Ein-/Ausgabe-Unterstützung aufzulösen.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet ebenfalls `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron per brute force zu testen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS-Brute-Force-Runde

Nachdem du mithilfe offener Quellen und durch Brute-Forcing Subdomains gefunden hast, kannst du Variationen der gefundenen Subdomains erzeugen, um möglicherweise noch mehr zu finden. Für diesen Zweck sind mehrere Tools nützlich:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Erzeugt Permutationen aus den Domains und Subdomains.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Generiert anhand der Domains und Subdomains Permutationen.
- Du kannst die goaltdns-Permutationen-[**wordlist**](https://github.com/subfinder/goaltdns/blob/master/words.txt) [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) herunterladen.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Erzeugt anhand der Domains und Subdomains Permutationen. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Neben dem Generieren von Subdomain-Permutationen kann es auch versuchen, diese aufzulösen (es ist jedoch besser, die zuvor auskommentierten Tools zu verwenden).
- Die altdns-Permutationen-**wordlist** findest du [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zum Erstellen von Permutationen, Mutationen und Abwandlungen von Subdomains. Dieses Tool führt Brute-Force auf das Ergebnis aus (es unterstützt keine DNS-Wildcards).
- Die dmut-Permutationswortliste erhältst du [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Generiert auf Grundlage einer Domain **neue potenzielle Subdomain-Namen** anhand angegebener Muster, um weitere Subdomains zu entdecken.

#### Intelligente Generierung von Permutationen

- [**regulator**](https://github.com/cramppet/regulator): Lernt regex-ähnliche Muster aus entdeckten Subdomains und generiert auflösbare Kandidatennamen.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven, DNS-Response-gesteuerten Algorithmus arbeitet. Er verwendet einen bereitgestellten Datensatz, etwa eine speziell zusammengestellte Wordlist oder historische DNS/TLS-Records, um präzise weitere passende Domainnamen zu synthetisieren und diese in einer Schleife auf Grundlage der während des DNS-Scans gesammelten Informationen noch weiter zu erweitern.
```
echo www | subzuf facebook.com
```
### **Workflow zur Subdomain-Discovery**

Trickest-Workflow-Beispiele kombinieren OSINT-, DNS-Brute-Force- und Permutation-Phasen für eine wiederholbare Subdomain-Aufzählung.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Wenn du eine IP-Adresse mit **einer oder mehreren Webseiten** gefunden hast, die zu Subdomains gehören, kannst du versuchen, **weitere Subdomains mit Webseiten auf dieser IP** zu finden, indem du in **OSINT-Quellen** nach Domains auf einer IP suchst oder **VHost-Domainnamen auf dieser IP brute-forcest**.

#### OSINT

Du kannst einige **VHosts auf IPs mit** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder anderen APIs** finden.

**Brute Force**

Wenn du vermutest, dass eine Subdomain auf einem Webserver verborgen sein könnte, kannst du versuchen, sie zu brute-forcen:

Bei namensbasierten VHosts kannst du den `Host`-Header fuzzing und die Auto-Kalibrierung von ffuf verwenden, um die Standardantwort herauszufiltern.<sup>[[2]](#references)</sup>
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
> Mit dieser Technik können Sie möglicherweise sogar auf interne/versteckte Endpunkte zugreifen.

### **CORS Brute Force**

Manchmal finden Sie Seiten, die den Header _**Access-Control-Allow-Origin**_ nur zurückgeben, wenn im _**Origin**_-Header eine gültige Domain/Subdomain gesetzt ist. In diesen Szenarien können Sie dieses Verhalten missbrauchen, um neue **Subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Während du nach **Subdomains** suchst, achte darauf, ob diese auf irgendeine Art von **Bucket** **zeigen**, und prüfe in diesem Fall [**die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Da du zu diesem Zeitpunkt alle Domains innerhalb des Scopes kennst, versuche außerdem, [**mögliche Bucket-Namen per Brute Force zu ermitteln und die Berechtigungen zu prüfen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Überwachung**

Du kannst überwachen, ob **neue Subdomains** einer Domain erstellt werden, indem du die **Certificate Transparency**-Logs überwachst, wie es [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) macht.

### **Suche nach Schwachstellen**

Prüfe auf mögliche [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3-Bucket** zeigt, [**prüfe die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn du eine **Subdomain mit einer anderen IP-Adresse** als den bereits bei der Asset-Ermittlung gefundenen IPs findest, solltest du einen **grundlegenden Schwachstellen-Scan** (mit Nessus oder OpenVAS) sowie einen [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Abhängig davon, welche Services ausgeführt werden, kannst du in **diesem Buch einige Tricks finden, um sie zu „attackieren“**.\
_Beachte, dass die Subdomain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht im Scope liegt. Sei vorsichtig._

## IPs

In den ersten Schritten hast du möglicherweise **einige IP-Bereiche, Domains und Subdomains gefunden**.\
Jetzt ist es an der Zeit, **alle IPs aus diesen Bereichen** sowie für die **Domains/Subdomains (DNS-Abfragen)** zu sammeln.

Mithilfe von Services aus den folgenden **kostenlosen APIs** kannst du außerdem **frühere, von Domains und Subdomains verwendete IPs** finden. Diese IPs könnten weiterhin dem Kunden gehören (und dir möglicherweise ermöglichen, [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Du kannst auch mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) nach Domains suchen, die auf eine bestimmte IP-Adresse zeigen.

### **Suche nach Schwachstellen**

**Führe einen port scan für alle IPs durch, die nicht zu CDNs gehören** (da du dort höchstwahrscheinlich nichts Interessantes finden wirst). Bei den gefundenen laufenden Services kannst du möglicherweise **Schwachstellen finden**.

**Finde einen** [**Leitfaden**](../pentesting-network/index.html) **darüber, wie Hosts gescannt werden.**

## Suche nach Webservern

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen die IP-Bereiche, Domains und Subdomains innerhalb des Scopes. Jetzt ist es an der Zeit, nach Webservern zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits eine **Recon der gefundenen IPs und Domains** durchgeführt und möglicherweise **alle verfügbaren Webserver gefunden**. Falls nicht, sehen wir uns nun einige **schnelle Tricks an, um Webserver** innerhalb des Scopes zu finden.

Beachte, dass dies auf die **Ermittlung von Web-Apps** ausgerichtet ist. Daher solltest du zusätzlich einen **Schwachstellen-Scan** und einen **port scan** durchführen (**falls** dies vom Scope **erlaubt** ist).

Eine **schnelle Methode**, um mithilfe von [**masscan** offene, mit **Webservern** verbundene Ports zu ermitteln, findest du hier](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres benutzerfreundliches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste von Domains, und das Tool versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich kannst du angeben, dass weitere Ports getestet werden sollen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Nachdem du **alle Webserver** im Scope entdeckt hast (unter den **IPs** des Unternehmens sowie allen **Domains** und **Subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es also einfach und beginnen damit, von allen Screenshots zu erstellen. Schon durch einen **Blick** auf die **Hauptseite** kannst du **seltsame** Endpunkte finden, die eher **gefährdet** sein könnten.

Für die vorgeschlagene Idee kannst du [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** verwenden.**

Anschließend kannst du [**eyeballer**](https://github.com/BishopFox/eyeballer) über alle **Screenshots** laufen lassen, um festzustellen, **welche wahrscheinlich Schwachstellen enthalten** und welche nicht.

## Public Cloud Assets

Um potenzielle Cloud Assets eines Unternehmens zu finden, solltest du **mit einer Liste von Schlüsselwörtern beginnen, die das Unternehmen identifizieren**. Bei einem Krypto-Unternehmen könntest du beispielsweise Wörter wie `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Du benötigst außerdem Wordlists mit **häufig in Buckets verwendeten Wörtern**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Anschließend solltest du mit diesen Wörtern **Permutationen** erzeugen (weitere Informationen findest du unter [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Mit den resultierenden Wordlists könntest du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.**

Denke daran, dass du bei der Suche nach Cloud Assets nach **mehr als nur Buckets in AWS** suchen solltest.

### **Looking for vulnerabilities**

Wenn du Dinge wie **offene Buckets oder exponierte Cloud Functions** findest, solltest du **darauf zugreifen** und versuchen herauszufinden, was sie dir bieten und ob du sie missbrauchen kannst.

## Emails

Mit den **Domains** und **Subdomains** innerhalb des Scopes hast du im Grunde alles, was du **benötigst, um mit der Suche nach E-Mail-Adressen zu beginnen**. Dies sind die **APIs** und **Tools**, die für mich am besten funktioniert haben, um E-Mail-Adressen eines Unternehmens zu finden:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Looking for vulnerabilities**

E-Mail-Adressen werden später beim **Brute-Force von Web-Logins und Auth-Services** (wie SSH) nützlich sein. Außerdem werden sie für **Phishing** benötigt. Darüber hinaus liefern dir diese APIs noch mehr **Informationen über die Person** hinter der E-Mail-Adresse, was für die Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains,** **Subdomains** und **E-Mail-Adressen** kannst du damit beginnen, nach Credentials zu suchen, die in der Vergangenheit zu diesen E-Mail-Adressen gehörten und geleakt wurden:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Wenn du **gültige geleakte** Credentials findest, ist das ein sehr einfacher Erfolg.

## Secrets Leaks

Credential Leaks stehen im Zusammenhang mit Hacks von Unternehmen, bei denen **sensible Informationen geleakt und verkauft wurden**. Unternehmen können jedoch von **anderen Leaks** betroffen sein, deren Informationen sich nicht in diesen Datenbanken befinden:

### Github Leaks

Credentials und APIs können in den **öffentlichen Repositories** des **Unternehmens** oder der **Benutzer**, die für dieses GitHub-Unternehmen arbeiten, geleakt werden.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repositories** einer **Organisation** und ihrer **Entwickler** herunterzuladen und automatisch [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber laufen zu lassen.

**Leakos** kann auch verwendet werden, um **gitleaks** gegen den gesamten **Text** der ihm übergebenen **URLs** laufen zu lassen, da manchmal auch **Webseiten Secrets enthalten**.

#### Github Dorks

Sieh dir die Seite [GitHub dorks and leaks page](github-leaked-secrets.md) an, um nach potenziellen **GitHub dorks** in der Organisation zu suchen.

### Pastes Leaks

Manchmal **veröffentlichen Angreifer oder einfach Mitarbeiter Unternehmensinhalte auf einer Paste-Seite**. Dies kann **sensible Informationen** enthalten oder auch nicht, aber die Suche danach ist sehr interessant.\
Du kannst das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig auf mehr als 80 Paste-Seiten zu suchen.

### Google Dorks

Alte, aber bewährte Google dorks sind immer nützlich, um **exponierte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem besteht darin, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausend** mögliche Abfragen enthält, die du nicht manuell ausführen kannst. Daher kannst du deine bevorzugten 10 auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Beachte, dass Tools, die versuchen, die gesamte Datenbank über den normalen Google-Browser auszuführen, niemals fertig werden, da Google dich sehr, sehr schnell blockieren wird._

### **Looking for vulnerabilities**

Wenn du **gültige geleakte** Credentials oder API-Tokens findest, ist das ein sehr einfacher Erfolg.

## Public Code Vulnerabilities

Wenn du feststellst, dass das Unternehmen **Open-Source-Code** hat, kannst du ihn **analysieren** und darin nach **Schwachstellen** suchen.

**Je nach Sprache** gibt es verschiedene **Tools**, die du verwenden kannst; siehe die Liste der [Source-Code-Review-Tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Es gibt auch kostenlose Services, mit denen du **öffentliche Repositories scannen** kannst, zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **Mehrheit der von Bug Huntern gefundenen Schwachstellen** befindet sich in **Webanwendungen**. Daher möchte ich an dieser Stelle über eine **Methodik zum Testen von Webanwendungen** sprechen; [**hier findest du diese Informationen**](../../network-services-pentesting/pentesting-web/index.html).

Außerdem möchte ich den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) besonders erwähnen, da sie zwar nicht unbedingt sehr kritische Schwachstellen finden, aber nützlich sind, um sie in **Workflows einzubinden und erste Informationen über das Web zu erhalten.**

## Recapitulation

> Glückwunsch! Zu diesem Zeitpunkt hast du bereits **die gesamte grundlegende Enumeration** durchgeführt. Ja, sie ist grundlegend, weil noch sehr viel mehr Enumeration möglich ist (weitere Tricks werden später behandelt).

Du hast also bereits:

1. Alle **Unternehmen** innerhalb des Scopes gefunden
2. Alle **Assets** der Unternehmen gefunden (und, falls im Scope, einige Vulnerability Scans durchgeführt)
3. Alle **Domains** der Unternehmen gefunden
4. Alle **Subdomains** der Domains gefunden (irgendein Subdomain Takeover?)
5. Alle **IPs** innerhalb des Scopes gefunden (von **CDNs** und **nicht von CDNs**).
6. Alle **Webserver** gefunden und von ihnen einen **Screenshot** erstellt (irgendetwas Seltsames, das eine genauere Untersuchung wert ist?)
7. Alle potenziellen **Public Cloud Assets** des Unternehmens gefunden.
8. **E-Mail-Adressen**, **Credential Leaks** und **Secret Leaks**, die dir sehr einfach einen **großen Erfolg** verschaffen könnten.
9. **Pentesting aller gefundenen Websites**

## **Full Recon Automatic Tools**

Es gibt verschiedene Tools, die einen Teil der vorgeschlagenen Aktionen gegen einen bestimmten Scope durchführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Etwas veraltet und nicht aktualisiert

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
{{#include ../../banners/hacktricks-training.md}}
