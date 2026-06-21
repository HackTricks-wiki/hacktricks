# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Asset-Entdeckungen

> Also dir wurde gesagt, dass alles, was zu irgendeinem Unternehmen gehört, im Scope ist, und du willst herausfinden, was dieses Unternehmen tatsächlich besitzt.

Das Ziel dieser Phase ist es, alle **Unternehmen im Besitz des Hauptunternehmens** und dann alle **Assets** dieser Unternehmen zu ermitteln. Dafür werden wir:

1. Die Akquisitionen des Hauptunternehmens finden, das gibt uns die Unternehmen im Scope.
2. Die ASN (falls vorhanden) jedes Unternehmens finden, das gibt uns die von jedem Unternehmen besessenen IP-Bereiche
3. Reverse-WHOIS-Lookups verwenden, um nach anderen Einträgen zu suchen (Organisationsnamen, Domains...), die mit dem ersten zusammenhängen (das kann rekursiv gemacht werden)
4. Andere Techniken wie Shodan `org`und `ssl`Filter verwenden, um nach weiteren Assets zu suchen (der `ssl`-Trick kann rekursiv gemacht werden).

### **Akquisitionen**

Zuerst müssen wir wissen, welche **anderen Unternehmen vom Hauptunternehmen übernommen wurden**.\
Eine Option ist, [https://www.crunchbase.com/](https://www.crunchbase.com) zu besuchen, nach dem **Hauptunternehmen** zu **suchen** und auf "**acquisitions**" zu **klicken**. Dort siehst du andere vom Hauptunternehmen übernommene Unternehmen.\
Eine andere Option ist, die **Wikipedia**-Seite des Hauptunternehmens zu besuchen und nach **acquisitions** zu suchen.\
Bei börsennotierten Unternehmen prüfe **SEC/EDGAR filings**, Seiten für **investor relations** oder lokale Unternehmensregister (z. B. **Companies House** im Vereinigten Königreich).\
Für globale Unternehmensstrukturen und Tochtergesellschaften probiere **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, an diesem Punkt solltest du alle Unternehmen im Scope kennen. Finden wir heraus, wie man ihre Assets findet.

### **ASNs**

Eine Autonomous System Number (**ASN**) ist eine **eindeutige Nummer**, die einem **Autonomous System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, die eine klar definierte Richtlinie für den Zugriff auf externe Netzwerke haben und von einer einzigen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant herauszufinden, ob dem **Unternehmen irgendeine ASN zugewiesen wurde**, um seine **IP-Bereiche** zu finden. Es ist sinnvoll, einen **Vulnerability Test** gegen alle **Hosts** im **Scope** durchzuführen und **nach Domains** innerhalb dieser IPs zu suchen.\
Du kannst in [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **oder** [**https://ipinfo.io/**](https://ipinfo.io/) **nach Firmenname**, **IP** oder **Domain** **suchen**.\
**Je nach Region des Unternehmens könnten diese Links nützlich sein, um mehr Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Dennoch erscheinen wahrscheinlich alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Außerdem aggregiert und fasst die Enumeration von [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** ASNs am Ende des Scans automatisch zusammen.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Nach Schwachstellen suchen**

An diesem Punkt kennen wir **alle Assets innerhalb des Scopes**, also könntest du, wenn du dazu berechtigt bist, einen **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) gegen alle Hosts laufen lassen.\
Außerdem könntest du einige [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) starten **oder Dienste wie** Shodan, Censys oder ZoomEye **verwenden, um** offene Ports **zu finden, und je nachdem, was du findest, solltest du** in diesem Buch nachsehen, wie man verschiedene mögliche laufende Services pentestet.\
**Außerdem könnte es sich lohnen zu erwähnen, dass du auch einige** default username **und** passwords **Listen vorbereiten und versuchen kannst, Dienste mit** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **zu bruteforcen**.

## Domains

> Wir kennen alle Unternehmen innerhalb des Scopes und ihre Assets, jetzt ist es an der Zeit, die Domains innerhalb des Scopes zu finden.

_Bitte beachte, dass du in den folgenden beschriebenen Techniken auch Subdomains finden kannst und diese Information nicht unterschätzt werden sollte._

Zuerst solltest du nach der/den **Hauptdomain(s)** jedes Unternehmens suchen. Zum Beispiel ist für _Tesla Inc._ _tesla.com_.

### **Reverse DNS**

Da du alle IP-Bereiche der Domains gefunden hast, könntest du versuchen, auf diesen **IPs reverse dns lookups** durchzuführen, um **weitere Domains innerhalb des Scopes zu finden**. Versuche, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit dies funktioniert, muss der Administrator den PTR manuell aktivieren.\
Du kannst auch ein Online-Tool für diese Informationen verwenden: [http://ptrarchive.com/](http://ptrarchive.com).\
Für große Bereiche sind Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx) nützlich, um reverse lookups und enrichment zu automatisieren.

### **Reverse Whois (loop)**

In einem **whois** kannst du viele interessante **Informationen** finden, wie **Organisationsname**, **Adresse**, **E-Mails**, Telefonnummern... Aber noch interessanter ist, dass du **weitere Assets im Zusammenhang mit dem Unternehmen** finden kannst, wenn du **reverse whois lookups anhand eines dieser Felder** durchführst (zum Beispiel andere whois-Registrierungen, in denen dieselbe E-Mail auftaucht).\
Du kannst Online-Tools wie diese verwenden:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web und API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, nicht kostenlose API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht Free (nur **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht Free
- [https://securitytrails.com/](https://securitytrails.com/) - Nicht free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nicht free (API)

Du kannst diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (erfordert einen whoxy API key).\
Du kannst auch mit [amass](https://github.com/OWASP/Amass) einige automatische reverse whois discovery durchführen: `amass intel -d tesla.com -whois`

**Beachte, dass du diese Technik nutzen kannst, um jedes Mal, wenn du eine neue Domain findest, weitere Domainnamen zu entdecken.**

### **Trackers**

Wenn du die **gleiche ID desselben trackers** auf 2 verschiedenen Seiten findest, kannst du annehmen, dass **beide Seiten** vom selben Team **verwaltet** werden.\
Wenn du zum Beispiel auf mehreren Seiten dieselbe **Google Analytics ID** oder dieselbe **Adsense ID** siehst.

Es gibt einige Seiten und Tools, mit denen du nach diesen trackers und mehr suchen kannst:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Wusstest du, dass wir verwandte Domains und Subdomains zu unserem Ziel finden können, indem wir nach demselben favicon icon hash suchen? Genau das macht das Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), erstellt von [@m4ll0k2](https://twitter.com/m4ll0k2). So verwendest du es:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt, favihash ermöglicht es uns, Domains zu entdecken, die denselben favicon icon hash wie unser Ziel haben.

Außerdem kannst du auch Technologien anhand des favicon hash suchen, wie in [**diesem Blogbeitrag**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erklärt wird. Das bedeutet, dass wenn du den **Hash des favicon einer verwundbaren Version einer Web-Technologie** kennst, du in shodan suchen und **mehr verwundbare Stellen finden** kannst:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
So kannst du den **favicon hash** einer Webanwendung **berechnen**:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
Du kannst auch Favicon-Hashes in großem Umfang mit [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) erhalten und dann in Shodan/Censys weitermachen.

### **Copyright / Uniq string**

Suche innerhalb der Webseiten nach **Strings, die über verschiedene Webseiten derselben Organisation geteilt werden könnten**. Der **Copyright-String** könnte ein gutes Beispiel sein. Suche dann nach diesem String in **google**, in anderen **browsern** oder sogar in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es ist üblich, einen cron job wie zum Beispiel zu haben
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to erneuern alle Domain-Zertifikate auf dem Server. Das bedeutet, dass selbst wenn die CA, die dafür verwendet wurde, die Zeit, zu der es generiert wurde, nicht in der Validity time setzt, es möglich ist, **Domains zu finden, die zur selben Firma gehören, in den certificate transparency logs**.\
Schau dir diese [**writeup für mehr Informationen**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/) an.

Verwende außerdem **certificate transparency** logs direkt:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-Informationen

Du kannst eine web wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben dmarc informationen teilen**.\
Weitere nützliche Tools sind [**spoofcheck**](https://github.com/BishopFox/spoofcheck) und [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Anscheinend ist es üblich, dass Leute Subdomains IPs zuweisen, die zu Cloud-Anbietern gehören, und irgendwann **diese IP-Adresse verlieren, aber vergessen, den DNS-Eintrag zu entfernen**. Daher kannst du allein durch das **Starten einer VM** in einer Cloud (wie Digital Ocean) tatsächlich **einige Subdomains übernehmen**.

[**Dieser Beitrag**](https://kmsec.uk/blog/passive-takeover/) erklärt eine Geschichte dazu und schlägt ein Skript vor, das **eine VM in DigitalOcean startet**, die **IPv4** der neuen Maschine **holt** und in Virustotal nach Subdomain-Einträgen **sucht**, die auf sie zeigen.

### **Andere Wege**

**Beachte, dass du diese Technik verwenden kannst, um jedes Mal, wenn du eine neue Domain findest, weitere Domainnamen zu entdecken.**

**Shodan**

Da du bereits den Namen der Organisation kennst, der der IP-Bereich gehört, kannst du in shodan mit diesen Daten suchen: `org:"Tesla, Inc."` Prüfe die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Du könntest auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisation name** ermitteln und dann in allen von **shodan** bekannten Webseiten mit dem Filter `ssl:"Tesla Motors"` nach diesem Namen in den **TLS-Zertifikaten** suchen oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) verwenden.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **Domains related** mit einer Hauptdomain und deren **Subdomains** sucht, ziemlich beeindruckend.

**Passive DNS / Historical DNS**

Passive-DNS-Daten sind großartig, um **alte und vergessene Einträge** zu finden, die noch auflösbar sind oder übernommen werden können. Schau dir an:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Auf der Suche nach Schwachstellen**

Prüfe auf einen [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht **verwendet eine Firma eine Domain**, hat aber **den Besitz verloren**. Registriere sie einfach (wenn billig genug) und informiere die Firma.

Wenn du eine **Domain mit einer anderen IP** als den bereits bei der Asset-Erkennung gefundenen findest, solltest du einen **grundlegenden Vulnerability-Scan** (mit Nessus oder OpenVAS) und einen [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste laufen, findest du in **diesem Buch einige Tricks, um sie "anzugreifen"**.\
_Hinweis: Manchmal wird die Domain innerhalb einer IP gehostet, die nicht vom Kunden kontrolliert wird, also ist sie nicht im Scope, sei vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen innerhalb des Scopes, alle Assets jedes Unternehmens und alle Domains, die mit den Unternehmen verbunden sind.

Es ist Zeit, alle möglichen Subdomains jeder gefundenen Domain zu finden.

> [!TIP]
> Beachte, dass einige der Tools und Techniken zum Finden von Domains auch dabei helfen können, Subdomains zu finden

### **DNS**

Lass uns versuchen, **Subdomains** aus den **DNS**-Einträgen zu bekommen. Wir sollten auch einen **Zone Transfer** versuchen (wenn verwundbar, solltest du es melden).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Der schnellste Weg, viele Subdomains zu erhalten, ist die Suche in externen Quellen. Die am häufigsten verwendeten **Tools** sind die folgenden (für bessere Ergebnisse die API-Schlüssel konfigurieren):

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
Es gibt **andere interessante Tools/APIs**, die auch wenn sie nicht direkt auf das Finden von Subdomains spezialisiert sind, nützlich sein könnten, um Subdomains zu finden, wie:

- [**IP.THC.ORG**](https://ip.thc.org) kostenlose API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um Subdomains zu erhalten
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** ruft bekannte URLs aus AlienVaults Open Threat Exchange, der Wayback Machine und Common Crawl für eine beliebige Domain ab.
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
- [**securitytrails.com**](https://securitytrails.com/) hat eine kostenlose API, um nach Subdomains und IP-Historie zu suchen
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle Subdomains an, die zu Bug-Bounty-Programmen gehören**. Du kannst auf diese Daten auch mit [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder sogar den von diesem Projekt genutzten Scope einsehen [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Du findest einen **Vergleich** vieler dieser Tools hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Lass uns versuchen, neue **Subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen brute-forcen.

Für diese Aktion brauchst du einige **gängige Subdomain-Wordlists wie**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Und außerdem IPs guter DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, kannst du die Resolver von [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) herunterladen und [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) verwenden, um sie zu filtern. Oder du könntest verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die am meisten empfohlenen Tools für DNS Brute-force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das einen effektiven DNS-Brute-force durchführte. Es ist sehr schnell, allerdings anfällig für False Positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Dieser hier verwendet meines Erachtens nur 1 Resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in go, der es dir ermöglicht, gültige Subdomains per aktivem Bruteforce zu enumerieren sowie Subdomains mit Wildcard-Handling und einfacher Input-Output-Unterstützung aufzulösen.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet ebenfalls `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron zu bruteforcen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS-Brute-Force-Runde

Nachdem du Subdomains mithilfe von Open-Source-Quellen und Brute-Forcing gefunden hast, könntest du Variationen der gefundenen Subdomains erzeugen, um noch mehr zu finden. Mehrere Tools sind für diesen Zweck nützlich:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Erzeugt Permutationen aus den Domains und Subdomains.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Aus den Domains und Subdomains Permutationen generieren.
- Du kannst die goaltdns-Permutations-**wordlist** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) erhalten.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegeben die Domains und Subdomains, generiere Permutationen. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Abgesehen vom Generieren von Subdomain-Permutationen kann es auch versuchen, sie aufzulösen (aber es ist besser, die zuvor kommentierten Tools zu verwenden).
- Die altdns-Permutations-**Wordlist** findest du [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zum Durchführen von Permutationen, Mutationen und Änderungen von Subdomains. Dieses Tool führt einen Brute-Force-Angriff auf das Ergebnis aus (es unterstützt kein DNS-Wildcard).
- Du kannst die dmut-Permutations-Wordlist [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) erhalten.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es neue potenzielle Subdomain-Namen** anhand angegebener Muster, um weitere Subdomains zu entdecken.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Für mehr Informationen lies diesen [**post**](https://cramppet.github.io/regulator/index.html), aber im Wesentlichen nimmt es die **Hauptbestandteile** der **entdeckten Subdomains** und mischt sie, um weitere Subdomains zu finden.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, gekoppelt mit einem immens einfachen, aber effektiven, DNS-Antwort-gesteuerten Algorithmus. Er nutzt einen bereitgestellten Satz von Eingabedaten, wie eine angepasste Wordlist oder historische DNS/TLS-Records, um präzise weitere passende Domainnamen zu synthetisieren und diese in einer Schleife anhand der während des DNS-Scans gesammelten Informationen weiter auszubauen.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Schau dir diesen Blogpost an, den ich darüber geschrieben habe, wie man die **Subdomain discovery** aus einer Domain mit **Trickest workflows** automatisieren kann, damit ich nicht manuell eine Menge Tools auf meinem Computer starten muss:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Wenn du eine IP-Adresse gefunden hast, die **eine oder mehrere web pages** enthält, die zu Subdomains gehören, könntest du versuchen, **andere Subdomains mit webs in dieser IP** zu finden, indem du in **OSINT sources** nach Domains in einer IP suchst oder **VHost domain names in dieser IP per brute-force**.

#### OSINT

Du kannst einige **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder other APIs** finden.

**Brute Force**

Wenn du vermutest, dass eine Subdomain in einem web server verborgen sein könnte, könntest du versuchen, sie per brute force zu finden:

Wenn die **IP zu einem hostname weiterleitet** (name-based vhosts), fuzz den `Host` header direkt und lass ffuf **auto-calibrate**, um Responses hervorzuheben, die sich vom default vhost unterscheiden:
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
> Mit dieser Technik kannst du möglicherweise sogar auf interne/verborgene Endpunkte zugreifen.

### **CORS Brute Force**

Manchmal findest du Seiten, die den Header _**Access-Control-Allow-Origin**_ nur dann zurückgeben, wenn im _**Origin**_-Header eine gültige Domain/Subdomain gesetzt ist. In solchen Szenarien kannst du dieses Verhalten ausnutzen, um neue **Subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Während du nach **Subdomains** suchst, achte darauf, ob sie auf irgendeine Art von **bucket** zeigen, und prüfe in diesem Fall [**die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Da du zu diesem Zeitpunkt alle Domains innerhalb des Scopes kennen wirst, versuche außerdem, [**mögliche bucket-Namen per brute force zu erraten und die Berechtigungen zu prüfen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Du kannst **überwachen**, ob **neue Subdomains** einer Domain erstellt werden, indem du die **Certificate Transparency** Logs überwachst, wie es [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)macht.

### **Looking for vulnerabilities**

Prüfe auf mögliche [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3 bucket** zeigt, [**prüfe die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn du eine **Subdomain mit einer anderen IP** als denjenigen findest, die du bereits bei der Asset-Discovery gefunden hast, solltest du einen **grundlegenden vulnerability scan** (mit Nessus oder OpenVAS) und einen [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Services laufen, kannst du in **diesem Buch einige Tricks finden, um sie "anzugreifen"**.\
_Hinweis: Manchmal wird die Subdomain auf einer IP gehostet, die nicht vom Client kontrolliert wird, also nicht im Scope liegt; sei vorsichtig._

## IPs

In den ersten Schritten hast du möglicherweise **einige IP-Ranges, Domains und Subdomains gefunden**.\
Jetzt ist es an der Zeit, **alle IPs aus diesen Ranges zu sammeln** und für die **Domains/Subdomains (DNS queries).**

Mit Services aus den folgenden **free apis** kannst du außerdem **frühere IPs finden, die von Domains und Subdomains verwendet wurden**. Diese IPs könnten noch immer dem Client gehören (und dir möglicherweise helfen, [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Du kannst auch mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) nach Domains prüfen, die auf eine bestimmte IP-Adresse zeigen

### **Looking for vulnerabilities**

**Führe einen Port scan aller IPs durch, die nicht zu CDNs gehören** (da du dort höchstwahrscheinlich nichts Interessantes finden wirst). In den entdeckten laufenden Services könntest du **Schwachstellen finden**.

**Finde einen** [**guide**](../pentesting-network/index.html) **darüber, wie man Hosts scannt.**

## Web servers hunting

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen IP-Ranges, Domains und Subdomains innerhalb des Scopes. Jetzt ist es an der Zeit, nach Webservern zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits einige **Recon der gefundenen IPs und Domains** durchgeführt, also hast du möglicherweise **bereits alle möglichen Webserver gefunden**. Falls nicht, sehen wir uns jetzt einige **schnelle Tricks an, um Webserver** innerhalb des Scopes zu finden.

Bitte beachte, dass dies **auf die Discovery von Web-Apps ausgerichtet** ist, daher solltest du auch **vulnerability** und **port scanning** durchführen (**wenn der Scope es erlaubt**).

Eine **schnelle Methode**, um **offene Ports** im Zusammenhang mit **Web**-Servern mit [**masscan** zu entdecken, findest du hier](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres nützliches Tool, um nach Webservern zu suchen, ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste von Domains, und es versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich kannst du angeben, dass andere Ports ausprobiert werden sollen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Jetzt, da du **alle Webserver** im Scope entdeckt hast (unter den **IPs** der Firma sowie allen **Domains** und **Subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es also einfach und beginnen damit, von allen Screenshots zu erstellen. Schon allein durch einen **Blick** auf die **Hauptseite** kannst du **komische** Endpunkte finden, die **anfälliger** für **Schwachstellen** sind.

Um die vorgeschlagene Idee umzusetzen, kannst du [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Außerdem könntest du dann [**eyeballer**](https://github.com/BishopFox/eyeballer) verwenden, um alle **Screenshots** durchzugehen und dir zu sagen, **was wahrscheinlich Schwachstellen enthält** und was nicht.

## Public Cloud Assets

Um potenzielle Cloud Assets einer Firma zu finden, solltest du **mit einer Liste von Schlüsselwörtern beginnen, die diese Firma identifizieren**. Zum Beispiel könntest du bei einer Krypto-Firma Wörter wie `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Du benötigst außerdem Wortlisten mit **häufigen Wörtern, die in Buckets verwendet werden**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dann solltest du mit diesen Wörtern **Permutationen** erzeugen (siehe die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) für mehr Infos).

Mit den resultierenden Wortlisten könntest du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Denk daran, dass du bei der Suche nach Cloud Assets l**ook for more than just buckets in AWS** solltest.

### **Looking for vulnerabilities**

Wenn du Dinge wie **offene Buckets oder exponierte Cloud Functions** findest, solltest du **darauf zugreifen** und versuchen zu sehen, was sie dir bieten und ob du sie missbrauchen kannst.

## Emails

Mit den **Domains** und **Subdomains** im Scope hast du im Grunde alles, was du **brauchst, um mit der Suche nach E-Mails zu beginnen**. Das sind die **APIs** und **Tools**, die sich für mich am besten bewährt haben, um E-Mails einer Firma zu finden:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Looking for vulnerabilities**

E-Mails werden später nützlich sein, um **Web-Logins und Auth-Services** (wie SSH) per **Brute-Force** anzugreifen. Außerdem werden sie für **Phishings** benötigt. Darüber hinaus liefern dir diese APIs noch mehr **Infos über die Person** hinter der E-Mail, was für die Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains,** **Subdomains** und **E-Mails** kannst du damit beginnen, nach in der Vergangenheit geleakten Zugangsdaten zu suchen, die zu diesen E-Mails gehören:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Wenn du **gültige geleakte** Zugangsdaten findest, ist das ein sehr einfacher Gewinn.

## Secrets Leaks

Credential Leaks hängen mit Hacks von Unternehmen zusammen, bei denen **sensible Informationen geleakt und verkauft** wurden. Unternehmen können jedoch auch von **anderen leaks** betroffen sein, deren Infos nicht in diesen Datenbanken enthalten sind:

### Github Leaks

Credentials und APIs können in den **öffentlichen Repositories** des **Unternehmens** oder der **Benutzer**, die für dieses github-Unternehmen arbeiten, geleakt sein.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um automatisch alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** **herunterzuladen** und [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber auszuführen.

**Leakos** kann auch verwendet werden, um **gitleaks** auf allen per **Text** bereitgestellten **URLs** auszuführen, da **Webseiten manchmal ebenfalls Secrets enthalten**.

#### Github Dorks

Sieh dir auch diese **Seite** für potenzielle **github dorks** an, nach denen du ebenfalls in der Organisation suchen könntest, die du angreifst:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Manchmal veröffentlichen Angreifer oder einfach Mitarbeiter **Unternehmensinhalte auf einer Paste-Seite**. Das kann **sensible Informationen** enthalten oder auch nicht, ist aber sehr interessant zu durchsuchen.\
Du kannst das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 Paste-Seiten zu suchen.

### Google Dorks

Alte, aber gute google dorks sind immer nützlich, um **offengelegte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **tausend** mögliche Abfragen enthält, die du nicht manuell ausführen kannst. Du kannst also deine 10 Favoriten wählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Beachte, dass Tools, die erwarten, die gesamte Datenbank mit dem normalen Google-Browser auszuführen, niemals fertig werden, da Google dich sehr, sehr schnell blockieren wird._

### **Looking for vulnerabilities**

Wenn du **gültige geleakte** Zugangsdaten oder API-Token findest, ist das ein sehr einfacher Gewinn.

## Public Code Vulnerabilities

Wenn du herausgefunden hast, dass die Firma **Open-Source-Code** hat, kannst du ihn **analysieren** und darin nach **Schwachstellen** suchen.

**Je nach Sprache** gibt es verschiedene **Tools**, die du verwenden kannst:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Es gibt auch kostenlose Dienste, mit denen du **öffentliche Repositories scannen** kannst, wie zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Der **Großteil der Schwachstellen**, die von Bug Huntern gefunden werden, befindet sich in **Webanwendungen**, daher möchte ich an dieser Stelle über eine **Methodik zum Testen von Webanwendungen** sprechen, und du kannst [**diese Informationen hier finden**](../../network-services-pentesting/pentesting-web/index.html).

Ich möchte außerdem den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) besonders erwähnen, denn auch wenn du nicht erwarten solltest, dass sie dir sehr sensible Schwachstellen finden, sind sie nützlich, um sie in **Workflows** einzubinden, um zunächst einige Web-Informationen zu erhalten.

## Recapitulation

> Glückwunsch! An diesem Punkt hast du bereits **alle grundlegenden Enumerations** durchgeführt. Ja, sie sind grundlegend, weil noch viel mehr Enumeration möglich ist (wir werden später noch weitere Tricks sehen).

Also hast du bereits:

1. Alle **Unternehmen** im Scope gefunden
2. Alle **Assets** gefunden, die zu den Unternehmen gehören (und falls im Scope, einen Schwachstellenscan durchgeführt)
3. Alle **Domains** gefunden, die zu den Unternehmen gehören
4. Alle **Subdomains** der Domains gefunden (irgendein Subdomain-Takeover?)
5. Alle **IPs** (von und **nicht von CDNs**) im Scope gefunden.
6. Alle **Webserver** gefunden und von ihnen einen **Screenshot** gemacht (etwas Seltsames, das einen genaueren Blick wert ist?)
7. Alle **potenziellen öffentlichen Cloud Assets** gefunden, die zur Firma gehören.
8. **E-Mails**, **Credential Leaks** und **Secret Leaks**, die dir sehr einfach einen **großen Gewinn** bringen könnten.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Es gibt mehrere Tools, die einen Teil der vorgeschlagenen Aktionen gegen einen gegebenen Scope ausführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ein bisschen alt und nicht aktualisiert

## **References**

- Alle kostenlosen Kurse von [**@Jhaddix**](https://twitter.com/Jhaddix) wie [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
