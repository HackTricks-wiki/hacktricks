# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Vermögensentdeckungen

> Ihnen wurde gesagt, dass alles, was zu einem Unternehmen gehört, im Geltungsbereich liegt, und Sie möchten herausfinden, was dieses Unternehmen tatsächlich besitzt.

Das Ziel dieser Phase ist es, alle **Unternehmen, die im Besitz des Hauptunternehmens sind**, und dann alle **Vermögenswerte** dieser Unternehmen zu ermitteln. Dazu werden wir:

1. Die Übernahmen des Hauptunternehmens finden, dies wird uns die Unternehmen im Geltungsbereich geben.
2. Die ASN (falls vorhanden) jedes Unternehmens finden, dies wird uns die IP-Bereiche geben, die jedem Unternehmen gehören.
3. Rückwärtige Whois-Abfragen verwenden, um nach anderen Einträgen (Organisationsnamen, Domains...) zu suchen, die mit dem ersten verbunden sind (dies kann rekursiv erfolgen).
4. Andere Techniken wie Shodan `org` und `ssl` Filter verwenden, um nach anderen Vermögenswerten zu suchen (der `ssl` Trick kann rekursiv durchgeführt werden).

### **Übernahmen**

Zunächst müssen wir wissen, welche **anderen Unternehmen im Besitz des Hauptunternehmens sind**.\
Eine Möglichkeit besteht darin, [https://www.crunchbase.com/](https://www.crunchbase.com) zu besuchen, **nach** dem **Hauptunternehmen** zu **suchen** und auf "**Übernahmen**" zu **klicken**. Dort sehen Sie andere Unternehmen, die von dem Hauptunternehmen übernommen wurden.\
Eine andere Möglichkeit besteht darin, die **Wikipedia**-Seite des Hauptunternehmens zu besuchen und nach **Übernahmen** zu suchen.

> Ok, an diesem Punkt sollten Sie alle Unternehmen im Geltungsbereich kennen. Lassen Sie uns herausfinden, wie wir ihre Vermögenswerte finden können.

### **ASNs**

Eine autonome Systemnummer (**ASN**) ist eine **eindeutige Nummer**, die einem **autonomen System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, die eine eindeutig definierte Richtlinie für den Zugriff auf externe Netzwerke haben und von einer einzigen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant herauszufinden, ob das **Unternehmen eine ASN zugewiesen hat**, um seine **IP-Bereiche** zu finden. Es wäre interessant, einen **Sicherheitstest** gegen alle **Hosts** im **Geltungsbereich** durchzuführen und **nach Domains** innerhalb dieser IPs zu suchen.\
Sie können **nach** dem **Namen** des Unternehmens, nach **IP** oder nach **Domain** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Je nach Region des Unternehmens könnten diese Links nützlich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Jedenfalls erscheinen wahrscheinlich alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Außerdem aggregiert und fasst die Subdomain-Enumeration von [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** die ASNs am Ende des Scans automatisch zusammen.
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
Sie können die IP-Bereiche einer Organisation auch mit [http://asnlookup.com/](http://asnlookup.com) finden (es hat eine kostenlose API).\
Sie können die IP und ASN einer Domain mit [http://ipv4info.com/](http://ipv4info.com) finden.

### **Auf der Suche nach Schwachstellen**

An diesem Punkt kennen wir **alle Vermögenswerte im Geltungsbereich**, also könnten Sie, wenn Sie dazu berechtigt sind, einige **Schwachstellenscanner** (Nessus, OpenVAS) über alle Hosts starten.\
Außerdem könnten Sie einige [**Port-Scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **starten oder Dienste wie** shodan **verwenden, um** offene Ports **zu finden, und je nachdem, was Sie finden, sollten Sie** in diesem Buch nachsehen, wie man mehrere mögliche Dienste testet.\
**Es könnte auch erwähnenswert sein, dass Sie auch einige** Standardbenutzernamen **und** Passwortlisten **vorbereiten und versuchen können,** Dienste mit [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) zu bruteforcen.

## Domains

> Wir kennen alle Unternehmen im Geltungsbereich und deren Vermögenswerte, es ist Zeit, die Domains im Geltungsbereich zu finden.

_Bitte beachten Sie, dass Sie mit den folgenden vorgeschlagenen Techniken auch Subdomains finden können und diese Informationen nicht unterschätzt werden sollten._

Zunächst sollten Sie nach der **Hauptdomain**(s) jedes Unternehmens suchen. Zum Beispiel wird für _Tesla Inc._ die Domain _tesla.com_ sein.

### **Reverse DNS**

Da Sie alle IP-Bereiche der Domains gefunden haben, könnten Sie versuchen, **Reverse-DNS-Abfragen** auf diesen **IPs durchzuführen, um weitere Domains im Geltungsbereich zu finden**. Versuchen Sie, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit dies funktioniert, muss der Administrator manuell den PTR aktivieren.\
Sie können auch ein Online-Tool für diese Informationen verwenden: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Innerhalb eines **whois** finden Sie viele interessante **Informationen** wie **Organisationsname**, **Adresse**, **E-Mails**, Telefonnummern... Aber was noch interessanter ist, ist, dass Sie **weitere Vermögenswerte, die mit dem Unternehmen verbunden sind**, finden können, wenn Sie **Reverse-Whois-Abfragen nach einem dieser Felder** durchführen (zum Beispiel andere Whois-Registrierungen, bei denen dieselbe E-Mail erscheint).\
Sie können Online-Tools wie verwenden:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Kostenlos** web, nicht kostenloses API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht kostenlos
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Suchen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos

Sie können diese Aufgabe automatisieren, indem Sie [**DomLink** ](https://github.com/vysecurity/DomLink) verwenden (benötigt einen Whoxy-API-Schlüssel).\
Sie können auch einige automatische Reverse-Whois-Entdeckungen mit [amass](https://github.com/OWASP/Amass) durchführen: `amass intel -d tesla.com -whois`

**Beachten Sie, dass Sie diese Technik verwenden können, um jedes Mal weitere Domainnamen zu entdecken, wenn Sie eine neue Domain finden.**

### **Trackers**

Wenn Sie die **gleiche ID des gleichen Trackers** auf 2 verschiedenen Seiten finden, können Sie annehmen, dass **beide Seiten** von **dem gleichen Team** verwaltet werden.\
Zum Beispiel, wenn Sie dieselbe **Google Analytics-ID** oder dieselbe **Adsense-ID** auf mehreren Seiten sehen.

Es gibt einige Seiten und Tools, die es Ihnen ermöglichen, nach diesen Trackern und mehr zu suchen:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Wussten Sie, dass wir verwandte Domains und Subdomains zu unserem Ziel finden können, indem wir nach dem gleichen Favicon-Icon-Hash suchen? Genau das macht das Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), das von [@m4ll0k2](https://twitter.com/m4ll0k2) erstellt wurde. So verwenden Sie es:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - entdecke Domains mit dem gleichen Favicon-Icon-Hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt, favihash ermöglicht es uns, Domains zu entdecken, die denselben Favicon-Icon-Hash wie unser Ziel haben.

Darüber hinaus kannst du auch Technologien mithilfe des Favicon-Hashes suchen, wie in [**diesem Blogbeitrag**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erklärt. Das bedeutet, dass du, wenn du den **Hash des Favicon einer verwundbaren Version einer Webtechnologie** kennst, in Shodan suchen und **weitere verwundbare Orte finden** kannst:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
So können Sie den **Favicon-Hash** einer Website berechnen:
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
### **Copyright / Uniq string**

Suchen Sie auf den Webseiten **Strings, die in verschiedenen Webseiten derselben Organisation geteilt werden könnten**. Der **Copyright-String** könnte ein gutes Beispiel sein. Suchen Sie dann nach diesem String in **Google**, in anderen **Browsern** oder sogar in **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es ist üblich, einen Cron-Job zu haben, wie
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
um alle Domainzertifikate auf dem Server zu erneuern. Das bedeutet, dass selbst wenn die CA, die dafür verwendet wird, die Zeit, zu der es generiert wurde, nicht in der Gültigkeitszeit festlegt, es möglich ist, **Domains zu finden, die zur gleichen Firma in den Zertifikatstransparenzprotokollen gehören**.\
Siehe diesen [**Artikel für weitere Informationen**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC Informationen

Sie können eine Webseite wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die die gleichen DMARC-Informationen teilen**.

### **Passive Übernahme**

Es ist anscheinend üblich, dass Menschen Subdomains IPs zuweisen, die zu Cloud-Anbietern gehören, und irgendwann **diese IP-Adresse verlieren, aber vergessen, den DNS-Eintrag zu entfernen**. Daher werden Sie durch **das Erstellen einer VM** in einer Cloud (wie Digital Ocean) tatsächlich **einige Subdomains übernehmen**.

[**Dieser Beitrag**](https://kmsec.uk/blog/passive-takeover/) erklärt eine Geschichte darüber und schlägt ein Skript vor, das **eine VM in DigitalOcean erstellt**, **die** **IPv4** der neuen Maschine **erhält** und **in Virustotal nach Subdomain-Einträgen** sucht, die darauf verweisen.

### **Andere Möglichkeiten**

**Beachten Sie, dass Sie diese Technik verwenden können, um jedes Mal mehr Domainnamen zu entdecken, wenn Sie eine neue Domain finden.**

**Shodan**

Wie Sie bereits wissen, gehört der Name der Organisation, die den IP-Bereich besitzt. Sie können nach diesen Daten in Shodan suchen mit: `org:"Tesla, Inc."` Überprüfen Sie die gefundenen Hosts auf neue unerwartete Domains im TLS-Zertifikat.

Sie könnten das **TLS-Zertifikat** der Hauptwebseite abrufen, den **Namen der Organisation** erhalten und dann nach diesem Namen in den **TLS-Zertifikaten** aller Webseiten suchen, die von **Shodan** bekannt sind, mit dem Filter: `ssl:"Tesla Motors"` oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) verwenden.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **Domains sucht, die mit einer Hauptdomain und deren Subdomains** verbunden sind, ziemlich erstaunlich.

### **Nach Schwachstellen suchen**

Überprüfen Sie einige [Domainübernahmen](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht verwendet ein Unternehmen **eine Domain**, hat aber **die Eigentümerschaft verloren**. Registrieren Sie sie einfach (wenn sie günstig genug ist) und informieren Sie das Unternehmen.

Wenn Sie eine **Domain mit einer anderen IP** als den bereits in der Asset-Entdeckung gefundenen finden, sollten Sie einen **einfachen Schwachscann** (mit Nessus oder OpenVAS) und einen [**Portscan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste ausgeführt werden, können Sie in **diesem Buch einige Tricks finden, um sie zu "angreifen"**.\
&#xNAN;_&#x4E;ote, dass manchmal die Domain innerhalb einer IP gehostet wird, die nicht vom Kunden kontrolliert wird, sodass sie nicht im Geltungsbereich liegt, seien Sie vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen im Geltungsbereich, alle Vermögenswerte jedes Unternehmens und alle Domains, die mit den Unternehmen verbunden sind.

Es ist Zeit, alle möglichen Subdomains jeder gefundenen Domain zu finden.

> [!TIP]
> Beachten Sie, dass einige der Tools und Techniken zur Auffindung von Domains auch helfen können, Subdomains zu finden.

### **DNS**

Lassen Sie uns versuchen, **Subdomains** aus den **DNS**-Einträgen zu erhalten. Wir sollten auch nach **Zonenübertragungen** suchen (wenn anfällig, sollten Sie dies melden).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Der schnellste Weg, um viele Subdomains zu erhalten, ist die Suche in externen Quellen. Die am häufigsten verwendeten **Tools** sind die folgenden (für bessere Ergebnisse API-Schlüssel konfigurieren):

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
Es gibt **andere interessante Tools/APIs**, die, auch wenn sie nicht direkt auf das Finden von Subdomains spezialisiert sind, nützlich sein könnten, um Subdomains zu finden, wie:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um Subdomains zu erhalten.
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
- [**gau**](https://github.com/lc/gau)**:** ruft bekannte URLs von AlienVaults Open Threat Exchange, der Wayback Machine und Common Crawl für eine gegebene Domain ab.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Sie durchsuchen das Web nach JS-Dateien und extrahieren von dort Subdomains.
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
- [**Censys Subdomain-Finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) hat eine kostenlose API, um nach Subdomains und IP-Historie zu suchen.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle Subdomains, die mit Bug-Bounty-Programmen verbunden sind**. Sie können auf diese Daten auch mit [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder sogar auf den Umfang zugreifen, der von diesem Projekt verwendet wird [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list).

Sie finden einen **Vergleich** vieler dieser Tools hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off).

### **DNS Brute Force**

Lassen Sie uns versuchen, neue **Subdomains** durch Brute-Forcing von DNS-Servern mit möglichen Subdomain-Namen zu finden.

Für diese Aktion benötigen Sie einige **gemeinsame Subdomain-Wortlisten wie**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Und auch IPs von guten DNS-Resolvern. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, können Sie die Resolver von [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) herunterladen und [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) verwenden, um sie zu filtern. Oder Sie könnten verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt).

Die am meisten empfohlenen Tools für DNS-Brute-Force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das ein effektives DNS-Brute-Force durchführte. Es ist sehr schnell, jedoch anfällig für falsche Positivmeldungen.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ich denke, dass dieser nur 1 Resolver verwendet.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, der es Ihnen ermöglicht, gültige Subdomains mit aktivem Bruteforce zu enumerieren sowie Subdomains mit Wildcard-Verarbeitung und einfacher Eingabe-Ausgabe-Unterstützung aufzulösen.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet ebenfalls `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domänennamen asynchron zu brute-forcen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS Brute-Force Runde

Nachdem Sie Subdomains mit offenen Quellen und Brute-Forcing gefunden haben, können Sie Variationen der gefundenen Subdomains generieren, um noch mehr zu finden. Mehrere Tools sind dafür nützlich:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Gegebene Domains und Subdomains generieren Permutationen.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Gegebene Domains und Subdomains Permutationen generieren.
- Sie können die **wordlist** von goaltdns **hier** erhalten: [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Gegebenen Domains und Subdomains Permutationen generieren. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Neben der Generierung von Subdomain-Permutationen kann es auch versuchen, diese aufzulösen (aber es ist besser, die zuvor kommentierten Tools zu verwenden).
- Sie können die altdns-Permutationen **Wortliste** in [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) erhalten.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zur Durchführung von Permutationen, Mutationen und Änderungen von Subdomains. Dieses Tool wird das Ergebnis brute-forcen (es unterstützt keine DNS-Wildcards).
- Sie können die dmut-Permutationen-Wortliste [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) erhalten.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es neue potenzielle Subdomänennamen** basierend auf angegebenen Mustern, um weitere Subdomänen zu entdecken.

#### Intelligente Permutationsgenerierung

- [**regulator**](https://github.com/cramppet/regulator): Für weitere Informationen lesen Sie diesen [**Beitrag**](https://cramppet.github.io/regulator/index.html), aber es wird im Grunde die **Hauptteile** von den **entdeckten Subdomänen** extrahieren und sie mischen, um weitere Subdomänen zu finden.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven DNS-Antwort-gesteuerten Algorithmus gekoppelt ist. Es nutzt einen bereitgestellten Satz von Eingabedaten, wie eine maßgeschneiderte Wortliste oder historische DNS/TLS-Aufzeichnungen, um genauere entsprechende Domainnamen zu synthetisieren und diese in einer Schleife basierend auf den während des DNS-Scans gesammelten Informationen weiter zu erweitern.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Überprüfen Sie diesen Blogbeitrag, den ich über die **Automatisierung der Subdomain-Entdeckung** von einer Domain mit **Trickest-Workflows** geschrieben habe, damit ich nicht manuell eine Reihe von Tools auf meinem Computer starten muss:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtuelle Hosts**

Wenn Sie eine IP-Adresse gefunden haben, die **eine oder mehrere Webseiten** von Subdomains enthält, könnten Sie versuchen, **andere Subdomains mit Webseiten in dieser IP** zu finden, indem Sie in **OSINT-Quellen** nach Domains in einer IP suchen oder **VHost-Domainnamen in dieser IP brute-forcen**.

#### OSINT

Sie können einige **VHosts in IPs finden, indem Sie** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder andere APIs** verwenden.

**Brute Force**

Wenn Sie vermuten, dass eine Subdomain auf einem Webserver verborgen sein könnte, könnten Sie versuchen, sie brute zu forcen:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Mit dieser Technik können Sie möglicherweise sogar auf interne/verborgene Endpunkte zugreifen.

### **CORS Brute Force**

Manchmal finden Sie Seiten, die nur den Header _**Access-Control-Allow-Origin**_ zurückgeben, wenn eine gültige Domain/Subdomain im _**Origin**_ Header gesetzt ist. In diesen Szenarien können Sie dieses Verhalten ausnutzen, um **neue** **Subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Während Sie nach **Subdomains** suchen, achten Sie darauf, ob sie auf irgendeine Art von **Bucket** zeigen, und in diesem Fall [**überprüfen Sie die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Außerdem, da Sie zu diesem Zeitpunkt alle Domains im Geltungsbereich kennen, versuchen Sie, [**mögliche Bucket-Namen zu brute-forcen und die Berechtigungen zu überprüfen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorisierung**

Sie können **überwachen**, ob **neue Subdomains** einer Domain erstellt werden, indem Sie die **Certificate Transparency** Logs überwachen, was [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) tut.

### **Suche nach Schwachstellen**

Überprüfen Sie auf mögliche [**Subdomain-Übernahmen**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3-Bucket** zeigt, [**überprüfen Sie die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn Sie eine **Subdomain mit einer anderen IP** als den bereits in der Asset-Entdeckung gefundenen finden, sollten Sie einen **grundlegenden Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**Portscan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste ausgeführt werden, können Sie in **diesem Buch einige Tricks finden, um sie zu "angreifen"**.\
&#xNAN;_&#x4E;ote, dass die Subdomain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird, sodass sie nicht im Geltungsbereich liegt. Seien Sie vorsichtig._

## IPs

In den ersten Schritten haben Sie möglicherweise **einige IP-Bereiche, Domains und Subdomains** gefunden.\
Es ist Zeit, **alle IPs aus diesen Bereichen zu sammeln** und für die **Domains/Subdomains (DNS-Abfragen).**

Mit Diensten aus den folgenden **kostenlosen APIs** können Sie auch **frühere IPs finden, die von Domains und Subdomains verwendet wurden**. Diese IPs könnten immer noch dem Kunden gehören (und könnten Ihnen helfen, [**CloudFlare-Bypässe**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Sie können auch nach Domains suchen, die auf eine bestimmte IP-Adresse zeigen, indem Sie das Tool [**hakip2host**](https://github.com/hakluke/hakip2host) verwenden.

### **Suche nach Schwachstellen**

**Portscannen Sie alle IPs, die nicht zu CDNs gehören** (da Sie dort höchstwahrscheinlich nichts Interessantes finden werden). In den entdeckten laufenden Diensten könnten Sie **Schwachstellen finden**.

**Finden Sie einen** [**Leitfaden**](../pentesting-network/index.html) **zum Scannen von Hosts.**

## Webserver-Jagd

> Wir haben alle Unternehmen und deren Vermögenswerte gefunden und kennen IP-Bereiche, Domains und Subdomains im Geltungsbereich. Es ist Zeit, nach Webservern zu suchen.

In den vorherigen Schritten haben Sie wahrscheinlich bereits einige **Recon der entdeckten IPs und Domains** durchgeführt, sodass Sie **bereits alle möglichen Webserver gefunden haben**. Wenn nicht, werden wir jetzt einige **schnelle Tricks zur Suche nach Webservern** im Geltungsbereich sehen.

Bitte beachten Sie, dass dies **auf die Entdeckung von Webanwendungen** ausgerichtet sein wird, sodass Sie auch **den Schwachstellenscan** und **Portscan** durchführen sollten (**wenn im Geltungsbereich erlaubt**).

Eine **schnelle Methode**, um **offene Ports** im Zusammenhang mit **Web**-Servern zu entdecken, ist [**masscan** hier zu finden](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres benutzerfreundliches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Sie geben einfach eine Liste von Domains ein, und es wird versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich können Sie angeben, dass andere Ports ausprobiert werden sollen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Jetzt, da Sie **alle Webserver** im Geltungsbereich (unter den **IPs** des Unternehmens und allen **Domains** und **Subdomains**) entdeckt haben, wissen Sie wahrscheinlich **nicht, wo Sie anfangen sollen**. Lassen Sie uns das einfach machen und beginnen Sie einfach damit, Screenshots von allen zu machen. Nur durch **einen Blick** auf die **Hauptseite** können Sie **seltsame** Endpunkte finden, die eher **anfällig** für **Schwachstellen** sind.

Um die vorgeschlagene Idee umzusetzen, können Sie [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Darüber hinaus könnten Sie dann [**eyeballer**](https://github.com/BishopFox/eyeballer) verwenden, um alle **Screenshots** zu durchsuchen und Ihnen zu sagen, **was wahrscheinlich Schwachstellen enthält** und was nicht.

## Öffentliche Cloud-Ressourcen

Um potenzielle Cloud-Ressourcen eines Unternehmens zu finden, sollten Sie **mit einer Liste von Schlüsselwörtern beginnen, die dieses Unternehmen identifizieren**. Zum Beispiel, für ein Krypto-Unternehmen könnten Sie Wörter wie: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Sie benötigen auch Wortlisten von **häufig verwendeten Wörtern in Buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dann sollten Sie mit diesen Wörtern **Permutationen** generieren (siehe [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) für weitere Informationen).

Mit den resultierenden Wortlisten könnten Sie Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Denken Sie daran, dass Sie bei der Suche nach Cloud-Ressourcen **mehr als nur Buckets in AWS suchen sollten**.

### **Auf der Suche nach Schwachstellen**

Wenn Sie Dinge wie **offene Buckets oder exponierte Cloud-Funktionen** finden, sollten Sie **auf sie zugreifen** und versuchen zu sehen, was sie Ihnen bieten und ob Sie sie missbrauchen können.

## E-Mails

Mit den **Domains** und **Subdomains** im Geltungsbereich haben Sie im Grunde alles, was Sie **brauchen, um nach E-Mails zu suchen**. Dies sind die **APIs** und **Tools**, die für mich am besten funktioniert haben, um E-Mails eines Unternehmens zu finden:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Auf der Suche nach Schwachstellen**

E-Mails werden später nützlich sein, um **Web-Logins und Authentifizierungsdienste** (wie SSH) zu **brute-forcen**. Außerdem werden sie für **Phishing** benötigt. Darüber hinaus geben Ihnen diese APIs sogar noch mehr **Informationen über die Person** hinter der E-Mail, was für die Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains,** **Subdomains** und **E-Mails** können Sie nach in der Vergangenheit geleakten Anmeldeinformationen suchen, die zu diesen E-Mails gehören:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Auf der Suche nach Schwachstellen**

Wenn Sie **gültige geleakte** Anmeldeinformationen finden, ist das ein sehr einfacher Gewinn.

## Secrets Leaks

Credential Leaks stehen im Zusammenhang mit Hacks von Unternehmen, bei denen **sensible Informationen geleakt und verkauft** wurden. Unternehmen könnten jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken enthalten sind:

### Github Leaks

Anmeldeinformationen und APIs könnten in den **öffentlichen Repositories** des **Unternehmens** oder der **Benutzer**, die für dieses Github-Unternehmen arbeiten, geleakt werden.\
Sie können das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** herunterzuladen und automatisch [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber auszuführen.

**Leakos** kann auch verwendet werden, um **gitleaks** gegen alle **Text-URLs**, die ihm übergeben werden, auszuführen, da manchmal **Webseiten auch Geheimnisse enthalten**.

#### Github Dorks

Überprüfen Sie auch diese **Seite** auf potenzielle **Github Dorks**, nach denen Sie in der Organisation, die Sie angreifen, suchen könnten:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Manchmal veröffentlichen Angreifer oder einfach Mitarbeiter **Unternehmensinhalte auf einer Paste-Seite**. Dies könnte **sensible Informationen** enthalten oder auch nicht, aber es ist sehr interessant, danach zu suchen.\
Sie können das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 Paste-Seiten zu suchen.

### Google Dorks

Alte, aber bewährte Google Dorks sind immer nützlich, um **exponierte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **tausend** mögliche Abfragen enthält, die Sie nicht manuell ausführen können. Sie können also Ihre 10 Lieblingsabfragen auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Bedenken Sie, dass die Tools, die erwarten, die gesamte Datenbank mit dem regulären Google-Browser auszuführen, niemals enden werden, da Google Sie sehr schnell blockieren wird._

### **Auf der Suche nach Schwachstellen**

Wenn Sie **gültige geleakte** Anmeldeinformationen oder API-Token finden, ist das ein sehr einfacher Gewinn.

## Öffentliche Code-Schwachstellen

Wenn Sie festgestellt haben, dass das Unternehmen **Open-Source-Code** hat, können Sie ihn **analysieren** und nach **Schwachstellen** suchen.

**Je nach Sprache** gibt es verschiedene **Tools**, die Sie verwenden können:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Es gibt auch kostenlose Dienste, die es Ihnen ermöglichen, **öffentliche Repositories zu scannen**, wie:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **Mehrheit der Schwachstellen**, die von Bug-Huntern gefunden werden, befindet sich in **Webanwendungen**, daher möchte ich an dieser Stelle über eine **Testmethodik für Webanwendungen** sprechen, und Sie können [**diese Informationen hier finden**](../../network-services-pentesting/pentesting-web/index.html).

Ich möchte auch einen besonderen Hinweis auf den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) geben, da, auch wenn Sie nicht erwarten sollten, dass sie sehr sensible Schwachstellen finden, sie nützlich sind, um sie in **Workflows zu implementieren, um einige erste Webinformationen zu erhalten.**

## Rekapitulation

> Herzlichen Glückwunsch! An diesem Punkt haben Sie bereits **alle grundlegenden Enumeration** durchgeführt. Ja, es ist grundlegend, weil viel mehr Enumeration durchgeführt werden kann (wir werden später mehr Tricks sehen).

Also haben Sie bereits:

1. Alle **Unternehmen** im Geltungsbereich gefunden
2. Alle **Assets** gefunden, die zu den Unternehmen gehören (und einige Schwachstellenscans durchgeführt, wenn im Geltungsbereich)
3. Alle **Domains** gefunden, die zu den Unternehmen gehören
4. Alle **Subdomains** der Domains gefunden (gibt es eine Subdomain-Übernahme?)
5. Alle **IPs** (von und **nicht von CDNs**) im Geltungsbereich gefunden.
6. Alle **Webserver** gefunden und einen **Screenshot** davon gemacht (gibt es etwas Seltsames, das einen genaueren Blick wert ist?)
7. Alle **potenziellen öffentlichen Cloud-Ressourcen** gefunden, die zu dem Unternehmen gehören.
8. **E-Mails**, **Credential Leaks** und **Secret Leaks**, die Ihnen einen **großen Gewinn sehr einfach** bringen könnten.
9. **Pentesting aller Webseiten, die Sie gefunden haben**

## **Vollständige Recon Automatische Tools**

Es gibt mehrere Tools, die Teile der vorgeschlagenen Aktionen gegen einen bestimmten Geltungsbereich durchführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ein wenig alt und nicht aktualisiert

## **Referenzen**

- Alle kostenlosen Kurse von [**@Jhaddix**](https://twitter.com/Jhaddix) wie [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
