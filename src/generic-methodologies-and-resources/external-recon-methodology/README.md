# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets Entdeckungen

> Dir wurde also gesagt, dass alles, was zu einem Unternehmen gehört, im scope ist, und du willst herausfinden, was dieses Unternehmen tatsächlich besitzt.

Ziel dieser Phase ist es, alle **von der Hauptfirma gehaltenen Unternehmen** zu ermitteln und anschließend alle **assets** dieser Unternehmen. Dazu werden wir:

1. Finde die Akquisitionen der Hauptfirma; das gibt uns die Unternehmen, die im scope sind.
2. Ermittele die ASN (falls vorhanden) jeder Firma; das gibt uns die IP ranges, die von jeder Firma gehalten werden.
3. Verwende reverse whois-Abfragen, um nach weiteren Einträgen (Organisationsnamen, domains...) zu suchen, die mit dem ersten zusammenhängen (dies kann rekursiv durchgeführt werden).
4. Verwende andere Techniken wie shodan `org` und `ssl`-Filter, um nach weiteren assets zu suchen (der `ssl` Trick kann rekursiv angewendet werden).

### **Akquisitionen**

Zuerst müssen wir wissen, welche **anderen Unternehmen von der Hauptfirma gehalten werden**.\
Eine Option ist, [https://www.crunchbase.com/](https://www.crunchbase.com), die **Hauptfirma** zu **suchen** und auf "**acquisitions**" zu **klicken**. Dort siehst du weitere Unternehmen, die von der Hauptfirma übernommen wurden.\
Eine andere Möglichkeit ist, die **Wikipedia**-Seite der Hauptfirma zu besuchen und nach **acquisitions** zu suchen.\
Für börsennotierte Unternehmen prüfe **SEC/EDGAR filings**, **investor relations**-Seiten oder lokale Unternehmensregister (z. B. **Companies House** im UK).\
Für globale Unternehmensstrukturen und Tochtergesellschaften versuche **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, an diesem Punkt solltest du alle Unternehmen im scope kennen. Lass uns herausfinden, wie man deren assets findet.

### **ASNs**

Eine autonomous system number (**ASN**) ist eine **eindeutige Nummer**, die einem **autonomen System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, die eine klar definierte Policy für den Zugriff auf externe Netzwerke haben und von einer einzelnen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant herauszufinden, ob das Unternehmen eine ASN zugewiesen bekommen hat, um dessen **IP ranges** zu ermitteln. Es ist sinnvoll, einen **vulnerability test** gegen alle **hosts** im **scope** durchzuführen und nach **domains** innerhalb dieser IPs zu suchen.\
Du kannst **suchen** nach Firmen**name**, nach **IP** oder nach **domain** in [**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) **oder** [**https://ipinfo.io/**](https://ipinfo.io/).\
Je nach Region des Unternehmens könnten diese Links nützlich sein, um weitere Daten zu sammeln: [**AFRINIC**](https://www.afrinic.net) (Africa), [**Arin**](https://www.arin.net/about/welcome/region/) (North America), [**APNIC**](https://www.apnic.net) (Asia), [**LACNIC**](https://www.lacnic.net) (Latin America), [**RIPE NCC**](https://www.ripe.net) (Europe). Anyway, wahrscheinlich sind ohnehin bereits alle **nützlichen Informationen** (IP ranges und Whois) im ersten Link enthalten.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Außerdem aggregiert und fasst [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration automatisch ASNs am Ende des Scans zusammen.
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
Du kannst die IP-Bereiche einer Organisation auch mit [http://asnlookup.com/](http://asnlookup.com) finden (es hat eine kostenlose API).\
Du kannst die IP und ASN einer Domain mit [http://ipv4info.com/](http://ipv4info.com) finden.

### **Suche nach Schwachstellen**

An diesem Punkt kennen wir **alle Assets im Scope**, daher könntest du, sofern erlaubt, über alle Hosts einige **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) laufen lassen.\
Außerdem könntest du einige [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) starten **oder Dienste wie** Shodan, Censys oder ZoomEye **nutzen, um** offene Ports **zu finden und abhängig davon, was du findest, solltest du** in diesem Buch nachschlagen, wie man verschiedene mögliche laufende Services pentestet.\
**Außerdem kann es sinnvoll sein zu erwähnen, dass du einige** Standard-Benutzernamen **und** Passwortlisten **vorbereitest und versuchst,** bruteforce **Dienste mit [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) anzugreifen.**

## Domains

> Wir kennen alle Firmen im Scope und ihre Assets, es ist Zeit, die Domains im Scope zu finden.

_Please, beachte, dass du mit den folgenden vorgeschlagenen Techniken auch Subdomains finden kannst und diese Information nicht unterschätzt werden sollte._

Zuerst solltest du nach der **main domain**(s) jeder Firma suchen. Zum Beispiel ist für _Tesla Inc._ die _tesla.com_.

### **Reverse DNS**

Da du alle IP-Bereiche der Domains gefunden hast, könntest du versuchen, **reverse dns lookups** auf diesen **IPs durchzuführen, um weitere Domains im Scope zu finden**. Versuche, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit das funktioniert, muss der Administrator den PTR manuell aktivieren.\
Sie können auch ein Online-Tool für diese Informationen verwenden: [http://ptrarchive.com/](http://ptrarchive.com).\
Für große Bereiche sind Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx) nützlich, um Reverse-Lookups und Anreicherung zu automatisieren.

### **Reverse Whois (loop)**

Innerhalb eines **whois** finden Sie viele interessante **Informationen** wie **Organisationsname**, **Adresse**, **E-Mails**, Telefonnummern... Noch interessanter ist, dass Sie **mehr Assets, die mit dem Unternehmen zusammenhängen**, finden können, wenn Sie **reverse whois lookups by any of those fields** durchführen (zum Beispiel andere whois-Registries, in denen dieselbe E-Mail erscheint).\
Sie können Online-Tools verwenden wie:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Kostenlos** web, API nicht kostenlos.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht kostenlos
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenfreie** Suchen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos
- [https://securitytrails.com/](https://securitytrails.com/) - Nicht kostenlos (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nicht kostenlos (API)

Sie können diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (erfordert einen whoxy API-Schlüssel).\
Sie können auch eine automatische reverse whois discovery mit [amass](https://github.com/OWASP/Amass) durchführen: `amass intel -d tesla.com -whois`

**Beachte, dass Sie diese Technik verwenden können, um jedes Mal, wenn Sie eine neue Domain finden, weitere Domainnamen zu entdecken.**

### **Trackers**

Wenn Sie die **gleiche ID desselben Trackers** auf 2 verschiedenen Seiten finden, können Sie davon ausgehen, dass **beide Seiten** vom **gleichen Team** verwaltet werden.\
Zum Beispiel, wenn Sie dieselbe **Google Analytics ID** oder dieselbe **Adsense ID** auf mehreren Seiten sehen.

Es gibt einige Seiten und Tools, mit denen Sie nach diesen Trackern und mehr suchen können:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (findet verwandte Seiten durch geteilte Analytics/Tracker)

### **Favicon**

Wussten Sie, dass wir verwandte Domains und Subdomains zu unserem Ziel finden können, indem wir nach demselben favicon-Hash suchen? Genau das macht das Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) von [@m4ll0k2](https://twitter.com/m4ll0k2). So verwenden Sie es:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt, favihash ermöglicht es uns, Domains zu entdecken, die denselben favicon icon hash wie unser target haben.

Außerdem kannst du Technologien mithilfe des favicon hash durchsuchen, wie in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erläutert. Das bedeutet, dass, wenn du den **hash of the favicon of a vulnerable version of a web tech** kennst, du in shodan danach suchen und **find more vulnerable places**.
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
So können Sie den **favicon hash** einer Website berechnen:
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
Du kannst Favicon-Hashes auch in großem Umfang mit [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) erhalten und dann in Shodan/Censys pivoten.

### **Copyright / Einzigartige Zeichenfolge**

Durchsuche die Webseiten nach Zeichenfolgen, die über verschiedene Websites derselben Organisation hinweg geteilt werden könnten. Die Copyright-Zeichenfolge könnte ein gutes Beispiel sein. Suche dann nach dieser Zeichenfolge in Google, in anderen Browsern oder sogar in Shodan: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es ist üblich, einen cron job wie zum Beispiel zu haben
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
um alle Domain-Zertifikate auf dem Server zu erneuern. Das bedeutet, dass selbst wenn die CA dafür die Erstellungszeit nicht im Validity-Feld setzt, es möglich ist, **Domains derselben Firma in den certificate transparency logs zu finden**.\
Siehe dieses [**writeup für mehr Informationen**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-Informationen

Du kannst eine Webseite wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen teilen**.\
Andere nützliche Tools sind [**spoofcheck**](https://github.com/BishopFox/spoofcheck) und [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Anscheinend ist es üblich, dass Leute Subdomains IPs zuweisen, die Cloud-Providern gehören, und irgendwann **diese IP-Adresse verlieren, aber vergessen, den DNS-Eintrag zu entfernen**. Daher kannst du durch einfaches **spawning a VM** in einer Cloud (like Digital Ocean) tatsächlich **einige Subdomains übernehmen**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) erklärt eine Geschichte dazu und schlägt ein Skript vor, das **spawns a VM in DigitalOcean**, **gets** die **IPv4** der neuen Maschine und **searches in Virustotal for subdomain records**, die darauf zeigen.

### **Andere Wege**

**Beachte, dass du diese Technik verwenden kannst, um jedes Mal, wenn du eine neue Domain findest, weitere Domainnamen zu entdecken.**

**Shodan**

Da du bereits den Namen der Organisation kennst, die den IP-Space besitzt, kannst du danach in shodan suchen mit: `org:"Tesla, Inc."` Prüfe die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Du könntest das **TLS certificate** der Hauptwebseite auslesen, den **Organisationsnamen** erhalten und dann nach diesem Namen in den **TLS certificates** aller von **shodan** bekannten Webseiten suchen mit dem Filter: `ssl:"Tesla Motors"` oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) verwenden.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **Domains** im Zusammenhang mit einer Hauptdomain und deren **Subdomains** sucht — ziemlich beeindruckend.

**Passive DNS / Historical DNS**

Passive DNS-Daten sind großartig, um **alte und vergessene Einträge** zu finden, die noch auflösen oder die übernommen werden können. Schau dir an:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Überprüfe auf [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht verwendet eine Firma eine Domain, hat aber **den Besitz verloren**. Registriere sie einfach (wenn günstig genug) und informiere die Firma.

Wenn du eine **Domain mit einer IP entdeckst, die sich von denen unterscheidet**, die du bereits bei der Asset-Discovery gefunden hast, solltest du einen **grundlegenden Vulnerability-Scan** (mit Nessus oder OpenVAS) sowie einige [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Abhängig davon, welche Dienste laufen, findest du in **diesem Buch einige Tricks, um sie "anzugreifen"**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> Wir kennen alle Unternehmen inside the scope, alle Assets jedes Unternehmens und alle Domains related to the companies.

> [!TIP]
> Beachte, dass einige der Tools und Techniken zum Finden von Domains auch helfen können, Subdomains zu finden

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Einträgen zu erhalten. Wir sollten auch einen **Zone Transfer** versuchen (Wenn verwundbar, solltest du es melden).
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
Es gibt **andere interessante Tools/APIs**, die, auch wenn sie nicht direkt auf das Finden von subdomains spezialisiert sind, nützlich sein können, um subdomains zu finden, wie:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um subdomains zu finden
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
- [**gau**](https://github.com/lc/gau)**:** ruft für jede beliebige domain bekannte URLs aus AlienVault's Open Threat Exchange, der Wayback Machine und Common Crawl ab.
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
- [**securitytrails.com**](https://securitytrails.com/) hat eine kostenlose API, um nach subdomains und IP-Historie zu suchen
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle subdomains, die mit bug-bounty programs verbunden sind**. Sie können auf diese Daten auch über [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder sogar den Scope verwenden, den dieses Projekt nutzt [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Sie finden einen **Vergleich** vieler dieser Tools hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **subdomains** zu finden, brute-forcing DNS-Server mit möglichen Subdomain-Namen.

Für diese Aktion benötigen Sie einige **gängige subdomains wordlists wie**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Und außerdem IPs guter DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, können Sie die Resolver von [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) herunterladen und [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) verwenden, um sie zu filtern. Oder Sie könnten: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt) verwenden.

Die am meisten empfohlenen Tools für DNS brute-force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das ein effektives DNS brute-force durchführte. Es ist sehr schnell, allerdings anfällig für false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ich glaube, dieses verwendet nur 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in go, der es ermöglicht, gültige Subdomains mittels aktivem bruteforce zu ermitteln, sowie Subdomains mit Wildcard-Handling aufzulösen und einfache Ein-/Ausgabe-Unterstützung bereitzustellen.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet auch `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron zu brute-forcen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS Brute-Force-Runde

Nachdem Sie Subdomains mithilfe öffentlicher Quellen und brute-forcing gefunden haben, können Sie Abwandlungen der gefundenen Subdomains erzeugen, um noch mehr zu finden. Mehrere Tools sind für diesen Zweck nützlich:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Erzeugt aus Domains und Subdomains Permutationen.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Generiert Permutationen aus Domains und Subdomains.
- Die goaltdns-Permutationen **wordlist** findest du [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Erzeugt Permutationen aus den angegebenen domains und subdomains. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Abgesehen vom Generieren von Subdomain-Permutationen kann es diese auch auflösen (aber es ist besser, die zuvor genannten Tools zu verwenden).
- Du kannst die altdns-Permutationen **wordlist** in [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) erhalten.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool, um Permutationen, Mutationen und Änderungen an Subdomains durchzuführen. Dieses Tool wird das Ergebnis brute force prüfen (es unterstützt kein dns wild card).
- Sie können die dmut permutations wordlist [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) erhalten.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer domain generiert es **neue potenzielle subdomains-Namen** anhand angegebener Muster, um weitere subdomains zu entdecken.

#### Intelligente Permutationsgenerierung

- [**regulator**](https://github.com/cramppet/regulator): Für mehr Infos lies diesen [**post**](https://cramppet.github.io/regulator/index.html) aber es extrahiert im Wesentlichen die **Hauptteile** der **entdeckten subdomains** und mischt sie, um mehr subdomains zu finden.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein subdomain brute-force fuzzer, gekoppelt mit einem immensly einfachen, aber effektiven DNS reponse-guided algorithm. Es verwendet einen bereitgestellten Satz von Eingabedaten, wie eine maßgeschneiderte wordlist oder historische DNS/TLS records, um präzise weitere korrespondierende domain names zu synthetisieren und diese in einer Schleife basierend auf während des DNS scan gesammelten Informationen noch weiter zu erweitern.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Schau dir diesen Blogpost an, den ich geschrieben habe, darüber, wie man **automate the subdomain discovery** von einer Domain mit **Trickest workflows**, damit ich nicht manuell eine Reihe von Tools auf meinem Rechner starten muss:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Wenn du eine IP-Adresse gefunden hast, die **one or several web pages** enthält, die zu Subdomains gehören, könntest du versuchen, **find other subdomains with webs in that IP** — entweder indem du in **OSINT sources** nach Domains in einer IP suchst oder indem du **brute-forcing VHost domain names in that IP** betreibst.

#### OSINT

Du kannst einige **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs** finden.

**Brute Force**

Wenn du vermutest, dass eine Subdomain in einem Webserver verborgen sein könnte, könntest du versuchen, sie zu brute force:

Wenn die **IP redirects to a hostname** (name-based vhosts), fuzz den `Host`-Header direkt und lass ffuf **auto-calibrate** um Antworten hervorzuheben, die sich vom default vhost unterscheiden:
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
> Mit dieser Technik kannst du möglicherweise sogar auf internal/hidden endpoints zugreifen.

### **CORS Brute Force**

Manchmal stößt du auf Seiten, die den Header _**Access-Control-Allow-Origin**_ nur zurückgeben, wenn im _**Origin**_-Header eine gültige domain/subdomain gesetzt ist. In solchen Szenarien kannst du dieses Verhalten ausnutzen, um neue **subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

While looking for **subdomains** keep an eye to see if it is **pointing** to any type of **bucket**, and in that case [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Also, as at this point you will know all the domains inside the scope, try to [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Du kannst **monitor**, ob **new subdomains** einer Domain erstellt werden, indem du die **Certificate Transparency** Logs beobachtest — so wie es [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) tut.

### **Looking for vulnerabilities**

Prüfe auf mögliche [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **subdomain** auf ein **S3 bucket** zeigt, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn du eine **subdomain with an IP different** findest als die, die du bereits bei der assets discovery entdeckt hast, solltest du einen **basic vulnerability scan** (mit Nessus oder OpenVAS) durchführen und einige [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan**. Abhängig von den laufenden Services kannst du in **this book some tricks to "attack" them** finden.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

In den ersten Schritten hast du möglicherweise **einige IP-Ranges, Domains und subdomains** gefunden.\
Es ist Zeit, **alle IPs aus diesen Ranges zusammenzutragen** und für die **domains/subdomains (DNS queries).**

Using services from the following **free apis** you can also find **previous IPs used by domains and subdomains**. These IPs might still be owned by the client (and might allow you to find [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Du kannst auch Domains prüfen, die auf eine bestimmte IP zeigen, mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (da du dort sehr wahrscheinlich nichts Interessantes finden wirst). Bei den entdeckten laufenden Services könntest du **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Wir haben alle Unternehmen und deren Assets gefunden und kennen IP-Ranges, Domains und subdomains im Scope. Es ist Zeit, nach Webservern zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits etwas **recon of the IPs and domains discovered** durchgeführt, daher hast du möglicherweise **already found all the possible web servers**. Falls nicht, sehen wir uns jetzt einige **fast tricks to search for web servers** im Scope an.

Bitte beachte, dass dies auf die Entdeckung von Web-Apps ausgerichtet ist, daher solltest du auch **vulnerability**- und **port scanning** durchführen (**wenn im Scope erlaubt**).

Eine **schnelle Methode**, um offene **ports** im Zusammenhang mit **web**-Servern zu entdecken, using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres hilfreiches Tool, um nach Webservern zu suchen, ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste von Domains und es versucht, sich zu Port 80 (http) und 443 (https) zu verbinden. Zusätzlich kannst du angeben, andere Ports zu versuchen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Jetzt, da du alle **web servers** im Scope entdeckt hast (unter den **IPs** des Unternehmens und allen **domains** und **subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es einfach: Fang damit an, von allen Screenshots zu machen. Allein durch einen **Blick** auf die **main page** kannst du **seltsame** Endpoints finden, die eher zu **vulnerable** sind.

Um die vorgeschlagene Idee umzusetzen, kannst du [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Außerdem kannst du dann [**eyeballer**](https://github.com/BishopFox/eyeballer) über alle **screenshots** laufen lassen, um dir zu sagen, **was wahrscheinlich Vulnerabilities enthält**, und was nicht.

## Public Cloud Assets

Um potenzielle cloud assets zu finden, die zu einer Firma gehören, solltest du mit einer Liste von Keywords beginnen, die diese Firma identifizieren. Zum Beispiel: für ein Crypto-Unternehmen könntest du Worte wie: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names"> verwenden.

Du wirst außerdem Wordlists mit **häufig verwendeten Wörtern in buckets** benötigen:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Dann solltest du mit diesen Wörtern **Permutationen** erzeugen (siehe die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) für mehr Infos).

Mit den resultierenden Wordlists kannst du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.**

Denke daran, dass du beim Suchen nach Cloud Assets **mehr als nur buckets in AWS** suchen solltest.

### **Looking for vulnerabilities**

Wenn du Dinge wie **open buckets oder cloud functions exposed** findest, solltest du **access them** und prüfen, was sie dir bieten und ob du sie **abuse** kannst.

## Emails

Mit den **domains** und **subdomains** im Scope hast du im Grunde alles, was du brauchst, um mit der Suche nach **emails** zu beginnen. Das sind die **APIs** und **tools**, die für mich am besten funktioniert haben, um emails eines Unternehmens zu finden:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (freie Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (freie Version)
- API von [**https://minelead.io/**](https://minelead.io/) (freie Version)

### **Looking for vulnerabilities**

Emails sind später nützlich, um **brute-force web logins und auth services** (wie SSH) durchzuführen. Außerdem werden sie für **phishings** benötigt. Zusätzlich liefern dir diese APIs oft noch mehr **Info über die Person** hinter der Email, was für eine Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **domains**, **subdomains** und **emails** kannst du anfangen, nach credentials leaked zu suchen, die in der Vergangenheit zu diesen emails gehörten:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Wenn du **valid leaked** credentials findest, ist das ein sehr einfacher Gewinn.

## Secrets Leaks

Credential leaks hängen mit Hacks von Unternehmen zusammen, bei denen **sensitive information was leaked and sold**. Unternehmen können jedoch auch von **anderen leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken stehen:

### Github Leaks

Credentials und APIs könnten in den **public repositories** des **Unternehmens** oder der **Nutzer**, die für dieses GitHub-Unternehmen arbeiten, geleakt sein.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **public repos** einer **organization** und ihrer **developers** herunterzuladen und automatisch [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber laufen zu lassen.

**Leakos** kann auch verwendet werden, um **gitleaks** gegen alle als Text übergebenen **URLs** laufen zu lassen, da manchmal **web pages** ebenfalls secrets enthalten.

#### Github Dorks

Sieh dir auch diese **page** für potenzielle **github dorks** an, nach denen du in der Organisation, die du angreifst, suchen könntest:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Manchmal veröffentlichen Angreifer oder einfach Angestellte **company content in a paste site**. Das kann sensible Informationen enthalten oder auch nicht, aber es ist sehr interessant, danach zu suchen.\
Du kannst das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 paste sites zu suchen.

### Google Dorks

Old but gold: google dorks sind immer nützlich, um **exposed information that shouldn't be there** zu finden. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **tausend** mögliche Queries enthält, die du nicht manuell ausführen kannst. Du kannst dir deine zehn Favoriten aussuchen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) verwenden, um sie alle auszuführen.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

Wenn du **valid leaked** credentials oder API tokens findest, ist das ein sehr einfacher Gewinn.

## Public Code Vulnerabilities

Wenn du feststellst, dass das Unternehmen **open-source code** hat, kannst du ihn **analysieren** und nach **vulnerabilities** suchen.

Je nach Sprache gibt es verschiedene **tools**, die du verwenden kannst:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Es gibt auch kostenlose Dienste, die es dir erlauben, **public repositories** zu scannen, wie zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **Mehrzahl der vulnerabilities**, die Bug Hunter finden, liegen in **web applications**, daher möchte ich an dieser Stelle eine **Web Application Testing Methodology** ansprechen; du kannst [**diese Informationen hier finden**](../../network-services-pentesting/pentesting-web/index.html).

Ich möchte auch besonders auf den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) hinweisen, da diese zwar nicht unbedingt sehr sensitive vulnerabilities finden, sie sich jedoch gut in **workflows** integrieren lassen, um erste Web-Informationen zu erhalten.

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

Also hast du bereits:

1. Alle **Unternehmen** im Scope gefunden
2. Alle **assets** des Unternehmens gefunden (und einige vuln scans durchgeführt, falls im Scope)
3. Alle **domains** des Unternehmens gefunden
4. Alle **subdomains** der domains gefunden (gibt es Subdomain Takeover?)
5. Alle **IPs** (von und **nicht von CDNs**) im Scope gefunden.
6. Alle **web servers** gefunden und von ihnen einen **screenshot** gemacht (irgendetwas Auffälliges, das einen tieferen Blick wert ist?)
7. Alle möglichen **public cloud assets** des Unternehmens gefunden.
8. **Emails**, **credentials leaks**, und **secret leaks**, die dir sehr leicht einen großen Gewinn bringen könnten.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Es gibt mehrere Tools, die einen Teil der vorgeschlagenen Aktionen gegen einen gegebenen Scope automatisch ausführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Ein wenig alt und nicht aktualisiert

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
