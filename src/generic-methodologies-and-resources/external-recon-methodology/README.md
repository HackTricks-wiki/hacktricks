# Externe Recon-Methodologie

{{#include ../../banners/hacktricks-training.md}}

## Assets-Ermittlungen

> Dir wurde gesagt, dass alles, was zu einer Firma gehört, im Scope ist, und du willst herausfinden, was diese Firma tatsächlich besitzt.

Das Ziel dieser Phase ist es, alle **vom Hauptunternehmen gehaltenen Firmen** und anschließend alle **Assets** dieser Firmen zu erlangen. Dazu werden wir:

1. Die Akquisitionen des Hauptunternehmens finden — das gibt uns die Firmen, die im Scope liegen.
2. Für jede Firma das **ASN** (falls vorhanden) finden — das liefert die von der Firma gehaltenen **IP ranges**.
3. Reverse whois lookups verwenden, um nach weiteren Einträgen (Organisationsnamen, Domains...) zu suchen, die mit der ersten in Verbindung stehen (dies kann rekursiv erfolgen).
4. Andere Techniken verwenden, wie shodan `org`and `ssl`filters, um nach weiteren Assets zu suchen (der `ssl`-Trick kann rekursiv angewendet werden).

### **Acquisitions**

Zuerst müssen wir wissen, welche **anderen companies vom Hauptunternehmen gehalten werden**.\
Eine Möglichkeit ist, [https://www.crunchbase.com/](https://www.crunchbase.com/), das **main company** zu **search** und auf "**acquisitions**" zu **clicken**. Dort siehst du andere Firmen, die vom Hauptunternehmen acquired wurden.\
Eine andere Option ist, die **Wikipedia**-Seite des Hauptunternehmens zu besuchen und nach **acquisitions** zu suchen.\
Bei börsennotierten Unternehmen überprüfe **SEC/EDGAR filings**, **investor relations**-Seiten oder lokale Firmenregister (z. B. **Companies House** im UK).\
Für globale Konzernstrukturen und Tochtergesellschaften probiere **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, an diesem Punkt solltest du alle companies im Scope kennen. Lass uns herausfinden, wie wir deren assets finden.

### **ASNs**

Eine autonomous system number (**ASN**) ist eine **einzigartige Nummer**, die einem **autonomous system** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus Blöcken von **IP addresses**, die eine klar definierte Richtlinie für den Zugriff auf externe Netzwerke haben und von einer einzelnen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant herauszufinden, ob die **company ein ASN zugewiesen bekommen hat**, um ihre **IP ranges** zu finden. Es lohnt sich, einen **vulnerability test** gegen alle **hosts** im **scope** durchzuführen und nach **domains** in diesen IPs zu suchen.\
Du kannst nach Firmennamen, nach **IP** oder nach **domain** auf [**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) oder [**https://ipinfo.io/**](https://ipinfo.io/) **searchen**.\
**Je nach Region des Unternehmens können diese Links nützlich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Wahrscheinlich sind ohnehin bereits alle** nützlichen Informationen **(IP-Bereiche und Whois)** im ersten Link zu finden.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration aggregiert und fasst ASNs automatisch am Ende des Scans zusammen.
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
Du kannst die IP und ASN einer Domain mit [http://ipv4info.com/](http://ipv4info.com) herausfinden.

### **Nach Schwachstellen suchen**

An diesem Punkt kennen wir **all the assets inside the scope**, daher kannst du, falls erlaubt, einige **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) über alle Hosts laufen lassen.\
Außerdem könntest du einige [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) starten **oder Dienste wie** Shodan, Censys oder ZoomEye **verwenden, um** offene Ports zu finden, **und je nachdem, was du findest, solltest du** in diesem Buch nachlesen, wie man verschiedene laufende Services pentestet.\
**Außerdem kann es sinnvoll sein zu erwähnen, dass du auch einige** default username **und** passwords **lists vorbereiten und versuchen kannst, Dienste mit** bruteforce **anzugreifen, z. B. mit** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Wir kennen alle Firmen inside the scope und deren Assets, jetzt ist es Zeit, die Domains inside the scope zu finden.

_Bitte beachte, dass du mit den folgenden vorgeschlagenen Techniken auch Subdomains finden kannst und diese Informationen nicht unterschätzt werden sollten._

Zuerst solltest du nach der/dem **Hauptdomain(en)** jeder Firma suchen. Zum Beispiel ist für _Tesla Inc._ die _tesla.com_.

### **Reverse DNS**

Sobald du alle IP-Bereiche der Domains gefunden hast, kannst du versuchen, **reverse dns lookups** auf diesen **IPs durchzuführen, um mehr Domains inside the scope zu finden**. Versuche, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit das funktioniert, muss der Administrator den PTR manuell aktivieren.\
Sie können auch ein Online-Tool für diese Informationen verwenden: [http://ptrarchive.com/](http://ptrarchive.com).\
Für große Bereiche sind Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx) nützlich, um reverse lookups und Datenanreicherung zu automatisieren.

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
You can use online tools like:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Kostenlos** Web, kostenpflichtige API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nicht kostenlos
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Suchanfragen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos
- [https://securitytrails.com/](https://securitytrails.com/) - Nicht kostenlos (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nicht kostenlos (API)

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(benötigt einen whoxy API-Schlüssel).\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Beachten Sie, dass Sie diese Technik nutzen können, um jedes Mal, wenn Sie eine neue Domain finden, weitere Domainnamen zu entdecken.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.

Es gibt einige Seiten und Tools, mit denen Sie nach diesen Trackern und mehr suchen können:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Wussten Sie, dass wir verwandte Domains und Subdomains unseres Ziels finden können, indem wir nach demselben favicon-Hash suchen? Genau das macht das Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) von [@m4ll0k2](https://twitter.com/m4ll0k2). Here’s how to use it:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kurz gesagt ermöglicht uns favihash, Domains zu entdecken, die denselben favicon icon hash wie unser Ziel haben.

Außerdem kannst du Technologien anhand des favicon hash durchsuchen, wie in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erklärt. Das bedeutet, dass wenn du den **hash of the favicon of a vulnerable version of a web tech** kennst, du damit in shodan suchen und **find more vulnerable places** kannst:
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
Man kann Favicon-Hashes auch großflächig mit [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) abrufen und anschließend in Shodan/Censys pivoten.

### **Copyright / Eindeutige Zeichenfolge**

Suche auf den Webseiten nach **Strings, die zwischen verschiedenen Sites derselben Organisation geteilt werden könnten**. Der **Copyright-String** könnte ein gutes Beispiel sein. Suche dann nach dieser Zeichenfolge in **google**, in anderen **Browsern** oder sogar in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es ist üblich, einen cron job wie folgt zu haben:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
um alle Domain-Zertifikate auf dem Server zu erneuern. Das bedeutet, dass selbst wenn die dafür verwendete CA die Erstellungszeit nicht im Validity-Feld setzt, es möglich ist, **Domains derselben Firma in den certificate transparency logs zu finden**.\
Siehe dieses [**Writeup für weitere Informationen**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC-Informationen

Du kannst eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen teilen**.\
Weitere nützliche Tools sind [**spoofcheck**](https://github.com/BishopFox/spoofcheck) und [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Anscheinend ist es üblich, dass Leute Subdomains IPs zuweisen, die zu Cloud-Providern gehören, und irgendwann **die IP-Adresse verlieren, aber vergessen, den DNS-Eintrag zu entfernen**. Daher kannst du durch einfaches **Starten einer VM** in einer Cloud (wie Digital Ocean) tatsächlich einige Subdomains **übernehmen**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) erklärt eine Geschichte dazu und schlägt ein Script vor, das **eine VM in DigitalOcean startet**, die **IPv4** der neuen Maschine **ermittelt** und **in Virustotal nach Subdomain-Einträgen** sucht, die auf diese IP zeigen.

### **Other ways**

**Beachte, dass du diese Technik nutzen kannst, um bei jeder neuen gefundenen Domain weitere Domainnamen zu entdecken.**

**Shodan**

Da du bereits den Namen der Organisation kennst, die den IP-Bereich besitzt, kannst du in shodan danach suchen mit: `org:"Tesla, Inc."` Überprüfe die gefundenen Hosts auf neue unerwartete Domains im TLS certificate.

Du könntest das **TLS-Zertifikat** der Hauptwebseite abrufen, den **Organisationsnamen** extrahieren und dann nach diesem Namen in den **TLS-Zertifikaten** aller Webseiten suchen, die **shodan** kennt, mit dem Filter: `ssl:"Tesla Motors"` oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) verwenden.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ist ein Tool, das nach **zugehörigen Domains** einer Hauptdomain und deren **Subdomains** sucht — ziemlich beeindruckend.

**Passive DNS / Historical DNS**

Passive DNS-Daten eignen sich hervorragend, um **alte und vergessene Einträge** zu finden, die noch auflösen oder die übernommen werden können. Schau dir an:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Prüfe auf [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht verwendet ein Unternehmen eine Domain, hat aber **die Inhaberschaft verloren**. Registriere sie einfach (wenn sie günstig ist) und informiere das Unternehmen.

Wenn du eine **Domain mit einer anderen IP** findest als die, die du bereits bei der Asset-Ermittlung gefunden hast, solltest du einen **grundlegenden Vulnerability-Scan** (z. B. mit Nessus oder OpenVAS) sowie einige [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nach laufenden Services findest du in **diesem Buch einige Tricks, um sie zu "attacken"**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

Es ist Zeit, alle möglichen Subdomains jeder gefundenen Domain zu finden.

> [!TIP]
> Beachte, dass einige der Tools und Techniken zum Finden von Domains auch dabei helfen können, Subdomains zu finden

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Records zu erhalten. Wir sollten außerdem einen **Zone Transfer** versuchen (wenn verwundbar, solltest du es melden).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Der schnellste Weg, viele subdomains zu erhalten, ist die Suche in externen Quellen. Die am häufigsten verwendeten **tools** sind die folgenden (für bessere Ergebnisse API keys konfigurieren):

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
Es gibt **weitere interessante Tools/APIs**, die zwar nicht direkt auf das Auffinden von subdomains spezialisiert sind, aber nützlich sein können, um subdomains zu finden, wie:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Verwendet die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um subdomains zu erhalten
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
- [**gau**](https://github.com/lc/gau)**:** ruft bekannte URLs von AlienVault's Open Threat Exchange, der Wayback Machine und Common Crawl für eine beliebige Domain ab.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Sie durchsuchen das Web nach JS files und extrahieren daraus subdomains.
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
- [**Censys Subdomain-Suche**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) hat eine kostenlose API, um nach subdomains und IP-History zu suchen
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle subdomains related to bug-bounty programs**. Auf diese Daten kann man auch mit [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder sogar den Scope, den dieses Projekt verwendet, einsehen: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Einen **Vergleich** vieler dieser Tools finden Sie hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen brute-forcing betreiben.

Für diese Aktion benötigen Sie einige **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Und außerdem IPs guter DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erzeugen, können Sie die Resolver von [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) herunterladen und [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) verwenden, um sie zu filtern. Oder Sie können folgende Liste verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die am meisten empfohlenen Tools für DNS brute-force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das effektives DNS brute-force durchgeführt hat. Es ist sehr schnell, allerdings anfällig für false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Dieses hier verwendet, denke ich, nur einen Resolver.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, der es ermöglicht, gültige Subdomains mittels aktivem bruteforce zu ermitteln und Subdomains mit Wildcard-Handling aufzulösen sowie einfache Input-Output-Unterstützung bietet.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet ebenfalls `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron per brute force zu finden.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS-Brute-Force-Runde

Nach dem Auffinden von Subdomains mithilfe öffentlicher Quellen und brute-forcing kannst du Änderungen der gefundenen Subdomains erzeugen, um noch mehr zu finden. Mehrere Tools sind hierfür nützlich:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Erzeugt Permutationen aus Domains und Subdomains.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Erzeugt Permutationen für gegebene domains und subdomains.
- Du kannst die goaltdns permutations **wordlist** in [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bekommen.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Erzeugt Permutationen aus den angegebenen Domains und Subdomains. Wenn keine Permutationsdatei angegeben ist, verwendet gotator eine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Abgesehen davon, dass es subdomains permutations generiert, kann es auch versuchen, diese aufzulösen (aber es ist besser, die zuvor genannten Tools zu verwenden).
- Die altdns permutations **wordlist** erhalten Sie [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool, um permutations, mutations und alteration von subdomains durchzuführen. Dieses Tool wird das Ergebnis brute force (es unterstützt kein dns wild card).
- Du kannst die dmut permutations wordlist [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) herunterladen.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer domain generiert es neue potenzielle subdomains-Namen anhand angegebener Muster, um weitere subdomains zu entdecken.

#### Intelligente Permutationsgenerierung

- [**regulator**](https://github.com/cramppet/regulator): Für mehr Infos lies diesen [**post**](https://cramppet.github.io/regulator/index.html), aber im Grunde extrahiert es die **Hauptteile** aus den **entdeckten subdomains** und mischt sie, um weitere subdomains zu finden.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, gekoppelt an einen äußerst einfachen, aber effektiven DNS-antwortgesteuerten Algorithmus. Er nutzt einen bereitgestellten Satz von Input-Daten, wie eine maßgeschneiderte wordlist oder historische DNS/TLS records, um weitere entsprechende Domainnamen präzise zu synthetisieren und diese in einer Schleife basierend auf während des DNS-Scans gesammelten Informationen weiter auszudehnen.
```
echo www | subzuf facebook.com
```
### **Workflow zur Subdomain-Erkennung**

Siehe diesen Blogeintrag, den ich geschrieben habe, über die Automatisierung der Subdomain-Erkennung für eine Domain mit Trickest workflows, damit ich nicht manuell viele Tools auf meinem Rechner starten muss:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Wenn Sie eine IP-Adresse gefunden haben, die eine oder mehrere Webseiten enthält, die zu Subdomains gehören, können Sie versuchen, weitere Subdomains mit Webseiten auf dieser IP zu finden, indem Sie in OSINT-Quellen nach Domains auf dieser IP suchen oder indem Sie VHost-Domainnamen auf dieser IP brute-forcen.

#### OSINT

Sie können einige VHosts, die auf einer IP liegen, mit [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder anderen APIs** finden.

**Brute Force**

Wenn Sie vermuten, dass eine Subdomain auf einem Webserver versteckt ist, könnten Sie versuchen, sie zu brute-forcen:
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

Manchmal findest du Seiten, die den Header _**Access-Control-Allow-Origin**_ nur zurückgeben, wenn im Header _**Origin**_ eine gültige domain/subdomain gesetzt ist. In solchen Fällen kannst du dieses Verhalten ausnutzen, um neue **subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Während du nach **subdomains** suchst, achte darauf, ob diese auf irgendeine Art von **bucket** zeigen, und falls ja [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Da du zu diesem Zeitpunkt alle Domains im Scope kennst, versuche außerdem [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Überwachung**

Du kannst **überwachen**, ob **new subdomains** einer Domain erstellt werden, indem du die **Certificate Transparency** Logs überwachst, wie es [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) tut.

### **Looking for vulnerabilities**

Prüfe mögliche [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **subdomain** auf ein **S3 bucket** zeigt, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn du eine **subdomain with an IP different** findest als die, die du bereits bei der Asset-Discovery gefunden hast, solltest du einen **basic vulnerability scan** (mit Nessus oder OpenVAS) und einige [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nach laufenden Diensten findest du in **this book some tricks to "attack" them**.\
_Hinweis: Manchmal ist die Subdomain in einer IP gehostet, die nicht vom Kunden kontrolliert wird, daher ist sie nicht im Scope — sei vorsichtig._

## IPs

In den ersten Schritten hast du möglicherweise **some IP ranges, domains and subdomains** gefunden.\
Es ist Zeit, **recollect all the IPs from those ranges** und für die **domains/subdomains (DNS queries).**

Unter Verwendung der folgenden kostenlosen **free apis** kannst du auch **previous IPs used by domains and subdomains** finden. Diese IPs könnten noch dem Kunden gehören (und könnten es dir ermöglichen, [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Du kannst auch Domains, die auf eine spezifische IP zeigen, mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) überprüfen.

### **Looking for vulnerabilities**

Führe einen Port-Scan auf alle IPs durch, die nicht zu CDNs gehören (dort wirst du höchstwahrscheinlich nichts Interessantes finden). In den entdeckten laufenden Services könntest du **vulnerabilities** finden.

Finde einen [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Wir haben alle Firmen und deren Assets gefunden und kennen IP ranges, domains und subdomains innerhalb des Scope. Es ist Zeit, nach web servers zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits etwas **recon of the IPs and domains discovered** durchgeführt, daher hast du möglicherweise **already found all the possible web servers**. Falls nicht, sehen wir uns jetzt einige schnelle Tricks an, um web servers innerhalb des Scope zu finden.

Beachte bitte, dass dies auf die Entdeckung von web apps ausgerichtet ist, daher solltest du auch **vulnerability** und **port scanning** durchführen (**falls im Scope erlaubt**).

Eine **fast method** um **ports open** im Zusammenhang mit **web** servers zu entdecken, using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres nützliches Tool, um nach web servers zu suchen, ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste von domains und es versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich kannst du angeben, andere Ports zu testen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Jetzt, da du **alle Webserver** im Scope entdeckt hast (unter den **IPs** des Unternehmens sowie allen **Domains** und **Subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es einfach: Fang damit an, von allen Screenshots zu machen. Schon ein **Blick** auf die **Hauptseite** kann **merkwürdige** Endpunkte offenbaren, die eher **anfällig** sein könnten.

Um die vorgeschlagene Idee umzusetzen, kannst du [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Außerdem könntest du dann [**eyeballer**](https://github.com/BishopFox/eyeballer) verwenden, um alle **Screenshots** durchzugehen und dir zu sagen, **was wahrscheinlich Schwachstellen enthält** und was nicht.

## Öffentliche Cloud-Assets

Um potenzielle Cloud-Assets zu finden, die zu einer Firma gehören, solltest du **mit einer Liste von Keywords beginnen, die diese Firma identifizieren**. Für ein Krypto-Unternehmen könntest du z. B. Wörter wie: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names"> verwenden.

Du benötigst außerdem Wortlisten mit **häufig verwendeten Wörtern in Buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Anschließend solltest du mit diesen Wörtern **Permutationen** erzeugen (siehe die [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) für mehr Infos).

Mit den resultierenden Wortlisten kannst du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.**

Denk daran, dass du bei der Suche nach Cloud-Assets **nach mehr als nur Buckets in AWS** schauen solltest.

### **Auf Schwachstellen prüfen**

Wenn du Dinge wie **offene Buckets oder exponierte Cloud-Funktionen** findest, solltest du **auf sie zugreifen** und prüfen, was sie dir bieten und ob du sie ausnutzen kannst.

## E‑Mails

Mit den **Domains** und **Subdomains** im Scope hast du im Grunde alles, was du **brauchst, um mit der Suche nach E‑Mails zu beginnen**. Das sind die **APIs** und **Tools**, die für mich am besten funktioniert haben, um die E‑Mails eines Unternehmens zu finden:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Auf Schwachstellen prüfen**

E‑Mails sind später nützlich, um Web-Logins und Auth-Services zu **brute-force**n (z. B. SSH). Außerdem werden sie für **phishings** benötigt. Darüber hinaus liefern diese APIs oft noch mehr **Infos über die Person** hinter der E‑Mail, was für eine Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains**, **Subdomains** und **E‑Mails** kannst du damit beginnen, nach Credentials zu suchen, die in der Vergangenheit zu diesen E‑Mails leaked wurden:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Auf Schwachstellen prüfen**

Wenn du **gültige leaked** Credentials findest, ist das ein sehr einfacher Erfolg.

## Secrets Leaks

Credential Leaks hängen mit Hacks von Firmen zusammen, bei denen **sensible Informationen leaked und verkauft** wurden. Firmen können jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken enthalten sind:

### Github Leaks

Credentials und APIs könnten in den **öffentlichen Repositories** der **Firma** oder der **User**, die für diese GitHub-Firma arbeiten, geleakt worden sein.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** herunterzuladen und automatisiert [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber laufen zu lassen.

**Leakos** kann auch verwendet werden, um **gitleaks** gegen alle als Text übergebenen URLs laufen zu lassen, da manchmal **Webseiten ebenfalls Secrets** enthalten.

#### Github Dorks

Sieh dir auch diese **Seite** für mögliche **github dorks** an, nach denen du in der Organisation suchen könntest:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Manchmal veröffentlichen Angreifer oder Mitarbeiter **Firmeninhalte auf Paste-Seiten**. Das kann sensible Informationen enthalten oder auch nicht, aber es ist sehr interessant, danach zu suchen.\
Du kannst das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 Paste-Seiten zu suchen.

### Google Dorks

Old but gold: google dorks sind immer nützlich, um **offengelegte Informationen, die dort nicht sein sollten**, zu finden. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausend** mögliche Queries enthält, die du nicht manuell abarbeiten kannst. Du kannst dir also deine 10 Favoriten raussuchen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Auf Schwachstellen prüfen**

Wenn du **gültige leaked** Credentials oder API-Tokens findest, ist das ein sehr einfacher Erfolg.

## Öffentliche Code-Schwachstellen

Wenn du feststellst, dass das Unternehmen **Open-Source-Code** hat, kannst du ihn **analysieren** und nach **Schwachstellen** suchen.

**Je nach Programmiersprache** gibt es verschiedene **Tools**, die du verwenden kannst:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Es gibt auch kostenlose Dienste, die erlauben, **öffentliche Repositories** zu scannen, z. B.:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **Mehrheit der Schwachstellen**, die Bug-Hunter finden, liegt in **Webanwendungen**, daher möchte ich an dieser Stelle eine **Methodik zum Testen von Webanwendungen** ansprechen, und du kannst [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

Ich möchte auch einen besonderen Hinweis auf den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) geben, da — auch wenn du nicht erwarten solltest, dass sie sehr sensitive Schwachstellen finden — sie praktisch sind, um sie in **Workflows für erste Web-Informationen** einzubinden.

## Rekapitulation

> Glückwunsch! An diesem Punkt hast du bereits **alle grundlegenden Enumeration** durchgeführt. Ja, das ist grundlegend, denn es lässt sich noch viel mehr enumerieren (wir sehen später noch mehr Tricks).

Du hast bereits:

1. Alle **Companies** im Scope gefunden
2. Alle **Assets** der Companies gefunden (und einige Vuln-Scans durchgeführt, falls im Scope)
3. Alle **Domains** der Companies gefunden
4. Alle **Subdomains** der Domains gefunden (gibt es Subdomain-Takeover?)
5. Alle **IPs** (von und **nicht von CDNs**) im Scope gefunden
6. Alle **Webserver** gefunden und **Screenshots** gemacht (gibt es etwas Merkwürdiges, das einen tieferen Blick wert ist?)
7. Alle **potenziellen öffentlichen Cloud-Assets** des Unternehmens gefunden
8. **E‑Mails**, **Credential Leaks**, und **Secrets Leaks**, die dir sehr leicht einen großen Erfolg bringen können
9. **Pentesting all the webs you found**

## **Vollständige automatische Recon-Tools**

Es gibt mehrere Tools, die Teile der vorgeschlagenen Aktionen gegen einen gegebenen Scope automatisch ausführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Etwas älter und nicht mehr aktualisiert

## **Quellen**

- Alle kostenlosen Kurse von [**@Jhaddix**](https://twitter.com/Jhaddix) wie [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
