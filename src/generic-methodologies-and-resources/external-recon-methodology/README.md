# Externe Recon-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Entdeckung von Assets

> Dir wurde also gesagt, dass alles, was zu einem Unternehmen gehört, im Scope liegt, und du möchtest herausfinden, was dieses Unternehmen tatsächlich besitzt.

Das Ziel dieser Phase besteht darin, alle **Unternehmen im Besitz des Hauptunternehmens** und anschließend alle **Assets** dieser Unternehmen zu ermitteln. Dazu werden wir:

1. Die Übernahmen des Hauptunternehmens finden; dadurch erhalten wir die Unternehmen innerhalb des Scopes.
2. Die ASN (falls vorhanden) jedes Unternehmens ermitteln; dadurch erhalten wir die IP-Bereiche, die jedem Unternehmen gehören.
3. Reverse-Whois-Lookups verwenden, um nach weiteren Einträgen (Organisationsnamen, Domains ...) zu suchen, die mit dem ersten Eintrag verbunden sind (dies kann rekursiv durchgeführt werden).
4. Andere Techniken wie die Shodan-Filter `org` und `ssl` verwenden, um nach weiteren Assets zu suchen (der `ssl`-Trick kann rekursiv durchgeführt werden).

### **Übernahmen**

Zunächst müssen wir wissen, **welche anderen Unternehmen dem Hauptunternehmen gehören**.\
Eine Möglichkeit besteht darin, [https://www.crunchbase.com/](https://www.crunchbase.com) aufzurufen, nach dem **Hauptunternehmen** zu **suchen** und auf "**acquisitions**" zu **klicken**. Dort werden andere Unternehmen angezeigt, die vom Hauptunternehmen übernommen wurden.\
Eine weitere Möglichkeit besteht darin, die **Wikipedia**-Seite des Hauptunternehmens aufzurufen und nach **Übernahmen** zu suchen.\
Bei börsennotierten Unternehmen solltest du **SEC/EDGAR filings**, die Seiten der **Investor Relations** oder lokale Unternehmensregister (z. B. **Companies House** im Vereinigten Königreich) prüfen.\
Für globale Unternehmensstrukturen und Tochtergesellschaften kannst du **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF-LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)) verwenden.

> Zu diesem Zeitpunkt solltest du alle Unternehmen innerhalb des Scopes kennen. Sehen wir uns an, wie wir ihre Assets finden können.

### **ASNs**

Eine Autonomous System Number (**ASN**) ist eine **eindeutige Nummer**, die von der **Internet Assigned Numbers Authority (IANA)** einem **autonomen System** (AS) zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, für deren Zugriff auf externe Netzwerke eine klar definierte Richtlinie gilt und die von einer einzelnen Organisation verwaltet werden, aber aus mehreren Betreibern bestehen können.

Es ist interessant herauszufinden, ob dem **Unternehmen eine ASN zugewiesen wurde**, um seine **IP-Bereiche** zu ermitteln. Es kann sinnvoll sein, einen **Vulnerability Test** gegen alle **Hosts** innerhalb des **Scopes** durchzuführen und innerhalb dieser IPs nach **Domains** zu suchen.\
Du kannst nach dem **Unternehmensnamen**, einer **IP** oder einer **Domain** in [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **oder** [**https://ipinfo.io/**](https://ipinfo.io/) suchen.\
**Abhängig von der Region des Unternehmens können diese Links nützlich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Wie auch immer, wahrscheinlich erscheinen alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link.
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
Du kannst die IP-Ranges einer Organisation auch über [http://asnlookup.com/](http://asnlookup.com) finden (es verfügt über eine kostenlose API).\
Du kannst die IP und den ASN einer Domain über [http://ipv4info.com/](http://ipv4info.com) finden.

### **Suche nach Schwachstellen**

An diesem Punkt kennen wir **alle Assets innerhalb des Scopes**. Wenn es dir erlaubt ist, könntest du daher einen **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) über alle Hosts starten.\
Außerdem könntest du einige [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) starten **oder Services wie** Shodan, Censys oder ZoomEye **verwenden, um** offene Ports **zu finden. Je nachdem, was du findest, solltest du** in diesem Buch nachsehen, wie man verschiedene möglicherweise laufende Services pentestet.\
**Außerdem sollte erwähnt werden, dass du auch einige** Listen mit Standardbenutzernamen **und** Passwörtern **vorbereiten und versuchen kannst,** Services mit [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) zu **bruteforcen**.

## Domains

> Wir kennen alle Unternehmen innerhalb des Scopes und deren Assets. Nun ist es an der Zeit, die Domains innerhalb des Scopes zu finden.

_Bitte beachte, dass du mit den folgenden vorgeschlagenen Techniken auch Subdomains finden kannst und diese Information nicht unterschätzt werden sollte._

Zuerst solltest du nach der **Hauptdomain** jeder Organisation suchen. Für _Tesla Inc._ wäre dies beispielsweise _tesla.com_.

### **Reverse DNS**

Da du alle IP-Ranges der Domains gefunden hast, könntest du versuchen, **Reverse-DNS-Lookups** für diese **IPs durchzuführen, um weitere Domains innerhalb des Scopes zu finden**. Versuche, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Damit dies funktioniert, muss der Administrator den PTR manuell aktivieren.\
Du kannst für diese Information auch ein Online-Tool verwenden: [http://ptrarchive.com/](http://ptrarchive.com).\
Für große Bereiche sind Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx) nützlich, um Reverse Lookups und die Anreicherung zu automatisieren.

### **Reverse Whois (loop)**

In einem **whois** kannst du viele interessante **Informationen** finden, wie den **Organisationsnamen**, die **Adresse**, **E-Mail-Adressen**, Telefonnummern usw. Noch interessanter ist jedoch, dass du **weitere mit dem Unternehmen verbundene Assets** finden kannst, wenn du **Reverse-Whois-Lookups anhand eines dieser Felder** durchführst (zum Beispiel andere Whois-Registrierungen, bei denen dieselbe E-Mail-Adresse erscheint).\
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

Du kannst diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (erfordert einen whoxy-API-Key).\
Du kannst auch mit [amass](https://github.com/OWASP/Amass) eine automatische Reverse-Whois-Erkennung durchführen: `amass intel -d tesla.com -whois`

**Beachte, dass du diese Technik verwenden kannst, um jedes Mal weitere Domainnamen zu entdecken, wenn du eine neue Domain findest.**

### **Trackers**

Wenn du die **gleiche ID desselben Trackers** auf 2 verschiedenen Seiten findest, kannst du annehmen, dass **beide Seiten** vom **gleichen Team** verwaltet werden.\
Wenn du beispielsweise auf mehreren Seiten dieselbe **Google-Analytics-ID** oder dieselbe **Adsense-ID** siehst.

Es gibt einige Seiten und Tools, mit denen du nach diesen Trackers und weiteren Informationen suchen kannst:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (findet verwandte Websites anhand gemeinsam verwendeter Analytics/Trackers)

### **Favicon**

Wusstest du, dass wir verwandte Domains und Subdomains unseres Ziels finden können, indem wir nach demselben Favicon-Icon-Hash suchen? Genau das macht das von [@m4ll0k2](https://twitter.com/m4ll0k2) entwickelte Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py). So wird es verwendet:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - Domains mit demselben Favicon-Icon-Hash entdecken](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt ermöglicht uns favihash, Domains zu entdecken, die denselben Favicon-Icon-Hash wie unser Ziel haben.

Darüber hinaus kannst du auch nach Technologien suchen, indem du den Favicon-Hash verwendest, wie in [**diesem Blogbeitrag**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) erklärt. Das bedeutet: Wenn du den **Hash des Favicons einer verwundbaren Version einer Webtechnologie** kennst, kannst du in Shodan danach suchen und **weitere verwundbare Stellen finden**:<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
So kannst du den **Favicon-Hash** einer Website berechnen (MMH3 über die **Base64-kodierten** Favicon-Bytes):
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

Useful things to remember when using favicon fingerprints:<sup>[[3]](#references)[[4]](#references)</sup>

- **Behandle den Hash als Indikator, nicht als Beweis**: MMH3 ist kompakt und Kollisionen sind möglich; Betreiber können Favicons außerdem ersetzen oder absichtlich ein irreführendes Icon wiederverwenden.
- **Prüfe mehr als** `/favicon.ico`: Viele Produkte stellen Icons in Framework-/Build-Pfaden oder über `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, eingebettete `data:`-URLs oder HTML-`<link rel="icon">`-Tags bereit. Der Pfad selbst kann eine Produktfamilie fingerprinten.
- **Statische Dateien sind oft erreichbar, wenn die Anwendung es nicht ist**: WAF-/SSO-/IdP-Kontrollen können dynamische Routen schützen, aber statische Icons weiterhin offenlegen. Fordere das Favicon immer direkt an und überprüfe `ETag`, `Last-Modified`, Redirects und Cache-Header auf schwache Versions-/Build-Hinweise.
- **Validiere Treffer mit zusätzlichen Signalen**: Vergleiche Titel, HTML-/Body-Hash, Header, TLS-Zertifikat-Subjects/SANs, Shodan-/Censys-Komponenten und offene Ports, bevor du schlussfolgerst, dass ein Favicon ein Produkt identifiziert.
- **Cluster beim Pivoting im großen Maßstab nach HTML-/Body-Hash**: Wenn die meisten Hosts mit demselben Favicon zu einem Seitentemplate zusammenfallen, ist der Fingerprint aussagekräftiger; wenn derselbe Hash in viele nicht zusammenhängende Templates aufgeteilt wird, verwende lieber „generic/shared/honeypot“ statt einer Produktbezeichnung.
- **Honeypot-Heuristik**: Wenn derselbe Favicon-Hash bei vielen nicht zusammenhängenden HTML-Signaturen, zufälligen Ports und widersprüchlichen Produkten auftaucht, behandle ihn eher als wahrscheinlichen Honeypot oder generischen Platzhalter und nicht als echten Produkt-Fingerprint.
- **Verwende bei mehrdeutigen Zielen einen 404-Probe**: Rufe in einem Browser eine echte Seite und einen nicht vorhandenen Pfad wie `/_favicon_probe_<8-hex>` ab. Übereinstimmende Antworten von Hosting-Providern/Parking-Seiten erklären gemeinsam genutzte Favicons oft besser als eine echte Produktüberschneidung.
- **Leite Mappings aus Detection Rules ab**: Nuclei-Templates und öffentliche Favicon-Datasets können bekannte `favicon` ↔ `product` ↔ `CPE`-Mappings bereitstellen, die nach der Veröffentlichung von CVEs für eine schnelle Triage nützlich sind.
- **Hinweis zur Abdeckung**: Shodan-ähnliche Datensätze sind IP-zentriert. CDN-vorgelagerte, SNI-geroutete, Anycast- und nur über Domains erreichbare Oberflächen können unterrepräsentiert sein. Eine geringe Trefferzahl bedeutet daher **nicht**, dass es in der Praxis nur wenige Deployments gibt.

### **Copyright / Uniq string**

Suche in den Webseiten nach **Strings, die auf verschiedenen Webseiten derselben Organisation gemeinsam vorkommen könnten**. Der **Copyright-String** könnte ein gutes Beispiel sein. Suche anschließend in **Google**, anderen **Browsern** oder sogar in **Shodan** nach diesem String: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es ist üblich, einen Cronjob zu haben wie
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
um alle Domain-Zertifikate auf dem Server zu erneuern. Das bedeutet, dass es möglich ist, **Domains desselben Unternehmens in den Certificate-Transparency-Logs zu finden**, selbst wenn die dafür verwendete CA den Zeitpunkt der Erstellung nicht in der Gültigkeitsdauer festlegt.\
Schau dir dieses [**writeup für weitere Informationen an**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).<sup>[[6]](#references)</sup>

Verwende außerdem direkt **Certificate-Transparency**-Logs:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail-DMARC-Informationen

Du kannst eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen verwenden**.\
Weitere nützliche Tools sind [**spoofcheck**](https://github.com/BishopFox/spoofcheck) und [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Offenbar weisen viele Personen Subdomains IPs zu, die zu Cloud-Anbietern gehören, und **verlieren diese IP-Adresse irgendwann, vergessen aber, den DNS-Eintrag zu entfernen**. Wenn du daher einfach eine **VM** in einer Cloud (wie Digital Ocean) **startest**, wirst du tatsächlich **einige Subdomain(s) übernehmen**.

[**Dieser Beitrag**](https://kmsec.uk/blog/passive-takeover/) erklärt die Geschichte dahinter und schlägt ein Script vor, das eine **VM in DigitalOcean startet**, die **IPv4**-Adresse des neuen Systems **ermittelt** und in Virustotal nach **Subdomain-Einträgen sucht**, die auf diese Adresse zeigen.<sup>[[7]](#references)</sup>

### **Weitere Möglichkeiten**

**Beachte, dass du diese Technik verwenden kannst, um jedes Mal weitere Domainnamen zu entdecken, wenn du eine neue Domain findest.**

**Shodan**

Da du bereits den Namen der Organisation kennst, der der IP-Adressbereich gehört, kannst du in Shodan anhand dieser Daten suchen: `org:"Tesla, Inc."` Überprüfe die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Du kannst auf das **TLS-Zertifikat** der Hauptwebsite zugreifen, den **Organisationsnamen** ermitteln und anschließend innerhalb der **TLS-Zertifikate** aller von **Shodan** bekannten Webseiten nach diesem Namen suchen, und zwar mit dem Filter: `ssl:"Tesla Motors"`, oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) verwenden.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ist ein Tool, das nach **Domains sucht, die mit einer Hauptdomain zusammenhängen**, sowie nach deren **Subdomains** – ziemlich beeindruckend.

**Passive DNS / Historical DNS**

Passive DNS-Daten eignen sich hervorragend, um **alte und vergessene Einträge zu finden**, die noch aufgelöst werden oder übernommen werden können. Siehe:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Suche nach Schwachstellen**

Prüfe auf einen möglichen [Domain Takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht **verwendet ein Unternehmen eine Domain**, hat aber **die Inhaberschaft verloren**. Registriere sie einfach (falls sie günstig genug ist) und informiere das Unternehmen.

Wenn du eine **Domain mit einer anderen IP** als den bereits bei der Asset-Ermittlung gefundenen IPs findest, solltest du einen **grundlegenden Vulnerability Scan** (mit Nessus oder OpenVAS) sowie einen [**Port Scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Services ausgeführt werden, findest du in **diesem Buch einige Tricks, um sie zu „attackieren“**.\
_Beachte, dass die Domain manchmal innerhalb einer IP gehostet wird, die nicht vom Kunden kontrolliert wird. Sie befindet sich daher nicht im Scope. Sei vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen innerhalb des Scopes, alle Assets jedes Unternehmens und alle Domains, die mit den Unternehmen zusammenhängen.

Es ist an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu ermitteln.

> [!TIP]
> Beachte, dass einige Tools und Techniken zum Finden von Domains auch beim Finden von Subdomains helfen können.

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Einträgen zu ermitteln. Wir sollten auch einen **Zone Transfer** versuchen (falls dieser möglich ist, solltest du ihn melden).
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
Es gibt **weitere interessante Tools/APIs**, die zwar nicht direkt auf das Finden von Subdomains spezialisiert sind, aber dennoch nützlich sein könnten, um Subdomains zu finden, wie zum Beispiel:

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
- [**Kostenlose JLDC API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** Ruft bekannte URLs für eine beliebige Domain von AlienVaults Open Threat Exchange, der Wayback Machine und Common Crawl ab.
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
- [**securitytrails.com**](https://securitytrails.com/) bietet eine kostenlose API zur Suche nach subdomains und IP-Historie
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Dieses Projekt bietet **kostenlos alle subdomains im Zusammenhang mit Bug-Bounty-Programmen** an. Auf diese Daten können Sie auch über [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder sogar den von diesem Projekt verwendeten Scope unter [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) einsehen.

Einen **Vergleich** vieler dieser Tools finden Sie hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **subdomains** zu finden, indem wir DNS-Server mit möglichen subdomain-Namen per Brute-Force durchsuchen.

Für diese Aktion benötigen Sie einige **gängige subdomains-Wordlists wie**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Außerdem benötigen Sie IPs guter DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, können Sie die Resolver von [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) herunterladen und mit [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) filtern. Alternativ können Sie [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt) verwenden.

Die am meisten empfohlenen Tools für DNS-Brute-Force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das effektives DNS-Brute-Force durchführte. Es ist sehr schnell, neigt jedoch zu Fehlalarmen.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bei diesem glaube ich, dass er nur 1 Resolver verwendet.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, der es ermöglicht, gültige Subdomains mittels aktivem Bruteforce zu enumerieren sowie Subdomains mit Wildcard-Behandlung und einfacher Input-Output-Unterstützung aufzulösen.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Es verwendet ebenfalls `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) verwendet asyncio, um Domainnamen asynchron per Brute-Force zu ermitteln.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Zweite DNS-Brute-Force-Runde

Nachdem du mithilfe offener Quellen und durch Brute-Forcing Subdomains gefunden hast, kannst du Varianten der gefundenen Subdomains generieren, um zu versuchen, noch mehr zu finden. Mehrere Tools sind dafür nützlich:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Generiert Permutationen anhand der Domains und Subdomains.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Generiert anhand der Domains und Subdomains Permutationen.
- Du kannst die goaltdns-Permutations-**Wortliste** [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt) abrufen.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Erhält gotator die Domains und Subdomains, generiert es permutations. Wenn keine permutations-Datei angegeben wird, verwendet gotator seine eigene.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Neben der Generierung von Subdomain-Permutationen kann es auch versuchen, diese aufzulösen (aber es ist besser, die zuvor kommentierten Tools zu verwenden).
- Du kannst die altdns-Permutations-**wordlist** [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt) erhalten.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zum Durchführen von Permutationen, Mutationen und Änderungen von Subdomains. Dieses Tool führt einen Brute-Force-Angriff auf das Ergebnis durch (es unterstützt keine DNS-Wildcards).
- Die dmut-Permutationswortliste erhältst du [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es neue potenzielle Subdomain-Namen** anhand angegebener Muster, um weitere Subdomains zu entdecken.

#### Generierung intelligenter Permutationen

- [**regulator**](https://github.com/cramppet/regulator): Weitere Informationen finden Sie in diesem [**Beitrag**](https://cramppet.github.io/regulator/index.html). Das Tool extrahiert im Wesentlichen die **Hauptbestandteile** aus den **entdeckten Subdomains** und kombiniert sie, um weitere Subdomains zu finden.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, gekoppelt mit einem äußerst einfachen, aber effektiven DNS-response-guided algorithm. Er nutzt einen bereitgestellten Datensatz, beispielsweise eine maßgeschneiderte Wordlist oder historische DNS-/TLS-Records, um präzise weitere passende Domainnamen zu generieren und diese in einer Schleife auf Grundlage der während des DNS-Scans gesammelten Informationen noch weiter auszubauen.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Lies diesen Blogbeitrag, den ich darüber geschrieben habe, wie man die **Subdomain Discovery** einer Domain mithilfe von **Trickest workflows automatisiert**, sodass ich nicht mehr manuell eine Reihe von Tools auf meinem Computer starten muss:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Wenn du eine IP-Adresse gefunden hast, die **eine oder mehrere Webseiten** von Subdomains enthält, kannst du versuchen, **weitere Subdomains mit Webauftritten auf dieser IP** zu **finden**, indem du in **OSINT-Quellen** nach Domains auf einer IP suchst oder **VHost-Domainnamen auf dieser IP per Brute Force** testest.

#### OSINT

Du kannst einige **VHosts in IPs mithilfe von** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder anderen APIs** finden.

**Brute Force**

Wenn du vermutest, dass eine Subdomain in einem Webserver verborgen sein könnte, kannst du versuchen, sie per Brute Force zu finden:

Wenn die **IP zu einem Hostnamen weiterleitet** (name-based vhosts), fuzz den `Host`-Header direkt und lass ffuf **auto-calibrate**, um Responses hervorzuheben, die sich vom standardmäßigen vhost unterscheiden:<sup>[[2]](#references)</sup>
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
> Mit dieser Technik können Sie möglicherweise sogar auf interne/versteckte endpoints zugreifen.

### **CORS Brute Force**

Manchmal finden Sie Seiten, die den Header _**Access-Control-Allow-Origin**_ nur zurückgeben, wenn im Header _**Origin**_ eine gültige Domain/Subdomain gesetzt ist. In diesen Szenarien können Sie dieses Verhalten ausnutzen, um neue **Subdomains** zu **entdecken**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Bei der Suche nach **Subdomains** solltest du darauf achten, ob sie auf irgendeine Art von **Bucket** **zeigt**. In diesem Fall [**prüfe die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Da du zu diesem Zeitpunkt alle Domains innerhalb des Scopes kennst, solltest du außerdem versuchen, [**mögliche Bucket-Namen per Brute Force zu ermitteln und die Berechtigungen zu prüfen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Du kannst **überwachen**, ob **neue Subdomains** einer Domain erstellt werden, indem du die **Certificate Transparency** Logs überwachst, wie es [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) tut.

### **Looking for vulnerabilities**

Prüfe auf mögliche [**Subdomain Takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3 Bucket** zeigt, [**prüfe die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn du eine **Subdomain mit einer anderen IP** als den bereits bei der Asset-Ermittlung gefundenen IPs findest, solltest du einen **grundlegenden Vulnerability Scan** (mit Nessus oder OpenVAS) sowie einen [**Port Scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Abhängig davon, welche Services ausgeführt werden, kannst du in **diesem Buch einige Tricks finden, um sie zu „attackieren“**.\
_Beachte, dass die Subdomain manchmal auf einer IP gehostet wird, die nicht vom Client kontrolliert wird und sich daher nicht im Scope befindet. Sei vorsichtig._

## IPs

In den ersten Schritten hast du möglicherweise **einige IP-Bereiche, Domains und Subdomains gefunden**.\
Es ist an der Zeit, **alle IPs aus diesen Bereichen** sowie die IPs der **Domains/Subdomains (DNS-Abfragen)** zu **sammeln**.

Mithilfe der Services der folgenden **kostenlosen APIs** kannst du außerdem **frühere, von Domains und Subdomains verwendete IPs** finden. Diese IPs könnten weiterhin dem Client gehören (und dir möglicherweise helfen, [**CloudFlare-Bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Du kannst außerdem mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) nach Domains suchen, die auf eine bestimmte IP-Adresse zeigen.

### **Looking for vulnerabilities**

**Führe einen Port Scan für alle IPs durch, die nicht zu CDNs gehören** (da du dort höchstwahrscheinlich nichts Interessantes finden wirst). Bei den gefundenen laufenden Services kannst du möglicherweise **Vulnerabilities finden**.

**Hier findest du einen** [**Guide**](../pentesting-network/index.html) **zum Scannen von Hosts.**

## Web servers hunting

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen die IP-Bereiche, Domains und Subdomains innerhalb des Scopes. Es ist an der Zeit, nach Webservern zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits eine **Recon der ermittelten IPs und Domains durchgeführt** und daher möglicherweise **alle potenziellen Webserver gefunden**. Falls nicht, sehen wir uns nun einige **schnelle Tricks an, um Webserver** innerhalb des Scopes zu finden.

Beachte bitte, dass dies auf die **Ermittlung von Web-Apps ausgerichtet** ist. Daher solltest du auch einen **Vulnerability Scan** und **Port Scanning** durchführen (**falls** dies vom Scope **erlaubt** ist).

Eine **schnelle Methode**, um mithilfe von [**masscan** Ports zu finden, die im Zusammenhang mit **Webservern** offen sind, findest du [hier](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres benutzerfreundliches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste von Domains, und das Tool versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich kannst du angeben, dass weitere Ports ausprobiert werden sollen:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Nachdem du nun **alle Webserver** entdeckt hast, die sich innerhalb des Scopes befinden (unter den **IPs** des Unternehmens sowie allen **Domains** und **Subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es also einfach und beginnen damit, Screenshots von allen zu erstellen. Schon durch einen **Blick** auf die **Hauptseite** kannst du **seltsame** Endpoints finden, die eher **vulnerable** sein könnten.

Um die vorgeschlagene Idee umzusetzen, kannst du [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** verwenden.**

Außerdem könntest du anschließend [**eyeballer**](https://github.com/BishopFox/eyeballer) über alle **Screenshots** laufen lassen, damit es dir mitteilt, welche davon **wahrscheinlich Vulnerabilities enthalten** und welche nicht.

## Public Cloud Assets

Um potenzielle Cloud Assets zu finden, die zu einem Unternehmen gehören, solltest du **mit einer Liste von Keywords beginnen, die dieses Unternehmen identifizieren**. Für ein Krypto-Unternehmen könntest du beispielsweise Wörter wie `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Du benötigst außerdem Wordlists mit **häufig in Buckets verwendeten Wörtern**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Anschließend solltest du mit diesen Wörtern **Permutationen** erzeugen (weitere Informationen findest du unter [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Mit den daraus resultierenden Wordlists könntest du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.**

Denke daran, dass du bei der Suche nach Cloud Assets nach **mehr als nur Buckets in AWS** suchen solltest.

### **Suche nach Vulnerabilities**

Wenn du Dinge wie **offene Buckets oder offengelegte Cloud Functions** findest, solltest du **darauf zugreifen** und versuchen herauszufinden, was sie dir anbieten und ob du sie missbrauchen kannst.

## Emails

Mit den **Domains** und **Subdomains** innerhalb des Scopes hast du grundsätzlich alles, was du **für die Suche nach Emails benötigst**. Dies sind die **APIs** und **Tools**, die für mich am besten funktioniert haben, um Emails eines Unternehmens zu finden:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Suche nach Vulnerabilities**

Emails werden dir später beim **Brute-Forcen von Web-Logins und Auth-Services** (wie SSH) nützlich sein. Außerdem werden sie für **Phishings** benötigt. Darüber hinaus liefern dir diese APIs noch mehr **Informationen über die Person** hinter der Email, was für die Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains,** **Subdomains** und **Emails** kannst du beginnen, nach Credentials zu suchen, die in der Vergangenheit zu diesen Emails gehörten und geleakt wurden:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Suche nach Vulnerabilities**

Wenn du **gültige geleakte** Credentials findest, ist das ein sehr einfacher Erfolg.

## Secrets Leaks

Credential Leaks stehen im Zusammenhang mit Hacks von Unternehmen, bei denen **sensible Informationen geleakt und verkauft wurden**. Unternehmen können jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken enthalten sind:

### Github Leaks

Credentials und APIs können in den **öffentlichen Repositories** des **Unternehmens** oder der **Benutzer**, die für dieses Github-Unternehmen arbeiten, geleakt werden.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repos** einer **Organisation** und deren **Entwickler** herunterzuladen und automatisch [**gitleaks**](https://github.com/zricethezav/gitleaks) darüber laufen zu lassen.

**Leakos** kann außerdem verwendet werden, um **gitleaks** gegen den gesamten **Text** der ihm übergebenen **URLs** laufen zu lassen, da auch **Webseiten manchmal Secrets enthalten**.

#### Github Dorks

Sieh dir auch diese **Seite** nach potenziellen **Github Dorks** an, nach denen du ebenfalls in der Organisation suchen könntest, die du angreifst:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Manchmal **veröffentlichen Angreifer oder einfach Mitarbeiter Unternehmensinhalte auf einer Paste-Seite**. Diese können **sensible Informationen enthalten oder auch nicht**, aber es ist sehr interessant, danach zu suchen.\
Du kannst das Tool [**Pastos**](https://github.com/carlospolop/Pastos) verwenden, um gleichzeitig in mehr als 80 Paste-Seiten zu suchen.

### Google Dorks

Alte, aber bewährte Google Dorks sind immer nützlich, um **offengelegte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem besteht darin, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausend** mögliche Abfragen enthält, die du nicht manuell ausführen kannst. Daher kannst du deine bevorzugten 10 auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) verwenden, **um sie alle auszuführen**.

_Beachte, dass Tools, die versuchen, die gesamte Datenbank über den regulären Google-Browser auszuführen, niemals fertig werden, da Google dich sehr bald blockieren wird._

### **Suche nach Vulnerabilities**

Wenn du **gültige geleakte** Credentials oder API-Tokens findest, ist das ein sehr einfacher Erfolg.

## Public Code Vulnerabilities

Wenn du feststellst, dass das Unternehmen **Open-Source-Code** besitzt, kannst du diesen **analysieren** und nach **Vulnerabilities** darin suchen.

**Je nach Sprache** gibt es verschiedene **Tools**, die du verwenden kannst:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Es gibt auch kostenlose Services, mit denen du **öffentliche Repositories scannen** kannst, wie zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Die **Mehrheit der von Bug Huntern gefundenen Vulnerabilities** befindet sich in **Webanwendungen**. Daher möchte ich an dieser Stelle über eine **Methodik zum Testen von Webanwendungen** sprechen. [**Diese Informationen findest du hier**](../../network-services-pentesting/pentesting-web/index.html).

Ich möchte außerdem den Abschnitt [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) besonders erwähnen, da sie zwar voraussichtlich keine sehr kritischen Vulnerabilities finden, aber nützlich sind, um sie in **Workflows zu integrieren und erste Informationen über das Web zu erhalten.**

## Zusammenfassung

> Glückwunsch! Zu diesem Zeitpunkt hast du bereits **die gesamte grundlegende Enumeration** durchgeführt. Ja, sie ist grundlegend, da noch sehr viel mehr Enumeration möglich ist (weitere Tricks sehen wir später).

Du hast bereits:

1. Alle **Unternehmen** innerhalb des Scopes gefunden
2. Alle **Assets** gefunden, die zu den Unternehmen gehören (und einen Vuln Scan durchgeführt, sofern dieser im Scope liegt)
3. Alle **Domains** gefunden, die zu den Unternehmen gehören
4. Alle **Subdomains** der Domains gefunden (irgendein Subdomain Takeover?)
5. Alle **IPs** innerhalb des Scopes gefunden (von **CDNs** und **nicht von CDNs**).
6. Alle **Webserver** gefunden und einen **Screenshot** davon erstellt (etwas Seltsames, das einen genaueren Blick wert ist?)
7. Alle potenziellen Public Cloud Assets gefunden, die zum Unternehmen gehören.
8. **Emails**, **Credential Leaks** und **Secret Leaks** gefunden, die dir sehr einfach einen **großen Erfolg** bescheren könnten.
9. **Alle gefundenen Websites pentested**

## **Full Recon Automatic Tools**

Es gibt verschiedene Tools, die einen Teil der vorgeschlagenen Aktionen gegen einen bestimmten Scope durchführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Etwas veraltet und nicht aktualisiert

## Referenzen

- [1] Alle kostenlosen Kurse von [**@Jhaddix**](https://twitter.com/Jhaddix), wie [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [@Asm0d3us - Weaponizing Favicon Ico For Bugbounties Osint And What Not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [swarm.ptsecurity.com - Discovering Domains Via A Time Correlation Attack](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [kmsec.uk - Passive Takeover](https://kmsec.uk/blog/passive-takeover)
- [8] [cramppet.github.io - Regulator - Index](https://cramppet.github.io/regulator/index.html)

{{#include ../../banners/hacktricks-training.md}}
