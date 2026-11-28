# Methodik für External Recon

{{#include ../../banners/hacktricks-training.md}}

## Asset-Ermittlung

Eine kategorisierte Liste zusätzlicher OSINT- und Web-Ermittlungsprojekte findest du unter [Tools und Ressourcen von Drittanbietern](../third-party-tools-and-resources.md#osint).

> Man hat dir also gesagt, dass alles, was einem bestimmten Unternehmen gehört, im Scope liegt, und du möchtest herausfinden, was dieses Unternehmen tatsächlich besitzt.

Ziel dieser Phase ist es, alle **Unternehmen im Besitz des Hauptunternehmens** und anschließend alle **Assets** dieser Unternehmen zu ermitteln. Dazu werden wir:<sup>[[1]](#references)</sup>

1. Die Übernahmen des Hauptunternehmens ermitteln. So finden wir die Unternehmen, die zum Scope gehören.
2. Die ASN (falls vorhanden) jedes Unternehmens ermitteln. So finden wir die IP-Bereiche, die den jeweiligen Unternehmen gehören.
3. Reverse-Whois-Abfragen verwenden, um nach weiteren Einträgen (Organisationsnamen, Domains usw.) zu suchen, die mit dem ersten Eintrag zusammenhängen (dies lässt sich rekursiv durchführen).
4. Weitere Techniken wie die Shodan-Filter `org` und `ssl` verwenden, um nach anderen Assets zu suchen (der `ssl`-Trick lässt sich rekursiv durchführen).

Eine schrittweise Übergabe von aufgelösten Subdomains an HTTP-Crawling und Port-Erkennung findest du in der [Pentesting-Methodik](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Übernahmen**

Zunächst müssen wir herausfinden, **welche anderen Unternehmen dem Hauptunternehmen gehören**.\
Eine Möglichkeit ist, [https://www.crunchbase.com/](https://www.crunchbase.com) aufzurufen, nach dem **Hauptunternehmen zu suchen** und auf "**Übernahmen**" zu klicken. Dort werden andere Unternehmen angezeigt, die vom Hauptunternehmen übernommen wurden.\
Alternativ kannst du die **Wikipedia**-Seite des Hauptunternehmens aufrufen und nach **Übernahmen** suchen.\
Bei börsennotierten Unternehmen solltest du **SEC/EDGAR-Unterlagen**, **Investor-Relations**-Seiten oder lokale Unternehmensregister prüfen (z. B. **Companies House** im Vereinigten Königreich).\
Für globale Konzernstrukturen und Tochtergesellschaften eignen sich **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF-LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)).

> Okay, an diesem Punkt solltest du alle Unternehmen kennen, die zum Scope gehören. Sehen wir uns an, wie du ihre Assets findest.

### **ASNs**

Eine Autonomous System Number (**ASN**) ist eine **eindeutige Nummer**, die von der **Internet Assigned Numbers Authority (IANA)** einem **autonomen System** (AS) zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, für die eine klar definierte Richtlinie für den Zugriff auf externe Netzwerke gilt und die von einer einzelnen Organisation verwaltet werden, sich aber aus mehreren Betreibern zusammensetzen können.

Es ist sinnvoll herauszufinden, ob dem **Unternehmen eine ASN zugewiesen wurde**, um seine **IP-Bereiche** zu ermitteln. Es kann interessant sein, einen **Schwachstellentest** gegen alle **Hosts** im **Scope** durchzuführen und in diesen IPs nach **Domains** zu suchen.\
Du kannst auf [**https://bgp.he.net/**](https://bgp.he.net) **oder** [**https://ipinfo.io/**](https://ipinfo.io/) anhand des Unternehmens**namens**, einer **IP** oder einer **Domain** suchen.\
**Je nach Region des Unternehmens können diese Links hilfreich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Wahrscheinlich finden sich jedoch alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Außerdem aggregiert und fasst [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** Enumeration am Ende des Scans automatisch ASNs zusammen.

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

You kannst die IP-Bereiche einer Organisation auch mit [ASNLookup](https://asnlookup.com/) finden, das eine begrenzte kostenlose API-Stufe anbietet.

### **Nach Schwachstellen suchen**

An diesem Punkt kennen wir **alle Assets innerhalb des Scopes**. Wenn es dir also erlaubt ist, könntest du einen **Vulnerability Scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) über alle Hosts laufen lassen.\
Außerdem könntest du [**Port-Scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) durchführen **oder Dienste wie** Shodan, Censys oder ZoomEye **nutzen, um** offene Ports **zu finden. Je nachdem, was du findest, solltest du in diesem Buch nachsehen, wie du verschiedene möglicherweise laufende Dienste pentesten kannst.**\
**Außerdem ist es vielleicht erwähnenswert, dass du auch Listen mit** Standard-Benutzernamen **und** Passwörtern **vorbereiten und versuchen kannst, Dienste mit** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **zu bruteforcen.**

## Domains

> Wir kennen alle Unternehmen innerhalb des Scopes und ihre Assets. Jetzt ist es an der Zeit, die Domains innerhalb des Scopes zu finden.

_Bitte beachte, dass du mit den folgenden vorgeschlagenen Techniken auch Subdomains finden kannst und diese Informationen nicht unterschätzen solltest._

Zuerst solltest du nach der **Hauptdomain** jedes Unternehmens suchen. Zum Beispiel ist es für _Tesla Inc._ die Domain _tesla.com_.

### **Reverse DNS**

Da du alle IP-Bereiche der Domains gefunden hast, könntest du versuchen, **Reverse-DNS-Lookups** für diese **IPs durchzuführen, um weitere Domains innerhalb des Scopes zu finden**. Versuche, einen DNS-Server des Opfers oder einen bekannten DNS-Server zu verwenden (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Damit dies funktioniert, muss der Administrator PTR manuell aktivieren.\
Für diese Informationen kannst du auch [SecurityTrails](https://securitytrails.com/) verwenden, historische DNS-Daten erfordern jedoch einen kostenpflichtigen Tarif.\
Bei großen Bereichen eignen sich Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx), um Reverse Lookups und die Anreicherung der Ergebnisse zu automatisieren.

### **Reverse Whois (loop)**

In einem **whois** findest du viele interessante **Informationen**, wie **Organisationsname**, **Adresse**, **E-Mail-Adressen**, Telefonnummern ... Noch interessanter ist jedoch, dass du **weitere Assets des Unternehmens finden kannst**, wenn du **Reverse-Whois-Abfragen anhand dieser Felder durchführst** (zum Beispiel andere Whois-Einträge, in denen dieselbe E-Mail-Adresse vorkommt).\
Du kannst Online-Tools verwenden, wie:

- [https://ip.thc.org/](https://ip.thc.org/) - **Kostenlos** (Web und API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Kostenlose** Weboberfläche; kostenpflichtige API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Kostenpflichtig
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nicht kostenlos (nur **100 kostenlose** Abfragen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nicht kostenlos
- [https://securitytrails.com/](https://securitytrails.com/) - Begrenzter kostenloser API-Zugriff auf aktuelle DNS-Daten/Subdomains; für historische Daten und Reverse Lookups ist ein kostenpflichtiger Tarif erforderlich.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 kostenlose API-Credits bei der Registrierung; danach kostenpflichtig.

Du kannst diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (erfordert einen whoxy-API-Schlüssel).\
Mit [amass](https://github.com/owasp-amass/amass) kannst du auch automatisch Reverse-Whois-Suchen durchführen: `amass intel -d tesla.com -whois`

**Beachte, dass du mit dieser Technik jedes Mal weitere Domainnamen entdecken kannst, wenn du eine neue Domain findest.**

### **Tracker**

Wenn du auf 2 verschiedenen Seiten **dieselbe ID desselben Trackers** findest, kannst du davon ausgehen, dass **beide Seiten** **vom selben Team verwaltet werden**.\
Wenn du beispielsweise auf mehreren Seiten dieselbe **Google-Analytics-ID** oder dieselbe **Adsense-ID** siehst.

Es gibt einige Seiten und Tools, mit denen du nach diesen und weiteren Trackern suchen kannst:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Kostenpflichtiger** Web- und API-Dienst ([Preise](https://www.stackscan.com/pricing)); derzeit wird kein kostenloser Tarif angeboten. Suche anhand beliebiger bereitgestellter Assets, nicht nur Tracker-IDs: einem Skriptpfad, dem Namen eines selbst gehosteten Bundles oder dem Host, von dem ein Asset geladen wird. Das Ergebnis listet alle Websites auf, die dieses Asset verwenden.

Die API gibt den Stack für eine einzelne Domain zurück. Das ist hilfreich, um zu bestätigen, dass ein mögliches Asset zum selben Bestand gehört:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gibt jede erkannte Technologie mit ihrer Kategorie zurück. Asset Pivoting ist derzeit nur für das Web verfügbar; die API unterstützt die Suche nach einzelnen Domains.

### **Favicon**

Wusstest du, dass wir verwandte Domains und Subdomains unseres Ziels finden können, indem wir nach demselben Favicon-Hash suchen? Genau das macht das von [@m4ll0k2](https://twitter.com/m4ll0k2) entwickelte Tool [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py). So verwendest du es:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash-Ergebnisse zum Auffinden von Domains mit demselben Favicon-Hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Einfach gesagt ermöglicht uns favihash, Domains zu finden, die denselben Favicon-Hash wie unser Ziel haben.

![favihash-Ausgabe zum Auffinden von Domains mit demselben Favicon-Hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

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

Du kannst favicon-Hashes auch in großem Umfang mit [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) abrufen und dann in Shodan/Censys pivotieren.

Betrachte favicon-Fingerprints als Hinweise und validiere sie anhand umgebender Signale.<sup>[[3]](#references)[[4]](#references)</sup>

- **Betrachte den Hash als Indikator, nicht als Beweis**: MMH3 ist kompakt; Kollisionen, wiederverwendete Icons und absichtliches Spoofing sind möglich.
- **Prüfe mehr als nur** `/favicon.ico`: Untersuche Framework-/Build-Pfade, Manifest-Dateien, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, Inline-Data-URLs und HTML-`<link rel="icon">`-Tags.
- **Statische Assets können hinter WAF-/SSO-/IdP-Kontrollen weiterhin erreichbar sein**: Rufe das Icon direkt ab und prüfe `ETag`, `Last-Modified`, Redirects und Cache-Header.
- **Validiere Treffer anhand umgebender Signale**: Vergleiche den Titel, den HTML-/Body-Hash, Header, TLS-Zertifikat-Subjects/SANs, Produktkomponenten und exponierte Ports.
- **Gruppiere nach HTML-/Body-Hash**: Ein einheitliches Template stärkt den Fingerprint; unterschiedliche Templates deuten auf ein generisches oder gemeinsam verwendetes Icon hin.
- **Betrachte einen Hash, der über nicht zusammenhängende Signaturen, Ports und Produkte hinweg auftaucht, als möglichen Honeypot oder Platzhalter.**
- **Vergleiche bei uneindeutigen Zielen eine echte Seite mit einem nicht existierenden Pfad**, etwa `/_favicon_probe_<8-hex>`; übereinstimmende Hosting- oder Parking-Antworten können das gemeinsame Icon erklären.
- **Beginne die Triage mit Nuclei-Erkennungsregeln oder öffentlichen Datensätzen**, die favicon-Hashes Produkten und CPEs zuordnen.
- **Beachte die IP-zentrierte Abdeckungslücke**: CDN-geschützte, SNI-geroutete, Anycast- und nur über Domains erreichbare Oberflächen können in Shodan-ähnlichen Datensätzen fehlen.

### **Copyright / Uniq-String**

Suche auf den Webseiten nach **Strings, die auf verschiedenen Websites derselben Organisation vorkommen könnten**. Ein **Copyright-String** kann ein gutes Beispiel sein. Suche dann bei **Google**, in anderen **Browsern** oder sogar in **shodan** nach diesem String: `shodan search http.html:"Copyright string"`

### **CRT-Zeit**

Es ist üblich, einen cron job wie den folgenden zu haben

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

um alle Zertifikate auf einem Server gleichzeitig zu erneuern. Der Abgleich von Zertifikat-Zeitstempeln oder Positionen in Certificate-Transparency-Logs kann verwandte Domains aufdecken.<sup>[[6]](#references)</sup>

Verwenden Sie auch **Certificate-Transparency**-Logs direkt:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail-DMARC-Informationen

Sie können eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen teilen**.\
Ein weiterer nützlicher Dienst ist [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ein verwaister A-Record kann wieder erreichbar werden, wenn ein Cloud-Anbieter eine IP-Adresse neu vergibt. Die angeführte Forschung beschreibt einen opportunistischen Workflow, bei dem eine Instanz bereitgestellt und ihre Adresse mit passiven DNS-Daten abgeglichen wird; testen Sie Takeover-Szenarien nur innerhalb des autorisierten Umfangs.<sup>[[7]](#references)</sup>

### **Weitere Möglichkeiten**

Wiederholen Sie die passenden Discovery-Pivots jedes Mal, wenn Sie eine neue Domain finden: Jedes Ergebnis kann zusätzliche Zertifikatsnamen, Beziehungen aus passivem DNS, Favicon-Übereinstimmungen und Unternehmenskennungen offenlegen, die ausgehend vom ursprünglichen Startpunkt nicht sichtbar waren.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Da Sie bereits den Namen der Organisation kennen, der der IP-Adressbereich gehört, können Sie in Shodan anhand dieser Daten suchen, zum Beispiel mit: `org:"Tesla, Inc."` Prüfen Sie die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Sie können auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisationsnamen** ermitteln und dann in den **TLS-Zertifikaten** aller bei **Shodan** bekannten Webseiten nach diesem Namen suchen. Verwenden Sie dazu den Filter: `ssl:"Tesla Motors"` oder ein Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ist ein Tool, das nach **Domains sucht, die mit einer Hauptdomain verwandt sind**, sowie nach deren **Subdomains** – wirklich beeindruckend.

**Passives DNS / Historisches DNS**

Passive DNS-Daten eignen sich hervorragend, um **alte und vergessene Einträge zu finden**, die noch aufgelöst werden oder übernommen werden können. Sehen Sie sich Folgendes an:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Suche nach Schwachstellen**

Prüfen Sie, ob ein [Domain-Takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) möglich ist. Vielleicht **nutzt ein Unternehmen eine Domain**, hat aber **die Eigentümerschaft verloren**. Registrieren Sie sie einfach (wenn sie günstig genug ist) und informieren Sie das Unternehmen.

Wenn Sie eine **Domain mit einer IP-Adresse finden, die sich von den bereits bei der Asset Discovery gefundenen unterscheidet**, sollten Sie einen **grundlegenden Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**Portscan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste laufen, finden Sie **in diesem Buch einige Tricks, um sie „anzugreifen“**.\
_Beachten Sie, dass die Domain manchmal auf einer IP-Adresse gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht zum Umfang gehört. Seien Sie vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen im Umfang, sämtliche Assets jedes Unternehmens und alle Domains, die mit den Unternehmen in Verbindung stehen.

Jetzt ist es an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu ermitteln.

> [!TIP]
> Beachten Sie, dass einige Tools und Techniken zum Finden von Domains auch beim Finden von Subdomains helfen können.

### **DNS**

Versuchen wir, **Subdomains** anhand der **DNS**-Einträge zu finden. Wir sollten auch **Zone Transfer** ausprobieren (falls dies möglich ist, sollten Sie es melden).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Für APIs und Plattformen rund um Infrastruktur, Reputation, Breach-Datensätze und Enrichment über die Subdomain-Suche hinaus siehe den [Katalog für Reconnaissance- und Threat-Intelligence-APIs](reconnaissance-and-threat-intelligence-apis.md).

Am schnellsten erhältst du viele Subdomains, indem du externe Quellen durchsuchst. Die meistgenutzten **Tools** sind die folgenden (für bessere Ergebnisse die API-Schlüssel konfigurieren):


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

Es gibt **weitere interessante Tools/APIs**, die zwar nicht direkt auf das Finden von Subdomains spezialisiert sind, aber dafür nützlich sein können, zum Beispiel:

- [**IP.THC.ORG**](https://ip.thc.org) kostenlose API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Kostenlose AnubisDB-API**](https://github.com/jonluca/Anubis-DB)

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

- [**gau**](https://github.com/lc/gau)**:** ruft bekannte URLs für eine beliebige Domain von AlienVault's Open Threat Exchange, der Wayback Machine und Common Crawl ab.

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

- [**SecurityTrails**](https://securitytrails.com/) bietet begrenzten kostenlosen API-Zugriff auf aktuelle DNS- und Subdomain-Daten; für historische DNS-/IP-Daten ist ein kostenpflichtiger Tarif erforderlich.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Dieses Projekt bietet **kostenlos alle Subdomains zu Bug-Bounty-Programmen** an. Auf diese Daten kannst du auch mit [chaospy](https://github.com/Moaaz-0x/chaospy) zugreifen oder sogar den von diesem Projekt verwendeten Scope unter [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) abrufen.

Hier findest du einen **Vergleich** vieler dieser Tools: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **Subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen per Brute-Force abfragen.

Dafür benötigst du einige **gängige Subdomain-Wordlists, zum Beispiel**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Außerdem benötigst du IP-Adressen zuverlässiger DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, kannst du die Resolver von [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) herunterladen und mit [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) filtern. Alternativ kannst du diese Liste verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die am häufigsten empfohlenen Tools für DNS-Brute-Force sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das effektive DNS-Brute-Force ermöglichte. Es ist sehr schnell, neigt jedoch zu falsch-positiven Ergebnissen.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Ich glaube, dieses Tool verwendet nur einen Resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, mit dem sich gültige Subdomains durch aktives Brute-Forcing aufzählen und Subdomains mit Wildcard-Behandlung sowie einfacher Ein-/Ausgabe-Unterstützung auflösen lassen.

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

Nachdem du Subdomains mithilfe offener Quellen und durch Brute-Forcing gefunden hast, kannst du Variationen der gefundenen Subdomains erstellen, um noch mehr zu finden. Dafür eignen sich mehrere Tools:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Erzeugt Permutationen anhand der Domains und Subdomains.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Erzeugt Permutationen aus den angegebenen Domains und Subdomains.
  - Die goaltdns-**wordlist** mit Permutationen findest du [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Anhand der Domains und Subdomains Permutationen generieren. Wenn keine Permutationsdatei angegeben ist, verwendet gotator seine eigene.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Neben der Generierung von Subdomain-Permutationen kann es auch versuchen, diese aufzulösen (dafür verwendet man jedoch besser die zuvor erwähnten Tools).
  - Die altdns-Permutations-**Wortliste** findest du [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zum Erstellen von Permutationen, Mutationen und Varianten von Subdomains. Dieses Tool führt für das Ergebnis einen Brute-Force-Angriff durch (DNS-Wildcards werden nicht unterstützt).
  - Die Permutations-Wortliste für dmut findest du [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es neue potenzielle Subdomain-Namen** anhand angegebener Muster, um weitere Subdomains aufzuspüren.

#### Generierung intelligenter Permutationen

- [**regulator**](https://github.com/cramppet/regulator): Lernt regexähnliche Muster aus entdeckten Subdomains und generiert Kandidatennamen, die aufgelöst werden sollen.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven DNS-antwortgesteuerten Algorithmus kombiniert wird. Er nutzt bereitgestellte Eingabedaten wie eine angepasste Wordlist oder historische DNS-/TLS-Einträge, um präzise weitere passende Domainnamen zu generieren und diese auf Grundlage der während des DNS-Scans gesammelten Informationen in einer Schleife weiter auszubauen.

```
echo www | subzuf facebook.com
```

### **Workflow zur Subdomain-Erkennung**

Trickest-Workflow-Beispiele kombinieren OSINT, DNS-Brute-Force und Permutationsphasen für eine wiederholbare Subdomain-Aufzählung.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Wenn du eine IP-Adresse mit **einer oder mehreren Webseiten** gefunden hast, die zu Subdomains gehören, kannst du versuchen, **weitere Subdomains mit Webseiten auf dieser IP** zu finden, indem du in **OSINT-Quellen** nach Domains auf einer IP suchst oder **VHost-Domainnamen auf dieser IP per Brute-Force ermittelst**.

#### OSINT

Du kannst **VHosts auf IPs mithilfe von** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder anderen APIs finden**.

**Brute Force**

Wenn du vermutest, dass eine Subdomain auf einem Webserver verborgen sein könnte, kannst du versuchen, sie per Brute-Force zu ermitteln:

Bei name-based vhosts kannst du den `Host`-Header fuzzing und die Auto-Kalibrierung von ffuf verwenden, um die Standardantwort herauszufiltern.<sup>[[2]](#references)</sup>

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
> Mit dieser Technik kannst du möglicherweise sogar auf interne/versteckte Endpunkte zugreifen.

### **CORS Brute Force**

Manchmal findest du Seiten, die den Header _**Access-Control-Allow-Origin**_ nur zurückgeben, wenn im Header _**Origin**_ eine gültige Domain/Subdomain angegeben ist. In solchen Fällen kannst du dieses Verhalten ausnutzen, um neue **Subdomains** zu **entdecken**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Bucket-Brute-Force**

Achte bei der Suche nach **Subdomains** darauf, ob eine davon auf irgendeine Art von **Bucket** **zeigt**. Falls ja, [**prüfe die Berechtigungen**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Da du zu diesem Zeitpunkt alle Domains innerhalb des Scope kennst, kannst du außerdem versuchen, [**mögliche Bucket-Namen per Brute-Force zu ermitteln und die Berechtigungen zu prüfen**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Überwachung**

Du kannst überwachen, ob **neue Subdomains** einer Domain erstellt werden, indem du die **Certificate-Transparency-Logs** überwachst – das macht [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Suche nach Schwachstellen**

Prüfe auf mögliche [**Subdomain-Übernahmen**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Falls die **Subdomain** auf einen **S3-Bucket** zeigt, [**prüfe die Berechtigungen**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Wenn du **eine Subdomain mit einer IP-Adresse findest, die sich von denen unterscheidet**, die du bei der Asset-Ermittlung bereits gefunden hast, solltest du einen **einfachen Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**Portscan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste laufen, findest du in **diesem Buch einige Tricks, um sie „anzugreifen“**.\
_Beachte, dass die Subdomain manchmal auf einer IP-Adresse gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht zum Scope gehört. Sei vorsichtig._

## IPs

Bei den ersten Schritten hast du möglicherweise **einige IP-Bereiche, Domains und Subdomains gefunden**.\
Jetzt ist es an der Zeit, **alle IPs aus diesen Bereichen sowie für die Domains/Subdomains zusammenzutragen (DNS-Abfragen).**

Mit Diensten wie den folgenden kannst du auch **frühere IPs finden, die von Domains und Subdomains verwendet wurden**. Diese IPs könnten noch immer dem Kunden gehören (und dir möglicherweise dabei helfen, [**CloudFlare-Umgehungen**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

- [**SecurityTrails**](https://securitytrails.com/) (historische DNS/IP-Daten erfordern einen kostenpflichtigen Tarif)

Du kannst auch mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) oder einem Online-Reverse-IP-Lookup wie [**NetAPI**](https://netapi.com/lookup-ip/) nach Domains suchen, die auf eine bestimmte IP-Adresse zeigen.

### **Suche nach Schwachstellen**

**Scanne alle IPs, die nicht zu CDNs gehören, auf offene Ports** (da du dort mit hoher Wahrscheinlichkeit nichts Interessantes finden wirst). Bei den entdeckten laufenden Diensten kannst du möglicherweise **Schwachstellen finden**.

**Hier findest du einen** [**Leitfaden**](../pentesting-network/index.html) **zum Scannen von Hosts.**

## Suche nach Webservern

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen die IP-Bereiche, Domains und Subdomains innerhalb des Scope. Jetzt ist es an der Zeit, nach Webservern zu suchen.

Bei den vorherigen Schritten hast du wahrscheinlich bereits etwas **Recon der entdeckten IPs und Domains** durchgeführt und daher möglicherweise **alle möglichen Webserver bereits gefunden**. Falls nicht, sehen wir uns nun einige **schnelle Tricks an, um Webserver innerhalb des Scope zu finden**.

Beachte, dass dies auf die **Ermittlung von Web-Apps** ausgerichtet ist. Daher solltest du auch einen **Schwachstellen-** und **Portscan** durchführen (**sofern der Scope dies erlaubt**).

Eine **schnelle Methode**, um mit [**masscan** offene Ports** im Zusammenhang mit Webservern zu finden, gibt es hier](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres praktisches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste mit Domains, und das Tool versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Außerdem kannst du festlegen, dass auch andere Ports geprüft werden sollen:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Nachdem du jetzt **alle Webserver** im Scope entdeckt hast (unter den **IPs** des Unternehmens sowie allen **Domains** und **Subdomains**), **weißt du wahrscheinlich nicht, wo du anfangen sollst**. Machen wir es also einfach und beginnen damit, Screenshots von allen zu erstellen. Schon ein **Blick** auf die **Hauptseite** kann **seltsame** Endpunkte aufdecken, die **wahrscheinlicher** **verwundbar** sind.

Für den vorgeschlagenen Ansatz kannst du [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** verwenden.**

Außerdem könntest du anschließend [**eyeballer**](https://github.com/BishopFox/eyeballer) über alle **Screenshots** laufen lassen, damit es dir mitteilt, **welche wahrscheinlich Schwachstellen enthalten** und welche nicht.

## Öffentliche Cloud-Assets

Um potenzielle Cloud-Assets zu finden, die einem Unternehmen gehören, solltest du **mit einer Liste von Schlüsselwörtern beginnen, die das Unternehmen identifizieren**. Für ein Krypto-Unternehmen könntest du zum Beispiel Wörter wie `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Du brauchst außerdem Wortlisten mit **häufig in Buckets verwendeten Wörtern**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Anschließend solltest du mit diesen Wörtern **Permutationen** erzeugen (weitere Informationen findest du unter [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Mit den daraus resultierenden Wortlisten könntest du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** verwenden.**

Denk daran: Wenn du nach Cloud-Assets suchst, solltest du n**icht nur nach Buckets in AWS suchen**.

### **Suche nach Schwachstellen**

Wenn du Dinge wie **offene Buckets oder offengelegte Cloud Functions** findest, solltest du **darauf zugreifen** und herausfinden, was sie bieten und ob du sie missbrauchen kannst.

## E-Mails

Mit den **Domains** und **Subdomains** im Scope hast du im Grunde alles, was du **für die Suche nach E-Mail-Adressen brauchst**. Mit diesen **APIs** und **Tools** habe ich die besten Ergebnisse bei der Suche nach E-Mail-Adressen eines Unternehmens erzielt:

- [**theHarvester**](https://github.com/laramies/theHarvester) – mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Suche nach Schwachstellen**

E-Mail-Adressen sind später beim **Brute-Forcing von Web-Logins und Auth-Diensten** (wie SSH) nützlich. Außerdem werden sie für **Phishing** benötigt. Darüber hinaus liefern dir diese APIs noch mehr **Informationen über die Person** hinter der E-Mail-Adresse, was für die Phishing-Kampagne hilfreich ist.

## Credential-Leaks

Mit den **Domains,** **Subdomains** und **E-Mail-Adressen** kannst du nach Zugangsdaten suchen, die in der Vergangenheit geleakt wurden und zu diesen E-Mail-Adressen gehören:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Suche nach Schwachstellen**

Wenn du **gültige geleakte** Zugangsdaten findest, ist das ein sehr einfacher Erfolg.

## Secrets-Leaks

Credential-Leaks hängen mit Hacks von Unternehmen zusammen, bei denen **sensible Informationen geleakt und verkauft wurden**. Unternehmen können jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken zu finden sind:

### Github-Leaks

Zugangsdaten und APIs könnten in den **öffentlichen Repositories** des **Unternehmens** oder der **Mitarbeiter** dieses Unternehmens auf Github geleakt worden sein.\
Mit dem **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) kannst du alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** **herunterladen** und automatisch [**gitleaks**](https://github.com/gitleaks/gitleaks) darauf ausführen.

**Leakos** kann auch verwendet werden, um **gitleaks** auf allen **Text-URLs** auszuführen, die ihm übergeben werden, da manchmal auch **Webseiten Secrets enthalten**.

#### Github Dorks

Auf der Seite [GitHub dorks and leaks](github-leaked-secrets.md) findest du mögliche **GitHub-Dorks**, mit denen du die Organisation durchsuchen kannst.

### Paste-Leaks

Manchmal **veröffentlichen Angreifer oder auch Mitarbeiter Unternehmensinhalte auf einer Paste-Site**. Diese können **sensible Informationen enthalten oder auch nicht**, aber die Suche danach lohnt sich.\
Mit dem Tool [**Pastos**](https://github.com/carlospolop/Pastos) kannst du gleichzeitig auf mehr als 80 Paste-Sites suchen.

### Google-Dorks

Alte, aber bewährte Google-Dorks sind immer nützlich, um **offengelegte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausend** mögliche Abfragen enthält, die du nicht manuell ausführen kannst. Du kannst also deine zehn Favoriten auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Beachte, dass Tools, die die gesamte Datenbank über den regulären Google-Browser abfragen sollen, nie fertig werden, da Google dich sehr, sehr schnell blockiert._

### **Suche nach Schwachstellen**

Wenn du **gültige geleakte** Zugangsdaten oder API-Tokens findest, ist das ein sehr einfacher Erfolg.

## Schwachstellen in öffentlichem Code

Wenn du herausgefunden hast, dass das Unternehmen **Open-Source-Code** hat, kannst du ihn **analysieren** und nach **Schwachstellen** suchen.

**Je nach Sprache** kannst du verschiedene **Tools** verwenden. Eine Liste findest du unter [Tools zur Überprüfung von Quellcode](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Es gibt auch kostenlose Dienste, mit denen du **öffentliche Repositories scannen** kannst, zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Methodik für Web-Pentesting**](../../network-services-pentesting/pentesting-web/index.html)

Die **meisten von Bug Huntern gefundenen Schwachstellen** befinden sich in **Webanwendungen**. Deshalb möchte ich an dieser Stelle eine **Methodik zum Testen von Webanwendungen** vorstellen. [**Hier findest du diese Informationen**](../../network-services-pentesting/pentesting-web/index.html).

Besonders erwähnen möchte ich auch den Abschnitt [**Open-Source-Tools für automatisierte Web-Scanner**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners). Auch wenn du nicht erwarten solltest, dass sie sehr schwerwiegende Schwachstellen finden, eignen sie sich gut, um sie in **Workflows einzubinden und erste Informationen über das Web zu erhalten.**

## Zusammenfassung

> Glückwunsch! An diesem Punkt hast du bereits **alle grundlegenden Aufklärungsarbeiten** durchgeführt. Ja, sie sind grundlegend, denn es ist noch viel mehr Aufklärung möglich (später sehen wir uns weitere Tricks an).

Du hast also bereits:

1. Alle **Unternehmen** im Scope gefunden
2. Alle **Assets** der Unternehmen gefunden (und einen Vuln-Scan durchgeführt, falls dies im Scope liegt)
3. Alle **Domains** der Unternehmen gefunden
4. Alle **Subdomains** der Domains gefunden (gibt es ein Subdomain Takeover?)
5. Alle **IPs** (von **CDNs und nicht von CDNs**) im Scope gefunden.
6. Alle **Webserver** gefunden und von ihnen einen **Screenshot** erstellt (gibt es etwas Seltsames, das einen genaueren Blick wert ist?)
7. Alle **potenziellen öffentlichen Cloud-Assets** des Unternehmens gefunden.
8. **E-Mail-Adressen**, **Credential-Leaks** und **Secret-Leaks**, die dir **sehr leicht einen großen Erfolg verschaffen können**.
9. **Pentesting auf allen gefundenen Websites**

## **Tools für automatisierte vollständige Recon**

Es gibt verschiedene Tools, die einen Teil der vorgeschlagenen Aktionen für einen angegebenen Scope durchführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) – etwas älter und nicht aktualisiert



## References

- [1] [Jason Haddix – Die Methodik des Bug Hunters v4.0: Recon-Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Über Favicons: Von Browser-Symbolen zu Intelligence über die Angriffsfläche](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.ico für Bug Bounties, OSINT und mehr als Waffe einsetzen](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Domains durch einen zeitlichen Korrelationsangriff auf Certificate Transparency entdecken](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passives Takeover: Eine aufwendige Subdomain-Takeover-Kampagne aufdecken (und nachbilden)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Eine einzigartige Methode zur Subdomain-Aufzählung](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Vollständiger Workflow zur Subdomain-Erkennung, Teil 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Vollständige Brute-Force-Erkennung von Subdomains mit einem automatisierten Trickest-Workflow, Teil 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot der favihash-Ausgabe](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
