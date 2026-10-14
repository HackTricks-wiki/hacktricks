# Externe Recon-Methodik

{{#include ../../banners/hacktricks-training.md}}

## Asset-Ermittlung

> Man hat dir also gesagt, dass alles, was zu einem Unternehmen gehört, im Scope liegt, und du möchtest herausfinden, was dieses Unternehmen tatsächlich besitzt.

Ziel dieser Phase ist es, alle **Unternehmen im Besitz des Hauptunternehmens** und anschließend alle **Assets** dieser Unternehmen zu ermitteln. Dazu werden wir:<sup>[[1]](#references)</sup>

1. Die Übernahmen des Hauptunternehmens ermitteln. So finden wir die Unternehmen im Scope.
2. Für jedes Unternehmen die ASN (falls vorhanden) ermitteln. So finden wir die IP-Bereiche, die zu jedem Unternehmen gehören.
3. Mit Reverse-Whois-Abfragen nach weiteren Einträgen (Organisationsnamen, Domains usw.) suchen, die mit dem ersten Eintrag in Verbindung stehen (dies kann rekursiv erfolgen).
4. Weitere Techniken wie die `org`- und `ssl`-Filter von shodan verwenden, um nach anderen Assets zu suchen (der `ssl`-Trick kann rekursiv angewendet werden).

### **Übernahmen**

Zuerst müssen wir herausfinden, **welche anderen Unternehmen dem Hauptunternehmen gehören**.\
Eine Möglichkeit ist, [https://www.crunchbase.com/](https://www.crunchbase.com) aufzurufen, nach dem **Hauptunternehmen zu suchen** und auf "**acquisitions**" zu **klicken**. Dort werden weitere Unternehmen angezeigt, die vom Hauptunternehmen übernommen wurden.\
Eine andere Möglichkeit ist, auf der **Wikipedia**-Seite des Hauptunternehmens nach **Übernahmen** zu suchen.\
Bei börsennotierten Unternehmen solltest du **SEC/EDGAR-Einreichungen**, **Investor-Relations**-Seiten oder lokale Unternehmensregister prüfen (z. B. **Companies House** im Vereinigten Königreich).\
Für globale Unternehmensstrukturen und Tochtergesellschaften kannst du **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) und die **GLEIF-LEI**-Datenbank ([https://www.gleif.org/](https://www.gleif.org/)) nutzen.

> Okay, an diesem Punkt solltest du alle Unternehmen im Scope kennen. Sehen wir uns an, wie wir ihre Assets finden.

### **ASNs**

Eine autonome Systemnummer (**ASN**) ist eine **eindeutige Nummer**, die einem **autonomen System** (AS) von der **Internet Assigned Numbers Authority (IANA)** zugewiesen wird.\
Ein **AS** besteht aus **Blöcken** von **IP-Adressen**, für die eine eindeutig definierte Richtlinie für den Zugriff auf externe Netzwerke gilt. Es wird von einer einzelnen Organisation verwaltet, kann aber aus mehreren Betreibern bestehen.

Es ist sinnvoll herauszufinden, ob dem **Unternehmen eine ASN zugewiesen wurde**, um dessen **IP-Bereiche** zu ermitteln. Es ist sinnvoll, einen **Schwachstellentest** gegen alle **Hosts** im **Scope** durchzuführen und innerhalb dieser IPs nach **Domains zu suchen**.\
Du kannst auf [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **oder** [**https://ipinfo.io/**](https://ipinfo.io/) nach dem Unternehmensnamen, einer **IP** oder einer **Domain** **suchen**.\
**Je nach Region des Unternehmens können diese Links hilfreich sein, um weitere Daten zu sammeln:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nordamerika),** [**APNIC**](https://www.apnic.net) **(Asien),** [**LACNIC**](https://www.lacnic.net) **(Lateinamerika),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In jedem Fall sind wahrscheinlich alle** nützlichen Informationen **(IP-Bereiche und Whois)** bereits im ersten Link zu finden.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Außerdem aggregiert und fasst die [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-Enumeration** am Ende des Scans automatisch ASNs zusammen.

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

You can find the IP ranges of an organisation auch mit [http://asnlookup.com/](http://asnlookup.com) (es bietet eine kostenlose API).\
Du kannst die IP und ASN einer Domain mit [http://ipv4info.com/](http://ipv4info.com) finden.

### **Nach Schwachstellen suchen**

An diesem Punkt kennen wir **alle Assets innerhalb des Scopes**. Wenn es dir erlaubt ist, kannst du also einen **Schwachstellen-Scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) auf allen Hosts starten.\
Du könntest auch [**Port Scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) starten **oder Dienste wie** Shodan, Censys oder ZoomEye **nutzen, um** offene Ports **zu finden. Je nachdem, was du findest, solltest du in diesem Buch nachsehen, wie du verschiedene möglicherweise laufende Dienste pentestest.**\
**Erwähnenswert ist auch, dass du Listen mit** Standardbenutzernamen **und** Passwörtern **erstellen und versuchen kannst, Dienste mit** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **zu bruteforcen.**

## Domains

> Wir kennen alle Unternehmen innerhalb des Scopes und ihre Assets. Jetzt ist es an der Zeit, die Domains innerhalb des Scopes zu finden.

_Bitte beachte, dass du mit den folgenden vorgeschlagenen Techniken auch Subdomains finden kannst und diese Informationen nicht unterschätzen solltest._

Zuerst solltest du nach der **Hauptdomain** jedes Unternehmens suchen. Zum Beispiel ist es für _Tesla Inc._ _tesla.com_.

### **Reverse DNS**

Da du alle IP-Bereiche der Domains gefunden hast, kannst du versuchen, **Reverse-DNS-Lookups** für diese **IPs durchzuführen, um weitere Domains innerhalb des Scopes zu finden**. Versuche, einen DNS-Server des Opfers oder einen bekannten DNS-Server (1.1.1.1, 8.8.8.8) zu verwenden.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Damit dies funktioniert, muss der Administrator PTR manuell aktivieren.\
Für diese Informationen können Sie auch ein Online-Tool verwenden: [http://ptrarchive.com/](http://ptrarchive.com).\
Für große Bereiche eignen sich Tools wie [**massdns**](https://github.com/blechschmidt/massdns) und [**dnsx**](https://github.com/projectdiscovery/dnsx), um Reverse Lookups und die Anreicherung der Ergebnisse zu automatisieren.

### **Reverse Whois (loop)**

In einem **whois** finden Sie viele interessante **Informationen**, etwa **Organisationsnamen**, **Adressen**, **E-Mail-Adressen**, Telefonnummern ... Noch interessanter ist jedoch, dass Sie **weitere mit dem Unternehmen verbundene Assets finden können**, wenn Sie **Reverse-Whois-Lookups anhand beliebiger dieser Felder durchführen** (beispielsweise andere Whois-Registrierungen, in denen dieselbe E-Mail-Adresse vorkommt).\
Sie können Online-Tools verwenden wie:

- [https://ip.thc.org/](https://ip.thc.org/) - **Kostenlos** (Web und API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Kostenlos**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Kostenlos**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Kostenlos**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web kostenlos, API kostenpflichtig.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Kostenpflichtig
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Kostenpflichtig (nur **100 kostenlose** Suchanfragen)
- [https://www.domainiq.com/](https://www.domainiq.com) - Kostenpflichtig
- [https://securitytrails.com/](https://securitytrails.com/) - Kostenpflichtig (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Kostenpflichtig (API)

Sie können diese Aufgabe mit [**DomLink** ](https://github.com/vysecurity/DomLink) automatisieren (ein whoxy-API-Schlüssel ist erforderlich).\
Mit [amass](https://github.com/OWASP/Amass) können Sie auch automatisch Reverse-Whois-Abfragen durchführen: `amass intel -d tesla.com -whois`

**Beachten Sie, dass Sie mit dieser Technik jedes Mal weitere Domainnamen entdecken können, wenn Sie eine neue Domain finden.**

### **Tracker**

Wenn Sie auf zwei verschiedenen Seiten **dieselbe ID desselben Trackers** finden, können Sie davon ausgehen, dass **beide Seiten** **vom selben Team verwaltet werden**.\
Wenn Sie beispielsweise auf mehreren Seiten dieselbe **Google-Analytics-ID** oder dieselbe **Adsense-ID** sehen.

Es gibt einige Seiten und Tools, mit denen Sie nach diesen und weiteren Trackern suchen können:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (findet verwandte Websites anhand gemeinsamer Analytics/Tracker)
- [**StackScan**](https://www.stackscan.com) - **Kostenlose Stufe** (Web und API). Suchen Sie nach beliebigen ausgelieferten Assets, nicht nur nach Tracker-IDs: einem Skriptpfad, dem Namen eines selbst gehosteten Bundles oder dem Host, von dem ein Asset geladen wird. Das Tool liefert alle Websites, auf denen es vorkommt.

Die API gibt den Stack für eine einzelne Domain zurück. Das ist hilfreich, um zu bestätigen, dass ein infrage kommendes Asset zum selben Bestand gehört:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Gibt jede erkannte Technologie mit ihrer Kategorie zurück. Asset-Pivoting ist derzeit nur für das Web verfügbar; die API deckt die Suche pro Domain ab.

### **Favicon**

Wusstest du, dass wir verwandte Domains und Subdomains unseres Ziels finden können, indem wir nach demselben Favicon-Hash suchen? Genau das macht das von [@m4ll0k2](https://twitter.com/m4ll0k2) entwickelte Tool [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py). So verwendest du es:

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

You kannst Favicon-Hashes auch in großem Umfang mit [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) abrufen und anschließend in Shodan/Censys pivotieren.

Behandle Favicon-Fingerprints als Hinweise und validiere sie anhand umliegender Signale.<sup>[[3]](#references)[[4]](#references)</sup>

- **Behandle den Hash als Indikator, nicht als Beweis**: MMH3 ist kompakt; Kollisionen, wiederverwendete Icons und gezielte Spoofing-Versuche sind möglich.
- **Untersuche mehr als nur** `/favicon.ico`: Prüfe Framework-/Build-Pfade, Manifest-Dateien, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, Inline-Data-URLs und HTML-`<link rel="icon">`-Tags.
- **Statische Assets können hinter WAF-/SSO-/IdP-Kontrollen weiterhin erreichbar sein**: Rufe das Icon direkt ab und prüfe `ETag`, `Last-Modified`, Weiterleitungen und Cache-Header.
- **Validiere Treffer anhand umliegender Signale**: Vergleiche Titel, HTML-/Body-Hash, Header, TLS-Zertifikatssubjekte/SANs, Produktkomponenten und offene Ports.
- **Gruppiere nach HTML-/Body-Hash**: Eine einheitliche Vorlage stärkt den Fingerprint; unterschiedliche Vorlagen deuten auf ein generisches oder gemeinsam genutztes Icon hin.
- **Behandle einen Hash, der in nicht zusammenhängenden Signaturen, Ports und Produkten auftaucht, als möglichen Honeypot oder Platzhalter.**
- **Vergleiche bei mehrdeutigen Zielen eine echte Seite mit einem nicht existierenden Pfad**, etwa `/_favicon_probe_<8-hex>`; übereinstimmende Hosting- oder Parking-Antworten können das gemeinsam genutzte Icon erklären.
- **Starte die Triage anhand von Nuclei-Erkennungsregeln oder öffentlichen Datensätzen**, die Favicon-Hashes Produkten und CPEs zuordnen.
- **Beachte die IP-zentrierte Abdeckungslücke**: CDN-geschützte, SNI-geroutete, Anycast- und nur über Domains erreichbare Oberflächen können in Shodan-ähnlichen Datensätzen fehlen.

### **Copyright / eindeutige Zeichenfolge**

Suche in den Webseiten nach **Zeichenfolgen, die auf verschiedenen Websites derselben Organisation vorkommen könnten**. Eine **Copyright-Zeichenfolge** ist ein gutes Beispiel. Suche dann in **Google**, anderen **Browsern** oder sogar in **Shodan** nach dieser Zeichenfolge: `shodan search http.html:"Copyright string"`

### **CRT-Zeit**

Häufig gibt es einen Cron-Job wie diesen:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

um alle Zertifikate auf einem Server gleichzeitig zu erneuern. Das Abgleichen von Zertifikat-Zeitstempeln oder Positionen in Certificate-Transparency-Logs kann verwandte Domains aufdecken.<sup>[[6]](#references)</sup>

Verwende auch direkt **Certificate-Transparency-Logs**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail-DMARC-Informationen

Du kannst eine Website wie [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oder ein Tool wie [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) verwenden, um **Domains und Subdomains zu finden, die dieselben DMARC-Informationen verwenden**.\
Weitere nützliche Tools sind [**spoofcheck**](https://github.com/BishopFox/spoofcheck) und [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Ein verwaister A-Record kann wieder erreichbar werden, wenn ein Cloud-Anbieter eine IP-Adresse neu vergibt. Die referenzierte Recherche beschreibt einen opportunistischen Workflow, bei dem eine Instanz bereitgestellt und ihre Adresse mit passiven DNS-Daten abgeglichen wird. Teste Takeover-Szenarien nur innerhalb des autorisierten Umfangs.<sup>[[7]](#references)</sup>

### **Weitere Möglichkeiten**

Wiederhole die geeigneten Discovery-Pivots jedes Mal, wenn du eine neue Domain findest: Jedes Ergebnis kann weitere Zertifikatsnamen, Passive-DNS-Beziehungen, Favicon-Übereinstimmungen und Organisationskennungen offenlegen, die mit dem ursprünglichen Ausgangspunkt nicht sichtbar waren.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Da du bereits den Namen der Organisation kennst, der der IP-Adressbereich gehört, kannst du in Shodan mit diesen Daten suchen: `org:"Tesla, Inc."` Prüfe die gefundenen Hosts auf neue, unerwartete Domains im TLS-Zertifikat.

Du kannst auf das **TLS-Zertifikat** der Hauptwebseite zugreifen, den **Organisationsnamen** ermitteln und anschließend in den **TLS-Zertifikaten** aller von **Shodan** erfassten Webseiten nach diesem Namen suchen, und zwar mit dem Filter: `ssl:"Tesla Motors"` oder mit einem Tool wie [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ist ein Tool, das nach **Domains sucht, die mit einer Hauptdomain verwandt sind**, sowie nach deren **Subdomains** – ziemlich beeindruckend.

**Passive DNS / Historisches DNS**

Passive-DNS-Daten eignen sich hervorragend, um **alte und vergessene Einträge zu finden**, die noch aufgelöst werden oder übernommen werden können. Siehe:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Suche nach Schwachstellen**

Prüfe auf [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Vielleicht **verwendet ein Unternehmen eine Domain**, hat aber **das Eigentum daran verloren**. Registriere sie einfach (sofern sie günstig genug ist) und informiere das Unternehmen.

Wenn du eine **Domain mit einer anderen IP-Adresse** als den bereits bei der Asset-Erkennung gefundenen entdeckst, solltest du einen **einfachen Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nachdem, welche Dienste laufen, findest du in **diesem Buch einige Tricks, um sie „anzugreifen“**.\
_Beachte, dass die Domain manchmal auf einer IP gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht zum Umfang gehört. Sei vorsichtig._

## Subdomains

> Wir kennen alle Unternehmen innerhalb des Umfangs, alle Assets der einzelnen Unternehmen und alle mit den Unternehmen verbundenen Domains.

Jetzt ist es an der Zeit, alle möglichen Subdomains jeder gefundenen Domain zu ermitteln.

> [!TIP]
> Beachte, dass einige Tools und Techniken zum Finden von Domains auch beim Finden von Subdomains helfen können.

### **DNS**

Versuchen wir, **Subdomains** aus den **DNS**-Einträgen zu ermitteln. Wir sollten auch einen **Zone Transfer** versuchen (falls dieser möglich ist, solltest du ihn melden).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

APIs und Plattformen, die Infrastruktur, Reputation, Breach-Daten und Anreicherung über die Subdomain-Erkennung hinaus abdecken, finden Sie im [Katalog für Reconnaissance- und Threat-Intelligence-APIs](reconnaissance-and-threat-intelligence-apis.md).

Am schnellsten erhalten Sie viele Subdomains, indem Sie in externen Quellen suchen. Die am häufigsten verwendeten **Tools** sind folgende (für bessere Ergebnisse sollten Sie die API-Schlüssel konfigurieren):


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

Es gibt **weitere interessante Tools/APIs**, die nützlich sein könnten, um Subdomains zu finden, auch wenn sie nicht direkt darauf spezialisiert sind, wie zum Beispiel:

- [**IP.THC.ORG**](https://ip.thc.org) kostenlose API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Nutzt die API [https://sonar.omnisint.io](https://sonar.omnisint.io), um Subdomains abzurufen.

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**Kostenlose JLDC-API**](https://jldc.me/anubis/subdomains/google.com)

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

- [**gau**](https://github.com/lc/gau)**:** Ruft bekannte URLs für eine beliebige Domain von AlienVault's Open Threat Exchange, der Wayback Machine und Common Crawl ab.

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

- [**securitytrails.com**](https://securitytrails.com/) bietet eine kostenlose API zur Suche nach Subdomains und IP-Verlauf
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Dieses Projekt bietet **kostenlos alle Subdomains zu Bug-Bounty-Programmen** an. Auf diese Daten kannst du auch über [chaospy](https://github.com/dr-0x0x/chaospy) zugreifen oder den von diesem Projekt verwendeten Scope unter [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) einsehen.

Einen **Vergleich** vieler dieser Tools findest du hier: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Versuchen wir, neue **Subdomains** zu finden, indem wir DNS-Server mit möglichen Subdomain-Namen per Brute-Force durchsuchen.

Dafür brauchst du einige **gängige Subdomain-Wordlists, zum Beispiel**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Außerdem benötigst du IPs zuverlässiger DNS-Resolver. Um eine Liste vertrauenswürdiger DNS-Resolver zu erstellen, kannst du die Resolver von [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) herunterladen und sie mit [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) filtern. Alternativ kannst du diese Liste verwenden: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Die für DNS Brute-force am häufigsten empfohlenen Tools sind:

- [**massdns**](https://github.com/blechschmidt/massdns): Dies war das erste Tool, das effektives DNS Brute-force ermöglichte. Es ist sehr schnell, erzeugt jedoch häufig False Positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Dieser verwendet meines Wissens nur einen Resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ist ein Wrapper um `massdns`, geschrieben in Go, mit dem sich gültige Subdomains per aktivem Brute-Force enumerieren lassen. Außerdem kann er Subdomains mit Wildcard-Behandlung und einfacher Ein-/Ausgabe-Unterstützung auflösen.

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

Nachdem du mithilfe offener Quellen und durch Brute-Forcing Subdomains gefunden hast, kannst du daraus Varianten generieren, um noch mehr zu finden. Dafür eignen sich mehrere Tools:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Generiert Permutationen aus den Domains und Subdomains.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Ausgehend von Domains und Subdomains Permutationen generieren.
  - Die goaltdns-Permutations-**wordlist** findest du [**hier**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Generiert Permutationen aus den angegebenen Domains und Subdomains. Wenn keine Datei mit Permutationen angegeben ist, verwendet gotator seine eigene.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Neben dem Generieren von Subdomain-Permutationen kann es auch versuchen, diese aufzulösen (dafür sind jedoch die zuvor erwähnten Tools besser).
  - Die **wordlist** für altdns-Permutationen findest du [**hier**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ein weiteres Tool zum Erstellen von Permutationen, Mutationen und Variationen von Subdomains. Dieses Tool brute-forced das Ergebnis (es unterstützt keine DNS-Wildcards).
  - Die Permutations-Wordlist für dmut findest du [**hier**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basierend auf einer Domain **generiert es anhand angegebener Muster neue potenzielle Subdomain-Namen**, um weitere Subdomains zu entdecken.

#### Generierung intelligenter Permutationen

- [**regulator**](https://github.com/cramppet/regulator): Lernt regex-ähnliche Muster aus entdeckten Subdomains und generiert Kandidatennamen, die aufgelöst werden sollen.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ ist ein Subdomain-Brute-Force-Fuzzer, der mit einem äußerst einfachen, aber effektiven DNS-Response-gesteuerten Algorithmus gekoppelt ist. Er nutzt bereitgestellte Eingabedaten, etwa eine maßgeschneiderte Wordlist oder historische DNS-/TLS-Records, um präzise weitere passende Domainnamen zu generieren und sie anhand der während des DNS-Scans gewonnenen Informationen in einer Schleife weiter zu erweitern.

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest-Workflow-Beispiele kombinieren OSINT, DNS-Brute-Force und Permutationsschritte für eine wiederholbare Subdomain-Enumeration.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Wenn du eine IP-Adresse gefunden hast, auf der sich **eine oder mehrere Webseiten** befinden, die zu Subdomains gehören, kannst du versuchen, **weitere Subdomains mit Webseiten auf dieser IP** zu **finden**, indem du in **OSINT-Quellen** nach Domains auf einer IP suchst oder **VHost-Domainnamen auf dieser IP per Brute Force ermittelst**.

#### OSINT

Du kannst **VHosts auf IPs mit** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **oder anderen APIs finden**.

**Brute Force**

Wenn du vermutest, dass sich eine Subdomain auf einem Webserver verbergen könnte, kannst du versuchen, sie per Brute Force zu ermitteln:

Bei namensbasierten VHosts kannst du den `Host`-Header fuzzing und die automatische Kalibrierung von ffuf verwenden, um die Standardantwort herauszufiltern.<sup>[[2]](#references)</sup>

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

Manchmal findest du Seiten, die den Header _**Access-Control-Allow-Origin**_ nur dann zurückgeben, wenn im Header _**Origin**_ eine gültige Domain/Subdomain angegeben ist. In solchen Fällen kannst du dieses Verhalten ausnutzen, um neue **Subdomains** zu **entdecken**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets per Brute Force**

Achte bei der Suche nach **Subdomains** darauf, ob diese auf irgendeine Art von **Bucket** **verweisen**. Falls ja, [**überprüfe die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Da du zu diesem Zeitpunkt alle Domains innerhalb des Scopes kennst, kannst du außerdem versuchen, [**mögliche Bucket-Namen per Brute Force zu ermitteln und die Berechtigungen zu überprüfen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Überwachung**

Du kannst überwachen, ob **neue Subdomains** einer Domain erstellt werden, indem du die **Certificate Transparency**-Logs überwachst, wie es [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) macht.

### **Suche nach Schwachstellen**

Prüfe auf mögliche [**Subdomain Takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Wenn die **Subdomain** auf einen **S3-Bucket** verweist, [**überprüfe die Berechtigungen**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Wenn du eine **Subdomain mit einer anderen IP-Adresse** als den bereits bei der Asset-Ermittlung gefundenen findest, solltest du einen **grundlegenden Schwachstellenscan** (mit Nessus oder OpenVAS) und einen [**Portscan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) mit **nmap/masscan/shodan** durchführen. Je nach den laufenden Diensten findest du in **diesem Buch einige Tricks, um sie „anzugreifen“**.\
_Beachte, dass die Subdomain manchmal auf einer IP-Adresse gehostet wird, die nicht vom Kunden kontrolliert wird und daher nicht zum Scope gehört. Sei vorsichtig._

## IPs

In den ersten Schritten hast du möglicherweise **einige IP-Bereiche, Domains und Subdomains gefunden**.\
Jetzt ist es an der Zeit, **alle IPs aus diesen Bereichen sowie die IPs der Domains/Subdomains (über DNS-Abfragen) zusammenzutragen**.

Mithilfe der folgenden **kostenlosen APIs** kannst du außerdem **frühere IPs finden, die von Domains und Subdomains verwendet wurden**. Diese IPs könnten dem Kunden weiterhin gehören (und dir möglicherweise dabei helfen, [**CloudFlare-Bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) zu finden).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Mit dem Tool [**hakip2host**](https://github.com/hakluke/hakip2host) kannst du außerdem nach Domains suchen, die auf eine bestimmte IP-Adresse verweisen.

### **Suche nach Schwachstellen**

Führe einen **Portscan für alle IPs durch, die nicht zu CDNs gehören** (da du dort höchstwahrscheinlich nichts Interessantes finden wirst). Bei den entdeckten laufenden Diensten kannst du möglicherweise **Schwachstellen finden**.

Hier findest du einen [**Leitfaden**](../pentesting-network/index.html) **zum Scannen von Hosts**.

## Suche nach Webservern

> Wir haben alle Unternehmen und ihre Assets gefunden und kennen die IP-Bereiche, Domains und Subdomains innerhalb des Scopes. Jetzt ist es an der Zeit, nach Webservern zu suchen.

In den vorherigen Schritten hast du wahrscheinlich bereits **eine Recon der entdeckten IPs und Domains durchgeführt** und möglicherweise **alle möglichen Webserver gefunden**. Falls nicht, sehen wir uns jetzt einige **schnelle Tricks an, um Webserver innerhalb des Scopes zu finden**.

Beachte, dass dies auf die **Erkennung von Web-Apps ausgerichtet** ist. Daher solltest du außerdem **Schwachstellen-Scans** und **Portscans** durchführen (**sofern vom Scope erlaubt**).

Eine **schnelle Methode**, um mithilfe von [**masscan offene Ports** von **Webservern** zu entdecken, findest du hier](../pentesting-network/index.html#http-port-discovery).\
Ein weiteres praktisches Tool zur Suche nach Webservern ist [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) und [**httpx**](https://github.com/projectdiscovery/httpx). Du übergibst einfach eine Liste mit Domains, und das Tool versucht, eine Verbindung zu Port 80 (http) und 443 (https) herzustellen. Zusätzlich kannst du weitere Ports angeben, die getestet werden sollen:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Nachdem du nun **alle Webserver** im Scope entdeckt hast (unter den **IPs** des Unternehmens und allen **Domains** und **Subdomains**), weißt du wahrscheinlich **nicht, wo du anfangen sollst**. Machen wir es also einfach und beginnen damit, Screenshots von allen zu erstellen. Schon ein **Blick** auf die **Hauptseite** kann **seltsame** Endpunkte aufdecken, die eher **anfällig** für **Schwachstellen** sind.

Für diese Idee kannst du [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oder [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** verwenden.

Außerdem kannst du anschließend [**eyeballer**](https://github.com/BishopFox/eyeballer) auf allen **Screenshots** ausführen, damit das Tool dir mitteilt, **welche wahrscheinlich Schwachstellen enthalten** und welche nicht.

## Public Cloud Assets

Um potenzielle Cloud Assets eines Unternehmens zu finden, solltest du **mit einer Liste von Schlüsselwörtern beginnen, die das Unternehmen identifizieren**. Für ein Krypto-Unternehmen könntest du beispielsweise Wörter wie `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` verwenden.

Außerdem benötigst du Wortlisten mit **häufig in Buckets verwendeten Wörtern**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Anschließend solltest du mit diesen Wörtern **Permutationen** generieren (weitere Informationen findest du unter [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Mit den daraus resultierenden Wortlisten kannst du Tools wie [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oder** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** verwenden.

Denk daran: Bei der Suche nach Cloud Assets solltest du **nach mehr als nur Buckets in AWS suchen**.

### **Suche nach Schwachstellen**

Wenn du Dinge wie **offene Buckets oder exponierte Cloud Functions** findest, solltest du **darauf zugreifen** und herausfinden, was sie anbieten und ob du sie missbrauchen kannst.

## Emails

Mit den **Domains** und **Subdomains** im Scope hast du im Grunde alles, was du **für die Suche nach Emails brauchst**. Mit diesen **APIs** und **Tools** habe ich die besten Ergebnisse bei der Suche nach Emails eines Unternehmens erzielt:

- [**theHarvester**](https://github.com/laramies/theHarvester) - mit APIs
- API von [**https://hunter.io/**](https://hunter.io/) (kostenlose Version)
- API von [**https://app.snov.io/**](https://app.snov.io/) (kostenlose Version)
- API von [**https://minelead.io/**](https://minelead.io/) (kostenlose Version)

### **Suche nach Schwachstellen**

Emails sind später beim **Brute-Force-Angriff auf Web-Logins und Auth-Dienste** (wie SSH) nützlich. Außerdem werden sie für **Phishing** benötigt. Darüber hinaus liefern dir diese APIs weitere **Informationen über die Person** hinter der Email, was für die Phishing-Kampagne nützlich ist.

## Credential Leaks

Mit den **Domains,** **Subdomains** und **Emails** kannst du nach Zugangsdaten suchen, die in der Vergangenheit geleakt wurden und zu diesen Emails gehören:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Suche nach Schwachstellen**

Wenn du **gültige geleakte** Zugangsdaten findest, ist das ein sehr einfacher Erfolg.

## Secrets Leaks

Credential Leaks stehen im Zusammenhang mit Hacks von Unternehmen, bei denen **sensible Informationen geleakt und verkauft wurden**. Unternehmen können jedoch auch von **anderen Leaks** betroffen sein, deren Informationen nicht in diesen Datenbanken auftauchen:

### Github Leaks

Zugangsdaten und APIs können in den **öffentlichen Repositories** des **Unternehmens** oder der **Mitarbeiter** dieses Unternehmens auf Github geleakt werden.\
Du kannst das **Tool** [**Leakos**](https://github.com/carlospolop/Leakos) verwenden, um alle **öffentlichen Repos** einer **Organisation** und ihrer **Entwickler** **herunterzuladen** und automatisch **gitleaks** darauf auszuführen.

**Leakos** kann auch verwendet werden, um **gitleaks** auf allen **Text-URLs** auszuführen, die ihm übergeben werden, da manchmal auch **Webseiten Secrets enthalten**.

#### Github Dorks

Auf der Seite [GitHub dorks and leaks](github-leaked-secrets.md) findest du potenzielle **GitHub dorks**, mit denen du die Organisation durchsuchen kannst.

### Pastes Leaks

Manchmal **veröffentlichen Angreifer oder einfach Mitarbeiter Unternehmensinhalte auf einer Paste-Seite**. Diese können **sensible Informationen enthalten oder auch nicht**, aber die Suche danach ist sehr interessant.\
Mit dem Tool [**Pastos**](https://github.com/carlospolop/Pastos) kannst du gleichzeitig auf mehr als 80 Paste-Seiten suchen.

### Google Dorks

Die altbewährten Google dorks sind immer hilfreich, um **exponierte Informationen zu finden, die dort nicht sein sollten**. Das einzige Problem ist, dass die [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) mehrere **Tausend** mögliche Suchanfragen enthält, die du nicht manuell ausführen kannst. Du kannst also deine zehn Favoriten auswählen oder ein **Tool wie** [**Gorks**](https://github.com/carlospolop/Gorks) **verwenden, um sie alle auszuführen**.

_Hinweis: Tools, die versuchen, die gesamte Datenbank über den normalen Google-Browser zu durchsuchen, werden nie fertig, da Google dich sehr schnell blockiert._

### **Suche nach Schwachstellen**

Wenn du **gültige geleakte** Zugangsdaten oder API-Tokens findest, ist das ein sehr einfacher Erfolg.

## Public Code Vulnerabilities

Wenn du herausgefunden hast, dass das Unternehmen **Open-Source-Code** hat, kannst du ihn **analysieren** und nach **Schwachstellen** suchen.

Je nach **Programmiersprache** gibt es verschiedene **Tools**, die du verwenden kannst. Siehe die Liste der [Source-Code-Review-Tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Es gibt auch kostenlose Dienste, mit denen du **öffentliche Repositories scannen** kannst, zum Beispiel:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting-Web-Methodik**](../../network-services-pentesting/pentesting-web/index.html)

Die **meisten von Bug Huntern gefundenen Schwachstellen** befinden sich in **Webanwendungen**. Deshalb möchte ich an dieser Stelle eine **Testmethodik für Webanwendungen** vorstellen. [**Hier findest du diese Informationen**](../../network-services-pentesting/pentesting-web/index.html).

Außerdem möchte ich besonders auf den Abschnitt [**Open-Source-Tools für automatisierte Web-Scanner**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) hinweisen. Auch wenn du nicht erwarten solltest, dass sie sehr sensible Schwachstellen finden, sind sie nützlich, um sie in **Workflows zu integrieren und erste Informationen über das Web zu sammeln.**

## Recapitulation

> Glückwunsch! An diesem Punkt hast du bereits **alle grundlegenden Enumerationsschritte** durchgeführt. Ja, sie sind grundlegend, denn es gibt noch viel mehr zu enumerieren (weitere Tricks folgen später).

Du hast also bereits:

1. Alle **Unternehmen** im Scope gefunden
2. Alle **Assets** der Unternehmen gefunden (und einen Vuln-Scan durchgeführt, sofern dieser im Scope liegt)
3. Alle **Domains** der Unternehmen gefunden
4. Alle **Subdomains** der Domains gefunden (mögliche Subdomain Takeovers?)
5. Alle **IPs** im Scope gefunden (sowohl von **CDNs** als auch nicht von **CDNs**).
6. Alle **Webserver** gefunden und einen **Screenshot** von ihnen erstellt (ist etwas Seltsames dabei, das genauer untersucht werden sollte?)
7. Alle **potenziellen Public-Cloud-Assets** des Unternehmens gefunden.
8. **Emails**, **Credential Leaks** und **Secret Leaks**, die dir **sehr leicht einen großen Erfolg verschaffen könnten**.
9. **Pentesting aller gefundenen Websites**

## **Vollständige automatische Recon-Tools**

Es gibt verschiedene Tools, die einige der vorgeschlagenen Aktionen für einen bestimmten Scope durchführen.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Etwas veraltet und nicht aktualisiert

## References

- [1] [Jason Haddix – Die Methodik eines Bug Hunters v4.0: Recon-Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Über Favicons: Von Browser-Icons zu Attack-Surface-Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.ico für Bug Bounties, OSINT und mehr als Waffe einsetzen](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Domains durch einen Zeitkorrelationsangriff auf Certificate Transparency entdecken](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Übernahme: Eine kostspielige Subdomain-Takeover-Kampagne aufdecken (und nachahmen)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Eine einzigartige Methode zur Subdomain-Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Vollständiger Workflow zur Subdomain-Erkennung, Teil 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Vollständige Brute-Force-Erkennung von Subdomains mit einem automatisierten Trickest-Workflow, Teil 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot der favihash-Ausgabe](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
