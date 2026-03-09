# Metodologia di External Recon

{{#include ../../banners/hacktricks-training.md}}

## Scoperta degli Assets

> Ti è stato detto che tutto ciò che appartiene a una certa azienda è nello scope, e vuoi capire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è ottenere tutte le **aziende possedute dalla società principale** e poi tutti gli **asset** di queste aziende. Per farlo, procederemo a:

1. Trovare le acquisizioni della società principale, questo ci darà le aziende nello scope.
2. Trovare l'ASN (se presente) di ogni azienda, questo ci darà i range IP posseduti da ciascuna azienda.
3. Usare reverse whois lookup per cercare altre voci (nomi di organizzazioni, domini...) correlate alla prima (ciò può essere fatto ricorsivamente).
4. Usare altre tecniche come shodan `org` e `ssl` filters per cercare altri asset (il trucco `ssl` può essere fatto ricorsivamente).

### **Acquisizioni**

Prima di tutto, dobbiamo sapere quali **altre aziende sono possedute dalla società principale**.\
Un'opzione è visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** la **società principale**, e **cliccare** su "**acquisizioni**". Lì vedrai altre aziende acquisite dalla principale.\
Un'altra opzione è visitare la pagina di **Wikipedia** della società principale e cercare le **acquisizioni**.\
Per le società pubbliche, controlla i **SEC/EDGAR filings**, le pagine delle **relazioni con gli investitori**, o i registri societari locali (es., **Companies House** nel Regno Unito).\
Per alberi societari globali e sussidiarie, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, a questo punto dovresti conoscere tutte le aziende nello scope. Vediamo come trovare i loro asset.

### **ASNs**

Un Autonomous System Number (**ASN**) è un **numero univoco** assegnato a un **sistema autonomo** (AS) dalla **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** è costituito da **blocchi** di **indirizzi IP** che condividono una policy definita per l'accesso alle reti esterne e sono amministrati da una singola organizzazione, ma possono essere composti da più operatori.

È utile scoprire se la **società ha assegnato qualche ASN** per individuare i suoi **range IP.** Sarà interessante eseguire un **test di vulnerabilità** su tutti gli **host** all'interno dello **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per **nome** dell'azienda, per **IP** o per **dominio** su [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione della società questi link possono essere utili per raccogliere più dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nord America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(America Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Comunque, probabilmente tutte le** informazioni utili **(range IP e Whois)** appaiono già nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Inoltre, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration raggruppa e riassume automaticamente gli ASNs alla fine della scan.
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
Puoi trovare gli intervalli IP di un'organizzazione anche usando [http://asnlookup.com/](http://asnlookup.com) (ha un'API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Ricerca di vulnerabilità**

A questo punto conosciamo **tutti gli asset all'interno del perimetro**, quindi se sei autorizzato potresti lanciare alcuni **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, potresti effettuare [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usare servizi come** Shodan, Censys, o ZoomEye **per trovare** porte aperte **e, a seconda di quello che trovi, dovresti** consultare questo libro per vedere come fare pentesting sui vari servizi possibili in esecuzione.\
Vale inoltre la pena menzionare che puoi anche preparare delle liste predefinite di default username e passwords e provare a bruteforce i servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende incluse nel perimetro e i loro asset, è ora di trovare i domini inclusi nel perimetro.

_Porta attenzione al fatto che nelle tecniche proposte di seguito puoi anche trovare subdomains e che queste informazioni non vanno sottovalutate._

Prima di tutto dovresti cercare il **main domain**(s) di ogni azienda. Per esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Una volta che hai trovato tutti gli intervalli IP dei domini potresti provare ad effettuare **reverse dns lookups** su quegli **IPs per trovare altri domini all'interno del perimetro**. Prova a usare il dns server della vittima o un dns server ben noto (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Perché questo funzioni, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche usare uno strumento online per queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com).\
Per range estesi, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare reverse lookups e l'enrichment.

### **Reverse Whois (loop)**

All'interno di un **whois** puoi trovare molte **informazioni** interessanti come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ancora più interessante è che puoi trovare **più asset correlati all'azienda** se esegui **reverse whois lookups per uno qualsiasi di questi campi** (per esempio altri registri whois dove appare la stessa email).\
Puoi usare strumenti online come:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratis** web, API a pagamento.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - A pagamento
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - A pagamento (solo **100 ricerche gratuite**)
- [https://www.domainiq.com/](https://www.domainiq.com) - A pagamento
- [https://securitytrails.com/](https://securitytrails.com/) - A pagamento (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - A pagamento (API)

Puoi automatizzare questo compito usando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una whoxy API key).\
Puoi anche eseguire una scoperta automatica di reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

Nota che puoi usare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Ad esempio, se vedi lo stesso **Google Analytics ID** o lo stesso **Adsense ID** su più pagine.

Esistono alcune pagine e strumenti che ti permettono di cercare per questi tracker e altro:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trova siti correlati tramite analytics/trackers condivisi)

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro target cercando lo stesso hash del favicon? Questo è esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In parole semplici, favihash ci permetterà di scoprire domini che hanno lo stesso favicon icon hash del nostro target.

Inoltre, è anche possibile cercare tecnologie usando il favicon hash come spiegato in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Ciò significa che se conosci il **hash del favicon di una versione vulnerabile di una web tech** puoi cercarlo in shodan e **trovare altri posti vulnerabili**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ecco come puoi **calculate the favicon hash** di un sito web:
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
Puoi anche ottenere gli hash dei favicon su larga scala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e poi pivotare in Shodan/Censys.

### **Copyright / Uniq string**

Cerca all'interno delle pagine web **stringhe che potrebbero essere condivise tra diversi siti della stessa organizzazione**. La **stringa di copyright** potrebbe essere un buon esempio. Poi cerca quella stringa su **google**, in altri **browser** o anche su **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

È comune avere un cron job come
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
per rinnovare tutti i certificati dei domini sul server. Questo significa che, anche se la CA usata per questo non imposta l'ora in cui è stato generato nel campo Validity, è possibile **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni DMARC della mail

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Altri metodi**

**Nota che puoi usare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Sottodomini

> Conosciamo tutte le aziende dentro lo scope, tutti gli asset di ogni azienda e tutti i domini collegati alle aziende.

È tempo di trovare tutti i possibili subdomains di ogni dominio trovato.

> [!TIP]
> Nota che alcuni degli strumenti e delle tecniche per trovare domini possono anche aiutare a trovare subdomains

### **DNS**

Proviamo a ottenere **subdomains** dai record **DNS**. Dovremmo anche provare per un **Zone Transfer** (Se vulnerabile, dovresti segnalarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più veloce per ottenere molti subdomains è cercare in fonti esterne. I **tools** più usati sono i seguenti (per risultati migliori configura le API keys):

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
Ci sono **altri strumenti/API interessanti** che, anche se non sono direttamente specializzati nel trovare subdomains, possono essere utili per trovare subdomains, come:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC API gratuita**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) API gratuita
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
- [**gau**](https://github.com/lc/gau)**:** recupera URL noti da AlienVault's Open Threat Exchange, the Wayback Machine e Common Crawl per qualsiasi dominio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Scansionano il web cercando file JS ed estraggono subdomains da lì.
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
- [**securitytrails.com**](https://securitytrails.com/) ha un'API gratuita per cercare subdomains e la cronologia degli IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre **gratuitamente tutti i subdomains relativi ai bug-bounty programs**. Puoi accedere a questi dati anche usando [chaospy](https://github.com/dr-0x0x/chaospy) o consultare lo scope usato da questo progetto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare un **confronto** di molti di questi strumenti qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **subdomains** effettuando brute-force sui server DNS usando possibili nomi di subdomain.

Per questa azione avrai bisogno di alcune **common wordlists per subdomains, come**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche gli IP di buoni DNS resolvers. Per generare una lista di DNS resolvers affidabili puoi scaricare i resolver da [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. Oppure puoi usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più raccomandati per DNS brute-force sono:

- [**massdns**](https://github.com/blechschmidt/massdns): Questo è stato il primo tool che ha effettuato un DNS brute-force efficace. È molto veloce, tuttavia è soggetto a false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Questo, penso, usa solo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper per `massdns`, scritto in go, che permette di enumerare sottodomini validi usando active bruteforce, oltre a risolvere sottodomini con wildcard handling e con semplice supporto input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Usa anche `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio per effettuare brute force sui nomi di dominio in modo asincrono.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Secondo round di DNS Brute-Force

Dopo aver trovato sottodomini usando fonti pubbliche e brute-forcing, puoi generare variazioni dei sottodomini trovati per cercarne ancora di più. Diversi strumenti sono utili a questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dati i domini e i sottodomini, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): A partire da domini e sottodomini, genera permutazioni.
- Puoi ottenere la **wordlist** delle permutazioni di goaltdns in [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Data una lista di domini e sottodomini, genera permutazioni. Se non viene indicato un file di permutazioni, gotator userà il proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di subdomains, può anche provare a risolverle (ma è meglio usare gli strumenti citati in precedenza).
- Puoi ottenere la **wordlist** delle permutazioni di altdns in [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per eseguire permutazioni, mutazioni e alterazioni dei subdomains. Questo strumento esegue brute force sui risultati (non supporta dns wild card).
- Puoi ottenere la wordlist di permutazioni di dmut in [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basandosi su un dominio, genera nuovi potenziali nomi di subdomains basati sui pattern indicati per provare a scoprire altri subdomains.

#### Generazione intelligente di permutazioni

- [**regulator**](https://github.com/cramppet/regulator): Per maggiori informazioni leggi questo [**post**](https://cramppet.github.io/regulator/index.html) ma fondamentalmente prenderà le **parti principali** dai **subdomains scoperti** e le mescolerà per trovare altri subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un subdomain brute-force fuzzer abbinato a un algoritmo DNS response-guided estremamente semplice ma efficace. Utilizza un set di input fornito, come una wordlist personalizzata o record DNS/TLS storici, per sintetizzare con precisione ulteriori nomi di dominio corrispondenti ed espanderli ancora di più in un ciclo basato sulle informazioni raccolte durante il DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Leggi questo post del blog che ho scritto su come **automate the subdomain discovery** da un dominio usando **Trickest workflows** così non devo avviare manualmente una serie di tools sul mio computer:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Se trovi un indirizzo IP che ospita **one or several web pages** appartenenti a subdomains, puoi provare a **find other subdomains with webs in that IP** cercando nelle **OSINT sources** domini associati all'IP oppure effettuando un **brute-forcing VHost domain names in that IP**.

#### OSINT

Puoi trovare alcuni **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**.

**Brute Force**

Se sospetti che qualche subdomain possa essere nascosto in un web server, puoi provare a brute forcearlo:

When the **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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
> Con questa tecnica potresti persino riuscire ad accedere a endpoint interni/nascosti.

### **CORS Brute Force**

A volte troverai pagine che restituiscono solo l'header _**Access-Control-Allow-Origin**_ quando nel header _**Origin**_ è impostato un domain/subdomain valido. In questi scenari puoi abusare di questo comportamento per **scoprire** nuovi **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mentre cerchi **subdomains** presta attenzione se stanno **pointing** a qualche tipo di **bucket**, e in tal caso [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, dato che a questo punto conoscerai tutti i domini all'interno dello scope, prova a [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoraggio**

Puoi **monitorare** se vengono creati **nuovi subdomains** di un dominio controllando i **Certificate Transparency** Logs come fa [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Ricerca di vulnerabilità**

Controlla la presenza di possibili [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdomain** sta **pointing** a qualche **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi qualche **subdomain with an IP different** rispetto a quelli già individuati durante l'asset discovery, dovresti eseguire una **basic vulnerability scan** (usando Nessus o OpenVAS) e qualche [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, in **this book** puoi trovare alcuni trucchi per "attack" them.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

Nei primi passi potresti aver **trovato alcuni IP ranges, domains and subdomains**.\
È il momento di **recolect all the IPs from those ranges** e per i **domains/subdomains (DNS queries).**

Usando servizi dalle seguenti **API gratuite** puoi anche trovare **precedenti IPs usati da domains e subdomains**. Questi IP potrebbero ancora essere di proprietà del cliente (e potrebbero permetterti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche controllare quali domini puntano a un IP specifico usando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Ricerca di vulnerabilità**

**Port scan all the IPs that doesn’t belong to CDNs** (dato che molto probabilmente non troverai nulla di interessante lì). Nei servizi in esecuzione scoperti potresti **riuscire a trovare vulnerabilità**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Abbiamo trovato tutte le aziende e i loro asset e conosciamo gli IP ranges, i domains e i subdomains all'interno dello scope. È ora di cercare web servers.

Nei passi precedenti probabilmente hai già eseguito del **recon sugli IPs e domains scoperti**, quindi potresti aver **già trovato tutti i possibili web servers**. Tuttavia, se non l'hai fatto, ora vedremo alcuni **trucchi veloci per cercare web servers** all'interno dello scope.

Nota che questo sarà **orientato alla scoperta di web app**, quindi dovresti anche **eseguire vulnerability e port scanning** (**se consentito** dallo scope).

Un **metodo veloce** per scoprire **porte aperte** relative a **web** server usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento utile per cercare web servers è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Basta fornire una lista di domini e proverà a connettersi alle porte 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Ora che hai scoperto **all the web servers** presenti nello scope (tra le **IPs** dell'azienda e tutti i **domains** e **subdomains**), probabilmente non sai da dove cominciare. Quindi, facciamo semplice e iniziamo semplicemente prendendo screenshot di tutti. Solo dando un'occhiata alla **main page** puoi trovare endpoint **weird** che sono più **prone** a essere **vulnerable**.

Per realizzare l'idea proposta puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, puoi poi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) per analizzare tutti gli **screenshots** e dirti **quello che probabilmente contiene vulnerabilities**, e cosa no.

## Risorse Cloud Pubbliche

Per trovare potenziali cloud assets appartenenti a un'azienda dovresti **iniziare con una lista di keywords che identificano quell'azienda**. Per esempio, per una crypto company potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ti serviranno anche wordlist di **parole comuni usate in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con quelle parole dovresti generare **permutazioni** (vedi la [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) per maggiori informazioni).

Con le wordlist risultanti puoi usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che quando cerchi Cloud Assets dovresti **look for more than just buckets in AWS**.

### **Ricerca di vulnerabilità**

Se trovi cose come **open buckets or cloud functions exposed** dovresti **accedervi** e provare a vedere cosa ti offrono e se puoi abusarne.

## Email

Con i **domains** e i **subdomains** nello scope hai praticamente tutto ciò che ti **serve per iniziare a cercare email**. Queste sono le **APIs** e gli **tools** che hanno funzionato meglio per me per trovare le email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API di [**https://hunter.io/**](https://hunter.io/) (versione free)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione free)
- API di [**https://minelead.io/**](https://minelead.io/) (versione free)

### **Ricerca di vulnerabilità**

Le email saranno utili più avanti per **brute-force web logins and auth services** (come SSH). Inoltre, sono necessarie per i **phishings**. Inoltre queste API ti daranno ancora più **info about the person** dietro l'email, utile per la campagna di phishing.

## Leak di credenziali

Con i **domains,** **subdomains**, e le **emails** puoi iniziare a cercare credenziali leaked in passato appartenenti a quelle email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Ricerca di vulnerabilità**

Se trovi **valid leaked** credentials, questa è una vittoria molto semplice.

## Leak di segreti

I credential leaks sono legati ad hack di aziende dove **sensitive information was leaked and sold**. Tuttavia, le aziende potrebbero essere affette da **other leaks** le cui info non sono in quei database:

### Github Leaks

Credentials e API potrebbero essere leaked nei **public repositories** dell'**azienda** o degli **users** che lavorano per quell'organizzazione su GitHub.\
Puoi usare lo **tool** [**Leakos**](https://github.com/carlospolop/Leakos) per **download** tutti i **public repos** di un'**organization** e dei suoi **developers** e lanciare [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi automaticamente.

**Leakos** può anche essere usato per eseguire **gitleaks** contro tutti gli **URL** di testo forniti passati allo strumento poiché a volte anche le **web pages** contengono secrets.

#### Github Dorks

Controlla anche questa **page** per potenziali **github dorks** che potresti cercare nell'organization che stai attaccando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A volte attacker o semplicemente dipendenti pubblicheranno **company content in a paste site**. Questo potrebbe contenere o meno **sensitive information**, ma è molto interessante cercarlo.\
Puoi usare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare in più di 80 paste sites contemporaneamente.

### Google Dorks

I vecchi ma validi google dorks sono sempre utili per trovare **exposed information that shouldn't be there**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **thousands** di possibili query che non puoi eseguire manualmente. Quindi, puoi prendere le tue 10 preferite oppure puoi usare un **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirle tutte**.

_Nota che gli strumenti che cercano di eseguire l'intero database usando il normale browser Google non finiranno mai perché google ti bloccherà molto molto presto._

### **Ricerca di vulnerabilità**

Se trovi **valid leaked** credentials o API tokens, questa è una vittoria molto facile.

## Vulnerabilità in codice pubblico

Se scopri che l'azienda ha **open-source code** puoi **analizzarlo** e cercare **vulnerabilities** al suo interno.

**A seconda del linguaggio** ci sono diversi **tools** che puoi usare:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ci sono anche servizi gratuiti che ti permettono di **scan public repositories**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilities** trovate dai bug hunter risiede all'interno delle **web applications**, quindi a questo punto vorrei parlare di una **web application testing methodology**, e puoi [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

Voglio anche fare una menzione speciale alla sezione [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), poiché, anche se non dovresti aspettarti che trovino vulnerabilità molto sensibili, sono comodi da integrare nelle **workflows** per ottenere alcune informazioni web iniziali.

## Ricapitolazione

> Congratulazioni! A questo punto hai già eseguito **all the basic enumeration**. Sì, è basico perché si può fare molta più enumeration (vedremo altri trucchi più avanti).

Quindi hai già:

1. Trovato tutte le **companies** nello scope
2. Trovato tutti gli **assets** appartenenti alle companies (e eseguito qualche vuln scan se in scope)
3. Trovato tutti i **domains** appartenenti alle companies
4. Trovato tutti i **subdomains** dei domains (possibile subdomain takeover?)
5. Trovato tutte le **IPs** (da e non da CDN) nello scope.
6. Trovato tutti i **web servers** e ne hai preso uno **screenshot** (qualcosa di weird che valga un'analisi più approfondita?)
7. Trovato tutti i **potential public cloud assets** appartenenti all'azienda.
8. **Emails**, **credentials leaks**, e **secret leaks** che potrebbero darti una **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Ci sono diversi strumenti che eseguiranno parte delle azioni proposte contro uno scope dato.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' vecchio e non aggiornato

## **Riferimenti**

- Tutti i corsi gratuiti di [**@Jhaddix**](https://twitter.com/Jhaddix) come [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
