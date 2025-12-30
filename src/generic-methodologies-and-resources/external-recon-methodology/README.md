# Metodologia di External Recon

{{#include ../../banners/hacktricks-training.md}}

## Individuazione degli asset

> Quindi ti è stato detto che tutto ciò che appartiene a una certa azienda è incluso nel scope, e vuoi capire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è ottenere tutte le **aziende possedute dalla company principale** e poi tutti gli **asset** di queste aziende. Per farlo, faremo:

1. Trovare le acquisizioni della company principale, questo ci darà le aziende dentro lo scope.
2. Trovare l'ASN (se presente) di ogni azienda, questo ci darà i range IP posseduti da ogni azienda
3. Usare reverse whois lookups per cercare altre voci (nomi di organizzazioni, domini...) correlate alla prima (questo può essere fatto ricorsivamente)
4. Usare altre tecniche come filtri shodan `org` e `ssl` per cercare altri asset (il trick `ssl` può essere fatto ricorsivamente).

### **Acquisizioni**

Prima di tutto, dobbiamo sapere quali **altre aziende sono possedute dalla company principale**.\
Un'opzione è visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** la **company principale**, e **cliccare** su "**acquisizioni**". Lì vedrai altre aziende acquisite da quella principale.\
Un'altra opzione è visitare la pagina di **Wikipedia** della company principale e cercare le **acquisizioni**.\
Per le società quotate, controlla i **filings SEC/EDGAR**, le pagine di **investor relations**, o i registri societari locali (es., **Companies House** nel Regno Unito).\
Per alberi societari globali e sussidiarie, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, a questo punto dovresti conoscere tutte le aziende dentro lo scope. Vediamo come trovare i loro asset.

### **ASNs**

Un autonomous system number (**ASN**) è un **numero univoco** assegnato a un **sistema autonomo** (AS) dall'**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste di **blocchi** di **IP addresses** che hanno una policy chiaramente definita per accedere a reti esterne e sono amministrati da una singola organizzazione ma possono essere composti da diversi operatori.

È interessante verificare se la **company ha assegnato qualche ASN** per trovare i suoi **range IP.** Sarà utile eseguire un **vulnerability test** contro tutti gli **hosts** dentro lo **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per nome della company, per **IP** o per **dominio** su [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione della company questi link potrebbero essere utili per raccogliere più dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Comunque, probabilmente tutte le** informazioni utili **(range IP e Whois)** appaiono già nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Inoltre, l'enumerazione di [**BBOT**](https://github.com/blacklanternsecurity/bbot) aggrega e riassume automaticamente gli ASNs alla fine della scansione.
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
Puoi trovare gli IP ranges di un'organizzazione anche usando [http://asnlookup.com/](http://asnlookup.com) (ha un'API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Cercare vulnerabilità**

A questo punto conosciamo **tutti gli assets nello scope**, quindi se sei autorizzato potresti lanciare qualche **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, potresti eseguire alcuni [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usare servizi come** Shodan, Censys, o ZoomEye **per trovare** porte aperte **e a seconda di ciò che trovi dovresti** consultare questo libro per sapere come pentestare i vari servizi in esecuzione.\
**Vale anche la pena menzionare che puoi preparare alcune** default username **e** passwords **lists e provare a** bruteforce **i servizi con** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende nello scope e i loro asset, è ora di trovare i domini nello scope.

_Per favore, nota che nelle tecniche proposte qui sotto puoi anche trovare sottodomini e che queste informazioni non dovrebbero essere sottovalutate._

Prima di tutto dovresti cercare il **main domain**(s) di ogni azienda. Per esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Poiché hai trovato tutti gli IP ranges dei domini potresti provare ad eseguire **reverse dns lookups** su quegli **IPs per trovare più domini nello scope**. Prova a usare qualche dns server della vittima o qualche dns server ben noto (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Perché questo funzioni, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche usare uno strumento online per queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com).\
Per intervalli estesi, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare ricerche inverse e l'arricchimento.

### **Reverse Whois (loop)**

All'interno di un **whois** puoi trovare molte **informazioni** interessanti come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ancora più interessante è che puoi trovare **altri asset correlati all'azienda** se esegui delle **reverse whois lookups su uno qualsiasi di questi campi** (per esempio altri registri whois dove appare la stessa email).\
Puoi usare strumenti online come:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratis** web, API non gratuita.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Non gratuito
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Non gratuito (solo **100 ricerche gratuite**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Non gratuito
- [https://securitytrails.com/](https://securitytrails.com/) - Non gratuito (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Non gratuito (API)

Puoi automatizzare questo compito usando [**DomLink** ](https://github.com/vysecurity/DomLink) (richiede una API key di whoxy).\
Puoi anche eseguire una scoperta automatica di reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi usare questa tecnica per scoprire altri nomi di dominio ogni volta che trovi un nuovo dominio.**

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Per esempio, se vedi lo stesso **Google Analytics ID** o lo stesso **Adsense ID** su più pagine.

Esistono alcune pagine e strumenti che permettono di cercare tramite questi tracker e altro:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trova siti correlati tramite analytics/trackers condivisi)

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro target cercando lo stesso hash dell'icona favicon? Questo è esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - scopri domini con lo stesso favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In poche parole, favihash ci permetterà di scoprire domini che hanno lo stesso favicon icon hash del nostro target.

Inoltre, puoi anche cercare tecnologie utilizzando il favicon hash come spiegato in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Ciò significa che se conosci il **hash of the favicon of a vulnerable version of a web tech** puoi cercarlo in shodan e **find more vulnerable places**:
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
Puoi anche ottenere favicon hashes su larga scala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e poi pivot in Shodan/Censys.

### **Copyright / Stringa univoca**

Cerca all'interno delle pagine web stringhe che potrebbero essere condivise tra diversi siti della stessa organizzazione. La stringa di copyright può essere un buon esempio. Poi cerca quella stringa su Google, in altri browser o anche su shodan: `shodan search http.html:"Copyright string"`

### **CRT Time**

È comune avere un cron job come
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
per rinnovare tutti i certificati di dominio sul server. Ciò significa che anche se la CA usata per questo non imposta l'ora di generazione nel campo Validity, è possibile **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni DMARC della mail

Puoi usare un sito web come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e subdomain che condividono le stesse informazioni DMARC**.\
Altri strumenti utili sono [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparentemente è comune che le persone assegnino subdomains a indirizzi IP che appartengono a cloud provider e, a un certo punto, **lose that IP address but forget about removing the DNS record**. Pertanto, semplicemente **spawning a VM** in un cloud (come Digital Ocean) ti porterà effettivamente a **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) spiega la storia a riguardo e propone uno script che **spawns a VM in DigitalOcean**, **gets** the **IPv4** della nuova macchina, e **searches in Virustotal for subdomain records** che puntano ad essa.

### **Other ways**

**Nota che puoi usare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.**

**Shodan**

Dato che conosci già il nome dell'organizzazione che possiede lo spazio IP, puoi cercare quel dato in shodan usando: `org:"Tesla, Inc."` Controlla gli host trovati per eventuali nuovi domini inattesi nel TLS certificate.

Puoi accedere al **TLS certificate** della pagina principale, ottenere il nome dell'organizzazione e poi cercare quel nome all'interno dei **TLS certificates** di tutte le pagine web note da **shodan** con il filtro: `ssl:"Tesla Motors"` oppure usare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) è uno strumento che cerca **domains related** con un dominio principale e i suoi **subdomains**, davvero notevole.

**Passive DNS / Historical DNS**

I dati di Passive DNS sono ottimi per trovare **old and forgotten records** che ancora risolvono o che possono essere taken over. Guarda:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Controlla per un [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Forse qualche azienda sta usando un dominio ma ha **lost the ownership**. Registralo (se è sufficientemente economico) e avvisa l'azienda.

Se trovi qualche **domain with an IP different** rispetto a quelli già trovati nella discovery degli asset, dovresti eseguire una **basic vulnerability scan** (usando Nessus o OpenVAS) e qualche [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione puoi trovare in **this book some tricks to "attack" them**.\
_Nota che a volte il dominio è ospitato su un IP non controllato dal cliente, quindi non è in scope — fai attenzione._

## Subdomains

> Sappiamo tutte le aziende all'interno dello scope, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È ora di trovare tutti i possibili subdomains di ogni dominio trovato.

> [!TIP]
> Nota che alcuni degli strumenti e delle tecniche per trovare domini possono anche aiutare a trovare subdomains

### **DNS**

Proviamo a ottenere **subdomains** dai record **DNS**. Dovremmo anche provare un **Zone Transfer** (se vulnerabile, va segnalato).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più veloce per ottenere molti sottodomini è cercare in fonti esterne. Gli **tools** più usati sono i seguenti (per risultati migliori configura le API keys):

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
Ci sono **altri strumenti/API interessanti** che, anche se non direttamente specializzati nel trovare sottodomini, potrebbero essere utili per trovare sottodomini, come:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere sottodomini
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
- [**gau**](https://github.com/lc/gau)**:** recupera gli URL noti da AlienVault's Open Threat Exchange, the Wayback Machine e Common Crawl per qualsiasi dominio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Scansionano il web alla ricerca di JS files e estraggono subdomains da lì.
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
- [**securitytrails.com**](https://securitytrails.com/) ha un'API gratuita per cercare subdomains e IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre **gratuitamente tutti i subdomains relativi ai bug-bounty programs**. Puoi accedere a questi dati anche usando [chaospy](https://github.com/dr-0x0x/chaospy) o persino accedere allo scope usato da questo progetto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare un **confronto** di molti di questi strumenti qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **subdomains** effettuando brute-force sui server DNS usando possibili nomi di subdomains.

Per questa azione avrai bisogno di alcune wordlists comuni per subdomains come:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche gli IP di buoni DNS resolvers. Per generare una lista di DNS resolvers affidabili puoi scaricare i resolvers da [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. Oppure puoi usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più consigliati per il DNS brute-force sono:

- [**massdns**](https://github.com/blechschmidt/massdns): Questo è stato il primo strumento che ha eseguito un DNS brute-force efficace. È molto veloce ma soggetto a false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Penso che questo usi solo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper attorno a `massdns`, scritto in go, che permette di enumerare sottodomini validi usando active bruteforce, oltre a risolvere sottodomini con gestione dei wildcard e semplice supporto input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Utilizza anche `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio per effettuare brute force sui nomi di dominio in modo asincrono.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Secondo round di DNS Brute-Force

Dopo aver trovato subdomains usando fonti aperte e brute-forcing, puoi generare variazioni dei subdomains trovati per provare a trovarne altri. Diversi strumenti sono utili a questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Data una lista di domains e subdomains, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dati i domini e i sottodomini, genera permutazioni.
- Puoi ottenere la **wordlist** delle permutazioni di goaltdns in [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati i domini e i sottodomini genera permutazioni. Se non viene indicato un file di permutazioni, gotator utilizzerà il proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare subdomains permutations, può anche provare a risolverle (ma è meglio usare i tool commentati precedentemente).
- Puoi ottenere la altdns permutations **wordlist** in [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un altro tool per eseguire permutations, mutations e alteration di subdomains. Questo tool eseguirà brute force sul risultato (non supporta dns wild card).
- Puoi ottenere la wordlist di permutations di dmut da [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basato su un dominio, **genera nuovi potenziali nomi di subdomains** basandosi sui pattern indicati per provare a scoprire altri subdomains.

#### Generazione intelligente di permutazioni

- [**regulator**](https://github.com/cramppet/regulator): Per maggiori informazioni leggi questo [**post**](https://cramppet.github.io/regulator/index.html) ma fondamentalmente prenderà le **parti principali** dai **subdomains scoperti** e le mescolerà per trovare altri subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un subdomain brute-force fuzzer accoppiato a un algoritmo estremamente semplice ma efficace guidato dalle risposte DNS. Utilizza un set di input fornito, come una wordlist su misura o record storici DNS/TLS, per sintetizzare con precisione altri nomi di dominio corrispondenti ed espanderli ulteriormente in un loop basato sulle informazioni raccolte durante il DNS scan.
```
echo www | subzuf facebook.com
```
### **Workflow di scoperta dei sottodomini**

Leggi questo post del blog che ho scritto su come **automatizzare la scoperta dei sottodomini** di un dominio usando **Trickest workflows**, così non devo avviare manualmente una serie di tool sul mio computer:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Host virtuali**

Se trovi un indirizzo IP che ospita **una o più pagine web** appartenenti a sottodomini, puoi provare a **trovare altri sottodomini con siti in quell'IP** cercando in **fonti OSINT** domini associati a quell'IP oppure facendo **brute-forcing dei nomi di dominio VHost su quell'IP**.

#### OSINT

Puoi trovare alcuni **VHosts in un IP usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre API**.

**Brute Force**

Se sospetti che qualche sottodominio possa essere nascosto su un web server, puoi provare a forzarlo con brute force:
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

A volte troverai pagine che restituiscono l'header _**Access-Control-Allow-Origin**_ solo quando un domain/subdomain valido è impostato nell'header _**Origin**_. In questi scenari, puoi abusare di questo comportamento per **scoprire** nuovi **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mentre cerchi i **subdomains** fai attenzione se è **pointing** a qualche tipo di **bucket**, e in quel caso [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, dato che a questo punto conoscerai tutti i domini nello scope, prova a [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Puoi **monitor** se vengono creati **new subdomains** di un dominio monitorando i **Certificate Transparency** Logs. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) lo fa.

### **Looking for vulnerabilities**

Controlla eventuali [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdomain** è **pointing** a qualche **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi un **subdomain with an IP different** rispetto a quelli già trovati durante l'asset discovery, dovresti eseguire una **basic vulnerability scan** (usando Nessus o OpenVAS) e qualche [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione puoi trovare in **this book some tricks to "attack" them**.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

Nei passaggi iniziali potresti aver **found some IP ranges, domains and subdomains**.\
È il momento di **recollect all the IPs from those ranges** e per i **domains/subdomains (DNS queries).**

Usando i servizi dei seguenti **free apis** puoi anche trovare **previous IPs used by domains and subdomains**. Questi IP potrebbero ancora essere di proprietà del cliente (e potrebbero permetterti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche verificare i domini che puntano a un indirizzo IP specifico usando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (dato che molto probabilmente lì non troverai nulla di interessante). Nei servizi in esecuzione scoperti potresti essere **able to find vulnerabilities**.

Trova una [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Abbiamo trovato tutte le aziende e i loro asset e conosciamo gli IP ranges, domains e subdomains nello scope. È tempo di cercare web servers.

Nei passaggi precedenti probabilmente hai già eseguito del **recon of the IPs and domains discovered**, quindi potresti aver **already found all the possible web servers**. Tuttavia, se non l'hai fatto, vedremo ora alcuni **fast tricks to search for web servers** all'interno dello scope.

Nota che questo sarà **oriented for web apps discovery**, quindi dovresti **perform the vulnerability** e **port scanning** anche (**if allowed** dallo scope).

Un **fast method** per scoprire **ports open** relativi a server **web** usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento utile per trovare web servers è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Passi semplicemente una lista di domini e tenterà di connettersi alla porta 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Ora che hai scoperto **tutti i web server** presenti nel perimetro (tra gli **IPs** dell'azienda e tutti i **domains** e **subdomains**) probabilmente **non sai da dove iniziare**. Quindi facciamo semplice e iniziamo scattando screenshot di tutti. Basta dare un'occhiata alla **pagina principale** per trovare endpoint **strani** che sono più **propensi** ad essere **vulnerabili**.

Per realizzare questa idea puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, puoi poi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) per analizzare tutti gli **screenshot** e dirti **cosa è probabile contenga vulnerabilità**, e cosa no.

## Risorse Cloud Pubbliche

Per trovare potenziali cloud assets appartenenti a un'azienda dovresti **iniziare con una lista di parole chiave che identificano quell'azienda**. Per esempio, per una crypto o azienda crypto potresti usare parole come: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Avrai anche bisogno di wordlist di **parole comuni usate nei buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con quelle parole dovresti generare **permutazioni** (controlla la [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) per maggiori informazioni).

Con le wordlist risultanti puoi usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che quando cerchi Cloud Assets dovresti **cercare più di semplici buckets in AWS**.

### **Looking for vulnerabilities**

Se trovi elementi come **open buckets o cloud functions esposte** dovresti **accedervi** e provare a vedere cosa ti offrono e se puoi abusarne.

## Emails

Con i **domains** e i **subdomains** nel perimetro hai fondamentalmente tutto ciò di cui hai **bisogno per iniziare a cercare emails**. Queste sono le **APIs** e gli **tools** che hanno funzionato meglio per me per trovare le email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Le email saranno utili più avanti per **brute-force web logins and auth services** (come SSH). Inoltre, sono necessarie per i **phishings**. Inoltre, queste API ti forniranno anche più **info about the person** dietro l'email, cosa utile per la campagna di phishing.

## Credential Leaks

Con i **domains,** **subdomains**, e le **emails** puoi iniziare a cercare credentials leaked in passato appartenenti a quegli indirizzi:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Se trovi **valid leaked** credentials, questa è una vittoria molto semplice.

## Secrets Leaks

I Credential Leaks sono legati a compromissioni di aziende dove informazione sensibile è stata leaked e venduta. Tuttavia, le aziende potrebbero essere colpite da altri leak le cui informazioni non sono in quei database:

### Github Leaks

Credentials e API potrebbero essere leaked nei **public repositories** della **company** o degli **users** che lavorano per quella azienda su GitHub.\
Puoi usare lo **strumento** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **public repos** di un'**organization** e dei suoi **developers** ed eseguire automaticamente [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi.

**Leakos** può anche essere usato per eseguire **gitleaks** contro tutti gli **text** forniti **URL** passati ad esso, dato che a volte anche le pagine web contengono secrets.

#### Github Dorks

Controlla anche questa **page** per potenziali **github dorks** che potresti cercare nell'organization che stai attaccando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A volte attaccanti o anche dipendenti pubblicano **contenuti dell'azienda in un sito di paste**. Questo potrebbe contenere o meno **informazioni sensibili**, ma è molto interessante cercarlo.\
Puoi usare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare in più di 80 paste sites contemporaneamente.

### Google Dorks

I vecchi ma efficaci google dorks sono sempre utili per trovare **informazioni esposte che non dovrebbero esserci**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di possibili query che non puoi eseguire manualmente. Quindi puoi prendere le tue 10 preferite o usare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) per eseguirle tutte.

_Nota che gli strumenti che cercano di eseguire l'intero database usando il browser Google normale non finiranno mai poiché Google ti bloccherà molto molto presto._

### **Looking for vulnerabilities**

Se trovi **valid leaked** credentials o API tokens, è un successo molto facile.

## Vulnerabilità nel codice pubblico

Se scopri che l'azienda ha codice **open-source** puoi **analizzarlo** e cercare **vulnerabilità** al suo interno.

**A seconda del linguaggio** ci sono diversi **tools** che puoi usare:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ci sono anche servizi gratuiti che ti permettono di **scansionare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilità** trovate dai bug hunter risiedono nelle **web applications**, quindi a questo punto vorrei parlare di una **metodologia di testing per applicazioni web**, e puoi [**trovare queste informazioni qui**](../../network-services-pentesting/pentesting-web/index.html).

Voglio anche menzionare in modo speciale la sezione [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), poiché, pur non aspettandoti che trovino vulnerabilità molto sensibili, sono utili da integrare nei **workflows per ottenere informazioni web iniziali.**

## Riepilogo

> Congratulazioni! A questo punto hai già eseguito **tutta l'enumerazione di base**. Sì, è di base perché si può fare molta più enumerazione (vedremo altri trucchi più avanti).

Quindi hai già:

1. Trovato tutte le **companies** all'interno dello scope
2. Trovato tutti gli **assets** appartenenti alle companies (e aver eseguito qualche vuln scan se in scope)
3. Trovato tutti i **domains** appartenenti alle companies
4. Trovato tutti i **subdomains** dei domains (possibile subdomain takeover?)
5. Trovato tutti gli **IPs** (da e non da **CDNs**) nello scope.
6. Trovato tutti i **web servers** e scattato uno **screenshot** di essi (qualcosa di strano merita un'analisi più approfondita?)
7. Trovato tutti i **potential public cloud assets** appartenenti all'azienda.
8. Rilevate **Emails**, **credentials leaks**, e **secret leaks** che potrebbero darti una **vittoria molto facile**.
9. **Pentesting** di tutti i web che hai trovato

## **Full Recon Automatic Tools**

Ci sono diversi strumenti che eseguiranno parte delle azioni proposte contro uno scope dato.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' datato e non aggiornato

## **Riferimenti**

- Tutti i corsi gratuiti di [**@Jhaddix**](https://twitter.com/Jhaddix) come [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
