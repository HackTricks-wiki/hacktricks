# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Scoperta degli asset

> Quindi ti è stato detto che tutto ciò che appartiene a una certa company è dentro lo scope, e vuoi capire cosa possiede realmente questa company.

L'obiettivo di questa fase è ottenere tutte le **company di proprietà della company principale** e poi tutti gli **asset** di queste company. Per farlo, faremo:

1. Trovare le acquisizioni della company principale, questo ci darà le company dentro lo scope.
2. Trovare l'ASN (se presente) di ogni company, questo ci darà gli intervalli IP posseduti da ogni company
3. Usare reverse whois lookups per cercare altre voci (nomi di organizzazioni, domini...) correlate alla prima (questo può essere fatto ricorsivamente)
4. Usare altre tecniche come i filtri `org` e `ssl` di shodan per cercare altri asset (il trucco `ssl` può essere fatto ricorsivamente).

### **Acquisizioni**

Prima di tutto, dobbiamo sapere quali **altre company sono possedute dalla company principale**.\
Un'opzione è visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** la **company principale** e **cliccare** su "**acquisitions**". Lì vedrai altre company acquisite da quella principale.\
Un'altra opzione è visitare la pagina **Wikipedia** della company principale e cercare **acquisitions**.\
Per le company pubbliche, controlla i filing **SEC/EDGAR**, le pagine di **investor relations**, o i registri societari locali (ad es., **Companies House** nel Regno Unito).\
Per alberi societari globali e sussidiarie, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, a questo punto dovresti conoscere tutte le company dentro lo scope. Vediamo come trovare i loro asset.

### **ASN**

Un autonomous system number (**ASN**) è un **numero univoco** assegnato a un **autonomous system** (AS) dalla **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste in **blocchi** di **indirizzi IP** che hanno una policy chiaramente definita per l'accesso alle reti esterne ed è amministrato da una singola organizzazione ma può essere composto da diversi operatori.

È interessante verificare se la **company ha assegnato qualche ASN** per trovare i suoi **intervalli IP.** Sarà utile eseguire un **vulnerability test** contro tutti gli **host** dentro lo **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per **nome** della company, per **IP** o per **domain** in [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione della company, questi link potrebbero essere utili per raccogliere più dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). In ogni caso, probabilmente tutte le** useful information **(IP ranges and Whois)** sono già presenti nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Anche [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration aggrega e riassume automaticamente gli ASN alla fine della scansione.
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
Puoi trovare anche gli intervalli IP di un'organizzazione usando [http://asnlookup.com/](http://asnlookup.com) (ha una API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Ricerca di vulnerabilità**

A questo punto sappiamo **tutti gli asset dentro lo scope**, quindi, se autorizzato, potresti lanciare un **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, potresti lanciare alcuni [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usare servizi come** Shodan, Censys o ZoomEye **per trovare** porte aperte **e, a seconda di ciò che trovi, dovresti** dare un'occhiata in questo libro per capire come fare pentest di diversi possibili servizi in esecuzione.\
**Inoltre, potrebbe valere la pena menzionare che puoi anche preparare alcune** liste di username **e** password predefiniti **e provare a** bruteforce i servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende dentro lo scope e i loro asset, è il momento di trovare i domini dentro lo scope.

_Per favore, nota che nelle tecniche proposte seguenti puoi anche trovare subdomains e che questa informazione non dovrebbe essere sottovalutata._

Per prima cosa dovresti cercare il **dominio principale** di ogni azienda. Per esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Dato che hai trovato tutti gli intervalli IP dei domini, potresti provare a eseguire **reverse dns lookups** su quegli **IP per trovare più domini dentro lo scope**. Prova a usare qualche dns server della vittima o qualche dns server noto (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Per far funzionare questo, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche usare uno strumento online per queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com).\
Per intervalli grandi, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare le reverse lookups e l'enrichment.

### **Reverse Whois (loop)**

Dentro un **whois** puoi trovare molte **informazioni** interessanti come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ciò che è ancora più interessante è che puoi trovare **più asset مرتبط alla società** se esegui **reverse whois lookups su uno qualsiasi di questi campi** (per esempio altri registri whois in cui compare la stessa email).\
Puoi usare strumenti online come:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Puoi automatizzare questo compito usando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una chiave API whoxy).\
Puoi anche eseguire una discovery automatica di reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi usare questa tecnica per scoprire altri nomi di dominio ogni volta che trovi un nuovo dominio.**

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Per esempio, se vedi lo stesso **Google Analytics ID** o lo stesso **Adsense ID** su più pagine.

Ci sono alcune pagine e strumenti che ti permettono di cercare tramite questi tracker e altro:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trova siti correlati tramite analytics/tracker condivisi)

### **Favicon**

Sapevi che possiamo trovare domini e subdomini correlati al nostro target cercando lo stesso hash dell'icona favicon? È esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In modo semplice, favihash ci permetterà di scoprire domini che hanno lo stesso hash dell'icona favicon del nostro target.

Inoltre, puoi anche cercare tecnologie usando l'hash della favicon come spiegato in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Questo significa che se conosci l'**hash della favicon di una versione vulnerabile di una web tech** puoi cercare se in shodan e **trovare più posti vulnerabili**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Questo è come puoi **calcolare l'hash del favicon** di un web:
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
Puoi anche ottenere hash di favicon su larga scala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e poi fare pivot in Shodan/Censys.

### **Copyright / Uniq string**

Cerca all'interno delle pagine web **stringhe che potrebbero essere condivise tra diversi siti nella stessa organizzazione**. La **stringa di copyright** potrebbe essere un buon esempio. Poi cerca quella stringa in **google**, in altri **browser** o persino in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

È comune avere un cron job come
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni Mail DMARC

Puoi usare un web come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) oppure uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e sottodomini che condividono le stesse informazioni dmarc**.\
Altri strumenti utili sono [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

A quanto pare è comune assegnare sottodomini a IP che appartengono a provider cloud e a un certo punto **perdere quell'indirizzo IP ma dimenticare di rimuovere il record DNS**. Quindi, semplicemente **avviando una VM** in un cloud (come Digital Ocean) in realtà **prenderai il controllo di alcuni sottodomini**.

[**Questo post**](https://kmsec.uk/blog/passive-takeover/) spiega una storia al riguardo e propone uno script che **avvia una VM in DigitalOcean**, **ottiene** l'**IPv4** della nuova macchina e **cerca in Virustotal i record di sottodominio** che puntano ad essa.

### **Altri modi**

**Nota che puoi usare questa tecnica per scoprire altri nomi di dominio ogni volta che trovi un nuovo dominio.**

**Shodan**

Come già sai il nome dell'organizzazione che possiede lo spazio IP. Puoi cercare quei dati in shodan usando: `org:"Tesla, Inc."` Controlla gli host trovati per nuovi domini inattesi nel certificato TLS.

Potresti accedere al **certificato TLS** della pagina web principale, ottenere il nome dell'**Organizzazione** e poi cercare quel nome all'interno dei **certificati TLS** di tutte le pagine web conosciute da **shodan** con il filtro : `ssl:"Tesla Motors"` oppure usare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)è uno strumento che cerca **domini correlati** con un dominio principale e i relativi **sottodomini**, davvero notevole.

**Passive DNS / Historical DNS**

I dati Passive DNS sono ottimi per trovare **vecchi record dimenticati** che ancora risolvono o che possono essere presi in consegna. Guarda:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Ricerca di vulnerabilità**

Controlla alcuni [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Forse qualche azienda sta **usando un dominio** ma ne ha **perso la proprietà**. Registralo semplicemente (se abbastanza economico) e fallo sapere all'azienda.

Se trovi qualche **dominio con un IP diverso** da quelli che hai già trovato nella scoperta degli asset, dovresti eseguire una **scansione di vulnerabilità di base** (usando Nessus o OpenVAS) e una [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il dominio è ospitato dentro un IP che non è controllato dal cliente, quindi non è nello scope, fai attenzione._

## Sottodomini

> Conosciamo tutte le aziende incluse nello scope, tutte le risorse di ciascuna azienda e tutti i domini correlati alle aziende.

È il momento di trovare tutti i possibili sottodomini di ciascun dominio trovato.

> [!TIP]
> Nota che alcuni degli strumenti e delle tecniche per trovare domini possono anche aiutare a trovare sottodomini

### **DNS**

Proviamo a ottenere **sottodomini** dai record **DNS**. Dovremmo anche provare il **Zone Transfer** (se vulnerabile, dovresti segnalarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più rapido per ottenere molti subdomain è cercare in fonti esterne. Gli **tool** più usati sono i seguenti (per risultati migliori configura le API key):

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
Ci sono **altri strumenti/API interessanti** che, anche se non specializzati direttamente nel trovare subdomain, possono essere utili per trovare subdomain, come:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere i subdomain
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** recupera gli URL noti da AlienVault's Open Threat Exchange, la Wayback Machine e Common Crawl per qualsiasi dominio dato.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Scansionano il web alla ricerca di file JS ed estraggono da lì i sottodomini.
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
- [**securitytrails.com**](https://securitytrails.com/) ha una API gratuita per cercare subdomains e cronologia degli IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre **gratuitamente tutti i subdomains relativi ai programmi bug-bounty**. Puoi accedere a questi dati anche usando [chaospy](https://github.com/dr-0x0x/chaospy) o persino accedere allo scope usato da questo progetto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare una **comparazione** di molti di questi strumenti qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **subdomains** facendo brute-forcing sui server DNS usando possibili nomi di subdomain.

Per questa azione avrai bisogno di alcune **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche IP di buoni resolver DNS. Per generare una lista di resolver DNS affidabili puoi scaricare i resolver da [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. Oppure potresti usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più consigliati per il brute-force DNS sono:

- [**massdns**](https://github.com/blechschmidt/massdns): Questo è stato il primo strumento che ha eseguito un brute-force DNS efficace. È molto veloce, tuttavia è soggetto a falsi positivi.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Questo penso usi solo 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper attorno a `massdns`, scritto in go, che consente di enumerare subdomain validi usando bruteforce attivo, oltre a risolvere subdomain con gestione del wildcard e supporto facile input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Usa anche `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio per fare brute force dei nomi di dominio in modo asincrono.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

Dopo aver trovato sottodomini usando fonti aperte e brute-forcing, potresti generare variazioni dei sottodomini trovati per provare a trovarne ancora di più. Diversi tool sono utili per questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dati i domini e i sottodomini, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Date i domini e i sottodomini, genera permutazioni.
- Puoi ottenere la **wordlist** delle permutazioni di goaltdns [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati i domini e i sottodomini, genera permutazioni. Se non è indicato un file di permutazioni, gotator userà il proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di subdomain, può anche provare a risolverle (ma è meglio usare i tool commentati in precedenza).
- Puoi ottenere la **wordlist** delle permutazioni di altdns [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per eseguire permutazioni, mutazioni e alterazioni di sottodomini. Questo strumento eseguirà brute force sul risultato (non supporta il wildcard DNS).
- Puoi ottenere la wordlist delle permutazioni di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basato su un dominio, **genera nuovi possibili nomi di subdomains** in base ai pattern indicati per provare a scoprire altri subdomains.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Per maggiori informazioni leggi questo [**post**](https://cramppet.github.io/regulator/index.html), ma in pratica prenderà le **parti principali** dai **subdomains scoperti** e le mescolerà per trovare più subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un subdomain brute-force fuzzer abbinato a un algoritmo guidato dalle risposte DNS immensamente semplice ma efficace. Utilizza un insieme fornito di dati di input, come una wordlist personalizzata o record DNS/TLS storici, per sintetizzare con precisione altri domain name corrispondenti ed espanderli ulteriormente in un loop basato sulle informazioni raccolte durante la scansione DNS.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Controlla questo post del blog che ho scritto su come **automatizzare la subdomain discovery** da un domain usando **Trickest workflows** così non devo avviare manualmente un sacco di tools sul mio computer:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Se hai trovato un IP address contenente **una o più web pages** appartenenti a subdomains, potresti provare a **trovare altri subdomains con webs in quell'IP** cercando in **OSINT sources** dei domains in un IP oppure facendo **brute-force dei VHost domain names in quell'IP**.

#### OSINT

Puoi trovare alcuni **VHosts in IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre APIs**.

**Brute Force**

Se sospetti che qualche subdomain possa essere nascosto in un web server potresti provare a fare brute force:

Quando l'**IP redirects to a hostname** (name-based vhosts), fai fuzz direttamente dell'header `Host` e lascia che ffuf **auto-calibrate** per evidenziare le responses che differiscono dal default vhost:
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
> Con questa tecnica potresti persino essere in grado di accedere a endpoint interni/nascosti.

### **CORS Brute Force**

A volte troverai pagine che restituiscono l'header _**Access-Control-Allow-Origin**_ solo quando un dominio/subdomain valido è impostato nell'header _**Origin**_. In questi scenari, puoi abusare di questo comportamento per **scoprire** nuovi **subdomain**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mentre cerchi **subdomains**, fai attenzione se stanno **puntando** a qualche tipo di **bucket**, e in tal caso [**controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, visto che a questo punto conoscerai tutti i domains dentro lo scope, prova a [**fare brute force dei possibili nomi dei bucket e controllare i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Puoi **monitorare** se vengono creati **nuovi subdomains** di un domain monitorando i log di **Certificate Transparency**. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)fa questo.

### **Looking for vulnerabilities**

Controlla possibili [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdomain** punta a un **S3 bucket**, [**controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi qualsiasi **subdomain con un IP diverso** da quelli che hai già trovato nella discovery degli assets, dovresti eseguire una **basic vulnerability scan** (usando Nessus o OpenVAS) e una **port scan** [**di base**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione potresti trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

Nelle fasi iniziali potresti aver **trovato alcuni IP ranges, domains e subdomains**.\
È il momento di **raccogliere di nuovo tutti gli IP da quei ranges** e per i **domains/subdomains (DNS queries).**

Usando servizi dalle seguenti **free apis** puoi anche trovare **gli IP usati in passato da domains e subdomains**. Questi IP potrebbero essere ancora di proprietà del client (e potrebbero permetterti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche controllare quali domains puntano a un specifico indirizzo IP usando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Esegui una port scan su tutti gli IP che non appartengono a CDN** (visto che molto probabilmente lì non troverai nulla di interessante). Nei servizi in esecuzione scoperti potresti essere **in grado di trovare vulnerabilità**.

**Trova una** [**guide**](../pentesting-network/index.html) **su come scansionare gli host.**

## Web servers hunting

> Abbiamo trovato tutte le companies e i loro assets e conosciamo IP ranges, domains e subdomains dentro lo scope. È il momento di cercare i web servers.

Nelle fasi precedenti hai probabilmente già eseguito alcune **ricognizioni degli IP e domains scoperti**, quindi potresti aver **già trovato tutti i possibili web servers**. Tuttavia, se non l'hai fatto, ora vedremo alcuni **trucchi rapidi per cercare web servers** dentro lo scope.

Per favore, nota che questo sarà **orientato alla discovery di web apps**, quindi dovresti **eseguire la vulnerability** e anche la **port scanning** (**se consentito** dallo scope).

Un **metodo rapido** per scoprire i **porti aperti** relativi ai server **web** usando [**masscan** può essere trovato qui](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento utile per cercare web servers è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Ti basta passare una lista di domains e proverà a connettersi alle porte 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Ora che hai scoperto **tutti i web server** presenti nel scope (tra gli **IP** dell'azienda e tutti i **domini** e **subdomini**) probabilmente **non sai da dove iniziare**. Quindi, rendiamo tutto semplice e iniziamo facendo solo screenshot di tutti. Già solo **dando un'occhiata** alla **pagina principale** puoi trovare endpoint **strani** che sono più **proni** a essere **vulnerabili**.

Per realizzare l'idea proposta puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, puoi poi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) per analizzare tutti gli **screenshots** e dirti **cosa è probabile contenga vulnerabilità** e cosa no.

## Public Cloud Assets

Per trovare potenziali cloud assets appartenenti a un'azienda dovresti **iniziare con una lista di keyword che identificano quell'azienda**. Per esempio, per una crypto company potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ti serviranno anche wordlist di **parole comuni usate nei bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con quelle parole dovresti generare **permutazioni** (controlla il [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) per maggiori info).

Con le wordlist risultanti potresti usare tool come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che quando cerchi Cloud Assets dovresti c**ercare più di soli bucket in AWS**.

### **Looking for vulnerabilities**

Se trovi cose come **bucket aperti o cloud functions esposte** dovresti **accedervi** e provare a vedere cosa ti offrono e se puoi abusarne.

## Emails

Con i **domini** e i **subdomini** dentro lo scope hai praticamente tutto ciò che ti **serve per iniziare a cercare email**. Queste sono le **API** e i **tool** che per me hanno funzionato meglio per trovare le email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
- API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Looking for vulnerabilities**

Le email ti saranno utili più avanti per fare **brute-force di web login e servizi di auth** (come SSH). Inoltre, servono per i **phishing**. Inoltre, queste API ti daranno ancora più **info sulla persona** dietro l'email, cosa utile per la campagna di phishing.

## Credential Leaks

Con i **domini,** **subdomini**, e **email** puoi iniziare a cercare credenziali leaked in passato appartenenti a quelle email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Se trovi credenziali leaked **valide**, questo è un win molto facile.

## Secrets Leaks

I credential leaks sono legati a hack di aziende in cui **informazioni sensibili sono state leakate e vendute**. Tuttavia, le aziende possono essere colpite da **altri leak** le cui info non sono in quei database:

### Github Leaks

Credenziali e API potrebbero essere leakate nei **repository pubblici** dell'**azienda** o degli **utenti** che lavorano in quella azienda github.\
Puoi usare il **tool** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repo pubblici** di un'**organizzazione** e dei suoi **developer** ed eseguire [**gitleaks**](https://github.com/zricethezav/gitleaks) sopra di essi automaticamente.

**Leakos** può anche essere usato per eseguire **gitleaks** su tutti gli **URL** passati come **testo**, dato che a volte **le pagine web contengono anche secrets**.

#### Github Dorks

Controlla anche questa **pagina** per potenziali **github dorks** che potresti cercare anche nell'organizzazione che stai attaccando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A volte gli attacker o semplicemente dei lavoratori pubblicheranno **contenuti aziendali in un sito di paste**. Questo può contenere o meno **informazioni sensibili**, ma è molto interessante cercarli.\
Puoi usare il tool [**Pastos**](https://github.com/carlospolop/Pastos) per cercare in più di 80 paste site allo stesso tempo.

### Google Dorks

I vecchi ma sempre utili google dorks sono sempre utili per trovare **informazioni esposte che non dovrebbero esserci**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di possibili query che non puoi eseguire manualmente. Quindi, puoi scegliere i tuoi 10 preferiti oppure usare un **tool come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirli tutti**.

_Nota che i tool che si aspettano di eseguire tutto il database usando il browser Google normale non finiranno mai, perché google ti bloccherà molto, molto presto._

### **Looking for vulnerabilities**

Se trovi credenziali leaked **valide** o API token, questo è un win molto facile.

## Public Code Vulnerabilities

Se hai scoperto che l'azienda ha **codice open-source** puoi **analizzarlo** e cercare **vulnerabilities** al suo interno.

**A seconda del linguaggio** ci sono diversi **tool** che puoi usare:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ci sono anche servizi gratuiti che permettono di **scansionare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilità** trovate dai bug hunter si trova all'interno delle **web application**, quindi a questo punto vorrei parlare di una **metodologia di testing per web application**, e puoi [**trovare queste informazioni qui**](../../network-services-pentesting/pentesting-web/index.html).

Voglio anche fare una menzione speciale alla sezione [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), perché, anche se non dovresti aspettarti che ti trovino vulnerabilità molto sensibili, tornano utili per integrarle in **workflow** per avere qualche informazione iniziale sul web.

## Recapitulation

> Congratulazioni! A questo punto hai già eseguito **tutta la enumerazione di base**. Sì, è base perché si può fare molta più enumerazione (vedremo altri trick più avanti).

Quindi hai già:

1. Trovato tutte le **company** dentro lo scope
2. Trovato tutti gli **asset** appartenenti alle company (ed eseguito anche qualche vuln scan se in scope)
3. Trovato tutti i **domini** appartenenti alle company
4. Trovato tutti i **subdomini** dei domini (qualche subdomain takeover?)
5. Trovato tutti gli **IP** (da e **non da CDN**) dentro lo scope.
6. Trovato tutti i **web server** e fatto uno **screenshot** di ciascuno (c'è qualcosa di strano che merita uno sguardo più approfondito?)
7. Trovato tutti i **potenziali public cloud assets** appartenenti all'azienda.
8. **Email**, **credential leaks**, e **secret leaks** che potrebbero darti un **grande win molto facilmente**.
9. **Pentesting di tutti i web che hai trovato**

## **Full Recon Automatic Tools**

Ci sono diversi tool là fuori che eseguiranno parte delle azioni proposte contro uno scope dato.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' vecchio e non aggiornato

## **References**

- Tutti i corsi gratuiti di [**@Jhaddix**](https://twitter.com/Jhaddix) come [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
