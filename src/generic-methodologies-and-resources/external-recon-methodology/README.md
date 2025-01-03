# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}


## Scoperta degli asset

> Ti è stato detto che tutto ciò che appartiene a una certa azienda è all'interno dell'ambito, e vuoi scoprire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è ottenere tutte le **aziende possedute dalla società principale** e poi tutti gli **asset** di queste aziende. Per farlo, procederemo a:

1. Trovare le acquisizioni della società principale, questo ci darà le aziende all'interno dell'ambito.
2. Trovare l'ASN (se presente) di ciascuna azienda, questo ci darà gli intervalli IP posseduti da ciascuna azienda.
3. Utilizzare ricerche whois inverse per cercare altre voci (nomi delle organizzazioni, domini...) correlate alla prima (questo può essere fatto in modo ricorsivo).
4. Utilizzare altre tecniche come i filtri shodan `org` e `ssl` per cercare altri asset (il trucco `ssl` può essere fatto in modo ricorsivo).

### **Acquisizioni**

Prima di tutto, dobbiamo sapere quali **altre aziende sono possedute dalla società principale**.\
Un'opzione è visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** la **società principale** e **cliccare** su "**acquisizioni**". Lì vedrai altre aziende acquisite dalla principale.\
Un'altra opzione è visitare la pagina **Wikipedia** della società principale e cercare le **acquisizioni**.

> Ok, a questo punto dovresti conoscere tutte le aziende all'interno dell'ambito. Scopriamo come trovare i loro asset.

### **ASNs**

Un numero di sistema autonomo (**ASN**) è un **numero unico** assegnato a un **sistema autonomo** (AS) dall'**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste in **blocchi** di **indirizzi IP** che hanno una politica definita per l'accesso a reti esterne e sono amministrati da un'unica organizzazione, ma possono essere composti da più operatori.

È interessante scoprire se la **società ha assegnato qualche ASN** per trovare i suoi **intervalli IP.** Sarà interessante eseguire un **test di vulnerabilità** contro tutti gli **host** all'interno dell'**ambito** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per nome dell'azienda, per **IP** o per **dominio** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**A seconda della regione della società, questi link potrebbero essere utili per raccogliere ulteriori dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nord America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(America Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Comunque, probabilmente tutte le** informazioni utili **(intervalli IP e Whois)** appaiono già nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Inoltre, la **enumerazione dei sottodomini di [**BBOT**](https://github.com/blacklanternsecurity/bbot)** aggrega e riassume automaticamente gli ASN alla fine della scansione.
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
Puoi trovare gli intervalli IP di un'organizzazione anche utilizzando [http://asnlookup.com/](http://asnlookup.com) (ha un'API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Cercare vulnerabilità**

A questo punto conosciamo **tutti gli asset all'interno dell'ambito**, quindi se sei autorizzato potresti lanciare alcuni **scanner di vulnerabilità** (Nessus, OpenVAS) su tutti gli host.\
Inoltre, potresti lanciare alcune [**scansioni delle porte**](../pentesting-network/#discovering-hosts-from-the-outside) **o utilizzare servizi come** shodan **per trovare** porte aperte **e a seconda di ciò che trovi dovresti** dare un'occhiata a questo libro su come fare pentesting a diversi servizi possibili in esecuzione.\
**Inoltre, potrebbe valere la pena menzionare che puoi anche preparare alcune** liste di nomi utente **e** password **predefiniti e provare a** forzare i servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende all'interno dell'ambito e i loro asset, è tempo di trovare i domini all'interno dell'ambito.

_Please, nota che nelle seguenti tecniche proposte puoi anche trovare sottodomini e che queste informazioni non dovrebbero essere sottovalutate._

Prima di tutto dovresti cercare il(i) **dominio(i) principale(i)** di ciascuna azienda. Ad esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Poiché hai trovato tutti gli intervalli IP dei domini, potresti provare a eseguire **ricerche DNS inverse** su quegli **IP per trovare più domini all'interno dell'ambito**. Prova a utilizzare un server DNS della vittima o un server DNS ben noto (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Per far funzionare questo, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche utilizzare uno strumento online per queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

All'interno di un **whois** puoi trovare molte **informazioni** interessanti come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ciò che è ancora più interessante è che puoi trovare **più asset correlati all'azienda** se esegui **ricerche reverse whois per uno di questi campi** (ad esempio altri registri whois dove appare la stessa email).\
Puoi utilizzare strumenti online come:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratuito** web, API non gratuita.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Non gratuito
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Non gratuito (solo **100 ricerche gratuite**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Non gratuito

Puoi automatizzare questo compito utilizzando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una chiave API whoxy).\
Puoi anche eseguire alcune scoperte automatiche di reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi utilizzare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.**

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Ad esempio, se vedi lo stesso **ID di Google Analytics** o lo stesso **ID di Adsense** su più pagine.

Ci sono alcune pagine e strumenti che ti permettono di cercare tramite questi tracker e altro:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro obiettivo cercando lo stesso hash dell'icona favicon? Questo è esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - scopri domini con lo stesso hash dell'icona favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In parole semplici, favihash ci permetterà di scoprire domini che hanno lo stesso hash dell'icona favicon del nostro obiettivo.

Inoltre, puoi anche cercare tecnologie utilizzando l'hash favicon come spiegato in [**questo post del blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Ciò significa che se conosci il **hash della favicon di una versione vulnerabile di una tecnologia web** puoi cercare in shodan e **trovare più luoghi vulnerabili**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Questo è il modo in cui puoi **calcolare l'hash del favicon** di un web:
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

Cerca all'interno delle pagine web **stringhe che potrebbero essere condivise tra diversi siti nella stessa organizzazione**. La **stringa di copyright** potrebbe essere un buon esempio. Poi cerca quella stringa in **google**, in altri **browser** o anche in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

È comune avere un cron job come
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
per rinnovare tutti i certificati di dominio sul server. Questo significa che anche se la CA utilizzata per questo non imposta il tempo in cui è stato generato nel tempo di validità, è possibile **trovare domini appartenenti alla stessa azienda nei log di trasparenza dei certificati**.\
Controlla questo [**writeup per ulteriori informazioni**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Informazioni DMARC Mail

Puoi utilizzare un sito web come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e sottodomini che condividono le stesse informazioni DMARC**.

### **Takeover Passivo**

A quanto pare è comune per le persone assegnare sottodomini a IP che appartengono a fornitori di cloud e a un certo punto **perdere quell'indirizzo IP ma dimenticare di rimuovere il record DNS**. Pertanto, semplicemente **creando una VM** in un cloud (come Digital Ocean) stai effettivamente **prendendo possesso di alcuni sottodomini**.

[**Questo post**](https://kmsec.uk/blog/passive-takeover/) spiega una storia al riguardo e propone uno script che **crea una VM in DigitalOcean**, **ottiene** l'**IPv4** della nuova macchina e **cerca in Virustotal i record di sottodominio** che puntano ad essa.

### **Altri modi**

**Nota che puoi utilizzare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.**

**Shodan**

Come già sai il nome dell'organizzazione che possiede lo spazio IP. Puoi cercare quei dati in shodan usando: `org:"Tesla, Inc."` Controlla gli host trovati per nuovi domini inaspettati nel certificato TLS.

Potresti accedere al **certificato TLS** della pagina web principale, ottenere il **nome dell'organizzazione** e poi cercare quel nome all'interno dei **certificati TLS** di tutte le pagine web conosciute da **shodan** con il filtro: `ssl:"Tesla Motors"` o utilizzare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) è uno strumento che cerca **domini correlati** con un dominio principale e **sottodomini** di essi, davvero sorprendente.

### **Cercare vulnerabilità**

Controlla per qualche [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Forse qualche azienda sta **utilizzando un dominio** ma ha **perso la proprietà**. Registralo (se abbastanza economico) e fai sapere all'azienda.

Se trovi qualche **dominio con un IP diverso** da quelli già trovati nella scoperta degli asset, dovresti eseguire una **scansione di vulnerabilità di base** (utilizzando Nessus o OpenVAS) e qualche [**port scan**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
&#xNAN;_&#x4E;ota che a volte il dominio è ospitato all'interno di un IP che non è controllato dal cliente, quindi non è nel campo, fai attenzione._



## Sottodomini

> Sappiamo tutte le aziende all'interno del campo, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È tempo di trovare tutti i possibili sottodomini di ciascun dominio trovato.

> [!TIP]
> Nota che alcuni degli strumenti e delle tecniche per trovare domini possono anche aiutare a trovare sottodomini

### **DNS**

Proviamo a ottenere **sottodomini** dai record **DNS**. Dovremmo anche provare per il **Zone Transfer** (Se vulnerabile, dovresti segnalarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più veloce per ottenere molti sottodomini è cercare in fonti esterne. Gli **strumenti** più utilizzati sono i seguenti (per risultati migliori configura le chiavi API):

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
Ci sono **altri strumenti/API interessanti** che, anche se non specializzati direttamente nella ricerca di sottodomini, potrebbero essere utili per trovarli, come:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilizza l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere sottodomini
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**API gratuita JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** recupera URL noti da Open Threat Exchange di AlienVault, dalla Wayback Machine e da Common Crawl per un dato dominio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Scrappano il web alla ricerca di file JS ed estraggono i sottodomini da lì.
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
- [**securitytrails.com**](https://securitytrails.com/) ha un'API gratuita per cercare subdomini e la cronologia degli IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre **gratuitamente tutti i subdomini relativi ai programmi di bug-bounty**. Puoi accedere a questi dati anche utilizzando [chaospy](https://github.com/dr-0x0x/chaospy) o persino accedere all'ambito utilizzato da questo progetto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare un **confronto** di molti di questi strumenti qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **subdomini** forzando i server DNS utilizzando possibili nomi di subdominio.

Per questa azione avrai bisogno di alcune **wordlist comuni di subdomini come**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche IP di buoni risolutori DNS. Per generare un elenco di risolutori DNS affidabili puoi scaricare i risolutori da [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e utilizzare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. Oppure potresti usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più raccomandati per il brute-force DNS sono:

- [**massdns**](https://github.com/blechschmidt/massdns): Questo è stato il primo strumento a eseguire un efficace brute-force DNS. È molto veloce, tuttavia è soggetto a falsi positivi.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Questo penso utilizzi solo 1 risolutore
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper attorno a `massdns`, scritto in go, che ti consente di enumerare sottodomini validi utilizzando un bruteforce attivo, oltre a risolvere sottodomini con gestione dei wildcard e supporto facile per input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Utilizza anche `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilizza asyncio per forzare in modo asincrono i nomi di dominio.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Seconda fase di brute-force DNS

Dopo aver trovato i sottodomini utilizzando fonti aperte e brute-forcing, puoi generare alterazioni dei sottodomini trovati per cercare di trovarne ancora di più. Diversi strumenti sono utili a questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dati i domini e i sottodomini, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dati i domini e i sottodomini generare permutazioni.
- Puoi ottenere le permutazioni di goaltdns **wordlist** in [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati i domini e i sottodomini, genera permutazioni. Se non viene indicato un file di permutazioni, gotator utilizzerà il proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di sottodomini, può anche provare a risolverli (ma è meglio usare gli strumenti commentati in precedenza).
- Puoi ottenere le permutazioni di altdns **wordlist** [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per eseguire permutazioni, mutazioni e alterazioni di sottodomini. Questo strumento forzerà il risultato (non supporta i wildcard DNS).
- Puoi ottenere la wordlist delle permutazioni di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basato su un dominio, **genera nuovi potenziali nomi di sottodomini** basati su modelli indicati per cercare di scoprire più sottodomini.

#### Generazione di permutazioni intelligenti

- [**regulator**](https://github.com/cramppet/regulator): Per ulteriori informazioni leggi questo [**post**](https://cramppet.github.io/regulator/index.html), ma fondamentalmente prenderà le **parti principali** dai **sottodomini scoperti** e li mescolerà per trovare più sottodomini.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un fuzzer di brute-force per sottodomini abbinato a un algoritmo guidato dalla risposta DNS immensamente semplice ma efficace. Utilizza un insieme di dati di input fornito, come una wordlist personalizzata o record DNS/TLS storici, per sintetizzare accuratamente nomi di dominio corrispondenti e ampliarli ulteriormente in un ciclo basato sulle informazioni raccolte durante la scansione DNS.
```
echo www | subzuf facebook.com
```
### **Flusso di lavoro per la scoperta di sottodomini**

Controlla questo post del blog che ho scritto su come **automatizzare la scoperta di sottodomini** da un dominio utilizzando **Trickest workflows** in modo da non dover avviare manualmente un sacco di strumenti sul mio computer:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / Host Virtuali**

Se hai trovato un indirizzo IP contenente **una o più pagine web** appartenenti a sottodomini, potresti provare a **trovare altri sottodomini con siti in quell'IP** cercando in **fonti OSINT** per domini in un IP o **forzando i nomi di dominio VHost in quell'IP**.

#### OSINT

Puoi trovare alcuni **VHosts in IP utilizzando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre API**.

**Forza Bruta**

Se sospetti che qualche sottodominio possa essere nascosto in un server web, potresti provare a forzarlo:
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
> Con questa tecnica potresti persino essere in grado di accedere a endpoint interni/nascosti.

### **CORS Brute Force**

A volte troverai pagine che restituiscono solo l'intestazione _**Access-Control-Allow-Origin**_ quando un dominio/subdominio valido è impostato nell'intestazione _**Origin**_. In questi scenari, puoi abusare di questo comportamento per **scoprire** nuovi **subdomini**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mentre cerchi **subdomini**, fai attenzione a vedere se sta **puntando** a qualche tipo di **bucket**, e in tal caso [**controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Inoltre, poiché a questo punto conoscerai tutti i domini all'interno dell'ambito, prova a [**forzare i nomi dei bucket possibili e controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorizzazione**

Puoi **monitorare** se vengono creati **nuovi subdomini** di un dominio monitorando i **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Cercare vulnerabilità**

Controlla possibili [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdominio** sta puntando a qualche **S3 bucket**, [**controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/).

Se trovi un **subdominio con un IP diverso** da quelli che hai già trovato nella scoperta delle risorse, dovresti eseguire una **scansione di vulnerabilità di base** (utilizzando Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
&#xNAN;_&#x4E;ota che a volte il subdominio è ospitato all'interno di un IP che non è controllato dal cliente, quindi non è nell'ambito, fai attenzione._

## IPs

Nei passaggi iniziali potresti aver **trovato alcuni intervalli di IP, domini e subdomini**.\
È tempo di **raccogliere tutti gli IP da quegli intervalli** e per i **domini/subdomini (query DNS).**

Utilizzando i servizi delle seguenti **api gratuite**, puoi anche trovare **IP precedenti utilizzati da domini e subdomini**. Questi IP potrebbero ancora essere di proprietà del cliente (e potrebbero permetterti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche controllare i domini che puntano a un indirizzo IP specifico utilizzando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Cercare vulnerabilità**

**Scansiona tutte le porte degli IP che non appartengono a CDN** (poiché probabilmente non troverai nulla di interessante lì). Nei servizi in esecuzione scoperti potresti essere **in grado di trovare vulnerabilità**.

**Trova una** [**guida**](../pentesting-network/) **su come scansionare gli host.**

## Ricerca di server web

> Abbiamo trovato tutte le aziende e i loro asset e conosciamo gli intervalli di IP, domini e subdomini all'interno dell'ambito. È tempo di cercare server web.

Nei passaggi precedenti probabilmente hai già eseguito alcune **ricerche sugli IP e domini scoperti**, quindi potresti aver **già trovato tutti i possibili server web**. Tuttavia, se non lo hai fatto, ora vedremo alcuni **trucchi rapidi per cercare server web** all'interno dell'ambito.

Si prega di notare che questo sarà **orientato alla scoperta di web app**, quindi dovresti **eseguire la scansione delle vulnerabilità** e **scansione delle porte** anche (**se consentito** dall'ambito).

Un **metodo veloce** per scoprire **porte aperte** relative ai **server** web utilizzando [**masscan** può essere trovato qui](../pentesting-network/#http-port-discovery).\
Un altro strumento amichevole per cercare server web è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Devi solo passare un elenco di domini e cercherà di connettersi alla porta 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshot**

Ora che hai scoperto **tutti i server web** presenti nell'ambito (tra gli **IP** dell'azienda e tutti i **domini** e **sottodomini**) probabilmente **non sai da dove iniziare**. Quindi, rendiamolo semplice e iniziamo semplicemente a fare screenshot di tutti loro. Basta **dare un'occhiata** alla **pagina principale** per trovare endpoint **strani** che sono più **suscettibili** a essere **vulnerabili**.

Per eseguire l'idea proposta puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, potresti poi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) per esaminare tutti gli **screenshot** e dirti **cosa è probabile contenga vulnerabilità** e cosa non lo è.

## Risorse Cloud Pubbliche

Per trovare potenziali risorse cloud appartenenti a un'azienda dovresti **iniziare con un elenco di parole chiave che identificano quell'azienda**. Ad esempio, per una crypto per un'azienda crypto potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Avrai anche bisogno di wordlist di **parole comuni usate nei bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con quelle parole dovresti generare **permutazioni** (controlla il [**Second Round DNS Brute-Force**](./#second-dns-bruteforce-round) per ulteriori informazioni).

Con le wordlist risultanti potresti usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che quando cerchi risorse Cloud dovresti **cercare più di semplici bucket in AWS**.

### **Cercare vulnerabilità**

Se trovi cose come **bucket aperti o funzioni cloud esposte** dovresti **accedervi** e cercare di vedere cosa ti offrono e se puoi abusarne.

## Email

Con i **domini** e **sottodomini** all'interno dell'ambito hai fondamentalmente tutto ciò di cui hai **bisogno per iniziare a cercare email**. Queste sono le **API** e **strumenti** che hanno funzionato meglio per me per trovare email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
- API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Cercare vulnerabilità**

Le email saranno utili in seguito per **brute-forzare accessi web e servizi di autenticazione** (come SSH). Inoltre, sono necessarie per **phishing**. Inoltre, queste API ti daranno ancora più **info sulla persona** dietro l'email, il che è utile per la campagna di phishing.

## Credential Leaks

Con i **domini,** **sottodomini** e **email** puoi iniziare a cercare credenziali trapelate in passato appartenenti a quelle email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Cercare vulnerabilità**

Se trovi credenziali **valide trapelate**, questa è una vittoria molto facile.

## Secrets Leaks

Le perdite di credenziali sono correlate agli attacchi alle aziende in cui **informazioni sensibili sono state trapelate e vendute**. Tuttavia, le aziende potrebbero essere colpite da **altre perdite** le cui informazioni non sono in quelle banche dati:

### Github Leaks

Credenziali e API potrebbero essere trapelate nei **repository pubblici** dell'**azienda** o degli **utenti** che lavorano per quell'azienda github.\
Puoi usare lo **strumento** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repository pubblici** di un'**organizzazione** e dei suoi **sviluppatori** e eseguire [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi automaticamente.

**Leakos** può anche essere usato per eseguire **gitleaks** contro tutto il **testo** fornito **URL passati** ad esso poiché a volte **le pagine web contengono anche segreti**.

#### Github Dorks

Controlla anche questa **pagina** per potenziali **github dorks** che potresti cercare nell'organizzazione che stai attaccando:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A volte gli attaccanti o semplicemente i lavoratori pubblicheranno **contenuti aziendali in un sito di paste**. Questo potrebbe o meno contenere **informazioni sensibili**, ma è molto interessante cercarlo.\
Puoi usare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare in più di 80 siti di paste contemporaneamente.

### Google Dorks

I vecchi ma buoni google dorks sono sempre utili per trovare **informazioni esposte che non dovrebbero esserci**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di possibili query che non puoi eseguire manualmente. Quindi, puoi prendere le tue 10 preferite o puoi usare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirle tutte**.

_Nota che gli strumenti che si aspettano di eseguire tutto il database utilizzando il normale browser Google non finiranno mai poiché google ti bloccherà molto molto presto._

### **Cercare vulnerabilità**

Se trovi credenziali o token API **valide trapelate**, questa è una vittoria molto facile.

## Vulnerabilità di Codice Pubblico

Se hai scoperto che l'azienda ha **codice open-source** puoi **analizzarlo** e cercare **vulnerabilità** in esso.

**A seconda del linguaggio** ci sono diversi **strumenti** che puoi usare:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ci sono anche servizi gratuiti che ti permettono di **scansionare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

La **maggior parte delle vulnerabilità** trovate dai bug hunter risiede all'interno delle **applicazioni web**, quindi a questo punto vorrei parlare di una **metodologia di testing delle applicazioni web**, e puoi [**trovare queste informazioni qui**](../../network-services-pentesting/pentesting-web/).

Voglio anche fare una menzione speciale alla sezione [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/#automatic-scanners), poiché, se non dovresti aspettarti che trovino vulnerabilità molto sensibili, sono utili per implementarle in **workflow per avere alcune informazioni web iniziali.**

## Ricapitolazione

> Congratulazioni! A questo punto hai già eseguito **tutta l'enumerazione di base**. Sì, è di base perché può essere eseguita molta più enumerazione (vedremo altri trucchi più avanti).

Quindi hai già:

1. Trovato tutte le **aziende** all'interno dell'ambito
2. Trovato tutte le **risorse** appartenenti alle aziende (e eseguito alcune scansioni di vulnerabilità se nell'ambito)
3. Trovato tutti i **domini** appartenenti alle aziende
4. Trovato tutti i **sottodomini** dei domini (qualche takeover di sottodominio?)
5. Trovato tutti gli **IP** (da e **non da CDN**) all'interno dell'ambito.
6. Trovato tutti i **server web** e fatto uno **screenshot** di essi (c'è qualcosa di strano che merita un'analisi più approfondita?)
7. Trovato tutte le **potenziali risorse cloud pubbliche** appartenenti all'azienda.
8. **Email**, **perdite di credenziali** e **perdite di segreti** che potrebbero darti una **grande vittoria molto facilmente**.
9. **Pentesting di tutti i siti web che hai trovato**

## **Strumenti Automatici di Full Recon**

Ci sono diversi strumenti là fuori che eseguiranno parte delle azioni proposte contro un dato ambito.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' vecchio e non aggiornato

## **Riferimenti**

- Tutti i corsi gratuiti di [**@Jhaddix**](https://twitter.com/Jhaddix) come [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
