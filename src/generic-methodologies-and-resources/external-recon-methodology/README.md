# Metodologia di External Recon

{{#include ../../banners/hacktricks-training.md}}

## Scoperta degli asset

> Ti è stato detto che tutto ciò che appartiene a una determinata azienda è incluso nello scope e vuoi capire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è ottenere tutte le **aziende possedute dalla società principale** e quindi tutti gli **asset** di queste aziende. Per farlo, procederemo come segue:<sup>[[1]](#references)</sup>

1. Trovare le acquisizioni della società principale; questo ci fornirà le aziende incluse nello scope.
2. Trovare l'ASN (se presente) di ogni azienda; questo ci fornirà gli intervalli IP posseduti da ciascuna azienda.
3. Utilizzare reverse whois lookup per cercare altre voci (nomi di organizzazioni, domini...) correlate alla prima (questa operazione può essere eseguita ricorsivamente).
4. Utilizzare altre tecniche, come i filtri `org` e `ssl` di shodan, per cercare altri asset (il trucco `ssl` può essere eseguito ricorsivamente).

### **Acquisizioni**

Innanzitutto, dobbiamo sapere quali **altre aziende sono possedute dalla società principale**.\
Un'opzione consiste nel visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** la **società principale** e fare clic su "**acquisitions**". Qui verranno visualizzate le altre aziende acquisite dalla società principale.\
Un'altra opzione consiste nel visitare la pagina **Wikipedia** della società principale e cercare **acquisitions**.\
Per le aziende quotate in borsa, controlla i **SEC/EDGAR filings**, le pagine **investor relations** o i registri societari locali (ad esempio, **Companies House** nel Regno Unito).\
Per ottenere alberi societari globali e società controllate, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> A questo punto dovresti conoscere tutte le aziende incluse nello scope. Vediamo come trovare i loro asset.

### **ASN**

Un autonomous system number (**ASN**) è un **numero univoco** assegnato a un **autonomous system** (AS) dalla **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** è costituito da **blocchi** di **indirizzi IP** che dispongono di una policy chiaramente definita per l'accesso alle reti esterne e sono amministrati da una singola organizzazione, ma possono essere costituiti da diversi operatori.

È interessante verificare se alla **società è stato assegnato un ASN** per trovare i suoi **intervalli IP.** Sarà utile eseguire un **vulnerability test** su tutti gli **host** inclusi nello **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per **nome** dell'azienda, per **IP** o per **dominio** su [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **oppure** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione in cui si trova l'azienda, questi link potrebbero essere utili per raccogliere ulteriori dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). In ogni caso, probabilmente tutte le** informazioni utili **(intervalli IP e Whois)** sono già presenti nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Inoltre, l'enumerazione di [**BBOT**](https://github.com/blacklanternsecurity/bbot) aggrega e riassume automaticamente gli ASN al termine della scansione.
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

### **Ricerca delle vulnerabilità**

A questo punto conosciamo **tutti gli asset inclusi nell'ambito**, quindi, se autorizzati, potresti avviare un **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, potresti avviare alcuni [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **oppure usare servizi come** Shodan, Censys o ZoomEye **per trovare** porte aperte **e, in base a ciò che trovi, dovresti** consultare questo libro per capire come eseguire il pentesting di diversi possibili servizi in esecuzione.\
**Inoltre, potrebbe essere utile ricordare che puoi anche preparare alcune** liste di username **e** password **predefiniti e provare a eseguire il** bruteforce dei servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Conosciamo tutte le aziende incluse nell'ambito e i relativi asset; è il momento di trovare i domini inclusi nell'ambito.

_Nota che, con le tecniche proposte di seguito, puoi trovare anche sottodomini e che tali informazioni non dovrebbero essere sottovalutate._

Prima di tutto dovresti cercare il **dominio principale** di ogni azienda. Ad esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Dato che hai trovato tutti gli intervalli IP dei domini, potresti provare a eseguire dei **reverse dns lookups** su quegli **IP per trovare altri domini inclusi nell'ambito**. Prova a usare qualche server DNS della vittima o un server DNS noto (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Perché funzioni, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche usare uno strumento online per ottenere queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com).\
Per intervalli ampi, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare le reverse lookup e l'arricchimento dei dati.

### **Reverse Whois (loop)**

All'interno di un **whois** puoi trovare molte **informazioni** interessanti come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma l'aspetto ancora più interessante è che puoi trovare **altri asset correlati all'azienda** se esegui **reverse whois lookup utilizzando uno qualsiasi di questi campi** (ad esempio, altri registri whois in cui compare la stessa email).\
Puoi usare strumenti online come:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratuito** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **gratuito**, API non gratuita.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Non gratuito
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Non gratuito (solo **100 ricerche gratuite**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Non gratuito
- [https://securitytrails.com/](https://securitytrails.com/) - Non gratuito (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Non gratuito (API)

Puoi automatizzare questa attività usando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una chiave API di whoxy).\
Puoi anche eseguire una reverse whois discovery automatica con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi usare questa tecnica per scoprire più nomi di dominio ogni volta che trovi un nuovo dominio.**

### **Tracker**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse, puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Ad esempio, se vedi lo stesso **ID di Google Analytics** o lo stesso **ID di Adsense** su diverse pagine.

Esistono alcune pagine e strumenti che consentono di effettuare ricerche utilizzando questi tracker e altri elementi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trova siti correlati tramite analytics/tracker condivisi)

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro target cercando lo stesso hash dell'icona favicon? Questo è esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), realizzato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![Risultati di Favihash utilizzati per scoprire domini che condividono un favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In parole semplici, favihash ci permette di scoprire domini che hanno lo stesso favicon hash del nostro target.

![Output di favihash utilizzato per scoprire domini con lo stesso favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Utilizza un favicon hash noto come pivot di Shodan o FOFA per trovare altre istanze esposte della stessa tecnologia.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ecco come puoi **calcolare l'hash della favicon** di un sito web (MMH3 sui byte della favicon **codificati in base64**):
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
Puoi anche ottenere hash dei favicon su larga scala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e poi fare pivot in Shodan/Censys.

Considera le fingerprint dei favicon come indizi e convalidale con i segnali circostanti.<sup>[[3]](#references)[[4]](#references)</sup>

- **Considera l'hash un indicatore, non una prova**: MMH3 è compatto; sono possibili collisioni, icone riutilizzate e spoofing deliberato.
- **Esegui il probe su più percorsi oltre a** `/favicon.ico`: controlla i percorsi di framework/build, i file manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, gli URL data inline e i tag HTML `<link rel="icon">`.
- **Gli asset statici possono rimanere raggiungibili dietro controlli WAF/SSO/IdP**: richiedi direttamente l'icona e analizza gli header `ETag`, `Last-Modified`, i redirect e quelli di cache.
- **Convalida le corrispondenze con i segnali circostanti**: confronta il titolo, l'hash HTML/body, gli header, i subject/SAN del certificato TLS, i componenti del prodotto e le porte esposte.
- **Raggruppa per hash HTML/body**: un template coerente rafforza la fingerprint; template misti suggeriscono un'icona generica o condivisa.
- **Considera un hash che compare in signature, porte e prodotti non correlati come un potenziale honeypot o placeholder.**
- **Sui target ambigui, confronta una pagina reale con un percorso inesistente** come `/_favicon_probe_<8-hex>`; risposte di hosting o parking corrispondenti possono spiegare l'icona condivisa.
- **Avvia il triage dalle regole di rilevamento Nuclei o dai dataset pubblici** che associano gli hash dei favicon a prodotti e CPE.
- **Ricorda il coverage gap centrato sugli IP**: le superfici con CDN, routing basato su SNI, anycast e solo dominio potrebbero mancare dai dataset simili a Shodan.

### **Copyright / stringa univoca**

Cerca nelle pagine web **stringhe che potrebbero essere condivise tra diversi siti della stessa organizzazione**. La **stringa di copyright** potrebbe essere un buon esempio. Cerca quindi quella stringa in **google**, in altri **browser** o persino in **shodan**: `shodan search http.html:"Copyright string"`

### **Tempo CRT**

È comune avere un cron job come
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
per rinnovare tutti i certificati su un server contemporaneamente. Correlare i timestamp dei certificati o le posizioni nei log di certificate transparency può rivelare domini correlati.<sup>[[6]](#references)</sup>

Utilizza anche direttamente i log di **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni Mail DMARC

Puoi utilizzare un sito come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e sottodomini che condividono le stesse informazioni DMARC**.\
Altri strumenti utili sono [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un record A abbandonato può diventare raggiungibile quando un cloud provider riassegna un IP. La ricerca citata dimostra un workflow opportunistico che esegue il provisioning di un'istanza e correla il suo indirizzo con i dati del passive DNS; testa gli scenari di takeover esclusivamente nell'ambito autorizzato.<sup>[[7]](#references)</sup>

### **Altri metodi**

Ripeti i pivot di discovery applicabili ogni volta che trovi un nuovo dominio: ogni risultato può esporre ulteriori nomi nei certificati, relazioni di passive DNS, corrispondenze favicon e identificatori dell'organizzazione che non erano visibili dal seed originale.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Poiché conosci già il nome dell'organizzazione proprietaria dello spazio IP, puoi cercare questi dati in shodan utilizzando: `org:"Tesla, Inc."` Controlla gli host trovati per individuare nuovi domini imprevisti nel certificato TLS.

Puoi accedere al **certificato TLS** della pagina web principale, ottenere il **nome dell'organizzazione** e poi cercare quel nome all'interno dei **certificati TLS** di tutte le pagine web note a **shodan** con il filtro: `ssl:"Tesla Motors"` oppure utilizzare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)è uno strumento che cerca **domini correlati** a un dominio principale e i relativi **sottodomini**, davvero notevole.

**Passive DNS / DNS storico**

I dati di Passive DNS sono ottimi per trovare **record vecchi e dimenticati** che continuano a risolvere o che possono essere soggetti a takeover. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Ricerca di vulnerabilità**

Controlla la presenza di un [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Potrebbe esserci un'azienda che **utilizza un dominio** ma ha **perso la proprietà**. Registralo (se abbastanza economico) e informa l'azienda.

Se trovi un **dominio con un IP diverso** da quelli già individuati durante la discovery degli asset, dovresti eseguire una **scansione di base delle vulnerabilità** (utilizzando Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il dominio è ospitato all'interno di un IP non controllato dal cliente, quindi non rientra nell'ambito, fai attenzione._

## Sottodomini

> Conosciamo tutte le aziende incluse nell'ambito, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È il momento di trovare tutti i possibili sottodomini di ciascun dominio individuato.

> [!TIP]
> Nota che alcuni strumenti e tecniche per trovare domini possono aiutare anche a trovare sottodomini

### **DNS**

Proviamo a ottenere i **sottodomini** dai record **DNS**. Dovremmo anche provare il **Zone Transfer** (se vulnerabile, dovresti segnalarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più rapido per ottenere molti sottodomini è cercare nelle fonti esterne. I **tools** più utilizzati sono i seguenti (per ottenere risultati migliori, configura le chiavi API):

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
Esistono **altri strumenti/API interessanti** che, anche se non sono direttamente specializzati nella ricerca di subdomini, potrebbero essere utili per trovare subdomini, come:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilizza l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere i sottodomini
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
- [**gau**](https://github.com/lc/gau)**:** recupera gli URL noti da AlienVault's Open Threat Exchange, Wayback Machine e Common Crawl per qualsiasi dominio specificato.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Analizzano il web alla ricerca di file JS ed estraggono i subdomini da questi.
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
- [**securitytrails.com**](https://securitytrails.com/) dispone di una API gratuita per cercare sottodomini e la cronologia degli IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre **gratuitamente tutti i sottodomini relativi ai programmi di bug bounty**. Puoi accedere a questi dati anche tramite [chaospy](https://github.com/dr-0x0x/chaospy) o persino accedere allo scope utilizzato da questo progetto: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare un **confronto** tra molti di questi tool qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **sottodomini** eseguendo il brute-forcing dei server DNS utilizzando possibili nomi di sottodomini.

Per questa operazione avrai bisogno di alcune **wordlist di sottodomini comuni, come**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche gli IP di buoni resolver DNS. Per generare un elenco di resolver DNS affidabili, puoi scaricare i resolver da [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e utilizzare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. In alternativa, puoi usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

I tool più consigliati per il DNS brute-force sono:

- [**massdns**](https://github.com/blechschmidt/massdns): è stato il primo tool a eseguire un DNS brute-force efficace. È molto veloce, tuttavia è soggetto a falsi positivi.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Questo credo utilizzi un solo resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper di `massdns`, scritto in Go, che consente di enumerare sottodomini validi usando il bruteforce attivo, oltre a risolvere sottodomini con gestione dei wildcard e supporto semplificato per input e output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Utilizza anch'esso `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilizza asyncio per eseguire il brute force asincrono dei nomi di dominio.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Secondo round di DNS Brute-Force

Dopo aver trovato i sottodomini utilizzando fonti open e il brute-forcing, potresti generare variazioni dei sottodomini trovati per provare a individuarne ancora di più. Diversi tool sono utili a questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dati i domini e i sottodomini, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): A partire dai domini e sottodomini, genera permutations.
- Puoi ottenere la **wordlist** delle permutations di goaltdns [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati i domini e i sottodomini, genera permutazioni. Se non viene indicato alcun file di permutazioni, gotator utilizzerà il proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di subdomain, può anche provare a risolverle (ma è meglio usare i tool commentati in precedenza).
- Puoi ottenere la **wordlist** delle permutazioni di altdns [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per eseguire permutations, mutations e alteration dei subdomain. Questo strumento eseguirà il brute force del risultato (non supporta il dns wild card).
- Puoi ottenere la wordlist delle permutations di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** In base a un dominio, **genera nuovi potenziali nomi di sottodomini** basati sui pattern indicati, per provare a scoprire altri sottodomini.

#### Generazione intelligente di permutazioni

- [**regulator**](https://github.com/cramppet/regulator): Apprende pattern simili a regex dai sottodomini scoperti e genera nomi candidati da risolvere.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un fuzzer di brute-force per i sottodomini, abbinato a un algoritmo guidato dalle risposte DNS incredibilmente semplice ma efficace. Utilizza un set di dati di input fornito, come una wordlist personalizzata o record DNS/TLS storici, per sintetizzare accuratamente altri nomi di dominio corrispondenti ed espanderli ulteriormente in un ciclo, in base alle informazioni raccolte durante la scansione DNS.
```
echo www | subzuf facebook.com
```
### **Workflow di Discovery dei Subdomain**

Gli esempi di workflow di Trickest combinano OSINT, DNS brute force e fasi di permutazione per un'enumerazione ripetibile dei subdomain.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Se hai trovato un indirizzo IP contenente **una o più pagine web** appartenenti a subdomain, puoi provare a **trovare altri subdomain con siti web su quell'IP** cercando nelle **fonti OSINT** i domini associati a un IP oppure facendo il **brute-force dei nomi di dominio dei VHost su quell'IP**.

#### OSINT

Puoi trovare alcuni **VHosts negli IP usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre API**.

**Brute Force**

Se sospetti che un subdomain possa essere nascosto in un web server, puoi provare a fare il brute force:

Per i vhost basati sui nomi, esegui il fuzzing dell'header `Host` e usa l'auto-calibrazione di ffuf per filtrare la risposta predefinita.<sup>[[2]](#references)</sup>
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

A volte troverai pagine che restituiscono l'header _**Access-Control-Allow-Origin**_ solo quando nell'header _**Origin**_ viene impostato un dominio/sottodominio valido. In questi scenari, puoi sfruttare questo comportamento per **scoprire** nuovi **sottodomini**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Durante la ricerca di **subdomains**, presta attenzione per verificare se stanno **pointing** a qualche tipo di **bucket** e, in tal caso, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, poiché a questo punto conoscerai tutti i domini inclusi nello scope, prova a [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoraggio**

Puoi **monitorare** la creazione di **new subdomains** di un dominio monitorando i log di **Certificate Transparency**, come fa [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Ricerca di vulnerabilità**

Verifica la presenza di possibili [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdomain** punta a un **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi un **subdomain con un IP diverso** da quelli già individuati durante l'assets discovery, dovresti eseguire una **basic vulnerability scan** (utilizzando Nessus o OpenVAS) e una [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. In base ai servizi in esecuzione, in **questo libro potresti trovare alcuni trucchi per "attaccarli"**.\
_Nota che a volte il subdomain è ospitato all'interno di un IP non controllato dal client, quindi non è incluso nello scope: fai attenzione._

## IPs

Durante i passaggi iniziali potresti aver **trovato alcuni intervalli di IP, domini e subdomains**.\
È il momento di **raccogliere tutti gli IP da quegli intervalli** e quelli relativi ai **domini/subdomains (DNS queries).**

Utilizzando i servizi delle seguenti **free apis** puoi anche trovare **IP precedenti utilizzati da domini e subdomains**. Questi IP potrebbero essere ancora di proprietà del client (e potrebbero permetterti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche verificare quali domini puntano a uno specifico indirizzo IP utilizzando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Ricerca di vulnerabilità**

**Esegui una port scan su tutti gli IP che non appartengono alle CDN** (poiché molto probabilmente non troverai nulla di interessante). Nei servizi in esecuzione individuati potresti **riuscire a trovare vulnerabilità**.

**Trova una** [**guide**](../pentesting-network/index.html) **su come eseguire la scansione degli host.**

## Caccia ai web server

> Abbiamo trovato tutte le aziende e i relativi asset e conosciamo gli intervalli di IP, i domini e i subdomains inclusi nello scope. È il momento di cercare i web server.

Nei passaggi precedenti probabilmente hai già eseguito alcune attività di **recon sugli IP e sui domini individuati**, quindi potresti aver **già trovato tutti i web server possibili**. Tuttavia, se non lo hai fatto, ora vedremo alcuni **trucchi rapidi per cercare web server** all'interno dello scope.

Tieni presente che questa attività sarà **orientata alla web apps discovery**, quindi dovresti eseguire anche la **vulnerability** e la **port scanning** (**se consentito** dallo scope).

Un **metodo rapido** per scoprire le **ports open** relative ai **web** server utilizzando [**masscan** è disponibile qui](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento intuitivo per cercare web server è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). È sufficiente passare un elenco di domini e lo strumento tenterà di connettersi alla porta 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshot**

Ora che hai scoperto **tutti i web server** presenti nello scope (tra gli **IP** dell'azienda e tutti i **domini** e **sottodomini**) probabilmente **non sai da dove iniziare**. Quindi, semplifichiamo e iniziamo semplicemente facendo screenshot di tutti. Anche solo **dando un'occhiata** alla **pagina principale** puoi trovare endpoint **strani** che sono più **inclini** a essere **vulnerabili**.

Per realizzare l'idea proposta puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, puoi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) su tutti gli **screenshot** per indicarti **quali probabilmente contengono vulnerabilità** e quali no.

## Risorse Cloud pubbliche

Per trovare potenziali risorse cloud appartenenti a un'azienda dovresti **iniziare con un elenco di parole chiave che identifichino quell'azienda**. Ad esempio, per un'azienda crypto potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Avrai inoltre bisogno di wordlist di **parole comuni usate nei bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Successivamente, con queste parole dovresti generare **permutazioni** (consulta la sezione [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) per maggiori informazioni).

Con le wordlist risultanti potresti usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che, quando cerchi risorse Cloud, dovresti c**ercare qualcosa in più dei soli bucket in AWS**.

### **Ricerca di vulnerabilità**

Se trovi elementi come **bucket aperti o funzioni cloud esposte**, dovresti **accedervi** e cercare di capire cosa possono offrirti e se puoi abusarne.

## Email

Con i **domini** e i **sottodomini** presenti nello scope hai praticamente tutto ciò che **ti serve per iniziare a cercare email**. Queste sono le **API** e gli **strumenti** che hanno funzionato meglio per me per trovare le email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
- API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Ricerca di vulnerabilità**

Le email torneranno utili in seguito per fare **brute-force dei login web e dei servizi di autenticazione** (come SSH). Sono inoltre necessarie per i **phishing**. Queste API ti forniranno anche ulteriori **informazioni sulla persona** dietro l'email, utili per la campagna di phishing.

## Credential Leak

Con i **domini,** i **sottodomini** e le **email** puoi iniziare a cercare credenziali oggetto di leak in passato appartenenti a quegli indirizzi email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Ricerca di vulnerabilità**

Se trovi credenziali **valide ottenute tramite leak**, è una vittoria molto facile.

## Secret Leak

I credential leak sono legati agli attacchi contro aziende durante i quali **informazioni sensibili sono state oggetto di leak e vendute**. Tuttavia, le aziende possono essere interessate da **altri leak** le cui informazioni non si trovano in quei database:

### Leak su Github

Credenziali e API potrebbero essere oggetto di leak nei **repository pubblici** dell'**azienda** o degli **utenti** che lavorano per quell'azienda su github.\
Puoi usare il **tool** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repo pubblici** di una **organization** e dei suoi **developer**, ed eseguire automaticamente [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi.

**Leakos** può essere usato anche per eseguire **gitleaks** contro tutto il **testo** fornito dagli **URL passati** al tool, poiché a volte anche le **pagine web contengono secret**.

#### Github Dork

Consulta la [pagina GitHub dorks and leaks](github-leaked-secrets.md) per trovare potenziali **GitHub dorks** da cercare nell'organization.

### Leak nei Paste

A volte gli attaccanti o semplicemente i dipendenti **pubblicano contenuti aziendali su un sito di paste**. Questi contenuti possono contenere o meno **informazioni sensibili**, ma è molto interessante cercarli.\
Puoi usare il tool [**Pastos**](https://github.com/carlospolop/Pastos) per cercare contemporaneamente in più di 80 siti di paste.

### Google Dork

I vecchi ma validi Google dork sono sempre utili per trovare **informazioni esposte che non dovrebbero essere presenti**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di query possibili che non puoi eseguire manualmente. Quindi, puoi scegliere le tue 10 preferite oppure usare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirle tutte**.

_Notare che gli strumenti che tentano di utilizzare l'intero database tramite il browser Google standard non finiranno mai, perché Google ti bloccherà molto, molto presto._

### **Ricerca di vulnerabilità**

Se trovi credenziali **valide ottenute tramite leak** o token API, è una vittoria molto facile.

## Vulnerabilità nel codice pubblico

Se scopri che l'azienda dispone di **codice open source**, puoi **analizzarlo** e cercarvi **vulnerabilità**.

**A seconda del linguaggio** puoi usare diversi **strumenti**; consulta l'elenco degli [strumenti di source-code review](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Esistono anche servizi gratuiti che consentono di **scansionare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia di pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilità** trovate dai bug hunter risiede nelle **web application**, quindi a questo punto vorrei parlare di una **metodologia di testing delle web application**; puoi [**trovare qui queste informazioni**](../../network-services-pentesting/pentesting-web/index.html).

Vorrei inoltre fare una menzione speciale alla sezione [**Strumenti open source di Web Automated Scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), poiché, anche se non dovresti aspettarti che trovino vulnerabilità molto sensibili, sono utili per implementarli nei **workflow e ottenere alcune informazioni iniziali sul web.**

## Riepilogo

> Congratulazioni! A questo punto hai già eseguito **tutta l'enumerazione di base**. Sì, è di base perché è possibile fare molta più enumerazione (vedremo altri trucchi più avanti).

Quindi hai già:

1. Trovato tutte le **aziende** incluse nello scope
2. Trovato tutti gli **asset** appartenenti alle aziende (ed eseguito una vuln scan, se inclusa nello scope)
3. Trovato tutti i **domini** appartenenti alle aziende
4. Trovato tutti i **sottodomini** dei domini (possibile subdomain takeover?)
5. Trovato tutti gli **IP** (provenienti e **non provenienti da CDN**) inclusi nello scope.
6. Trovato tutti i **web server** e fatto uno **screenshot** di ciascuno (qualcosa di strano che merita un'analisi più approfondita?)
7. Trovato tutte le **potenziali risorse cloud pubbliche** appartenenti all'azienda.
8. Trovato **email**, **credential leak** e **secret leak** che potrebbero offrirti una **grande vittoria molto facilmente**.
9. Eseguito il **pentesting di tutti i siti web trovati**

## **Strumenti automatici completi per la recon**

Esistono diversi strumenti che eseguono parte delle azioni proposte contro uno scope specificato.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' datato e non aggiornato

## References

- [1] [Jason Haddix – La metodologia del bug hunter v4.0: edizione Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sui favicon: dalle icone del browser all'intelligence sulla attack surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Scoprire domini tramite un attacco di correlazione temporale alla Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: scoprire (ed emulare) una costosa campagna di subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: un metodo unico per l'enumerazione dei sottodomini](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow completo per la scoperta dei sottodomini, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Scoperta dei sottodomini tramite brute-force automatizzato con il workflow Trickest, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot dell'output di favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
