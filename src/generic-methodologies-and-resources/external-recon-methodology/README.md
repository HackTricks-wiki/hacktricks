# Metodologia di Recon esterna

{{#include ../../banners/hacktricks-training.md}}

## Scoperta degli asset

> Quindi ti è stato detto che tutto ciò che appartiene a una determinata azienda è incluso nello scope e vuoi capire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è ottenere tutte le **aziende possedute dall'azienda principale** e quindi tutti gli **asset** di queste aziende. Per farlo, procederemo a:

1. Trovare le acquisizioni dell'azienda principale; questo ci fornirà le aziende incluse nello scope.
2. Trovare l'ASN (se presente) di ogni azienda; questo ci fornirà gli intervalli IP posseduti da ciascuna azienda.
3. Utilizzare reverse whois lookup per cercare altre voci (nomi di organizzazioni, domini...) correlate alla prima (l'operazione può essere eseguita ricorsivamente).
4. Utilizzare altre tecniche, come i filtri `org` e `ssl` di shodan, per cercare altri asset (il trucco `ssl` può essere eseguito ricorsivamente).

### **Acquisizioni**

Prima di tutto, dobbiamo sapere quali **altre aziende sono possedute dall'azienda principale**.\
Un'opzione consiste nel visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** l'**azienda principale** e fare **click** su "**acquisitions**". Qui vedrai altre aziende acquisite da quella principale.\
Un'altra opzione consiste nel visitare la pagina **Wikipedia** dell'azienda principale e cercare **acquisitions**.\
Per le aziende quotate in borsa, controlla i **SEC/EDGAR filings**, le pagine di **investor relations** o i registri societari locali (ad esempio **Companies House** nel Regno Unito).\
Per gli alberi societari globali e le subsidiary, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, a questo punto dovresti conoscere tutte le aziende incluse nello scope. Vediamo come trovare i loro asset.

### **ASNs**

Un autonomous system number (**ASN**) è un **numero univoco** assegnato a un **autonomous system** (AS) dalla **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** è costituito da **blocchi** di **indirizzi IP** che dispongono di una policy chiaramente definita per l'accesso alle reti esterne e sono amministrati da una singola organizzazione, ma possono essere composti da diversi operatori.

È interessante verificare se l'**azienda ha ottenuto un ASN** per trovare i suoi **intervalli IP.** Sarà utile eseguire un **vulnerability test** su tutti gli **host** all'interno dello **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per **nome** dell'azienda, per **IP** o per **dominio** su [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **oppure** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione dell'azienda, questi link potrebbero essere utili per raccogliere più dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nord America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(America Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In ogni caso, probabilmente tutte le** informazioni utili **(intervalli IP e Whois)** sono già presenti nel primo link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Inoltre, l'enumerazione di [**BBOT**](https://github.com/blacklanternsecurity/bbot)
aggrega e riepiloga automaticamente gli ASN al termine della scansione.
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
Puoi trovare gli intervalli IP di un'organizzazione anche usando [http://asnlookup.com/](http://asnlookup.com) (dispone di un'API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Ricerca delle vulnerabilità**

A questo punto conosciamo **tutti gli asset inclusi nell'ambito**, quindi, se sei autorizzato, potresti eseguire uno **scanner di vulnerabilità** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, potresti eseguire dei [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **oppure usare servizi come** Shodan, Censys o ZoomEye **per trovare** le porte aperte **e, in base a ciò che trovi, dovresti** consultare questo libro per capire come eseguire il pentest di diversi possibili servizi in esecuzione.\
**Inoltre, potrebbe essere utile ricordare che puoi anche preparare alcune** liste di username **e** password **predefiniti e provare a eseguire il** bruteforce dei servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende incluse nell'ambito e i relativi asset: è il momento di trovare i domini inclusi nell'ambito.

_Nota che con le tecniche proposte di seguito puoi trovare anche sottodomini e che queste informazioni non dovrebbero essere sottovalutate._

Per prima cosa dovresti cercare il **dominio principale** di ogni azienda. Ad esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Avendo trovato tutti gli intervalli IP dei domini, potresti provare a eseguire dei **reverse DNS lookup** su quegli **IP per trovare altri domini inclusi nell'ambito**. Prova a usare un server DNS della vittima o un server DNS noto (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Perché funzioni, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche usare uno strumento online per ottenere queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com).\
Per intervalli estesi, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare le reverse lookup e l'enrichment.

### **Reverse Whois (loop)**

All'interno di un **whois** puoi trovare molte **informazioni** interessanti, come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ciò che è ancora più interessante è che puoi trovare **altri asset correlati all'azienda** eseguendo **reverse whois lookup in base a uno qualsiasi di questi campi** (per esempio altri registri whois in cui compare la stessa email).\
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

Puoi automatizzare questo task usando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una API key di whoxy).\
Puoi anche eseguire una reverse whois discovery automatica con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi usare questa tecnica per scoprire altri nomi di dominio ogni volta che ne trovi uno nuovo.**

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse, puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Per esempio, se vedi lo stesso **Google Analytics ID** o lo stesso **Adsense ID** su diverse pagine.

Esistono alcune pagine e strumenti che permettono di effettuare ricerche tramite questi tracker e altri elementi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trova siti correlati tramite analytics/tracker condivisi)

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro target cercando lo stesso hash dell'icona favicon? È esattamente ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - scopri i domini con lo stesso hash dell'icona favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In poche parole, favihash ci permette di scoprire i domini che hanno lo stesso hash dell'icona favicon del nostro target.

Inoltre, puoi anche cercare le tecnologie usando l'hash della favicon, come spiegato in [**questo post del blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Ciò significa che, se conosci l'**hash della favicon di una versione vulnerabile di una tecnologia web**, puoi cercare su Shodan e **trovare altri luoghi vulnerabili**:
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
Puoi anche ottenere gli hash dei favicon su larga scala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e poi fare pivot in Shodan/Censys.

Aspetti utili da ricordare quando usi i fingerprint dei favicon:

- **Considera l'hash un indicatore, non una prova**: MMH3 è compatto e sono possibili collisioni; gli operatori possono anche sostituire i favicon o riutilizzare intenzionalmente un'icona fuorviante.
- **Analizza più percorsi oltre a** `/favicon.ico`: molti prodotti espongono le icone in percorsi framework/build o tramite `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, URL `data:` inline o tag HTML `<link rel="icon">`. Il percorso stesso può identificare una famiglia di prodotti.
- **I file statici sono spesso raggiungibili quando l'applicazione non lo è**: i controlli WAF/SSO/IdP possono proteggere le route dinamiche, lasciando però esposte le icone statiche. Richiedi sempre direttamente il favicon ed esamina `ETag`, `Last-Modified`, i redirect e gli header di cache alla ricerca di deboli indizi sulla versione/build.
- **Convalida i match con i segnali circostanti**: confronta il titolo, l'hash HTML/body, gli header, i subject/SAN dei certificati TLS, i componenti Shodan/Censys e le porte esposte prima di concludere che un favicon identifichi un prodotto.
- **Raggruppa per hash HTML/body durante il pivot su larga scala**: se la maggior parte degli host che condividono un favicon converge in un unico template di pagina, il fingerprint è più solido; se lo stesso hash si suddivide in molti template non correlati, preferisci "generic/shared/honeypot" a un'etichetta di prodotto.
- **Heuristica per gli honeypot**: se lo stesso hash del favicon compare in molte firme HTML non correlate, porte casuali e prodotti in conflitto, consideralo probabilmente un honeypot o un placeholder generico anziché un fingerprint reale del prodotto.
- **Usa una probe 404 sui target ambigui**: recupera una pagina reale e un percorso inesistente come `/_favicon_probe_<8-hex>` in un browser. Le risposte corrispondenti del provider di hosting/parking spesso spiegano meglio i favicon condivisi rispetto a una reale sovrapposizione di prodotti.
- **Crea mapping iniziali dalle detection rules**: i template Nuclei e i dataset pubblici di favicon possono fornire mapping noti `favicon` ↔ `product` ↔ `CPE`, utili per un triage rapido dopo la divulgazione di CVE.
- **Nota sulla copertura**: i dataset in stile Shodan sono incentrati sugli IP. Le superfici protette da CDN, instradate tramite SNI, anycast e basate solo sul dominio possono essere sottostimate; quindi un numero ridotto di risultati **non** significa una bassa diffusione nel mondo reale.

### **Copyright / Uniq string**

Cerca nelle pagine web **stringhe che potrebbero essere condivise tra siti web diversi della stessa organizzazione**. La **stringa di copyright** può essere un buon esempio. Poi cerca quella stringa su **google**, in altri **browser** o persino in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

È comune avere un cron job come񎟟
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
per rinnovare tutti i certificati dei domini sul server. Questo significa che, anche se la CA utilizzata per farlo non imposta l'orario di generazione nel campo Validity, è possibile **trovare domini appartenenti alla stessa azienda nei certificate transparency logs**.\
Consulta questo [**writeup per ulteriori informazioni**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Usa anche direttamente i log di **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni DMARC delle email

Puoi usare un sito web come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e sottodomini che condividono le stesse informazioni DMARC**.\
Altri strumenti utili sono [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

A quanto pare, è comune che le persone assegnino sottodomini a IP appartenenti a cloud provider e a un certo punto **perdano quell'indirizzo IP, dimenticando però di rimuovere il record DNS**. Pertanto, semplicemente **avviando una VM** in un cloud (come Digital Ocean), si finirà per **prendere il controllo di alcuni sottodomini**.

[**Questo post**](https://kmsec.uk/blog/passive-takeover/) spiega un caso al riguardo e propone uno script che **avvia una VM in DigitalOcean**, **ottiene** l'**IPv4** della nuova macchina e **cerca in Virustotal i record dei sottodomini** che puntano a essa.

### **Altri metodi**

**Nota che puoi utilizzare questa tecnica per scoprire più nomi di dominio ogni volta che ne trovi uno nuovo.**

**Shodan**

Come già sai il nome dell'organizzazione proprietaria dello spazio IP, puoi cercare questi dati in shodan usando: `org:"Tesla, Inc."` Controlla gli host trovati per individuare nuovi domini imprevisti nel certificato TLS.

Potresti accedere al **certificato TLS** della pagina web principale, ottenere il **nome dell'Organizzazione** e quindi cercare quel nome all'interno dei **certificati TLS** di tutte le pagine web note a **shodan** con il filtro: `ssl:"Tesla Motors"` oppure utilizzare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)è uno strumento che cerca **domini correlati** a un dominio principale e i relativi **sottodomini**, davvero notevole.

**Passive DNS / Historical DNS**

I dati Passive DNS sono ottimi per trovare **record vecchi e dimenticati** che continuano a risolversi o che possono essere presi in consegna. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Ricerca di vulnerabilità**

Controlla la presenza di eventuali [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Potrebbe darsi che un'azienda **stia utilizzando un dominio** ma ne abbia **perso la proprietà**. Registralo (se è abbastanza economico) e informa l'azienda.

Se trovi un **dominio con un IP diverso** da quelli già individuati durante la discovery degli asset, dovresti eseguire una **scansione di base delle vulnerabilità** (utilizzando Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il dominio è ospitato all'interno di un IP non controllato dal cliente, quindi non rientra nell'ambito, fai attenzione._

## Sottodomini

> Conosciamo tutte le aziende incluse nell'ambito, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È il momento di trovare tutti i sottodomini possibili di ciascun dominio individuato.

> [!TIP]
> Nota che alcuni strumenti e tecniche per trovare domini possono essere utili anche per trovare sottodomini

### **DNS**

Proviamo a ottenere i **sottodomini** dai record **DNS**. Dovremmo anche provare il **Zone Transfer** (se vulnerabile, dovresti segnalarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Il modo più veloce per ottenere molti sottodomini è cercare in fonti esterne. I **tool** più utilizzati sono i seguenti (per ottenere risultati migliori, configura le chiavi API):

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
Esistono **altri strumenti/API interessanti** che, anche se non sono specializzati direttamente nella ricerca di sottodomini, potrebbero essere utili per trovare sottodomini, come:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilizza l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere sottodomini
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**API gratuita di JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** recupera URL noti da AlienVault's Open Threat Exchange, Wayback Machine e Common Crawl per qualsiasi dominio.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **e** [**subscraper**](https://github.com/Cillian-Collins/subscraper): analizzano il web alla ricerca di file JS ed estraggono i sottodomini da questi.
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
- [**securitytrails.com**](https://securitytrails.com/) dispone di un'API gratuita per cercare subdomain e la cronologia degli IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Questo progetto offre **gratuitamente tutti i subdomain correlati ai programmi di bug bounty**. Puoi accedere a questi dati anche usando [chaospy](https://github.com/dr-0x0x/chaospy) o persino accedere allo scope usato da questo progetto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare un **confronto** tra molti di questi tool qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **subdomain** eseguendo il brute-forcing dei server DNS usando possibili nomi di subdomain.

Per questa attività avrai bisogno di alcune **wordlist di subdomain comuni, come**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E anche gli IP di buoni resolver DNS. Per generare un elenco di resolver DNS affidabili, puoi scaricare i resolver da [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e usare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. In alternativa, puoi usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

I tool più consigliati per il DNS brute-force sono:

- [**massdns**](https://github.com/blechschmidt/massdns): è stato il primo tool a eseguire un DNS brute-force efficace. È molto veloce, tuttavia è soggetto a falsi positivi.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Questo, credo, utilizzi un solo resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper di `massdns`, scritto in Go, che consente di enumerare sottodomini validi usando il bruteforce attivo, oltre a risolvere sottodomini con gestione dei wildcard e un semplice supporto input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Utilizza anche `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilizza asyncio per eseguire il brute force asincrono dei nomi di dominio.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Secondo Round di DNS Brute-Force

Dopo aver trovato subdomini utilizzando open sources e il brute-forcing, potresti generare alterazioni dei subdomini trovati per provare a trovarne ancora di più. Diversi tool sono utili a questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dati i domini e i subdomini, genera permutazioni.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dati i domini e i sottodomini, genera permutazioni.
- Puoi ottenere la **wordlist** delle permutazioni di goaltdns [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dati i domini e i sottodomini, genera permutazioni. Se non viene indicato alcun file di permutazioni, gotator ne utilizzerà uno proprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di subdomains, può anche provare a risolverle (ma è meglio usare i tool commentati in precedenza).
- Puoi trovare la **wordlist** delle permutazioni di altdns [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un altro tool per eseguire permutations, mutations e alteration dei subdomain. Questo tool esegue il brute force del risultato (non supporta i wildcard DNS).
- Puoi ottenere la wordlist delle permutations di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** In base a un dominio, **genera nuovi nomi di potenziali sottodomini** basati sui pattern indicati, per provare a scoprire altri sottodomini.

#### Generazione intelligente delle permutazioni

- [**regulator**](https://github.com/cramppet/regulator): Per maggiori informazioni, leggi questo [**post**](https://cramppet.github.io/regulator/index.html), ma sostanzialmente recupera le **parti principali** dai **sottodomini scoperti** e le combina per trovare altri sottodomini.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un fuzzer di brute-force per subdomain, abbinato a un algoritmo estremamente semplice ma efficace, guidato dalle risposte DNS. Utilizza un set di dati di input fornito, come una wordlist personalizzata o record DNS/TLS storici, per sintetizzare accuratamente altri nomi di dominio corrispondenti ed espanderli ulteriormente in un loop, basandosi sulle informazioni raccolte durante la scansione DNS.
```
echo www | subzuf facebook.com
```
### **Workflow di Subdomain Discovery**

Leggi questo post del blog che ho scritto su come **automatizzare la subdomain discovery** da un dominio usando i **workflow di Trickest**, così non devo avviare manualmente una serie di tool sul mio computer:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Se hai trovato un indirizzo IP contenente **una o più pagine web** appartenenti a subdomain, puoi provare a **trovare altri subdomain con siti web su quell'IP** cercando nelle **fonti OSINT** domini associati a un IP oppure facendo il **brute-forcing dei nomi di dominio VHost su quell'IP**.

#### OSINT

Puoi trovare alcuni **VHosts negli IP usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre API**.

**Brute Force**

Se sospetti che un subdomain possa essere nascosto in un web server, puoi provare a eseguire il brute force:

Quando l'**IP reindirizza a un hostname** (vhost basati sul nome), esegui il fuzzing diretto dell'header `Host` e lascia che ffuf esegua l'**auto-calibrate** per evidenziare le risposte che differiscono dal vhost predefinito:
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

A volte troverai pagine che restituiscono l'header _**Access-Control-Allow-Origin**_ solo quando nell'header _**Origin**_ viene impostato un domain/subdomain valido. In questi scenari, puoi abusare di questo comportamento per **scoprire** nuovi **subdomain**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mentre cerchi **subdomains**, tieni d'occhio se qualche elemento **punta** a un qualsiasi tipo di **bucket** e, in tal caso, [**controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, dato che a questo punto conoscerai tutti i domini inclusi nello scope, prova a [**eseguire il brute force di possibili nomi di bucket e controllare i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoraggio**

Puoi **monitorare** la creazione di **nuovi subdomains** di un dominio monitorando i log di **Certificate Transparency**, come fa [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Ricerca di vulnerabilità**

Controlla la presenza di possibili [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdomain** punta a un **bucket S3**, [**controlla i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi un **subdomain con un IP diverso** da quelli già individuati durante l'asset discovery, dovresti eseguire una **basic vulnerability scan** (usando Nessus o OpenVAS) e una [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. In base ai servizi in esecuzione, in **questo libro potresti trovare alcuni trucchi per "attaccarli"**.\
_Notare che a volte il subdomain è ospitato su un IP non controllato dal client, quindi non rientra nello scope: presta attenzione._

## IP

Nei passaggi iniziali potresti aver **trovato alcuni intervalli IP, domini e subdomains**.\
È il momento di **raccogliere tutti gli IP appartenenti a tali intervalli** e quelli relativi ai **domini/subdomains (query DNS).**

Utilizzando i servizi delle seguenti **free APIs**, puoi anche trovare **IP precedentemente utilizzati da domini e subdomains**. Questi IP potrebbero essere ancora di proprietà del client (e potrebbero permetterti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche verificare quali domini puntano a uno specifico indirizzo IP usando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Ricerca di vulnerabilità**

**Esegui una port scan su tutti gli IP che non appartengono a CDN** (poiché molto probabilmente non troverai nulla di interessante). Nei servizi in esecuzione individuati potresti **riuscire a trovare vulnerabilità**.

**Consulta una** [**guida**](../pentesting-network/index.html) **su come eseguire la scansione degli host.**

## Ricerca di web server

> Abbiamo trovato tutte le aziende e i relativi asset e conosciamo gli intervalli IP, i domini e i subdomains inclusi nello scope. È il momento di cercare i web server.

Nei passaggi precedenti probabilmente hai già eseguito una certa attività di **recon sugli IP e sui domini individuati**, quindi potresti aver **già trovato tutti i web server possibili**. Tuttavia, se non l'hai fatto, ora vedremo alcuni **trucchi veloci per cercare web server** all'interno dello scope.

Tieni presente che questa attività sarà **orientata alla web apps discovery**, quindi dovresti eseguire anche il **vulnerability** e il **port scanning** (**se consentito** dallo scope).

Un **metodo rapido** per individuare le **porte aperte** relative ai **web** server usando [**masscan** può essere trovato qui](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento intuitivo per cercare web server è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Devi solo passargli un elenco di domini e tenterà di connettersi alle porte 80 (http) e 443 (https). Inoltre, puoi indicargli di provare altre porte:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Ora che hai scoperto **tutti i web server** presenti nello scope (tra gli **IP** dell'azienda e tutti i **domini** e **sottodomini**) probabilmente **non sai da dove iniziare**. Quindi, semplifichiamo e iniziamo semplicemente a fare screenshot di tutti. Già solo **dando un'occhiata** alla **pagina principale** puoi trovare endpoint **strani** che hanno maggiori probabilità di essere **vulnerabili**.

Per realizzare quanto proposto puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, potresti usare [**eyeballer**](https://github.com/BishopFox/eyeballer) su tutti gli **screenshot** per indicarti **cosa probabilmente contiene vulnerabilità** e cosa no.

## Public Cloud Assets

Per trovare potenziali cloud asset appartenenti a un'azienda dovresti **iniziare con una lista di parole chiave che identificano quell'azienda**. Ad esempio, per un'azienda crypto potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Avrai anche bisogno di wordlist di **parole comuni usate nei bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con queste parole dovresti generare **permutazioni** (controlla la [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) per maggiori informazioni).

Con le wordlist risultanti potresti usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che, quando cerchi Cloud Assets, dovresti c**ercare più dei soli bucket in AWS**.

### **Looking for vulnerabilities**

Se trovi elementi come **bucket aperti o cloud function esposte**, dovresti **accedervi** e provare a capire cosa ti offrono e se puoi abusarne.

## Emails

Con i **domini** e i **sottodomini** presenti nello scope hai praticamente tutto ciò di cui **hai bisogno per iniziare a cercare email**. Queste sono le **API** e gli **strumenti** che hanno funzionato meglio per me per trovare le email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
- API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Looking for vulnerabilities**

Le email torneranno utili in seguito per fare **brute-force dei web login e dei servizi di autenticazione** (come SSH). Sono inoltre necessarie per i **phishing**. Inoltre, queste API ti forniranno ancora più **informazioni sulla persona** associata all'email, utili per la campagna di phishing.

## Credential Leaks

Con **domini,** **sottodomini** ed **email** puoi iniziare a cercare credenziali leakate in passato e appartenenti a quegli indirizzi email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Se trovi credenziali **leakate valide**, è una vittoria molto facile.

## Secrets Leaks

I credential leak sono legati agli hack di aziende in cui **informazioni sensibili sono state leakate e vendute**. Tuttavia, le aziende potrebbero essere colpite da **altri leak** le cui informazioni non si trovano in quei database:

### Github Leaks

Credenziali e API potrebbero essere leakate nei **repository pubblici** dell'**azienda** o degli **utenti** che lavorano per quell'azienda su Github.\
Puoi usare lo **strumento** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repository pubblici** di un'**organizzazione** e dei suoi **developer**, ed eseguire automaticamente [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi.

**Leakos** può essere usato anche per eseguire **gitleaks** contro tutto il **testo** fornito dagli **URL passati** come input, perché a volte anche le **pagine web contengono secret**.

#### Github Dorks

Controlla anche questa **pagina** per trovare potenziali **github dork** che potresti cercare anche nell'organizzazione che stai attaccando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A volte gli attaccanti o semplicemente i dipendenti **pubblicano contenuti aziendali su un paste site**. Questo potrebbe contenere o meno **informazioni sensibili**, ma è molto interessante cercarle.\
Puoi usare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare contemporaneamente in oltre 80 paste site.

### Google Dorks

I vecchi ma validi google dork sono sempre utili per trovare **informazioni esposte che non dovrebbero essere lì**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di query possibili che non puoi eseguire manualmente. Quindi puoi scegliere le tue 10 preferite oppure usare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirle tutte**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

Se trovi credenziali **leakate valide** o token API, è una vittoria molto facile.

## Public Code Vulnerabilities

Se hai scoperto che l'azienda dispone di **codice open-source**, puoi **analizzarlo** e cercare **vulnerabilità** al suo interno.

**A seconda del linguaggio** puoi usare diversi **strumenti**:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Esistono anche servizi gratuiti che consentono di **scansionare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilità** trovate dai bug hunter risiede nelle **web application**, quindi a questo punto vorrei parlare di una **metodologia di testing delle web application**; puoi [**trovare qui queste informazioni**](../../network-services-pentesting/pentesting-web/index.html).

Vorrei inoltre fare una menzione speciale alla sezione [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), perché, anche se non dovresti aspettarti che trovino vulnerabilità molto sensibili, sono utili per implementarli nei **workflow e ottenere alcune informazioni web iniziali.**

## Recapitulation

> Congratulazioni! A questo punto hai già completato **tutta l'enumerazione di base**. Sì, è di base perché è possibile fare molta più enumerazione (vedremo altri trucchi più avanti).

Hai quindi già:

1. Trovato tutte le **aziende** presenti nello scope
2. Trovato tutti gli **asset** appartenenti alle aziende (ed eseguito alcune vuln scan se inclusi nello scope)
3. Trovato tutti i **domini** appartenenti alle aziende
4. Trovato tutti i **sottodomini** dei domini (qualche subdomain takeover?)
5. Trovato tutti gli **IP** (provenienti e **non provenienti da CDN**) presenti nello scope.
6. Trovato tutti i **web server** e fatto uno **screenshot** di ciascuno (c'è qualcosa di strano che merita un'analisi più approfondita?)
7. Trovato tutti i **potenziali public cloud asset** appartenenti all'azienda.
8. **Email**, **credential leak** e **secret leak** che potrebbero offrirti una **grande vittoria molto facilmente**.
9. Eseguito il **pentesting su tutti i siti web trovati**

## **Full Recon Automatic Tools**

Esistono diversi strumenti che eseguono parte delle azioni proposte contro uno scope specifico.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' datato e non aggiornato

## **References**

- Tutti i corsi gratuiti di [**@Jhaddix**](https://twitter.com/Jhaddix), come [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
