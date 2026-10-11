# Metodologia di ricognizione esterna

{{#include ../../banners/hacktricks-training.md}}

## Scoperta degli asset

> Ti hanno detto che tutto ciò che appartiene a un'azienda è incluso nello scope e vuoi capire cosa possiede davvero questa azienda.

L'obiettivo di questa fase è individuare tutte le **aziende possedute dall'azienda principale** e poi tutti gli **asset** di queste aziende. Per farlo, procederemo così:<sup>[[1]](#references)</sup>

1. Individuare le acquisizioni dell'azienda principale: questo ci permetterà di trovare le aziende incluse nello scope.
2. Individuare l'ASN (se presente) di ogni azienda: questo ci permetterà di trovare gli intervalli IP posseduti da ciascuna.
3. Usare ricerche reverse whois per cercare altre voci (nomi di organizzazioni, domini...) correlate alla prima (è possibile farlo ricorsivamente).
4. Usare altre tecniche, come i filtri `org`e `ssl` di shodan, per cercare altri asset (il trucco `ssl` può essere usato ricorsivamente).

### **Acquisizioni**

Per prima cosa, dobbiamo sapere quali **altre aziende sono possedute dall'azienda principale**.\
Un'opzione è visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** l'**azienda principale** e **fare clic** su "**acquisitions**". Qui vedrai le altre aziende acquisite da quella principale.\
Un'altra opzione è visitare la pagina **Wikipedia** dell'azienda principale e cercare **acquisitions**.\
Per le società quotate in borsa, controlla i documenti **SEC/EDGAR**, le pagine **investor relations** o i registri delle imprese locali (ad es. **Companies House** nel Regno Unito).\
Per gli alberi societari globali e le filiali, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, a questo punto dovresti conoscere tutte le aziende incluse nello scope. Vediamo come trovare i loro asset.

### **ASN**

Un numero di sistema autonomo (**ASN**) è un **numero univoco** assegnato a un **sistema autonomo** (AS) dalla **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** è costituito da **blocchi** di **indirizzi IP** con una policy chiaramente definita per l'accesso alle reti esterne; è amministrato da una singola organizzazione, ma può essere composto da più operatori.

È interessante scoprire se all'**azienda è stato assegnato un ASN**, così da individuare i suoi **intervalli IP**. È utile eseguire un **test di vulnerabilità** su tutti gli **host** inclusi nello **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per **nome** dell'azienda, per **IP** o per **dominio** su [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione in cui si trova l'azienda, questi link possono essere utili per raccogliere altri dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nord America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(America Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In ogni caso, probabilmente tutte le informazioni** utili **(intervalli IP e Whois)** sono già presenti nel primo link.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Inoltre, l'enumeration di [**BBOT**](https://github.com/blacklanternsecurity/bbot) aggrega e riepiloga automaticamente gli ASN al termine della scansione.

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

Puoi trovare anche gli intervalli IP di un'organizzazione usando [http://asnlookup.com/](http://asnlookup.com) (ha un'API gratuita).\
Puoi trovare l'IP e l'ASN di un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Ricerca di vulnerabilità**

A questo punto conosciamo **tutti gli asset inclusi nello scope**, quindi, se hai l'autorizzazione, puoi avviare uno **scanner di vulnerabilità** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, puoi avviare delle [**scansioni delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **oppure usare servizi come** Shodan, Censys o ZoomEye **per trovare** porte aperte **e, in base a ciò che trovi, dovresti** consultare questo libro per scoprire come eseguire il pentest di diversi servizi possibili.\
**Inoltre, vale la pena ricordare che puoi anche preparare alcuni elenchi di** username **e** password **predefiniti e provare a fare** bruteforce dei servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende incluse nello scope e i loro asset: è ora di trovare i domini inclusi nello scope.

_Nota che le tecniche proposte di seguito possono aiutarti a trovare anche sottodomini, e che queste informazioni non vanno sottovalutate._

Per prima cosa, dovresti cercare il **dominio principale** di ogni azienda. Ad esempio, per _Tesla Inc._ sarà _tesla.com_.

### **Reverse DNS**

Dato che hai trovato tutti gli intervalli IP dei domini, puoi provare a eseguire **reverse DNS lookup** su quegli **IP per trovare altri domini inclusi nello scope**. Prova a usare un server DNS della vittima oppure un server DNS noto (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Perché funzioni, l'amministratore deve abilitare manualmente il PTR.\
Puoi anche usare uno strumento online per ottenere queste informazioni: [http://ptrarchive.com/](http://ptrarchive.com).\
Per gli intervalli ampi, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare le reverse lookup e arricchire i risultati.

### **Reverse Whois (loop)**

In un **whois** puoi trovare molte **informazioni** interessanti, come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ciò che è ancora più interessante è che puoi trovare **altri asset correlati all'azienda** eseguendo **reverse whois lookup usando uno qualsiasi di questi dati** (ad esempio, altri registri whois in cui compare la stessa email).\
Puoi usare strumenti online come:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratuito** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratuito** via web, API a pagamento.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - A pagamento
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - A pagamento (solo **100 ricerche gratuite**)
- [https://www.domainiq.com/](https://www.domainiq.com) - A pagamento
- [https://securitytrails.com/](https://securitytrails.com/) - A pagamento (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - A pagamento (API)

Puoi automatizzare questa attività usando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una chiave API di whoxy).\
Puoi anche eseguire una ricerca automatica di reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota che puoi usare questa tecnica per scoprire altri nomi di dominio ogni volta che ne trovi uno nuovo.**

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse, puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Ad esempio, se vedi lo stesso **ID di Google Analytics** o lo stesso **ID di Adsense** su più pagine.

Esistono alcune pagine e strumenti che permettono di cercare questi tracker e altro:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trova siti correlati tramite analytics/tracker condivisi)
- [**StackScan**](https://www.stackscan.com) - **Piano gratuito** (Web e API). Permette di effettuare pivot su qualsiasi asset servito, non solo sugli ID dei tracker: un percorso di script, il nome di un bundle self-hosted o l'host da cui viene caricato un asset, restituendo tutti i siti che lo includono

L'API restituisce lo stack di un singolo dominio, utile per confermare che un asset candidato appartenga allo stesso perimetro:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Restituisce ogni tecnologia rilevata con la relativa categoria. Asset pivoting è attualmente disponibile solo per il web; l’API consente ricerche per singolo dominio.

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro target cercando lo stesso hash dell’icona favicon? È proprio ciò che fa lo strumento [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Risultati di Favihash usati per individuare domini che condividono un hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In parole semplici, favihash ci permette di individuare domini che hanno lo stesso hash dell'icona favicon del nostro target.

![Output di favihash usato per individuare domini con lo stesso hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Usa un hash favicon noto come pivot in Shodan o FOFA per trovare altre istanze esposte della stessa tecnologia.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ecco come puoi **calcolare l'hash del favicon** di una pagina web (MMH3 sui byte del favicon **codificati in base64**):

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

Puoi anche ottenere favicon hash su larga scala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) e poi fare pivot in Shodan/Censys.

Considera le fingerprint dei favicon come indizi e convalidale con i segnali circostanti.<sup>[[3]](#references)[[4]](#references)</sup>

- **Considera l'hash un indicatore, non una prova**: MMH3 è compatto; sono possibili collisioni, icone riutilizzate e spoofing intenzionale.
- **Esamina più di** `/favicon.ico`: controlla i percorsi di framework/build, i file manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, gli URL data inline e i tag HTML `<link rel="icon">`.
- **Gli asset statici potrebbero rimanere raggiungibili dietro controlli WAF/SSO/IdP**: richiedi direttamente l'icona ed esamina `ETag`, `Last-Modified`, i redirect e gli header di cache.
- **Convalida le corrispondenze con i segnali circostanti**: confronta il titolo, l'hash HTML/body, gli header, i subject/SAN del certificato TLS, i componenti del prodotto e le porte esposte.
- **Raggruppa per hash HTML/body**: un template coerente rafforza la fingerprint; template diversi suggeriscono un'icona generica o condivisa.
- **Considera un hash presente su signature, porte e prodotti non correlati come un potenziale honeypot o placeholder.**
- **Per i target ambigui, confronta una pagina reale con un percorso inesistente**, come `/_favicon_probe_<8-hex>`; risposte identiche di hosting o parking potrebbero spiegare l'icona condivisa.
- **Avvia il triage con le regole di detection di Nuclei o con dataset pubblici** che associano hash dei favicon a prodotti e CPE.
- **Ricorda il gap di copertura basato sugli IP**: le superfici dietro CDN, instradate tramite SNI, anycast e accessibili solo tramite dominio potrebbero non comparire nei dataset simili a quelli di Shodan.

### **Copyright / stringa univoca**

Cerca nelle pagine web **stringhe che potrebbero essere condivise da diversi siti della stessa organizzazione**. La **stringa di copyright** può essere un buon esempio. Poi cerca quella stringa in **Google**, in altri **browser** o anche in **Shodan**: `shodan search http.html:"Copyright string"`

### **Tempo CRT**

È comune avere un cron job come il seguente:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

per rinnovare contemporaneamente tutti i certificati su un server. Correlare i timestamp dei certificati o le posizioni nei log di certificate transparency può rivelare domini correlati.<sup>[[6]](#references)</sup>

Usa anche direttamente i log di **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni DMARC della posta

Puoi usare un sito web come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e sottodomini che condividono le stesse informazioni DMARC**.\
Altri strumenti utili sono [**spoofcheck**](https://github.com/BishopFox/spoofcheck) e [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un record A abbandonato può diventare raggiungibile quando un cloud provider riassegna un IP. La ricerca citata illustra un workflow opportunistico che crea un'istanza e correla il suo indirizzo con i dati DNS passivi; testa gli scenari di takeover solo nell'ambito autorizzato.<sup>[[7]](#references)</sup>

### **Altri metodi**

Ripeti i pivot di discovery pertinenti ogni volta che trovi un nuovo dominio: ogni risultato può rivelare ulteriori nomi nei certificati, relazioni DNS passive, corrispondenze di favicon e identificativi dell'organizzazione che non erano visibili partendo dal seed originale.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Conosci già il nome dell'organizzazione proprietaria dello spazio IP. Puoi cercare questi dati in Shodan usando: `org:"Tesla, Inc."` Controlla gli host trovati per individuare nuovi domini inattesi nel certificato TLS.

Puoi accedere al **certificato TLS** della pagina web principale, ottenere il **nome dell'organizzazione** e poi cercare quel nome nei **certificati TLS** di tutte le pagine web note a **Shodan** con il filtro : `ssl:"Tesla Motors"` oppure usare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)è uno strumento che cerca **domini correlati** a un dominio principale e i relativi **sottodomini**: è davvero fantastico.

**DNS passivo / DNS storico**

I dati DNS passivi sono ottimi per trovare **record vecchi e dimenticati** che continuano a risolvere o che possono essere acquisiti. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Ricerca di vulnerabilità**

Verifica la presenza di eventuali [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). È possibile che un'azienda **stia usando un dominio** ma **ne abbia perso la proprietà**. Registralo (se costa poco) e avvisa l'azienda.

Se trovi un **dominio con un IP diverso** da quelli già individuati durante la discovery degli asset, dovresti eseguire una **scansione di vulnerabilità di base** (usando Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. In base ai servizi in esecuzione, puoi trovare in **questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il dominio è ospitato su un IP non controllato dal cliente e quindi fuori scope: fai attenzione._

## Sottodomini

> Conosciamo tutte le aziende incluse nello scope, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È il momento di trovare tutti i possibili sottodomini di ciascun dominio individuato.

> [!TIP]
> Nota che alcuni degli strumenti e delle tecniche per trovare domini possono aiutare anche a trovare sottodomini

### **DNS**

Proviamo a ottenere **sottodomini** dai record **DNS**. Dovremmo anche provare a eseguire un **Zone Transfer** (se è vulnerabile, segnalalo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Il modo più rapido per ottenere molti sottodomini è cercarli in fonti esterne. Gli **strumenti** più usati sono i seguenti (per ottenere risultati migliori, configura le API key):


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

Esistono **altri strumenti/API interessanti** che, pur non essendo specializzati direttamente nella ricerca di sottodomini, possono essere utili per trovarli, come:

- API gratuita di [**IP.THC.ORG**](https://ip.thc.org)

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa l’API [https://sonar.omnisint.io](https://sonar.omnisint.io) per ottenere sottodomini

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**API gratuita JLDC**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) API gratuito

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

- [**gau**](https://github.com/lc/gau)**:** recupera gli URL noti da AlienVault's Open Threat Exchange, Wayback Machine e Common Crawl per un dominio specificato.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): effettuano scraping del web alla ricerca di file JS ed estraggono i sottodomini da questi file.

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

- [**Ricerca di sottodomini di Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/) offre un'API gratuita per cercare sottodomini e lo storico degli IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Questo progetto offre **gratuitamente tutti i sottodomini relativi ai programmi di bug bounty**. Puoi accedere a questi dati anche tramite [chaospy](https://github.com/dr-0x0x/chaospy) o consultare direttamente lo scope usato da questo progetto: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puoi trovare qui un **confronto** tra molti di questi strumenti: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **sottodomini** eseguendo il brute-force dei server DNS con possibili nomi di sottodomini.

Per questa attività ti serviranno alcune **wordlist di sottodomini comuni, ad esempio**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ti serviranno anche gli IP di buoni resolver DNS. Per generare un elenco di resolver DNS affidabili, puoi scaricare i resolver da [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e usare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. In alternativa, puoi usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più consigliati per il DNS brute-force sono:

- [**massdns**](https://github.com/blechschmidt/massdns): è stato il primo strumento a eseguire un DNS brute-force efficace. È molto veloce, ma tende a produrre falsi positivi.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Questo, credo, usa solo 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper per `massdns`, scritto in Go, che permette di enumerare sottodomini validi tramite bruteforce attivo e di risolvere sottodomini gestendo i wildcard, con un semplice supporto per input e output.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Usa anche `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio per eseguire brute force asincrono sui nomi di dominio.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Secondo round di brute-force DNS

Dopo aver trovato sottodomini usando fonti aperte e il brute-forcing, potresti generare variazioni dei sottodomini trovati per provare a trovarne ancora di più. Diversi strumenti sono utili a questo scopo:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dati i domini e i sottodomini, genera permutazioni.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Dati i domini e i sottodomini, genera permutazioni.
  - Puoi trovare la **wordlist** di permutazioni di goaltdns [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Genera permutazioni dati i domini e sottodomini. Se non viene indicato un file di permutazioni, gotator ne userà uno proprio.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di sottodomini, può anche provare a risolverli (ma è meglio usare gli strumenti citati in precedenza).
  - Puoi trovare la **wordlist** delle permutazioni di altdns [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per generare permutazioni, modifiche e varianti dei sottodomini. Questo strumento esegue il brute force dei risultati (non supporta i wildcard DNS).
  - Puoi trovare la wordlist delle permutazioni di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** A partire da un dominio, **genera potenziali nomi di sottodomini** in base ai pattern indicati, per provare a scoprirne altri.

#### Generazione intelligente di permutazioni

- [**regulator**](https://github.com/cramppet/regulator): Impara pattern simili a regex dai sottodomini scoperti e genera nomi candidati da risolvere.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un fuzzer per il brute-force dei sottodomini, abbinato a un algoritmo estremamente semplice ma efficace, guidato dalle risposte DNS. Utilizza un insieme di dati di input fornito, come una wordlist personalizzata o record DNS/TLS storici, per generare con precisione altri nomi di dominio corrispondenti e ampliarli ulteriormente in un ciclo, in base alle informazioni raccolte durante la scansione DNS.

```
echo www | subzuf facebook.com
```

### **Workflow di discovery dei sottodomini**

Gli esempi di workflow di Trickest combinano OSINT, DNS brute force e fasi di permutation per enumerare i sottodomini in modo ripetibile.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Se hai trovato un indirizzo IP che ospita **una o più pagine web** appartenenti a sottodomini, puoi provare a **trovare altri sottodomini con siti web su quell’IP** cercando **nelle fonti OSINT** i domini associati a un IP oppure eseguendo il **brute force dei nomi di dominio VHost su quell’IP**.

#### OSINT

Puoi trovare alcuni **VHosts negli IP usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre API**.

**Brute Force**

Se sospetti che un sottodominio possa essere nascosto in un web server, puoi provare a eseguire un brute force:

Per i vhost basati sul nome, esegui il fuzzing dell’header `Host` e usa l’auto-calibration di ffuf per filtrare la risposta predefinita.<sup>[[2]](#references)</sup>

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

A volte troverai pagine che restituiscono l’header _**Access-Control-Allow-Origin**_ solo quando nell’header _**Origin**_ viene specificato un dominio/sottodominio valido. In questi casi, puoi sfruttare questo comportamento per **scoprire** nuovi **sottodomini**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Mentre cerchi **subdomains**, fai attenzione a verificare se puntano a qualche tipo di **bucket** e, in tal caso, [**controllane i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, dato che a questo punto conoscerai tutti i domini inclusi nello scope, prova a [**fare brute force dei possibili nomi dei bucket e a controllarne i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoraggio**

Puoi **monitorare** la creazione di **nuovi subdomains** per un dominio controllando i log di **Certificate Transparency**, come fa [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Ricerca di vulnerabilità**

Controlla la presenza di possibili [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **subdomain** punta a un **bucket S3**, [**controllane i permessi**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi un **subdomain con un IP diverso** da quelli già individuati durante l'asset discovery, dovresti eseguire un **vulnerability scan di base** (usando Nessus o OpenVAS) e una [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. In base ai servizi in esecuzione, in **questo libro puoi trovare alcuni trucchi per "attaccarli"**.\
_Nota che a volte il subdomain è ospitato su un IP non controllato dal cliente, quindi non è nello scope: fai attenzione._

## IPs

Nei passaggi iniziali potresti aver **trovato alcuni range IP, domini e subdomains**.\
È il momento di **raccogliere tutti gli IP di quei range** e quelli dei **domini/subdomains (tramite query DNS).**

Usando i servizi delle seguenti **API gratuite** puoi anche trovare **IP usati in passato da domini e subdomains**. Questi IP potrebbero essere ancora di proprietà del cliente (e potrebbero consentirti di trovare [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Puoi anche cercare i domini che puntano a un indirizzo IP specifico usando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Ricerca di vulnerabilità**

Esegui una **port scan su tutti gli IP che non appartengono a CDN** (perché con ogni probabilità non troverai nulla di interessante). Tra i servizi in esecuzione individuati potresti **riuscire a trovare vulnerabilità**.

**Trova una** [**guida**](../pentesting-network/index.html) **su come eseguire la scansione degli host.**

## Caccia ai web server

> Abbiamo trovato tutte le aziende e i relativi asset e conosciamo i range IP, i domini e i subdomains inclusi nello scope. È il momento di cercare i web server.

Nei passaggi precedenti probabilmente hai già eseguito attività di **recon sugli IP e sui domini individuati**, quindi potresti **aver già trovato tutti i possibili web server**. In caso contrario, vediamo ora alcuni **trucchi rapidi per cercare web server** all'interno dello scope.

Tieni presente che questa attività sarà **orientata alla discovery di web app**, quindi dovresti eseguire anche **vulnerability scan** e **port scan** (**se consentito** dallo scope).

Qui trovi un [**metodo rapido per individuare le porte aperte**](../pentesting-network/index.html#http-port-discovery) relative ai web server usando [**masscan**](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento semplice da usare per cercare web server è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Basta passare un elenco di domini e lo strumento proverà a connettersi alle porte 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshot**

Ora che hai individuato **tutti i web server** presenti nell'ambito (tra gli **IP** dell'azienda e tutti i **domini** e **sottodomini**) probabilmente **non sai da dove iniziare**. Semplifichiamo: comincia facendo screenshot di tutti. Basta **dare un'occhiata** alla **pagina principale** per trovare endpoint **strani**, più **inclini** a essere **vulnerabili**.

Per mettere in pratica questa idea puoi usare [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, puoi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) per analizzare tutti gli **screenshot** e indicarti **quali probabilmente contengono vulnerabilità** e quali no.

## Risorse del cloud pubblico

Per individuare potenziali risorse cloud appartenenti a un'azienda, dovresti **partire da un elenco di parole chiave che la identificano**. Per esempio, per un'azienda crypto potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ti serviranno anche wordlist di **parole comuni usate nei bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con queste parole, dovresti generare **permutazioni** (per maggiori informazioni, consulta la [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Con le wordlist risultanti puoi usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Ricorda che, quando cerchi risorse cloud, dovresti **cercare più dei soli bucket in AWS**.

### **Ricerca di vulnerabilità**

Se trovi elementi come **bucket aperti o funzioni cloud esposte**, dovresti **accedervi** e provare a vedere cosa offrono e se puoi abusarne.

## Email

Con i **domini** e i **sottodomini** inclusi nell'ambito hai praticamente tutto ciò che **ti serve per iniziare a cercare email**. Queste sono le **API** e gli **strumenti** che hanno funzionato meglio per trovare le email di un'azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
- API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Ricerca di vulnerabilità**

Le email torneranno utili in seguito per fare **brute-force dei login web e dei servizi di autenticazione** (come SSH). Servono anche per il **phishing**. Inoltre, queste API ti forniranno ulteriori **informazioni sulla persona** associata all'email, utili per la campagna di phishing.

## Leak di credenziali

Con i **domini,** i **sottodomini** e le **email** puoi iniziare a cercare credenziali trapelate in passato e associate a quegli indirizzi email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Ricerca di vulnerabilità**

Se trovi credenziali **trapelate e valide**, è una vittoria facile.

## Leak di segreti

I leak di credenziali sono legati agli attacchi alle aziende in cui **informazioni sensibili sono state divulgate e vendute**. Tuttavia, le aziende potrebbero essere coinvolte in **altri leak** le cui informazioni non sono presenti in quei database:

### Leak su Github

Credenziali e API potrebbero essere state divulgate nei **repository pubblici** dell'**azienda** o degli **utenti** che lavorano per quell'azienda su Github.\
Puoi usare lo **strumento** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repository pubblici** di un'**organizzazione** e dei suoi **sviluppatori**, quindi eseguire automaticamente [**gitleaks**](https://github.com/zricethezav/gitleaks) su di essi.

**Leakos** può anche essere usato per eseguire **gitleaks** su tutti i **testi** forniti tramite **URL passati** allo strumento, perché a volte anche le **pagine web contengono segreti**.

#### Dorks di Github

Consulta la pagina [GitHub dorks and leaks](github-leaked-secrets.md) per trovare potenziali **GitHub dorks** da usare per cercare nell'organizzazione.

### Leak nei paste

A volte gli aggressori, o semplicemente i dipendenti, **pubblicano contenuti aziendali su un sito di paste**. Potrebbero contenere o meno **informazioni sensibili**, ma vale comunque la pena cercarli.\
Puoi usare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare contemporaneamente in più di 80 siti di paste.

### Google Dorks

I vecchi ma intramontabili Google dorks sono sempre utili per trovare **informazioni esposte che non dovrebbero essere accessibili**. L'unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di query possibili, che non puoi eseguire manualmente. Puoi quindi scegliere le tue 10 preferite oppure usare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirle tutte**.

_Nota che gli strumenti che tentano di consultare l'intero database usando il normale browser Google non finiranno mai, perché Google ti bloccherà molto presto._

### **Ricerca di vulnerabilità**

Se trovi credenziali **trapelate e valide** o token API, è una vittoria facile.

## Vulnerabilità nel codice pubblico

Se scopri che l'azienda ha **codice open source**, puoi **analizzarlo** e cercarvi **vulnerabilità**.

**A seconda del linguaggio**, puoi usare **strumenti** diversi; consulta l'elenco degli [strumenti per la revisione del codice sorgente](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Esistono anche servizi gratuiti che permettono di **analizzare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia di pentesting web**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilità** individuate dai bug hunter si trova nelle **applicazioni web**, quindi a questo punto vorrei parlare di una **metodologia di test delle applicazioni web**. Puoi [**trovare queste informazioni qui**](../../network-services-pentesting/pentesting-web/index.html).

Vorrei anche segnalare in particolare la sezione [**Strumenti open source per scanner web automatizzati**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners): anche se non dovresti aspettarti che individuino vulnerabilità molto sensibili, sono utili da integrare nei **workflow per ottenere alcune informazioni iniziali sul web**.

## Riepilogo

> Congratulazioni! A questo punto hai già completato **tutta l'enumerazione di base**. Sì, è di base perché si può fare molta altra enumerazione (vedremo altri trucchi più avanti).

Hai già:

1. Individuato tutte le **aziende** incluse nell'ambito
2. Individuato tutti gli **asset** appartenenti alle aziende (ed eseguito qualche scansione delle vulnerabilità, se rientrava nell'ambito)
3. Individuato tutti i **domini** appartenenti alle aziende
4. Individuato tutti i **sottodomini** dei domini (possibili subdomain takeover?)
5. Individuato tutti gli **IP** (sia **dietro CDN** sia **non dietro CDN**) inclusi nell'ambito.
6. Individuato tutti i **web server** e ne hai fatto uno **screenshot** (c'è qualcosa di strano che merita un'analisi più approfondita?)
7. Individuato tutte le **potenziali risorse cloud pubbliche** appartenenti all'azienda.
8. Trovato **email**, **leak di credenziali** e **leak di segreti** che potrebbero darti una **facile vittoria**.
9. Eseguito il **pentesting di tutti i siti web individuati**

## **Strumenti automatici per il recon completo**

Esistono diversi strumenti che eseguono alcune delle attività proposte su un determinato ambito.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po' datato e non aggiornato

## References

- [1] [Jason Haddix – La metodologia del bug hunter v4.0: edizione recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sulle favicon: dalle icone del browser all'intelligence della superficie d'attacco](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Come armare favicon.ico per bug bounty, OSINT e altro ancora](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Scoprire domini tramite un attacco di correlazione temporale alla Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: scoprire (e simulare) una costosa campagna di subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: un metodo unico per l'enumerazione dei sottodomini](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow completo per la scoperta dei sottodomini, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Scoperta dei sottodomini tramite brute-force con un workflow automatizzato di Trickest, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot dell'output di favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
