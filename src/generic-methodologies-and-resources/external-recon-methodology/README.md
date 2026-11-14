# Metodologia di ricognizione esterna

{{#include ../../banners/hacktricks-training.md}}

## Scoperta degli asset

> Ti è stato detto che tutto ciò che appartiene a una certa azienda rientra nello scope e vuoi capire cosa possiede effettivamente questa azienda.

L'obiettivo di questa fase è individuare tutte le **aziende possedute dalla società principale** e poi tutti gli **asset** di queste aziende. Per farlo, procederemo così:<sup>[[1]](#references)</sup>

1. Individuare le acquisizioni della società principale: questo ci permetterà di identificare le aziende incluse nello scope.
2. Individuare l'ASN (se presente) di ogni azienda: questo ci permetterà di trovare gli intervalli IP posseduti da ciascuna azienda.
3. Usare ricerche reverse whois per trovare altre voci (nomi di organizzazioni, domini...) correlate alla prima (si può procedere ricorsivamente).
4. Usare altre tecniche, come i filtri `org` e `ssl` di shodan, per cercare altri asset (il trucco `ssl` si può applicare ricorsivamente).

Per il passaggio graduale dai sottodomini risolti al crawling HTTP e alla scansione delle porte, consulta la [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Acquisizioni**

Per prima cosa, dobbiamo sapere **quali altre aziende appartengono alla società principale**.\
Un'opzione consiste nel visitare [https://www.crunchbase.com/](https://www.crunchbase.com), **cercare** la **società principale** e fare **clic** su "**acquisitions**". Qui troverai le altre aziende acquisite dalla società principale.\
Un'altra opzione consiste nel visitare la pagina **Wikipedia** della società principale e cercare le **acquisitions**.\
Per le società quotate in borsa, controlla i documenti **SEC/EDGAR**, le pagine **investor relations** o i registri delle imprese locali (ad esempio, **Companies House** nel Regno Unito).\
Per consultare gli alberi societari globali e le filiali, prova **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) e il database **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Bene, a questo punto dovresti conoscere tutte le aziende incluse nello scope. Vediamo come trovare i loro asset.

### **ASN**

Un autonomous system number (**ASN**) è un **numero univoco** assegnato a un **sistema autonomo** (AS) dalla **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** è composto da **blocchi** di **indirizzi IP** con una policy di accesso alle reti esterne definita in modo distinto. È amministrato da una singola organizzazione, ma può essere costituito da diversi operatori.

È utile scoprire se alla **società è stato assegnato un ASN**, così da individuare i suoi **intervalli IP**. Sarà utile eseguire un **test di vulnerabilità** su tutti gli **host** inclusi nello **scope** e **cercare domini** all'interno di questi IP.\
Puoi **cercare** per **nome** dell'azienda, **IP** o **dominio** su [**https://bgp.he.net/**](https://bgp.he.net) **oppure** [**https://ipinfo.io/**](https://ipinfo.io/).\
**A seconda della regione in cui si trova l'azienda, questi link possono essere utili per raccogliere altri dati:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Nord America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(America Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). In ogni caso, probabilmente tutte le informazioni** utili **(intervalli IP e Whois)** sono già disponibili nel primo link.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Inoltre, l'enumerazione di [**BBOT**](https://github.com/blacklanternsecurity/bbot) aggrega e riepiloga automaticamente gli ASN al termine della scansione.

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

Puoi anche trovare gli intervalli IP di un'organizzazione usando [ASNLookup](https://asnlookup.com/), che offre un piano API gratuito limitato.

### **Ricerca di vulnerabilità**

A questo punto conosciamo **tutti gli asset all'interno dello scope**, quindi, se hai l'autorizzazione, potresti avviare uno **scanner di vulnerabilità** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) su tutti gli host.\
Inoltre, potresti avviare delle [**scansioni delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **oppure usare servizi come** Shodan, Censys o ZoomEye **per trovare** porte aperte **e, in base a ciò che trovi, dovresti** consultare questo libro per scoprire come eseguire il pentest di diversi servizi potenzialmente in esecuzione.\
**Vale anche la pena ricordare che puoi preparare alcune liste di** username **e** password **predefiniti e provare a fare** bruteforce sui servizi con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domini

> Conosciamo tutte le aziende all'interno dello scope e i loro asset: è il momento di trovare i domini all'interno dello scope.

_Nota che con le tecniche proposte di seguito puoi trovare anche sottodomini e che queste informazioni non vanno sottovalutate._

Per prima cosa dovresti cercare il **dominio principale** di ciascuna azienda. Ad esempio, per _Tesla Inc._ è _tesla.com_.

### **Reverse DNS**

Dato che hai trovato tutti gli intervalli IP dei domini, potresti provare a eseguire **lookup DNS inversi** su quegli **IP per trovare altri domini all'interno dello scope**. Prova a usare un server DNS della vittima o un server DNS noto (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Affinché funzioni, l'amministratore deve abilitare manualmente il PTR.\
Puoi usare anche [SecurityTrails](https://securitytrails.com/) per ottenere queste informazioni, anche se i dati DNS storici richiedono un piano a pagamento.\
Per gli intervalli di grandi dimensioni, strumenti come [**massdns**](https://github.com/blechschmidt/massdns) e [**dnsx**](https://github.com/projectdiscovery/dnsx) sono utili per automatizzare le query inverse e l'arricchimento dei dati.

### **Reverse Whois (loop)**

In un **whois** puoi trovare molte **informazioni** interessanti, come **nome dell'organizzazione**, **indirizzo**, **email**, numeri di telefono... Ma ciò che è ancora più interessante è che puoi trovare **altri asset correlati all'azienda** eseguendo **query reverse whois usando uno qualsiasi di questi campi** (per esempio, altri registri whois in cui compare la stessa email).\
Puoi usare strumenti online come:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratuito** (Web e API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuito**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuito**
- [https://www.whoxy.com/](https://www.whoxy.com) - Interfaccia web **gratuita**; API a pagamento.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - A pagamento
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Non gratuito (solo **100 ricerche gratuite**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Non gratuito
- [https://securitytrails.com/](https://securitytrails.com/) - Accesso gratuito limitato all'API per DNS e sottodomini attuali; i dati storici e le query inverse richiedono un piano a pagamento.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 crediti API gratuiti alla registrazione; in seguito a pagamento.

Puoi automatizzare questa attività usando [**DomLink** ](https://github.com/vysecurity/DomLink)(richiede una chiave API whoxy).\
Puoi anche eseguire alcune ricerche automatiche di reverse whois con [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Nota che puoi usare questa tecnica per scoprire altri nomi di dominio ogni volta che ne trovi uno nuovo.**

### **Trackers**

Se trovi lo **stesso ID dello stesso tracker** in 2 pagine diverse, puoi supporre che **entrambe le pagine** siano **gestite dallo stesso team**.\
Per esempio, se vedi lo stesso **ID di Google Analytics** o lo stesso **ID di Adsense** su diverse pagine.

Esistono pagine e strumenti che permettono di cercare questi tracker e altri elementi:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Servizio web e API **a pagamento** ([prezzi](https://www.stackscan.com/pricing)); al momento non è pubblicizzato alcun piano gratuito. Cerca correlazioni basandoti su qualsiasi asset fornito, non solo sugli ID dei tracker: il percorso di uno script, il nome di un bundle self-hosted o l'host da cui viene caricato un asset, per individuare tutti i siti che lo includono.

L'API restituisce lo stack di un singolo dominio, utile per confermare che un asset candidato appartenga allo stesso ecosistema:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Restituisce ogni tecnologia rilevata con la relativa categoria. Il pivoting degli asset è attualmente disponibile solo per il web; l’API consente la ricerca per dominio.

### **Favicon**

Sapevi che possiamo trovare domini e sottodomini correlati al nostro target cercando lo stesso hash dell’icona favicon? È proprio quello che fa lo strumento [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), creato da [@m4ll0k2](https://twitter.com/m4ll0k2). Ecco come usarlo:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Risultati di Favihash usati per individuare domini che condividono lo stesso hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

In poche parole, favihash ci permette di individuare domini che hanno lo stesso hash dell'icona favicon del nostro target.

![Output di favihash usato per individuare domini con lo stesso hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Usa un hash favicon noto come pivot su Shodan o FOFA per trovare altre istanze esposte della stessa tecnologia.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ecco come puoi **calcolare l'hash del favicon** di un sito web (MMH3 sui byte del favicon **codificati in base64**):

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

Considera le impronte dei favicon come indizi e convalidale con i segnali circostanti.<sup>[[3]](#references)[[4]](#references)</sup>

- **Considera l'hash un indicatore, non una prova**: MMH3 è compatto; sono possibili collisioni, icone riutilizzate e falsificazioni intenzionali.
- **Esamina più di** `/favicon.ico`: controlla i percorsi di framework/build, i file manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, gli URL di dati inline e i tag HTML `<link rel="icon">`.
- **Le risorse statiche potrebbero rimanere accessibili dietro controlli WAF/SSO/IdP**: richiedi direttamente l'icona e controlla `ETag`, `Last-Modified`, reindirizzamenti e intestazioni di cache.
- **Convalida le corrispondenze con i segnali circostanti**: confronta il titolo, l'hash HTML/body, le intestazioni, i soggetti/SAN dei certificati TLS, i componenti del prodotto e le porte esposte.
- **Raggruppa in base all'hash HTML/body**: un template coerente rafforza l'impronta; template diversi suggeriscono un'icona generica o condivisa.
- **Considera un hash presente in firme, porte e prodotti non correlati come un possibile honeypot o segnaposto.**
- **Per gli obiettivi ambigui, confronta una pagina reale con un percorso inesistente**, ad esempio `/_favicon_probe_<8-hex>`; risposte identiche del servizio di hosting o di parcheggio del dominio possono spiegare l'icona condivisa.
- **Avvia il triage con le regole di rilevamento di Nuclei o con dataset pubblici** che associano gli hash dei favicon a prodotti e CPE.
- **Tieni presente il limite della copertura basata sugli IP**: le superfici che passano attraverso CDN, instradate tramite SNI, anycast o accessibili solo tramite dominio potrebbero non essere presenti in dataset simili a quelli di Shodan.

### **Copyright / stringa univoca**

Cerca nelle pagine web **stringhe che potrebbero essere condivise tra diversi siti della stessa organizzazione**. La **stringa di copyright** può essere un buon esempio. Poi cerca quella stringa su **google**, in altri **browser** o persino su **shodan**: `shodan search http.html:"Copyright string"`

### **Ora CRT**

È comune avere un cron job come il seguente 恒一

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

per rinnovare tutti i certificati di un server contemporaneamente. Correlare i timestamp dei certificati o le posizioni nei log di certificate transparency può rivelare domini correlati.<sup>[[6]](#references)</sup>

Usa anche direttamente i log di **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informazioni DMARC della posta

Puoi usare un sito web come [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o uno strumento come [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) per trovare **domini e sottodomini che condividono le stesse informazioni DMARC**.\
Un altro servizio utile è [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un record A abbandonato può diventare raggiungibile quando un cloud provider riassegna un IP. La ricerca citata illustra un workflow opportunistico che crea un'istanza e ne correla l'indirizzo con dati DNS passivi; verifica gli scenari di takeover solo nell'ambito autorizzato.<sup>[[7]](#references)</sup>

### **Altri metodi**

Ripeti i pivot di discovery pertinenti ogni volta che trovi un nuovo dominio: ogni risultato può rivelare ulteriori nomi nei certificati, relazioni DNS passive, corrispondenze di favicon e identificativi dell'organizzazione non visibili a partire dal seed originale.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Dato che conosci già il nome dell'organizzazione che possiede lo spazio IP, puoi cercare su Shodan usando questo dato: `org:"Tesla, Inc."` Controlla gli host trovati per individuare nuovi domini imprevisti nel certificato TLS.

Puoi accedere al **certificato TLS** della pagina web principale, ricavare il **nome dell'organizzazione** e poi cercare quel nome nei **certificati TLS** di tutte le pagine web note a **Shodan** usando il filtro: `ssl:"Tesla Motors"` oppure usare uno strumento come [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)è uno strumento che cerca **domini correlati** a un dominio principale e i relativi **sottodomini**: è davvero notevole.

**DNS passivo / DNS storico**

I dati DNS passivi sono ottimi per trovare **record vecchi e dimenticati** che continuano a risolversi o che possono essere oggetto di takeover. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Ricerca di vulnerabilità**

Verifica la presenza di un [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Potrebbe esserci un'azienda che **utilizza un dominio** ma **ne ha perso la proprietà**. Registralo (se costa poco) e avvisa l'azienda.

Se trovi un **dominio con un IP diverso** da quelli già individuati durante la discovery degli asset, dovresti eseguire una **scansione di base delle vulnerabilità** (con Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. A seconda dei servizi in esecuzione, puoi trovare **in questo libro alcuni trucchi per "attaccarli"**.\
_Nota che a volte il dominio è ospitato su un IP non controllato dal cliente, quindi non rientra nello scope: fai attenzione._

## Sottodomini

> Conosciamo tutte le aziende nello scope, tutti gli asset di ciascuna azienda e tutti i domini correlati alle aziende.

È il momento di trovare tutti i possibili sottodomini di ciascun dominio individuato.

> [!TIP]
> Nota che alcuni strumenti e tecniche per trovare domini possono essere utili anche per trovare sottodomini

### **DNS**

Proviamo a ricavare **sottodomini** dai record **DNS**. Dovremmo provare anche il **Zone Transfer** (se è vulnerabile, segnalalo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Per le API e le piattaforme che coprono infrastruttura, reputazione, registri di breach ed enrichment oltre alla scoperta dei sottodomini, consulta il [catalogo delle API di reconnaissance e threat intelligence](reconnaissance-and-threat-intelligence-apis.md).

Il modo più rapido per ottenere molti sottodomini è cercarli in fonti esterne. Gli **strumenti** più utilizzati sono i seguenti (per ottenere risultati migliori, configura le API key):


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

Ci sono **altri strumenti/API interessanti** che, anche se non sono specializzati direttamente nella ricerca di sottodomini, potrebbero essere utili per trovarli, come:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB API gratuita**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** recupera URL noti da AlienVault's Open Threat Exchange, Wayback Machine e Common Crawl per qualsiasi dominio.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Esplorano il web alla ricerca di file JS ed estraggono i sottodomini da questi.

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

- [**SecurityTrails**](https://securitytrails.com/) offre accesso API gratuito limitato per i dati DNS e dei subdomain attuali; per i dati storici DNS/IP è necessario un piano a pagamento.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Questo progetto offre **gratuitamente tutti i subdomain relativi ai programmi bug-bounty**. Puoi accedere a questi dati anche tramite [chaospy](https://github.com/Moaaz-0x/chaospy) o persino accedere allo scope usato da questo progetto [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Puoi trovare un **confronto** di molti di questi strumenti qui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Proviamo a trovare nuovi **subdomain** eseguendo il brute-force dei server DNS con possibili nomi di subdomain.

Per questa operazione ti serviranno alcune **wordlist comuni di subdomain, come**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Inoltre, ti serviranno gli IP di buoni DNS resolver. Per generare un elenco di DNS resolver affidabili, puoi scaricare i resolver da [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) e usare [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) per filtrarli. In alternativa, puoi usare: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Gli strumenti più consigliati per il DNS brute-force sono:

- [**massdns**](https://github.com/blechschmidt/massdns): è stato il primo strumento a eseguire efficacemente il DNS brute-force. È molto veloce, ma tende a produrre falsi positivi.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Questo, credo, usa un solo resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) è un wrapper per `massdns`, scritto in go, che permette di enumerare sottodomini validi tramite bruteforce attivo, oltre a risolvere sottodomini con gestione dei wildcard e un semplice supporto input-output.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Usa anche `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio per eseguire il brute force dei nomi di dominio in modo asincrono.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Secondo round di brute-force DNS

Dopo aver trovato sottodomini tramite fonti aperte e brute-force, puoi generare variazioni dei sottodomini trovati per provare a trovarne altri. A questo scopo sono utili diversi strumenti:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Genera permutazioni a partire da domini e sottodomini.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genera permutazioni a partire da domini e sottodomini.
  - Puoi trovare [**qui**](https://github.com/subfinder/goaltdns/blob/master/words.txt) la **wordlist** delle permutazioni di goaltdns.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** A partire dai domini e sottodomini genera permutazioni. Se non viene specificato un file di permutazioni, gotator ne utilizza uno proprio.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Oltre a generare permutazioni di sottodomini, può anche provare a risolverli (ma è meglio usare gli strumenti menzionati in precedenza).
  - Puoi trovare la **wordlist** delle permutazioni di altdns [**qui**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Un altro strumento per eseguire permutazioni, mutazioni e alterazioni dei sottodomini. Questo strumento eseguirà brute force sul risultato (non supporta il wildcard DNS).
  - Puoi trovare la wordlist delle permutazioni di dmut [**qui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** A partire da un dominio, **genera potenziali nuovi nomi di sottodomini** in base ai pattern indicati, per cercare di scoprirne altri.

#### Generazione di permutazioni intelligenti

- [**regulator**](https://github.com/cramppet/regulator): Apprende pattern simili a regex dai sottodomini individuati e genera nomi candidati da risolvere.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ è un fuzzer per il brute-force dei sottodomini, abbinato a un algoritmo estremamente semplice ma efficace guidato dalle risposte DNS. Utilizza un set di dati di input fornito, come una wordlist personalizzata o record DNS/TLS storici, per generare con precisione altri nomi di dominio corrispondenti e ampliarli ulteriormente in un ciclo, basandosi sulle informazioni raccolte durante la scansione DNS.

```
echo www | subzuf facebook.com
```

### **Workflow di discovery dei sottodomini**

Gli esempi di workflow di Trickest combinano OSINT, DNS brute force e fasi di permutazione per enumerare i sottodomini in modo ripetibile.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Se hai trovato un indirizzo IP che ospita **una o più pagine web** appartenenti a sottodomini, puoi provare a **trovare altri sottodomini con siti web su quell'IP** cercando **fonti OSINT** per individuare domini associati a un IP oppure eseguendo un **brute force dei nomi di dominio VHost su quell'IP**.

#### OSINT

Puoi trovare alcuni **VHosts sugli IP usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o altre API**.

**Brute Force**

Se sospetti che un sottodominio sia nascosto su un web server, puoi provare a eseguire un brute force:

Per i vhost basati sul nome, esegui il fuzzing dell'header `Host` e usa l'auto-calibrazione di ffuf per filtrare la risposta predefinita.<sup>[[2]](#references)</sup>

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

A volte troverai pagine che restituiscono l'header _**Access-Control-Allow-Origin**_ solo quando nell'header _**Origin**_ è impostato un dominio/sottodominio valido. In questi scenari, puoi abusare di questo comportamento per **scoprire** nuovi **sottodomini**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute force dei bucket**

Quando cerchi **sottodomini**, controlla se uno di essi **punta** a un qualche tipo di **bucket** e, in tal caso, [**verifica le autorizzazioni**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Inoltre, a questo punto conoscerai tutti i domini inclusi nello scope: prova quindi a [**indovinare con il brute force i possibili nomi dei bucket e verificarne le autorizzazioni**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitoraggio**

Puoi **monitorare** la creazione di **nuovi sottodomini** per un dominio seguendo i log di **Certificate Transparency**, come fa [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Ricerca di vulnerabilità**

Verifica la presenza di possibili [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se il **sottodominio** punta a un **bucket S3**, [**verifica le autorizzazioni**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Se trovi un **sottodominio con un IP diverso** da quelli già individuati durante la ricognizione degli asset, dovresti eseguire una **scansione di base delle vulnerabilità** (con Nessus o OpenVAS) e una [**scansione delle porte**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. In base ai servizi in esecuzione, in **questo libro puoi trovare alcuni trucchi per "attaccarli"**.\
_Nota che a volte il sottodominio è ospitato su un IP non controllato dal cliente e quindi non rientra nello scope: fai attenzione._

## IP

Durante le fasi iniziali potresti aver **individuato alcuni intervalli IP, domini e sottodomini**.\
È il momento di **raccogliere tutti gli IP di quegli intervalli** e quelli associati ai **domini/sottodomini (tramite query DNS).**

Usando servizi come quelli elencati di seguito, puoi trovare anche **IP precedentemente usati da domini e sottodomini**. Questi IP potrebbero essere ancora di proprietà del cliente (e permetterti di individuare [**bypass di CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (i dati storici DNS/IP richiedono un piano a pagamento)

Puoi anche verificare quali domini puntano a un indirizzo IP specifico usando lo strumento [**hakip2host**](https://github.com/hakluke/hakip2host).

### **Ricerca di vulnerabilità**

**Esegui una scansione delle porte su tutti gli IP che non appartengono a CDN** (poiché con ogni probabilità non troverai nulla di interessante). Tra i servizi in esecuzione che individuerai potresti **trovare delle vulnerabilità**.

**Consulta una** [**guida**](../pentesting-network/index.html) **su come scansionare gli host.**

## Ricerca di server web

> Abbiamo individuato tutte le aziende e i relativi asset e conosciamo gli intervalli IP, i domini e i sottodomini inclusi nello scope. È il momento di cercare i server web.

Nelle fasi precedenti probabilmente hai già eseguito una **ricognizione degli IP e dei domini individuati**, quindi potresti aver già trovato **tutti i possibili server web**. Se non è così, vediamo ora alcuni **metodi rapidi per cercare server web** nello scope.

Tieni presente che questa procedura è **orientata all’individuazione di web app**, quindi dovresti eseguire anche la **scansione delle vulnerabilità** e delle **porte** (**se consentito** dallo scope).

[**Qui trovi un metodo rapido**](../pentesting-network/index.html#http-port-discovery) per individuare le **porte aperte** associate ai server **web** usando [**masscan**](../pentesting-network/index.html#http-port-discovery).\
Un altro strumento pratico per cercare server web è [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Basta passargli un elenco di domini e proverà a connettersi alle porte 80 (http) e 443 (https). Inoltre, puoi indicare di provare altre porte:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshot**

Ora che hai individuato **tutti i web server** presenti nell’ambito (tra gli **IP** dell’azienda e tutti i **domini** e **sottodomini**), probabilmente **non sai da dove iniziare**. Semplifichiamo le cose e cominciamo semplicemente a fare screenshot di tutti. Basta **dare un’occhiata** alla **pagina principale** per trovare endpoint **insoliti** che hanno maggiori **probabilità** di essere **vulnerabili**.

Per mettere in pratica questa idea puoi usare [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) oppure [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Inoltre, puoi usare [**eyeballer**](https://github.com/BishopFox/eyeballer) per analizzare tutti gli **screenshot** e indicarti **quali potrebbero contenere vulnerabilità** e quali no.

## Risorse cloud pubbliche

Per individuare potenziali risorse cloud appartenenti a un’azienda, dovresti **iniziare con un elenco di parole chiave che la identificano**. Per esempio, per un’azienda crypto potresti usare parole come: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ti serviranno anche wordlist di **parole comuni usate nei bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Poi, con queste parole dovresti generare **permutazioni** (per maggiori informazioni, consulta il [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Con le wordlist risultanti puoi usare strumenti come [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **oppure** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Quando cerchi risorse cloud, ricorda che dovresti **cercare altro oltre ai bucket in AWS**.

### **Ricerca di vulnerabilità**

Se trovi elementi come **bucket aperti o funzioni cloud esposte**, dovresti **accedervi** e verificare cosa offrono e se puoi abusarne.

## Email

Con i **domini** e i **sottodomini** inclusi nell’ambito hai praticamente tutto ciò che **ti serve per iniziare a cercare email**. Queste sono le **API** e gli **strumenti** che hanno funzionato meglio per trovare le email di un’azienda:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API di [**https://hunter.io/**](https://hunter.io/) (versione gratuita)
- API di [**https://app.snov.io/**](https://app.snov.io/) (versione gratuita)
- API di [**https://minelead.io/**](https://minelead.io/) (versione gratuita)

### **Ricerca di vulnerabilità**

Le email torneranno utili in seguito per fare **brute-force sui login web e sui servizi di autenticazione** (come SSH). Servono anche per le **campagne di phishing**. Inoltre, queste API ti forniranno altre **informazioni sulla persona** che si cela dietro l’email, utili per la campagna di phishing.

## Leak di credenziali

Con **domini**, **sottodomini** ed **email** puoi iniziare a cercare credenziali finite in leak in passato e associate a quegli indirizzi email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Ricerca di vulnerabilità**

Se trovi credenziali **valide finite in un leak**, è un risultato molto facile da ottenere.

## Leak di segreti

I leak di credenziali sono legati ad attacchi contro aziende in cui **informazioni sensibili sono state divulgate e vendute**. Tuttavia, le aziende potrebbero essere coinvolte in **altri leak** le cui informazioni non si trovano in quei database:

### Leak su Github

Credenziali e API potrebbero essere finite in leak nei **repository pubblici** dell’**azienda** o degli **utenti** che lavorano per quell’azienda su GitHub.\
Puoi usare lo **strumento** [**Leakos**](https://github.com/carlospolop/Leakos) per **scaricare** tutti i **repository pubblici** di un’**organizzazione** e dei suoi **sviluppatori**, quindi eseguire automaticamente [**gitleaks**](https://github.com/gitleaks/gitleaks) su di essi.

Puoi usare **Leakos** anche per eseguire **gitleaks** su tutti gli **URL di testo** forniti, perché a volte anche le **pagine web contengono segreti**.

#### Dorks di Github

Consulta la [pagina GitHub dorks and leaks](github-leaked-secrets.md) per trovare potenziali **GitHub dorks** da cercare nell’organizzazione.

### Leak su Paste

A volte gli aggressori, o semplicemente i dipendenti, **pubblicano contenuti aziendali su un sito di paste**. Potrebbero contenere o meno **informazioni sensibili**, ma vale comunque la pena cercarli.\
Puoi usare lo strumento [**Pastos**](https://github.com/carlospolop/Pastos) per cercare contemporaneamente in oltre 80 siti di paste.

### Google Dorks

I vecchi ma sempre validi Google dorks sono utili per trovare **informazioni esposte che non dovrebbero essere accessibili**. L’unico problema è che il [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene diverse **migliaia** di query possibili, impossibili da eseguire manualmente. Puoi quindi scegliere le tue 10 preferite oppure usare uno **strumento come** [**Gorks**](https://github.com/carlospolop/Gorks) **per eseguirle tutte**.

_Nota: gli strumenti che cercano di consultare l’intero database usando il normale browser Google non finiranno mai, perché Google ti bloccherà molto, molto presto._

### **Ricerca di vulnerabilità**

Se trovi credenziali **valide finite in un leak** o token API, è un risultato molto facile da ottenere.

## Vulnerabilità nel codice pubblico

Se hai scoperto che l’azienda dispone di **codice open source**, puoi **analizzarlo** e cercare **vulnerabilità**.

**A seconda del linguaggio**, puoi usare **strumenti** diversi; consulta l’elenco dei [tool per la revisione del codice sorgente](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Esistono anche servizi gratuiti che consentono di **analizzare repository pubblici**, come:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia di pentesting web**](../../network-services-pentesting/pentesting-web/index.html)

La **maggior parte delle vulnerabilità** individuate dai bug hunter si trova nelle **applicazioni web**, quindi a questo punto vorrei parlare di una **metodologia di testing delle applicazioni web**. Puoi [**trovare qui queste informazioni**](../../network-services-pentesting/pentesting-web/index.html).

Vorrei inoltre segnalare in particolare la sezione [**Strumenti open source per scanner automatizzati web**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners): anche se non dovresti aspettarti che trovino vulnerabilità molto sensibili, sono utili da integrare nei **workflow per ottenere alcune informazioni iniziali sul web**.

## Riepilogo

> Congratulazioni! A questo punto hai già completato **tutta l’enumerazione di base**. Sì, è di base perché si può fare molta altra enumerazione (vedremo altri trucchi più avanti).

Hai già:

1. Individuato tutte le **aziende** incluse nell’ambito
2. Individuato tutte le **risorse** appartenenti alle aziende (ed eseguito una scansione delle vulnerabilità, se rientrava nell’ambito)
3. Individuato tutti i **domini** appartenenti alle aziende
4. Individuato tutti i **sottodomini** dei domini (possibili subdomain takeover?)
5. Individuato tutti gli **IP** (sia provenienti da **CDN** che non) inclusi nell’ambito.
6. Individuato tutti i **web server** e ne hai fatto uno **screenshot** (c’è qualcosa di insolito che merita un’analisi più approfondita?)
7. Individuato tutte le **potenziali risorse cloud pubbliche** appartenenti all’azienda.
8. Trovato **email**, **leak di credenziali** e **leak di segreti** che potrebbero consentirti di ottenere **facilmente un grande risultato**.
9. Eseguito il **pentesting di tutti i siti web trovati**

## **Strumenti automatici per il recon completo**

Esistono diversi strumenti che eseguono parte delle attività proposte su un determinato ambito.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un po’ datato e non aggiornato



## References

- [1] [Jason Haddix – La metodologia del bug hunter v4.0: edizione ricognizione](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sulle favicon: dalle icone del browser alla threat intelligence della superficie d’attacco](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Rendere weaponized favicon.ico per bug bounty, OSINT e altro](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Scoprire domini tramite un attacco di correlazione temporale alla Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Subdomain takeover passivo: individuare (e replicare) una costosa campagna di subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: un metodo unico per enumerare i sottodomini](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow completo per la scoperta dei sottodomini, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Scoperta completa dei sottodomini tramite brute-force con un workflow automatizzato di Trickest, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot dell’output di favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
