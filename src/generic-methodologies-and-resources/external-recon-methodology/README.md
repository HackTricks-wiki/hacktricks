# Méthodologie de reconnaissance externe

{{#include ../../banners/hacktricks-training.md}}

## Découverte des actifs

> On vous a dit que tout ce qui appartient à une entreprise est dans le périmètre, et vous voulez déterminer ce que cette entreprise possède réellement.

L’objectif de cette phase est d’identifier toutes les **entreprises détenues par l’entreprise principale**, puis tous les **actifs** de ces entreprises. Pour cela, nous allons :<sup>[[1]](#references)</sup>

1. Trouver les acquisitions de l’entreprise principale afin d’identifier les entreprises dans le périmètre.
2. Trouver l’ASN (le cas échéant) de chaque entreprise afin d’identifier les plages IP qu’elle possède.
3. Utiliser des recherches reverse whois pour trouver d’autres entrées (noms d’organisations, domaines...) liées à la première (cette démarche peut être répétée récursivement).
4. Utiliser d’autres techniques, comme les filtres `org` et `ssl` de shodan, pour rechercher d’autres actifs (l’astuce `ssl` peut être utilisée récursivement).

### **Acquisitions**

Tout d’abord, nous devons savoir quelles **autres entreprises appartiennent à l’entreprise principale**.\
Une possibilité consiste à consulter [https://www.crunchbase.com/](https://www.crunchbase.com), à **rechercher** l’**entreprise principale**, puis à cliquer sur "**acquisitions**". Vous y trouverez les autres entreprises acquises par l’entreprise principale.\
Une autre possibilité consiste à consulter la page **Wikipedia** de l’entreprise principale et à rechercher les **acquisitions**.\
Pour les entreprises cotées en bourse, consultez les documents **SEC/EDGAR**, les pages de **relations avec les investisseurs** ou les registres locaux des entreprises (par exemple, **Companies House** au Royaume-Uni).\
Pour trouver les structures d’entreprise et les filiales à l’échelle mondiale, essayez **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) et la base de données **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> D’accord, à ce stade, vous devriez connaître toutes les entreprises dans le périmètre. Voyons comment trouver leurs actifs.

### **ASN**

Un numéro de système autonome (**ASN**) est un **numéro unique** attribué à un **système autonome** (AS) par l’**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** se compose de **blocs** d’**adresses IP** dont la politique d’accès aux réseaux externes est définie de manière distincte. Il est administré par une seule organisation, mais peut regrouper plusieurs opérateurs.

Il est intéressant de vérifier si un **ASN a été attribué à l’entreprise** afin de trouver ses **plages IP**. Il peut être utile d’effectuer un **test de vulnérabilité** sur tous les **hôtes** dans le **périmètre** et de **rechercher les domaines** présents dans ces plages IP.\
Vous pouvez effectuer une **recherche** par **nom** d’entreprise, par **IP** ou par **domaine** sur [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Selon la région où se trouve l’entreprise, ces liens peuvent être utiles pour recueillir davantage de données :** [**AFRINIC**](https://www.afrinic.net) **(Afrique),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amérique du Nord),** [**APNIC**](https://www.apnic.net) **(Asie),** [**LACNIC**](https://www.lacnic.net) **(Amérique latine),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Quoi qu’il en soit, la plupart des informations** utiles **(plages IP et Whois)** figurent probablement déjà dans le premier lien.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Aussi, l'énumération de [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrège et résume automatiquement les ASN à la fin du scan.

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

Vous pouvez également trouver les plages IP d’une organisation sur [http://asnlookup.com/](http://asnlookup.com) (l’API est gratuite).\
Vous pouvez trouver l’adresse IP et l’ASN d’un domaine sur [http://ipv4info.com/](http://ipv4info.com).

### **Recherche de vulnérabilités**

À ce stade, nous connaissons **tous les actifs dans le périmètre**. Si vous y êtes autorisé, vous pouvez donc lancer un **scanner de vulnérabilités** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sur tous les hôtes.\
Vous pouvez aussi lancer des [**scans de ports**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou utiliser des services comme** Shodan, Censys ou ZoomEye **pour trouver** des ports ouverts. **En fonction de vos découvertes, vous devriez** consulter ce livre pour savoir comment pentester les différents services susceptibles de fonctionner.\
**Il peut aussi être utile de préparer des listes de noms d’utilisateur** et de mots de passe **par défaut et d’essayer de** bruteforce les services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises dans le périmètre et leurs actifs. Il est temps de trouver les domaines qui en font partie.

_À noter que les techniques proposées ci-dessous peuvent également permettre de trouver des sous-domaines. Ces informations ne doivent pas être sous-estimées._

Tout d’abord, cherchez le ou les **domaines principaux** de chaque entreprise. Par exemple, pour _Tesla Inc._, il s’agira de _tesla.com_.

### **Reverse DNS**

Comme vous avez trouvé toutes les plages IP des domaines, vous pouvez essayer d’effectuer des **reverse DNS lookups** sur ces **adresses IP afin de trouver d’autres domaines dans le périmètre**. Essayez d’utiliser un serveur DNS de la victime ou un serveur DNS connu (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Pour que cela fonctionne, l’administrateur doit activer manuellement le PTR.\
Vous pouvez également utiliser un outil en ligne pour obtenir ces informations : [http://ptrarchive.com/](http://ptrarchive.com).\
Pour les grandes plages, des outils comme [**massdns**](https://github.com/blechschmidt/massdns) et [**dnsx**](https://github.com/projectdiscovery/dnsx) sont utiles pour automatiser les recherches inverses et l’enrichissement des données.

### **Reverse Whois (boucle)**

Dans un **whois**, vous pouvez trouver de nombreuses **informations** intéressantes, comme le **nom de l’organisation**, l’**adresse**, les **adresses e-mail**, les numéros de téléphone... Mais le plus intéressant, c’est que vous pouvez découvrir **d’autres actifs liés à l’entreprise** en effectuant des **recherches inverses whois à partir de l’un de ces champs** (par exemple, d’autres registres whois où apparaît la même adresse e-mail).\
Vous pouvez utiliser des outils en ligne comme :

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratuit** (Web et API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuit**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuit**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuit**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratuit** sur le Web, API payante.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Payant
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Payant (**100 recherches gratuites** uniquement)
- [https://www.domainiq.com/](https://www.domainiq.com) - Payant
- [https://securitytrails.com/](https://securitytrails.com/) - Payant (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Payant (API)

Vous pouvez automatiser cette tâche avec [**DomLink** ](https://github.com/vysecurity/DomLink) (nécessite une clé API whoxy).\
Vous pouvez également effectuer une recherche automatique de reverse whois avec [amass](https://github.com/OWASP/Amass) : `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir d’autres noms de domaine chaque fois que vous en trouvez un nouveau.**

### **Trackers**

Si vous trouvez le **même ID de tracker** sur 2 pages différentes, vous pouvez supposer que **les deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **ID Google Analytics** ou le même **ID Adsense** sur plusieurs pages.

Il existe des pages et des outils qui permettent d’effectuer des recherches à partir de ces trackers et d’autres éléments :

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trouve des sites associés grâce aux analytics/trackers partagés)
- [**StackScan**](https://www.stackscan.com) - **Offre gratuite** (Web et API). Permet de rechercher à partir de n’importe quel actif servi, pas seulement des ID de trackers : un chemin de script, le nom d’un bundle hébergé en interne ou l’hôte depuis lequel un actif est chargé. Il renvoie tous les sites qui l’intègrent.

L’API renvoie la stack d’un seul domaine, ce qui est utile pour confirmer qu’un actif candidat appartient au même ensemble :

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Renvoie chaque technologie détectée avec sa catégorie. Le pivotement d’assets est actuellement limité au web ; l’API permet une recherche par domaine.

### **Favicon**

Saviez-vous que nous pouvons trouver des domaines et sous-domaines associés à notre cible en recherchant la même empreinte de hash d’icône favicon ? C’est exactement ce que fait l’outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), créé par [@m4ll0k2](https://twitter.com/m4ll0k2). Voici comment l’utiliser :

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Résultats de Favihash utilisés pour découvrir des domaines partageant un hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En bref, favihash nous permet de découvrir les domaines qui ont le même hash d’icône favicon que notre cible.

![Sortie de favihash utilisée pour découvrir des domaines ayant le même hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Utilisez un hash de favicon connu comme pivot dans Shodan ou FOFA pour trouver d’autres instances exposées de la même technologie.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

This is how you can **calculer le hash du favicon** d'un site web (MMH3 sur les octets du favicon **encodés en base64**) :

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

Vous pouvez également obtenir des hashes de favicon à grande échelle avec [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), puis pivoter dans Shodan/Censys.

Considérez les empreintes de favicon comme des pistes et validez-les à l’aide des signaux environnants.<sup>[[3]](#references)[[4]](#references)</sup>

- **Considérez le hash comme un indicateur, pas comme une preuve** : MMH3 est compact ; des collisions, des icônes réutilisées et une usurpation délibérée sont possibles.
- **Ne vous limitez pas à** `/favicon.ico` : inspectez les chemins liés aux frameworks/builds, les fichiers manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, les data URLs inline et les balises HTML `<link rel="icon">`.
- **Les assets statiques peuvent rester accessibles derrière des contrôles WAF/SSO/IdP** : demandez directement l’icône et examinez `ETag`, `Last-Modified`, les redirections et les en-têtes de cache.
- **Validez les correspondances à l’aide des signaux environnants** : comparez le titre, le hash HTML/body, les en-têtes, les sujets/SAN des certificats TLS, les composants du produit et les ports exposés.
- **Regroupez par hash HTML/body** : un template cohérent renforce l’empreinte ; des templates différents suggèrent une icône générique ou partagée.
- **Considérez qu’un hash apparaissant sur des signatures, ports et produits sans lien entre eux peut indiquer un honeypot ou un placeholder.**
- **Pour les cibles ambiguës, comparez une vraie page avec un chemin inexistant**, comme `/_favicon_probe_<8-hex>` ; des réponses d’hébergement ou de parking identiques peuvent expliquer l’icône partagée.
- **Amorcez le triage à l’aide des règles de détection Nuclei ou de jeux de données publics** qui associent les hashes de favicon à des produits et à des CPE.
- **N’oubliez pas les lacunes de couverture centrée sur les IP** : les surfaces derrière un CDN, routées par SNI, anycast et accessibles uniquement par domaine peuvent être absentes des jeux de données de type Shodan.

### **Copyright / chaîne unique**

Recherchez dans les pages web des **chaînes susceptibles d’être partagées par différents sites d’une même organisation**. La **chaîne de copyright** peut en être un bon exemple. Recherchez ensuite cette chaîne sur **Google**, dans d’autres **navigateurs**, voire dans **Shodan** : `shodan search http.html:"Copyright string"`

### **Heure CRT**

Il est courant d’avoir une tâche cron telle que

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

pour renouveler tous les certificats d’un serveur en même temps. La corrélation des horodatages des certificats ou de leur position dans les journaux de transparence des certificats peut révéler des domaines associés.<sup>[[6]](#references)</sup>

Utilisez également directement les journaux de **transparence des certificats** :

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informations DMARC du courrier

Vous pouvez utiliser un site web comme [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou un outil comme [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) pour trouver les **domaines et sous-domaines partageant les mêmes informations DMARC**.\
D’autres outils utiles sont [**spoofcheck**](https://github.com/BishopFox/spoofcheck) et [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un enregistrement A abandonné peut redevenir accessible lorsqu’un fournisseur cloud réattribue une adresse IP. L’étude citée présente un processus opportuniste qui provisionne une instance et corrèle son adresse avec les données DNS passives ; ne testez les scénarios de takeover que dans le périmètre autorisé.<sup>[[7]](#references)</sup>

### **Autres méthodes**

Répétez les pivots de découverte applicables chaque fois que vous trouvez un nouveau domaine : chaque résultat peut révéler des noms de certificats supplémentaires, des liens DNS passifs, des correspondances de favicon et des identifiants d’organisation qui n’étaient pas visibles à partir du domaine initial.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Comme vous connaissez déjà le nom de l’organisation propriétaire de l’espace IP, vous pouvez effectuer une recherche dans Shodan à l’aide de ces données : `org:"Tesla, Inc."` Vérifiez si les hôtes trouvés présentent de nouveaux domaines inattendus dans leur certificat TLS.

Vous pouvez accéder au **certificat TLS** de la page web principale, récupérer le **nom de l’organisation**, puis rechercher ce nom dans les **certificats TLS** de toutes les pages web connues de **Shodan**, avec le filtre : `ssl:"Tesla Motors"`, ou utiliser un outil comme [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)est un outil qui recherche les **domaines associés** à un domaine principal et leurs **sous-domaines** ; il est vraiment impressionnant.

**DNS passif / DNS historique**

Les données DNS passives sont très utiles pour trouver les **anciens enregistrements oubliés** qui se résolvent encore ou qui peuvent faire l’objet d’un takeover. Consultez :

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Recherche de vulnérabilités**

Vérifiez s’il existe un [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Une entreprise **utilise peut-être un domaine**, mais en a **perdu la propriété**. Enregistrez-le simplement (s’il est suffisamment bon marché), puis informez l’entreprise.

Si vous trouvez un **domaine dont l’adresse IP est différente** de celles déjà découvertes lors de l’identification des actifs, vous devriez effectuer un **scan de vulnérabilités de base** (avec Nessus ou OpenVAS) et un [**scan de ports**](../pentesting-network/index.html#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services en cours d’exécution, vous trouverez dans **ce livre quelques astuces pour les « attaquer »**.\
_Notez que le domaine est parfois hébergé sur une adresse IP qui n’est pas contrôlée par le client et ne fait donc pas partie du périmètre ; soyez prudent._

## Sous-domaines

> Nous connaissons toutes les entreprises dans le périmètre, tous les actifs de chaque entreprise et tous les domaines associés à ces entreprises.

Il est temps de trouver tous les sous-domaines possibles de chaque domaine découvert.

> [!TIP]
> Notez que certains outils et techniques de recherche de domaines peuvent également aider à trouver des sous-domaines.

### **DNS**

Essayons de trouver des **sous-domaines** à partir des enregistrements **DNS**. Nous devrions également tenter un **transfert de zone** (s’il est possible en raison d’une vulnérabilité, vous devriez le signaler).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Pour découvrir des API et plateformes couvrant l’infrastructure, la réputation, les dossiers de fuites et l’enrichissement au-delà de la découverte de sous-domaines, consultez le [catalogue des API de reconnaissance et de threat intelligence](reconnaissance-and-threat-intelligence-apis.md).

Le moyen le plus rapide d’obtenir de nombreux sous-domaines consiste à effectuer des recherches dans des sources externes. Les **outils** les plus utilisés sont les suivants (pour de meilleurs résultats, configurez les clés API) :

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

Il existe **d’autres outils/APIs intéressants** qui, même s’ils ne sont pas directement spécialisés dans la recherche de sous-domaines, peuvent être utiles pour en trouver, comme :

- [**IP.THC.ORG**](https://ip.thc.org) API gratuite

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)** :** Utilise l’API [https://sonar.omnisint.io](https://sonar.omnisint.io) pour obtenir des sous-domaines.

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**API gratuite de JLDC**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) API gratuit

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

- [**gau**](https://github.com/lc/gau)** :** récupère les URL connues depuis l’Open Threat Exchange d’AlienVault, la Wayback Machine et Common Crawl pour tout domaine donné.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper) : ils parcourent le Web à la recherche de fichiers JS et en extraient les sous-domaines.

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

- [**Outil de recherche de sous-domaines Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/) propose une API gratuite pour rechercher des sous-domaines et l’historique des adresses IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ce projet propose **gratuitement tous les sous-domaines associés aux programmes de bug bounty**. Vous pouvez également accéder à ces données avec [chaospy](https://github.com/dr-0x0x/chaospy) ou même consulter le scope utilisé par ce projet : [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous trouverez une **comparaison** de nombreux outils de ce type ici : [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux **sous-domaines** en effectuant du brute force sur les serveurs DNS à l’aide de noms de sous-domaines possibles.

Pour cela, vous aurez besoin de **listes de mots contenant des sous-domaines courants**, telles que :

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Vous aurez également besoin des adresses IP de bons résolveurs DNS. Pour générer une liste de résolveurs DNS fiables, vous pouvez télécharger la liste depuis [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Vous pouvez aussi utiliser : [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour le brute force DNS sont :

- [**massdns**](https://github.com/blechschmidt/massdns) : c’est le premier outil à avoir permis d’effectuer efficacement du brute force DNS. Il est très rapide, mais il est sujet aux faux positifs.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster) : Celui-ci, je pense, utilise simplement 1 résolveur.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est un wrapper autour de `massdns`, écrit en Go, qui permet d’énumérer des sous-domaines valides par brute force actif, ainsi que de résoudre des sous-domaines avec gestion des wildcards et une prise en charge simple des entrées-sorties.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns) : Il utilise également `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour effectuer des attaques par force brute sur les noms de domaine de manière asynchrone.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Deuxième round de brute-force DNS

Après avoir découvert des sous-domaines à l’aide de sources ouvertes et du brute-force, vous pouvez générer des variantes des sous-domaines trouvés pour essayer d’en découvrir encore davantage. Plusieurs outils sont utiles à cette fin :

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)** :** Génère des permutations à partir des domaines et sous-domaines.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns) : À partir des domaines et sous-domaines, génère des permutations.
  - Vous pouvez obtenir [**ici**](https://github.com/subfinder/goaltdns/blob/master/words.txt) la **wordlist** de permutations de goaltdns.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** À partir des domaines et sous-domaines, génère des permutations. Si aucun fichier de permutations n’est indiqué, gotator utilisera le sien.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns) : En plus de générer des permutations de sous-domaines, il peut aussi essayer de les résoudre (mais il vaut mieux utiliser les outils mentionnés précédemment).
  - Vous pouvez obtenir la **wordlist** de permutations d’altdns [**ici**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut) : Un autre outil pour effectuer des permutations, des mutations et des modifications de sous-domaines. Cet outil effectuera une recherche par brute force (il ne prend pas en charge les wildcards DNS).
  - Vous pouvez obtenir la wordlist de permutations de dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)** :** À partir d’un domaine, il **génère de nouveaux noms de sous-domaines potentiels** en fonction de motifs indiqués afin d’en découvrir d’autres.

#### Génération de permutations intelligentes

- [**regulator**](https://github.com/cramppet/regulator) : Apprend des motifs similaires à des expressions régulières à partir des sous-domaines découverts et génère des noms candidats à résoudre.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)** :** _subzuf_ est un fuzzer de brute-force de sous-domaines, associé à un algorithme extrêmement simple, mais efficace, guidé par les réponses DNS. Il utilise un ensemble de données fourni, comme une wordlist personnalisée ou des enregistrements DNS/TLS historiques, pour générer avec précision d’autres noms de domaine correspondants et les développer encore davantage en boucle, à partir des informations recueillies lors du scan DNS.

```
echo www | subzuf facebook.com
```

### **Workflow de découverte de sous-domaines**

Les exemples de workflows Trickest combinent OSINT, DNS brute force et étapes de permutation pour une énumération reproductible des sous-domaines.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Si vous avez trouvé une adresse IP hébergeant **une ou plusieurs pages web** appartenant à des sous-domaines, vous pouvez essayer de **trouver d’autres sous-domaines hébergés sur cette IP** en recherchant dans les **sources OSINT** des domaines associés à une IP ou en **effectuant un brute force des noms de domaine VHost sur cette IP**.

#### OSINT

Vous pouvez trouver certains **VHosts sur des IP à l’aide de** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou d’autres API**.

**Brute Force**

Si vous pensez qu’un sous-domaine peut être caché sur un serveur web, vous pouvez essayer d’effectuer un brute force :

Pour les vhosts basés sur le nom, fuzz le header `Host` et utilise l’auto-calibration de ffuf pour filtrer la réponse par défaut.<sup>[[2]](#references)</sup>

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
> Avec cette technique, vous pourriez même accéder à des endpoints internes/cachés.

### **CORS Brute Force**

Parfois, vous trouverez des pages qui ne renvoient l’en-tête _**Access-Control-Allow-Origin**_ que lorsqu’un domaine/sous-domaine valide est défini dans l’en-tête _**Origin**_. Dans ces situations, vous pouvez abuser de ce comportement pour **découvrir** de nouveaux **sous-domaines**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Lorsque vous recherchez des **sous-domaines**, vérifiez s’ils **pointent** vers un type de **bucket** et, le cas échéant, [**vérifiez les autorisations**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
De plus, puisque vous connaîtrez à ce stade tous les domaines inclus dans le périmètre, essayez de [**brute force les noms de buckets possibles et d’en vérifier les autorisations**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Surveillance**

Vous pouvez **surveiller** la création de **nouveaux sous-domaines** d’un domaine en surveillant les journaux **Certificate Transparency**, comme le fait [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Recherche de vulnérabilités**

Vérifiez la présence éventuelle de [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **sous-domaine** pointe vers un **bucket S3**, [**vérifiez les autorisations**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si vous trouvez un **sous-domaine avec une adresse IP différente** de celles déjà trouvées lors de la découverte des actifs, vous devriez effectuer un **scan de vulnérabilités de base** (avec Nessus ou OpenVAS) ainsi qu’un [**scan de ports**](../pentesting-network/index.html#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services en cours d’exécution, vous trouverez dans **ce livre quelques astuces pour les « attaquer »**.\
_Notez que le sous-domaine est parfois hébergé sur une adresse IP qui n’est pas contrôlée par le client et qui ne fait donc pas partie du périmètre. Soyez prudent._

## IPs

Lors des étapes initiales, vous avez peut-être **trouvé des plages d’adresses IP, des domaines et des sous-domaines**.\
Il est temps de **récupérer toutes les adresses IP de ces plages** ainsi que celles des **domaines/sous-domaines (requêtes DNS).**

Les services des **API gratuites** suivantes peuvent également vous aider à trouver les **anciennes adresses IP utilisées par des domaines et des sous-domaines**. Le client possède peut-être encore ces adresses IP (et vous pourriez ainsi trouver des [**contournements de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Vous pouvez également rechercher les domaines qui pointent vers une adresse IP spécifique à l’aide de l’outil [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Recherche de vulnérabilités**

**Scannez les ports de toutes les adresses IP qui n’appartiennent pas à des CDN** (car il est très probable que vous n’y trouviez rien d’intéressant). Les services en cours d’exécution que vous découvrirez pourraient **présenter des vulnérabilités**.

**Consultez un** [**guide**](../pentesting-network/index.html) **sur le scan des hôtes.**

## Recherche de serveurs web

> Nous avons trouvé toutes les entreprises et leurs actifs, et nous connaissons les plages d’adresses IP, les domaines et les sous-domaines inclus dans le périmètre. Il est temps de rechercher les serveurs web.

Lors des étapes précédentes, vous avez probablement déjà effectué une **reconnaissance des adresses IP et des domaines découverts**. Vous avez donc peut-être **déjà trouvé tous les serveurs web possibles**. Sinon, nous allons voir quelques **astuces rapides pour rechercher des serveurs web** dans le périmètre.

Veuillez noter que cette démarche sera **axée sur la découverte d’applications web** : vous devriez donc également effectuer le **scan de vulnérabilités** et le **scan de ports** (**si le périmètre l’autorise**).

Vous trouverez [**ici une méthode rapide pour découvrir les ports ouverts associés aux serveurs web avec masscan**](../pentesting-network/index.html#http-port-discovery).\
Un autre outil pratique pour rechercher des serveurs web est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Il suffit de leur fournir une liste de domaines : ils tenteront de se connecter aux ports 80 (http) et 443 (https). Vous pouvez également leur demander d’essayer d’autres ports :

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Captures d’écran**

Maintenant que vous avez découvert **tous les serveurs web** présents dans le périmètre (parmi les **IP** de l’entreprise et tous ses **domaines** et **sous-domaines**), vous ne savez probablement **pas par où commencer**. Alors, faisons simple : commençons par prendre des captures d’écran de tous ces serveurs. En **jetant simplement un œil** à la **page principale**, vous pouvez trouver des points de terminaison **étranges**, plus **susceptibles** d’être **vulnérables**.

Pour mettre en œuvre cette idée, vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Vous pouvez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) pour analyser toutes les **captures d’écran** et vous indiquer **ce qui est susceptible de contenir des vulnérabilités** et ce qui ne l’est pas.

## Ressources du cloud public

Pour trouver les ressources cloud potentielles appartenant à une entreprise, vous devriez **commencer par une liste de mots-clés permettant de l’identifier**. Par exemple, pour une entreprise de crypto, vous pourriez utiliser des mots tels que : `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Vous aurez également besoin de listes de mots contenant des **termes couramment utilisés dans les noms de buckets** :

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, vous devriez générer des **permutations** à partir de ces mots (consultez la section [**Deuxième passe de brute-force DNS**](#second-dns-bruteforce-round) pour plus d’informations).

Avec les listes de mots obtenues, vous pouvez utiliser des outils tels que [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

N’oubliez pas que, lorsque vous recherchez des ressources cloud, vous devez **chercher autre chose que des buckets AWS**.

### **Recherche de vulnérabilités**

Si vous trouvez des éléments tels que des **buckets ouverts ou des fonctions cloud exposées**, vous devriez **y accéder** pour voir ce qu’ils contiennent et si vous pouvez en abuser.

## E-mails

Avec les **domaines** et les **sous-domaines** inclus dans le périmètre, vous avez pratiquement tout ce qu’il **vous faut pour commencer à rechercher des e-mails**. Voici les **API** et les **outils** qui m’ont été les plus utiles pour trouver les e-mails d’une entreprise :

- [**theHarvester**](https://github.com/laramies/theHarvester) - avec des API
- API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
- API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
- API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Recherche de vulnérabilités**

Les e-mails seront utiles plus tard pour le **brute-force des connexions web et des services d’authentification** (tels que SSH). Ils sont également nécessaires pour le **phishing**. De plus, ces API vous fourniront davantage d’**informations sur la personne** derrière l’adresse e-mail, ce qui est utile pour la campagne de phishing.

## Fuites d’identifiants

Avec les **domaines**, les **sous-domaines** et les **e-mails**, vous pouvez commencer à rechercher les identifiants qui ont fait l’objet de fuites par le passé et qui sont associés à ces adresses :

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Recherche de vulnérabilités**

Si vous trouvez des identifiants **valides ayant fait l’objet d’une fuite**, c’est une victoire facile.

## Fuites de secrets

Les fuites d’identifiants sont liées aux piratages d’entreprises, au cours desquels des **informations sensibles ont été divulguées et vendues**. Cependant, les entreprises peuvent être touchées par **d’autres fuites** dont les informations ne figurent pas dans ces bases de données :

### Fuites sur Github

Des identifiants et des API peuvent être exposés dans les **dépôts publics** de l’**entreprise** ou des **utilisateurs** qui y travaillent.\
Vous pouvez utiliser l’**outil** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **dépôts publics** d’une **organisation** et de ses **développeurs**, puis lancer automatiquement [**gitleaks**](https://github.com/zricethezav/gitleaks) sur ces dépôts.

**Leakos** peut également lancer **gitleaks** sur toutes les **URL** de **texte fournies** en entrée, car les **pages web peuvent aussi contenir des secrets**.

#### Dorks Github

Consultez la [page GitHub dorks et fuites](github-leaked-secrets.md) pour trouver des **dorks GitHub** susceptibles de rechercher des informations dans l’organisation.

### Fuites sur les sites Paste

Parfois, des attaquants ou de simples employés **publient du contenu de l’entreprise sur un site paste**. Celui-ci peut contenir ou non des **informations sensibles**, mais il est très intéressant de faire des recherches à ce sujet.\
Vous pouvez utiliser l’outil [**Pastos**](https://github.com/carlospolop/Pastos) pour effectuer des recherches simultanément sur plus de 80 sites paste.

### Dorks Google

Les vieux dorks Google, toujours efficaces, sont utiles pour trouver des **informations exposées qui ne devraient pas l’être**. Le seul problème, c’est que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas exécuter manuellement. Vous pouvez donc choisir vos 10 préférées ou utiliser un **outil tel que** [**Gorks**](https://github.com/carlospolop/Gorks) **pour les exécuter toutes**.

_Notez que les outils qui tentent d’interroger toute la base de données à l’aide du navigateur Google classique ne termineront jamais, car Google vous bloquera très rapidement._

### **Recherche de vulnérabilités**

Si vous trouvez des identifiants ou des jetons d’API **valides ayant fait l’objet d’une fuite**, c’est une victoire facile.

## Vulnérabilités dans le code public

Si vous découvrez que l’entreprise dispose de **code open source**, vous pouvez l’**analyser** et rechercher des **vulnérabilités**.

Il existe différents **outils** selon le **langage** ; consultez la liste des [outils d’audit de code source](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Il existe également des services gratuits qui permettent d’**analyser des dépôts publics**, tels que :

- [**Snyk**](https://app.snyk.io/)

## [**Méthodologie de pentesting web**](../../network-services-pentesting/pentesting-web/index.html)

La **majorité des vulnérabilités** découvertes par les bug hunters se trouvent dans les **applications web**. À ce stade, je voudrais donc vous présenter une **méthodologie de test d’applications web**. Vous pouvez [**consulter ces informations ici**](../../network-services-pentesting/pentesting-web/index.html).

Je souhaite également mentionner tout particulièrement la section [**Outils open source de scanners web automatisés**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) : même si vous ne devriez pas vous attendre à ce qu’ils découvrent des vulnérabilités très sensibles, ils sont pratiques à intégrer à des **workflows pour obtenir quelques premières informations sur le web**.

## Récapitulation

> Félicitations ! À ce stade, vous avez déjà effectué **toute l’énumération de base**. Oui, elle est basique, car il est possible d’effectuer beaucoup plus d’énumérations (nous verrons d’autres astuces plus tard).

Vous avez donc déjà :

1. Trouvé toutes les **entreprises** incluses dans le périmètre
2. Trouvé toutes les **ressources** appartenant à ces entreprises (et effectué quelques scans de vulnérabilités si cela est inclus dans le périmètre)
3. Trouvé tous les **domaines** appartenant aux entreprises
4. Trouvé tous les **sous-domaines** des domaines (y a-t-il des prises de contrôle de sous-domaines ?)
5. Trouvé toutes les **IP** (issues ou **non de CDN**) incluses dans le périmètre.
6. Trouvé tous les **serveurs web** et pris une **capture d’écran** de chacun d’eux (y a-t-il quelque chose d’étrange qui mérite d’être examiné de plus près ?)
7. Trouvé toutes les **ressources potentielles du cloud public** appartenant à l’entreprise.
8. Trouvé des **e-mails**, des **fuites d’identifiants** et des **fuites de secrets** qui pourraient vous apporter une **victoire facile et importante**.
9. Effectué le **pentesting de tous les sites web trouvés**

## **Outils automatiques complets de recon**

Il existe plusieurs outils qui effectuent une partie des actions proposées sur un périmètre donné.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et non mis à jour

## References

- [1] [Jason Haddix – La méthodologie du bug hunter v4.0 : édition recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB : Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – À propos des favicons : des icônes de navigateur à l’intelligence sur la surface d’attaque](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Exploiter favicon.ico pour les bug bounties, l’OSINT et bien plus encore](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Découverte de domaines par une attaque de corrélation temporelle sur Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Prise de contrôle passive : découverte (et reproduction) d’une campagne coûteuse de prise de contrôle de sous-domaines](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator : une méthode unique d’énumération de sous-domaines](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow complet de découverte de sous-domaines, partie 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Découverte complète de sous-domaines par brute-force à l’aide d’un workflow Trickest automatisé, partie 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Capture d’écran du résultat de favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
