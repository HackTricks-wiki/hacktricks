# Méthodologie de Recon externe

{{#include ../../banners/hacktricks-training.md}}

## Découverte des assets

> On vous a donc indiqué que tout ce qui appartient à une entreprise donnée est dans le scope, et vous voulez déterminer ce que cette entreprise possède réellement.

L’objectif de cette phase est d’identifier toutes les **entreprises détenues par l’entreprise principale**, puis tous les **assets** de ces entreprises. Pour cela, nous allons :

1. Trouver les acquisitions de l’entreprise principale afin d’identifier les entreprises incluses dans le scope.
2. Trouver l’ASN (le cas échéant) de chaque entreprise afin d’identifier les plages d’adresses IP détenues par chacune d’elles.
3. Utiliser des recherches reverse whois pour trouver d’autres entrées (noms d’organisations, domaines...) liées à la première (cela peut être effectué récursivement).
4. Utiliser d’autres techniques, comme les filtres `org` et `ssl` de shodan, pour rechercher d’autres assets (l’astuce `ssl` peut être utilisée récursivement).

### **Acquisitions**

Tout d’abord, nous devons savoir quelles **autres entreprises sont détenues par l’entreprise principale**.\
Une possibilité consiste à consulter [https://www.crunchbase.com/](https://www.crunchbase.com), à **rechercher** l’**entreprise principale**, puis à cliquer sur "**acquisitions**". Vous y verrez les autres entreprises acquises par celle-ci.\
Une autre possibilité consiste à consulter la page **Wikipedia** de l’entreprise principale et à rechercher les **acquisitions**.\
Pour les entreprises publiques, consultez les **documents SEC/EDGAR**, les pages de **relations avec les investisseurs** ou les registres locaux des sociétés (par exemple, **Companies House** au Royaume-Uni).\
Pour obtenir les structures mondiales des entreprises et leurs filiales, essayez **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) et la base de données **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> À ce stade, vous devriez connaître toutes les entreprises incluses dans le scope. Voyons maintenant comment trouver leurs assets.

### **ASNs**

Un autonomous system number (**ASN**) est un **numéro unique** attribué à un **autonomous system** (AS) par l’**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** se compose de **blocs** d’**adresses IP** qui disposent d’une politique clairement définie pour l’accès aux réseaux externes et qui sont administrés par une seule organisation, mais peuvent être constitués de plusieurs opérateurs.

Il est intéressant de vérifier si l’**entreprise s’est vu attribuer un ASN** afin de trouver ses **plages d’adresses IP.** Il peut être intéressant d’effectuer un **test de vulnérabilités** sur tous les **hôtes** du **scope** et de **rechercher des domaines** dans ces adresses IP.\
Vous pouvez **rechercher** par **nom** d’entreprise, par **IP** ou par **domaine** sur [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Selon la région de l’entreprise, ces liens peuvent être utiles pour recueillir davantage de données :** [**AFRINIC**](https://www.afrinic.net) **(Afrique),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amérique du Nord),** [**APNIC**](https://www.apnic.net) **(Asie),** [**LACNIC**](https://www.lacnic.net) **(Amérique latine),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Quoi qu’il en soit, la plupart des** informations utiles **(plages d’adresses IP et Whois)** apparaissent déjà dans le premier lien.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
De plus, l’énumération effectuée par [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrège et résume automatiquement les ASN à la fin du scan.
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
Vous pouvez également trouver les plages IP d’une organisation à l’aide de [http://asnlookup.com/](http://asnlookup.com) (une API gratuite est disponible).\
Vous pouvez trouver l’IP et l’ASN d’un domaine à l’aide de [http://ipv4info.com/](http://ipv4info.com).

### **Recherche de vulnérabilités**

À ce stade, nous connaissons **tous les assets dans le scope**. Si vous y êtes autorisé, vous pouvez donc lancer un **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sur tous les hosts.\
Vous pouvez également lancer des [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou utiliser des services comme** Shodan, Censys ou ZoomEye **pour trouver** les ports ouverts **et, selon ce que vous trouvez, vous devriez** consulter ce livre pour savoir comment effectuer le pentest de plusieurs services potentiellement actifs.\
**Il convient également de préciser que vous pouvez préparer des** listes de noms d’utilisateur **et de** mots de passe **par défaut, puis tenter de** bruteforce des services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises dans le scope ainsi que leurs assets. Il est maintenant temps de trouver les domaines dans le scope.

_Veuillez noter que les techniques proposées ci-dessous peuvent également permettre de trouver des subdomains et que ces informations ne doivent pas être sous-estimées._

Tout d’abord, vous devez rechercher le ou les **domaines principaux** de chaque entreprise. Par exemple, pour _Tesla Inc._, il s’agira de _tesla.com_.

### **Reverse DNS**

Après avoir trouvé toutes les plages IP des domaines, vous pouvez tenter d’effectuer des **reverse dns lookups** sur ces **IPs afin de trouver d’autres domaines dans le scope**. Essayez d’utiliser un serveur DNS de la victime ou un serveur DNS connu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Pour que cela fonctionne, l’administrateur doit activer manuellement le PTR.\
Vous pouvez également utiliser un outil en ligne pour obtenir ces informations : [http://ptrarchive.com/](http://ptrarchive.com).\
Pour les grandes plages, des outils comme [**massdns**](https://github.com/blechschmidt/massdns) et [**dnsx**](https://github.com/projectdiscovery/dnsx) sont utiles pour automatiser les reverse lookups et l’enrichissement.

### **Reverse Whois (loop)**

Dans un **whois**, vous pouvez trouver de nombreuses **informations** intéressantes comme le **nom de l’organisation**, l’**adresse**, les **emails**, les numéros de téléphone... Mais le plus intéressant est que vous pouvez trouver **davantage d’assets liés à l’entreprise** si vous effectuez des **reverse whois lookups à partir de l’un de ces champs** (par exemple, d’autres registres whois où le même email apparaît).\
Vous pouvez utiliser des outils en ligne comme :

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web et API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **Free**, API payante.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (seulement **100 recherches gratuites**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Vous pouvez automatiser cette tâche avec [**DomLink** ](https://github.com/vysecurity/DomLink)(nécessite une clé API whoxy).\
Vous pouvez également effectuer une découverte automatique de reverse whois avec [amass](https://github.com/OWASP/Amass) : `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir davantage de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

### **Trackers**

Si vous trouvez le **même ID du même tracker** sur 2 pages différentes, vous pouvez supposer que **les deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **Google Analytics ID** ou le même **Adsense ID** sur plusieurs pages.

Certaines pages et certains outils permettent d’effectuer des recherches à partir de ces trackers, entre autres :

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trouve les sites associés grâce aux analytics/trackers partagés)

### **Favicon**

Saviez-vous que nous pouvons trouver les domaines et sous-domaines associés à notre cible en recherchant le même hash d’icône favicon ? C’est exactement ce que fait l’outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), créé par [@m4ll0k2](https://twitter.com/m4ll0k2). Voici comment l’utiliser :
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - découvrir les domaines utilisant la même empreinte d'icône favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En termes simples, favihash nous permet de découvrir les domaines qui utilisent la même empreinte d'icône favicon que notre cible.

De plus, vous pouvez également rechercher des technologies à l'aide de l'empreinte favicon, comme expliqué dans [**cet article de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Cela signifie que si vous connaissez l'**empreinte du favicon d'une version vulnérable d'une technologie web**, vous pouvez effectuer une recherche dans shodan et **trouver davantage de cibles vulnérables** :
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Voici comment **calculer le hash du favicon** d’un site web (MMH3 sur les octets du favicon **encodés en base64**) :
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

Points importants à retenir lors de l'utilisation des fingerprints de favicon :

- **Considérez le hash comme un indicateur, pas comme une preuve** : MMH3 est compact et des collisions sont possibles ; les opérateurs peuvent également remplacer les favicons ou réutiliser intentionnellement une icône trompeuse.
- **Sondez plus que** `/favicon.ico` : de nombreux produits exposent leurs icônes dans des chemins de framework/build ou via `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, des URLs `data:` inline ou des balises HTML `<link rel="icon">`. Le chemin lui-même peut identifier une famille de produits.
- **Les fichiers statiques sont souvent accessibles lorsque l'application ne l'est pas** : les contrôles WAF/SSO/IdP peuvent protéger les routes dynamiques tout en exposant les icônes statiques. Demandez toujours directement le favicon et examinez `ETag`, `Last-Modified`, les redirections et les headers de cache afin de détecter de faibles indices de version/build.
- **Validez les correspondances avec les signaux environnants** : comparez le titre, le hash du HTML/body, les headers, les sujets/SANs des certificats TLS, les composants Shodan/Censys et les ports exposés avant de conclure qu'un favicon identifie un produit.
- **Regroupez par hash HTML/body lors d'un pivot à grande échelle** : si la plupart des hosts partageant un favicon se réduisent à un seul template de page, le fingerprint est plus fiable ; si le même hash se divise en nombreux templates sans lien, préférez « générique/partagé/honeypot » à un label de produit.
- **Heuristique de honeypot** : si le même hash de favicon apparaît sur de nombreuses signatures HTML sans lien, des ports aléatoires et des produits contradictoires, considérez-le comme un honeypot probable ou un placeholder générique plutôt que comme le fingerprint d'un véritable produit.
- **Utilisez une sonde 404 sur les targets ambiguës** : récupérez une page réelle et un chemin inexistant tel que `/_favicon_probe_<8-hex>` dans un navigateur. Les réponses correspondantes d'un hébergeur/parking expliquent souvent mieux les favicons partagés qu'un réel recouvrement de produits.
- **Initialisez les mappings à partir des règles de détection** : les templates Nuclei et les datasets publics de favicons peuvent fournir des mappings connus `favicon` ↔ `product` ↔ `CPE`, utiles pour un triage rapide après la divulgation de CVE.
- **Limite de couverture** : les datasets de type Shodan sont centrés sur les IP. Les surfaces situées derrière un CDN, routées par SNI, anycast ou accessibles uniquement par domaine peuvent être sous-représentées ; un faible nombre de résultats ne signifie **pas** une faible présence dans le monde réel.

### **Copyright / Uniq string**

Recherchez dans les pages web des **strings susceptibles d'être partagées entre différents sites d'une même organisation**. La **string de copyright** peut être un bon exemple. Recherchez ensuite cette string dans **google**, dans d'autres **browsers** ou même dans **shodan** : `shodan search http.html:"Copyright string"`

### **CRT Time**

Il est courant d'avoir un cron job tel que
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
pour renouveler tous les certificats des domaines sur le serveur. Cela signifie que même si la CA utilisée à cette fin n'inscrit pas la date de génération dans la période de validité, il est possible de **trouver des domaines appartenant à la même entreprise dans les certificate transparency logs**.\
Consultez [**ce writeup pour plus d'informations**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Utilisez également directement les logs de **certificate transparency** :

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informations DMARC des e-mails

Vous pouvez utiliser un site web tel que [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou un outil tel que [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) pour trouver des **domaines et sous-domaines partageant les mêmes informations DMARC**.\
D'autres outils utiles sont [**spoofcheck**](https://github.com/BishopFox/spoofcheck) et [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparemment, il est courant que des personnes associent des sous-domaines à des IP appartenant à des cloud providers et qu'à un moment donné elles **perdent cette adresse IP, mais oublient de supprimer l'enregistrement DNS**. Ainsi, le simple fait de **spawner une VM** dans un cloud (comme Digital Ocean) vous permettra en réalité de **prendre le contrôle de certains sous-domaines**.

[**Cet article**](https://kmsec.uk/blog/passive-takeover/) explique une histoire à ce sujet et propose un script qui **spawne une VM dans DigitalOcean**, **récupère** l'**IPv4** de la nouvelle machine et **recherche dans Virustotal les enregistrements de sous-domaines** qui pointent vers celle-ci.

### **Autres méthodes**

**Notez que vous pouvez utiliser cette technique pour découvrir davantage de noms de domaines chaque fois que vous trouvez un nouveau domaine.**

**Shodan**

Comme vous connaissez déjà le nom de l'organisation qui possède l'espace IP, vous pouvez rechercher cette information dans Shodan avec : `org:"Tesla, Inc."` Vérifiez les hosts trouvés à la recherche de nouveaux domaines inattendus dans le certificat TLS.

Vous pouvez accéder au **certificat TLS** de la page web principale, obtenir le **nom de l'organisation**, puis rechercher ce nom dans les **certificats TLS** de toutes les pages web connues par **Shodan** avec le filtre : `ssl:"Tesla Motors"` ou utiliser un outil comme [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) est un outil qui recherche les **domaines liés** à un domaine principal ainsi que leurs **sous-domaines**, et il est assez impressionnant.

**Passive DNS / DNS historique**

Les données de Passive DNS sont très utiles pour trouver d'**anciens enregistrements oubliés** qui se résolvent encore ou qui peuvent être pris en contrôle. Consultez :

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Recherche de vulnérabilités**

Recherchez d'éventuels cas de [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Il est possible qu'une entreprise **utilise un domaine**, mais qu'elle ait **perdu sa propriété**. Enregistrez-le simplement (s'il est suffisamment peu coûteux), puis informez-en l'entreprise.

Si vous trouvez un **domaine avec une IP différente** de celles que vous avez déjà trouvées lors de la découverte des assets, vous devez effectuer un **scan de vulnérabilités de base** (avec Nessus ou OpenVAS) ainsi qu'un [**scan de ports**](../pentesting-network/index.html#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services qui tournent, vous pouvez trouver dans **ce livre des astuces pour les « attaquer »**.\
_Notez que le domaine est parfois hébergé sur une IP qui n'est pas contrôlée par le client ; il n'est donc pas dans le périmètre, soyez prudents._

## Sous-domaines

> Nous connaissons toutes les entreprises incluses dans le périmètre, tous les assets de chaque entreprise et tous les domaines liés aux entreprises.

Il est temps de trouver tous les sous-domaines possibles de chaque domaine trouvé.

> [!TIP]
> Notez que certains outils et techniques permettant de trouver des domaines peuvent également aider à trouver des sous-domaines

### **DNS**

Essayons d'obtenir les **sous-domaines** à partir des enregistrements **DNS**. Nous devons également essayer un **Zone Transfer** (s'il est vulnérable, vous devez le signaler).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

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
Il existe **d’autres outils/API intéressants** qui, même s’ils ne sont pas directement spécialisés dans la recherche de sous-domaines, pourraient être utiles pour trouver des sous-domaines, comme :

- [**IP.THC.ORG**](https://ip.thc.org) API gratuite
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilise l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) pour obtenir des sous-domaines
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper) : Ils parcourent le web à la recherche de fichiers JS et en extraient les sous-domaines.
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
- [**securitytrails.com**](https://securitytrails.com/) dispose d'une API gratuite pour rechercher des sous-domaines et l'historique des IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ce projet offre **gratuitement tous les sous-domaines liés aux programmes de bug bounty**. Vous pouvez également accéder à ces données avec [chaospy](https://github.com/dr-0x0x/chaospy), ou même accéder au scope utilisé par ce projet : [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous trouverez une **comparaison** de nombreux outils de ce type ici : [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux **sous-domaines** en effectuant du brute-forcing sur les serveurs DNS à l'aide de noms de sous-domaines possibles.

Pour cette action, vous aurez besoin de **wordlists de sous-domaines courants, telles que** :

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Vous aurez également besoin d'IP de bons resolvers DNS. Pour générer une liste de resolvers DNS fiables, vous pouvez télécharger les resolvers depuis [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Vous pouvez également utiliser : [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour le DNS brute-force sont :

- [**massdns**](https://github.com/blechschmidt/massdns) : Il s'agit du premier outil à avoir effectué un DNS brute-force efficace. Il est très rapide, mais est sujet aux false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster) : Celui-ci, je pense, utilise simplement 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est un wrapper autour de `massdns`, écrit en go, qui permet d'énumérer des sous-domaines valides à l'aide d'un bruteforce actif, ainsi que de résoudre des sous-domaines avec gestion des wildcards et une prise en charge simple des entrées-sorties.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns) : Il utilise également `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour effectuer du brute force de noms de domaine de manière asynchrone.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Deuxième round de DNS Brute-Force

Après avoir trouvé des subdomains à l'aide de sources ouvertes et du brute-forcing, vous pouvez générer des variations des subdomains trouvés afin d'essayer d'en découvrir encore davantage. Plusieurs outils sont utiles à cette fin :

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Génère des permutations à partir des domains et subdomains.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns) : À partir des domaines et sous-domaines, génère des permutations.
- Vous pouvez obtenir la **wordlist** de permutations de goaltdns [**ici**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Étant donné les domaines et sous-domaines, génère des permutations. Si aucun fichier de permutations n’est indiqué, gotator utilisera le sien.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns) : En plus de générer des permutations de subdomains, il peut également essayer de les résoudre (mais il est préférable d'utiliser les outils précédemment commentés).
- Vous pouvez obtenir la **wordlist** de permutations d'altdns [**ici**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut) : Un autre outil pour effectuer des permutations, des mutations et des modifications de sous-domaines. Cet outil brute force le résultat (il ne prend pas en charge les wildcards DNS).
- Vous pouvez obtenir la wordlist de permutations de dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** À partir d’un domaine, il **génère de nouveaux noms de sous-domaines potentiels** selon les patterns indiqués afin d’essayer de découvrir davantage de sous-domaines.

#### Génération intelligente de permutations

- [**regulator**](https://github.com/cramppet/regulator) : Pour plus d’informations, consultez cet [**article**](https://cramppet.github.io/regulator/index.html), mais il récupère essentiellement les **parties principales** des **sous-domaines découverts** et les combine pour trouver davantage de sous-domaines.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)** :** _subzuf_ est un fuzzer de brute-force de sous-domaines associé à un algorithme extrêmement simple, mais efficace, guidé par les réponses DNS. Il utilise un ensemble de données fourni, comme une wordlist personnalisée ou des enregistrements DNS/TLS historiques, afin de générer précisément d'autres noms de domaine correspondants et de les développer davantage en boucle, en fonction des informations recueillies pendant le scan DNS.
```
echo www | subzuf facebook.com
```
### **Workflow de découverte de sous-domaines**

Consultez cet article de blog que j'ai écrit sur la façon d'**automatiser la découverte de sous-domaines** à partir d'un domaine à l'aide des **workflows Trickest**, afin de ne pas avoir à lancer manuellement un grand nombre d'outils sur mon ordinateur :


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Si vous avez trouvé une adresse IP contenant **une ou plusieurs pages web** appartenant à des sous-domaines, vous pouvez essayer de **trouver d'autres sous-domaines hébergeant des sites sur cette IP** en recherchant dans des **sources OSINT** les domaines associés à une IP ou en effectuant un **brute force de noms de domaine VHost sur cette IP**.

#### OSINT

Vous pouvez trouver certains **VHosts sur des IP à l'aide de** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou d'autres APIs**.

**Brute Force**

Si vous soupçonnez qu'un sous-domaine est caché sur un serveur web, vous pouvez essayer de le découvrir par brute force :

Lorsque l'**IP redirige vers un hostname** (vhosts basés sur le nom), fuzz le header `Host` directement et laissez ffuf effectuer un **auto-calibrate** afin de mettre en évidence les réponses qui diffèrent du vhost par défaut :
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
> Avec cette technique, vous pourrez même accéder à des endpoints internes/cachés.

### **CORS Brute Force**

Il vous arrivera de trouver des pages qui ne renvoient l’en-tête _**Access-Control-Allow-Origin**_ que lorsqu’un domaine/sous-domaine valide est défini dans l’en-tête _**Origin**_. Dans ces scénarios, vous pouvez exploiter ce comportement pour **découvrir** de nouveaux **sous-domaines**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Lors de la recherche de **subdomains**, surveillez si l’un d’eux **pointe** vers un type de **bucket** et, dans ce cas, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
De plus, à ce stade, vous connaîtrez tous les domaines inclus dans le scope. Essayez donc de [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Vous pouvez **monitorer** la création de **nouveaux subdomains** d’un domaine en surveillant les logs de **Certificate Transparency**, comme le fait [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Recherche de vulnerabilities**

Vérifiez la présence éventuelle de [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **subdomain** pointe vers un **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si vous trouvez un **subdomain avec une IP différente** de celles déjà trouvées lors de l’asset discovery, vous devez effectuer un **basic vulnerability scan** (avec Nessus ou OpenVAS) ainsi qu’un [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services exécutés, vous pourrez trouver **dans ce livre certaines techniques pour les « attaquer »**.\
_Notez que le subdomain est parfois hébergé sur une IP qui n’est pas contrôlée par le client et qui n’est donc pas dans le scope. Soyez prudents._

## IPs

Lors des premières étapes, vous avez peut-être **trouvé certaines plages d’IPs, certains domaines et subdomains**.\
Il est temps de **récupérer toutes les IPs de ces plages**, ainsi que celles des **domaines/subdomains (requêtes DNS)**.

En utilisant les services des **free APIs** suivantes, vous pouvez également trouver les **IPs précédemment utilisées par des domaines et subdomains**. Ces IPs peuvent toujours appartenir au client et vous permettre de trouver des [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Vous pouvez également rechercher les domaines pointant vers une adresse IP spécifique à l’aide de l’outil [**hakip2host**](https://github.com/hakluke/hakip2host).

### **Recherche de vulnerabilities**

**Effectuez un port scan sur toutes les IPs qui n’appartiennent pas à des CDNs** (car vous n’y trouverez très probablement rien d’intéressant). Les services en cours d’exécution qui auront été découverts peuvent présenter des **vulnerabilities**.

**Consultez ce** [**guide**](../pentesting-network/index.html) **sur la manière de scanner des hosts.**

## Chasse aux web servers

> Nous avons trouvé toutes les entreprises et leurs assets, et nous connaissons les plages d’IPs, les domaines et les subdomains inclus dans le scope. Il est temps de rechercher les web servers.

Lors des étapes précédentes, vous avez probablement déjà effectué une **recon des IPs et des domaines découverts**. Vous avez donc peut-être **déjà trouvé tous les web servers possibles**. Toutefois, si ce n’est pas le cas, nous allons maintenant voir quelques **techniques rapides pour rechercher des web servers** dans le scope.

Veuillez noter que cette étape sera **orientée vers la découverte de web apps**. Vous devez donc également effectuer le **vulnerability scanning** et le **port scanning** (**si le scope l’autorise**).

Une **méthode rapide pour découvrir les ports ouverts** associés aux web servers avec [**masscan** est disponible ici](../pentesting-network/index.html#http-port-discovery).\
Un autre outil convivial pour rechercher des web servers est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Il suffit de lui transmettre une liste de domaines et il tentera de se connecter aux ports 80 (http) et 443 (https). Vous pouvez également lui indiquer d’essayer d’autres ports :
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Captures d'écran**

Maintenant que vous avez découvert **tous les serveurs web** présents dans le périmètre (parmi les **IPs** de l'entreprise et tous les **domaines** et **sous-domaines**), vous ne savez probablement **pas par où commencer**. Alors, simplifions les choses et commençons par prendre des captures d'écran de chacun d'entre eux. En **jetant simplement un coup d'œil** à la **page principale**, vous pouvez trouver des endpoints **étranges** qui sont plus **susceptibles** d'être **vulnérables**.

Pour mettre en œuvre l'idée proposée, vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

De plus, vous pouvez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) sur toutes les **captures d'écran** afin de déterminer ce qui est **susceptible de contenir des vulnérabilités** et ce qui ne l'est pas.

## Ressources Cloud publiques

Pour trouver des ressources cloud potentielles appartenant à une entreprise, vous devez **commencer par une liste de mots-clés permettant d'identifier cette entreprise**. Par exemple, pour une entreprise crypto, vous pouvez utiliser des mots tels que : `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Vous aurez également besoin de wordlists de **mots couramment utilisés dans les buckets** :

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, avec ces mots, vous devez générer des **permutations** (consultez le [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) pour plus d'informations).

Avec les wordlists obtenues, vous pouvez utiliser des outils tels que [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

N'oubliez pas que lorsque vous recherchez des Cloud Assets, vous devez **chercher plus que de simples buckets dans AWS**.

### **Recherche de vulnérabilités**

Si vous trouvez des éléments tels que des **buckets ouverts ou des cloud functions exposées**, vous devez **y accéder** et essayer de voir ce qu'ils vous offrent et si vous pouvez en abuser.

## E-mails

Avec les **domaines** et **sous-domaines** compris dans le périmètre, vous disposez en principe de tout ce dont vous **avez besoin pour commencer à rechercher des e-mails**. Voici les **APIs** et **outils** qui ont été les plus efficaces pour moi afin de trouver les e-mails d'une entreprise :

- [**theHarvester**](https://github.com/laramies/theHarvester) - avec des APIs
- API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
- API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
- API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Recherche de vulnérabilités**

Les e-mails vous seront utiles plus tard pour **brute-force les connexions web et les services d'authentification** (comme SSH). Ils sont également nécessaires pour les **phishings**. De plus, ces APIs vous fourniront encore plus d'**informations sur la personne** derrière l'e-mail, ce qui est utile pour la campagne de phishing.

## Credential Leaks

Avec les **domaines,** **sous-domaines** et **e-mails**, vous pouvez commencer à rechercher les identifiants ayant leak dans le passé et appartenant à ces adresses e-mail :

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Recherche de vulnérabilités**

Si vous trouvez des identifiants **leakés valides**, c'est une victoire très facile.

## Secrets Leaks

Les credential leaks sont liés aux hacks d'entreprises lors desquels des **informations sensibles ont été leakées et vendues**. Cependant, les entreprises peuvent être affectées par d'**autres leaks** dont les informations ne figurent pas dans ces bases de données :

### Github Leaks

Des identifiants et des APIs peuvent être leakés dans les **repositories publics** de l'**entreprise** ou des **utilisateurs** travaillant pour cette entreprise github.\
Vous pouvez utiliser l'**outil** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **repos publics** d'une **organisation** et de ses **développeurs**, puis exécuter automatiquement [**gitleaks**](https://github.com/zricethezav/gitleaks) dessus.

**Leakos** peut également être utilisé pour exécuter **gitleaks** contre tout le **texte** fourni par les **URLs passées** en argument, car les **pages web peuvent parfois aussi contenir des secrets**.

#### Github Dorks

Consultez également cette **page** pour trouver d'éventuels **github dorks** que vous pourriez rechercher dans l'organisation que vous attaquez :


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Parfois, des attaquants ou simplement des employés vont **publier du contenu de l'entreprise sur un paste site**. Celui-ci peut contenir ou non des **informations sensibles**, mais il est très intéressant de le rechercher.\
Vous pouvez utiliser l'outil [**Pastos**](https://github.com/carlospolop/Pastos) pour rechercher simultanément sur plus de 80 paste sites.

### Google Dorks

Les anciens mais toujours efficaces google dorks sont toujours utiles pour trouver des **informations exposées qui ne devraient pas l'être**. Le seul problème est que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas exécuter manuellement. Vous pouvez donc sélectionner vos 10 préférées ou utiliser un **outil tel que** [**Gorks**](https://github.com/carlospolop/Gorks) **pour toutes les exécuter**.

_Notez que les outils qui tentent d'exécuter toute la base de données avec le navigateur Google classique ne termineront jamais, car Google vous bloquera très rapidement._

### **Recherche de vulnérabilités**

Si vous trouvez des identifiants **leakés valides** ou des tokens API, c'est une victoire très facile.

## Vulnérabilités du code public

Si vous découvrez que l'entreprise possède du code **open-source**, vous pouvez l'**analyser** et y rechercher des **vulnérabilités**.

**Selon le langage**, il existe différents **outils** que vous pouvez utiliser :


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Il existe également des services gratuits permettant de **scanner des repositories publics**, tels que :

- [**Snyk**](https://app.snyk.io/)

## [**Méthodologie de Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

La **majorité des vulnérabilités** trouvées par les bug hunters se trouvent dans les **applications web**. À ce stade, je souhaite donc parler d'une **méthodologie de test d'application web**, et vous pouvez [**trouver ces informations ici**](../../network-services-pentesting/pentesting-web/index.html).

Je souhaite également faire une mention spéciale de la section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), car, même si vous ne devez pas vous attendre à ce qu'ils trouvent des vulnérabilités très sensibles, ils sont pratiques pour les intégrer à des **workflows afin d'obtenir quelques informations web initiales.**

## Récapitulation

> Félicitations ! À ce stade, vous avez déjà effectué **toute l'énumération de base**. Oui, elle est basique, car il est possible d'effectuer beaucoup plus d'énumérations (nous verrons d'autres astuces plus tard).

Vous avez donc déjà :

1. Trouvé toutes les **entreprises** comprises dans le périmètre
2. Trouvé tous les **assets** appartenant aux entreprises (et effectué un vuln scan si cela est compris dans le périmètre)
3. Trouvé tous les **domaines** appartenant aux entreprises
4. Trouvé tous les **sous-domaines** des domaines (subdomain takeover ?)
5. Trouvé toutes les **IPs** (provenant ou **non de CDNs**) comprises dans le périmètre.
6. Trouvé tous les **serveurs web** et pris une **capture d'écran** de ceux-ci (quelque chose d'étrange méritant un examen plus approfondi ?)
7. Trouvé toutes les **ressources cloud publiques potentielles** appartenant à l'entreprise.
8. Trouvé les **e-mails**, les **credential leaks** et les **secret leaks** qui pourraient vous donner une **grande victoire très facilement**.
9. Effectué le **Pentesting de tous les sites web trouvés**

## **Outils automatiques de recon complète**

Il existe plusieurs outils qui effectueront une partie des actions proposées sur un périmètre donné.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et plus mis à jour

## **Références**

- Tous les cours gratuits de [**@Jhaddix**](https://twitter.com/Jhaddix), comme [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
