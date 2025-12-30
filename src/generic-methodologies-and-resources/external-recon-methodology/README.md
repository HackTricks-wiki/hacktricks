# Méthodologie de reconnaissance externe

{{#include ../../banners/hacktricks-training.md}}

## Découverte des actifs

> On vous a dit que tout ce qui appartient à une entreprise fait partie du périmètre, et vous voulez déterminer ce que cette entreprise possède réellement.

L'objectif de cette phase est d'obtenir toutes les **entreprises détenues par la société principale** puis tous les **actifs** de ces entreprises. Pour ce faire, nous allons :

1. Trouver les acquisitions de la société principale, cela nous donnera les entreprises dans le périmètre.
2. Trouver l'ASN (le cas échéant) de chaque entreprise, cela nous donnera les plages IP détenues par chaque entreprise
3. Utiliser des reverse whois lookups pour rechercher d'autres entrées (noms d'organisation, domains...) liées à la première (cela peut être fait de manière récursive)
4. Utiliser d'autres techniques comme shodan `org` et `ssl` filtres pour rechercher d'autres assets (le `ssl` trick peut être effectué de manière récursive).

### **Acquisitions**

Tout d'abord, nous devons savoir quelles **autres entreprises sont détenues par la société principale**.\
Une option est de visiter [https://www.crunchbase.com/](https://www.crunchbase.com), **chercher** la **société principale**, et **cliquer** sur « **acquisitions** ». Vous y verrez les autres entreprises acquises par la société principale.\
Autre option : visiter la page **Wikipedia** de la société principale et rechercher **acquisitions**.\
Pour les sociétés cotées, consultez les dépôts **SEC/EDGAR**, les pages relations investisseurs, ou les registres du commerce locaux (par ex. **Companies House** au Royaume-Uni).\
Pour les arbres d'entreprises et filiales à l'échelle mondiale, essayez **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) et la base **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> OK, à ce stade vous devriez connaître toutes les entreprises dans le périmètre. Voyons comment trouver leurs actifs.

### **ASNs**

Un autonomous system number (**ASN**) est un **numéro unique** attribué à un **système autonome** (AS) par la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** est composé de **blocs** d'**adresses IP** qui ont une politique distinctement définie pour accéder aux réseaux externes et sont administrés par une seule organisation mais peuvent être composés de plusieurs opérateurs.

Il est intéressant de vérifier si la **société** a obtenu un **ASN** afin de trouver ses **plages IP.** Il est pertinent d'effectuer un **test de vulnérabilité** contre tous les **hosts** dans le **périmètre** et de **rechercher des domains** dans ces IPs.\
Vous pouvez **rechercher** par nom d'entreprise, par **IP** ou par **domaine** sur [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Selon la région de la société ces liens peuvent être utiles pour rassembler plus de données :** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). De toute façon, probablement toutes les** informations utiles **(plages IP et Whois)** apparaissent déjà dans le premier lien.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
De plus, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration agrège et résume automatiquement les ASNs à la fin du scan.
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
Vous pouvez également trouver les plages IP d'une organisation en utilisant [http://asnlookup.com/](http://asnlookup.com) (il dispose d'une API gratuite).\
Vous pouvez trouver l'IP et l'ASN d'un domaine en utilisant [http://ipv4info.com/](http://ipv4info.com).

### **Recherche de vulnérabilités**

À ce stade nous connaissons **tous les actifs dans le périmètre**, donc si vous êtes autorisé vous pouvez lancer un **scanner de vulnérabilités** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sur tous les hosts.\
De plus, vous pouvez lancer des [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou utiliser des services comme** Shodan, Censys ou ZoomEye **pour trouver** des ports ouverts **et selon ce que vous trouvez vous devriez** consulter ce livre pour savoir comment pentest plusieurs services possibles en cours d'exécution.\
**Il peut aussi valoir la peine de mentionner que vous pouvez préparer des** default username **and** passwords **lists et essayer de** bruteforce des services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises dans le périmètre et leurs actifs ; il est temps de trouver les domaines dans le périmètre.

_Veuillez noter que dans les techniques proposées ci-dessous vous pouvez aussi trouver des sous-domaines et que ces informations ne doivent pas être sous-estimées._

Tout d'abord, recherchez le(s) **domaine(s) principal(aux)** de chaque entreprise. Par exemple, pour _Tesla Inc._ ce sera _tesla.com_.

### **Reverse DNS**

Comme vous avez trouvé toutes les plages IP des domaines vous pouvez essayer d'effectuer des **reverse dns lookups** sur ces **IPs pour trouver plus de domaines dans le périmètre**. Essayez d'utiliser un serveur DNS de la cible ou un serveur DNS bien connu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Pour que cela fonctionne, l'administrateur doit activer manuellement le PTR.\
Vous pouvez aussi utiliser un outil en ligne pour cette info : [http://ptrarchive.com/](http://ptrarchive.com).\
Pour de larges plages, des outils comme [**massdns**](https://github.com/blechschmidt/massdns) et [**dnsx**](https://github.com/projectdiscovery/dnsx) sont utiles pour automatiser les recherches inverses et l'enrichissement.

### **Reverse Whois (loop)**

Dans un **whois** vous pouvez trouver beaucoup d'**informations** intéressantes comme le **nom de l'organisation**, **l'adresse**, **emails**, numéros de téléphone... Mais ce qui est encore plus intéressant, c'est que vous pouvez trouver **plus d'actifs liés à l'entreprise** si vous effectuez des **reverse whois lookups par n'importe lequel de ces champs** (par exemple d'autres registres whois où le même email apparaît).\
Vous pouvez utiliser des outils en ligne comme :

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuit**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuit**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuit**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratuit** interface web, API non gratuite.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com/) - Payant
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Payant (seulement **100** recherches gratuites)
- [https://www.domainiq.com/](https://www.domainiq.com) - Payant
- [https://securitytrails.com/](https://securitytrails.com/) - Payant (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Payant (API)

Vous pouvez automatiser cette tâche en utilisant [**DomLink** ](https://github.com/vysecurity/DomLink) (requiert une clé API whoxy).\
Vous pouvez aussi effectuer une découverte reverse whois automatique avec [amass](https://github.com/OWASP/Amass) : `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir davantage de noms de domaine à chaque fois que vous trouvez un nouveau domaine.**

### **Trackers**

Si vous trouvez le **même ID du même tracker** sur 2 pages différentes vous pouvez supposer que **les deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **Google Analytics ID** ou le même **Adsense ID** sur plusieurs pages.

Il existe des sites et outils qui permettent de rechercher par ces trackers et plus :

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trouve des sites liés par des analytics/trackers partagés)

### **Favicon**

Saviez-vous que l'on peut trouver des domaines et sous-domaines liés à notre cible en cherchant le même hash d'icône favicon ? C'est exactement ce que fait l'outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) créé par [@m4ll0k2](https://twitter.com/m4ll0k2). Voici comment l'utiliser :
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - découvrir des domaines ayant le même hash du favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En clair, favihash permet de découvrir des domaines ayant le même hash du favicon que notre cible.

De plus, vous pouvez aussi rechercher des technologies en utilisant le hash du favicon comme expliqué dans [**cet article de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Cela signifie que si vous connaissez le **hash du favicon d'une version vulnérable d'une technologie web** vous pouvez le rechercher sur shodan et **trouver d'autres endroits vulnérables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Voici comment vous pouvez **calculer le favicon hash** d'un site web:
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
Vous pouvez aussi obtenir des hashes de favicon à grande échelle avec [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) puis pivoter dans Shodan/Censys.

### **Droits d'auteur / chaîne unique**

Recherchez à l'intérieur des pages web des **chaînes qui pourraient être partagées entre différents sites au sein de la même organisation**. La **chaîne de copyright** peut être un bon exemple. Ensuite, recherchez cette chaîne dans **google**, dans d'autres **navigateurs** ou même dans **shodan** : `shodan search http.html:"Copyright string"`

### **CRT Time**

Il est courant d'avoir un cron job tel que
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
pour renouveler tous les certificats de domaine sur le serveur. Cela signifie que même si la CA utilisée pour cela n'indique pas l'heure de génération dans la Validity time, il est possible de **trouver des domaines appartenant à la même entreprise dans les logs de certificate transparency**.\
Consultez ce [**writeup pour plus d'informations**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Utilisez également directement les logs **certificate transparency** :

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informations DMARC

Vous pouvez utiliser un site web tel que [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou un outil tel que [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) pour trouver **des domaines et subdomain partageant les mêmes informations dmarc**.\
D'autres outils utiles sont [**spoofcheck**](https://github.com/BishopFox/spoofcheck) et [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Il est apparemment courant que des personnes assignent des subdomains à des IP appartenant à des fournisseurs cloud et qu'à un moment donné elles **perdent cette adresse IP mais oublient de supprimer l'enregistrement DNS**. Par conséquent, en **spawning a VM** dans un cloud (comme Digital Ocean) vous allez en réalité **prendre le contrôle de certains subdomains**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explique une histoire à ce sujet et propose un script qui **spawns a VM in DigitalOcean**, **gets** l'**IPv4** de la nouvelle machine, et **searches in Virustotal for subdomain records** qui y pointent.

### **Autres façons**

**Notez que vous pouvez utiliser cette technique pour découvrir davantage de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

**Shodan**

Comme vous connaissez déjà le nom de l'organisation propriétaire de l'espace IP. Vous pouvez rechercher cette donnée dans shodan en utilisant : `org:"Tesla, Inc."` Vérifiez les hôtes trouvés pour de nouveaux domaines inattendus dans le TLS certificate.

Vous pouvez accéder au **TLS certificate** de la page web principale, obtenir le **nom de l'organisation** puis rechercher ce nom à l'intérieur des **TLS certificates** de toutes les pages web connues par **shodan** avec le filtre : `ssl:"Tesla Motors"` ou utiliser un outil comme [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) est un outil qui recherche des **domaines related** à un domaine principal et les **subdomains** de ceux-ci, assez incroyable.

**Passive DNS / Historical DNS**

Les données Passive DNS sont excellentes pour trouver des **anciens et oubliés enregistrements** qui résolvent encore ou qui peuvent être repris. Consultez :

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Recherche de vulnérabilités**

Cherchez un [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Peut-être qu'une entreprise **utilise un domaine** mais a **perdu la propriété**. Enregistrez-le simplement (si assez bon marché) et informez l'entreprise.

Si vous trouvez un **domaine avec une IP différente** des IP que vous avez déjà trouvées lors de la découverte des assets, vous devriez effectuer un **basic vulnerability scan** (en utilisant Nessus ou OpenVAS) et quelques [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services en cours d'exécution, vous pouvez trouver dans **ce livre quelques trucs pour "attaquer" them**.\
_Notez que parfois le domaine est hébergé sur une IP qui n'est pas contrôlée par le client, donc ce n'est pas dans le scope, soyez prudent._

## Sous-domaines

> Nous connaissons toutes les entreprises dans le scope, tous les assets de chaque entreprise et tous les domaines liés aux entreprises.

Il est temps de trouver tous les subdomains possibles de chaque domaine trouvé.

> [!TIP]
> Notez que certains des outils et techniques pour trouver des domaines peuvent aussi aider à trouver des subdomains

### **DNS**

Essayons d'obtenir des **subdomains** à partir des enregistrements **DNS**. Nous devrions aussi tenter un **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Le moyen le plus rapide d'obtenir un grand nombre de subdomains est de les rechercher dans des sources externes. Les **outils** les plus utilisés sont les suivants (pour de meilleurs résultats, configurez les API keys) :

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
Il existe d'autres outils/APIs intéressants qui, même s'ils ne sont pas directement spécialisés dans la recherche de subdomains, peuvent être utiles pour en trouver, comme :

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilise l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) pour obtenir des subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC API gratuite**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) API gratuite
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
- [**gau**](https://github.com/lc/gau)**:** récupère les URLs connues depuis AlienVault's Open Threat Exchange, the Wayback Machine et Common Crawl pour un domaine donné.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Ils parcourent le web à la recherche de fichiers JS et en extraient des sous-domaines.
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
- [**securitytrails.com**](https://securitytrails.com/) dispose d'une API gratuite pour rechercher des subdomains et l'historique des IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ce projet offre gratuitement tous les subdomains liés aux bug-bounty programs. Vous pouvez accéder à ces données aussi en utilisant [chaospy](https://github.com/dr-0x0x/chaospy) ou même accéder au scope utilisé par ce projet [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous pouvez trouver une **comparaison** de beaucoup de ces outils ici : [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux **subdomains** en brute-forçant les DNS servers en utilisant des noms de subdomain possibles.

Pour cette action, vous aurez besoin de quelques wordlists courantes de subdomains, telles que :

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Et aussi des IPs de bons DNS resolvers. Pour générer une liste de resolvers de confiance, vous pouvez télécharger les resolvers depuis [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Ou vous pouvez utiliser : [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour DNS brute-force sont :

- [**massdns**](https://github.com/blechschmidt/massdns) : C'était le premier outil à effectuer un DNS brute-force efficace. Il est très rapide mais sujet à des false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Je pense que celui-ci n'utilise qu'un seul resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est une surcouche de `massdns`, écrite en go, qui permet d'énumérer des sous-domaines valides en utilisant active bruteforce, ainsi que de résoudre des sous-domaines avec wildcard handling et un support input-output simple.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Il utilise également `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour effectuer du brute force sur des noms de domaine de manière asynchrone.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Deuxième ronde de DNS Brute-Force

Après avoir trouvé des sous-domaines en utilisant des sources ouvertes et le brute-forcing, vous pouvez générer des variantes des sous-domaines trouvés pour essayer d'en découvrir davantage. Plusieurs outils sont utiles à cet effet :

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Génère des permutations à partir des domaines et sous-domaines.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): À partir des domaines et sous-domaines fournis, génère des permutations.
- Vous pouvez obtenir la wordlist de permutations de goaltdns en [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** À partir des domaines et des sous-domaines, génère des permutations. Si aucun fichier de permutations n'est indiqué, gotator utilisera le sien.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): En plus de générer des permutations de sous-domaines, il peut aussi tenter de les résoudre (mais il est préférable d'utiliser les outils commentés précédemment).
- Vous pouvez obtenir la **wordlist** de permutations d'altdns [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un autre outil pour effectuer des permutations, des mutations et des altérations de sous-domaines. Cet outil appliquera un brute force sur le résultat (il ne prend pas en charge dns wild card).
- Vous pouvez obtenir la wordlist de permutations de dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basé sur un domaine, il **génère de nouveaux noms de subdomains potentiels** selon des modèles indiqués pour tenter de découvrir davantage de subdomains.

#### Génération intelligente de permutations

- [**regulator**](https://github.com/cramppet/regulator): Pour plus d'infos lisez ce [**post**](https://cramppet.github.io/regulator/index.html) mais il va essentiellement extraire les **parties principales** des **subdomains découverts** et les mélanger pour en trouver davantage.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ est un subdomain brute-force fuzzer couplé à un algorithme guidé par DNS response extrêmement simple mais efficace. Il utilise un jeu de données d'entrée fourni, comme une wordlist sur mesure ou des enregistrements DNS/TLS historiques, pour synthétiser avec précision davantage de noms de domaine correspondants et les étendre encore plus dans une boucle basée sur les informations collectées lors du DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Consultez cet article de blog que j'ai écrit sur la façon d'**automatiser le subdomain discovery** d'un domaine en utilisant **Trickest workflows**, afin de ne pas avoir à lancer manuellement une série d'outils sur mon ordinateur :


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Si vous trouvez une adresse IP contenant une ou plusieurs pages web appartenant à des subdomains, vous pouvez essayer de trouver d'autres subdomains avec des sites sur cette IP en cherchant dans des sources OSINT des domaines liés à cette IP ou en brute-forcing des VHost domain names sur cette IP.

#### OSINT

Vous pouvez trouver certains **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**.

**Brute Force**

Si vous suspectez qu'un subdomain peut être caché sur un serveur web, vous pouvez essayer de le brute force :
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
> Avec cette technique, vous pouvez même accéder à des endpoints internes/cachés.

### **CORS Brute Force**

Parfois, vous trouverez des pages qui ne retournent le header _**Access-Control-Allow-Origin**_ que lorsqu'un domaine/subdomain valide est défini dans le header _**Origin**_. Dans ces scénarios, vous pouvez abuser de ce comportement pour **découvrir** de nouveaux **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

En recherchant des **subdomains**, surveillez si elles sont **pointing** vers un type de **bucket**, et dans ce cas [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Aussi, à ce stade, comme vous connaîtrez tous les domains à l'intérieur du scope, essayez de [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Vous pouvez **monitor** si des **new subdomains** d'un domain sont créés en surveillant les logs de **Certificate Transparency**, comme le fait [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Vérifiez d'éventuels [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **subdomain** est **pointing** vers un **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si vous trouvez un **subdomain avec une IP différente** de celles déjà trouvées lors de l'assets discovery, vous devriez effectuer un **basic vulnerability scan** (avec Nessus ou OpenVAS) et un **port scan** ([**discovering-hosts-from-the-outside**](../pentesting-network/index.html#discovering-hosts-from-the-outside)) avec **nmap/masscan/shodan**. Selon les services en cours d'exécution, vous pouvez trouver dans **ce livre quelques astuces pour "attaquer" them**.\
_Remarquez que parfois le subdomain est hébergé sur une IP qui n'est pas contrôlée par le client, donc hors scope — soyez prudent._

## IPs

Aux étapes initiales vous avez peut‑être **found some IP ranges, domains and subdomains**.\
Il est temps de **recollect all the IPs from those ranges** et pour les **domains/subdomains (DNS queries).**

En utilisant les services des **free apis** suivants vous pouvez aussi retrouver des **previous IPs used by domains and subdomains**. Ces IPs peuvent encore appartenir au client (et peuvent vous permettre de trouver des [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Vous pouvez aussi vérifier quels domains pointent vers une IP spécifique en utilisant l'outil [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan** toutes les IPs qui n'appartiennent pas à des CDNs (vous ne trouverez probablement rien d'intéressant là‑dedans). Parmi les services découverts en cours d'exécution vous pourriez **be able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

Lors des étapes précédentes vous avez probablement déjà effectué du **recon** sur les IPs et domains découverts, donc vous avez peut‑être **already found all the possible web servers**. Cependant, si ce n'est pas le cas, nous allons voir quelques **fast tricks to search for web servers** à l'intérieur du scope.

Veuillez noter que ceci sera **oriented for web apps discovery**, donc vous devriez aussi **perform the vulnerability** et le **port scanning** (**if allowed** par le scope).

A **fast method** pour découvrir les **ports open** liés aux **web** servers en utilisant [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Un autre outil pratique pour rechercher des web servers est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Vous fournissez simplement une liste de domains et il essaiera de se connecter sur le port 80 (http) et 443 (https). De plus, vous pouvez indiquer d'essayer d'autres ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Captures d'écran**

Maintenant que vous avez découvert **all the web servers** présents dans le scope (parmi les **IPs** de la société et tous les **domains** et **subdomains**) vous ne savez probablement **pas par où commencer**. Donc, simplifions et commencez simplement à prendre des screenshots de tous. Rien qu'en **regardant** la **main page** vous pouvez trouver des endpoints **bizarres** plus **susceptibles** d'être **vulnérables**.

Pour mettre en œuvre cette idée vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

De plus, vous pouvez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) pour analyser toutes les **screenshots** et vous indiquer **ce qui est susceptible de contenir des vulnérabilités**, et ce qui ne l'est pas.

## Actifs Cloud publics

Pour trouver des cloud assets potentiels appartenant à une entreprise, commencez par une liste de mots-clés qui identifient cette entreprise. Par exemple, pour une entreprise crypto vous pouvez utiliser des mots tels que : "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Vous aurez aussi besoin de wordlists de **mots communs utilisés dans les buckets** :

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, avec ces mots vous devriez générer des **permutations** (check the [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) for more info).

Avec les wordlists obtenues vous pouvez utiliser des outils tels que [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

N'oubliez pas que lorsque vous recherchez des Cloud Assets vous devez **regarder au-delà des seuls buckets dans AWS**.

### **Looking for vulnerabilities**

Si vous trouvez des éléments tels que des **buckets ouverts** ou des **cloud functions exposées**, vous devriez y **accéder** et essayer de voir ce qu'ils vous offrent et si vous pouvez les abuser.

## Emails

Avec les **domains** et **subdomains** dans le scope vous avez essentiellement tout ce qu'il vous faut pour commencer à rechercher des emails. Voici les **APIs** et **outils** qui ont le mieux fonctionné pour moi afin de trouver des emails d'une entreprise :

- [**theHarvester**](https://github.com/laramies/theHarvester) - avec APIs
- API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
- API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
- API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Looking for vulnerabilities**

Les emails seront utiles plus tard pour **brute-force** des web logins et des auth services (comme **SSH**). De plus, ils sont nécessaires pour des phishings. En outre, ces APIs vous donneront encore plus d'info sur la personne derrière l'email, ce qui est utile pour la campagne de phishing.

## Credential Leaks

Avec les **domains**, **subdomains**, et **emails** vous pouvez commencer à rechercher des credentials leakés par le passé appartenant à ces emails :

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Si vous trouvez des credentials valides leakés, c'est une victoire très facile.

## Secrets Leaks

Les credential leaks sont liés à des hacks d'entreprises où des **informations sensibles ont été leakées et vendues**. Cependant, les entreprises peuvent être affectées par d'autres leaks dont les infos ne figurent pas dans ces bases de données :

### Github Leaks

Des credentials et des APIs peuvent être leakés dans les **public repositories** de l'**organisation** ou des **utilisateurs** travaillant pour cette organization sur GitHub.\
Vous pouvez utiliser l'**outil** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **public repos** d'une **organisation** et de ses **développeurs** et exécuter [**gitleaks**](https://github.com/zricethezav/gitleaks) dessus automatiquement.

**Leakos** peut aussi être utilisé pour exécuter **gitleaks** contre tous les **textes** fournis via des URLs passées en paramètre car parfois des **web pages** contiennent aussi des secrets.

#### Github Dorks

Consultez aussi cette **page** pour des **github dorks** potentiels que vous pouvez rechercher dans l'organisation que vous attaquez :


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Parfois des attaquants ou des employés publient du contenu d'entreprise sur un paste site. Cela peut contenir ou non des informations sensibles, mais c'est très intéressant à rechercher.\
Vous pouvez utiliser l'outil [**Pastos**](https://github.com/carlospolop/Pastos) pour rechercher sur plus de 80 paste sites simultanément.

### Google Dorks

Les vieux mais efficaces google dorks sont toujours utiles pour trouver des **informations exposées qui ne devraient pas être là**. Le seul problème est que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas lancer manuellement. Donc, prenez vos 10 préférées ou utilisez un **outil comme** [**Gorks**](https://github.com/carlospolop/Gorks) **pour toutes les exécuter**.

_Remarque : les outils qui tentent d'exécuter toute la database en utilisant le navigateur Google régulier ne finiront jamais car google vous bloquera très rapidement._

### **Looking for vulnerabilities**

Si vous trouvez des credentials valides ou des API tokens leakés, c'est une victoire très facile.

## Public Code Vulnerabilities

Si vous découvrez que l'entreprise possède du **code open-source** vous pouvez l'**analyser** et rechercher des **vulnérabilités** dedans.

**Selon le langage** il existe différents **outils** que vous pouvez utiliser :


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Il existe aussi des services gratuits qui permettent de **scanner les repositories publics**, tels que :

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **majorité des vulnérabilités** trouvées par les bug hunters se situe dans les **web applications**, donc à ce stade je voudrais parler d'une **méthodologie de test d'applications web**, et vous pouvez [**trouver ces informations ici**](../../network-services-pentesting/pentesting-web/index.html).

Je souhaite aussi mentionner spécialement la section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), car même si vous ne devez pas attendre d'eux qu'ils trouvent des vulnérabilités très sensibles, ils sont utiles à intégrer dans des **workflows** pour obtenir des informations web initiales.

## Récapitulation

> Félicitations ! À ce stade vous avez déjà effectué **toute l'énumération de base**. Oui, c'est basique car beaucoup plus d'énumération peut être faite (nous verrons plus d'astuces plus tard).

Donc vous avez déjà :

1. Trouvé toutes les **companies** dans le scope
2. Trouvé tous les **assets** appartenant aux companies (et effectué quelques scans vuln si en scope)
3. Trouvé tous les **domains** appartenant aux companies
4. Trouvé tous les **subdomains** des domains (possible subdomain takeover ?)
5. Trouvé toutes les **IPs** (provenant ou non de **CDNs**) dans le scope.
6. Trouvé tous les **web servers** et pris une **screenshot** d'eux (quelque chose d'étrange mérite-t-il un examen plus approfondi ?)
7. Trouvé tous les **potentiels public cloud assets** appartenant à l'entreprise.
8. **Emails**, **credentials leaks**, et **secret leaks** qui pourraient vous donner une **grosse victoire très facilement**.
9. **Pentesting** de tous les webs que vous avez trouvés

## **Full Recon Automatic Tools**

Il existe plusieurs outils qui réaliseront une partie des actions proposées contre un scope donné.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et pas mis à jour

## **References**

- Tous les cours gratuits de [**@Jhaddix**](https://twitter.com/Jhaddix) comme [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
