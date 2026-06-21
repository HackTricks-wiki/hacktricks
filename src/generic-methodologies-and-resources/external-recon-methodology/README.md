# Méthodologie de External Recon

{{#include ../../banners/hacktricks-training.md}}

## Découverte des assets

> On vous a dit que tout ce qui appartient à une certaine société est dans le scope, et vous voulez déterminer ce que cette société possède réellement.

L’objectif de cette phase est d’obtenir toutes les **sociétés détenues par la société principale**, puis tous les **assets** de ces sociétés. Pour cela, nous allons :

1. Trouver les acquisitions de la société principale, cela nous donnera les sociétés dans le scope.
2. Trouver l’ASN (s’il y en a un) de chaque société, cela nous donnera les plages IP détenues par chaque société
3. Utiliser des reverse whois lookups pour rechercher d’autres entrées (noms d’organisation, domaines...) liées à la première (cela peut être fait de manière récursive)
4. Utiliser d’autres techniques comme les filtres shodan `org` et `ssl` pour rechercher d’autres assets (l’astuce `ssl` peut être faite de manière récursive).

### **Acquisitions**

Tout d’abord, nous devons savoir quelles **autres sociétés sont détenues par la société principale**.\
Une option consiste à visiter [https://www.crunchbase.com/](https://www.crunchbase.com), **rechercher** la **société principale**, puis **cliquer** sur "**acquisitions**". Vous y verrez les autres sociétés acquises par la principale.\
Une autre option consiste à visiter la page **Wikipedia** de la société principale et à chercher les **acquisitions**.\
Pour les sociétés cotées, vérifiez les dépôts **SEC/EDGAR**, les pages d’**investor relations**, ou les registres d’entreprises locaux (par ex. **Companies House** au Royaume-Uni).\
Pour les arbres d’entreprise globaux et les filiales, essayez **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) et la base de données **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, à ce stade vous devriez connaître toutes les sociétés dans le scope. Voyons comment trouver leurs assets.

### **ASNs**

Un autonomous system number (**ASN**) est un **numéro unique** attribué à un **autonomous system** (AS) par l’**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** est constitué de **blocs** d’**adresses IP** qui ont une politique clairement définie pour l’accès aux réseaux externes et qui sont administrés par une seule organisation, mais peuvent être composés de plusieurs opérateurs.

Il est intéressant de vérifier si la **société a attribué un ASN** afin de trouver ses **plages IP**. Il sera intéressant d’effectuer un **vulnerability test** contre tous les **hosts** dans le **scope** et de **chercher des domaines** dans ces IPs.\
Vous pouvez **rechercher** par **nom** de société, par **IP** ou par **domain** dans [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Selon la région de la société, ces liens pourraient être utiles pour collecter plus de données :** [**AFRINIC**](https://www.afrinic.net) **(Afrique),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amérique du Nord),** [**APNIC**](https://www.apnic.net) **(Asie),** [**LACNIC**](https://www.lacnic.net) **(Amérique latine),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Quoi qu’il en soit, probablement toutes les** informations utiles **(plages IP et Whois)** apparaissent déjà dans le premier lien.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
énumération agrège et résume automatiquement les ASN à la fin du scan.
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
Vous pouvez également trouver les plages d'IP d'une organisation en utilisant [http://asnlookup.com/](http://asnlookup.com) (il a une API gratuite).\
Vous pouvez trouver l'IP et l'ASN d'un domaine en utilisant [http://ipv4info.com/](http://ipv4info.com).

### **Recherche de vulnérabilités**

À ce stade, nous connaissons **tous les assets dans le scope**, donc si vous êtes autorisé, vous pourriez lancer un **scanner de vulnérabilités** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sur tous les hôtes.\
Vous pourriez aussi lancer des [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou utiliser des services comme** Shodan, Censys, ou ZoomEye **pour trouver** les ports ouverts **et, selon ce que vous trouvez, vous devriez** consulter ce livre pour apprendre à pentest plusieurs services possibles en cours d'exécution.\
**Aussi, il peut être utile de mentionner que vous pouvez également préparer des listes de** usernames **et de** passwords **par défaut et essayer de** bruteforce des services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises dans le scope et leurs assets, il est temps de trouver les domaines dans le scope.

_Please, notez que dans les techniques proposées ci-dessous, vous pouvez également trouver des sous-domaines et que cette information ne devrait pas être sous-estimée._

Tout d'abord, vous devriez chercher le(s) **domaine(s) principal(aux)** de chaque entreprise. Par exemple, pour _Tesla Inc._, ce sera _tesla.com_.

### **Reverse DNS**

Comme vous avez trouvé toutes les plages d'IP des domaines, vous pourriez essayer d'effectuer des **reverse dns lookups** sur ces **IPs pour trouver d'autres domaines dans le scope**. Essayez d'utiliser un serveur dns de la victime ou un serveur dns bien connu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Pour que cela fonctionne, l’administrateur doit activer manuellement le PTR.\
Vous pouvez aussi utiliser un outil en ligne pour cette info : [http://ptrarchive.com/](http://ptrarchive.com).\
Pour de grandes plages, des outils comme [**massdns**](https://github.com/blechschmidt/massdns) et [**dnsx**](https://github.com/projectdiscovery/dnsx) sont utiles pour automatiser les reverse lookups et l’enrichissement.

### **Reverse Whois (loop)**

Dans un **whois**, vous pouvez trouver beaucoup d’**informations** intéressantes comme le **nom de l’organisation**, l’**adresse**, les **emails**, les numéros de téléphone... Mais ce qui est encore plus intéressant, c’est que vous pouvez trouver **plus d’assets liés à l’entreprise** si vous effectuez des **reverse whois lookups** à partir de l’un de ces champs (par exemple, d’autres registres whois où le même email apparaît).\
Vous pouvez utiliser des outils en ligne comme :

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

Vous pouvez automatiser cette tâche en utilisant [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Vous pouvez aussi effectuer une découverte automatique de reverse whois avec [amass](https://github.com/OWASP/Amass) : `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir davantage de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

### **Trackers**

Si vous trouvez le **même ID du même tracker** sur 2 pages différentes, vous pouvez supposer que les **deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **Google Analytics ID** ou le même **Adsense ID** sur plusieurs pages.

Il existe des pages et des outils qui vous permettent de rechercher avec ces trackers et plus encore :

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Saviez-vous que nous pouvons trouver des domaines et sous-domaines liés à notre cible en recherchant le même hash d’icône favicon ? C’est exactement ce que fait l’outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) créé par [@m4ll0k2](https://twitter.com/m4ll0k2). Voici comment l’utiliser :
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En termes simples, favihash nous permettra de découvrir des domaines qui ont le même favicon icon hash que notre cible.

De plus, vous pouvez également rechercher des technologies en utilisant le favicon hash comme expliqué dans [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Cela signifie que si vous connaissez le **hash du favicon d’une version vulnérable d’une technologie web** vous pouvez rechercher s'il est dans shodan et **trouver plus d'endroits vulnérables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Voici comment vous pouvez **calculer le hash du favicon** d’un site web :
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
Vous pouvez également obtenir des hashes de favicon à grande échelle avec [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) puis pivoter dans Shodan/Censys.

### **Copyright / Uniq string**

Recherchez à l'intérieur des pages web des **strings qui pourraient être partagées entre différents sites web de la même organisation**. La **copyright string** pourrait être un bon exemple. Ensuite, recherchez cette string dans **google**, dans d'autres **browsers** ou même dans **shodan** : `shodan search http.html:"Copyright string"`

### **CRT Time**

Il est courant d'avoir une tâche cron comme
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew all the certificates de domaine sur le serveur. Cela signifie que même si le CA utilisé pour cela ne définit pas l’heure à laquelle il a été généré dans le temps de Validity, il est possible de **trouver des domaines appartenant à la même entreprise dans les certificate transparency logs**.\
Consultez cette [**writeup pour plus d’informations**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Utilisez aussi directement les logs de **certificate transparency** :

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informations Mail DMARC

Vous pouvez utiliser un site web comme [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou un outil comme [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) pour trouver des **domaines et sous-domaines partageant les mêmes informations dmarc**.\
D’autres outils utiles sont [**spoofcheck**](https://github.com/BishopFox/spoofcheck) et [**dmarcian**](https://dmarcian.com/).

### **Prise de contrôle passive**

Apparemment, il est courant que des personnes associent des sous-domaines à des IP qui appartiennent à des fournisseurs cloud et qu’à un moment elles **perdent cette adresse IP mais oublient de supprimer l’enregistrement DNS**. Par conséquent, il suffit de **lancer une VM** dans un cloud (comme Digital Ocean) pour **prendre le contrôle de certains sous-domaine(s)**.

[**Ce post**](https://kmsec.uk/blog/passive-takeover/) explique une histoire à ce sujet et propose un script qui **lance une VM dans DigitalOcean**, **récupère** l’**IPv4** de la nouvelle machine, et **cherche dans Virustotal des enregistrements de sous-domaines** pointant vers elle.

### **Autres façons**

**Notez que vous pouvez utiliser cette technique pour découvrir davantage de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

**Shodan**

Comme vous connaissez déjà le nom de l’organisation qui possède l’espace IP. Vous pouvez rechercher ces données dans shodan avec : `org:"Tesla, Inc."` Vérifiez les hôtes trouvés pour repérer de nouveaux domaines inattendus dans le certificat TLS.

Vous pourriez accéder au **certificat TLS** de la page web principale, obtenir le nom de l’**Organisation**, puis rechercher ce nom dans les **certificats TLS** de toutes les pages web connues par **shodan** avec le filtre : `ssl:"Tesla Motors"` ou utiliser un outil comme [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)est un outil qui recherche des **domaines liés** à un domaine principal et leurs **sous-domaines**, vraiment impressionnant.

**Passive DNS / Historical DNS**

Les données de Passive DNS sont idéales pour trouver des **anciens enregistrements oubliés** qui résolvent encore ou qui peuvent être pris de contrôle. Regardez :

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Recherche de vulnérabilités**

Vérifiez s’il y a un [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Peut-être qu’une entreprise **utilise un domaine** mais qu’elle **en a perdu la propriété**. Il suffit de l’enregistrer (si c’est assez peu coûteux) et d’en informer l’entreprise.

Si vous trouvez un **domaine avec une IP différente** de celles que vous avez déjà trouvées lors de la découverte des assets, vous devriez effectuer un **scan de vulnérabilités basique** (en utilisant Nessus ou OpenVAS) et un **port scan** avec **nmap/masscan/shodan**. Selon les services qui tournent, vous pouvez trouver dans **ce livre quelques astuces pour les "attaquer"**.\
_Remarque : parfois le domaine est hébergé sur une IP qui n’est pas contrôlée par le client, donc ce n’est pas dans le scope, soyez prudent._

## Sous-domaines

> Nous connaissons toutes les entreprises dans le scope, tous les assets de chaque entreprise et tous les domaines liés aux entreprises.

Il est temps de trouver tous les sous-domaines possibles de chaque domaine trouvé.

> [!TIP]
> Notez que certains outils et certaines techniques pour trouver des domaines peuvent aussi aider à trouver des sous-domaines

### **DNS**

Essayons d’obtenir des **sous-domaines** à partir des enregistrements **DNS**. Nous devrions aussi essayer un **Zone Transfer** (si c’est vulnérable, vous devriez le signaler).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Le moyen le plus rapide d’obtenir beaucoup de subdomains est de rechercher dans des sources externes. Les **tools** les plus utilisés sont les suivants (pour de meilleurs résultats, configurez les API keys) :

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
Il existe **d'autres outils/API intéressants** qui, même s'ils ne sont pas directement spécialisés dans la recherche de sous-domaines, peuvent être utiles pour en trouver, comme :

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
- [**gau**](https://github.com/lc/gau)**:** récupère les URLs connues depuis AlienVault's Open Threat Exchange, the Wayback Machine, et Common Crawl pour n'importe quel domaine donné.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Ils parcourent le web à la recherche de fichiers JS et en extraient les sous-domaines.
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
- [**securitytrails.com**](https://securitytrails.com/) a une API gratuite pour rechercher des sous-domaines et l’historique des IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ce projet offre **gratuitement tous les sous-domaines liés aux programmes de bug-bounty**. Vous pouvez accéder à ces données aussi avec [chaospy](https://github.com/dr-0x0x/chaospy) ou même accéder au scope utilisé par ce projet [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous pouvez trouver une **comparaison** de nombreux de ces outils ici : [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux **sous-domaines** en brute-forçant les serveurs DNS à l’aide de possibles noms de sous-domaines.

Pour cette action, vous aurez besoin de **listes de mots de sous-domaines courants comme** :

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Et aussi des IPs de bons résolveurs DNS. Afin de générer une liste de résolveurs DNS de confiance, vous pouvez télécharger les résolveurs depuis [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Ou vous pouvez utiliser : [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour le brute-force DNS sont :

- [**massdns**](https://github.com/blechschmidt/massdns) : C’était le premier outil à réaliser un brute-force DNS efficace. Il est très rapide cependant il est sujet aux faux positifs.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Celui-ci, je pense, n'utilise qu’un seul resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est un wrapper autour de `massdns`, écrit en go, qui permet d’énumérer des sous-domaines valides en utilisant le bruteforce actif, ainsi que de résoudre des sous-domaines avec gestion des wildcards et un support simple des entrées-sorties.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns) : Il utilise aussi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour brute force des noms de domaine de manière asynchrone.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Deuxième tour de brute-force DNS

Après avoir trouvé des sous-domaines en utilisant des sources ouvertes et du brute-forcing, vous pourriez générer des variations des sous-domaines trouvés afin d’essayer d’en découvrir encore plus. Plusieurs outils sont utiles à cette fin :

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** À partir des domaines et sous-domaines, génère des permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Étant donné les domaines et sous-domaines, génère des permutations.
- Vous pouvez obtenir la **wordlist** des permutations de **goaltdns** [**ici**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Étant donné les domaines et sous-domaines, génère des permutations. Si aucun fichier de permutations n’est indiqué, gotator utilisera le sien.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): En plus de générer des permutations de sous-domaines, il peut aussi essayer de les résoudre (mais il vaut mieux utiliser les outils commentés précédemment).
- Vous pouvez obtenir la **wordlist** des permutations d’**altdns** [**ici**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut) : Un autre outil pour effectuer des permutations, mutations et altérations de sous-domaines. Cet outil va brute force le résultat (il ne prend pas en charge le wildcard DNS).
- Vous pouvez obtenir la wordlist de permutations de dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basé sur un domaine, il **génère de nouveaux noms potentiels de sous-domaines** à partir de motifs indiqués pour essayer de découvrir plus de sous-domaines.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Pour plus d'informations, lis ce [**post**](https://cramppet.github.io/regulator/index.html), mais il va essentiellement prendre les **parties principales** des **sous-domaines découverts** et les mélanger pour en trouver d'autres.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ est un fuzzeur de brute-force de sous-domaines couplé à un algorithme guidé par les réponses DNS, immensément simple mais efficace. Il utilise un ensemble de données d’entrée fourni, comme une wordlist adaptée ou des enregistrements DNS/TLS historiques, pour synthétiser avec précision davantage de noms de domaine correspondants et les étendre encore plus dans une boucle basée sur les informations recueillies pendant le scan DNS.
```
echo www | subzuf facebook.com
```
### **Flux de travail de découverte de sous-domaines**

Consultez cet article de blog que j'ai écrit sur la façon d'**automatiser la découverte de sous-domaines** à partir d'un domaine en utilisant des **workflows Trickest** afin que je n'aie pas besoin de lancer manuellement une foule d'outils sur mon ordinateur :


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Hôtes virtuels**

Si vous avez trouvé une adresse IP contenant **une ou plusieurs pages web** appartenant à des sous-domaines, vous pouvez essayer de **trouver d'autres sous-domaines avec des sites web sur cette IP** en recherchant dans des **sources OSINT** des domaines sur une IP ou en **brute-forçant les noms de domaine VHost sur cette IP**.

#### OSINT

Vous pouvez trouver certains **VHosts dans des IPs en utilisant** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou d'autres API**.

**Brute Force**

Si vous soupçonnez qu'un sous-domaine peut être caché dans un serveur web, vous pouvez essayer de le brute force :

Lorsque l'**IP redirige vers un hostname** (name-based vhosts), fuzz directement l'en-tête `Host` et laissez ffuf **auto-calibrer** pour mettre en évidence les réponses qui diffèrent du vhost par défaut :
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
> Avec cette technique, vous pourriez même être en mesure d'accéder à des endpoints internes/cachés.

### **CORS Brute Force**

Parfois, vous trouverez des pages qui ne renvoient l'en-tête _**Access-Control-Allow-Origin**_ que lorsqu'un domaine/sous-domaine valide est défini dans l'en-tête _**Origin**_. Dans ces scénarios, vous pouvez abuser de ce comportement pour **découvrir** de nouveaux **sous-domaines**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Lors de la recherche de **sous-domaines**, surveillez s’ils **pointent** vers un type de **bucket**, et dans ce cas [**vérifiez les permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
De plus, comme à ce stade vous connaîtrez tous les domaines dans le périmètre, essayez de [**brute force les noms de bucket possibles et vérifiez les permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Vous pouvez **surveiller** si de **nouveaux sous-domaines** d’un domaine sont créés en surveillant les logs de **Certificate Transparency** ; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)le fait.

### **Looking for vulnerabilities**

Vérifiez les possibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **sous-domaine** pointe vers un **bucket S3**, [**vérifiez les permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si vous trouvez un **sous-domaine avec une IP différente** de celles que vous avez déjà trouvées lors de la découverte des assets, vous devriez lancer un **scan de vulnérabilités basique** (avec Nessus ou OpenVAS) et un **scan de ports** [**nmap/masscan/shodan**](../pentesting-network/index.html#discovering-hosts-from-the-outside). Selon les services en cours d’exécution, vous pouvez trouver dans **ce livre quelques astuces pour les "attaquer"**.\
_Remarque : parfois le sous-domaine est hébergé sur une IP qui n’est pas contrôlée par le client, donc elle n’est pas dans le périmètre, soyez prudent._

## IPs

Dans les étapes initiales, vous avez peut-être **trouvé des plages d’IP, des domaines et des sous-domaines**.\
Il est temps de **récupérer toutes les IPs de ces plages** et pour les **domaines/sous-domaines (requêtes DNS).**

En utilisant des services des **apis gratuites** suivantes, vous pouvez aussi trouver les **anciennes IPs utilisées par les domaines et sous-domaines**. Ces IPs sont peut-être encore détenues par le client (et peuvent vous permettre de trouver des [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Vous pouvez aussi vérifier quels domaines pointent vers une adresse IP spécifique en utilisant l’outil [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Scannez les ports de toutes les IPs qui n’appartiennent pas à des CDN** (car vous n’y trouverez très probablement rien d’intéressant). Dans les services découverts en cours d’exécution, vous pourriez être **en mesure de trouver des vulnérabilités**.

**Trouvez un** [**guide**](../pentesting-network/index.html) **sur la façon de scanner des hôtes.**

## Web servers hunting

> Nous avons trouvé toutes les entreprises et leurs assets et nous connaissons les plages d’IP, domaines et sous-domaines dans le périmètre. Il est temps de rechercher des serveurs web.

Dans les étapes précédentes, vous avez probablement déjà effectué une partie de la **recon des IPs et domaines découverts**, donc vous avez peut-être **déjà trouvé tous les serveurs web possibles**. Cependant, si ce n’est pas le cas, nous allons maintenant voir quelques **astuces rapides pour rechercher des serveurs web** dans le périmètre.

Veuillez noter que ceci sera **orienté vers la découverte d’applications web**, donc vous devriez aussi **effectuer la recherche de vulnérabilités** et le **scan de ports** (**si autorisé** par le périmètre).

Une **méthode rapide** pour découvrir les **ports ouverts** liés aux serveurs **web** en utilisant [**masscan** peut être trouvée ici](../pentesting-network/index.html#http-port-discovery).\
Un autre outil pratique pour rechercher des serveurs web est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Il suffit de fournir une liste de domaines et il essaiera de se connecter au port 80 (http) et 443 (https). De plus, vous pouvez indiquer d’essayer d’autres ports :
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Maintenant que vous avez découvert **tous les web servers** présents dans le scope (parmi les **IPs** de l’entreprise et tous les **domains** et **subdomains**) vous ne **savez probablement pas par où commencer**. Alors, faisons simple et commençons par prendre des screenshots de tous. Rien qu’en **regardant** la **main page**, vous pouvez trouver des endpoints **étranges** plus **susceptibles** d’être **vulnérables**.

Pour mettre en œuvre l’idée proposée, vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

De plus, vous pourriez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) pour parcourir tous les **screenshots** afin de vous dire **ce qui est susceptible de contenir des vulnérabilités**, et ce qui n’en contient pas.

## Public Cloud Assets

Afin de trouver des cloud assets potentiels appartenant à une entreprise, vous devriez **commencer par une liste de mots-clés qui identifient cette entreprise**. Par exemple, pour une entreprise crypto, vous pourriez utiliser des mots tels que : `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Vous aurez également besoin de wordlists de **mots courants utilisés dans les buckets** :

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, avec ces mots, vous devriez générer des **permutations** (voir le [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) pour plus d’infos).

Avec les wordlists obtenues, vous pourriez utiliser des outils tels que [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

N’oubliez pas que, lorsque vous cherchez des Cloud Assets, vous devez chercher plus que des buckets dans AWS.

### **Looking for vulnerabilities**

Si vous trouvez des éléments tels que des **buckets ouverts ou des cloud functions exposées**, vous devriez **y accéder** et essayer de voir ce qu’ils vous offrent et si vous pouvez en abuser.

## Emails

Avec les **domains** et **subdomains** dans le scope, vous avez en gros tout ce qu’il vous **faut pour commencer à chercher des emails**. Voici les **APIs** et **tools** qui ont le mieux fonctionné pour moi pour trouver les emails d’une entreprise :

- [**theHarvester**](https://github.com/laramies/theHarvester) - avec des APIs
- API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
- API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
- API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Looking for vulnerabilities**

Les emails seront utiles plus tard pour **brute-force des web logins et des auth services** (comme SSH). Ils sont aussi nécessaires pour les **phishings**. De plus, ces APIs vous donneront encore plus d’**infos sur la personne** derrière l’email, ce qui est utile pour la campagne de phishing.

## Credential Leaks

Avec les **domains**, **subdomains**, et **emails**, vous pouvez commencer à chercher des credentials leakés dans le passé appartenant à ces emails :

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Si vous trouvez des credentials **leakés valides**, c’est une victoire très facile.

## Secrets Leaks

Les credential leaks sont liés à des hacks d’entreprises où des **informations sensibles ont été leakées et vendues**. Cependant, les entreprises peuvent être affectées par d’autres leaks dont les infos ne sont pas dans ces bases de données :

### Github Leaks

Des credentials et des APIs peuvent être leakés dans les **public repositories** de l’**entreprise** ou des **utilisateurs** qui travaillent pour cette entreprise github.\
Vous pouvez utiliser le **tool** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **public repos** d’une **organisation** et de ses **développeurs** et exécuter [**gitleaks**](https://github.com/zricethezav/gitleaks) dessus automatiquement.

**Leakos** peut aussi être utilisé pour exécuter **gitleaks** contre tous les **text** **URLs passed** fournis, car parfois les **web pages** contiennent aussi des secrets.

#### Github Dorks

Consultez aussi cette **page** pour d’éventuels **github dorks** que vous pourriez aussi rechercher dans l’organisation que vous attaquez :


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Parfois, des attaquants ou simplement des employés vont **publier du contenu de l’entreprise sur un site de paste**. Cela peut contenir ou non des **informations sensibles**, mais cela vaut vraiment le coup de chercher.\
Vous pouvez utiliser le tool [**Pastos**](https://github.com/carlospolop/Pastos) pour chercher dans plus de 80 sites de paste en même temps.

### Google Dorks

Les google dorks, vieux mais toujours utiles, servent à trouver des **informations exposées qui ne devraient pas être là**. Le seul problème est que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas exécuter manuellement. Vous pouvez donc garder vos 10 préférées ou utiliser un **tool tel que** [**Gorks**](https://github.com/carlospolop/Gorks) **pour toutes les exécuter**.

_Notez que les tools qui s’attendent à exécuter toute la base de données via le navigateur Google normal ne finiront jamais, car Google vous bloquera très, très vite._

### **Looking for vulnerabilities**

Si vous trouvez des credentials ou des API tokens **leakés valides**, c’est une victoire très facile.

## Public Code Vulnerabilities

Si vous avez trouvé que l’entreprise a du **open-source code**, vous pouvez l’**analyser** et y chercher des **vulnerabilities**.

**Selon le langage**, il existe différents **tools** que vous pouvez utiliser :


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Il existe aussi des services gratuits qui permettent de **scanner des public repositories**, comme :

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **majorité des vulnerabilities** trouvées par les bug hunters se trouvent dans des **web applications**, donc à ce stade je voudrais parler d’une **web application testing methodology**, et vous pouvez [**trouver ces informations ici**](../../network-services-pentesting/pentesting-web/index.html).

Je veux aussi faire une mention spéciale à la section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), car, même si vous ne devez pas vous attendre à y trouver des vulnérabilités très sensibles, elles sont pratiques à intégrer dans des **workflows** pour obtenir quelques informations web initiales.

## Recapitulation

> Félicitations ! À ce stade, vous avez déjà effectué **toute l’énumération basique**. Oui, c’est basique, car beaucoup plus d’énumération peut être faite (nous verrons plus d’astuces plus tard).

Donc vous avez déjà :

1. Trouvé toutes les **companies** dans le scope
2. Trouvé tous les **assets** appartenant aux companies (et effectué un scan de vuln si dans le scope)
3. Trouvé tous les **domains** appartenant aux companies
4. Trouvé tous les **subdomains** des domains (un takeover de subdomain ?)
5. Trouvé toutes les **IPs** (depuis et **pas depuis les CDNs**) dans le scope.
6. Trouvé tous les **web servers** et pris un **screenshot** de chacun (quelque chose d’étrange qui mérite un examen plus approfondi ?)
7. Trouvé tous les **potential public cloud assets** appartenant à l’entreprise.
8. **Emails**, **credential leaks**, et **secret leaks** qui pourraient vous apporter un **gros gain très facilement**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Il existe plusieurs tools capables d’effectuer une partie des actions proposées sur un scope donné.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et non mis à jour

## **References**

- Tous les cours gratuits de [**@Jhaddix**](https://twitter.com/Jhaddix) comme [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
