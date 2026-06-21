# Méthodologie de reconnaissance externe

{{#include ../../banners/hacktricks-training.md}}

## Découverte des actifs

> On t’a dit que tout ce qui appartient à une certaine entreprise est dans le scope, et tu veux déterminer ce que cette entreprise possède réellement.

Le but de cette phase est d’obtenir toutes les **sociétés détenues par la société principale** puis tous les **actifs** de ces sociétés. Pour cela, nous allons :

1. Trouver les acquisitions de la société principale, cela nous donnera les sociétés dans le scope.
2. Trouver le ASN (s’il y en a un) de chaque société, cela nous donnera les plages IP détenues par chaque société.
3. Utiliser des recherches reverse whois pour trouver d’autres entrées (noms d’organisation, domaines...) liées à la première (cela peut être fait récursivement).
4. Utiliser d’autres techniques comme les filtres shodan `org` et `ssl` pour rechercher d’autres actifs (l’astuce `ssl` peut être faite récursivement).

### **Acquisitions**

Tout d’abord, nous devons savoir quelles **autres sociétés sont détenues par la société principale**.\
Une option est de visiter [https://www.crunchbase.com/](https://www.crunchbase.com), **rechercher** la **société principale**, puis **cliquer** sur "**acquisitions**". Tu y verras les autres sociétés acquises par la société principale.\
Une autre option est de visiter la page **Wikipedia** de la société principale et de rechercher **acquisitions**.\
Pour les sociétés cotées, vérifie les dépôts **SEC/EDGAR**, les pages **relations investisseurs**, ou les registres des sociétés locaux (par ex. **Companies House** au Royaume-Uni).\
Pour les structures d’entreprise mondiales et les filiales, essaie **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) et la base de données **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, à ce stade tu devrais connaître toutes les sociétés dans le scope. Voyons comment trouver leurs actifs.

### **ASNs**

Un numéro de système autonome (**ASN**) est un **numéro unique** attribué à un **système autonome** (AS) par l’**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** se compose de **blocs** d’**adresses IP** qui ont une politique clairement définie pour accéder aux réseaux externes et qui sont administrés par une seule organisation, mais peuvent être composés de plusieurs opérateurs.

Il est intéressant de voir si la **société a attribué un ASN** pour trouver ses **plages IP**. Il sera intéressant de réaliser un **test de vulnérabilité** contre tous les **hosts** dans le **scope** et de **chercher des domaines** à l’intérieur de ces IP.\
Tu peux **rechercher** par **nom** de société, par **IP** ou par **domaine** sur [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ou** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Selon la région de la société, ces liens peuvent être utiles pour recueillir plus de données :** [**AFRINIC**](https://www.afrinic.net) **(Afrique),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amérique du Nord),** [**APNIC**](https://www.apnic.net) **(Asie),** [**LACNIC**](https://www.lacnic.net) **(Amérique latine),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Quoi qu’il en soit, probablement que toutes les** informations utiles **(plages IP et Whois)** apparaissent déjà dans le premier lien.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
énumération agrège et résume automatiquement les ASNs à la fin du scan.
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

### **À la recherche de vulnérabilités**

À ce stade, nous connaissons **tous les assets dans le scope**, donc si vous y êtes autorisé, vous pourriez lancer un **scanner de vulnérabilités** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sur tous les hôtes.\
De plus, vous pourriez lancer des [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ou utiliser des services comme** Shodan, Censys ou ZoomEye **pour trouver** des ports ouverts **et, selon ce que vous trouvez, vous devriez** consulter ce livre pour savoir comment pentest plusieurs services potentiels en cours d'exécution.\
**Aussi, il peut être utile de mentionner que vous pouvez également préparer des** listes de noms d'utilisateur **et** de mots de passe **par défaut et essayer de** bruteforce des services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises dans le scope et leurs assets, il est temps de trouver les domaines dans le scope.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

Tout d'abord, vous devriez rechercher le(s) **domaine(s) principal(aux)** de chaque entreprise. Par exemple, pour _Tesla Inc._, ce sera _tesla.com_.

### **Reverse DNS**

Comme vous avez trouvé toutes les plages d'IP des domaines, vous pourriez essayer d'effectuer des **reverse dns lookups** sur ces **IP** pour trouver plus de domaines dans le scope. Essayez d'utiliser un serveur dns de la victime ou un serveur dns bien connu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Pour que cela fonctionne, l'administrateur doit activer manuellement le PTR.\
Vous pouvez aussi utiliser un outil en ligne pour cette info : [http://ptrarchive.com/](http://ptrarchive.com).\
Pour de grandes plages, des outils comme [**massdns**](https://github.com/blechschmidt/massdns) et [**dnsx**](https://github.com/projectdiscovery/dnsx) sont utiles pour automatiser les reverse lookups et l'enrichment.

### **Reverse Whois (loop)**

Dans un **whois**, vous pouvez trouver beaucoup d'**information** intéressante comme le **nom de l'organisation**, l'**adresse**, les **emails**, les numéros de téléphone... Mais ce qui est encore plus intéressant, c'est que vous pouvez trouver **plus d'assets liés à l'entreprise** si vous effectuez des **reverse whois lookups** à partir de l'un de ces champs (par exemple d'autres registres whois où le même email apparaît).\
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

Vous pouvez automatiser cette tâche avec [**DomLink** ](https://github.com/vysecurity/DomLink)(nécessite une clé API whoxy).\
Vous pouvez aussi effectuer une découverte automatique de reverse whois avec [amass](https://github.com/OWASP/Amass) : `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir plus de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

### **Trackers**

Si vous trouvez le **même ID du même tracker** sur 2 pages différentes, vous pouvez supposer que **les deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **Google Analytics ID** ou le même **Adsense ID** sur plusieurs pages.

Il existe plusieurs pages et outils qui permettent de rechercher à partir de ces trackers et plus encore :

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (trouve des sites liés par des analytics/trackers partagés)

### **Favicon**

Saviez-vous que nous pouvons trouver des domaines et sous-domaines liés à notre cible en recherchant le même hash d'icône favicon ? C'est exactement ce que fait l'outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) créé par [@m4ll0k2](https://twitter.com/m4ll0k2). Voici comment l'utiliser :
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En termes simples, favihash nous permettra de découvrir des domaines qui ont le même favicon icon hash que notre cible.

De plus, vous pouvez aussi rechercher des technologies en utilisant le favicon hash, comme expliqué dans [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Cela signifie que si vous connaissez le **hash du favicon d'une version vulnérable d'une web tech** vous pouvez rechercher cela dans shodan et **trouver plus de places vulnérables**:
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

Recherchez dans les pages web des **strings qui pourraient être partagées entre différents sites du même organisme**. La **copyright string** pourrait être un bon exemple. Puis recherchez cette string dans **google**, dans d’autres **browsers** ou même dans **shodan** : `shodan search http.html:"Copyright string"`

### **CRT Time**

Il est courant d’avoir une tâche cron telle que
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La façon la plus rapide d’obtenir beaucoup de sous-domaines est de rechercher dans des sources externes. Les **tools** les plus utilisés sont les suivants (pour de meilleurs résultats, configurez les clés API) :

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
Il existe **d’autres outils/API intéressants** qui, même s’ils ne sont pas directement spécialisés dans la recherche de sous-domaines, peuvent être utiles pour en trouver, comme :

- [**IP.THC.ORG**](https://ip.thc.org) free API
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
- [**gau**](https://github.com/lc/gau)**:** récupère les URLs connues depuis AlienVault's Open Threat Exchange, la Wayback Machine et Common Crawl pour n'importe quel domaine donné.
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

Ce projet offre **gratuitement tous les sous-domaines liés aux programmes bug-bounty**. Vous pouvez aussi accéder à ces données en utilisant [chaospy](https://github.com/dr-0x0x/chaospy) ou même accéder au scope utilisé par ce projet [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous pouvez trouver une **comparaison** de nombreux de ces outils ici : [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux **sous-domaines** en brute-forçant des serveurs DNS à l’aide de noms de sous-domaines possibles.

Pour cette action, vous aurez besoin de **listes de mots courants pour les sous-domaines comme** :

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Et aussi des IP de bons résolveurs DNS. Afin de générer une liste de résolveurs DNS de confiance, vous pouvez télécharger les résolveurs depuis [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Ou vous pouvez utiliser : [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour le brute-force DNS sont :

- [**massdns**](https://github.com/blechschmidt/massdns) : C’était le premier outil à effectuer un brute-force DNS efficace. Il est très rapide, cependant il est sujet aux faux positifs.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Celui-ci, je pense, n’utilise qu’un seul resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est un wrapper autour de `massdns`, écrit en go, qui permet d’énumérer des sous-domaines valides en utilisant le bruteforce actif, ainsi que de résoudre des sous-domaines avec la gestion des wildcards et une prise en charge simple des entrées-sorties.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Il utilise aussi `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour brute force des noms de domaine de manière asynchrone.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Deuxième round de brute-force DNS

Après avoir trouvé des sous-domaines en utilisant des sources ouvertes et du brute-forcing, vous pourriez générer des variantes des sous-domaines trouvés afin d’essayer d’en découvrir encore plus. Plusieurs outils sont utiles à cette fin :

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** À partir des domaines et sous-domaines, génère des permutations.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): À partir des domaines et sous-domaines, génère des permutations.
- Vous pouvez obtenir la **wordlist** des permutations de goaltdns [**ici**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** À partir des domaines et sous-domaines, génère des permutations. Si aucun fichier de permutations n’est indiqué, gotator utilisera le sien.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): En plus de générer des permutations de sous-domaines, il peut aussi essayer de les résoudre (mais il vaut mieux utiliser les outils commentés précédemment).
- Vous pouvez obtenir la **wordlist** des permutations d'altdns **wordlist** [**ici**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Un autre outil pour effectuer des permutations, mutations et modifications de sous-domaines. Cet outil fera du brute force sur le résultat (il ne supporte pas le wildcard DNS).
- Vous pouvez obtenir la wordlist des permutations de dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basé sur un domaine, il **génère de nouveaux noms de sous-domaines potentiels** à partir de motifs indiqués pour essayer de découvrir plus de sous-domaines.

#### Génération intelligente de permutations

- [**regulator**](https://github.com/cramppet/regulator): Pour plus d'informations, lis ce [**post**](https://cramppet.github.io/regulator/index.html) mais, en gros, il récupère les **parties principales** des **sous-domaines découverts** et les mélange pour en trouver d'autres.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ est un fuzzeur de brute-force de sous-domaines couplé à un algorithme guidé par les réponses DNS extrêmement simple mais efficace. Il utilise un ensemble de données d’entrée fourni, comme une wordlist adaptée ou des enregistrements DNS/TLS historiques, pour synthétiser avec précision davantage de noms de domaine correspondants et les étendre encore plus dans une boucle, en se basant sur les informations recueillies pendant le scan DNS.
```
echo www | subzuf facebook.com
```
### **Workflow de découverte de sous-domaines**

Consultez cet article de blog que j’ai écrit sur la manière d’**automatiser la découverte de sous-domaines** d’un domaine à l’aide de **Trickest workflows**, afin de ne pas avoir à lancer manuellement une série d’outils sur mon ordinateur :


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Si vous avez trouvé une adresse IP contenant **une ou plusieurs pages web** appartenant à des sous-domaines, vous pouvez essayer de **trouver d’autres sous-domaines avec des webs sur cette IP** en cherchant dans des **sources OSINT** des domaines associés à une IP, ou en **brute-forçant les noms de domaine VHost sur cette IP**.

#### OSINT

Vous pouvez trouver certains **VHosts dans des IPs en utilisant** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou d’autres APIs**.

**Brute Force**

Si vous pensez qu’un sous-domaine peut être caché dans un web server, vous pouvez essayer de le brute force :

Lorsque l’**IP redirige vers un hostname** (name-based vhosts), fuzz directement l’en-tête `Host` et laissez ffuf **auto-calibrer** pour mettre en évidence les réponses qui diffèrent du vhost par défaut :
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

Pendant la recherche de **subdomains**, garde un œil pour voir s’ils **pointent** vers un type de **bucket**, et dans ce cas [**vérifie les permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
De plus, à ce stade tu connaîtras tous les domaines dans le périmètre, essaie de [**brute force les noms possibles de buckets et vérifie les permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Tu peux **monitor** si de **nouveaux subdomains** d’un domaine sont créés en surveillant les logs de **Certificate Transparency** ; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)le fait.

### **Looking for vulnerabilities**

Vérifie les possibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **subdomain** pointe vers un **bucket S3**, [**vérifie les permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si tu trouves un **subdomain avec une IP différente** de celles que tu as déjà trouvées lors de la découverte des assets, tu devrais lancer un **scan de vulnérabilités basique** (avec Nessus ou OpenVAS) et un **port scan** [**(using nmap/masscan/shodan)**](../pentesting-network/index.html#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services en cours d’exécution, tu peux trouver dans **ce livre des astuces pour les "attaquer"**.\
_Remarque : parfois le subdomain est hébergé sur une IP qui n’est pas contrôlée par le client, donc elle n’est pas dans le scope, fais attention._

## IPs

Dans les étapes initiales, tu as peut-être **trouvé des plages d’IP, des domaines et des subdomains**.\
Il est temps de **rassembler toutes les IP de ces plages** et, pour les **domains/subdomains (requêtes DNS).**

En utilisant les services des **apis gratuites** suivantes, tu peux aussi trouver les **anciennes IP utilisées par les domains et subdomains**. Ces IP peuvent encore appartenir au client (et peuvent te permettre de trouver des [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Tu peux aussi vérifier les domaines qui pointent vers une adresse IP spécifique à l’aide de l’outil [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Scanne tous les ports de toutes les IP qui n’appartiennent pas aux CDN** (car tu n’y trouveras très probablement rien d’intéressant). Dans les services en cours d’exécution découverts, tu pourrais être **en mesure de trouver des vulnérabilités**.

**Trouve un** [**guide**](../pentesting-network/index.html) **sur la façon de scanner des hosts.**

## Web servers hunting

> Nous avons trouvé toutes les entreprises et leurs assets et nous connaissons les plages d’IP, domaines et subdomains dans le scope. Il est temps de rechercher des web servers.

Dans les étapes précédentes, tu as probablement déjà effectué une partie du **recon des IP et des domains découverts**, donc tu as peut-être **déjà trouvé tous les web servers possibles**. Cependant, si ce n’est pas le cas, nous allons maintenant voir quelques **astuces rapides pour rechercher des web servers** dans le scope.

Veuillez noter que cela sera **orienté vers la découverte d’applications web**, donc tu dois aussi **effectuer le scan de vulnérabilités** et le **port scanning** (**si autorisé** par le scope).

Une **méthode rapide** pour découvrir les **ports ouverts** liés aux serveurs **web** en utilisant [**masscan** peut être trouvée ici](../pentesting-network/index.html#http-port-discovery).\
Un autre outil pratique pour rechercher des web servers est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Il suffit de lui passer une liste de domaines et il essaiera de se connecter au port 80 (http) et 443 (https). De plus, tu peux indiquer d’essayer d’autres ports :
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Maintenant que vous avez découvert **tous les serveurs web** présents dans le scope (parmi les **IP** de l’entreprise et tous les **domains** et **subdomains**), vous **ne savez probablement pas par où commencer**. Alors, simplifions et commençons par prendre des screenshots de tous. Rien qu’en **regardant** la **page principale**, vous pouvez trouver des endpoints **bizarres** qui sont plus **susceptibles** d’être **vulnérables**.

Pour mettre en œuvre l’idée proposée, vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

De plus, vous pourriez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) pour parcourir tous les **screenshots** et vous dire **ce qui est susceptible de contenir des vulnerabilities**, et ce qui n’en contient pas.

## Public Cloud Assets

Afin de trouver des cloud assets potentiels appartenant à une entreprise, vous devriez **commencer par une liste de mots-clés qui identifient cette entreprise**. Par exemple, pour une crypto company, vous pourriez utiliser des mots tels que : `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Vous aurez également besoin de wordlists de **mots courants utilisés dans les buckets** :

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, avec ces mots, vous devriez générer des **permutations** (consultez la [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) pour plus d’infos).

Avec les wordlists obtenues, vous pourriez utiliser des outils tels que [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Rappelez-vous que lorsque vous cherchez des Cloud Assets, vous devriez c**hercher plus que de simples buckets dans AWS**.

### **Looking for vulnerabilities**

Si vous trouvez des choses comme des **buckets ouverts ou des fonctions cloud exposées**, vous devriez **y accéder** et essayer de voir ce qu’elles vous offrent et si vous pouvez les abuser.

## Emails

Avec les **domains** et **subdomains** dans le scope, vous avez en gros tout ce qu’il **faut pour commencer à chercher des emails**. Voici les **APIs** et **tools** qui ont le mieux fonctionné pour moi pour trouver les emails d’une entreprise :

- [**theHarvester**](https://github.com/laramies/theHarvester) - avec des APIs
- API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
- API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
- API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Looking for vulnerabilities**

Les emails seront utiles plus tard pour **brute-force des web logins et des auth services** (comme SSH). Ils sont aussi nécessaires pour les **phishings**. De plus, ces APIs vous donneront encore plus d’**infos sur la personne** derrière l’email, ce qui est utile pour la campagne de phishing.

## Credential Leaks

Avec les **domains,** **subdomains**, et **emails**, vous pouvez commencer à chercher des credentials leakés dans le passé appartenant à ces emails :

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Si vous trouvez des credentials **valid leaked**, c’est une victoire très facile.

## Secrets Leaks

Les credential leaks sont liés à des hacks d’entreprises où des **informations sensibles ont été leakées et vendues**. Cependant, les entreprises peuvent être affectées par **d’autres leaks** dont les infos ne sont pas dans ces bases de données :

### Github Leaks

Des credentials et des APIs peuvent être leakés dans les **public repositories** de l’**entreprise** ou des **users** travaillant pour cette entreprise github.\
Vous pouvez utiliser l’**outil** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **public repos** d’une **organization** et de ses **developers** et lancer [**gitleaks**](https://github.com/zricethezav/gitleaks) dessus automatiquement.

**Leakos** peut aussi être utilisé pour lancer **gitleaks** sur tous les **text** **URLs passées** en entrée, car parfois les **web pages** contiennent aussi des secrets.

#### Github Dorks

Consultez aussi cette **page** pour des **github dorks** potentiels que vous pourriez aussi rechercher dans l’organisation que vous attaquez :


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Parfois, des attaquants ou simplement des employés vont **publier du contenu d’entreprise sur un site de paste**. Cela peut contenir ou non des **informations sensibles**, mais c’est très intéressant d’en faire la recherche.\
Vous pouvez utiliser l’outil [**Pastos**](https://github.com/carlospolop/Pastos) pour chercher simultanément dans plus de 80 paste sites.

### Google Dorks

Les vieux mais bons google dorks sont toujours utiles pour trouver des **informations exposées qui ne devraient pas être là**. Le seul problème est que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas exécuter manuellement. Vous pouvez donc prendre vos 10 préférées ou utiliser un **outil tel que** [**Gorks**](https://github.com/carlospolop/Gorks) **pour toutes les exécuter**.

_Notez que les outils qui s’attendent à exécuter toute la base de données via le navigateur Google normal ne termineront jamais, car Google vous bloquera très, très vite._

### **Looking for vulnerabilities**

Si vous trouvez des credentials ou des API tokens **valid leaked**, c’est une victoire très facile.

## Public Code Vulnerabilities

Si vous avez trouvé que l’entreprise a du **code open-source**, vous pouvez l’**analyser** et y chercher des **vulnerabilities**.

**Selon le langage**, il existe différents **tools** que vous pouvez utiliser :


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Il existe aussi des services gratuits qui permettent de **scanner des public repositories**, tels que :

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **majorité des vulnerabilities** trouvées par les bug hunters se trouvent dans les **web applications**, donc à ce stade je voudrais parler d’une **méthodologie de test des web applications**, et vous pouvez [**trouver ces informations ici**](../../network-services-pentesting/pentesting-web/index.html).

Je veux aussi faire une mention spéciale à la section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), car, même si vous ne devriez pas vous attendre à ce qu’ils trouvent des vulnerabilities très sensibles, ils sont utiles pour les intégrer dans des **workflows afin d’obtenir quelques informations web initiales.**

## Recapitulation

> Félicitations ! À ce stade, vous avez déjà effectué **toute l’énumération de base**. Oui, c’est basique, car beaucoup plus d’énumération peut être faite (nous verrons plus d’astuces plus tard).

Donc vous avez déjà :

1. Trouvé toutes les **companies** dans le scope
2. Trouvé tous les **assets** appartenant aux companies (et effectué un scan de vuln si dans le scope)
3. Trouvé tous les **domains** appartenant aux companies
4. Trouvé tous les **subdomains** des domains (subdomain takeover possible ?)
5. Trouvé toutes les **IPs** (provenant et **ne provenant pas de CDNs**) dans le scope.
6. Trouvé tous les **web servers** et pris un **screenshot** de chacun (quelque chose de bizarre qui mérite un examen plus approfondi ?)
7. Trouvé tous les **potential public cloud assets** appartenant à l’entreprise.
8. **Emails**, **credentials leaks**, et **secret leaks** qui pourraient vous donner un **gros gain très facilement**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Il existe plusieurs outils qui effectueront une partie des actions proposées sur un scope donné.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et non mis à jour

## **References**

- Tous les cours gratuits de [**@Jhaddix**](https://twitter.com/Jhaddix) comme [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
