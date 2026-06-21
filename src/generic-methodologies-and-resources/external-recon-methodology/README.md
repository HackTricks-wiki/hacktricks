# Metodología de External Recon

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de assets

> Así que te dijeron que todo lo perteneciente a alguna empresa está dentro del alcance, y quieres averiguar qué posee realmente esa empresa.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y luego todos los **assets** de estas empresas. Para hacerlo, vamos a:

1. Encontrar las adquisiciones de la empresa principal, esto nos dará las empresas dentro del alcance.
2. Encontrar el ASN (si lo hay) de cada empresa, esto nos dará los rangos de IP pertenecientes a cada empresa
3. Usar reverse whois lookups para buscar otras entradas (nombres de organización, dominios...) relacionadas con la primera (esto se puede hacer de forma recursiva)
4. Usar otras técnicas como los filtros `org` y `ssl` de shodan para buscar otros assets (el truco `ssl` se puede hacer de forma recursiva).

### **Adquisiciones**

Ante todo, necesitamos saber qué **otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal** y hacer **clic** en "**acquisitions**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **acquisitions**.\
Para empresas públicas, revisa los registros de **SEC/EDGAR**, las páginas de **investor relations** o los registros corporativos locales (por ejemplo, **Companies House** en el Reino Unido).\
Para árboles corporativos globales y subsidiarias, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Vale, en este punto ya deberías conocer todas las empresas dentro del alcance. Vamos a ver cómo encontrar sus assets.

### **ASNs**

Un autonomous system number (**ASN**) es un **número único** asignado a un **autonomous system** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste en **bloques** de **direcciones IP** que tienen una política claramente definida para acceder a redes externas y es administrado por una única organización, pero puede estar formado por varios operadores.

Es interesante averiguar si la **empresa tiene asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **vulnerability test** contra todos los **hosts** dentro del **scope** y **buscar dominios** dentro de estas IPs.\
Puedes **buscar** por **nombre** de empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Según la región de la empresa, estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). En cualquier caso, probablemente toda la** información útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
También, la enumeración de [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** agrega y resume automáticamente los ASN al final del escaneo.
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
Puedes encontrar los rangos de IP de una organización también usando [http://asnlookup.com/](http://asnlookup.com) (tiene API gratuita).\
Puedes encontrar la IP y el ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Buscando vulnerabilidades**

En este punto sabemos **todos los activos dentro del scope**, así que si estás autorizado podrías lanzar algún **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sobre todos los hosts.\
Además, podrías lanzar algunos [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys o ZoomEye **para encontrar** open ports **y, dependiendo de lo que encuentres, deberías** echar un vistazo en este libro a cómo hacer pentest de varios posibles servicios en ejecución.\
**También podría ser útil mencionar que puedes preparar algunas** listas de usuario **y** contraseñas **por defecto y probar a** bruteforcear servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Sabemos todas las empresas dentro del scope y sus activos, es hora de encontrar los domains dentro del scope.

_Please, ten en cuenta que en las siguientes técnicas propuestas también puedes encontrar subdomains y que esa información no debería subestimarse._

Lo primero de todo deberías buscar el **main domain**(s) de cada empresa. Por ejemplo, para _Tesla Inc._ va a ser _tesla.com_.

### **Reverse DNS**

Como ya has encontrado todos los rangos de IP de los domains, podrías intentar realizar **reverse dns lookups** sobre esas **IPs para encontrar más domains dentro del scope**. Intenta usar algún servidor dns de la víctima o algún servidor dns conocido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador tiene que habilitar manualmente el PTR.\
También puedes usar una herramienta online para esta información: [http://ptrarchive.com/](http://ptrarchive.com).\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar reverse lookups y enriquecimiento.

### **Reverse Whois (loop)**

Dentro de un **whois** puedes encontrar mucha **información** interesante como **organisation name**, **address**, **emails**, números de teléfono... Pero lo que es aún más interesante es que puedes encontrar **más assets relacionados con la empresa** si haces **reverse whois lookups por cualquiera de esos campos** (por ejemplo, otros registros whois donde aparece el mismo email).\
Puedes usar herramientas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web y API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, no free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Puedes automatizar esta tarea usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
También puedes realizar algo de descubrimiento automático de reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

### **Trackers**

Si encuentras el **mismo ID del mismo tracker** en 2 páginas diferentes, puedes suponer que **ambas páginas** son **gestionadas por el mismo equipo**.\
Por ejemplo, si ves el mismo **Google Analytics ID** o el mismo **Adsense ID** en varias páginas.

Hay algunas páginas y herramientas que te permiten buscar por estos trackers y más:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (encuentra sitios relacionados por analytics/trackers compartidos)

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del icono favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así es como se usa:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Dicho de forma simple, favihash nos permitirá descubrir dominios que tienen el mismo hash del icono favicon que nuestro objetivo.

Además, también puedes buscar tecnologías usando el hash del favicon, como se explica en [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Eso significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web** puedes buscarlo en shodan y **encontrar más sitios vulnerables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Así es como puedes **calcular el favicon hash** de una web:
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
También puedes obtener hashes de favicon a escala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) y luego pivotar en Shodan/Censys.

### **Copyright / Uniq string**

Busca dentro de las páginas web **strings que puedan compartirse entre diferentes webs de la misma organización**. La **copyright string** podría ser un buen ejemplo. Luego busca esa string en **google**, en otros **browsers** o incluso en **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es común tener un cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Información DMARC de correo

Puedes usar un web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información dmarc**.\
Otras herramientas útiles son [**spoofcheck**](https://github.com/BishopFox/spoofcheck) y [**dmarcian**](https://dmarcian.com/).

### **Adquisición pasiva**

Aparentemente es común que la gente asigne subdominios a IPs que pertenecen a proveedores cloud y, en algún momento, **pierda esa dirección IP pero olvide eliminar el registro DNS**. Por lo tanto, solo con **levantar una VM** en un cloud (como Digital Ocean) en realidad estarás **tomando control de algunos subdominios**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica una historia sobre ello y propone un script que **levanta una VM en DigitalOcean**, **obtiene** la **IPv4** de la nueva máquina, y **busca en Virustotal registros de subdominios** que apunten a ella.

### **Otras formas**

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

**Shodan**

Como ya conoces el nombre de la organización que posee el espacio de IPs. Puedes buscar por esos datos en shodan usando: `org:"Tesla, Inc."` Revisa los hosts encontrados en busca de nuevos dominios inesperados en el certificado TLS.

Podrías acceder al **certificado TLS** de la página web principal, obtener el nombre de la **Organisation** y luego buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **shodan** con el filtro : `ssl:"Tesla Motors"` o usar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)es una herramienta que busca **dominios relacionados** con un dominio principal y sus **subdominios**, bastante increíble.

**Passive DNS / Historical DNS**

Los datos de Passive DNS son geniales para encontrar **registros antiguos y olvidados** que todavía resuelven o que pueden ser tomados. Mira:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Buscando vulnerabilidades**

Comprueba si hay algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Quizá alguna empresa esté **usando un dominio** pero **haya perdido la propiedad**. Solo regístralo (si es lo bastante barato) e infórmaselo a la empresa.

Si encuentras algún **dominio con una IP diferente** de las que ya encontraste en el descubrimiento de activos, deberías realizar un **escaneo básico de vulnerabilidades** (usando Nessus u OpenVAS) y un **escaneo de puertos** con **nmap/masscan/shodan**. Dependiendo de qué servicios estén ejecutándose puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Nota que a veces el dominio está alojado dentro de una IP que no está controlada por el cliente, así que no está en el alcance, ten cuidado._

## Subdominios

> Sabemos todas las empresas dentro del alcance, todos los activos de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios

### **DNS**

Intentemos obtener **subdominios** de los registros **DNS**. También deberíamos intentar **Transferencia de Zona** (si es vulnerable, deberías reportarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **tools** más usadas son las siguientes (para mejores resultados configura las API keys):

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
Hay **otras herramientas/APIs interesantes** que, aunque no estén especializadas directamente en encontrar subdomains, podrían ser útiles para encontrar subdomains, como:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdominios
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, the Wayback Machine y Common Crawl para cualquier dominio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hacen scraping de la web buscando archivos JS y extraen subdominios de allí.
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
- [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdominios e historial de IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este proyecto ofrece **gratis todos los subdominios relacionados con programas de bug-bounty**. También puedes acceder a estos datos usando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al scope usado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos a intentar encontrar nuevos **subdominios** haciendo brute-force a servidores DNS usando posibles nombres de subdominios.

Para esta acción necesitarás algunas **wordlists comunes de subdominios como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos resolvedores DNS. Para generar una lista de resolvedores DNS de confianza, puedes descargar los resolvedores desde [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O podrías usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para DNS brute-force son:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó un DNS brute-force efectivo. Es muy rápida, sin embargo es propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este creo que solo usa 1 resolvedor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper alrededor de `massdns`, escrito en go, que permite enumerar subdomains válidos usando active bruteforce, así como resolver subdomains con manejo de wildcard y soporte fácil de input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): También usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para hacer brute force de nombres de dominio de forma asíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda ronda de fuerza bruta de DNS

Después de haber encontrado subdominios usando fuentes abiertas y fuerza bruta, podrías generar alteraciones de los subdominios encontrados para intentar encontrar aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado los dominios y subdominios, genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dados los dominios y subdominios, genera permutaciones.
- Puedes obtener la **wordlist** de permutaciones de **goaltdns** [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dado los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará el suyo propio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Aparte de generar permutaciones de subdominios, también puede intentar resolverlas (pero es mejor usar las herramientas comentadas anteriormente).
- Puedes obtener la **wordlist** de permutaciones de **altdns** [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta hará fuerza bruta sobre el resultado (no soporta wildcard de DNS).
- Puedes obtener la wordlist de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos posibles nombres de subdominios** según patrones indicados para intentar descubrir más subdominios.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Para más información, lee este [**post**](https://cramppet.github.io/regulator/index.html), pero básicamente obtendrá las **partes principales** de los **subdominios descubiertos** y las mezclará para encontrar más subdominios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un subdomain brute-force fuzzer junto con un algoritmo guiado por la respuesta DNS, inmensamente simple pero efectivo. Utiliza un conjunto proporcionado de datos de entrada, como un tailored wordlist o registros históricos DNS/TLS, para sintetizar con precisión más domain names correspondientes y ampliarlos aún más en un loop basado en la información recopilada durante el DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Mira este blog post que escribí sobre cómo **automatizar la discovery de subdomains** desde un domain usando **Trickest workflows** para no tener que lanzar manualmente un montón de tools en mi computer:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Si encontraste una dirección IP que contiene **una o varias web pages** pertenecientes a subdomains, podrías intentar **encontrar otros subdomains con webs en esa IP** buscando en **OSINT sources** dominios en una IP o haciendo **brute-forcing de VHost domain names** en esa IP.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Brute Force**

Si sospechas que algún subdomain puede estar oculto en un web server, podrías intentar hacer brute force:

Cuando la **IP redirige a un hostname** (name-based vhosts), fuzz the `Host` header directamente y deja que ffuf **auto-calibrate** para resaltar respuestas que difieren del default vhost:
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
> Con esta técnica incluso podrías ser capaz de acceder a endpoints internos/ocultos.

### **CORS Brute Force**

A veces encontrarás páginas que solo devuelven el header _**Access-Control-Allow-Origin**_ cuando se establece un dominio/subdominio válido en el header _**Origin**_. En estos escenarios, puedes abusar de este comportamiento para **descubrir** nuevos **subdominios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mientras buscas **subdomains**, fíjate si está **apuntando** a algún tipo de **bucket**, y en ese caso [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, como en este punto ya conocerás todos los domains dentro del scope, intenta [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Puedes **monitor** si se crean **new subdomains** de un domain monitorizando los **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)lo hace.

### **Looking for vulnerabilities**

Comprueba posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdomain** apunta a algún **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras cualquier **subdomain con una IP diferente** a las que ya encontraste en el descubrimiento de assets, deberías realizar un **basic vulnerability scan** (usando Nessus o OpenVAS) y algún [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén ejecutándose, puedes encontrar en **this book some tricks to "attack" them**.\
_Note que a veces el subdomain está alojado dentro de una IP que no está controlada por el cliente, así que no está en el scope, ten cuidado._

## IPs

En los pasos iniciales quizá hayas **encontrado algunos rangos de IP, domains y subdomains**.\
Es hora de **recolectar todas las IPs de esos rangos** y para los **domains/subdomains (DNS queries).**

Usando servicios de las siguientes **free apis** también puedes encontrar **previous IPs used by domains and subdomains**. Estas IPs podrían seguir perteneciendo al cliente (y podrían permitirte encontrar [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes comprobar domains que apunten a una dirección IP específica usando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (ya que probablemente no encontrarás nada interesante ahí). En los servicios en ejecución descubiertos podrías ser **capaz de encontrar vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Hemos encontrado todas las companies y sus assets y conocemos los rangos de IP, domains y subdomains dentro del scope. Es hora de buscar web servers.

En los pasos anteriores probablemente ya hayas realizado algo de **recon de las IPs y domains descubiertos**, así que puede que ya hayas **encontrado todos los posibles web servers**. Sin embargo, si no lo has hecho, ahora vamos a ver algunos **trucos rápidos para buscar web servers** dentro del scope.

Por favor, ten en cuenta que esto estará **orientado a la discovery de web apps**, así que también deberías **perform the vulnerability** y **port scanning** (**si está permitido** por el scope).

Un **método rápido** para descubrir **puertos abiertos** relacionados con servidores **web** usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta útil para buscar web servers es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Solo tienes que pasar una lista de domains y tratará de conectarse al puerto 80 (http) y 443 (https). Además, puedes indicar que pruebe otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **todos los web servers** presentes en el alcance (entre las **IPs** de la empresa y todos los **domains** y **subdomains**) probablemente **no sabes por dónde empezar**. Así que, simplifiquemos y empecemos haciendo capturas de pantalla de todos ellos. Solo con **echar un vistazo** a la **página principal** puedes encontrar **endpoints raros** que tienen más **probabilidad** de ser **vulnerables**.

Para llevar a cabo la idea propuesta puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, luego podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para revisar todas las **screenshots** y decirte **cuáles probablemente contengan vulnerabilidades** y cuáles no.

## Activos de Cloud públicos

Para encontrar posibles activos de cloud pertenecientes a una empresa deberías **empezar con una lista de palabras clave que identifiquen a esa empresa**. Por ejemplo, para una empresa de crypto podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás wordlists de **palabras comunes usadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras deberías generar **permutations** (consulta el [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para más información).

Con las wordlists resultantes podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que, al buscar Cloud Assets, debes b**uscar más que solo buckets en AWS**.

### **Buscando vulnerabilidades**

Si encuentras cosas como **open buckets o cloud functions exposed**, deberías **acceder a ellas** e intentar ver qué te ofrecen y si puedes abusar de ellas.

## Emails

Con los **domains** y **subdomains** dentro del alcance básicamente ya tienes todo lo que **necesitas para empezar a buscar emails**. Estas son las **APIs** y **tools** que mejor me han funcionado para encontrar emails de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Buscando vulnerabilidades**

Los emails serán útiles más adelante para **brute-force web logins and auth services** (como SSH). Además, son necesarios para **phishings**. También, estas APIs te darán aún más **info about the person** detrás del email, lo cual es útil para la campaña de phishing.

## Credential Leaks

Con los **domains,** **subdomains**, y **emails** puedes empezar a buscar credenciales filtradas en el pasado pertenecientes a esos emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Buscando vulnerabilidades**

Si encuentras credenciales **valid leaked**, esto es una victoria muy fácil.

## Secrets Leaks

Los credential leaks están relacionados con hacks de empresas donde **sensitive information was leaked and sold**. Sin embargo, las empresas pueden verse afectadas por **other leaks** cuya info no está en esas bases de datos:

### Github Leaks

Credenciales y APIs podrían haberse filtrado en los **public repositories** de la **company** o de los **users** que trabajan en esa github company.\
Puedes usar la **tool** [**Leakos**](https://github.com/carlospolop/Leakos) para **download** todos los **public repos** de una **organization** y de sus **developers** y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también puede usarse para ejecutar **gitleaks** agains all the **text** provided **URLs passed** to it, ya que a veces las **web pages also contains secrets**.

#### Github Dorks

Consulta también esta **page** para posibles **github dorks** que también podrías buscar en la organización que estás atacando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A veces los atacantes o simplemente trabajadores publican contenido de la empresa en un paste site. Esto puede contener o no **sensitive information**, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 paste sites al mismo tiempo.

### Google Dorks

Los viejos pero valiosos google dorks siempre son útiles para encontrar **exposed information that shouldn't be there**. El único problema es que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de posibles queries que no puedes ejecutar manualmente. Así que puedes quedarte con tus 10 favoritas o puedes usar una **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Buscando vulnerabilidades**

Si encuentras credenciales o tokens de API **valid leaked**, esto es una victoria muy fácil.

## Vulnerabilidades en código público

Si encontraste que la empresa tiene **open-source code** puedes **analizarlo** y buscar **vulnerabilities** en él.

**Depending on the language** hay diferentes **tools** que puedes usar:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

También hay servicios gratuitos que permiten **scan public repositories**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** encontradas por bug hunters reside dentro de **web applications**, así que en este punto me gustaría hablar de una **web application testing methodology**, y puedes [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, son útiles para implementarlos en **workflows to have some initial web information.**

## Recapitulación

> ¡Felicidades! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos después).

Así que ya has:

1. Encontrado todas las **companies** dentro del alcance
2. Encontrado todos los **assets** pertenecientes a las companies (y realizado algún vuln scan si está dentro del alcance)
3. Encontrado todos los **domains** pertenecientes a las companies
4. Encontrado todos los **subdomains** de los domains (¿algún subdomain takeover?)
5. Encontrado todas las **IPs** (from and **not from CDNs**) dentro del alcance.
6. Encontrado todos los **web servers** y hecho una **screenshot** de ellos (¿algo raro que merezca una revisión más profunda?)
7. Encontrado todos los **potential public cloud assets** pertenecientes a la company.
8. **Emails**, **credentials leaks**, y **secret leaks** que podrían darte una **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Hay varias herramientas por ahí que realizarán parte de las acciones propuestas contra un alcance dado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antiguo y sin actualizar

## **References**

- Todos los cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
