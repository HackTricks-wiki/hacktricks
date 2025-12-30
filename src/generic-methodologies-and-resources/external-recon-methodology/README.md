# Metodología de Reconocimiento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de activos

> Entonces te dijeron que todo lo perteneciente a alguna compañía está dentro del scope, y quieres averiguar qué posee realmente esa compañía.

El objetivo de esta fase es obtener todas las **companies owned by the main company** y luego todos los **assets** de esas compañías. Para ello vamos a:

1. Encontrar las adquisiciones de la compañía principal; esto nos dará las companies inside the scope.
2. Encontrar el ASN (si lo tiene) de cada compañía; esto nos dará los IP ranges owned by each company.
3. Usar reverse whois lookups para buscar otras entradas (organisation names, domains...) relacionadas con la primera (esto puede hacerse de forma recursiva).
4. Usar otras técnicas como shodan `org` and `ssl` filters para buscar otros assets (el `ssl` trick puede hacerse de forma recursiva).

### **Adquisiciones**

Primero que nada, necesitamos saber qué **other companies are owned by the main company**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **search** por la **main company**, y **click** en "**acquisitions**". Allí verás otras compañías adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la compañía principal y buscar **acquisitions**.\
Para compañías públicas, revisa **SEC/EDGAR filings**, las páginas de **investor relations**, o los registros corporativos locales (p. ej., **Companies House** en el Reino Unido).\
Para árboles corporativos globales y subsidiarias, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, en este punto deberías conocer todas las compañías dentro del scope. Vamos a averiguar cómo encontrar sus assets.

### **ASNs**

An autonomous system number (**ASN**) es un **número único** asignado a un **autonomous system** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste en **bloques** de **IP addresses** que tienen una política claramente definida para acceder a redes externas y son administrados por una única organización, aunque pueden estar compuestos por varios operadores.

Conviene averiguar si la **company have assigned any ASN** para encontrar sus **IP ranges.** Será interesante realizar una **vulnerability test** contra todos los **hosts** dentro del **scope** y **buscar dominios** dentro de esas IPs.\
Puedes **search** por el **company name**, por **IP** o por **domain** en [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **u** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependiendo de la región de la compañía estos links podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). De todos modos, probablemente toda la** useful information **(IP ranges and Whois)** ya aparezca en el primer link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Además, la enumeración de [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** agrega y resume automáticamente los ASNs al final del escaneo.
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
Puedes encontrar los rangos de IP de una organización también usando [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
Puedes encontrar la IP y el ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

En este punto conocemos **todos los assets dentro del scope**, así que si tienes permiso podrías lanzar algún **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sobre todos los hosts.\
También podrías lanzar algunos [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys, o ZoomEye **para encontrar** puertos abiertos **y dependiendo de lo que encuentres deberías** consultar en este libro cómo pentestear varios servicios posibles que estén corriendo.\
**Además, puede valer la pena mencionar que también puedes preparar algunas** listas de default username y passwords **y probar a** bruteforce servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del scope y sus assets, es hora de encontrar los dominios dentro del scope.

_Por favor, ten en cuenta que en las siguientes técnicas propuestas también puedes encontrar subdomains y que esa información no debe ser infravalorada._

Antes que nada deberías buscar el **main domain**(s) de cada empresa. Por ejemplo, para _Tesla Inc._ va a ser _tesla.com_.

### **Reverse DNS**

Como ya has encontrado todos los IP ranges de los dominios podrías intentar realizar **reverse dns lookups** sobre esas **IPs para encontrar más dominios dentro del scope**. Intenta usar algún dns server de la víctima o algún dns server conocido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador tiene que habilitar manualmente el PTR.\
También puedes usar una herramienta online para esta información: [http://ptrarchive.com/](http://ptrarchive.com).\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar búsquedas reversas y el enriquecimiento de datos.

### **Reverse Whois (loop)**

Dentro de un **whois** puedes encontrar mucha **información** interesante como **nombre de la organización**, **dirección**, **correos electrónicos**, números de teléfono... Pero aún más interesante es que puedes encontrar **más assets relacionados con la empresa** si realizas **reverse whois lookups por cualquiera de esos campos** (por ejemplo otros registros whois donde aparece el mismo correo).\
Puedes usar herramientas online como:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratis** web, API de pago.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - De pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - De pago (solo **100 gratis** búsquedas)
- [https://www.domainiq.com/](https://www.domainiq.com) - De pago
- [https://securitytrails.com/](https://securitytrails.com/) - De pago (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - De pago (API)

Puedes automatizar esta tarea usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una API key de whoxy).\
También puedes realizar cierto descubrimiento automático de reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

### **Rastreadores**

Si encuentras el mismo ID del mismo rastreador en 2 páginas diferentes puedes suponer que **ambas páginas** son **gestionadas por el mismo equipo**.\
Por ejemplo, si ves el mismo **Google Analytics ID** o el mismo **Adsense ID** en varias páginas.

Hay algunas páginas y herramientas que te permiten buscar por estos trackers y más:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (encuentra sitios relacionados por analytics/trackers compartidos)

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Aquí se muestra cómo usarla:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubrir dominios con el mismo favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permitirá descubrir dominios que tengan el mismo hash del favicon que nuestro objetivo.

Además, también puedes buscar tecnologías usando el favicon hash como se explica en [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Eso significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web** puedes buscarlo en shodan y **encontrar más lugares vulnerables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Así es como puedes **calculate the favicon hash** de un sitio web:
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
También puedes obtener hashes de favicon a gran escala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) y luego pivotar en Shodan/Censys.

### **Copyright / Cadena única**

Busca dentro de las páginas web **cadenas que podrían compartirse entre diferentes webs de la misma organización**. La **cadena de copyright** podría ser un buen ejemplo. Luego busca esa cadena en **google**, en otros **navegadores** o incluso en **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es común tener un cron job such as
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
para renovar todos los certificados de dominio en el servidor. Esto significa que, incluso si la CA usada para esto no establece la hora en que fue generado en el Validity time, es posible **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Información DMARC de correo

Puedes usar un sitio web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información DMARC**.\
Otras herramientas útiles son [**spoofcheck**](https://github.com/BishopFox/spoofcheck) y [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Aparentemente es común que la gente asigne subdominios a IPs que pertenecen a cloud providers y en algún momento **pierdan esa IP pero olviden eliminar el registro DNS**. Por lo tanto, simplemente **spawning a VM** en un cloud (como Digital Ocean) en realidad estarás **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explica una historia al respecto y propone un script que **spawns a VM in DigitalOcean**, **gets** la **IPv4** de la nueva máquina, y **searches in Virustotal for subdomain records** apuntando a ella.

### **Otras formas**

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un dominio nuevo.**

**Shodan**

Como ya conoces el nombre de la organización propietaria del espacio IP, puedes buscar por ese dato en shodan usando: `org:"Tesla, Inc."` Revisa los hosts encontrados por nuevos dominios inesperados en el certificado TLS.

Podrías acceder al **TLS certificate** de la página principal, obtener el **Organisation name** y luego buscar ese nombre dentro de los **TLS certificates** de todas las páginas web conocidas por **shodan** con el filtro: `ssl:"Tesla Motors"` o usar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) es una herramienta que busca **dominios relacionados** con un dominio principal y **sus subdominios**, bastante impresionante.

**Passive DNS / Historical DNS**

Los datos de Passive DNS son excelentes para encontrar **registros antiguos y olvidados** que todavía resuelven o que pueden ser tomados. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Revisa por algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Quizás alguna empresa está usando algún dominio pero perdió la propiedad. Simplemente regístralo (si es lo suficientemente barato) y avisa a la empresa.

Si encuentras algún dominio con una IP distinta de las que ya encontraste en el descubrimiento de assets, deberías realizar un escaneo básico de vulnerabilidades (usando Nessus u OpenVAS) y algunos **port scan** (using nmap/masscan/shodan) y [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén corriendo, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Note que a veces el dominio está alojado en una IP que no es controlada por el cliente, así que no está dentro del scope, ten cuidado._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios

### **DNS**

Intentemos obtener **subdomains** desde los registros **DNS**. También deberíamos intentar un **Zone Transfer** (si es vulnerable, deberías reportarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **tools** más usadas son las siguientes (para mejores resultados, configura las API keys):

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
Hay **otras herramientas/APIs interesantes** que, aunque no estén directamente especializadas en encontrar subdomains, podrían ser útiles para encontrar subdomains, como:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utiliza la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdomains
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
- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, la Wayback Machine y Common Crawl para cualquier dominio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **y** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Rastrean la web buscando archivos JS y extraen subdomains desde ahí.
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
- [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdomains e IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este proyecto ofrece de **forma gratuita todos los subdomains relacionados con bug-bounty programs**. Puedes acceder a estos datos también usando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al scope usado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Intentemos encontrar nuevos **subdomains** haciendo brute-force a DNS servers usando posibles nombres de subdominio.

Para esta acción necesitarás algunas **common subdomains wordlists como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos DNS resolvers. Para generar una lista de DNS resolvers de confianza puedes descargar los resolvers de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para DNS brute-force son:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó un DNS brute-force efectivo. Es muy rápida, sin embargo es propensa a false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Creo que este solo usa 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper alrededor de `massdns`, escrito en go, que te permite enumerar subdominios válidos usando active bruteforce, así como resolver subdominios con wildcard handling y soporte sencillo de entrada/salida.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): También usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar brute force sobre nombres de dominio de forma asíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda ronda de brute-force DNS

Después de haber encontrado subdominios usando fuentes abiertas y brute-forcing, podrías generar alteraciones de los subdominios encontrados para intentar encontrar aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Toma los dominios y subdominios y genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Genera permutaciones a partir de los dominios y subdominios.
- Puedes obtener la **wordlist** de permutaciones de goaltdns en [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Genera permutaciones a partir de dominios y subdominios. Si no se indica un archivo de permutaciones, gotator usará el suyo.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdomains, también puede intentar resolverlas (pero es mejor usar las herramientas comentadas anteriormente).
- Puedes obtener la **wordlist** de permutaciones de altdns en [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta hará brute force del resultado (no soporta dns wild card).
- Puedes obtener la wordlist de permutaciones de dmut en [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos nombres potenciales de subdomains** según patrones indicados para intentar descubrir más subdomains.

#### Generación inteligente de permutaciones

- [**regulator**](https://github.com/cramppet/regulator): Para más info, lee esta [**entrada**](https://cramppet.github.io/regulator/index.html), pero básicamente obtendrá las **partes principales** de los **subdomains descubiertos** y las mezclará para encontrar más subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un subdomain brute-force fuzzer acoplado a un algoritmo DNS response-guided inmensamente simple pero efectivo. Utiliza un conjunto proporcionado de datos de entrada, como una wordlist personalizada o registros históricos DNS/TLS, para sintetizar con precisión más nombres de dominio correspondientes y expandirlos aún más en un bucle basado en la información recopilada durante el escaneo DNS.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Consulta este blog que escribí sobre cómo **automate the subdomain discovery** desde un dominio usando **Trickest workflows** para no tener que lanzar manualmente un montón de herramientas en mi equipo:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Si encuentras una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **find other subdomains with webs in that IP** buscando en **fuentes OSINT** dominios asociados a esa IP o mediante **brute-forcing VHost domain names in that IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Brute Force**

Si sospechas que algún subdominio puede estar oculto en un servidor web, podrías intentar hacer brute force:
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
> Con esta técnica incluso podrías acceder a endpoints internos/ocultos.

### **CORS Brute Force**

A veces encontrarás páginas que solo devuelven la cabecera _**Access-Control-Allow-Origin**_ cuando un dominio/subdomain válido está establecido en la cabecera _**Origin**_. En esos casos, puedes abusar de este comportamiento para **descubrir** nuevos **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mientras buscas **subdomains** estate atento para ver si está **pointing** a algún tipo de **bucket**, y en ese caso [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
También, como en este punto conocerás todos los dominios dentro del scope, intenta [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorización**

Puedes **monitor** si se crean **new subdomains** de un dominio monitorizando los Logs de **Certificate Transparency** como lo hace [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Buscando vulnerabilidades**

Revisa posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdomain** está **pointing** a algún **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras algún **subdomain with an IP different** de los que ya encontraste en el assets discovery, deberías realizar un **basic vulnerability scan** (usando Nessus u OpenVAS) y algunos [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén corriendo, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Nota que a veces el subdomain está alojado en una IP que no es controlada por el cliente, por lo que no está en el scope; ten cuidado._

## IPs

En los pasos iniciales quizá hayas encontrado algunos IP ranges, domains y subdomains.\
Es hora de recopilar todas las IPs de esos ranges y de los domains/subdomains (DNS queries).

Usando servicios de las siguientes **free apis** también puedes encontrar **previous IPs used by domains and subdomains**. Estas IPs podrían seguir siendo propiedad del cliente (y podrían permitirte encontrar [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes comprobar qué domains apuntan a una IP específica usando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Buscando vulnerabilidades**

**Port scan all the IPs that doesn’t belong to CDNs** (ya que muy probablemente no encontrarás nada interesante allí). En los servicios en ejecución que descubras podrías **poder encontrar vulnerabilidades**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Búsqueda de servidores web

> Hemos encontrado todas las empresas y sus assets y conocemos los IP ranges, domains y subdomains dentro del scope. Es hora de buscar servidores web.

En los pasos previos probablemente ya realizaste algo de **recon of the IPs and domains discovered**, por lo que puede que ya hayas **already found all the possible web servers**. Sin embargo, si no lo has hecho vamos a ver algunos **fast tricks to search for web servers** dentro del scope.

Por favor, ten en cuenta que esto estará **oriented for web apps discovery**, así que también deberías **perform the vulnerability** y **port scanning** (**si está permitido** por el scope).

Un **fast method** para descubrir **ports open** relacionados con servidores **web** usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta amigable para buscar web servers es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Simplemente pasas una lista de domains y tratará de conectarse al puerto 80 (http) y 443 (https). Adicionalmente, puedes indicar que pruebe otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **all the web servers** presentes en el scope (entre las **IPs** de la empresa y todos los **domains** y **subdomains**) probablemente **no sepas por dónde empezar**. Así que simplifiquemos: comienza tomando **screenshots** de todos ellos. Con solo **echar un vistazo** a la **main page** puedes encontrar endpoints extraños que son más propensos a ser vulnerables.

Para llevar a cabo esta idea puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para procesar todas las **screenshots** y decirte **qué es probable que contenga vulnerabilidades**, y qué no.

## Activos Cloud Públicos

Para encontrar posibles activos cloud pertenecientes a una empresa deberías **comenzar con una lista de keywords que identifiquen esa empresa**. Por ejemplo, para una empresa crypto podrías usar palabras como: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

También necesitarás wordlists de **palabras comunes usadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras deberías generar **permutations** (revisa [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para más info).

Con las wordlists resultantes podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que cuando busques Cloud Assets deberías buscar más que solo buckets en AWS.

### **Buscando vulnerabilidades**

Si encuentras cosas como **open buckets or cloud functions exposed** deberías acceder a ellas e intentar ver qué te ofrecen y si puedes abusar de ellas.

## Emails

Con los **domains** y **subdomains** dentro del scope básicamente tienes todo lo que necesitas para empezar a buscar **emails**. Estas son las **APIs** y **herramientas** que mejor me han funcionado para encontrar emails de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versión free)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión free)
- API de [**https://minelead.io/**](https://minelead.io/) (versión free)

### **Buscando vulnerabilidades**

Los emails serán útiles más tarde para **brute-force** de logins web y servicios de auth (como **SSH**). También son necesarios para **phishings**. Además, estas APIs te darán más **info sobre la persona** detrás del email, lo cual es útil para la campaña de phishing.

## Credential Leaks

Con los **domains,** **subdomains**, y **emails** puedes empezar a buscar credenciales leaked en el pasado que pertenezcan a esos emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Buscando vulnerabilidades**

Si encuentras credenciales leaked válidas, es una victoria muy sencilla.

## Secrets Leaks

Los credential leaks están relacionados con hacks de empresas donde se filtró y vendió información sensible. Sin embargo, las empresas pueden verse afectadas por otros tipos de leaks cuya info no aparece en esas bases de datos:

### Github Leaks

Credentials y API keys pueden estar leak en los **public repositories** de la **company** o de los **users** que trabajan para esa company.\
Puedes usar la herramienta [**Leakos**](https://github.com/carlospolop/Leakos) para **download** todos los **public repos** de una **organization** y de sus **developers** y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también puede usarse para ejecutar **gitleaks** contra todos los **text** proporcionados en URLs que le pases, ya que a veces las **web pages** también contienen secrets.

#### Github Dorks

Revisa también esta **page** para posibles **github dorks** que podrías buscar en la organización que estás atacando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A veces atacantes o incluso empleados publican contenido de la empresa en un paste site. Esto puede o no contener información sensible, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 paste sites a la vez.

### Google Dorks

Los viejos pero efectivos google dorks siempre son útiles para encontrar **info expuesta que no debería estar ahí**. El problema es que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **thousands** de queries posibles que no puedes ejecutar manualmente. Así que puedes quedarte con tus 10 favoritas o usar una herramienta como [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que intentan ejecutar toda la database usando el navegador regular de Google nunca acabarán porque Google te bloqueará muy, muy pronto._

### **Buscando vulnerabilidades**

Si encuentras credenciales o API tokens leaked válidos, es una victoria muy sencilla.

## Public Code Vulnerabilities

Si descubres que la empresa tiene **open-source code** puedes analizarlo y buscar vulnerabilidades en él.

**Dependiendo del lenguaje** hay diferentes **herramientas** que puedes usar:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

También hay servicios gratuitos que permiten **scan** de repos public, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** encontradas por bug hunters reside dentro de **web applications**, así que en este punto me gustaría hablar de una **web application testing methodology**, y puedes [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

También quiero mencionar especialmente la sección [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, son útiles para integrarlas en **workflows** y obtener información web inicial.

## Recapitulación

> ¡Congratulations! En este punto ya has realizado **all the basic enumeration**. Sí, es básico porque se puede hacer mucha más enumeración (veremos más trucos luego).

Así que ya has:

1. Encontrado todas las **companies** dentro del scope
2. Encontrado todos los **assets** pertenecientes a las companies (y realizado algún vuln scan si está in scope)
3. Encontrado todos los **domains** pertenecientes a las companies
4. Encontrado todos los **subdomains** de los domains (¿algún subdomain takeover?)
5. Encontrado todas las **IPs** (de y **not from CDNs**) dentro del scope.
6. Encontrado todos los **web servers** y tomado una **screenshot** de ellos (¿algo weird que merezca una revisión más profunda?)
7. Encontrado todos los **potential public cloud assets** pertenecientes a la company.
8. **Emails**, **credentials leaks**, y **secret leaks** que podrían darte una **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Hay varias herramientas que realizarán parte de las acciones propuestas contra un scope dado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco viejo y sin actualizar

## **Referencias**

- Todos los cursos free de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
