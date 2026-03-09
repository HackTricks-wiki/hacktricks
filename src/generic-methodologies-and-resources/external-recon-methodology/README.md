# Metodología de External Recon

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de activos

> Entonces te dijeron que todo lo perteneciente a una compañía está dentro del scope, y quieres averiguar qué posee realmente esa compañía.

El objetivo de esta fase es obtener todas las **empresas propiedad de la compañía principal** y luego todos los **activos** de estas empresas. Para ello, vamos a:

1. Encontrar las adquisiciones de la compañía principal, esto nos dará las empresas dentro del scope.
2. Encontrar el ASN (si lo hay) de cada empresa, esto nos dará los rangos de IP propiedad de cada empresa
3. Usar búsquedas reverse whois para buscar otras entradas (nombres de organización, dominios...) relacionadas con la primera (esto puede hacerse de forma recursiva)
4. Usar otras técnicas como shodan `org`and `ssl`filters para buscar otros assets (el truco de `ssl` puede hacerse de forma recursiva).

### **Adquisiciones**

Antes que nada, necesitamos saber qué **otras empresas son propiedad de la compañía principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **compañía principal**, y **hacer clic** en "**adquisiciones**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la compañía principal y buscar **adquisiciones**.\
Para empresas públicas, revisa los **filings SEC/EDGAR**, las páginas de **relaciones con inversores**, o los registros corporativos locales (p. ej., **Companies House** en el Reino Unido).\
Para árboles corporativos globales y subsidiarias, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, en este punto deberías conocer todas las empresas dentro del scope. Veamos cómo encontrar sus activos.

### **ASNs**

Un autonomous system number (**ASN**) es un **número único** asignado a un **autonomous system** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consiste en **bloques** de **direcciones IP** que tienen una política claramente definida para el acceso a redes externas y son administrados por una sola organización pero pueden estar compuestos por varios operadores.

Es interesante averiguar si la **compañía ha asignado algún ASN** para encontrar sus **rangos de IP.** Será interesante realizar una **prueba de vulnerabilidad** contra todos los **hosts** dentro del **scope** y **buscar dominios** dentro de estas IPs.\
Puedes **buscar** por **nombre** de compañía, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependiendo de la región de la compañía estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todas formas, probablemente toda la** información útil **(rangos de IP y Whois)** ya aparece en el primer enlace.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Además, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeración agrega y resume automáticamente los ASN al final del escaneo.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Buscando vulnerabilidades**

En este punto sabemos **todos los activos dentro del alcance**, así que si tienes permiso podrías lanzar algún **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sobre todos los hosts.\
También podrías lanzar algunos [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys, o ZoomEye **para encontrar** open ports **y dependiendo de lo que encuentres deberías** consultar en este libro cómo pentestear varios posibles servicios en ejecución.\
**Además, podría valer la pena mencionar que también puedes preparar algunas** default username **and** passwords **lists and try to** bruteforce servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Sabemos todas las empresas dentro del alcance y sus activos, es hora de encontrar los dominios dentro del alcance.

_Por favor, ten en cuenta que en las técnicas propuestas a continuación también puedes encontrar subdominios y esa información no debe subestimarse._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador tiene que habilitar manualmente el PTR.\
También puedes usar una herramienta online para esta info: [http://ptrarchive.com/](http://ptrarchive.com).\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar reverse lookups y enriquecimiento.

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
Puedes usar herramientas online como:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Gratis** web, API de pago.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **De pago**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **De pago** (solo **100 búsquedas gratis**)
- [https://www.domainiq.com/](https://www.domainiq.com) - **De pago**
- [https://securitytrails.com/](https://securitytrails.com/) - **De pago** (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **De pago** (API)

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Nota: puedes usar esta técnica para descubrir más domain names cada vez que encuentres un nuevo dominio.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.

Hay algunas páginas y herramientas que permiten buscar por estos trackers y más:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (encuentra sitios relacionados por analytics/trackers compartidos)

### **Favicon**

Did you know that we can find related domains and subdomains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubre dominios con el mismo hash del favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permitirá descubrir dominios que tengan el mismo hash del favicon que nuestro objetivo.

Además, también puedes buscar tecnologías usando el hash del favicon como se explica en [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Eso significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web** puedes buscarlo en shodan y **encontrar más lugares vulnerables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Así es como puedes **calcular el favicon hash** de un sitio web:
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
También puedes obtener favicon hashes a gran escala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) y luego pivot en Shodan/Censys.

### **Copyright / Cadena única**

Busca dentro de las páginas web **cadenas que podrían compartirse entre diferentes sitios de la misma organización**. La **cadena de copyright** podría ser un buen ejemplo. Luego busca esa cadena en **google**, en otros **browsers** o incluso en **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es común tener un cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
para renovar todos los certificados de dominio en el servidor. Esto significa que, incluso si la CA usada para esto no establece la hora en que se generó en el Validity time, es posible **encontrar dominios pertenecientes a la misma empresa en los certificate transparency logs**.\
Revisa este [**artículo con más información**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

También usa los logs de **certificate transparency** directamente:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Información DMARC de correo

Puedes usar un sitio web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información dmarc**.\
Otras herramientas útiles son [**spoofcheck**](https://github.com/BishopFox/spoofcheck) y [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Aparentemente es común que la gente asigne subdominios a IPs que pertenecen a proveedores cloud y en algún momento **pierdan esa dirección IP pero se olviden de eliminar el registro DNS**. Por lo tanto, simplemente **spawning a VM** en un cloud (como Digital Ocean) en realidad estarás **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explica una historia al respecto y propone un script que **spawns a VM in DigitalOcean**, **gets** la **IPv4** de la nueva máquina, y **searches in Virustotal for subdomain records** que apuntan a ella.

### **Otras formas**

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un dominio nuevo.**

**Shodan**

Como ya conoces el nombre de la organización propietaria del espacio de IPs, puedes buscar esa información en shodan usando: `org:"Tesla, Inc."` Revisa los hosts encontrados por dominios nuevos e inesperados en el TLS certificate.

Podrías acceder al **TLS certificate** de la página web principal, obtener el **Organisation name** y luego buscar ese nombre dentro de los **TLS certificates** de todas las páginas web conocidas por **shodan** con el filtro: `ssl:"Tesla Motors"` o usar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) es una herramienta que busca **dominios relacionados** con un dominio principal y sus **subdominios**, bastante impresionante.

**Passive DNS / Historical DNS**

Los datos de Passive DNS son excelentes para encontrar **registros antiguos y olvidados** que aún resuelven o que pueden ser tomados. Mira:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Revisa por algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Quizás alguna empresa está **usando algún dominio** pero **perdió la propiedad**. Simplemente regístralo (si es barato) y avisa a la empresa.

Si encuentras algún **domain with an IP different** de las que ya encontraste en el descubrimiento de assets, deberías realizar un **basic vulnerability scan** (usando Nessus u OpenVAS) y algún [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén corriendo, puedes encontrar en **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdominios

> Sabemos todas las empresas dentro del scope, todos los assets de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios

### **DNS**

Intentemos obtener **subdomains** desde los registros de **DNS**. También deberíamos intentar un **Zone Transfer** (si es vulnerable, deberías reportarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **herramientas** más usadas son las siguientes (para mejores resultados, configura las API keys):

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

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**API gratuita de JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl para cualquier dominio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Rastrean la web buscando archivos JS y extraen subdominios desde allí.
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
- [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdomains e historial de IPs
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este proyecto ofrece de **forma gratuita todos los subdomains relacionados con bug-bounty programs**. También puedes acceder a estos datos usando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al scope usado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Intentemos encontrar nuevos **subdomains** brute-forcing servidores DNS usando posibles nombres de subdomain.

Para esta acción necesitarás algunas **wordlists comunes de subdomains como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos DNS resolvers. Para generar una lista de resolvers DNS de confianza puedes descargar los resolvers desde [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para DNS brute-force son:

- [**massdns**](https://github.com/blechschmidt/massdns): Fue la primera herramienta que realizó un DNS brute-force efectivo. Es muy rápida; sin embargo, es propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Creo que este solo usa 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper alrededor de `massdns`, escrito en go, que te permite enumerar subdominios válidos usando active bruteforce, además de resolver subdominios con manejo de wildcard y soporte sencillo de input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): También usa `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para brute force nombres de dominio de forma asíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda ronda de DNS Brute-Force

Después de haber encontrado subdomains usando fuentes públicas y brute-forcing, podrías generar alteraciones de los subdomains encontrados para intentar encontrar aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Toma domains y subdomains y genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dado los domains y subdomains, genera permutaciones.
- Puedes obtener la wordlist de permutaciones de goaltdns en [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dados los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará el suyo.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdomains, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
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
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos nombres potenciales de subdomains** basados en los patrones indicados para intentar descubrir más subdomains.

#### Generación inteligente de permutaciones

- [**regulator**](https://github.com/cramppet/regulator): Para más info lee este [**post**](https://cramppet.github.io/regulator/index.html) pero básicamente obtendrá las **partes principales** de las **discovered subdomains** y las mezclará para encontrar más subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un subdomain brute-force fuzzer acoplado con un algoritmo guiado por las respuestas DNS inmensamente simple pero efectivo. Utiliza un conjunto de datos de entrada proporcionado, como una wordlist personalizada o registros históricos DNS/TLS, para sintetizar con precisión más domain names correspondientes y expandirlos aún más en un bucle basado en la información recopilada durante un DNS scan.
```
echo www | subzuf facebook.com
```
### **Flujo de trabajo de descubrimiento de subdominios**

Consulta este post del blog que escribí sobre cómo **automatizar el descubrimiento de subdominios** desde un dominio usando **Trickest workflows** para no tener que lanzar manualmente un montón de herramientas en mi equipo:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Si encontraste una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios con webs en esa IP** buscando en **OSINT sources** dominios en una IP o realizando **brute-forcing VHost domain names in that IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **o otras APIs**.

**Brute Force**

Si sospechas que algún subdominio puede estar oculto en un servidor web podrías intentar brute forcearlo:

Cuando la **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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
> Con esta técnica incluso podrías acceder a endpoints internos/ocultos.

### **CORS Brute Force**

A veces encontrarás páginas que solo devuelven el header _**Access-Control-Allow-Origin**_ cuando se establece un domain/subdomain válido en el header _**Origin**_. En estos escenarios, puedes abusar de este comportamiento para **descubrir** nuevos **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mientras buscas **subdomains** fíjate si está **pointing** a algún tipo de **bucket**, y en ese caso [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, dado que en este punto conocerás todos los dominios dentro del alcance, intenta [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorización**

Puedes **monitor** si se crean **new subdomains** de un dominio monitorizando los **Certificate Transparency** Logs como lo hace [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Comprueba posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdomain** está **pointing** a algún **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras cualquier **subdomain with an IP different** de las que ya encontraste en el descubrimiento de assets, deberías realizar un **basic vulnerability scan** (using Nessus or OpenVAS) y algún [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén corriendo puedes encontrar en **this book some tricks to "attack" them**.\
_Ten en cuenta que a veces el subdomain está alojado en una IP que no controla el cliente, por lo que no está dentro del alcance, ten cuidado._

## IPs

En los pasos iniciales puedes haber **found some IP ranges, domains and subdomains**.\
Es hora de **recollect all the IPs from those ranges** y de los **domains/subdomains (DNS queries).**

Usando servicios de las siguientes **free apis** también puedes encontrar **previous IPs used by domains and subdomains**. Estas IPs podrían seguir perteneciendo al cliente (y podrían permitirte encontrar [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes comprobar qué dominios apuntan a una IP específica usando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Búsqueda de vulnerabilidades**

**Port scan all the IPs that doesn’t belong to CDNs** (ya que probablemente no encontrarás nada interesante allí). En los servicios en ejecución que descubras podrías **able to find vulnerabilities**.

**Encuentra una** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Búsqueda de servidores web

> Hemos encontrado todas las compañías y sus assets y conocemos rangos de IP, dominios y subdomains dentro del alcance. Es hora de buscar servidores web.

En los pasos previos probablemente ya realizaste algo de **recon of the IPs and domains discovered**, por lo que puede que ya hayas **already found all the possible web servers**. Sin embargo, si no lo has hecho, ahora vamos a ver algunos **fast tricks to search for web servers** dentro del alcance.

Por favor, ten en cuenta que esto estará **oriented for web apps discovery**, así que deberías **perform the vulnerability** y **port scanning** también (**si está permitido** por el alcance).

Un **fast method** para descubrir **ports open** relacionadas con **web** servers usando [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta amigable para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Simplemente pasas una lista de dominios y tratará de conectarse al puerto 80 (http) y 443 (https). Adicionalmente, puedes indicar que pruebe otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** presentes en el scope (entre las **IPs** de la compañía y todos los **dominios** y **subdominios**) probablemente **no sepas por dónde empezar**. Así que, pongámoslo simple y empecemos simplemente tomando capturas de pantalla de todos ellos. Con solo **echar un vistazo** a la **página principal** puedes encontrar endpoints **raros** que son más **propensos** a ser **vulnerables**.

Para realizar la idea propuesta puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, podrías luego usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para procesar todas las **screenshots** y decirte **qué es probable que contenga vulnerabilidades**, y qué no.

## Activos públicos en la nube

Para encontrar posibles activos en la nube pertenecientes a una compañía deberías **empezar con una lista de keywords que identifiquen a esa compañía**. Por ejemplo, para una compañía crypto podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás listas de palabras de **palabras comunes usadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras deberías generar **permutaciones** (revisa el [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para más info).

Con las wordlists resultantes podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que al buscar activos en la nube deberías **buscar más que solo buckets en AWS**.

### **Buscando vulnerabilidades**

Si encuentras cosas como **buckets abiertos o cloud functions expuestas** deberías **acceder a ellas** e intentar ver qué te ofrecen y si puedes abusarlas.

## Correos electrónicos

Con los **dominios** y **subdominios** dentro del scope básicamente tienes todo lo que **necesitas para empezar a buscar correos electrónicos**. Estas son las **APIs** y **herramientas** que me han funcionado mejor para encontrar emails de una compañía:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Buscando vulnerabilidades**

Los emails serán útiles más adelante para **brute-force de inicios de sesión web y servicios auth** (como SSH). Además, son necesarios para los **phishings**. Asimismo, estas APIs te darán aún más **info sobre la persona** detrás del email, lo cual es útil para la campaña de phishing.

## Credential Leaks

Con los **dominios,** **subdominios**, y **emails** puedes empezar a buscar credenciales que se hayan leak en el pasado pertenecientes a esos emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Buscando vulnerabilidades**

Si encuentras **credenciales leak válidas**, esto es una victoria muy fácil.

## Secrets Leaks

Credential leaks están relacionados con hackeos de compañías donde se filtró y vendió información **sensible**. Sin embargo, las compañías podrían estar afectadas por **otros leaks** cuya info no esté en esas bases de datos:

### Github Leaks

Credenciales y APIs podrían estar leak en los **repos públicos** de la **compañía** o de los **usuarios** que trabajan para esa compañía de github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repos públicos** de una **organización** y de sus **desarrolladores** y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también puede usarse para ejecutar **gitleaks** contra todas las **URLs de texto** que le pases ya que, a veces, **las páginas web también contienen secrets**.

#### Github Dorks

Revisa también esta **página** para posibles **github dorks** que también podrías buscar en la organización que estás atacando:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

A veces atacantes o simplemente empleados publican **contenido de la compañía en un sitio de paste**. Esto podría o no contener **información sensible**, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 paste sites al mismo tiempo.

### Google Dorks

Los google dorks, aunque antiguos, siempre son útiles para encontrar **información expuesta que no debería estar ahí**. El único problema es que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varias **miles** de queries posibles que no puedes ejecutar manualmente. Así que puedes elegir tus 10 favoritas o usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Toma en cuenta que las herramientas que esperan ejecutar toda la base de datos usando el navegador regular de google nunca terminarán, ya que google te bloqueará muy muy pronto._

### **Buscando vulnerabilidades**

Si encuentras **credenciales leak válidas** o tokens de API, esto es una victoria muy fácil.

## Vulnerabilidades en código público

Si encontraste que la compañía tiene código **open-source** puedes **analizarlo** y buscar **vulnerabilidades** en él.

**Dependiendo del lenguaje** hay diferentes **herramientas** que puedes usar:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

También existen servicios gratuitos que te permiten **escanear repos públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** que encuentran los bug hunters reside dentro de **aplicaciones web**, así que en este punto me gustaría hablar sobre una **metodología de testing de aplicaciones web**, y puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, vienen bien para implementarlas en **workflows** y obtener algo de información web inicial.

## Recapitulación

> ¡Felicidades! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos después).

Así que ya has:

1. Encontrado todas las **compañías** dentro del scope
2. Encontrado todos los **activos** pertenecientes a las compañías (y realizado algún scan de vuln si está en scope)
3. Encontrado todos los **dominios** pertenecientes a las compañías
4. Encontrado todos los **subdominios** de los dominios (¿algún subdomain takeover?)
5. Encontrado todas las **IPs** (de CDN y **no** de CDN) dentro del scope.
6. Encontrado todos los **servidores web** y tomado una **screenshot** de ellos (¿algo raro que merezca una inspección más profunda?)
7. Encontrado todos los **potenciales activos públicos en la nube** pertenecientes a la compañía.
8. **Emails**, **credential leaks**, y **secret leaks** que podrían darte una **gran victoria muy fácilmente**.
9. **Pentesting** de todos los webs que encontraste

## **Full Recon Automatic Tools**

Hay varias herramientas que realizarán parte de las acciones propuestas contra un scope dado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco vieja y no actualizada

## **Referencias**

- Todos los cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
