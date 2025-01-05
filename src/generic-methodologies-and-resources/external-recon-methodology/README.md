# Metodología de Reconocimiento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de Activos

> Se te ha dicho que todo lo que pertenece a una empresa está dentro del alcance, y quieres averiguar qué posee realmente esta empresa.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y luego todos los **activos** de estas empresas. Para hacerlo, vamos a:

1. Encontrar las adquisiciones de la empresa principal, esto nos dará las empresas dentro del alcance.
2. Encontrar el ASN (si lo hay) de cada empresa, esto nos dará los rangos de IP propiedad de cada empresa.
3. Usar búsquedas de whois inversas para buscar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer de forma recursiva).
4. Usar otras técnicas como filtros `org` y `ssl` de shodan para buscar otros activos (el truco `ssl` se puede hacer de forma recursiva).

### **Adquisiciones**

Primero que nada, necesitamos saber qué **otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal**, y **hacer clic** en "**adquisiciones**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **adquisiciones**.

> Ok, en este punto deberías conocer todas las empresas dentro del alcance. Vamos a averiguar cómo encontrar sus activos.

### **ASNs**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Autoridad de Números Asignados de Internet (IANA)**.\
Un **AS** consiste en **bloques** de **direcciones IP** que tienen una política definida para acceder a redes externas y son administrados por una sola organización, pero pueden estar compuestos por varios operadores.

Es interesante averiguar si la **empresa ha asignado algún ASN** para encontrar sus **rangos de IP.** Será interesante realizar una **prueba de vulnerabilidad** contra todos los **hosts** dentro del **alcance** y **buscar dominios** dentro de estas IPs.\
Puedes **buscar** por el **nombre** de la empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependiendo de la región de la empresa, estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América del Norte),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todos modos, probablemente toda la** información útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Además, la enumeración de subdominios de [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** agrega y resume automáticamente los ASN al final del escaneo.
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
Puedes encontrar la IP y ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Buscando vulnerabilidades**

En este punto conocemos **todos los activos dentro del alcance**, así que si tienes permiso podrías lanzar algún **escáner de vulnerabilidades** (Nessus, OpenVAS) sobre todos los hosts.\
Además, podrías lanzar algunos [**escaneos de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** shodan **para encontrar** puertos abiertos **y dependiendo de lo que encuentres deberías** consultar este libro sobre cómo hacer pentesting a varios servicios posibles en ejecución.\
**Además, podría valer la pena mencionar que también puedes preparar algunas** listas de nombres de usuario **y** contraseñas **por defecto y tratar de** forzar servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del alcance y sus activos, es hora de encontrar los dominios dentro del alcance.

_Por favor, ten en cuenta que en las siguientes técnicas propuestas también puedes encontrar subdominios y esa información no debe ser subestimada._

Primero que nada, deberías buscar el(los) **dominio(s) principal(es)** de cada empresa. Por ejemplo, para _Tesla Inc._ será _tesla.com_.

### **DNS inverso**

Como has encontrado todos los rangos de IP de los dominios, podrías intentar realizar **búsquedas de dns inverso** en esas **IPs para encontrar más dominios dentro del alcance**. Intenta usar algún servidor dns de la víctima o algún servidor dns bien conocido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador tiene que habilitar manualmente el PTR.\
También puedes usar una herramienta en línea para esta información: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Dentro de un **whois** puedes encontrar mucha **información** interesante como **nombre de la organización**, **dirección**, **correos electrónicos**, números de teléfono... Pero lo que es aún más interesante es que puedes encontrar **más activos relacionados con la empresa** si realizas **búsquedas inversas de whois por cualquiera de esos campos** (por ejemplo, otros registros whois donde aparece el mismo correo electrónico).\
Puedes usar herramientas en línea como:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** web, no gratis API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - No gratis
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - No Gratis (solo **100 gratis** búsquedas)
- [https://www.domainiq.com/](https://www.domainiq.com) - No Gratis

Puedes automatizar esta tarea usando [**DomLink** ](https://github.com/vysecurity/DomLink) (requiere una clave API de whoxy).\
También puedes realizar un descubrimiento automático de reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

### **Trackers**

Si encuentras el **mismo ID del mismo tracker** en 2 páginas diferentes, puedes suponer que **ambas páginas** son **gestionadas por el mismo equipo**.\
Por ejemplo, si ves el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que te permiten buscar por estos trackers y más:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash de icono de favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Aquí te explicamos cómo usarla:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubrir dominios con el mismo hash de icono favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Dicho de manera simple, favihash nos permitirá descubrir dominios que tienen el mismo hash de icono favicon que nuestro objetivo.

Además, también puedes buscar tecnologías utilizando el hash de favicon como se explica en [**este artículo del blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Eso significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web** puedes buscar en shodan y **encontrar más lugares vulnerables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Así es como puedes **calcular el hash del favicon** de una web:
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
### **Copyright / Uniq string**

Busca dentro de las páginas web **cadenas que podrían ser compartidas entre diferentes webs en la misma organización**. La **cadena de copyright** podría ser un buen ejemplo. Luego busca esa cadena en **google**, en otros **navegadores** o incluso en **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Es común tener un trabajo cron como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
renovar todos los certificados de dominio en el servidor. Esto significa que incluso si la CA utilizada para esto no establece la hora en que se generó en el tiempo de validez, es posible **encontrar dominios que pertenecen a la misma empresa en los registros de transparencia de certificados**.\
Consulta este [**artículo para más información**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Información de Mail DMARC

Puedes usar una web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información de dmarc**.

### **Toma Pasiva**

Aparentemente es común que las personas asignen subdominios a IPs que pertenecen a proveedores de nube y en algún momento **pierdan esa dirección IP pero se olviden de eliminar el registro DNS**. Por lo tanto, simplemente **creando una VM** en una nube (como Digital Ocean) estarás **tomando el control de algunos subdominios**.

[**Esta publicación**](https://kmsec.uk/blog/passive-takeover/) explica una historia al respecto y propone un script que **crea una VM en DigitalOcean**, **obtiene** la **IPv4** de la nueva máquina y **busca en Virustotal registros de subdominio** que apunten a ella.

### **Otras formas**

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

**Shodan**

Como ya conoces el nombre de la organización que posee el espacio IP. Puedes buscar por esos datos en shodan usando: `org:"Tesla, Inc."` Revisa los hosts encontrados en busca de nuevos dominios inesperados en el certificado TLS.

Podrías acceder al **certificado TLS** de la página web principal, obtener el **nombre de la organización** y luego buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **shodan** con el filtro: `ssl:"Tesla Motors"` o usar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) es una herramienta que busca **dominios relacionados** con un dominio principal y **subdominios** de ellos, bastante impresionante.

### **Buscando vulnerabilidades**

Verifica algún [toma de dominio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Quizás alguna empresa esté **usando un dominio** pero **haya perdido la propiedad**. Simplemente regístralo (si es lo suficientemente barato) y avísale a la empresa.

Si encuentras algún **dominio con una IP diferente** de las que ya encontraste en el descubrimiento de activos, deberías realizar un **escaneo básico de vulnerabilidades** (usando Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén en funcionamiento, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
&#xNAN;_&#x4E;ote que a veces el dominio está alojado dentro de una IP que no está controlada por el cliente, así que no está en el alcance, ten cuidado._

## Subdominios

> Conocemos todas las empresas dentro del alcance, todos los activos de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios.

### **DNS**

Intentemos obtener **subdominios** de los registros **DNS**. También deberíamos intentar una **Transferencia de Zona** (Si es vulnerable, deberías reportarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para mejores resultados, configura las claves de API):

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
Hay **otras herramientas/APIs interesantes** que, aunque no están directamente especializadas en encontrar subdominios, podrían ser útiles para encontrarlos, como:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utiliza la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdominios
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
- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de Open Threat Exchange de AlienVault, la Wayback Machine y Common Crawl para cualquier dominio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **y** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Buscan en la web archivos JS y extraen subdominios de allí.
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

Este proyecto ofrece **gratis todos los subdominios relacionados con programas de recompensas por errores**. También puedes acceder a estos datos usando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al alcance utilizado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Fuerza bruta DNS**

Intentemos encontrar nuevos **subdominios** forzando servidores DNS usando posibles nombres de subdominio.

Para esta acción necesitarás algunas **listas de palabras comunes de subdominios como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos resolutores DNS. Para generar una lista de resolutores DNS de confianza, puedes descargar los resolutores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O podrías usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para fuerza bruta DNS son:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó una fuerza bruta DNS efectiva. Es muy rápida, sin embargo, es propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este creo que solo utiliza 1 resolvedor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un envoltorio alrededor de `massdns`, escrito en go, que te permite enumerar subdominios válidos utilizando un ataque de fuerza bruta activo, así como resolver subdominios con manejo de comodines y soporte fácil de entrada-salida.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): También utiliza `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para forzar nombres de dominio de manera asíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Ronda de Fuerza Bruta DNS

Después de haber encontrado subdominios utilizando fuentes abiertas y fuerza bruta, podrías generar alteraciones de los subdominios encontrados para intentar encontrar aún más. Varios herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dadas las dominios y subdominios, genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dado los dominios y subdominios, genera permutaciones.
- Puedes obtener las permutaciones de goaltdns **wordlist** en [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dado los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará uno propio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Aparte de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
- Puedes obtener la **wordlist** de permutaciones de altdns **aquí** en [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta forzará el resultado (no soporta comodines DNS).
- Puedes obtener la lista de palabras de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos nombres de subdominios potenciales** basados en patrones indicados para intentar descubrir más subdominios.

#### Generación de permutaciones inteligentes

- [**regulator**](https://github.com/cramppet/regulator): Para más información, lee este [**post**](https://cramppet.github.io/regulator/index.html), pero básicamente obtendrá las **partes principales** de los **subdominios descubiertos** y las mezclará para encontrar más subdominios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta para subdominios acoplado con un algoritmo guiado por respuestas DNS que es inmensamente simple pero efectivo. Utiliza un conjunto de datos de entrada proporcionado, como una lista de palabras personalizada o registros DNS/TLS históricos, para sintetizar con precisión más nombres de dominio correspondientes y expandirlos aún más en un bucle basado en la información recopilada durante el escaneo DNS.
```
echo www | subzuf facebook.com
```
### **Flujo de Trabajo de Descubrimiento de Subdominios**

Revisa esta publicación de blog que escribí sobre cómo **automatizar el descubrimiento de subdominios** de un dominio utilizando **Trickest workflows** para no tener que lanzar manualmente un montón de herramientas en mi computadora:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Hosts Virtuales**

Si encontraste una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios con webs en esa IP** buscando en **fuentes OSINT** para dominios en una IP o **forzando nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Fuerza Bruta**

Si sospechas que algún subdominio puede estar oculto en un servidor web, podrías intentar forzarlo:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Con esta técnica, incluso podrías acceder a endpoints internos/ocultos.

### **CORS Brute Force**

A veces encontrarás páginas que solo devuelven el encabezado _**Access-Control-Allow-Origin**_ cuando se establece un dominio/subdominio válido en el encabezado _**Origin**_. En estos escenarios, puedes abusar de este comportamiento para **descubrir** nuevos **subdominios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Fuerza Bruta de Buckets**

Mientras buscas **subdominios**, presta atención a ver si está **apuntando** a algún tipo de **bucket**, y en ese caso [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, como en este punto conocerás todos los dominios dentro del alcance, intenta [**fuerza bruta posibles nombres de buckets y verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorización**

Puedes **monitorear** si se crean **nuevos subdominios** de un dominio monitoreando los **Registros de Transparencia de Certificados** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)lo hace.

### **Buscando vulnerabilidades**

Verifica posibles [**tomas de control de subdominios**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** está apuntando a algún **bucket S3**, [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras algún **subdominio con una IP diferente** de las que ya encontraste en el descubrimiento de activos, deberías realizar un **escaneo básico de vulnerabilidades** (usando Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de qué servicios estén en ejecución, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
&#xNAN;_&#x4E;ote que a veces el subdominio está alojado dentro de una IP que no está controlada por el cliente, así que no está en el alcance, ten cuidado._

## IPs

En los pasos iniciales podrías haber **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recolectar todas las IPs de esos rangos** y para los **dominios/subdominios (consultas DNS).**

Usando servicios de las siguientes **APIs gratuitas** también puedes encontrar **IPs anteriores utilizadas por dominios y subdominios**. Estas IPs podrían seguir siendo propiedad del cliente (y podrían permitirte encontrar [**bypass de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes verificar dominios que apuntan a una dirección IP específica usando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Buscando vulnerabilidades**

**Escanea todos los puertos de las IPs que no pertenecen a CDNs** (ya que probablemente no encontrarás nada interesante allí). En los servicios en ejecución descubiertos podrías **encontrar vulnerabilidades**.

**Encuentra una** [**guía**](../pentesting-network/index.html) **sobre cómo escanear hosts.**

## Caza de servidores web

> Hemos encontrado todas las empresas y sus activos y conocemos rangos de IP, dominios y subdominios dentro del alcance. Es hora de buscar servidores web.

En los pasos anteriores probablemente ya hayas realizado algún **reconocimiento de las IPs y dominios descubiertos**, así que es posible que ya hayas **encontrado todos los posibles servidores web**. Sin embargo, si no lo has hecho, ahora vamos a ver algunos **trucos rápidos para buscar servidores web** dentro del alcance.

Por favor, ten en cuenta que esto estará **orientado a la descubrimiento de aplicaciones web**, así que deberías **realizar el escaneo de vulnerabilidades** y **escaneo de puertos** también (**si está permitido** por el alcance).

Un **método rápido** para descubrir **puertos abiertos** relacionados con **servidores web** usando [**masscan** se puede encontrar aquí](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta amigable para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Solo pasas una lista de dominios y intentará conectarse al puerto 80 (http) y 443 (https). Además, puedes indicar que intente otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** presentes en el alcance (entre las **IPs** de la empresa y todos los **dominios** y **subdominios**) probablemente **no sepas por dónde empezar**. Así que, hagámoslo simple y comencemos tomando capturas de pantalla de todos ellos. Solo con **echar un vistazo** a la **página principal** puedes encontrar **puntos finales extraños** que son más **propensos** a ser **vulnerables**.

Para llevar a cabo la idea propuesta, puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para revisar todas las **capturas de pantalla** y decirte **qué es probable que contenga vulnerabilidades**, y qué no.

## Activos de Nube Pública

Para encontrar activos potenciales en la nube que pertenezcan a una empresa, debes **comenzar con una lista de palabras clave que identifiquen a esa empresa**. Por ejemplo, para una empresa de criptomonedas podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás listas de palabras de **palabras comunes utilizadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras deberías generar **permutaciones** (consulta el [**Segundo Ronda de Fuerza Bruta DNS**](#second-dns-bruteforce-round) para más información).

Con las listas de palabras resultantes, podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que al buscar Activos en la Nube debes **buscar más que solo buckets en AWS**.

### **Buscando vulnerabilidades**

Si encuentras cosas como **buckets abiertos o funciones de nube expuestas**, debes **acceder a ellas** y tratar de ver qué te ofrecen y si puedes abusar de ellas.

## Correos Electrónicos

Con los **dominios** y **subdominios** dentro del alcance, básicamente tienes todo lo que **necesitas para comenzar a buscar correos electrónicos**. Estas son las **APIs** y **herramientas** que mejor me han funcionado para encontrar correos electrónicos de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Buscando vulnerabilidades**

Los correos electrónicos serán útiles más tarde para **fuerza bruta en inicios de sesión web y servicios de autenticación** (como SSH). Además, son necesarios para **phishings**. Además, estas APIs te darán aún más **información sobre la persona** detrás del correo electrónico, lo cual es útil para la campaña de phishing.

## Filtraciones de Credenciales

Con los **dominios,** **subdominios** y **correos electrónicos** puedes comenzar a buscar credenciales filtradas en el pasado que pertenezcan a esos correos electrónicos:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Buscando vulnerabilidades**

Si encuentras credenciales **filtradas válidas**, esto es una victoria muy fácil.

## Filtraciones de Secretos

Las filtraciones de credenciales están relacionadas con hacks de empresas donde **información sensible fue filtrada y vendida**. Sin embargo, las empresas pueden verse afectadas por **otras filtraciones** cuya información no está en esas bases de datos:

### Filtraciones de Github

Las credenciales y APIs pueden haber sido filtradas en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan para esa empresa de github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repos públicos** de una **organización** y de sus **desarrolladores** y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también puede ser utilizado para ejecutar **gitleaks** contra todo el **texto** proporcionado **URLs pasadas** a él, ya que a veces **las páginas web también contienen secretos**.

#### Dorks de Github

Consulta también esta **página** para posibles **dorks de github** que podrías buscar en la organización que estás atacando:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Filtraciones de Pastas

A veces, atacantes o simplemente trabajadores **publicarán contenido de la empresa en un sitio de paste**. Esto puede o no contener **información sensible**, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 sitios de paste al mismo tiempo.

### Dorks de Google

Los viejos pero buenos dorks de google siempre son útiles para encontrar **información expuesta que no debería estar allí**. El único problema es que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de posibles consultas que no puedes ejecutar manualmente. Así que, puedes obtener tus 10 favoritas o podrías usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que esperan ejecutar toda la base de datos usando el navegador regular de Google nunca terminarán, ya que Google te bloqueará muy, muy pronto._

### **Buscando vulnerabilidades**

Si encuentras credenciales o tokens de API **filtrados válidos**, esto es una victoria muy fácil.

## Vulnerabilidades de Código Público

Si descubriste que la empresa tiene **código de código abierto**, puedes **analizarlo** y buscar **vulnerabilidades** en él.

**Dependiendo del lenguaje**, hay diferentes **herramientas** que puedes usar:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

También hay servicios gratuitos que te permiten **escanear repositorios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Metodología de Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** encontradas por cazadores de bugs residen dentro de **aplicaciones web**, así que en este punto me gustaría hablar sobre una **metodología de pruebas de aplicaciones web**, y puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Herramientas de escaneo automático de código abierto**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, si no deberías esperar que encuentren vulnerabilidades muy sensibles, son útiles para implementarlas en **flujos de trabajo para tener alguna información web inicial.**

## Recapitulación

> ¡Felicidades! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos más adelante).

Así que ya has:

1. Encontrado todas las **empresas** dentro del alcance
2. Encontrado todos los **activos** que pertenecen a las empresas (y realizado algún escaneo de vulnerabilidades si está en el alcance)
3. Encontrado todos los **dominios** que pertenecen a las empresas
4. Encontrado todos los **subdominios** de los dominios (¿alguna toma de subdominio?)
5. Encontrado todas las **IPs** (de y **no de CDNs**) dentro del alcance.
6. Encontrado todos los **servidores web** y tomado una **captura de pantalla** de ellos (¿algo extraño que valga la pena investigar más a fondo?)
7. Encontrado todos los **activos potenciales de nube pública** que pertenecen a la empresa.
8. **Correos electrónicos**, **filtraciones de credenciales** y **filtraciones de secretos** que podrían darte una **gran victoria muy fácilmente**.
9. **Pentesting todas las webs que encontraste**

## **Herramientas Automáticas de Reconocimiento Completo**

Hay varias herramientas disponibles que realizarán parte de las acciones propuestas contra un alcance dado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antigua y no actualizada

## **Referencias**

- Todos los cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**La Metodología del Cazador de Bugs v4.0 - Edición Recon**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
