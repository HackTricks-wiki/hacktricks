# Metodología de Reconocimiento Externo

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) **y** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo imposible - ¡**estamos contratando**! (_se requiere dominio del polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Descubrimiento de Activos

> Te dijeron que todo lo que pertenece a una empresa está dentro del alcance, y quieres averiguar qué posee realmente esta empresa.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y luego todos los **activos** de estas empresas. Para hacerlo, vamos a:

1. Encontrar las adquisiciones de la empresa principal, esto nos dará las empresas dentro del alcance.
2. Encontrar el ASN (si hay alguno) de cada empresa, esto nos dará los rangos de IP propiedad de cada empresa.
3. Utilizar búsquedas de whois inverso para buscar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer de forma recursiva).
4. Utilizar otras técnicas como los filtros `org` y `ssl` de shodan para buscar otros activos (el truco de `ssl` se puede hacer de forma recursiva).

### **Adquisiciones**

En primer lugar, necesitamos saber qué **otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal**, y **hacer clic** en "**adquisiciones**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **adquisiciones**.

> Ok, en este punto deberías conocer todas las empresas dentro del alcance. Veamos cómo encontrar sus activos.

### **ASNs**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Autoridad de Números Asignados de Internet (IANA)**.\
Un **AS** consta de **bloques** de **direcciones IP** que tienen una política claramente definida para acceder a redes externas y son administradas por una sola organización pero pueden estar compuestas por varios operadores.

Es interesante saber si la **empresa ha asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **prueba de vulnerabilidad** contra todos los **hosts** dentro del **alcance** y buscar **dominios** dentro de estas IPs.\
Puedes **buscar** por el **nombre de la empresa**, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependiendo de la región de la empresa, estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América del Norte),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todos modos, probablemente toda la** información útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Además, la enumeración de subdominios de [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrega automáticamente y resume los ASN al final del escaneo.
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
Puedes encontrar los rangos de IP de una organización también usando [http://asnlookup.com/](http://asnlookup.com) (tiene una API gratuita).\
Puedes encontrar la IP y ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Buscando vulnerabilidades**

En este punto conocemos **todos los activos dentro del alcance**, así que si se te permite, podrías lanzar algún **escáner de vulnerabilidades** (Nessus, OpenVAS) sobre todos los hosts.\
También podrías lanzar algunos [**escaneos de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) **o usar servicios como** shodan **para encontrar** puertos abiertos **y dependiendo de lo que encuentres deberías** consultar este libro sobre cómo hacer pentesting en varios servicios posibles que se estén ejecutando.\
**Además, podría valer la pena mencionar que también puedes preparar algunas listas de** nombres de usuario por defecto **y** contraseñas **y tratar de** forzar servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del alcance y sus activos, es hora de encontrar los dominios dentro del alcance.

_Por favor, ten en cuenta que en las técnicas propuestas a continuación también puedes encontrar subdominios y esa información no debería ser subestimada._

En primer lugar, deberías buscar el/los **dominio(s) principal(es)** de cada empresa. Por ejemplo, para _Tesla Inc._ será _tesla.com_.

### **DNS Reverso**

Una vez que hayas encontrado todos los rangos de IP de los dominios, podrías intentar realizar **búsquedas de DNS reverso** en esas **IPs para encontrar más dominios dentro del alcance**. Intenta usar algún servidor DNS de la víctima o algún servidor DNS conocido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador debe habilitar manualmente el PTR.\
También puedes utilizar una herramienta en línea para esta información: [http://ptrarchive.com/](http://ptrarchive.com)

### **Búsqueda inversa de Whois (loop)**

Dentro de un **whois** puedes encontrar mucha **información** interesante como el **nombre de la organización**, **dirección**, **emails**, números de teléfono... Pero lo que es aún más interesante es que puedes encontrar **más activos relacionados con la empresa** si realizas **búsquedas inversas de whois por cualquiera de esos campos** (por ejemplo, otros registros whois donde aparece el mismo email).\
Puedes utilizar herramientas en línea como:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** en la web, no gratis en API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - No gratis
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - No gratis (solo **100 búsquedas gratuitas**)
* [https://www.domainiq.com/](https://www.domainiq.com) - No gratis

Puedes automatizar esta tarea utilizando [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También puedes realizar descubrimiento automático de whois inverso con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes utilizar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

### **Rastreadores**

Si encuentras el **mismo ID del mismo rastreador** en 2 páginas diferentes, puedes suponer que **ambas páginas** son **gestionadas por el mismo equipo**.\
Por ejemplo, si ves el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que te permiten buscar por estos rastreadores y más:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash de icono de favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así es como se usa:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubre dominios con el mismo hash de ícono de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permitirá descubrir dominios que tienen el mismo hash de ícono de favicon que nuestro objetivo.

Además, también puedes buscar tecnologías utilizando el hash de favicon como se explica en [**esta publicación de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Esto significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web**, puedes buscar si está en shodan y **encontrar más lugares vulnerables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Así es como puedes **calcular el hash del favicon** de un sitio web:
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
### **Derechos de autor / Cadena única**

Busca dentro de las páginas web **cadenas que podrían ser compartidas en diferentes sitios web de la misma organización**. La **cadena de derechos de autor** podría ser un buen ejemplo. Luego busca esa cadena en **Google**, en otros **navegadores** o incluso en **Shodan**: `shodan search http.html:"Cadena de derechos de autor"`

### **Tiempo de CRT**

Es común tener una tarea programada como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### Metodología de Reconocimiento Externo

- Renovar todos los certificados de dominio en el servidor. Esto significa que incluso si la CA utilizada para esto no establece la hora en que se generó en el tiempo de validez, es posible **encontrar dominios pertenecientes a la misma empresa en los registros de transparencia de certificados**.\
Echa un vistazo a este [**artículo para más información**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Información DMARC de Correo

Puedes utilizar un sitio web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información dmarc**.

### **Toma de Control Pasiva**

Aparentemente es común que las personas asignen subdominios a IPs que pertenecen a proveedores de nube y en algún momento **pierdan esa dirección IP pero olviden eliminar el registro DNS**. Por lo tanto, simplemente **iniciando una VM** en una nube (como Digital Ocean) realmente **tomarás el control de algunos subdominios**.

Este [**post**](https://kmsec.uk/blog/passive-takeover/) explica una historia al respecto y propone un script que **inicia una VM en DigitalOcean**, **obtiene** la **IPv4** de la nueva máquina y **busca en Virustotal registros de subdominios** que apunten a ella.

### **Otras formas**

**Ten en cuenta que puedes utilizar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio**.

**Shodan**

Como ya conoces el nombre de la organización que posee el espacio IP, puedes buscar esa información en Shodan usando: `org:"Tesla, Inc."`. Revisa los hosts encontrados en busca de nuevos dominios inesperados en el certificado TLS.

Podrías acceder al **certificado TLS** de la página web principal, obtener el **nombre de la organización** y luego buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **Shodan** con el filtro: `ssl:"Tesla Motors"` o utilizar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) es una herramienta que busca **dominios relacionados** con un dominio principal y sus **subdominios**, bastante sorprendente.

### **Búsqueda de Vulnerabilidades**

Busca posibles [tomas de dominio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Tal vez alguna empresa esté **utilizando un dominio** pero **perdió la propiedad**. Simplemente regístralo (si es lo suficientemente barato) y notifica a la empresa.

Si encuentras algún **dominio con una IP diferente** a las que ya encontraste en el descubrimiento de activos, debes realizar un **escaneo de vulnerabilidades básico** (usando Nessus o OpenVAS) y un [**escaneo de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que se estén ejecutando, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el dominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance, ten cuidado._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Consejo de recompensa por errores**: **Regístrate** en **Intigriti**, una plataforma de **recompensas por errores premium creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdominios

> Conocemos todas las empresas dentro del alcance, todos los activos de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

{% hint style="success" %}
¡Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios!
{% endhint %}

### **DNS**

Intentemos obtener **subdominios** de los registros de **DNS**. También deberíamos intentar la **Transferencia de Zona** (si es vulnerable, deberías informarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener una gran cantidad de subdominios es buscar en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para obtener mejores resultados, configure las claves de la API):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Hay **otras herramientas/APIs interesantes** que, aunque no estén directamente especializadas en encontrar subdominios, podrían ser útiles para encontrar subdominios, como:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utiliza la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdominios
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**API gratuita de JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API gratuito
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, la Wayback Machine y Common Crawl para cualquier dominio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Buscan en la web archivos JS y extraen subdominios de allí.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Buscador de subdominios de Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdominios e historial de IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este proyecto ofrece de forma **gratuita todos los subdominios relacionados con programas de recompensas por errores**. Puedes acceder a estos datos también utilizando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al alcance utilizado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Fuerza bruta de DNS**

Intentemos encontrar nuevos **subdominios** forzando servidores DNS utilizando posibles nombres de subdominio.

Para esta acción necesitarás algunas **listas de palabras comunes de subdominios como**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos resolutores de DNS. Para generar una lista de resolutores de DNS confiables, puedes descargar los resolutores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O podrías usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para la fuerza bruta de DNS son:

* [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó una fuerza bruta de DNS efectiva. Es muy rápida, sin embargo, es propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Creo que este solo utiliza 1 resolutor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un envoltorio alrededor de `massdns`, escrito en go, que te permite enumerar subdominios válidos utilizando fuerza bruta activa, así como resolver subdominios con manejo de comodines y soporte fácil de entrada y salida.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): También utiliza `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para forzar de forma asincrónica nombres de dominio.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Ronda de Fuerza Bruta en DNS

Después de haber encontrado subdominios utilizando fuentes abiertas y fuerza bruta, podrías generar alteraciones de los subdominios encontrados para intentar encontrar aún más. Varios herramientas son útiles para este propósito:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado los dominios y subdominios, genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dado los dominios y subdominios, genera permutaciones.
* Puedes obtener la lista de permutaciones de **wordlist** de goaltdns [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dado los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará el suyo propio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Aparte de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
* Puedes obtener la **lista de palabras** de permutaciones de altdns [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta realizará fuerza bruta en el resultado (no admite comodines de DNS).
* Puedes obtener la lista de palabras de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos posibles nombres de subdominios** basados en patrones indicados para intentar descubrir más subdominios.

#### Generación inteligente de permutaciones

* [**regulator**](https://github.com/cramppet/regulator): Para más información, lee este [**post**](https://cramppet.github.io/regulator/index.html) pero básicamente obtendrá las **partes principales** de los **subdominios descubiertos** y las mezclará para encontrar más subdominios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios acoplado con un algoritmo inmensamente simple pero efectivo guiado por respuestas de DNS. Utiliza un conjunto de datos de entrada proporcionados, como una lista de palabras personalizada o registros históricos de DNS/TLS, para sintetizar con precisión más nombres de dominio correspondientes y expandirlos aún más en un bucle basado en la información recopilada durante el escaneo de DNS.
```
echo www | subzuf facebook.com
```
### **Flujo de trabajo de descubrimiento de subdominios**

Revisa este artículo que escribí sobre cómo **automatizar el descubrimiento de subdominios** de un dominio utilizando **flujos de trabajo de Trickest** para no tener que lanzar manualmente un montón de herramientas en mi computadora:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Hosts Virtuales**

Si encuentras una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios con sitios web en esa IP** buscando en **fuentes de OSINT** para dominios en una IP o mediante **fuerza bruta en los nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs utilizando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

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
{% hint style="info" %}
Con esta técnica, incluso podrías acceder a puntos finales internos/ocultos.
{% endhint %}

### **Fuerza Bruta de CORS**

A veces encontrarás páginas que solo devuelven el encabezado _**Access-Control-Allow-Origin**_ cuando se establece un dominio/subdominio válido en el encabezado _**Origin**_. En estos escenarios, puedes abusar de este comportamiento para **descubrir** nuevos **subdominios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Fuerza bruta en Buckets**

Mientras buscas **subdominios**, mantén un ojo para ver si está **apuntando** a algún tipo de **bucket**, y en ese caso [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Además, en este punto, al conocer todos los dominios dentro del alcance, intenta [**realizar fuerza bruta en posibles nombres de buckets y verificar los permisos**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorización**

Puedes **monitorizar** si se crean **nuevos subdominios** de un dominio monitoreando los **Logs de Transparencia de Certificados** que hace [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Verifica posibles [**apoderamientos de subdominios**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** está apuntando a algún **bucket S3**, [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/).

Si encuentras algún **subdominio con una IP diferente** a las que ya encontraste en el descubrimiento de activos, debes realizar un **escaneo de vulnerabilidades básico** (usando Nessus u OpenVAS) y un [**escaneo de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que se estén ejecutando, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el subdominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance, ten cuidado._

## IPs

En los pasos iniciales, es posible que hayas **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recopilar todas las IPs de esos rangos** y de los **dominios/subdominios (consultas DNS).**

Utilizando servicios de las siguientes **APIs gratuitas**, también puedes encontrar **IPs anteriores utilizadas por dominios y subdominios**. Estas IPs aún podrían ser propiedad del cliente (y podrían permitirte encontrar [**bypasses de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes verificar los dominios que apuntan a una dirección IP específica utilizando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Búsqueda de vulnerabilidades**

**Escanea todos los IPs que no pertenecen a CDNs** (ya que es muy probable que no encuentres nada interesante allí). En los servicios en ejecución descubiertos, es posible que **encuentres vulnerabilidades**.

**Encuentra una** [**guía**](../pentesting-network/) **sobre cómo escanear hosts.**

## Búsqueda de servidores web

> Hemos encontrado todas las empresas y sus activos y conocemos los rangos de IP, dominios y subdominios dentro del alcance. Es hora de buscar servidores web.

En los pasos anteriores, probablemente ya hayas realizado algo de **reconocimiento de las IPs y dominios descubiertos**, por lo que es posible que ya hayas encontrado todos los posibles servidores web. Sin embargo, si no lo has hecho, ahora vamos a ver algunos **trucos rápidos para buscar servidores web** dentro del alcance.

Ten en cuenta que esto estará **orientado a la búsqueda de aplicaciones web**, por lo que debes **realizar el escaneo de vulnerabilidades** y **escaneo de puertos** también (**si está permitido** por el alcance).

Un **método rápido** para descubrir **puertos abiertos** relacionados con **servidores web** utilizando [**masscan se puede encontrar aquí**](../pentesting-network/#http-port-discovery).\
Otra herramienta útil para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Simplemente pasas una lista de dominios e intentará conectarse al puerto 80 (http) y 443 (https). Además, puedes indicar que intente otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** presentes en el alcance (entre las **IPs** de la empresa y todos los **dominios** y **subdominios**), probablemente **no sepas por dónde empezar**. Por lo tanto, hagámoslo simple y comencemos tomando capturas de pantalla de todos ellos. Solo con **echar un vistazo** a la **página principal** puedes encontrar **endpoints extraños** que son más **propensos** a ser **vulnerables**.

Para llevar a cabo la idea propuesta, puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, luego podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para revisar todas las **capturas de pantalla** y decirte **qué es probable que contenga vulnerabilidades** y qué no.

## Activos en la Nube Pública

Para encontrar posibles activos en la nube pertenecientes a una empresa, debes **comenzar con una lista de palabras clave que identifiquen a esa empresa**. Por ejemplo, para una empresa de criptomonedas podrías usar palabras como: `"crypto", "wallet", "dao", "<nombre_del_dominio>", <"nombres_de_subdominios">`.

También necesitarás listas de palabras comunes utilizadas en buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras, deberías generar **permutaciones** (consulta la [**Segunda Ronda de Fuerza Bruta DNS**](./#second-dns-bruteforce-round) para obtener más información).

Con las listas de palabras resultantes, podrías usar herramientas como [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que al buscar Activos en la Nube, debes **buscar más que solo buckets en AWS**.

### **Búsqueda de vulnerabilidades**

Si encuentras cosas como **buckets abiertos o funciones en la nube expuestas**, deberías **acceder a ellas** e intentar ver qué te ofrecen y si puedes abusar de ellas.

## Correos Electrónicos

Con los **dominios** y **subdominios** dentro del alcance, básicamente tienes todo lo que **necesitas para comenzar a buscar correos electrónicos**. Estas son las **APIs** y **herramientas** que mejor me han funcionado para encontrar correos electrónicos de una empresa:

* [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
* API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
* API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
* API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Búsqueda de vulnerabilidades**

Los correos electrónicos serán útiles más adelante para **fuerza bruta en logins web y servicios de autenticación** (como SSH). Además, son necesarios para **phishings**. Además, estas APIs te darán aún más **información sobre la persona** detrás del correo electrónico, lo cual es útil para la campaña de phishing.

## Fugas de Credenciales

Con los **dominios**, **subdominios** y **correos electrónicos**, puedes comenzar a buscar credenciales filtradas en el pasado pertenecientes a esos correos electrónicos:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales filtradas **válidas**, esto es una victoria muy fácil.

## Fugas de Secretos

Las fugas de credenciales están relacionadas con hackeos de empresas donde se filtró y vendió **información sensible**. Sin embargo, las empresas podrían verse afectadas por **otras fugas** cuya información no está en esas bases de datos:

### Fugas de Github

Las credenciales y APIs podrían filtrarse en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan para esa empresa de github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repos públicos** de una **organización** y de sus **desarrolladores** y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también se puede usar para ejecutar **gitleaks** en todos los **textos** proporcionados **URLs pasadas** a él, ya que a veces las **páginas web también contienen secretos**.

#### Dorks de Github

Consulta también esta **página** para posibles **dorks de github** que también podrías buscar en la organización que estás atacando:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Fugas de Pastes

A veces los atacantes o simplemente los trabajadores **publicarán contenido de la empresa en un sitio de paste**. Esto podría o no contener **información sensible**, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 sitios de paste al mismo tiempo.

### Dorks de Google

Los dorks antiguos pero útiles de Google siempre son útiles para encontrar **información expuesta que no debería estar allí**. El único problema es que la [**base de datos de google-hacking**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de consultas posibles que no puedes ejecutar manualmente. Por lo tanto, puedes obtener tus 10 favoritas o podrías usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que esperan ejecutar toda la base de datos utilizando el navegador regular de Google nunca terminarán, ya que Google te bloqueará muy pronto._

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales o tokens de API filtrados **válidos**, esto es una victoria muy fácil.

## Vulnerabilidades en Código Público

Si descubres que la empresa tiene **código abierto**, puedes **analizarlo** y buscar **vulnerabilidades** en él.

**Dependiendo del lenguaje**, hay diferentes **herramientas** que puedes usar:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

También hay servicios gratuitos que te permiten **escanear repositorios públicos**, como:

* [**Snyk**](https://app.snyk.io/)
## [**Metodología de Pentesting Web**](../../network-services-pentesting/pentesting-web/)

La **mayoría de las vulnerabilidades** encontradas por los cazadores de bugs residen dentro de las **aplicaciones web**, por lo que en este punto me gustaría hablar sobre una **metodología de prueba de aplicaciones web**, y puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/).

También quiero hacer una mención especial a la sección [**Herramientas de escaneo automático web de código abierto**](../../network-services-pentesting/pentesting-web/#automatic-scanners), ya que, aunque no debes esperar que encuentren vulnerabilidades muy sensibles, son útiles para implementarlas en **flujos de trabajo para obtener información web inicial.**

## Recapitulación

> ¡Felicidades! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se pueden hacer muchas más enumeraciones (veremos más trucos más adelante).

Así que ya has:

1. Encontrado todas las **empresas** dentro del alcance
2. Encontrado todos los **activos** pertenecientes a las empresas (y realizado un escaneo de vulnerabilidades si está en el alcance)
3. Encontrado todos los **dominios** pertenecientes a las empresas
4. Encontrado todos los **subdominios** de los dominios (¿algún secuestro de subdominio?)
5. Encontrado todas las **IPs** (de y **no de CDNs**) dentro del alcance.
6. Encontrado todos los **servidores web** y tomado una **captura de pantalla** de ellos (¿algo extraño que valga la pena investigar más a fondo?)
7. Encontrado todos los **activos potenciales de la nube pública** pertenecientes a la empresa.
8. **Emails**, **filtraciones de credenciales** y **filtraciones de secretos** que podrían darte una **gran victoria muy fácilmente**.
9. **Pentesting de todas las webs que encontraste**

## **Herramientas Automáticas de Reconocimiento Completo**

Existen varias herramientas que realizarán parte de las acciones propuestas contra un alcance dado.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antiguo y no actualizado

## **Referencias**

* Todos los cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo imposible - **¡estamos contratando!** (_se requiere polaco escrito y hablado con fluidez_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
