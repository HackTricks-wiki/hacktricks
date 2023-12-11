# Metodología de Reconocimiento Externo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Consejo de recompensa por errores**: ¡**regístrate** en **Intigriti**, una plataforma premium de **recompensas por errores creada por hackers, para hackers**! Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**.

{% embed url="https://go.intigriti.com/hacktricks" %}

## Descubrimiento de activos

> Te dijeron que todo lo que pertenece a una empresa está dentro del alcance, y quieres averiguar qué es lo que realmente posee esta empresa.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y luego todos los **activos** de estas empresas. Para hacerlo, vamos a:

1. Encontrar las adquisiciones de la empresa principal, esto nos dará las empresas dentro del alcance.
2. Encontrar el ASN (si existe) de cada empresa, esto nos dará los rangos de IP propiedad de cada empresa.
3. Utilizar búsquedas inversas de whois para buscar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer de forma recursiva).
4. Utilizar otras técnicas como los filtros `org` y `ssl` de Shodan para buscar otros activos (el truco de `ssl` se puede hacer de forma recursiva).

### **Adquisiciones**

En primer lugar, necesitamos saber qué **otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal** y **hacer clic** en "**adquisiciones**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **adquisiciones**.

> Ok, en este punto deberías saber todas las empresas dentro del alcance. Ahora averigüemos cómo encontrar sus activos.

### **ASN**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Autoridad de Números Asignados de Internet (IANA)**.\
Un **AS** consta de **bloques** de **direcciones IP** que tienen una política definida para acceder a redes externas y son administrados por una sola organización pero pueden estar compuestos por varios operadores.

Es interesante saber si la **empresa ha asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **prueba de vulnerabilidad** contra todos los **hosts** dentro del **alcance** y buscar dominios dentro de estas IPs.\
Puedes **buscar** por el **nombre** de la empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**.**\
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
Puedes encontrar los rangos de IP de una organización utilizando [http://asnlookup.com/](http://asnlookup.com) (tiene una API gratuita).\
Puedes encontrar la IP y ASN de un dominio utilizando [http://ipv4info.com/](http://ipv4info.com).

### **Buscando vulnerabilidades**

En este punto, conocemos **todos los activos dentro del alcance**, así que si se te permite, puedes lanzar algún **escáner de vulnerabilidades** (Nessus, OpenVAS) en todos los hosts.\
También puedes lanzar algunos [**escaneos de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) **o utilizar servicios como** shodan **para encontrar** puertos abiertos **y dependiendo de lo que encuentres, deberías** consultar este libro para aprender cómo hacer pruebas de penetración en varios servicios posibles que se estén ejecutando.\
**Además, podría valer la pena mencionar que también puedes preparar algunas** listas de nombres de usuario **y** contraseñas **predeterminadas y tratar de** forzar servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del alcance y sus activos, es hora de encontrar los dominios dentro del alcance.

_Ten en cuenta que en las siguientes técnicas propuestas también puedes encontrar subdominios y esa información no debe subestimarse._

En primer lugar, debes buscar el **dominio principal**(es) de cada empresa. Por ejemplo, para _Tesla Inc._ será _tesla.com_.

### **DNS inverso**

Una vez que hayas encontrado todos los rangos de IP de los dominios, puedes intentar realizar **búsquedas de DNS inverso** en esas **IP para encontrar más dominios dentro del alcance**. Intenta utilizar algún servidor DNS de la víctima o algún servidor DNS conocido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador debe habilitar manualmente el PTR.\
También puedes utilizar una herramienta en línea para obtener esta información: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (bucle)**

Dentro de un **whois** puedes encontrar mucha **información interesante** como el **nombre de la organización**, **dirección**, **correos electrónicos**, números de teléfono... Pero lo que es aún más interesante es que puedes encontrar **más activos relacionados con la empresa** si realizas **búsquedas de reverse whois por cualquiera de esos campos** (por ejemplo, otros registros de whois donde aparece el mismo correo electrónico).\
Puedes utilizar herramientas en línea como:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Gratis** web, no API gratuita.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - No es gratis
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - No es gratis (solo **100 búsquedas gratuitas**)
* [https://www.domainiq.com/](https://www.domainiq.com) - No es gratis

Puedes automatizar esta tarea utilizando [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También puedes realizar descubrimiento automático de reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes utilizar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

### **Trackers**

Si encuentras el **mismo ID del mismo tracker** en 2 páginas diferentes, puedes suponer que **ambas páginas** son **administradas por el mismo equipo**.\
Por ejemplo, si ves el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que te permiten buscar por estos trackers y más:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del icono del favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así es cómo se utiliza:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubrir dominios con el mismo hash de icono de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permitirá descubrir dominios que tienen el mismo hash de icono de favicon que nuestro objetivo.

Además, también puedes buscar tecnologías utilizando el hash de favicon como se explica en [**esta publicación de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Esto significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web**, puedes buscarlo en shodan y **encontrar más lugares vulnerables**:
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

Busca dentro de las páginas web **cadenas que podrían ser compartidas en diferentes sitios web de la misma organización**. La cadena de **derechos de autor** podría ser un buen ejemplo. Luego busca esa cadena en **Google**, en otros **navegadores** o incluso en **Shodan**: `shodan search http.html:"Cadena de derechos de autor"`

### **Hora del CRT**

Es común tener una tarea programada como un cron job, como por ejemplo:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Para renovar todos los certificados de dominio en el servidor. Esto significa que incluso si la CA utilizada para esto no establece la hora en que se generó en el tiempo de validez, es posible **encontrar dominios pertenecientes a la misma empresa en los registros de transparencia de certificados**.\
Echa un vistazo a este [**artículo para obtener más información**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Toma de control pasiva**

Aparentemente, es común que las personas asignen subdominios a IPs que pertenecen a proveedores de servicios en la nube y en algún momento **pierdan esa dirección IP pero olviden eliminar el registro DNS**. Por lo tanto, simplemente **iniciando una VM** en una nube (como Digital Ocean), en realidad estarás **tomando el control de algunos subdominios**.

[**Este artículo**](https://kmsec.uk/blog/passive-takeover/) explica una historia al respecto y propone un script que **inicia una VM en DigitalOcean**, **obtiene** la **IPv4** de la nueva máquina y **busca en Virustotal registros de subdominios** que apunten a ella.

### **Otras formas**

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

**Shodan**

Como ya conoces el nombre de la organización que posee el espacio de IP, puedes buscar esa información en Shodan usando: `org:"Tesla, Inc."` Verifica los hosts encontrados en busca de nuevos dominios inesperados en el certificado TLS.

Podrías acceder al **certificado TLS** de la página web principal, obtener el **nombre de la organización** y luego buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **Shodan** con el filtro: `ssl:"Tesla Motors"` o utilizar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) es una herramienta que busca **dominios relacionados** con un dominio principal y **subdominios** de ellos, bastante sorprendente.

### **Búsqueda de vulnerabilidades**

Verifica si hay algún [ataque de toma de dominio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Tal vez alguna empresa esté **utilizando un dominio** pero **perdió la propiedad**. Simplemente regístralo (si es lo suficientemente barato) y hazle saber a la empresa.

Si encuentras algún **dominio con una IP diferente** a las que ya encontraste en el descubrimiento de activos, debes realizar un **escaneo básico de vulnerabilidades** (usando Nessus o OpenVAS) y un [**escaneo de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que se estén ejecutando, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el dominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance, ten cuidado._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Consejo de recompensa por errores**: **regístrate** en **Intigriti**, una plataforma premium de **recompensas por errores creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdominios

> Conocemos todas las empresas dentro del alcance, todos los activos de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

### **DNS**

Intentemos obtener **subdominios** de los registros de **DNS**. También deberíamos intentar realizar una **Transferencia de Zona** (si es vulnerable, debes informarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener una gran cantidad de subdominios es buscar en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para obtener mejores resultados, configure las claves de API):

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

---

* [**findomain**](https://github.com/Edu4rdSHL/findomain/)

---
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/es-es)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)

Assetfinder es una herramienta de reconstrucción externa desarrollada por [tomnomnom](https://github.com/tomnomnom). Esta herramienta se utiliza para descubrir subdominios asociados a un dominio objetivo. Assetfinder utiliza múltiples fuentes de información, como motores de búsqueda, registros DNS y certificados SSL, para recopilar subdominios. Esta información puede ser útil para identificar posibles puntos de entrada en un objetivo y realizar un análisis de superficie de ataque más completo. Assetfinder es una herramienta de línea de comandos y se puede ejecutar desde la terminal.
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

theHarvester es una herramienta de código abierto que se utiliza para recopilar información de fuentes públicas en línea. Esta herramienta es útil en la fase de reconocimiento externo de un pentesting, ya que puede ayudar a recopilar información sobre direcciones de correo electrónico, nombres de dominio, subdominios, nombres de usuario y mucho más. theHarvester utiliza técnicas de búsqueda en motores de búsqueda, servicios de correo electrónico y redes sociales para extraer información relevante. Es una herramienta muy útil para obtener información inicial sobre un objetivo y puede ayudar a identificar posibles puntos de entrada para un ataque.
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Hay **otras herramientas/APIs interesantes** que, aunque no estén directamente especializadas en encontrar subdominios, podrían ser útiles para encontrar subdominios, como:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utiliza la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdominios.
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
* [**gau**](https://github.com/lc/gau)**:** obtiene las URL conocidas de AlienVault's Open Threat Exchange, la Wayback Machine y Common Crawl para cualquier dominio dado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Buscan en la web archivos JS y extraen subdominios de ellos.
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
* [**Censys buscador de subdominios**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdominios e historial de IP.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este proyecto ofrece de forma gratuita todos los subdominios relacionados con programas de recompensas por errores. También puedes acceder a estos datos utilizando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al alcance utilizado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Fuerza bruta de DNS**

Intentemos encontrar nuevos subdominios forzando servidores DNS utilizando posibles nombres de subdominio.

Para esta acción necesitarás algunas **listas de palabras comunes de subdominios como**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también las IPs de buenos resolutores DNS. Para generar una lista de resolutores DNS confiables, puedes descargar los resolutores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

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
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para realizar fuerza bruta de nombres de dominio de forma asíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Ronda de Fuerza Bruta DNS

Después de haber encontrado subdominios utilizando fuentes abiertas y fuerza bruta, podrías generar alteraciones de los subdominios encontrados para intentar encontrar aún más. Varios herramientas son útiles para este propósito:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado los dominios y subdominios, genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dado los dominios y subdominios, genera permutaciones.
* Puedes obtener la lista de permutaciones de goaltdns **wordlist** [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dado los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator utilizará el suyo propio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
* Puedes obtener la lista de permutaciones de altdns **wordlist** [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta realizará un ataque de fuerza bruta en los resultados (no admite comodines DNS).
* Puedes obtener la lista de palabras de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos nombres potenciales de subdominios** basados en patrones indicados para intentar descubrir más subdominios.

#### Generación inteligente de permutaciones

* [**regulator**](https://github.com/cramppet/regulator): Para obtener más información, lee este [**post**](https://cramppet.github.io/regulator/index.html), pero básicamente tomará las **partes principales** de los **subdominios descubiertos** y las mezclará para encontrar más subdominios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios combinado con un algoritmo inmensamente simple pero efectivo de guía de respuestas DNS. Utiliza un conjunto de datos de entrada proporcionados, como una lista de palabras personalizada o registros históricos de DNS/TLS, para sintetizar de manera precisa más nombres de dominio correspondientes y expandirlos aún más en un bucle basado en la información recopilada durante el escaneo DNS.
```
echo www | subzuf facebook.com
```
### **Flujo de Descubrimiento de Subdominios**

Revisa esta publicación de blog que escribí sobre cómo **automatizar el descubrimiento de subdominios** de un dominio utilizando **flujos de trabajo de Trickest** para no tener que lanzar manualmente un montón de herramientas en mi computadora:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtual Hosts**

Si encuentras una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, puedes intentar **encontrar otros subdominios con sitios web en esa IP** buscando en **fuentes de OSINT** los dominios en una IP o **realizando un ataque de fuerza bruta a los nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs utilizando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Fuerza Bruta**

Si sospechas que algún subdominio puede estar oculto en un servidor web, puedes intentar realizar un ataque de fuerza bruta:
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
### **Fuerza Bruta de Buckets**

Mientras buscas **subdominios**, mantén un ojo para ver si está **apuntando** a algún tipo de **bucket**, y en ese caso [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Además, en este punto ya conocerás todos los dominios dentro del alcance, intenta [**realizar una fuerza bruta de posibles nombres de buckets y verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorización**

Puedes **monitorizar** si se crean **nuevos subdominios** de un dominio mediante la monitorización de los registros de **Certificate Transparency**. Esto lo hace [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Verifica posibles [**apoderamientos de subdominios**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** está apuntando a algún **bucket de S3**, [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/).

Si encuentras algún **subdominio con una IP diferente** a las que ya encontraste en el descubrimiento de activos, debes realizar un **escaneo básico de vulnerabilidades** (usando Nessus o OpenVAS) y un [**escaneo de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que se estén ejecutando, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el subdominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance, ten cuidado._

## IPs

En los pasos iniciales, es posible que hayas **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recopilar todas las IPs de esos rangos** y de los **dominios/subdominios (consultas DNS)**.

Utilizando servicios de las siguientes **APIs gratuitas**, también puedes encontrar **IPs anteriores utilizadas por dominios y subdominios**. Estas IPs aún podrían ser propiedad del cliente (y podrían permitirte encontrar [**bypasses de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes verificar los dominios que apuntan a una dirección IP específica utilizando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Búsqueda de vulnerabilidades**

**Escanea los puertos de todas las IPs que no pertenezcan a CDNs** (ya que es muy probable que no encuentres nada interesante allí). En los servicios en ejecución que descubras, es posible que **puedas encontrar vulnerabilidades**.

Encuentra una [**guía**](../pentesting-network/) **sobre cómo escanear hosts**.

## Búsqueda de servidores web

> Hemos encontrado todas las empresas y sus activos, y conocemos los rangos de IP, dominios y subdominios dentro del alcance. Es hora de buscar servidores web.

En los pasos anteriores, probablemente ya hayas realizado alguna **reconocimiento de las IPs y dominios descubiertos**, por lo que es posible que ya hayas encontrado todos los posibles servidores web. Sin embargo, si no lo has hecho, ahora vamos a ver algunos **trucos rápidos para buscar servidores web** dentro del alcance.

Ten en cuenta que esto estará **orientado a la búsqueda de aplicaciones web**, por lo que también debes realizar el **escaneo de vulnerabilidades** y **puertos** (**si está permitido** por el alcance).

Un **método rápido** para descubrir **puertos abiertos** relacionados con servidores **web** se puede encontrar aquí [**masscan**](../pentesting-network/#http-port-discovery).\
Otra herramienta útil para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Simplemente pasas una lista de dominios y tratará de conectarse a los puertos 80 (http) y 443 (https). Además, puedes indicar que intente otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** presentes en el alcance (entre las **IPs** de la empresa y todos los **dominios** y **subdominios**), probablemente **no sepas por dónde empezar**. Así que hagámoslo simple y comencemos tomando capturas de pantalla de todos ellos. Solo con **echar un vistazo** a la **página principal**, puedes encontrar puntos finales extraños que son más **propensos** a ser **vulnerables**.

Para llevar a cabo la idea propuesta, puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, luego podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para revisar todas las **capturas de pantalla** y decirte **qué es probable que contenga vulnerabilidades** y qué no.

## Activos en la Nube Pública

Para encontrar posibles activos en la nube pertenecientes a una empresa, debes **comenzar con una lista de palabras clave que identifiquen a esa empresa**. Por ejemplo, para una empresa de criptomonedas, podrías usar palabras como: `"crypto", "wallet", "dao", "<nombre_de_dominio>", <"nombres_de_subdominios">`.

También necesitarás listas de palabras comunes utilizadas en buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras, debes generar **permutaciones** (consulta la [**Segunda Ronda de Fuerza Bruta DNS**](./#segunda-ronda-de-fuerza-bruta-dns) para obtener más información).

Con las listas de palabras resultantes, puedes usar herramientas como [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que al buscar Activos en la Nube, debes buscar **más que solo buckets en AWS**.

### **Búsqueda de vulnerabilidades**

Si encuentras cosas como **buckets abiertos o funciones en la nube expuestas**, debes **acceder a ellas** e intentar ver qué te ofrecen y si puedes abusar de ellas.

## Correos Electrónicos

Con los **dominios** y **subdominios** dentro del alcance, básicamente tienes todo lo que **necesitas para comenzar a buscar correos electrónicos**. Estas son las **APIs** y **herramientas** que mejor me han funcionado para encontrar correos electrónicos de una empresa:

* [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
* API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
* API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
* API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Búsqueda de vulnerabilidades**

Los correos electrónicos serán útiles más adelante para **fuerza bruta en inicios de sesión web y servicios de autenticación** (como SSH). Además, son necesarios para **phishings**. Además, estas APIs te darán aún más **información sobre la persona** detrás del correo electrónico, lo cual es útil para la campaña de phishing.

## Fugas de Credenciales

Con los **dominios**, **subdominios** y **correos electrónicos**, puedes comenzar a buscar credenciales filtradas en el pasado pertenecientes a esos correos electrónicos:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales filtradas **válidas**, esto es una victoria muy fácil.

## Fugas de Secretos

Las fugas de credenciales están relacionadas con ataques a empresas donde se filtró y vendió **información confidencial**. Sin embargo, las empresas también pueden verse afectadas por **otras fugas** cuya información no está en esas bases de datos:

### Fugas de Github

Las credenciales y las APIs pueden filtrarse en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan para esa empresa de Github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repositorios públicos** de una **organización** y de sus **desarrolladores** y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) automáticamente sobre ellos.

**Leakos** también se puede usar para ejecutar **gitleaks** en todas las **URLs de texto** proporcionadas **pasadas** a él, ya que a veces **las páginas web también contienen secretos**.

#### Dorks de Github

Consulta también esta **página** para posibles **dorks de Github** que también podrías buscar en la organización que estás atacando:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Fugas en Paste Sites

A veces, los atacantes o simplemente los trabajadores **publicarán contenido de la empresa en un sitio de pegado**. Esto puede o no contener **información confidencial**, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 sitios de pegado al mismo tiempo.

### Dorks de Google

Los dorks antiguos pero efectivos de Google siempre son útiles para encontrar **información expuesta que no debería estar ahí**. El único problema es que la [**base de datos de google-hacking**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de posibles consultas que no puedes ejecutar manualmente. Así que puedes elegir tus 10 favoritas o puedes usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que esperan ejecutar toda la base de datos utilizando el navegador regular de Google nunca terminarán, ya que Google te bloqueará muy pronto._
### **Buscando vulnerabilidades**

Si encuentras credenciales o tokens de API **filtrados y válidos**, esto es una victoria muy fácil.

## Vulnerabilidades en el código público

Si encuentras que la empresa tiene **código de código abierto**, puedes **analizarlo** y buscar **vulnerabilidades** en él.

**Dependiendo del lenguaje**, hay diferentes **herramientas** que puedes utilizar:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

También hay servicios gratuitos que te permiten **escanear repositorios públicos**, como:

* [**Snyk**](https://app.snyk.io/)

## [**Metodología de Pentesting Web**](../../network-services-pentesting/pentesting-web/)

La **mayoría de las vulnerabilidades** encontradas por los cazadores de bugs residen en las **aplicaciones web**, así que en este punto me gustaría hablar sobre una **metodología de prueba de aplicaciones web**, y puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/).

También quiero hacer una mención especial a la sección [**Herramientas de escaneo automático de código abierto para web**](../../network-services-pentesting/pentesting-web/#automatic-scanners), ya que, aunque no debes esperar que encuentren vulnerabilidades muy sensibles, son útiles para implementarlos en **flujos de trabajo para obtener información web inicial**.

## Recapitulación

> ¡Felicidades! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos más adelante).

Así que ya has:

1. Encontrado todas las **empresas** dentro del alcance.
2. Encontrado todos los **activos** pertenecientes a las empresas (y realizado un escaneo de vulnerabilidades si está dentro del alcance).
3. Encontrado todos los **dominios** pertenecientes a las empresas.
4. Encontrado todos los **subdominios** de los dominios (¿alguna toma de subdominio?).
5. Encontrado todas las **IP** (de y **no de CDNs**) dentro del alcance.
6. Encontrado todos los **servidores web** y tomado una **captura de pantalla** de ellos (¿algo extraño que valga la pena investigar más a fondo?).
7. Encontrado todos los **activos potenciales de la nube pública** pertenecientes a la empresa.
8. **Correos electrónicos**, **filtraciones de credenciales** y **filtraciones de secretos** que podrían darte una **gran victoria de manera muy fácil**.
9. **Realizado pruebas de penetración en todas las webs que encontraste**.

## **Herramientas automáticas de reconocimiento completo**

Hay varias herramientas disponibles que realizarán parte de las acciones propuestas en un alcance determinado.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antiguo y no actualizado

## **Referencias**

* **Todos los cursos gratuitos de** [**@Jhaddix**](https://twitter.com/Jhaddix) **(como** [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)**)**

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Consejo de bug bounty**: **regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
