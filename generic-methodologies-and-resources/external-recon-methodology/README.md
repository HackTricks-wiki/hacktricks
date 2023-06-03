# Metodología de Reconocimiento Externo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Consejo de recompensa por errores**: **regístrate** en **Intigriti**, una plataforma premium de **recompensa por errores creada por hackers, para hackers**. Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**.

{% embed url="https://go.intigriti.com/hacktricks" %}

## Descubrimiento de activos

> Te han dicho que todo lo que pertenece a una empresa está dentro del alcance, y quieres averiguar lo que esta empresa realmente posee.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y luego todos los **activos** de estas empresas. Para hacerlo, vamos a:

1. Encontrar las adquisiciones de la empresa principal, esto nos dará las empresas dentro del alcance.
2. Encontrar el ASN (si lo hay) de cada empresa, esto nos dará los rangos de IP propiedad de cada empresa.
3. Usar búsquedas inversas de whois para buscar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer recursivamente).
4. Usar otras técnicas como los filtros `org` y `ssl` de shodan para buscar otros activos (el truco `ssl` se puede hacer recursivamente).

### **Adquisiciones**

En primer lugar, necesitamos saber qué **otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal**, y **hacer clic** en "**adquisiciones**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **adquisiciones**.

> Ok, en este punto deberías conocer todas las empresas dentro del alcance. Averigüemos cómo encontrar sus activos.

### **ASN**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Autoridad de Números Asignados de Internet (IANA)**.\
Un **AS** consta de **bloques** de **direcciones IP** que tienen una política definida de forma distintiva para acceder a redes externas y son administrados por una sola organización pero pueden estar compuestos por varios operadores.

Es interesante saber si la **empresa ha asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **prueba de vulnerabilidad** contra todos los **hosts** dentro del **alcance** y **buscar dominios** dentro de estas IPs.\
Puedes **buscar** por el **nombre** de la empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependiendo de la región de la empresa, estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todos modos, probablemente toda la información útil (rangos de IP y Whois)** ya aparece en el primer enlace.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
También, la enumeración de subdominios de [**BBOT**](https://github.com/blacklanternsecurity/bbot) automáticamente agrega y resume los ASN al final del escaneo.
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

En este punto conocemos **todos los activos dentro del alcance**, así que si se nos permite, podríamos lanzar algún **escáner de vulnerabilidades** (Nessus, OpenVAS) en todos los hosts.\
También podrías lanzar algunos [**escaneos de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) **o usar servicios como** shodan **para encontrar** puertos abiertos **y dependiendo de lo que encuentres, deberías** buscar en este libro cómo hacer pentesting en varios posibles servicios en ejecución.\
**También podría valer la pena mencionar que también puedes preparar algunas** listas de nombres de usuario y contraseñas **y tratar de** hacer fuerza bruta en servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del alcance y sus activos, es hora de encontrar los dominios dentro del alcance.

_Ten en cuenta que en las siguientes técnicas propuestas también puedes encontrar subdominios y esa información no debe subestimarse._

En primer lugar, deberías buscar el **dominio principal**(es) de cada empresa. Por ejemplo, para _Tesla Inc._ va a ser _tesla.com_.

### **DNS inverso**

Como has encontrado todos los rangos de IP de los dominios, podrías intentar realizar **búsquedas de DNS inverso** en esas **IP para encontrar más dominios dentro del alcance**. Trata de usar algún servidor DNS de la víctima o algún servidor DNS bien conocido (1.1.1.1, 8.8.8.8).
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador tiene que habilitar manualmente el PTR.\
También se puede utilizar una herramienta en línea para obtener esta información: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (bucle)**

Dentro de un **whois** se pueden encontrar muchos datos interesantes como el **nombre de la organización**, **dirección**, **correos electrónicos**, números de teléfono... Pero lo que es aún más interesante es que se pueden encontrar **más activos relacionados con la empresa** si se realizan **búsquedas de whois inversas por cualquiera de esos campos** (por ejemplo, otros registros de whois donde aparece el mismo correo electrónico).\
Se pueden utilizar herramientas en línea como:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
* [https://www.whoxy.com/](https://www.whoxy.com) - Web **gratis**, no API gratis.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - No gratis
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - No gratis (solo **100 búsquedas gratis**)
* [https://www.domainiq.com/](https://www.domainiq.com) - No gratis

Se puede automatizar esta tarea utilizando [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También se puede realizar una búsqueda automática de whois inverso con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Tenga en cuenta que se puede utilizar esta técnica para descubrir más nombres de dominio cada vez que se encuentra un nuevo dominio.**

### **Trackers**

Si encuentra el **mismo ID del mismo tracker** en 2 páginas diferentes, se puede suponer que **ambas páginas** son **administradas por el mismo equipo**.\
Por ejemplo, si ve el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que le permiten buscar por estos trackers y más:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

¿Sabía que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash de icono de favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así es cómo utilizarlo:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubre dominios con el mismo hash de icono favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permitirá descubrir dominios que tienen el mismo hash de icono favicon que nuestro objetivo.

Además, también puedes buscar tecnologías utilizando el hash de favicon como se explica en [**esta publicación de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Eso significa que si conoces el **hash del favicon de una versión vulnerable de una tecnología web**, puedes buscar si está en shodan y **encontrar más lugares vulnerables**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Así es como puedes **calcular el hash del favicon** de una página web:
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

Busque dentro de las páginas web **cadenas que puedan ser compartidas en diferentes sitios web de la misma organización**. La **cadena de derechos de autor** podría ser un buen ejemplo. Luego busque esa cadena en **Google**, en otros **navegadores** o incluso en **Shodan**: `shodan search http.html:"Cadena de derechos de autor"`

### **Tiempo de CRT**

Es común tener un trabajo cron como el siguiente:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Renovar todos los certificados de dominio en el servidor. Esto significa que, incluso si la CA utilizada para esto no establece la hora en que se generó en el tiempo de validez, es posible **encontrar dominios pertenecientes a la misma empresa en los registros de transparencia de certificados**.\
Echa un vistazo a este [**artículo para obtener más información**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Toma de control pasiva**

Aparentemente, es común que las personas asignen subdominios a IPs que pertenecen a proveedores de nube y, en algún momento, **pierdan esa dirección IP pero olviden eliminar el registro DNS**. Por lo tanto, simplemente **iniciando una VM** en una nube (como Digital Ocean), en realidad estarás **tomando el control de algunos subdominios**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica una historia al respecto y propone un script que **inicia una VM en DigitalOcean**, **obtiene** el **IPv4** de la nueva máquina y **busca en Virustotal registros de subdominios** que apunten a ella.

### **Otras formas**

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un nuevo dominio.**

**Shodan**

Como ya conoces el nombre de la organización que posee el espacio IP, puedes buscar esa información en Shodan usando: `org:"Tesla, Inc."` Revisa los hosts encontrados en busca de nuevos dominios inesperados en el certificado TLS.

Podrías acceder al **certificado TLS** de la página web principal, obtener el **nombre de la organización** y luego buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **Shodan** con el filtro: `ssl:"Tesla Motors"`

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) es una herramienta que busca **dominios relacionados** con un dominio principal y **subdominios** de ellos, bastante sorprendente.

### **Buscando vulnerabilidades**

Revisa si hay algún [toma de control de dominio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Tal vez alguna empresa esté **usando un dominio** pero **perdió la propiedad**. Solo regístralo (si es lo suficientemente barato) y hazle saber a la empresa.

Si encuentras algún **dominio con una IP diferente** de las que ya encontraste en el descubrimiento de activos, deberías realizar un **escaneo de vulnerabilidades básico** (usando Nessus o OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que se estén ejecutando, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el dominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance, ten cuidado._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Consejo de bug bounty**: **regístrate** en **Intigriti**, una plataforma premium de **bug bounty creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy mismo y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdominios

> Conocemos todas las empresas dentro del alcance, todos los activos de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los posibles subdominios de cada dominio encontrado.

### **DNS**

Intentemos obtener **subdominios** de los registros **DNS**. También deberíamos intentar hacer una **Transferencia de zona** (si es vulnerable, deberías informarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para obtener mejores resultados, configure las claves de API):

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

Amass es una herramienta de reconocimiento externo que ayuda a recopilar información sobre objetivos específicos. Puede descubrir subdominios, puertos abiertos y servicios en ejecución, y también puede realizar búsquedas de DNS y Whois. Amass es una herramienta muy útil para la fase de reconocimiento de cualquier prueba de penetración.
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)

Subfinder es una herramienta de reconocimiento de subdominios que utiliza múltiples fuentes públicas para encontrar subdominios asociados a un dominio dado. Es una herramienta muy útil para la fase de reconocimiento externo.
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)

Findomain es una herramienta de reconocimiento de dominios que utiliza diversas fuentes públicas para encontrar subdominios asociados a un dominio dado. Es una herramienta muy útil para la fase de reconocimiento externo.
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

OneForAll es una herramienta de reconocimiento de dominios que puede buscar subdominios, correos electrónicos y nombres de usuario en más de 100 fuentes públicas. Es muy útil para encontrar información sobre una organización y sus empleados.
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder): Herramienta para encontrar subdominios de un dominio dado.
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)

Sudomy es una herramienta de reconstrucción de subdominios que utiliza múltiples fuentes para recopilar información sobre subdominios. La herramienta es altamente personalizable y permite a los usuarios agregar sus propias fuentes de búsqueda. Sudomy también puede realizar búsquedas de subdominios utilizando motores de búsqueda como Google, Bing y Yahoo.
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita) - Vita es una herramienta de reconstrucción de subdominios que utiliza múltiples fuentes de información para encontrar subdominios.
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)

theHarvester es una herramienta de código abierto que se utiliza para recopilar información de correo electrónico y nombres de dominio de diferentes fuentes públicas, como motores de búsqueda, servidores DNS y páginas web. Es una herramienta muy útil para la fase de reconocimiento externo de un pentesting.
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Existen **otras herramientas/APIs interesantes** que, aunque no estén directamente especializadas en encontrar subdominios, podrían ser útiles para encontrar subdominios, como:

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

Este sitio web es una herramienta de búsqueda de certificados SSL/TLS. Puede ser utilizado para buscar certificados emitidos para un dominio específico, lo que puede ser útil para la recopilación de información y la enumeración de subdominios. También puede ser utilizado para buscar certificados emitidos por una autoridad de certificación específica, lo que puede ser útil para la identificación de infraestructuras y servicios.
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
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Estas herramientas buscan en la web archivos JS y extraen subdominios a partir de ellos.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)

Shodan es un motor de búsqueda que permite a los usuarios encontrar dispositivos conectados a Internet y ver información sobre ellos, como el sistema operativo, el software utilizado y la dirección IP. Es una herramienta útil para la recopilación de información y la identificación de vulnerabilidades en dispositivos conectados a Internet.
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Buscador de subdominios de Censys**](https://github.com/christophetd/censys-subdomain-finder)
```
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdominios e historial de IP.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/) Este proyecto ofrece de forma gratuita todos los subdominios relacionados con programas de recompensa por errores. También puedes acceder a estos datos utilizando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al alcance utilizado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **Fuerza bruta DNS**

Intentemos encontrar nuevos subdominios forzando servidores DNS utilizando posibles nombres de subdominios.

Para esta acción necesitarás algunas **listas de palabras comunes de subdominios como**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos resolutores DNS. Para generar una lista de resolutores DNS confiables, puedes descargar los resolutores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para la fuerza bruta DNS son:

* [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó una fuerza bruta DNS efectiva. Es muy rápida, sin embargo, es propensa a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Creo que este solo utiliza 1 resolutor.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un envoltorio alrededor de `massdns`, escrito en go, que te permite enumerar subdominios válidos utilizando fuerza bruta activa, así como resolver subdominios con manejo de comodines y soporte fácil de entrada-salida.
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
### Segunda ronda de fuerza bruta DNS

Después de haber encontrado subdominios utilizando fuentes abiertas y fuerza bruta, podrías generar alteraciones de los subdominios encontrados para intentar encontrar aún más. Varios herramientas son útiles para este propósito:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dados los dominios y subdominios, genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dado un dominio o subdominio, genera permutaciones.
  * Puedes obtener la lista de permutaciones de goaltdns en [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dado un conjunto de dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator utilizará uno propio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
  * Puedes obtener la **lista de palabras** de permutaciones de altdns [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta fuerza bruta el resultado (no soporta comodines DNS).
  * Puedes obtener la lista de palabras de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basado en un dominio, **genera nuevos nombres potenciales de subdominios** basados en patrones indicados para intentar descubrir más subdominios.

#### Generación inteligente de permutaciones

* [**regulator**](https://github.com/cramppet/regulator): Para más información, lee este [**post**](https://cramppet.github.io/regulator/index.html), pero básicamente obtendrá las **partes principales** de los **subdominios descubiertos** y las mezclará para encontrar más subdominios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios acoplado con un algoritmo inmensamente simple pero efectivo guiado por respuestas DNS. Utiliza un conjunto de datos de entrada proporcionados, como una lista de palabras personalizada o registros históricos de DNS/TLS, para sintetizar con precisión más nombres de dominio correspondientes y expandirlos aún más en un bucle basado en la información recopilada durante el escaneo DNS.
```
echo www | subzuf facebook.com
```
### **Flujo de descubrimiento de subdominios**

Revisa este artículo que escribí sobre cómo **automatizar el descubrimiento de subdominios** de un dominio utilizando **flujos de trabajo de Trickest** para no tener que lanzar manualmente un montón de herramientas en mi ordenador:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Hosts Virtuales**

Si encontraste una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios con webs en esa IP** buscando en **fuentes OSINT** para dominios en una IP o mediante **fuerza bruta de nombres de dominio VHost en esa IP**.

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
{% hint style="info" %}
Con esta técnica, incluso podrías acceder a endpoints internos/ocultos.
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

Puedes **monitorizar** si se crean **nuevos subdominios** de un dominio mediante la monitorización de los **registros de transparencia de certificados** que hace [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Verifica posibles [**tomas de subdominios**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** está apuntando a algún **bucket S3**, [**verifica los permisos**](../../network-services-pentesting/pentesting-web/buckets/).

Si encuentras algún **subdominio con una IP diferente** a las que ya encontraste en el descubrimiento de activos, debes realizar un **escaneo básico de vulnerabilidades** (usando Nessus o OpenVAS) y un [**escaneo de puertos**](../pentesting-network/#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que se estén ejecutando, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el subdominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance, ten cuidado._

## IPs

En los pasos iniciales, es posible que hayas **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recopilar todas las IPs de esos rangos** y de los **dominios/subdominios (consultas DNS).**

Usando servicios de las siguientes **APIs gratuitas**, también puedes encontrar **IPs anteriores utilizadas por dominios y subdominios**. Estas IPs aún podrían ser propiedad del cliente (y podrían permitirte encontrar [**bypasses de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

### **Búsqueda de vulnerabilidades**

**Escanea los puertos de todas las IPs que no pertenezcan a CDNs** (ya que es muy probable que no encuentres nada interesante allí). En los servicios en ejecución descubiertos, es posible que puedas encontrar **vulnerabilidades**.

**Encuentra una** [**guía**](../pentesting-network/) **sobre cómo escanear hosts.**

## Caza de servidores web

> Hemos encontrado todas las empresas y sus activos y conocemos los rangos de IP, dominios y subdominios dentro del alcance. Es hora de buscar servidores web.

En los pasos anteriores, probablemente ya hayas realizado algo de **reconocimiento de las IPs y dominios descubiertos**, por lo que es posible que ya hayas encontrado todos los posibles servidores web. Sin embargo, si no lo has hecho, ahora vamos a ver algunos **trucos rápidos para buscar servidores web** dentro del alcance.

Ten en cuenta que esto estará **orientado a la búsqueda de aplicaciones web**, por lo que también debes **realizar el escaneo de vulnerabilidades** y **de puertos** (**si está permitido** por el alcance).

Un **método rápido** para descubrir **puertos abiertos** relacionados con **servidores web** usando [**masscan se puede encontrar aquí**](../pentesting-network/#http-port-discovery).\
Otra herramienta útil para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Simplemente pasas una lista de dominios e intentará conectarse al puerto 80 (http) y 443 (https). Además, puedes indicar que intente otros puertos:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** presentes en el alcance (entre las **IP** de la empresa y todos los **dominios** y **subdominios**), probablemente **no sepas por dónde empezar**. Así que, hagámoslo simple y comencemos tomando capturas de pantalla de todos ellos. Solo con **echar un vistazo** a la **página principal** puedes encontrar puntos finales **extraños** que son más **propensos** a ser **vulnerables**.

Para realizar la idea propuesta, puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, luego podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para ejecutar todas las **capturas de pantalla** y decirte **qué es probable que contenga vulnerabilidades** y qué no.

## Activos de nube pública

Para encontrar posibles activos de nube pertenecientes a una empresa, debes **comenzar con una lista de palabras clave que identifiquen a esa empresa**. Por ejemplo, para una empresa de criptomonedas, podrías usar palabras como: `"crypto", "wallet", "dao", "<nombre_de_dominio>", <"nombres_de_subdominios">`.

También necesitarás listas de palabras comunes utilizadas en los buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras, deberías generar **permutaciones** (consulta la [**Segunda ronda de fuerza bruta DNS**](./#second-dns-bruteforce-round) para obtener más información).

Con las listas de palabras resultantes, puedes usar herramientas como [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que al buscar activos de nube, debes buscar **más que solo buckets en AWS**.

### **Buscando vulnerabilidades**

Si encuentras cosas como **buckets abiertos o funciones en la nube expuestas**, debes **acceder a ellas** e intentar ver qué te ofrecen y si puedes abusar de ellas.

## Correos electrónicos

Con los **dominios** y **subdominios** dentro del alcance, básicamente tienes todo lo que necesitas para comenzar a buscar correos electrónicos. Estas son las **API** y **herramientas** que mejor me han funcionado para encontrar correos electrónicos de una empresa:

* [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
* API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
* API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
* API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Buscando vulnerabilidades**

Los correos electrónicos serán útiles más adelante para **ataques de fuerza bruta en el inicio de sesión web y servicios de autenticación** (como SSH). Además, se necesitan para **phishing**. Además, estas APIs te darán aún más **información sobre la persona** detrás del correo electrónico, lo cual es útil para la campaña de phishing.

## Fugas de credenciales

Con los **dominios**, **subdominios** y **correos electrónicos**, puedes comenzar a buscar credenciales filtradas en el pasado que pertenezcan a esos correos electrónicos:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Buscando vulnerabilidades**

Si encuentras credenciales filtradas **válidas**, esto es una victoria muy fácil.

## Fugas de secretos

Las fugas de credenciales están relacionadas con
