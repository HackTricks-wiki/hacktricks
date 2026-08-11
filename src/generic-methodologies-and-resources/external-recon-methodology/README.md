# Metodología de Reconocimiento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de activos

> Así que te han dicho que todo lo que pertenece a una empresa está dentro del scope, y quieres averiguar qué posee realmente esta empresa.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y, después, todos los **activos** de estas empresas. Para ello, vamos a:<sup>[[1]](#references)</sup>

1. Encontrar las adquisiciones de la empresa principal; esto nos dará las empresas dentro del scope.
2. Encontrar el ASN (si existe) de cada empresa; esto nos dará los rangos de IP propiedad de cada empresa.
3. Usar búsquedas de reverse whois para encontrar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto puede hacerse de forma recursiva).
4. Usar otras técnicas, como los filtros `org` y `ssl` de shodan, para buscar otros activos (el truco de `ssl` puede hacerse de forma recursiva).

### **Adquisiciones**

En primer lugar, necesitamos saber qué **otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal** y hacer **clic** en "**acquisitions**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **acquisitions**.\
Para empresas públicas, revisa los **informes de SEC/EDGAR**, las páginas de **relaciones con inversores** o los registros corporativos locales (por ejemplo, **Companies House** en Reino Unido).\
Para consultar árboles corporativos globales y subsidiarias, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Bien, en este punto deberías conocer todas las empresas dentro del scope. Averigüemos cómo encontrar sus activos.

### **ASNs**

Un autonomous system number (**ASN**) es un **número único** asignado a un **autonomous system** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** está formado por **bloques** de **direcciones IP** que tienen una política claramente definida para acceder a redes externas y son administrados por una única organización, aunque pueden estar compuestos por varios operadores.

Es interesante comprobar si la **empresa tiene asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **prueba de vulnerabilidades** contra todos los **hosts** dentro del **scope** y **buscar dominios** dentro de estas IPs.\
Puedes **buscar** por **nombre** de empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Dependiendo de la región de la empresa, estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todos modos, probablemente toda la** información útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Además, la enumeración de [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrega y resume automáticamente los ASN al final del escaneo.
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
También puedes encontrar los rangos de IP de una organización usando [http://asnlookup.com/](http://asnlookup.com) (tiene una API gratuita).\
Puedes encontrar la IP y el ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Búsqueda de vulnerabilidades**

En este punto conocemos **todos los activos dentro del alcance**, así que, si tienes autorización, podrías lanzar algún **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) sobre todos los hosts.\
También podrías realizar algunos [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys o ZoomEye **para encontrar** puertos abiertos **y, dependiendo de lo que encuentres, deberías** consultar este libro para aprender a hacer pentesting de varios servicios posibles en ejecución.\
**También podría ser útil mencionar que puedes preparar algunas** listas de nombres de usuario **y** contraseñas **predeterminadas e intentar** hacer bruteforce contra servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del alcance y sus activos; es hora de encontrar los dominios dentro del alcance.

_Ten en cuenta que con las técnicas propuestas a continuación también puedes encontrar subdominios y que esa información no debe subestimarse._

En primer lugar, deberías buscar el **dominio principal** de cada empresa. Por ejemplo, para _Tesla Inc._ sería _tesla.com_.

### **Reverse DNS**

Como has encontrado todos los rangos de IP de los dominios, podrías intentar realizar **consultas DNS inversas** sobre esas **IP para encontrar más dominios dentro del alcance**. Intenta usar algún servidor DNS de la víctima o algún servidor DNS conocido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que esto funcione, el administrador tiene que habilitar manualmente el PTR.\
También puedes utilizar una herramienta online para obtener esta información: [http://ptrarchive.com/](http://ptrarchive.com).\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar las búsquedas inversas y el enriquecimiento.

### **Reverse Whois (loop)**

Dentro de un **whois** puedes encontrar mucha **información** interesante, como **el nombre de la organización**, **la dirección**, **correos electrónicos**, números de teléfono... Pero lo que resulta aún más interesante es que puedes encontrar **más assets relacionados con la empresa** si realizas **búsquedas reverse whois utilizando cualquiera de esos campos** (por ejemplo, otros registros whois donde aparezca el mismo correo electrónico).\
Puedes utilizar herramientas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web y API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **gratis**, API de pago.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - De pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - De pago (**solo 100 búsquedas gratis**)
- [https://www.domainiq.com/](https://www.domainiq.com) - De pago
- [https://securitytrails.com/](https://securitytrails.com/) - De pago (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - De pago (API)

Puedes automatizar esta tarea utilizando [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También puedes realizar discovery automático de reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes utilizar esta técnica para descubrir más nombres de dominio cada vez que encuentres un dominio nuevo.**

### **Trackers**

Si encuentras el **mismo ID del mismo tracker** en 2 páginas diferentes, puedes suponer que **ambas páginas** están **gestionadas por el mismo equipo**.\
Por ejemplo, si ves el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que permiten buscar utilizando estos trackers y otros:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (encuentra sitios relacionados mediante analytics/trackers compartidos)

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del icono favicon? Esto es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así es como se utiliza:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
En pocas palabras, favihash nos permitirá descubrir dominios que tienen el mismo hash del icono favicon que nuestro objetivo.

![salida de favihash utilizada para descubrir dominios con el mismo hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Utiliza un hash de favicon conocido como pivote en Shodan o FOFA para encontrar otras instancias expuestas de la misma tecnología.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Así es como puedes **calcular el hash del favicon** de una web (MMH3 sobre los bytes del favicon **codificados en base64**):
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url, timeout=10)
favicon = codecs.encode(response.content, "base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
También puedes obtener hashes de favicon a escala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) y después hacer pivot en Shodan/Censys.

Trata los fingerprints de favicon como pistas y valídalos con señales contextuales.<sup>[[3]](#references)[[4]](#references)</sup>

- **Trata el hash como un indicador, no como una prueba**: MMH3 es compacto; son posibles las colisiones, los iconos reutilizados y la suplantación deliberada.
- **Sondea más que** `/favicon.ico`: inspecciona las rutas de framework/build, los archivos de manifiesto, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, las data URLs inline y las etiquetas HTML `<link rel="icon">`.
- **Los assets estáticos pueden seguir siendo accesibles detrás de controles WAF/SSO/IdP**: solicita el icono directamente y revisa `ETag`, `Last-Modified`, las redirecciones y las cabeceras de caché.
- **Valida las coincidencias con señales contextuales**: compara el título, el hash del HTML/body, las cabeceras, los subjects/SANs del certificado TLS, los componentes del producto y los puertos expuestos.
- **Agrupa por hash del HTML/body**: una plantilla consistente refuerza el fingerprint; las plantillas mezcladas sugieren un icono genérico o compartido.
- **Considera que un hash que aparece en firmas, puertos y productos no relacionados podría corresponder a un honeypot o placeholder.**
- **En objetivos ambiguos, compara una página real con una ruta inexistente**, como `/_favicon_probe_<8-hex>`; las respuestas coincidentes de hosting o parking pueden explicar el icono compartido.
- **Inicia el triage a partir de reglas de detección de Nuclei o datasets públicos** que relacionen hashes de favicon con productos y CPEs.
- **Recuerda la brecha de cobertura centrada en IP**: las superficies detrás de CDN, enrutadas mediante SNI, anycast y basadas únicamente en dominios pueden faltar en datasets similares a los de Shodan.

### **Copyright / Uniq string**

Busca dentro de las páginas web **strings que podrían compartirse entre diferentes webs de la misma organización**. El **copyright string** podría ser un buen ejemplo. Después busca ese string en **google**, en otros **browsers** o incluso en **shodan**: `shodan search http.html:"Copyright string"`

### **Tiempo de CRT**

Es habitual tener un cron job como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
para renovar todos los certificados de un servidor al mismo tiempo. Correlacionar las marcas de tiempo de los certificados o las posiciones en los logs de certificate transparency puede revelar dominios relacionados.<sup>[[6]](#references)</sup>

También usa directamente los logs de **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Información de Mail DMARC

Puedes usar una web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información de dmarc**.\
Otras herramientas útiles son [**spoofcheck**](https://github.com/BishopFox/spoofcheck) y [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un registro A abandonado puede volverse accesible cuando un proveedor cloud reasigna una IP. La investigación mencionada demuestra un flujo de trabajo oportunista que aprovisiona una instancia y correlaciona su dirección con datos de passive DNS; prueba escenarios de takeover únicamente dentro del alcance autorizado.<sup>[[7]](#references)</sup>

### **Otras formas**

Repite los pivotes de discovery aplicables cada vez que encuentres un dominio nuevo: cada resultado puede revelar nombres de certificados adicionales, relaciones de passive-DNS, coincidencias de favicon e identificadores de la organización que no eran visibles a partir de la semilla original.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Como ya conoces el nombre de la organización propietaria del espacio de IP, puedes buscar esos datos en shodan usando: `org:"Tesla, Inc."` Comprueba si los hosts encontrados contienen nuevos dominios inesperados en el certificado TLS.

Puedes acceder al **certificado TLS** de la página web principal, obtener el **nombre de la Organisation** y después buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **shodan** con el filtro: `ssl:"Tesla Motors"` o usar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)es una herramienta que busca **dominios relacionados** con un dominio principal y sus **subdominios**, bastante increíble.

**Passive DNS / Historical DNS**

Los datos de Passive DNS son excelentes para encontrar **registros antiguos y olvidados** que todavía resuelven o que pueden ser objeto de takeover. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Búsqueda de vulnerabilidades**

Comprueba si existe algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Quizás alguna empresa **esté usando un dominio** pero **haya perdido su propiedad**. Simplemente regístralo (si es suficientemente barato) e informa a la empresa.

Si encuentras algún **dominio con una IP diferente** de las que ya encontraste durante el discovery de assets, deberías realizar un **basic vulnerability scan** (usando Nessus u OpenVAS) y algún [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que estén ejecutándose, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el dominio está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del alcance; ten cuidado._

## Subdominios

> Conocemos todas las empresas dentro del alcance, todos los assets de cada empresa y todos los dominios relacionados con las empresas.

Es hora de encontrar todos los subdominios posibles de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios

### **DNS**

Intentemos obtener **subdominios** a partir de los registros **DNS**. También deberíamos probar la **Zone Transfer** (si es vulnerable, debes informarlo).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para obtener mejores resultados, configura las claves de API):

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
Hay **otras herramientas/APIs interesantes** que, aunque no estén directamente especializadas en encontrar subdominios, podrían ser útiles para encontrar subdominios, como:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Usa la API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obtener subdominios
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
- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, Wayback Machine y Common Crawl para cualquier dominio indicado.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Hacen scraping de la web buscando archivos JS y extraen subdominios de estos.
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
- [**Buscador de subdominios de Censys**](https://github.com/christophetd/censys-subdomain-finder)
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

Este proyecto ofrece **gratis todos los subdomains relacionados con programas de bug bounty**. También puedes acceder a estos datos mediante [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al scope utilizado por este proyecto: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparativa** de muchas de estas tools aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Intentemos encontrar nuevos **subdomains** haciendo brute force contra servidores DNS mediante posibles nombres de subdomains.

Para esta acción necesitarás algunas **wordlists de subdomains comunes, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Y también IPs de buenos resolvers DNS. Para generar una lista de resolvers DNS de confianza, puedes descargar los resolvers desde [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. También puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las tools más recomendadas para hacer brute force de DNS son:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera tool que realizó un brute force de DNS eficaz. Es muy rápida, pero tiende a generar falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Este creo que solo usa 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper de `massdns`, escrito en Go, que permite enumerar subdominios válidos mediante bruteforce activo, así como resolver subdominios con gestión de wildcards y soporte sencillo de entrada y salida.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): También utiliza `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar brute force de nombres de dominio de forma asíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda ronda de fuerza bruta de DNS

Después de encontrar subdominios mediante fuentes abiertas y fuerza bruta, podrías generar variaciones de los subdominios encontrados para intentar encontrar aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado los dominios y subdominios, genera permutaciones.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Genera permutaciones a partir de los dominios y subdominios.
- Puedes obtener la **wordlist** de permutaciones de goaltdns [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Dados los dominios y subdominios, genera permutaciones. Si no se indica ningún archivo de permutaciones, gotator utilizará el suyo propio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
- Puedes obtener el **wordlist** de permutaciones de altdns [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutations, mutations y alteration de subdominios. Esta herramienta hará brute force del resultado (no admite dns wild card).
- Puedes obtener la wordlist de permutations de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basándose en un dominio, **genera nuevos nombres de subdominios potenciales** según los patrones indicados para intentar descubrir más subdominios.

#### Generación de permutaciones inteligentes

- [**regulator**](https://github.com/cramppet/regulator): Aprende patrones similares a expresiones regulares a partir de los subdominios descubiertos y genera nombres candidatos para resolver.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios combinado con un algoritmo inmensamente simple pero efectivo, guiado por respuestas DNS. Utiliza un conjunto de datos de entrada proporcionado, como una wordlist personalizada o registros DNS/TLS históricos, para sintetizar con precisión más nombres de dominio correspondientes y ampliarlos aún más en un bucle, basándose en la información recopilada durante el escaneo DNS.
```
echo www | subzuf facebook.com
```
### **Flujo de descubrimiento de subdominios**

Los ejemplos de workflows de Trickest combinan OSINT, fuerza bruta de DNS y etapas de permutación para una enumeración de subdominios repetible.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Si encontraste una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios con sitios web en esa IP** buscando en **fuentes de OSINT** dominios asociados a una IP o mediante **fuerza bruta de nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Brute Force**

Si sospechas que algún subdominio puede estar oculto en un servidor web, podrías intentar hacerle brute force:

Para vhosts basados en nombres, fuzzifica el header `Host` y utiliza la autoc##alibración de ffuf para filtrar la respuesta predeterminada.<sup>[[2]](#references)</sup>
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
> Con esta técnica incluso podrías conseguir acceso a endpoints internos/ocultos.

### **CORS Brute Force**

A veces encontrarás páginas que solo devuelven el header _**Access-Control-Allow-Origin**_ cuando se establece un dominio/subdominio válido en el header _**Origin**_. En estos escenarios, puedes abusar de este comportamiento para **descubrir** nuevos **subdominios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Mientras buscas **subdomains**, presta atención para comprobar si alguno está **pointing** a algún tipo de **bucket** y, en ese caso, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, como en este punto conocerás todos los dominios dentro del scope, intenta [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Puedes **monitorizar** si se crean **new subdomains** de un dominio monitorizando los logs de **Certificate Transparency**, como hace [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Comprueba posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdomain** apunta a algún **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras algún **subdomain with an IP different** de las que ya encontraste durante el descubrimiento de assets, deberías realizar un **basic vulnerability scan** (usando Nessus u OpenVAS) y algún [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que estén ejecutándose, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el subdomain está alojado dentro de una IP que no está controlada por el cliente, por lo que no está dentro del scope; ten cuidado._

## IPs

En los pasos iniciales es posible que hayas **encontrado algunos rangos de IPs, dominios y subdomains**.\
Es hora de **recopilar todas las IPs de esos rangos** y de los **dominios/subdomains (consultas DNS).**

Usando servicios de las siguientes **free apis**, también puedes encontrar **IPs anteriores usadas por dominios y subdomains**. Estas IPs aún podrían pertenecer al cliente (y podrían permitirte encontrar [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes comprobar qué dominios apuntan a una dirección IP específica usando la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

Realiza un **port scan de todas las IPs que no pertenezcan a CDNs** (ya que probablemente no encontrarás nada interesante allí). En los servicios en ejecución descubiertos podrías **encontrar vulnerabilidades**.

**Consulta una** [**guía**](../pentesting-network/index.html) **sobre cómo escanear hosts.**

## Web servers hunting

> Hemos encontrado todas las empresas y sus assets, y conocemos los rangos de IPs, dominios y subdomains dentro del scope. Es hora de buscar web servers.

En los pasos anteriores probablemente ya hayas realizado algo de **recon de las IPs y dominios descubiertos**, por lo que es posible que ya hayas **encontrado todos los web servers posibles**. Sin embargo, si no lo has hecho, ahora veremos algunos **trucos rápidos para buscar web servers** dentro del scope.

Ten en cuenta que esto estará **orientado al descubrimiento de web apps**, por lo que también deberías **realizar el vulnerability** y el **port scanning** (**si el scope lo permite**).

Puedes encontrar [**aquí un método rápido**](../pentesting-network/index.html#http-port-discovery) para descubrir **ports open** relacionados con **web** servers usando [**masscan**].\
Otra herramienta sencilla para buscar web servers es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Solo tienes que pasar una lista de dominios y la herramienta intentará conectarse al port 80 (http) y al 443 (https). Además, puedes indicar que pruebe otros ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Ahora que has descubierto **todos los servidores web** presentes en el scope (entre las **IPs** de la empresa y todos los **dominios** y **subdominios**) probablemente **no sepas por dónde empezar**. Así que vamos a simplificarlo y comenzar tomando screenshots de todos ellos. Con solo **echar un vistazo** a la **página principal** puedes encontrar endpoints **extraños** que son más **propensos** a ser **vulnerables**.

Para llevar a cabo la idea propuesta puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) sobre todos los **screenshots** para indicarte cuáles **probablemente contengan vulnerabilidades** y cuáles no.

## Public Cloud Assets

Para encontrar posibles cloud assets pertenecientes a una empresa, deberías **empezar con una lista de keywords que identifiquen a esa empresa**. Por ejemplo, para una empresa de crypto podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás wordlists de **palabras comunes usadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Después, con esas palabras deberías generar **permutations** (consulta la [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para obtener más información).

Con las wordlists resultantes podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que, al buscar Cloud Assets, deberías **buscar algo más que solo buckets en AWS**.

### **Looking for vulnerabilities**

Si encuentras cosas como **buckets abiertos o cloud functions expuestas**, deberías **acceder a ellas** e intentar ver qué te ofrecen y si puedes abusar de ellas.

## Emails

Con los **dominios** y **subdominios** dentro del scope básicamente tienes todo lo que **necesitas para empezar a buscar emails**. Estas son las **APIs** y **herramientas** que mejor me han funcionado para encontrar emails de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Looking for vulnerabilities**

Los emails te serán útiles más adelante para hacer **brute-force de logins web y servicios de autenticación** (como SSH). También son necesarios para hacer **phishings**. Además, estas APIs te proporcionarán aún más **información sobre la persona** detrás del email, lo que resulta útil para la campaña de phishing.

## Credential Leaks

Con los **dominios,** **subdominios** y **emails** puedes empezar a buscar credenciales leaked en el pasado pertenecientes a esos emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Si encuentras credenciales **leaked válidas**, es una victoria muy fácil.

## Secrets Leaks

Los credential leaks están relacionados con hacks de empresas en los que **se filtró y vendió información sensible**. Sin embargo, las empresas pueden verse afectadas por **otros leaks** cuya información no se encuentra en esas bases de datos:

### Github Leaks

Las credenciales y APIs pueden filtrarse en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan para esa empresa de Github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repos públicos** de una **organización** y de sus **desarrolladores**, y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también puede usarse para ejecutar **gitleaks** contra todo el **texto** proporcionado por las **URLs pasadas** como entrada, ya que a veces las **páginas web también contienen secretos**.

#### Github Dorks

Consulta la [página de GitHub dorks and leaks](github-leaked-secrets.md) para encontrar posibles **GitHub dorks** que buscar en la organización.

### Pastes Leaks

A veces los atacantes o simplemente los trabajadores **publican contenido de la empresa en un paste site**. Esto puede contener o no **información sensible**, pero resulta muy interesante buscarla.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar simultáneamente en más de 80 paste sites.

### Google Dorks

Los antiguos pero efectivos Google dorks siempre son útiles para encontrar **información expuesta que no debería estar ahí**. El único problema es que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de posibles consultas que no puedes ejecutar manualmente. Por tanto, puedes elegir tus 10 favoritas o usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que intentan ejecutar toda la base de datos usando el navegador normal de Google nunca terminarán, ya que Google te bloqueará muy rápidamente._

### **Looking for vulnerabilities**

Si encuentras credenciales **leaked válidas** o tokens de API, es una victoria muy fácil.

## Public Code Vulnerabilities

Si descubres que la empresa tiene **código open-source**, puedes **analizarlo** y buscar **vulnerabilidades** en él.

**Dependiendo del lenguaje**, existen diferentes **herramientas** que puedes usar; consulta la lista de [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

También existen servicios gratuitos que permiten **escanear repositorios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** encontradas por los bug hunters se encuentran dentro de **aplicaciones web**, así que en este punto me gustaría hablar sobre una **metodología de testing de aplicaciones web**, cuya información puedes [**encontrar aquí**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, resultan útiles para implementarlos en **workflows y obtener información web inicial.**

## Recapitulation

> ¡Enhorabuena! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos después).

Ya has:

1. Encontrado todas las **empresas** dentro del scope
2. Encontrado todos los **assets** pertenecientes a las empresas (y realizado algún vuln scan si está dentro del scope)
3. Encontrado todos los **dominios** pertenecientes a las empresas
4. Encontrado todos los **subdominios** de los dominios (¿algún subdomain takeover?)
5. Encontrado todas las **IPs** (de y **no pertenecientes a CDNs**) dentro del scope.
6. Encontrado todos los **servidores web** y tomado un **screenshot** de ellos (¿hay algo extraño que merezca una revisión más profunda?)
7. Encontrado todos los **potential public cloud assets** pertenecientes a la empresa.
8. Encontrado **emails**, **credential leaks** y **secret leaks** que podrían darte una **gran victoria muy fácilmente**.
9. Realizado **pentesting de todas las webs encontradas**

## **Full Recon Automatic Tools**

Existen varias herramientas que realizarán parte de las acciones propuestas contra un scope determinado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antiguo y no actualizado

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
