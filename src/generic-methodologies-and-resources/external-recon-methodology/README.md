# Metodología de reconocimiento externo

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de activos

> Te han dicho que todo lo que pertenece a una empresa está dentro del scope, y quieres averiguar qué posee realmente esta empresa.

El objetivo de esta fase es obtener todas las **empresas propiedad de la empresa principal** y, después, todos los **activos** de esas empresas. Para ello, vamos a:<sup>[[1]](#references)</sup>

1. Encontrar las adquisiciones de la empresa principal; esto nos indicará qué empresas están dentro del scope.
2. Encontrar el ASN (si lo hay) de cada empresa; esto nos indicará los rangos de IP que posee cada una.
3. Usar búsquedas inversas de whois para buscar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer recursivamente).
4. Usar otras técnicas, como los filtros `org`y `ssl`de shodan, para buscar otros activos (el truco de `ssl` se puede aplicar recursivamente).

### **Adquisiciones**

En primer lugar, necesitamos saber **qué otras empresas son propiedad de la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal** y hacer **clic** en "**acquisitions**". Allí verás otras empresas adquiridas por la principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **acquisitions**.\
En el caso de las empresas públicas, consulta las **presentaciones SEC/EDGAR**, las páginas de **relaciones con inversores** o los registros mercantiles locales (por ejemplo, **Companies House** en el Reino Unido).\
Para consultar estructuras corporativas globales y filiales, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Bien, a estas alturas deberías conocer todas las empresas dentro del scope. Veamos cómo encontrar sus activos.

### **ASN**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** está compuesto por **bloques** de **direcciones IP** que tienen una política claramente definida para acceder a redes externas y que administra una sola organización, aunque puede estar formado por varios operadores.

Es interesante averiguar si a la **empresa se le ha asignado algún ASN** para encontrar sus **rangos de IP**. Sería interesante realizar una **prueba de vulnerabilidades** contra todos los **hosts** dentro del **scope** y **buscar dominios** dentro de estas IP.\
Puedes **buscar** por **nombre** de empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Según la región de la empresa, estos enlaces pueden ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todos modos, probablemente toda la información** útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.

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

También puedes encontrar los rangos de IP de una organización usando [ASNLookup](https://asnlookup.com/), que tiene un nivel gratuito limitado de API.

### **Búsqueda de vulnerabilidades**

En este punto conocemos **todos los activos dentro del alcance**, así que, si tienes autorización, podrías ejecutar algún **escáner de vulnerabilidades** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) en todos los hosts.\
También podrías ejecutar algunos [**escaneos de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys o ZoomEye **para encontrar** puertos **abiertos y, según lo que encuentres, deberías** consultar este libro para ver cómo hacer pentesting a varios de los posibles servicios en ejecución.\
**Además, cabe mencionar que también puedes preparar algunas listas de** nombres de usuario **y** contraseñas **predeterminados e intentar hacer** bruteforce a los servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Conocemos todas las empresas dentro del alcance y sus activos; es hora de encontrar los dominios dentro del alcance.

_Ten en cuenta que con las técnicas propuestas a continuación también puedes encontrar subdominios y no debes subestimar esa información._

En primer lugar, deberías buscar el **dominio principal** de cada empresa. Por ejemplo, para _Tesla Inc._ sería _tesla.com_.

### **Reverse DNS**

Como has encontrado todos los rangos de IP de los dominios, podrías intentar realizar **búsquedas de DNS inverso** en esas **IP para encontrar más dominios dentro del alcance**. Intenta usar algún servidor DNS de la víctima o un servidor DNS conocido (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Para que esto funcione, el administrador debe habilitar manualmente el PTR.\
También puedes usar [SecurityTrails](https://securitytrails.com/) para obtener esta información, aunque los datos históricos de DNS requieren un plan de pago.\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar las búsquedas inversas y el enriquecimiento de datos.

### **Reverse Whois (loop)**

En un **whois** puedes encontrar mucha **información** interesante, como el **nombre de la organización**, la **dirección**, los **correos electrónicos**, los números de teléfono... Pero aún más interesante es que puedes encontrar **más activos relacionados con la empresa** si realizas **búsquedas de reverse whois usando cualquiera de esos campos** (por ejemplo, otros registros whois en los que aparezca el mismo correo electrónico).\
Puedes usar herramientas online como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web y API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - Interfaz web **gratuita**; API de pago.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - De pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - No es gratis (solo **100 búsquedas gratis**)
- [https://www.domainiq.com/](https://www.domainiq.com) - No es gratis
- [https://securitytrails.com/](https://securitytrails.com/) - Acceso gratuito limitado a la API para DNS y subdominios actuales; las búsquedas históricas e inversas requieren un plan de pago.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 créditos gratuitos de API al registrarse; después, de pago.

Puedes automatizar esta tarea con [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También puedes realizar búsquedas automáticas de reverse whois con [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres uno nuevo.**

### **Rastreadores**

Si encuentras el **mismo ID del mismo rastreador** en 2 páginas diferentes, puedes suponer que **ambas páginas** están **administradas por el mismo equipo**.\
Por ejemplo, si ves el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que permiten buscar estos rastreadores y otros elementos:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Servicio web y API **de pago** ([precios](https://www.stackscan.com/pricing)); actualmente no se anuncia ningún plan gratuito. Pivotar a partir de cualquier recurso servido, no solo de los ID de rastreadores: una ruta de script, el nombre de un bundle autoalojado o el host desde el que se carga un recurso, para obtener todos los sitios que lo incluyen

La API devuelve el stack de un único dominio, lo que resulta útil para confirmar que un recurso candidato pertenece al mismo entorno:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Devuelve cada tecnología detectada junto con su categoría. El pivotado de activos actualmente solo está disponible para web; la API permite consultas por dominio.

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del icono favicon? Eso es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así se usa:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Resultados de Favihash usados para descubrir dominios que comparten un hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permitirá descubrir dominios que tienen el mismo hash del icono favicon que nuestro objetivo.

![Salida de favihash usada para descubrir dominios con el mismo hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Usa un hash de favicon conocido como pivot en Shodan o FOFA para encontrar otras instancias expuestas de la misma tecnología.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Así puedes **calcular el hash del favicon** de un sitio web (MMH3 sobre los bytes del favicon **codificados en base64**):

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

También puedes obtener hashes de favicon a escala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) y luego pivotar en Shodan/Censys.

Trata las huellas de favicon como pistas y valídalas con señales adicionales.<sup>[[3]](#references)[[4]](#references)</sup>

- **Trata el hash como un indicador, no como una prueba**: MMH3 es compacto; son posibles las colisiones, los iconos reutilizados y la suplantación deliberada.
- **Sondea más rutas que** `/favicon.ico`: inspecciona rutas de frameworks y compilaciones, archivos de manifiesto, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, URL de datos en línea y etiquetas HTML `<link rel="icon">`.
- **Los recursos estáticos pueden seguir siendo accesibles tras los controles de WAF/SSO/IdP**: solicita el icono directamente y revisa `ETag`, `Last-Modified`, las redirecciones y los encabezados de caché.
- **Valida las coincidencias con señales adicionales**: compara el título, el hash del HTML/cuerpo, los encabezados, los nombres de los sujetos y SAN del certificado TLS, los componentes del producto y los puertos expuestos.
- **Agrupa por hash de HTML/cuerpo**: una plantilla coherente refuerza la huella; las plantillas variadas sugieren un icono genérico o compartido.
- **Trata un hash que aparezca en firmas, puertos y productos no relacionados como un posible honeypot o marcador de posición.**
- **En objetivos ambiguos, compara una página real con una ruta inexistente**, como `/_favicon_probe_<8-hex>`; las respuestas coincidentes de hosting o de páginas aparcadas pueden explicar el icono compartido.
- **Inicia el triaje con reglas de detección de Nuclei o conjuntos de datos públicos** que relacionen hashes de favicon con productos y CPE.
- **Recuerda la brecha de cobertura centrada en IP**: las superficies detrás de CDN, enrutadas por SNI, anycast y solo por dominio pueden no aparecer en conjuntos de datos similares a Shodan.

### **Copyright / cadena única**

Busca en las páginas web **cadenas que podrían compartirse entre distintos sitios de una misma organización**. La **cadena de copyright** podría ser un buen ejemplo. Luego busca esa cadena en **Google**, en otros **navegadores** o incluso en **Shodan**: `shodan search http.html:"Copyright string"`

### **Hora de CRT**

Es común tener un trabajo cron como el siguiente

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

para renovar todos los certificados de un servidor al mismo tiempo. Correlacionar las marcas de tiempo de los certificados o las posiciones en los registros de Certificate Transparency puede revelar dominios relacionados.<sup>[[6]](#references)</sup>

También puedes consultar directamente los registros de **Certificate Transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Información DMARC del correo

Puedes usar un sitio web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información DMARC**.\
Otro servicio útil es [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un registro A abandonado puede volver a ser accesible cuando un proveedor cloud reasigna una IP. La investigación citada demuestra un flujo de trabajo oportunista que aprovisiona una instancia y correlaciona su dirección con datos de DNS pasivo; prueba escenarios de takeover solo dentro del alcance autorizado.<sup>[[7]](#references)</sup>

### **Otras formas**

Repite los pivotes de descubrimiento aplicables cada vez que encuentres un dominio nuevo: cada resultado puede revelar nombres de certificados adicionales, relaciones de DNS pasivo, coincidencias de favicon e identificadores de organización que no eran visibles en el dominio inicial.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Como ya conoces el nombre de la organización propietaria del espacio de IP, puedes buscar esos datos en Shodan usando: `org:"Tesla, Inc."` Revisa los hosts encontrados para detectar dominios nuevos e inesperados en el certificado TLS.

Puedes acceder al **certificado TLS** de la página web principal, obtener el **nombre de la organización** y luego buscar ese nombre dentro de los **certificados TLS** de todas las páginas web conocidas por **Shodan** usando el filtro: `ssl:"Tesla Motors"` o una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)es una herramienta que busca **dominios relacionados** con un dominio principal y sus **subdominios**; es increíble.

**DNS pasivo / DNS histórico**

Los datos de DNS pasivo son excelentes para encontrar **registros antiguos y olvidados** que todavía resuelven o que pueden ser objeto de takeover. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Búsqueda de vulnerabilidades**

Comprueba si hay algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Puede que alguna empresa **esté usando un dominio** pero **haya perdido la propiedad**. Simplemente regístralo (si es lo suficientemente barato) e informa a la empresa.

Si encuentras algún **dominio con una IP diferente** de las que ya encontraste durante el descubrimiento de activos, deberías realizar un **análisis básico de vulnerabilidades** (con Nessus u OpenVAS) y un [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Según los servicios que estén en ejecución, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el dominio está alojado en una IP que no controla el cliente, por lo que queda fuera del alcance; ten cuidado._

## Subdominios

> Conocemos todas las empresas incluidas en el alcance, todos los activos de cada empresa y todos los dominios relacionados con ellas.

Es hora de encontrar todos los subdominios posibles de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas de las herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios.

### **DNS**

Intentemos obtener **subdominios** de los registros **DNS**. También deberíamos intentar una **transferencia de zona** (si es vulnerable, deberías informarlo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Para consultar APIs y plataformas que cubren infraestructura, reputación, registros de brechas y enriquecimiento más allá del descubrimiento de subdominios, consulta el [catálogo de APIs de reconocimiento e inteligencia de amenazas](reconnaissance-and-threat-intelligence-apis.md).

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

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Hay **otras herramientas/APIs interesantes** que, aunque no estén especializadas directamente en encontrar subdominios, podrían ser útiles para encontrarlos, como:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita

```bash
curl https://ip.thc.org/tesla.com
```

- [**API gratuito de AnubisDB**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) API gratuito

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

- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, Wayback Machine y Common Crawl para cualquier dominio.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Rastrean la web en busca de archivos JS y extraen subdominios de ellos.

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

- [**SecurityTrails**](https://securitytrails.com/) ofrece acceso gratuito limitado a la API para consultar datos actuales de DNS y subdominios; los datos históricos de DNS/IP requieren un plan de pago.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Este proyecto ofrece **gratis todos los subdominios relacionados con programas de bug bounty**. También puedes acceder a estos datos usando [chaospy](https://github.com/Moaaz-0x/chaospy) o incluso consultar el scope que usa este proyecto: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Aquí puedes encontrar una **comparación** de muchas de estas herramientas: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Intentemos encontrar nuevos **subdominios** haciendo brute force contra servidores DNS con posibles nombres de subdominio.

Para realizar esta acción necesitarás algunas **wordlists comunes de subdominios, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

También necesitarás IPs de buenos resolvers DNS. Para generar una lista de resolvers DNS de confianza, puedes descargar los resolvers de [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. O puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para DNS brute-force son:

- [**massdns**](https://github.com/blechschmidt/massdns): Fue la primera herramienta que realizó un DNS brute-force eficaz. Es muy rápida, aunque es propensa a generar falsos positivos.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Este creo que solo usa 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper de `massdns`, escrito en Go, que permite enumerar subdominios válidos mediante fuerza bruta activa, así como resolver subdominios con gestión de wildcard y soporte sencillo para entrada y salida.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): También usa `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar brute force de nombres de dominio de forma asíncrona.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Segunda ronda de brute-force de DNS

Después de encontrar subdominios mediante fuentes abiertas y brute-force, puedes generar variaciones de los subdominios encontrados para intentar encontrar aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Genera permutaciones a partir de los dominios y subdominios.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Dada una lista de dominios y subdominios, genera permutaciones.
  - Puedes obtener la **wordlist** de permutaciones de goaltdns [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Dado un conjunto de dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará el suyo.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
  - Puedes obtener la **wordlist** de permutaciones de altdns [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta hará brute force del resultado (no admite wildcard DNS).
  - Puedes obtener la wordlist de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** A partir de un dominio, **genera posibles nombres de subdominios nuevos** basándose en los patrones indicados para intentar descubrir más subdominios.

#### Generación inteligente de permutaciones

- [**regulator**](https://github.com/cramppet/regulator): Aprende patrones similares a regex a partir de los subdominios descubiertos y genera nombres candidatos para resolver.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios que utiliza un algoritmo guiado por respuestas DNS extremadamente simple pero eficaz. Usa un conjunto de datos de entrada, como una wordlist personalizada o registros históricos de DNS/TLS, para sintetizar con precisión más nombres de dominio relacionados y ampliarlos aún más en un bucle, basándose en la información recopilada durante el escaneo DNS.

```
echo www | subzuf facebook.com
```

### **Flujo de descubrimiento de subdominios**

Los ejemplos de workflows de Trickest combinan OSINT, DNS brute force y etapas de permutación para enumerar subdominios de forma repetible.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Si encontraste una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios con sitios web en esa IP** buscando en **fuentes OSINT** dominios asociados a una IP o haciendo **brute force de nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Brute Force**

Si sospechas que algún subdominio puede estar oculto en un servidor web, podrías intentar descubrirlo mediante brute force:

Para vhosts basados en nombres, aplica fuzzing al encabezado `Host` y usa la autocorrelación de ffuf para filtrar la respuesta predeterminada.<sup>[[2]](#references)</sup>

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
> Con esta técnica, incluso podrías acceder a endpoints internos/ocultos.

### **CORS Brute Force**

A veces encontrarás páginas que solo devuelven el encabezado _**Access-Control-Allow-Origin**_ cuando se establece un dominio/subdominio válido en el encabezado _**Origin**_. En estos casos, puedes aprovechar este comportamiento para **descubrir** nuevos **subdominios**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Fuerza bruta de buckets**

Mientras buscas **subdominios**, presta atención para ver si **apuntan** a algún tipo de **bucket** y, en ese caso, [**comprueba los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, como a estas alturas ya conocerás todos los dominios dentro del alcance, intenta [**probar por fuerza bruta posibles nombres de buckets y comprobar los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorización**

Puedes **monitorizar** si se crean **nuevos subdominios** de un dominio mediante la monitorización de los registros de **Certificate Transparency**, como hace [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Comprueba si hay posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** apunta a algún **bucket de S3**, [**comprueba los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras algún **subdominio con una IP diferente** de las que ya encontraste durante el descubrimiento de activos, deberías realizar un **análisis básico de vulnerabilidades** (con Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Según los servicios que estén en ejecución, puedes encontrar en **este libro algunos trucos para «atacarlos»**.\
_Ten en cuenta que, a veces, el subdominio está alojado en una IP que no controla el cliente, así que no está dentro del alcance; ten cuidado._

## IPs

En los pasos iniciales quizá hayas **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recopilar todas las IPs de esos rangos** y de los **dominios/subdominios (consultas DNS).**

Mediante servicios como los siguientes, también puedes encontrar **IPs anteriores utilizadas por dominios y subdominios**. Es posible que el cliente todavía sea el propietario de estas IPs (y que te permitan encontrar [**bypasses de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (los datos históricos de DNS/IP requieren un plan de pago)

También puedes buscar dominios que apunten a una dirección IP específica con la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host).

### **Búsqueda de vulnerabilidades**

**Escanea los puertos de todas las IPs que no pertenezcan a CDNs** (ya que es muy probable que no encuentres nada interesante allí). En los servicios en ejecución que descubras, quizá **puedas encontrar vulnerabilidades**.

**Encuentra una** [**guía**](../pentesting-network/index.html) **sobre cómo escanear hosts.**

## Búsqueda de servidores web

> Hemos encontrado todas las empresas y sus activos, y conocemos los rangos de IP, los dominios y los subdominios dentro del alcance. Es hora de buscar servidores web.

En los pasos anteriores probablemente ya hayas realizado algo de **reconocimiento de las IPs y los dominios descubiertos**, así que quizá **ya hayas encontrado todos los posibles servidores web**. Sin embargo, si no lo has hecho, ahora veremos algunos **trucos rápidos para buscar servidores web** dentro del alcance.

Ten en cuenta que esto estará **orientado al descubrimiento de aplicaciones web**, por lo que también deberías **realizar el análisis de vulnerabilidades** y el **escaneo de puertos** (**si el alcance lo permite**).

Puedes encontrar [**aquí un método rápido para descubrir puertos abiertos**](../pentesting-network/index.html#http-port-discovery) relacionados con servidores **web** usando [**masscan**](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta sencilla para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Solo tienes que pasarle una lista de dominios e intentará conectarse a los puertos 80 (http) y 443 (https). Además, puedes indicar que pruebe otros puertos:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** presentes dentro del alcance (entre las **IP** de la empresa y todos sus **dominios** y **subdominios**), probablemente **no sepas por dónde empezar**. Así que simplifiquémoslo y empecemos simplemente por tomar capturas de pantalla de todos ellos. Con solo **echar un vistazo** a la **página principal**, puedes encontrar endpoints **extraños** que tienen más **probabilidades** de ser **vulnerables**.

Para llevar a cabo esta idea, puedes usar [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, luego podrías usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analizar todas las **capturas de pantalla** e indicarte **cuáles probablemente contengan vulnerabilidades** y cuáles no.

## Activos en la nube pública

Para encontrar posibles activos en la nube que pertenezcan a una empresa, deberías **empezar con una lista de palabras clave que la identifiquen**. Por ejemplo, para una empresa crypto podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás listas de palabras con **palabras comunes usadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Luego, con esas palabras, deberías generar **permutaciones** (consulta [**Segunda ronda de DNS Brute-Force**](#second-dns-bruteforce-round) para más información).

Con las listas de palabras resultantes, podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que al buscar activos en la nube deberías b**uscar algo más que buckets en AWS**.

### **Búsqueda de vulnerabilidades**

Si encuentras cosas como **buckets abiertos o funciones cloud expuestas**, deberías **acceder a ellas** e intentar ver qué ofrecen y si puedes abusar de ellas.

## Correos electrónicos

Con los **dominios** y **subdominios** dentro del alcance, básicamente ya tienes todo lo que **necesitas para empezar a buscar correos electrónicos**. Estas son las **API** y **herramientas** que mejor me han funcionado para encontrar correos electrónicos de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Búsqueda de vulnerabilidades**

Los correos electrónicos te serán útiles más adelante para **hacer brute-force de inicios de sesión web y servicios de autenticación** (como SSH). También son necesarios para **phishing**. Además, estas API te darán aún más **información sobre la persona** detrás del correo electrónico, lo que resulta útil para la campaña de phishing.

## Filtraciones de credenciales

Con los **dominios,** **subdominios** y **correos electrónicos**, puedes empezar a buscar credenciales filtradas en el pasado que pertenezcan a esas direcciones:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales **filtradas válidas**, es una victoria muy fácil.

## Filtraciones de secretos

Las filtraciones de credenciales están relacionadas con hackeos de empresas en los que **se filtró y vendió información confidencial**. Sin embargo, las empresas pueden verse afectadas por **otras filtraciones** cuya información no está en esas bases de datos:

### Filtraciones de Github

Es posible que se filtren credenciales y API en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan en esa empresa de github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repositorios públicos** de una **organización** y de sus **desarrolladores**, y ejecutar [**gitleaks**](https://github.com/gitleaks/gitleaks) sobre ellos automáticamente.

**Leakos** también puede usarse para ejecutar **gitleaks** contra todo el **texto** de las **URL proporcionadas**, ya que a veces **las páginas web también contienen secretos**.

#### Github Dorks

Consulta la [página de GitHub dorks y filtraciones](github-leaked-secrets.md) para ver posibles **GitHub dorks** que puedes buscar en la organización.

### Filtraciones en pastes

A veces los atacantes, o simplemente los trabajadores, **publican contenido de la empresa en un sitio de paste**. Puede que contenga **información confidencial** o no, pero resulta muy interesante buscarla.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 sitios de paste al mismo tiempo.

### Google Dorks

Los viejos pero valiosos Google dorks siempre son útiles para encontrar **información expuesta que no debería estar ahí**. El único problema es que [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de consultas posibles que no puedes ejecutar manualmente. Así que puedes elegir tus 10 favoritas o usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que intentan ejecutar toda la base de datos usando el navegador normal de Google nunca terminarán, ya que Google te bloqueará muy pronto._

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales o tokens de API **filtrados válidos**, es una victoria muy fácil.

## Vulnerabilidades en código público

Si descubres que la empresa tiene **código open source**, puedes **analizarlo** y buscar **vulnerabilidades**.

**Según el lenguaje**, hay distintas **herramientas** que puedes usar; consulta la lista de [herramientas de revisión de código fuente](../../network-services-pentesting/pentesting-web/code-review-tools.md).

También hay servicios gratuitos que permiten **analizar repositorios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Metodología de Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** que encuentran los bug hunters se encuentran en **aplicaciones web**, así que en este punto me gustaría hablar de una **metodología de pruebas de aplicaciones web**. Puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Herramientas open source de escáneres web automatizados**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, resultan útiles para implementarlas en **workflows y obtener información web inicial**.

## Recapitulación

> ¡Enhorabuena! Llegados a este punto, ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos adelante).

Así que ya has:

1. Encontrado todas las **empresas** dentro del alcance
2. Encontrado todos los **activos** pertenecientes a las empresas (y realizado algunos análisis de vulnerabilidades si están dentro del alcance)
3. Encontrado todos los **dominios** pertenecientes a las empresas
4. Encontrado todos los **subdominios** de los dominios (¿hay algún subdomain takeover?)
5. Encontrado todas las **IP** (de **CDN y no de CDN**) dentro del alcance.
6. Encontrado todos los **servidores web** y tomado una **captura de pantalla** de ellos (¿algo extraño que merezca un análisis más profundo?)
7. Encontrado todos los **posibles activos en la nube pública** pertenecientes a la empresa.
8. **Correos electrónicos**, **filtraciones de credenciales** y **filtraciones de secretos** que podrían darte una **gran victoria muy fácilmente**.
9. **Pentesting de todos los sitios web que encontraste**

## **Herramientas automáticas completas de Recon**

Existen varias herramientas que realizan parte de las acciones propuestas contra un alcance determinado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antigua y sin actualizar

## References

- [1] [Jason Haddix – La metodología del Bug Hunter v4.0: edición de Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sobre Favicons: de los iconos del navegador a la inteligencia de superficie de ataque](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Uso ofensivo de favicon.ico para BugBounties, OSINT y demás](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Descubrimiento de dominios mediante un ataque de correlación temporal a Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Toma de control pasiva: descubriendo (y emulando) una costosa campaña de subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: un método único de enumeración de subdominios](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Flujo de trabajo completo para descubrir subdominios, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Descubrimiento completo de subdominios mediante brute-force con el flujo de trabajo automatizado de Trickest, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Captura de pantalla de la salida de favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
