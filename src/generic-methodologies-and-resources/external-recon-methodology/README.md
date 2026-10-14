# Metodología de reconocimiento externo

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de activos

> Te dijeron que todo lo que pertenece a cierta empresa está dentro del alcance, y quieres averiguar qué posee realmente esa empresa.

El objetivo de esta fase es obtener todas las **empresas que pertenecen a la empresa principal** y, después, todos los **activos** de esas empresas. Para ello, vamos a:<sup>[[1]](#references)</sup>

1. Encontrar las adquisiciones de la empresa principal; esto nos dará las empresas dentro del alcance.
2. Encontrar el ASN (si lo hay) de cada empresa; esto nos dará los rangos de IP que posee cada empresa.
3. Usar búsquedas inversas de Whois para encontrar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer de forma recursiva).
4. Usar otras técnicas como los filtros `org` y `ssl` de shodan para buscar otros activos (el truco de `ssl` se puede aplicar de forma recursiva).

### **Adquisiciones**

En primer lugar, necesitamos saber **qué otras empresas pertenecen a la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal** y **hacer clic** en "**adquisiciones**". Allí verás otras empresas adquiridas por la empresa principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **adquisiciones**.\
En el caso de las empresas que cotizan en bolsa, consulta las **declaraciones ante la SEC/EDGAR**, las páginas de **relaciones con inversores** o los registros mercantiles locales (p. ej., **Companies House** en el Reino Unido).\
Para consultar estructuras corporativas globales y filiales, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Bien, en este punto deberías conocer todas las empresas dentro del alcance. Veamos cómo encontrar sus activos.

### **ASN**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consta de **bloques** de **direcciones IP** que tienen una política claramente definida para acceder a redes externas y son administrados por una sola organización, aunque pueden estar compuestos por varios operadores.

Es interesante averiguar si a la **empresa se le ha asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **prueba de vulnerabilidades** en todos los **hosts** dentro del **alcance** y **buscar dominios** en estas IP.\
Puedes **buscar** por **nombre** de empresa, **IP** o **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Según la región de la empresa, estos enlaces pueden ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). En cualquier caso, probablemente toda la información** útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Además, la enumeración de [**BBOT**](https://github.com/blacklanternsecurity/bbot) agrega y resume los ASNs automáticamente al final del escaneo.

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

Puedes encontrar los rangos de IP de una organización usando también [http://asnlookup.com/](http://asnlookup.com) (tiene una API gratuita).\
Puedes encontrar la IP y el ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Búsqueda de vulnerabilidades**

En este punto conocemos **todos los assets dentro del scope**, así que, si tienes permiso, podrías ejecutar algún **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) en todos los hosts.\
También podrías ejecutar algunos [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys o ZoomEye **para encontrar** puertos abiertos **y, según lo que encuentres, deberías** consultar este libro para saber cómo hacer pentest a varios de los posibles servicios en ejecución.\
**También vale la pena mencionar que puedes preparar listas de** usernames **y** passwords **predeterminados e intentar hacer** bruteforce **a los servicios con** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Ya conocemos todas las empresas dentro del scope y sus assets; es hora de encontrar los dominios dentro del scope.

_Ten en cuenta que con las técnicas propuestas a continuación también puedes encontrar subdomains y que no debes subestimar esa información._

Primero, deberías buscar el **dominio principal** de cada empresa. Por ejemplo, para _Tesla Inc._ sería _tesla.com_.

### **Reverse DNS**

Como ya has encontrado todos los rangos de IP de los dominios, podrías intentar hacer **reverse DNS lookups** en esas **IP para encontrar más dominios dentro del scope**. Prueba a usar algún DNS server de la víctima o algún DNS server conocido (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Para que esto funcione, el administrador debe habilitar manualmente el PTR.\
También puedes usar una herramienta en línea para obtener esta información: [http://ptrarchive.com/](http://ptrarchive.com).\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar las búsquedas inversas y el enriquecimiento de datos.

### **Reverse Whois (loop)**

En un **whois** puedes encontrar mucha **información** interesante, como el **nombre de la organización**, la **dirección**, los **correos electrónicos**, los números de teléfono... Pero lo más interesante es que puedes encontrar **más activos relacionados con la empresa** si realizas **búsquedas inversas de whois usando cualquiera de esos campos** (por ejemplo, otros registros whois donde aparece el mismo correo electrónico).\
Puedes usar herramientas en línea como:

- [https://ip.thc.org/](https://ip.thc.org/) - **Gratis** (Web y API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratis**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratis**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratis**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **gratis**, API de pago.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - De pago
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - De pago (solo **100 búsquedas gratis**)
- [https://www.domainiq.com/](https://www.domainiq.com) - De pago
- [https://securitytrails.com/](https://securitytrails.com/) - De pago (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - De pago (API)

Puedes automatizar esta tarea usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También puedes realizar búsquedas inversas de whois de forma automática con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres un dominio nuevo.**

### **Trackers**

Si encuentras el **mismo ID del mismo tracker** en 2 páginas diferentes, puedes suponer que **ambas páginas** están **gestionadas por el mismo equipo**.\
Por ejemplo, si ves el mismo **ID de Google Analytics** o el mismo **ID de Adsense** en varias páginas.

Hay algunas páginas y herramientas que te permiten buscar usando estos trackers y otros datos:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (encuentra sitios relacionados mediante analytics/trackers compartidos)
- [**StackScan**](https://www.stackscan.com) - **Plan gratuito** (Web y API). Permite pivotar sobre cualquier activo servido, no solo IDs de trackers: una ruta de script, el nombre de un bundle autoalojado o el host desde el que se carga un activo, y devuelve todos los sitios que lo contienen

La API devuelve el stack de un único dominio, lo que resulta útil para confirmar que un activo candidato pertenece al mismo entorno:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Devuelve cada tecnología detectada junto con su categoría. El asset pivoting actualmente solo está disponible para la web; la API permite búsquedas por dominio.

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del icono favicon? Eso es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así se usa:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Resultados de Favihash usados para descubrir dominios que comparten un hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, favihash nos permite descubrir dominios que tienen el mismo hash de favicon que nuestro objetivo.

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

También puedes obtener hashes de favicon a gran escala con [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) y luego hacer pivot en Shodan/Censys.

Trata las huellas de favicon como pistas y valídalas con señales del entorno.<sup>[[3]](#references)[[4]](#references)</sup>

- **Trata el hash como un indicador, no como una prueba**: MMH3 es compacto; son posibles las colisiones, los iconos reutilizados y la suplantación deliberada.
- **Busca más allá de** `/favicon.ico`: inspecciona rutas de framework/build, archivos de manifiesto, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, URL de datos en línea y etiquetas HTML `<link rel="icon">`.
- **Los recursos estáticos pueden seguir siendo accesibles tras controles WAF/SSO/IdP**: solicita el icono directamente y revisa `ETag`, `Last-Modified`, las redirecciones y los encabezados de caché.
- **Valida las coincidencias con señales del entorno**: compara el título, el hash del HTML/cuerpo, los encabezados, los sujetos/SAN del certificado TLS, los componentes del producto y los puertos expuestos.
- **Agrupa por hash del HTML/cuerpo**: una plantilla coherente refuerza la huella; las plantillas mezcladas sugieren un icono genérico o compartido.
- **Trata un hash presente en firmas, puertos y productos no relacionados como un posible honeypot o marcador de posición.**
- **En objetivos ambiguos, compara una página real con una ruta inexistente**, como `/_favicon_probe_<8-hex>`; las respuestas coincidentes del proveedor de hosting o de una página aparcada pueden explicar el icono compartido.
- **Inicia el análisis con reglas de detección de Nuclei o conjuntos de datos públicos** que relacionen hashes de favicon con productos y CPE.
- **Recuerda la brecha de cobertura centrada en IP**: las superficies detrás de CDN, enrutadas por SNI, anycast y solo de dominio pueden faltar en conjuntos de datos similares a los de Shodan.

### **Copyright / cadena única**

Busca en las páginas web **cadenas que podrían compartirse entre distintos sitios web de una misma organización**. La **cadena de copyright** puede ser un buen ejemplo. Luego busca esa cadena en **google**, en otros **navegadores** o incluso en **shodan**: `shodan search http.html:"Copyright string"`

### **Hora CRT**

Es común tener un cron job como este

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

para renovar todos los certificados de un servidor al mismo tiempo. Correlacionar las marcas de tiempo de los certificados o las posiciones en los registros de certificate transparency puede revelar dominios relacionados.<sup>[[6]](#references)</sup>

Usa también directamente los registros de **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Información de DMARC del correo

Puedes usar un sitio web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información de DMARC**.\
Otras herramientas útiles son [**spoofcheck**](https://github.com/BishopFox/spoofcheck) y [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un registro A abandonado puede volver a ser accesible cuando un proveedor de cloud reasigna una IP. La investigación citada demuestra un flujo de trabajo oportunista que aprovisiona una instancia y correlaciona su dirección con datos de DNS pasivo; prueba escenarios de takeover solo dentro del alcance autorizado.<sup>[[7]](#references)</sup>

### **Otras formas**

Repite los pivotes de descubrimiento pertinentes cada vez que encuentres un dominio nuevo: cada resultado puede revelar nombres de certificados adicionales, relaciones de DNS pasivo, coincidencias de favicon e identificadores de organizaciones que no eran visibles desde el dominio inicial.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Como ya sabes el nombre de la organización propietaria del espacio de IP, puedes buscar esa información en Shodan con: `org:"Tesla, Inc."` Revisa los hosts encontrados para identificar dominios nuevos e inesperados en el certificado TLS.

Puedes acceder al **certificado TLS** de la página web principal, obtener el **nombre de la organización** y luego buscar ese nombre en los **certificados TLS** de todas las páginas web conocidas por **Shodan** con el filtro: `ssl:"Tesla Motors"` o usar una herramienta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)es una herramienta que busca **dominios relacionados** con un dominio principal y sus **subdominios**; es increíble.

**DNS pasivo / DNS histórico**

Los datos de DNS pasivo son excelentes para encontrar **registros antiguos y olvidados** que todavía resuelven o que pueden ser objeto de takeover. Consulta:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Búsqueda de vulnerabilidades**

Comprueba si hay algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Puede que alguna empresa **esté usando un dominio** pero **haya perdido la titularidad**. Simplemente regístralo (si es lo bastante barato) e informa a la empresa.

Si encuentras algún **dominio con una IP distinta** de las que ya encontraste durante el descubrimiento de activos, deberías realizar un **análisis básico de vulnerabilidades** (con Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Según los servicios que estén ejecutándose, puedes encontrar en **este libro algunos trucos para «atacarlos»**.\
_Ten en cuenta que a veces el dominio está alojado en una IP que no controla el cliente, por lo que queda fuera del alcance; ten cuidado._

## Subdominios

> Conocemos todas las empresas dentro del alcance, todos los activos de cada empresa y todos los dominios relacionados con ellas.

Es hora de encontrar todos los subdominios posibles de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios.

### **DNS**

Intentemos obtener **subdominios** a partir de los registros **DNS**. También deberíamos probar la **transferencia de zona** (si es vulnerable, deberías reportarlo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Para consultar APIs y plataformas que cubren infraestructura, reputación, registros de brechas y enriquecimiento más allá del descubrimiento de subdominios, consulta el [catálogo de APIs de reconnaissance e inteligencia de amenazas](reconnaissance-and-threat-intelligence-apis.md).

La forma más rápida de obtener muchos subdominios es buscarlos en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para obtener mejores resultados, configura las API keys):


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

Hay **otras herramientas/APIs interesantes** que, aunque no estén especializadas directamente en encontrar subdominios, podrían ser útiles para encontrarlos, como:

- [**IP.THC.ORG**](https://ip.thc.org) API gratuita

```bash
curl https://ip.thc.org/tesla.com
```

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

- [**RapidDNS**](https://rapiddns.io) API gratis

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

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Buscan archivos JS en la web y extraen subdominios de ellos.

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

- [**securitytrails.com**](https://securitytrails.com/) tiene una API gratuita para buscar subdominios e historial de IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Este proyecto ofrece **gratis todos los subdominios relacionados con programas de bug bounty**. También puedes acceder a estos datos con [chaospy](https://github.com/dr-0x0x/chaospy) o incluso acceder al alcance utilizado por este proyecto: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Intentemos encontrar nuevos **subdominios** haciendo brute-force contra servidores DNS con posibles nombres de subdominios.

Para esta acción necesitarás algunas **listas de palabras de subdominios comunes, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

También necesitarás IP de buenos resolvers DNS. Para generar una lista de resolvers DNS confiables, puedes descargar los resolvers desde [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. También puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para hacer brute-force de DNS son:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó un brute-force de DNS eficaz. Es muy rápida, pero tiende a generar falsos positivos.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Este creo que solo usa 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper de `massdns`, escrito en go, que permite enumerar subdominios válidos mediante bruteforce activo, así como resolver subdominios con manejo de wildcards y compatibilidad sencilla para entrada y salida.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): También utiliza `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar fuerza bruta de nombres de dominio de forma asíncrona.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Segunda ronda de fuerza bruta DNS

Después de encontrar subdominios mediante fuentes abiertas y fuerza bruta, puedes generar variaciones de los subdominios encontrados para intentar descubrir aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Genera permutaciones a partir de los dominios y subdominios.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Dado un conjunto de dominios y subdominios, genera permutaciones.
  - Puedes obtener la **wordlist** de permutaciones de goaltdns [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Dados los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará el suyo propio.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas anteriores).
  - Puedes obtener la **wordlist** de permutaciones de altdns [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y alteraciones de subdominios. Esta herramienta fuerza bruta los resultados (no admite comodines DNS).
  - Puedes obtener la wordlist de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** A partir de un dominio, **genera posibles nombres de subdominios** basados en los patrones indicados para intentar descubrir más subdominios.

#### Generación inteligente de permutaciones

- [**regulator**](https://github.com/cramppet/regulator): Aprende patrones similares a regex a partir de los subdominios descubiertos y genera nombres candidatos para resolver.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios, combinado con un algoritmo de guía por respuestas DNS inmensamente simple pero eficaz. Utiliza un conjunto de datos de entrada proporcionado, como una wordlist personalizada o registros DNS/TLS históricos, para sintetizar con precisión más nombres de dominio correspondientes y ampliarlos aún más en un bucle según la información recopilada durante el escaneo DNS.

```
echo www | subzuf facebook.com
```

### **Flujo de trabajo de descubrimiento de subdominios**

Los ejemplos de flujos de trabajo de Trickest combinan OSINT, fuerza bruta de DNS y etapas de permutación para enumerar subdominios de forma reproducible.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Hosts virtuales**

Si encontraste una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, podrías intentar **encontrar otros subdominios que tengan sitios web en esa IP** consultando **fuentes OSINT** para encontrar dominios en una IP o haciendo **fuerza bruta de nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras API**.

**Fuerza bruta**

Si sospechas que un subdominio puede estar oculto en un servidor web, podrías intentar hacer fuerza bruta:

Para los vhosts basados en nombre, aplica fuzzing al encabezado `Host` y usa la autoc alibración de ffuf para filtrar la respuesta predeterminada.<sup>[[2]](#references)</sup>

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

### **Brute Force de Buckets**

Mientras buscas **subdominios**, presta atención para ver si alguno **apunta** a algún tipo de **bucket** y, en ese caso, [**comprueba los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, como a estas alturas conocerás todos los dominios incluidos en el alcance, intenta [**probar por fuerza bruta posibles nombres de bucket y comprobar los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorización**

Puedes **monitorizar** si se crean **nuevos subdominios** de un dominio consultando los registros de **Certificate Transparency**, como hace [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Comprueba si hay posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** apunta a algún **bucket de S3**, [**comprueba los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras algún **subdominio con una IP distinta** de las que ya encontraste durante el descubrimiento de activos, deberías realizar un **análisis básico de vulnerabilidades** (con Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Según los servicios que estén en ejecución, puedes encontrar en **este libro algunos trucos para «atacarlos»**.\
_Ten en cuenta que, a veces, el subdominio está alojado en una IP que no está controlada por el cliente, por lo que queda fuera del alcance; ten cuidado._

## IPs

En los pasos iniciales quizá hayas **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recopilar todas las IPs de esos rangos** y de los **dominios/subdominios (consultas DNS).**

También puedes encontrar **IPs usadas anteriormente por dominios y subdominios** usando los servicios de las siguientes **APIs gratuitas**. Es posible que el cliente aún sea propietario de esas IPs (y que te permitan encontrar [**métodos para eludir CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes comprobar qué dominios apuntan a una dirección IP concreta con la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Búsqueda de vulnerabilidades**

**Escanea los puertos de todas las IPs que no pertenezcan a CDNs** (ya que probablemente no encontrarás nada interesante allí). Es posible que **encuentres vulnerabilidades** en los servicios en ejecución.

**Encuentra una** [**guía**](../pentesting-network/index.html) **sobre cómo escanear hosts.**

## Búsqueda de servidores web

> Hemos encontrado todas las empresas y sus activos, y conocemos los rangos de IP, dominios y subdominios incluidos en el alcance. Es hora de buscar servidores web.

En los pasos anteriores probablemente ya hayas realizado algo de **recon de las IPs y los dominios encontrados**, así que quizá **ya hayas encontrado todos los servidores web posibles**. Sin embargo, si no es así, ahora veremos algunos **trucos rápidos para buscar servidores web** dentro del alcance.

Ten en cuenta que esto estará **orientado al descubrimiento de aplicaciones web**, por lo que también deberías realizar **escaneos de vulnerabilidades** y **de puertos** (**si el alcance lo permite**).

Puedes encontrar aquí un [**método rápido** para descubrir **puertos abiertos** relacionados con servidores **web** mediante [**masscan**](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta práctica para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Solo tienes que pasarle una lista de dominios y tratará de conectarse a los puertos 80 (http) y 443 (https). Además, puedes indicar que pruebe otros puertos:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** dentro del alcance (entre las **IP** de la empresa y todos sus **dominios** y **subdominios**), probablemente **no sepas por dónde empezar**. Así que simplifiquémoslo y empecemos simplemente por tomar capturas de pantalla de todos ellos. Con solo **echar un vistazo** a la **página principal**, puedes encontrar endpoints **extraños** que tienen más **probabilidades** de ser **vulnerables**.

Para llevar a cabo esta idea, puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, puedes usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analizar todas las **capturas de pantalla** e indicarte **cuáles probablemente contengan vulnerabilidades** y cuáles no.

## Activos de la nube pública

Para encontrar posibles activos en la nube pertenecientes a una empresa, deberías **empezar con una lista de palabras clave que la identifiquen**. Por ejemplo, si se trata de una empresa de criptomonedas, podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás listas de palabras con **palabras comunes usadas en los buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Después, con esas palabras, deberías generar **permutaciones** (consulta [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) para obtener más información).

Con las listas de palabras resultantes, puedes usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que, al buscar activos en la nube, deberías **buscar más que solo buckets en AWS**.

### **Búsqueda de vulnerabilidades**

Si encuentras elementos como **buckets abiertos o funciones de la nube expuestas**, deberías **acceder a ellos** y ver qué ofrecen y si puedes abusar de ellos.

## Correos electrónicos

Con los **dominios** y **subdominios** incluidos en el alcance, básicamente ya tienes todo lo que **necesitas para empezar a buscar correos electrónicos**. Estas son las **API** y **herramientas** que mejor me han funcionado para encontrar correos electrónicos de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con API
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Búsqueda de vulnerabilidades**

Los correos electrónicos te serán útiles más adelante para **hacer brute-force contra inicios de sesión web y servicios de autenticación** (como SSH). También son necesarios para el **phishing**. Además, estas API te proporcionarán aún más **información sobre la persona** detrás del correo electrónico, lo que resulta útil para la campaña de phishing.

## Filtraciones de credenciales

Con los **dominios,** **subdominios** y **correos electrónicos**, puedes empezar a buscar credenciales filtradas anteriormente que pertenezcan a esas direcciones de correo:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales **filtradas válidas**, es una victoria muy fácil.

## Filtraciones de secretos

Las filtraciones de credenciales están relacionadas con ataques a empresas en los que se **filtró y vendió información confidencial**. Sin embargo, las empresas también pueden verse afectadas por **otras filtraciones** cuya información no aparece en esas bases de datos:

### Filtraciones en Github

Es posible que se filtren credenciales y API en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan para esa empresa en Github.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repositorios públicos** de una **organización** y de sus **desarrolladores**, y ejecutar **gitleaks** sobre ellos automáticamente con [**gitleaks**](https://github.com/zricethezav/gitleaks).

También puedes usar **Leakos** para ejecutar **gitleaks** contra todo el **texto** de las **URL proporcionadas**, ya que a veces las **páginas web también contienen secretos**.

#### Github Dorks

Consulta la [página de GitHub dorks y filtraciones](github-leaked-secrets.md) para ver posibles **GitHub dorks** con los que buscar en la organización.

### Filtraciones en pastes

A veces, atacantes o simplemente empleados **publican contenido de la empresa en un sitio de pastes**. Puede que este contenido incluya o no **información confidencial**, pero es muy interesante buscarlo.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 sitios de pastes a la vez.

### Google Dorks

Los antiguos pero infalibles Google dorks siempre son útiles para encontrar **información expuesta que no debería estar ahí**. El único problema es que [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de consultas posibles que no puedes ejecutar manualmente. Así que puedes elegir tus 10 favoritas o usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que intentan ejecutar toda la base de datos mediante el navegador normal de Google nunca terminarán, ya que Google te bloqueará muy pronto._

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales **filtradas válidas** o tokens de API, es una victoria muy fácil.

## Vulnerabilidades en código público

Si descubres que la empresa tiene **código open source**, puedes **analizarlo** y buscar **vulnerabilidades**.

**Según el lenguaje**, hay diferentes **herramientas** que puedes usar; consulta la lista de [herramientas de revisión de código fuente](../../network-services-pentesting/pentesting-web/code-review-tools.md).

También hay servicios gratuitos que permiten **analizar repositorios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Metodología de pentesting web**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** que encuentran los bug hunters están en **aplicaciones web**, así que en este punto me gustaría hablar de una **metodología de pruebas para aplicaciones web**. Puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Herramientas open source de análisis automatizado web**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, resultan útiles para incorporarlas en **workflows y obtener información web inicial**.

## Recapitulación

> ¡Enhorabuena! Llegados a este punto, ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (veremos más trucos adelante).

Ya has:

1. Encontrado todas las **empresas** incluidas en el alcance
2. Encontrado todos los **activos** pertenecientes a las empresas (y realizado algún análisis de vulnerabilidades si está dentro del alcance)
3. Encontrado todos los **dominios** pertenecientes a las empresas
4. Encontrado todos los **subdominios** de los dominios (¿algún subdomain takeover?)
5. Encontrado todas las **IP** (de CDN y **no de CDN**) incluidas en el alcance.
6. Encontrado todos los **servidores web** y tomado una **captura de pantalla** de cada uno (¿algo extraño que merezca un análisis más profundo?)
7. Encontrado todos los **posibles activos de la nube pública** pertenecientes a la empresa.
8. **Correos electrónicos**, **filtraciones de credenciales** y **filtraciones de secretos** que podrían darte una **gran victoria muy fácilmente**.
9. **Realizado pentesting en todas las webs que encontraste**

## **Herramientas de recon automático completo**

Hay varias herramientas que ejecutan parte de las acciones propuestas contra un alcance determinado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un poco antigua y sin actualizar

## References

- [1] [Jason Haddix – La metodología de Bug Hunter v4.0: edición Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sobre los favicons: de iconos del navegador a inteligencia sobre la superficie de ataque](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Cómo weaponizar favicon.ico para BugBounties, OSINT y mucho más](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Descubrimiento de dominios mediante un ataque de correlación temporal a Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Toma de control pasiva: descubrir (y emular) una costosa campaña de subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: un método único de enumeración de subdominios](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow completo de descubrimiento de subdominios, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Descubrimiento de subdominios mediante brute-force automatizado con Trickest Workflow, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Captura de pantalla de la salida de favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
