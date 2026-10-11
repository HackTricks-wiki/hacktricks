# Metodología de Reconocimiento Externo

{{#include ../../banners/hacktricks-training.md}}

## Descubrimiento de activos

> Así que te dijeron que todo lo que pertenece a cierta empresa está dentro del scope, y quieres averiguar qué posee realmente esta empresa.

El objetivo de esta fase es obtener todas las **empresas que pertenecen a la empresa principal** y, después, todos los **activos** de estas empresas. Para ello, vamos a:<sup>[[1]](#references)</sup>

1. Encontrar las adquisiciones de la empresa principal; esto nos dará las empresas dentro del scope.
2. Encontrar el ASN (si lo hay) de cada empresa; esto nos dará los rangos de IP que posee cada empresa.
3. Usar búsquedas de reverse whois para buscar otras entradas (nombres de organizaciones, dominios...) relacionadas con la primera (esto se puede hacer de forma recursiva).
4. Usar otras técnicas, como los filtros `org` y `ssl` de shodan, para buscar otros activos (el truco de `ssl` se puede aplicar de forma recursiva).

### **Adquisiciones**

Lo primero que necesitamos es saber qué **otras empresas pertenecen a la empresa principal**.\
Una opción es visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **buscar** la **empresa principal** y **hacer clic** en "**acquisitions**". Allí verás otras empresas que adquirió la empresa principal.\
Otra opción es visitar la página de **Wikipedia** de la empresa principal y buscar **adquisitions**.\
Para empresas que cotizan en bolsa, consulta los documentos **SEC/EDGAR**, las páginas de **relaciones con inversores** o los registros corporativos locales (por ejemplo, **Companies House** en el Reino Unido).\
Para consultar estructuras corporativas globales y filiales, prueba **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) y la base de datos **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Bien, llegados a este punto deberías conocer todas las empresas dentro del scope. Veamos cómo encontrar sus activos.

### **ASNs**

Un número de sistema autónomo (**ASN**) es un **número único** asignado a un **sistema autónomo** (AS) por la **Internet Assigned Numbers Authority (IANA)**.\
Un **AS** consta de **bloques** de **direcciones IP** que tienen una política claramente definida para acceder a redes externas y son administrados por una única organización, aunque pueden estar formados por varios operadores.

Es interesante averiguar si a la **empresa se le ha asignado algún ASN** para encontrar sus **rangos de IP**. Será interesante realizar una **prueba de vulnerabilidades** en todos los **hosts** dentro del **scope** y **buscar dominios** dentro de estas IPs.\
Puedes **buscar** por **nombre** de la empresa, por **IP** o por **dominio** en [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **o** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Según la región de la empresa, estos enlaces podrían ser útiles para recopilar más datos:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Norteamérica),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latinoamérica),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De todos modos, probablemente toda la** información útil **(rangos de IP y Whois)** ya aparezca en el primer enlace.

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

Puedes encontrar los rangos de IP de una organización también usando [http://asnlookup.com/](http://asnlookup.com) (tiene una API gratuita).\
Puedes encontrar la IP y el ASN de un dominio usando [http://ipv4info.com/](http://ipv4info.com).

### **Búsqueda de vulnerabilidades**

En este punto conocemos **todos los activos dentro del alcance**, así que, si tienes permiso, podrías ejecutar algún **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) en todos los hosts.\
También podrías ejecutar algunos [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **o usar servicios como** Shodan, Censys o ZoomEye **para encontrar** puertos **abiertos y, dependiendo de lo que encuentres, deberías** consultar este libro para aprender a hacer pentest de varios servicios posibles que estén en ejecución.\
**También cabe mencionar que podrías preparar algunas listas de** nombres de usuario **y** contraseñas **predeterminados e intentar hacer** bruteforce contra servicios con [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Dominios

> Ya conocemos todas las empresas dentro del alcance y sus activos; es hora de encontrar los dominios dentro del alcance.

_Ten en cuenta que con las técnicas propuestas a continuación también puedes encontrar subdominios, y no deberías subestimar esa información._

En primer lugar, deberías buscar el **dominio principal** de cada empresa. Por ejemplo, para _Tesla Inc._ sería _tesla.com_.

### **DNS inverso**

Como ya encontraste todos los rangos de IP de los dominios, podrías intentar realizar **consultas DNS inversas** a esas **IP para encontrar más dominios dentro del alcance**. Intenta usar algún servidor DNS de la víctima o algún servidor DNS conocido (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Para que esto funcione, el administrador debe habilitar manualmente el PTR.\
También puedes usar una herramienta en línea para obtener esta información: [http://ptrarchive.com/](http://ptrarchive.com).\
Para rangos grandes, herramientas como [**massdns**](https://github.com/blechschmidt/massdns) y [**dnsx**](https://github.com/projectdiscovery/dnsx) son útiles para automatizar las búsquedas inversas y el enriquecimiento.

### **Reverse Whois (loop)**

En un **whois** puedes encontrar mucha **información** interesante, como el **nombre de la organización**, la **dirección**, los **correos electrónicos**, los números de teléfono... Pero lo más interesante es que puedes encontrar **más activos relacionados con la empresa** si haces **búsquedas inversas de whois usando cualquiera de esos campos** (por ejemplo, otros registros de whois donde aparezca el mismo correo electrónico).\
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

Puedes automatizar esta tarea con [**DomLink** ](https://github.com/vysecurity/DomLink)(requiere una clave de API de whoxy).\
También puedes realizar una búsqueda automática de reverse whois con [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Ten en cuenta que puedes usar esta técnica para descubrir más nombres de dominio cada vez que encuentres uno nuevo.**

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
- [**StackScan**](https://www.stackscan.com) - **Plan gratuito** (Web y API). Busca cualquier activo servido, no solo IDs de trackers: una ruta de script, el nombre de un bundle autoalojado o el host desde el que se carga un activo, y devuelve todos los sitios que lo contienen

La API devuelve el stack de un solo dominio, lo que resulta útil para confirmar que un activo candidato pertenece al mismo entorno:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Devuelve cada tecnología detectada junto con su categoría. El pivoteo de activos actualmente solo funciona con la web; la API permite búsquedas por dominio.

### **Favicon**

¿Sabías que podemos encontrar dominios y subdominios relacionados con nuestro objetivo buscando el mismo hash del icono favicon? Eso es exactamente lo que hace la herramienta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), creada por [@m4ll0k2](https://twitter.com/m4ll0k2). Así es como se usa:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Resultados de Favihash usados para descubrir dominios que comparten un hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En pocas palabras, Favihash nos permite descubrir dominios que tienen el mismo hash de icono de favicon que nuestro objetivo.

![Salida de favihash usada para descubrir dominios con el mismo hash de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Usa un hash de favicon conocido como pivote en Shodan o FOFA para encontrar otras instancias expuestas de la misma tecnología.<sup>[[5]](#references)</sup>

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

Considera las huellas de favicon como pistas y valídalas con señales circundantes.<sup>[[3]](#references)[[4]](#references)</sup>

- **Considera el hash un indicador, no una prueba**: MMH3 es compacto; es posible que haya colisiones, iconos reutilizados y suplantación deliberada.
- **Examina más que** `/favicon.ico`: inspecciona rutas de frameworks y builds, archivos manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, URL de datos en línea y etiquetas HTML `<link rel="icon">`.
- **Los recursos estáticos pueden seguir siendo accesibles detrás de controles WAF/SSO/IdP**: solicita el icono directamente y revisa `ETag`, `Last-Modified`, las redirecciones y las cabeceras de caché.
- **Valida las coincidencias con señales circundantes**: compara el título, el hash del HTML/cuerpo, las cabeceras, los sujetos/SAN de los certificados TLS, los componentes del producto y los puertos expuestos.
- **Agrupa por hash del HTML/cuerpo**: una plantilla coherente refuerza la huella; las plantillas mixtas sugieren un icono genérico o compartido.
- **Considera que un hash presente en firmas, puertos y productos no relacionados podría indicar un honeypot o un marcador de posición.**
- **En objetivos ambiguos, compara una página real con una ruta inexistente**, como `/_favicon_probe_<8-hex>`; las respuestas coincidentes de hosting o parking pueden explicar el icono compartido.
- **Inicia el triaje con reglas de detección de Nuclei o datasets públicos** que asocien hashes de favicon con productos y CPE.
- **Recuerda la brecha de cobertura centrada en IP**: las superficies detrás de CDN, enrutadas por SNI, anycast y solo accesibles por dominio pueden faltar en datasets similares a Shodan.

### **Copyright / cadena única**

Busca en las páginas web **cadenas que puedan compartirse entre distintos sitios web de una misma organización**. La **cadena de copyright** puede ser un buen ejemplo. Luego, busca esa cadena en **Google**, en otros **buscadores** o incluso en **Shodan**: `shodan search http.html:"Copyright string"`

### **Hora CRT**

Es habitual tener un cron job como este:

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

### Información de correo DMARC

Puedes usar un sitio web como [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) o una herramienta como [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) para encontrar **dominios y subdominios que comparten la misma información DMARC**.\
Otras herramientas útiles son [**spoofcheck**](https://github.com/BishopFox/spoofcheck) y [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Un registro A abandonado puede volver a ser accesible cuando un proveedor cloud reasigna una IP. La investigación citada demuestra un flujo de trabajo oportunista que aprovisiona una instancia y correlaciona su dirección con datos de DNS pasivo; prueba escenarios de takeover solo dentro del alcance autorizado.<sup>[[7]](#references)</sup>

### **Otras formas**

Repite los pivotes de descubrimiento aplicables cada vez que encuentres un dominio nuevo: cada resultado puede revelar nombres de certificados adicionales, relaciones de DNS pasivo, coincidencias de favicon e identificadores de organizaciones que no eran visibles a partir del seed original.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Como ya conoces el nombre de la organización propietaria del espacio de IP, puedes buscar usando esos datos en Shodan: `org:"Tesla, Inc."` Revisa los hosts encontrados en busca de nuevos dominios inesperados en el certificado TLS.

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

Comprueba si hay algún [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Puede que alguna empresa **esté usando un dominio**, pero **haya perdido su propiedad**. Simplemente regístralo (si es lo bastante barato) e informa a la empresa.

Si encuentras algún **dominio con una IP diferente** de las que ya encontraste durante el descubrimiento de activos, deberías realizar un **análisis básico de vulnerabilidades** (con Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Según los servicios que estén ejecutándose, puedes encontrar en **este libro algunos trucos para "atacarlos"**.\
_Ten en cuenta que a veces el dominio está alojado en una IP que no controla el cliente, por lo que queda fuera del alcance; ten cuidado._

## Subdominios

> Conocemos todas las empresas incluidas en el alcance, todos los activos de cada empresa y todos los dominios relacionados con ellas.

Es hora de encontrar todos los subdominios posibles de cada dominio encontrado.

> [!TIP]
> Ten en cuenta que algunas herramientas y técnicas para encontrar dominios también pueden ayudar a encontrar subdominios

### **DNS**

Intentemos obtener **subdominios** a partir de los registros **DNS**. También deberíamos intentar una **transferencia de zona** (si es vulnerable, deberías reportarlo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

La forma más rápida de obtener muchos subdominios es buscar en fuentes externas. Las **herramientas** más utilizadas son las siguientes (para obtener mejores resultados, configura las claves API):


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

Hay **otras herramientas/API interesantes** que, aunque no estén especializadas directamente en encontrar subdominios, podrían ser útiles para encontrarlos, como:

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

- [**gau**](https://github.com/lc/gau)**:** obtiene URLs conocidas de AlienVault's Open Threat Exchange, Wayback Machine y Common Crawl para cualquier dominio dado.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Analizan la web en busca de archivos JS y extraen subdominios de ellos.

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

Este proyecto ofrece **gratis todos los subdominios relacionados con programas de bug bounty**. También puedes acceder a estos datos usando [chaospy](https://github.com/dr-0x0x/chaospy) o incluso consultar el scope utilizado por este proyecto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Puedes encontrar una **comparación** de muchas de estas herramientas aquí: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Intentemos encontrar nuevos **subdominios** haciendo brute force contra servidores DNS con posibles nombres de subdominios.

Para esta acción necesitarás algunas **wordlists de subdominios comunes, como**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

También necesitarás IP de buenos resolvers DNS. Para generar una lista de resolvers DNS de confianza, puedes descargar los resolvers de [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) y usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrarlos. También puedes usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Las herramientas más recomendadas para hacer brute force de DNS son:

- [**massdns**](https://github.com/blechschmidt/massdns): Esta fue la primera herramienta que realizó un brute force de DNS eficaz. Es muy rápida, pero propensa a generar falsos positivos.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Creo que este solo usa 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) es un wrapper de `massdns`, escrito en Go, que permite enumerar subdominios válidos mediante fuerza bruta activa, así como resolver subdominios con manejo de wildcard y soporte sencillo de entrada y salida.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): También usa `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) usa asyncio para realizar fuerza bruta de nombres de dominio de forma asíncrona.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Segunda ronda de Brute-Force de DNS

Después de encontrar subdominios mediante fuentes abiertas y brute-forcing, puedes generar variaciones de los subdominios encontrados para intentar encontrar aún más. Varias herramientas son útiles para este propósito:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Genera permutaciones a partir de dominios y subdominios.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Genera permutaciones a partir de los dominios y subdominios.
  - Puedes obtener la **wordlist** de permutaciones de goaltdns [**aquí**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Dados los dominios y subdominios, genera permutaciones. Si no se indica un archivo de permutaciones, gotator usará uno propio.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Además de generar permutaciones de subdominios, también puede intentar resolverlos (pero es mejor usar las herramientas comentadas anteriormente).
  - Puedes obtener [**aquí**](https://github.com/infosec-au/altdns/blob/master/words.txt) la **wordlist** de permutaciones de altdns.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Otra herramienta para realizar permutaciones, mutaciones y modificaciones de subdominios. Esta herramienta fuerza por fuerza bruta los resultados (no admite comodines DNS).
  - Puedes obtener la wordlist de permutaciones de dmut [**aquí**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** A partir de un dominio, **genera posibles nombres de subdominios nuevos** basándose en patrones indicados para intentar descubrir más subdominios.

#### Generación inteligente de permutaciones

- [**regulator**](https://github.com/cramppet/regulator): Aprende patrones similares a regex a partir de los subdominios descubiertos y genera nombres candidatos para resolver.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ es un fuzzer de fuerza bruta de subdominios combinado con un algoritmo de orientación por respuestas DNS sumamente simple pero eficaz. Utiliza un conjunto de datos de entrada, como una wordlist personalizada o registros históricos de DNS/TLS, para generar con precisión más nombres de dominio correspondientes y ampliarlos aún más en un bucle, basándose en la información recopilada durante el escaneo DNS.

```
echo www | subzuf facebook.com
```

### **Flujo de trabajo para descubrir subdominios**

Los ejemplos de flujos de trabajo de Trickest combinan OSINT, DNS brute force y etapas de permutación para realizar una enumeración de subdominios repetible.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Si encuentras una dirección IP que contiene **una o varias páginas web** pertenecientes a subdominios, puedes intentar **encontrar otros subdominios con sitios web en esa IP** consultando **fuentes OSINT** en busca de dominios asociados a una IP o haciendo **brute force de nombres de dominio VHost en esa IP**.

#### OSINT

Puedes encontrar algunos **VHosts en IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **u otras APIs**.

**Brute Force**

Si sospechas que puede haber algún subdominio oculto en un servidor web, puedes intentar hacer brute force:

Para vhosts basados en nombres, aplica fuzzing al encabezado `Host` y usa la autoc
alibración de ffuf para filtrar la respuesta predeterminada.<sup>[[2]](#references)</sup>

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

A veces encontrarás páginas que solo devuelven el encabezado _**Access-Control-Allow-Origin**_ cuando se establece un dominio/subdominio válido en el encabezado _**Origin**_. En estos casos, puedes aprovechar este comportamiento para **descubrir** nuevos **subdominios**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Mientras buscas **subdominios**, presta atención para ver si **apuntan** a algún tipo de **bucket** y, en ese caso, [**comprueba los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Además, como a estas alturas ya conocerás todos los dominios dentro del scope, intenta [**hacer brute force de posibles nombres de bucket y comprobar los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorización**

Puedes **monitorizar** si se crean **nuevos subdominios** de un dominio supervisando los logs de **Certificate Transparency**, como hace [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Búsqueda de vulnerabilidades**

Comprueba si hay posibles [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si el **subdominio** apunta a algún **bucket de S3**, [**comprueba los permisos**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Si encuentras algún **subdominio con una IP diferente** de las que ya encontraste durante el descubrimiento de activos, deberías realizar un **análisis básico de vulnerabilidades** (con Nessus u OpenVAS) y algún [**escaneo de puertos**](../pentesting-network/index.html#discovering-hosts-from-the-outside) con **nmap/masscan/shodan**. Dependiendo de los servicios que estén en ejecución, puedes encontrar en **este libro algunos trucos para «atacarlos»**.\
_Ten en cuenta que a veces el subdominio está alojado en una IP que no controla el cliente, por lo que no está dentro del scope; ten cuidado._

## IPs

En los pasos iniciales quizá hayas **encontrado algunos rangos de IP, dominios y subdominios**.\
Es hora de **recopilar todas las IP de esos rangos** y las de los **dominios/subdominios (consultas DNS).**

Con los servicios de las siguientes **APIs gratuitas** también puedes encontrar **IP anteriores utilizadas por dominios y subdominios**. Es posible que el cliente todavía sea propietario de estas IP (y que te permitan encontrar [**bypasses de CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

También puedes buscar dominios que apunten a una dirección IP específica con la herramienta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Búsqueda de vulnerabilidades**

**Escanea los puertos de todas las IP que no pertenezcan a CDN** (ya que probablemente no encontrarás nada interesante allí). En los servicios descubiertos que estén en ejecución quizá **puedas encontrar vulnerabilidades**.

**Encuentra una** [**guía**](../pentesting-network/index.html) **sobre cómo escanear hosts.**

## Búsqueda de servidores web

> Hemos encontrado todas las empresas y sus activos, y conocemos los rangos de IP, dominios y subdominios dentro del scope. Es hora de buscar servidores web.

En los pasos anteriores, probablemente ya hayas realizado algo de **recon de las IP y los dominios descubiertos**, así que quizá **ya hayas encontrado todos los servidores web posibles**. Sin embargo, si no lo has hecho, ahora veremos algunos **trucos rápidos para buscar servidores web** dentro del scope.

Ten en cuenta que esto estará **orientado al descubrimiento de aplicaciones web**, por lo que también deberías **realizar el análisis de vulnerabilidades** y el **escaneo de puertos** (**si el scope lo permite**).

Puedes encontrar aquí un [**método rápido** para descubrir **puertos abiertos** relacionados con servidores **web** usando **masscan**](../pentesting-network/index.html#http-port-discovery).\
Otra herramienta sencilla para buscar servidores web es [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) y [**httpx**](https://github.com/projectdiscovery/httpx). Solo tienes que pasarle una lista de dominios e intentará conectarse a los puertos 80 (http) y 443 (https). Además, puedes indicarle que pruebe otros puertos:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Capturas de pantalla**

Ahora que has descubierto **todos los servidores web** dentro del alcance (entre las **IPs** de la empresa y todos los **dominios** y **subdominios**), probablemente **no sepas por dónde empezar**. Así que simplifiquémoslo y empecemos simplemente por tomar capturas de pantalla de todos ellos. Con solo **echar un vistazo** a la **página principal**, puedes encontrar endpoints **extraños** con más **probabilidades** de ser **vulnerables**.

Para llevar a cabo esta idea, puedes usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) o [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Además, puedes usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para analizar todas las **capturas de pantalla** e indicarte **cuáles probablemente contienen vulnerabilidades** y cuáles no.

## Activos en la nube pública

Para encontrar posibles activos en la nube que pertenezcan a una empresa, deberías **empezar con una lista de palabras clave que la identifiquen**. Por ejemplo, para una empresa de criptomonedas podrías usar palabras como: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

También necesitarás listas de palabras con **palabras comunes usadas en buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Después, con esas palabras, deberías generar **permutaciones** (consulta la [**Segunda ronda de DNS brute-force**](#second-dns-bruteforce-round) para obtener más información).

Con las listas de palabras resultantes, podrías usar herramientas como [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **o** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Recuerda que, al buscar activos en la nube, deberías **buscar algo más que solo buckets en AWS**.

### **Búsqueda de vulnerabilidades**

Si encuentras elementos como **buckets abiertos o funciones en la nube expuestas**, deberías **acceder a ellos** e intentar ver qué ofrecen y si puedes abusar de ellos.

## Emails

Con los **dominios** y **subdominios** dentro del alcance, básicamente ya tienes todo lo que **necesitas para empezar a buscar emails**. Estas son las **APIs** y **herramientas** que mejor me han funcionado para encontrar emails de una empresa:

- [**theHarvester**](https://github.com/laramies/theHarvester) - con APIs
- API de [**https://hunter.io/**](https://hunter.io/) (versión gratuita)
- API de [**https://app.snov.io/**](https://app.snov.io/) (versión gratuita)
- API de [**https://minelead.io/**](https://minelead.io/) (versión gratuita)

### **Búsqueda de vulnerabilidades**

Los emails te serán útiles más adelante para hacer **brute-force de inicios de sesión web y servicios de autenticación** (como SSH). También se necesitan para hacer **phishing**. Además, estas APIs te darán aún más **información sobre la persona** detrás del email, lo cual es útil para la campaña de phishing.

## Credential Leaks

Con los **dominios**, **subdominios** y **emails**, puedes empezar a buscar credenciales filtradas anteriormente que pertenezcan a esos emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales **filtradas válidas**, es una victoria muy fácil.

## Secrets Leaks

Los credential leaks están relacionados con ataques a empresas en los que **se filtró y vendió información sensible**. Sin embargo, las empresas podrían verse afectadas por **otros leaks** cuya información no aparece en esas bases de datos:

### Github Leaks

Las credenciales y las APIs podrían filtrarse en los **repositorios públicos** de la **empresa** o de los **usuarios** que trabajan en esa empresa de GitHub.\
Puedes usar la **herramienta** [**Leakos**](https://github.com/carlospolop/Leakos) para **descargar** todos los **repositorios públicos** de una **organización** y de sus **desarrolladores**, y ejecutar [**gitleaks**](https://github.com/zricethezav/gitleaks) sobre ellos automáticamente.

**Leakos** también se puede usar para ejecutar **gitleaks** contra todo el **texto** de las **URLs proporcionadas**, ya que a veces las **páginas web también contienen secretos**.

#### Github Dorks

Consulta la [página de GitHub dorks y leaks](github-leaked-secrets.md) para encontrar posibles **GitHub dorks** que buscar en la organización.

### Pastes Leaks

A veces, los atacantes o simplemente los trabajadores **publican contenido de la empresa en un sitio de paste**. Este contenido puede contener o no **información sensible**, pero es muy interesante buscarla.\
Puedes usar la herramienta [**Pastos**](https://github.com/carlospolop/Pastos) para buscar en más de 80 sitios de paste a la vez.

### Google Dorks

Los antiguos pero valiosos Google dorks siempre son útiles para encontrar **información expuesta que no debería estar ahí**. El único problema es que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contiene varios **miles** de consultas posibles que no puedes ejecutar manualmente. Así que puedes elegir tus 10 favoritas o usar una **herramienta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para ejecutarlas todas**.

_Ten en cuenta que las herramientas que intentan recorrer toda la base de datos usando el navegador normal de Google nunca terminarán, ya que Google te bloqueará muy pronto._

### **Búsqueda de vulnerabilidades**

Si encuentras credenciales o tokens de API **filtrados válidos**, es una victoria muy fácil.

## Vulnerabilidades en código público

Si descubres que la empresa tiene **código open-source**, puedes **analizarlo** y buscar **vulnerabilidades**.

**Según el lenguaje**, puedes usar distintas **herramientas**; consulta la lista de [herramientas de revisión de código fuente](../../network-services-pentesting/pentesting-web/code-review-tools.md).

También hay servicios gratuitos que permiten **analizar repositorios públicos**, como:

- [**Snyk**](https://app.snyk.io/)

## [**Metodología de pentesting web**](../../network-services-pentesting/pentesting-web/index.html)

La **mayoría de las vulnerabilidades** que encuentran los bug hunters se encuentran en **aplicaciones web**, así que en este punto quiero hablar de una **metodología para probar aplicaciones web**. Puedes [**encontrar esta información aquí**](../../network-services-pentesting/pentesting-web/index.html).

También quiero hacer una mención especial a la sección [**Herramientas open source de escáneres web automatizados**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ya que, aunque no deberías esperar que encuentren vulnerabilidades muy sensibles, resultan útiles para incluirlas en **workflows y obtener información web inicial**.

## Recapitulación

> ¡Felicidades! En este punto ya has realizado **toda la enumeración básica**. Sí, es básica porque se puede hacer mucha más enumeración (más adelante veremos otros trucos).

Así que ya has:

1. Encontrado todas las **empresas** dentro del alcance
2. Encontrado todos los **activos** que pertenecen a las empresas (y realizado algún escaneo de vulnerabilidades, si estaba dentro del alcance)
3. Encontrado todos los **dominios** que pertenecen a las empresas
4. Encontrado todos los **subdominios** de los dominios (¿hay algún subdomain takeover?)
5. Encontrado todas las **IPs** (de CDNs y **que no son de CDNs**) dentro del alcance.
6. Encontrado todos los **servidores web** y tomado una **captura de pantalla** de ellos (¿hay algo extraño que merezca un análisis más detallado?)
7. Encontrado todos los **posibles activos en la nube pública** que pertenecen a la empresa.
8. Encontrado **emails**, **credential leaks** y **secret leaks** que podrían darte una **gran victoria muy fácilmente**.
9. Hecho **pentesting a todos los sitios web encontrados**

## **Herramientas automáticas para Full Recon**

Hay varias herramientas que realizan parte de las acciones propuestas contra un alcance determinado.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Algo antigua y sin actualizar

## References

- [1] [Jason Haddix – Metodología del bug hunter v4.0: edición de recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Sobre los favicons: de iconos del navegador a inteligencia sobre la superficie de ataque](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Cómo convertir favicon.ico en un arma para BugBounties, OSINT y mucho más](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Descubrir dominios mediante un ataque de correlación temporal a Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: descubrir (y emular) una costosa campaña de subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: un método único de enumeración de subdominios](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Workflow completo de descubrimiento de subdominios, parte 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Descubrimiento de subdominios mediante brute-force con un workflow automatizado de Trickest, parte 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Captura de pantalla de la salida de favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
