# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introducción

Para detectar un intento de phishing es importante **entender las técnicas de phishing que se están utilizando actualmente**. En la página principal de esta publicación puedes encontrar esta información, así que si no conoces las técnicas que se están utilizando hoy en día, te recomiendo ir a la página principal y leer al menos esa sección.

Esta publicación se basa en la idea de que los **attackers intentarán imitar o utilizar de alguna manera el domain name de la víctima**. Si tu domain se llama `example.com` y sufres phishing utilizando por alguna razón un domain name completamente diferente, como `youwonthelottery.com`, estas técnicas no lo descubrirán.

## Variaciones del domain name

Es relativamente **fácil** **uncover** esos intentos de **phishing** que utilizan un **domain** similar dentro del correo electrónico.\
Solo hay que **generar una lista de los nombres de phishing más probables** que un attacker podría utilizar y **comprobar** si están **registered** o simplemente verificar si hay alguna **IP** utilizándolos.

### Encontrar domains sospechosos

Para este propósito, puedes utilizar cualquiera de las siguientes herramientas. Ambas resuelven los candidate domains para comprobar si están en uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Consejo: Si generas una lista de candidates, introdúcela también en tus logs del DNS resolver para detectar **NXDOMAIN lookups desde dentro de tu org** (usuarios intentando acceder a un typo antes de que el attacker lo registre realmente). Haz sinkhole o bloquea previamente estos domains si la policy lo permite.

### Bitflipping

**Para una breve explicación, consulta la página principal; para la investigación principal sobre Windows.com bitsquatting, consulta el [write-up de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) y el [informe de BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Por ejemplo, una modificación de 1 bit en el domain microsoft.com puede transformarlo en _windnws.com._\
**Los attackers pueden registrar tantos domains de bit-flipping relacionados con la víctima como sea posible para redirigir a los usuarios legítimos hacia su infraestructura**.<sup>[[1]](#references)[[2]](#references)</sup>

**También se deben monitorizar todos los posibles nombres de domain de bit-flipping.**

Si también necesitas tener en cuenta los homoglyph/IDN lookalikes (por ejemplo, mezclando caracteres latinos y cirílicos), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Comprobaciones básicas

Una vez que tengas una lista de posibles nombres de domains sospechosos, deberías **comprobarlos** (principalmente los puertos HTTP y HTTPS) para **ver si utilizan algún login form similar** al de algún domain de la víctima.\
También podrías comprobar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **qué antigüedad tiene cada domain sospechoso descubierto**; cuanto más reciente sea, mayor será el riesgo.\
También puedes obtener **screenshots** de la página web HTTP y/o HTTPS sospechosa para comprobar si es sospechosa y, en ese caso, **acceder a ella para examinarla más a fondo**.

### Comprobaciones avanzadas

Si quieres ir un paso más allá, te recomiendo **monitorizar esos domains sospechosos y buscar más** de vez en cuando (¿cada día? solo lleva unos segundos/minutos). También deberías **comprobar** los **puertos** abiertos de las IP relacionadas y **buscar instancias de `gophish` o herramientas similares** (sí, los attackers también cometen errores), así como **monitorizar las páginas web HTTP y HTTPS de los domains y subdomains sospechosos** para comprobar si han copiado algún login form de las páginas web de la víctima.\
Para **automatizar esto**, te recomiendo tener una lista de los login forms de los domains de la víctima, hacer spidering de las páginas web sospechosas y comparar cada login form encontrado dentro de los domains sospechosos con cada login form del domain de la víctima utilizando algo como `ssdeep`.\
Si has localizado los login forms de los domains sospechosos, puedes intentar **enviar junk credentials** y **comprobar si te redirige al domain de la víctima**.

---

### Hunting mediante favicon y web fingerprints (Shodan/Censys)

Muchos phishing kits reutilizan los favicons de la marca que están suplantando. Shodan aplica un hash a los datos del favicon codificados en base64 mediante MurmurHash3, mientras que Censys expone sus propios campos de favicon hash.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Puedes generar un hash compatible con Shodan y pivotar usando él:

Ejemplo en Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consultar Shodan: `http.favicon.hash:309020573`
- Con tooling: consultar herramientas de la comunidad como favfreak para calcular hashes y generar dorks de Shodan.<sup>[[16]](#references)</sup>

Notas
- Los favicons se reutilizan; considera las coincidencias como indicios y valida el contenido y los certificados antes de actuar.
- Combínalo con heurísticas de antigüedad del dominio y palabras clave para obtener una mayor precisión.

### Búsqueda de telemetría de URL (urlscan.io)

`urlscan.io` almacena capturas de pantalla históricas, el DOM, solicitudes y metadatos TLS de las URL enviadas. Puedes buscar abusos de marca y clones:<sup>[[8]](#references)</sup>

Consultas de ejemplo (UI o API):
- Buscar imitaciones excluyendo tus dominios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Buscar sitios que hacen hotlinking de tus recursos: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restringir a resultados recientes: añadir `AND date:>now-7d`

Ejemplo de API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Desde el JSON, pivota sobre:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para detectar certificados muy nuevos en lookalikes
- valores de `task.source` como `certstream-suspicious` para vincular los hallazgos con la monitorización de CT

### Antigüedad del dominio mediante RDAP (scriptable)

RDAP devuelve eventos de registro legibles por máquinas. Es útil para marcar **dominios registrados recientemente (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriquezca su pipeline etiquetando los dominios con categorías de antigüedad de registro (por ejemplo, <7 días, <30 días) y priorice el triage en consecuencia.

### Huellas TLS/JAx para detectar infraestructura AiTM

El phishing de credenciales puede utilizar reverse proxies **Adversary-in-the-Middle (AiTM)** (por ejemplo, Evilginx) para robar tokens de sesión.<sup>[[11]](#references)</sup> Puede añadir detecciones en el lado de la red:

- Registre las huellas TLS/HTTP (JA3/JA4/JA4S/JA4H) en el tráfico de salida. Se han observado algunas compilaciones de Evilginx con valores JA4 de cliente/servidor estables. Genere alertas sobre huellas conocidas como maliciosas solo como una señal débil y confirme siempre con inteligencia de contenido y de dominios.<sup>[[12]](#references)</sup>
- Registre proactivamente los metadatos de los certificados TLS (emisor, cantidad de SAN, uso de comodines y validez) de los hosts parecidos descubiertos mediante CT o urlscan, y correlaciónelos con la antigüedad del DNS y la geolocalización.

> Nota: trate las huellas como enriquecimiento, no como bloqueadores únicos; los frameworks evolucionan y pueden aleatorizar u ofuscar sus características.

### Nombres de dominio que utilizan palabras clave

La página principal también menciona una técnica de variación de nombres de dominio que consiste en colocar el **nombre de dominio de la víctima dentro de un dominio más grande** (por ejemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

Los logs de Certificate Transparency (CT) exponen las identidades de los certificados, por lo que buscar palabras clave de marcas en los nombres Subject o SAN puede revelar dominios parecidos (por ejemplo, un certificado para `paypal-financial.com` expone la palabra clave `paypal`). Filtre los resultados por fecha de emisión y CA cuando sea útil, y valide los candidatos porque las coincidencias de palabras clave pueden generar falsos positivos.<sup>[[13]](#references)</sup>

El [write-up original de Patrik Hudak sobre la búsqueda de dominios de phishing](https://0xpatrik.com/phishing-domains/) demuestra este flujo de trabajo en Censys, incluidos filtros para la fecha y el emisor del certificado, como Let's Encrypt.<sup>[[13]](#references)</sup>

![Resultados de búsqueda de certificados en Censys utilizados para identificar dominios parecidos](<../../images/image (1115).png>)

También puede utilizar el servicio gratuito [**crt.sh**](https://crt.sh) para buscar una palabra clave y filtrar los resultados por fecha y CA.<sup>[[13]](#references)</sup>

![Búsqueda de palabras clave en crt.sh para identificar certificados sospechosos](<../../images/image (519).png>)

Su campo Matching Identities puede ayudar a comparar las identidades del dominio real con las de dominios sospechosos, pero trate las coincidencias como indicios y no como una prueba.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) transmite actualizaciones de CT casi en tiempo real, y [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consume ese flujo para asignar una puntuación a los nombres de certificados sospechosos.<sup>[[14]](#references)[[15]](#references)</sup>

Consejo práctico: al realizar el triage de resultados de CT, priorice los NRD, los registradores no confiables o desconocidos, el WHOIS con proxy de privacidad y los certificados con valores `NotBefore` muy recientes. Mantenga una allowlist de sus dominios y marcas propios para reducir el ruido.

#### **Nuevos dominios**

Otra opción consiste en recopilar dominios registrados recientemente por TLD (por ejemplo, mediante [Whoxy](https://www.whoxy.com/newly-registered-domains/)) y filtrarlos por palabras clave de marcas. Esto no detecta el phishing alojado en subdominios cuando la palabra clave no aparece en el dominio registrado.<sup>[[13]](#references)</sup>

Heurística adicional: trate ciertos **TLD de extensiones de archivo** (por ejemplo, `.zip`, `.mov`) con especial sospecha en las alertas. En los señuelos, suelen confundirse con nombres de archivo; combine la señal del TLD con las palabras clave de marcas y la antigüedad del NRD para mejorar la precisión.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Secuestro del tráfico hacia windows.com de Microsoft mediante bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Análisis detallado: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentación de mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Conjunto de datos de propiedades web de plataformas](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referencia de la API de búsqueda](https://urlscan.io/docs/search/)
- [9] [Ayuda del protocolo de acceso a datos de registro](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Respuestas JSON para el protocolo de acceso a datos de registro](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Tácticas de tokens: cómo prevenir, detectar y responder al robo de tokens cloud](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Fingerprinting de red JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Cómo encontrar phishing: herramientas y técnicas](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Presentación de CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
