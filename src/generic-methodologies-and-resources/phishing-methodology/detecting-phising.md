# Detección de phishing

{{#include ../../banners/hacktricks-training.md}}

## Introducción

Para detectar un intento de phishing, es importante **entender las técnicas de phishing que se utilizan actualmente**. En la página principal de esta publicación puedes encontrar esta información, así que, si no sabes qué técnicas se utilizan hoy en día, te recomiendo que vayas a la página principal y leas al menos esa sección.

Esta publicación se basa en la idea de que los **atacantes intentarán de algún modo imitar o usar el nombre de dominio de la víctima**. Si tu dominio se llama `example.com` y sufres un ataque de phishing que, por algún motivo, usa un nombre de dominio completamente distinto, como `youwonthelottery.com`, estas técnicas no lo descubrirán.

## Variaciones del nombre de dominio

Es bastante **fácil** **detectar** esos intentos de **phishing** que usan un nombre de dominio **similar** en el correo electrónico.\
Basta con **generar una lista de los nombres de phishing más probables** que un atacante podría usar y **comprobar** si están **registrados** o simplemente verificar si alguna **IP** los está usando.

### Cómo encontrar dominios sospechosos

Para ello, puedes usar cualquiera de las siguientes herramientas. Ambas resuelven los dominios candidatos para comprobar si están en uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Consejo: Si generas una lista de candidatos, también puedes introducirla en los registros de tu resolvedor DNS para detectar **consultas NXDOMAIN desde dentro de tu organización** (usuarios que intentan acceder a un error tipográfico antes de que el atacante registre realmente el dominio). Usa un sinkhole o bloquea previamente estos dominios si la política lo permite.

### Bitflipping

**Para una breve explicación, consulta la página principal; para la investigación original sobre bitsquatting en Windows.com, consulta el [artículo de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) y el [informe de BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes podrían registrar tantos dominios generados mediante bit-flipping como sea posible, relacionados con la víctima, para redirigir a usuarios legítimos a su infraestructura**.<sup>[[1]](#references)[[2]](#references)</sup>

**También se deberían supervisar todos los nombres de dominio posibles generados mediante bit-flipping.**

Si también necesitas tener en cuenta homógrafos o dominios IDN visualmente similares (p. ej., mezclas de caracteres latinos y cirílicos), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Comprobaciones básicas

Una vez que tengas una lista de posibles nombres de dominio sospechosos, deberías **comprobarlos** (principalmente los puertos HTTP y HTTPS) para **ver si usan algún formulario de inicio de sesión parecido a uno del dominio de la víctima**.\
También podrías comprobar si el puerto 3333 está abierto y ejecuta una instancia de `gophish`.\
También es interesante saber **qué antigüedad tiene cada dominio sospechoso descubierto**; cuanto más reciente sea, mayor será el riesgo.\
También puedes obtener **capturas de pantalla** de las páginas web sospechosas HTTP o HTTPS para ver si resultan sospechosas y, en ese caso, **acceder a ellas para examinarlas con más detalle**.

### Comprobaciones avanzadas

Si quieres ir un paso más allá, te recomiendo **supervisar esos dominios sospechosos y buscar otros nuevos** de vez en cuando (¿cada día? Solo lleva unos segundos o minutos). También deberías **comprobar** los **puertos** abiertos de las IP relacionadas y **buscar instancias de `gophish` u herramientas similares** (sí, los atacantes también cometen errores), además de **supervisar las páginas web HTTP y HTTPS de los dominios y subdominios sospechosos** para ver si han copiado algún formulario de inicio de sesión de las páginas web de la víctima.\
Para **automatizarlo**, te recomiendo tener una lista de los formularios de inicio de sesión de los dominios de la víctima, rastrear las páginas web sospechosas y comparar cada formulario de inicio de sesión encontrado en los dominios sospechosos con cada formulario de inicio de sesión del dominio de la víctima mediante algo como `ssdeep`.\
Si has localizado los formularios de inicio de sesión de los dominios sospechosos, puedes intentar **enviar credenciales basura** y **comprobar si te redirige al dominio de la víctima**.

---

### Búsqueda mediante favicon y huellas web (Shodan/Censys)

Muchos kits de phishing reutilizan los favicons de la marca que suplantan. Shodan calcula un hash de los datos del favicon codificados en base64 mediante MurmurHash3, mientras que Censys expone sus propios campos de hash de favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Puedes generar un hash compatible con Shodan y buscar coincidencias a partir de él:

Ejemplo en Python (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Consulta Shodan: `http.favicon.hash:309020573`
- Con herramientas: consulta herramientas de la comunidad como favfreak para calcular hashes y generar dorks de Shodan.<sup>[[16]](#references)</sup>

Notas
- Los favicons se reutilizan; trata las coincidencias como pistas y valida el contenido y los certificados antes de actuar.
- Combina heurísticas de antigüedad del dominio y palabras clave para obtener mayor precisión.

### Búsqueda de telemetría de URL (urlscan.io)

`urlscan.io` almacena capturas de pantalla históricas, DOM, solicitudes y metadatos TLS de las URL enviadas. Puedes buscar abusos de marca y clones:<sup>[[8]](#references)</sup>

Ejemplos de consultas (UI o API):
- Encuentra sitios similares excluyendo tus dominios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encuentra sitios que hacen hotlinking de tus recursos: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limita los resultados a los más recientes: añade `AND date:>now-7d`

Ejemplo de API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

A partir del JSON, pivota por:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para detectar certificados muy nuevos de dominios que imitan a otros
- Valores de `task.source`, como `certstream-suspicious`, para vincular los hallazgos con la monitorización de CT

### Antigüedad del dominio mediante RDAP (programable)

RDAP devuelve eventos de registro legibles por máquina. Es útil para señalar **dominios recién registrados (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Enriquece tu pipeline etiquetando los dominios según su antigüedad de registro (p. ej., <7 días, <30 días) y prioriza el triaje en consecuencia.

### Huellas TLS/JAx para detectar infraestructura AiTM

El phishing de credenciales puede usar reverse proxies de **Adversary-in-the-Middle (AiTM)** (p. ej., Evilginx) para robar tokens de sesión.<sup>[[11]](#references)</sup> Puedes añadir detecciones del lado de la red:

- Registra las huellas TLS/HTTP (JA3/JA4/JA4S/JA4H) en el tráfico de salida. Se han observado valores estables de JA4 de cliente/servidor en algunas builds de Evilginx. Genera alertas solo ante huellas conocidas como maliciosas, considerándolas una señal débil, y confirma siempre con inteligencia sobre el contenido y los dominios.<sup>[[12]](#references)</sup>
- Registra de forma proactiva los metadatos de los certificados TLS (emisor, número de SAN, uso de comodines, validez) de los hosts similares detectados mediante CT o urlscan y correlaciónalos con la antigüedad del DNS y la geolocalización.

> Nota: Trata las huellas como datos complementarios, no como único criterio para bloquear; los frameworks evolucionan y pueden aleatorizar u ofuscar las huellas.

### Nombres de dominio con palabras clave

La página principal también menciona una técnica de variación de nombres de dominio que consiste en colocar el **nombre de dominio de la víctima dentro de un dominio más largo** (p. ej., paypal-financial.com para paypal.com).

#### Certificate Transparency

Los logs de Certificate Transparency (CT) exponen las identidades de los certificados, por lo que buscar palabras clave de marcas en los nombres Subject o SAN puede revelar dominios similares (por ejemplo, un certificado para `paypal-financial.com` expone la palabra clave `paypal`). Cuando sea útil, filtra los resultados por fecha de emisión y CA, y valida los candidatos, ya que las coincidencias de palabras clave pueden ser falsos positivos.<sup>[[13]](#references)</sup>

El [artículo original de caza de dominios de phishing](https://0xpatrik.com/phishing-domains/) de Patrik Hudak muestra este flujo de trabajo en Censys, incluidos los filtros por fecha del certificado y emisor, como Let's Encrypt.<sup>[[13]](#references)</sup>

![Resultados de búsqueda de certificados en Censys utilizados para identificar dominios similares](<../../images/image (1115).png>)

También puedes usar el servicio gratuito [**crt.sh**](https://crt.sh) para buscar una palabra clave y filtrar los resultados por fecha y CA.<sup>[[13]](#references)</sup>

![Búsqueda de palabras clave en crt.sh para encontrar identidades de certificados sospechosas](<../../images/image (519).png>)

El campo Matching Identities puede ayudar a comparar identidades del dominio real con las de dominios sospechosos, pero trata las coincidencias como pistas, no como pruebas.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) transmite actualizaciones de CT casi en tiempo real, y [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consume ese flujo para puntuar nombres de certificados sospechosos.<sup>[[14]](#references)[[15]](#references)</sup>

Consejo práctico: al clasificar alertas de CT, prioriza los NRD, los registradores no confiables o desconocidos, los WHOIS con proxy de privacidad y los certificados con valores `NotBefore` muy recientes. Mantén una lista de permitidos de tus dominios y marcas para reducir el ruido.

#### **Dominios nuevos**

Otra opción es recopilar dominios recién registrados por TLD (por ejemplo, mediante [Whoxy](https://www.whoxy.com/newly-registered-domains/)) y filtrar por palabras clave de marcas. Esto no detecta el phishing alojado en subdominios cuando la palabra clave no aparece en el dominio registrado.<sup>[[13]](#references)</sup>

Heurística adicional: considera ciertos **TLD de extensiones de archivo** (p. ej., `.zip`, `.mov`) especialmente sospechosos al generar alertas. A menudo se confunden con nombres de archivo en los señuelos; combina la señal del TLD con palabras clave de marcas y la antigüedad del NRD para mejorar la precisión.

## References

- [1] [Remy Hax – Bitsquatting en Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Secuestro del tráfico hacia windows.com de Microsoft mediante bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Análisis en profundidad: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentación de mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Conjunto de datos de propiedades web de Platform](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referencia de la API de búsqueda](https://urlscan.io/docs/search/)
- [9] [Ayuda del protocolo de acceso a datos de registro](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Respuestas JSON para el protocolo de acceso a datos de registro](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Tácticas con tokens: cómo prevenir, detectar y responder al robo de tokens en la nube](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [Blog de APNIC – Huellas de red JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Cómo encontrar phishing: herramientas y técnicas](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Presentación de CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
