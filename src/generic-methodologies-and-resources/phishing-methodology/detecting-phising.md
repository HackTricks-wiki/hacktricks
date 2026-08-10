# Detectando Phishing

## Introducción

Para detectar un intento de phishing es importante **entender las técnicas de phishing que se utilizan actualmente**. En la página principal de esta publicación puedes encontrar esta información, así que si no sabes qué técnicas se están utilizando hoy en día, te recomiendo que visites la página principal y leas al menos esa sección.

Esta publicación se basa en la idea de que los **atacantes intentarán imitar o utilizar de alguna forma el nombre de dominio de la víctima**. Si tu dominio se llama `example.com` y sufres un ataque de phishing utilizando por algún motivo un nombre de dominio completamente diferente, como `youwonthelottery.com`, estas técnicas no lo descubrirán.

## Variaciones del nombre de dominio

Es bastante **fácil** **descubrir** esos intentos de **phishing** que utilizarán un nombre de **dominio similar** dentro del correo electrónico.\
Solo hay que **generar una lista de los nombres de phishing más probables** que un atacante podría utilizar y **comprobar** si están **registrados**, o simplemente comprobar si hay alguna **IP** utilizándolos.

### Encontrar dominios sospechosos

Para este propósito, puedes utilizar cualquiera de las siguientes herramientas. Ambas resuelven los dominios candidatos para comprobar si están en uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Consejo: Si generas una lista de candidatos, introdúcela también en los logs de tu resolvedor DNS para detectar **consultas NXDOMAIN desde dentro de tu organización** (usuarios intentando acceder a un typo antes de que el atacante lo registre). Redirige estos dominios a un sinkhole o bloquéalos previamente si la política lo permite.

### Bitflipping

**Para una explicación breve, consulta la página principal; para la investigación principal sobre bitsquatting de Windows.com, consulta el [análisis de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) y el [informe de BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios de bit-flipping como sea posible relacionados con la víctima para redirigir a los usuarios legítimos hacia su infraestructura**.<sup>[[1]](#references)[[2]](#references)</sup>

**También se deben monitorizar todos los nombres de dominio posibles de bit-flipping.**

Si también necesitas tener en cuenta los homoglyphs/lookalikes de IDN (por ejemplo, mezclando caracteres latinos y cirílicos), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Comprobaciones básicas

Una vez que tengas una lista de posibles nombres de dominio sospechosos, deberías **comprobarlos** (principalmente los puertos HTTP y HTTPS) para **ver si utilizan algún formulario de inicio de sesión similar** al de algún dominio de la víctima.\
También podrías comprobar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **qué antigüedad tiene cada dominio sospechoso descubierto**; cuanto más reciente sea, mayor será el riesgo.\
También puedes obtener **capturas de pantalla** de la página web sospechosa HTTP y/o HTTPS para ver si resulta sospechosa y, en ese caso, **acceder a ella para examinarla con más detalle**.

### Comprobaciones avanzadas

Si quieres ir un paso más allá, te recomiendo **monitorizar esos dominios sospechosos y buscar más de vez en cuando** (¿cada día? Solo lleva unos segundos o minutos). También deberías **comprobar** los **puertos** abiertos de las IP relacionadas y **buscar instancias de `gophish` o herramientas similares** (sí, los atacantes también cometen errores), además de **monitorizar las páginas web HTTP y HTTPS de los dominios y subdominios sospechosos** para comprobar si han copiado algún formulario de inicio de sesión de las páginas web de la víctima.\
Para **automatizar esto**, te recomiendo tener una lista de los formularios de inicio de sesión de los dominios de la víctima, hacer spidering de las páginas web sospechosas y comparar cada formulario de inicio de sesión encontrado dentro de los dominios sospechosos con cada formulario de inicio de sesión del dominio de la víctima utilizando algo como `ssdeep`.\
Si has localizado los formularios de inicio de sesión de los dominios sospechosos, puedes intentar **enviar credenciales basura** y **comprobar si te redirige al dominio de la víctima**.

---

### Búsqueda mediante favicon y fingerprints web (Shodan/Censys)

Muchos kits de phishing reutilizan los favicons de la marca que están suplantando. Shodan calcula un hash de sus datos de favicon codificados en base64 con MurmurHash3, mientras que Censys expone sus propios campos de hash de favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Puedes generar un hash compatible con Shodan y pivotar sobre él:

Ejemplo en Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consultar Shodan: `http.favicon.hash:309020573`
- Con tooling: consulta herramientas de la comunidad como favfreak para calcular hashes y generar dorks de Shodan.<sup>[[16]](#references)</sup>

Notas
- Los favicons se reutilizan; trata las coincidencias como pistas y valida el contenido y los certificados antes de actuar.
- Combínalo con heurísticas de antigüedad del dominio y palabras clave para obtener mayor precisión.

### Búsqueda de telemetría de URL (urlscan.io)

`urlscan.io` almacena capturas de pantalla históricas, el DOM, las solicitudes y los metadatos TLS de las URL enviadas. Puedes buscar abusos de marca y clones:<sup>[[8]](#references)</sup>

Consultas de ejemplo (UI o API):
- Encontrar imitaciones excluyendo tus dominios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encontrar sitios que enlazan directamente a tus recursos: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limitar a resultados recientes: añadir `AND date:>now-7d`

Ejemplo de API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Desde el JSON, pivota sobre:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para detectar certificados muy recientes en dominios similares
- valores de `task.source` como `certstream-suspicious` para vincular los hallazgos con la monitorización de CT

### Antigüedad del dominio mediante RDAP (automatizable)

RDAP devuelve eventos de registro legibles por máquinas. Es útil para marcar **dominios registrados recientemente (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriquece tu pipeline etiquetando los dominios con categorías de antigüedad de registro (por ejemplo, <7 días, <30 días) y prioriza el triage en consecuencia.

### Fingerprints TLS/JAx para detectar infraestructura AiTM

El credential-phishing puede utilizar reverse proxies **Adversary-in-the-Middle (AiTM)** (por ejemplo, Evilginx) para robar tokens de sesión.<sup>[[11]](#references)</sup> Puedes añadir detecciones en el lado de la red:

- Registra fingerprints TLS/HTTP (JA3/JA4/JA4S/JA4H) en el tráfico de salida. Se han observado algunas builds de Evilginx con valores JA4 de cliente/servidor estables. Genera alertas sobre fingerprints conocidos como maliciosos solo como señal débil y confirma siempre con inteligencia de contenido y de dominios.<sup>[[12]](#references)</sup>
- Registra de forma proactiva los metadatos de los certificados TLS (emisor, número de SAN, uso de wildcard, validez) de los hosts similares descubiertos mediante CT o urlscan y correlaciónalos con la antigüedad del DNS y la geolocalización.

> Nota: Trata los fingerprints como enriquecimiento, no como bloqueadores únicos; los frameworks evolucionan y pueden aleatorizarse u ofuscarse.

### Nombres de dominio que utilizan keywords

La página principal también menciona una técnica de variación del nombre de dominio que consiste en colocar el **nombre de dominio de la víctima dentro de un dominio más grande** (por ejemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

Los logs de Certificate Transparency (CT) exponen las identidades de los certificados, por lo que buscar keywords de marcas en los nombres Subject o SAN puede revelar dominios similares (por ejemplo, un certificado para `paypal-financial.com` expone la keyword `paypal`). Filtra los resultados por fecha de emisión y CA cuando sea útil, y valida los candidatos porque las coincidencias de keywords pueden ser falsos positivos.<sup>[[13]](#references)</sup>

El [write-up original sobre búsqueda de dominios de phishing](https://0xpatrik.com/phishing-domains/) de Patrik Hudak demuestra este workflow en Censys, incluidos filtros para la fecha del certificado y el emisor, como Let's Encrypt.<sup>[[13]](#references)</sup>

También puedes utilizar el servicio gratuito [**crt.sh**](https://crt.sh) para buscar una keyword y filtrar los resultados por fecha y CA.<sup>[[13]](#references)</sup>

Su campo Matching Identities puede ayudar a comparar identidades del dominio real con dominios sospechosos, pero trata las coincidencias como indicios y no como pruebas.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) transmite actualizaciones de CT casi en tiempo real, y [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consume ese stream para asignar una puntuación a nombres de certificados sospechosos.<sup>[[14]](#references)[[15]](#references)</sup>

Consejo práctico: al hacer triage de resultados de CT, prioriza los NRD, los registradores no confiables/desconocidos, el WHOIS con privacy-proxy y los certificados con tiempos `NotBefore` muy recientes. Mantén una allowlist de tus dominios/marcas propios para reducir el ruido.

#### **Nuevos dominios**

Otra opción es recopilar dominios registrados recientemente por TLD (por ejemplo, mediante [Whoxy](https://www.whoxy.com/newly-registered-domains/)) y filtrar por keywords de marcas. Esto no detecta el phishing alojado en subdominios cuando la keyword no aparece en el dominio registrado.<sup>[[13]](#references)</sup>

Heurística adicional: trata ciertos **TLD de extensiones de archivo** (por ejemplo, `.zip`, `.mov`) con mayor sospecha en las alertas. Estos suelen confundirse con nombres de archivo en los lures; combina la señal del TLD con las keywords de marca y la antigüedad del NRD para mejorar la precisión.

## References

- [1] [Remy Hax – Bitsquatting de Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Secuestro del tráfico hacia windows.com de Microsoft mediante bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Análisis profundo: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentación de mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Conjunto de datos de propiedades web de la plataforma](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referencia de la Search API](https://urlscan.io/docs/search/)
- [9] [Ayuda del Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Respuestas JSON para el Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Tácticas de tokens: cómo prevenir, detectar y responder al robo de tokens cloud](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Fingerprinting de red JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Encontrar phishing: herramientas y técnicas](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Presentación de CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
