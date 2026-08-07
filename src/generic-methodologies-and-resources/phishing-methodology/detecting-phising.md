# Detectando Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introducción

Para detectar un intento de phishing es importante **entender las técnicas de phishing que se utilizan actualmente**. En la página principal de este post puedes encontrar esta información, así que si no sabes qué técnicas se utilizan hoy en día, te recomiendo ir a la página principal y leer al menos esa sección.

Este post se basa en la idea de que los **atacantes intentarán de alguna manera imitar o utilizar el nombre de dominio de la víctima**. Si tu dominio se llama `example.com` y sufres phishing utilizando por alguna razón un nombre de dominio completamente diferente, como `youwonthelottery.com`, estas técnicas no lo descubrirán.

## Variaciones del nombre de dominio

Es bastante **fácil** **descubrir** esos intentos de **phishing** que utilizarán un nombre de dominio **similar** dentro del email.\
Solo tienes que **generar una lista de los nombres de phishing más probables** que podría utilizar un atacante y **comprobar** si está **registrado**, o simplemente comprobar si hay alguna **IP** utilizándolo.

### Encontrar dominios sospechosos

Para este propósito, puedes utilizar cualquiera de las siguientes herramientas. Ten en cuenta que estas herramientas también realizarán automáticamente solicitudes DNS para comprobar si el dominio tiene alguna IP asignada:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Consejo: Si generas una lista de candidatos, introdúcela también en los logs de tu resolvedor DNS para detectar **búsquedas NXDOMAIN desde dentro de tu organización** (usuarios intentando acceder a un typo antes de que el atacante lo registre). Redirige estos dominios a un sinkhole o bloquéalos previamente si la política lo permite.

### Bitflipping

**Puedes encontrar una breve explicación de esta técnica en la página principal. O leer la investigación original en** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios de bit-flipping como sea posible relacionados con la víctima para redirigir a los usuarios legítimos hacia su infraestructura**.<sup>[[1]](#references)</sup>

**También se deben monitorizar todos los posibles nombres de dominio de bit-flipping.**

Si también necesitas considerar homógrafos/lookalikes de IDN (por ejemplo, mezclando caracteres latinos y cirílicos), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Comprobaciones básicas

Una vez que tengas una lista de posibles nombres de dominio sospechosos, deberías **comprobarlos** (principalmente los puertos HTTP y HTTPS) para **ver si utilizan algún formulario de login similar** al de alguno de los dominios de la víctima.\
También podrías comprobar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **qué antigüedad tiene cada dominio sospechoso descubierto**; cuanto más reciente sea, mayor será el riesgo.\
También puedes obtener **screenshots** de la página web HTTP y/o HTTPS sospechosa para ver si es sospechosa y, en ese caso, **acceder a ella para examinarla con más detalle**.

### Comprobaciones avanzadas

Si quieres ir un paso más allá, te recomiendo **monitorizar esos dominios sospechosos y buscar más de vez en cuando** (¿cada día? solo lleva unos segundos/minutos). También deberías **comprobar** los **puertos** abiertos de las IP relacionadas y **buscar instancias de `gophish` o herramientas similares** (sí, los atacantes también cometen errores), así como **monitorizar las páginas web HTTP y HTTPS de los dominios y subdominios sospechosos** para comprobar si han copiado algún formulario de login de las páginas web de la víctima.\
Para **automatizar esto**, te recomiendo tener una lista de los formularios de login de los dominios de la víctima, hacer spidering de las páginas web sospechosas y comparar cada formulario de login encontrado dentro de los dominios sospechosos con cada formulario de login del dominio de la víctima utilizando algo como `ssdeep`.\
Si has localizado los formularios de login de los dominios sospechosos, puedes intentar **enviar credenciales basura** y **comprobar si te redirige al dominio de la víctima**.

---

### Hunting mediante favicon y fingerprints web (Shodan/ZoomEye/Censys)

Muchos kits de phishing reutilizan favicons de la marca que suplantan. Los scanners de Internet calculan un MurmurHash3 del favicon codificado en base64. Puedes generar el hash y pivotar sobre él:

Ejemplo en Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consultar Shodan: `http.favicon.hash:309020573`
- Con tooling: consulta herramientas de la comunidad como favfreak para generar hashes y dorks para Shodan/ZoomEye/Censys.

Notas
- Los favicons se reutilizan; trata las coincidencias como indicios y valida el contenido y los certificados antes de actuar.
- Combínalo con heurísticas de antigüedad del dominio y palabras clave para obtener mayor precisión.

### Búsqueda de telemetría de URL (urlscan.io)

`urlscan.io` almacena capturas de pantalla históricas, DOM, solicitudes y metadatos de TLS de las URL enviadas. Puedes buscar abuso de marca y clones:<sup>[[2]](#references)</sup>

Consultas de ejemplo (UI o API):
- Encontrar sitios similares excluyendo tus dominios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encontrar sitios que cargan tus recursos mediante hotlinking: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limitar a resultados recientes: añade `AND date:>now-7d`

Ejemplo de API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Desde el JSON, filtra por:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para detectar certificados muy recientes en lookalikes
- valores de `task.source` como `certstream-suspicious` para vincular los hallazgos con la monitorización de CT

### Antigüedad del dominio mediante RDAP (automatizable mediante scripts)

RDAP devuelve eventos de creación legibles por máquinas. Es útil para identificar **dominios registrados recientemente (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriquece tu pipeline etiquetando los dominios con categorías de antigüedad de registro (por ejemplo, <7 días, <30 días) y prioriza el triage en consecuencia.

### TLS/JAx fingerprints para detectar infraestructura AiTM

El credential-phishing moderno utiliza cada vez más reverse proxies **Adversary-in-the-Middle (AiTM)** (por ejemplo, Evilginx) para robar session tokens. Puedes añadir detecciones en el lado de la red:

- Registra fingerprints TLS/HTTP (JA3/JA4/JA4S/JA4H) en el tráfico de salida. Se han observado algunos builds de Evilginx con valores JA4 de cliente/servidor estables. Genera alertas sobre fingerprints conocidos como maliciosos únicamente como señal débil y confirma siempre con inteligencia de contenido y de dominios.<sup>[[3]](#references)</sup>
- Registra proactivamente los metadatos de los certificados TLS (emisor, cantidad de SAN, uso de wildcard y validez) de los hosts parecidos descubiertos mediante CT o urlscan, y correlaciónalos con la antigüedad del DNS y la geolocalización.

> Nota: Trata los fingerprints como información de enriquecimiento, no como bloqueadores únicos; los frameworks evolucionan y pueden aleatorizar u ofuscar estos datos.

### Domain names using keywords

La página principal también menciona una técnica de variación del nombre de dominio que consiste en poner el **nombre de dominio de la víctima dentro de un dominio más grande** (por ejemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

No es posible aplicar el enfoque anterior de "Brute-Force", pero sí es **posible descubrir este tipo de intentos de phishing** gracias también a certificate transparency. Cada vez que una CA emite un certificado, sus detalles se hacen públicos. Esto significa que, leyendo certificate transparency o incluso monitorizándolo, es **posible encontrar dominios que utilizan una keyword dentro de su nombre**. Por ejemplo, si un atacante genera un certificado para [https://paypal-financial.com](https://paypal-financial.com), al ver el certificado es posible encontrar la keyword "paypal" y saber que se está utilizando un email sospechoso.

El post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugiere que puedes utilizar Censys para buscar certificados relacionados con una keyword específica y filtrar por fecha (solo certificados "nuevos") y por el emisor de la CA "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Sin embargo, puedes hacer "lo mismo" utilizando la web gratuita [**crt.sh**](https://crt.sh). Puedes **buscar la keyword** y **filtrar** los resultados **por fecha y CA** si lo deseas.

![Domain names using keywords - Certificate Transparency: However, you can do "the same" using the free web crt.sh . You can search for the keyword and the filter the results by date and...](<../../images/image (519).png>)

Con esta última opción incluso puedes utilizar el campo Matching Identities para comprobar si alguna identidad del dominio real coincide con alguno de los dominios sospechosos (ten en cuenta que un dominio sospechoso puede ser un falso positivo).

**Otra alternativa** es el fantástico proyecto llamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream proporciona un stream en tiempo real de certificados recién generados que puedes utilizar para detectar keywords específicas en tiempo (casi) real. De hecho, existe un proyecto llamado [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) que hace precisamente eso.

Consejo práctico: al hacer triage de resultados de CT, prioriza los NRD, los registrars no confiables/desconocidos, el WHOIS con privacy-proxy y los certificados con valores `NotBefore` muy recientes. Mantén una allowlist de tus dominios/brands propios para reducir el ruido.

#### **Nuevos dominios**

**Una última alternativa** es recopilar una lista de **dominios recién registrados** para algunos TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) ofrece este servicio) y **comprobar las keywords en estos dominios**. Sin embargo, los dominios largos suelen utilizar uno o más subdominios; por lo tanto, la keyword no aparecerá dentro del FLD y no podrás encontrar el subdominio de phishing.

Heurística adicional: trata ciertos **file-extension TLDs** (por ejemplo, `.zip`, `.mov`) con especial sospecha en las alertas. Suelen confundirse con nombres de archivos en los lures; combina la señal del TLD con keywords de brands y la antigüedad del NRD para obtener mayor precisión.

## Referencias

- [1] [Secuestro del tráfico de windows.com de Microsoft mediante bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Referencia de Search API](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – Fingerprinting de red JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Encontrar phishing: herramientas y técnicas](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
