# Detección de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introducción

Para detectar un intento de phishing es importante **entender las técnicas de phishing que se están usando hoy en día**. En la página padre de esta entrada puedes encontrar esa información, así que si no conoces qué técnicas se usan actualmente te recomiendo ir a la página padre y leer al menos esa sección.

Esta entrada se basa en la idea de que **los atacantes intentarán de alguna manera imitar o usar el nombre de dominio de la víctima**. Si tu dominio se llama `example.com` y eres phished usando un nombre de dominio completamente diferente por alguna razón como `youwonthelottery.com`, estas técnicas no lo van a descubrir.

## Variaciones del nombre de dominio

Es bastante **fácil** **descubrir** esos intentos de **phishing** que usarán un **dominio similar** dentro del correo.\
Basta con **generar una lista de los nombres de phishing más probables** que un atacante puede usar y **comprobar** si está **registrado** o simplemente verificar si hay alguna **IP** usándolo.

### Encontrar dominios sospechosos

Para este propósito puedes usar cualquiera de las siguientes herramientas. Ten en cuenta que estas herramientas también realizarán consultas DNS automáticamente para comprobar si el dominio tiene alguna IP asignada:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: Si generas una lista de candidatos, también introdúcela en los logs de tu DNS resolver para detectar **NXDOMAIN lookups from inside your org** (usuarios intentando alcanzar un typo antes de que el atacante lo registre realmente). Sinkhole o pre-block estos dominios si la política lo permite.

### Bitflipping

**Puedes encontrar una breve explicación de esta técnica en la página padre. O lee la investigación original en** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios bit-flipping como les sea posible relacionados con la víctima para redirigir usuarios legítimos a su infraestructura**.

**Todos los posibles nombres de dominio bit-flipping también deben ser monitorizados.**

Si además necesitas considerar homoglyph/IDN lookalikes (p. ej., mezcla de caracteres Latinos/Cirílicos), revisa:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Comprobaciones básicas

Una vez que tengas una lista de nombres de dominio potencialmente sospechosos deberías **comprobarlos** (principalmente los puertos HTTP y HTTPS) para **ver si están usando algún formulario de login similar** a los de alguno de los dominios de la víctima.\
También podrías comprobar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **qué edad tiene cada dominio sospechoso descubierto**, cuanto más joven sea, más riesgo implica.\
También puedes obtener **capturas de pantalla** de la página web HTTP y/o HTTPS sospechosa para ver si resulta sospechosa y, en ese caso, **acceder a ella para inspeccionarla más a fondo**.

### Comprobaciones avanzadas

Si quieres ir un paso más allá te recomendaría **monitorizar esos dominios sospechosos y buscar más** de vez en cuando (¿cada día? solo toma unos segundos/minutos). También deberías **comprobar** los **puertos** abiertos de las IPs relacionadas y **buscar instancias de `gophish` o herramientas similares** (sí, los atacantes también cometen errores) y **monitorizar las páginas web HTTP y HTTPS de los dominios y subdominios sospechosos** para ver si han copiado algún formulario de login de las páginas de la víctima.\
Para **automatizar esto** recomendaría tener una lista de formularios de login de los dominios de la víctima, spiderear las páginas sospechosas y comparar cada formulario de login encontrado dentro de los dominios sospechosos con cada formulario de login del dominio de la víctima usando algo como `ssdeep`.\
Si has localizado los formularios de login de los dominios sospechosos, puedes intentar **enviar credenciales basura** y **comprobar si te redirige al dominio de la víctima**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Muchos kits de phishing reutilizan favicons de la marca que suplantan. Los escáneres a escala de Internet calculan un MurmurHash3 del favicon codificado en base64. Puedes generar el hash y pivotar en él:

Ejemplo en Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consulta en Shodan: `http.favicon.hash:309020573`
- Con herramientas: revisa herramientas comunitarias como favfreak para generar hashes y dorks para Shodan/ZoomEye/Censys.

Notes
- Favicons se reutilizan; trata las coincidencias como pistas y valida el contenido y los certs antes de actuar.
- Combina con heurísticas de domain-age y keyword para mejorar la precisión.

### Búsqueda de telemetría de URL (urlscan.io)

`urlscan.io` almacena capturas de pantalla históricas, DOM, requests y metadata TLS de las URLs enviadas. Puedes buscar abuso de marca y clones:

Example queries (UI or API):
- Find lookalikes excluding your legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Find sites hotlinking your assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restrict to recent results: append `AND date:>now-7d`

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
A partir del JSON, céntrate en:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para detectar certificados muy nuevos usados en dominios lookalike
- `task.source` valores como `certstream-suspicious` para vincular los hallazgos con el monitoreo CT

### Edad del dominio vía RDAP (automatizable)

RDAP devuelve eventos de creación legibles por máquina. Útil para marcar **dominios recién registrados (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriquece tu pipeline etiquetando dominios por rangos de edad de registro (p. ej., <7 días, <30 días) y prioriza el triage en consecuencia.

### TLS/JAx fingerprints para detectar infraestructura AiTM

El credential-phishing moderno utiliza cada vez más reverse proxies Adversary-in-the-Middle (AiTM) (p. ej., Evilginx) para robar session tokens. Puedes añadir detecciones en el lado de la red:

- Registra TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) en egress. Algunas builds de Evilginx se han observado con valores JA4 cliente/servidor estables. Genera alertas por fingerprints known-bad solo como una señal débil y confirma siempre con contenido y domain intel.
- Registra proactivamente TLS certificate metadata (issuer, SAN count, wildcard use, validity) para lookalike hosts descubiertos vía CT o urlscan y correlaciónalo con DNS age y geolocation.

> Nota: Trata los fingerprints como enriquecimiento, no como bloqueadores únicos; los frameworks evolucionan y pueden aleatorizarse u ofuscarse.

### Domain names using keywords

La página padre también menciona una técnica de variación de nombres de dominio que consiste en insertar el **nombre de dominio de la víctima dentro de un dominio más grande** (p. ej., paypal-financial.com para paypal.com).

#### Transparencia de certificados

No es posible tomar el enfoque anterior de "Brute-Force", pero en realidad sí es **posible descubrir estos intentos de phishing** también gracias a Certificate Transparency. Cada vez que una CA emite un certificado, los detalles se hacen públicos. Esto significa que al leer Certificate Transparency o incluso monitorizarlo, es **posible encontrar dominios que usan una palabra clave dentro de su nombre**. Por ejemplo, si un atacante genera un certificado de [https://paypal-financial.com](https://paypal-financial.com), al ver el certificado es posible encontrar la palabra clave "paypal" y saber que se está usando un email sospechoso.

La entrada [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugiere que puedes usar Censys para buscar certificados que afecten a una palabra clave específica y filtrar por fecha (solo certificados "nuevos") y por la CA emisora "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Sin embargo, puedes hacer "lo mismo" usando la web gratuita [**crt.sh**](https://crt.sh). Puedes **buscar la palabra clave** y **filtrar** los resultados **por fecha y CA** si lo deseas.

![](<../../images/image (519).png>)

Usando esta última opción incluso puedes usar el campo Matching Identities para ver si alguna identidad del dominio real coincide con alguno de los dominios sospechosos (nota: un dominio sospechoso puede ser un falso positivo).

**Otra alternativa** es el fantástico proyecto llamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream proporciona un flujo en tiempo real de certificados recién generados que puedes usar para detectar palabras clave especificadas en tiempo (casi) real. De hecho, existe un proyecto llamado [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) que hace precisamente eso.

Consejo práctico: al triagear los hits de CT, prioriza NRDs, registradores no confiables/desconocidos, privacy-proxy WHOIS y certs con tiempos `NotBefore` muy recientes. Mantén una allowlist de tus dominios/marcas para reducir ruido.

#### **Nuevos dominios**

**Una última alternativa** es recopilar una lista de **dominios recién registrados** para algunos TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) proporciona ese servicio) y **comprobar las palabras clave en estos dominios**. Sin embargo, los dominios largos normalmente usan uno o más subdominios, por lo que la palabra clave no aparecerá dentro del FLD y no podrás encontrar el subdominio de phishing.

Heurística adicional: trata ciertos **file-extension TLDs** (p. ej., `.zip`, `.mov`) con mayor sospecha en las alertas. Estos suelen confundirse con nombres de archivo en los lures; combina la señal del TLD con brand keywords y NRD age para mayor precisión.

## Referencias

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (incluye ejemplo Evilginx): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
