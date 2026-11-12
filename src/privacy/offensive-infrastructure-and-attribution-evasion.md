# Infraestructura ofensiva y evasión de atribución

{{#include ../banners/hacktricks-training.md}}

Un operador rara vez obtiene un anonimato significativo con un solo proxy. Las campañas reales construyen un **grafo de separación**: el operador llega a un nodo de acceso, los nodos de tránsito ocultan ese nodo de salida, los redirectors protegen el C2 real y los nombres desechables apuntan al borde público.

Consulta el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) para obtener una perspectiva normalizada de las ventajas, desventajas, implementación y detección de cada ruta. Esta página profundiza en la composición de infraestructura adversaria.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

La última dirección que ve un objetivo es, por tanto, evidencia de una ruta, no una prueba de quién controlaba el teclado. MITRE asigna los componentes principales a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) y Web Service (T1102).<sup>[[1]](#references)</sup>

## Clases de infraestructura

| Clase | Por qué la usa un actor | Exposición duradera | Mejor punto de pivote para el defensor |
|---|---|---|---|
| VPS/nube alquilada | Rápida, predecible, enrutable y fácil de reconstruir | Historial del inquilino, facturación, consola, inicios de sesión de origen e imágenes | Eventos de la cuenta/plano de control y huellas de servidor repetidas |
| VPN comercial/Tor | Gran conjunto de salidas compartidas; no requiere administrar servidores | Visibilidad del proveedor/de la guardia y temporización de extremo a extremo | Comportamiento del destino, evidencia del endpoint y correlación de flujos |
| Proxy residencial/móvil | ASN de consumidor y plausibilidad geográfica | Registros del intermediario/cliente; comportamiento de proxyware o de un host infectado | Desplazamientos imposibles, protocolos de proxy y cambios de dirección por sesión |
| Servidor/router/IoT comprometido | Toma prestada la reputación y jurisdicción de la víctima | Implant, flujo de administración y controlador upstream recurrente | Telemetría del dispositivo y topología ORB, no una única IP de salida |
| CDN/redirector | Separa el edge público del C2 back-end | Artefactos de TLS/HTTP, certificado, enrutamiento y cuenta cloud | Correlación entre edge y origen, y agrupación por forma de solicitudes |
| Servicio web legítimo | Se mezcla con el tráfico permitido de GitHub/cloud/redes sociales | Token de API, identificadores de inquilino/objeto y linaje inusual de procesos | Proceso del endpoint y semántica del servicio/API |
| Ruta física/celular/satelital | Cambia el origen físico aparente | Registros de RF, operador, abonado, dispositivo y ubicación | Evidencia de radio/física y de red combinada |

## Redes operativas de nodos de retransmisión

Una **red ORB** es una flota de proxy administrada y utilizada como servicio intermediario. Mandiant las divide en redes aprovisionadas de servidores arrendados, redes no aprovisionadas de routers/IoT comprometidos e híbridas. Una topología madura tiene cuatro roles lógicos:<sup>[[2]](#references)</sup>

1. **Servidor de administración (ACOS):** mantiene el inventario, las credenciales, el estado y la política de enrutamiento.
2. **Nodo de acceso/retransmisión:** autentica a clientes u operadores; es la entrada estable a una malla cambiante.
3. **Nodos de tránsito:** uno o más sistemas arrendados o comprometidos retransmiten conexiones opacas.
4. **Nodo de salida/preparación:** presenta la dirección de origen final a los objetivos de reconocimiento, explotación o C2.

La malla puede seleccionar salidas por país, ASN, latencia o disponibilidad, y rotar los nodos que no estén en buen estado. Varios grupos de amenazas pueden alquilar la misma red. Mandiant observó que algunas direcciones IPv4 permanecieron asociadas con ciertas ORB tan solo 31 días; por ello recomienda tratar la **red como una entidad cambiante, similar a un actor**, en lugar de bloquear una lista obsoleta de IP.<sup>[[2]](#references)</sup>

### Qué ofrece y qué filtra

- El objetivo ve una salida que puede estar geográficamente cerca y parecer residencial.
- La salida ve al objetivo y al salto anterior, pero no necesariamente al operador.
- El servicio de acceso ve al cliente y la solicitud de ruta. Una malla administrada de forma independiente puede mantener al cliente separado de las salidas, pero genera un registro valioso para la contraparte.
- Los puertos recurrentes, el orden de los handshakes, los banners del servidor, los certificados, los periodos de actividad y las relaciones entre controladores pueden revelar la flota incluso mientras rotan las IP.
- Un router comprometido suele carecer de telemetría de endpoint, pero su ISP conserva datos de abonado y de flujo; una incautación revela artefactos del implant y de configuración.

{% hint style="info" %}
Para un ejercicio autorizado, reproduce la topología con VM o routers propiedad de la organización y conserva el mapa de atribución del controlador. No reclutes proxies abiertos ni dispositivos de terceros. La [guía del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la misma estructura de saltos visible para los defensores sin victimizar a un intermediario.
{% endhint %}

## Redes de proxy residencial y móvil

Los servicios de proxy residencial asignan sesiones a direcciones de banda ancha de consumidores; los proxies móviles salen por grupos de NAT de operadores. El suministro puede proceder de dispositivos inscritos expresamente, SDK/proxyware incluidos en aplicaciones de consumo, revendedores o malware. Estos orígenes no son equivalentes: la falta de consentimiento informado convierte un servicio de privacidad en infraestructura comprometida.

Los modos de rotación afectan a la detección:

- La **rotación por solicitud** produce discontinuidades rápidas de IP y ASN/geografía mientras la identidad de capas superiores se mantiene estable.
- Las **sesiones persistentes** conservan una salida durante minutos u horas, lo que se parece a un abonado común.
- Las **pasarelas de conexión inversa** exponen al cliente un único endpoint del intermediario y eligen las salidas internamente.
- Los **grupos móviles** sitúan a muchos abonados reales detrás de un pequeño conjunto de direcciones NAT de operador, por lo que bloquear una IP puede resultar costoso.

Los defensores deben correlacionar la IP con la sesión autenticada, la huella TLS/del cliente, el orden HTTP, la cookie del dispositivo y el comportamiento. Un inicio de sesión supuestamente local desde una dirección residencial, seguido de otro desde un país distinto mientras todas las características de capas superiores siguen siendo idénticas, es una señal más sólida que la reputación por sí sola. En cambio, el uso compartido de direcciones y el cambio entre celdas móviles generan cambios legítimos, así que nunca se debe tratar la clasificación residencial/de proxy como un veredicto.

### Planos de control de proxyware y solapamiento entre revendedores

No modeles un grupo residencial como una lista plana de salidas. El análisis del ecosistema IPIDEA reveló un **plano de control reutilizable de dos niveles**: un SDK integrado primero comunica metadatos del dispositivo/inscripción a un dominio Tier One y recibe pares IP:puerto `connect`/`proxy` de Tier Two junto con la programación. El nodo consulta periódicamente el puerto connect de Tier Two para obtener una tarea codificada, abre una segunda conexión al puerto proxy asociado y retransmite los bytes proporcionados al destino solicitado. SDK y marcas de proxy aparentemente distintos tenían dominios de descubrimiento separados, pero convergían en infraestructura compartida de Tier Two y grupos de salida solapados mediante relaciones de propiedad común y reventa.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Esto genera pivotes de hunting más duraderos que un bloque de IP residencial:<sup>[[13]](#references)</sup>

- un proceso inesperado de utilidad, VPN, juego o dispositivo integrado envía un ID de dispositivo/clave de cliente estable y recibe una lista de servidores cambiante;
- el endpoint consulta una IP directa en un puerto inusual y, justo antes de abrir un socket hacia un nuevo destino, se conecta a otro puerto en la misma dirección;
- varias marcas aparentes comparten direcciones Tier Two, gramática de protocolo, código SDK o solapamiento de nodos de salida;
- distintas aplicaciones que se comunican con diferentes dominios Tier One reciben direcciones del mismo grupo Tier Two.

El solapamiento también limita la atribución: ver una IP en el grupo anunciado por un proveedor no demuestra qué revendedor, cliente o actor de amenazas la usó en ese momento. Conserva las marcas de tiempo del flujo, la relación de procesos, los cuerpos de respuesta de Tier One y los identificadores de tareas de Tier Two.<sup>[[13]](#references)</sup> En un ejercicio autorizado, emula esta jerarquía solo con endpoints propiedad de la organización; nunca inscribas dispositivos de consumidores ni software proxy de terceros.

## Multi-hop proxy chains

MITRE distingue los proxies externos de **multi-hop proxies (T1090.003)**. La propiedad importante no es la cantidad de saltos, sino la separación del conocimiento y la administración.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Si una misma parte opera A y B, los logs compartidos o la sincronización del flujo pueden permitir reconstruir el circuito. Añadir VPN comerciales secuenciales desde el mismo endpoint/cuenta puede aumentar la latencia y, a la vez, dejar pruebas comunes de identidad, pago y sincronización. Tor reduce este problema con relays seleccionados de forma independiente y un diseño de cliente compartido, pero una red interactiva de baja latencia no puede prometer resistencia ante un observador que mide ambos extremos.

Entre los fallos habituales están las fugas de DNS o IPv6, las aplicaciones que abren sus propios sockets, el tráfico de administración que llega directamente a los relays, la actividad sincronizada, la reutilización de claves SSH y el inicio de sesión en cuentas que identifican al usuario. La verificación correcta es una prueba de fallo: detener cada relay por turno y demostrar que la carga de trabajo no puede recurrir a una ruta sin cifrar.

### Colapso del túnel y fugas upstream

La arquitectura de relays suele ser más fácil de atribuir cuando falla. Unit 42 documentó una ruta de espionaje multinivel que usaba VPS orientados a las víctimas, VPS de relay, proxies residenciales, Tor y otros servicios de proxy; cuando se omitía o colapsaba un túnel, la infraestructura upstream oculta se conectaba directamente a los sistemas de relay y a los orientados a las víctimas. La misma investigación también usó como pivote entre niveles un certificado X.509 expuesto brevemente en la infraestructura upstream.<sup>[[14]](#references)</sup>

Mantén separado el **plano de datos** (`victim <-> exit`) del **plano de control** (`operator/upstream -> relay administration`). Conserva los logs de ingreso y autenticación en cada nivel bajo tu control, los historiales de certificados y las conexiones fallidas breves, no solo las sesiones C2 exitosas. Un origen que solo aparece durante las interrupciones del relay o administra directamente varios nodos orientados a las víctimas es un candidato upstream más sólido que un exit común, pero su ASN/geolocalización sigue siendo una hipótesis, no una prueba de la identidad del operador.

Un laboratorio autorizado debe hacer que la carga de trabajo falle de forma cerrada. Para una carga de trabajo aislada en un espacio de nombres de red de Linux, la primera ruta debe usar el túnel; después de eliminarlo, tanto la solicitud como la búsqueda de ruta deben fallar, en lugar de seleccionar la interfaz física de salida:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Repite la prueba para DNS e IPv6 y en cada límite entre relays. Si alguna prueba tiene éxito, registra la interfaz/dirección de origen real antes de reparar el enrutamiento por políticas o el firewall; esa observación es el leak de atribución que vería un investigador.

## Niveles de redirector y modelado del tráfico

Un **redirector** público acepta el tráfico que coincide con una gramática específica de la operación y lo reenvía a un team server protegido. Todo lo demás puede rechazarse o recibir contenido inocuo.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Varias capas limitan la exposición: quemar un dominio público no tiene por qué exponer el team server. Las CDN añaden capacidad anycast y un dominio externo de buena reputación, pero la cuenta de la CDN y los logs de edge se convierten en puntos de atribución. Las huellas TLS, el historial de certificados, las rutas distintivas, el orden de los encabezados, el tamaño de las respuestas, el comportamiento de las redirecciones y las listas de permitidos del origen pueden agrupar frentes supuestamente no relacionados.

Para la detección, registra los campos del proxy inverso antes de normalizarlos, compara SNI/Host/authority, inspecciona combinaciones poco comunes de encabezados, agrupa los cuerpos de las respuestas y las huellas TLS, y busca coincidencias de configuración en los logs de auditoría de cloud/CDN. En red teams autorizados, evita copiar una marca real o poner la recolección de credenciales detrás de un tercero no relacionado.

## Domain fronting and domainless fronting

Con el **domain fronting clásico (T1090.004)**, la conexión TLS anuncia un dominio frontal permitido en SNI, mientras que el `Host` HTTP cifrado o `:authority` de HTTP/2 solicita un dominio back-end distinto. Una CDN colaboradora enruta según el valor interno. Un observador de red sin descifrado TLS ve el frente; la CDN ve ambos valores y el origen. En variantes domainless, SNI puede estar vacío mientras otro campo de enrutamiento selecciona el destino.<sup>[[4]](#references)</sup>

Esto no es una suplantación mágica: solo funciona cuando el intermediario permite la discrepancia de forma intencional o accidental y sabe cómo enrutar el nombre interno. Los principales proveedores han restringido el fronting entre cuentas. Encrypted ClientHello (ECH) cambia lo que puede ver un observador en la ruta, pero no elimina los registros de la CDN, el endpoint o la aplicación.

Los puntos de detección incluyen:

- la ascendencia del proceso en el endpoint y un destino inesperado para esa aplicación;
- la discrepancia entre SNI y HTTP authority, cuando la inspección TLS sea legal y esté disponible;
- logs de CDN que muestren que un tenant/frente enruta a otra authority/origen;
- sesiones inusualmente largas o periódicas hacia un servicio normalmente interactivo;
- tamaños y cadencia estables de los flujos cifrados a través de distintos dominios frontales.

El laboratorio seguro simula la discrepancia de enrutamiento en un proxy inverso propio; no abusa de una CDN pública.

## Resolución dinámica: DDNS, DGA y fast flux

La resolución dinámica desacopla un servicio lógico de una infraestructura fija:

- **DDNS:** un cliente autenticado actualiza un nombre estable cuando cambia su dirección.
- **DGA:** el endpoint deriva nombres de dominio a partir de una semilla, a menudo el tiempo o una clave, pero a veces contenido público mutable; el operador configura el DNS para el nombre activo.<sup>[[17]](#references)</sup>
- **Fast flux:** un nombre devuelve un conjunto de direcciones comprometidas/de proxy que cambia rápidamente, a menudo con TTL bajos.
- **Double flux:** rotan tanto las direcciones del servicio como las de los servidores de nombres autoritativos, ocultando también la capa de control.

Fast flux es un patrón de distribución de carga utilizado con fines adversarios, no simplemente «muchas respuestas DNS». Las evidencias más sólidas combinan TTL bajo, un gran número de direcciones únicas, amplia dispersión de ASN/geográfica, corta vida de los nodos, comportamiento repetido de la aplicación e historial de registro sospechoso. Las CDN comparten legítimamente varias de esas propiedades. MITRE recomienda correlacionar el comportamiento DNS con el proceso y las conexiones posteriores.<sup>[[5]](#references)</sup>

Una DGA puede detectarse mediante la entropía léxica, patrones de consonantes/dígitos, ráfagas de NXDOMAIN, dominios cuya primera detección está sincronizada y el contexto del proceso. Las DGA basadas en listas de palabras y los modelos generativos eluden las reglas simples de entropía, por lo que la agrupación temporal en toda la flota y la genealogía del endpoint cobran más importancia.

### Semilla de imagen mutable para una DGA basada en listas de palabras

Una DGA no tiene por qué depender del tiempo. Un loader obtiene la página de un canal público de Telegram, lee el `src` de su elemento `tgme_page_photo_image`, descarga esa imagen de perfil y calcula el hash de sus **últimos 50 bytes**, no de los píxeles decodificados. Cuatro semillas de hash seleccionan un adjetivo, un sustantivo, un verbo y un número. Cambiar la imagen cambia el nombre DNS derivado sin distribuir un cliente nuevo. Conserva exactamente los mismos bytes de la imagen descargada y el mismo orden de las listas de palabras en ambos lados; volver a codificar la imagen o reordenar una lista produce nombres distintos.<sup>[[17]](#references)</sup>

Con las listas de palabras recuperadas del cliente, esto reproduce el paso de selección del nombre. El hash byte a byte de la fuente usa un acumulador de 64 bits, el multiplicador `0x1000193` y semillas distintas para cada componente:<sup>[[17]](#references)</sup>

<details>
<summary>Reproduce la selección del nombre de la lista de palabras basada en la semilla de imagen</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

A diferencia de un [dead-drop resolver](#web-services-and-dead-drop-resolvers) que publica el propio endpoint, el objeto público aquí solo proporciona una semilla mutable; el cliente deriva el endpoint localmente.

A continuación, se consulta el nombre generado para obtener un registro DNS TXT mediante `https://dns.google/resolve?name=<domain>&type=TXT`. El cliente decodifica en Base64 el campo `data` de la respuesta JSON, verifica una firma Ed25519 con su clave pública integrada y solo entonces descifra el comando con AES-ECB. El texto sin cifrar observado comienza con un selector de método y una URL para un payload cifrado. La verificación de la firma implica que un registro TXT resoluble por sí solo no puede proporcionar instrucciones aceptadas.<sup>[[17]](#references)</sup>

## Dominios comprometidos y domain shadowing

Un actor puede secuestrar una cuenta de registrador/DNS, tomar el control de un subdominio abandonado o añadir registros bajo un dominio que, por lo demás, goza de buena reputación. **Domain shadowing** conserva el dominio apex legítimo, mientras que grandes cantidades de subdominios controlados por el atacante apuntan a hosts de entrega o C2 que cambian. Aprovecha la antigüedad y la reputación del dominio, y puede eludir el bloqueo de dominios completos.<sup>[[6]](#references)</sup>

Los defensores necesitan registros de auditoría del registrador y del DNS autoritativo, MFA, bloqueos de registro/registrador, alertas para nuevas delegaciones, tokens de API y servidores de nombres, monitoreo de Certificate Transparency y un inventario de los recursos cloud a los que hace referencia el DNS. Investiga la resolución y el historial de certificados de un subdominio por separado de la reputación del dominio apex.

## Servicios web y dead-drop resolvers

Un **dead-drop resolver (T1102.001)** almacena un puntero codificado al C2 actual en una publicación, perfil, documento, repositorio, objeto cloud o campo de blockchain legítimo. El malware obtiene el objeto público, decodifica un dominio/IP y se comunica con la siguiente etapa. Las variantes bidireccionales intercambian comandos o archivos mediante API de servicios.<sup>[[7]](#references)</sup>

Una variante específica de GitHub usa la API de búsqueda de Issues solo cuando falla un canal de repositorio autenticado. El cliente busca Issues que coincidan con la fecha actual, el repositorio y el tipo de Issue, sigue la URL de comentarios de cada Issue y extrae el texto cifrado entre los marcadores `<!--` y `-->`. Tras descifrarlo por host usando una fecha derivada, campos como `Owner`, `LicRepo` y `LicToken` sustituyen al propietario, la ruta y el token del repositorio principal. Esto permite al operador rotar credenciales y endpoints sin reemplazar el cliente; el comentario del Issue actúa como resolver, mientras que los archivos del repositorio siguen siendo el canal de instrucciones.<sup>[[15]](#references)</sup>

Una variante para Android selecciona al inicio una de dos páginas públicas de Telegram y extrae el texto cifrado entre dos apariciones de un marcador integrado en el APK. Decodifica el valor con Base64URL y lo descifra con AES-128-CBC: los primeros 16 bytes de `SHA-256(marker)` son la clave y los 16 restantes son el IV. El texto sin cifrar es la URL base real del C2, no la URL de la página de Telegram. Conserva el contenido de la página y el marcador exacto al reproducir la resolución; cambiar la página pública rota el endpoint sin reconstruir el APK.<sup>[[16]](#references)</sup>

Esto proporciona resiliencia y oculta el C2 de backend del análisis estático de binarios. También crea identificadores estables de objetos, tenants, repositorios, API y patrones de acceso. Los defensores deberían correlacionar:

1. el proceso que se comunicó con el servicio;
2. la ruta/API u objeto exactos y el hash de la respuesta;
3. la actividad de decodificación o procesamiento de cadenas;
4. la nueva conexión saliente poco después; y
5. el mismo comportamiento en otros equipos de la flota.

Bloquear todo GitHub, almacenamiento cloud o redes sociales rara vez es viable. Las políticas de salida que tienen en cuenta el servicio y la correlación a nivel de proceso superan al bloqueo basado solo en dominios.

## Personas, cuentas y compartimentos de adquisición

El anonimato de la infraestructura falla cuando una persona, correo electrónico de recuperación, teléfono, método de pago, navegador o IP de administración conecta compartimentos. Las operaciones vinculadas a Estados han cultivado perfiles sociales, identidades de correo electrónico y cuentas cloud mucho antes de usarlas; ATT&CK registra esto como Establish Accounts (T1585), incluidas las sub técnicas de redes sociales, correo electrónico y cloud.<sup>[[8]](#references)</sup>

Un defensor o investigador construye un grafo a partir de:

- la hora de creación y del primer inicio de sesión, la configuración regional, la zona horaria y el horario de trabajo;
- los campos de recuperación, dispositivos MFA, documentos de identidad e instrumentos de pago;
- las huellas del navegador/TLS y el historial de redes de origen;
- la reutilización de avatares, la procedencia de imágenes, el estilo de escritura y el crecimiento del grafo social;
- el registrante de dominio, servidor de nombres, certificado, ID de analítica o commit de repositorio compartidos;
- las acciones del plano de administración que eluden la arquitectura de relay público.

En un red team autorizado, las personas sintéticas deben estar documentadas para el controlador del ejercicio, usar canales de recuperación/pago propiedad de la organización, evitar suplantar a personas reales no implicadas y tener prevista su retirada. El SOC puede permanecer a ciegas; la operación no debe quedar sin rendir cuentas.

## Patrones compuestos emergentes que conviene modelar en el threat model

Los siguientes son **composiciones dirigidas a defensores**, no afirmaciones de que un actor identificado haya implementado cada diseño exacto. Combinan primitivas ya observadas y sirven como hipótesis para purple team.

### Instrucciones asimétricas unidireccionales

Los comandos llegan mediante una fuente pública, de difusión o de solo anexado, mientras que los resultados salen por un canal no relacionado tras un retraso. Entre las primitivas de este tipo están la comunicación unidireccional mediante servicios web y los dead drops. La separación impide que un solo flujo parezca bidireccional y dificulta la correlación simple de solicitudes y respuestas.<sup>[[9]](#references)</sup>

**Detección:** conserva las lecturas a nivel de objeto y luego correlaciónalas con cambios de estado del proceso y transferencias salientes posteriores en un intervalo más amplio. Busca procesos poco comunes que lean el mismo objeto público, incluso si no hay una respuesta inmediata.

### Promoción de canales en varias etapas

Una primera etapa discreta realiza un inventario y solo promueve los sistemas seleccionados a un canal de segunda etapa no relacionado. El segundo endpoint, protocolo y proceso pueden no compartir infraestructura con el primero. Esto limita la exposición de la infraestructura más capaz y está modelado explícitamente como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detección:** correlaciona `primer proceso de red -> estado descargado/configurado -> nuevo proceso o inyección -> destino no relacionado`; no cierres el incidente tras bloquear el primer dominio.

### Traducción de relay entre protocolos

Los distintos saltos traducen entre HTTPS, QUIC, WebSocket, DNS, SSH o una API de colas de mensajes, en lugar de reenviar paquetes de forma transparente. La traducción elimina una única huella de protocolo de extremo a extremo, pero crea gateways con patrones distintivos de temporización, almacenamiento en búfer y conversión semántica. Protocol tunneling (T1572) puede combinarse con proxies e impersonation de servicios.<sup>[[11]](#references)</sup>

**Detección:** busca hosts gateway que reciben un protocolo e inician otro con un comportamiento de bytes/tiempo estrechamente correlacionado; compara la finalidad del endpoint con el protocolo que realmente transporta.

### Activación pasiva en dispositivos edge

En lugar de enviar beacons, un implante monitorea el tráfico que ya llega a un router/VPN y se activa solo ante un valor mágico, un patrón de puerto de origen o un token autenticado. El tráfico normal sigue llegando al servicio real. ATT&CK lo denomina Traffic Signaling (T1205), con ejemplos documentados en dispositivos de red y APT.<sup>[[12]](#references)</sup>

**Detección:** integridad del firmware/archivos, captura de paquetes sin procesar durante una investigación autorizada, filtros de socket inesperados y comportamiento diferencial del servicio. La ausencia de un beacon periódico no demuestra que un dispositivo edge esté limpio.

### Rotación de orígenes serverless y efímeros

Un front mantiene una identidad lógica estable, mientras que funciones/contenedores de corta duración gestionan etapas individuales en varias regiones/cuentas. Esto reduce el tiempo de permanencia en disco y la cantidad de IP de origen fijas, pero la creación en el plano de control, la imagen/capa, el rol, el secreto, el ID de solicitud y la telemetría de facturación se convierten en el grafo persistente.

**Detección:** conserva los registros de auditoría e invocación cloud fuera de la carga de trabajo; agrupa las plantillas de despliegue, los roles, las claves de entorno y las relaciones entre front y origen.

### Diversidad de capas de privacidad

Una operación puede evitar deliberadamente una cadena homogénea: por ejemplo, un canal usa un relay alquilado, las instrucciones usan un objeto público, la salida proviene de un enlace celular de laboratorio propio y la administración usa una red de otra organización. Esto reduce el valor de comprometer a un proveedor, pero aumenta el riesgo de correlación temporal entre capas y de errores operativos.

**Detección:** crea cronologías de campaña que abarquen sensores de identidad, DNS, SaaS, red y cloud. Busca transiciones de estado sincronizadas en vez de indicadores idénticos.

### Dead drops descentralizados o en registros de transparencia

Un actor puede colocar un pequeño puntero cifrado en cualquier sistema público duradero de solo anexado, almacén direccionado por contenido o feed similar a un registro de transparencia. El objeto público es resiliente, pero su índice/hash de contenido exacto y el comportamiento de sondeo del cliente se convierten en identificadores estables.

**Detección:** registra los identificadores completos de API/objeto y los hashes de respuesta; alerta sobre procesos no estándar que sondeen objetos inmutables y luego los decodifiquen o establezcan nuevas conexiones.

### Operaciones con almacenamiento y reenvío retrasados

El C2 interactivo genera una fuerte correlación temporal. Un diseño de almacenamiento y reenvío agrupa tareas cifradas y devuelve los resultados minutos u horas después mediante otra cola o transferencia física. Sacrifica capacidad de respuesta para reducir la correlación temporal de extremo a extremo.

**Detección:** amplía las ventanas de correlación, modela el acceso periódico a las colas y examina la preparación de los endpoints. El agrupamiento desplaza la señal del tiempo entre paquetes al comportamiento programado de procesos/archivos; no la elimina.

## Revisión de diseño: piensa en los observadores

Para cada ruta, completa esta tabla antes del despliegue y después de la recopilación:

| Capa | ¿Ve el origen? | ¿Ve el destino? | ¿Ve el contenido? | Identificadores estables | Retención/responsable legal |
|---|---:|---:|---:|---|---|
| red local/operador | | | | | |
| servicio de entrada/acceso | | | | | |
| operador(es) de tránsito | | | | | |
| salida/redirector/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| objetivo | | | | | |
| proveedor de cuenta/pago | | | | | |

Si un proveedor común puede completar todas las columnas, la arquitectura oculta la actividad al objetivo, pero no proporciona una separación sólida. Si ningún controlador interno puede atribuir la actividad a un engagement, no es adecuada para un red team profesional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestructura (T1583), Comprometer infraestructura (T1584) y Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actores de espionaje vinculados a China usan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Comprometer infraestructura: dominios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establecer cuentas (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Desarticulación de la mayor red de proxy residencial del mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Las campañas Shadow: desentrañando el espionaje global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campaña Blinder Tunnel apunta a la infraestructura iraquí](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: la IA creó las superposiciones. Las víctimas pierden sus PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Trucos del pasado desplegados mediante binarios firmados de ChatGPT y Claude](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
