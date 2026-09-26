# Infraestructura ofensiva y evasión de atribución

{{#include ../banners/hacktricks-training.md}}

Un operador rara vez obtiene un anonimato significativo mediante un solo proxy. Las campañas reales construyen un **grafo de separación**: el operador llega a un nodo de acceso, los nodos de tránsito ocultan ese nodo frente a la salida, los redirectors protegen el C2 real y los nombres desechables apuntan al perímetro público.

Usa el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) para consultar una perspectiva normalizada sobre las ventajas y desventajas, el despliegue y la detección de cada ruta. Esta página profundiza en la composición de infraestructura adversaria.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
La última dirección observada por un objetivo es, por tanto, evidencia de una ruta, no una prueba de quién controlaba el teclado. MITRE asigna los componentes principales a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) y Web Service (T1102).<sup>[[1]](#references)</sup>

## Clases de infraestructura

| Clase | Por qué la usa un actor | Exposición duradera | Mejor pivote del defensor |
|---|---|---|---|
| VPS/cloud alquilado | Rápido, predecible, enrutable y fácil de reconstruir | tenant, facturación, consola, inicios de sesión de origen e historial de imágenes | eventos de la cuenta/control-plane y fingerprint repetido del servidor |
| VPN/Tor comercial | Gran conjunto de egress compartido; sin administración del servidor | visibilidad del proveedor/guard y timing de extremo a extremo | comportamiento del destino, evidencia del endpoint y correlación de flujos |
| Proxy residencial/móvil | ASN de consumidor y plausibilidad geográfica | registros del broker/cliente; comportamiento de proxyware o del host infectado | viajes imposibles, protocolos de proxy y cambio de direcciones por sesión |
| Servidor/router/IoT comprometido | Toma prestada la reputación y jurisdicción de la víctima | implant, flujo de administración y controlador upstream recurrente | telemetría del dispositivo y topología ORB, no una sola IP de salida |
| CDN/redirector | Separa el edge público del C2 back-end | gramática TLS/HTTP, certificado, routing y artefactos de la cuenta cloud | correlación edge-to-origin y clustering de la forma de las requests |
| Web service legítimo | Se mezcla con el tráfico permitido de GitHub/cloud/social | API token, identificadores de tenant/objeto y lineage inusual de procesos | proceso del endpoint junto con la semántica del servicio/API |
| Ruta física/celular/satelital | Cambia el origen físico aparente | registros de RF, operador, suscriptor, dispositivo y ubicación | evidencia de radio/física y de red combinada |

## Redes de relay box operativas

Una **red ORB** es una flota de proxies administrada que se utiliza como servicio intermedio. Mandiant las divide en redes provisionadas de servidores alquilados, redes no provisionadas de routers/IoT comprometidos e híbridas. Una topología madura tiene cuatro roles lógicos:<sup>[[2]](#references)</sup>

1. **Servidor de administración (ACOS):** mantiene el inventario, las credenciales, el estado y la política de routing.
2. **Nodo de acceso/relay:** autentica a clientes u operadores; es la entrada estable a una mesh cambiante.
3. **Nodos de traversal:** uno o más sistemas alquilados o comprometidos retransmiten conexiones opacas.
4. **Nodo de salida/staging:** presenta la dirección de origen final ante objetivos de reconnaissance, exploitation o C2.

La mesh puede seleccionar salidas por país, ASN, latencia o disponibilidad y rotar nodos que no estén saludables. Varios threat groups pueden alquilar la misma red. Mandiant observó que una dirección IPv4 permaneció asociada con algunos ORB durante tan solo 31 días; por ello recomienda tratar la **red como una entidad cambiante similar a un actor**, en lugar de bloquear una lista obsoleta de IPs.<sup>[[2]](#references)</sup>

### Qué proporciona y qué filtra

- El objetivo ve una salida que puede estar geográficamente cercana y parecer residencial.
- La salida ve al objetivo y al salto anterior, pero no necesariamente al operador.
- El servicio de acceso ve al cliente y la solicitud de ruta. Una mesh administrada de forma independiente puede mantener al cliente separado de las salidas, pero crea un potente registro de la contraparte.
- Los puertos repetidos, el orden del handshake, los banners del servidor, los certificados, las ventanas de uptime y las relaciones con los controladores pueden revelar la flota incluso mientras rotan las IPs.
- Un router comprometido suele carecer de telemetría del endpoint, pero su ISP aún dispone de datos del suscriptor y de los flujos; una incautación expone artefactos del implant/configuración.

{% hint style="info" %}
Para un ejercicio autorizado, reproduce la topología con VMs o routers propiedad de la organización y conserva el mapa de atribución del controlador. No reclutes proxies abiertos ni dispositivos de terceros. La [guía del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la misma estructura de saltos visible para el defensor sin victimizar a un intermediario.
{% endhint %}

## Redes de proxies residenciales y móviles

Los servicios de proxies residenciales asignan sesiones a direcciones de banda ancha de consumidores; los proxies móviles realizan egress mediante pools de NAT de operadores. El suministro puede proceder de appliances inscritos expresamente, SDK/proxyware incluido en aplicaciones de consumo, resellers o malware. Estos orígenes no son equivalentes: la falta de consentimiento informado convierte un servicio de privacidad en infraestructura comprometida.

Los modos de rotación afectan a la detección:

- la **rotación por request** produce discontinuidades rápidas de IP y ASN/geografía mientras la identidad de las capas superiores permanece estable;
- las **sticky sessions** mantienen una salida durante minutos u horas, pareciéndose a un suscriptor ordinario;
- los **backconnect gateways** exponen un endpoint de broker al cliente y seleccionan las salidas internamente;
- los **mobile pools** sitúan a muchos suscriptores reales detrás de un pequeño conjunto de direcciones NAT del operador, lo que encarece un bloqueo por IP.

Los defensores deberían correlacionar la IP con la sesión autenticada, el fingerprint TLS/cliente, el orden HTTP, la cookie del dispositivo y el comportamiento. Un inicio de sesión residencial supuestamente local seguido de otro país mientras todas las características de las capas superiores permanecen idénticas es una señal más sólida que la reputación por sí sola. Por el contrario, el uso compartido de direcciones y el handoff móvil generan cambios legítimos, así que nunca trates la clasificación residencial/proxy como un veredicto.

### Control planes de proxyware y solapamiento de resellers

No modeles un pool residencial como una lista plana de salidas. El análisis del ecosistema IPIDEA expuso un **control plane de dos niveles reutilizable**: un SDK integrado primero reporta metadatos del dispositivo/inscripción a un dominio Tier One y recibe programación, además de pares `connect`/`proxy` IP:port de Tier Two. El nodo consulta periódicamente el puerto connect de Tier Two en busca de una tarea codificada, abre una segunda conexión con el puerto proxy asociado y retransmite los bytes proporcionados al destino solicitado. SDKs y marcas de proxy nominalmente diferentes tenían dominios de discovery separados, pero convergían en una infraestructura Tier Two compartida y pools de salida solapados mediante propiedad común y relaciones con resellers.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Esto produce pivotes de hunting más duraderos que un bloque de IP residencial:<sup>[[13]](#references)</sup>

- un proceso inesperado de utility, VPN, game o dispositivo embebido envía un identificador de dispositivo/clave de cliente estable y recibe una lista cambiante de servidores;
- el endpoint consulta una IP directa en un puerto inusual y después se conecta a otro puerto en la misma dirección inmediatamente antes de abrir un nuevo socket de destino;
- varias marcas aparentes comparten direcciones de Tier Two, gramática de protocolo, código SDK o solapamiento de exit nodes;
- distintas aplicaciones que contactan con diferentes dominios de Tier One reciben direcciones del mismo pool de Tier Two.

El solapamiento también limita la atribución: ver una IP en el pool anunciado de un proveedor no demuestra qué reseller, cliente o threat actor la utilizó en el momento relevante. Conserva las marcas de tiempo de los flujos, la genealogía de los procesos, los cuerpos de respuesta de Tier One y los identificadores de tareas de Tier Two.<sup>[[13]](#references)</sup> En un ejercicio autorizado, emula esta jerarquía únicamente con endpoints propiedad de la organización; nunca inscribas dispositivos de consumidores ni proxyware de terceros.

## Cadenas de proxy multi-hop

MITRE distingue los proxies externos de los **multi-hop proxies (T1090.003)**. La propiedad importante no es el número de saltos, sino la separación del conocimiento y la administración.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Si una misma entidad opera A y B, los logs compartidos o la sincronización temporal del flujo pueden reconstruir el circuito. Añadir VPNs comerciales secuenciales desde el mismo endpoint/cuenta puede aumentar la latencia, pero mantiene las mismas evidencias de identidad, pago y sincronización temporal. Tor reduce este problema mediante relays seleccionados de forma independiente y un diseño de cliente compartido, pero una red interactiva de baja latencia no puede prometer resistencia frente a un observador que mida ambos extremos.

Los fallos comunes son el bypass de DNS o IPv6, las aplicaciones que abren sus propios sockets, el tráfico de administración que llega directamente a los relays, la actividad sincronizada, la reutilización de claves SSH y el inicio de sesión en cuentas identificables. La verificación correcta es una prueba de fallo: detener cada relay por turnos y demostrar que la carga de trabajo no puede recurrir a una ruta en claro.

### Colapso del túnel y filtración upstream

Una arquitectura de relay suele ser más atribuible cuando falla. Unit 42 documentó una ruta de espionaje multinivel que utilizaba VPSs orientados a las víctimas, VPSs de relay, proxies residenciales, Tor y otros servicios de proxy; cuando se omitía o colapsaba un túnel, la infraestructura upstream oculta se conectaba directamente a los sistemas de relay y orientados a las víctimas. La misma investigación también utilizó un certificado X.509 expuesto brevemente en la infraestructura upstream como pivote entre niveles.<sup>[[14]](#references)</sup>

Mantén separado el **data plane** (`victim <-> exit`) del **control plane** (`operator/upstream -> relay administration`). Conserva los logs de entrada y autenticación en cada nivel controlado, los historiales de certificados y las conexiones fallidas breves, no solo las sesiones C2 exitosas. Un origen que aparece únicamente durante las interrupciones de los relays o que administra directamente varios nodos orientados a las víctimas es un candidato upstream más sólido que un exit ordinario, pero su ASN/geolocalización sigue siendo una hipótesis, no una prueba de la identidad del operador.

Un laboratorio autorizado debe hacer que la carga de trabajo falle de forma segura. Para una carga de trabajo aislada en un network namespace de Linux, la primera ruta debe utilizar el túnel; después de eliminarlo, tanto la solicitud como la búsqueda de la ruta deben fallar en lugar de seleccionar el uplink físico:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Repite la prueba para DNS e IPv6 y en cada límite entre relays. Si alguna sonda tiene éxito, registra la interfaz/dirección de origen real antes de corregir el enrutamiento basado en políticas o el firewall; esa observación es el attribution leak que vería un investigador.

## Capas de redirectors y configuración del tráfico

Un **redirector** público acepta el tráfico que coincide con una gramática específica de la operación y lo reenvía a un team server protegido. Todo lo demás puede rechazarse o recibir contenido inocuo.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Múltiples capas limitan la exposición: quemar un dominio público no tiene por qué exponer el servidor del equipo. Los CDNs añaden capacidad anycast y un dominio externo reputado, pero la cuenta del CDN y los edge logs se convierten en puntos de atribución. Las huellas TLS, los historiales de certificados, las rutas distintivas/orden de headers, los tamaños de respuesta, el comportamiento de redirección y las allowlists de origen pueden agrupar frentes supuestamente no relacionados.

Para la detección, registra los campos del reverse proxy antes de la normalización, compara SNI/Host/authority, inspecciona combinaciones poco frecuentes de headers, agrupa cuerpos de respuesta y huellas TLS, y busca solapamientos de configuración en los logs de auditoría de cloud/CDN. Para red teams autorizados, evita copiar una marca real o colocar la recopilación de credenciales detrás de un tercero no relacionado.

## Domain fronting and domainless fronting

Con el **domain fronting (T1090.004)** clásico, la conexión TLS anuncia un dominio front permitido en SNI, mientras que el `Host` HTTP cifrado o `:authority` de HTTP/2 solicita un dominio de back-end diferente. Un CDN cooperante enruta según el valor interno. Un observador de red sin descifrado TLS ve el front; el CDN ve ambos valores y el origen. En las variantes domainless, SNI puede estar vacío mientras otro campo de routing selecciona el destino.<sup>[[4]](#references)</sup>

Esto no es una suplantación mágica: solo funciona cuando el intermediario permite intencionada o accidentalmente la discrepancia y sabe cómo enrutar el nombre interno. Los principales proveedores han restringido el fronting entre cuentas. Encrypted ClientHello (ECH) cambia lo que puede ver un observador en el trayecto, pero no elimina los registros del CDN, del endpoint ni de la aplicación.

Los puntos de detección incluyen:

- ascendencia del proceso del endpoint y destino no esperado para esa aplicación;
- discrepancia entre SNI y la autoridad HTTP cuando la inspección TLS es legal y está disponible;
- logs del CDN que muestran a un tenant/front enroutando hacia otra autoridad/origen;
- sesiones inusualmente largas o periódicas con un servicio normalmente interactivo;
- tamaños y cadencia estables de flujos cifrados a través de dominios front cambiantes.

El laboratorio seguro simula la discrepancia de routing en un reverse proxy propio; no abusa de un CDN público.

## Dynamic resolution: DDNS, DGA and fast flux

La resolución dinámica desacopla un servicio lógico de una infraestructura fija:

- **DDNS:** un cliente autenticado actualiza un nombre estable después de que cambie su dirección.
- **DGA:** tanto el endpoint como el controller derivan nombres de dominio candidatos a partir de una semilla temporal o clave; el operador registra un subconjunto pequeño.
- **Fast flux:** un nombre devuelve un conjunto que cambia rápidamente de direcciones comprometidas/proxy, a menudo con TTL bajos.
- **Double flux:** rotan tanto las direcciones del servicio como las de los name servers autoritativos, ocultando también la capa de control.

Fast flux es un patrón de distribución de carga utilizado de forma adversaria, no simplemente “muchas respuestas DNS”. Las evidencias más sólidas combinan TTL bajo, un número elevado de direcciones únicas, amplia dispersión de ASN/geográfica, corta vida de los nodos, comportamiento repetido de la aplicación e historial de registro sospechoso. Los CDNs comparten legítimamente varias de esas propiedades. MITRE recomienda correlacionar el comportamiento DNS con el proceso y las conexiones posteriores.<sup>[[5]](#references)</sup>

Un DGA puede detectarse mediante entropía léxica, patrones de consonantes/dígitos, ráfagas de NXDOMAIN, dominios vistos por primera vez de forma sincronizada y contexto del proceso. Los DGAs basados en wordlists y los modelos generativos evaden reglas simples de entropía, haciendo más importantes la agrupación temporal en toda la flota y la lineage del endpoint.

## Compromised domains and domain shadowing

Un actor puede secuestrar una cuenta de registrar/DNS, tomar control de un subdominio abandonado o añadir registros bajo un dominio por lo demás reputado. **Domain shadowing** conserva el apex legítimo mientras grandes cantidades de subdominios controlados por el atacante apuntan a hosts de delivery o C2 cambiantes. Toma prestadas la antigüedad y la reputación, y puede evadir el bloqueo de todo el dominio.<sup>[[6]](#references)</sup>

Los defensores necesitan logs de auditoría del registrar y del DNS autoritativo, MFA, bloqueos de registry/registrar, alertas para nuevas delegaciones/tokens de API/name servers, monitorización de certificate transparency y un inventario de los recursos cloud referenciados por DNS. Investiga la resolución y el historial de certificados de un subdominio independientemente de la reputación del apex.

## Web services and dead-drop resolvers

Un **dead-drop resolver (T1102.001)** almacena un puntero codificado al C2 actual dentro de una publicación, perfil, documento, repositorio, objeto cloud o campo de blockchain legítimo. El malware obtiene el objeto público, decodifica un dominio/IP y contacta con la siguiente etapa. Las variantes bidireccionales intercambian comandos o archivos mediante APIs de servicios.<sup>[[7]](#references)</sup>

Esto proporciona resiliencia y oculta el C2 de back-end al análisis estático del binario. También crea identificadores estables de objeto, tenant, repositorio, API y patrón de acceso. Los defensores deberían relacionar:

1. el proceso que contactó con el servicio;
2. la ruta/API u objeto exactos y el hash de respuesta;
3. la actividad de decodificación o procesamiento de strings;
4. la nueva conexión saliente poco después; y
5. el comportamiento idéntico en otros puntos de la flota.

Bloquear todo GitHub, cloud storage o las redes sociales rara vez es viable. Una política de egress consciente del servicio y la correlación a nivel de proceso superan al bloqueo basado únicamente en dominios.

## Personas, cuentas y compartimentos de procurement

El anonimato de la infraestructura falla cuando una persona, email de recuperación, teléfono, pago, navegador o IP de administración conecta compartimentos. Las operaciones vinculadas a Estados han cultivado perfiles sociales, identidades de email y cuentas cloud mucho antes de utilizarlas; ATT&CK registra esto como Establish Accounts (T1585), incluidas las sub-técnicas sociales, de email y cloud.<sup>[[8]](#references)</sup>

Un defensor o investigador construye un grafo a partir de:

- hora de creación y primer login, locale, zona horaria y horario de trabajo;
- campos de recuperación, dispositivos MFA, documentos de identidad e instrumentos de pago;
- huellas de navegador/TLS e historial de la red de origen;
- reutilización de avatar, procedencia de imágenes, estilo de escritura y crecimiento del grafo social;
- registrante de dominio, name server, certificado, ID de analytics o commit de repositorio compartidos;
- acciones del plano de administración que evitan la arquitectura pública de relay.

Para un red team autorizado, las personas sintéticas deben documentarse ante el controlador del ejercicio, utilizar canales de recuperación/pago propiedad de la organización, evitar suplantar a personas reales no implicadas y tener una retirada planificada. El SOC puede permanecer ciego; la operación no debe volverse irresponsable.

## Emerging compound patterns to threat-model

Los siguientes son **composiciones impulsadas por el defensor**, no afirmaciones de que un actor nombrado haya desplegado exactamente cada diseño. Combinan primitivas ya observadas y son hipótesis útiles para purple teams.

### Asymmetric one-way tasking

Los comandos llegan mediante una fuente pública, broadcast o append-only, mientras que los resultados salen por un canal no relacionado después de un retraso. Ejemplos de la primitiva incluyen la comunicación unidireccional mediante web services y los dead drops. La separación evita que un único flujo parezca bidireccional y dificulta la correlación simple de solicitud/respuesta.<sup>[[9]](#references)</sup>

**Detección:** conserva las lecturas a nivel de objeto y después correlaciona los cambios de estado del proceso y las transferencias salientes posteriores en una ventana más amplia. Busca un proceso poco frecuente que lea el mismo objeto público incluso cuando no haya una respuesta inmediata.

### Multi-stage channel promotion

Una primera etapa silenciosa realiza el inventario y solo promociona sistemas seleccionados a un canal de segunda etapa no relacionado. El segundo endpoint, protocolo y proceso pueden no compartir infraestructura con el primero. Esto limita la exposición de la infraestructura capaz y está modelado explícitamente como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detección:** relaciona `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; no cierres el incidente después de bloquear el primer dominio.

### Cross-protocol relay translation

Diferentes saltos traducen HTTPS, QUIC, WebSocket, DNS, SSH o una API de message queue en lugar de reenviar paquetes de forma transparente. La traducción elimina una única huella de protocolo de extremo a extremo, pero crea gateways con tiempos, buffering y conversión semántica distintivos. Protocol tunneling (T1572) puede combinarse con proxies y service impersonation.<sup>[[11]](#references)</sup>

**Detección:** busca hosts gateway que reciban un protocolo e inicien otro con un comportamiento de bytes/tiempo estrechamente acoplado; compara la intención del endpoint con el protocolo que realmente transporta.

### Passive activation on edge devices

En lugar de hacer beaconing, un implant monitoriza el tráfico que ya llega a un router/VPN y se activa únicamente ante un valor mágico, un patrón de puerto de origen o un token autenticado. El tráfico normal continúa hacia el servicio real. ATT&CK lo denomina Traffic Signaling (T1205), con ejemplos documentados en dispositivos de red y APT.<sup>[[12]](#references)</sup>

**Detección:** integridad del firmware/archivo, captura de paquetes sin procesar durante un hunt autorizado, filtros de socket inesperados y comportamiento diferencial del servicio. La ausencia de un beacon periódico no demuestra que un dispositivo edge esté limpio.

### Serverless and ephemeral origin rotation

Un front mantiene una identidad lógica estable mientras funciones/contenedores de corta duración gestionan etapas individuales en varias regiones/cuentas. Esto reduce la permanencia en disco y las IP de origen fijas, pero la creación en el plano de control, la imagen/capa, el rol, el secreto, el ID de solicitud y la telemetría de billing se convierten en el grafo duradero.

**Detección:** conserva los logs de auditoría e invocación de cloud fuera del workload; agrupa templates de deployment, roles, claves de entorno y relaciones front-to-origin.

### Privacy-layer diversity

Una operación puede evitar deliberadamente una única cadena homogénea: por ejemplo, un canal utiliza un relay alquilado, el tasking utiliza un objeto público, un exit procede de un enlace celular de laboratorio propio y la administración utiliza una red independiente de la organización. Esto reduce el valor de comprometer un proveedor, pero aumenta el riesgo de correlación temporal entre capas y de errores operativos.

**Detección:** construye timelines de campaña entre sensores de identidad, DNS, SaaS, red y cloud. Busca transiciones de estado sincronizadas en lugar de indicadores idénticos.

### Decentralized or transparency-log dead drops

Un actor puede colocar un pequeño puntero cifrado en cualquier sistema público durable append-only, almacén content-addressed o feed similar a transparency. El objeto público es resiliente, pero su índice/hash de contenido exacto y el comportamiento de polling del cliente se convierten en identificadores estables.

**Detección:** registra los identificadores completos de API/objeto y los hashes de respuesta; alerta sobre procesos no estándar que hagan polling de objetos inmutables seguido de decodificación o nuevas conexiones.

### Delayed store-and-forward operations

El C2 interactivo crea una fuerte correlación temporal. Un diseño store-and-forward agrupa jobs cifrados y devuelve los resultados minutos u horas después mediante otra cola o transferencia física. Sacrifica capacidad de respuesta para debilitar la temporización de extremo a extremo.

**Detección:** amplía las ventanas de correlación, modela el acceso periódico a colas y examina el staging del endpoint. El batching desplaza la señal desde la temporización de paquetes hacia el comportamiento programado de procesos/archivos; no la elimina.

## Design review: think in observers

Para cada ruta, completa esta tabla antes del despliegue y después de la recopilación:

| Capa | ¿Ve el origen? | ¿Ve el destino? | ¿Ve el contenido? | Identificadores estables | Responsable de retención/legal |
|---|---:|---:|---:|---|---|
| red local/carrier | | | | | |
| servicio de entrada/acceso | | | | | |
| operador(es) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autoritativo/registrar | | | | | |
| objetivo | | | | | |
| proveedor de cuenta/pago | | | | | |

Si un proveedor común puede completar todas las columnas, la arquitectura proporciona ocultación frente al objetivo, pero no una separación sólida. Si ningún controlador interno puede relacionar la actividad con un engagement, no es adecuada para red teaming profesional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestructura (T1583), Comprometer infraestructura (T1584) y Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Comprometer infraestructura: dominios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Interrumpiendo la mayor red de proxies residenciales del mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Las campañas Shadow: descubriendo el espionaje global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
