# Infraestructura ofensiva y evasión de atribución

{{#include ../banners/hacktricks-training.md}}

Un operator rara vez obtiene un anonimato significativo mediante un único proxy. Las campañas reales construyen un **grafo de separación**: el operator llega a un nodo de acceso, los nodos de tránsito ocultan ese nodo frente al exit, los redirectors protegen el C2 real y los nombres desechables apuntan al perímetro público.

Usa el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) para consultar una visión normalizada de las ventajas/desventajas, el despliegue y la detección de cada ruta. Esta página profundiza en la composición de infraestructura adversaria.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
La última dirección observada por un objetivo es, por tanto, evidencia de una ruta, no una prueba de quién controlaba el teclado. MITRE asigna los componentes principales a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) y Web Service (T1102).<sup>[[1]](#references)</sup>

## Clases de infraestructura

| Clase | Por qué la usa un actor | Exposición duradera | Mejor pivote del defensor |
|---|---|---|---|
| VPS/cloud alquilado | Rápido, predecible, enrutable y fácil de reconstruir | tenant, facturación, consola, inicios de sesión de origen e historial de imágenes | eventos de la cuenta/control plane y fingerprint repetido del servidor |
| VPN/Tor comercial | Gran conjunto de salidas compartidas; sin administración del servidor | visibilidad del proveedor/guard y sincronización de extremo a extremo | comportamiento del destino, evidencia del endpoint y correlación de flujos |
| Proxy residencial/móvil | ASN de consumidor y plausibilidad geográfica | registros del broker/cliente; comportamiento de proxyware o de hosts infectados | viajes imposibles, protocolos de proxy y cambios de dirección por sesión |
| Servidor/router/IoT comprometido | Aprovecha la reputación y jurisdicción de la víctima | implant, flujo de administración y controlador upstream recurrente | telemetría del dispositivo y topología ORB, no una sola IP de salida |
| CDN/redirector | Separa el edge público del C2 back-end | gramática TLS/HTTP, certificado, routing y artefactos de la cuenta cloud | correlación edge-origen y agrupación por forma de las solicitudes |
| Servicio web legítimo | Se mezcla con el tráfico permitido de GitHub/cloud/social | API token, identificadores de tenant/objeto y lineage inusual de procesos | proceso del endpoint junto con la semántica del servicio/API |
| Ruta física/celular/satelital | Cambia el origen físico aparente | registros de RF, carrier, suscriptor, dispositivo y ubicación | evidencia radiofísica y de red combinada |

## Redes de relay box operativas

Una **red ORB** es una flota de proxies administrada que se utiliza como servicio intermediario. Mandiant las divide en redes provisionadas de servidores alquilados, redes no provisionadas de routers/IoT comprometidos e híbridos. Una topología madura tiene cuatro roles lógicos:<sup>[[2]](#references)</sup>

1. **Servidor de administración (ACOS):** mantiene el inventario, las credenciales, el estado y la política de routing.
2. **Nodo de acceso/relay:** autentica a clientes u operadores; es la entrada estable a una mesh cambiante.
3. **Nodos de traversal:** uno o más sistemas alquilados o comprometidos retransmiten conexiones opacas.
4. **Nodo de salida/staging:** presenta la dirección de origen final ante objetivos de reconocimiento, exploitation o C2.

La mesh puede seleccionar salidas por país, ASN, latencia o disponibilidad, y rotar los nodos que no estén saludables. Varios threat groups pueden alquilar la misma red. Mandiant observó que una dirección IPv4 permanecía asociada con algunos ORB durante tan solo 31 días; por ello recomienda tratar la **red como una entidad cambiante similar a un actor**, en lugar de bloquear una lista obsoleta de IPs.<sup>[[2]](#references)</sup>

### Qué proporciona y qué filtra

- El objetivo ve una salida que puede estar geográficamente cerca y parecer residencial.
- La salida ve al objetivo y al salto anterior, pero no necesariamente al operador.
- El servicio de acceso ve al cliente y la solicitud de ruta. Una mesh administrada de forma independiente puede mantener al cliente separado de las salidas, pero crea un registro muy valioso de la contraparte.
- Los puertos repetidos, el orden del handshake, los banners del servidor, los certificados, las ventanas de uptime y las relaciones con los controladores pueden revelar la flota incluso mientras rotan las IPs.
- Un router comprometido suele carecer de telemetría del endpoint, pero su ISP aún conserva datos del suscriptor y de los flujos; una incautación expone artefactos del implant/configuración.

{% hint style="info" %}
Para un ejercicio autorizado, reproduce la topología con VMs o routers propiedad de la organización y conserva el mapa de attribution del controlador. No reclutes proxies abiertos ni dispositivos de terceros. La [guía del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la misma estructura de saltos visible para el defensor sin victimizar a un intermediario.
{% endhint %}

## Redes de proxies residenciales y móviles

Los servicios de proxies residenciales asignan sesiones a direcciones de banda ancha de consumidores; los proxies móviles realizan el egress mediante pools de NAT de carriers. El suministro puede provenir de appliances inscritos expresamente, SDK/proxyware integrado en aplicaciones de consumo, revendedores o malware. Estos orígenes no son equivalentes: la falta de consentimiento informado convierte un servicio de privacidad en infraestructura comprometida.

Los modos de rotación afectan a la detección:

- la **rotación por solicitud** produce discontinuidades rápidas de IP, ASN y geografía mientras la identidad de las capas superiores permanece estable;
- las **sticky sessions** mantienen una salida durante minutos u horas, pareciéndose a un suscriptor normal;
- los **backconnect gateways** exponen un endpoint de broker al cliente y seleccionan las salidas internamente;
- los **mobile pools** colocan a muchos suscriptores reales detrás de un pequeño conjunto de direcciones NAT de carrier, lo que hace costoso bloquear una IP.

Los defensores deben correlacionar la IP con la sesión autenticada, el fingerprint de TLS/cliente, el orden HTTP, la cookie del dispositivo y el comportamiento. Un inicio de sesión residencial supuestamente local seguido de otro país mientras todas las características de las capas superiores permanecen idénticas es una señal más sólida que la reputación por sí sola. Por el contrario, el uso compartido de direcciones y el handoff móvil generan cambios legítimos, así que nunca trates la clasificación residencial/proxy como un veredicto.

## Cadenas de proxies multi-hop

MITRE distingue los proxies externos de los **multi-hop proxies (T1090.003)**. La propiedad importante no es el número de saltos, sino la separación del conocimiento y la administración.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Si una misma parte opera A y B, los logs compartidos o la sincronización temporal del flujo pueden reconstruir el circuito. Añadir VPNs comerciales secuenciales desde el mismo endpoint/cuenta puede añadir latencia, pero mantiene evidencias comunes de identidad, pago y sincronización temporal. Tor reduce este problema mediante relays seleccionados de forma independiente y un diseño de cliente compartido, pero una red interactiva de baja latencia no puede prometer resistencia frente a un observador que mida ambos extremos.

Los fallos comunes son los bypasses de DNS o IPv6, las aplicaciones que abren sus propios sockets, el tráfico de gestión que llega directamente a los relays, la actividad sincronizada, la reutilización de claves SSH y el inicio de sesión en cuentas identificables. La verificación correcta es una prueba de fallo: detener cada relay por turnos y demostrar que la carga de trabajo no puede recurrir a una ruta en claro.

## Tiers de redirectors y shaping del tráfico

Un **redirector** público acepta el tráfico que coincide con una gramática específica de la operación y lo reenvía a un team server protegido. Todo lo demás puede rechazarse o recibir contenido inocuo.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Múltiples niveles limitan la exposición: quemar un dominio público no tiene por qué exponer el team server. Las CDN añaden capacidad anycast y un dominio externo reputado, pero la cuenta de la CDN y los edge logs se convierten en puntos de atribución. Las huellas TLS, los historiales de certificados, las rutas distintivas/orden de headers, los tamaños de respuesta, el comportamiento de las redirecciones y las listas de permitidos del origin pueden agrupar frentes supuestamente no relacionados.

Para la detección, registra los campos del reverse proxy antes de la normalización, compara SNI/Host/authority, inspecciona combinaciones poco frecuentes de headers, agrupa cuerpos de respuesta y huellas TLS, y busca solapamientos de configuración en los audit logs de cloud/CDN. En red teams autorizados, evita copiar una marca real o colocar la recopilación de credenciales detrás de un tercero no relacionado.

## Domain fronting y domainless fronting

Con el **domain fronting (T1090.004)** clásico, la conexión TLS anuncia un dominio front permitido en SNI, mientras que el `Host` HTTP cifrado o `:authority` de HTTP/2 solicita un dominio back-end diferente. Una CDN cooperante enruta según el valor interno. Un observador de red sin descifrado TLS ve el front; la CDN ve ambos valores y el origin. En las variantes domainless, SNI puede estar vacío mientras otro campo de routing selecciona el destino.<sup>[[4]](#references)</sup>

Esto no es una suplantación mágica: solo funciona cuando el intermediario permite intencionada o accidentalmente la discrepancia y sabe cómo enrutar el nombre interno. Los principales proveedores han restringido el fronting entre cuentas. Encrypted ClientHello (ECH) cambia lo que puede ver un observador en la ruta, pero no elimina los registros de la CDN, el endpoint o la aplicación.

Los puntos de detección incluyen:

- la ascendencia del proceso del endpoint y un destino no esperado para esa aplicación;
- discrepancias entre SNI y la autoridad HTTP cuando la inspección TLS es legal y está disponible;
- logs de la CDN que muestran un tenant/front enroutando hacia otra autoridad/origin;
- sesiones inusualmente largas o periódicas con un servicio normalmente interactivo;
- tamaños y cadencia estables de flujos cifrados a través de dominios front cambiantes.

El laboratorio seguro simula la discrepancia de routing en un reverse proxy propio; no abusa de una CDN pública.

## Resolución dinámica: DDNS, DGA y fast flux

La resolución dinámica desacopla un servicio lógico de una infraestructura fija:

- **DDNS:** un cliente autenticado actualiza un nombre estable después de que cambie su dirección.
- **DGA:** tanto el endpoint como el controller derivan nombres de dominio candidatos a partir de una semilla de tiempo/clave; el operador registra un pequeño subconjunto.
- **Fast flux:** un nombre devuelve un conjunto que cambia rápidamente de direcciones comprometidas/proxy, normalmente con TTL bajos.
- **Double flux:** rotan tanto las direcciones del servicio como las de los name servers autoritativos, ocultando también la capa de control.

El fast flux es un patrón de distribución de carga utilizado de forma adversaria, no simplemente “muchas respuestas DNS”. Las evidencias más sólidas combinan TTL bajo, un número elevado de direcciones únicas, amplia dispersión de ASN/geográfica, corta vida de los nodos, comportamiento repetido de la aplicación e historial de registro sospechoso. Las CDN comparten legítimamente varias de esas propiedades. MITRE recomienda correlacionar el comportamiento DNS con el proceso y las conexiones posteriores.<sup>[[5]](#references)</sup>

Un DGA puede detectarse mediante entropía léxica, patrones de consonantes/dígitos, ráfagas de NXDOMAIN, dominios sincronizados vistos por primera vez y contexto del proceso. Los DGA basados en wordlists y los modelos generativos derrotan las reglas simples de entropía, por lo que el clustering temporal en toda la flota y la lineage del endpoint adquieren mayor importancia.

## Dominios comprometidos y domain shadowing

Un actor puede secuestrar una cuenta de registrar/DNS, tomar el control de un subdominio abandonado o añadir registros bajo un dominio que, por lo demás, es reputado. El **domain shadowing** conserva el apex legítimo mientras grandes cantidades de subdominios controlados por el atacante apuntan a hosts de delivery o C2 cambiantes. Aprovecha la antigüedad y la reputación, y puede evadir el bloqueo de todo el dominio.<sup>[[6]](#references)</sup>

Los defensores necesitan audit logs del registrar y del DNS autoritativo, MFA, bloqueos de registry/registrar, alertas para nuevas delegaciones/tokens de API/name servers, monitorización de certificate transparency y un inventario de los recursos cloud referenciados por DNS. Investiga la resolución y el historial de certificados de un subdominio independientemente de la reputación del apex.

## Web services y dead-drop resolvers

Un **dead-drop resolver (T1102.001)** almacena un puntero codificado al C2 actual dentro de un post, perfil, documento, repositorio, objeto cloud o campo de blockchain legítimo. El malware obtiene el objeto público, decodifica un dominio/IP y contacta con la siguiente etapa. Las variantes bidireccionales intercambian comandos o archivos mediante APIs de servicios.<sup>[[7]](#references)</sup>

Esto proporciona resiliencia y oculta el C2 back-end del análisis estático del binario. También crea identificadores estables de objeto, tenant, repositorio, API y patrones de acceso. Los defensores deberían relacionar:

1. el proceso que contactó con el servicio;
2. la ruta/API/objeto exactos y el hash de respuesta;
3. la actividad de decodificación o procesamiento de strings;
4. la nueva conexión saliente poco después; y
5. el comportamiento idéntico en otros puntos de la flota.

Bloquear todo GitHub, cloud storage o las redes sociales rara vez es viable. La política de egress aware del servicio y la correlación a nivel de proceso superan al bloqueo basado únicamente en dominios.

## Personas, cuentas y compartimentos de procurement

El anonimato de la infraestructura falla cuando una persona, email de recuperación, teléfono, pago, navegador o IP de administración conecta compartimentos. Las operaciones vinculadas a Estados han cultivado perfiles sociales, identidades de email y cuentas cloud mucho antes de utilizarlas; ATT&CK registra esto como Establish Accounts (T1585), incluidas las sub-técnicas sociales, de email y cloud.<sup>[[8]](#references)</sup>

Un defensor o investigador construye un grafo a partir de:

- la hora de creación y del primer login, la configuración regional, la zona horaria y el horario de trabajo;
- los campos de recuperación, dispositivos MFA, documentos de identidad e instrumentos de pago;
- las huellas del navegador/TLS y el historial de redes de origen;
- la reutilización de avatares, la procedencia de imágenes, el estilo de escritura y el crecimiento del grafo social;
- el registrante del dominio, name server, certificado, ID de analytics o commit de repositorio compartidos;
- acciones del plano de administración que eluden la arquitectura pública de relay.

Para un red team autorizado, las personas sintéticas deben documentarse ante el responsable del ejercicio, utilizar canales de recuperación/pago propiedad de la organización, evitar suplantar a personas reales no involucradas y contar con una retirada planificada. El SOC puede permanecer ciego; la operación no debe volverse irresponsable.

## Patrones compuestos emergentes que deben modelarse como amenazas

Los siguientes son **composiciones impulsadas por el defensor**, no afirmaciones de que un actor identificado haya desplegado exactamente cada diseño. Combinan primitivas ya observadas y son hipótesis útiles para purple teams.

### Tasking asimétrico unidireccional

Los comandos llegan mediante una fuente pública, de broadcast o append-only, mientras que los resultados salen por un canal no relacionado después de un retraso. Entre los ejemplos de la primitiva se incluyen la comunicación unidireccional mediante web service y los dead drops. La separación impide que un único flujo parezca bidireccional y dificulta la correlación simple de solicitud/respuesta.<sup>[[9]](#references)</sup>

**Detección:** conserva las lecturas a nivel de objeto y, después, correlaciona los cambios de estado del proceso y las transferencias salientes posteriores en una ventana más amplia. Busca un proceso poco frecuente que lea el mismo objeto público incluso cuando no haya una respuesta inmediata.

### Promoción de canales multietapa

Una primera etapa silenciosa realiza inventario y solo promueve determinados sistemas a un canal de segunda etapa no relacionado. El segundo endpoint, protocolo y proceso pueden no compartir infraestructura con el primero. Esto limita la exposición de la infraestructura capaz y está modelado explícitamente como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detección:** relaciona `primer proceso de red -> estado descargado/configurado -> nuevo proceso o inyección -> destino no relacionado`; no cierres el incidente después de bloquear el primer dominio.

### Traducción de relay entre protocolos

Diferentes hops traducen HTTPS, QUIC, WebSocket, DNS, SSH o una API de message queue en lugar de reenviar paquetes de forma transparente. La traducción elimina una única huella de protocolo end-to-end, pero crea gateways con timing, buffering y conversión semántica distintivos. Protocol tunneling (T1572) puede combinarse con proxies y service impersonation.<sup>[[11]](#references)</sup>

**Detección:** busca hosts gateway que reciben un protocolo e inician otro con un comportamiento de bytes/tiempo estrechamente acoplado; compara la intención del endpoint con el protocolo que realmente se transporta.

### Activación pasiva en edge devices

En lugar de hacer beaconing, un implant monitoriza el tráfico que ya llega a un router/VPN y se activa únicamente ante un valor mágico, un patrón de source-port o un token autenticado. El tráfico normal continúa hacia el servicio real. ATT&CK lo denomina Traffic Signaling (T1205), con ejemplos documentados de dispositivos de red y APT.<sup>[[12]](#references)</sup>

**Detección:** integridad del firmware/archivo, captura de paquetes sin procesar durante un hunt autorizado, filtros de socket inesperados y comportamiento diferencial del servicio. La ausencia de un beacon periódico no demuestra que un edge device esté limpio.

### Rotación de origins serverless y efímeros

Un front mantiene una identidad lógica estable mientras funciones/containers de corta duración gestionan etapas individuales en varias regiones/cuentas. Esto reduce la vida en disco y las IP de origin fijas, pero la creación en el plano de control, la imagen/layer, el rol, el secreto, el request ID y la telemetría de billing se convierten en el grafo duradero.

**Detección:** conserva los cloud audit logs y los invocation logs fuera del workload; agrupa templates de deployment, roles, claves de entorno y relaciones front-to-origin.

### Diversidad de privacy layers

Una operación puede evitar deliberadamente una única cadena homogénea: por ejemplo, un canal utiliza un relay alquilado, el tasking usa un objeto público, un exit procede de un enlace celular de laboratorio propio y la administración utiliza una red independiente de la organización. Esto reduce el valor de comprometer un proveedor, pero aumenta los riesgos de timing entre capas y de errores operativos.

**Detección:** construye timelines de campaña entre sensores de identidad, DNS, SaaS, red y cloud. Busca transiciones de estado sincronizadas en lugar de indicadores idénticos.

### Dead drops descentralizados o basados en transparency logs

Un actor puede colocar un pequeño puntero cifrado en cualquier sistema público duradero append-only, almacenamiento content-addressed o feed similar a transparency. El objeto público es resiliente, pero su índice/hash de contenido exacto y el comportamiento de polling del cliente se convierten en identificadores estables.

**Detección:** registra los identificadores completos de API/objeto y los hashes de respuesta; alerta ante procesos no estándar que hagan polling de objetos inmutables seguido de decodificación o nuevas conexiones.

### Operaciones store-and-forward retrasadas

El C2 interactivo crea una fuerte correlación temporal. Un diseño store-and-forward agrupa jobs cifrados y devuelve los resultados minutos u horas después mediante una queue diferente o una transferencia física. Sacrifica capacidad de respuesta para debilitar el timing end-to-end.

**Detección:** amplía las ventanas de correlación, modela el acceso periódico a queues y examina el staging en los endpoints. El batching desplaza la señal del timing de paquetes al comportamiento programado de procesos/archivos; no la elimina.

## Revisión del diseño: piensa en observadores

Para cada ruta, completa esta tabla antes del deployment y después de la recopilación:

| Capa | ¿Ve el origen? | ¿Ve el destino? | ¿Ve el contenido? | Identificadores estables | Responsable de retención/legal |
|---|---:|---:|---:|---|---|
| red local/carrier | | | | | |
| servicio de entrada/acceso | | | | | |
| operador(es) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autoritativo/registrar | | | | | |
| target | | | | | |
| proveedor de cuenta/pago | | | | | |

Si un único proveedor ordinario puede completar todas las columnas, la arquitectura proporciona ocultación frente al target, pero no una separación sólida. Si ningún controller interno puede relacionar la actividad con un engagement, no es adecuada para red teaming profesional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestructura (T1583), comprometer infraestructura (T1584) y Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
