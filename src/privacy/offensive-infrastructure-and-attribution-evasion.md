# Infraestructura ofensiva y evasión de atribución

Un operador rara vez obtiene un anonimato significativo mediante un único proxy. Las campañas reales construyen un **grafo de separación**: el operador llega a un nodo de acceso, los nodos de traversal ocultan ese nodo del exit, los redirectors protegen el C2 real y los nombres desechables apuntan al borde público.

Usa el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) para consultar una vista normalizada de ventajas/desventajas/despliegue/detección de cada ruta. Esta página profundiza en la composición de infraestructura adversaria.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
La última dirección observada por un objetivo es, por tanto, evidencia de una ruta, no una prueba de quién controlaba el teclado. MITRE asigna los componentes principales a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) y Web Service (T1102).<sup>[[1]](#references)</sup>

## Clases de infraestructura

| Clase | Por qué la usa un actor | Exposición persistente | Mejor pivote del defensor |
|---|---|---|---|
| VPS/cloud alquilado | Rápido, predecible, enrutable y fácil de reconstruir | tenant, facturación, consola, inicios de sesión de origen e historial de imágenes | eventos de la cuenta/control plane y fingerprint repetido del servidor |
| VPN/Tor comercial | Gran conjunto de egress compartido; sin administración del servidor | visibilidad del proveedor/guard y timing de extremo a extremo | comportamiento del destino, evidencia en endpoints y correlación de flujos |
| Proxy residencial/móvil | ASN de consumidor y plausibilidad geográfica | registros del broker/cliente; comportamiento de proxyware o del host infectado | viajes imposibles, protocolos de proxy y churn de direcciones por sesión |
| Servidor/router/IoT comprometido | Aprovecha la reputación y jurisdicción de la víctima | implant, flujo de administración y controlador upstream repetido | telemetría del dispositivo y topología ORB, no una única IP de salida |
| CDN/redirector | Separa el edge público del C2 de back-end | gramática TLS/HTTP, certificado, routing y artefactos de la cuenta cloud | correlación edge-to-origin y clustering de la forma de las solicitudes |
| Servicio web legítimo | Se mezcla con el tráfico permitido de GitHub/cloud/social | API token, identificadores de tenant/objeto y lineage inusual de procesos | proceso del endpoint más semántica del servicio/API |
| Ruta física/celular/satelital | Cambia el origen físico aparente | registros de RF, operador, suscriptor, dispositivo y ubicación | evidencia de radio/física y de red combinada |

## Redes de relay box operativas

Una **red ORB** es una flota de proxies administrada que se utiliza como servicio intermediario. Mandiant las divide en redes provisionadas de servidores alquilados, redes no provisionadas de routers/IoT comprometidos e híbridos. Una topología madura tiene cuatro roles lógicos:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** mantiene el inventario, las credenciales, el estado y la política de routing.
2. **Access/relay node:** autentica a clientes u operadores; es la entrada estable a una mesh cambiante.
3. **Traversal nodes:** uno o más sistemas alquilados o comprometidos retransmiten conexiones opacas.
4. **Exit/staging node:** presenta la dirección de origen final durante el reconocimiento, la explotación o ante objetivos de C2.

La mesh puede seleccionar exits por país, ASN, latencia o disponibilidad, y rotar los nodos que no están saludables. Varios threat groups pueden alquilar la misma red. Mandiant observó que una dirección IPv4 permanecía asociada a algunos ORBs durante tan solo 31 días; por ello recomienda tratar la **red como una entidad en evolución similar a un actor**, en lugar de bloquear una lista obsoleta de IPs.<sup>[[2]](#references)</sup>

### Lo que esto consigue y lo que filtra

- El objetivo ve un exit que puede estar geográficamente cercano y parecer residencial.
- El exit ve al objetivo y al salto anterior, pero no necesariamente al operador.
- El servicio de acceso ve al cliente y la solicitud de ruta. Una mesh administrada de forma independiente puede mantener al cliente separado de los exits, pero crea un registro muy valioso de la contraparte.
- Los puertos repetidos, el orden del handshake, los banners del servidor, los certificados, las ventanas de uptime y las relaciones con el controlador pueden revelar la flota incluso mientras rotan las IPs.
- Un router comprometido suele carecer de telemetría del endpoint, pero su ISP sigue teniendo datos del suscriptor y de los flujos; una incautación revela artefactos del implant/configuración.

{% hint style="info" %}
Para un ejercicio autorizado, reproduce la topología con VMs o routers propiedad de la organización y conserva el mapa de atribución del controlador. No reclutes proxies abiertos ni dispositivos de terceros. La [guía del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la misma estructura de saltos visible para el defensor sin victimizar a un intermediario.
{% endhint %}

## Redes de proxies residenciales y móviles

Los servicios de proxies residenciales asignan sesiones a direcciones de banda ancha de consumidores; los proxies móviles realizan el egress mediante pools de NAT de operadores. El suministro puede proceder de appliances inscritos expresamente, SDK/proxyware integrado en aplicaciones de consumidores, revendedores o malware. Estos orígenes no son equivalentes: la falta de consentimiento informado convierte un servicio de privacidad en infraestructura comprometida.

Los modos de rotación afectan a la detección:

- la **rotación por solicitud** produce discontinuidades rápidas de IP y ASN/geografía mientras la identidad de las capas superiores permanece estable;
- las **sticky sessions** mantienen un exit durante minutos u horas, pareciéndose a un suscriptor ordinario;
- los **backconnect gateways** exponen un endpoint del broker al cliente y eligen los exits internamente;
- los **mobile pools** sitúan a muchos suscriptores reales detrás de un pequeño conjunto de direcciones NAT del operador, lo que hace costoso bloquear una IP.

Los defensores deberían correlacionar la IP con la sesión autenticada, el fingerprint de TLS/cliente, el orden HTTP, la cookie del dispositivo y el comportamiento. Un inicio de sesión residencial supuestamente local seguido de otro país mientras todas las características de las capas superiores permanecen idénticas es una señal más sólida que la reputación por sí sola. Por el contrario, el uso compartido de direcciones y el handoff móvil generan churn legítimo, por lo que nunca se debe tratar la clasificación residencial/proxy como un veredicto.

## Cadenas de proxies multi-hop

MITRE distingue los proxies externos de los **multi-hop proxies (T1090.003)**. La propiedad importante no es el número de saltos, sino la separación del conocimiento y la administración.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Si una misma parte opera A y B, los logs compartidos o la sincronización temporal del flujo pueden reconstruir el circuito. Añadir VPNs comerciales secuenciales desde el mismo endpoint/cuenta puede aumentar la latencia, pero mantiene evidencias comunes de identidad, pago y sincronización temporal. Tor reduce este problema mediante relays seleccionados de forma independiente y un diseño de cliente compartido, pero una red interactiva de baja latencia no puede prometer resistencia frente a un observador que mida ambos extremos.

Los fallos comunes son el bypass de DNS o IPv6, las aplicaciones que abren sus propios sockets, el tráfico de gestión que llega directamente a los relays, la actividad sincronizada, la reutilización de claves SSH y el inicio de sesión en cuentas identificables. La verificación correcta es una prueba de fallo: detener cada relay por turnos y demostrar que la carga de trabajo no puede recurrir a una ruta en claro.

## Capas de redirectors y traffic shaping

Un **redirector** público acepta el tráfico que coincide con una gramática específica de la operación y lo reenvía a un servidor protegido del equipo. Todo lo demás puede rechazarse o recibir contenido inocuo.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Múltiples capas limitan la exposición: quemar un dominio público no tiene por qué exponer el team server. Los CDNs añaden capacidad anycast y un dominio exterior de buena reputación, pero la cuenta del CDN y los edge logs se convierten en puntos de atribución. Las huellas TLS, los historiales de certificados, las rutas distintivas/orden de headers, los tamaños de respuesta, el comportamiento de redirección y las allowlists del origin pueden agrupar fronts supuestamente no relacionados.

Para la detección, registra los campos del reverse proxy antes de la normalización, compara SNI/Host/authority, inspecciona combinaciones poco frecuentes de headers, agrupa los cuerpos de respuesta y las huellas TLS, y busca solapamientos de configuración en los audit logs de cloud/CDN. En red teams autorizados, evita copiar una marca real o colocar la recolección de credenciales detrás de un tercero no relacionado.

## Domain fronting and domainless fronting

Con el **domain fronting (T1090.004)** clásico, la conexión TLS anuncia un dominio front permitido en SNI, mientras que el `Host` HTTP cifrado o `:authority` de HTTP/2 solicita un dominio back-end diferente. Un CDN colaborador enruta según el valor interno. Un observador de red sin descifrado TLS ve el front; el CDN ve ambos valores y el origin. En las variantes domainless, SNI puede estar vacío mientras otro campo de routing selecciona el destino.<sup>[[4]](#references)</sup>

Esto no es una suplantación mágica: solo funciona cuando el intermediario permite intencionadamente o por accidente la discrepancia y sabe cómo enrutar el nombre interno. Los principales proveedores han restringido el fronting entre cuentas. Encrypted ClientHello (ECH) cambia lo que puede ver un observador situado en la ruta, pero no elimina los registros del CDN, del endpoint o de la aplicación.

Los puntos de detección incluyen:

- la ascendencia del proceso del endpoint y un destino no esperado para esa aplicación;
- discrepancias entre SNI y la authority HTTP cuando la inspección TLS sea legal y esté disponible;
- logs del CDN que muestren un tenant/front enrutando hacia otra authority/origin;
- sesiones inusualmente largas o periódicas hacia un servicio normalmente interactivo;
- tamaños y cadencia estables de flujos cifrados a través de dominios front cambiantes.

El laboratorio seguro simula la discrepancia de routing en un reverse proxy propio; no abusa de un CDN público.

## Dynamic resolution: DDNS, DGA and fast flux

La resolución dinámica desacopla un servicio lógico de una infraestructura fija:

- **DDNS:** un cliente autenticado actualiza un nombre estable después de que cambie su dirección.
- **DGA:** tanto el endpoint como el controller derivan nombres de dominio candidatos a partir de una semilla temporal/de clave; el operador registra un subconjunto pequeño.
- **Fast flux:** un nombre devuelve un conjunto que cambia rápidamente de direcciones de sistemas comprometidos/proxy, normalmente con TTL bajos.
- **Double flux:** rotan tanto las direcciones de servicio como las direcciones de los name servers autoritativos, ocultando también la capa de control.

Fast flux es un patrón de distribución de carga usado de forma adversaria, no simplemente “muchas respuestas DNS”. Las evidencias más sólidas combinan TTL bajo, un número elevado de direcciones únicas, amplia dispersión de ASN/geográfica, corta vida de los nodos, comportamiento repetido de la aplicación e historial de registro sospechoso. Los CDNs comparten legítimamente varias de esas propiedades. MITRE recomienda correlacionar el comportamiento DNS con el proceso y las conexiones posteriores.<sup>[[5]](#references)</sup>

Un DGA puede detectarse mediante entropía léxica, patrones de consonantes/dígitos, ráfagas de NXDOMAIN, dominios sincronizados vistos por primera vez y contexto del proceso. Los DGAs basados en wordlists y los modelos generativos derrotan las reglas simples de entropía, por lo que la agrupación temporal en toda la flota y la lineage del endpoint adquieren mayor importancia.

## Compromised domains and domain shadowing

Un actor puede secuestrar una cuenta de registrar/DNS, tomar el control de un subdominio abandonado o añadir registros bajo un dominio que, por lo demás, goza de buena reputación. El **domain shadowing** conserva el apex legítimo mientras grandes cantidades de subdominios controlados por el atacante apuntan a hosts cambiantes de delivery o C2. Aprovecha la antigüedad y la reputación, y puede evadir el bloqueo de todo el dominio.<sup>[[6]](#references)</sup>

Los defensores necesitan audit logs del registrar y del DNS autoritativo, MFA, bloqueos de registry/registrar, alertas para nuevas delegaciones/tokens de API/name servers, monitorización de certificate transparency y un inventario de los recursos cloud referenciados por DNS. Investiga la resolución y el historial de certificados de un subdominio independientemente de la reputación del apex.

## Web services and dead-drop resolvers

Un **dead-drop resolver (T1102.001)** almacena un puntero codificado al C2 actual dentro de una publicación, perfil, documento, repositorio, objeto cloud o campo de blockchain legítimo. El malware obtiene el objeto público, decodifica un dominio/IP y contacta con la siguiente etapa. Las variantes bidireccionales intercambian comandos o archivos mediante APIs de servicios.<sup>[[7]](#references)</sup>

Esto proporciona resiliencia y oculta el C2 back-end del análisis estático del binario. También crea identificadores estables de objeto, tenant, repositorio, API y patrón de acceso. Los defensores deberían relacionar:

1. el proceso que contactó con el servicio;
2. la ruta/objeto exactos de la API y el hash de respuesta;
3. la actividad de decodificación o procesamiento de strings;
4. la nueva conexión saliente poco después; y
5. el comportamiento idéntico en otros puntos de la flota.

Bloquear todo GitHub, cloud storage o social media rara vez es viable. Una política de egress consciente del servicio y la correlación a nivel de proceso superan al bloqueo basado únicamente en dominios.

## Personas, cuentas y compartimentos de procurement

El anonimato de la infraestructura falla cuando una persona, un email de recuperación, un teléfono, un pago, un navegador o una IP de administración conecta compartimentos. Las operaciones vinculadas a estados han cultivado perfiles sociales, identidades de email y cuentas cloud mucho antes de usarlas; ATT&CK registra esto como Establish Accounts (T1585), incluidas las sub-técnicas sociales, de email y cloud.<sup>[[8]](#references)</sup>

Un defensor o investigador construye un grafo a partir de:

- hora de creación y del primer login, locale, zona horaria y horario de trabajo;
- campos de recuperación, dispositivos MFA, documentos de identidad e instrumentos de pago;
- huellas del navegador/TLS e historial de la red de origen;
- reutilización de avatares, procedencia de imágenes, estilo de escritura y crecimiento del grafo social;
- registrante de dominio, name server, certificado, ID de analytics o commit de repositorio compartidos;
- acciones del plano de administración que eviten la arquitectura pública de relay.

Para un red team autorizado, las personas sintéticas deben documentarse ante el responsable del ejercicio, utilizar canales de recuperación/pago propiedad de la organización, evitar suplantar a personas reales no implicadas y contar con una retirada planificada. El SOC puede permanecer ciego; la operación no debe volverse irresponsable.

## Emerging compound patterns to threat-model

Las siguientes son **composiciones impulsadas por el defensor**, no afirmaciones de que un actor identificado haya desplegado cada diseño exacto. Combinan primitivas ya observadas y son hipótesis útiles para purple teams.

### Asymmetric one-way tasking

Los comandos llegan a través de una fuente pública, de broadcast o append-only, mientras que los resultados salen por un canal no relacionado después de un retraso. Algunos ejemplos de la primitiva incluyen la comunicación unidireccional mediante web service y los dead drops. La separación evita que un único flujo parezca bidireccional y dificulta la correlación simple de solicitud/respuesta.<sup>[[9]](#references)</sup>

**Detección:** conserva las lecturas a nivel de objeto y correlaciona los cambios de estado del proceso y las transferencias salientes posteriores en una ventana más amplia. Busca un proceso poco frecuente que lea el mismo objeto público incluso cuando no haya una respuesta inmediata.

### Multi-stage channel promotion

Una primera etapa silenciosa realiza el inventario y solo promociona los sistemas seleccionados a un canal de segunda etapa no relacionado. El segundo endpoint, protocolo y proceso pueden no compartir infraestructura con el primero. Esto limita la exposición de la infraestructura capaz y se modela explícitamente como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detección:** relaciona `primer proceso de red -> estado descargado/configurado -> nuevo proceso o inyección -> destino no relacionado`; no cierres el incidente después de bloquear el primer dominio.

### Cross-protocol relay translation

Diferentes saltos traducen HTTPS, QUIC, WebSocket, DNS, SSH o una API de message queue en lugar de reenviar paquetes de forma transparente. La traducción elimina una única huella de protocolo end-to-end, pero crea gateways con timing, buffering y conversión semántica distintivos. Protocol tunneling (T1572) puede combinarse con proxies y service impersonation.<sup>[[11]](#references)</sup>

**Detección:** busca hosts gateway que reciban un protocolo e inicien otro con un comportamiento de bytes/tiempo estrechamente acoplado; compara la intención del endpoint con el protocolo que realmente se transporta.

### Passive activation on edge devices

En lugar de hacer beaconing, un implant monitoriza el tráfico que ya llega a un router/VPN y se activa únicamente ante un valor mágico, un patrón de source-port o un token autenticado. El tráfico normal continúa hacia el servicio real. ATT&CK lo denomina Traffic Signaling (T1205), con ejemplos documentados de network devices y APT.<sup>[[12]](#references)</sup>

**Detección:** integridad del firmware/archivos, captura de paquetes sin procesar durante un hunt autorizado, filtros de socket inesperados y comportamiento diferencial del servicio. La ausencia de un beacon periódico no demuestra que un edge device esté limpio.

### Serverless and ephemeral origin rotation

Un front mantiene una identidad lógica estable mientras funciones/containers de corta duración gestionan etapas individuales en varias regiones/cuentas. Esto reduce la duración en disco y las IPs de origin fijas, pero la creación en el plano de control, la imagen/layer, el role, el secret, el request ID y la telemetría de billing se convierten en el grafo duradero.

**Detección:** conserva los audit logs de cloud y los logs de invocación fuera del workload; agrupa las plantillas de deployment, roles, claves de entorno y relaciones front-to-origin.

### Privacy-layer diversity

Una operación puede evitar deliberadamente una única cadena homogénea: por ejemplo, un canal usa un relay alquilado, el tasking utiliza un objeto público, un exit procede de un enlace celular de laboratorio propio y la administración usa una red independiente de la organización. Esto reduce el valor de comprometer un proveedor, pero aumenta el riesgo de timing entre capas y de errores operativos.

**Detección:** construye timelines de campaña entre sensores de identidad, DNS, SaaS, red y cloud. Busca transiciones de estado sincronizadas en lugar de indicadores idénticos.

### Decentralized or transparency-log dead drops

Un actor puede colocar un pequeño puntero cifrado en cualquier sistema público duradero append-only, content-addressed store o feed similar a transparency. El objeto público es resiliente, pero su índice/hash de contenido exacto y el comportamiento de polling del cliente se convierten en identificadores estables.

**Detección:** registra los identificadores completos de API/objeto y los hashes de respuesta; alerta sobre procesos no estándar que hagan polling de objetos inmutables seguido de decodificación o nuevas conexiones.

### Delayed store-and-forward operations

El C2 interactivo crea una fuerte correlación temporal. Un diseño store-and-forward agrupa jobs cifrados y devuelve los resultados minutos u horas después mediante una queue diferente o una transferencia física. Sacrifica capacidad de respuesta a cambio de un timing end-to-end más débil.

**Detección:** amplía las ventanas de correlación, modela el acceso periódico a queues y examina el staging del endpoint. El batching desplaza la señal del timing de paquetes al comportamiento programado de procesos/archivos; no la elimina.

## Design review: think in observers

Para cada ruta, completa esta tabla antes del deployment y después de la recopilación:

| Capa | ¿Ve el origen? | ¿Ve el destino? | ¿Ve el contenido? | Identificadores estables | Retención/responsable legal |
|---|---:|---:|---:|---|---|
| red local/carrier | | | | | |
| servicio de entrada/acceso | | | | | |
| operador(es) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autoritativo/registrar | | | | | |
| target | | | | | |
| proveedor de cuenta/pagos | | | | | |

Si un proveedor ordinario puede completar todas las columnas, la arquitectura proporciona ocultación frente al target, pero no una separación sólida. Si ningún controller interno puede relacionar la actividad con un engagement, no es adecuada para red teaming profesional.

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
