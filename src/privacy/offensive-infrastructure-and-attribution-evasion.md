# Infraestructura ofensiva y evasión de atribución

{{#include ../banners/hacktricks-training.md}}

Un operador rara vez logra un anonimato significativo con un solo proxy. Las campañas reales construyen un **grafo de separación**: el operador llega a un nodo de acceso, los nodos de tránsito ocultan ese nodo de la salida, los redirectors protegen el C2 real y los nombres desechables apuntan al perímetro público.

Consulta el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) para ver una descripción normalizada de las ventajas, desventajas, implementación y detección de cada ruta. Esta página profundiza en la composición de infraestructura adversarial.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

La última dirección que ve un objetivo es, por tanto, evidencia de una ruta, no una prueba de quién controlaba el teclado. MITRE asigna los componentes principales a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) y Web Service (T1102).<sup>[[1]](#references)</sup>

## Clases de infraestructura

| Clase | Por qué la usa un actor | Exposición duradera | Mejor punto de pivote para el defensor |
|---|---|---|---|
| VPS/cloud alquilado | Rápido, predecible, enrutable y fácil de reconstruir | tenant, facturación, consola, historial de inicios de sesión desde el origen e imágenes | eventos de cuenta/plano de control y huellas de servidor repetidas |
| VPN comercial/Tor | Gran conjunto de salidas compartidas; no requiere administrar servidores | visibilidad del proveedor/guardián y tiempos de extremo a extremo | comportamiento del destino, evidencia del endpoint y correlación de flujos |
| Proxy residencial/móvil | ASN de consumidor y plausibilidad geográfica | registros del bróker/cliente; comportamiento de proxyware o de host infectado | viajes imposibles, protocolos de proxy y cambios de dirección por sesión |
| Servidor/router/IoT comprometido | Aprovecha la reputación y jurisdicción de la víctima | implante, flujo de administración y controlador upstream recurrente | telemetría del dispositivo y topología ORB, no una única IP de salida |
| CDN/redirector | Separa el edge público del C2 del back-end | gramática TLS/HTTP, certificado, artefactos de enrutamiento y cuenta cloud | correlación entre edge y origen, y agrupación por forma de las solicitudes |
| Servicio web legítimo | Se mezcla con el tráfico permitido de GitHub/cloud/redes sociales | token de API, identificadores de tenant/objeto y linaje inusual de procesos | proceso del endpoint más semántica del servicio/API |
| Ruta física/celular/satelital | Cambia el origen físico aparente | registros de radiofrecuencia, operador, suscriptor, dispositivo y ubicación | evidencia de radio/física y de red combinada |

## Redes operativas de cajas relay

Una **red ORB** es una flota de proxies administrada y utilizada como servicio intermediario. Mandiant las divide en redes provisionadas de servidores arrendados, redes no provisionadas de routers/IoT comprometidos e híbridas. Una topología madura tiene cuatro roles lógicos:<sup>[[2]](#references)</sup>

1. **Servidor de administración (ACOS):** mantiene el inventario, las credenciales, el estado y la política de enrutamiento.
2. **Nodo de acceso/relay:** autentica a clientes u operadores; es la entrada estable a una malla cambiante.
3. **Nodos de tránsito:** uno o más sistemas arrendados o comprometidos retransmiten conexiones opacas.
4. **Nodo de salida/preparación:** presenta la dirección de origen final a los objetivos de reconnaissance, exploitation o C2.

La malla puede seleccionar salidas por país, ASN, latencia o disponibilidad, y rotar los nodos que no estén funcionando correctamente. Varios grupos de amenazas pueden alquilar la misma red. Mandiant observó que algunas direcciones IPv4 permanecían asociadas a ciertos ORB apenas 31 días; por ello recomienda tratar la **red como una entidad cambiante similar a un actor**, en lugar de bloquear una lista obsoleta de IPs.<sup>[[2]](#references)</sup>

### Qué ofrece y qué leaks

- El objetivo ve una salida que puede estar geográficamente cerca y parecer residencial.
- La salida ve al objetivo y al salto anterior, pero no necesariamente al operador.
- El servicio de acceso ve al cliente y la solicitud de ruta. Una malla administrada de forma independiente puede mantener al cliente separado de las salidas, pero genera un registro valioso de la contraparte.
- Los puertos recurrentes, el orden del handshake, los banners del servidor, los certificados, los periodos de actividad y las relaciones con el controlador pueden revelar la flota aunque roten las IPs.
- Un router comprometido suele carecer de telemetría de endpoint, pero su ISP sigue teniendo datos de suscriptor y de flujo; una incautación revela artefactos del implante y su configuración.

{% hint style="info" %}
Para un ejercicio autorizado, reproduce la topología con VMs o routers propiedad de la organización y conserva el mapa de atribución del controlador. No reclutes proxies abiertos ni dispositivos de terceros. La [guía del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la misma estructura de saltos visible para los defensores sin victimizar a un intermediario.
{% endhint %}

## Redes de proxies residenciales y móviles

Los servicios de proxy residencial asignan sesiones a direcciones de banda ancha de consumidores; los proxies móviles salen a través de grupos de NAT de operadores. El suministro puede provenir de dispositivos inscritos expresamente, SDK/proxyware incluido en aplicaciones de consumo, revendedores o malware. Estos orígenes no son equivalentes: la falta de consentimiento informado convierte un servicio de privacidad en infraestructura comprometida.

Los modos de rotación afectan la detección:

- **rotación por solicitud** produce discontinuidades rápidas de IP y ASN/geografía mientras la identidad de capas superiores permanece estable;
- **sesiones persistentes** mantienen una salida durante minutos u horas, lo que se parece a un suscriptor común;
- **gateways backconnect** exponen al cliente un único endpoint del bróker y eligen las salidas internamente;
- **grupos móviles** colocan a muchos suscriptores reales detrás de un pequeño conjunto de direcciones NAT de operadores, lo que hace costoso bloquear una IP.

Los defensores deben correlacionar la IP con la sesión autenticada, la huella TLS/cliente, el orden HTTP, la cookie del dispositivo y el comportamiento. Un inicio de sesión supuestamente local y residencial seguido de otro desde un país distinto, mientras todas las características de capas superiores siguen siendo idénticas, constituye una señal más sólida que la reputación por sí sola. A la inversa, el uso compartido de direcciones y el cambio de antena móvil generan cambios legítimos; por tanto, nunca se debe tratar la clasificación residencial/proxy como un veredicto.

### Planos de control de proxyware y solapamiento de revendedores

No modeles un grupo residencial como una lista plana de salidas. El análisis del ecosistema IPIDEA reveló un **plano de control reutilizable de dos niveles**: un SDK integrado primero reporta metadatos del dispositivo/inscripción a un dominio Tier One y recibe pares IP:puerto de programación y `connect`/`proxy` de Tier Two. El nodo consulta periódicamente el puerto connect de Tier Two para obtener una tarea codificada, abre una segunda conexión al puerto proxy emparejado y retransmite los bytes proporcionados al destino solicitado. SDKs y marcas de proxy nominalmente distintos tenían dominios de descubrimiento separados, pero convergían en infraestructura Tier Two compartida y grupos de salida superpuestos debido a relaciones de propiedad común y reventa.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Esto produce pivotes de hunting más duraderos que un bloque de IP residenciales:<sup>[[13]](#references)</sup>

- un proceso inesperado de una utilidad, VPN, juego o dispositivo integrado envía un ID de dispositivo/clave de cliente estable y recibe una lista cambiante de servidores;
- el endpoint consulta una IP directa en un puerto inusual y luego se conecta a otro puerto en la misma dirección, justo antes de abrir un nuevo socket de destino;
- varias marcas aparentes comparten direcciones Tier Two, gramática de protocolo, código SDK o solapamiento de nodos de salida;
- distintas aplicaciones que se conectan a diferentes dominios Tier One reciben direcciones del mismo pool Tier Two.

El solapamiento también limita la atribución: ver una IP en el pool anunciado por un proveedor no demuestra qué revendedor, cliente o actor de amenazas la usó en ese momento. Conserva las marcas de tiempo de los flujos, el linaje de procesos, los cuerpos de respuesta de Tier One y los identificadores de tareas de Tier Two.<sup>[[13]](#references)</sup> En un ejercicio autorizado, emula esta jerarquía solo con endpoints propiedad de la organización; nunca inscribas dispositivos de consumidores ni proxyware de terceros.

## Cadenas de proxy multi-hop

MITRE distingue los proxies externos de los **proxies multi-hop (T1090.003)**. La propiedad importante no es el número de saltos, sino la separación de conocimientos y administración.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Si una misma parte opera A y B, los registros compartidos o la sincronización del flujo pueden permitir reconstruir el circuito. Añadir VPN comerciales secuenciales desde el mismo endpoint/cuenta puede aumentar la latencia, pero deja intactas las pruebas de identidad, pago y sincronización comunes. Tor reduce este problema mediante relays seleccionados de forma independiente y un diseño de cliente compartido, pero una red interactiva de baja latencia no puede garantizar resistencia frente a un observador que mida ambos extremos.

Entre los fallos comunes están las fugas de DNS o IPv6, las aplicaciones que abren sus propios sockets, el tráfico de administración que llega directamente a los relays, la actividad sincronizada, las claves SSH reutilizadas y el inicio de sesión en cuentas que permiten identificar al usuario. La verificación correcta es una prueba de fallo: detener cada relay, uno por uno, y comprobar que la carga de trabajo no pueda recurrir a una ruta sin cifrar.

### Colapso del túnel y leak upstream

Una arquitectura de relays suele ser más fácil de atribuir cuando falla. Unit 42 documentó una ruta de espionaje de varios niveles que usaba VPS orientados a las víctimas, VPS de retransmisión, proxies residenciales, Tor y otros servicios de proxy; cuando se omitía o colapsaba un túnel, la infraestructura upstream oculta se conectaba directamente a los sistemas de retransmisión y a los orientados a las víctimas. La misma investigación también usó un certificado X.509 expuesto brevemente en la infraestructura upstream como pivote entre niveles.<sup>[[14]](#references)</sup>

Mantén separado el **plano de datos** (`victim <-> exit`) del **plano de control** (`operator/upstream -> relay administration`). Conserva los registros de ingreso y autenticación de cada nivel bajo tu control, los historiales de certificados y las conexiones fallidas breves, no solo las sesiones C2 exitosas. Una fuente que aparece únicamente durante las interrupciones de los relays o administra directamente varios nodos orientados a las víctimas es una candidata upstream más sólida que un exit común, pero su ASN/geolocalización sigue siendo una hipótesis, no una prueba de la identidad del operador.

Un laboratorio autorizado debe hacer que la carga de trabajo falle de forma segura. Para una carga de trabajo aislada en un espacio de nombres de red de Linux, la primera ruta debe usar el túnel; al eliminarlo, tanto la solicitud como la consulta de rutas deben fallar, en lugar de seleccionar la conexión física de salida:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Repite la prueba para DNS e IPv6 y en cada límite entre relays. Si alguna sonda tiene éxito, registra la interfaz/dirección de origen real antes de reparar el enrutamiento de políticas o el firewall; esa observación es la filtración de atribución que vería un investigador.

## Niveles de redirectors y configuración del tráfico

Un **redirector** público acepta el tráfico que coincide con una gramática específica de la operación y lo reenvía a un team server protegido. Todo lo demás se puede rechazar o responder con contenido inocuo.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Varias capas limitan la exposición: que se queme un dominio público no tiene por qué exponer el team server. Las CDN añaden capacidad anycast y un dominio externo de buena reputación, pero la cuenta de la CDN y los registros de edge se convierten en puntos de atribución. Las huellas TLS, el historial de certificados, las rutas distintivas y el orden de los encabezados, los tamaños de respuesta, el comportamiento de las redirecciones y las listas de permitidos del origin pueden agrupar frontends que supuestamente no están relacionados.

Para la detección, registra los campos del proxy inverso antes de la normalización, compara SNI/Host/authority, inspecciona combinaciones poco comunes de encabezados, agrupa los cuerpos de respuesta y las huellas TLS, y busca solapamientos de configuración en los registros de auditoría de cloud/CDN. En red teams autorizados, evita copiar una marca real o alojar la recopilación de credenciales en un tercero no relacionado.

## Domain fronting y domainless fronting

Con el **domain fronting clásico (T1090.004)**, la conexión TLS anuncia un dominio front permitido en SNI, mientras que el `Host` HTTP cifrado o `:authority` de HTTP/2 solicita un dominio de back-end diferente. Una CDN cooperante enruta según el valor interno. Un observador de red sin descifrado TLS ve el front; la CDN ve ambos valores y el origin. En las variantes domainless, SNI puede estar vacío mientras otro campo de enrutamiento selecciona el destino.<sup>[[4]](#references)</sup>

No es una suplantación mágica: solo funciona si el intermediario permite intencionalmente o por accidente la discrepancia y sabe cómo enrutar el nombre interno. Los principales proveedores han restringido el fronting entre cuentas. Encrypted ClientHello (ECH) cambia lo que puede ver un observador en la ruta, pero no elimina los registros de la CDN, el endpoint o la aplicación.

Los puntos de detección incluyen:

- la ascendencia del proceso en el endpoint y un destino inesperado para esa aplicación;
- discrepancias entre SNI y HTTP authority cuando la inspección TLS es legal y está disponible;
- registros de la CDN que muestran que un tenant/front enruta a otra authority/origin;
- sesiones inusualmente largas o periódicas con un servicio que normalmente es interactivo;
- tamaños y frecuencia estables de flujos cifrados a través de distintos dominios front.

El laboratorio seguro simula la discrepancia de enrutamiento en un proxy inverso propio; no abusa de una CDN pública.

## Resolución dinámica: DDNS, DGA y fast flux

La resolución dinámica desacopla un servicio lógico de una infraestructura fija:

- **DDNS:** un cliente autenticado actualiza un nombre estable cuando cambia su dirección.
- **DGA:** el endpoint y el controlador derivan nombres de dominio candidatos a partir de una semilla de tiempo/clave; el operador registra un subconjunto pequeño.
- **Fast flux:** un nombre devuelve un conjunto de direcciones comprometidas/de proxy que cambia rápidamente, a menudo con TTL bajos.
- **Double flux:** rotan tanto las direcciones del servicio como las de los servidores de nombres autoritativos, lo que también oculta la capa de control.

Fast flux es un patrón de distribución de carga usado con fines adversarios, no simplemente «muchas respuestas DNS». Las pruebas más sólidas combinan TTL bajo, un gran número de direcciones únicas, amplia dispersión de ASN/geográfica, corta duración de los nodos, comportamiento repetido de la aplicación e historial de registro sospechoso. Las CDN comparten legítimamente varias de estas características. MITRE recomienda correlacionar el comportamiento DNS con el proceso y las conexiones posteriores.<sup>[[5]](#references)</sup>

Una DGA puede detectarse mediante entropía léxica, patrones de consonantes/dígitos, ráfagas de NXDOMAIN, dominios sincronizados vistos por primera vez y contexto del proceso. Las DGA basadas en listas de palabras y los modelos generativos evaden las reglas simples de entropía, por lo que la agrupación temporal en toda la flota y la genealogía de los endpoints cobran más importancia.

## Dominios comprometidos y domain shadowing

Un actor puede secuestrar una cuenta de registrador/DNS, tomar el control de un subdominio abandonado o añadir registros bajo un dominio que, por lo demás, tiene buena reputación. **Domain shadowing** conserva el apex legítimo mientras un gran número de subdominios controlados por el atacante apuntan a hosts cambiantes de delivery o C2. Aprovecha la antigüedad y la reputación del dominio y puede evadir los bloqueos que abarcan todo el dominio.<sup>[[6]](#references)</sup>

Los defensores necesitan registros de auditoría del registrador y del DNS autoritativo, MFA, bloqueos de registro/registrador, alertas para nuevas delegaciones/tokens de API/servidores de nombres, monitorización de Certificate Transparency y un inventario de los recursos de cloud referenciados por DNS. Investiga la resolución y el historial de certificados de un subdominio independientemente de la reputación del apex.

## Web services y dead-drop resolvers

Un **dead-drop resolver (T1102.001)** almacena un puntero codificado al C2 actual dentro de una publicación, perfil, documento, repositorio, objeto de cloud o campo de blockchain legítimos. El malware obtiene el objeto público, decodifica un dominio/IP y contacta con la siguiente etapa. Las variantes bidireccionales intercambian comandos o archivos mediante las API del servicio.<sup>[[7]](#references)</sup>

Una variante de resolver específica de GitHub usa la API de búsqueda de Issues solo cuando falla un canal autenticado del repositorio. El cliente busca issues que coincidan con la fecha actual, el repositorio y el tipo de issue, sigue la URL de comentarios de cada issue y extrae el texto cifrado entre los marcadores `<!--` y `-->`. Tras descifrarlo por host usando una fecha derivada, campos como `Owner`, `LicRepo` y `LicToken` sustituyen al propietario, la ruta y el token principales del repositorio. Esto permite al operador rotar credenciales y endpoints sin reemplazar el cliente; el comentario del issue actúa como resolver, mientras que los archivos del repositorio siguen siendo el canal de tasking.<sup>[[15]](#references)</sup>

Esto proporciona resiliencia y oculta el C2 de back-end al análisis estático de binarios. También crea identificadores estables de objetos, tenants, repositorios, API y patrones de acceso. Los defensores deberían correlacionar:

1. el proceso que contactó con el servicio;
2. la ruta/objeto exactos de la API y el hash de respuesta;
3. la actividad de decodificación o procesamiento de cadenas;
4. la nueva conexión saliente poco después; y
5. el mismo comportamiento en otros puntos de la flota.

Bloquear GitHub, el almacenamiento de cloud o las redes sociales en su totalidad rara vez es viable. Las políticas de salida que reconocen el servicio y la correlación a nivel de proceso son más eficaces que bloquear solo por dominio.

## Personas, cuentas y compartimentos de aprovisionamiento

El anonimato de la infraestructura falla cuando una persona, un correo de recuperación, un teléfono, un pago, un navegador o una IP de administrador conecta compartimentos. Las operaciones vinculadas a Estados han cultivado perfiles sociales, identidades de correo y cuentas de cloud mucho antes de usarlos; ATT&CK lo registra como Establish Accounts (T1585), incluidas las sub-técnicas de redes sociales, correo y cloud.<sup>[[8]](#references)</sup>

Un defensor o investigador construye un grafo a partir de:

- la fecha de creación y del primer inicio de sesión, la configuración regional, la zona horaria y el horario de actividad;
- los campos de recuperación, los dispositivos MFA, los documentos de identidad y los medios de pago;
- las huellas del navegador/TLS y el historial de redes de origen;
- la reutilización de avatares, la procedencia de imágenes, el estilo de escritura y el crecimiento del grafo social;
- el registrante de dominio, el servidor de nombres, el certificado, el ID de analytics o el commit de repositorio compartidos;
- las acciones del plano de administración que evaden la arquitectura pública de relay.

En un red team autorizado, las personas sintéticas deben documentarse para el responsable del ejercicio, usar canales de recuperación/pago propiedad de la organización, evitar hacerse pasar por personas reales ajenas al ejercicio y tener previsto su retiro. El SOC puede seguir a ciegas; la operación no debe quedar sin responsables.

## Patrones compuestos emergentes para el modelado de amenazas

Lo siguiente son **composiciones orientadas a la defensa**, no afirmaciones de que un actor identificado haya desplegado exactamente cada diseño. Combinan primitivas ya observadas y son hipótesis útiles para ejercicios purple team.

### Tasking asimétrico unidireccional

Los comandos llegan a través de una fuente pública, de difusión o de solo anexado, mientras que los resultados salen por un canal no relacionado tras un retraso. Entre los ejemplos de esta primitiva se incluyen la comunicación unidireccional mediante web services y los dead drops. La separación impide que un único flujo parezca bidireccional y dificulta la correlación simple de solicitud/respuesta.<sup>[[9]](#references)</sup>

**Detección:** conserva los accesos a nivel de objeto y correlaciona los cambios de estado del proceso con las transferencias salientes posteriores en una ventana más amplia. Busca procesos poco comunes que lean el mismo objeto público aunque no haya una respuesta inmediata.

### Promoción de canales en varias etapas

Una primera etapa discreta realiza un inventario y solo promueve los sistemas seleccionados a un canal de segunda etapa no relacionado. El segundo endpoint, protocolo y proceso pueden no compartir infraestructura con el primero. Esto limita la exposición de la infraestructura de capacidades avanzadas y se modela explícitamente como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detección:** correlaciona `primer proceso de red -> estado descargado/configurado -> nuevo proceso o inyección -> destino no relacionado`; no cierres el incidente tras bloquear el primer dominio.

### Traducción de relay entre protocolos

Los distintos saltos traducen HTTPS, QUIC, WebSocket, DNS, SSH o una API de message queue en lugar de reenviar paquetes de forma transparente. La traducción elimina una única huella de protocolo de extremo a extremo, pero crea gateways con patrones distintivos de temporización, buffering y conversión semántica. Protocol tunneling (T1572) puede combinarse con proxies y suplantación de servicios.<sup>[[11]](#references)</sup>

**Detección:** busca hosts gateway que reciben un protocolo e inician otro con un comportamiento de bytes/tiempo estrechamente correlacionado; compara la intención del endpoint con el protocolo que realmente transporta.

### Activación pasiva en dispositivos edge

En lugar de enviar beacons, un implante supervisa el tráfico que ya llega a un router/VPN y se activa solo ante un valor mágico, un patrón de puerto de origen o un token autenticado. El tráfico normal sigue llegando al servicio real. ATT&CK lo denomina Traffic Signaling (T1205), con ejemplos documentados de dispositivos de red y APT.<sup>[[12]](#references)</sup>

**Detección:** integridad del firmware/archivos, captura de paquetes sin procesar durante una investigación autorizada, filtros de socket inesperados y comportamiento diferencial del servicio. La ausencia de un beacon periódico no demuestra que un dispositivo edge esté limpio.

### Rotación de origins serverless y efímeros

Un front mantiene una identidad lógica estable mientras funciones/contenedores de corta duración gestionan etapas individuales en varias regiones/cuentas. Esto reduce la duración de los datos en disco y elimina las IP de origin fijas, pero los datos de telemetría de creación del plano de control, imagen/capa, rol, secreto, ID de solicitud y facturación se convierten en el grafo persistente.

**Detección:** conserva los registros de auditoría e invocación de cloud fuera de la carga de trabajo; agrupa las plantillas de despliegue, los roles, las claves de entorno y las relaciones entre front y origin.

### Diversidad de capas de privacidad

Una operación puede evitar deliberadamente una cadena homogénea: por ejemplo, un canal usa un relay alquilado, el tasking usa un objeto público, la salida proviene de un enlace celular de laboratorio propio y la administración usa una red de la organización separada. Esto reduce el valor de comprometer a un solo proveedor, pero aumenta el riesgo de correlación temporal entre capas y de errores operativos.

**Detección:** crea cronologías de campaña que abarquen sensores de identidad, DNS, SaaS, red y cloud. Busca transiciones de estado sincronizadas en lugar de indicadores idénticos.

### Dead drops descentralizados o basados en registros de transparencia

Un actor puede colocar un pequeño puntero cifrado en cualquier sistema público duradero de solo anexado, almacén direccionable por contenido o feed similar a un registro de transparencia. El objeto público es resiliente, pero su índice/hash de contenido exactos y el comportamiento de sondeo del cliente se convierten en identificadores estables.

**Detección:** registra los identificadores completos de API/objeto y los hashes de respuesta; genera alertas cuando procesos no convencionales sondean objetos inmutables y después los decodifican o establecen nuevas conexiones.

### Operaciones store-and-forward con demora

El C2 interactivo crea una fuerte correlación temporal. Un diseño store-and-forward agrupa trabajos cifrados y devuelve los resultados minutos u horas después a través de otra cola o transferencia física. Sacrifica capacidad de respuesta para reducir la correlación temporal de extremo a extremo.

**Detección:** amplía las ventanas de correlación, modela el acceso periódico a las colas y examina el staging de los endpoints. El batching traslada la señal de la temporización de paquetes al comportamiento programado de procesos/archivos; no la elimina.

## Revisión del diseño: piensa en los observadores

Para cada ruta, completa esta tabla antes del despliegue y después de la recopilación:

| Capa | ¿Ve el origen? | ¿Ve el destino? | ¿Ve el contenido? | Identificadores estables | Retención/propietario legal |
|---|---:|---:|---:|---|---|
| red local/operador | | | | | |
| servicio de entrada/acceso | | | | | |
| operador(es) de traversal | | | | | |
| salida/redirector/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| objetivo | | | | | |
| proveedor de cuenta/pago | | | | | |

Si un proveedor común puede completar todas las columnas, la arquitectura oculta la actividad al objetivo, pero no proporciona una separación sólida. Si ningún responsable interno puede vincular la actividad con un ejercicio, no es adecuada para un red team profesional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestructura (T1583), comprometer infraestructura (T1584) y Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multicapa (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — DNS Fast Flux (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Comprometer infraestructura: dominios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establecer cuentas (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: comunicación unidireccional (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canales multietapa (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Desarticulación de la mayor red de proxies residenciales del mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Las campañas Shadow: revelación del espionaje global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campaña Blinder Tunnel ataca infraestructura iraquí](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
