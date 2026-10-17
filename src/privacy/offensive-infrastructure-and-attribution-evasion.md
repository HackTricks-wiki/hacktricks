# Infraestructura ofensiva y evasión de atribución

{{#include ../banners/hacktricks-training.md}}

Rara vez un operador obtiene un anonimato significativo con un solo proxy. Las campañas reales construyen un **grafo de separación**: el operador llega a un nodo de acceso, los nodos de tránsito ocultan ese nodo de salida, los redirectores protegen el C2 real y los dominios desechables apuntan al perímetro público.

Consulta el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) para ver una comparación normalizada de las ventajas, desventajas, implementación y detección de cada ruta. Esta página profundiza en la composición de infraestructura adversaria.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

La última dirección que ve un objetivo es, por tanto, evidencia de una ruta, no una prueba de quién controlaba el teclado. MITRE asigna los componentes principales a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) y Web Service (T1102).<sup>[[1]](#references)</sup>

## Clases de infraestructura

| Clase | Por qué la usa un actor | Exposición duradera | Mejor punto de pivote para los defensores |
|---|---|---|---|
| VPS/cloud alquilado | Rápido, predecible, enrutable y fácil de reconstruir | Historial del tenant, facturación, consola, inicios de sesión de origen e imágenes | Eventos de la cuenta/plano de control y huellas de servidor repetidas |
| VPN comercial/Tor | Gran conjunto compartido de salidas; no requiere administrar servidores | Visibilidad del proveedor/guardián y tiempos de extremo a extremo | Comportamiento del destino, evidencia del endpoint y correlación de flujos |
| Proxy residencial/móvil | ASN de consumidor y plausibilidad geográfica | Registros del broker/cliente; comportamiento de proxyware o de hosts infectados | Viajes imposibles, protocolos de proxy y cambios de dirección por sesión |
| Servidor/router/IoT comprometido | Aprovecha la reputación y jurisdicción de la víctima | Implant, flujo de administración y controlador upstream repetido | Telemetría del dispositivo y topología ORB, no una única IP de salida |
| CDN/redirector | Separa el edge público del C2 back-end | Artefactos de TLS/HTTP, certificados, enrutamiento y cuenta cloud | Correlación edge-to-origin y agrupación por forma de solicitud |
| Servicio web legítimo | Se mezcla con el tráfico permitido de GitHub/cloud/redes sociales | Token de API, identificadores de tenant/objeto y linaje de procesos inusual | Proceso del endpoint y semántica del servicio/API |
| Ruta física/celular/satelital | Cambia el origen físico aparente | Registros de RF, operador, abonado, dispositivo y ubicación | Evidencia de radio/física y de red combinada |

## Redes operativas de relay

Una **red ORB** es una flota administrada de proxies que se utiliza como servicio intermediario. Mandiant las divide en redes aprovisionadas de servidores alquilados, redes no aprovisionadas de routers/IoT comprometidos e híbridas. Una topología madura tiene cuatro funciones lógicas:<sup>[[2]](#references)</sup>

1. **Servidor de administración (ACOS):** mantiene el inventario, las credenciales, el estado y la política de enrutamiento.
2. **Nodo de acceso/relay:** autentica a clientes u operadores; es la entrada estable a una mesh cambiante.
3. **Nodos de tránsito:** uno o más sistemas alquilados o comprometidos retransmiten conexiones opacas.
4. **Nodo de salida/puesta en escena:** presenta la dirección de origen final a objetivos de reconocimiento, explotación o C2.

La mesh puede seleccionar salidas por país, ASN, latencia o disponibilidad, y rotar los nodos que no estén en buen estado. Varios grupos de amenazas pueden alquilar la misma red. Mandiant observó que una dirección IPv4 permanecía asociada a algunos ORB apenas 31 días; por ello, recomienda tratar la **red como una entidad dinámica similar a un actor**, en lugar de bloquear una lista obsoleta de IP.<sup>[[2]](#references)</sup>

### Qué permite y qué expone

- El objetivo ve una salida que puede estar geográficamente cerca y parecer residencial.
- La salida ve al objetivo y al salto anterior, pero no necesariamente al operador.
- El servicio de acceso ve al cliente y la solicitud de ruta. Una mesh administrada de forma independiente puede mantener al cliente separado de las salidas, pero genera un registro poderoso de la contraparte.
- Los puertos repetidos, el orden de los handshakes, los banners de servidor, los certificados, las ventanas de actividad y las relaciones entre controladores pueden revelar la flota incluso mientras rotan las IP.
- Un router comprometido suele carecer de telemetría de endpoint, pero su ISP aún conserva datos de abonado y de flujo; una incautación revela artefactos del implant y de la configuración.

{% hint style="info" %}
Para un ejercicio autorizado, reproduce la topología con VM o routers propiedad de la organización y conserva el mapa de atribución del controlador. No reclutes proxies abiertos ni dispositivos de terceros. La [guía del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la misma estructura de saltos visible para los defensores sin victimizar a un intermediario.
{% endhint %}

## Redes de proxies residenciales y móviles

Los servicios de proxy residencial asignan sesiones a direcciones de banda ancha de consumidores; los proxies móviles salen a través de grupos NAT de operadores. El suministro puede provenir de dispositivos inscritos expresamente, SDK/proxyware incluido en aplicaciones de consumo, revendedores o malware. Estos orígenes no son equivalentes: la falta de consentimiento informado convierte un servicio de privacidad en infraestructura comprometida.

Los modos de rotación afectan a la detección:

- la **rotación por solicitud** produce cambios rápidos de IP y ASN/geografía mientras la identidad de capas superiores permanece estable;
- las **sesiones persistentes** mantienen una salida durante minutos u horas, con apariencia de un abonado común;
- las **puertas de enlace backconnect** muestran al cliente un único endpoint de broker y eligen las salidas internamente;
- los **grupos móviles** colocan a muchos abonados reales detrás de un pequeño conjunto de direcciones NAT de operadores, por lo que bloquear una IP puede resultar costoso.

Los defensores deben correlacionar la IP con la sesión autenticada, la huella TLS/cliente, el orden HTTP, la cookie del dispositivo y el comportamiento. Un inicio de sesión supuestamente local y residencial, seguido de otro país mientras todas las características de capas superiores permanecen idénticas, constituye una evidencia más sólida que la reputación por sí sola. A la inversa, el uso compartido de direcciones y los cambios de conexión móvil generan rotación legítima, así que nunca se debe tratar la clasificación residencial/de proxy como un veredicto.

### Planos de control de proxyware y solapamiento entre revendedores

No modeles un grupo residencial como una lista plana de salidas. El análisis del ecosistema IPIDEA reveló un **plano de control reutilizable de dos niveles**: un SDK integrado primero informa los metadatos del dispositivo/inscripción a un dominio Tier One y recibe pares IP:puerto de programación y `connect`/`proxy` de Tier Two. El nodo consulta periódicamente el puerto de conexión de Tier Two para obtener una tarea codificada, abre una segunda conexión al puerto proxy asociado y retransmite los bytes proporcionados al destino solicitado. SDK y marcas de proxy aparentemente distintos tenían dominios de descubrimiento separados, pero convergían en infraestructura compartida de Tier Two y grupos de salida superpuestos debido a relaciones de propiedad común y reventa.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Esto genera pivotes de hunting más duraderos que un bloque de IP residenciales:<sup>[[13]](#references)</sup>

- un proceso inesperado de una utilidad, VPN, juego o dispositivo integrado envía un ID de dispositivo o una clave de cliente estable y recibe una lista cambiante de servidores;
- el endpoint consulta una IP directa en un puerto inusual y luego se conecta a otro puerto de la misma dirección justo antes de abrir un socket hacia un nuevo destino;
- varias marcas aparentes comparten direcciones Tier Two, gramática de protocolo, código SDK o superposición de nodos de salida;
- distintas aplicaciones que se conectan a diferentes dominios Tier One reciben direcciones del mismo conjunto Tier Two.

La superposición también limita la atribución: ver una IP en el conjunto anunciado de un proveedor no permite determinar qué revendedor, cliente o actor de amenazas la usó en ese momento. Conserva las marcas de tiempo del flujo, la cadena de procesos, los cuerpos de respuesta de Tier One y los identificadores de tareas de Tier Two.<sup>[[13]](#references)</sup> En un ejercicio autorizado, emula esta jerarquía solo con endpoints propiedad de la organización; nunca inscribas dispositivos de consumidores ni software de proxy de terceros.

## Cadenas de proxies de varios saltos

MITRE distingue los proxies externos de los **multi-hop proxies (T1090.003)**. La propiedad importante no es la cantidad de saltos, sino la separación del conocimiento y la administración.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Si una misma parte opera A y B, los logs compartidos o la sincronización del flujo pueden permitir reconstruir el circuito. Añadir VPN comerciales secuenciales desde el mismo endpoint/cuenta puede aumentar la latencia y, al mismo tiempo, dejar pruebas comunes de identidad, pago y sincronización. Tor reduce este problema con relays seleccionados de forma independiente y un diseño de cliente compartido, pero una red interactiva de baja latencia no puede prometer resistencia ante un observador que mida ambos extremos.

Entre los fallos habituales están las filtraciones por DNS o IPv6, las aplicaciones que abren sus propios sockets, el tráfico de administración que llega directamente a los relays, la actividad sincronizada, la reutilización de claves SSH y el inicio de sesión en cuentas que revelan la identidad. La verificación correcta es una prueba de fallo: detener cada relay por turnos y demostrar que la carga de trabajo no puede recurrir a una ruta sin cifrar.

### Colapso del túnel y filtración upstream

Una arquitectura de relays suele ser más fácil de atribuir cuando falla. Unit 42 documentó una ruta de espionaje multinivel que usaba VPS orientados a las víctimas, VPS de relay, proxies residenciales, Tor y otros servicios proxy; cuando se omitía o colapsaba un túnel, la infraestructura upstream oculta se conectaba directamente a los sistemas de relay y a los orientados a las víctimas. La misma investigación también usó un certificado X.509 expuesto brevemente en la infraestructura upstream como pivote entre niveles.<sup>[[14]](#references)</sup>

Mantén separado el **plano de datos** (`victim <-> exit`) del **plano de control** (`operator/upstream -> relay administration`). Conserva los logs de entrada y autenticación de cada nivel que controles, los historiales de certificados y las conexiones fallidas de corta duración, no solo las sesiones C2 exitosas. Una fuente que aparece únicamente durante las interrupciones del relay o que administra directamente varios nodos orientados a las víctimas es una candidata upstream más sólida que un exit común, pero su ASN/geolocalización sigue siendo una hipótesis, no una prueba de la identidad del operador.

Un laboratorio autorizado debe hacer que la carga de trabajo falle de forma cerrada. Para una carga de trabajo aislada en un namespace de red de Linux, la primera ruta debe usar el túnel; al quitarlo, tanto la solicitud como la búsqueda de rutas deben fallar, en vez de seleccionar el enlace físico de salida:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Repite la prueba para DNS e IPv6 y en cada límite entre relays. Si alguna sonda tiene éxito, registra la interfaz/dirección de origen real antes de corregir el enrutamiento de políticas o el firewall; esa observación es el attribution leak que vería un investigador.

## Capas de redirectors y modelado del tráfico

Un **redirector** público acepta el tráfico que coincide con una gramática específica de la operación y lo reenvía a un team server protegido. Todo lo demás puede rechazarse o recibir contenido inocuo.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Los múltiples niveles limitan la exposición: que se queme un dominio público no tiene por qué exponer el team server. Las CDN añaden capacidad anycast y un dominio externo de buena reputación, pero la cuenta de la CDN y los logs del edge se convierten en puntos de atribución. Las fingerprints TLS, el historial de certificados, las rutas distintivas/el orden de los headers, los tamaños de respuesta, el comportamiento de redirección y las allowlists de origen pueden agrupar frontends aparentemente no relacionados.

Para la detección, registra los campos del reverse proxy antes de normalizarlos, compara SNI/Host/authority, inspecciona combinaciones de headers poco comunes, agrupa los cuerpos de respuesta y las fingerprints TLS, y busca coincidencias de configuración en los logs de auditoría de cloud/CDN. En red teams autorizados, evita copiar una marca real o recopilar credenciales detrás de un tercero no relacionado.

## domain fronting y domainless fronting

Con **domain fronting (T1090.004)** clásico, la conexión TLS anuncia un dominio frontal permitido en SNI, mientras que el `Host` HTTP cifrado o `:authority` de HTTP/2 solicita un dominio de back-end distinto. Una CDN colaboradora enruta según el valor interno. Un observador de red sin descifrado TLS ve el dominio frontal; la CDN ve ambos valores y el origen. En las variantes domainless, SNI puede estar vacío mientras otro campo de enrutamiento selecciona el destino.<sup>[[4]](#references)</sup>

Esto no es una suplantación mágica: solo funciona cuando el intermediario permite la discrepancia intencionadamente o por accidente, y sabe cómo enrutar el nombre interno. Los principales proveedores han restringido el fronting entre cuentas. Encrypted ClientHello (ECH) cambia lo que puede ver un observador en la ruta, pero no elimina los registros de la CDN, el endpoint o la aplicación.

Los puntos de detección incluyen:

- la ascendencia del proceso en el endpoint y un destino no esperado para esa aplicación;
- discrepancias entre SNI y la authority HTTP cuando la inspección TLS es legal y está disponible;
- logs de la CDN que muestran un tenant/front que enruta a otra authority/origen;
- sesiones inusualmente largas o periódicas con un servicio normalmente interactivo;
- tamaños y cadencia estables de flujos cifrados pese a cambios en los dominios frontales.

El laboratorio seguro simula la discrepancia de enrutamiento en un reverse proxy propio; no abusa de una CDN pública.

## Resolución dinámica: DDNS, DGA y fast flux

La resolución dinámica desvincula un servicio lógico de una infraestructura fija:

- **DDNS:** un cliente autenticado actualiza un nombre estable cuando cambia su dirección.
- **DGA:** tanto el endpoint como el controlador derivan nombres de dominio candidatos a partir de una semilla de tiempo/clave; el operador registra un subconjunto pequeño.
- **Fast flux:** un nombre devuelve un conjunto de direcciones comprometidas/de proxy que cambia rápidamente, a menudo con TTL bajos.
- **Double flux:** rotan tanto las direcciones del servicio como las de los servidores de nombres autoritativos, ocultando también la capa de control.

Fast flux es un patrón de distribución de carga usado con fines adversarios, no simplemente «muchas respuestas DNS». Las pruebas más sólidas combinan TTL bajo, una gran cantidad de direcciones únicas, amplia dispersión de ASN/geográfica, corta vida de los nodos, comportamiento repetido de la aplicación e historial de registro sospechoso. Las CDN comparten legítimamente varias de esas propiedades. MITRE recomienda correlacionar el comportamiento DNS con el proceso y las conexiones posteriores.<sup>[[5]](#references)</sup>

Una DGA puede detectarse mediante entropía léxica, patrones de consonantes/dígitos, ráfagas de NXDOMAIN, dominios vistos por primera vez de forma sincronizada y contexto del proceso. Las DGA basadas en listas de palabras y los modelos generativos eluden las reglas simples de entropía, por lo que la agrupación temporal en toda la flota y la procedencia del endpoint cobran mayor importancia.

## Dominios comprometidos y domain shadowing

Un actor puede secuestrar una cuenta de registrador/DNS, tomar el control de un subdominio huérfano o añadir registros bajo un dominio que, por lo demás, tiene buena reputación. **Domain shadowing** mantiene el dominio apex legítimo mientras grandes cantidades de subdominios controlados por el atacante apuntan a hosts de entrega o C2 cambiantes. Aprovecha la antigüedad y la reputación, y puede evadir el bloqueo de todo el dominio.<sup>[[6]](#references)</sup>

Los defensores necesitan logs de auditoría del registrador y del DNS autoritativo, MFA, bloqueos de registro/registrador, alertas de nuevas delegaciones/tokens de API/servidores de nombres, supervisión de Certificate Transparency y un inventario de los recursos cloud referenciados por DNS. Investiga la resolución y el historial de certificados de un subdominio independientemente de la reputación del dominio apex.

## Servicios web y dead-drop resolvers

Un **dead-drop resolver (T1102.001)** almacena un puntero codificado al C2 actual dentro de una publicación, perfil, documento, repositorio, objeto cloud o campo de blockchain legítimo. El malware obtiene el objeto público, decodifica un dominio/IP y contacta con la siguiente etapa. Las variantes bidireccionales intercambian comandos o archivos a través de las API del servicio.<sup>[[7]](#references)</sup>

Una variante de resolver específica de GitHub utiliza la API de búsqueda de Issues solo cuando falla un canal autenticado del repositorio. El cliente busca issues que coincidan con la fecha actual, el repositorio y el tipo de issue, sigue la URL de comentarios de cada issue y extrae el texto cifrado entre los marcadores `<!--` y `-->`. Tras el descifrado por host y derivado de la fecha, campos como `Owner`, `LicRepo` y `LicToken` reemplazan al propietario, la ruta y el token del repositorio principal. Esto permite al operador rotar credenciales y endpoints sin reemplazar el cliente; el comentario del issue es un resolver, mientras que los archivos del repositorio siguen siendo el canal de tasking.<sup>[[15]](#references)</sup>

Una variante para Android selecciona una de dos páginas públicas de Telegram al iniciarse y extrae el texto cifrado entre dos apariciones de un marcador incrustado en el APK. Decodifica el valor con Base64URL y lo descifra con AES-128-CBC: los primeros 16 bytes de `SHA-256(marker)` son la clave y los 16 restantes son el IV. El texto plano es la URL base real del C2, no la URL de la página de Telegram. Al reproducir la resolución, conserva el contenido de la página y el marcador exacto; cambiar la página pública rota el endpoint sin tener que recompilar el APK.<sup>[[16]](#references)</sup>

Esto proporciona resiliencia y oculta el C2 de back-end del análisis estático del binario. También crea identificadores estables de objetos, tenants, repositorios, API y patrones de acceso. Los defensores deberían correlacionar:

1. el proceso que contactó con el servicio;
2. la ruta/API u objeto exactos y el hash de la respuesta;
3. la actividad de decodificación o procesamiento de cadenas;
4. la nueva conexión saliente poco después; y
5. el mismo comportamiento en otros puntos de la flota.

Rara vez es viable bloquear todo GitHub, el almacenamiento cloud o las redes sociales. Las políticas de egreso que tienen en cuenta el servicio y la correlación a nivel de proceso superan al bloqueo basado únicamente en dominios.

## Personas, cuentas y compartimentos de adquisición

El anonimato de la infraestructura falla cuando una persona, un correo de recuperación, un teléfono, un pago, un navegador o una IP de administrador conecta compartimentos. Las operaciones vinculadas a Estados han cultivado perfiles sociales, identidades de correo y cuentas cloud mucho antes de usarlas; ATT&CK lo registra como Establish Accounts (T1585), con sub-técnicas sociales, de correo y cloud.<sup>[[8]](#references)</sup>

Un defensor o investigador construye un grafo a partir de:

- la hora de creación y del primer inicio de sesión, la configuración regional, la zona horaria y el horario de actividad;
- los campos de recuperación, dispositivos MFA, documentos de identidad e instrumentos de pago;
- las fingerprints del navegador/TLS y el historial de redes de origen;
- la reutilización de avatares, la procedencia de imágenes, el estilo de escritura y el crecimiento del grafo social;
- un registrante de dominio, servidor de nombres, certificado, ID de analítica o commit de repositorio compartidos;
- acciones del plano de gestión que eluden la arquitectura pública de relay.

Para un red team autorizado, las personas sintéticas deben documentarse para el controlador del ejercicio, usar canales de recuperación/pago propiedad de la organización, evitar suplantar a personas reales ajenas y contar con un plan de retiro. El SOC puede seguir a ciegas; la operación no debe quedar sin rendición de cuentas.

## Patrones compuestos emergentes para modelar amenazas

Los siguientes son **composiciones impulsadas por la defensa**, no afirmaciones de que un actor nombrado haya desplegado cada diseño exacto. Combinan primitivas ya observadas y sirven como hipótesis para purple teams.

### Tasking asimétrico unidireccional

Los comandos llegan mediante una fuente pública, de difusión o de solo anexado, mientras que los resultados salen por un canal no relacionado y con retraso. Entre los ejemplos de esta primitiva están la comunicación unidireccional mediante servicios web y los dead drops. La separación impide que un solo flujo parezca bidireccional y dificulta la correlación simple de solicitud/respuesta.<sup>[[9]](#references)</sup>

**Detección:** conserva los accesos a nivel de objeto y correlaciona después los cambios de estado del proceso y las transferencias salientes en una ventana más amplia. Busca procesos poco comunes que lean el mismo objeto público aunque no haya una respuesta inmediata.

### Promoción de canales por etapas

Una primera etapa discreta realiza el inventario y solo promueve sistemas seleccionados a un canal de segunda etapa no relacionado. El segundo endpoint, protocolo y proceso pueden no compartir infraestructura con el primero. Esto limita la exposición de la infraestructura de alta capacidad y está modelado explícitamente como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detección:** correlaciona `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; no cierres el incidente después de bloquear el primer dominio.

### Traducción de relay entre protocolos

Los distintos saltos traducen HTTPS, QUIC, WebSocket, DNS, SSH o una API de cola de mensajes, en lugar de reenviar paquetes de forma transparente. La traducción elimina una única fingerprint de protocolo de extremo a extremo, pero crea gateways con patrones distintivos de tiempos, buffering y conversión semántica. Protocol tunneling (T1572) puede combinarse con proxies y suplantación de servicios.<sup>[[11]](#references)</sup>

**Detección:** busca hosts gateway que reciben un protocolo e inician otro con un comportamiento de bytes/tiempo estrechamente vinculado; compara la intención del endpoint con el protocolo que realmente transporta.

### Activación pasiva en dispositivos edge

En lugar de enviar beacons, un implante supervisa el tráfico que ya llega a un router/VPN y se activa solo con un valor mágico, un patrón de puertos de origen o un token autenticado. El tráfico normal sigue llegando al servicio real. ATT&CK lo denomina Traffic Signaling (T1205), con ejemplos documentados de dispositivos de red y APT.<sup>[[12]](#references)</sup>

**Detección:** integridad del firmware/archivos, captura de paquetes sin procesar durante una investigación autorizada, filtros de socket inesperados y comportamiento diferencial del servicio. La ausencia de un beacon periódico no demuestra que un dispositivo edge esté limpio.

### Rotación de orígenes serverless y efímeros

Un frontend mantiene una identidad lógica estable mientras funciones/contenedores de corta duración gestionan etapas individuales en varias regiones/cuentas. Esto reduce el tiempo de permanencia en disco y las IP de origen fijas, pero la creación en el plano de control, la imagen/capa, el rol, el secreto, el ID de solicitud y la telemetría de facturación se convierten en el grafo persistente.

**Detección:** conserva los logs de auditoría e invocación cloud fuera de la carga de trabajo; agrupa las plantillas de despliegue, los roles, las claves de entorno y las relaciones entre frontend y origen.

### Diversidad de capas de privacidad

Una operación puede evitar deliberadamente una cadena homogénea: por ejemplo, un canal usa un relay alquilado, el tasking utiliza un objeto público, una salida procede de un enlace celular de laboratorio propio y la administración usa una red de la organización separada. Esto reduce el valor de comprometer a un solo proveedor, pero aumenta el riesgo de correlación temporal entre capas y de errores operativos.

**Detección:** crea cronologías de campaña en los sensores de identidad, DNS, SaaS, red y cloud. Busca transiciones de estado sincronizadas en lugar de indicadores idénticos.

### Dead drops descentralizados o basados en logs de transparencia

Un actor puede colocar un pequeño puntero cifrado en cualquier sistema público duradero de solo anexado, almacenamiento direccionable por contenido o feed similar a los de transparencia. El objeto público es resiliente, pero su índice/hash de contenido exacto y el comportamiento de polling del cliente se convierten en identificadores estables.

**Detección:** registra los identificadores completos de API/objeto y los hashes de respuesta; alerta cuando procesos no estándar consulten objetos inmutables y luego los decodifiquen o establezcan nuevas conexiones.

### Operaciones retrasadas de almacenamiento y reenvío

El C2 interactivo crea una fuerte correlación temporal. Un diseño de almacenamiento y reenvío agrupa tareas cifradas y devuelve resultados minutos u horas después mediante una cola distinta o una transferencia física. Sacrifica capacidad de respuesta para reducir la correlación temporal de extremo a extremo.

**Detección:** amplía las ventanas de correlación, modela el acceso periódico a colas y examina el staging en los endpoints. El batching desplaza la señal del tiempo de los paquetes al comportamiento programado de procesos/archivos; no la elimina.

## Revisión del diseño: piensa en los observadores

Para cada ruta, completa esta tabla antes del despliegue y después de la recopilación:

| Capa | ¿Ve el origen? | ¿Ve el destino? | ¿Ve el contenido? | Identificadores estables | Responsable de retención/legal |
|---|---:|---:|---:|---|---|
| red local/operador | | | | | |
| servicio de entrada/acceso | | | | | |
| operador(es) de tránsito | | | | | |
| salida/redirector/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| objetivo | | | | | |
| proveedor de cuentas/pagos | | | | | |

Si un proveedor común puede completar todas las columnas, la arquitectura oculta la actividad del objetivo, pero no proporciona una separación sólida. Si ningún controlador interno puede vincular la actividad con un ejercicio, no es adecuada para un red team profesional.

## References

- [1] [MITRE ATT&CK — Adquisición de infraestructura (T1583), compromiso de infraestructura (T1584) y proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multinivel (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromiso de infraestructura: dominios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Servicio web: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Crear cuentas (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Servicio web: comunicación unidireccional (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canales de varias etapas (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Túnel de protocolos (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Señalización de tráfico (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Desarticulación de la mayor red de proxy residencial del mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Las campañas Shadow: revelación de una campaña global de espionaje](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campaña Blinder Tunnel apunta a infraestructura iraquí](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: la IA creó las superposiciones. Las víctimas pierden sus PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
