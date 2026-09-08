# Catálogo de técnicas de acceso anónimo a Internet

{{#include ../banners/hacktricks-training.md}}

Este es el inventario canónico de rutas de acceso. Cubre **familias** de protocolos y operaciones, no todos los nombres de proveedores. Ninguna ruta de Internet garantiza el anonimato: las evidencias de cuentas, navegador, endpoint, tiempos, pagos, cloud-control-plane y presencia física pueden derrotar una ruta que parezca perfecta.

Todas las entradas usan los mismos campos. “Procedimiento” significa un despliegue legal o una emulación en un laboratorio propio. Cuando la técnica real depende de comprometer un router, robar acceso o abusar de un intermediario que no ha dado su consentimiento, la reproducción sustituye esos sistemas por sistemas propiedad del ejercicio.

## Matriz de cobertura

| Familia | Lo que ve el destino | Propiedad más fuerte | Velocidad | Tratamiento |
|---|---|---|---|---|
| Shared NAT/CGNAT | dirección pública compartida | ambigüedad entre suscriptores | alta | desplegable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | dirección del relay | separación rápida de la dirección de origen | alta | desplegable |
| Multi-hop/split relay, MASQUE | proxy final | separación del conocimiento o túnel IP completo | alta/moderada | desplegable con relays de confianza |
| Tor, bridge, onion service | exit o identidad onion | ruta multipartita y navegador común | moderada | desplegable |
| I2P, GNUnet, mixnet | peer/gateway del overlay | resistencia del overlay o frente a análisis temporal | baja/variable | específica de la aplicación |
| OHTTP/ODoH, Private Relay | gateway/egress | partición de origen y solicitud | alta | solo aplicaciones compatibles |
| Public Wi-Fi, travel router | dirección del local/túnel | cambio de ubicación/ruta de acceso | alta | requiere permiso |
| Cellular/eSIM, satellite | dirección del carrier/proveedor | uplink físico independiente | alta/variable | el proveedor observa |
| Remote browser/jump host | workspace remoto | separación de endpoint y egress | alta | desplegable |
| Residential/mobile proxy | dirección de red de consumidor/carrier | apariencia de red de consumidor | alta | consentimiento/procedencia críticos |
| ORB/compromised relay | dirección de otra víctima | ocultación del origen y reputación prestada | alta | solo reproducción en laboratorio propio |
| CDN/fronting/redirector | dirección frontal del CDN | protección de infraestructura back-end | alta | requiere aprobación del proveedor/propietario |
| Fast flux/DGA/dead drop | nodo/servicio rotatorio | resistencia al descubrimiento de infraestructura | variable | solo reproducción en laboratorio propio |
| Drop/nearest-neighbor | dirección cercana al objetivo | cruce de límite geográfico/de red | alta | solo laboratorio en sitio propio |
| Store-and-forward/offline | gateway o receptor físico | reducción de la relación temporal interactiva | baja | específica de la aplicación |
| Pluggable/refraction transport | entrada de Tor o proxy cooperante de desvío | alcanzabilidad resistente a la censura | variable | cliente compatible o laboratorio de investigación |
| IPFS gateway/PIR/remote fetcher | gateway o servicio de aplicación | partición de publicador/consulta/solicitud | variable | solo aplicación limitada |
| Anycast/QUIC/MPTCP | broker estable o varios subflujos | rendezvous y continuidad de sesión | alta | disponibilidad, no anonimato |
| CI/CD automation runner | dirección del runner alojado | egress desechable y atribuible | alta | solo workflow propio |
| Non-IP local first hop | gateway de la organización | eliminación de la pila de Internet del sensor | baja | despliegue aprobado por el propietario |

## NAT compartido directo y NAT de carrier-grade

**Mecánica:** varios usuarios comparten una dirección pública; el proveedor de acceso asigna direcciones y puertos del suscriptor a la tupla pública.

**Ventajas:** rápido; no requiere cliente especial; la IP del destino puede identificar únicamente un hogar, local o grupo del carrier.

**Desventajas:** el proveedor puede conservar las correspondencias suscriptor/puerto/hora; las cuentas y fingerprints permanecen; otros usuarios pueden dañar la reputación de la dirección.

**Procedimiento:** (1) confirmar si el acceso autorizado usa NAT/CGNAT; (2) registrar la IP pública exacta y el puerto de origen en un endpoint propio; (3) mantener separadas las identidades de aplicación; (4) no tratar el direccionamiento compartido como control de privacidad; (5) usar una ruta más fuerte si el ISP no debe conocer los destinos.

**Detección:** los destinos deben conservar el puerto de origen y la hora precisa, no solo la IP. Los proveedores correlacionan los logs de asignación NAT; los investigadores unen evidencias de cuenta, dispositivo y navegador.

## VPN comercial

**Mecánica:** una conexión cifrada de túnel completo termina en la VPN; los destinos ven su egress. Normalmente, la VPN puede asociar origen, tiempos y destinos.

**Ventajas:** rápida y sencilla; protege contra observación pasiva local; exits estables o compartidos; adecuada para egress controlado de red-team.

**Desventajas:** confianza concentrada; telemetría de facturación/login; fallos de kill-switch/DNS/IPv6; los exits compartidos suelen estar bloqueados por reputación.

**Procedimiento:** (1) identificar proveedor, propietario, jurisdicción, retención y política de evaluación; (2) instalar el cliente oficial firmado; (3) activar túnel completo, always-on y comportamiento fail-closed; (4) enrutar DNS e IPv6 deliberadamente; (5) verificar IPv4/IPv6/DNS observados en un endpoint propio; (6) detener/reconectar el túnel y confirmar que no existe fallback en claro.<sup>[[1]](#references)</sup>

**Detección:** las redes locales ven un flujo cifrado prolongado hacia infraestructura VPN; los proveedores tienen registros de autenticación/conexión; los destinos usan ASN/reputación junto con correlación de cuenta, TLS/browser y comportamiento.

## Egress de VPN autoalojada o VPS alquilado

**Mecánica:** el operador controla un gateway WireGuard/OpenVPN o reenvía el tráfico mediante un servidor alquilado.

**Ventajas:** velocidad alta predecible; dirección fija que puede incluirse en allowlists; logging/firewall personalizado; buen control de incidentes.

**Desventajas:** conjunto de anonimato reducido; el tenant cloud, pago, login de origen, API e historial de imágenes vinculan al operador; un servidor nuevo y distintivo es fácil de agrupar.

**Procedimiento:** (1) crear un proyecto de organización específico del engagement; (2) aprovisionar una imagen compatible y una dirección fija; (3) restringir la administración a MFA/llaves; (4) configurar egress de túnel completo y DNS; (5) permitir solo destinos definidos cuando sea práctico; (6) probar el comportamiento ante leaks/fallos; (7) conservar los audit records del controller; (8) destruir credenciales y recursos durante el teardown.

**Detección:** correlacionar ASN de hosting, dirección vista por primera vez, fingerprint de certificado/servicio y comportamiento de scanning; los propietarios cloud usan logs del control-plane, consola, billing y flujo.

## HTTP CONNECT, SOCKS y forwarding SSH

**Mecánica:** una aplicación solicita a un proxy que abra un stream TCP; SOCKS también puede transportar resolución de nombres y UDP según la versión; SSH reenvía streams dentro de una sesión cifrada.

**Ventajas:** ligero; por aplicación; rápido; útil para chaining y para alcanzar redes segmentadas.

**Desventajas:** las aplicaciones pueden evitarlo; el DNS puede filtrarse; el proxy ve los endpoints adyacentes; el estado del navegador permanece; los open proxies pueden ser trampas o sistemas comprometidos.

**Procedimiento:** (1) desplegar el proxy en un host propio; (2) exigir autenticación y restringir origen/destino; (3) configurar un perfil de aplicación desechable; (4) asegurar la resolución DNS remota cuando sea necesaria; (5) verificar con un endpoint DNS/HTTP propio; (6) bloquear el egress directo del workload; (7) inspeccionar y rotar las credenciales del proxy.

**Detección:** identificar procesos capaces de crear túneles, negociación CONNECT/SOCKS, sesiones SSH prolongadas y destinos incompatibles con la aplicación; los logs del proxy reconstruyen los streams.

## Web proxy con reescritura de URL y browser proxy extension

**Mecánica:** un sitio obtiene un destino y reescribe enlaces/forms a través de su propio origen, o una extension dirige las solicitudes del navegador a un proxy. El destino ve el servicio, mientras que el servicio puede ver plaintext tras terminar TLS e inyectar o conservar contenido.

**Ventajas:** no requiere cliente para todo el sistema; rápido para browsing sencillo; funciona donde no es posible instalar una VPN.

**Desventajas:** el proxy puede leer credenciales/contenido, reescribir descargas y fingerprintear usuarios; scripts/WebSockets/downloads pueden evitarlo; una browser extension tiene privilegios amplios; conjunto de anonimato pequeño y bloqueos frecuentes.

**Procedimiento:** (1) usar únicamente un proxy operado por la organización para pruebas autorizadas; (2) aislarlo en un navegador desechable sin cuentas personales; (3) prohibir la introducción de contraseñas y descargas sensibles; (4) verificar que cada subrecurso de una página propia se resuelve mediante el proxy; (5) probar WebSocket, downloads y forms; (6) eliminar extension/profile después de usarlo.

**Detección:** el destino registra el proxy; el proxy/DNS empresarial y el inventario de extensions identifican el servicio; subrecursos canary propios o de content-security/reporting revelan bypass directo; los logs del proxy vinculan la sesión de usuario con los objetivos.

## Multi-hop proxy o VPN multi-hop del proveedor

**Mecánica:** una entrada ve el origen, mientras uno o más relays de tránsito la separan de un exit que ve el destino.

**Ventajas:** ningún relay ordinario necesita conocer ambos extremos; el fallo/incautación de un nodo revela menos; geografía flexible.

**Desventajas:** la administración o logging compartidos derrotan la separación; latencia; correlación temporal; más fallos y rutas DNS; la misma cuenta/pago puede unir todos los hops.

**Procedimiento:** (1) definir qué observador elimina cada hop; (2) usar relays propios/aprobados y administrados independientemente cuando importe la separación; (3) imponer acceso solo de entrada desde el workload; (4) asegurar que cada relay solo pueda alcanzar el siguiente hop; (5) verificar los logs en cada capa; (6) detener cada hop y confirmar comportamiento fail-closed. Reproducir con [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detección:** correlacionar tiempos/volumen de NetFlow adyacentes, handshakes de proxy repetidos e infraestructura común de controller; no inferir la geografía del operador a partir del exit.

## Application relay de conocimiento dividido y OHTTP

**Mecánica:** el cliente cifra un mensaje HTTP stateless para un gateway y lo envía mediante un relay. El relay ve la IP del cliente pero no la solicitud; el gateway ve la solicitud, pero normalmente solo la IP del relay.

**Ventajas:** partición de privacidad fuerte y auditable para solicitudes compatibles; menor overhead que las redes de anonimato generales.

**Desventajas:** no permite browsing arbitrario; cookies/authentication pueden volver a vincular; permanecen la colusión relay/gateway y el análisis de tráfico; la aplicación debe implementarlo.

**Procedimiento:** (1) seleccionar una aplicación que admita explícitamente RFC 9458; (2) verificar las keys del gateway mediante la ruta de configuración oficial; (3) evitar campos estables por usuario; (4) enviar solo la solicitud stateless compatible; (5) comparar logs de relay, gateway y target; (6) probar rotación/fallo de keys sin fallback directo.<sup>[[2]](#references)</sup>

**Detección:** los endpoints empresariales exponen el proceso iniciador y el OHTTP relay; los gateways detectan tráfico malformado/repetido; los tiempos y campos estables de payload/account pueden correlacionar solicitudes.

## MASQUE CONNECT-UDP/CONNECT-IP y HTTP privacy proxies

**Mecánica:** HTTP Extended CONNECT sobre TLS/QUIC transporta paquetes UDP o IP mediante un proxy. Puede implementar un túnel moderno similar a una VPN y mezclar el transporte con HTTP/3, pero el proxy continúa siendo un observador.<sup>[[3]](#references)</sup>

**Ventajas:** multiplexación/roaming eficientes; admite UDP o IP completo; se despliega mediante infraestructura HTTP moderna.

**Desventajas:** no es una red de anonimato; el proxy/cuenta ve origen y destinos; los fingerprints QUIC/HTTP y las rutas conocidas son visibles para endpoints/proveedores.

**Procedimiento:** (1) usar un cliente/servicio que documente compatibilidad con RFC 9298/9484; (2) autenticar el certificado/configuración del proxy; (3) definir las rutas de destino permitidas; (4) activar DNS cifrado dentro de la ruta; (5) verificar UDP, TCP, IPv6 y failover frente a endpoints propios; (6) inspeccionar los logs de solicitudes y flujos del proxy.

**Detección:** los endpoints ven el proceso cliente y la interfaz virtual; las redes pueden clasificar QUIC/TLS sostenido hacia un proxy; los logs del proxy exponen target/path de CONNECT y rutas asignadas.

## Tor Browser

**Mecánica:** Tor selecciona relays guard, middle y exit; el cifrado por capas limita la visión de cada relay. Tor Browser añade un navegador estandarizado destinado a resistir fingerprinting.

**Ventajas:** gran conjunto público de anonimato; ningún relay ordinario conoce ambos extremos; unlinkability del destino sin operar servidores.

**Desventajas:** más lento; centrado en TCP; reputación/bloqueos de exits; los logins y divulgaciones identifican al usuario; permanece la correlación temporal de baja latencia.

**Procedimiento:** (1) descargar y verificar Tor Browser desde el proyecto; (2) mantener los valores predeterminados y evitar extensions; (3) elegir un nivel de seguridad apropiado; (4) crear una identidad/sesión separada; (5) evitar cuentas identificables y documentos activos externos; (6) usar HTTPS u onion services autenticados; (7) verificar el exit únicamente con un endpoint propio.<sup>[[4]](#references)</sup>

**Detección:** las redes locales pueden identificar tráfico hacia guards conocidos si no se usa bridge/transport; los destinos ven exits y el comportamiento de Tor Browser; los observadores extremo a extremo correlacionan tiempos/volumen.

## Tor bridges y pluggable transports

**Mecánica:** un bridge no público sustituye al guard público; obfs4, Snowflake o WebTunnel modifican el transporte del primer hop para resistir bloqueos/probing simples.

**Ventajas:** evita la censura y oculta destinos de relays públicos evidentes; conserva el circuito Tor tras la entrada.

**Desventajas:** siguen siendo posibles los patrones de transporte y el descubrimiento del bridge; rendimiento variable; no añade protección contra cuentas ni against global timing.

**Procedimiento:** (1) probar primero Tor directo; (2) en los ajustes Connection de Tor Browser seleccionar un transport compatible integrado o solicitar un bridge oficial; (3) no usar binaries/lists aleatorios; (4) conectar y ejecutar una prueba benigna; (5) probar la reconexión y el reloj; (6) mantener estándar el resto de la configuración del navegador.<sup>[[5]](#references)</sup>

**Detección:** los censores usan descubrimiento de destinos, clasificación de protocolo/flujo y probing activo; los defensores deben distinguir el uso de circumvention del compromiso y apoyarse en el proceso/contexto del endpoint.

## VPN antes de Tor y Tor antes de VPN

**Mecánica:** VPN-before-Tor oculta el uso directo de Tor al ISP de acceso, pero expone el origen a la VPN. Tor-before-VPN entrega a la VPN el tráfico posterior a Tor y a menudo una identidad estable de cliente/túnel.

**Ventajas:** elimina un observador concreto cuando se diseña correctamente; puede alcanzar redes que bloquean una capa.

**Desventajas:** complejidad, fingerprint poco común, leaks, conjunto de anonimato reducido y falsa confianza; Tor Project considera estas combinaciones avanzadas.<sup>[[6]](#references)</sup>

**Procedimiento:** (1) escribir qué observador se elimina y cuál nuevo se introduce; (2) usar un entorno desechable; (3) establecer únicamente la ruta exterior prevista; (4) imponer las rutas del firewall; (5) verificar DNS/IPv4/IPv6 y cada orden de fallo; (6) comparar la visibilidad de ambos proveedores; (7) abandonar la pila si no ofrece una ventaja medible.

**Detección:** los observadores local/VPN/Tor ven capas adyacentes distintas; el timing permanece extremo a extremo; fingerprints inusuales de túneles anidados y cuentas de proveedores pueden vincular sesiones.

## Onion service

**Mecánica:** el cliente y el servicio construyen circuitos Tor hasta un rendezvous, ocultando la IP del servicio y evitando un exit.

**Ventajas:** protección de la ubicación del origen y del servicio; autenticación onion extremo a extremo; ningún puerto inbound público; autorización opcional del cliente.

**Desventajas:** el origen puede filtrarse mediante updates/analytics/errors; la onion key es crítica; permanecen la identidad/tiempos de la aplicación y el compromiso del host.

**Procedimiento:** (1) aislar la aplicación y enlazarla solo a loopback/socket; (2) instalar Tor compatible; (3) configurar un servicio onion v3 siguiendo las instrucciones oficiales; (4) proteger/hacer backup de su key solo si se necesita una identidad estable; (5) añadir autorización de cliente para uso cerrado; (6) eliminar fetches de terceros; (7) verificar externamente que el origen no sea accesible.<sup>[[7]](#references)</sup>

**Detección:** los defensores del host/red encuentran el proceso/configuración de Tor y los circuitos outbound; errores de aplicación, DNS, certificados o recursos de terceros pueden exponer el origen.

## Servicios internos I2P

**Mecánica:** I2P usa túneles inbound/outbound unidireccionales separados para destinos dentro del overlay; los outproxies hacia Internet público añaden un punto de confianza.

**Ventajas:** publicación interna descentralizada; no depende de un exit oficial; rutas inbound/outbound separadas.

**Desventajas:** no sustituye a la web general; ecosistema menor; comportamiento de peers de larga duración; el outproxy puede observar el browsing público.

**Procedimiento:** (1) instalar desde la fuente oficial; (2) usar un contexto dedicado; (3) permitir la estabilización de integración/ancho de banda; (4) acceder a un servicio propio nativo de I2P; (5) evitar outproxies salvo que sean necesarios; (6) verificar que el apagado no produzca fallback directo; (7) inspeccionar logs locales de peers y servicios.<sup>[[8]](#references)</sup>

**Detección:** las redes locales ven tráfico de peers de larga duración y bootstrap; los endpoints exponen procesos de router/aplicación; los outproxies registran los exits.

## Mixnets

**Mecánica:** paquetes de tamaño fijo, batching, retraso, reordenación y cover traffic reducen la correlación temporal; los gateways conectan las aplicaciones.

**Ventajas:** mejor resistencia al análisis temporal que los proxies de baja latencia; útiles para mensajes/transacciones asíncronos.

**Desventajas:** latencia, overhead de ancho de banda, menor despliegue y límites de aplicación; los metadatos del gateway/cuenta pueden persistir.

**Procedimiento:** (1) seleccionar un cliente mantenido y una aplicación compatible; (2) leer el threat model real; (3) instalarlo en un compartimento separado; (4) enviar datos benignos a un endpoint propio; (5) medir latencia/fiabilidad y la ruta de respuesta; (6) probar el fallo del gateway; (7) no desactivar delays/cover traffic solo por velocidad.<sup>[[9]](#references)</sup>

**Detección:** los endpoints identifican el cliente; las redes de acceso pueden clasificar gateways/cadencia de paquetes; los gateways y exits observan roles adyacentes, mientras que una correlación más amplia requiere ventanas estadísticas mayores.

## GNUnet anonymous file sharing

**Mecánica:** GNUnet puede enrutar solicitudes de publish/search/download mediante peers y añadir cover traffic según un anonymity level. Su documentación advierte que el nivel predeterminado 1 no exige cover traffic y que un análisis de tráfico potente puede identificar el origen.<sup>[[10]](#references)</sup>

**Ventajas:** compartición descentralizada y anónima nativa de la aplicación; requisito de cover traffic ajustable.

**Desventajas:** no es acceso web anónimo ordinario; coste de rendimiento/almacenamiento; limitaciones de peers y análisis de tráfico; la documentación de GNUnet VPN indica que su overlay IP no proporciona buen anonimato.

**Procedimiento:** (1) instalar una build oficial mantenida; (2) aislar un peer de prueba; (3) limitar ancho de banda/almacenamiento; (4) publicar un archivo de prueba único e inofensivo con un anonymity level elegido; (5) recuperarlo desde otro peer propio; (6) registrar cover traffic y latencia; (7) no afirmar que el componente IP VPN ofrece anonimato equivalente.

**Detección:** bootstrap de peers, tráfico del overlay, datastore/proceso local e identificadores de archivos; un observador amplio puede analizar el volumen frente al cover traffic.

## DNS cifrado, ODoH y ECH

**Mecánica:** DoH/DoT/DoQ cifra hacia un resolver; ODoH separa la dirección del cliente y la consulta entre proxy y resolver; ECH cifra el ClientHello/nombre del servidor TLS interno.

**Ventajas:** elimina DNS/SNI en claro de algunos observadores locales; ODoH divide el conocimiento de origen/consulta.

**Desventajas:** no es una ruta de anonimato IP; resolver/proxy/servidor conservan roles; permanecen IP, timing, volumen y endpoint del destino; el fallback puede filtrar.

**Procedimiento:** (1) decidir si el DNS pertenece al OS, aplicación o túnel; (2) activar modo estricto cifrado u ODoH compatible; (3) probar un dominio propio único; (4) capturar localmente para confirmar que no hay consultas en claro; (5) hacer fallar el resolver y verificar el comportamiento previsto; (6) para ECH, confirmar mediante diagnósticos del servidor que se acepta el ClientHello interno.<sup>[[11]](#references)</sup>

**Detección:** los logs del endpoint/resolver exponen consultas; las redes identifican endpoints de resolvers cifrados y flujos de destino; el estado ECH es visible en endpoints/CDN aunque esté oculto en la ruta.

## Privacy relay de proveedores divididos

**Mecánica:** productos como iCloud Private Relay usan un ingress que conoce al cliente y un egress operado independientemente que conoce el destino, con tratamiento regional aproximado.

**Ventajas:** separación de conocimiento con poca fricción; rapidez; protección integrada de DNS/web para tráfico compatible.

**Desventajas:** alcance limitado por producto/aplicación; el proveedor de la cuenta/plataforma sigue identificando al cliente; no proporciona anonimato arbitrario del sistema; persisten riesgos de colusión/legalidad y timing.

**Procedimiento:** (1) confirmar las aplicaciones y tipos de tráfico compatibles; (2) activar la función en un contexto de plataforma dedicado cuando corresponda; (3) seleccionar el comportamiento regional; (4) probar Safari/DNS y las aplicaciones no compatibles por separado; (5) inspeccionar la dirección del destino; (6) probar cambios/fallos de red.<sup>[[12]](#references)</sup>

**Detección:** el acceso ve el ingress; el destino ve el egress; los logs de plataforma/relay y los registros de cuenta cubren sus respectivas capas; las aplicaciones no compatibles exponen rutas normales.

## Remote browser, VDI, RDP o organization jump host

**Mecánica:** el browsing/ejecución de herramientas ocurre en un sistema remoto; el destino ve su egress, mientras el proveedor del workspace ve la conexión del operador y el control-plane.

**Ventajas:** rápido; aísla contenido peligroso; egress estable y controlado; estado desechable y auditoría organizativa fuerte.

**Desventajas:** el proveedor/admin puede observar sesión/cuenta; los canales de pantalla/clipboard/files filtran; el fingerprint del navegador remoto puede ser único; no es anónimo frente al propietario del workspace.

**Procedimiento:** (1) crear un workspace propiedad de la organización por engagement; (2) exigir MFA y restringir administración; (3) desactivar o limitar clipboard/upload/download; (4) enrutar mediante egress fijo aprobado; (5) no usar IdP/sync personal; (6) exportar solo evidencias revisadas; (7) destruir workspace y credenciales según calendario.

**Detección:** los logs del proveedor e IdP vinculan usuario y sesión; los destinos agrupan egress/browser del workspace; los defensores empresariales identifican protocolos de control remoto y sesiones cloud anómalas.

## Public o guest Wi-Fi

**Mecánica:** el tráfico sale por el NAT del local o por un túnel iniciado allí.

**Ventajas:** alta velocidad y dirección compartida no doméstica; no requiere infraestructura dedicada.

**Desventajas:** evidencias de asociación con el local, DHCP/portal, cámaras, compra y ubicación; peers/APs hostiles; términos de uso; riesgo físico.

**Procedimiento:** (1) obtener el acceso ofrecido a invitados y verificar el SSID con el personal; (2) usar un dispositivo parcheado de baja confianza; (3) desactivar sharing/auto-join y activar private MAC; (4) completar el portal sin reutilizar identidad; (5) iniciar una ruta VPN/Tor fail-closed; (6) verificar el tráfico tethered; (7) olvidar la red.

**Detección:** el local correlaciona AP, MAC, DHCP, portal y hora; el destino ve el local/túnel; los investigadores combinan evidencias físicas y del dispositivo. Nunca evadir controles de acceso.

## Travel router

**Mecánica:** un router propiedad del operador se une a Wi-Fi/Ethernet del local y proporciona una red interna aislada con política de túnel impuesta.

**Ventajas:** aísla workstations; kill switch/DNS central; red cliente consistente; protege endpoints privilegiados de broadcasts locales.

**Desventajas:** el router se convierte en un fingerprint estable de radio/DHCP; añade superficie de ataque; captive portals y tethering pueden evitar el túnel.

**Procedimiento:** (1) actualizar firmware compatible; (2) establecer credenciales de administración únicas y desactivar WAN admin/WPS/UPnP; (3) configurar private MAC del upstream cuando esté permitido; (4) crear un SSID interno separado; (5) imponer política firewall de DNS/IPv6 con túnel completo; (6) probar portal, reconexión y fallo del túnel.

**Detección:** el local ve la asociación del router y la forma del tráfico; el fingerprinting RF/DHCP local lo identifica; el proveedor VPN ve el origen del local.

## Cellular, prepaid SIM y eSIM

**Mecánica:** un modem usa acceso radio del carrier y normalmente carrier NAT; una capa VPN/Tor puede cambiar el exit visible para el destino.

**Ventajas:** independencia de la red cableada/Wi-Fi local; movilidad; alta velocidad; backhaul útil para drops autorizados.

**Desventajas:** el carrier conoce suscriptor/eSIM, IMSI, IMEI, celdas, hora y puertos asignados; las leyes de registro varían; la coincidencia física con el teléfono personal vincula dispositivos.

**Procedimiento:** (1) obtener el servicio legalmente con los datos exigidos; (2) usar un modem/dispositivo separado propiedad de la organización; (3) registrarlo con el controller del ejercicio; (4) desactivar radios/cuentas no relacionadas; (5) establecer el túnel aprobado; (6) probar si los clientes tethered realmente lo siguen; (7) verificar las suposiciones del proveedor y de retención antes de viajar.<sup>[[13]](#references)</sup>

**Detección:** registros del carrier y ubicación RF; inventario empresarial USB/PCI/MDM y búsquedas de hotspots no autorizados; timing de destino/túnel.

## Satellite Internet y abuso de satellite downlink

**Mecánica:** el servicio normal usa un terminal/proveedor registrado. El abuso histórico de DVB-S unidireccional permitía a un receptor dentro de un beam observar tráfico downlink no cifrado dirigido a un suscriptor legítimo, mientras usaba otra ruta para solicitudes outbound.

**Ventajas:** amplia cobertura; last mile independiente; el abuso unidireccional histórico podía atribuir erróneamente C2 a la geografía de un suscriptor.

**Desventajas:** registros de equipo/RF/proveedor; latencia y cobertura; los sistemas bidireccionales modernos son diferentes; la ruta outbound y el routing asimétrico siguen siendo evidencias.

**Procedimiento:** para acceso legal, registrar un terminal propio y tunelizar el tráfico según sea necesario. Para emular el comportamiento histórico de Turla, reproducir packet captures sintéticos unidireccionales dentro de un laboratorio sin RF y probar si los analistas detectan una respuesta a un host que no hizo ninguna solicitud; no interceptar tráfico satelital real.<sup>[[14]](#references)</sup>

**Detección:** telemetría del proveedor/terminal, direction finding RF, flujo imposible/asimétrico, inconsistencias de RTT/routing y configuración del malware.

## Residential/mobile proxy o proxyware con consentimiento

**Mecánica:** un gateway backconnect asigna exits de banda ancha móvil/doméstica, fijos o rotatorios. El suministro puede ser consentido, estar incluido de forma engañosa o ser malicioso.

**Ventajas:** rapidez; elección geográfica; ASN de consumidor evita algunos bloqueos de hosting; pools grandes.

**Desventajas:** riesgo de procedencia/consentimiento/legalidad; el broker ve al cliente; los exits infectados dañan a víctimas; la rotación crea anomalías; caro y poco fiable.

**Procedimiento:** usar únicamente agentes propios con consentimiento informado y documentado para emulación: (1) inscribir endpoints de prueba; (2) inventariar propietarios/IPs; (3) configurar un gateway; (4) rotar modos sticky/per-request; (5) enviar solo a un objetivo propio; (6) comparar logs de gateway/exit/target; (7) eliminar todos los agentes.

**Detección:** impossible travel, navegador/cuenta estable con cambios rápidos de IP/ASN, protocolos backconnect, artefactos de proceso/red de proxyware y relaciones broker/controller.

## ORB, botnet y relays de edge devices comprometidos

**Mecánica:** routers/IoT/servidores alquilados o comprometidos forman roles de acceso, tránsito y exit administrados como una flota. Varios clientes APT pueden compartirla.

**Ventajas:** reputación/geografía prestadas; exits de corta duración; mesh multi-hop resiliente; vínculo directo débil entre actor e IP.

**Desventajas:** victimización criminal; patrones del implant/controller y la flota; incautación del intermediario; rendimiento irregular; registros de operador/cliente.

**Procedimiento:** nunca comprometer dispositivos reales. Usar [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) crear redes aisladas de entrada/tránsito/objetivo; (2) conectar relay containers propios dual-homed; (3) reenviar un único puerto de prueba; (4) enviar una solicitud benigna; (5) verificar que el objetivo solo ve el exit; (6) rotar el exit; (7) eliminar todos los activos identificados.<sup>[[15]](#references)</sup>

**Detección:** rastrear topología, puertos/servicios, relaciones con controllers, fingerprints de implants y ciclo de vida de nodos; centralizar telemetría de configuración/flujo/integridad de edge; no equiparar exit IP con actor.

## CDN redirector, domain fronting y domainless fronting

**Mecánica:** un edge público reenvía únicamente el tráfico que coincide con una gramática; fronting coloca un SNI exterior benigno y una autoridad HTTP interna diferente, o SNI vacío, cuando el intermediario lo permite.

**Ventajas:** oculta/protege el back-end; edge global rápido; mezcla el destino con un servicio compartido; cambio rápido.

**Desventajas:** el CDN ve todo el routing y tenant; muchos proveedores prohíben fronting entre tenants; artefactos de SNI/Host/proceso/flujo/cuenta; la reutilización de configuración agrupa campañas.

**Procedimiento:** reproducir únicamente en un reverse proxy propio con [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): crear un certificado/edge local, dirigir un Host no coincidente a un objetivo propio, registrar SNI y Host, enviar solicitudes normales/no coincidentes y eliminar los containers.<sup>[[16]](#references)</sup>

**Detección:** comparar SNI/ECH/Host/`:authority` en el endpoint o edge terminador; unir proceso iniciador, tenant/origen, gramática de solicitudes y cadencia del flujo.

## Dynamic DNS, DGA, fast flux y double flux

**Mecánica:** DDNS actualiza un nombre estable; DGA deriva nombres candidatos cambiantes; fast flux rota direcciones de servicio con TTL bajo; double flux también rota name servers.

**Ventajas:** descubrimiento resiliente; sustitución rápida de infraestructura; oculta el controller tras muchos nodos.

**Desventajas:** DNS crea telemetría centralizada; entropía/NXDOMAIN/churn; TTL bajo y patrones amplios de ASN; permanecen el registro y la infraestructura authoritative.

**Procedimiento:** usar [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): servir una zona propia que devuelva direcciones RFC 5737 con TTL de cinco segundos, consultarla repetidamente, cambiar la época sintética y validar analytics. Nunca dirigir registros de prueba a terceros.<sup>[[17]](#references)</sup>

**Detección:** respuestas/ASNs únicos en ventanas móviles, TTL mediano, geografía, churn authoritative, clusters DGA de NXDOMAIN/léxico/tiempo y acciones posteriores del proceso; excluir CDNs legítimos con contexto.

## Servicio web legítimo, dead-drop resolver y one-way tasking

**Mecánica:** un post público, repository, document, object o feed contiene un endpoint o task actual codificado. El cliente puede devolver resultados por otro canal.

**Ventajas:** servicio permitido de alta reputación; TLS; rotación del endpoint sin cambiar el binary; tasking asimétrico dificulta la correlación simple de flujos.

**Desventajas:** identificadores estables de object/account/API; registros del proveedor; secuencia decode/follow-on del endpoint; el contenido puede ser incautado o modificado.

**Procedimiento:** usar [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): alojar un pointer codificado en un container propio, obtenerlo/decodificarlo desde un cliente de corta duración, contactar un segundo servicio propio, conservar ambos logs y eliminar los recursos.

**Detección:** correlacionar proceso inusual → lectura de object estable → decode → nuevo destino; hacer hash y conservar el contenido y las rutas completas de los objects, no solo el dominio.

## Serverless, ephemeral container y egress cloud-NAT

**Mecánica:** functions/jobs de corta duración se ejecutan detrás del NAT del proveedor o de un front; el servicio lógico permanece estable mientras rotan instancias y direcciones.

**Ventajas:** despliegue/destrucción rápidos; egress compartido a escala del proveedor; poco disco local; routing regional elástico.

**Desventajas:** tenant, role, API, image, secret, invocation, billing y logs front-to-origin son duraderos; fingerprints de cold-start/plataforma; política del proveedor.

**Procedimiento:** (1) usar un tenant de ejercicio propiedad de la organización; (2) desplegar una función benigna que solicite únicamente un endpoint propio; (3) registrar project/role/image/config; (4) invocar en varias instancias; (5) comparar IPs del objetivo con audit/request IDs; (6) probar la retención de logs; (7) eliminar función, roles y secrets.

**Detección:** logs cloud de auditoría/invocación, creación inusual de roles, egress compartido con gramática estable de solicitudes, reutilización de image/layer/secrets y correlación front-origin.

## Drop autorizado en sitio

**Mecánica:** un ordenador pequeño inventariado usa la red cableada/Wi-Fi local y un rendezvous VPN/cellular outbound, presentando un origen local.

**Ventajas:** pruebas realistas de origen interno; alta velocidad; permite probar NAC, inventario físico y controles de egress.

**Desventajas:** descubrimiento/robo físico; evidencias de serial/MAC/USB/DHCP/PoE/RF y cámaras; la pérdida puede exponer credenciales.

**Procedimiento:** seguir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) obtener autorización escrita exacta de colocación; (2) registrar serial, MAC, foto, ubicación y hora de recuperación; (3) usar una imagen mínima firmada y credenciales mutuales de corta duración; (4) restringir destinos/capacidades outbound-only; (5) añadir quarantine server-side y límites de ancho de banda; (6) probar la visibilidad del SOC y la respuesta ante pérdida; (7) recuperar, conservar las evidencias requeridas y sanitizar según la política de lifecycle acordada. Nunca ocultar uno en un local sin consentimiento.

**Detección:** NAC/802.1X, switchport/PoE/DHCP, inventario USB, inspección RF, túnel recurrente, recepción/cámaras e inspección física.

## Nearest-neighbor wireless pivot

**Mecánica:** un actor controla un host dentro del alcance de radio del objetivo y usa las credenciales Wi-Fi del objetivo para cruzar remotamente el límite. APT28 lo utilizó con organizaciones comprometidas cercanas.<sup>[[18]](#references)</sup>

**Ventajas:** no requiere desplazamiento del operador; el objetivo ve un origen de radio local; evita controles aplicados únicamente a la entrada desde Internet.

**Desventajas:** requiere un host cercano comprometido/propio con dos radios y acceso válido; existen evidencias de RADIUS/NAC/AP y del endpoint vecino; anomalías de señal/dispositivo.

**Procedimiento:** reproducir únicamente con el [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): conectar un pivot propio a los SSID de laboratorio vecino y objetivo, reenviar un único servicio, recopilar logs de ambos AP/pivot y activar EAP-TLS/device posture para confirmar que el segundo intento falla.

**Detección:** correlacionar identidad RADIUS, certificado/posture gestionado, dispositivo visto por primera vez, edge/señal del AP, login concurrente y presencia física; buscar endpoints cercanos con radios simultáneas, forwarding y tunnels.

## Community mesh, delay-tolerant y offline store-and-forward

**Mecánica:** el tráfico atraviesa peers locales, gateways asíncronos, medios extraíbles o queues programadas en vez de una única sesión interactiva de Internet.

**Ventajas:** funciona durante interrupciones/censura; la entrega retrasada/en batches debilita el timing simple; no requiere last mile central para comunicación local.

**Desventajas:** latencia alta; conjunto de anonimato pequeño; metadatos de custodia/físicos; peers maliciosos; los datos finalmente llegan a un gateway que los observa.

**Procedimiento:** (1) construir un mesh o file queue aislado de tres nodos propios; (2) cifrar/autenticar el contenido extremo a extremo; (3) eliminar rutas directas a Internet del origen; (4) reenviar un archivo benigno tras un delay controlado; (5) verificar que solo el gateway contacta el destino propio; (6) comparar custodia/timestamps; (7) conservar las evidencias requeridas y sanitizar medios/queues temporales durante el cierre aprobado.

**Detección:** actividad de archivos/procesos del endpoint, enlaces radio de peers, auditoría de medios extraíbles, periodicidad de queue/gateway e identificadores de contenido. Las ventanas de correlación más largas sustituyen el análisis del flujo interactivo.

## TURN relay y WebRTC con forced-relay

**Mecánica:** Traversal Using Relays around NAT (TURN) asigna una dirección pública de relay y transporta tráfico UDP, TCP o TLS entre un cliente y peers. Una política ICE puede imponer el uso del relay en vez de exponer un candidate directo. TURN resuelve alcanzabilidad, no anonimato general: el servidor autentica al cliente y observa allocations, peers, tiempo y volumen.<sup>[[19]](#references)</sup>

**Ventajas:** ampliamente implementado; gestiona NAT restrictivo; compatible con WebRTC móvil; el peer no recibe la dirección de transporte directa del cliente cuando se impone correctamente una política relay-only.

**Desventajas:** el operador TURN ve ambos lados adyacentes; permanecen la identidad de aplicación, media fingerprint y signaling; relay-only cuesta ancho de banda y latencia; una configuración incorrecta aún puede recopilar candidates host o server-reflexive.

**Procedimiento:** (1) desplegar un servicio TURN propio de la organización con TLS y credenciales de corta duración; (2) restringir realms, peers, puertos, cuotas y expiración; (3) configurar la aplicación de prueba con ICE relay-only; (4) llamar a un peer propio; (5) inspeccionar `getStats()` y packet capture para confirmar que solo relay candidates transportaron media; (6) hacer fallar el relay y confirmar que no existe fallback directo; (7) conservar allocation logs del engagement.

**Detección:** signaling, proceso del navegador y allocations TURN vinculan la sesión al relay; las redes observan flujos sostenidos hacia puertos TURN o endpoints TLS; el peer ve el relay asignado. **Nodo capturado:** el estado de la aplicación y las credenciales TURN efímeras pueden revelar realm y servicio de rendezvous. Minimizar la exposición con credenciales por dispositivo y de corta duración, manteniendo la autenticación del operador únicamente en el controller.

## Rendezvous outbound-only o reverse overlay

**Mecánica:** un nodo detrás de NAT inicia una conexión autenticada hacia un broker controlado por la organización. El operador se autentica separadamente ante el broker, que autoriza un canal de administración estrecho; no se necesita port forwarding inbound ni una ruta directa operador-nodo.

**Ventajas:** estable detrás de NAT y last miles cautivos; revocación y auditoría centralizadas; los cambios de dirección del field node no requieren descubrimiento; separa claramente identidad del operador y credencial del nodo.

**Desventajas:** el broker se convierte en un punto de correlación de alto valor; los keepalives periódicos son reconocibles; un túnel amplio puede convertirse en un pivot inseguro; la pérdida del broker termina la administración.

**Procedimiento:** seguir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): emitir una device identity con alcance único, permitir solo el broker propio y el servicio de administración aprobado, usar keepalive autenticado, imponer routing fail-closed, probar cambios de dirección y recuperación tras reboot, y revocar la identidad durante el loss drill. WireGuard documenta un persistent keepalive de 25 segundos como intervalo NAT ampliamente útil cuando realmente se necesita.<sup>[[20]](#references)</sup>

**Detección:** los logs del broker y del identity provider vinculan ambos lados; la red de acceso ve un destino/cadencia cifrado repetido; el inventario del endpoint muestra el overlay agent. **Nodo capturado:** asumir que quedan expuestos su device key, nombre del broker, direcciones del túnel y task data almacenada. No debe contener private key del operador, cuenta personal ni controller token reutilizable.

## Pull mailbox, message queue u object-store rendezvous

**Mecánica:** un workload de campo consulta un mailbox autenticado para obtener jobs firmados y preaprobados, y publica resultados limitados. El operador escribe en la queue mediante un control-plane separado; no existe un socket interactivo entre ellos.

**Ventajas:** tolera enlaces intermitentes; desacopla tiempo y direccionamiento; quotas y schemas pueden limitar capacidades; auditoría y revocación centralizadas sencillas.

**Desventajas:** la cadencia de polling y los nombres estables de object/queue fingerprintean el sistema; los logs del proveedor unen productor y consumidor; control retrasado; los datos en queue capturados pueden exponer el ejercicio.

**Procedimiento:** (1) crear una queue y una device identity por engagement; (2) definir un schema firmado de jobs benignos y explícitamente limitados; (3) establecer message TTL, tamaño máximo de resultado y rate; (4) permitir al nodo leer solo su queue y escribir únicamente en su prefix de resultados; (5) probar acumulación offline, entrega duplicada y revocación; (6) centralizar access logs inmutables; (7) eliminar la queue tras cumplir los requisitos de retención.

**Detección:** buscar llamadas API periódicas de un proceso inusual, rutas estables de bucket/object/queue, user-agent o comportamiento TLS idéntico y secuencia fetch-then-new-connection. **Nodo capturado:** la cache local puede revelar jobs pendientes y nombres de objects; mantenerla cifrada, limitada y desechable, conservando los logs autoritativos del controller.

## Dual-uplink failover y connection migration

**Mecánica:** un field node aprobado tiene dos uplinks independientes —por ejemplo Ethernet/Wi-Fi del local y cellular de la organización— y mantiene su sesión de control mediante un overlay o message broker mientras cambian las rutas. Esto es ingeniería de disponibilidad, no anonimato.

**Ventajas:** sobrevive al fallo de un proveedor, AP o captive portal; permite mantenimiento planificado; facilita aislar rápidamente una ruta sospechosa.

**Desventajas:** dos proveedores crean dos registros de ubicación/cuenta; el uso simultáneo facilita la correlación; leaks de ruta y DNS durante failover; permanece la evidencia de co-ubicación cellular.

**Procedimiento:** (1) registrar ambas interfaces y proveedores propios de la organización; (2) asignar prioridades de rutas y health checks deterministas hacia endpoints propios; (3) vincular DNS y administración al overlay; (4) impedir que la ruta secundaria acepte tráfico inbound; (5) desconectar cada ruta y verificar recuperación de sesión, política de origen y ausencia de acceso directo al destino; (6) alertar ante cambios de ruta no planificados; (7) documentar uso de datos y límites de roaming.

**Detección:** correlacionar el mismo certificado de dispositivo, gramática de solicitudes y timing entre ASNs; el inventario local ve ambas radios; carriers/locales conservan sus propios registros. **Nodo capturado:** ambos identificadores SIM/dispositivo y SSIDs conocidos pueden estar visibles; usar activos de la organización y nunca co-ubicar ni emparejar el nodo con dispositivos personales.

## Private APN de la organización o managed cellular tunnel

**Mecánica:** un private APN del carrier coloca SIMs inscritas en un dominio privado enrutado o tuneliza el tráfico hacia un gateway empresarial. Separa el dispositivo de Internet móvil pública, pero no lo oculta al carrier ni a la organización contratante.

**Ventajas:** direccionamiento privado estable; enrollment y política de tráfico a nivel de carrier; evita exposición inbound pública; útil para appliances remotos autorizados.

**Desventajas:** atribución fuerte de suscriptor, IMSI/IMEI, celda y billing; tiempo y coste de procurement; fallo del carrier/gateway; no es anónimo frente al operador.

**Procedimiento:** (1) contratar el APN a nombre de la organización evaluada; (2) allowlist únicamente SIMs y prefixes del gateway registrados; (3) añadir mutual authentication en la capa de aplicación; (4) restringir la ruta del APN al rendezvous y servicios de update; (5) probar retirada de SIM, roaming, breakout a Internet pública y revocación; (6) monitorizar registros del carrier y gateway; (7) cancelar o poner en quarantine cada SIM durante el cierre.

**Detección:** inventario y telemetría celular del carrier, flujos del gateway APN, incompatibilidad SIM/IMEI y activos empresariales. **Nodo capturado:** la SIM y el modem identifican el contrato incluso con almacenamiento cifrado; la resiliencia de captura implica suspensión rápida y autorización limitada, no negación.

## Long-range point-to-point wireless bridge

**Mecánica:** Wi-Fi direccional u otra radio punto a punto licenciada/no licenciada conecta dos sitios aprobados por los propietarios, con egress de Internet en el sitio remoto. Puede mover la ubicación IP aparente sin un proxy comercial.

**Ventajas:** alto throughput; independencia de carriers cableados intermedios; RF y routing controlables; útil para probar segmentación y monitorización de sitios remotos.

**Desventajas:** línea de visión, espectro, propietarios y restricciones regulatorias; emisiones RF y hardware distintivos; ambos endpoints son evidencia física; clima/energía/alineación afectan la estabilidad.

**Procedimiento:** (1) obtener permiso escrito para ambos sitios y verificar reglas de espectro/potencia; (2) inspeccionar la ruta sin transmitir fuera de parámetros aprobados; (3) usar cifrado autenticado y una management VLAN; (4) limitar el bridge a un rendezvous o test subnet propio; (5) probar failover, alineación, recuperación de energía y contención RF; (6) etiquetar/inventariar ambas radios; (7) retirarlas y verificar el reset de configuración tras el ejercicio.

**Detección:** RF surveys, análisis de espectro, inspección de rooftops/sitios, bridge MAC/OUI, tráfico de administración y logs de egress del sitio remoto. **Nodo capturado:** la configuración revela su peer y management domain; usar credenciales únicas del ejercicio, ninguna cuenta personal de administración y revocación rápida de peer keys.

## Cooperative o community exit con consentimiento

**Mecánica:** voluntarios u organizaciones asociadas ejecutan relays conscientemente bajo una política publicada. El tráfico sale desde un pool comunitario compartido, mientras la capa de coordinación gestiona abuso y revocación.

**Ventajas:** redes diversas no cloud; el consentimiento explícito es más seguro que proxyware; la gobernanza compartida puede distribuir la confianza; útil para investigación y estudios de resistencia a la censura.

**Desventajas:** pools pequeños y registros de miembros reducen el anonimato; los operadores de exits reciben complaints y observan metadatos de tráfico; participantes maliciosos, uptime variable y diferencias jurisdiccionales.

**Procedimiento:** (1) publicar una política de uso aceptable y logging; (2) obtener opt-in informado de cada operador; (3) emitir una identidad única de relay y restringir destinos/rates; (4) proporcionar gestión de abuso y revocación de una acción; (5) enviar únicamente tráfico autorizado a endpoints propios durante las pruebas; (6) medir churn y exposición a correlación; (7) eliminar limpiamente el relay cuando termine el consentimiento.

**Detección:** registros de membership/control-plane, certificados de relays, fingerprint común de software y comportamiento del exit identifican el pool. **Nodo capturado:** la configuración del relay puede identificar al cooperante, pero no debe contener identidades de clientes; almacenar la accountability cliente-sesión en el controller autorizado bajo control de acceso.

## IPv6 temporary addresses y rotación de prefijos

**Mecánica:** las privacy extensions de IPv6 crean interface identifiers temporales para no reutilizar una dirección estable en cada conexión outbound. Los cambios de prefix del proveedor pueden añadir rotación, pero el prefix delegado, el registro del suscriptor y el fingerprint de capas superiores permanecen.<sup>[[21]](#references)</sup>

**Ventajas:** reduce el tracking pasivo a largo plazo mediante un interface identifier estable; está integrado en sistemas operativos comunes; no añade overhead de relay.

**Desventajas:** no proporciona anonimato de origen; el ISP y la red local siguen conociendo prefix/dispositivo; DNS, cuentas y estado del navegador vinculan sesiones; el churn de direcciones complica allowlists y logging.

**Procedimiento:** (1) inspeccionar las direcciones estables y temporales actuales en un cliente propio; (2) activar el valor predeterminado de privacy-address soportado por el OS en vez de spoofing de terceros; (3) solicitar repetidamente un endpoint IPv6 propio durante varios ciclos de vida; (4) confirmar que los servicios inbound solo se vinculan a las direcciones estables previstas; (5) conservar logs DHCPv6/RA/neighbor y de endpoints precisos; (6) probar el comportamiento de VPN/firewall para cada dirección IPv6.

**Detección:** correlacionar prefix delegado, identidad de capa 2, neighbor discovery, cuenta y telemetría del endpoint en vez de tratar una dirección como un dispositivo. **Nodo capturado:** permanecen los perfiles de red y interface identifiers; el direccionamiento temporal evita un identificador pasivo único, no la atribución forense.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 y meek

**Mecánica:** un pluggable transport cambia la apariencia de la primera conexión Tor o la forma en que llega a un bridge. Snowflake usa proxies WebRTC voluntarios de corta duración, WebTunnel se parece a HTTPS ordinario, obfs4 resiste la identificación simple de protocolo y el probing activo, y meek retransmite mediante infraestructura web compatible. Son transports de circumvention hacia Tor, no capas adicionales de anonimato extremo a extremo.<sup>[[22]](#references)</sup>

**Ventajas:** útiles cuando Tor directo o los relays conocidos están bloqueados; Snowflake evita una dirección pública estable de bridge; integrados en clientes Tor mantenidos; el destino sigue recibiendo las propiedades normales de Tor.

**Desventajas:** rendimiento menor o variable; broker/front/bridge y red local observan metadatos diferentes; siguen siendo posibles fingerprints y bloqueos; el proxy voluntario no sustituye a Tor ni debe recibir plaintext de la aplicación.

**Procedimiento:** (1) instalar y verificar Tor Browser oficial o cliente Tor compatible; (2) seleccionar el transport integrado en Connection/Bridges; (3) conectar únicamente a una página de diagnóstico propia; (4) confirmar que la página ve un Tor exit, no el peer Snowflake/WebTunnel; (5) comparar bootstrap y rendimiento; (6) hacer fallar el transport y confirmar que el cliente no conecta directamente de forma silenciosa; (7) volver a la configuración estándar compatible tras la prueba.

**Detección:** un censor puede combinar allowlists de destinos, comportamiento TLS/WebRTC, descubrimiento del broker y análisis de flujos; los endpoints exponen la configuración de Tor y transport. **Capture-resilient OPSEC:** usar el cliente estándar, nunca copiar estado personal del navegador y asumir que el historial de bridge/broker puede recuperarse. **Monitoring:** observar logs de bootstrap de Tor, intentos directos inesperados de DNS/conexión y observaciones desde páginas propias del controller; el fallo del transport no demuestra descubrimiento.

## Refraction networking o decoy routing

**Mecánica:** un operador de red cooperante detecta una señal encubierta en tráfico aparentemente dirigido a un decoy permitido y desvía el flujo hacia un proxy de circumvention. El despliegue requiere infraestructura en la ruta de red; un cliente no puede crearlo simplemente seleccionando un sitio inocente.<sup>[[23]](#references)</sup>

**Ventajas:** el destino aparente puede ser difícil de bloquear sin daños colaterales; no es necesario distribuir una dirección pública de bridge; modelo de investigación útil para circumvention asistido desde la ruta.

**Desventajas:** participación especializada de ISP/transit; el despliegue y rendimiento dependen del routing; permanecen el flujo cliente-decoy y la actividad del proxy; un observador global o cooperante puede correlacionar tiempos.

**Procedimiento:** no señalizar mediante redes no implicadas. Reproducir la arquitectura en un laboratorio aislado: (1) crear namespaces propios de cliente, router, decoy y proxy; (2) usar una solicitud de prueba benigna etiquetada; (3) permitir que el router propio redirija solo esa etiqueta al proxy; (4) registrar tuplas y request IDs antes/después del routing; (5) comparar flujos normales y señalizados; (6) probar falsos positivos y eliminación; (7) destruir las rutas del laboratorio.

**Detección:** los operadores autorizados pueden inspeccionar divergencia de routing, comportamiento inusual de client hello/tag y discrepancias de flujo decoy-versus-back-end. **Capture-resilient OPSEC:** un cliente de investigación solo debe contener test keys y direcciones documentales. **Monitoring:** comparar decisiones firmadas del router de laboratorio con llegadas al proxy; no sondear proveedores de transit productivos para averiguar si detectaron la señalización.

## Content-addressed gateway o cached peer retrieval

**Mecánica:** un gateway HTTP obtiene un content identifier (CID) de IPFS, posiblemente desde su cache o peers, y devuelve el contenido verificable al cliente. El publicador original puede ver el gateway u otros peers en vez del lector final; el gateway ve la IP del lector y el CID solicitado. La recuperación nativa peer-to-peer expone el cliente a peers y participantes de DHT/routing.<sup>[[24]](#references)</sup>

**Ventajas:** caches separan publicador y lector; el contenido inmutable puede verificarse por hash; los datos replicados sobreviven a un host; los clientes HTTP no requieren una pila peer nativa.

**Desventajas:** CIDs públicos y logs del gateway revelan intereses; el timing de la primera recuperación puede correlacionar publicador y lector; contenido web malicioso y riesgos same-origin de path-style; los gateways públicos son best-effort y prohíben abuso.

**Procedimiento:** (1) publicar un archivo de prueba inofensivo en un private IPFS swarm o gateway propio; (2) registrar su CID; (3) recuperarlo mediante un gateway HTTP propio separado usando aislamiento por subdomain; (4) verificar los bytes contra el CID; (5) repetir después de caching; (6) comparar logs de publicador, peer y gateway; (7) unpin y eliminar el contenido cuando termine la retención.

**Detección:** los gateways registran source/CID; las conexiones DHT y peer revelan la recuperación; el historial del endpoint y los hashes del archivo identifican el contenido. **Capture-resilient OPSEC:** no almacenar private publishing keys en un field client read-only y cifrar contenido sensible antes del content addressing. **Monitoring:** alertar ante pinning inesperado, cambios en el peer set, solicitudes CID fuera de allowlist o avisos de la cuenta del gateway.

## Private information retrieval service

**Mecánica:** Private Information Retrieval (PIR) permite que un cliente obtenga un registro de una base de datos ocultando criptográficamente el índice seleccionado al servidor bajo un threat model single-server o multi-server definido. Protege la selección de consulta para un dataset limitado; no es acceso web general ni anonimato IP.<sup>[[25]](#references)</sup>

**Ventajas:** privacidad fuerte y específica de la aplicación; modelo de filtración medible; útil para key directories, blocklists o pequeñas bases públicas; puede reducir la necesidad de revelar términos exactos de lookup.

**Desventajas:** overhead de computación/ancho de banda; el servidor conoce IP/hora de conexión salvo que se combine con un relay; la versión del dataset, tamaño de respuesta y estado de aplicación pueden particionar usuarios; madurez de implementación variable.

**Procedimiento:** (1) desplegar una implementación PIR auditada contra una base sintética propia; (2) publicar versión y parámetros del dataset; (3) recuperar varios índices usando tamaños de solicitud idénticos; (4) verificar localmente la corrección; (5) comparar logs del servidor y confirmar que el índice está ausente; (6) probar respuestas maliciosas/truncadas y mismatch de versión; (7) documentar la suposición exacta de privacidad en vez de llamarlo browsing anónimo.

**Detección:** las redes ven uso y volumen del servicio; la telemetría del endpoint expone el cliente y el uso final del registro; un servidor comprometido puede manipular datasets o tiempos. **Capture-resilient OPSEC:** conservar en el cliente únicamente parámetros públicos y una cache limitada. **Monitoring:** validar signed dataset roots, formas de solicitud fijas, cambios en error rate y rotaciones de server keys.

## Constrained server-side fetcher, preview o rendering service

**Mecánica:** un servicio remoto obtiene o renderiza una URL y devuelve screenshot, metadata o contenido sanitizado. El destino ve la dirección del fetcher; el servicio ve requester, URL y resultado. Abusar de link-preview bots, security scanners o URL fetchers de terceros no es uso autorizado de proxy.

**Ventajas:** aísla contenido activo de la workstation; el destino recibe un fingerprint de fetcher controlado; puede imponer límites de tipo de archivo, tamaño, destino y rendering; entorno de ejecución desechable.

**Desventajas:** el servicio conoce toda la solicitud; registros de cuenta/API/billing; riesgo de SSRF y exfiltración; scripts, autenticación y sitios interactivos pueden no funcionar; URLs únicas correlacionan requester y fetch.

**Procedimiento:** (1) desplegar un fetcher propio de la organización con allowlist estricta de dominios de prueba propios; (2) bloquear direcciones private, link-local, metadata y redirect-to-unapproved; (3) limitar métodos, redirects, bytes y tiempo de render; (4) eliminar credenciales/cookies; (5) enviar una URL propia; (6) comparar logs de requester, fetcher y target; (7) destruir la instancia de render y conservar la auditoría central según la política.

**Detección:** el objetivo ve el ASN/fingerprint del servicio; los logs del proveedor y controller vinculan requester con URL; el proceso/API del endpoint muestra el envío. **Capture-resilient OPSEC:** usar un único project token de corta duración sin autoridad sobre destinos arbitrarios. **Monitoring:** alertar ante denegaciones de allowlist, violaciones de redirect, fetches sin controller job ID y avisos de abuso del proveedor.

## Anycast rendezvous pool

**Mecánica:** varios nodos controlados por la organización anuncian o frontan una dirección de servicio estable, y el routing selecciona una instancia cercana. Anycast mejora la disponibilidad y oculta un back-end individual al cliente, pero el operador controla todas las instancias y la dirección del servicio es estable.<sup>[[26]](#references)</sup>

**Ventajas:** ingress regional resiliente; no requiere reconfiguración de campo cuando falla una instancia; distribución DDoS/load; la política central puede mover sesiones entre nodos conocidos.

**Desventajas:** los registros BGP/CDN y de proveedores identifican a la organización; los cambios de ruta pueden romper sesiones stateful; el monitoring varía según la ubicación del cliente; una dirección estable se bloquea o agrupa fácilmente por reputación.

**Procedimiento:** usar un proyecto de organización soportado por el proveedor o un routing lab aislado: (1) desplegar dos health endpoints autenticados idénticos; (2) exponer una dirección de servicio documentada; (3) mantener el estado de sesión en el broker y no en el edge; (4) retirar un nodo y verificar la reconexión; (5) probar consistencia de certificado, política y logs; (6) alertar ante origen/región no autorizados; (7) eliminar advertisements y credenciales durante el cierre.

**Detección:** BGP/RPKI/history, tenancy del proveedor, certificados y comportamiento idéntico del servicio identifican el pool. **Capture-resilient OPSEC:** un edge solo contiene la identidad regional del servicio, no una key del operador o de enrollment de la flota. **Monitoring:** sondear cada región desde monitores autorizados, comparar origen de ruta y digest de configuración, y tratar un origen inesperado como incidente.

## QUIC migration y continuidad Multipath TCP

**Mecánica:** los connection IDs de QUIC pueden mantener viva una sesión a través de rebinding NAT o cambios de dirección; Multipath TCP puede transportar un único byte stream fiable mediante varios subflows. Mejoran la continuidad entre Wi-Fi/cellular, pero exponen las rutas antiguas y nuevas al peer común y pueden facilitar la correlación entre rutas.<sup>[[27]](#references)</sup>

**Ventajas:** recuperación más rápida durante cambios de uplink; la sesión de aplicación no necesita reiniciarse; MPTCP puede combinar resiliencia y throughput; útil para field nodes aprobados.

**Desventajas:** no es anonimato; el peer ve migración/subflows; connection identifiers y tráfico simultáneo vinculan rutas; el soporte de middleboxes/carriers varía; los registros duplicados de proveedores aumentan la exposición.

**Procedimiento:** (1) activar el transporte compatible únicamente entre un field client propio y el rendezvous; (2) autenticar la aplicación independientemente de IP; (3) iniciar una transferencia limitada en Wi-Fi aprobado; (4) cambiar a cellular de la organización; (5) confirmar path validation, integridad de datos y ausencia de fallback directo/en claro; (6) probar idle timeout y retorno; (7) conservar en el broker los registros de cada transición de ruta.

**Detección:** el peer observa directamente la migración de dirección o los subflows MPTCP; los proveedores de acceso ven su parte; connection IDs, identidad TLS y timing unen ambos lados. **Capture-resilient OPSEC:** almacenar solo material de sesión específico del dispositivo y expirar rápidamente el estado reanudable. **Monitoring:** alertar ante cambios de ruta imposibles, redes no aprobadas simultáneas, migration storms y reanudación tras quarantine.

## Managed CI/CD o egress de ephemeral automation runner

**Mecánica:** un workflow propiedad de la organización ejecuta un network check limitado en un runner alojado. El destino ve una dirección del cloud runner, mientras la plataforma conserva la atribución de repository, actor, workflow, token, logs y billing. Es ejecución remota con egress atribuible, no anonimato frente al proveedor.<sup>[[28]](#references)</sup>

**Ventajas:** entorno limpio y desechable; definición reproducible del job; no requiere conexión inbound; útil para checks de disponibilidad distribuidos geográficamente; auditoría fuerte del controller.

**Desventajas:** la plataforma y la organización identifican al iniciador; los workflow tokens amplios y pull requests no confiables son peligrosos; reputación de IP compartida; logs/artifacts pueden conservar secrets o datos del objetivo.

**Procedimiento:** (1) crear un repository privado y environment de organización para la evaluación; (2) permitir solo jobs benignos fijos y aprobados manualmente contra endpoints propios; (3) usar permisos workflow mínimos de solo lectura y ningún production secret; (4) ejecutar el check; (5) comparar registros de workflow, proveedor y objetivo; (6) verificar que los artifacts no contienen credenciales; (7) eliminar el environment token y conservar la auditoría requerida.

**Detección:** la auditoría del proveedor y los workflow logs proporcionan atribución directa; los objetivos identifican ASNs/rangos de runners y gramática estable de solicitudes. **Capture-resilient OPSEC:** nunca colocar secrets de field devices, signing, wallets o cloud administrators en variables del runner. **Monitoring:** exigir aprobación de branch/environment y alertar ante cambios de workflow, ejecución desde forks, lecturas de secrets y destinos inesperados.

## Non-IP local first hop hacia un gateway propio

**Mecánica:** Bluetooth mesh, Wi-Fi Aware/Direct, radio de baja potencia o un enlace serial/óptico transporta mensajes limitados desde un sensor cercano a un Internet gateway aprobado por el propietario. El field device no tiene ruta a Internet; el gateway es el único egress. El alcance radio y los límites del protocolo hacen que sea un diseño de telemetry/store-and-forward, no Internet interactiva anónima.

**Ventajas:** elimina la pila de Internet y las credenciales del dispositivo de campo más pequeño; bajo consumo; el gateway centraliza la política; puede atravesar dead zones temporales.

**Desventajas:** descubrimiento RF/físico, pairing e identificadores del dispositivo; poco ancho de banda y alcance; el gateway sigue vinculando todos los mensajes; las restricciones de espectro y cifrado varían; la captura puede exponer datos en queue.

**Procedimiento:** (1) obtener aprobación del sitio y espectro; (2) emparejar un sensor propio con un gateway propio usando keys únicas; (3) definir tipos de mensajes firmados y de tamaño fijo, TTL y rate; (4) dar al sensor ninguna ruta IP predeterminada; (5) permitir que el gateway reenvíe solo a un collector propio; (6) probar replay, pérdida de alcance y fallo del gateway; (7) inventariar y recuperar ambos dispositivos.

**Detección:** RF survey, pairing database, inspección física y logs de proceso/flujo del gateway revelan la ruta. **Capture-resilient OPSEC:** el sensor contiene únicamente su pairwise key y una encrypted queue limitada, nunca credenciales de operador, Wi-Fi, cellular o controller. **Monitoring:** alertar ante peers nuevos, rollback de secuencia, fallo de key, tasa RF inusual y mensajes que lleguen mediante un gateway no registrado.

## Matriz de exposición ante captura/compromiso

Esta tabla aplica una comprobación de capture-resilience a cada familia anterior. “Minimizar” significa reducir secrets y blast radius en activos autorizados; nunca significa borrar evidencias ni ocultarse de una investigación.

| Familia de técnicas | Lo que puede revelar un endpoint/relay capturado | Control autorizado mínimo |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | redes conocidas, historial DHCP/portal, MACs, peer del túnel | dispositivo separado de la organización; private MAC cuando sea compatible; ninguna cuenta personal; inventario del controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | proveedores/hostnames, keys, rutas, logs y hop adyacente | una identidad por engagement; TTL corto; rutas limitadas; revocación desde el broker; ninguna master key |
| OHTTP/ODoH, MASQUE, split-provider relay | configuración relay/gateway, identificadores de aplicación y requests en cache | minimizar identificadores de payload; fijar config aprobada; cache limitada; no-direct fallback estricto |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software instalado, material bridge/onion, estado local e historial de peers | cliente estándar; service keys separadas; estado mínimo cifrado; rotar identidad comprometida del servicio |
| Remote browser/VDI/jump host | workspace token, clipboard/files y tenant remoto | MFA resistente a phishing en gateway; canales de transferencia desactivados; revocación rápida de sesión |
| Cellular, satellite, private APN | SIM/eSIM, identidad IMEI/terminal, proveedor y ubicación aproximada | contrato de la organización; sin co-ubicación personal; política APN/overlay limitada; runbook de suspensión |
| Residential/cooperative proxy, ORB lab | identidad del agente, controller/next hop, tráfico en cache | solo nodos consentidos/propios; agent firmado; credencial por nodo; mapping de participantes en el controller |
| CDN/fronting, fast flux, serverless | tenant/origen/config, API tokens, referencias de deployment y billing | proyecto dedicado; role de mínimo privilegio; deploy token de corta duración; auditoría del proveedor centralizada |
| Dead drop, pull mailbox, store-and-forward | nombres de objects, queue, jobs/results en cache y datos de custodia | jobs firmados y limitados; TTL; cache cifrada; identidad de productor separada; logs de servidor inmutables |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, artefactos de ubicación física | colocación escrita; identidad única; ningún secret del operador; telemetría de estado/tamper; revocar y recuperar |
| TURN, reverse overlay, dual-uplink | realm/broker, credencial del dispositivo, peer/ruta y perfiles uplink | servicio outbound-only limitado; credencial de dispositivo corta; login de operador independiente; rutas fail-closed |
| IPv6 temporary addressing | perfiles, historial de prefijos y estado endpoint/aplicación | tratarlo solo como anti-tracking; conservar logs de red; combinar con compartmentation del endpoint |
| Pluggable transport/refraction lab | configuración bridge/broker/decoy, estado Tor y keys de investigación | cliente estándar o laboratorio aislado; ningún estado personal del navegador; no signalización productiva |
| IPFS/PIR/fetcher | CID/query solicitada, contenido en cache, gateway o service token | cache cifrada limitada; parámetros solo públicos; service token de corta duración y allowlist |
| Anycast/QUIC/MPTCP | nodos de servicio, connection IDs, estado reanudable y todas las rutas conocidas | solo identidad regional; lifetime corto de reanudación; revocación central de rutas/sesiones |
| Managed CI/CD runner | repository, workflow, provider token, logs y artifacts | workflow con mínimo privilegio; ningún secret de producción/campo/wallet; aprobación de environment |
| Non-IP local hop | peer radio, pairwise key, mensajes en queue e identidad del gateway | pairwise key única; schema fijo; ninguna credencial Wi-Fi/cellular/operator |

## Monitoring del posible descubrimiento para cada familia de acceso

Ninguna prueba del lado del cliente demuestra que un investigador o defensor esté observando. Monitorizar cambios en sistemas propiedad del engagement, corroborarlos con el controller/cliente y detenerse en vez de sondear a los observadores. Las filas siguientes cubren todas las técnicas anteriores; combinarlas con los [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Técnicas cubiertas | Señales seguras del controller | Condición de quarantine/stop |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | sesión lease/portal/carrier, tupla pública, cambio BSSID/celda/ruta, aviso del proveedor | red/SIM/dispositivo no aprobado, reubicación inexplicada o escalada del proveedor/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | autenticación del peer, estado del túnel, leaks de ruta/DNS, nuevo evento admin/API, complaint | credencial duplicada/robada, administrador desconocido, fallback directo o egress fuera de alcance |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | allocation de relay/gateway, versión de key/config, conexión directa no compatible, error/replay rate | mismatch de key, fallback directo, realm/peer desconocido o aviso de abuso del proveedor |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | estado bootstrap, fallo de circuito, descriptor onion/health del servicio y página canary propia | cruce con cuenta personal, conexión no Tor inesperada o service key comprometida |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, edad/secuencia de queue, llegada al gateway, asociación radio y hash de contenido | peer/gateway desconocido, rollback de secuencia, contenido no autorizado o registro de custodia ausente |
| Remote browser/VDI/jump host, CI/CD runner, serverless | sesión IdP, cambios workflow/image/config, nuevo uso de token, artifact/export y cloud audit | login/workflow edit desconocido, lectura de secret, destino inesperado o escalada project-role |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventario de nodos propios, acceso DNS/edge/object, grafo del controller, firma de job y TTL | nodo/origen/object writer desconocido, job sin firma/repetido, escape de topología del laboratorio |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | heartbeat firmado, boot/config hash, estado de enclosure, contexto AP/switch, identidad duplicada | nodo movido/abierto, boot/hash/ruta inesperados, uso de sentinel o informe del sitio |
| IPv6 temporary addresses, QUIC migration, MPTCP | prefijo delegado, connection ID/subflows, path-validation y sesión del broker | migración imposible, rutas no aprobadas simultáneas o reanudación tras revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, cambio de peer/gateway, redirect/allowlist denial | pin/query/destino inesperado, dataset root sin firma o aviso de abuso del proveedor |
| Refraction/decoy-routing lab, anycast rendezvous | decisión de desvío propia, llegada al proxy, origen BGP/RPKI, digest de config regional | señal en ruta productiva, origen de ruta desconocido, inconsistencia regional/configuración |

## Elección y prueba de una ruta

1. Nombrar el observador que se quiere eliminar y los datos que se quieren ocultar.
2. Seleccionar la familia menos compleja que lo elimine.
3. Dibujar los observadores de origen, entrada, tránsito, salida, DNS, cuenta y pago.
4. Usar una identidad separada de endpoint/aplicación.
5. Verificar bypass de IPv4, IPv6, DNS, WebRTC/aplicación y la vista del destino.
6. Romper cada hop y confirmar que el fallo es cerrado.
7. Comparar los logs de cada componente controlado.
8. Registrar los vínculos residuales de tiempo, proveedor, endpoint y presencia física.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
