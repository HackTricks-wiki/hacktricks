# Catálogo de técnicas de acceso anónimo a Internet

Este es el inventario canónico de rutas de acceso. Cubre **familias** de protocolos y operaciones, no todos los nombres de proveedores. Ninguna ruta de Internet garantiza el anonimato: las pruebas de cuenta, navegador, endpoint, temporales, pagos, plano de control cloud y físicas pueden derrotar una ruta aparentemente perfecta.

Cada entrada usa los mismos campos. “Procedimiento” significa un despliegue legal o una emulación en un laboratorio propio. Cuando la técnica real depende de comprometer un router, robar acceso o abusar de un intermediario que no coopera, la reproducción sustituye esos sistemas por sistemas propiedad del ejercicio.

## Matriz de cobertura

| Familia | Lo que ve el destino | Propiedad más fuerte | Velocidad | Tratamiento |
|---|---|---|---|---|
| NAT/CGNAT compartido | dirección pública compartida | ambigüedad entre suscriptores | alta | desplegable |
| VPN, VPS, proxy SOCKS/HTTP/SSH | dirección del relay | separación rápida de la dirección de origen | alta | desplegable |
| Relay multip salto/split, MASQUE | proxy final | división del conocimiento o túnel IP completo | alta/moderada | desplegable con relays de confianza |
| Tor, bridge, onion service | exit o identidad onion | ruta multipartita y navegador común | moderada | desplegable |
| I2P, GNUnet, mixnet | peer/gateway del overlay | resistencia del overlay o a temporales | baja/variable | específico de la aplicación |
| OHTTP/ODoH, Private Relay | gateway/egress | partición de origen/solicitud | alta | solo aplicaciones compatibles |
| Wi-Fi público, travel router | dirección del local/túnel | cambio de ubicación/ruta de acceso | alta | requiere permiso |
| Celular/eSIM, satélite | dirección del operador/proveedor | uplink físico independiente | alta/variable | el proveedor observa la suscripción |
| Navegador remoto/jump host | workspace remoto | separación de endpoint y egress | alta | desplegable |
| Proxy residencial/móvil | dirección de consumidor/operador | apariencia de red de consumo | alta | consentimiento/proveniencia críticos |
| ORB/relay comprometido | dirección de otra víctima | ocultación del origen y reputación prestada | alta | solo reproducción en laboratorio propio |
| CDN/fronting/redirector | dirección frontal de la CDN | protección de la infraestructura back-end | alta | requiere aprobación del proveedor/propietario |
| Fast flux/DGA/dead drop | nodo/servicio rotatorio | resistencia al descubrimiento de infraestructura | variable | solo reproducción en laboratorio propio |
| Drop/vecino cercano | dirección adyacente al objetivo | cruce de límite geográfico/de red | alta | solo laboratorio en sitio propio |
| Store-and-forward/offline | gateway o receptor físico | reduce el vínculo temporal interactivo | baja | específico de la aplicación |
| Transporte pluggable/refraction | entrada Tor o proxy de desvío cooperante | alcanzabilidad resistente a censura | variable | cliente compatible o laboratorio de investigación |
| Gateway IPFS/PIR/fetcher remoto | gateway o servicio de aplicación | partición de editor/consulta/solicitud | variable | solo aplicación acotada |
| Anycast/QUIC/MPTCP | broker estable o varios subflujos | rendezvous y continuidad de sesión | alta | disponibilidad, no anonimato |
| Runner de automatización CI/CD | dirección del runner alojado | egress desechable y atribuible | alta | solo workflow propio |
| Primer salto local no IP | gateway de la organización | elimina la pila de Internet del sensor | baja | despliegue aprobado por el propietario |

## NAT compartido directo y NAT de nivel de operador

**Mecánica:** varios usuarios comparten una dirección pública; el proveedor de acceso asigna direcciones y puertos del suscriptor a la tupla pública.

**Ventajas:** rápido; no requiere cliente especial; la IP del destino puede identificar únicamente un hogar, local o grupo del operador.

**Desventajas:** el proveedor puede conservar las correspondencias de suscriptor/puerto/tiempo; las cuentas y fingerprints permanecen; otros usuarios pueden dañar la reputación de la dirección.

**Procedimiento:** (1) confirmar si el acceso autorizado usa NAT/CGNAT; (2) registrar la IP pública exacta y el puerto de origen en un endpoint propio; (3) separar las identidades de aplicación; (4) no tratar el direccionamiento compartido como control de privacidad; (5) usar una ruta más fuerte si el ISP no debe conocer los destinos.

**Detección:** los destinos deben conservar el puerto de origen y la hora exacta, no solo la IP. Los proveedores correlacionan los logs de asignación NAT; los investigadores unen evidencias de cuenta, dispositivo y navegador.

## VPN comercial

**Mecánica:** una conexión cifrada de túnel completo termina en la VPN; los destinos ven su egress. La VPN normalmente puede asociar origen, temporales y destinos.

**Ventajas:** rápida; sencilla; protege frente a observación pasiva local; exits estables o compartidos; adecuada para egress controlado de red team.

**Desventajas:** confianza concentrada; telemetría de facturación/login; fallos de kill-switch/DNS/IPv6; los exits compartidos suelen estar bloqueados por reputación.

**Procedimiento:** (1) identificar proveedor, propietario, jurisdicción, retención y política de evaluación; (2) instalar el cliente oficial firmado; (3) activar túnel completo, always-on y comportamiento fail-closed; (4) dirigir DNS e IPv6 deliberadamente; (5) verificar IPv4/IPv6/DNS observados en un endpoint propio; (6) detener y reconectar el túnel y confirmar que no existe fallback en claro.<sup>[[1]](#references)</sup>

**Detección:** las redes locales ven un flujo cifrado largo hacia infraestructura VPN; los proveedores tienen registros de autenticación/conexión; los destinos usan ASN/reputación junto con correlación de cuenta, TLS/navegador y comportamiento.

## Egress mediante VPN autoalojada o VPS alquilado

**Mecánica:** el operador controla un gateway WireGuard/OpenVPN o reenvía tráfico mediante un servidor alquilado.

**Ventajas:** alta velocidad predecible; dirección fija que puede incluirse en allowlists; logging/firewall personalizados; buen control de incidentes.

**Desventajas:** conjunto de anonimato reducido; tenant cloud, pagos, login de origen, API e historial de imágenes vinculan al operador; un servidor nuevo y distintivo es fácil de agrupar.

**Procedimiento:** (1) crear un proyecto de organización específico del engagement; (2) aprovisionar una imagen compatible y dirección fija; (3) restringir la administración a MFA/claves; (4) configurar egress de túnel completo y DNS; (5) permitir solo destinos acotados cuando sea práctico; (6) probar fugas y fallos; (7) conservar los registros de auditoría del controlador; (8) destruir credenciales y recursos durante el desmontaje.

**Detección:** correlacionar ASN de hosting, dirección vista por primera vez, fingerprint de certificado/servicio y comportamiento de scanning; los propietarios cloud usan logs del plano de control, consola, facturación y flujos.

## Reenvío HTTP CONNECT, SOCKS y SSH

**Mecánica:** una aplicación solicita a un proxy abrir un flujo TCP; SOCKS también puede transportar resolución de nombres y UDP según la versión; SSH reenvía flujos dentro de una sesión cifrada.

**Ventajas:** ligero; por aplicación; rápido; útil para chaining y redes segmentadas.

**Desventajas:** las aplicaciones pueden evitarlo; DNS puede filtrarse; el proxy ve los endpoints adyacentes; el estado del navegador permanece; los proxies abiertos pueden ser trampas o sistemas comprometidos.

**Procedimiento:** (1) desplegar el proxy en un host propio; (2) exigir autenticación y restringir origen/destino; (3) configurar un perfil de aplicación desechable; (4) asegurar resolución DNS remota cuando sea necesaria; (5) verificar con un endpoint DNS/HTTP propio; (6) bloquear el egress directo de la carga de trabajo; (7) inspeccionar y rotar las credenciales del proxy.

**Detección:** identificar procesos capaces de crear túneles, negociación CONNECT/SOCKS, sesiones SSH largas y destinos incompatibles con la aplicación; los logs del proxy reconstruyen los flujos.

## Proxy web de reescritura de URL y extensión proxy del navegador

**Mecánica:** un sitio obtiene un destino y reescribe enlaces/formularios mediante su propio origen, o una extensión dirige las solicitudes del navegador a un proxy. El destino ve el servicio, mientras el servicio puede ver el texto claro tras terminar TLS e inyectar o conservar contenido.

**Ventajas:** no requiere cliente para todo el sistema; rápido para navegación simple; funciona cuando no se puede instalar una VPN.

**Desventajas:** el proxy puede leer credenciales/contenido, modificar descargas y fingerprinting; scripts/WebSockets/descargas pueden evitarlo; la extensión tiene privilegios amplios; conjunto de anonimato pequeño y bloqueos frecuentes.

**Procedimiento:** (1) usar únicamente un proxy operado por la organización para pruebas autorizadas; (2) aislarlo en un navegador desechable sin cuentas personales; (3) prohibir introducir contraseñas y descargar información sensible; (4) verificar que cada subrecurso de una página propia se resuelve mediante el proxy; (5) probar WebSocket, descargas y formularios; (6) eliminar la extensión y el perfil después del uso.

**Detección:** el destino registra el proxy; el proxy/DNS empresarial y el inventario de extensiones identifican el servicio; subrecursos canary propios o de content-security/reporting revelan bypass directo; los logs del proxy vinculan la sesión del usuario con los objetivos.

## Proxy multip salto o VPN multip salto del proveedor

**Mecánica:** una entrada ve el origen mientras uno o más relays de tránsito lo separan de un exit que ve el destino.

**Ventajas:** ningún relay ordinario necesita conocer ambos extremos; el fallo o incautación de un nodo revela menos; geografía flexible.

**Desventajas:** la administración y los logs compartidos derrotan la separación; latencia; correlación temporal; más fallos y rutas DNS; la misma cuenta/pago puede unir todos los saltos.

**Procedimiento:** (1) definir qué observador elimina cada salto; (2) usar relays propios/aprobados y administrados independientemente cuando importe la separación; (3) imponer acceso solo a la entrada desde la carga de trabajo; (4) asegurar que cada relay solo pueda alcanzar el siguiente salto; (5) verificar los logs de cada capa; (6) detener cada salto y confirmar comportamiento fail-closed. Reproducir con [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detección:** correlacionar temporales/volumen de NetFlow adyacentes, handshakes de proxy repetidos e infraestructura de control común; no inferir la geografía del operador a partir del exit.

## Relay de aplicación con conocimiento dividido y OHTTP

**Mecánica:** el cliente cifra un mensaje HTTP stateless para un gateway y lo envía mediante un relay. El relay ve la IP del cliente, pero no la solicitud; el gateway ve la solicitud, pero normalmente solo la IP del relay.

**Ventajas:** partición de privacidad fuerte y auditable para solicitudes compatibles; menor coste que las redes de anonimato generales.

**Desventajas:** no permite navegación arbitraria; cookies/autenticación pueden volver a vincular; permanecen la colusión relay/gateway y el análisis de tráfico; la aplicación debe implementarlo.

**Procedimiento:** (1) seleccionar una aplicación que admita explícitamente RFC 9458; (2) verificar las claves del gateway mediante la ruta de configuración oficial; (3) evitar campos estables por usuario; (4) enviar únicamente la solicitud stateless compatible; (5) comparar logs del relay, gateway y objetivo; (6) probar rotación de claves/fallos sin fallback directo.<sup>[[2]](#references)</sup>

**Detección:** los endpoints exponen el proceso iniciador y el relay OHTTP; los gateways detectan tráfico malformado/repetido; los temporales y campos estables del payload/cuenta pueden correlacionar solicitudes.

## MASQUE CONNECT-UDP/CONNECT-IP y proxies HTTP de privacidad

**Mecánica:** Extended CONNECT de HTTP sobre TLS/QUIC transporta paquetes UDP o IP mediante un proxy. Puede implementar un túnel moderno similar a una VPN y mezclarse con HTTP/3, pero el proxy continúa siendo un observador.<sup>[[3]](#references)</sup>

**Ventajas:** multiplexación/roaming eficientes; soporta UDP o IP completo; se despliega mediante infraestructura HTTP moderna.

**Desventajas:** no es una red de anonimato; el proxy/cuenta ve origen y destinos; los fingerprints de QUIC/HTTP y las rutas conocidas son visibles para endpoints/proveedores.

**Procedimiento:** (1) usar un cliente/servicio que documente soporte para RFC 9298/9484; (2) autenticar el certificado/configuración del proxy; (3) definir rutas de destino permitidas; (4) activar DNS cifrado dentro de la ruta; (5) verificar UDP, TCP, IPv6 y failover frente a endpoints propios; (6) inspeccionar los logs de solicitudes y flujos del proxy.

**Detección:** los endpoints ven el proceso cliente y la interfaz virtual; las redes pueden clasificar QUIC/TLS sostenido hacia un proxy; los logs del proxy exponen el destino/ruta de CONNECT y las rutas asignadas.

## Tor Browser

**Mecánica:** Tor selecciona relays guard, middle y exit; el cifrado por capas limita la visión de cada relay. Tor Browser añade un navegador estandarizado diseñado para resistir fingerprinting.

**Ventajas:** gran conjunto público de anonimato; ningún relay ordinario conoce ambos extremos; desvinculación del destino sin operar servidores.

**Desventajas:** más lento; centrado en TCP; reputación/bloqueos de exits; los logins y las revelaciones identifican al usuario; permanece la correlación temporal de baja latencia.

**Procedimiento:** (1) descargar y verificar Tor Browser desde el proyecto; (2) conservar los valores predeterminados y evitar extensiones; (3) elegir un nivel de seguridad adecuado; (4) crear una identidad/sesión separada; (5) evitar cuentas identificables y documentos externos activos; (6) usar HTTPS u onion services autenticados; (7) verificar el exit únicamente con un endpoint propio.<sup>[[4]](#references)</sup>

**Detección:** las redes locales pueden identificar tráfico hacia guards conocidos salvo que se use un bridge/transport; los destinos ven exits y el comportamiento de Tor Browser; los observadores extremo a extremo correlacionan temporales/volumen.

## Tor bridges y pluggable transports

**Mecánica:** un bridge no público sustituye al guard público; obfs4, Snowflake o WebTunnel modifican el transporte del primer salto para resistir bloqueos/sondeos simples.

**Ventajas:** evita censura y oculta destinos de relays públicos evidentes; conserva el circuito Tor después de la entrada.

**Desventajas:** siguen siendo posibles los patrones de transporte y el descubrimiento del bridge; rendimiento variable; no añade protección frente a cuentas ni temporales globales.

**Procedimiento:** (1) probar primero Tor directo; (2) en los ajustes de conexión de Tor Browser seleccionar un transporte integrado compatible o solicitar un bridge oficial; (3) no usar binarios/listas aleatorios; (4) conectar y ejecutar una prueba inocua; (5) probar reconexión y reloj; (6) mantener estándar el resto de ajustes del navegador.<sup>[[5]](#references)</sup>

**Detección:** los censores usan descubrimiento de destinos, clasificación de protocolo/flujo y sondeo activo; los defensores deben distinguir el uso de circumvention del compromiso y apoyarse en el proceso/contexto del endpoint.

## VPN antes de Tor y Tor antes de VPN

**Mecánica:** VPN-before-Tor oculta el uso directo de Tor al ISP de acceso, pero expone el origen a la VPN. Tor-before-VPN entrega a la VPN tráfico posterior a Tor y a menudo una identidad estable de cliente/túnel.

**Ventajas:** elimina un observador concreto si se diseña correctamente; puede alcanzar redes que bloquean una capa.

**Desventajas:** complejidad, fingerprint inusual, fugas, conjunto de anonimato reducido y falsa confianza; Tor Project considera estas combinaciones avanzadas.<sup>[[6]](#references)</sup>

**Procedimiento:** (1) escribir el observador eliminado y el nuevo observador introducido; (2) usar un entorno desechable; (3) establecer únicamente la ruta externa prevista; (4) imponer rutas de firewall; (5) verificar DNS/IPv4/IPv6 y el orden de cada fallo; (6) comparar la visibilidad de ambos proveedores; (7) abandonar la pila si no aporta una ventaja medible.

**Detección:** los observadores local/VPN/Tor ven capas adyacentes distintas; los temporales permanecen extremo a extremo; los fingerprints de túneles anidados y las cuentas de proveedores pueden vincular sesiones.

## Onion service

**Mecánica:** el cliente y el servicio construyen circuitos Tor hasta un rendezvous, ocultando la IP del servicio y evitando un exit.

**Ventajas:** protección de la ubicación del origen y del servicio; autenticación onion extremo a extremo; sin puerto entrante público; autorización opcional del cliente.

**Desventajas:** las actualizaciones/analítica/errores pueden filtrar el origen; la clave onion es crítica; permanecen la identidad/temporales de la aplicación y el compromiso del host.

**Procedimiento:** (1) aislar la aplicación y vincularla únicamente a loopback/socket; (2) instalar Tor compatible; (3) configurar un onion service v3 siguiendo instrucciones oficiales; (4) proteger/hacer backup de su clave solo si se necesita una identidad estable; (5) añadir autorización de cliente para uso cerrado; (6) eliminar fetches de terceros; (7) verificar externamente que el origen no sea accesible.<sup>[[7]](#references)</sup>

**Detección:** los defensores del host/red encuentran el proceso/configuración de Tor y los circuitos salientes; errores de aplicación, DNS, certificados o recursos de terceros pueden revelar el origen.

## Servicios internos I2P

**Mecánica:** I2P usa túneles unidireccionales separados de entrada/salida para destinos dentro del overlay; los outproxies hacia Internet público añaden un punto de confianza.

**Ventajas:** publicación interna descentralizada; sin dependencia de exit oficial; rutas de entrada/salida separadas.

**Desventajas:** no sustituye la web general; ecosistema menor; comportamiento de peers de larga duración; el outproxy puede observar la navegación pública.

**Procedimiento:** (1) instalar desde la fuente oficial; (2) usar un contexto dedicado; (3) permitir la estabilización de integración/ancho de banda; (4) acceder a un servicio propio nativo de I2P; (5) evitar outproxies salvo necesidad explícita; (6) verificar que el apagado no deja fallback directo; (7) inspeccionar logs locales de peers y servicios.<sup>[[8]](#references)</sup>

**Detección:** las redes locales ven tráfico de peers de larga duración y bootstrap; los endpoints exponen procesos de router/aplicación; los outproxies registran los exits.

## Mixnets

**Mecánica:** paquetes de tamaño fijo, batching, retrasos, reordenamiento y cover traffic reducen la correlación temporal; los gateways conectan las aplicaciones.

**Ventajas:** mejor resistencia al análisis temporal que los proxies de baja latencia; útiles para mensajes/transacciones asíncronos.

**Desventajas:** latencia, sobrecarga de ancho de banda, despliegue menor y límites de aplicación; los metadatos del gateway/cuenta pueden persistir.

**Procedimiento:** (1) seleccionar un cliente mantenido y una aplicación compatible; (2) leer el modelo de amenazas real; (3) instalar en un compartimento separado; (4) enviar datos inocuos a un endpoint propio; (5) medir latencia/fiabilidad y ruta de respuesta; (6) probar el fallo del gateway; (7) nunca desactivar retrasos/cover traffic solo para ganar velocidad.<sup>[[9]](#references)</sup>

**Detección:** los endpoints identifican el cliente; las redes de acceso pueden clasificar gateways/cadencia de paquetes; los gateways y exits observan roles adyacentes, mientras que la correlación amplia requiere ventanas estadísticas más largas.

## Compartición anónima de archivos de GNUnet

**Mecánica:** GNUnet puede enrutar solicitudes de publicación/búsqueda/descarga mediante peers y añadir cover traffic según un nivel de anonimato. Su documentación advierte que el nivel predeterminado 1 no exige cover traffic y que un análisis de tráfico potente puede identificar el origen.<sup>[[10]](#references)</sup>

**Ventajas:** compartición anónima descentralizada y nativa de la aplicación; requisito de cover traffic configurable.

**Desventajas:** no es acceso web anónimo ordinario; coste de rendimiento/almacenamiento; limitaciones de peers y análisis de tráfico; la documentación de GNUnet VPN indica que su overlay IP no proporciona buen anonimato.

**Procedimiento:** (1) instalar una build oficial mantenida; (2) aislar un peer de prueba; (3) limitar ancho de banda/almacenamiento; (4) publicar un archivo de prueba inocuo y único con un nivel de anonimato elegido; (5) recuperarlo desde otro peer propio; (6) registrar cover traffic y latencia; (7) no afirmar que el componente VPN IP proporciona anonimato equivalente.

**Detección:** bootstrap de peers, tráfico del overlay, datastore/proceso local e identificadores de archivos; un observador amplio puede analizar el volumen frente al cover traffic.

## DNS cifrado, ODoH y ECH

**Mecánica:** DoH/DoT/DoQ cifran hacia un resolver; ODoH divide la dirección del cliente y la consulta entre proxy y resolver; ECH cifra el ClientHello/nombre del servidor TLS interno.

**Ventajas:** elimina DNS/SNI en claro para algunos observadores locales; ODoH divide el conocimiento de origen/consulta.

**Desventajas:** no es una ruta de anonimato IP; resolver/proxy/servidor conservan sus roles; la IP, temporales, volumen y endpoint del destino permanecen; el fallback puede filtrar.

**Procedimiento:** (1) elegir si el DNS pertenece al sistema operativo, aplicación o túnel; (2) activar modo cifrado estricto u ODoH compatible; (3) probar un dominio propio único; (4) capturar localmente para confirmar que no hay consultas en claro; (5) provocar el fallo del resolver y verificar el comportamiento previsto; (6) para ECH, confirmar en los diagnósticos del servidor la aceptación del ClientHello interno.<sup>[[11]](#references)</sup>

**Detección:** los logs del endpoint/resolver exponen las consultas; las redes identifican endpoints de resolvers cifrados y flujos de destino; el estado ECH es visible en endpoints/CDN aunque esté oculto en la ruta.

## Relay de privacidad con proveedores divididos

**Mecánica:** productos como iCloud Private Relay usan una entrada que conoce al cliente y un egress operado independientemente que conoce el destino, con gestión regional aproximada.

**Ventajas:** división del conocimiento con poca fricción; rapidez; protección integrada de DNS/web para tráfico compatible.

**Desventajas:** alcance limitado al producto/aplicación; el proveedor de cuenta/plataforma todavía identifica al cliente; no proporciona anonimato arbitrario del sistema; riesgos de colusión/legalidad y temporales.

**Procedimiento:** (1) confirmar las aplicaciones y tipos de tráfico compatibles; (2) activar la función en un contexto de plataforma dedicado cuando corresponda; (3) seleccionar el comportamiento regional; (4) probar Safari/DNS y aplicaciones no compatibles por separado; (5) inspeccionar la dirección del destino; (6) probar cambios/fallos de red.<sup>[[12]](#references)</sup>

**Detección:** el acceso ve la entrada; el destino ve el egress; los logs de plataforma/relay y las cuentas cubren sus respectivas capas; las aplicaciones no compatibles exponen las rutas normales.

## Navegador remoto, VDI, RDP o jump host de la organización

**Mecánica:** la navegación/ejecución ocurre en un sistema remoto; el destino ve su egress, mientras el proveedor del workspace ve la conexión del operador y el plano de control.

**Ventajas:** rápido; aísla contenido peligroso; egress controlado y estable; estado desechable y auditoría organizativa sólida.

**Desventajas:** el proveedor/administrador puede observar sesión/cuenta; canales de pantalla/clipboard/archivos filtran información; el fingerprint del navegador remoto puede ser único; no es anónimo para el propietario del workspace.

**Procedimiento:** (1) crear un workspace propiedad de la organización por engagement; (2) exigir MFA y restringir la administración; (3) desactivar o limitar clipboard/upload/download; (4) enrutar mediante egress fijo aprobado; (5) no usar IdP/sync personal; (6) exportar únicamente evidencias revisadas; (7) destruir workspace y credenciales según calendario.

**Detección:** los logs del proveedor e IdP vinculan usuario y sesión; los destinos agrupan egress/navegador del workspace; los defensores empresariales identifican protocolos de control remoto y sesiones cloud anómalas.

## Wi-Fi público o de invitados

**Mecánica:** el tráfico sale mediante el NAT del local o un túnel iniciado allí.

**Ventajas:** alta velocidad y dirección compartida no doméstica; no requiere infraestructura dedicada.

**Desventajas:** asociación con el local/DHCP/portal, cámaras, compras y evidencias de ubicación; peers/AP hostiles; términos de uso; riesgo físico.

**Procedimiento:** (1) obtener acceso ofrecido a invitados y verificar el SSID con el personal; (2) usar un dispositivo parcheado y de baja confianza; (3) desactivar sharing/auto-join y activar MAC privada; (4) completar el portal sin identidad reutilizada; (5) iniciar una ruta VPN/Tor fail-closed; (6) verificar el tráfico tethered; (7) olvidar la red.

**Detección:** el local correlaciona AP, MAC, DHCP, portal y hora; el destino ve el local/túnel; los investigadores combinan evidencia física y del dispositivo. Nunca evadir controles de acceso.

## Travel router

**Mecánica:** un router propiedad del operador se conecta al Wi-Fi/Ethernet del local y proporciona una red interna aislada con política de túnel impuesta.

**Ventajas:** aísla workstations; kill switch/DNS central; red cliente consistente; protege endpoints privilegiados de broadcasts locales.

**Desventajas:** el router se convierte en un fingerprint estable de radio/DHCP; añade superficie de ataque; portales cautivos y tethering pueden evitar el túnel.

**Procedimiento:** (1) actualizar firmware compatible; (2) establecer credenciales de administración únicas y desactivar WAN admin/WPS/UPnP; (3) configurar MAC upstream privada cuando esté permitido; (4) crear un SSID interno separado; (5) imponer política de firewall de túnel completo para DNS/IPv6; (6) probar portal, reconexión y fallo del túnel.

**Detección:** el local ve la asociación del router y la forma del tráfico; el fingerprinting RF/DHCP lo identifica; el proveedor VPN ve el origen del local.

## Celular, SIM prepago y eSIM

**Mecánica:** un módem usa acceso radio del operador y normalmente NAT del operador; una capa VPN/Tor puede cambiar el exit visible para el destino.

**Ventajas:** independiente de la red cableada/Wi-Fi local; móvil; alta velocidad; backhaul útil para drops autorizados.

**Desventajas:** el operador conoce suscriptor/eSIM, IMSI, IMEI, celdas, hora y puertos asignados; las leyes de registro varían; la coexistencia con el teléfono personal vincula dispositivos.

**Procedimiento:** (1) obtener el servicio legalmente con los datos requeridos correctos; (2) usar un módem/dispositivo separado propiedad de la organización; (3) registrarlo con el controlador del ejercicio; (4) desactivar radios/cuentas no relacionadas; (5) establecer el túnel aprobado; (6) probar si los clientes tethered realmente lo siguen; (7) verificar las suposiciones del proveedor y de retención antes del viaje.<sup>[[13]](#references)</sup>

**Detección:** registros del operador y ubicación RF; inventario empresarial USB/PCI/MDM y búsquedas de hotspots no autorizados; temporales del destino/túnel.

## Internet por satélite y abuso de downlink satelital

**Mecánica:** el servicio normal usa un terminal/proveedor registrado. El abuso histórico de DVB-S unidireccional permitía a un receptor dentro de un beam observar tráfico de downlink no cifrado dirigido a un suscriptor legítimo mientras usaba otra ruta para las solicitudes salientes.

**Ventajas:** amplia cobertura; último tramo independiente; el abuso unidireccional histórico podía atribuir erróneamente C2 a la geografía de un suscriptor.

**Desventajas:** equipos/RF/registros del proveedor; latencia y cobertura; los sistemas bidireccionales modernos son diferentes; la ruta saliente y el routing asimétrico siguen siendo evidencias.

**Procedimiento:** para acceso legal, registrar un terminal propio y tunelizar el tráfico según sea necesario. Para emular el comportamiento histórico de Turla, reproducir capturas sintéticas unidireccionales dentro de un laboratorio sin RF y probar si los analistas detectan una respuesta a un host que no realizó ninguna solicitud; no interceptar tráfico satelital real.<sup>[[14]](#references)</sup>

**Detección:** telemetría del proveedor/terminal, localización RF, flujo imposible/asimétrico, inconsistencia de RTT/routing y configuración del malware.

## Proxy residencial/móvil o proxyware consentido

**Mecánica:** un gateway backconnect asigna exits de banda ancha móvil/residencial, fijos o rotatorios. El suministro puede ser consentido, incluirse de forma engañosa o ser malicioso.

**Ventajas:** alta velocidad; elección geográfica; ASN de consumidor evita algunos bloqueos de hosting; pools grandes.

**Desventajas:** riesgo de proveniencia/consentimiento y legalidad; el broker ve al cliente; los exits infectados perjudican a víctimas; la rotación crea anomalías; es caro y poco fiable.

**Procedimiento:** usar únicamente agentes documentados y con consentimiento informado propiedad de la organización para emulación: (1) inscribir endpoints de prueba; (2) inventariar propietarios/IPs; (3) configurar un gateway; (4) rotar modos sticky/por solicitud; (5) enviar solo a un objetivo propio; (6) comparar logs del gateway/exit/objetivo; (7) eliminar todos los agentes.

**Detección:** viajes imposibles, navegador/cuenta estable a través de cambios rápidos de IP/ASN, protocolos backconnect, artefactos de proceso/red proxyware y relaciones broker/controlador.

## Relays ORB, botnet y dispositivos edge comprometidos

**Mecánica:** routers/IoT/servidores alquilados o comprometidos forman roles de acceso, tránsito y salida administrados como una flota. Varios clientes APT pueden compartirla.

**Ventajas:** reputación/geografía prestadas; exits efímeros; malla multip salto resistente; vínculo directo débil entre actor e IP.

**Desventajas:** victimización criminal; patrones de implant/controller y flota; incautación del intermediario; rendimiento irregular; registros del operador/servicio al cliente.

**Procedimiento:** nunca comprometer dispositivos reales. Usar [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) crear redes aisladas de entrada/tránsito/objetivo; (2) conectar contenedores relay propios dual-homed; (3) reenviar solo un puerto de prueba; (4) enviar una solicitud inocua; (5) verificar que el objetivo solo ve el exit; (6) rotar el exit; (7) desmontar todos los activos identificados.<sup>[[15]](#references)</sup>

**Detección:** rastrear topología, puertos/servicios, relaciones del controlador, fingerprints de implants y ciclo de vida de nodos; centralizar telemetría de configuración/flujo/integridad del edge; no equiparar la IP de salida con el actor.

## Redirector CDN, domain fronting y domainless fronting

**Mecánica:** un edge público reenvía únicamente el tráfico que coincide con una gramática; fronting coloca un SNI externo benigno y una autoridad HTTP interna diferente, o SNI vacío, cuando el intermediario lo permite.

**Ventajas:** oculta/protege el back-end; edge global rápido; mezcla el destino con un servicio compartido; cambio rápido.

**Desventajas:** la CDN ve todo el routing y tenant; muchos proveedores prohíben fronting entre tenants; artefactos de SNI/Host/proceso/flujo/cuenta; la reutilización de configuración agrupa campañas.

**Procedimiento:** reproducir únicamente en un reverse proxy propio con [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): crear un certificado/edge local, enrutar un Host discordante a un objetivo propio, registrar SNI y Host, enviar solicitudes normales/discordantes y eliminar los contenedores.<sup>[[16]](#references)</sup>

**Detección:** comparar SNI/ECH/Host/`:authority` en el endpoint o edge terminador; unir proceso iniciador, tenant/origen, gramática de solicitud y cadencia del flujo.

## DNS dinámico, DGA, fast flux y double flux

**Mecánica:** DDNS actualiza un nombre estable; DGA deriva nombres candidatos cambiantes; fast flux rota direcciones de servicio con TTL bajo; double flux también rota nameservers.

**Ventajas:** descubrimiento resistente; sustitución rápida de infraestructura; oculta el controlador detrás de muchos nodos.

**Desventajas:** DNS crea telemetría centralizada; entropía/NXDOMAIN/rotación; TTL bajo y patrones de ASN amplios; permanecen el registro y la infraestructura autoritativa.

**Procedimiento:** usar [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): servir una zona propia que devuelva direcciones RFC 5737 con TTL de cinco segundos, consultarla repetidamente, cambiar la época sintética y validar la analítica. Nunca apuntar registros de prueba a terceros.<sup>[[17]](#references)</sup>

**Detección:** respuestas/ASNs únicos en ventanas deslizantes, TTL mediano, geografía, rotación autoritativa, clusters DGA de NXDOMAIN/léxico/temporales y actividad posterior del proceso; excluir CDNs legítimas con contexto.

## Servicio web legítimo, resolver dead drop y tasking unidireccional

**Mecánica:** una publicación, repositorio, documento, objeto o feed público contiene un endpoint o tarea actual codificada. El cliente puede devolver resultados por otro canal.

**Ventajas:** servicio de alta reputación permitido; TLS; rotación del endpoint sin cambiar el binario; el tasking asimétrico dificulta la correlación simple de flujos.

**Desventajas:** identificadores estables de objeto/cuenta/API; registros del proveedor; secuencia decode/follow-on del endpoint; el contenido puede ser incautado o modificado.

**Procedimiento:** usar [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): alojar un puntero codificado en un contenedor propio, obtenerlo/decodificarlo desde un cliente de corta duración, contactar un segundo servicio propio, conservar ambos logs y desmontar.

**Detección:** correlacionar proceso inusual → lectura de objeto estable → decode → nuevo destino; aplicar hash/conservar contenido y mantener rutas completas de objetos, no solo el dominio.

## Egress serverless, contenedor efímero y cloud-NAT

**Mecánica:** funciones/jobs breves se ejecutan detrás del NAT del proveedor o de un front; el servicio lógico permanece estable mientras las instancias y direcciones rotan.

**Ventajas:** despliegue/destrucción rápidos; egress compartido a escala del proveedor; poco disco local; routing regional elástico.

**Desventajas:** tenant, rol, API, imagen, secreto, invocación, facturación y logs front-to-origin son duraderos; fingerprints de cold start/plataforma; políticas del proveedor.

**Procedimiento:** (1) usar un tenant cloud propio de la organización; (2) desplegar una función inocua que solicite únicamente un endpoint propio; (3) registrar proyecto/rol/imagen/configuración; (4) invocar en varias instancias; (5) comparar IPs objetivo con IDs de auditoría/solicitud; (6) probar la retención de logs; (7) eliminar función, roles y secretos.

**Detección:** logs de auditoría/invocación cloud, creación de roles inusual, egress compartido con gramática estable de solicitudes, reutilización de imagen/layers/secrets y correlación front-origin.

## Drop autorizado en sitio

**Mecánica:** un ordenador pequeño inventariado usa wired/Wi-Fi local y rendezvous VPN/celular saliente, presentando un origen local.

**Ventajas:** prueba realista de origen interno; alta velocidad; permite probar NAC, inventario físico y controles de egress.

**Desventajas:** descubrimiento/robo físico; evidencias de serial/MAC/USB/DHCP/PoE/RF y cámaras; la pérdida puede exponer credenciales.

**Procedimiento:** seguir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) obtener autorización escrita exacta para la colocación; (2) registrar serial, MAC, foto, ubicación y hora de recuperación; (3) usar una imagen mínima firmada y credenciales mTLS de corta duración; (4) restringir destinos/capacidades solo salientes; (5) añadir cuarentena en servidor y límites de ancho de banda; (6) probar visibilidad del SOC y respuesta ante pérdida; (7) recuperar, preservar la evidencia requerida y sanear según la política de ciclo de vida acordada. Nunca ocultarlo en un local sin consentimiento.

**Detección:** NAC/802.1X, puerto del switch/PoE/DHCP, inventario USB, estudio RF, túnel recurrente, recepción/cámaras e inspección física.

## Pivot inalámbrico de vecino cercano

**Mecánica:** un actor controla un host dentro del alcance radio del objetivo y usa credenciales Wi-Fi del objetivo para cruzar remotamente la frontera. APT28 lo usó así.<sup>[[18]](#references)</sup>

**Ventajas:** no requiere desplazamiento del operador; el objetivo ve un origen radio local; evita controles aplicados solo a la entrada desde Internet.

**Desventajas:** requiere un host cercano comprometido/propio con dos radios y acceso válido; evidencia de RADIUS/NAC/AP y del endpoint vecino; anomalías de señal/dispositivo.

**Procedimiento:** reproducir únicamente con el [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): conectar un pivot propio a los SSID de laboratorio vecino y objetivo, reenviar un solo servicio, recopilar logs de ambos AP/pivot, activar EAP-TLS/postura de dispositivo y confirmar que el segundo intento falla.

**Detección:** correlacionar identidad RADIUS, certificado/postura gestionados, dispositivo visto por primera vez, edge/señal del AP, login concurrente y presencia física; buscar endpoints cercanos con radios simultáneas, forwarding y túneles.

## Mesh comunitaria, delay-tolerant y store-and-forward offline

**Mecánica:** el tráfico atraviesa peers locales, gateways asíncronos, medios extraíbles o colas programadas en vez de una sesión interactiva de Internet.

**Ventajas:** funciona durante interrupciones/censura; la entrega retrasada/en lotes debilita la temporización simple; no hay último tramo central para comunicación local.

**Desventajas:** alta latencia; conjunto de anonimato pequeño; metadatos de custodia/físicos; peers maliciosos; los datos finalmente llegan a un gateway que los observa.

**Procedimiento:** (1) construir una mesh o cola de archivos aislada de tres nodos propios; (2) cifrar/autenticar contenido extremo a extremo; (3) eliminar rutas directas a Internet del origen; (4) retransmitir un archivo inocuo tras un retraso controlado; (5) verificar que solo el gateway contacta con el destino propio; (6) comparar custodia/temporales; (7) conservar la evidencia requerida y sanear medios/colas temporales durante el cierre aprobado.

**Detección:** actividad de archivos/procesos del endpoint, enlaces radio de peers, auditoría de medios extraíbles, periodicidad de cola/gateway e identificadores de contenido. Ventanas de correlación más largas sustituyen el análisis de flujo interactivo.

## Relay TURN y WebRTC con relay forzado

**Mecánica:** Traversal Using Relays around NAT (TURN) asigna una dirección pública de relay y transporta tráfico UDP, TCP o TLS entre un cliente y peers. Una política ICE puede forzar el uso del relay en vez de exponer un candidato directo. TURN resuelve alcanzabilidad, no anonimato general: el servidor autentica al cliente y observa asignaciones, peers, hora y volumen.<sup>[[19]](#references)</sup>

**Ventajas:** ampliamente implementado; gestiona NAT restrictivo; soporta WebRTC móvil; el peer no recibe la dirección de transporte directa del cliente cuando se impone correctamente una política relay-only.

**Desventajas:** el operador TURN ve ambos lados adyacentes; identidad de aplicación, fingerprint multimedia y signaling permanecen; relay-only consume ancho de banda y latencia; una mala configuración aún puede recopilar candidatos host o server-reflexive.

**Procedimiento:** (1) desplegar un servicio TURN propio de la organización con TLS y credenciales de corta duración; (2) restringir realms, peers, puertos, cuotas y expiración; (3) configurar la aplicación de prueba con ICE relay-only; (4) llamar a un peer propio; (5) inspeccionar `getStats()` y la captura de paquetes para confirmar que solo los candidatos relay transportaron media; (6) provocar el fallo del relay y confirmar que no existe fallback directo; (7) conservar logs de asignación para el engagement.

**Detección:** signaling, proceso del navegador y asignaciones TURN vinculan la sesión con el relay; las redes observan flujos sostenidos hacia puertos TURN o endpoints TLS; el peer ve el relay asignado. **Nodo capturado:** el estado de la aplicación y las credenciales TURN efímeras pueden revelar realm y servicio de rendezvous. Minimizar la exposición con credenciales por dispositivo y de corta duración, manteniendo la autenticación del operador solo en el controlador.

## Rendezvous solo saliente u overlay inverso

**Mecánica:** un nodo detrás de NAT inicia una conexión autenticada a un broker controlado por la organización. El operador se autentica por separado ante el broker, que autoriza un canal de administración estrecho; no se requiere port forwarding entrante ni ruta directa operador-nodo.

**Ventajas:** estable tras NAT y últimos tramos cautivos; revocación y auditoría centralizadas; los cambios de dirección del field node no requieren descubrimiento por el operador; separa limpiamente la identidad del operador de la credencial del nodo.

**Desventajas:** el broker se convierte en un punto de correlación de alto valor; los keepalives periódicos son reconocibles; un túnel amplio puede convertirse en un pivot inseguro; la pérdida del broker termina la administración.

**Procedimiento:** seguir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): emitir una identidad de dispositivo acotada, permitir solo un broker propio y servicio de administración aprobado, usar keepalive autenticado, imponer routing fail-closed, probar cambios de dirección y recuperación tras reinicio, y revocar la identidad durante el simulacro de pérdida. WireGuard documenta un persistent keepalive de 25 segundos como intervalo NAT ampliamente útil cuando realmente se necesita.<sup>[[20]](#references)</sup>

**Detección:** los logs del broker e IdP vinculan ambos lados; la red de acceso ve un destino/cadencia cifrado repetido; el inventario del endpoint muestra el agente overlay. **Nodo capturado:** asumir expuestas su clave de dispositivo, nombre del broker, direcciones del túnel y tareas almacenadas. No debe contener clave privada del operador, cuenta personal ni token reutilizable del controlador.

## Rendezvous mediante pull mailbox, message queue u object store

**Mecánica:** una carga de trabajo de campo consulta un mailbox autenticado para obtener jobs firmados y preaprobados, y publica resultados acotados. El operador escribe en la cola mediante un plano de control separado; no existe socket interactivo entre ambos.

**Ventajas:** tolera enlaces intermitentes; desacopla temporales y direccionamiento; cuotas y schemas limitan la capacidad; auditoría y revocación centralizadas sencillas.

**Desventajas:** la cadencia de polling y nombres estables de objetos/colas fingerprintan el sistema; los logs del proveedor unen productor y consumidor; control retrasado; los datos en cola capturados pueden exponer el ejercicio.

**Procedimiento:** (1) crear una cola por engagement y una identidad por dispositivo; (2) definir un schema firmado de jobs inocuos y explícitamente acotados; (3) establecer TTL de mensajes, tamaño máximo de resultados y tasa; (4) permitir al nodo extraer solo de su cola y escribir solo en su prefijo de resultados; (5) probar acumulación offline, entrega duplicada y revocación; (6) centralizar logs de acceso inmutables; (7) eliminar la cola una vez cumplidos los requisitos de retención.

**Detección:** buscar llamadas periódicas de API de un proceso inusual, rutas estables de bucket/objeto/cola, user-agent o comportamiento TLS idénticos y secuencia fetch-then-new-connection. **Nodo capturado:** la caché local puede revelar jobs pendientes y nombres de objetos; mantenerla cifrada, acotada y desechable, conservando los logs autoritativos del controlador.

## Failover de uplinks duales y migración de conexión

**Mecánica:** un field node aprobado tiene dos uplinks independientes —por ejemplo Ethernet/Wi-Fi del local y celular de la organización— y mantiene la sesión de control mediante un overlay o message broker cuando cambian las rutas. Esto es ingeniería de disponibilidad, no anonimato.

**Ventajas:** sobrevive al fallo de un proveedor, AP o portal cautivo; permite mantenimiento planificado; facilita aislar rápidamente una ruta sospechosa.

**Desventajas:** dos proveedores crean dos registros de ubicación/cuenta; el uso simultáneo facilita la correlación; fugas de ruta/DNS durante failover; permanece la evidencia de coexistencia celular.

**Procedimiento:** (1) registrar ambas interfaces y proveedores propiedad de la organización; (2) asignar prioridades de ruta y health checks deterministas hacia endpoints propios; (3) vincular DNS y administración al overlay; (4) impedir que la ruta secundaria acepte tráfico entrante; (5) desconectar cada ruta y verificar recuperación de sesión, política de origen y ausencia de acceso directo al destino; (6) alertar ante cambios no planificados; (7) documentar uso de datos y límites de roaming.

**Detección:** correlacionar el mismo certificado de dispositivo, gramática de solicitud y temporales entre ASNs; el inventario local ve ambas radios; operadores y locales conservan sus propios registros. **Nodo capturado:** ambos identificadores SIM/dispositivo y SSID conocidos pueden ser visibles; usar activos de la organización y nunca emparejar el nodo con dispositivos personales.

## APN privado de la organización o túnel celular gestionado

**Mecánica:** un APN privado del operador coloca las SIM inscritas en un dominio privado enrutado o tuneliza el tráfico a un gateway empresarial. Separa el dispositivo de la Internet móvil pública, pero no lo oculta al operador ni a la organización contratante.

**Ventajas:** direccionamiento privado estable; inscripción y política de tráfico a nivel de operador; evita exposición entrante pública; útil para appliances remotos autorizados.

**Desventajas:** suscriptor, IMSI/IMEI, celda y facturación proporcionan atribución fuerte; coste y plazo de adquisición; caída del operador/gateway; no es anónimo para el operador.

**Procedimiento:** (1) contratar el APN a nombre de la organización de evaluación; (2) permitir únicamente SIM y prefijos de gateway registrados; (3) añadir autenticación mutua en la capa de aplicación; (4) restringir la ruta APN al rendezvous y servicios de actualización; (5) probar retirada de SIM, roaming, breakout a Internet pública y revocación; (6) monitorizar registros del operador y gateway; (7) cancelar o poner en cuarentena cada SIM al cerrar.

**Detección:** inventario del operador y telemetría de celdas, flujos del gateway APN, discrepancia SIM/IMEI y registros de activos empresariales. **Nodo capturado:** la SIM y el módem identifican el contrato aunque el almacenamiento esté cifrado; la resiliencia de captura implica suspensión rápida y autorización estrecha, no negación plausible.

## Bridge inalámbrico punto a punto de largo alcance

**Mecánica:** Wi-Fi direccional u otra radio punto a punto licenciada/no licenciada conecta dos sitios aprobados por el propietario, con egress de Internet en el sitio remoto. Puede mover la ubicación IP aparente sin usar un proxy comercial.

**Ventajas:** alto throughput; independiente de operadores cableados intermedios; RF y routing controlables; útil para probar segmentación y monitorización de sitios remotos.

**Desventajas:** línea de visión, espectro, arrendador y restricciones regulatorias; emisiones RF y hardware distintivos; ambos endpoints son evidencia física; clima/energía/alineación afectan la estabilidad.

**Procedimiento:** (1) obtener permiso escrito para ambos sitios y verificar reglas de espectro/potencia; (2) inspeccionar la ruta sin transmitir fuera de los parámetros aprobados; (3) usar cifrado autenticado y una VLAN de administración; (4) restringir el bridge a un rendezvous o subnet de prueba propio; (5) probar failover, alineación, recuperación de energía y contención RF; (6) etiquetar e inventariar ambas radios; (7) retirarlas y verificar el reset de configuración tras el ejercicio.

**Detección:** estudios RF, análisis de espectro, inspección de tejados/sitios, MAC/OUI del bridge, tráfico de administración y logs de egress remoto. **Nodo capturado:** la configuración revela su peer y dominio de administración; usar credenciales únicas del ejercicio, ninguna cuenta personal de administración y revocación rápida de la clave del peer.

## Exit cooperativo o comunitario consentido

**Mecánica:** voluntarios u organizaciones asociadas operan relays conscientemente bajo una política publicada. El tráfico sale desde un pool comunitario compartido mientras la capa de coordinación gestiona abusos y revocaciones.

**Ventajas:** redes diversas no cloud; el consentimiento explícito es más seguro que proxyware; la gobernanza compartida distribuye la confianza; útil para investigación y resiliencia frente a censura.

**Desventajas:** pools pequeños y registros de miembros reducen el anonimato; los operadores del exit reciben quejas y observan metadatos; participantes maliciosos, disponibilidad variable y jurisdicciones distintas.

**Procedimiento:** (1) publicar política de uso aceptable y logging; (2) obtener opt-in informado de cada operador; (3) emitir una identidad de relay única y restringir destinos/tasas; (4) proporcionar gestión de abusos y revocación de una acción; (5) enviar durante las pruebas solo tráfico autorizado a endpoints propios; (6) medir rotación y exposición a correlación; (7) eliminar limpiamente el relay cuando termine el consentimiento.

**Detección:** registros de membresía/plano de control, certificados de relay, fingerprint de software común y comportamiento del exit identifican el pool. **Nodo capturado:** la configuración del relay puede identificar la cooperativa, pero no debe contener identidades de clientes; conservar la atribución cliente-sesión en el controlador autorizado bajo control de acceso.

## Direcciones temporales IPv6 y rotación de prefijos

**Mecánica:** las extensiones de privacidad IPv6 crean identificadores temporales de interfaz para no reutilizar una dirección estable en cada conexión saliente. Los cambios de prefijo del proveedor pueden añadir rotación, pero permanecen el prefijo delegado, el registro del suscriptor y el fingerprint de capas superiores.<sup>[[21]](#references)</sup>

**Ventajas:** reduce el tracking pasivo a largo plazo mediante un identificador de interfaz estable; integrado en sistemas operativos comunes; sin sobrecarga de relay.

**Desventajas:** no es anonimato de origen; ISP y red local aún conocen prefijo/dispositivo; DNS, cuentas y estado del navegador vinculan sesiones; la rotación complica allowlists y logs.

**Procedimiento:** (1) inspeccionar las direcciones estables y temporales actuales en un cliente propio; (2) activar el valor predeterminado de privacidad del sistema operativo, no spoofing de terceros; (3) solicitar repetidamente un endpoint IPv6 propio durante distintos ciclos de vida; (4) confirmar que los servicios entrantes se vinculan solo a las direcciones estables previstas; (5) conservar logs DHCPv6/RA/neighbor y del endpoint con hora exacta; (6) probar VPN/firewall para cada dirección IPv6.

**Detección:** correlacionar prefijo delegado, identidad de capa 2, neighbor discovery, cuenta y telemetría del endpoint en lugar de tratar una dirección como un dispositivo. **Nodo capturado:** permanecen perfiles de red e identificadores de interfaz; el direccionamiento temporal evita un identificador pasivo único, no la atribución forense.

## Transportes pluggable de Tor: Snowflake, WebTunnel, obfs4 y meek

**Mecánica:** un transporte pluggable cambia el aspecto de la primera conexión Tor o la forma de llegar a un bridge. Snowflake usa proxies WebRTC voluntarios de corta duración, WebTunnel se parece a HTTPS normal, obfs4 resiste la identificación de protocolo simple y el sondeo activo, y meek retransmite mediante infraestructura web compatible. Son transportes de circumvention hacia Tor, no capas adicionales de anonimato extremo a extremo.<sup>[[22]](#references)</sup>

**Ventajas:** útiles cuando Tor directo o los relays conocidos están bloqueados; Snowflake evita una dirección pública estable de bridge; integrados en clientes Tor mantenidos; el destino sigue recibiendo las propiedades normales de Tor.

**Desventajas:** rendimiento bajo o variable; broker/front/bridge y red local observan metadatos distintos; siguen siendo posibles los fingerprints y bloqueos; el proxy voluntario no sustituye a Tor y no debe recibir texto claro de la aplicación.

**Procedimiento:** (1) instalar y verificar Tor Browser oficial o cliente Tor compatible; (2) seleccionar el transporte integrado en Connection/Bridges; (3) conectar únicamente a una página de diagnóstico propia; (4) confirmar que la página ve un exit Tor, no el peer Snowflake/WebTunnel; (5) comparar bootstrap y rendimiento; (6) provocar fallo del transporte y confirmar que el cliente no conecta directamente de forma silenciosa; (7) volver a la configuración estándar compatible tras la prueba.

**Detección:** un censor puede combinar allowlists de destinos, comportamiento TLS/WebRTC, descubrimiento del broker y análisis de flujo; los endpoints exponen Tor y la configuración del transporte. **OPSEC resistente a captura:** usar el cliente estándar, nunca copiar estado personal del navegador y asumir que el historial del bridge/broker puede recuperarse. **Monitorización:** vigilar logs de bootstrap de Tor, intentos inesperados de DNS/conexión directa y observaciones del controlador en páginas propias; el fallo del transporte no demuestra descubrimiento.

## Refraction networking o decoy routing

**Mecánica:** un operador de red cooperante detecta una señal encubierta en tráfico aparentemente dirigido a un decoy permitido y desvía el flujo a un proxy de circumvention. El despliegue requiere infraestructura en la ruta de red; un cliente no puede crearlo simplemente seleccionando un sitio inocente.<sup>[[23]](#references)</sup>

**Ventajas:** el destino aparente puede ser difícil de bloquear sin daños colaterales; no es necesario distribuir una dirección pública de bridge; modelo útil de investigación para circumvention asistida en ruta.

**Desventajas:** participación especializada de ISP/transit; despliegue y rendimiento dependen del routing; el flujo cliente-decoy y la actividad del proxy siguen siendo visibles; un observador global o cooperante puede correlacionar temporales.

**Procedimiento:** no señalizar mediante redes no implicadas. Reproducir la arquitectura en un laboratorio aislado: (1) crear namespaces propios de cliente, router, decoy y proxy; (2) usar una solicitud de prueba benigna etiquetada; (3) permitir que el router propio redirija únicamente esa etiqueta al proxy; (4) registrar tuplas y request IDs antes/después del routing; (5) comparar flujos normales y señalizados; (6) probar falsos positivos y eliminación; (7) destruir las rutas del laboratorio.

**Detección:** los operadores de red autorizados pueden inspeccionar divergencia de routing, comportamiento inusual de ClientHello/etiquetas y discrepancias entre flujos decoy y back-end. **OPSEC resistente a captura:** un cliente de investigación solo debe contener claves de prueba y direcciones documentales. **Monitorización:** comparar decisiones firmadas del router de laboratorio con llegadas al proxy; no sondear proveedores de tránsito de producción para saber si detectaron la señalización.

## Gateway content-addressed o recuperación desde peer en caché

**Mecánica:** un gateway HTTP recupera un identificador de contenido IPFS (CID), posiblemente desde su caché o peers, y devuelve el contenido verificable al cliente. El editor original puede ver el gateway u otros peers en vez del lector final; el gateway ve la IP del lector y el CID solicitado. La recuperación nativa peer-to-peer expone al cliente a peers y participantes DHT/routing.<sup>[[24]](#references)</sup>

**Ventajas:** caches separan editor y lector; el contenido inmutable se verifica mediante hash; los datos replicados sobreviven a un host; los clientes HTTP no necesitan stack peer nativo.

**Desventajas:** los CID públicos y logs del gateway revelan intereses; el primer timing de recuperación puede correlacionar editor y lector; contenido web malicioso y riesgos same-origin de rutas; los gateways públicos son best-effort y prohíben abusos.

**Procedimiento:** (1) publicar un archivo de prueba inocuo en un swarm IPFS privado propio o gateway propio; (2) registrar su CID; (3) recuperarlo mediante un gateway HTTP propio separado usando aislamiento por subdominio; (4) verificar los bytes contra el CID; (5) repetir tras la caché; (6) comparar logs de editor, peer y gateway; (7) despin y eliminar el contenido de prueba al terminar la retención.

**Detección:** los gateways registran origen/CID; las conexiones DHT y peer revelan la recuperación; el historial del endpoint y los hashes de archivos identifican el contenido. **OPSEC resistente a captura:** no almacenar la clave privada de publicación en un field client de solo lectura y cifrar contenido sensible antes de addressarlo. **Monitorización:** alertar ante pinning inesperado, cambios en el conjunto de peers, solicitudes CID fuera de allowlist o avisos de la cuenta del gateway.

## Servicio de Private Information Retrieval

**Mecánica:** Private Information Retrieval (PIR) permite a un cliente obtener un registro de una base de datos ocultando criptográficamente el índice seleccionado al servidor bajo un modelo de amenazas single-server o multi-server declarado. Protege la selección de consulta para un dataset acotado; no es acceso web general ni anonimato IP.<sup>[[25]](#references)</sup>

**Ventajas:** privacidad de consulta específica de la aplicación; modelo de filtración medible; útil para directorios de claves, blocklists o bases públicas pequeñas; reduce la necesidad de revelar términos exactos.

**Desventajas:** sobrecarga de cómputo/ancho de banda; el servidor conoce hora/IP de conexión salvo que se combine con relay; versión del dataset, tamaño de respuesta y estado de aplicación pueden separar usuarios; madurez de implementación variable.

**Procedimiento:** (1) desplegar una implementación PIR auditada contra una base sintética propia; (2) publicar versión y parámetros del dataset; (3) recuperar varios índices usando tamaños idénticos de solicitud; (4) verificar localmente la corrección; (5) comparar logs del servidor y confirmar que el índice está ausente; (6) probar respuestas maliciosas/truncadas y discrepancia de versión; (7) documentar el supuesto exacto de privacidad en lugar de llamarlo navegación anónima.

**Detección:** las redes ven uso y volumen del servicio; la telemetría del endpoint expone el cliente y el uso del registro final; un servidor comprometido puede manipular datasets o temporales. **OPSEC resistente a captura:** conservar en el cliente únicamente parámetros públicos y una caché acotada. **Monitorización:** validar raíces firmadas del dataset, formas fijas de solicitud, cambios de tasa de errores y rotaciones de claves del servidor.

## Fetcher, preview o servicio de rendering server-side acotado

**Mecánica:** un servicio remoto obtiene o renderiza una URL y devuelve una captura, metadatos o contenido saneado. El destino ve la dirección del fetcher; el servicio ve solicitante, URL y resultado. Abusar de bots de link-preview, scanners de seguridad o fetchers de URL de terceros no es uso autorizado de proxy.

**Ventajas:** aísla contenido activo de la workstation; el destino recibe un fingerprint controlado del fetcher; permite imponer límites de tipo, tamaño, destino y rendering; entorno de ejecución desechable.

**Desventajas:** el servicio tiene conocimiento completo de la solicitud; registros de cuenta/API/facturación; riesgo de SSRF y exfiltración; scripts, autenticación y sitios interactivos pueden no funcionar; las URLs únicas correlacionan solicitante y fetch.

**Procedimiento:** (1) desplegar un fetcher propio de la organización con allowlist estricta de dominios de prueba propios; (2) bloquear direcciones privadas, link-local, metadata y redirecciones a direcciones no aprobadas; (3) limitar métodos, redirecciones, bytes y tiempo de rendering; (4) eliminar credenciales/cookies; (5) enviar una URL propia; (6) comparar logs de solicitante, fetcher y objetivo; (7) destruir la instancia de rendering y conservar la auditoría central según la política.

**Detección:** el objetivo ve ASN/fingerprint del servicio; los logs del proveedor/controlador vinculan solicitante y URL; el proceso del endpoint y las llamadas API muestran el envío. **OPSEC resistente a captura:** usar un único token de proyecto de corta duración sin autoridad sobre destinos arbitrarios. **Monitorización:** alertar ante denegaciones de allowlist, violaciones de redirección, fetches sin job ID del controlador y avisos de abuso del proveedor.

## Pool de rendezvous Anycast

**Mecánica:** múltiples nodos controlados por la organización anuncian o ponen delante una misma dirección de servicio estable, y el routing selecciona una instancia cercana. Anycast mejora la disponibilidad y oculta un back-end individual al cliente, pero el operador controla todas las instancias y la dirección de servicio es estable.<sup>[[26]](#references)</sup>

**Ventajas:** ingreso regional resistente; no requiere reconfigurar field nodes si falla una instancia; distribución de DDoS/carga; la política central puede mover sesiones entre nodos conocidos.

**Desventajas:** los registros de BGP/CDN y proveedor identifican a la organización; los cambios de ruta pueden romper sesiones stateful; la monitorización varía según la ubicación del cliente; una dirección estable se bloquea o agrupa fácilmente por reputación.

**Procedimiento:** usar un proyecto propio compatible con el proveedor o un laboratorio de routing aislado: (1) desplegar dos endpoints de health autenticados e idénticos; (2) exponer una dirección de servicio documentada; (3) mantener el estado de sesión en el broker, no en el edge; (4) retirar un nodo y verificar la reconexión; (5) probar consistencia de certificado, política y logs; (6) alertar ante origen/región no autorizados; (7) retirar anuncios y credenciales al cerrar.

**Detección:** BGP/RPKI/historial, tenancy del proveedor, certificados y comportamiento idéntico del servicio identifican el pool. **OPSEC resistente a captura:** un edge solo contiene la identidad regional del servicio y ninguna clave del operador o de inscripción de flota. **Monitorización:** sondear cada región desde monitores autorizados, comparar origen de ruta y digest de configuración, y tratar un origen inesperado como incidente.

## Migración QUIC y continuidad Multipath TCP

**Mecánica:** los Connection IDs de QUIC pueden mantener una sesión viva durante rebinding NAT o cambios de dirección; Multipath TCP puede transportar un mismo flujo fiable mediante varios subflujos. Mejoran la continuidad entre Wi-Fi/celular, pero exponen las rutas antigua y nueva al peer común y pueden facilitar la correlación entre rutas.<sup>[[27]](#references)</sup>

**Ventajas:** recuperación rápida durante cambios de uplink; la sesión de aplicación no debe reiniciarse; MPTCP puede combinar resiliencia y throughput; valioso para field nodes aprobados.

**Desventajas:** no es anonimato; el peer ve migración/subflujos; los identificadores de conexión y el tráfico simultáneo vinculan rutas; el soporte de middleboxes/operadores varía; los registros duplicados de proveedores aumentan la exposición.

**Procedimiento:** (1) activar el transporte compatible solo entre un field client propio y un rendezvous; (2) autenticar la aplicación independientemente de la IP; (3) comenzar una transferencia acotada por Wi-Fi aprobado; (4) cambiar a celular de la organización; (5) confirmar validación de ruta, integridad y ausencia de fallback directo/en claro; (6) probar timeout idle y retorno; (7) conservar en el broker los registros de cada transición.

**Detección:** el peer observa directamente migración de dirección o subflujos MPTCP; los proveedores de acceso ven su parte; Connection IDs, identidad TLS y temporales unen ambos. **OPSEC resistente a captura:** almacenar solo material de sesión vinculado al dispositivo y expirar rápidamente el estado reanudable. **Monitorización:** alertar ante cambios de ruta imposibles, redes simultáneas no aprobadas, tormentas de migración y reanudación después de cuarentena.

## Egress de runner CI/CD gestionado o automatización efímera

**Mecánica:** un workflow propiedad de la organización ejecuta una comprobación de red acotada en un runner alojado. El destino ve una dirección del runner cloud, mientras la plataforma conserva la atribución de repositorio, actor, workflow, token, logs y facturación. Es ejecución remota con egress atribuible, no anonimato frente al proveedor.<sup>[[28]](#references)</sup>

**Ventajas:** entorno limpio desechable; definición de job reproducible; sin conexión entrante; útil para comprobaciones de disponibilidad distribuidas geográficamente; auditoría sólida del controlador.

**Desventajas:** plataforma y organización identifican al iniciador; tokens amplios y pull requests no confiables son peligrosos; reputación IP compartida; logs/artifacts pueden conservar secretos o datos del objetivo.

**Procedimiento:** (1) crear un repositorio privado y environment de la organización para la evaluación; (2) permitir solo jobs benignos, fijos y aprobados manualmente contra endpoints propios; (3) usar permisos de workflow mínimos y de solo lectura, sin secretos de producción; (4) ejecutar la comprobación; (5) comparar registros del workflow, proveedor y objetivo; (6) verificar que los artifacts no contengan credenciales; (7) eliminar el token del environment y conservar la auditoría necesaria.

**Detección:** los logs de auditoría del proveedor y del workflow proporcionan atribución directa; los objetivos identifican ASNs/rangos del runner y gramática estable de solicitudes. **OPSEC resistente a captura:** nunca colocar secretos de field device, firma, wallet o administrador cloud en variables del runner. **Monitorización:** exigir aprobación de branch/environment y alertar ante cambios de workflow, ejecución desde forks, lecturas de secretos y destinos inesperados.

## Primer salto local no IP hacia un gateway propio

**Mecánica:** Bluetooth mesh, Wi-Fi Aware/Direct, radio de baja potencia o enlace serial/óptico transporta mensajes acotados desde un sensor cercano a un gateway de Internet aprobado por el propietario. El dispositivo de campo no tiene ruta a Internet; el gateway es el único egress. El alcance radio y los límites de protocolo hacen que sea telemetry/store-and-forward, no Internet interactiva anónima.

**Ventajas:** elimina la pila de Internet y credenciales del dispositivo de campo más pequeño; bajo consumo; el gateway centraliza la política; puede cruzar zonas muertas temporales.

**Desventajas:** descubrimiento RF/físico, pairing e identificadores de dispositivo; ancho de banda y alcance reducidos; el gateway vincula todos los mensajes; las restricciones de espectro y cifrado varían; una captura puede exponer datos en cola.

**Procedimiento:** (1) obtener aprobación del sitio y espectro; (2) emparejar un sensor propio con un gateway propio usando claves únicas; (3) definir tipos de mensajes firmados y de tamaño fijo, TTL y tasa; (4) dar al sensor ninguna ruta IP predeterminada; (5) permitir que el gateway reenvíe solo a un collector propio; (6) probar replay, pérdida de alcance y caída del gateway; (7) inventariar y recuperar ambos dispositivos.

**Detección:** estudio RF, base de datos de pairing, inspección física y logs de proceso/flujo del gateway revelan la ruta. **OPSEC resistente a captura:** el sensor contiene únicamente su clave pairwise y cola cifrada acotada, nunca credenciales de operador, Wi-Fi, celular o controlador. **Monitorización:** alertar ante nuevos peers, rollback de secuencia, fallo de clave, tasa RF inusual y mensajes que lleguen mediante un gateway no registrado.

## Matriz de exposición ante captura/compromiso

Esta tabla aplica una comprobación de resiliencia ante captura a cada familia anterior. “Minimizar” significa reducir secretos y blast radius en activos autorizados; nunca significa borrar evidencia ni ocultarse de una investigación.

| Familia de técnica | Lo que puede revelar un endpoint/relay capturado | Control autorizado mínimo |
|---|---|---|
| NAT/CGNAT, Wi-Fi público, travel router | redes conocidas, historial DHCP/portal, MACs, peer del túnel | dispositivo separado de la organización; MAC privada cuando sea compatible; sin cuentas personales; inventario del controlador |
| VPN, VPS, HTTP/SOCKS/SSH, multip salto | proveedores/hostnames, claves, rutas, logs y salto adyacente | una identidad por engagement; TTL corto; rutas estrechas; revocación en broker; sin claves maestras |
| OHTTP/ODoH, MASQUE, relay dividido | configuración relay/gateway, identificadores de aplicación y solicitudes en caché | minimizar identificadores del payload; fijar configuración aprobada; caché acotada; fallback directo prohibido |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software instalado, material bridge/onion, estado local e historial de peers | cliente estándar; claves de servicio separadas; estado mínimo cifrado; rotar identidad de servicio comprometida |
| Navegador remoto/VDI/jump host | token del workspace, clipboard/archivos y tenant remoto | MFA resistente a phishing en gateway; canales de transferencia desactivados; revocación rápida de sesión |
| Celular, satélite, APN privado | SIM/eSIM, identidad IMEI/terminal, proveedor y ubicación aproximada | contrato de organización; sin coexistencia personal; política APN/overlay estrecha; procedimiento de suspensión del proveedor |
| Proxy residencial/cooperativo, laboratorio ORB | identidad del agente, controlador/siguiente salto, tráfico en caché | solo nodos consentidos/propios; agente firmado; credencial por nodo; mapeo de participantes en el controlador |
| CDN/fronting, fast flux, serverless | tenant/origen/configuración, tokens API, referencias de despliegue y facturación | proyecto dedicado; rol de mínimo privilegio; token de despliegue efímero; auditoría del proveedor centralizada |
| Dead drop, mailbox pull, store-and-forward | nombres de objetos, cola, jobs/resultados en caché y datos de custodia | jobs acotados firmados; TTL; caché cifrada; identidad de productor separada; logs de servidor inmutables |
| Drop, vecino cercano, bridge de largo alcance | serial/radio/SSID/peer, clave del dispositivo, artefactos de colocación física | colocación escrita; identidad única; sin secreto del operador; telemetría de estado/tamper; revocar y recuperar |
| TURN, overlay inverso, uplink dual | realm/broker, credencial del dispositivo, peer/ruta y perfiles de uplink | servicio estrecho solo saliente; credencial efímera; login del operador independiente; rutas fail-closed |
| Direccionamiento temporal IPv6 | perfiles, historial de prefijo y estado endpoint/aplicación | tratarlo solo como anti-tracking; conservar logs de red; combinar con compartimentación del endpoint |
| Transporte pluggable/refraction lab | configuración bridge/broker/decoy, estado Tor y claves de investigación | cliente estándar o laboratorio aislado; sin estado de navegador personal; sin señalización de producción |
| IPFS/PIR/fetcher | CID/consulta solicitados, contenido en caché, token del gateway/servicio | caché cifrada acotada; solo parámetros públicos; token de servicio efímero con allowlist |
| Anycast/QUIC/MPTCP | nodos del servicio, Connection IDs, estado reanudable y rutas conocidas | solo identidad regional; reanudación breve; revocación central de ruta/sesión |
| Runner CI/CD gestionado | repositorio, workflow, token del proveedor, logs y artifacts | workflow de mínimo privilegio; sin secretos de producción/campo/wallet; aprobación de environment |
| Salto local no IP | peer radio, clave pairwise, mensajes en cola e identidad del gateway | clave pairwise única; schema fijo; sin credenciales Wi-Fi/celular/operador |

## Monitorización de posible descubrimiento para cada familia

Ninguna prueba del lado del cliente demuestra que un investigador o defensor esté observando. Monitorizar cambios en sistemas propiedad del engagement, corroborarlos con el controlador/cliente y detenerse en vez de sondear a los observadores. Las filas siguientes cubren todas las técnicas anteriores; combinarlas con los [estados de alerta y procedimiento de respuesta de field nodes](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Técnicas cubiertas | Señales seguras del lado del controlador | Condición de cuarentena/parada |
|---|---|---|
| NAT/CGNAT, Wi-Fi público/invitados, travel router, celular/eSIM, satélite, APN privado | lease/sesión de portal/operador, tupla pública, cambio de BSSID/celda/ruta, aviso del proveedor | red/SIM/dispositivo no aprobado, reubicación inexplicada o escalado del proveedor/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multip salto, proxy residencial/cooperativo | autenticación del peer, estado del túnel, fugas de ruta/DNS, nuevo evento admin/API, queja | credencial duplicada/robada, administrador desconocido, fallback directo o egress fuera de alcance |
| OHTTP/ODoH/ECH, MASQUE, relay dividido, TURN | asignación relay/gateway, versión de clave/configuración, conexión directa no compatible, tasa de error/replay | discrepancia de clave, fallback directo, realm/peer desconocido o aviso de abuso |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | estado de bootstrap, fallo de circuito, descriptor onion/salud del servicio y página canary propia | cruce con cuenta personal, conexión inesperada no Tor o clave de servicio comprometida |
| I2P, mixnet, GNUnet, mesh/store-forward, salto local no IP | conjunto de peers, antigüedad/secuencia de cola, llegada al gateway, asociación radio y hash del contenido | peer/gateway desconocido, rollback de secuencia, contenido no autorizado o falta de registro de custodia |
| Navegador remoto/VDI/jump host, runner CI/CD, serverless | sesión IdP, cambio de workflow/imagen/configuración, uso de token nuevo, artifact/export y auditoría cloud | login/cambio de workflow desconocido, lectura de secretos, destino inesperado o escalado de rol/proyecto |
| Laboratorio ORB, fast flux/DGA, CDN/fronting, dead drop/mailbox pull | inventario de nodos propios, acceso DNS/edge/objeto, grafo del controlador, firma del job y TTL | nodo/origen/escritor de objeto desconocido, job sin firma/repetido, escape de topología del laboratorio |
| Drop/vecino cercano/bridge largo/overlay saliente/uplink dual | heartbeat firmado, hash de boot/configuración, estado del enclosure, contexto AP/switch, identidad duplicada | nodo movido/abierto, boot/hash/ruta inesperado, uso de sentinel o informe del sitio |
| Direcciones temporales IPv6, migración QUIC, MPTCP | prefijo delegado, Connection ID/subflujos, validación de ruta y sesión del broker | migración imposible, rutas simultáneas no aprobadas o reanudación tras revocación |
| IPFS/cache, PIR, fetcher acotado | CID/forma de consulta/versión raíz, cambio de peer/gateway, redirección/denegación de allowlist | pinning/consulta/destino inesperado, raíz de dataset sin firma o aviso de abuso |
| Laboratorio refraction/decoy routing, rendezvous Anycast | decisión de desvío propia, llegada al proxy, origen BGP/RPKI, digest de configuración regional | señal en ruta de producción, origen de ruta desconocido, inconsistencia regional/configuración |

## Elección y prueba de una ruta

1. Nombrar el observador que se quiere eliminar y los datos que se quieren ocultar.
2. Seleccionar la familia menos compleja que lo elimine.
3. Dibujar los observadores de origen, entrada, tránsito, salida, DNS, cuenta y pago.
4. Usar una identidad separada de endpoint/aplicación.
5. Verificar bypass de IPv4, IPv6, DNS, WebRTC/aplicación y visión del destino.
6. Romper cada salto y confirmar que el fallo es cerrado.
7. Comparar los logs de cada componente bajo control.
8. Registrar los vínculos residuales temporales, del proveedor, del endpoint y físicos.

## References

- [1] [EFF — Elegir la VPN adecuada para usted](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — HTTP Oblivious](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Protecciones de Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Desbloquear Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Usar Tor Browser con una VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Descripción general de los onion services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Modelo de amenazas](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Modelo de amenazas](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Compartición anónima de archivos](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — DoH Oblivious](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Seguridad de iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Registro obligatorio de SIM](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — El ataque del vecino más cercano](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Inicio rápido: persistencia para NAT y traversal de firewall](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Extensiones de direcciones temporales para la autoconfiguración de direcciones sin estado en IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Transportes pluggable y bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — investigación de proyecto y despliegue](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Conceptos de HTTP Gateway y ciclo de vida de solicitudes](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Descripción general de Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operación de servicios Anycast](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — Migración de conexiones QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Referencia de runners alojados en GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
