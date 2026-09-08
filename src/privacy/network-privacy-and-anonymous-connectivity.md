# Privacidad de red y conectividad anónima

{{#include ../banners/hacktricks-training.md}}

La privacidad de red es una decisión de enrutamiento, no una identidad completa. Selecciona una ruta preguntando quién no debería poder vincular **origen**, **destino**, **contenido** y **tiempo**.

Para el inventario normalizado —`Pros`, `Cons`, `Procedure` paso a paso y `Detection` para cada familia de rutas de acceso— comienza con el [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Esta página amplía las opciones comunes que pueden implementarse.

## Lo que cada observador suele poder ver

| Ruta | Red local / ISP | Intermediario | Destino | Limitación principal | Velocidad relativa |
|---|---|---|---|---|---|
| HTTPS directo | Metadatos del origen, destino, tiempo y volumen | El hosting/CDN ve la conexión | IP de origen, datos del navegador/aplicación | No ofrece privacidad de la IP de origen | La más rápida |
| VPN comercial | Origen conectado a la VPN; no suele ver los metadatos del destino | La VPN ve los metadatos del origen y destino | IP de salida de la VPN | Un proveedor se convierte en un punto de correlación | Normalmente rápida |
| VPN/VPS autoalojada | Origen conectado al VPS | Registros del host/cuenta/pagos/control plane | IP de salida del VPS | Es fácil atribuirla al servidor/cuenta alquilados | Normalmente rápida |
| Tor Browser | Origen conectado a Tor/bridge; tiempo/volumen | Cada relay ve una parte limitada | Salida de Tor, datos del navegador | Más lenta; riesgos de cuenta/endpoint/correlación | Moderada/lenta |
| Tails/Whonix | Ruta Tor similar, con límites de enrutamiento más estrictos | Las mismas limitaciones de Tor | Salida de Tor/datos de la aplicación | Los errores operativos y el host/hardware siguen siendo relevantes | Moderada/lenta |
| Wi-Fi público de invitados + HTTPS | El establecimiento ve el dispositivo local/tiempo y los destinos | El ISP del establecimiento ve los metadatos | IP pública de invitados | Correlación física/captive portal/dispositivo | Rápida/variable |
| Hotspot celular | El operador ve el abonado/dispositivo/ubicación y los destinos | VPN/Tor, si se utiliza | IP de salida del operador, VPN o Tor | La suscripción móvil y la ubicación son identificadores duraderos | Rápida/variable |
| Mixnet | El acceso ve el uso de la mixnet; tiempo/volumen | Varios nodos de mezcla | Gateway/salida | Ecosistema emergente; coste de latencia y ancho de banda | La más lenta |

HTTPS protege el contenido en tránsito, pero no todos los metadatos. EFF señala que el dominio, la hora y el tamaño del tráfico pueden seguir siendo visibles para los intermediarios aunque las rutas de las páginas, las credenciales y los mensajes estén cifrados.<sup>[[1]](#references)</sup>

## VPN: privacidad rápida con confianza concentrada

Una VPN resulta útil para ocultar los metadatos del destino al ISP de acceso, proteger el primer salto en una red no confiable, presentar una dirección de salida estable para un engagement o acceder a una red privada. **No** hace anónimo al usuario. La VPN ve la conexión de origen y puede observar los metadatos del destino; las cuentas, cookies, GPS, fingerprints y datos de pago permanecen.<sup>[[1]](#references)</sup>

### Lista de comprobación para evaluar proveedores

1. **Propiedad y jurisdicción:** identifica la entidad legal, la empresa matriz, los países donde opera, los subcontratistas de infraestructura y los procesos legales aplicables.
2. **Datos recopilados:** distingue entre datos de cuenta/facturación, IP de origen, marcas de tiempo de conexión, ancho de banda, telemetría de fallos, consultas DNS y registros de destino. «Sin registros de navegación» no significa «sin datos».
3. **Retención y eliminación:** busca duraciones precisas y comprueba si las copias de seguridad, los sistemas antifraude y los encargados del tratamiento siguen el mismo calendario.
4. **Evidencias:** prioriza auditorías públicas con alcance, fecha, hallazgos y correcciones; clientes reproducibles/open source; informes de transparencia; e incidentes documentados.
5. **Protocolo y cliente:** WireGuard, OpenVPN u otro protocolo revisado y mantenido; actualizaciones automáticas; gestión de DNS e IPv6; kill switch; y pruebas de leak por plataforma.
6. **Modelo de negocio:** entiende cómo se financia un servicio gratuito o subvencionado. La presencia en una app store por sí sola no demuestra un funcionamiento confiable.
7. **Adecuación del pago:** un método de pago alternativo puede reducir la información de facturación revelada a la VPN, pero no elimina la IP de origen observada en cada conexión.

### Configurar y verificar una VPN

1. Instala el cliente firmado del proveedor/organización desde su fuente oficial.
2. Selecciona **full tunnel** salvo que una ruta documentada deba evitarlo. El split tunneling crea rutas de correlación y leak.
3. Activa el comportamiento fail-closed/always-on y bloquea el tráfico durante la reconexión.
4. Envía el DNS a través del túnel y prueba IPv4 e IPv6. Desactiva un protocolo solo si no puede tunelizarse de forma segura y se acepta la pérdida de funcionalidad.
5. Prueba suspensión/reactivación, cambio de red, inicio de sesión en captive portal, fallo del túnel y tethering mediante hotspot. NCSC advierte que los clientes conectados mediante tethering pueden evitar la VPN del teléfono en algunas plataformas.<sup>[[2]](#references)</sup>
6. Utiliza un endpoint de prueba controlado por la organización para registrar la IPv4, IPv6, el resolver DNS y el tiempo de conexión observados. No expongas un engagement sensible a sitios aleatorios de «leak test».
7. Repite las pruebas después de cambios en el cliente, el sistema operativo, la red o las políticas.

## Tor Browser: mayor unlinkability web

Tor construye un circuito a través de varios relays para que ningún relay individual conozca normalmente tanto el origen como el destino. El destino ve una salida de Tor en lugar de la IP del usuario; la red local normalmente ve una conexión Tor.<sup>[[3]](#references)</sup> Tor está diseñado para aplicaciones TCP de baja latencia, por lo que es más lento y no puede garantizar protección contra un adversario capaz de correlacionar ambos extremos.<sup>[[4]](#references)</sup>

### Flujo de trabajo seguro con Tor Browser

1. Descarga Tor Browser únicamente desde Tor Project o un mirror oficial y verifica la firma cuando sea posible.
2. Usa **Tor Browser**, no un navegador normal apuntando a un puerto SOCKS de Tor. Los navegadores comunes pueden filtrar DNS/WebRTC y estado identificable.<sup>[[5]](#references)</sup>
3. Mantén el tamaño, las fuentes, las extensiones y la configuración de privacidad predeterminados. Los add-ons adicionales pueden hacer que el navegador sea más único.<sup>[[6]](#references)</sup>
4. Elige el nivel de seguridad **Safer** o **Safest** cuando la mayor incompatibilidad sea aceptable.
5. Utiliza un bridge cuando Tor directo esté bloqueado o cuando las IP de los relays normales creen una visibilidad local inaceptable. Los bridges dificultan el reconocimiento inmediato, pero no eliminan el análisis de tráfico.<sup>[[7]](#references)</sup>
6. No inicies sesión en una cuenta identificable, no proporciones información identificable ni abras documentos activos descargados en una aplicación externa conectada a la red.
7. Utiliza una sesión/contexto separado para cada identidad. «New circuit» no equivale a borrar la identidad del navegador/aplicación; utiliza **New Identity** o reinicia el entorno aislado según corresponda.
8. Prioriza HTTPS autenticado o un onion service autenticado. Una salida de Tor puede observar tráfico HTTP no cifrado.

### Tor junto con una VPN

Combinar ambos no es automáticamente más seguro. Una VPN antes de Tor puede ocultar las conexiones directas a los relays de Tor frente a un ISP, mientras la VPN ve el origen; Tor antes de una VPN proporciona a la VPN una visión estable de la actividad posterior a Tor y puede reducir el anonymity set. Una configuración incorrecta puede introducir leaks. Tor Project recomienda estas combinaciones únicamente para threat models avanzados y explícitos.<sup>[[8]](#references)</sup>

## Wi-Fi público y de invitados

El HTTPS moderno significa que los vecinos pasivos normalmente no pueden leer contenido web correctamente cifrado, pero el Wi-Fi de invitados no es anonimato. El establecimiento puede registrar las horas de asociación, los identificadores del dispositivo, los datos del captive portal, los destinos y los detalles DHCP; las cámaras, las compras, el transporte y la observación física pueden identificar al usuario. Un hotspot falso con un nombre similar también puede capturar credenciales del portal o manipular tráfico no cifrado.<sup>[[9]](#references)</sup>

### Flujo de trabajo legítimo para una red de invitados

1. Utiliza únicamente una red ofrecida a los invitados o una cuyo propietario haya autorizado explícitamente su uso. Pregunta al personal por el SSID exacto y el procedimiento del portal.
2. Actualiza el endpoint y el travel router antes de llegar. Desactiva el uso compartido de archivos/impresoras, el descubrimiento entrante, la conexión automática y la búsqueda de redes recordadas.
3. Activa la dirección Wi-Fi privada/aleatorizada del sistema operativo. Los sistemas Apple actuales pueden usar direcciones rotativas en redes abiertas/débiles; la aleatorización moderna de Android suele ser persistente por SSID. Esto reduce un único identificador local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prioriza un travel router controlado por la organización o un dispositivo puente de baja confianza entre una workstation privilegiada y la red de invitados. Esto centraliza la política de firewall/VPN, pero no oculta el router al establecimiento.<sup>[[12]](#references)</sup>
5. Completa el captive portal únicamente mediante el dispositivo/navegador designado de baja confianza. Nunca introduzcas credenciales personales o reutilizadas en un contexto supuestamente anónimo. Cierra el navegador del portal una vez establecida la conectividad.
6. Inicia una VPN full-tunnel o Tor antes de realizar actividades sensibles y confirma el comportamiento fail-closed.
7. Olvida la red después de usarla y revisa la política de la cuenta del portal y de retención de datos.

{% hint style="danger" %}
Crackear el Wi-Fi de un vecino, evadir un portal, utilizar credenciales de invitados filtradas, clonar el acceso de otro invitado u ocultar una Raspberry Pi en una cafetería son actividades no autorizadas, no una técnica de privacidad. Las alternativas seguras son una red de invitados legítima, un sitio aprobado por el cliente o un drop node documentado, instalado y recuperado con el consentimiento escrito del propietario.
{% endhint %}

## Travel routers

Un travel router puede aislar una workstation de broadcasts locales hostiles, aplicar un firewall, proporcionar un SSID interno consistente y reconectar automáticamente una VPN. **No** es anónimo: el upstream ve su identidad de radio y el tiempo del tráfico, y el proveedor de VPN ve el origen del túnel.

- Utiliza firmware compatible de OpenWrt/vendor y elimina los servicios no utilizados.
- Administra mediante Ethernet o un SSID de gestión dedicado con una contraseña única.
- Desactiva la administración desde WAN, UPnP, WPS, el uso compartido de archivos y el tráfico entrante no solicitado.
- Utiliza una MAC WAN aleatorizada/privada únicamente cuando sea compatible y esté permitido.
- Aplica la política de VPN en el router, incluido DNS e IPv6, y bloquea la salida cuando falle el túnel.
- No supongas que un hotspot telefónico tuneliza los dispositivos conectados mediante tethering a través de la VPN del teléfono; pruébalo.

## Redes celulares, SIM y eSIM

La red celular es conveniente, pero no anónima. Los operadores mantienen identificadores del abonado/dispositivo y la ubicación derivada de la conexión a la red; una eSIM sigue siendo una suscripción móvil. El prepago no significa de forma fiable que no esté registrado: los requisitos varían según el país y cambian.<sup>[[13]](#references)</sup>

Operativamente:

- Utiliza un dispositivo separado y compatible para reducir la exposición de datos personales, no para crear un abonado ficticio.
- No lleves continuamente un dispositivo «separado» junto a un teléfono personal si la co-ubicación forma parte del threat model.
- Desactiva las funciones celulares, Wi-Fi, Bluetooth y de ubicación que no utilices; apagar el dispositivo proporciona un límite de radio más fuerte que los interruptores de la interfaz.
- Coloca el tráfico sensible dentro de la ruta VPN/Tor aprobada, reconociendo que el operador sigue conociendo la ubicación de la suscripción/dispositivo y el endpoint del túnel.
- Verifica las normas actuales de registro y retención con el regulador nacional o un asesor legal local; no dependas de listas online de «países con SIM anónimas».

## Metadatos DNS y TLS

- **DoH/DoT/DoQ** cifran el DNS entre el cliente y el resolver, evitando la lectura o modificación local simple, pero el resolver sigue viendo las consultas y los identificadores de transporte. Trasladan la confianza; no proporcionan anonimato.<sup>[[14]](#references)</sup>
- **ODoH** añade un proxy para que el resolver no tenga que conocer la IP del cliente, suponiendo que el proxy y el destino no coludan. El análisis de tráfico queda explícitamente fuera del alcance.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** puede proteger el nombre interno del servidor en un handshake TLS cuando el cliente, el DNS y el servidor lo admiten. La IP de destino, el tiempo, el volumen y el endpoint siguen siendo visibles.<sup>[[16]](#references)</sup>
- En un entorno VPN o Tor correctamente configurado, el DNS debería seguir la ruta compatible con ese entorno. Añadir un resolver separado puede crear un nuevo observador o fingerprint.

### Flujo de verificación de DNS cifrado/ECH

1. Decide si el DNS está controlado por el entorno VPN/Tor, el sistema operativo o la aplicación. Configúralo en **una** capa prevista en lugar de apilar resolvers no relacionados.
2. Selecciona un resolver según su política publicada de privacidad/retención y activa el modo cifrado estricto cuando la plataforma lo admita. El fallback oportunista puede volver silenciosamente al texto plano.
3. Consulta un subdominio único bajo una zona de prueba autoritativa que controles; confirma que el registro autoritativo ve el resolver recursivo previsto.
4. Captura únicamente el tráfico del dispositivo de prueba y con autorización. Confirma que la red de acceso no puede leer DNS en texto plano, reconociendo que puede ver el endpoint del resolver/túnel cifrado.
5. Prueba un resolver cifrado bloqueado/inaccesible. La condición de éxito es el comportamiento fail-closed elegido o el fallback documentado, no una consulta accidental en claro.
6. Para ECH, utiliza un host controlado compatible con ECH e inspecciona los diagnósticos del cliente/servidor para confirmar que se aceptó el **inner** ClientHello. Ofrecer simplemente un registro HTTPS no demuestra que ECH haya funcionado.
7. Repite las pruebas después de cambios de red, captive portals, actualizaciones del navegador y reconexiones de la VPN. Registra qué componente controla DNS/ECH para que los administradores posteriores no creen un bypass.

## Mixnets

Las mixnets como Nym o Katzenpost añaden paquetes de tamaño fijo, retraso, reordenación y cover traffic para resistir la correlación temporal. Estas propiedades tienen un coste de latencia y ancho de banda, y las evidencias independientes a escala de despliegue son limitadas. Trata las mixnets de consumo actuales como **opciones emergentes/de alta latencia**, no como sustitutos más rápidos o garantizados de Tor/VPN.<sup>[[17]](#references)</sup>

### Flujo de evaluación

1. Identifica un cliente mantenido y la aplicación exacta compatible; no fuerces tráfico arbitrario del navegador/sistema a través de un proxy no documentado.
2. Lee el threat model actual para los supuestos sobre entrada, mix nodes, gateway, destino y colusión.
3. Instala desde la fuente oficial firmada en un compartimento de prueba separado y utiliza únicamente un endpoint propio benigno.
4. Mide la latencia de entrega, los límites de tamaño de los mensajes, la fiabilidad, las retransmisiones y lo que ocurre cuando el gateway no está disponible.
5. Inspecciona el tráfico local y el endpoint propio para confirmar la ruta prevista y el origen. Comprueba si las respuestas utilizan el mismo diseño de privacidad.
6. Prueba el apagado/fallo: la aplicación no debe volver silenciosamente al acceso directo a Internet.
7. No desactives el cover traffic, reduzcas los retrasos ni elijas rutas fijas inusuales únicamente por velocidad; estos cambios pueden invalidar el modelo de anonimato declarado.
8. Mantenlo experimental hasta que el despliegue específico, el análisis independiente y la fiabilidad operativa sean adecuados para el nivel de consecuencias.

## Lista de comprobación previa de red

- [ ] La autorización cubre la red de acceso, el objetivo, las fechas y la infraestructura de origen.
- [ ] El endpoint no contiene identidades no relacionadas ni sesiones de sincronización activas.
- [ ] El comportamiento de IPv4, IPv6, DNS y reconexión coincide con el plan.
- [ ] El destino ve únicamente la salida esperada.
- [ ] El comportamiento del captive portal y del hotspot se ha probado sin tráfico sensible.
- [ ] El uso compartido/descubrimiento local y la conexión automática a redes están desactivados.
- [ ] El riesgo residual de correlación de tráfico y la tabla de observadores son aceptables.
- [ ] La política, la retención y el contacto de emergencia del proveedor están actualizados.

Para relays de conocimiento dividido, workloads con rutas forzadas, pluggable transports, onion services, I2P y navegadores remotos desechables, continúa en [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Cómo elegir la VPN adecuada para ti](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Guía de seguridad de dispositivos: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Protecciones de privacidad y anonimato que ofrece Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Una breve introducción a Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Usar Tor con otros navegadores](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins y add-ons en Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Desbloquear Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Usar Tor Browser con una VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — ¿Son seguras las redes Wi-Fi públicas?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Privacidad Wi-Fi con dispositivos Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementar la aleatorización de MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principios para estaciones de trabajo privilegiadas de acceso seguro](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registro obligatorio de SIM: perspectivas políticas y regulatorias](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recomendaciones para operadores de servicios de privacidad DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS sobre HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
