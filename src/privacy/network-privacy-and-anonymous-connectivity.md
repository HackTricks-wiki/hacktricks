# Privacidad de red y conectividad anónima

{{#include ../banners/hacktricks-training.md}}

La privacidad de red es una decisión de enrutamiento, no una identidad completa. Selecciona una ruta preguntando quién debería ser incapaz de relacionar **origen**, **destino**, **contenido** y **tiempo**.

Para el inventario normalizado —`Pros`, `Cons`, `Procedure` paso a paso y `Detection` para cada familia de rutas de acceso— comienza con el [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Esta página amplía las opciones comunes que se pueden implementar.

## Lo que normalmente puede ver cada observador

| Ruta | Red local / ISP | Intermediario | Destino | Limitación principal | Velocidad relativa |
|---|---|---|---|---|---|
| HTTPS directo | Metadatos del origen, destino, tiempo y volumen | El hosting/CDN ve la conexión | IP de origen, datos del navegador/app | No ofrece privacidad de la IP de origen | La más rápida |
| VPN comercial | Origen conectado a la VPN; no suele ver los metadatos del destino | La VPN ve los metadatos del origen y destino | IP de salida de la VPN | Un proveedor se convierte en un punto de correlación | Normalmente rápida |
| VPN/VPS self-hosted | Origen conectado al VPS | Registros del host/cuenta/pago/control-plane | IP de salida del VPS | Es fácil atribuirla al servidor/cuenta alquilados | Normalmente rápida |
| Tor Browser | Origen conectado a Tor/bridge; tiempo/volumen | Cada relay ve una parte limitada | Exit de Tor, datos del navegador | Más lento; riesgos de cuenta/endpoint/correlación | Moderada/lenta |
| Tails/Whonix | Ruta Tor similar, con límites de enrutamiento más sólidos | Las mismas limitaciones de Tor | Exit de Tor/datos de la aplicación | Los errores operativos y el host/hardware siguen siendo relevantes | Moderada/lenta |
| Wi-Fi público para invitados + HTTPS | El establecimiento ve el dispositivo local/tiempo y los destinos | El ISP del establecimiento ve los metadatos | IP pública de invitados | Correlación física/captive-portal/dispositivo | Rápida/variable |
| Hotspot móvil | El operador ve el suscriptor/dispositivo/ubicación y los destinos | VPN/Tor, si se usa | IP de salida del operador, VPN o Tor | La suscripción móvil y la ubicación son identificadores duraderos | Rápida/variable |
| Mixnet | El acceso ve el uso de la mixnet; tiempo/volumen | Múltiples nodos de mixing | Gateway/egress | Ecosistema emergente; coste de latencia y ancho de banda | La más lenta |

HTTPS protege el contenido en tránsito, pero no todos los metadatos. EFF señala que el dominio, la hora y el tamaño del tráfico pueden seguir siendo visibles para los intermediarios, incluso cuando las rutas de las páginas, las credenciales y los mensajes están cifrados.<sup>[[1]](#references)</sup>

## VPNs: privacidad rápida con confianza concentrada

Una VPN resulta útil para ocultar los metadatos del destino al ISP de acceso, proteger el primer salto en una red que no es de confianza, presentar una dirección de salida estable para un engagement o acceder a una red privada. **No** hace anónimo al usuario. La VPN ve la conexión de origen y puede observar los metadatos del destino; las cuentas, cookies, GPS, fingerprints y la información de pago permanecen.<sup>[[1]](#references)</sup>

### Lista de comprobación para evaluar proveedores

1. **Propiedad y jurisdicción:** identifica la entidad legal, la empresa matriz, los países donde opera, los subcontratistas de infraestructura y los procesos legales aplicables.
2. **Datos recopilados:** distingue entre cuenta/facturación, IP de origen, marcas de tiempo de conexión, ancho de banda, telemetría de fallos, consultas DNS y logs de destino. “No browsing logs” no significa “no data”.
3. **Retención y eliminación:** busca duraciones precisas y comprueba si las copias de seguridad, los sistemas antifraude y los procesadores siguen el mismo calendario.
4. **Evidencias:** prioriza auditorías públicas con alcance, fecha, hallazgos y correcciones; clientes reproducibles/open; informes de transparencia; e incidentes documentados.
5. **Protocolo y cliente:** WireGuard, OpenVPN u otro protocolo revisado y mantenido; actualizaciones automáticas; gestión de DNS e IPv6; kill switch; y pruebas de leak por plataforma.
6. **Modelo de negocio:** entiende cómo se financia un servicio gratuito o subvencionado. La presencia en una app store por sí sola no demuestra un funcionamiento fiable.
7. **Adecuación del pago:** un método de pago alternativo puede reducir la divulgación de datos de facturación a la VPN, pero no elimina la IP de origen observada en cada conexión.

### Configurar y verificar una VPN

1. Instala el cliente firmado del proveedor/organización desde su fuente oficial.
2. Selecciona **full tunnel**, salvo que una ruta documentada deba evitarlo. Split tunneling crea rutas de correlación y leak.
3. Activa el comportamiento fail-closed/always-on y bloquea el tráfico durante la reconexión.
4. Envía el DNS a través del túnel y prueba IPv4 e IPv6. Desactiva un protocolo solo si no puede tunelizarse de forma segura y se acepta la pérdida de funcionalidad.
5. Prueba suspensión/reactivación, cambio de red, inicio de sesión en captive portal, fallo del túnel y tethering mediante hotspot. NCSC advierte que los clientes conectados mediante tethering pueden evitar la VPN del teléfono en algunas plataformas.<sup>[[2]](#references)</sup>
6. Utiliza un endpoint de prueba controlado por la organización para registrar la IPv4, IPv6, el resolver DNS y el tiempo de conexión observados. No expongas un engagement sensible a sitios aleatorios de “leak test”.
7. Repite las pruebas después de cambios en el cliente, el sistema operativo, la red o las políticas.

### Bypasses de enrutamiento en una LAN hostil

Una VPN puede permanecer visiblemente “conectada” mientras determinados paquetes la evitan porque el sistema operativo elige una ruta **antes** de que la VPN cifre el paquete. TunnelCrack demostró dos formas de abusar de excepciones de enrutamiento comunes: **LocalNet** hace que un destino de Internet parezca estar en la subred conectada directamente, mientras que **ServerIP** falsifica la resolución del gateway de la VPN para que una dirección objetivo herede la excepción de red sin cifrar necesaria para el transporte de la VPN. Se trata de fallos del cliente/enrutamiento, no de vulnerabilidades de WireGuard, OpenVPN, IPsec o TLS; las cargas HTTPS permanecen cifradas end-to-end, pero el observador local puede recuperar los metadatos de destino/tiempo y cualquier dato de protocolos en claro.<sup>[[18]](#references)</sup>

TunnelVision aplica el mismo primitive previo al cifrado mediante la opción DHCP 121. Un servidor DHCP malicioso o comprometido puede instalar una ruta classless más específica que la ruta catch-all de la VPN, seleccionando la interfaz física para un host o rango arbitrario. El canal de control de la VPN puede permanecer activo, por lo que un kill switch activado únicamente por la desconexión del túnel puede no ejecutarse, y una única comprobación pública de “IP leak” puede no detectar bypasses selectivos.<sup>[[19]](#references)</sup>

Un kill switch basado en packet filter que permita únicamente DHCP y el transporte autenticado de la VPN en la interfaz física debería convertir esto en un comportamiento fail-closed, pero la inyección de rutas dirigida aún puede crear un canal lateral de denegación selectiva. Para workloads de Linux de alto impacto, prioriza el [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), donde el namespace de la aplicación no tiene una interfaz física ni una ruta predeterminada de red en claro.<sup>[[19]](#references)</sup>

#### Verificación en un lab propio

Prueba el cliente/SO/versión exactos en un AP, servidor DHCP, endpoint VPN y destino propios; las afirmaciones generales sobre un producto envejecen rápidamente porque las implementaciones de enrutamiento y packet filter dependen de la plataforma. Captura datos en el propio endpoint además de hacerlo en el servidor de prueba: un sitio web que muestre la IP de salida por sí solo no demuestra que todos los destinos sigan el túnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Conecta la VPN, registra la dirección del servidor VPN y guarda todas las tablas de enrutamiento IPv4/IPv6 y las reglas de policy-routing. En Windows usa `route print`; en macOS usa `netstat -rn`; en Linux usa los comandos siguientes.
2. Consulta la ruta seleccionada para varias IP de destino propias. El siguiente salto/interfaz debe ser el túnel, excepto para el endpoint de transporte VPN documentado.
3. Para TunnelVision, renueva el lease en la red DHCP controlada e instala una ruta de opción 121 **solo para un destino de prueba propio**. El resultado correcto significa que el tráfico sigue tunelizado o bloqueado; nunca debe emitirse como tráfico del destino por la interfaz física.
4. Para LocalNet, asigna al cliente una subred de documentación pública exclusiva del lab, como `203.0.113.0/24`, y coloca dentro de ella el destino de prueba propio. Verifica que activar el acceso a la LAN no haga que destinos de tipo Internet eviten el túnel.
5. Para ServerIP, antes de conectar la VPN, haz que el DNS controlado resuelva el hostname VPN propio al destino de prueba propio, mientras el gateway del lab reenvía el transporte VPN al endpoint VPN propio real. El cliente no debe excluir tráfico de aplicaciones no relacionado hacia la dirección falsificada.
6. Repite con el “acceso a la red local” activado y desactivado, después de reconectar, suspender/reactivar, cambiar de red y provocar un fallo del proceso VPN. Prueba IPv4, IPv6 y DNS de forma independiente.
7. Inspecciona la captura de la interfaz física. Debe contener DHCP y paquetes cifrados hacia el servidor VPN, no paquetes dirigidos directamente al destino de prueba propio. Confirma también que un bypass rechazado no pueda reactivarse silenciosamente después de prompts del usuario o de la reparación de la conectividad.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: mayor desvinculación web

Tor construye un circuito a través de múltiples relays, por lo que normalmente ningún relay individual conoce tanto el origen como el destino. El destino ve un exit de Tor en lugar de la IP del usuario; la red local normalmente ve una conexión de Tor.<sup>[[3]](#references)</sup> Tor está diseñado para aplicaciones TCP de baja latencia, por lo que es más lento y no puede garantizar protección contra un adversario capaz de correlacionar ambos extremos.<sup>[[4]](#references)</sup>

### Flujo de trabajo seguro con Tor Browser

1. Descarga Tor Browser únicamente desde Tor Project o un mirror oficial y verifica la firma cuando sea posible.
2. Usa **Tor Browser**, no un navegador normal apuntando a un puerto SOCKS de Tor. Los navegadores comunes pueden producir leaks de DNS/WebRTC y de estado identificable.<sup>[[5]](#references)</sup>
3. Mantén el tamaño, las fuentes, las extensiones y la configuración de privacidad predeterminados. Los add-ons adicionales pueden hacer que el navegador sea más único.<sup>[[6]](#references)</sup>
4. Elige el nivel de seguridad **Safer** o **Safest** cuando la mayor incompatibilidad sea aceptable.
5. Usa un bridge cuando Tor directo esté bloqueado o cuando las IP de los relays comunes generen una visibilidad local inaceptable. Los bridges reducen el reconocimiento sencillo; no eliminan el análisis de tráfico.<sup>[[7]](#references)</sup>
6. No inicies sesión en una cuenta identificable, no proporciones información identificable ni abras documentos activos descargados en una aplicación externa conectada a la red.
7. Usa una sesión/contexto separado para cada identidad. “New circuit” no equivale a borrar la identidad del navegador o de la aplicación; usa **New Identity** o reinicia el entorno aislado según corresponda.
8. Prefiere HTTPS autenticado o un onion service autenticado. Un exit de Tor puede observar tráfico HTTP sin cifrar.

### Tor más VPN

Combinarlos no es automáticamente más seguro. Una VPN antes de Tor puede ocultar las conexiones directas a los relays de Tor frente a un ISP, mientras la VPN ve el origen; Tor antes de una VPN proporciona a la VPN una visión estable de la actividad posterior a Tor y puede reducir el conjunto de anonimato. Una configuración incorrecta puede introducir leaks. Tor Project recomienda estas combinaciones únicamente para modelos de amenaza avanzados y explícitos.<sup>[[8]](#references)</sup>

## Wi-Fi público y de invitados

El HTTPS moderno significa que los vecinos pasivos normalmente no pueden leer contenido web correctamente cifrado, pero el Wi-Fi de invitados no proporciona anonimato. El establecimiento puede registrar horas de asociación, identificadores del dispositivo, datos del portal cautivo, destinos y detalles de DHCP; las cámaras, compras, transporte y observación física pueden identificar al usuario. Un hotspot falso con un nombre similar también puede capturar credenciales del portal o manipular tráfico sin cifrar.<sup>[[9]](#references)</sup>

### Flujo de trabajo legal en una red de invitados

1. Usa únicamente una red ofrecida para invitados o una cuyo propietario haya autorizado explícitamente su uso. Pregunta al personal por el SSID exacto y el procedimiento del portal.
2. Actualiza el endpoint y el travel router antes de llegar. Desactiva el uso compartido de archivos/impresoras, el descubrimiento entrante, la conexión automática y la búsqueda de redes recordadas.
3. Activa la dirección Wi-Fi privada/aleatoria del sistema operativo. Los sistemas actuales de Apple pueden usar direcciones rotativas en redes abiertas/débiles; la aleatorización moderna de Android suele ser persistente por SSID. Esto reduce un único identificador local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prefiere un travel router controlado por la organización o un dispositivo bridge de baja confianza entre una workstation privilegiada y la red de invitados. Esto centraliza la política de firewall/VPN, pero no oculta el router al establecimiento.<sup>[[12]](#references)</sup>
5. Completa un portal cautivo únicamente mediante el dispositivo/navegador designado de baja confianza. Nunca introduzcas credenciales personales o reutilizadas para un contexto supuestamente anónimo. Cierra el navegador del portal después de establecer la conectividad.
6. Inicia una VPN de túnel completo o Tor antes de realizar actividades sensibles y confirma el comportamiento fail-closed.
7. Olvida la red después de usarla y revisa la política de la cuenta del portal y de retención de datos.

{% hint style="danger" %}
Crackear el Wi-Fi de un vecino, evadir un portal, usar credenciales de invitados filtradas, clonar el acceso de otro invitado u ocultar una Raspberry Pi en una cafetería es actividad no autorizada, no una técnica de privacidad. Las alternativas seguras son una red de invitados legal, un sitio aprobado por el cliente o un drop node documentado, colocado y recuperado con el consentimiento escrito del propietario.
{% endhint %}

## Travel routers

Un travel router puede aislar una workstation de broadcasts locales hostiles, aplicar un firewall, proporcionar un SSID interno coherente y reconectar automáticamente una VPN. **No** es anónimo: la red ascendente ve su identidad de radio y los tiempos del tráfico, y su proveedor de VPN ve el origen del túnel.

- Usa firmware de OpenWrt/vendor compatible y elimina los servicios no utilizados.
- Adminístralo mediante Ethernet o un SSID de gestión dedicado con una contraseña única.
- Desactiva la administración desde el lado WAN, UPnP, WPS, el uso compartido de archivos y el tráfico entrante no solicitado.
- Usa una MAC WAN aleatoria/privada únicamente cuando sea compatible y esté permitido.
- Aplica la política de VPN en el router, incluidos DNS e IPv6, y bloquea el tráfico de salida cuando falle el túnel.
- No asumas que el hotspot de un teléfono canaliza los dispositivos conectados mediante la VPN del teléfono; pruébalo.

## Redes móviles, SIM y eSIM

Las redes móviles son prácticas, pero no anónimas. Los operadores mantienen identificadores de suscriptor/dispositivo y la ubicación derivada de la conexión a la red; una eSIM sigue siendo una suscripción móvil. El sistema prepago no implica de forma fiable que no haya registro: los requisitos varían según el país y cambian.<sup>[[13]](#references)</sup>

Operativamente:

- Usa un dispositivo separado y compatible para reducir la exposición de datos personales, no para crear un suscriptor ficticio.
- No lleves continuamente un dispositivo “separado” junto a un teléfono personal si la co-localización forma parte del modelo de amenaza.
- Desactiva el acceso móvil, Wi-Fi, Bluetooth y de ubicación que no utilices; apagar el dispositivo proporciona un límite de radio más fuerte que los interruptores de la interfaz.
- Mantén el tráfico sensible dentro de la ruta VPN/Tor aprobada, reconociendo que el operador seguirá conociendo la ubicación de la suscripción/dispositivo y el endpoint del túnel.
- Verifica las normas actuales de registro y retención con el regulador nacional o un asesor legal local; no dependas de listas online de “países con SIM anónimas”.

## Metadatos de DNS y TLS

- **DoH/DoT/DoQ** cifran el DNS entre el cliente y el resolver, evitando la lectura o modificación local sencilla, pero el resolver sigue viendo las consultas y los identificadores de transporte. Cambian la confianza; no proporcionan anonimato.<sup>[[14]](#references)</sup>
- **ODoH** añade un proxy para que el resolver no tenga que conocer la IP del cliente, suponiendo que el proxy y el destino no colaboren. El análisis de tráfico queda explícitamente fuera del alcance.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** puede proteger el nombre interno del servidor en un handshake TLS cuando el cliente, el DNS y el servidor lo admiten. La IP de destino, los tiempos, el volumen y el endpoint siguen siendo visibles.<sup>[[16]](#references)</sup>
- En un entorno VPN o Tor correctamente configurado, el DNS debería seguir la ruta compatible con ese entorno. Añadir un resolver separado puede crear un nuevo observador o fingerprint.

### Flujo de verificación de DNS cifrado/ECH

1. Decide si el DNS está controlado por el entorno VPN/Tor, el sistema operativo o la aplicación. Configúralo en **una** capa prevista, en lugar de apilar resolvers no relacionados.
2. Selecciona un resolver según su política publicada de privacidad/retención y activa el modo cifrado estricto cuando la plataforma lo admita. El fallback oportunista puede volver silenciosamente al texto plano.
3. Consulta un subdominio único bajo una zona de prueba autoritativa que controles; confirma que el log autoritativo ve el resolver recursivo previsto.
4. Captura únicamente el tráfico del dispositivo de prueba con autorización. Confirma que la red de acceso no puede leer DNS en texto plano, reconociendo que puede ver el endpoint del resolver/túnel cifrado.
5. Prueba un resolver cifrado bloqueado/inalcanzable. La condición de aprobación es el comportamiento fail-closed elegido o el fallback documentado, no una consulta accidental en claro.
6. Para ECH, usa un host controlado con ECH habilitado e inspecciona los diagnósticos del cliente/servidor para confirmar que se aceptó el **inner** ClientHello. Ofrecer simplemente un registro HTTPS no demuestra que ECH haya funcionado.
7. Repite las pruebas después de cambios de red, portales cautivos, actualizaciones del navegador y reconexiones de la VPN. Registra qué componente controla el DNS/ECH para que administradores posteriores no creen un bypass.

## Mixnets

Los mixnets, como Nym o Katzenpost, añaden paquetes de tamaño fijo, delays, reordenamiento y cover traffic para resistir la correlación temporal. Estas propiedades tienen un coste en latencia y ancho de banda, y las evidencias independientes a escala de despliegue son limitadas. Trata los mixnets de consumo actuales como **opciones emergentes/de alta latencia**, no como sustitutos más rápidos o garantizados de Tor/VPNs.<sup>[[17]](#references)</sup>

### Flujo de evaluación

1. Identifica un cliente mantenido y la aplicación compatible exacta; no fuerces tráfico arbitrario del navegador/sistema a través de un proxy no documentado.
2. Lee el modelo de amenaza actual para las suposiciones sobre entrada, mix nodes, gateway, destino y colaboración.
3. Instala desde la fuente oficial firmada en un compartimento de pruebas separado y usa únicamente un endpoint propio benigno.
4. Mide la latencia de entrega, los límites de tamaño de mensaje, la fiabilidad, las retransmisiones y lo que ocurre cuando el gateway no está disponible.
5. Inspecciona el tráfico local y el endpoint propio para confirmar la ruta y el origen previstos. Comprueba si las respuestas utilizan el mismo diseño de privacidad.
6. Prueba el apagado/fallo: la aplicación no debe volver silenciosamente al acceso directo a Internet.
7. No desactives el cover traffic, reduzcas los delays ni elijas rutas fijas inusuales únicamente por velocidad; estos cambios pueden invalidar el modelo de anonimato declarado.
8. Mantenlo experimental hasta que el despliegue específico, el análisis independiente y la fiabilidad operativa alcancen el nivel exigido por las consecuencias.

## Lista de comprobación previa de red

- [ ] La autorización cubre la red de acceso, el objetivo, las fechas y la infraestructura de origen.
- [ ] El endpoint no contiene identidades no relacionadas ni sesiones de sincronización activas.
- [ ] El comportamiento de IPv4, IPv6, DNS y reconexión coincide con el plan.
- [ ] La inyección controlada de rutas DHCP/subred local no puede mover el tráfico de prueba a la interfaz física.
- [ ] El destino solo ve el egress esperado.
- [ ] El comportamiento del portal cautivo y del hotspot se ha probado sin tráfico sensible.
- [ ] El uso compartido/descubrimiento local y la conexión automática a redes están desactivados.
- [ ] Se aceptan la tabla de observadores y el riesgo residual de correlación del tráfico.
- [ ] La política del proveedor, la retención y el contacto de emergencia están actualizados.

Para relays de conocimiento dividido, workloads con rutas aplicadas, pluggable transports, onion services, I2P y navegadores remotos desechables, continúa en [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



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
- [12] [UK NCSC — Principios para estaciones de trabajo seguras de acceso privilegiado](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registro obligatorio de SIM: perspectivas políticas y regulatorias](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recomendaciones para operadores de servicios de privacidad DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Modelo de amenaza](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: Leaking VPN Client Traffic by Abusing Routing Tables](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: How Attackers Can Decloak Routing-Based VPNs for a Total VPN Leak](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
