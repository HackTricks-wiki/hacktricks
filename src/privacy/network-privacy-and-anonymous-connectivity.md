# Privacidad de red y conectividad anónima

{{#include ../banners/hacktricks-training.md}}

La privacidad de red es una decisión de enrutamiento, no una identidad completa. Elige una ruta preguntándote quién no debería poder vincular el **origen**, el **destino**, el **contenido** y los **horarios**.

Para consultar el inventario normalizado —`Pros`, `Cons`, `Procedure` paso a paso y `Detection` para cada familia de rutas de acceso—, empieza por el [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md). Esta página amplía las opciones habituales que se pueden implementar.

## Qué suele poder ver cada observador

| Ruta | Red local / ISP | Intermediario | Destino | Limitación principal | Velocidad relativa |
|---|---|---|---|---|---|
| HTTPS directo | Origen, metadatos del destino, horarios/volumen | El hosting/CDN ve la conexión | IP de origen, datos del navegador/app | No protege la privacidad de la IP de origen | La más rápida |
| VPN comercial | Origen conectado a la VPN; normalmente no ve metadatos del destino | La VPN ve el origen y los metadatos del destino | IP de salida de la VPN | Un proveedor se convierte en un punto de correlación | Normalmente rápida |
| VPN/VPS autohospedado | Origen conectado al VPS | Registros del host/cuenta/pago/plano de control | IP de salida del VPS | Es fácil vincularlo con el servidor/cuenta alquilados | Normalmente rápida |
| Tor Browser | Origen conectado a Tor/bridge; horarios/volumen | Cada relay solo ve una parte limitada | Exit de Tor, datos del navegador | Más lento; riesgos de cuenta/endpoint/correlación | Media/lenta |
| Tails/Whonix | Ruta de Tor similar, con límites de enrutamiento más estrictos | Las mismas limitaciones de Tor | Exit de Tor/datos de la aplicación | Persisten los errores operativos y los riesgos del host/hardware | Media/lenta |
| Wi-Fi público para invitados + HTTPS | El establecimiento ve el dispositivo local/horarios y los destinos | El ISP del establecimiento ve metadatos | IP pública de la red para invitados | Correlación física, del portal cautivo y del dispositivo | Rápida/variable |
| Hotspot celular | El operador ve el abonado/dispositivo/ubicación y los destinos | VPN/Tor, si se usa | IP de salida del operador, VPN o Tor | La suscripción móvil y la ubicación son identificadores duraderos | Rápida/variable |
| Mixnet | El acceso detecta el uso de la mixnet; horarios/volumen | Varios nodos de mezcla | Gateway/salida | Ecosistema emergente; coste de latencia y ancho de banda | La más lenta |

HTTPS protege el contenido en tránsito, pero no todos los metadatos. EFF señala que el dominio, la hora y el tamaño del tráfico pueden seguir siendo visibles para los intermediarios, aunque las rutas de las páginas, las credenciales y los mensajes estén cifrados.<sup>[[1]](#references)</sup>

Una capa de red cifrada no es automáticamente una red de anonimato: los peers directos de Yggdrasil pueden ver las direcciones IP de los demás.<sup>[[20]](#references)</sup> Su [reenvío en userspace y transporte SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) es una opción de tunneling, no una capa de anonimato del origen.<sup>[[20]](#references)[[21]](#references)</sup>

## VPNs: privacidad rápida con confianza concentrada

Una VPN sirve para ocultar los metadatos del destino al ISP de acceso, proteger el primer salto en una red no confiable, proporcionar una dirección de salida estable para una operación o acceder a una red privada. **No** hace que el usuario sea anónimo. La VPN ve la conexión de origen y puede observar los metadatos del destino; las cuentas, cookies, GPS, fingerprints y la información de pago siguen estando presentes.<sup>[[1]](#references)</sup>

### Lista de verificación para evaluar proveedores

1. **Propiedad y jurisdicción:** identifica la entidad legal, la empresa matriz, los países donde opera, los subcontratistas de infraestructura y los procesos legales aplicables.
2. **Datos recopilados:** distingue entre datos de cuenta/facturación, IP de origen, marcas de tiempo de conexión, ancho de banda, telemetría de fallos, consultas DNS y registros de destinos. «Sin registros de navegación» no significa «sin datos».
3. **Retención y eliminación:** busca plazos precisos y comprueba si las copias de seguridad, los sistemas antifraude y los procesadores siguen el mismo calendario.
4. **Evidencia:** prioriza auditorías públicas que indiquen alcance, fecha, resultados y medidas correctivas; clientes reproducibles/de código abierto; informes de transparencia; e incidentes documentados.
5. **Protocolo y cliente:** WireGuard, OpenVPN u otro protocolo revisado y mantenido; actualizaciones automáticas; gestión de DNS e IPv6; kill switch; y pruebas de leak en cada plataforma.
6. **Modelo de negocio:** averigua cómo se financia un servicio gratuito o subvencionado. Estar en una tienda de aplicaciones no demuestra por sí solo que el servicio sea confiable.
7. **Opciones de pago:** los métodos de pago alternativos pueden reducir la información de facturación que recibe la VPN, pero no eliminan la IP de origen que observa en cada conexión.

### Configurar y verificar una VPN

1. Instala el cliente firmado del proveedor/organización desde su fuente oficial.
2. Selecciona **full tunnel**, salvo que una ruta documentada deba evitarlo. El split tunneling crea posibilidades de correlación y de leak.
3. Activa el modo fail-closed/always-on y bloquea el tráfico durante la reconexión.
4. Envía el DNS a través del túnel y prueba IPv4 e IPv6. Desactiva un protocolo solo si no se puede tunelizar de forma segura y aceptas la pérdida de funcionalidad.
5. Prueba la suspensión/reactivación, el cambio de red, el inicio de sesión en el portal cautivo, la caída del túnel y el tethering del hotspot. NCSC advierte que, en algunas plataformas, los clientes conectados mediante tethering pueden evitar la VPN del teléfono.<sup>[[2]](#references)</sup>
6. Usa un endpoint de prueba controlado por la organización para registrar la IPv4, IPv6, el resolver DNS y los horarios de conexión observados. No expongas una operación sensible a sitios aleatorios de «prueba de leak».
7. Repite las pruebas después de cambios en el cliente, el sistema operativo, la red o las políticas.

### Bypass de enrutamiento en una LAN hostil

Una VPN puede seguir apareciendo como «conectada» mientras algunos paquetes evitan el túnel, porque el sistema operativo elige una ruta **antes** de que la VPN cifre el paquete. TunnelCrack demostró dos formas de abusar de las excepciones de enrutamiento habituales: **LocalNet** hace que un destino de Internet parezca estar en la subred conectada directamente, mientras que **ServerIP** falsifica la resolución del gateway de la VPN para que una dirección de destino herede la excepción de red sin cifrar que necesita el transporte de la VPN. Son fallos del cliente/enrutamiento, no vulnerabilidades de WireGuard, OpenVPN, IPsec o TLS; las cargas útiles de HTTPS siguen cifradas de extremo a extremo, pero el observador local puede recuperar los metadatos del destino/horarios y cualquier dato de protocolos sin cifrar.<sup>[[18]](#references)</sup>

TunnelVision aplica la misma primitiva previa al cifrado mediante la opción 121 de DHCP. Un servidor DHCP malicioso o comprometido puede instalar una ruta sin clases más específica que la ruta general de la VPN y seleccionar la interfaz física para cualquier host o rango. El canal de control de la VPN puede seguir activo, por lo que un kill switch que solo se active al desconectarse el túnel quizá no se dispare, y una sola comprobación pública de «IP leak» puede no detectar los bypasses selectivos.<sup>[[19]](#references)</sup>

Un kill switch de filtrado de paquetes que permita únicamente DHCP y el transporte autenticado de la VPN en la interfaz física debería hacer que el sistema falle de forma cerrada, pero la inyección de rutas dirigida aún puede crear un canal lateral de denegación selectiva. Para cargas de trabajo Linux de alto impacto, es preferible el [patrón más sólido de network namespace con rutas forzadas](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), donde el namespace de la aplicación no tiene una interfaz física ni una ruta predeterminada de red sin cifrar.<sup>[[19]](#references)</sup>

#### Verificación en un laboratorio propio

Prueba el cliente/SO/versión exactos en un AP, servidor DHCP, endpoint VPN y destino propios; las afirmaciones sobre productos completos quedan obsoletas rápidamente, ya que las implementaciones de enrutamiento y filtrado de paquetes varían según la plataforma. Captura el tráfico tanto en el propio endpoint como en el servidor de prueba: un sitio que muestra la IP de salida no demuestra que todos los destinos sigan el túnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Conéctate a la VPN, registra la dirección del servidor VPN y guarda todas las tablas de enrutamiento IPv4/IPv6 y las reglas de enrutamiento por políticas. En Windows, usa `route print`; en macOS, usa `netstat -rn`; en Linux, usa los comandos de abajo.
2. Consulta la ruta seleccionada para varias IP de destino propias. El siguiente salto/interfaz debe ser el túnel, salvo el endpoint de transporte VPN documentado.
3. Para TunnelVision, renueva la concesión en la red DHCP controlada e instala una ruta de opción 121 **solo para un destino de prueba propio**. La prueba se supera si el tráfico sigue tunelizado o bloqueado, y nunca se emite como tráfico dirigido al destino por la interfaz física.
4. Para LocalNet, asigna al cliente una subred de documentación pública solo para el laboratorio, como `203.0.113.0/24`, y coloca dentro de ella el destino de prueba propio. Comprueba que habilitar el acceso a la LAN no haga que los destinos de tipo Internet eviten el túnel.
5. Para ServerIP, antes de conectar la VPN, haz que el DNS controlado resuelva el hostname VPN propio al destino de prueba propio, mientras el gateway del laboratorio reenvía el transporte VPN al endpoint VPN propio real. El cliente no debe eximir del túnel el tráfico de aplicaciones no relacionado dirigido a la dirección falsificada.
6. Repite con el «acceso a la red local» activado y desactivado, después de reconectar, suspender/reactivar, cambiar de red y provocar un fallo del proceso VPN. Prueba IPv4, IPv6 y DNS de forma independiente.
7. Inspecciona la captura de la interfaz física. Debe contener DHCP y paquetes cifrados dirigidos al servidor VPN, no paquetes dirigidos directamente al destino de prueba propio. Confirma también que un bypass rechazado no pueda activarse silenciosamente después de avisos al usuario o de una reparación de la conectividad.

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

Tor crea un circuito a través de varios relays para que ningún relay conozca normalmente tanto el origen como el destino. El destino ve una salida de Tor en lugar de la IP del usuario; la red local normalmente ve una conexión a Tor.<sup>[[3]](#references)</sup> Tor está diseñado para aplicaciones TCP de baja latencia, por lo que es más lento y no puede garantizar protección frente a un adversario capaz de correlacionar ambos extremos.<sup>[[4]](#references)</sup>

### Flujo de trabajo seguro con Tor Browser

1. Descarga Tor Browser solo desde Tor Project o un mirror oficial, y verifica la firma cuando sea posible.
2. Usa **Tor Browser**, no un navegador normal configurado para usar un puerto SOCKS de Tor. Los navegadores normales pueden filtrar DNS/WebRTC y datos de estado que permiten identificarte.<sup>[[5]](#references)</sup>
3. Mantén el tamaño, las fuentes, las extensiones y la configuración de privacidad predeterminados. Los complementos adicionales pueden hacer que el navegador sea más singular.<sup>[[6]](#references)</sup>
4. Elige el nivel de seguridad **Safer** o **Safest** cuando el aumento de errores o incompatibilidades sea aceptable.
5. Usa un bridge cuando Tor directo esté bloqueado o cuando la visibilidad local de las IP de los relays habituales sea inaceptable. Los bridges dificultan el reconocimiento inmediato, pero no eliminan el análisis del tráfico.<sup>[[7]](#references)</sup>
6. No inicies sesión en una cuenta que te identifique, no proporciones información identificativa ni abras documentos activos descargados en una aplicación externa con conexión a la red.
7. Usa una sesión o contexto distinto para cada identidad. «New circuit» no equivale a borrar la identidad del navegador o de la aplicación; usa **New Identity** o reinicia el entorno aislado según corresponda.
8. Prefiere HTTPS autenticado o un onion service autenticado. Una salida de Tor puede observar el tráfico HTTP sin cifrar.

### Tor más VPN

Combinarlos no es automáticamente más seguro. Una VPN antes de Tor puede ocultar las conexiones directas a los relays de Tor al ISP, mientras que la VPN ve el origen; Tor antes de una VPN le da a la VPN una visión estable de la actividad posterior a Tor y puede reducir el conjunto de anonimato. Una configuración incorrecta puede provocar leaks. Tor Project recomienda estas combinaciones solo para modelos de amenazas avanzados y explícitos.<sup>[[8]](#references)</sup>

## Wi-Fi público y de invitados

El HTTPS moderno significa que los observadores pasivos cercanos normalmente no pueden leer contenido web cifrado correctamente, pero el Wi-Fi de invitados no proporciona anonimato. El establecimiento puede registrar las horas de conexión, los identificadores de dispositivo, los datos del portal cautivo, los destinos y los detalles de DHCP; las cámaras, las compras, el transporte y la observación física pueden identificar al usuario. Un hotspot falso con un nombre similar también puede capturar credenciales del portal o manipular tráfico sin cifrar.<sup>[[9]](#references)</sup>

### Flujo de trabajo legal en una red de invitados

1. Usa únicamente una red ofrecida a los invitados o una para la que el propietario haya dado permiso explícito. Pide al personal el SSID exacto y el procedimiento del portal.
2. Actualiza el endpoint y el travel router antes de llegar. Desactiva el uso compartido de archivos e impresoras, la detección entrante, la conexión automática y la búsqueda de redes guardadas.
3. Activa la dirección Wi-Fi privada o aleatoria del sistema operativo. Los sistemas Apple actuales pueden usar direcciones rotativas en redes abiertas o débiles; la aleatorización de Android moderno suele ser persistente por SSID. Esto solo reduce un identificador local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prefiere un travel router controlado por la organización o un dispositivo puente de baja confianza entre una workstation privilegiada y la red de invitados. Esto centraliza las políticas de firewall y VPN, pero no oculta el router al establecimiento.<sup>[[12]](#references)</sup>
5. Completa el portal cautivo solo desde el dispositivo o navegador designado de baja confianza. Nunca introduzcas credenciales personales o reutilizadas en un contexto supuestamente anónimo. Cierra el navegador del portal una vez establecida la conectividad.
6. Inicia una VPN de túnel completo o Tor antes de realizar actividades sensibles y confirma que el comportamiento sea de bloqueo ante fallos.
7. Olvida la red después de usarla y revisa la política de retención de datos y de la cuenta del portal.

{% hint style="danger" %}
Crackear el Wi-Fi de un vecino, eludir un portal, usar credenciales filtradas de invitados, clonar el acceso de otro invitado u ocultar una Raspberry Pi en una cafetería son actividades no autorizadas, no técnicas de privacidad. Las alternativas seguras son una red de invitados legal, un sitio aprobado por el cliente o un nodo de entrega documentado, instalado y recuperado con el consentimiento por escrito del propietario.
{% endhint %}

## Travel routers

Un travel router puede aislar una workstation de las difusiones locales hostiles, aplicar un firewall, proporcionar un SSID interno constante y volver a conectar una VPN automáticamente. **No** proporciona anonimato: la red ascendente ve su identidad de radio y los tiempos del tráfico, y el proveedor de VPN ve el origen del túnel.

- Usa firmware compatible de OpenWrt o del fabricante y elimina los servicios que no uses.
- Adminístralo por Ethernet o mediante un SSID de administración dedicado con una contraseña única.
- Desactiva la administración desde el lado WAN, UPnP, WPS, el uso compartido de archivos y el tráfico entrante no solicitado.
- Usa una MAC WAN aleatoria o privada solo si es compatible y está permitido.
- Aplica las políticas de VPN en el router, incluidos DNS e IPv6, y bloquea la salida de tráfico si falla el túnel.
- No des por hecho que un hotspot de teléfono enviará los dispositivos conectados mediante tethering a través de la VPN del teléfono; compruébalo.

## Redes celulares, SIM y eSIM

La conexión celular es cómoda, pero no anónima. Los operadores conservan identificadores de suscriptor y dispositivo, así como datos de ubicación derivados de la conexión a la red; una eSIM sigue siendo una suscripción móvil. El prepago no significa necesariamente que no haya registro: los requisitos varían según el país y cambian.<sup>[[13]](#references)</sup>

En la práctica:

- Usa un dispositivo independiente y compatible para reducir la exposición de datos personales, no para crear un suscriptor ficticio.
- No lleves continuamente un dispositivo «independiente» junto a un teléfono personal si la ubicación conjunta forma parte del modelo de amenazas.
- Desactiva la conexión celular, el Wi-Fi, el Bluetooth y el acceso a la ubicación cuando no los uses; apagar el dispositivo establece una barrera de radio más sólida que usar los interruptores de la interfaz.
- Envía el tráfico sensible por la ruta aprobada de VPN/Tor, teniendo presente que el operador sigue conociendo la ubicación de la suscripción o el dispositivo y el endpoint del túnel.
- Verifica las normas actuales de registro y retención con el regulador nacional o un asesor legal local; no te fíes de listas en línea de «países con SIM anónimas».

## Metadatos de DNS y TLS

- **DoH/DoT/DoQ** cifran el DNS entre el cliente y el resolver, lo que impide que se lea o modifique fácilmente en la red local, pero el resolver sigue viendo las consultas y los identificadores de transporte. Cambian en quién confías; no proporcionan anonimato.<sup>[[14]](#references)</sup>
- **ODoH** añade un proxy para que el resolver no tenga que conocer la IP del cliente, suponiendo que el proxy y el destino no se confabulen. El análisis del tráfico queda explícitamente fuera del alcance.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** puede proteger el nombre interno del servidor en un handshake TLS cuando el cliente, el DNS y el servidor lo admiten. La IP de destino, los tiempos, el volumen y el endpoint siguen siendo visibles.<sup>[[16]](#references)</sup>
- En un entorno VPN o Tor configurado correctamente, el DNS debe seguir la ruta compatible con ese entorno. Añadir un resolver distinto puede crear un nuevo observador o una huella digital.

### Flujo de verificación de DNS cifrado/ECH

1. Decide si el DNS lo controla el entorno VPN/Tor, el sistema operativo o la aplicación. Configúralo en **una sola** capa prevista, en lugar de apilar resolvers no relacionados.
2. Elige un resolver según su política publicada de privacidad y retención, y activa el modo cifrado estricto cuando la plataforma lo admita. La alternativa oportunista puede volver silenciosamente al texto sin cifrar.
3. Consulta un subdominio único de una zona de pruebas autoritativa que controles; confirma que el registro autoritativo muestra el resolver recursivo previsto.
4. Captura únicamente el tráfico del dispositivo de prueba y con autorización. Confirma que la red de acceso no puede leer el DNS en texto sin cifrar, teniendo presente que puede ver el endpoint del resolver o del túnel cifrado.
5. Prueba qué ocurre cuando el resolver cifrado está bloqueado o no es accesible. El resultado esperado debe ser el comportamiento elegido de bloqueo ante fallos o la alternativa documentada, no una consulta accidental sin cifrar.
6. Para ECH, usa un host controlado que tenga ECH habilitado e inspecciona los diagnósticos del cliente y del servidor para confirmar que se aceptó el **ClientHello** interno. El mero hecho de ofrecer un registro HTTPS no demuestra que ECH haya funcionado.
7. Repite las pruebas después de cambiar de red, usar portales cautivos, actualizar el navegador y volver a conectar la VPN. Registra qué componente controla DNS/ECH para que los administradores posteriores no creen una vía de elusión.

## Mixnets

Los mixnets, como Nym o Katzenpost, añaden paquetes de tamaño fijo, demoras, reordenamiento y tráfico de cobertura para resistir la correlación temporal. Estas propiedades tienen un coste en latencia y ancho de banda, y hay poca evidencia independiente sobre despliegues a gran escala. Considera los mixnets de consumo actuales como **opciones emergentes de alta latencia**, no como reemplazos más rápidos o garantizados de Tor/VPN.<sup>[[17]](#references)</sup>

### Flujo de evaluación

1. Identifica un cliente mantenido y la aplicación concreta compatible; no fuerces el tráfico arbitrario del navegador o del sistema a través de un proxy no documentado.
2. Lee el modelo de amenazas actual respecto a los nodos de entrada, los nodos mix, el gateway, el destino y las hipótesis de colusión.
3. Instálalo desde la fuente oficial firmada en un entorno de prueba independiente y usa únicamente un endpoint propio e inocuo.
4. Mide la latencia de entrega, los límites de tamaño de mensaje, la fiabilidad, las retransmisiones y lo que ocurre si el gateway no está disponible.
5. Inspecciona el tráfico local y el endpoint propio para confirmar la ruta y el origen previstos. Comprueba si las respuestas usan el mismo diseño de privacidad.
6. Prueba el apagado y los fallos: la aplicación no debe recurrir silenciosamente al acceso directo a Internet.
7. No desactives el tráfico de cobertura, reduzcas las demoras ni elijas rutas fijas inusuales solo para ganar velocidad; estos cambios pueden invalidar el modelo de anonimato declarado.
8. Mantén el sistema en fase experimental hasta que el despliegue específico, el análisis independiente y la fiabilidad operativa estén a la altura de las consecuencias.

## Lista de comprobación previa de red

- [ ] La autorización cubre la red de acceso, el objetivo, las fechas y la infraestructura de origen.
- [ ] El endpoint no contiene identidades ajenas a la prueba ni sesiones de sincronización activas.
- [ ] IPv4, IPv6, DNS y el comportamiento de reconexión coinciden con el plan.
- [ ] La inyección controlada de rutas DHCP o de subred local no puede desviar el tráfico de prueba a la interfaz física.
- [ ] El destino solo ve la salida prevista.
- [ ] Se han probado el portal cautivo y el comportamiento del hotspot sin tráfico sensible.
- [ ] El uso compartido y la detección locales, así como la conexión automática a redes, están desactivados.
- [ ] Se aceptan la tabla de observadores y el riesgo residual de correlación del tráfico.
- [ ] La política del proveedor, la retención de datos y el contacto de emergencia están actualizados.

Para conocer los relays de conocimiento dividido, las cargas de trabajo con rutas forzadas, los transportes conectables, los onion services, I2P y los navegadores remotos desechables, continúa con [Arquitecturas avanzadas de privacidad de red](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Cómo elegir la VPN adecuada](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Guía de seguridad de dispositivos: redes privadas virtuales](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Las protecciones de privacidad y anonimato que ofrece Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Especificaciones de Tor — Breve introducción a Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Usar Tor con otros navegadores](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins y complementos en Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Desbloquear Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Usar Tor Browser con una VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [Consejos para consumidores de la FTC — ¿Son seguras las redes Wi-Fi públicas?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Seguridad de las plataformas de Apple — Privacidad del Wi-Fi en dispositivos Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementar la aleatorización de MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principios para workstations de acceso privilegiado seguras](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registro obligatorio de SIM: perspectivas normativas y de políticas](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recomendaciones para operadores de servicios de privacidad de DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS sobre HTTPS con ocultación](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Modelo de amenazas](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Elusión de túneles: filtración del tráfico de clientes VPN mediante el abuso de tablas de enrutamiento](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: cómo los atacantes pueden desocultar VPN basadas en enrutamiento y provocar un leak total de VPN](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [FAQ de Yggdrasil: ¿Yggdrasil es anónimo?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [README de Yggstack](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
