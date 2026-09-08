# Acceso físico y wireless encubierto

Para una implementación detallada y aprobada por el propietario que cubra rendezvous saliente, recuperación de alimentación/uplink, secretos mínimos almacenados en el dispositivo, pruebas de captura y monitorización ante un posible descubrimiento, consulta [Nodos de campo autorizados resistentes a la captura](capture-resilient-authorized-field-nodes.md).

Cambiar la ruta de red también puede cambiar el origen físico aparente. Un actor sofisticado puede usar un sistema comprometido cercano, un dispositivo oculto, acceso público, backhaul celular o un receptor satelital para que los logs del objetivo apunten lejos del operador. Ninguna de estas opciones elimina las evidencias físicas, de radio o del proveedor; desplaza la atribución a distintos conjuntos de datos.

## Matriz de técnicas

| Técnica | Origen aparente | Condición necesaria | Evidencia de alto valor |
|---|---|---|---|
| Pivote wireless cercano | una empresa o vivienda junto al objetivo | host comprometido con conectividad dual y acceso al Wi-Fi del objetivo | logs del endpoint del host vecino, asociación RF y RADIUS/DHCP del objetivo |
| Red pública/de invitados | NAT del establecimiento o salida del túnel | acceso legítimo o elusión del control de acceso | portal cautivo, DHCP, asociación al AP, CCTV y registros de pagos/ubicación |
| Dispositivo de entrega encubierto | dirección cableada, Wi-Fi o celular del objetivo/cercana | colocación o entrega física | switchport/USB, RF, inventario, alimentación y telemetría del túnel saliente |
| Router celular/eSIM | NAT del operador o APN dedicado | módem/SIM/suscripción | IMEI/IMSI/eSIM, sector celular, cuenta del operador y sincronización temporal del tráfico |
| Abuso del enlace satelital | dirección del suscriptor dentro de la huella del haz | debilidad específica del protocolo y del servicio | ubicación RF, flujo de uplink, RTT/routing imposible y registros del proveedor |

## Nearest-neighbor attack

Volexity documentó una operación de APT28/GRU en 2022 en la que el actor se encontraba lejos de su objetivo final. Realizó password spraying contra el servicio público del objetivo para obtener credenciales válidas, pero MFA impedía el inicio de sesión directo desde Internet. El Wi-Fi empresarial del objetivo aceptaba esas credenciales sin MFA. El actor comprometió organizaciones físicamente cercanas al objetivo, encontró un sistema con conectividad dual y alcance wireless, y utilizó ese sistema para autenticarse en el Wi-Fi del objetivo. Volexity denominó a esto **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
La novedad está en la composición. Ningún operador viaja hasta el objetivo y la MFA del servicio expuesto a Internet sigue funcionando. El vecino comprometido proporciona proximidad física; la credencial robada del objetivo proporciona acceso lógico; la Wi-Fi del objetivo se convierte en la ruta para cruzar el límite.

### Requisitos previos y visibilidad

- Un sistema cercano debe poder controlarse de forma remota y tener una radio compatible o acceso a otro pivot cercano.
- El SSID objetivo debe alcanzar ese sistema, y la admisión Wi-Fi debe aceptar una credencial, certificado o estado de dispositivo reutilizable.
- El pivot a menudo necesita dos rutas simultáneas: una de vuelta al operador y otra hacia la WLAN objetivo.
- El objetivo puede ver una nueva MAC de estación y un nombre de usuario legítimo, pero ningún certificado de dispositivo gestionado, información de postura, historial o entrada esperada al edificio.
- Los logs del endpoint vecino pueden mostrar escaneos inalámbricos, nuevos perfiles, cambios de interfaz, tunneling y actividad de remote-control.

### Detección y prevención

1. Exigir EAP-TLS respaldado por certificados y una postura de dispositivo gestionado para la Wi-Fi empresarial; no considerar suficiente una contraseña que haya fallado la MFA en Internet simplemente porque llegue por radio.
2. Correlacionar la autenticación RADIUS con la identidad de MDM/NAC, la asociación histórica de estación/dispositivo, la ubicación del AP, los eventos de acceso físico y las sesiones simultáneas.
3. Generar una alerta cuando una cuenta se asocie por primera vez, desde un borde de AP inusual, sin un certificado gestionado o mientras la misma identidad esté activa en otro lugar.
4. Monitorizar los endpoints capaces de puentear interfaces. En Windows, Linux y network appliances, investigar perfiles WLAN inesperados, configuraciones de forwarding/NAT, adaptadores virtuales y tunnels persistentes.
5. Reducir la dispersión innecesaria de la señal mediante una ubicación sensata de los AP y una planificación de potencia adecuada. Es un control de apoyo, no de autenticación.
6. Coordinar la respuesta ante incidentes con los inquilinos vecinos: la fuente de radio final podría ser también una víctima.

El [laboratorio de dos organizaciones controlado](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduce estas observaciones sin atacar a un vecino.

## Lugares públicos y Wi-Fi de terceros

Usar la Wi-Fi de una cafetería, un hotel, un aeropuerto o una entidad municipal cambia la IP que se muestra al destino. No crea anonimato. El lugar o su proveedor pueden conservar la asociación con el AP, la MAC del dispositivo, la concesión DHCP, la cuenta del captive portal, la validación por SMS/email y los logs de flujo. La entrada física, las cámaras CCTV, la compra, la ubicación móvil y los registros de viaje pueden conectar el evento digital con una persona.

Un actor puede intentar reducir uno de los identificadores usando direcciones MAC aleatorizadas, un dispositivo separado, efectivo o un tunnel. La correlación entre capas sigue siendo posible mediante la hora de llegada, los patrones repetidos de uso del lugar, las huellas de radio, el comportamiento del portal, la temporización del tráfico, las grabaciones de las cámaras y el proveedor del tunnel. Una VPN también traslada el destino de los logs del lugar a los logs de la VPN; no elimina el conocimiento del lugar de que el dispositivo estuvo presente.

Los defensores del acceso público deben aislar a los clientes, bloquear el tráfico lateral, usar WPA2/3-Enterprise o claves por dispositivo cuando sea viable, conservar logs DHCP/RADIUS/de seguridad proporcionales, proteger los captive portals y publicar un proceso de abuso. Los equipos red team deben usar un lugar de este tipo únicamente cuando sus condiciones y el engagement lo permitan; evadir un portal, robar acceso o atacar a otros usuarios no es un atajo autorizado para realizar pruebas.

## Dispositivos de drop encubiertos y Warshipping

Un drop es un sistema pequeño colocado o entregado en un sitio y controlado posteriormente mediante Ethernet saliente, Wi-Fi o conexión celular. “Warshipping” empaqueta el dispositivo de modo que una entrega ordinaria lo transporte dentro del perímetro de radio. El hardware puede ir desde un ordenador de placa única hasta un cargador modificado, un periférico USB, un network appliance o un módem alimentado por batería.

Arquitectura operativa:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
El dispositivo puede proporcionar un acceso remoto, realizar mediciones inalámbricas, emular un peripheral autorizado para un ejercicio o retransmitir tráfico. Su origen aparente es local, pero crea artefactos físicos: números de serie, embalaje, fingerprints, cámaras, registros de acceso, consumo eléctrico, descriptores USB, negociación del switchport, fingerprints de DHCP, comportamiento de OUI/aleatorización de MAC, emisiones RF y conexiones recurrentes de rendezvous.

### Controles defensivos

- Mantener procedimientos de recepción y de inventario de activos; inspeccionar dispositivos electrónicos y paquetes inesperados dirigidos a empleados inexistentes.
- Usar 802.1X/NAC en accesos cableados e inalámbricos, deshabilitar puertos no utilizados y colocar los dispositivos desconocidos en una VLAN de remediation restringida.
- Generar alertas ante nuevos fingerprints de DHCP, MAC administradas localmente que persistan, nuevos dispositivos de red/HID USB, Wi-Fi Direct/Bluetooth no autorizados y túneles salientes de larga duración.
- Establecer una línea base del switchport, Power over Ethernet, DNS y comportamiento TLS. Un host pequeño sin registro de inventario que realice conexiones cifradas periódicas es una señal más fiable que “Raspberry Pi OUI” por sí sola.
- Durante un ejercicio, inventariar, etiquetar, definir el alcance, cifrar, proporcionar un remote kill, establecer un plazo de recuperación y garantizar que la pérdida no pueda exponer credenciales reutilizables.

## Backhaul celular y eSIM

Un módem celular evita el gateway de Internet del objetivo y puede mantener un drop accesible detrás del NAT del operador mediante un rendezvous saliente. Las direcciones móviles pueden rotar o compartirse; aun así, el operador celular conserva evidencias sólidas del suscriptor y de la red: identidad de SIM/eSIM, IMSI, IMEI del dispositivo, direcciones/puertos asignados, temporización de celda/sector y registros de cuenta/pago y roaming.

Desde la perspectiva de la empresa, se deben detectar módems y hotspots personales inesperados mediante inspecciones inalámbricas/RF, inventario USB/PCI de endpoints, restricciones de MDM, monitorización de rogue SSID e inspección física. Un drop que use la red celular para el control aún puede detectarse por su comportamiento local de Ethernet/Wi-Fi y sus emisiones de radio.

Para ejercicios autorizados, la organización debería ser propietaria de la suscripción y del módem, registrar los identificadores con el controlador y validar que los términos del operador/proveedor permitan el tráfico. Una etiqueta prepago o una compra con criptomonedas no elimina los registros de torres, dispositivos o comercios.

## Aleatorización de MAC y fingerprinting de dispositivos

Los sistemas modernos pueden usar una MAC aleatoria administrada localmente por red. Esto reduce el tracking pasivo a largo plazo mediante una MAC de fábrica estable; no oculta:

- la temporización de las sondas/asociaciones ni el conjunto de capacidades de red solicitadas;
- los elementos de información 802.11, las velocidades compatibles y el comportamiento específico del proveedor;
- las opciones/nombre de host de DHCP, los identificadores IPv6 y el fingerprint del navegador/portal cautivo;
- la identidad o el certificado autenticados de 802.1X;
- la cuenta de capa superior, el túnel y el patrón de tráfico; ni
- la observación física.

Los defensores no deberían usar allowlists de MAC como autenticación. Se debe vincular la identidad de radio con el certificado/postura del dispositivo y tratar las MAC cambiantes como algo normal, salvo que otro contexto sea anómalo.

## Hijacking de enlaces satelitales

Kaspersky documentó el uso por parte de Turla de debilidades en el antiguo Internet satelital DVB-S unidireccional. En el modelo descrito, un suscriptor remoto legítimo enviaba solicitudes salientes a través de un enlace terrestre, pero recibía los datos downstream mediante una transmisión satelital de área extensa sin cifrar. Un actor dentro de la cobertura del satélite podía observar el downlink, seleccionar la IP de un suscriptor activo y hacer que las respuestas de C2 se dirigieran a esa IP. Tanto el suscriptor legítimo como el actor recibían la transmisión; el actor extraía el tráfico del puerto seleccionado, mientras que el suscriptor legítimo descartaba los paquetes no solicitados. Posteriormente, el operador de C2 parecía utilizar una dirección del proveedor satelital ubicada en otra geografía.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Esto era específico del protocolo/servicio, estaba limitado por el ancho de banda y no equivalía a comprometer un terminal satelital moderno bidireccional y cifrado. Tampoco ocultaba la ruta de salida de la solicitud del actor frente a un observador con capacidades suficientes. Las oportunidades de detección incluyen enrutamiento asimétrico/imposible, tráfico hacia un suscriptor que no inició el flujo, puertos de destino inusuales, telemetría del proveedor, investigación de la ubicación del receptor/RF y la configuración del malware. Usa este caso para cuestionar la suposición de que geolocalizar una IP de C2 permite geolocalizar a su controlador, no como una receta de construcción.

## Hoja de trabajo de correlación de físico a digital

Cuando un origen aparentemente local resulte sospechoso, construye una única línea temporal:

1. normaliza los relojes de AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch y control de acceso físico;
2. identifica la primera asociación de radio o activación del enlace, no solo la primera alerta;
3. vincula la estación con el certificado, la postura del dispositivo, la huella DHCP y la ubicación del switch/AP;
4. busca actividad simultánea de control remoto/túnel en sistemas cercanos;
5. revisa entregas, visitantes, excepciones de inventario, cámaras y hallazgos de RF conforme a la política/legislación aplicable;
6. preserva el dispositivo sospechoso y el estado volátil de la red; no lo apagues reiniciándolo sin evaluar;
7. determina si el origen aparente es una infraestructura controlada por el actor u otra víctima.

## References

- [1] [Volexity — El ataque del vecino más cercano: cómo un APT ruso armó redes Wi-Fi cercanas para obtener acceso encubierto](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla satelital: command and control de APT en el cielo](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Adiciones de hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Directrices para proteger redes inalámbricas de área local](https://csrc.nist.gov/pubs/sp/800/153/final)
