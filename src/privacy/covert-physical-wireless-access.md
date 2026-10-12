# Acceso físico y inalámbrico encubierto

{{#include ../banners/hacktricks-training.md}}

Para conocer una implementación detallada y aprobada por el propietario que abarque rendezvous saliente, recuperación de alimentación/conectividad, secretos mínimos almacenados en el dispositivo, pruebas de captura y monitoreo de posibles descubrimientos, consulta [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Cambiar la ruta de red también puede cambiar el origen físico aparente. Un actor sofisticado puede usar un sistema cercano comprometido, un dispositivo oculto, acceso público, conectividad celular o un receptor satelital para que los registros del objetivo apunten lejos del operador. Ninguna de estas opciones elimina las evidencias físicas, de radio o del proveedor; traslada la atribución a otros conjuntos de datos.

## Matriz de técnicas

| Técnica | Origen aparente | Condición necesaria | Evidencia de alto valor |
|---|---|---|---|
| Pivot inalámbrico cercano | un negocio o una vivienda junto al objetivo | host dual-homed comprometido y acceso a la Wi-Fi del objetivo | registros de endpoint del host vecino, asociación RF y RADIUS/DHCP del objetivo |
| Red pública/de invitados | NAT del establecimiento o salida del túnel | acceso legítimo o evasión de controles de acceso | portal cautivo, DHCP, asociación al AP, CCTV y registros de pagos/ubicación |
| Dispositivo de acceso encubierto | dirección cableada, Wi-Fi o celular del objetivo o de las cercanías | colocación o entrega física | switchport/USB, RF, inventario, alimentación y telemetría del túnel saliente |
| Router celular/eSIM | NAT del operador o APN dedicado | módem/SIM/suscripción | IMEI/IMSI/eSIM, sector de celda, cuenta del operador y temporización del tráfico |
| Abuso de enlace satelital | dirección del suscriptor dentro de la huella del haz | debilidad específica del protocolo y del servicio | ubicación RF, flujo de uplink, RTT/enrutamiento imposibles y registros del proveedor |

## Ataque del vecino más cercano

Volexity documentó una operación de APT28/GRU de 2022 en la que el actor estaba lejos de su objetivo final. Realizó password spraying contra el servicio público del objetivo para obtener credenciales válidas, pero la MFA impidió el inicio de sesión directo desde Internet. La Wi-Fi empresarial del objetivo aceptaba esas credenciales sin MFA. El actor comprometió organizaciones ubicadas físicamente cerca del objetivo, encontró un sistema dual-homed con alcance inalámbrico y usó ese sistema para autenticarse en la Wi-Fi del objetivo. Volexity denominó esto **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

La novedad está en la combinación. Ningún operador viaja hasta el objetivo y la MFA del servicio expuesto a Internet sigue funcionando. El vecino comprometido proporciona proximidad física; la credencial robada del objetivo proporciona acceso lógico; la Wi-Fi del objetivo se convierte en la ruta para cruzar el perímetro.

### Requisitos previos y visibilidad

- Un sistema cercano debe poder controlarse de forma remota y tener una radio compatible o acceso a otro pivot cercano.
- El SSID del objetivo debe llegar a ese sistema, y el control de acceso a la Wi-Fi debe aceptar una credencial, un certificado o un estado del dispositivo reutilizable.
- El pivot suele necesitar dos rutas simultáneas: una de vuelta al operador y otra hacia la WLAN del objetivo.
- El objetivo puede ver una nueva MAC de estación y un nombre de usuario legítimo, pero ningún certificado de dispositivo gestionado, estado de seguridad, historial o registro de entrada esperado al edificio que correspondan.
- Los registros del endpoint del vecino pueden mostrar búsquedas de redes inalámbricas, perfiles nuevos, cambios de interfaz, túneles y actividad de control remoto.

### Detección y prevención

1. Exige EAP-TLS respaldado por certificados y un estado de seguridad de dispositivo gestionado para la Wi-Fi empresarial; no permitas que una contraseña que no superó la MFA en Internet sea suficiente solo porque llega por radio.
2. Correlaciona la autenticación RADIUS con la identidad de MDM/NAC, las asociaciones históricas entre estaciones y dispositivos, la ubicación del AP, los eventos de acceso físico y las sesiones simultáneas.
3. Genera alertas cuando una cuenta se asocie por primera vez, desde un extremo de AP inusual, sin un certificado de dispositivo gestionado o mientras la misma identidad esté activa en otro lugar.
4. Supervisa los endpoints capaces de conectar interfaces en puente. En Windows, Linux y dispositivos de red, investiga perfiles WLAN inesperados, configuraciones de reenvío/NAT, adaptadores virtuales y túneles persistentes.
5. Reduce la propagación innecesaria de la señal mediante una ubicación adecuada de los AP y una planificación sensata de la potencia. Es una medida complementaria, no un método de autenticación.
6. Coordina la respuesta a incidentes con los inquilinos vecinos: la fuente de radio final también puede ser una víctima.

El [laboratorio propio de dos organizaciones](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduce estos indicios sin atacar a un vecino.

### Validar una ruta de pivot de Windows

Un host Windows con dos interfaces de red no conecta automáticamente sus interfaces en puente. Primero inventaría sus adaptadores, rutas y estado de WLAN; después, conéctate solo mediante un perfil aprobado. El argumento `name` de `netsh wlan connect` identifica un perfil instalado, no un SSID y una contraseña arbitrarios. Compara la tabla de rutas antes y después de la asociación para asegurarte de que una nueva ruta predeterminada no interrumpa la ruta de control ni invalide el resultado. Continúa con las [comprobaciones posteriores a la asociación](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) solo después de confirmar la interfaz y la ruta previstas.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

El artefacto del incidente publicado por Volexity muestra otra distinción útil. Su código C# integrado abre la WLAN API, enumera interfaces, lee XML de EAP desde el disco y llama a `WlanSetProfileEapXmlUserData` para un perfil con nombre en la primera interfaz inalámbrica. La API establece credenciales de usuario de EAP en un perfil 802.1X existente, pero el componente publicado no contiene ni `WlanConnect` ni la lógica de descubrimiento descrita en el informe. Considéralo aprovisionamiento de perfiles, no un conector completo, e inspecciona el perfil resultante como parte de la [evaluación del cliente y del supplicant](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Espacios públicos y Wi-Fi de terceros

Usar el Wi-Fi de una cafetería, un hotel, un aeropuerto o una red municipal cambia la IP que ve el destino. No proporciona anonimato. El establecimiento o su proveedor pueden conservar registros de asociación con el AP, la MAC del dispositivo, la concesión DHCP, la cuenta del portal cautivo, la validación por SMS/correo electrónico y los flujos de tráfico. Los registros de entrada, CCTV, compras, ubicación móvil y viajes pueden vincular el evento digital con una persona.

Un actor puede intentar ocultar una pista usando direcciones MAC aleatorizadas, un dispositivo separado, efectivo o un túnel. Aun así, es posible correlacionar la actividad entre capas mediante la hora de llegada, los patrones de visitas repetidas al establecimiento, las huellas de radio, el comportamiento en el portal, los tiempos del tráfico, las grabaciones de cámaras y el proveedor del túnel. Una VPN también traslada la visibilidad del destino de los registros del establecimiento a los de la VPN; no elimina el conocimiento del establecimiento de que el dispositivo estuvo allí.

Quienes administran el acceso público deberían aislar a los clientes, bloquear el tráfico lateral, usar WPA2/3-Enterprise o claves por dispositivo cuando sea viable, conservar registros de DHCP/RADIUS/seguridad de forma proporcional, proteger los portales cautivos y publicar un proceso para gestionar abusos. Los equipos red team solo deberían usar esos establecimientos cuando sus términos y el engagement lo permitan; evadir un portal, robar acceso o atacar a otros usuarios no es un atajo de pruebas autorizado.

## Dispositivos de entrega encubiertos y warshipping

Un dispositivo de entrega es un sistema pequeño que se coloca en un sitio o se envía allí, y luego se controla mediante Ethernet saliente, Wi-Fi o conexión celular. El “warshipping” empaqueta el dispositivo para que un envío normal lo introduzca en el perímetro de radio. El hardware posible abarca desde una computadora de placa única hasta un cargador modificado, un periférico USB, un dispositivo de red o un módem alimentado por batería.

Arquitectura operativa:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

El dispositivo puede proporcionar un punto de acceso remoto, realizar mediciones inalámbricas, emular un periférico autorizado para un ejercicio o retransmitir tráfico. Su origen aparente es local, pero deja rastros físicos: números de serie, embalajes, huellas dactilares, cámaras, registros de acceso, consumo eléctrico, descriptores USB, negociación del puerto del switch, huellas DHCP, comportamiento de OUI/randomización de MAC, emisiones de RF y conexiones recurrentes de rendezvous.

### Controles defensivos

- Mantén procedimientos de recepción e inventario de activos; inspecciona los dispositivos electrónicos inesperados y los paquetes dirigidos a empleados inexistentes.
- Usa 802.1X/NAC para el acceso por cable e inalámbrico, desactiva los puertos que no se utilicen y coloca los dispositivos desconocidos en una VLAN de remediación restringida.
- Genera alertas ante nuevas huellas DHCP, MAC administradas localmente que persistan, nuevos dispositivos de red/HID USB, Wi-Fi Direct/Bluetooth no autorizados y túneles salientes de larga duración.
- Establece una línea base del comportamiento de los puertos del switch, la alimentación por Ethernet, DNS y TLS. Un host pequeño sin registro en el inventario que realice conexiones cifradas periódicas es una señal mucho más relevante que el mero hecho de tener un «OUI de Raspberry Pi».
- Durante un ejercicio, inventaría, etiqueta, delimita el alcance, cifra, proporciona un mecanismo de desactivación remota, fija un plazo de recuperación y asegúrate de que su pérdida no pueda exponer credenciales reutilizables.

## Conexión de retorno celular y eSIM

Un módem celular evita la puerta de enlace de Internet del objetivo y puede mantener un drop accesible detrás del NAT del operador mediante un rendezvous saliente. Las direcciones móviles pueden cambiar o compartirse; aun así, el operador celular conserva pruebas sólidas de suscriptores y de la red: identidad de la SIM/eSIM, IMSI, IMEI del dispositivo, direcciones/puertos asignados, horarios de celda/sector y registros de cuenta/pago e itinerancia.

Desde la perspectiva de la empresa, detecta los módems y puntos de acceso personales inesperados mediante inspecciones inalámbricas/RF, inventario USB/PCI de los endpoints, restricciones de MDM, supervisión de SSID no autorizados e inspecciones físicas. Un drop que utiliza conexión celular para el control aún puede detectarse por su comportamiento local de Ethernet/Wi-Fi y sus emisiones de radio.

En los ejercicios autorizados, la organización debería ser titular de la suscripción y del módem, registrar los identificadores junto con los del controlador y verificar que los términos del operador/proveedor permitan el tráfico. Una etiqueta de prepago o una compra con criptomonedas no borra los registros de torres, dispositivos ni comercios minoristas.

## Randomización de MAC y fingerprinting de dispositivos

Los sistemas modernos pueden usar una MAC aleatoria administrada localmente para cada red. Esto reduce el seguimiento pasivo a largo plazo basado en una MAC de fábrica estable; no oculta:

- el momento de las sondas/asociaciones ni el conjunto de capacidades de red solicitadas;
- los elementos de información 802.11, las velocidades admitidas y el comportamiento específico del proveedor;
- las opciones DHCP/nombre de host, los identificadores IPv6 y el fingerprint del navegador/portal cautivo;
- la identidad o el certificado autenticados de 802.1X;
- las cuentas de capas superiores, los túneles y los patrones de tráfico; ni
- la observación física.

Los defensores no deberían usar listas de permitidos de MAC como autenticación. Vincula la identidad de radio con el certificado y la postura del dispositivo, y considera normales las MAC cambiantes, salvo que otro contexto resulte anómalo.

## Secuestro de enlaces satelitales

Kaspersky documentó que Turla aprovechó debilidades de sistemas antiguos de Internet satelital DVB-S unidireccional. Según el modelo descrito, un suscriptor remoto legítimo enviaba solicitudes salientes por un enlace terrestre, pero recibía datos descendentes mediante una transmisión satelital de área extensa sin cifrar. Un actor dentro de la cobertura del satélite podía observar el enlace descendente, elegir la IP de un suscriptor activo y hacer que las respuestas de C2 se dirigieran a esa IP. Tanto el suscriptor legítimo como el actor recibían la transmisión; el actor extraía el tráfico del puerto seleccionado, mientras que el suscriptor legítimo descartaba los paquetes no solicitados. Entonces, el operador de C2 parecía utilizar una dirección del proveedor satelital ubicada en otra región geográfica.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Esto era específico del protocolo/servicio, estaba limitado por el ancho de banda y no equivalía a comprometer un terminal satelital moderno bidireccional cifrado. Tampoco ocultaba la ruta de salida de la solicitud del actor ante un observador con capacidades suficientes. Entre las oportunidades de detección se incluyen el enrutamiento asimétrico/imposible, el tráfico dirigido a un suscriptor que no inició el flujo, los puertos de destino inusuales, la telemetría del proveedor, la investigación de la ubicación del receptor/RF y la configuración del malware. Usa este caso para cuestionar la suposición de que geolocalizar una IP de C2 permite geolocalizar a quien la controla, no como una receta para construirlo.

## Hoja de trabajo para correlacionar lo físico con lo digital

Cuando una fuente aparentemente local resulte sospechosa, crea una única cronología:

1. normaliza los relojes de AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switches y control de acceso físico;
2. identifica la primera asociación de radio o conexión de enlace, no solo la primera alerta;
3. relaciona la estación con el certificado, la postura del dispositivo, la huella DHCP y la ubicación del switch/AP;
4. busca actividad simultánea de control remoto/túnel en sistemas cercanos;
5. revisa entregas, visitantes, excepciones de inventario, cámaras y hallazgos de RF conforme a la política/ley aplicable;
6. preserva el dispositivo sospechoso y el estado volátil de la red; no lo apagues y vuelvas a encender a ciegas;
7. determina si la infraestructura que parece ser el origen está controlada por el actor o pertenece a otra víctima.

## References

- [1] [Volexity — El ataque Nearest Neighbor: cómo un APT ruso armó redes Wi-Fi cercanas para obtener acceso encubierto](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla satelital: comando y control de APT en el cielo](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Incorporaciones de hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Directrices para proteger redes inalámbricas de área local](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Código WLAN de PowerShell/C# censurado](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Función WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
