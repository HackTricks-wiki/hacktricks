# Nodos de campo autorizados resistentes a la captura

{{#include ../banners/hacktricks-training.md}}

Una Raspberry Pi, mini-PC, travel router o appliance celular ubicado en las instalaciones puede proporcionar a un red team autorizado un punto de observación duradero. También es un objetivo probable de descubrimiento, robo y atribución. Por lo tanto, el objetivo de diseño adecuado es un **acceso estable y controlado con poca autoridad en el nodo de campo**, no un implant no rastreable.

Esta guía se aplica únicamente a equipos colocados con la autorización escrita del propietario del sitio. Una cafetería, un vecino, un hotel o un edificio compartido no están dentro del alcance simplemente porque su red sea accesible. No ocultes hardware en un lugar cuyo propietario no haya dado su consentimiento, evites un captive portal, uses las credenciales de otra persona, interfieras con la monitorización ni intentes borrar evidencias después del descubrimiento.

{% hint style="warning" %}
No existe una configuración fiable de “no dejar rastros”. La asociación de radio, DHCP/NAT, el carrier, las cámaras y los registros de compra, dispositivo, proveedor, controller y destino pueden sobrevivir al dispositivo. En su lugar, un red team responsable elimina los **secretos personales y no relacionados** del nodo, conserva la atribución protegida en el controller y hace que la captura sea fácil de contener.
{% endhint %}

## Ventajas y desventajas

**Ventajas:** fuente interna o adyacente al objetivo realista; testing estable de alta velocidad; valida NAC, egress, inventario físico y cobertura del SOC; puede continuar aunque cambie la dirección del operador; el acceso acotado puede revocarse de forma centralizada.

**Desventajas:** la colocación física crea evidencias sólidas; la pérdida puede exponer credenciales del dispositivo, perfiles de red y datos recopilados; el tráfico de control repetido es detectable; la alimentación, los portales y los cambios de radio afectan a la fiabilidad; un túnel amplio puede convertirse en un pivot sin control.

## Modelo de amenazas e invariantes de diseño

Asume que quien encuentre el dispositivo puede retirar el almacenamiento, inspeccionar el firmware, copiar todos los secretos almacenados por el software, observar el comportamiento posterior de la red y entregar el dispositivo al cliente o a las fuerzas del orden. El cifrado de disco completo protege un dispositivo apagado únicamente dentro de su modelo de amenazas establecido; un nodo en ejecución y desbloqueado y las claves liberadas en memoria son casos diferentes.

| Invariante | Consecuencia práctica |
|---|---|
| Sin identidad directa entre el operador y el nodo | El operador inicia sesión en el gateway de la organización; el nodo tiene una identidad de dispositivo diferente |
| Sin material de la workstation personal | No hay clave SSH personal, perfil del navegador, correo electrónico, password manager, emparejamiento con el teléfono ni caché de cloud CLI personales |
| Sin secreto maestro del controller | Un nodo no puede inscribir otro, cambiar la policy ni descifrar otros engagements |
| Solo salida y de alcance reducido | La red de campo no acepta ningún listener de gestión; el nodo solo llega a servicios de rendezvous, actualización y tiempo con nombres definidos |
| Autoridad limitada y de corta duración | Cada credencial corresponde a un dispositivo, audience, servicio, expiración y vía de revocación inmediata |
| Datos locales mínimos | Los resultados se envían al controller; las cachés están cifradas, tienen un tamaño y TTL limitados y no son autoritativas |
| La responsabilidad del controller sobrevive a la captura | La relación entre activo y engagement, las aprobaciones, el acceso del operador y los comandos se almacenan de forma centralizada y con controles de acceso |
| La pérdida detiene el trabajo | El descubrimiento o un cambio de estado inexplicable activa la detención, revocación, notificación y conservación de evidencias, no la destrucción remota |

La línea base de IoT de NIST agrupa la identificación del dispositivo, la configuración, la protección de datos, el acceso lógico, la actualización segura del software y el conocimiento del estado de cybersecurity como capacidades esenciales. Trata específicamente el conocimiento del estado y los registros de eventos externos al dispositivo como elementos de apoyo para la investigación de compromisos.<sup>[[1]](#references)</sup>

## Arquitectura de referencia
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
El gateway debe saber qué operador identificado accedió a qué dispositivo identificado. El nodo de campo solo necesita una credencial de dispositivo para el rendezvous. Nunca obtiene la dirección de origen ni el secreto de autenticación del operador, y el operador nunca copia una clave privada de administración en él. Esto reduce el vínculo personal recuperable **del almacenamiento de campo** sin destruir la trazabilidad del ejercicio.

Para una flota mayor, un sistema de workload identity puede emitir identidades X.509 de corta duración y rotar las claves automáticamente. SPIFFE recomienda SVIDs X.509 cuando sea posible y describe las duraciones cortas y la rotación frecuente como medidas para limitar la exposición derivada del compromiso de claves.<sup>[[2]](#references)</sup> Un equipo pequeño puede aplicar las mismas propiedades con una CA privada y certificados automatizados por dispositivo; no es necesario instalar SPIRE simplemente para cumplir este patrón.

## Step 1: autorizar y registrar la colocación

1. Registra el propietario, el sitio, la zona exacta de colocación permitida, las redes autorizadas, la ventana de evaluación, los destinos/acciones permitidos y los contactos de emergencia.
2. Registra el modelo, el número de serie, el número de serie del almacenamiento, las direcciones MAC cableadas/inalámbricas, el IMEI/eSIM del módem o el ICCID de la SIM, la fuente de alimentación y una fotografía actual.
3. Asigna al dispositivo un identificador de engagement no personal, por ejemplo `E2026-014-DROP03`. No incluyas el nombre de un cliente en los hostnames o SSIDs difundidos.
4. Informa al responsable del ejercicio y al grupo mínimo necesario de seguridad física/SOC encargado de la desconflicción qué significan “perdido”, “movido” y “descubierto” para esta prueba.
5. Acuerda previamente quién puede recuperarlo y cómo puede informarlo quien lo encuentre. Una etiqueta de seguridad puede omitir detalles confidenciales del cliente y proporcionar un callback controlado.
6. Establece una caducidad automática de la autorización. La conectividad que continúe después del fin del alcance no debe prolongar el permiso.

## Step 2: crear una imagen mínima recuperable

Usa una imagen de OS compatible, verifica su firma/checksum mediante el canal documentado del proveedor, instala las actualizaciones de seguridad y conserva un manifiesto de build reproducible. Prefiere una base de solo lectura o inmutable con una pequeña partición de datos escribible cuando el software lo permita.

1. Elimina las cuentas predeterminadas, los servicios de demostración, los compiladores y los paquetes que no sean necesarios para la workload autorizada.
2. Deshabilita la GUI local, Bluetooth, los protocolos de descubrimiento, el uso compartido de archivos, Wi-Fi P2P y la administración entrante, salvo que el ejercicio requiera explícitamente alguno de ellos.
3. Habilita secure boot y measured boot/la liberación de claves respaldada por TPM si el hardware realmente los admite; no afirmes que una configuración de Raspberry Pi tiene measured boot de nivel PC sin validar el modelo exacto.
4. Cifra el estado local escribible y configura un tamaño máximo y un tiempo de retención estrictos. El cifrado es un control de retraso/contención, no una prueba de que un nodo en ejecución no revele nada.
5. Envía los logs importantes fuera del dispositivo. Limita los journals locales para evitar el agotamiento del almacenamiento, pero no configures el borrado de logs ni la eliminación anti-forense.
6. Almacena el manifiesto de la imagen, las versiones de los paquetes, el hash de configuración y las instrucciones de recuperación en el controller.
7. Reinstala la imagen de un dispositivo de repuesto a partir del manifiesto y ejecuta la misma prueba de estado. Un diseño que solo su creador puede recuperar no está preparado para el campo.

## Step 3: emitir identidades con confianza unidireccional

Crea tres identidades diferentes:

- una **identidad de dispositivo**, aceptada únicamente por el rendezvous de este dispositivo;
- una **identidad de operador**, aceptada por el gateway de la organización y protegida con MFA resistente al phishing; y
- una **identidad de controller/deployment**, utilizada para firmar jobs o configuraciones aprobados, mantenida fuera tanto del operador como del nodo de campo.

El nodo debe tener la clave pública necesaria para verificar los jobs firmados, nunca la clave de firma. Una credencial de dispositivo capturada no debe autenticar en consolas cloud, repositorios de código, cuentas de pago, otros nodos ni la producción del cliente.

Usa certificados de corta duración cuando la renovación automática sea fiable. Cuando sea operacionalmente necesario utilizar una clave de WireGuard de larga duración, trata su clave pública como identificador de revocación y restrínjela mediante una dirección de túnel específica del peer, una política de firewall y una autorización del broker. Conserva una acción del controller probada que elimine inmediatamente ese peer.

## Step 4: rendezvous saliente estable

El siguiente patrón de laboratorio propio proporciona una administración estable mediante NAT sin exponer un servicio entrante. Es networking ordinario de WireGuard, no un reverse shell encubierto. Usa direcciones de documentación y sustitúyelas únicamente por endpoints propiedad de la organización.

En el rendezvous de la organización, asigna `10.77.0.1/32`; asigna al nodo de campo `10.77.0.20/32`. La entrada del peer del gateway debe aceptar únicamente la dirección individual del nodo:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
El nodo se conecta de forma saliente al rendezvous y mantiene el mapeo NAT solo cuando es necesario:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard documenta 25 segundos como un intervalo de keepalive razonable en muchas implementaciones de NAT/firewall cuando se necesita persistencia; dejarlo deshabilitado es preferible cuando no se necesita.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` convierte deliberadamente esto en una ruta de gestión, no en un pivot de ruta predeterminada.

Después, aplica controles fuera de WireGuard:

1. Resuelve `vpn.redteam.example` mediante la ruta de DNS de bootstrap aprobada y fija el endpoint esperado de la organización en los registros de despliegue.
2. En el nodo, permite DHCP/RA saliente, el DNS/NTP requerido, el endpoint de rendezvous y la ruta mínima de actualización aprobada. Deniega el tráfico entrante no solicitado en cada uplink.
3. En el rendezvous, permite que `10.77.0.20` acceda únicamente al servicio de broker/health requerido para el ejercicio. No lo reenvíes de forma general a una red de clientes.
4. Coloca el acceso interactivo de operadores detrás del gateway de la organización. Evita exponer SSH desde el nodo a través del túnel si una interfaz de signed pull-job satisface la evaluación.
5. Configura el service manager para iniciar el túnel después de la red, reiniciarlo tras un fallo con backoff limitado y generar una alerta después de fallos repetidos. Un bucle de reinicio no debe saturar el recinto ni ocultar el fallo subyacente.
6. Verifica el último handshake del peer, pero no uses “existe un handshake” como prueba de que el dispositivo no está comprometido.

TURN puede proporcionar reachability solo mediante relay para un plano de control WebRTC diseñado específicamente, y una message queue puede tolerar un servicio intermitente. TURN proporciona explícitamente a un cliente una dirección pública de relay detrás de NAT; su servidor sigue siendo un observador.<sup>[[4]](#references)</sup> Elige una arquitectura de control en lugar de apilar túneles sin indicar el observador o el beneficio de fiabilidad.

## Paso 5: estabilidad del uplink sin enlaces personales

Para un nodo de recinto autorizado, prioriza este orden:

1. VLAN cableada o de pruebas dedicada proporcionada por el cliente;
2. perfil de Wi-Fi empresarial/de invitados aprobado por el propietario;
3. fallback de red celular/APN privado contratado por la organización.

Nunca lo configures con un hotspot de teléfono personal, SSID doméstico, eSIM personal, cuenta personal de Apple/Google ni un perfil Wi-Fi exportado desde un portátil de uso diario. Esos son exactamente los artefactos a los que se conectará una captura.

Para cada uplink aprobado:

- registra el SSID/BSSID o switch/VLAN y el comportamiento esperado del captive portal;
- establece una prioridad determinista y un health check hacia un endpoint controlado;
- haz que el failover cambie únicamente el underlay; las identidades del dispositivo y del operador permanecen en el broker;
- asegúrate de que el tráfico DNS, IPv6 y de las aplicaciones no evite el rendezvous durante la transición;
- genera alertas ante un SSID/BSSID desconocido, cambio de SIM, nuevo gateway predeterminado, cambio de IP pública/ASN o uplinks simultáneos;
- prueba la pérdida de alimentación, renovación DHCP, reinicio del AP, cambio de IP pública, 24 horas de inactividad, pérdida del túnel y la recuperación de primario a secundario y de nuevo a primario antes del despliegue.

El direccionamiento MAC privado puede reducir el tracking casual entre redes, pero a menudo se necesita una MAC estable por red para el NAC autorizado. Registra lo que realmente hace el sistema operativo elegido y no cambies la MAC para eludir el control de acceso del propietario.

## Paso 6: limita el trabajo y los datos

Un nodo de campo seguro no debe aceptar texto de shell arbitrario desde un buzón. Define tipos de jobs firmados como `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` u otra acción nombrada explícitamente en las rules of engagement. Valida de nuevo en el nodo el destino, la duración, la tasa, el tamaño de salida y el alcance.

1. Asigna a cada job un ID único, audiencia del dispositivo, hora de emisión, expiración, referencia de alcance y salida máxima.
2. Fírmalo con la identidad del controlador/despliegue.
3. Rechaza campos desconocidos, jobs expirados/reproducidos y jobs destinados a otro dispositivo.
4. Transmite los resultados a un collector controlado; cifra y aplica TTL a cualquier spool local inevitable.
5. Registra en el controlador el ID del job aceptado/rechazado y el hash del resultado. No coloques parámetros de comandos sensibles en un canal público de monitoring.
6. Detén el procesamiento cuando expire la autorización, falle la rotación de identidad o el controlador marque el dispositivo como quarantined.

## Monitoring para detectar descubrimiento, pérdida o compromiso

El monitoring puede indicar al controlador que el estado observado cambió. No puede demostrar de forma fiable que “los investigadores encontraron el dispositivo”, y tratar de vigilar a los responders o sondear sus sistemas excedería una evaluación autorizada.

### Recopila el estado fuera del dispositivo

Envía al controlador un health record firmado y de bajo volumen con un intervalo operativo aleatorio pero limitado. Incluye únicamente lo que el controlador necesite:

- ID del dispositivo, boot ID/counter y uptime monotónico;
- hash de configuración/imagen y versión del software;
- serial del certificado del dispositivo y estado de renovación;
- clase de uplink, interfaz, BSSID o contexto de switch según autorización, hash del gateway predeterminado e IP pública/ASN observados por un servicio controlado;
- antigüedad del handshake del túnel, contadores de paquetes y profundidad de la cola;
- estado del switch de la carcasa o del hardware-tamper si el propietario aprobó el sensor;
- presión del disco, temperatura, estimación del desfase del reloj y último ID de job exitoso;
- un número de secuencia y una firma para revelar replay o interrupciones.

Almacena de forma centralizada la autenticación del gateway, las decisiones de policy, el acceso de operadores, el envío de jobs, los hashes de resultados, los eventos de auditoría del proveedor y las alertas. CISA recomienda centralizar los logs, protegerlos frente al borrado, establecer una línea base de la actividad normal y designar contactos de incident response.<sup>[[5]](#references)</sup>

### Indicadores de descubrimiento/compromiso

| Señal | Posibles explicaciones | Acción del controlador |
|---|---|---|
| Heartbeat ausente | fallo de alimentación/red, cambio de portal, daño, bloqueo deliberado o retirada | corrobora el estado del proveedor/recinto; no reconectes desde una ruta no aprobada |
| Boot counter cambiado inesperadamente | corte de alimentación, crash, retirada o mantenimiento | pon los jobs en quarantine; compara la hora y los eventos del recinto |
| Hash de configuración/imagen cambiado | error de actualización, fallo de almacenamiento o tampering | detén el trabajo; revoca si no corresponde a una release aprobada por el controlador |
| Nuevo uplink/BSSID/gateway/ASN | sustitución del AP, roaming, desplazamiento del dispositivo o interception | compara con el inventario aprobado; pon en quarantine una transición no explicada |
| Job/firma rechazado repetidamente | corrupción, replay o controlador no autorizado | detén el procesamiento e investiga los logs del gateway/controlador |
| Credencial del dispositivo usada dos veces o desde rutas incompatibles | clave clonada, reutilización de snapshot o transición de red | revoca inmediatamente; conserva ambos registros de sesión |
| Login, interfaz, proceso o evento de privilegios local inesperado | mantenimiento o compromiso | aísla mediante la policy del broker; conserva la evidencia |
| Transición del switch/estado de la carcasa | servicio, movimiento o descubrimiento | notifica al contacto del recinto designado; no actives acciones destructivas |
| Aviso de abuso del proveedor/consulta sobre la cuenta o alerta del SOC | detección, configuración incorrecta o tráfico fuera de alcance | detén la actividad e inicia el proceso de deconfliction/incident |
| Sentinel credential utilizada | alguien leyó un secret señuelo sin privilegios, único para este nodo | revoca la identidad real del dispositivo y conserva el historial de alertas |

Una sentinel credential debe conceder **ningún acceso**, llamar únicamente a un servicio de alertas controlado por la organización y estar declarada en las rules of engagement. Es un tripwire para la lectura no autorizada, no un beacon para rastrear a quien encontró el equipo.

### Umbrales de alerta

Usa reglas stateful, no una única alarma dramática de “capturado”:

- **warning:** un intervalo perdido, cambio normal de dirección o crecimiento de la cola;
- **degraded:** tres intervalos consecutivos perdidos, retraso de renovación, pérdida del uplink primario o reinicio repetido;
- **quarantine:** cambio no aprobado de hash/boot/uplink, credencial duplicada, uso del sentinel o evento privilegiado inesperado;
- **confirmed discovery/loss:** informe del recinto/controlador, discrepancia en el inventario físico, recuperación del dispositivo por una persona no prevista o escalación validada del proveedor/SOC.

Prueba la entrega de alertas mediante un canal independiente del nodo de campo. Evita enviar detalles sensibles del cliente/dispositivo a mensajería personal o cuentas de push de consumo.

## Runbook ante sospecha de descubrimiento o captura

1. **Detén:** suspende los nuevos jobs y las sesiones de operadores. No envíes un probe para “comprobar si te están vigilando”.
2. **Pon en quarantine:** haz que el broker deniegue la identidad del dispositivo y sus rutas, conservando los logs existentes.
3. **Revoca:** revoca el certificado/clave del dispositivo, el token de la queue, la credencial de actualización y cualquier service token de propósito único. Suspende la SIM de la organización cuando sea plausible una pérdida física.
4. **Preserva:** toma snapshots de los registros del controlador, gateway, proveedor y alertas; registra la hora de confianza, quién actuó y la última configuración conocida. No borres ni hagas remote wipe del nodo.
5. **Notifica:** contacta con el controlador del ejercicio, el contacto de incident del cliente y los contactos legal/privacy definidos en la autorización. Si lo encontró un tercero, utiliza el proceso de recuperación acordado previamente.
6. **Evalúa:** asume que todos los secrets y resultados almacenados en caché en el nodo están expuestos. Enumera exactamente a qué podía acceder cada secret y si se utilizó después del evento sospechoso.
7. **Contén aguas abajo:** rota las credenciales de servicios afectados, invalida los jobs pendientes e inspecciona los logs de targets/proveedores controlados en busca de actividad inesperada.
8. **Recupera de forma segura:** recupéralo únicamente mediante una persona autorizada; fotografíalo/empaquétalo, registra la cadena de custodia y adquiere evidencia forense según indique el cliente.
9. **Reanuda con una nueva identidad:** nunca vuelvas a habilitar silenciosamente la credencial capturada. Reconstruye a partir del manifest conocido, corrige el fallo de control y obtén aprobación explícita.

La guía actual de incident response de NIST integra la preparación, detección, respuesta y recuperación en la gestión del riesgo de ciberseguridad de toda la organización; preserva primero para que el cliente pueda determinar qué ocurrió y elegir la respuesta adecuada.<sup>[[6]](#references)</sup>

## Simulacro de captura antes del despliegue

Entrega una unidad de prueba desbloqueada o una copia de su almacenamiento a un revisor independiente y pídele que enumere:

1. identificadores del dispositivo/recinto/engagement;
2. nombres de operadores, cuentas personales, redes domésticas/de estaciones de trabajo y contactos de recuperación;
3. destinos y credenciales del controlador/broker;
4. perfiles de red del cliente y resultados almacenados en caché;
5. otros dispositivos/proyectos accesibles con cada secret;
6. credenciales de valor o de pago;
7. qué puede revocar el controlador y con qué rapidez;
8. qué actividad sigue siendo atribuible a partir de los logs centrales.

Criterios de aprobación: cero cuentas personales/claves de estaciones de trabajo; cero autoridad de cross-engagement o enrollment; ninguna credencial de pago; caché cifrada y limitada; una acción documentada de revocación del dispositivo; accountability completa en el lado del controlador. Trata cualquier enlace personal inesperado o capacidad lateral como un bloqueo de release.

## Cierre

1. Detén los jobs y deshabilita la ruta del broker al finalizar el alcance.
2. Recupera y concilia el inventario exacto; informa de cualquier elemento que falte.
3. Conserva logs/resultados y, si es necesario, una imagen forense conforme al plan de retención del engagement.
4. Revoca las identidades del dispositivo, SIM, queue, actualización y servicios incluso cuando se haya recuperado el hardware.
5. Solo después de la preservación/aceptación, sanitiza o destruye los medios mediante el proceso de eliminación de datos aprobado por el propietario y registra la finalización. Esto es gestión del ciclo de vida, no concealment.
6. Elimina las reservas NAC/DHCP del recinto, las rutas del broker, el DNS, los roles cloud, las reglas de alertas y los contactos temporales.
7. Documenta la detección observada, la telemetría ausente, el tiempo hasta quarantine y cada artefacto que expuso la captura.

## References

- [1] [NIST — Catálogo de capacidades de ciberseguridad de dispositivos IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Conceptos e identidades de workloads de corta duración](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Uso de logging en sistemas empresariales](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Recomendaciones y consideraciones de Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
