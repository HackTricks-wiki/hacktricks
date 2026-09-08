# Nodos de campo autorizados resistentes a la captura

Un Raspberry Pi, mini-PC, travel router o dispositivo celular instalado en las instalaciones puede proporcionar a un red team autorizado un punto de observación duradero. También es un punto probable de descubrimiento, robo y atribución. Por tanto, el objetivo de diseño adecuado es **acceso estable y controlado con poca autoridad en el nodo de campo**, no un implant no rastreable.

Esta guía se aplica únicamente a equipos instalados con la autorización escrita del propietario del sitio. Una cafetería, un vecino, un hotel o un edificio compartido no están dentro del alcance simplemente porque su red sea accesible. No ocultes hardware en un lugar cuyo responsable no haya dado su consentimiento, evites un captive portal, uses las credenciales de otra persona, interfieras con la monitorización ni intentes borrar evidencias después del descubrimiento.

{% hint style="warning" %}
No existe una configuración fiable de «no dejar rastros». Los registros de asociación de radio, DHCP/NAT, operador, cámaras, compra, dispositivo, proveedor, controlador y destino pueden sobrevivir al dispositivo. Un red team responsable elimina del nodo los **secretos personales y no relacionados**, conserva la atribución protegida en el controlador y hace que la captura sea fácil de contener.
{% endhint %}

## Ventajas y desventajas

**Ventajas:** fuente interna o adyacente al objetivo realista; testing estable y de alta velocidad; valida NAC, egress, inventario físico y cobertura del SOC; puede continuar aunque cambie la dirección del operador; el acceso limitado puede revocarse centralmente.

**Desventajas:** la instalación física genera evidencias sólidas; la pérdida puede exponer credenciales del dispositivo, perfiles de red y datos recopilados; el tráfico de control repetido es detectable; los cambios de alimentación, portales y radio reducen la fiabilidad; un túnel amplio puede convertirse en un pivot no controlado.

## Modelo de amenazas e invariantes de diseño

Supón que quien encuentre el dispositivo puede retirar el almacenamiento, inspeccionar el firmware, copiar todos los secretos almacenados por el software, observar el comportamiento posterior de la red y entregar el dispositivo al cliente o a las fuerzas del orden. El cifrado de disco completo protege un dispositivo apagado únicamente según su modelo de amenazas declarado; un nodo desbloqueado y en ejecución, y las claves liberadas en memoria, son casos diferentes.

| Invariante | Consecuencia práctica |
|---|---|
| Sin identidad directa entre el operador y el nodo | El operador inicia sesión en el gateway de la organización; el nodo tiene una identidad de dispositivo diferente |
| Sin material de la workstation personal | No hay clave SSH personal, perfil del navegador, correo electrónico, password manager, pairing con el teléfono ni caché de la CLI de cloud |
| Sin secreto maestro del controlador | Un nodo no puede registrar otro, cambiar la policy ni descifrar otros engagements |
| Solo saliente y limitado | La red de campo no acepta ningún listener de management; el nodo solo accede a servicios de rendezvous, actualización y tiempo expresamente autorizados |
| Autoridad limitada y de corta duración | Cada credencial corresponde a un único dispositivo, audience, servicio, expiración y mecanismo de revocación inmediata |
| Datos locales mínimos | Los resultados se transmiten al controlador; las cachés están cifradas, tienen límites de tamaño/TTL y no son autoritativas |
| La responsabilidad del controlador sobrevive a la captura | La relación entre activo y engagement, las aprobaciones, el acceso de los operadores y los comandos se almacenan centralmente y tienen controles de acceso |
| La pérdida detiene el trabajo | El descubrimiento o un cambio de estado inexplicado activa la detención, revocación, notificación y conservación de evidencias, no la destrucción remota |

La baseline de IoT de NIST agrupa la identificación del dispositivo, la configuración, la protección de datos, el acceso lógico, la actualización segura del software y el conocimiento del estado de cybersecurity como capacidades esenciales. En concreto, considera el conocimiento del estado y los registros de eventos fuera del dispositivo como elementos de apoyo para investigar compromisos.<sup>[[1]](#references)</sup>

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
El gateway debe saber qué operador identificado accedió a qué dispositivo identificado. El nodo de campo solo necesita una credencial de dispositivo para el rendezvous. Nunca conoce la dirección de origen ni el secreto de autenticación del operador, y el operador nunca copia una private management key en él. Esto reduce el vínculo personal recuperable **desde el almacenamiento del nodo de campo** sin destruir la trazabilidad del ejercicio.

Para una flota más grande, un sistema de workload identity puede emitir identidades X.509 de corta duración y rotar las claves automáticamente. SPIFFE recomienda X.509 SVIDs cuando sea posible y describe las duraciones cortas y la rotación frecuente como medidas para limitar la exposición ante el compromiso de claves.<sup>[[2]](#references)</sup> Un equipo pequeño puede aplicar las mismas propiedades con una CA privada y certificados automatizados por dispositivo; no es necesario instalar SPIRE simplemente para cumplir este patrón.

## Step 1: autorizar y registrar la ubicación

1. Registra el propietario, el sitio, la zona exacta de ubicación permitida, las redes permitidas, la ventana de evaluación, los destinos/acciones permitidos y los contactos de emergencia.
2. Registra el modelo, el número de serie, el número de serie del almacenamiento, las MAC cableadas/inalámbricas, el IMEI/eSIM del módem o el ICCID de la SIM, la fuente de alimentación y una fotografía actual.
3. Asigna al dispositivo un identificador de engagement no personal, por ejemplo `E2026-014-DROP03`. No codifiques el nombre de un cliente en los hostnames o SSIDs de broadcast.
4. Informa al controlador del ejercicio y al grupo mínimo necesario de seguridad física/SOC encargado de la deconfliction qué significan “perdido”, “movido” y “descubierto” para esta prueba.
5. Acuerda previamente quién puede recuperarlo y cómo puede informar una persona que lo encuentre. Una etiqueta de seguridad puede omitir detalles confidenciales del cliente y proporcionar un callback controlado.
6. Establece una caducidad automática de la autorización. La conectividad que continúe después del final del scope no debe ampliar el permiso.

## Step 2: crear una imagen mínima recuperable

Usa una imagen de OS compatible, verifica su firma/checksum mediante el canal documentado por el proveedor, instala las security updates y conserva un build manifest reproducible. Prefiere una base de solo lectura o inmutable con una pequeña partición de datos writable cuando el software lo permita.

1. Elimina las cuentas predeterminadas, los servicios de demostración, los compiladores y los paquetes que no sean necesarios para el workload autorizado.
2. Deshabilita la GUI local, Bluetooth, los protocolos de discovery, el file sharing, Wi-Fi P2P y la administración entrante, salvo que el ejercicio requiera explícitamente alguno de ellos.
3. Habilita secure boot y measured boot/TPM-backed key release si el hardware realmente los admite; no afirmes que una configuración de Raspberry Pi tiene measured boot de clase PC sin validar el modelo exacto.
4. Cifra el estado local writable y configura un tamaño máximo y un tiempo de retención estrictos. El cifrado es un control de demora/contención, no una prueba de que un nodo en ejecución no revele nada.
5. Envía los logs importantes fuera del dispositivo. Limita los journals locales para evitar el agotamiento del almacenamiento, pero no configures el borrado de logs ni la eliminación anti-forense.
6. Almacena el manifest de la imagen, las versiones de los paquetes, el hash de configuración y las instrucciones de recovery en el controlador.
7. Reinstala la imagen de un spare a partir del manifest y ejecuta el mismo health test. Un diseño que solo su builder puede recuperar no está preparado para campo.

## Step 3: emitir identidades con confianza unidireccional

Crea tres identidades diferentes:

- una **identidad de dispositivo**, aceptada únicamente por el rendezvous de este dispositivo;
- una **identidad de operador**, aceptada por el gateway de la organización y protegida con MFA resistente al phishing; y
- una **identidad de controlador/deployment**, utilizada para firmar jobs o configuraciones aprobadas y conservada fuera del operador y del nodo de campo.

El nodo debe tener la clave pública necesaria para verificar jobs firmados, nunca la signing key. Una credencial de dispositivo capturada no debe autenticarse en consolas cloud, repositorios de código fuente, cuentas de pago, otros nodos ni la producción del cliente.

Usa duraciones cortas de certificados cuando la renovación automática sea fiable. Cuando una clave de WireGuard de larga duración sea necesaria por motivos operativos, trata su clave pública como el identificador de revocación y restríngela mediante la dirección de túnel específica del peer, la política de firewall y la autorización del broker. Mantén una acción del controlador probada que elimine inmediatamente ese peer.

## Step 4: rendezvous outbound estable

El siguiente patrón de laboratorio propio proporciona management estable mediante NAT sin exponer un servicio entrante. Es networking ordinario de WireGuard, no un reverse shell encubierto. Usa direcciones de documentación y sustitúyelas únicamente por endpoints propiedad de la organización.

En el rendezvous de la organización, asigna `10.77.0.1/32`; asigna al nodo de campo `10.77.0.20/32`. La entrada del peer del gateway solo debe aceptar la dirección única del nodo:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
El nodo apunta hacia el rendezvous y mantiene el mapeo NAT solo cuando es necesario:
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

1. Resuelve `vpn.redteam.example` mediante la ruta DNS de bootstrap aprobada y fija el endpoint esperado de la organización en los registros de deployment.
2. En el nodo, permite DHCP/RA saliente, el DNS/NTP requerido, el endpoint de rendezvous y la ruta mínima de actualización aprobada. Deniega el tráfico entrante no solicitado en cada uplink.
3. En el rendezvous, permite que `10.77.0.20` acceda únicamente al servicio de broker/health requerido para el ejercicio. No lo reenvíes de forma general a una red de clientes.
4. Sitúa el acceso interactivo del operador detrás del gateway de la organización. Evita exponer SSH desde el nodo a través del túnel si una interfaz de signed pull-job satisface la evaluación.
5. Configura el service manager para iniciar el túnel después de networking, reiniciarlo tras un fallo con backoff limitado y generar una alerta después de fallos repetidos. Un bucle de reinicio no debe saturar el recinto ni ocultar el fallo subyacente.
6. Verifica el último handshake del peer, pero no uses “handshake existe” como prueba de que el dispositivo no está comprometido.

TURN puede proporcionar reachability únicamente mediante relay para un control plane WebRTC diseñado específicamente para este fin, y una message queue puede tolerar un servicio intermitente. TURN proporciona explícitamente a un cliente una dirección pública de relay detrás de NAT; su servidor sigue siendo un observador.<sup>[[4]](#references)</sup> Elige una arquitectura de control en lugar de apilar túneles sin indicar un beneficio de observabilidad o fiabilidad.

## Paso 5: estabilidad del uplink sin enlaces personales

Para un nodo de recinto autorizado, prefiere este orden:

1. VLAN cableada o de pruebas dedicada proporcionada por el cliente;
2. perfil de Wi-Fi empresarial/de invitados aprobado por el propietario;
3. fallback de red móvil/APN privado contratado por la organización.

Nunca lo configures con un hotspot de teléfono personal, SSID doméstico, eSIM personal, cuenta personal de Apple/Google ni un perfil Wi-Fi exportado desde un portátil de uso diario. Esos son exactamente los artefactos a los que se conectará una captura.

Para cada uplink aprobado:

- registra el SSID/BSSID o switch/VLAN y el comportamiento esperado del captive portal;
- establece una prioridad determinista y un health check hacia un endpoint propio;
- haz que el failover cambie únicamente el underlay; las identidades del dispositivo y del operador permanecen en el broker;
- asegúrate de que DNS, IPv6 y el tráfico de la aplicación no eludan el rendezvous durante la transición;
- genera una alerta ante un SSID/BSSID desconocido, cambio de SIM, nuevo gateway predeterminado, cambio de IP pública/ASN o uplinks simultáneos;
- prueba la pérdida de alimentación, la renovación de DHCP, el reinicio del AP, el cambio de IP pública, 24 horas de inactividad, la pérdida del túnel y la recuperación primaria-secundaria-primaria antes del deployment.

El direccionamiento MAC privado puede reducir el tracking casual entre redes, pero a menudo se necesita una MAC estable por red para un NAC autorizado. Registra lo que realmente hace el OS elegido y no la rotes alrededor del control de acceso del propietario.

## Paso 6: limitar el trabajo y los datos

Un field node seguro no debería aceptar texto de shell arbitrario desde un mailbox. Define tipos de jobs firmados como `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` u otra acción nombrada explícitamente en las rules of engagement. Valida de nuevo en el nodo el destino, la duración, la tasa, el tamaño de salida y el scope.

1. Asigna a cada job un ID único, audiencia del dispositivo, hora de emisión, caducidad, referencia de scope y salida máxima.
2. Fírmalo con la identidad de controller/deployment.
3. Rechaza campos desconocidos, jobs caducados/reproducidos y jobs destinados a otro dispositivo.
4. Transmite los resultados a un collector propio; cifra y aplica TTL a cualquier spool local inevitable.
5. Registra en el controller el ID del job aceptado/rechazado y el hash del resultado. No coloques parámetros sensibles de comandos en un canal público de monitoring.
6. Detén el procesamiento cuando caduque la autorización, falle la rotación de identidad o el controller marque el dispositivo como quarantined.

## Monitoring para detectar discovery, pérdida o compromiso

El monitoring puede indicar al controller que el estado observado cambió. No puede demostrar de forma fiable que “los investigadores encontraron el dispositivo”, y tratar de vigilar a responders o sondear sus sistemas excedería una evaluación autorizada.

### Recopilar el estado fuera del dispositivo

Envía al controller un health record firmado y de bajo volumen en un intervalo operativo aleatorio pero limitado. Incluye únicamente lo que el controller necesite:

- ID del dispositivo, boot ID/contador y uptime monotónico;
- hash de configuración/imagen y versión del software;
- serial del certificado del dispositivo y estado de renovación;
- clase de uplink, interfaz, BSSID o contexto de switch según autorización, hash del gateway predeterminado e IP pública/ASN observados por un servicio propio;
- antigüedad del handshake del túnel, contadores de paquetes y profundidad de la cola;
- estado del switch del enclosure o de hardware-tamper si el propietario aprobó el sensor;
- presión del disco, temperatura, estimación del desfase del reloj y último ID de job correcto;
- un número de secuencia y una firma para detectar replay o gaps.

Almacena centralmente la autenticación del gateway, las decisiones de policy, el acceso de operadores, el envío de jobs, los hashes de resultados, los eventos de auditoría del provider y las alertas. CISA recomienda centralizar los logs, protegerlos contra el borrado, establecer una línea base de la actividad normal y designar contactos de incident-response.<sup>[[5]](#references)</sup>

### Indicadores de discovery/compromise

| Señal | Posibles explicaciones | Acción del controller |
|---|---|---|
| Heartbeat ausente | fallo de alimentación/red, cambio del portal, daño, bloqueo deliberado o retirada | corrobora el estado del provider/recinto; no reconectes desde una ruta no aprobada |
| Contador de boot cambiado inesperadamente | corte de alimentación, crash, retirada o mantenimiento | pon los jobs en quarantine; compara la hora y los eventos del recinto |
| Hash de configuración/imagen cambiado | error de actualización, fallo de almacenamiento o tampering | detén el trabajo; revoca si no corresponde a un release aprobado por el controller |
| Nuevo uplink/BSSID/gateway/ASN | sustitución del AP, roaming, dispositivo movido o intercepción | compara el inventario aprobado; pon en quarantine una transición inexplicada |
| Job/firma rechazado repetidamente | corrupción, replay o controller no autorizado | detén el procesamiento e investiga los logs del gateway/controller |
| Credencial del dispositivo usada dos veces o desde rutas incompatibles | clave clonada, reutilización de snapshot o transición de red | revoca inmediatamente; conserva ambos registros de sesión |
| Login, interfaz, proceso o evento de privilegios local inesperado | mantenimiento o compromiso | aísla mediante la policy del broker; conserva la evidencia |
| Transición del switch/estado del enclosure | servicio, movimiento o discovery | notifica al contacto del recinto designado; no actives una acción destructiva |
| Aviso de abuso del provider/consulta sobre la cuenta o alerta del SOC | detección, configuración incorrecta o tráfico fuera de scope | detén la actividad e inicia el proceso de deconfliction/incident |
| Sentinel credential utilizada | alguien leyó un secreto señuelo sin privilegios, único para este nodo | revoca la identidad real del dispositivo y conserva el rastro de la alerta |

Una sentinel credential no debe conceder **ningún acceso**, debe llamar únicamente a un servicio de alertas propiedad de la organización y debe estar indicada en las rules of engagement. Es un tripwire para la lectura no autorizada, no un beacon para rastrear a quien encontró el equipo.

### Umbrales de alerta

Usa reglas stateful, no una única alarma dramática de “caught”:

- **warning:** un intervalo perdido, cambio normal de dirección o crecimiento de la cola;
- **degraded:** tres intervalos consecutivos perdidos, retraso de renovación, pérdida del uplink primario o reinicio repetido;
- **quarantine:** cambio no aprobado de hash/boot/uplink, credencial duplicada, uso del sentinel o evento privilegiado inesperado;
- **confirmed discovery/loss:** informe del recinto/controller, discrepancia del inventario físico, recuperación del dispositivo por una persona no planificada o escalado validado del provider/SOC.

Prueba la entrega de alertas mediante un canal independiente del field node. Evita enviar detalles sensibles del cliente/dispositivo a mensajería personal o cuentas de push de consumo.

## Runbook ante sospecha de discovery o capture

1. **Detén:** suspende los nuevos jobs y las sesiones de operadores. No envíes un probe para “comprobar si están vigilando”.
2. **Pon en quarantine:** haz que el broker deniegue la identidad del dispositivo y sus rutas, conservando los logs existentes.
3. **Revoca:** revoca el certificado/clave del dispositivo, el token de la queue, la credencial de actualización y cualquier token de servicio de propósito único. Suspende la SIM de la organización cuando sea plausible una pérdida física.
4. **Conserva:** realiza un snapshot de los registros del controller, gateway, provider y alertas; registra la hora de confianza, quién actuó y la última configuración conocida. No borres ni limpies remotamente el nodo.
5. **Notifica:** contacta con el controller del ejercicio, el contacto de incidentes del cliente y los contactos legales/de privacidad definidos en la autorización. Si lo encontró un tercero, utiliza el proceso de recuperación acordado previamente.
6. **Evalúa:** asume que todos los secretos y resultados almacenados en caché en el nodo están expuestos. Enumera exactamente a qué podía acceder cada secreto y si se utilizó después del evento sospechoso.
7. **Contén aguas abajo:** rota las credenciales de servicio afectadas, invalida los jobs pendientes e inspecciona los logs de targets/providers propios en busca de actividad inesperada.
8. **Recupera de forma segura:** recógelo únicamente mediante una persona autorizada; fotografía/embala el equipo, registra la custodia y adquiere evidencia forense según indique el cliente.
9. **Reanuda con una identidad nueva:** nunca vuelvas a habilitar silenciosamente la credencial capturada. Reconstruye a partir del manifest conocido, corrige el fallo de control y obtén aprobación explícita.

La guía actual de incident-response de NIST integra la preparación, detección, respuesta y recuperación en la gestión de riesgos de ciberseguridad de toda la organización; conserva primero para que el cliente pueda determinar qué ocurrió y elegir la respuesta adecuada.<sup>[[6]](#references)</sup>

## Capture drill antes del deployment

Entrega una unidad de prueba desbloqueada o una copia de su almacenamiento a un reviewer independiente y pídele que enumere:

1. identificadores del dispositivo/recinto/engagement;
2. nombres de operadores, cuentas personales, redes domésticas/de estaciones de trabajo y contactos de recuperación;
3. destinos y credenciales del controller/broker;
4. perfiles de red del cliente y resultados almacenados en caché;
5. otros dispositivos/proyectos accesibles con cada secreto;
6. credenciales de valor o pago;
7. qué puede revocar el controller y con qué rapidez;
8. qué actividad sigue siendo atribuible a partir de los logs centralizados.

Criterios de aprobación: cero cuentas personales/claves de estaciones de trabajo; cero autoridad entre engagements o de enrollment; ninguna credencial de pago; caché cifrada y limitada; una acción documentada de revocación del dispositivo; accountability completa del lado del controller. Trata cualquier enlace personal inesperado o capacidad lateral como un bloqueo del release.

## Cierre

1. Detén los jobs y deshabilita la ruta del broker al finalizar el scope.
2. Recupera y concilia el inventario exacto; informa de cualquier elemento faltante.
3. Conserva los logs/resultados y, si es necesario, una imagen forense según el plan de retención del engagement.
4. Revoca las identidades del dispositivo, SIM, queue, actualización y servicios incluso si se recuperó el hardware.
5. Solo después de la conservación/aceptación, sanitiza o destruye los medios mediante el proceso de eliminación de datos aprobado por el propietario y registra la finalización. Esto es gestión del ciclo de vida, no concealment.
6. Elimina las reservas de NAC/DHCP del recinto, las rutas del broker, DNS, roles de cloud, reglas de alertas y contactos temporales.
7. Documenta la detección observada, la telemetría perdida, el tiempo hasta la quarantine y cada artefacto que expuso la capture.

## References

- [1] [NIST — Catálogo de capacidades de ciberseguridad para dispositivos IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Conceptos e identidades de workloads de corta duración](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Inicio rápido: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Uso de logging en sistemas empresariales](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Recomendaciones y consideraciones de Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
