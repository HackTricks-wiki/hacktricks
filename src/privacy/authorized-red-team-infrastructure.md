# Infraestructura autorizada de Red Team

{{#include ../banners/hacktricks-training.md}}

Para dispositivos duraderos instalados en el sitio, usa el diseño [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) y el runbook de descubrimiento sospechoso.

Para un Red Team profesional, el objetivo es la **atribución controlada**, no la inmunidad frente a la rendición de cuentas. El objetivo no debería poder ver de forma trivial la IP doméstica o las cuentas personales de un operador, mientras que el responsable del engagement debe poder identificar el origen, detener la operación, gestionar los informes de abuso, preservar las evidencias y demostrar la autorización.

Esta página es la base de despliegue para un engagement legal. Para las técnicas adversarias que pretende emular —incluidos ORBs comprometidos, relays residenciales, fronting, dead drops y pivots inalámbricos cercanos— comienza con [Infraestructura ofensiva y evasión de atribución](offensive-infrastructure-and-attribution-evasion.md) y [Casos de estudio de gobiernos y APT](government-and-apt-case-studies.md), y después reproduce la telemetría necesaria en los [labs autorizados](authorized-adversary-emulation-labs.md).

NIST define las reglas de engagement (ROE) como restricciones preestablecidas que conceden autoridad para realizar actividades de testing definidas.<sup>[[1]](#references)</sup> La arquitectura de privacidad no puede ampliar dicha autoridad.

## Elige un patrón de egress

| Patrón | Mejor uso | Lo que ve el objetivo | Lo que ve el proveedor/observador local | Rendición de cuentas |
|---|---|---|---|---|
| VPN/jump host proporcionado por el cliente | La mayoría de las evaluaciones | Rango de direcciones del cliente | Identidad del cliente y acceso del operador | Máxima |
| Bastion de la organización de Red Team | Egress controlado y repetible | Rango de la organización | Proveedor de hosting y organización | Alta |
| VPS específico para el engagement | Aislar clientes/campañas | Dirección del VPS | Cuenta del host, facturación, control-plane y logs de acceso | Alta si está documentado |
| VPN comercial aprobada | Research/scanning permitido por el proveedor y las ROE | Egress de VPN compartido/dedicado | Cuenta VPN y conexión de origen | Media |
| Tor Browser | Web research que requiere desvinculación del destino | Exit de Tor | La red local ve Tor/bridge; el destino ve Tor | Mala opción para la atribución de origen mediante allowlist |
| Drop on-site aprobado por el cliente | Simulación interna | Dispositivo/dirección on-site | Red del sitio y proveedor del túnel remoto | Alta si está inventariado |
| Wi-Fi de invitados legal | Uso administrativo/research de bajo riesgo | IP pública del establecimiento o egress del túnel | Establecimiento, ISP, VPN/Tor | Baja y físicamente observable |

Para la mayoría de los trabajos, un egress fijo proporcionado por el cliente o controlado por la organización es más seguro y rápido que los servicios de anonimato para consumidores. También permite a los defensores incluir en una allowlist, monitorizar o deliberadamente **no incluir en una allowlist** rangos de origen conocidos según el diseño del ejercicio.

## Anexo de infraestructura de las ROE

Registra antes del despliegue:

- entidades legales que conceden y reciben la autorización;
- objetivos exactos y exclusiones explícitas;
- horas de inicio/finalización, zona horaria y técnicas permitidas;
- IPs de origen, nombres de proveedores/autonomous systems, dominios, redirectors, infraestructura de correo e identificadores de dispositivos on-site;
- si están permitidos el phishing, C2, credential capture, testing inalámbrico, acceso físico, denial-of-service, persistence o servicios de terceros;
- aprobaciones del cliente y del proveedor, incluida cualquier referencia de pre-notificación;
- frase de emergency stop, contactos de abuso del cliente y del proveedor disponibles 24/7, y tiempo máximo de respuesta;
- clases de datos que pueden recopilarse, cifrado, acceso, retención y eliminación;
- requisitos de evidencias y logging, incluido quién conserva el mapeo entre la infraestructura pública y el operador;
- teardown, expiración de dominios, revocación de certificados, rotación de credenciales, recuperación de dispositivos y certificación final.

Verifica que las IPs públicas y los dominios estén realmente controlados por la parte autorizadora o incluidos explícitamente en el scope. NIST SP 800-115 recomienda confirmar que las direcciones públicas de los objetivos están bajo la jurisdicción de la organización antes del testing.<sup>[[2]](#references)</sup>

## Egress rápido específico para el engagement

### Flujo de trabajo de construcción

1. **Crea una cuenta/proyecto para el engagement** bajo la organización de Red Team usando datos precisos de facturación y titularidad. Separa los roles, API keys, presupuestos y audit logs de los de otros clientes.
2. **Comprueba la política de cada proveedor.** Los proveedores de cloud, VPS, CDN, dominios, correo y VPN tienen reglas diferentes. AWS, por ejemplo, permite evaluaciones específicas, pero requiere aprobación previa para C2 alojado/simulaciones encubiertas y prohíbe las actividades enumeradas.<sup>[[3]](#references)</sup>
3. **Asigna direcciones de egress fijas** e inclúyelas en el anexo de las ROE. Evita la rotación rápida de IPs/recursos; complica la respuesta a incidentes y puede infringir la política del proveedor.
4. **Refuerza la gestión:** SSH solo con keys o un management plane basado en identidad, MFA resistente al phishing, red de administración separada, mínimo privilegio, imágenes parcheadas, ningún puerto de administración público y almacenamiento cifrado de secrets.
5. **Crea una ruta full-tunnel** desde el endpoint del operador hasta el bastion. Enruta DNS e IPv6 deliberadamente y aplica un bloqueo de firewall cuando el túnel esté caído.
6. **Restringe los destinos y puertos de salida** al scope autorizado cuando sea viable. Limita la velocidad de los scanners y coloca las técnicas irreversibles/destructivas detrás de una aprobación independiente.
7. **Registra para la rendición de cuentas, no para la vigilancia:** autenticación del operador, cambios de configuración, inicio/parada, dirección de origen, destino dentro del scope e identificadores de herramientas/jobs. Evita capturar payloads/credenciales salvo que el ejercicio lo requiera y el plan de datos los proteja.
8. **Valida mediante un endpoint controlado** propiedad de la organización: IPv4/IPv6 observadas, ruta DNS, reverse DNS, reloj, comportamiento del puerto de origen, fallos/reconexiones y contacto de abuso del proveedor.
9. **Comparte el mapa de atribución de forma segura** con el controller del ejercicio o con un contacto de escrow acordado. No lo publiques para el equipo objetivo si la detección ciega forma parte del test.

### Arquitectura
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Un VPS es pseudónimo únicamente para el destino. El host puede tener registros de contacto, facturación, identidad, IP de origen, API, dispositivo, ubicación y uso; el historial de AWS CloudTrail visible para el cliente por sí solo puede exponer la actividad de administración.<sup>[[4]](#references)</sup> Pagar el hosting con cryptocurrency no elimina esos registros.

## Dominios y certificados

- Usar una cuenta de registrar específica para el engagement y propiedad de la organización.
- Activar el bloqueo del registrar, DNSSEC cuando sea compatible, MFA/security keys y la renovación automática solo durante el periodo aprobado.
- Usar registration privacy para reducir la exposición pública, no para falsear la información del registrante. La política de ICANN exige que los registrars recopilen los datos de registro incluso cuando la visualización pública está redactada o intermediada mediante proxy.<sup>[[5]](#references)</sup>
- Evitar nombres que suplanten ilegalmente a terceros no relacionados. Los dominios typosquatting/lookalike requieren la aprobación explícita del cliente y del proveedor.
- Inventariar DNS, certificados, configuración de CDN/redirector y analytics de terceros que puedan filtrar información sobre operadores o clientes.
- Durante el teardown, eliminar registros, revocar certificados/tokens, conservar la evidencia acordada y decidir si el dominio debe conservarse defensivamente.

## Nodos drop autorizados en las instalaciones

Un Raspberry Pi o appliance similar solo es aceptable cuando el propietario de la propiedad/red y el cliente autorizan explícitamente su ubicación y comportamiento exactos. Un plan seguro:

1. Registrar el número de serie del dispositivo, la política de MAC/private-MAC, una foto, el propietario, la ubicación exacta aprobada, la fuente de alimentación, la fecha límite de recuperación y el contacto para casos de manipulación.
2. Usar una imagen mínima firmada, secrets cifrados, almacenamiento de solo lectura o recuperable, host firewall, actualizaciones de seguridad automáticas cuando sea práctico y ninguna credencial predeterminada.
3. Configurar comunicación únicamente saliente hacia un endpoint del engagement identificado. No exponer un listener sin autenticación.
4. Permitir mediante allowlist los destinos y las capacidades. La captura de paquetes, la recolección de credenciales, la suplantación wireless y el movimiento lateral deben estar autorizados explícitamente de forma individual.
5. Usar autenticación mutua, claves de corta duración, remote kill, informes de estado y límites de bandwidth.
6. Asegurarse de que la pérdida o el robo no revele credenciales reutilizables ni datos del cliente.
7. Programar la recuperación y el secure wipe/decommission; obtener un registro de recuperación firmado.

No ocultar hardware en una cafetería, hotel, oficina compartida, propiedad de un vecino o lugar público sin el permiso escrito del propietario/operador.

## Redes de invitados y travel routers

Si un escenario autorizado requiere acceso de invitado:

- verificar el SSID y la acceptable-use policy con el establecimiento/cliente;
- usar un travel router propiedad de la organización o un dispositivo bridge de baja confianza para aislar la workstation privilegiada;
- completar los captive portals fuera de la workstation privilegiada;
- iniciar el túnel aprobado antes del tráfico de assessment;
- confirmar que los dispositivos conectados realmente usan ese túnel;
- asumir que el establecimiento puede correlacionar la asociación wireless, el portal, la presencia física y los registros de cámaras/pagos;
- nunca evadir controles de acceso, clonar otro dispositivo, atacar Wi-Fi ni dejar equipos abandonados.

## Separación operativa

- Un cliente/engagement por cada compartimento de endpoint, cloud project, conjunto de secrets, grupo de dominios, conjunto de redirectors y almacén de evidencia.
- No usar email personal, browser sync, número de teléfono, cloud drive, clave SSH/GPG, identidad de code-signing ni reembolsos de pagos fuera de los sistemas aprobados de la organización.
- No reutilizar configuraciones distintivas de payload, rutas de callback, certificados o repositorios públicos entre clientes, salvo que el diseño del ejercicio acepte el fingerprinting.
- Asignar a la infraestructura una fecha de finalización y una alerta de presupuesto. Los sistemas huérfanos se convierten en un riesgo tanto para el cliente como para Internet.
- Conservar suficiente atribución interna para investigar accidentes. “Sin logs” normalmente es incompatible con las obligaciones profesionales de evidencia y seguridad.

## Invisibles para los defensores, atribuibles al controlador

Cuando el objetivo del ejercicio es medir la detección en lugar de probar una allowlist, el SOC objetivo puede permanecer a ciegas sin que la operación deje de ser responsable:

1. El controlador del ejercicio aprueba cada fuente pública, dominio, certificado y dispositivo en las instalaciones, pero oculta la lista al SOC.
2. El controlador almacena el mapa fuente-engagement/operador en un vault cifrado separado con acceso de emergencia para dos personas.
3. Cada trabajo de operador recibe un manifest firmado que contiene el scope, la ventana temporal, el compartimento de origen y un identificador de trabajo irreversible. El objetivo no necesita ver el manifest durante el funcionamiento normal.
4. Los eventos de auditoría del bastion se encadenan o se envían en modo append-only al almacenamiento del controlador, para que un operador no pueda reescribir silenciosamente la atribución después de un incidente.
5. Un contacto 24/7 de provider-abuse mantiene una frase/referencia de verificación que confirma la autorización sin revelar públicamente al cliente.
6. Cada ruta implementa un canal de stop out-of-band que no depende del assessment C2, de la red objetivo ni de la cuenta de un único operador.
7. Antes de las pruebas en vivo, enviar canaries benignos desde cada fuente. Confirmar que el controlador puede resolverlos y detenerlos dentro del tiempo de respuesta del ROE.
8. Después del ejercicio, comparar la telemetría del SOC con el ledger del controlador, revelar la lista de fuentes y explicar las detecciones omitidas/incorrectas.

No añadir anti-forensics, destrucción de logs, relays comprometidos ni identidades falsas de suscriptores. Eso elimina la responsabilidad del testing en lugar de mejorarlo.

## Checklist de teardown

- [ ] El controlador del ejercicio confirma el stop.
- [ ] C2, túneles, redirectors, correo, VPN y scheduled jobs están deshabilitados.
- [ ] Los dispositivos instalados en las instalaciones se recuperan físicamente y se concilian.
- [ ] Tokens, API keys, claves SSH, certificados y credenciales capturadas se revocan/rotan.
- [ ] DNS y recursos cloud se eliminan o se transfieren para su conservación defensiva.
- [ ] Los datos del cliente se devuelven, conservan o destruyen según el contrato.
- [ ] Los registros financieros, de auditoría y de autorización requeridos permanecen cifrados y con acceso controlado.
- [ ] Los casos de provider-abuse se cierran y el cliente recibe los indicadores de fuente finales.
- [ ] Un segundo operador verifica que no quede infraestructura activa.

## References

- [1] [NIST CSRC — Reglas de engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guía técnica para las pruebas y evaluaciones de seguridad de la información](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Política de soporte al cliente para penetration testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Aviso de privacidad](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Política de datos de registro](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
