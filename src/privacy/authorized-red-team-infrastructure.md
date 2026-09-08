# Infraestructura autorizada de Red Team

Para dispositivos duraderos en las instalaciones, utiliza el diseño y el runbook de descubrimiento sospechado de [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Para un Red Team profesional, el objetivo es la **atribución controlada**, no la inmunidad frente a la rendición de cuentas. El objetivo no debería poder ver trivialmente la IP doméstica ni las cuentas personales de un operador, mientras que el responsable del engagement debe poder identificar el origen, detener la operación, gestionar los informes de abuso, preservar las evidencias y demostrar la autorización.

Esta página establece la base de despliegue para un engagement lícito. Para el tradecraft adversario que pretende emular —incluidos ORBs comprometidos, residential relays, fronting, dead drops y pivots inalámbricos cercanos— comienza con [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) y [Government and APT Case Studies](government-and-apt-case-studies.md), y después reproduce la telemetría necesaria en los [authorized labs](authorized-adversary-emulation-labs.md).

NIST define las reglas de engagement (ROE) como restricciones preestablecidas que conceden autoridad para actividades de testing definidas.<sup>[[1]](#references)</sup> La arquitectura de privacidad no puede ampliar dicha autoridad.

## Elige un patrón de egress

| Patrón | Mejor uso | Lo que ve el objetivo | Lo que ve el proveedor/observador local | Rendición de cuentas |
|---|---|---|---|---|
| VPN/jump host proporcionado por el cliente | La mayoría de las evaluaciones | Rango de direcciones del cliente | Identidad del cliente y acceso del operador | Más sólida |
| Bastion de la organización de Red Team | Egress controlado y repetible | Rango de la organización | Proveedor de hosting y organización | Sólida |
| VPS específico para el engagement | Aislar clientes/campañas | Dirección del VPS | Cuenta del host, facturación y logs del plano de control y de acceso | Sólida si está documentada |
| VPN comercial aprobada | Investigación/scanning permitidos por el proveedor y las ROE | Egress de VPN compartido/dedicado | Cuenta de VPN y conexión de origen | Media |
| Tor Browser | Investigación web que necesita unlinkability del destino | Exit de Tor | La red local ve Tor/bridge; el destino ve Tor | Poco adecuado para la atribución de origen mediante allowlist |
| Drop on-site aprobado por el cliente | Simulación interna | Dispositivo/dirección on-site | Red del sitio y proveedor del túnel remoto | Sólida si está inventariado |
| Wi-Fi de invitados lícito | Uso administrativo/de investigación de bajo riesgo | IP pública del lugar o egress del túnel | Lugar, ISP, VPN/Tor | Débil y físicamente observable |

Para la mayoría de los trabajos, un egress fijo proporcionado por el cliente o controlado por la organización es más seguro y rápido que los servicios de anonimato para consumidores. También permite a los defensores incluir en una allowlist, monitorizar o deliberadamente **no incluir en una allowlist** rangos de origen conocidos según el diseño del ejercicio.

## Anexo de infraestructura de las ROE

Registra antes del despliegue:

- entidades legales que conceden y reciben la autorización;
- objetivos exactos y exclusiones explícitas;
- horas de inicio/finalización, zona horaria y técnicas permitidas;
- IPs de origen, nombres del sistema autónomo/proveedor, dominios, redirectors, infraestructura de correo e identificadores de dispositivos on-site;
- si están permitidos el phishing, C2, credential capture, testing inalámbrico, acceso físico, denial-of-service, persistence o servicios de terceros;
- aprobaciones del cliente y del proveedor, incluida cualquier referencia de pre-notificación;
- frase de parada de emergencia, contactos de abuso del cliente y del proveedor disponibles 24/7, y tiempo máximo de respuesta;
- clases de datos que pueden recopilarse, cifrado, acceso, retención y eliminación;
- requisitos de evidencias y logging, incluido quién conserva la correspondencia entre la infraestructura pública y el operador;
- teardown, expiración de dominios, revocación de certificados, rotación de credenciales, recuperación de dispositivos y atestación final.

Verifica que las IPs públicas y los dominios estén realmente controlados por la parte autorizante o incluidos explícitamente en el alcance. NIST SP 800-115 recomienda confirmar que las direcciones públicas objetivo están bajo la competencia de la organización antes del testing.<sup>[[2]](#references)</sup>

## Egress rápido específico para el engagement

### Flujo de trabajo de construcción

1. **Crea una cuenta/proyecto para el engagement** dentro de la organización de Red Team utilizando datos exactos de facturación y titularidad. Separa los roles, API keys, presupuestos y audit logs de los de otros clientes.
2. **Comprueba la política de cada proveedor.** Los proveedores de Cloud, VPS, CDN, dominios, correo y VPN tienen reglas diferentes. AWS, por ejemplo, permite evaluaciones específicas, pero exige aprobación previa para C2 alojado/simulaciones encubiertas y prohíbe las actividades enumeradas.<sup>[[3]](#references)</sup>
3. **Asigna direcciones de egress fijas** e inclúyelas en el anexo de las ROE. Evita la rotación rápida de IPs/recursos; complica la respuesta a incidentes y puede infringir la política del proveedor.
4. **Refuerza la gestión:** SSH únicamente con claves o un plano de gestión identity-aware, MFA resistente al phishing, red de administración separada, mínimo privilegio, imágenes parcheadas, ningún puerto de administración público y almacenamiento cifrado de secrets.
5. **Crea una ruta full-tunnel** desde el endpoint del operador hasta el bastion. Encamina DNS e IPv6 deliberadamente y aplica un bloqueo de firewall cuando el túnel esté caído.
6. **Restringe los destinos y puertos salientes** al alcance autorizado cuando sea viable. Aplica rate limiting a los scanners y coloca las técnicas irreversibles/destructivas detrás de un gate de aprobación separado.
7. **Registra para la rendición de cuentas, no para la vigilancia:** autenticación del operador, cambios de configuración, inicio/parada, dirección de origen, destino dentro del alcance e identificadores de herramientas/jobs. Evita capturar payloads/credenciales salvo que sea necesario para el ejercicio y esté protegido por el plan de datos.
8. **Valida mediante un endpoint controlado** propiedad de la organización: IPv4/IPv6 observadas, ruta DNS, reverse DNS, reloj, comportamiento de los source ports, fallos/reconexión y contacto de abuso del proveedor.
9. **Comparte el mapa de atribución de forma segura** con el controlador del ejercicio o con un contacto de escrow acordado. No lo publiques para el equipo objetivo si la detección a ciegas forma parte del test.

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
Un VPS es pseudónimo únicamente para el destino. El host puede tener registros de contacto, facturación, identidad, source-IP, API, dispositivo, ubicación y uso; por sí solo, el historial de AWS CloudTrail visible para el cliente puede revelar actividad de gestión.<sup>[[4]](#references)</sup> Pagar el hosting con cryptocurrency no elimina esos registros.

## Dominios y certificados

- Usa una cuenta de registrar específica para el engagement y propiedad de la organización.
- Activa el bloqueo del registrar, DNSSEC cuando sea compatible, MFA/security keys y la renovación automática solo durante el período aprobado.
- Usa la privacidad de registro para reducir la exposición pública, no para falsear la información del registrante. La política de ICANN exige que los registrars recopilen los datos de registro incluso cuando la visualización pública está redactada o intermediada.<sup>[[5]](#references)</sup>
- Evita nombres que suplanten ilegalmente a terceros no relacionados. Los dominios typosquatting/lookalike requieren la aprobación explícita del cliente y del proveedor.
- Haz un inventario del DNS, certificados, configuración del CDN/redirector y analytics de terceros que puedan filtrar información sobre los operadores o clientes.
- Durante el teardown, elimina los registros, revoca certificados/tokens, conserva las evidencias acordadas y decide si el dominio debe conservarse de forma defensiva.

## Nodos de despliegue autorizados en sitio

Una Raspberry Pi o dispositivo similar solo es aceptable cuando el propietario de la propiedad/red y el cliente autorizan explícitamente su ubicación y comportamiento exactos. Un plan seguro:

1. Registra el número de serie del dispositivo, la política de MAC/private-MAC, una foto, el propietario, la ubicación exacta aprobada, la fuente de alimentación, la fecha límite de recuperación y el contacto para casos de manipulación.
2. Usa una imagen mínima firmada, secretos cifrados, almacenamiento de solo lectura o recuperable, host firewall, actualizaciones de seguridad automáticas cuando sea práctico y ninguna credencial predeterminada.
3. Configura comunicación únicamente saliente hacia un endpoint del engagement identificado. No expongas un listener sin autenticación.
4. Permite mediante allowlist los destinos y capacidades. La captura de paquetes, la recopilación de credenciales, la suplantación inalámbrica y el movimiento lateral deben estar autorizados explícitamente por separado.
5. Usa autenticación mutua, keys de corta duración, remote kill, informes de estado y límites de bandwidth.
6. Asegúrate de que la pérdida o el robo no revelen credenciales reutilizables ni datos del cliente.
7. Programa la recuperación y el secure wipe/decommission; obtén un registro de recuperación firmado.

No ocultes hardware en una cafetería, hotel, oficina compartida, propiedad de un vecino o espacio público sin el permiso escrito del propietario/operador.

## Redes de invitados y travel routers

Si un escenario autorizado requiere acceso de invitados:

- verifica el SSID y la política de uso aceptable con el establecimiento/cliente;
- usa un travel router propiedad de la organización o un dispositivo bridge de baja confianza para aislar la estación de trabajo privilegiada;
- completa los captive portals fuera de la estación de trabajo privilegiada;
- inicia el túnel aprobado antes del tráfico de assessment;
- confirma que los dispositivos tethered realmente usan ese túnel;
- asume que el establecimiento puede correlacionar la asociación de radio, el portal, la presencia física y los registros de cámaras/pagos;
- nunca eludas controles de acceso, clones otro dispositivo, ataques Wi-Fi ni dejes equipos abandonados.

## Separación operativa

- Un cliente/engagement por compartimento de endpoint, proyecto cloud, conjunto de secretos, grupo de dominios, conjunto de redirectors y almacén de evidencias.
- No uses correo personal, sincronización del navegador, número de teléfono, cloud drive, clave SSH/GPG, identidad de code-signing ni reembolsos de pagos fuera de los sistemas aprobados de la organización.
- No reutilices configuraciones distintivas de payload, rutas de callback, certificados ni repositorios públicos entre clientes, salvo que el diseño del ejercicio acepte el fingerprinting.
- Asigna a la infraestructura una fecha de finalización y una alerta de presupuesto. Los sistemas abandonados se convierten en un riesgo tanto para el cliente como para Internet.
- Conserva suficiente atribución interna para investigar accidentes. “Sin logs” suele ser incompatible con las obligaciones profesionales de evidencia y seguridad.

## Ciego para los defensores, atribuible al controlador

Cuando el objetivo del ejercicio es medir la detección en lugar de probar una allowlist, el SOC objetivo puede permanecer ciego sin que la operación deje de ser atribuible:

1. El controlador del ejercicio aprueba cada source público, dominio, certificado y dispositivo en sitio, pero oculta la lista al SOC.
2. El controlador almacena el mapa source-to-engagement/operator en un vault cifrado separado, con acceso de emergencia de dos personas.
3. Cada trabajo del operador recibe un manifest firmado que contiene el scope, la ventana temporal, el compartimento de origen y un identificador de trabajo irreversible. El objetivo nunca necesita ver el manifest durante el funcionamiento normal.
4. Los eventos de auditoría del bastion se encadenan o se envían en modo append-only al almacenamiento del controlador para que un operador no pueda reescribir silenciosamente la atribución después de un incidente.
5. Un contacto 24/7 de provider-abuse conserva una frase/referencia de verificación que confirma la autorización sin revelar públicamente al cliente.
6. Cada ruta implementa un canal de parada out-of-band que no depende del assessment C2, de la red objetivo ni de la cuenta de un único operador.
7. Antes de las pruebas en vivo, envía canaries benignos desde cada origen. Confirma que el controlador puede resolverlos y detenerlos dentro del tiempo de respuesta del ROE.
8. Después del ejercicio, compara la telemetría del SOC con el ledger del controlador, divulga la lista de orígenes y explica las detecciones omitidas/incorrectas.

No añadas anti-forensics, destrucción de logs, relays comprometidos ni identidades de suscriptor falsas. Eso perjudica las pruebas atribuibles en lugar de mejorarlas.

## Lista de teardown

- [ ] El controlador del ejercicio confirma la detención.
- [ ] C2, túneles, redirectors, correo, VPN y trabajos programados están deshabilitados.
- [ ] Los dispositivos en sitio se recuperan físicamente y se concilian.
- [ ] Los tokens, API keys, claves SSH, certificados y credenciales capturadas se revocan/rotan.
- [ ] El DNS y los recursos cloud se eliminan o transfieren para su conservación defensiva.
- [ ] Los datos del cliente se devuelven, conservan o destruyen según el contrato.
- [ ] Los registros financieros, de auditoría y de autorización requeridos permanecen cifrados y con acceso controlado.
- [ ] Los casos de provider-abuse se cierran y el cliente recibe los indicadores de origen finales.
- [ ] Un segundo operador verifica que no queda infraestructura activa.

## References

- [1] [NIST CSRC — Reglas de engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guía técnica para las pruebas y evaluaciones de seguridad de la información](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Política de Customer Support para Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Aviso de privacidad](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Política de datos de registro](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
