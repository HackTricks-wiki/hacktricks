# Playbooks de privacidad operacional

{{#include ../banners/hacktricks-training.md}}

Estos playbooks combinan los controles del resto de esta sección. Son puntos de partida, no garantías: actualiza el modelo de amenazas cada vez que un nuevo observador, cuenta, dispositivo, ubicación, pago, archivo o contraparte entre en el flujo de trabajo.

## Preflight universal

1. Escribe el objetivo legítimo y qué debe permanecer privado **frente a quién**.
2. Registra las identidades, dispositivos, redes, cuentas, medios de pago, contrapartes, ubicaciones físicas y datos que tocará la actividad.
3. Identifica al observador probable más potente y la consecuencia de un fallo.
4. Confirma la autorización, la legislación aplicable, los términos del proveedor y la política organizativa.
5. Decide qué debe seguir siendo atribuible internamente por motivos de seguridad, respuesta ante incidentes, contabilidad y auditoría.
6. Elige el compartimento funcional más pequeño; establece sus vías de recuperación y apagado antes de usarlo.
7. Prueba el compartimento frente a un servicio controlado, incluyendo IP/DNS/IPv6, identidad del navegador, metadatos de documentos, extracto de pago y fugas de notificaciones.

Usa el modelo detallado de [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Línea base de privacidad cotidiana

Objetivo: reducir el tracking comercial, la toma de control de cuentas y la exposición innecesaria sin intentar volverse anónimo.

- Usa un OS mantenido con cifrado de disco completo, actualizaciones automáticas, bloqueo de pantalla y secure boot cuando estén disponibles.
- Configura primero el gestor de contraseñas, el correo de recuperación y la MFA/llaves de seguridad resistentes al phishing.
- Revisa los permisos de las aplicaciones, el historial de ubicaciones, los identificadores publicitarios, la sincronización en la nube y las conexiones con cuentas de terceros.
- Usa un navegador convencional con pocas extensiones, protección contra el tracking, HTTPS y perfiles separados para la navegación laboral/personal/de alto riesgo.
- Usa alias de private relay o direcciones de correo distintas según la relación; no uses un número de teléfono personal cuando sea meramente opcional.
- Prefiere mensajería cifrada de extremo a extremo para el contenido, recordando que los participantes, horarios, grupos y endpoints siguen siendo metadatos.
- Elimina deliberadamente los metadatos de los archivos e inspecciona la copia exportada —no el original— antes de publicarla.
- Usa tarjetas virtuales o tokens de wallet para compartimentar las credenciales de pago; no los llames anónimos.
- Realiza copias de seguridad del material de recuperación cifrado y prueba su restauración.

## Publicación seudónima

Objetivo: impedir que lectores y plataformas vinculen trivialmente una publicación con una identidad civil. Esto no derrota una investigación dirigida con recursos.

1. Define si la plataforma, el proveedor de hosting, los lectores, los contactos, la red local, el proveedor de pagos o un proceso legal forman parte del modelo de amenazas.
2. Crea un contexto de endpoint/cuenta dedicado a partir de una línea base limpia. Desactiva la sincronización personal del navegador, los documentos en la nube, la carga de contactos y las vistas previas de notificaciones.
3. Crea la cuenta seudónima mediante el compartimento de red elegido. No reutilices nombres de usuario, avatares, canales de recuperación, textos de plantilla ni el inicio de sesión de un identity provider personal.
4. Usa Tor Browser cuando la desvinculación del destino sea más importante que la velocidad; no añadas extensiones, no cambies excesivamente su tamaño o configuración ni abras documentos descargados mientras estés online en una sesión normal de escritorio.
5. Redacta con un proceso que no inserte nombres de plantillas personales, autores de revisiones, rutas de impresora, GPS/EXIF, miniaturas o capas ocultas. Exporta una copia e inspecciónala con herramientas de metadatos adecuadas.
6. Comprueba si el contenido contiene datos autoidentificadores: fechas únicas, detalles del lugar de trabajo, clima/zona horaria local, reflejos, audio de fondo, hábitos lingüísticos y reutilización de texto de publicaciones anteriores.
7. Usa un canal de respuesta separado. Trata cada contacto directo, adjunto y enlace como un posible intento de correlación o phishing.
8. Si hay dinero involucrado, utiliza el método legal que exponga únicamente los datos necesarios. Asume que la plataforma y el intermediario regulado pueden conocer al beneficiario aunque los lectores no.
9. Publica y, después, inspecciona el resultado público desde un contexto limpio diferente. Registra lo que la plataforma haya añadido o transformado.
10. Mantén una cadencia planificada solo si no crea una huella conductual estable; retira el compartimento en lugar de reutilizarlo silenciosamente.

Para periodismo, activismo, violencia doméstica o riesgos a nivel estatal, obtén ayuda personalizada de una organización experimentada de seguridad digital; una checklist estática no puede modelar la legislación local ni a un adversario activo.

## Authorized red-team engagement

Objetivo: mantener las identidades personales y las redes domésticas de los operadores fuera de la telemetría del objetivo, preservando al mismo tiempo la autorización, el control y la respuesta ante incidentes.

### Antes de la ventana de inicio

- Finaliza el anexo de infraestructura del ROE, los objetivos/exclusiones, los rangos de origen, las fechas, la parada de emergencia y los permisos de terceros/proveedores.
- Asigna un perfil de operador o VM dedicado, secretos del engagement, almacén de evidencias, proyecto de cloud, dominios y presupuesto.
- Prefiere el egress proporcionado por el cliente o un bastion fijo controlado por la organización. Prueba el comportamiento de IPv4/IPv6/DNS mediante full-tunnel y la política fail-closed.
- Almacena la correspondencia entre el operador y la infraestructura pública con el responsable del ejercicio o el contacto de escrow acordado.
- Establece límites de velocidad, listas de destinos permitidos y una aprobación separada para acciones destructivas, wireless, físicas, de phishing o de recopilación de credenciales.
- Usa un medio de pago controlado por la organización y registra internamente las aprobaciones.

### Durante el engagement

- Comienza desde el endpoint y el túnel aprobados; verifica el egress observado antes del tráfico de evaluación.
- Mantén fuera del compartimento las cuentas personales, dispositivos, números de teléfono, repositorios, llaves SSH/GPG y la sincronización en la nube.
- Registra operador/trabajo, inicio/fin, origen, destino dentro del alcance y cambios de configuración sin recopilar contenido innecesario del cliente.
- Detente ante ambigüedades en el alcance, sistemas de terceros inesperados, notificaciones de abuso del proveedor, impactos de seguridad, pérdida de equipos o pérdida de contacto con el responsable.
- Nunca improvises usando el Wi-Fi de un vecino, credenciales robadas, una SIM/cuenta no aprobada o hardware oculto en un lugar.

### Fin del engagement

- Detén los trabajos y el C2; recupera los dispositivos drop aprobados; revoca tokens, credenciales y certificados.
- Concilia la infraestructura, los dominios, las direcciones de origen, los gastos, los datos y los casos del proveedor con el inventario.
- Devuelve, elimina o conserva los datos del cliente según el contrato, preserva las evidencias de auditoría mínimas necesarias y haz que un segundo operador verifique el apagado.

Consulta [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) para obtener la guía completa de construcción y desmontaje.

## Compra o donación privada legal

Objetivo: minimizar la información divulgada al comerciante o al público cumpliendo al mismo tiempo las obligaciones del emisor, contables, fiscales y de sanciones.

1. Enumera quién no debe saber qué: público, comerciante, intermediario de pagos, empleador/delegado de una cuenta familiar, servicio de entrega u observador de blockchain.
2. Comprueba las normas locales, el destinatario/la contraparte, los términos del proveedor, los límites de efectivo y las necesidades de conservación de registros.
3. Elige el medio:
- efectivo para pagos locales legales aceptados sin registro en la red de pagos;
- una tarjeta virtual regulada o específica del comerciante para separar las credenciales online;
- cryptocurrency solo después de analizar la adquisición, el ledger, el backend de la wallet, la red, la contraparte y los vínculos con gastos posteriores.
4. Usa los datos verídicos obligatorios y omite únicamente la información opcional de fidelización/marketing. No uses la identidad/dirección de otra persona ni dividas una transacción para esquivar un umbral.
5. Separa el contexto del navegador/cuenta del comerciante y evita inicios de sesión sociales, programas de fidelización o canales personales de recuperación que no estén relacionados.
6. Confirma qué aparece en los extractos, recibos, notificaciones, envíos y listas públicas de donantes.
7. Guarda cifrada la documentación requerida de recibos/impuestos/autorizaciones; revoca las credenciales de pago desechables una vez finalice el plazo de reembolso.

Consulta [Private Digital Payments](private-digital-payments.md) y [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Viajes y redes no confiables

Objetivo: proteger los datos y las cuentas en redes no administradas por el usuario, no ocultar actividades no autorizadas.

- Actualiza los dispositivos y descarga las credenciales/mapas necesarios antes del viaje.
- Minimiza los datos almacenados; usa cifrado de disco completo, un desbloqueo robusto, planificación de recuperación remota y procedimientos con el dispositivo apagado ante fronteras/riesgos físicos, según el asesoramiento legal.
- Verifica el SSID/portal cautivo del lugar. Prefiere un hotspot personal cuando sea apropiado, pero recuerda los registros del suscriptor y la ubicación celular.
- Usa una VPN aprobada full/forced para los datos organizativos; verifica que los dispositivos conectados la compartan y prueba el comportamiento de IPv6/DNS.
- Usa un router de viaje para el aislamiento de clientes y una política reproducible, no como garantía de anonimato.
- Trata la carga pública por USB, los ordenadores prestados, las impresoras públicas y los sistemas compartidos de salas de reuniones como amenazas separadas.
- Asume que la presencia física, los identificadores de radio, el inicio de sesión en el portal, las cámaras y los registros de pagos/ubicación pueden correlacionar la visita.

Los detalles de comparación y configuración se encuentran en [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Respuesta ante fallos y exposición

Cuando un compartimento se filtra o puede vincularse:

1. Detén la actividad si continuar aumenta el daño; usa la parada de emergencia del engagement cuando corresponda.
2. Conserva las evidencias necesarias sin propagar datos sensibles. Registra la hora exacta, el indicador observado y los activos afectados.
3. Notifica al propietario/responsable de seguridad adecuado. No ocultes un incidente para preservar una narrativa de privacidad.
4. Revoca sesiones, tokens, credenciales de pago y acceso a la infraestructura; rota los secretos desde un endpoint conocido como limpio.
5. Determina qué elementos establecieron el vínculo: endpoint, recuperación de cuenta, red, pago, metadatos, contenido, comportamiento, contraparte o presencia física.
6. Trata todo el compartimento afectado como comprometido. No te limites a cambiar su nombre de usuario o IP de salida.
7. Cumple las obligaciones de notificación de brechas, proveedores, clientes, entidades financieras y autoridades legales.
8. Reconstruye solo después de cambiar el proceso que causó el vínculo; documenta el control y pruébalo.

## Auditoría periódica

- [ ] El modelo de amenazas y las suposiciones legales/de los proveedores se revisan según un calendario fechado.
- [ ] Los dispositivos, cuentas, alias, dominios, rutas de red y credenciales de pago están inventariados.
- [ ] Las vías de recuperación no cruzan compartimentos inesperadamente.
- [ ] Se han probado el full-tunnel, DNS, IPv6 y el comportamiento fail-closed.
- [ ] Se han comprobado los archivos y perfiles públicos para detectar metadatos/reutilización de contenido.
- [ ] Los nodos/backends de wallet y las suposiciones sobre los protocolos crypto siguen actualizados.
- [ ] Los logs y recibos son mínimos, están cifrados, tienen acceso controlado y se conservan dentro del plazo establecido.
- [ ] Los compartimentos antiguos y la infraestructura del engagement se retiraron por completo.
{{#include ../banners/hacktricks-training.md}}
