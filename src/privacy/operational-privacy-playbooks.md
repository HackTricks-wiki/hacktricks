# Playbooks de privacidad operacional

Estos playbooks combinan los controles del resto de esta sección. Son puntos de partida, no garantías: actualiza el modelo de amenazas cada vez que un nuevo observador, cuenta, dispositivo, ubicación, pago, archivo o contraparte entre en el flujo de trabajo.

## Preflight universal

1. Escribe el objetivo legítimo y qué debe permanecer privado **frente a quién**.
2. Registra las identidades, dispositivos, redes, cuentas, métodos de pago, contrapartes, ubicaciones físicas y datos que tocará la actividad.
3. Identifica al observador probable más fuerte y la consecuencia de un fallo.
4. Confirma la autorización, la legislación aplicable, los términos del proveedor y la política organizativa.
5. Decide qué debe seguir siendo atribuible internamente por motivos de seguridad, respuesta a incidentes, contabilidad y auditoría.
6. Elige el compartimento funcional más pequeño; establece sus rutas de recuperación y apagado antes de usarlo.
7. Prueba el compartimento contra un servicio controlado, incluyendo fugas de IP/DNS/IPv6, identidad del navegador, metadatos de documentos, extracto de pago y notificaciones.

Usa el modelo detallado de [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Base de privacidad cotidiana

Objetivo: reducir el tracking comercial, la toma de control de cuentas y la exposición innecesaria sin intentar volverse anónimo.

- Usa un OS mantenido con cifrado de disco completo, actualizaciones automáticas, bloqueo de pantalla y secure boot cuando esté disponible.
- Configura primero el password manager, el correo de recuperación y la MFA resistente al phishing/security keys.
- Revisa los permisos de las aplicaciones, el historial de ubicaciones, los identificadores publicitarios, la sincronización cloud y las conexiones con cuentas de terceros.
- Usa un navegador convencional con pocas extensiones, protección contra tracking, HTTPS y perfiles separados para navegación laboral/personal/de alto riesgo.
- Usa aliases de private relay o direcciones de correo distintas según la relación; no uses un número de teléfono personal cuando sea meramente opcional.
- Prefiere messaging con cifrado end-to-end para el contenido, recordando que los participantes, los tiempos, los grupos y los endpoints siguen siendo metadatos.
- Elimina los metadatos de los archivos deliberadamente e inspecciona la copia exportada —no el original— antes de publicarla.
- Usa tokens de virtual-card o wallet para compartimentar las credenciales de pago; no los llames anónimos.
- Haz backup del material de recuperación cifrado y prueba su restauración.

## Publicación pseudónima

Objetivo: impedir que los lectores y las plataformas vinculen trivialmente una publicación con una identidad civil. Esto no derrota una investigación dirigida y con recursos.

1. Define si la plataforma, el proveedor de hosting, los lectores, los contactos, la red local, el proveedor de pagos o un proceso legal forman parte del modelo de amenazas.
2. Crea un contexto dedicado de endpoint/cuenta a partir de una baseline limpia. Desactiva la sincronización personal del navegador, los documentos cloud, la carga de contactos y las vistas previas de notificaciones.
3. Crea la cuenta pseudónima mediante el compartimento de red elegido. No reutilices usernames, avatares, canales de recuperación, boilerplate de escritura ni el login personal del identity provider.
4. Usa Tor Browser cuando la unlinkability del destino sea más importante que la velocidad; no añadas extensiones, no cambies excesivamente su tamaño o configuración y no abras documentos descargados mientras estés online en una sesión ordinaria de desktop.
5. Redacta con un proceso que no inserte nombres de plantillas personales, autores de revisiones, rutas de impresora, GPS/EXIF, thumbnails o capas ocultas. Exporta una copia e inspecciónala con herramientas de metadatos apropiadas.
6. Comprueba el contenido en busca de datos autoidentificativos: fechas únicas, detalles del lugar de trabajo, clima/zona horaria local, reflejos, audio de fondo, hábitos lingüísticos y reutilización de texto de publicaciones anteriores.
7. Usa un canal de respuesta separado. Trata cada contacto directo, attachment y link como un posible intento de correlación o phishing.
8. Si hay dinero involucrado, usa el método lícito que exponga solo los datos necesarios. Asume que la plataforma y el intermediario regulado pueden conocer al beneficiario aunque los lectores no lo conozcan.
9. Publica y después inspecciona el resultado público desde un contexto limpio diferente. Registra lo que la plataforma haya añadido o transformado.
10. Mantén una cadencia planificada solo si no crea una huella conductual estable; retira el compartimento en lugar de reutilizarlo silenciosamente.

Para periodismo serio, activismo, abuso doméstico o riesgo estatal, obtén ayuda personalizada de una organización experimentada de seguridad digital; una checklist estática no puede modelar la legislación local ni a un adversario activo.

## Authorized red-team engagement

Objetivo: mantener las identidades personales y las redes domésticas de los operadores fuera de la telemetría del objetivo, preservando al mismo tiempo la autorización, el control y la respuesta a incidentes.

### Antes de la ventana de inicio

- Finaliza el anexo de infraestructura del ROE, los objetivos/exclusiones, los rangos de origen, las fechas, el emergency stop y los permisos de terceros/proveedores.
- Asigna un perfil de operador o VM dedicado, secrets del engagement, almacén de evidencias, proyecto cloud, dominios y presupuesto.
- Prefiere el egress proporcionado por el cliente o un bastion fijo controlado por la organización. Prueba el comportamiento de full-tunnel IPv4/IPv6/DNS y la política fail-closed.
- Guarda la correspondencia entre el operador y la infraestructura pública con el controller del ejercicio o el contacto de escrow acordado.
- Establece rate limits, allowlists de destinos y una aprobación separada para acciones destructivas, wireless, físicas, de phishing o de credential-collection.
- Usa un método de pago controlado por la organización y registra internamente las aprobaciones.

### Durante el engagement

- Comienza desde el endpoint y el tunnel aprobados; verifica el egress observado antes del tráfico de assessment.
- Mantén fuera del compartimento las cuentas personales, dispositivos, números de teléfono, repositorios, claves SSH/GPG y la sincronización cloud.
- Registra operador/job, inicio/parada, origen, destino dentro del alcance y cambios de configuración sin recopilar contenido innecesario del cliente.
- Detente ante ambigüedad en el alcance, sistemas de terceros inesperados, una notificación de abuso del proveedor, impacto en la seguridad, pérdida de equipo o pérdida de contacto con el controller.
- Nunca improvises usando el Wi-Fi de un vecino, credenciales robadas, una SIM/cuenta no aprobada o hardware oculto en un local.

### Final del engagement

- Detén los jobs y el C2; recupera los drop devices aprobados; revoca tokens, credenciales y certificados.
- Concilia la infraestructura, los dominios, las direcciones de origen, los gastos, los datos y los casos con proveedores con respecto al inventario.
- Devuelve/elimina/conserva los datos del cliente según el contrato, preserva la evidencia de auditoría mínima necesaria y haz que un segundo operador verifique el apagado.

Consulta [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) para obtener la guía completa de build y teardown.

## Compra o donación privada lícita

Objetivo: minimizar la divulgación al merchant o al público cumpliendo al mismo tiempo las obligaciones del emisor, contables, fiscales y de sanciones.

1. Enumera quién no debe saber qué: público, merchant, intermediario de pagos, empleador/delegado de una cuenta familiar, servicio de entrega u observador de blockchain.
2. Comprueba las normas locales, el receptor/la contraparte, los términos del proveedor, los límites de efectivo y las necesidades de conservación de registros.
3. Elige el método:
- efectivo para pagos locales lícitos aceptados sin registro de la red de pagos;
- una tarjeta virtual regulada/específica del merchant para separar las credenciales online;
- cryptocurrency solo después de analizar la adquisición, el ledger, el backend de wallet, la red, la contraparte y los vínculos con gastos posteriores.
4. Usa datos reales obligatorios y omite solo la información opcional de loyalty/marketing. No uses la identidad/dirección de otra persona ni dividas una transacción para evitar un umbral.
5. Separa el contexto del navegador/cuenta del merchant y evita logins sociales, loyalty o canales personales de recuperación no relacionados.
6. Confirma qué aparece en extractos, recibos, notificaciones, envíos y listas públicas de donantes.
7. Guarda cifrada la evidencia requerida de recibos/impuestos/autorización; revoca las credenciales de pago desechables después del periodo de reembolso.

Consulta [Private Digital Payments](private-digital-payments.md) y [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Viajes y redes no confiables

Objetivo: proteger los datos y las cuentas en redes no administradas por el usuario, no ocultar actividad no autorizada.

- Actualiza los dispositivos y descarga las credenciales/mapas necesarios antes del viaje.
- Minimiza los datos almacenados; usa cifrado de disco completo, un desbloqueo seguro, planificación de recuperación remota y procedimientos con el dispositivo apagado frente a fronteras/riesgos físicos adecuados al asesoramiento legal.
- Verifica el SSID/portal cautivo del local. Prefiere un hotspot personal cuando sea apropiado, pero recuerda los registros del suscriptor y la ubicación celular.
- Usa una VPN full/forced aprobada para los datos organizativos; verifica que los dispositivos tethered la compartan y prueba el comportamiento de IPv6/DNS.
- Usa un travel router para el aislamiento de clientes y una política repetible, no como garantía de anonimato.
- Trata la carga pública por USB, los ordenadores prestados, las impresoras públicas y los sistemas compartidos de salas de reuniones como amenazas separadas.
- Asume que la presencia física, los identificadores de radio, el login del portal, las cámaras y los registros de pagos/ubicación pueden correlacionar la visita.

Los detalles de comparación y configuración están en [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Respuesta ante fallos y exposición

Cuando un compartimento sufra una leak o pueda vincularse:

1. Detén la actividad si continuar aumenta el daño; usa el emergency stop del engagement cuando corresponda.
2. Preserva la evidencia necesaria sin propagar datos sensibles. Registra la hora exacta, el indicador observado y los activos afectados.
3. Notifica al propietario/controller/contacto de seguridad correspondiente. No ocultes un incidente para preservar una narrativa de privacidad.
4. Revoca sesiones, tokens, credenciales de pago y acceso a la infraestructura; rota los secrets desde un endpoint conocido como limpio.
5. Determina qué edges establecieron el vínculo: endpoint, recuperación de cuenta, red, pago, metadatos, contenido, comportamiento, contraparte o presencia física.
6. Trata todo el compartimento afectado como burned. No cambies simplemente su username o IP de salida.
7. Cumple las obligaciones de notificación de breach, proveedor, cliente, financieras y legales.
8. Reconstruye solo después de cambiar el proceso que causó el vínculo; documenta el control y pruébalo.

## Auditoría periódica

- [ ] El modelo de amenazas y las suposiciones legales/sobre proveedores se revisan según un calendario fechado.
- [ ] Se han inventariado los dispositivos, cuentas, aliases, dominios, rutas de red y credenciales de pago.
- [ ] Las rutas de recuperación no cruzan compartimentos inesperadamente.
- [ ] Se han probado el full-tunnel, DNS, IPv6 y el comportamiento fail-closed.
- [ ] Se han comprobado los archivos y perfiles públicos en busca de metadatos/reutilización de contenido.
- [ ] Los nodos/backends de wallet y las suposiciones sobre los protocolos crypto siguen actualizados.
- [ ] Los logs y recibos son mínimos, están cifrados y controlados mediante acceso, y se encuentran dentro del periodo de conservación.
- [ ] Los compartimentos antiguos y la infraestructura del engagement se retiraron por completo.
