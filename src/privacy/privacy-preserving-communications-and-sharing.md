# Comunicaciones y uso compartido con preservación de la privacidad

El cifrado de extremo a extremo protege el contenido. No oculta automáticamente la cuenta, el número de teléfono, el grafo de contactos, la dirección IP, el push token, la vista previa de las notificaciones, los tiempos, los metadatos de los archivos ni el comportamiento del destinatario. Selecciona una herramienta según los metadatos que elimina y los observadores que introduce.

## Comparar modelos de comunicación

| Herramienta/modelo | Propiedad útil | Observadores y limitaciones restantes |
|---|---|---|
| Signal | E2EE maduro; los usernames pueden iniciar el contacto sin compartir el número; sealed sender reduce los metadatos del servicio | Se requiere un número de teléfono para registrarse; el servicio, el proveedor de push, los contactos y los endpoints conservan algunas observaciones |
| SimpleX | No tiene un identificador de usuario global; colas por contacto; transporte Tor opcional | Tiempos/transporte del relay, servicio de push, invitaciones y endpoints; ecosistema más nuevo y pequeño |
| Briar | Sincronización directa; Tor online; Bluetooth/Wi-Fi offline; sin almacenamiento central de mensajes | Contactos y endpoints; observadores de radio local; centrado en Android; ambas partes deben estar disponibles o usar Mailbox |
| OnionShare | Archivo/recepción/chat/sitio directo mediante un servicio onion temporal; sin proveedor de almacenamiento | El ordenador del remitente es el servicio; quien posee el enlace conoce el acceso; los tiempos y endpoints permanecen |
| Archivo cifrado con `age` | Cifrado sencillo con la clave del destinatario, independiente del transporte | El transporte ve remitente/destinatario/tiempos/tamaño; los nombres de archivo/metadatos del archivo y los endpoints permanecen |
| Email ordinario + TLS | Cifrado del canal entre servidores | Ambos proveedores de correo normalmente pueden leer el contenido y conservar metadatos de enrutamiento/cuenta |

## Signal: contacto privado sin revelar el número

Los usernames de Signal pueden iniciar un chat sin revelar el número de teléfono del usuario al nuevo contacto, pero el registro sigue requiriendo un número de teléfono.<sup>[[1]](#references)</sup> Sealed sender es una protección incremental de metadatos, no una defensa contra toda correlación de IP/tiempos.<sup>[[2]](#references)</sup>

### Flujo de trabajo

1. Instala Signal desde la tienda de aplicaciones/proyecto oficial y actualiza primero el sistema operativo.
2. Regístrate con un número que tengas derecho legal a utilizar. No uses activaciones de SMS alquiladas, el número de otra persona ni una cuenta de proveedor obtenida con una identidad falsa.
3. En **Ajustes → Privacidad → Número de teléfono**, establece quién puede ver el número y quién puede encontrar la cuenta por número según el modelo de amenazas.
4. Crea un username para descubrir nuevos contactos. Comparte su enlace/QR exacto a través de un canal ya autenticado; los usernames pueden cambiar y no son el nombre del perfil.
5. Desactiva la carga de contactos/permisos si la comodidad no compensa la vinculación, y añade contactos manualmente cuando la plataforma lo admita.
6. Abre los detalles del contacto y compara el safety number/QR mediante un segundo canal o en persona antes de compartir contenido sensible.
7. Revisa los dispositivos vinculados, el registration lock/PIN, las vistas previas de las notificaciones, la seguridad de pantalla, el relay de llamadas, los valores predeterminados de mensajes que desaparecen y el comportamiento de las copias de seguridad.
8. Envía un mensaje de prueba no sensible y realiza una llamada. Inspecciona las trazas en la pantalla de bloqueo, el escritorio, los dispositivos wearables y las notificaciones cloud en ambos lados.
9. Trata un safety number cambiado o un dispositivo vinculado inesperado como un evento que requiere investigación, no como una alerta que deba descartarse automáticamente.

No mezcles una foto de perfil seudónima, la biografía, la pertenencia a grupos ni los horarios con un contexto identificativo de Signal.

## SimpleX: conexiones por contacto sin un identificador global

SimpleX enruta los mensajes mediante colas unidireccionales y no asigna un identificador de usuario para toda la red. Su propia política documenta las sesiones de transporte, los datos temporales del servidor, las contrapartidas de las notificaciones push y la responsabilidad del endpoint.<sup>[[3]](#references)</sup>

### Flujo de trabajo

1. Descarga un cliente mantenido desde el proyecto/tienda oficial y verifica el editor. Usa un perfil de sistema operativo/aplicación dedicado cuando las identidades no deban mezclarse.
2. Crea un perfil **local** con un nombre y una imagen de presentación específicos del contexto. Eliminar la aplicación sin una copia de seguridad puede provocar la pérdida del perfil y las conexiones.
3. En el primer inicio, elige deliberadamente el modo de notificaciones. El push móvil instantáneo puede exponer metadatos adicionales a la infraestructura de Apple/Google.
4. Crea un enlace de invitación de un solo uso para un contacto. Transfiérelo mediante un canal autenticado; cualquiera que obtenga una invitación activa puede intentar usarla.
5. Después de conectarte, abre los detalles del contacto y compara el código de seguridad en persona o mediante un canal independiente verificado.<sup>[[4]](#references)</sup>
6. Usa un perfil incognito por grupo cuando sea compatible, en lugar de reutilizar el mismo perfil en grupos no relacionados.
7. Configura el transporte Tor compatible con el cliente si la red/servidor local no debe ver la IP directa. Confirma la conexión después del cambio; no fuerces un proxy de sistema no compatible.
8. Revisa los recibos de entrega, las vistas previas de enlaces, las llamadas, las descargas automáticas y la exportación/copia de seguridad de la base de datos. Cada elemento modifica los metadatos o la exposición del endpoint.
9. Prueba la recuperación en un dispositivo aislado de repuesto sin ejecutar un estado activo duplicado del perfil; el proyecto advierte que las copias simultáneas pueden interrumpir las conversaciones.

Un identificador global no impide que un contacto identifique al usuario mediante el contenido, la reutilización del perfil, la entrega de invitaciones, los tiempos o el grafo social.

## Briar: mensajería directa y resistente a interrupciones

Briar sincroniza directamente entre dispositivos, mediante Tor cuando está online y mediante Bluetooth/Wi-Fi durante interrupciones locales. El modelo de amenazas oficial asume únicamente una monitorización adversaria limitada de la radio de corto alcance, por lo que la red inalámbrica local no es invisible.<sup>[[5]](#references)</sup>

### Flujo de trabajo

1. Instala desde la distribución oficial de Briar y verifica el origen del paquete. Usa un dispositivo Android compatible con las actualizaciones de seguridad actuales.
2. Crea una cuenta local con un apodo de contexto único y una contraseña segura. No existe una ruta de restablecimiento de contraseña; comprueba que el secreto de desbloqueo pueda recuperarse.
3. Añade contactos cara a cara escaneando los códigos QR de cada uno cuando sea posible. Esto autentica el contacto y evita enviar un enlace mediante un canal correlacionable.
4. En los ajustes de conectividad, activa únicamente los transportes necesarios: Tor/Internet, Wi-Fi y/o Bluetooth. Desactiva las radios locales cuando no sean necesarias.
5. Para la entrega asíncrona, evalúa Briar Mailbox en un dispositivo dedicado y alimentado; inventaríalo y protégelo físicamente como un servidor de mensajes.
6. Envía una prueba no sensible mientras Internet esté disponible y, después, prueba la ruta de interrupción planificada con Internet desactivado en una ubicación autorizada por el propietario.
7. Inspecciona las copias de seguridad de Android, las vistas previas de las notificaciones, las capturas de pantalla y el contenido exportado. El almacenamiento local cifrado queda expuesto cuando el endpoint está desbloqueado o comprometido.
8. Elimina los contactos/dispositivos perdidos y retira todo el contexto si la custodia física o la contraseña de la cuenta se ven comprometidas.

## OnionShare: transferencia directa temporal

OnionShare ejecuta un servicio onion en el ordenador del remitente/receptor; los archivos no se cargan a un proveedor de almacenamiento y el tráfico está cifrado de extremo a extremo dentro de Tor.<sup>[[6]](#references)</sup> La URL onion completa es una bearer capability y debe protegerse.

### Flujo de uso compartido de archivos mediante GUI

1. Instala OnionShare desde su distribución oficial firmada y Tor Browser en el lado del receptor.
2. Coloca **copias saneadas** de los archivos en un directorio de staging dedicado. No apuntes OnionShare a un directorio personal de inicio.
3. Abre **Compartir archivos**, añade únicamente los archivos preparados, mantén activada la protección mediante clave privada/acceso y deja activada la opción **Detener el uso compartido después de enviar los archivos** para un solo receptor.
4. Inicia el uso compartido y envía la URL onion completa mediante un canal E2EE ya autenticado. No la pegues en email, gestores de incidencias ni chats públicos.
5. El receptor abre la URL en Tor Browser, verifica con el remitente los nombres/tamaños esperados y descarga los archivos.
6. Ambas partes comparan un digest SHA-256 acordado previamente o entregado por separado para comprobar la integridad cuando el propio archivo sea el límite de seguridad.
7. Confirma que OnionShare se detuvo después de la descarga; de lo contrario, detenlo manualmente y cierra la aplicación.
8. Elimina la copia preparada según la política de retención e inspecciona el historial/los ajustes de logs de OnionShare para detectar divulgaciones no intencionadas de nombres de archivo.

### Flujo de trabajo CLI

La CLI oficial acepta archivos como argumentos posicionales y se detiene después del primer uso compartido completado predeterminado. En un host con la CLI oficial/Tor instalados:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Entrega la URL completa resultante de forma segura. No añadas `--public`, `--no-autostop-sharing`, registro detallado del nombre de archivo ni persistencia, a menos que el modelo de amenazas requiera explícitamente la exposición resultante.<sup>[[7]](#references)</sup>

Trata los documentos recibidos como hostiles. Ábrelos en una VM desechable o en un renderer de estilo Dangerzone, en lugar de hacerlo en el host asociado a la identidad.

## Cifra un archivo de forma independiente con `age`

El cifrado independiente del transporte es útil cuando un proveedor de almacenamiento/email puede ver el objeto. No oculta el remitente, el destinatario, el tamaño, el momento ni el nombre de archivo, a menos que se gestionen por separado.

### Configuración del destinatario
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Autentica la cadena pública del destinatario a través de un segundo canal. A continuación, el remitente ejecuta:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
El receptor descifra en una nueva ruta:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
La CLI oficial advierte que `-o` sobrescribe una salida existente, así que usa un directorio nuevo y verifica el resumen criptográfico/contenido antes de moverlo.<sup>[[8]](#references)</sup> Nunca envíes el archivo de identidad junto con el ciphertext.

## Pipeline reproducible de sanitización de archivos

La eliminación de metadatos depende del formato. Conserva un original cifrado cuando la autenticidad, el análisis forense o la cadena de custodia sean importantes; trabaja sobre una copia.

### Ejemplo de JPEG
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Esto sigue las recomendaciones más seguras de ExifTool para JPEG: eliminar a ciegas todas las etiquetas también puede eliminar información de color.<sup>[[9]](#references)</sup> Después, inspecciona visualmente los píxeles en busca de rostros, reflejos, pantallas, puntos de referencia y patrones únicos de daños/ruido.

### Flujo de Office/PDF

1. Mantén el original editable cifrado y sin conexión del contexto de publicación.
2. Elimina los comentarios, los cambios registrados, las diapositivas/hojas ocultas, los archivos incrustados, las plantillas personales y las propiedades del documento en la aplicación de autoría.
3. Exporta un PDF nuevo desde un perfil limpio dedicado; no lo “imprimas” en una impresora cloud.
4. Inspecciónalo con herramientas conscientes del formato y con un renderizador visual desechable:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Busca en el resultado renderizado nombres, rutas, direcciones de correo electrónico y texto de revisión. La rasterización puede eliminar estructuras activas, pero perjudica la accesibilidad y la búsqueda, y no elimina el contenido visible ni el estilo de redacción.
6. Calcula el hash del artefacto final y transfiere **solo** esa copia mediante el compartimento de publicación.

## Privacy Pass: autorización anónima para diseñadores de servicios

Privacy Pass separa la **emisión** de tokens del **canje**. Un origen puede saber que un cliente posee un token aprobado por un emisor sin conocer la interacción específica de emisión del cliente. Reutilizar un token, usar metadatos únicos, la temporización o la colusión puede reintroducir la vinculabilidad.<sup>[[10]](#references)</sup>

Patrón de despliegue seguro:

1. Define la afirmación que demuestra el token (por ejemplo, la elegibilidad para límites de tasa), no una identidad global oculta.
2. Usa la arquitectura y los protocolos de emisión estandarizados; no implementes criptografía de firmas ciegas desde cero.
3. Separa la administración del emisor/atestador y del origen cuando la propiedad deseada lo requiera.
4. Minimiza los metadatos públicos/privados de los tokens y asegúrate de que los conjuntos de anonimato sean suficientemente grandes.
5. Emite lotes antes de usarlos cuando sea compatible, para que el momento de emisión no coincida trivialmente con el momento de canje.
6. Canjea cada token una sola vez, valida el desafío vinculado al origen y elimina el estado de los tokens expirados.
7. Evita que las cookies, el registro de IP y las cuentas de aplicación anulen silenciosamente la propiedad de privacidad del token.
8. Comprueba si los registros del emisor y del origen pueden asociar un evento controlado de emisión y canje mediante la temporización, los metadatos o errores únicos.

Privacy Pass es una funcionalidad de aplicación, no algo que un usuario pueda añadir a cualquier cuenta arbitraria.

## Lista de comprobación para la verificación de comunicaciones

- [ ] El contacto, la invitación o la clave se autenticó de forma independiente.
- [ ] Se comprende la exposición del número de teléfono, nombre de usuario, perfil, grupo y carga de contactos.
- [ ] Se han enumerado los observadores de IP directa, relay, Tor, proveedor de push y radio local.
- [ ] Se probaron las vistas previas de notificaciones, los wearables, los equipos de escritorio vinculados y las copias de seguridad.
- [ ] Los archivos se sanitizaron, cifraron cuando fue necesario y se abrieron en un contexto desechable.
- [ ] La recuperación funciona sin vincular identidades no relacionadas.
- [ ] Los registros, el historial y los servicios temporales de compartición tienen una regla de apagado/retención.

## References

- [1] [Signal — Privacidad del número de teléfono y nombres de usuario](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Política de privacidad y condiciones de uso](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Guía de privacidad y seguridad](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Cómo funciona](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Diseño de seguridad](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Uso avanzado y CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI y uso oficiales](https://github.com/FiloSottile/age)
- [9] [Preguntas frecuentes de ExifTool — Eliminación segura de metadatos](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Arquitectura de Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
