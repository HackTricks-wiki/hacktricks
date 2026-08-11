# iOS Backup Forensics (triage centrado en Messaging)

{{#include ../../banners/hacktricks-training.md}}

Esta página describe pasos prácticos para reconstruir y analizar backups de iOS en busca de indicios de entrega de exploits 0-click mediante archivos adjuntos de aplicaciones de mensajería. Se centra en convertir el diseño hashado de los backups de Apple en rutas legibles y, posteriormente, enumerar y escanear los archivos adjuntos de varias aplicaciones comunes.

Objetivos:
- Reconstruir rutas legibles a partir de Manifest.db
- Enumerar bases de datos de aplicaciones de mensajería (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver las rutas de los archivos adjuntos, extraer objetos incrustados cuando sea compatible (PDF/Images/Fonts) y proporcionárselos a detectores estructurales


## Reconstrucción de un backup de iOS

Los backups almacenados en MobileSync utilizan nombres de archivo hashados que no son legibles. La base de datos SQLite Manifest.db asigna cada objeto almacenado a su ruta lógica.<sup>[[1]](#references)[[2]](#references)</sup>

Procedimiento de alto nivel:
1) Abrir Manifest.db y leer los registros de archivos (domain, relativePath, flags, fileID/hash)
2) Recrear la jerarquía de carpetas original basándose en domain + relativePath
3) Copiar o crear un hardlink de cada objeto almacenado a su ruta reconstruida

Flujo de trabajo de ejemplo con una herramienta que implementa este proceso de extremo a extremo (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Descifra las copias de seguridad cifradas antes de pasarlas a una herramienta de reconstrucción; ElegantBouncer espera una copia de seguridad descifrada.<sup>[[2]](#references)[[3]](#references)</sup>
- Conserva las marcas de tiempo/ACL originales cuando sea posible para preservar su valor probatorio

### Adquisición y descifrado de la copia de seguridad (USB / Finder / libimobiledevice)

- En Finder/Apple Devices/iTunes, activa "Encrypt local backup" y crea una nueva copia de seguridad; las copias de seguridad cifradas pueden incluir contraseñas guardadas y datos de Salud que las copias de seguridad no cifradas omiten.<sup>[[8]](#references)</sup>
- Multiplataforma: libimobiledevice 1.4.0 incluye correcciones para `idevicebackup2`.<sup>[[4]](#references)</sup> Activa el cifrado de forma interactiva y, a continuación, fuerza una copia de seguridad completa usando el orden de comandos documentado, con el directorio de destino al final.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage basado en IOC con MVT

Mobile Verification Toolkit de Amnesty puede extraer una clave y descifrar backups de iTunes/Finder cifrados, y luego analizar el backup descifrado con un archivo IOC de STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Con `-o`, los resultados JSON se escriben en `/tmp/mvt-results/`; las coincidencias de IOC usan el sufijo `_detected` y pueden correlacionarse con las rutas de archivos adjuntos recuperadas a continuación.<sup>[[3]](#references)</sup>

### Análisis general de artefactos (iLEAPP)

Para obtener una línea temporal/metadatos más allá de la mensajería, ejecuta iLEAPP contra la carpeta de backup sin procesar; su tipo de entrada `itunes` acepta backups de iTunes/Finder y las versiones actuales son compatibles con iOS/iPadOS 11 y versiones posteriores.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeración de adjuntos de aplicaciones de mensajería

Después de la reconstrucción, enumera los adjuntos de las aplicaciones populares. El esquema exacto varía según la aplicación o la versión, pero el enfoque es similar: consulta la base de datos de mensajería, combina los mensajes con los adjuntos y resuelve las rutas en el disco.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tablas clave: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

Consultas de ejemplo:
```sql
-- List attachments with basic message linkage
SELECT
m.ROWID            AS message_rowid,
a.ROWID            AS attachment_rowid,
a.filename         AS attachment_path,
m.handle_id,
m.date,
m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
c.display_name,
a.filename AS attachment_path,
m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```
Las rutas de los archivos adjuntos pueden ser absolutas o relativas al árbol reconstruido bajo Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Vinculación habitual: tabla de mensajes ↔ tabla de medios/archivos adjuntos (la nomenclatura varía según la versión). Consulta las filas de medios para obtener las rutas en disco. Belkasoft identifica `ZMEDIALOCALPATH` en `ZWAMEDIAITEM` como la ubicación del archivo multimedia; la implementación actual de ElegantBouncer une `ZWAMEDIAITEM.ZMESSAGE` con `ZWAMESSAGE.Z_PK` y antepone `Message/` al resolver una ruta que comienza con `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Para esa ruta de reconstrucción de ElegantBouncer, una ruta de medios que comienza con `Media/` se resuelve bajo `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; la guía de Belkasoft documenta en cambio una ruta `Messages/Media/`, así que inspecciona el backup antes de asumir cualquiera de las dos grafías.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: la base de datos de mensajes está cifrada; sin embargo, los archivos adjuntos almacenados en cache en el disco (y las miniaturas) normalmente se pueden escanear.<sup>[[2]](#references)</sup>
- Telegram: inspecciona los directorios de media/cache de la app; Telegram documentó un bug de limpieza de cache en la app iOS 11.2 sobre iOS 18.0.1, marcado como corregido en la 11.3, así que comprueba si quedan archivos residuales.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite contiene tablas de mensajes/archivos adjuntos con referencias en disco.<sup>[[2]](#references)</sup>

Consejo: incluso cuando los metadatos están cifrados, escanear los directorios de media/cache aún permite detectar objetos maliciosos.<sup>[[2]](#references)</sup>


## Escaneo de archivos adjuntos en busca de exploits estructurales

Una vez que tengas las rutas de los archivos adjuntos, pásalas a detectores estructurales que validen las invariantes del formato de archivo en lugar de las firmas. Ejemplo con ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Las detecciones cubiertas por las reglas estructurales incluyen:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados de diccionario JBIG2 imposibles
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construcciones de tablas Huffman sobredimensionadas
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode no documentados
- DNG/TIFF CVE‑2025‑43300: discrepancias entre los componentes de metadatos y del flujo


## Validación, advertencias y falsos positivos

- Conversiones de tiempo: iMessage almacena las fechas en épocas/unidades de Apple en algunas versiones; conviértelas adecuadamente durante la elaboración de informes.<sup>[[2]](#references)</sup>
- Evolución del esquema: los esquemas SQLite de las aplicaciones cambian con el tiempo; confirma los nombres de tablas/columnas según la compilación del dispositivo
- Extracción recursiva: los PDF pueden incluir flujos JBIG2 y fuentes; utiliza un parser que pueda extraer y escanear los objetos internos
- Falsos positivos: las heurísticas estructurales son conservadoras, pero pueden señalar medios poco comunes, malformados y benignos.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Cuando no puedes obtener las muestras, pero aún necesitas detectar la amenaza](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Proyecto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Flujo de trabajo de MVT iOS backup](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Notas de la versión de libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [La actualización 11.2 ha interrumpido la limpieza de la caché en iOS 18.0.1 (rastreador de errores de Telegram)](https://bugs.telegram.org/c/44361)
- [6] [Manual de idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Proyecto iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Acerca de las copias de seguridad cifradas en tu iPhone, iPad o iPod touch (soporte de Apple)](https://support.apple.com/en-ie/108353)
- [9] [Forense de WhatsApp en iOS con Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Scanner de WhatsApp y resolvedor de rutas de ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
