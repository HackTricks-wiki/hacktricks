# Forensics de backups de iOS (triage centrado en messaging)

{{#include ../../banners/hacktricks-training.md}}

Esta página describe pasos prácticos para reconstruir y analizar backups de iOS en busca de indicios de entrega de exploits 0-click mediante attachments de apps de messaging. Se centra en convertir el layout hashed de backups de Apple en rutas legibles y, después, enumerar y escanear attachments en apps comunes.

Objetivos:
- Reconstruir rutas legibles a partir de Manifest.db
- Enumerar bases de datos de messaging (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver rutas de attachments, extraer objetos incrustados (PDF/Images/Fonts) y enviarlos a structural detectors


## Reconstrucción de un backup de iOS

Los backups almacenados bajo MobileSync utilizan filenames hashed que no son legibles para las personas. La base de datos SQLite Manifest.db asigna cada objeto almacenado a su ruta lógica.

Procedimiento de alto nivel:
1) Abrir Manifest.db y leer los registros de archivos (domain, relativePath, flags, fileID/hash)
2) Recrear la jerarquía de carpetas original basándose en domain + relativePath
3) Copiar o crear un hardlink de cada objeto almacenado a su ruta reconstruida

Ejemplo de workflow con una herramienta que implementa este proceso end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Gestiona los backups cifrados proporcionando la contraseña del backup a tu extractor
- Conserva las marcas de tiempo y las ACLs originales cuando sea posible por su valor probatorio

### Adquisición y descifrado del backup (USB / Finder / libimobiledevice)

- En macOS/Finder, activa "Encrypt local backup" y crea un backup cifrado *nuevo* para que los elementos del keychain estén presentes.
- Multiplataforma: `idevicebackup2` (libimobiledevice ≥1.4.0) es compatible con los cambios del protocolo de backup de iOS 17/18 y corrige errores anteriores de handshake de restauración/backup.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage basado en IOC con MVT

El Mobile Verification Toolkit de Amnesty (mvt-ios) ahora funciona directamente con copias de seguridad cifradas de iTunes/Finder, automatizando el descifrado y la coincidencia con IOC en casos de spyware mercenario.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Los resultados se guardan en `mvt-results/` (por ejemplo, analytics_detected.json y safari_history_detected.json) y se pueden correlacionar con las rutas de los archivos adjuntos recuperadas a continuación.

### Análisis general de artefactos (iLEAPP)

Para obtener información de la línea temporal o metadatos más allá de la mensajería, ejecuta iLEAPP directamente sobre la carpeta de backup (compatible con los esquemas de iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeración de archivos adjuntos de aplicaciones de mensajería

Después de la reconstrucción, enumera los archivos adjuntos de aplicaciones populares. El esquema exacto varía según la aplicación y la versión, pero el enfoque es similar: consulta la base de datos de mensajería, une los mensajes con los archivos adjuntos y resuelve las rutas en el disco.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tablas principales: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Las rutas de los adjuntos pueden ser absolutas o relativas al árbol reconstruido en Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Vinculación habitual: tabla de mensajes ↔ tabla de medios/adjuntos (el nombre varía según la versión). Consulta las filas de medios para obtener las rutas en disco. Las versiones recientes de iOS todavía exponen `ZMEDIALOCALPATH` en `ZWAMEDIAITEM`.
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Las rutas normalmente se resuelven bajo `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` dentro del backup reconstruido.

### Signal / Telegram / Viber
- Signal: la DB de mensajes está cifrada; sin embargo, los adjuntos almacenados en caché en el disco (y las miniaturas) normalmente se pueden escanear
- Telegram: la caché permanece en `Library/Caches/` dentro del sandbox; las versiones de iOS 18 presentan errores al borrar la caché, por lo que las cachés residuales grandes de medios son fuentes habituales de evidencia<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite contiene tablas de mensajes/adjuntos con referencias en disco

Consejo: incluso cuando los metadatos están cifrados, escanear los directorios de medios/caché sigue permitiendo detectar objetos maliciosos.


## Escaneo de adjuntos en busca de exploits estructurales

Una vez que tengas las rutas de los adjuntos, pásalas a detectores estructurales que validen las invariantes del formato de archivo en lugar de las firmas. Ejemplo con ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
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
- DNG/TIFF CVE‑2025‑43300: discrepancias entre los metadatos y los componentes del flujo


## Validación, consideraciones y falsos positivos

- Conversiones de tiempo: iMessage almacena las fechas usando épocas/unidades de Apple en algunas versiones; conviértelas adecuadamente durante la elaboración del informe
- Deriva del esquema: los esquemas SQLite de las aplicaciones cambian con el tiempo; confirma los nombres de las tablas/columnas según la compilación del dispositivo
- Extracción recursiva: los PDF pueden incluir flujos JBIG2 y fuentes; extrae y analiza los objetos internos
- Falsos positivos: las heurísticas estructurales son conservadoras, pero pueden señalar contenido multimedia poco común, malformado pero benigno<sup>[[1]](#references)[[2]](#references)</sup>


## Referencias

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Proyecto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Flujo de trabajo de backup de iOS de MVT](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Notas de la versión de libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [La actualización 11.2 ha roto la limpieza de la caché en iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
