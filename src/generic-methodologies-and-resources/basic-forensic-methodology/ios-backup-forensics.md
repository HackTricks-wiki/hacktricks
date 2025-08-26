# Forense de backups de iOS (triaje centrado en mensajería)

{{#include ../../banners/hacktricks-training.md}}

Esta página describe pasos prácticos para reconstruir y analizar backups de iOS en busca de señales de entrega de exploits 0‑click vía adjuntos de apps de mensajería. Se centra en convertir el layout de backups hasheados de Apple en rutas legibles por humanos, y luego enumerar y escanear adjuntos en apps comunes.

Goals:
- Reconstruir rutas legibles a partir de Manifest.db
- Enumerar bases de datos de mensajería (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver rutas de adjuntos, extraer objetos incrustados (PDF/Imágenes/Fuentes), y pasarlos a detectores estructurales


## Reconstrucción de un backup de iOS

Los backups almacenados bajo MobileSync usan nombres de archivo hasheados que no son legibles por humanos. La base de datos SQLite Manifest.db mapea cada objeto almacenado a su ruta lógica.

High‑level procedure:
1) Open Manifest.db and read the file records (domain, relativePath, flags, fileID/hash)
2) Recreate the original folder hierarchy based on domain + relativePath
3) Copy or hardlink each stored object to its reconstructed path

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Maneje las copias de seguridad cifradas suministrando la contraseña de la copia de seguridad a su extractor
- Preserve marcas de tiempo/ACLs originales cuando sea posible por su valor probatorio


## Enumeración de adjuntos de aplicaciones de mensajería

Después de la reconstrucción, enumere los adjuntos de las apps populares. El esquema exacto varía según la app/version, pero el enfoque es similar: consulte la base de datos de mensajería, una mensajes con adjuntos y resuelva las rutas en el disco.

### iMessage (sms.db)
Tablas clave: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Las rutas de los archivos adjuntos pueden ser absolutas o relativas al árbol reconstruido bajo Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Vinculación común: message table ↔ media/attachment table (naming varies by version). Consulta las filas de media para obtener las rutas en disco.

Ejemplo (genérico):
```sql
SELECT
m.Z_PK          AS message_pk,
mi.ZMEDIALOCALPATH AS media_path,
m.ZMESSAGEDATE  AS message_date
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Ajusta los nombres de tablas/columnas a la versión de tu app (ZWAMESSAGE/ZWAMEDIAITEM son comunes en iOS builds).

### Signal / Telegram / Viber
- Signal: el message DB está cifrado; sin embargo, los attachments cached on disk (y thumbnails) suelen ser scan‑able
- Telegram: inspecciona cache directories (photo/video/document caches) y mapea a chats cuando sea posible
- Viber: Viber.sqlite contiene message/attachment tables con referencias on‑disk

Tip: incluso cuando la metadata está cifrada, escanear los media/cache directories sigue revelando malicious objects.


## Escaneo de attachments para structural exploits

Una vez que tengas attachment paths, introdúcelos en structural detectors que validen file‑format invariants en lugar de signatures. Ejemplo con ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados de diccionario JBIG2 imposibles
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construcciones de tablas de Huffman sobredimensionadas
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode no documentados
- DNG/TIFF CVE‑2025‑43300: desajustes entre metadatos y componentes del flujo


## Validación, advertencias y falsos positivos

- Conversiones de tiempo: iMessage almacena fechas en epochs/unidades de Apple en algunas versiones; conviértelas apropiadamente al elaborar el informe
- Deriva de esquema: los esquemas SQLite de la app cambian con el tiempo; confirma los nombres de tablas/columnas según la versión del dispositivo
- Extracción recursiva: los PDFs pueden incrustar flujos JBIG2 y fuentes; extrae y analiza los objetos internos
- Falsos positivos: las heurísticas estructurales son conservadoras pero pueden marcar medios raramente malformados que, sin embargo, son benignos


## Referencias

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
