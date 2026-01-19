# Forense de copias de seguridad de iOS (triage centrado en mensajería)

{{#include ../../banners/hacktricks-training.md}}

Esta página describe pasos prácticos para reconstruir y analizar copias de seguridad de iOS en busca de indicios de entrega de exploits 0‑click mediante adjuntos de aplicaciones de mensajería. Se centra en convertir la estructura de copias de seguridad con nombres hash de Apple en rutas legibles por humanos, y luego en enumerar y escanear adjuntos en aplicaciones comunes.

Objetivos:
- Reconstruir rutas legibles a partir de Manifest.db
- Enumerar bases de datos de mensajería (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver rutas de adjuntos, extraer objetos embebidos (PDF/Imágenes/Fuentes) y alimentarlos a detectores estructurales


## Reconstrucción de una copia de seguridad de iOS

Las copias almacenadas bajo MobileSync usan nombres de archivo en hash que no son legibles para humanos. La base de datos SQLite Manifest.db mapea cada objeto almacenado a su ruta lógica.

Procedimiento general:
1) Abrir Manifest.db y leer los registros de archivos (domain, relativePath, flags, fileID/hash)
2) Recrear la jerarquía de carpetas original basada en domain + relativePath
3) Copiar o crear un hardlink de cada objeto almacenado a su ruta reconstruida

Ejemplo de flujo de trabajo con una herramienta que implementa esto de extremo a extremo (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Maneje copias de seguridad cifradas proporcionando la contraseña de la copia de seguridad a su extractor
- Conserve las marcas de tiempo/ACL originales cuando sea posible por su valor probatorio

### Adquisición y descifrado de la copia de seguridad (USB / Finder / libimobiledevice)

- En macOS/Finder active "Encrypt local backup" y cree una copia de seguridad cifrada *nueva* para que los elementos del keychain estén presentes.
- Multiplataforma: `idevicebackup2` (libimobiledevice ≥1.4.0) entiende los cambios del protocolo de copia de seguridad de iOS 17/18 y corrige errores previos de handshake en restauración/copia de seguridad.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triaje guiado por IOC con MVT

El Mobile Verification Toolkit de Amnesty (mvt-ios) ahora funciona directamente sobre backups cifrados de iTunes/Finder, automatizando el descifrado y la correlación de IOC para casos de spyware mercenario.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Los resultados se colocan en `mvt-results/` (por ejemplo, analytics_detected.json, safari_history_detected.json) y pueden correlacionarse con las rutas de los adjuntos recuperadas más abajo.

### Análisis general de artefactos (iLEAPP)

Para la línea de tiempo/metadatos más allá de la mensajería, ejecute iLEAPP directamente en la carpeta de backup (soporta esquemas iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeración de archivos adjuntos de apps de mensajería

Después de la reconstrucción, enumera los archivos adjuntos de apps populares. El esquema exacto varía según la app/versión, pero el enfoque es similar: consultar la base de datos de mensajería, unir messages con attachments y resolver rutas en el disco.

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
Las rutas de los adjuntos pueden ser absolutas o relativas al árbol reconstruido bajo Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Vinculación común: tabla message ↔ tabla media/attachment (los nombres varían según la versión). Consulta las filas de media para obtener las rutas en disco. Las versiones recientes de iOS aún exponen `ZMEDIALOCALPATH` en `ZWAMEDIAITEM`.
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
Las rutas suelen resolverse bajo `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` dentro de la copia de seguridad reconstruida.

### Signal / Telegram / Viber
- Signal: la base de datos de mensajes está cifrada; sin embargo, los adjuntos almacenados en caché en disco (y las miniaturas) suelen ser escaneables
- Telegram: la caché permanece bajo `Library/Caches/` dentro del sandbox; las compilaciones de iOS 18 presentan problemas de borrado de caché, por lo que grandes cachés residuales de medios son fuentes comunes de evidencia
- Viber: Viber.sqlite contiene tablas de mensajes/adjuntos con referencias en disco

Consejo: incluso cuando los metadatos están cifrados, escanear los directorios media/cache aún revela objetos maliciosos.


## Scanning attachments for structural exploits

Una vez que tengas las rutas de los adjuntos, introdúcelas en structural detectors que validen invariantes del formato de archivo en lugar de firmas. Ejemplo con ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detecciones cubiertas por reglas estructurales incluyen:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados imposibles del diccionario JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construcciones de tablas Huffman sobredimensionadas
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode no documentados
- DNG/TIFF CVE‑2025‑43300: desajustes entre metadatos y componentes de flujo


## Validación, advertencias y falsos positivos

- Conversiones de tiempo: iMessage almacena fechas en epochs/unidades de Apple en algunas versiones; convierta apropiadamente al reportar
- Deriva de esquema: los esquemas SQLite de la app cambian con el tiempo; confirme nombres de tablas/columnas según la build del dispositivo
- Extracción recursiva: los PDFs pueden incrustar streams JBIG2 y fuentes; extraiga y escanee los objetos internos
- Falsos positivos: las heurísticas estructurales son conservadoras pero pueden marcar medios raramente malformados aunque benignos


## Referencias

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
