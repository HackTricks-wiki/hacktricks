# Forensics des sauvegardes iOS (triage centré sur la messagerie)

{{#include ../../banners/hacktricks-training.md}}

Cette page décrit des étapes pratiques pour reconstruire et analyser des sauvegardes iOS afin de détecter des signes de diffusion d’exploits 0-click via des pièces jointes d’applications de messagerie. Elle se concentre sur la conversion de la structure hachée des sauvegardes Apple en chemins lisibles, puis sur l’énumération et l’analyse des pièces jointes dans les applications courantes.

Objectifs :
- Reconstituer des chemins lisibles à partir de Manifest.db
- Énumérer les bases de données de messagerie (iMessage, WhatsApp, Signal, Telegram, Viber)
- Résoudre les chemins des pièces jointes, extraire les objets intégrés (PDF/images/polices) et les transmettre à des détecteurs structurels


## Reconstruction d’une sauvegarde iOS

Les sauvegardes stockées sous MobileSync utilisent des noms de fichiers hachés qui ne sont pas lisibles par un humain. La base de données SQLite Manifest.db associe chaque objet stocké à son chemin logique.

Procédure générale :
1) Ouvrir Manifest.db et lire les enregistrements des fichiers (domaine, relativePath, indicateurs, fileID/hash)
2) Reconstituer la hiérarchie originale des dossiers à partir du domaine et de relativePath
3) Copier ou créer un lien physique pour chaque objet stocké vers son chemin reconstitué

Exemple de workflow avec un outil qui implémente ce processus de bout en bout (ElegantBouncer) :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes :
- Gérez les backups chiffrés en fournissant le mot de passe du backup à votre extracteur
- Préservez les horodatages/ACL d’origine lorsque cela est possible, pour leur valeur probante

### Acquisition et déchiffrement du backup (USB / Finder / libimobiledevice)

- Dans macOS/Finder, activez « Encrypt local backup » et créez un *nouveau* backup chiffré afin que les éléments du trousseau soient présents.
- Cross-platform : `idevicebackup2` (libimobiledevice ≥1.4.0) prend en charge les changements du protocole de backup d’iOS 17/18 et corrige les erreurs antérieures de handshake de restauration/backup.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage piloté par les IOC avec MVT

Le Mobile Verification Toolkit (mvt-ios) d'Amnesty fonctionne désormais directement sur les sauvegardes iTunes/Finder chiffrées, en automatisant le déchiffrement et la recherche de correspondances avec les IOC dans les cas de spyware mercenaire.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Les résultats sont enregistrés dans `mvt-results/` (par exemple, `analytics_detected.json`, `safari_history_detected.json`) et peuvent être corrélés avec les chemins des pièces jointes récupérés ci-dessous.

### Analyse générale des artefacts (iLEAPP)

Pour obtenir une chronologie/des métadonnées au-delà de la messagerie, exécutez directement iLEAPP sur le dossier de sauvegarde (prend en charge les schémas iOS 11‑17) :
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Énumération des pièces jointes des applications de messagerie

Après reconstruction, énumérez les pièces jointes des applications populaires. Le schéma exact varie selon l’application et la version, mais l’approche reste similaire : interroger la base de données de messagerie, relier les messages aux pièces jointes et résoudre les chemins sur le disque.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tables clés : message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Exemples de requêtes :
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
Les chemins des pièces jointes peuvent être absolus ou relatifs à l’arborescence reconstruite sous Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Liaison courante : table des messages ↔ table des médias/pièces jointes (la dénomination varie selon la version). Interrogez les lignes de médias pour obtenir les chemins sur disque. Les versions récentes d’iOS exposent toujours `ZMEDIALOCALPATH` dans `ZWAMEDIAITEM`.
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
Les chemins se résolvent généralement sous `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` dans la sauvegarde reconstruite.

### Signal / Telegram / Viber
- Signal : la base de données des messages est chiffrée ; cependant, les pièces jointes mises en cache sur le disque (ainsi que les miniatures) sont généralement analysables
- Telegram : le cache reste sous `Library/Caches/` dans le sandbox ; les versions iOS 18 présentent des bugs lors de l’effacement du cache, de sorte que les caches de médias résiduels volumineux constituent souvent des sources de preuves importantes<sup>[[5]](#references)</sup>
- Viber : Viber.sqlite contient des tables de messages et de pièces jointes avec des références vers les fichiers sur le disque

Conseil : même lorsque les métadonnées sont chiffrées, l’analyse des répertoires de médias et de cache permet toujours de mettre au jour des objets malveillants.


## Analyse des pièces jointes à la recherche d’exploits structurels

Une fois les chemins des pièces jointes obtenus, transmettez-les à des détecteurs structurels qui valident les invariants du format de fichier plutôt que les signatures. Exemple avec ElegantBouncer :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Les détections couvertes par les règles structurelles incluent :<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860) : états de dictionnaire JBIG2 impossibles
- WebP/VP8L BLASTPASS (CVE‑2023‑4863) : constructions de tables de Huffman surdimensionnées
- TrueType TRIANGULATION (CVE‑2023‑41990) : opcodes de bytecode non documentés
- DNG/TIFF CVE‑2025‑43300 : incohérences entre les métadonnées et les composants du flux


## Validation, réserves et faux positifs

- Conversions temporelles : iMessage stocke les dates dans les époques/unités Apple sur certaines versions ; convertissez-les correctement lors du reporting
- Évolution du schéma : les schémas SQLite des applications changent au fil du temps ; confirmez les noms des tables/colonnes pour chaque build de l’appareil
- Extraction récursive : les PDF peuvent intégrer des flux JBIG2 et des polices ; extrayez et analysez les objets internes
- Faux positifs : les heuristiques structurelles sont prudentes, mais peuvent signaler des médias rarement malformés mais inoffensifs<sup>[[1]](#references)[[2]](#references)</sup>


## Références

- [1] [ELEGANTBOUNCER : lorsque vous ne pouvez pas obtenir les échantillons, mais devez tout de même détecter la menace](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Projet ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow de sauvegarde iOS de MVT](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Notes de version de libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [La mise à jour 11.2 a cassé le nettoyage du cache sur iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
