# Analyse forensique des sauvegardes iOS (triage centré sur la messagerie)

{{#include ../../banners/hacktricks-training.md}}

Cette page décrit des étapes pratiques pour reconstruire et analyser des backups iOS à la recherche d'indices de livraison d'exploits 0‑click via des pièces jointes d'applications de messagerie. Elle se concentre sur la transformation du layout de backup haché d'Apple en chemins lisibles par l'humain, puis sur l'énumération et le scan des pièces jointes dans les applications courantes.

Objectifs :
- Reconstituer des chemins lisibles à partir de Manifest.db
- Énumérer les bases de données de messagerie (iMessage, WhatsApp, Signal, Telegram, Viber)
- Résoudre les chemins des pièces jointes, extraire les objets embarqués (PDF/Images/Fonts) et les soumettre à des détecteurs structurels


## Reconstruction d'une sauvegarde iOS

Les backups stockés sous MobileSync utilisent des noms de fichiers hachés qui ne sont pas lisibles par l'humain. La base de données SQLite Manifest.db mappe chaque objet stocké à son chemin logique.

Procédure générale :
1) Ouvrir Manifest.db et lire les enregistrements de fichiers (domain, relativePath, flags, fileID/hash)  
2) Recréer la hiérarchie de dossiers originale basée sur domain + relativePath  
3) Copier ou créer un hardlink pour chaque objet stocké vers son chemin reconstruit

Exemple de workflow avec un outil qui implémente cela de bout en bout (ElegantBouncer) :
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
- Traitez les sauvegardes chiffrées en fournissant le mot de passe de la sauvegarde à votre outil d'extraction
- Préservez les horodatages/ACLs d'origine lorsque c'est possible pour leur valeur probante

### Acquisition et déchiffrement de la sauvegarde (USB / Finder / libimobiledevice)

- Sous macOS/Finder, activez "Encrypt local backup" et créez une sauvegarde chiffrée *neuve* afin que les éléments du trousseau (keychain) soient présents.
- Multi-plateforme : `idevicebackup2` (libimobiledevice ≥1.4.0) comprend les changements du protocole de sauvegarde iOS 17/18 et corrige les anciennes erreurs de négociation lors de la restauration/sauvegarde.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage piloté par les IOC avec MVT

Le Mobile Verification Toolkit d'Amnesty (mvt-ios) fonctionne désormais directement sur les sauvegardes iTunes/Finder chiffrées, automatisant le déchiffrement et la mise en correspondance des IOC pour les cas de spyware mercenaire.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Les résultats se trouvent sous `mvt-results/` (p. ex., analytics_detected.json, safari_history_detected.json) et peuvent être corrélés avec les chemins des pièces jointes récupérés ci‑dessous.

### Analyse générale des artefacts (iLEAPP)

Pour la chronologie et les métadonnées au‑delà de la messagerie, exécutez iLEAPP directement sur le dossier de sauvegarde (prise en charge des schémas iOS 11‑17) :
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Énumération des pièces jointes des applications de messagerie

Après la reconstruction, énumérez les pièces jointes pour les applications populaires. Le schéma exact varie selon l'application/la version, mais l'approche est similaire : interroger la base de données de messagerie, lier les messages aux pièces jointes, et résoudre les chemins sur le disque.

### iMessage (sms.db)
Tables clés: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Exemples de requêtes:
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
Les chemins des pièces jointes peuvent être absolus ou relatifs à l'arborescence reconstruite sous Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Association courante : table message ↔ table media/attachment (la nomenclature varie selon la version). Interrogez les entrées media pour obtenir les chemins sur le disque. Les versions récentes d'iOS exposent encore `ZMEDIALOCALPATH` dans `ZWAMEDIAITEM`.
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
- Signal : la base de données des messages est chiffrée ; cependant, les attachments mis en cache sur le disque (et les thumbnails) sont généralement analysables
- Telegram : le cache reste sous `Library/Caches/` à l'intérieur du sandbox ; les builds iOS 18 présentent des bugs de vidage de cache, donc de larges caches médias résiduels sont des sources de preuve courantes
- Viber : Viber.sqlite contient des tables message/attachment avec des références sur disque

Astuce : même lorsque les métadonnées sont chiffrées, l'analyse des répertoires media/cache met toujours au jour des objets malveillants.


## Scanning attachments for structural exploits

Une fois que vous avez les chemins des pièces jointes, injectez-les dans des détecteurs structurels qui valident les invariants du format de fichier plutôt que les signatures. Exemple avec ElegantBouncer :
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): états de dictionnaire JBIG2 impossibles
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): constructions de tables Huffman surdimensionnées
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode non documentés
- DNG/TIFF CVE‑2025‑43300: incompatibilités entre métadonnées et composant de flux


## Validation, caveats, and false positives

- Conversions temporelles : iMessage stocke les dates en epochs/unités Apple sur certaines versions ; convertissez-les correctement lors de la rédaction du rapport
- Dérive de schéma : les schémas SQLite des apps évoluent dans le temps ; confirmez les noms de tables/colonnes selon la build de l'appareil
- Extraction récursive : les PDFs peuvent embarquer des flux JBIG2 et des polices ; extrayez et scannez les objets internes
- Faux positifs : les heuristiques structurelles sont conservatrices mais peuvent signaler des médias rares malformés mais bénins


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
