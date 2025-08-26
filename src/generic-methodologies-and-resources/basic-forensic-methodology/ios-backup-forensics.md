# Analyse forensique de sauvegardes iOS (triage centré sur la messagerie)

{{#include ../../banners/hacktricks-training.md}}

Cette page décrit des étapes pratiques pour reconstruire et analyser des sauvegardes iOS à la recherche d'indices de 0‑click exploit delivery via des pièces jointes d'applications de messagerie. Elle se concentre sur la conversion de la structure de sauvegarde hachée d'Apple en chemins lisibles par l'humain, puis sur l'énumération et l'analyse des pièces jointes des applications courantes.

Goals:
- Reconstruire des chemins lisibles à partir de Manifest.db
- Énumérer les bases de données de messagerie (iMessage, WhatsApp, Signal, Telegram, Viber)
- Résoudre les chemins des pièces jointes, extraire les objets incorporés (PDF/Images/Fonts) et les soumettre à des détecteurs structurels


## Reconstruction d'une sauvegarde iOS

Les sauvegardes stockées sous MobileSync utilisent des noms de fichiers hachés non lisibles. La base de données SQLite Manifest.db associe chaque objet stocké à son chemin logique.

Procédure générale :
1) Ouvrir Manifest.db et lire les enregistrements de fichiers (domain, relativePath, flags, fileID/hash)
2) Recréer la hiérarchie de dossiers originale basée sur domain + relativePath
3) Copier ou créer un hardlink pour chaque objet stocké vers son chemin reconstruit

Exemple de workflow avec un outil qui implémente cela de bout en bout (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- Traitez les sauvegardes chiffrées en fournissant le mot de passe de la sauvegarde à votre extracteur
- Conservez les horodatages/ACL d'origine lorsque possible pour leur valeur probante


## Énumération des pièces jointes des applications de messagerie

Après reconstruction, énumérez les pièces jointes des applications populaires. Le schéma exact varie selon l'application/la version, mais l'approche est similaire : interroger la base de données de messagerie, joindre les messages aux pièces jointes, et résoudre les chemins sur le disque.

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
Association courante : message table ↔ media/attachment table (les noms varient selon la version). Interroger les lignes media pour obtenir les chemins sur disque.

Exemple (générique):
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
Adjust table/column names to your app version (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal : la base de données de messages (DB) est chiffrée ; cependant, les pièces jointes mises en cache sur le disque (et les miniatures) sont généralement analysables
- Telegram : inspecter les répertoires de cache (caches photo/vidéo/document) et les associer aux conversations quand c'est possible
- Viber : Viber.sqlite contient des tables message/attachment avec des références sur disque

Tip: même lorsque les métadonnées sont chiffrées, scanner les répertoires media/cache met toujours au jour des objets malveillants.


## Scanning attachments for structural exploits

Une fois que vous avez les chemins des pièces jointes, passez-les dans des détecteurs structurels qui valident les invariants du format de fichier plutôt que les signatures. Exemple avec ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Les détections couvertes par des règles structurelles incluent :
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): états de dictionnaire JBIG2 impossibles
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): constructions de tables de Huffman surdimensionnées
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode non documentés
- DNG/TIFF CVE‑2025‑43300: incompatibilités entre métadonnées et composants de flux


## Validation, mises en garde et faux positifs

- Conversions temporelles : iMessage stocke les dates en époques/unités Apple sur certaines versions ; convertir correctement lors de la rédaction du rapport
- Dérive de schéma : les schémas SQLite des apps changent au fil du temps ; confirmer les noms de tables/colonnes selon la build de l'appareil
- Extraction récursive : les PDF peuvent embarquer des flux JBIG2 et des polices ; extraire et analyser les objets internes
- Faux positifs : les heuristiques structurelles sont conservatrices mais peuvent signaler des médias rares, malformés mais bénins


## Références

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
