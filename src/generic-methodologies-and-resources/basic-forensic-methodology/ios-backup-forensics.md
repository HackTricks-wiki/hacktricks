# Forensics des sauvegardes iOS (triage centré sur la messagerie)

{{#include ../../banners/hacktricks-training.md}}

Cette page décrit les étapes pratiques pour reconstruire et analyser des sauvegardes iOS afin de détecter des signes de livraison d’un exploit 0-click via des pièces jointes d’applications de messagerie. Elle se concentre sur la conversion de la structure de sauvegarde hachée d’Apple en chemins lisibles, puis sur l’énumération et l’analyse des pièces jointes de plusieurs applications courantes.

Objectifs :
- Reconstruire des chemins lisibles à partir de Manifest.db
- Énumérer les bases de données de messagerie (iMessage, WhatsApp, Signal, Telegram, Viber)
- Résoudre les chemins des pièces jointes, extraire les objets intégrés lorsque cela est pris en charge (PDF/Images/Fonts), puis les transmettre à des détecteurs structurels


## Reconstruction d’une sauvegarde iOS

Les sauvegardes stockées sous MobileSync utilisent des noms de fichiers hachés qui ne sont pas lisibles par l’humain. La base de données SQLite Manifest.db associe chaque objet stocké à son chemin logique.<sup>[[1]](#references)[[2]](#references)</sup>

Procédure générale :
1) Ouvrir Manifest.db et lire les enregistrements des fichiers (domain, relativePath, flags, fileID/hash)
2) Recréer la hiérarchie originale des dossiers à partir de domain + relativePath
3) Copier ou créer un hardlink vers chaque objet stocké dans son chemin reconstruit

Exemple de workflow avec un outil qui implémente ce processus de bout en bout (ElegantBouncer) :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes :
- Déchiffrez les sauvegardes chiffrées avant de les transmettre à un outil de reconstruction ; ElegantBouncer attend une sauvegarde déchiffrée.<sup>[[2]](#references)[[3]](#references)</sup>
- Préservez si possible les horodatages/ACL d’origine pour leur valeur probatoire

### Acquisition et déchiffrement de la sauvegarde (USB / Finder / libimobiledevice)

- Dans Finder/Apple Devices/iTunes, activez « Chiffrer la sauvegarde locale » et créez une nouvelle sauvegarde ; les sauvegardes chiffrées peuvent inclure les mots de passe enregistrés et les données de santé que les sauvegardes non chiffrées omettent.<sup>[[8]](#references)</sup>
- Multiplateforme : libimobiledevice 1.4.0 inclut des correctifs pour `idevicebackup2`.<sup>[[4]](#references)</sup> Activez le chiffrement de manière interactive, puis forcez une sauvegarde complète en respectant l’ordre des commandes documenté, avec le répertoire cible en dernier.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage piloté par les IOC avec MVT

Le Mobile Verification Toolkit d’Amnesty peut extraire une clé et déchiffrer les backups iTunes/Finder chiffrés, puis analyser le backup déchiffré avec un fichier IOC STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Avec `-o`, les résultats JSON sont écrits dans `/tmp/mvt-results/` ; les correspondances IOC utilisent le suffixe `_detected` et peuvent être corrélées aux chemins des pièces jointes récupérés ci-dessous.<sup>[[3]](#references)</sup>

### Analyse générale des artefacts (iLEAPP)

Pour obtenir une timeline/des métadonnées allant au-delà de la messagerie, exécutez iLEAPP sur le dossier de sauvegarde brut ; son type d’entrée `itunes` accepte les sauvegardes iTunes/Finder et les versions actuelles prennent en charge iOS/iPadOS 11 jusqu’aux versions actuelles.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Énumération des pièces jointes des applications de messagerie

Après la reconstruction, énumérez les pièces jointes des applications populaires. Le schéma exact varie selon l’application/la version, mais l’approche est similaire : interroger la base de données de messagerie, relier les messages aux pièces jointes et résoudre les chemins sur le disque.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tables clés : message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Les chemins des pièces jointes peuvent être absolus ou relatifs à l’arborescence reconstruite sous Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Association courante : table des messages ↔ table des médias/pièces jointes (la nomenclature varie selon la version). Interrogez les lignes de médias pour obtenir les chemins sur disque. Belkasoft identifie `ZMEDIALOCALPATH` dans `ZWAMEDIAITEM` comme l’emplacement du fichier média ; l’implémentation actuelle d’ElegantBouncer joint `ZWAMEDIAITEM.ZMESSAGE` à `ZWAMESSAGE.Z_PK` et préfixe `Message/` lors de la résolution d’un chemin commençant par `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Pour ce chemin de reconstruction ElegantBouncer, un chemin média commençant par `Media/` est résolu sous `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` ; le guide de Belkasoft documente quant à lui un chemin `Messages/Media/`, vérifiez donc le backup avant de supposer que l’une ou l’autre orthographe est correcte.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal : la base de données des messages est chiffrée ; cependant, les pièces jointes mises en cache sur le disque (ainsi que les miniatures) peuvent généralement être analysées.<sup>[[2]](#references)</sup>
- Telegram : inspectez les répertoires de médias/cache de l’application ; Telegram a documenté un bug de nettoyage du cache dans l’application iOS 11.2 sur iOS 18.0.1, indiqué comme corrigé dans la version 11.3. Vérifiez donc la présence de fichiers résiduels.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber : Viber.sqlite contient des tables de messages/pièces jointes avec des références vers le disque.<sup>[[2]](#references)</sup>

Conseil : même lorsque les métadonnées sont chiffrées, l’analyse des répertoires de médias/cache permet toujours de faire ressortir des objets malveillants.<sup>[[2]](#references)</sup>


## Analyse des pièces jointes à la recherche d’exploits structurels

Une fois les chemins des pièces jointes obtenus, transmettez-les à des détecteurs structurels qui valident les invariants du format de fichier plutôt que les signatures. Exemple avec ElegantBouncer :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Détections couvertes par les règles structurelles :<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860) : états de dictionnaire JBIG2 impossibles
- WebP/VP8L BLASTPASS (CVE‑2023‑4863) : constructions de tables Huffman surdimensionnées
- TrueType TRIANGULATION (CVE‑2023‑41990) : opcodes de bytecode non documentés
- DNG/TIFF CVE‑2025‑43300 : incohérences entre les métadonnées et les composants du flux


## Validation, réserves et faux positifs

- Conversions temporelles : iMessage stocke les dates selon les époques/unités Apple dans certaines versions ; convertissez-les correctement lors du reporting.<sup>[[2]](#references)</sup>
- Évolution du schéma : les schémas SQLite des applications changent au fil du temps ; confirmez les noms des tables/colonnes pour chaque build de l'appareil
- Extraction récursive : les PDF peuvent intégrer des flux JBIG2 et des polices ; utilisez un parseur capable d'extraire et d'analyser les objets internes
- Faux positifs : les heuristiques structurelles sont prudentes, mais peuvent signaler des médias malformés rares et pourtant inoffensifs.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER : Quand vous ne pouvez pas obtenir les échantillons, mais devez tout de même détecter la menace](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Projet ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow de backup iOS de MVT](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Notes de version de libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [La mise à jour 11.2 a cassé le nettoyage du cache sur iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Manuel de idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Projet iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [À propos des backups chiffrés sur votre iPhone, iPad ou iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Forensics WhatsApp iOS avec Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Scanner WhatsApp et résolveur de chemins ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
