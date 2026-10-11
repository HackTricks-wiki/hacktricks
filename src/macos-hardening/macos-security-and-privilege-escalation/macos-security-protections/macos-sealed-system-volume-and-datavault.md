# Volume système scellé de macOS et DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volume système scellé (SSV)

### Informations de base

Depuis **macOS Big Sur (11.0)**, le volume système est scellé de manière cryptographique à l’aide d’un **arbre de hachage d’instantané APFS**. C’est ce qu’on appelle le **Sealed System Volume (SSV)**. La partition système est montée **en lecture seule** et toute modification brise le sceau, dont la validité est vérifiée au démarrage.<sup>[[11]](#references)</sup>

Le SSV assure :
- **La détection des altérations** — toute modification des binaires ou frameworks système change la racine de l’arbre de Merkle et invalide le sceau signé par Apple
- **L’authentification au démarrage** — la chaîne de démarrage vérifie l’instantané système sélectionné avant qu’il ne devienne le système de fichiers racine
- **La résistance aux rootkits** — même l’utilisateur root ne peut pas remplacer durablement les fichiers de l’instantané système authentifié sans désactiver authenticated root ou compromettre un chemin de mise à jour autorisé

Le SSV protège le volume **System**, et non le volume **Data** inscriptible qui lui est associé. Les Firmlinks fusionnent les deux volumes dans l’espace de noms visible à `/` ; ainsi, un chemin qui semble inscriptible ne prouve pas que l’objet sous-jacent appartient à l’instantané scellé. FileVault et Data Protection assurent la confidentialité des données au repos ; ils sont distincts de l’intégrité assurée par le SSV.<sup>[[11]](#references)</sup>

### Vérification de l’état du SSV

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```

### Vue effective du système : SSV + greffes de Cryptex

Dans les versions récentes de macOS, tous les exécutables visibles sous `/System` ne proviennent pas nécessairement de l’instantané SSV démarré. Les **Cryptexes** sont des images disque APFS authentifiées séparément, dont le contenu est greffé sur des répertoires sélectionnés ; les Rapid Security Responses peuvent donc remplacer des composants sensibles à la sécurité sans reconstruire le SSV de base. Lors de l’analyse d’une persistance ou de la comparaison du code système, inventorie les montages actifs et le stockage Cryptex de Preboot au lieu de calculer le hash du seul instantané de base :

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Le démarrage de la chaîne d’amorçage et les détails des Rapid Security Response sont abordés dans [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) ; cette section se concentre sur la frontière du SSV lui-même.

### Autorisations d’écriture sur le SSV

Certains binaires système d’Apple disposent d’autorisations leur permettant de modifier ou de gérer le volume système scellé :

| Autorisation | Objectif |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Rétablir le volume système à un instantané précédent |
| `com.apple.private.apfs.create-sealed-snapshot` | Créer un nouvel instantané scellé après les mises à jour système |
| `com.apple.rootless.install.heritable` | Écrire dans des chemins protégés par SIP (autorisation héritée par les processus enfants) |
| `com.apple.rootless.install` | Écrire dans des chemins protégés par SIP |

### Identifier les processus autorisés à écrire sur le SSV

```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```

### Scénarios d’attaque

#### Attaque par restauration d’instantané

Si un attaquant compromet un binaire disposant de `com.apple.private.apfs.revert-to-snapshot`, il peut **restaurer le volume système à un état antérieur à une mise à jour**, rétablissant ainsi des vulnérabilités connues :

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Le rollback d’un snapshot **annule effectivement les mises à jour de sécurité**, restaurant les vulnérabilités du kernel et du système qui avaient été corrigées. C’est l’une des opérations les plus dangereuses possibles sur les versions modernes de macOS.

#### Remplacement de binaires système

Avec un contournement de SIP et la capacité d’écriture sur le SSV, un attaquant peut :

1. Monter le volume système en lecture-écriture
2. Remplacer un daemon système ou une bibliothèque de framework par une version trojanée
3. Re-sceller le snapshot (ou accepter que le sceau soit brisé si SIP est déjà dégradé)
4. Le rootkit persiste après les redémarrages et reste invisible pour les outils de détection en userland

### CVE dans le monde réel

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — contournement de SIP exploitant l’entitlement `com.apple.rootless.install.heritable` de `system_installd` pour exécuter des scripts post-installation arbitraires ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Contournement de SIP : `system_installd` plaçait le script post-installation dans un dossier protégé par SIP sous `/tmp`, mais `/tmp` lui-même n’est pas protégé par SIP ; le dossier pouvait donc être remplacé en montant une image par-dessus ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write dans XNU permettant d’écrire dans des fichiers en lecture seule appartenant à root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informations de base

**DataVault** est une protection du système de fichiers contrôlée par entitlement pour les fichiers et répertoires sensibles. Le flag BSD `UF_DATAVAULT` (`0x00000080`) indique qu’un objet nécessite un entitlement pour la lecture comme pour l’écriture ; contrairement au DAC classique, devenir simplement **root** ou obtenir un accès complet au disque ne satisfait pas cette vérification tant que la protection est appliquée.<sup>[[4]](#references)[[13]](#references)</sup>

N’utilisez pas « DataVault » comme synonyme de toutes les bases de données protégées. Les bases de données TCC sont régies par les politiques spécifiques à TCC/FDA et à SIP (voir [macOS TCC](macos-tcc/README.md)), tandis que l’accès aux éléments du trousseau dépend également des ACL du trousseau et de la protection cryptographique (voir [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Les exemples concrets de DataVault se trouvent souvent dans des espaces de stockage appartenant à des services sous `/private/var/folders/.../0/`, comme l’espace de stockage de Screen Time ; le flag apparaît sous la forme `datavault` dans les flags BSD du fichier lorsque le répertoire parent peut être interrogé avec `stat`.

### Entitlements des contrôleurs DataVault

| Entitlement | Périmètre |
|---|---|
| `com.apple.rootless.datavault.controller` | Accéder aux objets `UF_DATAVAULT` et les gérer<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gérer les décisions TCC ; il s’agit d’une limite de confidentialité liée, mais distincte |
| `com.apple.private.tcc.allow` | Contourner les services TCC sélectionnés et indiqués dans la valeur de l’entitlement |
| `com.apple.rootless.storage.TCC` | Écrire dans l’espace de stockage TCC protégé par SIP |

Un processus qui combine un entitlement de contrôleur DataVault avec des fonctionnalités FDA, de sauvegarde, d’indexation ou d’IPC est particulièrement intéressant : recherchez une primitive de confused deputy qui copie un objet protégé vers un chemin ordinaire, plutôt que d’essayer d’ouvrir directement le coffre-fort.<sup>[[14]](#references)</sup>

### Identifier les contrôleurs DataVault

```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```

### Scénarios d’attaque

#### Modification directe de la base de données TCC (frontière TCC distincte)

Si un attaquant compromet un processus TCC manager (par exemple, via du code injection dans un processus doté de `com.apple.private.tcc.manager`), il peut **modifier directement la base de données TCC** pour accorder n’importe quelle permission TCC à n’importe quelle application :<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> La modification de la base de données TCC constitue le **contournement ultime de la confidentialité** : elle accorde silencieusement n’importe quelle permission, sans invite ni indicateur visible pour l’utilisateur. Historiquement, plusieurs chaînes d’escalade de privilèges macOS se sont conclues par l’écriture dans la base de données TCC comme charge utile finale.

#### Accès à la base de données Keychain

L’accès brut à une base de données servant de stockage à un trousseau n’équivaut pas à l’accès aux secrets en clair. Si une autre frontière de privilèges permet à un attaquant de copier la base de données, il faut encore s’en prendre au matériel cryptographique et aux ACL des éléments ; consultez plutôt la page dédiée à [macOS Keychain](../../macos-red-teaming/macos-keychain.md) au lieu de supposer qu’une autorisation DataVault-controller suffit.

#### Frontière de la copie de sauvegarde : Time Machine

Une analyse de 2026 a mis en évidence un schéma général intéressant : `backupd` dispose à la fois de `com.apple.rootless.datavault.controller` et de l’accès complet au disque afin de pouvoir copier les stockages protégés. Dans la configuration testée, `/private/var/folders` était inclus dans Time Machine et la copie de sauvegarde montée n’appliquait pas la frontière DataVault en vigueur. Le chercheur s’en est servi pour localiser le stockage SQLite de Temps d’écran et lire le code PIN de restriction en clair sans ouvrir le coffre actif. Considérez cela comme une **attaque de frontière de copie** : recensez les mandataires de sauvegarde, d’exportation, de migration, d’indexation et de diagnostic capables de matérialiser les données du coffre sur un point de montage ou un chemin moins protégé.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Ce comportement dépend de la version et de la disposition de la sauvegarde. Validez-le sur la build cible et rappelez-vous qu’une destination Time Machine chiffrée ne protège la copie que lorsqu’elle est verrouillée ; une fois montée, ses contrôles d’accès font partie de la surface d’attaque.

### CVE réels impliquant DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2024-44131 | Une race condition sur un symlink FileProvider permet à un helper privilégié d’accéder à des données protégées par TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | En tant que root, **créer un utilisateur dont le `NFSHomeDirectory` pointe vers un `TCC.db` contrôlé par l’attaquant** ; à la connexion, `tccd` le charge et les autorisations s’appliquent, donnant accès aux données d’autres utilisateurs ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | « powerdir » : modifier le répertoire personnel de l’utilisateur pour y placer un TCC.db contrôlé par l’attaquant ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Une faille de conclusion de bundle permet à une application **d’hériter des autorisations TCC d’un bundle donneur** sans invite ; la faille a été exploitée dans la nature par **XCSSET** pour effectuer des captures d’écran du bureau ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` construisait le chemin de la base de données à partir de `$HOME`, si bien que `launchctl setenv HOME` le redirigeait vers un `TCC.db` contrôlé par l’attaquant ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` disposait de `com.apple.private.tcc.manager` **et** désactivait la validation des bibliothèques ; un plug-in HAL placé dans `/Library/Audio/Plug-Ins/HAL` pouvait donc accorder des droits TCC arbitraires ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft découvre une nouvelle vulnérabilité macOS, Shrootless, pouvant contourner la protection System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analyse technique : CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Sécurité des plateformes Apple — Protection des données](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131 : le contournement de TCC vole des données depuis iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Découverte des malwares macOS : contournement de TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Une nouvelle vulnérabilité macOS, « powerdir », pourrait permettre un accès non autorisé aux données des utilisateurs](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Un contournement zero-day de TCC découvert dans le malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934 : contournement du framework Transparency, Consent, and Control (TCC) de macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Jouer de la musique et contourner TCC, alias CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Le cauchemar des mises à jour OTA d’Apple (instantanés APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Exploitation de TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Comment contourner son propre code de Temps d’écran — analyse des sources et de Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
