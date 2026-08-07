# Volume système scellé de macOS et DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volume système scellé (SSV)

### Informations de base

À partir de **macOS Big Sur (11.0)**, le volume système est scellé cryptographiquement à l'aide d'un **arbre de hachage de snapshot APFS**. Cette fonctionnalité est appelée **Sealed System Volume (SSV)**. La partition système est montée en **lecture seule**, et toute modification brise le sceau, ce qui est vérifié lors du démarrage.<sup>[[11]](#references)</sup>

Le SSV fournit :
- **Détection des altérations** — toute modification des binaires ou frameworks système est détectable grâce à la rupture du sceau cryptographique
- **Protection contre les retours en arrière** — le processus de démarrage vérifie l'intégrité du snapshot système
- **Prévention des rootkits** — même root ne peut pas modifier de manière persistante les fichiers du volume système (sans briser le sceau)

### Vérification de l'état du SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### Entitlements des writers SSV

Certains binaires système Apple disposent d’entitlements leur permettant de modifier ou de gérer le sealed system volume :

| Entitlement | Objectif |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Restaurer le system volume vers un snapshot précédent |
| `com.apple.private.apfs.create-sealed-snapshot` | Créer un nouveau sealed snapshot après les mises à jour du système |
| `com.apple.rootless.install.heritable` | Écrire dans les chemins protégés par SIP (hérité par les processus enfants) |
| `com.apple.rootless.install` | Écrire dans les chemins protégés par SIP |

### Identifier les writers SSV
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

#### Attaque de restauration de snapshot

Si un attaquant compromet un binaire avec `com.apple.private.apfs.revert-to-snapshot`, il peut **restaurer le volume système à un état antérieur à une mise à jour**, rétablissant ainsi des vulnérabilités connues :
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Le rollback d'un **snapshot** annule effectivement les mises à jour de sécurité, en restaurant des vulnérabilités du kernel et du système qui avaient été corrigées. Il s'agit de l'une des opérations les plus dangereuses possibles sur les versions modernes de macOS.

#### Remplacement de binaires système

Avec un bypass de SIP + la capacité d'écriture sur le SSV, un attaquant peut :

1. Monter le volume système en lecture-écriture
2. Remplacer un daemon système ou une bibliothèque de framework par une version trojanisée
3. Re-scelller le snapshot (ou accepter le sceau invalide si SIP est déjà dégradé)
4. Le rootkit persiste après les redémarrages et reste invisible pour les outils de détection userland

### CVE réelles

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass de SIP exploitant l'entitlement `com.apple.rootless.install.heritable` de `system_installd` pour exécuter des scripts post-installation arbitraires ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass de SIP : `system_installd` plaçait le script post-installation dans un dossier protégé par SIP sous `/tmp`, mais `/tmp` lui-même n'est pas protégé par SIP ; le dossier pouvait donc être remplacé en montant une image par-dessus ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write dans XNU permettant d'écrire dans des fichiers en lecture seule appartenant à `root` ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informations de base

**DataVault** est la couche de protection d'Apple pour les bases de données système sensibles. Même **root ne peut pas accéder aux fichiers protégés par DataVault** — seuls les processus disposant d'entitlements spécifiques peuvent les lire ou les modifier.<sup>[[4]](#references)</sup> Les stores protégés comprennent :

| Base de données protégée | Chemin | Contenu |
|---|---|---|
| TCC (système) | `/Library/Application Support/com.apple.TCC/TCC.db` | Décisions de confidentialité TCC à l'échelle du système |
| TCC (utilisateur) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Décisions de confidentialité TCC propres à l'utilisateur |
| Keychain (système) | `/Library/Keychains/System.keychain` | Keychain système |
| Keychain (utilisateur) | `~/Library/Keychains/login.keychain-db` | Keychain utilisateur |

La protection DataVault est appliquée au **niveau du filesystem** à l'aide d'attributs étendus et de flags de protection du volume, vérifiés par le kernel.

### Entitlements du contrôleur DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Trouver les contrôleurs DataVault
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
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

#### Modification directe de la base de données TCC

Si un attaquant compromet un binaire contrôleur DataVault (par exemple, via une code injection dans un processus doté de `com.apple.private.tcc.manager`), il peut **modifier directement la base de données TCC** afin d’accorder n’importe quelle autorisation TCC à n’importe quelle application :<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modification de la base de données TCC constitue le **bypass ultime de la confidentialité** — elle accorde silencieusement n'importe quelle permission, sans aucune invite utilisateur ni indicateur visible. Historiquement, plusieurs chaînes d'escalade de privilèges macOS se sont terminées par des écritures dans la base de données TCC comme payload final.

#### Accès à la base de données du keychain

DataVault protège également les fichiers de support du keychain. Un contrôleur DataVault compromis peut :

1. Lire les fichiers bruts de la base de données du keychain
2. Extraire les éléments chiffrés du keychain
3. Tenter un déchiffrement offline à l'aide du mot de passe de l'utilisateur ou de clés récupérées

### CVE réelles impliquant un bypass de DataVault/TCC

| CVE | Description |
|---|---|
| CVE-2024-44131 | Race condition de symlink dans FileProvider permettant à un helper privilégié d'atteindre des données protégées par TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | En tant que root, **créer un nouvel utilisateur dont le `NFSHomeDirectory` pointe vers un `TCC.db` contrôlé par l'attaquant** ; lors de la connexion, `tccd` le consomme et les permissions s'appliquent, permettant d'atteindre les données d'autres utilisateurs ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | « powerdir » : modifier le répertoire personnel de l'utilisateur afin d'y placer un TCC.db contrôlé par l'attaquant ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Défaut de conclusion de bundle permettant à une application **d'hériter des permissions TCC d'un bundle donateur** sans invite ; exploité dans la nature par **XCSSET** pour effectuer des captures d'écran du bureau ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` construisait le chemin de la base de données à partir de `$HOME`, de sorte que `launchctl setenv HOME` le redirigeait vers un `TCC.db` contrôlé par l'attaquant ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` détenait `com.apple.private.tcc.manager` **et** désactivait la validation des bibliothèques ; un plug-in HAL déposé dans `/Library/Audio/Plug-Ins/HAL` pouvait donc accorder arbitrairement des droits TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## Références

- [1] [Microsoft découvre une nouvelle vulnérabilité macOS, Shrootless, qui pourrait contourner la protection de l'intégrité du système](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analyse technique : CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Sécurité des plateformes Apple — Protection des données](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131 : le bypass TCC vole des données depuis iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Découverte des malwares macOS : contournement de TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Une nouvelle vulnérabilité macOS, « powerdir », pourrait permettre un accès non autorisé aux données utilisateur](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Un bypass TCC zero-day découvert dans le malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934 : contournement du framework macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Jouer de la musique et contourner TCC, alias CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Le cauchemar des mises à jour OTA d'Apple (snapshots APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Exploitation de TCC](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
