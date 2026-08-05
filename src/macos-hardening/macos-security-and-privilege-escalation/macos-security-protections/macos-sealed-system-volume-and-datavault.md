# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informations de base

Depuis **macOS Big Sur (11.0)**, le volume système est scellé cryptographiquement à l’aide d’un **arbre de hachage de snapshot APFS**. Cette fonctionnalité est appelée **Sealed System Volume (SSV)**. La partition système est montée en **lecture seule** et toute modification rompt le sceau, ce qui est vérifié lors du démarrage.

Le SSV fournit :
- **Détection des falsifications** — toute modification des binaires ou frameworks système est détectable grâce à la rupture du sceau cryptographique
- **Protection contre les restaurations vers une version antérieure** — le processus de démarrage vérifie l’intégrité du snapshot système
- **Prévention des rootkits** — même root ne peut pas modifier durablement les fichiers du volume système (sans rompre le sceau)

### Vérification de l’état du SSV
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
| `com.apple.rootless.install.heritable` | Écrire dans des chemins protégés par SIP (hérité par les processus enfants) |
| `com.apple.rootless.install` | Écrire dans des chemins protégés par SIP |

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

#### Attaque par restauration d'instantané

Si un attaquant compromet un binaire doté de `com.apple.private.apfs.revert-to-snapshot`, il peut **restaurer le volume système à un état antérieur à une mise à jour**, rétablissant ainsi des vulnérabilités connues :
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Le rollback d'un **snapshot** annule effectivement les mises à jour de sécurité, en restaurant des vulnérabilités précédemment corrigées du kernel et du système. Il s'agit de l'une des opérations les plus dangereuses possibles sur les versions modernes de macOS.

#### System Binary Replacement

Avec un contournement de SIP et la capacité d'écriture sur le SSV, un attaquant peut :

1. Monter le volume système en lecture-écriture
2. Remplacer un daemon système ou une bibliothèque de framework par une version trojanisée
3. Re-scelller le snapshot (ou accepter le sceau invalide si SIP est déjà dégradé)
4. Le rootkit persiste après les redémarrages et est invisible pour les outils de détection en userland

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — contournement de SIP exploitant l'entitlement `com.apple.rootless.install.heritable` de `system_installd` pour exécuter des scripts post-install arbitraires ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Contournement de SIP : `system_installd` plaçait le script post-install dans un dossier protégé par SIP sous `/tmp`, mais `/tmp` lui-même n'est pas protégé par SIP ; le dossier pouvait donc être remplacé en montant une image par-dessus ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write dans XNU permettant d'écrire dans des fichiers en lecture seule appartenant à root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** est la couche de protection d'Apple pour les bases de données système sensibles. Même **root ne peut pas accéder aux fichiers protégés par DataVault** — seuls les processus disposant d'entitlements spécifiques peuvent les lire ou les modifier.<sup>[1]</sup> Les stores protégés comprennent :

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Décisions de confidentialité TCC à l'échelle du système |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Décisions de confidentialité TCC propres à chaque utilisateur |
| Keychain (system) | `/Library/Keychains/System.keychain` | Keychain système |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Keychain utilisateur |

La protection DataVault est appliquée au **niveau du filesystem** à l'aide d'attributs étendus et de flags de protection du volume, vérifiés par le kernel.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Recherche des contrôleurs DataVault
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
### Scénarios d'attaque

#### Modification directe de la base de données TCC

Si un attaquant compromet un binaire contrôleur DataVault (par exemple, via une injection de code dans un processus doté de `com.apple.private.tcc.manager`), il peut **modifier directement la base de données TCC** afin d'accorder à n'importe quelle application n'importe quelle autorisation TCC :
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modification de la base de données TCC est le **bypass ultime de la confidentialité** — elle accorde silencieusement n'importe quelle permission, sans aucun prompt utilisateur ni indicateur visible. Historiquement, plusieurs chaînes d'escalade de privilèges macOS se sont terminées par des écritures dans la base de données TCC comme payload final.

#### Accès à la base de données du Keychain

DataVault protège également les fichiers de support du keychain. Un contrôleur DataVault compromis peut :

1. Lire les fichiers bruts de la base de données du keychain
2. Extraire les éléments chiffrés du keychain
3. Tenter un déchiffrement hors ligne à l'aide du mot de passe de l'utilisateur ou de clés récupérées

### CVEs réels impliquant un bypass de DataVault/TCC

| CVE | Description |
|---|---|
| CVE-2024-44131 | Race condition de symlink dans FileProvider permettant à un helper privilégié d'atteindre des données protégées par TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | En tant que root, **créer un nouvel utilisateur dont `NFSHomeDirectory` pointe vers un `TCC.db` contrôlé par l'attaquant** ; lors de la connexion, `tccd` le consomme et les grants s'appliquent, permettant d'atteindre les données d'autres utilisateurs ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir" : modifier le répertoire personnel de l'utilisateur pour y placer un TCC.db contrôlé par l'attaquant ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Défaut de conclusion de bundle permettant à une application **d'hériter des grants TCC d'un bundle donateur** sans prompt ; exploité dans la nature par **XCSSET** pour prendre des captures d'écran du bureau ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` construisait le chemin de la DB à partir de `$HOME`, de sorte que `launchctl setenv HOME` le redirigeait vers un `TCC.db` contrôlé par l'attaquant ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` détenait `com.apple.private.tcc.manager` **et** désactivait la validation des bibliothèques ; ainsi, un plug-in HAL déposé dans `/Library/Audio/Plug-Ins/HAL` pouvait accorder des droits TCC arbitraires ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Références

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
