# macOS Volume Système Scellé & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informations de base

À partir de **macOS Big Sur (11.0)**, le volume système est scellé cryptographiquement à l'aide d'un **APFS snapshot hash tree**. Ceci est appelé le **Volume Système Scellé (SSV)**. La partition système est montée en **lecture seule** et toute modification brise le sceau, qui est vérifié lors du démarrage.

Le SSV fournit :
- **Détection des falsifications** — toute modification des binaires/frameworks système est détectable via le sceau cryptographique rompu
- **Protection contre le rollback** — le processus de démarrage vérifie l'intégrité du snapshot système
- **Prévention des rootkits** — même root ne peut pas modifier de manière persistante les fichiers sur le volume système (sans casser le sceau)

### Vérifier l'état du SSV
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
### Autorisations des écrivains SSV

Certains binaires système d'Apple disposent d'entitlements qui leur permettent de modifier ou de gérer le volume système scellé :

| Entitlement | But |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Rétablir le volume système à un instantané précédent |
| `com.apple.private.apfs.create-sealed-snapshot` | Créer un nouvel instantané scellé après les mises à jour système |
| `com.apple.rootless.install.heritable` | Écrire dans des chemins protégés par SIP (hérité par les processus enfants) |
| `com.apple.rootless.install` | Écrire dans des chemins protégés par SIP |

### Trouver les écrivains SSV
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

Si un attaquant compromet un binaire avec `com.apple.private.apfs.revert-to-snapshot`, il peut **ramener le volume système à un état antérieur à la mise à jour**, restaurant des vulnérabilités connues :
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> La restauration d'un snapshot annule en pratique **les mises à jour de sécurité**, rétablissant des vulnérabilités du kernel et du système déjà corrigées. C'est l'une des opérations les plus dangereuses possibles sur macOS moderne.

#### Remplacement de binaires système

Avec un contournement de SIP et la capacité d'écriture sur SSV, un attaquant peut :

1. Monter le volume système en lecture-écriture
2. Remplacer un daemon système ou une bibliothèque de framework par une version trojanisée
3. Re-sceller le snapshot (ou accepter le sceau rompu si SIP est déjà dégradé)
4. Le rootkit persiste après les redémarrages et est invisible aux outils de détection en espace utilisateur

### CVE réelles

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — contournement de SIP permettant la modification de SSV via `system_installd` |
| CVE-2022-22583 | Contournement de SSV via la gestion des snapshots de PackageKit |
| CVE-2022-46689 | Condition de course permettant des écritures sur des fichiers protégés par SIP |

---

## DataVault

### Informations de base

**DataVault** est la couche de protection d'Apple pour les bases de données système sensibles. Même **root ne peut pas accéder aux fichiers protégés par DataVault** — seuls les processus disposant d'entitlements spécifiques peuvent les lire ou les modifier. Les magasins protégés incluent :

| Base de données protégée | Chemin | Contenu |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Décisions de confidentialité TCC à l'échelle du système |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Décisions de confidentialité TCC par utilisateur |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

La protection DataVault est appliquée au **niveau du système de fichiers** en utilisant des attributs étendus et des flags de protection de volume, vérifiés par le kernel.

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
### Scénarios d'attaque

#### Modification directe de la base de données TCC

Si un attaquant compromet un binaire contrôleur DataVault (par ex., via une injection de code dans un processus avec `com.apple.private.tcc.manager`), il peut **modifier directement la base de données TCC** pour accorder à n'importe quelle application n'importe quelle autorisation TCC :
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modification de la base de données TCC est le contournement ultime de la vie privée — elle accorde silencieusement n'importe quelle permission, sans aucune invite utilisateur ni indicateur visible. Historiquement, plusieurs chaînes d'élévation de privilèges macOS se sont terminées par des écritures dans la base de données TCC comme charge finale.

#### Accès à la base de données du Keychain

DataVault protège également les fichiers sous-jacents du Keychain. Un contrôleur DataVault compromis peut :

1. Lire les fichiers bruts de la base de données du Keychain
2. Extraire les éléments chiffrés du Keychain
3. Tenter un déchiffrement hors ligne en utilisant le mot de passe de l'utilisateur ou des clés récupérées

### CVE réelles impliquant DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | Contournement TCC via un symlink vers un fichier protégé par DataVault |
| CVE-2023-32364 | Contournement du sandbox entraînant la modification de la base de données TCC |
| CVE-2021-30713 | Contournement TCC via le malware XCSSET modifiant TCC.db |
| CVE-2020-9934 | Contournement TCC via manipulation des variables d'environnement |
| CVE-2020-29621 | Contournement TCC de l'application Music atteignant DataVault |

## Références

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
