# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basic Information

A partire da **macOS Big Sur (11.0)**, il volume di sistema è sigillato crittograficamente usando un **APFS snapshot hash tree**. Questo è chiamato il **Sealed System Volume (SSV)**. La partizione di sistema viene montata **in sola lettura** e qualsiasi modifica rompe il sigillo, che viene verificato durante l'avvio.

L'SSV fornisce:
- **Rilevamento manomissioni** — qualsiasi modifica ai binari/framework di sistema è rilevabile tramite il sigillo crittografico compromesso
- **Protezione da rollback** — il processo di avvio verifica l'integrità dello snapshot di sistema
- **Prevenzione dei rootkit** — anche root non può modificare in modo persistente i file sul volume di sistema (senza rompere il sigillo)

### Verifica dello stato SSV
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
### Entitlements per SSV Writers

Alcuni binari di sistema Apple possiedono entitlements che consentono loro di modificare o gestire il sealed system volume:

| Entitlement | Scopo |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Ripristinare il volume di sistema a uno snapshot precedente |
| `com.apple.private.apfs.create-sealed-snapshot` | Creare un nuovo snapshot sigillato dopo gli aggiornamenti di sistema |
| `com.apple.rootless.install.heritable` | Scrivere nei percorsi protetti da SIP (ereditato dai processi figli) |
| `com.apple.rootless.install` | Scrivere nei percorsi protetti da SIP |

### Individuare SSV Writers
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
### Scenari di attacco

#### Snapshot Rollback Attack

Se un attacker compromette un binary con `com.apple.private.apfs.revert-to-snapshot`, può **ripristinare il volume di sistema a uno stato precedente all'aggiornamento**, ripristinando vulnerabilità note:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Il ripristino di uno snapshot effettivamente **annulla gli aggiornamenti di sicurezza**, ripristinando vulnerabilità del kernel e del sistema già corrette. Questa è una delle operazioni più pericolose possibili su macOS moderno.

#### Sostituzione di binari di sistema

Con SIP bypass + SSV write capability, un attaccante può:

1. Montare il volume di sistema in lettura-scrittura
2. Sostituire un daemon di sistema o una libreria di framework con una versione trojanizzata
3. Ri-sigillare lo snapshot (o accettare il sigillo rotto se SIP è già degradato)
4. Il rootkit persiste attraverso i reboot ed è invisibile agli strumenti di rilevamento in userland

### CVE reali

| CVE | Descrizione |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass che permette la modifica di SSV tramite `system_installd` |
| CVE-2022-22583 | SSV bypass attraverso la gestione degli snapshot di PackageKit |
| CVE-2022-46689 | Condizione di race che permette scritture su file protetti da SIP |

---

## DataVault

### Informazioni di base

**DataVault** è il livello di protezione di Apple per i database di sistema sensibili. Anche **root non può accedere ai file protetti da DataVault** — solo processi con specifici entitlements possono leggerli o modificarli. Gli archivi protetti includono:

| Database protetto | Percorso | Contenuto |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Decisioni TCC sulla privacy a livello di sistema |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decisioni TCC sulla privacy per utente |
| Keychain (system) | `/Library/Keychains/System.keychain` | Keychain di sistema |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Keychain dell'utente |

La protezione DataVault è applicata a livello di **filesystem** usando extended attributes e volume protection flags, verificata dal kernel.

### Entitlements del DataVault Controller
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Trovare i controller di DataVault
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
### Scenari di attacco

#### Modifica diretta del database TCC

Se un attaccante compromette un DataVault controller binary (ad es., via code injection in un processo con `com.apple.private.tcc.manager`), può **modificare direttamente il database TCC** per concedere a qualsiasi applicazione qualsiasi permesso TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modifica del database TCC è la **massima violazione della privacy** — concede qualsiasi permesso silenziosamente, senza alcuna richiesta all'utente o indicatore visibile. Storicamente, multiple macOS privilege escalation chains si sono concluse con scritture nel database TCC come payload finale.

#### Accesso al database del Keychain

DataVault protegge anche i file di backing del keychain. Un controller DataVault compromesso può:

1. Leggere i file raw del database del keychain
2. Estrarre elementi del keychain cifrati
3. Tentare la decrittazione offline usando la password dell'utente o chiavi recuperate

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## Riferimenti

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
