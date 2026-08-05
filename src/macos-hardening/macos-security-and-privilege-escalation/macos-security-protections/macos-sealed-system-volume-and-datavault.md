# Sealed System Volume e DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informazioni di base

A partire da **macOS Big Sur (11.0)**, il volume di sistema è protetto crittograficamente tramite un **hash tree di snapshot APFS**. Questo è chiamato **Sealed System Volume (SSV)**. La partizione di sistema è montata in modalità **sola lettura** e qualsiasi modifica invalida il seal, verificato durante l'avvio.

L'SSV fornisce:
- **Rilevamento delle manomissioni** — qualsiasi modifica ai binari o ai framework di sistema è rilevabile tramite la rottura del seal crittografico
- **Protezione dal rollback** — il processo di avvio verifica l'integrità dello snapshot di sistema
- **Prevenzione dei rootkit** — persino root non può modificare in modo persistente i file sul volume di sistema (senza rompere il seal)

### Verifica dello stato dell'SSV
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
### Entitlement dei writer SSV

Alcuni binari di sistema Apple dispongono di entitlement che consentono loro di modificare o gestire il sealed system volume:

| Entitlement | Scopo |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Ripristinare il system volume a uno snapshot precedente |
| `com.apple.private.apfs.create-sealed-snapshot` | Creare un nuovo sealed snapshot dopo gli aggiornamenti di sistema |
| `com.apple.rootless.install.heritable` | Scrivere nei percorsi protetti da SIP (ereditato dai processi figli) |
| `com.apple.rootless.install` | Scrivere nei percorsi protetti da SIP |

### Individuazione dei writer SSV
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
### Attack Scenarios

#### Snapshot Rollback Attack

Se un attaccante compromette un binary con `com.apple.private.apfs.revert-to-snapshot`, può **ripristinare il volume di sistema a uno stato precedente all'aggiornamento**, riattivando vulnerabilità note:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Il rollback dello snapshot **annulla di fatto gli aggiornamenti di sicurezza**, ripristinando vulnerabilità del kernel e del sistema precedentemente corrette. Questa è una delle operazioni più pericolose possibili sulle versioni moderne di macOS.

#### Sostituzione dei binari di sistema

Con un bypass di SIP + la capacità di scrittura su SSV, un attacker può:

1. Montare il volume di sistema in modalità read-write
2. Sostituire un daemon di sistema o una libreria framework con una versione trojanizzata
3. Ri-sigillare lo snapshot (oppure accettare il seal non valido se SIP è già degradato)
4. Il rootkit persiste attraverso i riavvii ed è invisibile agli strumenti di rilevamento in userland

### CVE reali

| CVE | Descrizione |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass di SIP che sfrutta l'entitlement `com.apple.rootless.install.heritable` di `system_installd` per eseguire script post-installazione arbitrari ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Bypass di SIP: `system_installd` posizionava lo script post-installazione in una cartella protetta da SIP sotto `/tmp`, ma `/tmp` non è protetto da SIP, quindi la cartella poteva essere sostituita montandovi sopra un'immagine ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write in XNU che consente scritture su file root-owned di sola lettura ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Informazioni di base

**DataVault** è il livello di protezione di Apple per i database di sistema sensibili. Anche **root non può accedere ai file protetti da DataVault** — solo i processi con entitlement specifici possono leggerli o modificarli.<sup>[[1]](#references)</sup> Gli archivi protetti includono:

| Database protetto | Percorso | Contenuto |
|---|---|---|
| TCC (sistema) | `/Library/Application Support/com.apple.TCC/TCC.db` | Decisioni sulla privacy TCC a livello di sistema |
| TCC (utente) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decisioni sulla privacy TCC per singolo utente |
| Keychain (sistema) | `/Library/Keychains/System.keychain` | Keychain di sistema |
| Keychain (utente) | `~/Library/Keychains/login.keychain-db` | Keychain dell'utente |

La protezione DataVault viene applicata a **livello del filesystem** utilizzando extended attributes e flag di protezione del volume, verificati dal kernel.

### Entitlement del controller DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Individuazione dei controller DataVault
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

Se un attaccante compromette un binario controller DataVault (ad esempio tramite code injection in un processo con `com.apple.private.tcc.manager`), può **modificare direttamente il database TCC** per concedere a qualsiasi applicazione qualsiasi autorizzazione TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modifica del database TCC è il **bypass definitivo della privacy**: concede silenziosamente qualsiasi permesso, senza alcuna richiesta all'utente o indicatore visibile. Storicamente, diverse privilege escalation chain su macOS si sono concluse con scritture nel database TCC come payload finale.

#### Accesso al database Keychain

DataVault protegge anche i file di supporto del keychain. Un controller DataVault compromesso può:

1. Leggere i file raw del database keychain
2. Estrarre gli elementi crittografati del keychain
3. Tentare la decrittazione offline usando la password dell'utente o le chiavi recuperate

### CVE reali che coinvolgono DataVault/TCC Bypass

| CVE | Descrizione |
|---|---|
| CVE-2024-44131 | Symlink race in FileProvider che consente a un helper privilegiato di raggiungere dati protetti da TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Come root, **creare un nuovo utente il cui `NFSHomeDirectory` punti a un `TCC.db` controllato dall'attaccante**; al login `tccd` lo utilizza e i grant vengono applicati, consentendo di raggiungere i dati di altri utenti ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": modificare la home directory dell'utente per installare un TCC.db controllato dall'attaccante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Difetto nella conclusione del bundle che consente a un'app di **ereditare i grant TCC di un bundle donatore** senza una richiesta; sfruttato in the wild da **XCSSET** per acquisire screenshot del desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` costruiva il percorso del DB a partire da `$HOME`, quindi `launchctl setenv HOME` lo reindirizzava a un `TCC.db` controllato dall'attaccante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` possedeva `com.apple.private.tcc.manager` **e** aveva disabilitato la library validation, quindi un plug-in HAL inserito in `/Library/Audio/Plug-Ins/HAL` poteva concedere diritti TCC arbitrari ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Riferimenti

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
