# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informazioni di base

A partire da **macOS Big Sur (11.0)**, il volume di sistema viene sigillato crittograficamente utilizzando un **albero hash di snapshot APFS**. Questo viene chiamato **Sealed System Volume (SSV)**. La partizione di sistema viene montata in **sola lettura** e qualsiasi modifica rompe il sigillo, che viene verificato durante l'avvio.<sup>[[11]](#references)</sup>

L'SSV fornisce:
- **Rilevamento delle manomissioni** — qualsiasi modifica ai binari o ai framework di sistema cambia la radice dell'albero Merkle e invalida il sigillo firmato da Apple
- **Autenticazione durante l'avvio** — la catena di avvio verifica lo snapshot di sistema selezionato prima che diventi il filesystem root
- **Resistenza ai rootkit** — persino root non può sostituire permanentemente i file nello snapshot di sistema autenticato senza disabilitare authenticated root o compromettere un percorso di aggiornamento autorizzato

L'SSV protegge il volume **System**, non il volume scrivibile **Data** abbinato a esso. I Firmlink uniscono entrambi i volumi nello spazio dei nomi visibile in `/`, quindi un percorso apparentemente scrivibile non dimostra che l'oggetto sottostante appartenga allo snapshot sigillato. FileVault e Data Protection garantiscono la riservatezza dei dati inattivi; sono separati dall'integrità dell'SSV.<sup>[[11]](#references)</sup>

### Verifica dello stato dell'SSV
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
### Vista effettiva del sistema: SSV + graft dei Cryptex

Nelle versioni recenti di macOS, non tutti gli eseguibili visibili sotto `/System` provengono necessariamente dallo snapshot SSV avviato. I **Cryptexes** sono immagini disco APFS autenticate separatamente, il cui contenuto viene sovrapposto a directory selezionate; le Rapid Security Responses possono quindi sostituire componenti sensibili per la sicurezza senza ricostruire l'SSV di base. Durante il triage della persistence o il diff del codice di sistema, inventaria i mount attivi e il Cryptex store di Preboot invece di calcolare gli hash solo dello snapshot di base:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
I dettagli della boot-chain e della Rapid Security Response sono descritti in [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); questa sezione si concentra sul boundary dello SSV.

### Entitlements dei writer SSV

Alcuni binari di sistema Apple dispongono di entitlements che consentono loro di modificare o gestire il sealed system volume:

| Entitlement | Scopo |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Riportare il system volume a uno snapshot precedente |
| `com.apple.private.apfs.create-sealed-snapshot` | Creare un nuovo sealed snapshot dopo gli aggiornamenti di sistema |
| `com.apple.rootless.install.heritable` | Scrivere nei percorsi protetti da SIP (ereditato dai processi figli) |
| `com.apple.rootless.install` | Scrivere nei percorsi protetti da SIP |

### Individuazione degli SSV writer
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

#### Attacco di rollback dello snapshot

Se un attaccante compromette un binario con `com.apple.private.apfs.revert-to-snapshot`, può **riportare il volume di sistema a uno stato precedente all'aggiornamento**, ripristinando vulnerabilità note:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Il rollback dello snapshot **annulla di fatto gli aggiornamenti di sicurezza**, ripristinando le vulnerabilità precedentemente corrette del kernel e del sistema. Questa è una delle operazioni più pericolose possibili sulle versioni moderne di macOS.

#### Sostituzione dei binari di sistema

Con il bypass di SIP + la capacità di scrittura su SSV, un attacker può:

1. Montare il volume di sistema in lettura-scrittura
2. Sostituire un daemon di sistema o una libreria framework con una versione trojanizzata
3. Risigillare lo snapshot (oppure accettare il sigillo non valido se SIP è già degradato)
4. Il rootkit persiste tra i riavvii ed è invisibile agli strumenti di rilevamento in userland

### CVE reali

| CVE | Descrizione |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass di SIP che sfrutta l'entitlement `com.apple.rootless.install.heritable` di `system_installd` per eseguire script post-install arbitrari ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass di SIP: `system_installd` memorizzava lo script post-install in una cartella protetta da SIP sotto `/tmp`, ma `/tmp` non è protetta da SIP, quindi la cartella poteva essere sostituita montandovi sopra un'immagine ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write in XNU che consente scritture su file di proprietà di root e in sola lettura ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informazioni di base

**DataVault** è una protezione del filesystem basata sugli entitlement per file e directory sensibili. Il flag BSD `UF_DATAVAULT` (`0x00000080`) indica un oggetto che richiede un entitlement sia per la lettura sia per la scrittura; a differenza del normale DAC, diventare semplicemente **root** o ottenere Full Disk Access non soddisfa questo controllo mentre la protezione è attiva.<sup>[[4]](#references)[[13]](#references)</sup>

Non usare “DataVault” come sinonimo di ogni database protetto. I database TCC sono regolati da TCC/FDA e da policy specifiche di SIP (vedi [macOS TCC](macos-tcc/README.md)), mentre l'accesso agli elementi del keychain dipende anche dalle ACL del Keychain e dalla protezione crittografica (vedi [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Esempi reali di DataVault si trovano comunemente in archivi di proprietà dei servizi sotto `/private/var/folders/.../0/`, come l'archivio Screen Time; il flag è visibile come `datavault` nei flag dei file BSD quando è possibile eseguire `stat` sul parent.

### Entitlement dei controller DataVault

| Entitlement | Confine |
|---|---|
| `com.apple.rootless.datavault.controller` | Accedere e gestire gli oggetti `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gestire le decisioni TCC; questo è un confine di privacy correlato ma separato |
| `com.apple.private.tcc.allow` | Bypassare i servizi TCC selezionati indicati nel valore dell'entitlement |
| `com.apple.rootless.storage.TCC` | Scrivere nell'archivio TCC protetto da SIP |

Un processo che combina un entitlement del controller DataVault con funzionalità FDA, di backup, indicizzazione o IPC è particolarmente interessante: cerca una primitive di confused deputy che copi un oggetto protetto in un percorso ordinario, invece di provare ad aprire direttamente il vault.<sup>[[14]](#references)</sup>

### Individuazione dei controller DataVault
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
### Scenari di attacco

#### Modifica diretta del database TCC (confine TCC separato)

Se un attacker compromette un processo del gestore TCC (ad esempio tramite code injection in un processo che dispone di `com.apple.private.tcc.manager`), può **modificare direttamente il database TCC** per concedere a qualsiasi applicazione qualsiasi autorizzazione TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modifica del database TCC è il **bypass definitivo della privacy**: concede qualsiasi autorizzazione in modo silenzioso, senza alcuna richiesta all'utente o indicatore visibile. Storicamente, diverse catene di privilege escalation su macOS si sono concluse con scritture nel database TCC come payload finale.

#### Accesso al database del Keychain

L'accesso raw a un database di supporto di un keychain non equivale all'accesso ai secret in plaintext. Se un altro confine di privilegio consente a un attacker di copiare il database, è comunque necessario attaccare il key material e le ACL degli item; consulta invece la pagina dedicata al [macOS Keychain](../../macos-red-teaming/macos-keychain.md), senza presumere che un entitlement DataVault-controller sia sufficiente.

#### Confine della copia di backup: Time Machine

Un'analisi del 2026 ha dimostrato un pattern generale utile: `backupd` dispone sia di `com.apple.rootless.datavault.controller` sia di Full Disk Access, quindi può copiare gli store protetti. Nella configurazione testata, `/private/var/folders` era incluso in Time Machine e la copia di backup montata non applicava il confine DataVault live. Il ricercatore ha usato questo metodo per individuare lo store SQLite di Screen Time e leggere il PIN delle restrizioni in plaintext senza aprire il vault live. Consideralo un **attacco al confine della copia**: enumera i deputy di backup, export, migrazione, indicizzazione e diagnostica che possono materializzare i dati del vault sotto un mount o un path più permissivo.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Questo comportamento dipende dalla versione e dalla struttura del backup. Convalidalo sulla build target e ricorda che una destinazione Time Machine crittografata protegge la copia solo mentre è bloccata; una volta montata, i relativi controlli di accesso diventano parte della attack surface.

### CVE reali che coinvolgono DataVault/TCC Bypass

| CVE | Descrizione |
|---|---|
| CVE-2024-44131 | FileProvider symlink race che permette a un helper privilegiato di raggiungere dati protetti da TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Come root, **creare un nuovo utente il cui `NFSHomeDirectory` punti a un `TCC.db` controllato dall'attaccante**; al login `tccd` lo utilizza e i grant vengono applicati, consentendo di raggiungere i dati di altri utenti ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": modificare la home directory dell'utente per inserire un TCC.db controllato dall'attaccante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Difetto nella conclusione del bundle che permette a un'app di **ereditare i grant TCC di un donor bundle** senza prompt; sfruttato in the wild da **XCSSET** per acquisire screenshot del desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` costruiva il percorso del DB a partire da `$HOME`, quindi `launchctl setenv HOME` lo reindirizzava a un `TCC.db` controllato dall'attaccante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` possedeva `com.apple.private.tcc.manager` **e** disabilitava la library validation, quindi un plug-in HAL inserito in `/Library/Audio/Plug-Ins/HAL` poteva concedere diritti TCC arbitrari ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft individua una nuova vulnerabilità di macOS, Shrootless, che potrebbe bypassare System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analisi tecnica: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vale la pena farlo male](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Protezione dei dati](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass sottrae dati da iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Scoprire il malware di macOS: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [La nuova vulnerabilità di macOS, "powerdir", potrebbe consentire l'accesso non autorizzato ai dati degli utenti](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass scoperto nel malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing il framework Transparency, Consent, and Control (TCC) di macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Riprodurre musica e bypassare TCC, ovvero CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [L'incubo degli aggiornamenti OTA di Apple (snapshot APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Sfruttamento di TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Come bypassare il proprio passcode di Screen Time — analisi del codice sorgente e di Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
