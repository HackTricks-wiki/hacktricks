# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Una baseline consiste nel creare uno snapshot di determinate parti di un sistema per **confrontarlo con uno stato futuro e mettere in evidenza le modifiche**.

Ad esempio, è possibile calcolare e memorizzare l'hash di ogni file del filesystem per individuare quali file sono stati modificati.\
Questo può essere fatto anche con gli account utente creati, i processi in esecuzione, i servizi attivi e qualsiasi altro elemento che non dovrebbe cambiare molto, o non dovrebbe cambiare affatto.

Una **baseline utile** di solito memorizza più di un semplice digest: vale la pena monitorare anche permessi, proprietario, gruppo, timestamp, inode, destinazione del symlink, ACL e attributi estesi selezionati.<sup>[[4]](#references)</sup> Dal punto di vista della ricerca degli attacker, questo aiuta a rilevare **manomissioni che modificano solo i permessi**, **sostituzioni atomiche dei file** e **persistence tramite file di servizio/unit modificati**, anche quando l'hash del contenuto non è il primo elemento a cambiare.

### File Integrity Monitoring

File Integrity Monitoring (FIM) è una tecnica di sicurezza fondamentale che protegge gli ambienti IT e i dati monitorando le modifiche ai file. Di solito combina:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Confronto con la baseline:** memorizzare metadati e checksum crittografici (preferibilmente `SHA-256` o migliori) per i confronti futuri.
2. **Notifiche in tempo reale:** sottoscriversi agli eventi dei file nativi del sistema operativo per sapere **quale file è cambiato, quando e, idealmente, quale processo/utente lo ha modificato**.
3. **Nuova scansione periodica:** ristabilire l'affidabilità dopo riavvii, eventi persi, interruzioni degli agent o attività anti-forensic deliberate.

Per la threat hunting, FIM è generalmente più utile quando si concentra su **percorsi di alto valore**, come:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unit `systemd`, percorsi di cron, materiale SSH, moduli PAM, web root
- percorsi di persistence di Windows, binari dei servizi, file delle attività pianificate, cartelle di avvio
- layer scrivibili dei container e secret/configuration montati tramite bind

## Real-Time Backends & Blind Spots

### Linux

Il backend di raccolta è importante:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: semplici e comuni, ma i limiti dei watch possono essere esauriti e alcuni edge case possono non essere rilevati.
- **`auditd` / audit framework**: migliori quando è necessario sapere **chi ha modificato il file** (login UID, process ID e nome del processo).
- **`eBPF` / `kprobes`**: opzioni più recenti utilizzate dagli stack FIM moderni per arricchire gli eventi e ridurre alcuni problemi operativi delle implementazioni basate sul solo `inotify`.

Alcuni problemi pratici:<sup>[[1]](#references)[[5]](#references)</sup>

- Se un programma **sostituisce** un file con `write temp -> rename`, monitorare il file stesso potrebbe non essere più utile. **Monitorare la directory padre**, non solo il file.
- I collector basati su `inotify` possono perdere eventi o degradare su **alberi di directory enormi**, **attività sui hard-link** o dopo l'eliminazione di un **file monitorato**.
- Set di watch ricorsivi molto grandi possono fallire senza segnalazioni se `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` sono troppo bassi.
- Per il monitoraggio basato su `inotify`, i filesystem di rete rappresentano un blind spot perché le modifiche remote non vengono segnalate.

Esempio di baseline + verifica con AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Esempio di configurazione FIM di `osquery` focalizzata sui percorsi di persistenza degli attaccanti:<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Se hai bisogno dell'**attribuzione del processo** invece delle sole modifiche a livello di percorso, preferisci la telemetria supportata dagli audit, come `osquery` `process_file_events` o la modalità `whodata` di Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: la telemetria delle syscall non è FIM

Sui Linux moderni, monitorare `openat(2)`, `write(2)` o altri punti di ingresso delle syscall **non equivale a monitorare l'operazione risultante sul filesystem**. Il proof of concept **Curing** del 2025 accodava richieste relative a file e rete tramite `io_uring`, pertanto i prodotti o le policy collegati esclusivamente alle corrispondenti syscall per singola operazione perdevano la telemetria del processo. Negli stessi test, un componente FIM con ambito limitato al percorso rilevava comunque le modifiche ai file, dimostrando che si tratta di un **punto cieco nella posizione degli hook**, non di un bypass delle autorizzazioni né di un metodo per eludere ogni backend FIM.<sup>[[10]](#references)</sup>

Durante la validazione di un sensore, modifica lo stesso canary attraverso diversi percorsi: `write` normale, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, sostituzione atomica e `io_uring`. Verifica non solo che venga rilevata la variazione dell'hash finale, ma anche se l'evento conserva il processo responsabile, il container/cgroup, il percorso visibile dal namespace, l'inode e la coppia di rename. Un evento real-time mancante seguito da una discrepanza rilevata dalla scansione periodica deve essere trattato come **perdita di telemetria**, non come una normale modifica priva di spiegazione.<sup>[[10]](#references)[[11]](#references)</sup>

Per il monitoraggio basato su eBPF, preferisci punti di enforcement comuni del kernel invece di un elenco di probe all'ingresso delle syscall. Ad esempio, la policy di accesso ai file di Tetragon utilizza `security_file_permission` per coprire l'I/O ordinario, `sendfile`, `copy_file_range`, AIO e `io_uring`; copre separatamente i memory mapping con `security_mmap_file` e le modifiche alle dimensioni con `security_path_truncate`. Questo illustra inoltre perché un singolo hook raramente garantisce una copertura completa.<sup>[[11]](#references)</sup>

### Windows

Su Windows, il FIM è più efficace quando si combinano i **change journal** con la **telemetria ad alto segnale di processi/file**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** fornisce un log persistente per volume delle modifiche ai file.
- **Sysmon Event ID 11** è utile per la creazione/sovrascrittura dei file.
- **Sysmon Event ID 2** aiuta a rilevare il **timestomping**.
- **Sysmon Event ID 15** è utile per gli **alternate data streams (ADS) denominati**, come `Zone.Identifier` o gli stream payload nascosti.

Esempi rapidi di triage USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Per approfondire le idee di anti-forensics relative alla **manipolazione dei timestamp**, all'**abuso degli ADS** e al **tampering degli USN**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Il FIM dei container spesso non rileva il reale percorso di scrittura. Con Docker `overlay2`, il filesystem del container combina i layer `lowerdir` di sola lettura dell'immagine con un **upper layer** scrivibile (`upperdir`/`diff`), e le scritture sui file dell'immagine vengono copiate in questo upper layer.<sup>[[8]](#references)</sup> Pertanto:

- Monitorare solo i percorsi **interni** a un container di breve durata può far perdere le modifiche dopo la ricreazione del container.
- Monitorare il **percorso sull'host** che supporta il layer scrivibile o il volume bind-mounted pertinente è spesso più utile.
- Il FIM sui layer dell'immagine è diverso dal FIM sul filesystem del container in esecuzione.

## Note di hunting orientate all'attaccante

- Tieni traccia delle **definizioni dei servizi** e degli **scheduler delle attività** con la stessa attenzione riservata ai binari. Gli attaccanti spesso ottengono la persistenza modificando un unit file, una voce cron o un task XML invece di fare patch a `/bin/sshd`.
- Un semplice content hash non è sufficiente. Molti compromessi si manifestano inizialmente come **variazioni di owner/mode/xattr/ACL**.
- Se sospetti un'intrusione avanzata, fai entrambe le cose: **FIM in tempo reale** per le attività recenti e un **confronto con una baseline offline** da supporti affidabili.
- Se l'attaccante dispone di root o di esecuzione a livello kernel, considera l'agente FIM e il relativo database non affidabili. Archivia log e baseline da remoto o su supporti di sola lettura ogni volta che è possibile.<sup>[[4]](#references)</sup>

## Strumenti

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitoraggio dell'integrità dei file con osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: un caso d'uso del monitoraggio dell'integrità dei file (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitoraggio dell'integrità dei file Wazuh (modalità Syscheck e whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manuale di AIDE versione 0.16.2](https://aide.github.io/doc/)
- [5] [Pagina del manuale Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Driver di storage OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Impostazioni avanzate Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Rootkit io_uring: bypass degli strumenti di sicurezza Linux (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Accesso ai nomi file: percorsi sincroni, asincroni, mappati e di troncamento (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
