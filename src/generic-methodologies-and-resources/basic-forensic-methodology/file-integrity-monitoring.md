# Monitoraggio dell'integrità dei file

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Una baseline consiste nel creare uno snapshot di determinate parti di un sistema per **confrontarlo con uno stato futuro e mettere in evidenza le modifiche**.

Ad esempio, è possibile calcolare e memorizzare l'hash di ogni file del filesystem per scoprire quali file sono stati modificati.\
Questo può essere fatto anche con gli account utente creati, i processi in esecuzione, i servizi in esecuzione e qualsiasi altro elemento che non dovrebbe cambiare molto, o affatto.

Una **baseline utile** di solito memorizza più di un semplice digest: vale la pena monitorare anche permessi, proprietario, gruppo, timestamp, inode, destinazione del symlink, ACL e attributi estesi selezionati. Dal punto di vista della ricerca degli attacker, questo aiuta a rilevare **manomissioni limitate ai permessi**, **sostituzioni atomiche dei file** e **persistence tramite file di servizio/unit modificati**, anche quando l'hash del contenuto non è il primo elemento a cambiare.

### Monitoraggio dell'integrità dei file

Il File Integrity Monitoring (FIM) è una tecnica di sicurezza fondamentale che protegge gli ambienti IT e i dati monitorando le modifiche ai file. Di solito combina:

1. **Confronto con la baseline:** memorizzare metadati e checksum crittografici (preferibilmente `SHA-256` o superiori) per confronti futuri.
2. **Notifiche in tempo reale:** sottoscriversi agli eventi dei file nativi del sistema operativo per sapere **quale file è cambiato, quando e, idealmente, quale processo/utente lo ha modificato**.
3. **Nuova scansione periodica:** ristabilire l'affidabilità dopo reboot, eventi persi, interruzioni dell'agent o attività anti-forensics deliberate.

Per la threat hunting, il FIM è generalmente più utile quando si concentra su **path di alto valore**, come:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unit `systemd`, percorsi cron, materiale SSH, moduli PAM, web root
- percorsi di persistence Windows, binari dei servizi, file delle scheduled task, cartelle di avvio
- layer scrivibili dei container e secret/configuration montati tramite bind

## Backend in tempo reale e punti ciechi

### Linux

Il backend di raccolta è importante:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: semplici e comuni, ma i limiti dei watch possono essere esauriti e alcuni edge case possono non essere rilevati.
- **`auditd` / audit framework**: migliori quando è necessario sapere **chi ha modificato il file** (`auid`, processo, pid, eseguibile).
- **`eBPF` / `kprobes`**: opzioni più recenti utilizzate dagli stack FIM moderni per arricchire gli eventi e ridurre alcuni problemi operativi delle implementazioni `inotify` standard.

Alcuni problemi pratici:<sup>[[1]](#references)</sup>

- Se un programma **sostituisce** un file con `write temp -> rename`, monitorare direttamente il file potrebbe non essere più utile. **Monitorare la directory padre**, non solo il file.
- I collector basati su `inotify` possono perdere eventi o degradare su **alberi di directory enormi**, **attività sui hard link** o dopo l'eliminazione di un **file monitorato**.
- Set di watch ricorsivi molto grandi possono fallire silenziosamente se `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` sono troppo bassi.
- I filesystem di rete sono generalmente obiettivi inadeguati per un FIM a basso rumore.

Esempio di baseline + verifica con AIDE:
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
Se hai bisogno dell'**attribuzione del processo** invece delle sole modifiche a livello di percorso, preferisci la telemetria supportata da audit come `osquery` `process_file_events` o la modalità `whodata` di Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Su Windows, FIM è più efficace quando combini i **journal delle modifiche** con la **telemetria ad alto segnale di processi/file**:

- Il **journal USN di NTFS** fornisce un log persistente delle modifiche ai file per volume.
- **Sysmon Event ID 11** è utile per la creazione/sovrascrittura di file.
- **Sysmon Event ID 2** aiuta a rilevare il **timestomping**.
- **Sysmon Event ID 15** è utile per gli **alternate data streams (ADS) denominati**, come `Zone.Identifier` o flussi di payload nascosti.

Esempi rapidi di triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Per approfondire le idee anti-forensic relative a **timestamp manipulation**, **ADS abuse** e **USN tampering**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contenitori

Il FIM dei container spesso non rileva il reale percorso di scrittura. Con Docker `overlay2`, le modifiche vengono salvate nel **writable upper layer** del container (`upperdir`/`diff`), non nei livelli dell'immagine in sola lettura. Pertanto:

- Monitorare solo i percorsi **all'interno** di un container di breve durata può far perdere le modifiche dopo la ricreazione del container.
- Monitorare il **percorso dell'host** che supporta il writable layer o il volume bind-mounted pertinente è spesso più utile.
- Il FIM sui livelli dell'immagine è diverso dal FIM sul filesystem del container in esecuzione.

## Note di hunting orientate all'attaccante

- Tieni sotto controllo le **definizioni dei servizi** e i **task scheduler** con la stessa attenzione riservata ai binari. Gli attaccanti spesso ottengono la persistenza modificando un unit file, una voce cron o un task XML, invece di modificare `/bin/sshd`.
- Un semplice content hash non è sufficiente. Molti compromessi emergono inizialmente come **owner/mode/xattr/ACL drift**.
- Se sospetti un'intrusione avanzata, esegui entrambe le attività: **FIM in tempo reale** per rilevare attività recenti e un **confronto con una baseline a freddo** utilizzando supporti affidabili.
- Se l'attaccante dispone di accesso root o di esecuzione nel kernel, presumi che l'agente FIM, il relativo database e persino la sorgente degli eventi possano essere manomessi. Archivia log e baseline in remoto o su supporti di sola lettura quando possibile.

## Strumenti

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Riferimenti

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
