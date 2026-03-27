# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Base di riferimento

Una base di riferimento consiste nel prendere uno snapshot di alcune parti di un sistema per **confrontarlo con uno stato futuro per evidenziare le modifiche**.

Ad esempio, puoi calcolare e memorizzare l'hash di ogni file del filesystem per poter scoprire quali file sono stati modificati.\
Questo può essere fatto anche con gli account utente creati, i processi in esecuzione, i servizi attivi e qualsiasi altra cosa che non dovrebbe cambiare molto, o per nulla.

Una **baseline utile** di solito memorizza più di un semplice digest: è utile tracciare anche i permessi, proprietario, gruppo, timestamp, inode, target dei symlink, ACL e alcuni attributi estesi selezionati. Dal punto di vista del threat hunting, questo aiuta a rilevare la **manomissione limitata ai permessi**, la **sostituzione atomica del file** e la **persistenza tramite file di service/unit modificati** anche quando l'hash del contenuto non è la prima cosa che cambia.

### File Integrity Monitoring

File Integrity Monitoring (FIM) è una tecnica di sicurezza critica che protegge gli ambienti IT e i dati tracciando le modifiche nei file. Solitamente combina:

1. **Confronto con la baseline:** Memorizzare metadata e checksum crittografici (preferire `SHA-256` o superiore) per confronti futuri.
2. **Notifiche in tempo reale:** Iscriversi agli eventi file nativi del sistema operativo per sapere **quale file è cambiato, quando, e idealmente quale processo/utente lo ha toccato**.
3. **Scansione periodica:** Ripristinare fiducia dopo reboot, eventi perduti, outage dell'agente o attività anti-forense deliberate.

Per il threat hunting, FIM è generalmente più utile se focalizzato su **percorsi ad alto valore** come:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Backend in tempo reale e punti ciechi

### Linux

Il backend di raccolta è importante:

- **`inotify` / `fsnotify`**: semplice e comune, ma i limiti di watch possono esaurirsi e alcuni casi limite vengono persi.
- **`auditd` / audit framework**: migliore quando hai bisogno di sapere **chi ha modificato il file** (`auid`, processo, pid, eseguibile).
- **`eBPF` / `kprobes`**: opzioni più recenti usate dagli stack FIM moderni per arricchire gli eventi e ridurre parte delle difficoltà operative delle semplici implementazioni basate su `inotify`.

Alcuni aspetti pratici da notare:

- Se un programma **sostituisce** un file con `write temp -> rename`, sorvegliare il file stesso può smettere di essere utile. **Sorveglia la directory padre**, non solo il file.
- I collector basati su `inotify` possono perdere eventi o degradare su **alberi di directory enormi**, **attività di hard-link**, o dopo che un **file sorvegliato è stato eliminato**.
- Set di watch ricorsivi molto grandi possono fallire silenziosamente se `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` sono troppo bassi.
- I filesystem di rete sono di solito cattivi target per FIM quando si vuole un monitoraggio a basso rumore.

Esempio di baseline + verifica con AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Esempio di configurazione FIM di `osquery` focalizzata sui percorsi di persistenza dell'attaccante:
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
Se hai bisogno di **attribuzione del processo** invece che soltanto di modifiche a livello di percorso, preferisci telemetria basata su audit come `osquery` `process_file_events` o la modalità `whodata` di Wazuh.

### Windows

Su Windows, FIM è più efficace quando combini i **change journals** con telemetria di processo/file ad alto segnale:

- **NTFS USN Journal** fornisce un registro persistente per volume delle modifiche ai file.
- **Sysmon Event ID 11** è utile per la creazione/sovrascrittura di file.
- **Sysmon Event ID 2** aiuta a rilevare il **timestomping**.
- **Sysmon Event ID 15** è utile per gli **named alternate data streams (ADS)** come `Zone.Identifier` o stream di payload nascosti.

Esempi rapidi di triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Per idee anti-forensi più approfondite su **timestamp manipulation**, **ADS abuse**, e **USN tampering**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container FIM spesso perde il percorso reale di scrittura. Con Docker `overlay2`, le modifiche vengono commesse nello **writable upper layer** del container (`upperdir`/`diff`), non negli strati immagine di sola lettura. Pertanto:

- Monitorare solo i percorsi dall'interno di un container a vita breve può far perdere modifiche dopo che il container viene ricreato.
- Monitorare il percorso host che supporta il writable layer o il volume bind-mounted rilevante è spesso più utile.
- FIM sugli image layer è diverso dal FIM sul filesystem del container in esecuzione.

## Note di hunting orientate all'attaccante

- Monitora con la stessa cura le definizioni di servizio e gli scheduler di task come faresti con i binari. Gli attaccanti spesso ottengono persistenza modificando un unit file, una voce di cron o un task XML invece di patchare `/bin/sshd`.
- Un hash di contenuto da solo non è sufficiente. Molte compromissioni si manifestano inizialmente come **owner/mode/xattr/ACL drift**.
- Se sospetti un'intrusione matura, fai entrambe le cose: **real-time FIM** per attività recenti e una **cold baseline comparison** da supporti trusted.
- Se l'attaccante ha esecuzione a livello root o kernel, considera che l'agente FIM, il suo database e persino la sorgente dell'evento possono essere manomessi. Conserva log e baseline in remoto o su supporti di sola lettura quando possibile.

## Strumenti

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Riferimenti

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
