# Monitoraggio dell'integrità dei file

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Una baseline consiste nel creare uno snapshot di determinate parti di un sistema per **confrontarlo con uno stato futuro e mettere in evidenza le modifiche**.

Ad esempio, è possibile calcolare e memorizzare l'hash di ogni file del filesystem per individuare quali file sono stati modificati.\
Lo stesso può essere fatto con gli account utente creati, i processi in esecuzione, i servizi attivi e qualsiasi altro elemento che non dovrebbe cambiare molto, o affatto.

Una **baseline utile** generalmente memorizza più di un semplice digest: vale la pena monitorare anche permessi, proprietario, gruppo, timestamp, inode, destinazione del symlink, ACL e attributi estesi selezionati. Dal punto di vista della ricerca degli attaccanti, questo aiuta a rilevare **manomissioni che modificano solo i permessi**, **sostituzioni atomiche dei file** e **persistenza tramite file di servizio/unit modificati**, anche quando l'hash del contenuto non è il primo elemento a cambiare.

### Monitoraggio dell'integrità dei file

Il File Integrity Monitoring (FIM) è una tecnica di sicurezza fondamentale che protegge gli ambienti IT e i dati monitorando le modifiche ai file. Di solito combina:

1. **Confronto con la baseline:** memorizzare metadati e checksum crittografici (preferibilmente `SHA-256` o superiore) per i confronti futuri.
2. **Notifiche in tempo reale:** sottoscriversi agli eventi sui file nativi del sistema operativo per sapere **quale file è cambiato, quando e, idealmente, quale processo/utente lo ha modificato**.
3. **Nuova scansione periodica:** ristabilire l'affidabilità dopo riavvii, eventi persi, interruzioni degli agent o attività deliberate di anti-forensics.

Per la threat hunting, il FIM è generalmente più utile se concentrato su **path di alto valore**, come:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unit `systemd`, percorsi dei cron, materiale SSH, moduli PAM, web root
- percorsi di persistenza Windows, binari dei servizi, file delle attività pianificate, cartelle di avvio
- layer scrivibili dei container e secret/configurazioni montati tramite bind

## Backend in tempo reale e punti ciechi

### Linux

Il backend di raccolta è importante:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: semplici e comuni, ma i limiti dei watch possono essere esauriti e alcuni casi limite non vengono rilevati.
- **`auditd` / audit framework**: migliori quando è necessario sapere **chi ha modificato il file** (`auid`, processo, pid, eseguibile).
- **`eBPF` / `kprobes`**: opzioni più recenti utilizzate dagli stack FIM moderni per arricchire gli eventi e ridurre alcuni problemi operativi delle implementazioni `inotify` standard.

Alcune problematiche pratiche:<sup>[[1]](#references)</sup>

- Se un programma **sostituisce** un file con `write temp -> rename`, monitorare direttamente il file potrebbe non essere più utile. **Monitorare la directory padre**, non solo il file.
- I collector basati su `inotify` possono perdere eventi o degradare su **alberi di directory enormi**, **attività sui hard link** o dopo l'**eliminazione di un file monitorato**.
- Set di watch ricorsivi molto grandi possono fallire silenziosamente se `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` sono troppo bassi.
- I filesystem di rete sono generalmente obiettivi inadeguati per un FIM a bassa rumorosità.

Esempio di baseline + verifica con AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Esempio di configurazione FIM di `osquery` incentrato sui percorsi di persistenza dell'attaccante:<sup>[[1]](#references)</sup>
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
Se hai bisogno dell'**attribuzione del processo** invece di rilevare solo le modifiche a livello di percorso, preferisci la telemetria supportata da audit come `osquery` `process_file_events` o la modalità `whodata` di Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Su Windows, la FIM è più efficace quando combini i **journal delle modifiche** con la **telemetria ad alto segnale di processi/file**:

- Il **journal USN di NTFS** fornisce un log persistente per volume delle modifiche ai file.
- **Sysmon Event ID 11** è utile per rilevare la creazione/sovrascrittura di file.
- **Sysmon Event ID 2** aiuta a rilevare il **timestomping**.
- **Sysmon Event ID 15** è utile per gli **alternate data streams (ADS) denominati**, come `Zone.Identifier` o gli stream con payload nascosto.

Esempi rapidi di triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Per approfondire le idee anti-forensic relative a **timestamp manipulation**, **ADS abuse** e **USN tampering**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contenitori

Il FIM dei contenitori spesso non rileva il percorso reale di scrittura. Con Docker `overlay2`, le modifiche vengono salvate nel **livello superiore scrivibile** del contenitore (`upperdir`/`diff`), non nei livelli di sola lettura dell'immagine. Pertanto:

- Monitorare solo i percorsi **all'interno** di un contenitore di breve durata può non rilevare le modifiche dopo la ricreazione del contenitore.
- Monitorare il **percorso sull'host** che supporta il livello scrivibile o il volume rilevante montato tramite bind è spesso più utile.
- Il FIM sui livelli dell'immagine è diverso dal FIM sul filesystem del contenitore in esecuzione.

## Note di hunting orientate all'attaccante

- Tieni traccia delle **definizioni dei servizi** e degli **scheduler delle attività** con la stessa attenzione riservata ai binari. Gli attaccanti spesso ottengono la persistenza modificando un file unit, una voce cron o un XML di attività invece di applicare patch a `/bin/sshd`.
- Un semplice hash del contenuto non è sufficiente. Molte compromissioni si manifestano inizialmente come **deriva di owner/mode/xattr/ACL**.
- Se sospetti un'intrusione avanzata, fai entrambe le cose: **FIM in tempo reale** per le attività recenti e un **confronto a freddo con una baseline** ottenuta da supporti affidabili.
- Se l'attaccante dispone dell'accesso root o dell'esecuzione nel kernel, considera compromessi l'agente FIM, il relativo database e persino la sorgente degli eventi. Archivia i log e le baseline da remoto o su supporti di sola lettura ogni volta che è possibile.

## Strumenti

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Riferimenti

- [1] [File Integrity Monitoring con osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: un caso d'uso di file integrity monitoring (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (modalità Syscheck e whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
