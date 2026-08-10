# File Integrity Monitoring

## Baseline

Una baseline consiste nel creare uno snapshot di determinate parti di un sistema per **confrontarlo con uno stato futuro e mettere in evidenza le modifiche**.

Ad esempio, è possibile calcolare e memorizzare l'hash di ogni file del filesystem per poter scoprire quali file sono stati modificati.\
Questo può essere fatto anche con gli account utente creati, i processi in esecuzione, i servizi attivi e qualsiasi altro elemento che non dovrebbe cambiare molto, o non cambiare affatto.

Una **baseline utile** di solito memorizza più di un semplice digest: vale la pena monitorare anche permessi, proprietario, gruppo, timestamp, inode, destinazione del symlink, ACL e attributi estesi selezionati.<sup>[[4]](#references)</sup> Dal punto di vista della ricerca degli attaccanti, ciò aiuta a rilevare **manomissioni limitate ai permessi**, **sostituzioni atomiche dei file** e **persistence tramite file di servizio/unit modificati**, anche quando l'hash del contenuto non è il primo elemento a cambiare.

### File Integrity Monitoring

File Integrity Monitoring (FIM) è una tecnica di sicurezza critica che protegge gli ambienti IT e i dati monitorando le modifiche ai file. Di solito combina:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Confronto con la baseline:** memorizzare metadati e checksum crittografici (preferibilmente `SHA-256` o superiore) per confronti futuri.
2. **Notifiche in tempo reale:** sottoscriversi agli eventi dei file nativi del sistema operativo per sapere **quale file è cambiato, quando e, idealmente, quale processo/utente lo ha modificato**.
3. **Nuova scansione periodica:** ristabilire l'affidabilità dopo reboot, eventi persi, interruzioni degli agent o attività deliberate di anti-forensics.

Per la threat hunting, FIM è generalmente più utile quando si concentra su **path di alto valore**, come:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unit `systemd`, percorsi di cron, materiale SSH, moduli PAM, web root
- percorsi di persistence di Windows, binari dei servizi, file delle attività pianificate, cartelle di avvio
- writable layer dei container e secret/configuration montati tramite bind mount

## Backend in tempo reale e punti ciechi

### Linux

Il backend di raccolta è importante:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: semplici e comuni, ma i limiti dei watch possono essere esauriti e alcuni casi limite possono non essere rilevati.
- **`auditd` / audit framework**: migliori quando è necessario sapere **chi ha modificato il file** (login UID, ID del processo e nome del processo).
- **`eBPF` / `kprobes`**: opzioni più recenti utilizzate dagli stack FIM moderni per arricchire gli eventi e ridurre alcuni problemi operativi delle implementazioni `inotify` standard.

Alcuni problemi pratici:<sup>[[1]](#references)[[5]](#references)</sup>

- Se un programma **sostituisce** un file con `write temp -> rename`, monitorare direttamente il file potrebbe non essere più utile. **Monitorare la directory padre**, non solo il file.
- I collector basati su `inotify` possono perdere eventi o degradare in presenza di **alberi di directory enormi**, **attività sui hard link** o dopo l'eliminazione di un **file monitorato**.
- Set di watch ricorsivi molto grandi possono fallire silenziosamente se `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` sono troppo bassi.
- Per il monitoraggio basato su `inotify`, i filesystem di rete sono un punto cieco perché le modifiche remote non vengono segnalate.

Esempio di baseline + verifica con AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Esempio di configurazione FIM di `osquery` incentrata sui percorsi di persistenza degli attaccanti:<sup>[[1]](#references)</sup>
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

### Windows

Su Windows, il FIM è più efficace quando combini i **change journal** con la **telemetria ad alto segnale di processi/file**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** fornisce un log persistente delle modifiche ai file per volume.
- **Sysmon Event ID 11** è utile per rilevare la creazione/sovrascrittura di file.
- **Sysmon Event ID 2** aiuta a rilevare il **timestomping**.
- **Sysmon Event ID 15** è utile per gli **alternate data streams (ADS) denominati**, come `Zone.Identifier` o gli stream con payload nascosti.

Esempi rapidi di triage USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Per approfondire le tecniche anti-forensics relative a **timestamp manipulation**, **ADS abuse** e **USN tampering**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Il FIM dei container spesso non rileva il percorso effettivo di scrittura. Con Docker `overlay2`, il filesystem del container combina i layer `lowerdir` di sola lettura dell'immagine con un **upper layer** scrivibile (`upperdir`/`diff`), e le scritture sui file dell'immagine vengono copiate in questo upper layer.<sup>[[8]](#references)</sup> Pertanto:

- Monitorare solo i percorsi **interni** a un container di breve durata può non rilevare le modifiche dopo la ricreazione del container.
- Monitorare il **percorso dell'host** che supporta il layer scrivibile o il volume con montaggio bind pertinente è spesso più utile.
- Il FIM sui layer dell'immagine è diverso dal FIM sul filesystem del container in esecuzione.

## Note di hunting orientate all'attaccante

- Tieni traccia delle **definizioni dei servizi** e degli **scheduler delle attività** con la stessa attenzione dedicata ai binari. Gli attaccanti spesso ottengono la persistenza modificando un file unit, una voce cron o un XML di attività invece di modificare `/bin/sshd`.
- Un semplice hash del contenuto non è sufficiente. Molte compromissioni si manifestano inizialmente come **variazioni di owner/mode/xattr/ACL**.
- Se sospetti un'intrusione avanzata, fai entrambe le cose: **FIM in tempo reale** per le attività recenti e un **confronto con una baseline offline** proveniente da supporti affidabili.
- Se l'attaccante dispone dell'accesso root o dell'esecuzione nel kernel, considera non attendibili l'agente FIM e il relativo database. Archivia i log e le baseline da remoto o su supporti in sola lettura ogni volta che è possibile.<sup>[[4]](#references)</sup>

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
{{#include ../../banners/hacktricks-training.md}}
