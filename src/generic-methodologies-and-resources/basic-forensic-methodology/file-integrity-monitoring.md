# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Ένα baseline αποτελείται από τη λήψη ενός snapshot συγκεκριμένων τμημάτων ενός συστήματος, ώστε να **συγκριθεί με μια μελλοντική κατάσταση για την ανάδειξη αλλαγών**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του filesystem, ώστε να μπορείτε να εντοπίσετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει με τους λογαριασμούς χρηστών που δημιουργήθηκαν, τις διεργασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο δεν θα έπρεπε να αλλάζει σημαντικά ή καθόλου.

Ένα **χρήσιμο baseline** συνήθως αποθηκεύει περισσότερα από ένα απλό digest: αξίζει επίσης να παρακολουθούνται τα permissions, ο owner, το group, τα timestamps, το inode, ο στόχος του symlink, τα ACLs και επιλεγμένα extended attributes.<sup>[[4]](#references)</sup> Από την οπτική του attacker-hunting, αυτό βοηθά στον εντοπισμό **tampering που αφορά μόνο permissions**, **atomic file replacement** και **persistence μέσω τροποποιημένων service/unit files**, ακόμη και όταν το content hash δεν είναι το πρώτο πράγμα που αλλάζει.

### File Integrity Monitoring

Το File Integrity Monitoring (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει IT περιβάλλοντα και δεδομένα παρακολουθώντας αλλαγές σε αρχεία. Συνήθως συνδυάζει:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Σύγκριση baseline:** Αποθήκευση metadata και cryptographic checksums (κατά προτίμηση `SHA-256` ή καλύτερο) για μελλοντικές συγκρίσεις.
2. **Ειδοποιήσεις σε πραγματικό χρόνο:** Εγγραφή σε OS-native file events, ώστε να γνωρίζετε **ποιο αρχείο άλλαξε, πότε και, ιδανικά, ποια διεργασία/χρήστης το άγγιξε**.
3. **Περιοδικό re-scan:** Επαναφορά της αξιοπιστίας μετά από reboots, dropped events, agent outages ή σκόπιμη anti-forensic δραστηριότητα.

Για threat hunting, το FIM είναι συνήθως πιο χρήσιμο όταν επικεντρώνεται σε **paths υψηλής αξίας**, όπως:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Μονάδες `systemd`, τοποθεσίες cron, υλικό SSH, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Writable layers containers και bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Το backend συλλογής έχει σημασία:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: εύκολα και συνηθισμένα, αλλά τα watch limits μπορούν να εξαντληθούν και ορισμένα edge cases να παραλειφθούν.
- **`auditd` / audit framework**: καλύτερο όταν χρειάζεστε να γνωρίζετε **ποιος άλλαξε το αρχείο** (login UID, process ID και process name).
- **`eBPF` / `kprobes`**: νεότερες επιλογές που χρησιμοποιούνται από σύγχρονα FIM stacks για τον εμπλουτισμό των events και τη μείωση ορισμένων operational προβλημάτων των απλών deployments με `inotify`.

Ορισμένες πρακτικές παγίδες:<sup>[[1]](#references)[[5]](#references)</sup>

- Αν ένα πρόγραμμα **αντικαταστήσει** ένα αρχείο με `write temp -> rename`, η παρακολούθηση του ίδιου του αρχείου μπορεί να πάψει να είναι χρήσιμη. **Παρακολουθείτε το parent directory**, όχι μόνο το αρχείο.
- Οι collectors που βασίζονται σε `inotify` μπορεί να χάσουν events ή να υποβαθμιστούν σε **τεράστια directory trees**, σε **hard-link activity** ή αφού **διαγραφεί ένα watched file**.
- Πολύ μεγάλα recursive watch sets μπορεί να αποτύχουν σιωπηλά, αν τα `fs.inotify.max_user_watches`, `max_user_instances` ή `max_queued_events` είναι υπερβολικά χαμηλά.
- Για monitoring που βασίζεται σε `inotify`, τα network filesystems αποτελούν blind spot, επειδή οι απομακρυσμένες αλλαγές δεν αναφέρονται.

Παράδειγμα baseline + verification με AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Παράδειγμα διαμόρφωσης `osquery` για FIM, εστιασμένο σε paths persistence επιτιθέμενων:<sup>[[1]](#references)</sup>
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
Αν χρειάζεστε **απόδοση διεργασίας** αντί μόνο για αλλαγές σε επίπεδο διαδρομής, προτιμήστε telemetry που υποστηρίζεται από audit, όπως το `osquery` `process_file_events` ή τη λειτουργία `whodata` του Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: το syscall telemetry δεν είναι FIM

Σε σύγχρονα Linux, η παρακολούθηση των `openat(2)`, `write(2)` ή άλλων entry points των syscalls **δεν ισοδυναμεί με την παρακολούθηση της αντίστοιχης λειτουργίας στο filesystem**. Το proof of concept **Curing** του 2025 τοποθέτησε αιτήματα αρχείων και δικτύου σε queue μέσω του `io_uring`, με αποτέλεσμα προϊόντα ή policies που ήταν συνδεδεμένα μόνο με τα αντίστοιχα per-operation syscall entries να χάνουν το telemetry της διεργασίας. Στις ίδιες δοκιμές, ένα path-scoped στοιχείο FIM εξακολούθησε να εντοπίζει τροποποιήσεις αρχείων, δείχνοντας ότι πρόκειται για **τυφλό σημείο στην τοποθέτηση των hooks**, όχι για παράκαμψη δικαιωμάτων ή για τρόπο εξουδετέρωσης κάθε FIM backend.<sup>[[10]](#references)</sup>

Κατά την επικύρωση ενός sensor, τροποποιήστε το ίδιο canary με διάφορους τρόπους: κανονικό `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomic replacement και `io_uring`. Ελέγξτε όχι μόνο αν εντοπίζεται η τελική απόκλιση του hash, αλλά και αν το event διατηρεί τη responsible process, το container/cgroup, τη διαδρομή όπως είναι ορατή στο namespace, το inode και το ζεύγος rename. Ένα real-time event που λείπει και ακολουθείται από mismatch σε periodic scan πρέπει να αντιμετωπίζεται ως **απώλεια telemetry**, όχι ως μια συνηθισμένη ανεξήγητη αλλαγή.<sup>[[10]](#references)[[11]](#references)</sup>

Για monitoring βασισμένο σε eBPF, προτιμήστε κοινά kernel enforcement points αντί για μια λίστα από syscall-entry probes. Για παράδειγμα, το file-access policy του Tetragon χρησιμοποιεί το `security_file_permission` για να καλύψει ordinary I/O, `sendfile`, `copy_file_range`, AIO και `io_uring`. Καλύπτει ξεχωριστά τα memory mappings μέσω του `security_mmap_file` και τις αλλαγές μεγέθους μέσω του `security_path_truncate`. Αυτό δείχνει επίσης γιατί ένα μόνο hook σπάνια παρέχει πλήρη κάλυψη.<sup>[[11]](#references)</sup>

### Windows

Στα Windows, το FIM είναι ισχυρότερο όταν συνδυάζετε **change journals** με **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- Το **NTFS USN Journal** παρέχει ένα persistent per-volume log των αλλαγών αρχείων.
- Το **Sysmon Event ID 11** είναι χρήσιμο για τη δημιουργία/αντικατάσταση αρχείων.
- Το **Sysmon Event ID 2** βοηθά στον εντοπισμό του **timestomping**.
- Το **Sysmon Event ID 15** είναι χρήσιμο για **named alternate data streams (ADS)**, όπως το `Zone.Identifier` ή κρυφά payload streams.

Γρήγορα παραδείγματα USN triage:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Για βαθύτερες anti-forensic ιδέες γύρω από **timestamp manipulation**, **ADS abuse** και **USN tampering**, δείτε το [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Το Container FIM συχνά παραλείπει την πραγματική διαδρομή εγγραφής. Με το Docker `overlay2`, το filesystem του container συνδυάζει επίπεδα εικόνας μόνο για ανάγνωση `lowerdir` με ένα εγγράψιμο **upper layer** (`upperdir`/`diff`), και οι εγγραφές σε αρχεία της εικόνας αντιγράφονται σε αυτό το upper layer.<sup>[[8]](#references)</sup> Επομένως:

- Η παρακολούθηση μόνο διαδρομών **μέσα** από ένα βραχύβιο container μπορεί να παραλείψει αλλαγές μετά την αναδημιουργία του container.
- Η παρακολούθηση της **διαδρομής στον host** που υποστηρίζει το εγγράψιμο layer ή του σχετικού bind-mounted volume είναι συχνά πιο χρήσιμη.
- Το FIM στα image layers διαφέρει από το FIM στο filesystem του εκτελούμενου container.

## Σημειώσεις Hunting με επίκεντρο τον Attacker

- Παρακολουθείτε τους **service definitions** και τους **task schedulers** εξίσου προσεκτικά με τα binaries. Οι Attackers συχνά εξασφαλίζουν persistence τροποποιώντας ένα unit file, μια cron entry ή ένα task XML, αντί να τροποποιούν το `/bin/sshd`.
- Ένα content hash από μόνο του δεν επαρκεί. Πολλά compromises εμφανίζονται αρχικά ως **owner/mode/xattr/ACL drift**.
- Αν υποψιάζεστε μια ώριμη intrusion, κάντε και τα δύο: **real-time FIM** για πρόσφατη δραστηριότητα και μια **cold baseline comparison** από trusted media.
- Αν ο attacker έχει root ή kernel execution, θεωρήστε το FIM agent και τη βάση δεδομένων του untrusted. Αποθηκεύετε τα logs και τα baselines απομακρυσμένα ή σε read-only media όποτε είναι δυνατό.<sup>[[4]](#references)</sup>

## Εργαλεία

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Παρακολούθηση ακεραιότητας αρχείων με το osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: Μια περίπτωση χρήσης για την παρακολούθηση ακεραιότητας αρχείων (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Παρακολούθηση ακεραιότητας αρχείων Wazuh (Syscheck και whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Εγχειρίδιο AIDE Έκδοση 0.16.2](https://aide.github.io/doc/)
- [5] [Σελίδα εγχειριδίου Linux για το inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Driver αποθήκευσης OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Προηγμένες ρυθμίσεις Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Το io_uring Rootkit παρακάμπτει τα Linux Security Tools (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Πρόσβαση σε filenames: κάλυψη synchronous, asynchronous, mapped και truncation paths (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
