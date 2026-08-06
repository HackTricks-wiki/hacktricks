# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Ένα baseline αποτελείται από τη λήψη ενός snapshot συγκεκριμένων τμημάτων ενός συστήματος, ώστε να **συγκριθεί με μια μελλοντική κατάσταση και να αναδειχθούν οι αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του filesystem, ώστε να μπορείτε να εντοπίσετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει για τους λογαριασμούς χρηστών που δημιουργήθηκαν, τις διεργασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο δεν θα έπρεπε να αλλάζει σημαντικά ή καθόλου.

Ένα **χρήσιμο baseline** συνήθως αποθηκεύει περισσότερα από ένα απλό digest: αξίζει επίσης να παρακολουθούνται τα permissions, ο owner, το group, τα timestamps, το inode, ο στόχος του symlink, τα ACLs και επιλεγμένα extended attributes. Από την οπτική του attacker-hunting, αυτό βοηθά στον εντοπισμό **παραποίησης μόνο των permissions**, **atomic file replacement** και **persistence μέσω τροποποιημένων service/unit files**, ακόμη και όταν το content hash δεν είναι το πρώτο στοιχείο που αλλάζει.

### File Integrity Monitoring

Το File Integrity Monitoring (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει IT περιβάλλοντα και δεδομένα, παρακολουθώντας τις αλλαγές σε αρχεία. Συνήθως συνδυάζει:

1. **Σύγκριση με baseline:** Αποθήκευση metadata και cryptographic checksums (κατά προτίμηση `SHA-256` ή καλύτερο) για μελλοντικές συγκρίσεις.
2. **Ειδοποιήσεις σε πραγματικό χρόνο:** Εγγραφή σε OS-native file events, ώστε να γνωρίζετε **ποιο αρχείο άλλαξε, πότε και, ιδανικά, ποια διεργασία/χρήστης το τροποποίησε**.
3. **Περιοδικό re-scan:** Επανα建立ση εμπιστοσύνης μετά από reboot, dropped events, διακοπές λειτουργίας του agent ή σκόπιμη anti-forensic activity.

Για threat hunting, το FIM είναι συνήθως πιο χρήσιμο όταν επικεντρώνεται σε **paths υψηλής αξίας**, όπως:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers και bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Το collection backend έχει σημασία:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: εύκολα και συνηθισμένα, αλλά τα watch limits μπορεί να εξαντληθούν και ορισμένα edge cases να μην εντοπιστούν.
- **`auditd` / audit framework**: καλύτερο όταν χρειάζεστε να γνωρίζετε **ποιος άλλαξε το αρχείο** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: νεότερες επιλογές που χρησιμοποιούνται από σύγχρονα FIM stacks, για εμπλουτισμό των events και μείωση ορισμένων operational προβλημάτων των απλών deployments με `inotify`.

Ορισμένα πρακτικά gotchas:<sup>[[1]](#references)</sup>

- Αν ένα πρόγραμμα **αντικαταστήσει** ένα αρχείο με `write temp -> rename`, η παρακολούθηση του ίδιου του αρχείου μπορεί να πάψει να είναι χρήσιμη. **Παρακολουθείτε το parent directory**, όχι μόνο το αρχείο.
- Collectors που βασίζονται στο `inotify` μπορεί να αποτύχουν ή να υποβαθμιστούν σε **τεράστια directory trees**, σε **hard-link activity** ή μετά τη **διαγραφή ενός watched file**.
- Πολύ μεγάλα recursive watch sets μπορεί να αποτύχουν σιωπηλά, αν τα `fs.inotify.max_user_watches`, `max_user_instances` ή `max_queued_events` είναι πολύ χαμηλά.
- Τα network filesystems είναι συνήθως κακοί στόχοι FIM για monitoring με χαμηλό θόρυβο.

Παράδειγμα baseline + verification με το AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Παράδειγμα διαμόρφωσης FIM του `osquery` με εστίαση σε paths persistence των attackers:<sup>[[1]](#references)</sup>
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
Αν χρειάζεστε **απόδοση διεργασιών** αντί μόνο για αλλαγές σε επίπεδο διαδρομής, προτιμήστε telemetry που υποστηρίζεται από audit, όπως το `osquery` `process_file_events` ή τη λειτουργία `whodata` του Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Στα Windows, το FIM είναι ισχυρότερο όταν συνδυάζετε **change journals** με **τηλεμετρία διεργασιών/αρχείων υψηλής αξίας**:

- Το **NTFS USN Journal** παρέχει ένα μόνιμο αρχείο καταγραφής αλλαγών αρχείων ανά τόμο.
- Το **Sysmon Event ID 11** είναι χρήσιμο για τη δημιουργία/αντικατάσταση αρχείων.
- Το **Sysmon Event ID 2** βοηθά στον εντοπισμό του **timestomping**.
- Το **Sysmon Event ID 15** είναι χρήσιμο για **named alternate data streams (ADS)**, όπως το `Zone.Identifier` ή κρυφά payload streams.

Γρήγορα παραδείγματα triage με USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Για βαθύτερες ιδέες anti-forensic σχετικά με **timestamp manipulation**, **ADS abuse** και **USN tampering**, ανατρέξτε στο [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Το Container FIM συχνά δεν εντοπίζει την πραγματική διαδρομή εγγραφής. Με το Docker `overlay2`, οι αλλαγές καταγράφονται στο **writable upper layer** του container (`upperdir`/`diff`), όχι στα read-only image layers. Επομένως:

- Η παρακολούθηση μόνο των paths **μέσα** σε ένα βραχύβιο container ενδέχεται να μην εντοπίσει αλλαγές μετά την αναδημιουργία του container.
- Η παρακολούθηση του **host path** που υποστηρίζει το writable layer ή του σχετικού bind-mounted volume είναι συχνά πιο χρήσιμη.
- Το FIM στα image layers διαφέρει από το FIM στο filesystem του running container.

## Attacker-Oriented Hunting Notes

- Παρακολουθείτε τους **service definitions** και τους **task schedulers** με την ίδια προσοχή όπως τα binaries. Οι attackers συχνά επιτυγχάνουν persistence τροποποιώντας ένα unit file, μια cron entry ή ένα task XML, αντί να τροποποιούν το `/bin/sshd`.
- Ένα content hash από μόνο του δεν επαρκεί. Πολλά compromises εμφανίζονται αρχικά ως **owner/mode/xattr/ACL drift**.
- Αν υποψιάζεστε μια ώριμη intrusion, κάντε και τα δύο: **real-time FIM** για πρόσφατη δραστηριότητα και μια **cold baseline comparison** από trusted media.
- Αν ο attacker έχει root ή kernel execution, θεωρήστε ότι ο FIM agent, η database του, ακόμη και η πηγή των events μπορεί να έχουν τροποποιηθεί. Αποθηκεύετε τα logs και τα baselines απομακρυσμένα ή σε read-only media whenever possible.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
