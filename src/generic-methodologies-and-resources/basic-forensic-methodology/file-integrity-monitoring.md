# File Integrity Monitoring

## Baseline

Ένα baseline συνίσταται στη λήψη ενός snapshot συγκεκριμένων τμημάτων ενός συστήματος, ώστε να **συγκριθεί με μια μελλοντική κατάσταση και να αναδειχθούν οι αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του filesystem, ώστε να εντοπίζετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει για τους λογαριασμούς χρηστών που δημιουργήθηκαν, τις διεργασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο δεν θα έπρεπε να αλλάζει συχνά ή καθόλου.

Ένα **χρήσιμο baseline** συνήθως αποθηκεύει περισσότερα από ένα απλό digest: αξίζει επίσης να παρακολουθούνται τα δικαιώματα, ο owner, το group, τα timestamps, το inode, ο στόχος του symlink, τα ACLs και επιλεγμένα extended attributes.<sup>[[4]](#references)</sup> Από την οπτική του attacker hunting, αυτό βοηθά στον εντοπισμό **παραποίησης μόνο δικαιωμάτων**, **atomic αντικατάστασης αρχείων** και **persistence μέσω τροποποιημένων service/unit files**, ακόμη και όταν το content hash δεν είναι το πρώτο πράγμα που αλλάζει.

### File Integrity Monitoring

Το File Integrity Monitoring (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει τα IT environments και τα δεδομένα, παρακολουθώντας τις αλλαγές στα αρχεία. Συνήθως συνδυάζει:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Σύγκριση baseline:** Αποθήκευση metadata και cryptographic checksums (κατά προτίμηση `SHA-256` ή καλύτερο) για μελλοντικές συγκρίσεις.
2. **Ειδοποιήσεις σε πραγματικό χρόνο:** Εγγραφή σε OS-native file events, ώστε να γνωρίζετε **ποιο αρχείο άλλαξε, πότε και, ιδανικά, ποια διεργασία/χρήστης το άγγιξε**.
3. **Περιοδικό re-scan:** Επαναφορά της αξιοπιστίας μετά από reboots, dropped events, agent outages ή σκόπιμη anti-forensic δραστηριότητα.

Για threat hunting, το FIM είναι συνήθως πιο χρήσιμο όταν εστιάζει σε **paths υψηλής αξίας**, όπως:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers και bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Το collection backend έχει σημασία:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: εύκολα και συνηθισμένα, αλλά τα watch limits μπορεί να εξαντληθούν και ορισμένες edge cases να μην εντοπιστούν.
- **`auditd` / audit framework**: καλύτερη επιλογή όταν χρειάζεται να γνωρίζετε **ποιος άλλαξε το αρχείο** (login UID, process ID και process name).
- **`eBPF` / `kprobes`**: νεότερες επιλογές που χρησιμοποιούνται από σύγχρονα FIM stacks για τον εμπλουτισμό των events και τη μείωση ορισμένων operational προβλημάτων των απλών deployments με `inotify`.

Ορισμένα πρακτικά gotchas:<sup>[[1]](#references)[[5]](#references)</sup>

- Αν ένα πρόγραμμα **αντικαταστήσει** ένα αρχείο με `write temp -> rename`, η παρακολούθηση του ίδιου του αρχείου μπορεί να πάψει να είναι χρήσιμη. **Παρακολουθείτε το parent directory**, όχι μόνο το αρχείο.
- Οι collectors που βασίζονται σε `inotify` μπορεί να χάσουν events ή να υποβαθμιστούν σε **τεράστια directory trees**, σε **hard-link activity** ή αφού **διαγραφεί ένα watched file**.
- Πολύ μεγάλα recursive watch sets μπορεί να αποτύχουν σιωπηλά αν τα `fs.inotify.max_user_watches`, `max_user_instances` ή `max_queued_events` είναι υπερβολικά χαμηλά.
- Για monitoring που βασίζεται σε `inotify`, τα network filesystems αποτελούν blind spot, επειδή οι remote αλλαγές δεν αναφέρονται.

Παράδειγμα baseline + verification με το AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Παράδειγμα διαμόρφωσης FIM του `osquery`, εστιασμένη σε paths persistence επιτιθέμενων:<sup>[[1]](#references)</sup>
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

### Windows

Στα Windows, το FIM είναι ισχυρότερο όταν συνδυάζετε **journals αλλαγών** με **telemetry διεργασιών/αρχείων υψηλής αξιοπιστίας**:<sup>[[6]](#references)[[7]](#references)</sup>

- Το **NTFS USN Journal** παρέχει ένα μόνιμο log ανά volume για τις αλλαγές αρχείων.
- Το **Sysmon Event ID 11** είναι χρήσιμο για τη δημιουργία/αντικατάσταση αρχείων.
- Το **Sysmon Event ID 2** βοηθά στον εντοπισμό **timestomping**.
- Το **Sysmon Event ID 15** είναι χρήσιμο για **named alternate data streams (ADS)**, όπως το `Zone.Identifier` ή κρυφά payload streams.

Γρήγορα παραδείγματα triage με USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Για βαθύτερες anti-forensic ιδέες γύρω από **timestamp manipulation**, **ADS abuse** και **USN tampering**, δείτε [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Το FIM των Containers συχνά παραλείπει την πραγματική διαδρομή εγγραφής. Με το Docker `overlay2`, το filesystem του container συνδυάζει επίπεδα **lowerdir** μόνο για ανάγνωση από το image με ένα εγγράψιμο **upper layer** (`upperdir`/`diff`), και οι εγγραφές σε αρχεία του image αντιγράφονται σε αυτό το upper layer.<sup>[[8]](#references)</sup> Επομένως:

- Η παρακολούθηση μόνο διαδρομών **μέσα** από ένα βραχύβιο container μπορεί να παραλείψει αλλαγές μετά την αναδημιουργία του container.
- Η παρακολούθηση της **host path** που υποστηρίζει το εγγράψιμο layer ή του σχετικού bind-mounted volume είναι συχνά πιο χρήσιμη.
- Το FIM στα image layers διαφέρει από το FIM στο filesystem του container που εκτελείται.

## Σημειώσεις Hunting με προσανατολισμό στον Attacker

- Παρακολουθείτε τους **service definitions** και τους **task schedulers** εξίσου προσεκτικά με τα binaries. Οι Attackers συχνά αποκτούν persistence τροποποιώντας ένα unit file, cron entry ή task XML αντί να κάνουν patch στο `/bin/sshd`.
- Ένα content hash από μόνο του δεν επαρκεί. Πολλά compromises εμφανίζονται αρχικά ως **owner/mode/xattr/ACL drift**.
- Αν υποψιάζεστε μια ώριμη intrusion, κάντε και τα δύο: **real-time FIM** για νέα δραστηριότητα και μια **cold baseline comparison** από trusted media.
- Αν ο attacker έχει root ή kernel execution, θεωρήστε το FIM agent και τη βάση δεδομένων του μη αξιόπιστα. Αποθηκεύετε τα logs και τα baselines απομακρυσμένα ή σε read-only media whenever possible.<sup>[[4]](#references)</sup>

## Εργαλεία

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Παρακολούθηση ακεραιότητας αρχείων με το osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: Μια περίπτωση χρήσης παρακολούθησης ακεραιότητας αρχείων (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Παρακολούθηση ακεραιότητας αρχείων Wazuh (Syscheck και whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Εγχειρίδιο AIDE έκδοση 0.16.2](https://aide.github.io/doc/)
- [5] [Σελίδα εγχειριδίου Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Οδηγός αποθήκευσης OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Προηγμένες ρυθμίσεις Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
