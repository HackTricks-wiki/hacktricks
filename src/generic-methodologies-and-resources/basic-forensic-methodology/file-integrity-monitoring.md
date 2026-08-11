# Παρακολούθηση ακεραιότητας αρχείων

{{#include ../../banners/hacktricks-training.md}}

## Βασική γραμμή

Μια βασική γραμμή αποτελείται από τη λήψη ενός στιγμιότυπου συγκεκριμένων τμημάτων ενός συστήματος, ώστε να **συγκριθεί με μια μελλοντική κατάσταση και να επισημανθούν οι αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του filesystem, ώστε να εντοπίσετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει για τους λογαριασμούς χρηστών που δημιουργήθηκαν, τις διεργασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο δεν θα έπρεπε να αλλάζει σημαντικά ή καθόλου.

Μια **χρήσιμη βασική γραμμή** συνήθως αποθηκεύει περισσότερα από ένα απλό digest: αξίζει επίσης να παρακολουθούνται τα δικαιώματα, ο ιδιοκτήτης, η ομάδα, οι χρονικές σημάνσεις, το inode, ο στόχος του symlink, τα ACLs και επιλεγμένα extended attributes.<sup>[[4]](#references)</sup> Από την οπτική του attacker-hunting, αυτό βοηθά στον εντοπισμό **παραποίησης μόνο δικαιωμάτων**, **atomic αντικατάστασης αρχείων** και **persistence μέσω τροποποιημένων αρχείων service/unit**, ακόμη και όταν το hash περιεχομένου δεν είναι το πρώτο στοιχείο που αλλάζει.

### Παρακολούθηση ακεραιότητας αρχείων

Το File Integrity Monitoring (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει τα IT περιβάλλοντα και τα δεδομένα, παρακολουθώντας τις αλλαγές στα αρχεία. Συνήθως συνδυάζει:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Σύγκριση με τη βασική γραμμή:** Αποθήκευση metadata και cryptographic checksums (κατά προτίμηση `SHA-256` ή καλύτερου) για μελλοντικές συγκρίσεις.
2. **Ειδοποιήσεις σε πραγματικό χρόνο:** Εγγραφή σε native file events του OS, ώστε να γνωρίζετε **ποιο αρχείο άλλαξε, πότε και, ιδανικά, ποια διεργασία/χρήστης το προσπέλασε**.
3. **Περιοδικός επανέλεγχος:** Επαναφορά της αξιοπιστίας μετά από reboot, dropped events, διακοπές λειτουργίας agent ή σκόπιμη anti-forensic δραστηριότητα.

Για threat hunting, το FIM είναι συνήθως πιο χρήσιμο όταν επικεντρώνεται σε **διαδρομές υψηλής αξίας**, όπως:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, τοποθεσίες cron, υλικό SSH, modules PAM, web roots
- Τοποθεσίες persistence των Windows, binaries υπηρεσιών, αρχεία scheduled tasks, φάκελοι startup
- Writable layers containers και bind-mounted secrets/configuration

## Backends πραγματικού χρόνου και τυφλά σημεία

### Linux

Το backend συλλογής έχει σημασία:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: εύκολα και συνηθισμένα, αλλά τα όρια των watches μπορεί να εξαντληθούν και ορισμένες edge cases να μην εντοπιστούν.
- **`auditd` / audit framework**: καλύτερο όταν χρειάζεστε να γνωρίζετε **ποιος άλλαξε το αρχείο** (login UID, process ID και process name).
- **`eBPF` / `kprobes`**: νεότερες επιλογές που χρησιμοποιούνται από σύγχρονα FIM stacks για εμπλουτισμό των events και μείωση ορισμένων λειτουργικών προβλημάτων των απλών deployments με `inotify`.

Ορισμένα πρακτικά προβλήματα:<sup>[[1]](#references)[[5]](#references)</sup>

- Αν ένα πρόγραμμα **αντικαταστήσει** ένα αρχείο με `write temp -> rename`, η παρακολούθηση του ίδιου του αρχείου μπορεί να πάψει να είναι χρήσιμη. **Παρακολουθείτε τον γονικό κατάλογο**, όχι μόνο το αρχείο.
- Οι collectors που βασίζονται στο `inotify` μπορεί να χάσουν events ή να υποβαθμίσουν την απόδοσή τους σε **τεράστια directory trees**, σε **δραστηριότητα hard links** ή μετά τη **διαγραφή ενός watched αρχείου**.
- Πολύ μεγάλα recursive watch sets μπορεί να αποτύχουν σιωπηλά αν τα `fs.inotify.max_user_watches`, `max_user_instances` ή `max_queued_events` είναι πολύ χαμηλά.
- Για monitoring που βασίζεται στο `inotify`, τα network filesystems αποτελούν τυφλό σημείο, επειδή οι απομακρυσμένες αλλαγές δεν αναφέρονται.

Παράδειγμα baseline και verification με το AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Παράδειγμα διαμόρφωσης FIM του `osquery` με εστίαση σε paths persistence attackers:<sup>[[1]](#references)</sup>
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
Αν χρειάζεστε **απόδοση διεργασίας** αντί μόνο για αλλαγές σε επίπεδο διαδρομής, προτιμήστε telemetry υποστηριζόμενο από audit, όπως το `osquery` `process_file_events` ή τη λειτουργία `whodata` του Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Στα Windows, το FIM είναι ισχυρότερο όταν συνδυάζετε **change journals** με **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- Το **NTFS USN Journal** παρέχει ένα μόνιμο αρχείο καταγραφής ανά τόμο για τις αλλαγές αρχείων.
- Το **Sysmon Event ID 11** είναι χρήσιμο για τη δημιουργία/αντικατάσταση αρχείων.
- Το **Sysmon Event ID 2** βοηθά στον εντοπισμό **timestomping**.
- Το **Sysmon Event ID 15** είναι χρήσιμο για **named alternate data streams (ADS)**, όπως το `Zone.Identifier` ή κρυφά payload streams.

Γρήγορα παραδείγματα triage με USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Για βαθύτερες anti-forensic ιδέες σχετικά με **timestamp manipulation**, **ADS abuse** και **USN tampering**, ανατρέξτε στο [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Το FIM των Containers συχνά δεν εντοπίζει την πραγματική διαδρομή εγγραφής. Με το Docker `overlay2`, το filesystem του Container συνδυάζει επίπεδα image μόνο για ανάγνωση `lowerdir` με ένα εγγράψιμο **upper layer** (`upperdir`/`diff`), και οι εγγραφές σε αρχεία του image αντιγράφονται σε αυτό το upper layer.<sup>[[8]](#references)</sup> Επομένως:

- Η παρακολούθηση μόνο διαδρομών **μέσα** από ένα βραχύβιο Container μπορεί να μην εντοπίσει αλλαγές μετά την αναδημιουργία του Container.
- Η παρακολούθηση της **διαδρομής στον host** που υποστηρίζει το εγγράψιμο layer ή του σχετικού bind-mounted volume είναι συχνά πιο χρήσιμη.
- Το FIM στα image layers διαφέρει από το FIM στο filesystem του Container που εκτελείται.

## Σημειώσεις Hunting με προσανατολισμό στον επιτιθέμενο

- Παρακολουθείτε τους **ορισμούς υπηρεσιών** και τους **task schedulers** τόσο προσεκτικά όσο και τα binaries. Οι επιτιθέμενοι συχνά επιτυγχάνουν persistence τροποποιώντας ένα unit file, μια καταχώριση cron ή ένα task XML αντί να τροποποιήσουν το `/bin/sshd`.
- Ένα content hash από μόνο του δεν επαρκεί. Πολλές παραβιάσεις εμφανίζονται αρχικά ως **απόκλιση owner/mode/xattr/ACL**.
- Αν υποψιάζεστε μια ώριμη εισβολή, κάντε και τα δύο: **real-time FIM** για νέα δραστηριότητα και μια **cold baseline comparison** από αξιόπιστο μέσο.
- Αν ο επιτιθέμενος έχει root ή kernel execution, θεωρήστε το FIM agent και τη βάση δεδομένων του μη αξιόπιστα. Αποθηκεύετε τα logs και τα baselines απομακρυσμένα ή σε μέσα μόνο για ανάγνωση, όποτε είναι δυνατόν.<sup>[[4]](#references)</sup>

## Εργαλεία

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Παρακολούθηση ακεραιότητας αρχείων με osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Ιχνηλάτηση του Linux: Περίπτωση χρήσης για παρακολούθηση ακεραιότητας αρχείων (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Παρακολούθηση ακεραιότητας αρχείων Wazuh (Syscheck και λειτουργία whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Εγχειρίδιο AIDE, έκδοση 0.16.2](https://aide.github.io/doc/)
- [5] [Σελίδα εγχειριδίου Linux για το inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Οδηγός αποθήκευσης OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Προηγμένες ρυθμίσεις Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
