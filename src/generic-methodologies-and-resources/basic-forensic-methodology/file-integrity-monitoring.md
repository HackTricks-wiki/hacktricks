# Παρακολούθηση ακεραιότητας αρχείων

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Ένα baseline αποτελείται από τη λήψη ενός στιγμιότυπου συγκεκριμένων τμημάτων ενός συστήματος, ώστε να **συγκριθεί με μια μελλοντική κατάσταση και να επισημανθούν οι αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του filesystem, ώστε να μπορείτε να εντοπίσετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει με τους λογαριασμούς χρηστών που δημιουργήθηκαν, τις διεργασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο δεν θα έπρεπε να αλλάζει σημαντικά ή καθόλου.

Ένα **χρήσιμο baseline** συνήθως αποθηκεύει περισσότερα από ένα απλό digest: τα permissions, τον owner, το group, τα timestamps, το inode, τον στόχο του symlink, τα ACLs και επιλεγμένα extended attributes αξίζει επίσης να παρακολουθούνται. Από την οπτική του hunting επιτιθέμενων, αυτό βοηθά στον εντοπισμό **παραποίησης μόνο των permissions**, **atomic αντικατάστασης αρχείων** και **persistence μέσω τροποποιημένων αρχείων service/unit**, ακόμη και όταν το hash του περιεχομένου δεν είναι το πρώτο στοιχείο που αλλάζει.

### Παρακολούθηση ακεραιότητας αρχείων

Το File Integrity Monitoring (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει τα IT environments και τα δεδομένα παρακολουθώντας τις αλλαγές σε αρχεία. Συνήθως συνδυάζει:

1. **Σύγκριση με baseline:** Αποθήκευση metadata και cryptographic checksums (προτιμήστε `SHA-256` ή καλύτερο) για μελλοντικές συγκρίσεις.
2. **Ειδοποιήσεις σε πραγματικό χρόνο:** Εγγραφή σε OS-native file events, ώστε να γνωρίζετε **ποιο αρχείο άλλαξε, πότε και, ιδανικά, ποια διεργασία/χρήστης το προσπέλασε**.
3. **Περιοδικό re-scan:** Επαναδημιουργία της αξιοπιστίας μετά από reboot, χαμένα events, διακοπές λειτουργίας agent ή σκόπιμη anti-forensic δραστηριότητα.

Για threat hunting, το FIM είναι συνήθως πιο χρήσιμο όταν επικεντρώνεται σε **διαδρομές υψηλής αξίας**, όπως:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Μονάδες `systemd`, τοποθεσίες cron, υλικό SSH, PAM modules, web roots
- Τοποθεσίες persistence στα Windows, binaries υπηρεσιών, αρχεία scheduled tasks, startup folders
- Writable layers containers και bind-mounted secrets/configuration

## Backends πραγματικού χρόνου και τυφλά σημεία

### Linux

Το collection backend έχει σημασία:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: εύκολα και συνηθισμένα, αλλά τα όρια παρακολούθησης μπορούν να εξαντληθούν και ορισμένες edge cases να μην εντοπιστούν.
- **`auditd` / audit framework**: καλύτερο όταν χρειάζεστε να γνωρίζετε **ποιος άλλαξε το αρχείο** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: νεότερες επιλογές που χρησιμοποιούνται από σύγχρονα FIM stacks για εμπλουτισμό των events και μείωση ορισμένων λειτουργικών προβλημάτων των απλών deployments με `inotify`.

Ορισμένες πρακτικές παγίδες:<sup>[[1]](#references)</sup>

- Αν ένα πρόγραμμα **αντικαταστήσει** ένα αρχείο με `write temp -> rename`, η παρακολούθηση του ίδιου του αρχείου μπορεί να πάψει να είναι χρήσιμη. **Παρακολουθείτε τον γονικό κατάλογο**, όχι μόνο το αρχείο.
- Οι collectors που βασίζονται στο `inotify` μπορεί να χάσουν events ή να υποβαθμιστούν σε **τεράστια directory trees**, σε **δραστηριότητα hard links** ή μετά τη **διαγραφή ενός παρακολουθούμενου αρχείου**.
- Πολύ μεγάλα recursive watch sets μπορεί να αποτύχουν σιωπηρά αν τα `fs.inotify.max_user_watches`, `max_user_instances` ή `max_queued_events` είναι πολύ χαμηλά.
- Τα network filesystems είναι συνήθως κακοί στόχοι FIM για monitoring με χαμηλό θόρυβο.

Παράδειγμα baseline και verification με AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Παράδειγμα διαμόρφωσης `osquery` FIM με έμφαση σε διαδρομές persistence των attackers:<sup>[[1]](#references)</sup>
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
Αν χρειάζεστε **process attribution** αντί μόνο για αλλαγές σε επίπεδο διαδρομής, προτιμήστε telemetry με υποστήριξη `audit`, όπως `osquery` `process_file_events` ή τη λειτουργία `whodata` του Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Στα Windows, το FIM είναι ισχυρότερο όταν συνδυάζετε **change journals** με **high-signal process/file telemetry**:

- Το **NTFS USN Journal** παρέχει ένα persistent per-volume log των αλλαγών αρχείων.
- Το **Sysmon Event ID 11** είναι χρήσιμο για δημιουργία/αντικατάσταση αρχείων.
- Το **Sysmon Event ID 2** βοηθά στον εντοπισμό **timestomping**.
- Το **Sysmon Event ID 15** είναι χρήσιμο για **named alternate data streams (ADS)**, όπως το `Zone.Identifier` ή hidden payload streams.

Παραδείγματα γρήγορου USN triage:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Για βαθύτερες anti-forensic ιδέες γύρω από το **timestamp manipulation**, το **ADS abuse** και το **USN tampering**, δείτε το [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Το Container FIM συχνά δεν εντοπίζει το πραγματικό write path. Με το Docker `overlay2`, οι αλλαγές καταγράφονται στο **writable upper layer** (`upperdir`/`diff`) του container και όχι στα read-only image layers. Επομένως:

- Η παρακολούθηση μόνο των paths **μέσα** σε ένα short-lived container μπορεί να μην εντοπίσει αλλαγές μετά την αναδημιουργία του container.
- Η παρακολούθηση του **host path** που υποστηρίζει το writable layer ή του σχετικού bind-mounted volume είναι συχνά πιο χρήσιμη.
- Το FIM στα image layers διαφέρει από το FIM στο filesystem του running container.

## Σημειώσεις Hunting με Προσανατολισμό στον Attacker

- Παρακολουθείτε τα **service definitions** και τους **task schedulers** με την ίδια προσοχή όπως τα binaries. Οι Attackers συχνά επιτυγχάνουν persistence τροποποιώντας ένα unit file, μια cron entry ή ένα task XML, αντί να κάνουν patch το `/bin/sshd`.
- Ένα content hash από μόνο του δεν επαρκεί. Πολλά compromises εμφανίζονται αρχικά ως **owner/mode/xattr/ACL drift**.
- Αν υποψιάζεστε mature intrusion, κάντε και τα δύο: **real-time FIM** για fresh activity και μια **cold baseline comparison** από trusted media.
- Αν ο attacker έχει root ή kernel execution, θεωρήστε ότι ο FIM agent, η database του, ακόμη και το event source μπορούν να παραποιηθούν. Αποθηκεύετε τα logs και τα baselines remotely ή σε read-only media όποτε είναι δυνατό.

## Εργαλεία

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Αναφορές

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
