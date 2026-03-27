# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Βάση αναφοράς

Μια baseline συνίσταται στην λήψη ενός snapshot συγκεκριμένων τμημάτων ενός συστήματος για να το **συγκρίνετε με μια μελλοντική κατάσταση ώστε να αναδείξετε αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του filesystem για να μπορείτε να βρείτε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει με τους χρήστες που έχουν δημιουργηθεί, τις διεργασίες που τρέχουν, τις υπηρεσίες που τρέχουν και οποιοδήποτε άλλο στοιχείο που δεν θα έπρεπε να αλλάζει πολύ, ή καθόλου.

Μια **χρήσιμη baseline** συνήθως αποθηκεύει περισσότερα από έναν απλό digest: δικαιώματα, κάτοχο, ομάδα, timestamps, inode, symlink target, ACLs, και επιλεγμένα extended attributes αξίζουν επίσης παρακολούθησης. Από την σκοπιά του threat hunting, αυτό βοηθά στον εντοπισμό **tampering μόνο στα δικαιώματα**, **ατομικής αντικατάστασης αρχείων (atomic file replacement)**, και **persistence μέσω τροποποιημένων service/unit files** ακόμη και όταν το content hash δεν είναι το πρώτο που αλλάζει.

### File Integrity Monitoring

File Integrity Monitoring (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει IT περιβάλλοντα και δεδομένα παρακολουθώντας αλλαγές σε αρχεία. Συνήθως συνδυάζει:

1. **Baseline comparison:** Αποθήκευση metadata και κρυπτογραφικών checksums (προτιμήστε `SHA-256` ή καλύτερο) για μελλοντικές συγκρίσεις.
2. **Real-time notifications:** Subscribe σε OS-native file events για να γνωρίζετε **ποιο αρχείο άλλαξε, πότε, και ιδανικά ποια διεργασία/ποιος χρήστης το άγγιξε**.
3. **Periodic re-scan:** Επανακατασκευή εμπιστοσύνης μετά από reboots, dropped events, agent outages, ή σκόπιμη anti-forensic δραστηριότητα.

Για threat hunting, το FIM είναι συνήθως πιο χρήσιμο όταν εστιάζει σε **υψηλής αξίας διαδρομές** όπως:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Το backend συλλογής έχει σημασία:

- **`inotify` / `fsnotify`**: εύκολο και κοινό, αλλά τα όρια των watch μπορούν να εξαντληθούν και μερικές edge περιπτώσεις χάνουν.
- **`auditd` / audit framework**: καλύτερο όταν χρειάζεστε **ποιος άλλαξε το αρχείο** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: νεότερες επιλογές που χρησιμοποιούνται από σύγχρονα FIM stacks για να εμπλουτίζουν τα events και να μειώσουν κάποιο από το λειτουργικό πόνο των απλών `inotify` deployments.

Μερικά πρακτικά προβλήματα:

- Αν ένα πρόγραμμα **αντικαθιστά** ένα αρχείο με `write temp -> rename`, η παρακολούθηση του ίδιου του αρχείου μπορεί να σταματήσει να είναι χρήσιμη. **Παρακολουθήστε τον γονικό κατάλογο**, όχι μόνο το αρχείο.
- `inotify`-based collectors μπορούν να χάσουν ή να υποβαθμιστούν σε **τεράστια δέντρα καταλόγων**, **δραστηριότητα με hard-link**, ή μετά από ένα **διαγραμμένο watched αρχείο**.
- Πολύ μεγάλα recursive watch sets μπορούν να αποτύχουν σιωπηλά αν τα `fs.inotify.max_user_watches`, `max_user_instances`, ή `max_queued_events` είναι πολύ χαμηλά.
- Network filesystems είναι συνήθως κακοί στόχοι για FIM όταν θέλετε low-noise monitoring.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Παράδειγμα διαμόρφωσης FIM του `osquery` που επικεντρώνεται σε attacker persistence paths:
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
If you need **process attribution** instead of only path-level changes, prefer audit-backed telemetry such as `osquery` `process_file_events` or Wazuh `whodata` mode.

### Windows

Στα Windows, το FIM είναι πιο αποτελεσματικό όταν συνδυάζετε τα **change journals** με **high-signal process/file telemetry**:

- **NTFS USN Journal** παρέχει ένα μόνιμο ημερολόγιο ανά τόμο για τις αλλαγές αρχείων.
- **Sysmon Event ID 11** είναι χρήσιμο για δημιουργία/επικάλυψη αρχείων.
- **Sysmon Event ID 2** βοηθά στον εντοπισμό του **timestomping**.
- **Sysmon Event ID 15** είναι χρήσιμο για **named alternate data streams (ADS)** όπως `Zone.Identifier` ή κρυφά payload streams.

Γρήγορα παραδείγματα triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Για πιο αναλυτικές αντι-εγκληματολογικές ιδέες σχετικά με **timestamp manipulation**, **ADS abuse**, και **USN tampering**, δείτε [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Το Container FIM συχνά χάνει την πραγματική διαδρομή εγγραφής. Με το Docker `overlay2`, οι αλλαγές δεσμεύονται στο container's **writable upper layer** (`upperdir`/`diff`), όχι στα read-only image layers. Επομένως:

- Η παρακολούθηση μόνο μονοπατιών από το **εσωτερικό** ενός βραχύβιου container μπορεί να μην εντοπίσει αλλαγές μετά την αναδημιουργία του container.
- Συχνά είναι πιο χρήσιμη η παρακολούθηση της διαδρομής στο host που στηρίζει το writable layer ή του αντίστοιχου bind-mounted volume.
- Το FIM σε image layers διαφέρει από το FIM στο filesystem που τρέχει μέσα στο container.

## Attacker-Oriented Hunting Notes

- Παρακολουθήστε τις **service definitions** και τους **task schedulers** με την ίδια προσοχή που δίνετε στα binaries. Οι επιτιθέμενοι συχνά αποκτούν persistence τροποποιώντας ένα unit file, μια cron εγγραφή ή ένα task XML αντί να κάνουν patch το `/bin/sshd`.
- Ένας content hash από μόνος του δεν αρκεί. Πολλές παραβιάσεις εμφανίζονται αρχικά ως **owner/mode/xattr/ACL drift**.
- Αν υποπτεύεστε ώριμη εισβολή, κάντε και τα δύο: **real-time FIM** για φρέσκια δραστηριότητα και μια **cold baseline comparison** από αξιόπιστα μέσα.
- Αν ο επιτιθέμενος έχει root ή εκτέλεση στον kernel, θεωρήστε ότι ο FIM agent, η βάση δεδομένων του και ακόμη και η πηγή γεγονότων μπορεί να έχουν παραποιηθεί. Αποθηκεύετε logs και baselines απομακρυσμένα ή σε read-only μέσα όποτε είναι δυνατό.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
