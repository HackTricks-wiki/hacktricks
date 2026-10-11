# 프로세스 열거 및 서비스 경로

{{#include ../../banners/hacktricks-training.md}}

중요한 질문은 낮은 권한의 사용자가 영향을 줄 수 있는 데이터나 코드를 어떤 권한 있는 프로세스가 사용하는가입니다. 프로세스 트리, 현재 환경, 열린 파일, 그리고 각 후보 프로세스를 시작한 unit 또는 스크립트를 확인하세요.

## 프로세스 및 소유자 매핑하기

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

교차 사용자 부모-자식 관계는 정상일 수 있지만, 예상치 못한 전환이 있다면 부모 명령, 인수, 실행 파일, 작업 디렉터리, 참조 파일을 검토해야 합니다. 소유자와 로그인 컨텍스트를 파악하려면 [users and sessions](../user-information/user-and-session-triage.md)을 참조하세요.

### 로컬 가상 머신 콘솔

QEMU 프로세스의 `-spice` 옵션을 수신 주소와 함께 검토하세요. [QEMU 문서](https://www.qemu.org/docs/master/system/qemu-manpage.html)에 따르면 `disable-ticketing`을 사용하면 SPICE 클라이언트가 인증 없이 연결할 수 있습니다. 루프백에 바인딩된 리스너도 다른 로컬 호스트 사용자에게 잠재적으로 접근 가능할 수 있습니다. 명령줄을 노출된 콘솔로 간주하기 전에 실제 리스너, 인증 옵션, 로컬 접근 가능 여부를 확인하세요. 콘솔 제어는 **게스트**에 영향을 줍니다. 게스트 계정을 얻거나 부팅 상태를 변경하려면 게스트 측의 별도 조건이 필요하며, 가상화 호스트의 root 권한을 얻는 것은 아닙니다. 수동 열거 중에는 게스트에 연결하거나 게스트를 재부팅하지 말고 프로세스 인수와 소켓 메타데이터를 읽으세요.

로컬에서 접근 가능한 웹 인터페이스는 첫 번째 셸에서 서비스 계정의 파일에 접근할 수 없더라도 해당 서비스 계정으로 코드를 실행할 수 있습니다. 예를 들어 CVE-2023-0297은 신뢰할 수 없는 JavaScript가 Python import가 활성화된 Js2Py에 전달될 때 발생하는 pyLoad의 `/flash/addcrypted2` 처리 문제였습니다. [업스트림 수정](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)에서는 `pyimport`를 비활성화했습니다. pyLoad 프로세스를 권한 상승 경로로 간주하기 전에 실행 중인 프로세스의 소유자, 수신 주소, 엔드포인트 노출 여부, 설치된 패치 또는 벤더 백포트를 대조하세요. 프로세스 이름, 열린 포트, 패키지 버전만으로는 노출이 입증되지 않습니다. 수동 열거 중에는 코드 실행 페이로드를 전송하지 마세요.

### 터미널을 공유하는 권한 있는 로그인 셸

독립된 pseudo-terminal 없이 `su --login <user>`를 실행하는 권한 있는 대화형 셸은 권한이 낮은 로그인 셸과 터미널을 공유할 수 있습니다. 해당 사용자의 시작 파일을 제어할 수 있고, 그 안의 코드가 `TIOCSTI`를 사용해 터미널 입력을 삽입할 수 있다면 권한 있는 셸이 다시 활성화될 때 그 입력이 전달될 수 있습니다. [util-linux `su` 매뉴얼](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)은 터미널 공유 위험을 설명하고 대화형 사용 시 `su --pty`/`-P`를 권장합니다. `su -c`는 제어 터미널 없이 별도의 세션을 시작합니다. 이 위험이 실제로 성립하려면 부모 셸, 터미널 관계, 대상 시작 파일, 커널 정책을 확인해야 합니다. 프로세스 이름이나 `su -l` 인수만으로는 추가 검토가 필요한 단서일 뿐입니다.

관찰된 프로세스 트리와 TTY 열을 확인한 다음, 읽을 수 있는 실행 스크립트와 시작 파일의 소유권 및 권한을 확인하세요. Linux에서는 `/proc/sys/dev/tty/legacy_tiocsti`가 존재할 경우 정책을 파악하는 데 도움이 됩니다. 이 파일이 없다고 해서 안전하다는 뜻은 아닙니다. [Linux `TIOCSTI` 매뉴얼](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)에 따르면 Linux 6.2부터 이 sysctl이 false일 때 해당 작업에 `CAP_SYS_ADMIN`이 필요할 수 있습니다. 호스트를 열거하기 위해 ioctl을 호출하지 마세요.

데이터베이스 계정은 파일 시스템에 직접 쓰기 권한이 없더라도 대상 사용자의 시작 파일을 변경할 수 있는 경우가 있습니다. PostgreSQL 서버 측 `COPY ... TO 'filename'`은 데이터베이스 서버의 OS 계정으로 파일을 기록하지만, [PostgreSQL 제한 사항](https://www.postgresql.org/docs/current/sql-copy.html)에 따라 이 파일 형식은 데이터베이스 슈퍼유저 또는 `pg_write_server_files`와 같은 역할만 사용할 수 있습니다. 데이터베이스 역할과 서버 OS의 파일 권한을 모두 확인하세요. 애플리케이션 연결 문자열만으로 파일 쓰기 권한이 부여되지는 않습니다. 이 체인을 평가할 때 권한 있는 실행 스크립트와 데이터베이스 계정의 기능을 별도로 고려하세요.

## 런타임 아티팩트 검사하기

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

삭제된 실행 파일과 삭제되었지만 열린 파일은 마지막 파일 디스크립터가 닫힐 때까지 참조된 상태로 남습니다. 이러한 파일은 증거 또는 접근 가능한 비밀 정보를 보존할 수 있습니다. 프로세스 환경과 메모리에 자격 증명이 있을 수 있지만, 다른 프로세스를 읽는 것은 소유권, `/proc` 마운트 옵션, Yama ptrace 정책 및 기타 보안 제어에 의해 제한됩니다. 관련 기법은 [파일 디스크립터](../main-system-information/filesystem-links-and-file-descriptors.md) 및 [post-exploitation 자격 증명 탐색](../post-exploitation/README.md)을 참조하세요.

저장된 syscall trace도 또 다른 파일 권한 경계입니다. [`strace`는 syscall 인수를 출력 파일에 기록하므로](https://man7.org/linux/man-pages/man1/strace.1.html), [`execve` 인수](https://man7.org/linux/man-pages/man2/execve.2.html)를 읽을 수 있는 trace에 권한이 높은 작업이 명령줄에 전달한 비밀번호가 노출될 수 있습니다. 먼저 현재 사용자가 해당 trace를 읽을 수 있는지, 인수에 실제로 자격 증명이 포함되어 있는지 확인하세요. 이후 Unix 계정 전환을 시도하려면 해당 자격 증명이 그 계정에서 유효하다는 별도의 증거가 필요합니다. 파일 메타데이터는 일반적인 열거 과정에서 모든 trace를 검사하거나 내용을 출력하지 않고도 얻을 수 있는 유용한 수동 단서입니다.

## 권한이 높은 office 자동화 소켓

LibreOffice와 OpenOffice는 `--accept=socket,host=<host>,port=<port>;urp;` 인수를 통해 UNO API를 노출할 수 있습니다. 접근 가능한 엔드포인트를 가진 root 소유 office 프로세스가 있으면, 권한이 낮은 로컬 사용자가 해당 프로세스의 보안 컨텍스트에서 API 서비스를 호출할 수 있습니다. `SystemShellExecute` 서비스에는 시스템 명령을 실행하는 작업이 포함되어 있습니다. loopback에 바인딩하면 원격 접근은 제한되지만, 다른 제어로 접근을 차단하지 않는 한 로컬 사용자는 여전히 소켓에 접근할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

프로세스 소유자, 정확한 `--accept` 인수, 현재 수신 대기 중인 주소와 포트를 서로 대조하세요. 바인딩에 실패한 acceptor는 단서일 뿐입니다. passive enumeration 중에는 API에 연결하거나 API를 호출하지 마세요. 이 조건을 테스트하려고 권한이 높은 office 인스턴스를 시작하지 마세요.

## 권한이 높은 프로세스가 사용하는 System V 공유 메모리

root 소유 helper가 다른 사용자가 쓸 수 있는 System V 공유 메모리 세그먼트를 만들 수 있습니다. helper가 나중에 해당 세그먼트의 데이터를 셸 명령이나 다른 민감한 작업에 신뢰해 사용한다면, 실행 파일과 그 파일들이 보호되더라도 이 세그먼트는 권한 경계를 넘습니다. `shmget()`은 플래그의 하위 9비트에서 접근 권한을 가져옵니다. 모드 `0666`은 다른 사용자의 쓰기를 허용하며, `IPC_CREAT` 플래그를 추가해도 해당 권한이 제한되지는 않습니다. `ipcs -m`을 사용해 활성 세그먼트를 수동적으로 확인하고, 소유자, 모드, 수명을 권한이 높은 프로세스 및 해당 프로세스의 입력 처리 방식과 대조하세요. 누구나 쓸 수 있는 세그먼트만으로는 명령 실행이 입증되지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V 세그먼트는 `/dev/shm` 아래의 POSIX 공유 메모리 파일과 별개입니다. 잠깐만 생성되는 세그먼트는 단일 `ipcs` 스냅샷에 나타나지 않을 수 있으므로, 출력이 비어 있다고 해서 공유 메모리를 사용하는 도우미 프로그램이 배제되는 것은 아닙니다. 해당 프로그램의 소스 코드나 바이너리 동작, 그리고 이를 실행하는 `sudo` 규칙을 검토하세요. 열거 중 세그먼트를 만들 목적으로 권한이 있는 도우미 프로그램을 실행하지 마세요. [IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md)에서 namespace가 가시성에 미치는 영향을 설명합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul 에이전트 스크립트 검사

Consul은 에이전트의 운영 체제 계정으로 스크립트 상태 검사를 실행할 수 있습니다. 에이전트가 root로 실행되고, `enable_script_checks`가 활성화되어 있으며, 권한이 낮은 사용자가 로컬 HTTP API를 통해 스크립트 검사가 포함된 서비스를 등록할 수 있다면, 해당 사용자가 root 권한으로 실행되는 명령을 유발할 수 있습니다. API를 `127.0.0.1`에만 바인딩해도 로컬 사용자는 여전히 API에 접근할 수 있습니다. `enable_local_script_checks` 설정은 범위가 더 좁습니다. HTTP API 등록을 통해 제출된 스크립트 검사는 허용하지 않습니다. Consul ACL이 활성화된 경우 서비스 등록에는 `service:write`가 필요합니다. `acl.default_policy=allow` 한 줄만으로 익명의 호출자가 등록할 수 있다고 단정할 수는 없습니다. 실제 에이전트 계정, 로드된 설정, API 바인딩, 권한 부여를 함께 검토하세요.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

실행 중인 agent의 `-config-dir` 및 `-config-file` 인수를 따라 관련 구성 파일을 찾고, script-check 및 ACL 필드 이름과 설정만 살펴보세요. 구성 파일에 gossip 키나 토큰이 포함되어 있을 수도 있으므로 공유 로그에 붙여 넣지 마세요. 이 조건을 열거하기 위해 서비스를 등록하거나 상태 확인을 실행하지 마세요.

권한이 낮은 사용자가 root로 실행되는 agent의 `-config-dir`로 지정된 디렉터리에 **쓰기 및 탐색 권한**이 있는 경우, 별도의 로컬 파일 경로가 존재합니다. 해당 디렉터리에서 새 `.hcl` 또는 `.json` 서비스 정의가 로드될 수 있습니다. 디렉터리 탐색 및 쓰기 권한이 있으면 디렉터리 목록 조회가 거부되더라도 파일을 추가할 수 있습니다. root 명령 실행을 확인하려면 agent가 실제로 해당 디렉터리를 로드하는지, **유효한** script-check 설정이 로컬 정의를 허용하는지, 정의가 로드되는지, 그리고 agent가 root 권한을 유지하는지 확인하세요. [Consul 문서](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)에서는 다시 로드할 수 있는 설정과 상태 확인 정의를 설명합니다. script check를 활성화하려면 재시작이 필요할 수 있으므로 설치된 버전의 동작을 확인하세요. ACL로 agent를 보호하는 경우, [`consul reload`에는 `agent:write`가 필요합니다](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent). KV 쓰기 권한만으로는 이 권한이 부여되지 않습니다. 쓰기 가능한 디렉터리 메타데이터는 검토 신호일 뿐, 승인된 reload, 재시작 또는 명령 실행의 증거가 아닙니다. 구성을 쓰거나 API를 호출하지 말고 경로, 권한 및 정책을 확인하세요.

## 서비스 실행 체인 따라가기

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

unit, drop-in, `EnvironmentFile=`, helper script, 상대 경로 명령, 쓰기 가능한 디렉터리, socket activation을 확인하세요. root 소유 unit도 사용자 쓰기 가능 설정 파일이나 script를 읽으면 안전하지 않을 수 있습니다. [arbitrary file write](../interesting-files-permissions/write-to-root.md) 페이지에서 흔한 service 및 unit 악용 경로를 다룹니다. 일회성 `ps` 목록에 나타나지 않는 짧게 실행되는 작업은 [pspy](https://github.com/DominicBreuker/pspy) 또는 audit/process telemetry로 모니터링하세요.

사용자 지정 **xinetd** service의 경우, 활성화된 stanza의 `server`, `user`, 접근 제어 설정을 실제 listener 및 정확한 실행 파일과 대조하세요. [`user` 설정](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)은 생성되는 process의 identity를 지정하며, 실행 파일의 set-user-ID bit는 [`execve`가 해당 전환을 허용하는 경우](https://man7.org/linux/man-pages/man2/execve.2.html) 유효 identity를 별도로 바꿀 수 있습니다. 신뢰할 수 없는 입력을 받는 접근 가능한 privileged binary는 고정 버퍼에 길이 제한 없는 [`scanf` 문자열 변환](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)을 수행하는 경우처럼, 메모리 안전성 버그가 없는지 오프라인에서 source나 disassembly를 검토할 가치가 있습니다. service 매핑과 set-user-ID metadata는 단서일 뿐, 그러한 버그의 증거는 아닙니다. 수동 열거 중에는 crash 입력을 보내거나 실행 중인 privileged service를 디버깅하지 마세요.

source를 읽을 수 있는 사용자 지정 privileged listener의 경우, [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html)와 같은 복사 작업에 사용되는 각 호출자 제어 길이를 검토하세요. 현재 쓰기 index가 고정 버퍼 안에 있는지만 확인해서는 **복사 길이**가 남은 공간에 맞는다는 것을 입증할 수 없습니다. index가 범위 내에 있는지 확인한 후 `copy_length <= capacity - index`인지 검증하고, 부호 및 산술 오버플로도 확인하세요. 이는 입력이 해당 작업에 도달하고, 낮은 권한의 사용자가 listener에 접근할 수 있으며, process가 더 높은 유효 identity를 유지하는 경우에만 검토 단서가 됩니다. 열거 중에는 source와 process metadata를 오프라인에서 확인하고, 실행 중인 service에 crash 입력을 보내지 마세요.

**Upstart**를 사용하는 시스템에서는 system job 정의가 `/etc/init/*.conf`에 있을 수 있습니다. 현재 사용자가 쓸 수 있는 job 파일이 문제가 되려면, 활성 init daemon이 해당 job을 실제로 불러오고, `script` 또는 `exec` stanza가 더 높은 권한의 identity로 실행되며, 사용자가 허용된 `initctl` 명령이나 실제 다른 trigger를 통해 이를 시작할 수 있어야 합니다. sudo `initctl` 권한만으로는 job 파일을 쓸 수 있거나 수정된 job이 실행된다는 사실이 입증되지 않습니다. 열거 중에는 job을 수정하거나 시작하지 말고, 정확한 job 파일 권한, 유효한 run-as 설정, 활성 daemon, trigger를 확인하세요. [Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) 및 [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html) 매뉴얼을 참고하세요.

시스템의 [boot job이 정확한 경로를 읽는 경우](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), `/etc/autologin/passwd`와 같은 읽을 수 있는 autologin password 파일은 credential 노출 단서입니다. boot job이 설치되어 있고 해당 파일을 사용하는지 확인한 다음, password가 다른 로컬 계정이나 service에서도 유효한지 별도로 검증하세요. 파일명만으로 password 재사용이 입증되지는 않습니다. 공유 열거 결과에 password를 넣지 말고 경로와 접근 metadata만 기록하세요.

unit의 `ExecStart=` 또는 예약된 명령에서 목록 조회가 불가능한 디렉터리 안 script의 정확한 경로가 드러날 수 있습니다. [디렉터리 search 권한](https://man7.org/linux/man-pages/man7/path_resolution.7.html)이 있으면 알려진 경로를 현재 identity로 따라갈 수 있습니다. 디렉터리 목록 조회가 실패했다고 파일을 보호한다고 가정하지 말고, 모든 상위 디렉터리의 search 권한과 파일의 read 권한을 확인하세요. 읽을 수 있는 script에 transfer credential이 있을 수 있지만, 다른 계정으로 접근하려면 credential이 여전히 유효하고 그 계정에서도 별도로 허용되어야 합니다. 공유 로그에 secret 값을 출력하지 말고 경로와 권한 근거를 기록하세요.

예약된 CommonJS Node.js script의 경우, script 자체가 읽기 전용이더라도 `require('package')`와 같은 bare import를 검토하세요. [Node는 importing 파일 옆의 `node_modules`와 상위 디렉터리에서 검색한 뒤 설정된 전역 경로를 확인합니다](https://nodejs.org/api/modules.html#loading-from-node_modules-folders). 낮은 권한의 사용자가 이러한 상위 디렉터리 중 하나에 **쓰기와 search 권한**을 가진 경우, 먼저 일치하는 package를 만들 수 있습니다. 정확한 import가 실행되는지, 선택된 package가 built-in module이 아닌지, 해당 경로를 생성하거나 변경할 수 있는지, 설치된 runtime에서 module이 그 경로로 resolve되는지, 더 높은 권한의 job이 다음 실행 때 이를 불러오는지 확인하세요. 쓰기 가능한 상위 디렉터리 metadata는 검토 단서일 뿐입니다. module을 심거나 job을 실행하지 말고 script와 scheduler를 수동으로 확인하세요.

자동화된 job이 다른 OS identity로 package를 설치하는 경우, private Python package index도 신뢰 경계입니다. 정확한 job과 run-as 계정을 설정된 index, 선택된 package 이름, 낮은 권한의 사용자가 job이 실제 설치할 package를 publish하거나 교체할 수 있는지와 대조하세요. source distribution을 빌드할 때 설치자의 identity로 build backend나 legacy `setup.py`가 실행될 수 있습니다. 설치된 package를 import하는 것은 별도의 실행 경로입니다. index listener, 읽을 수 있는 upload password hash, package 파일명만으로는 이 연결이 입증되지 않습니다. 열거 중에는 아무것도 업로드하거나 설치하지 말고 job, index authorization, package provenance를 검토하세요. [pip의 build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) 및 [secure-install 지침](https://pip.pypa.io/en/stable/topics/secure-installs/)을 참고하세요.

privileged agent가 별도의 web service나 container가 관리하는 task queue를 주기적으로 확인할 수 있습니다. 낮은 신뢰도의 identity가 service의 task database에 쓸 수 있다면, 해당 행이 실제로 agent에 제공되는지와 command task가 agent의 OS identity로 실행되는지 확인하세요. database 쓰기 권한, 대상 session 또는 routing key, 활성 polling, task authorization, agent의 유효 사용자 identity를 각각 확인하세요. container 내부의 root가 host-root 접근을 의미하지는 않습니다. host-privileged consumer가 공격자가 제어하는 task data를 실행할 때만 경계를 넘습니다. 열거 중에는 queue를 수정하거나 task를 보내지 말고 process, database 파일, service metadata를 확인하세요.

반복 실행되는 job이 application database 설정 행에서 명령을 읽는 경우도 있습니다. 낮은 권한의 database role이 해당 행을 변경할 수 있는지, 활성 job이 변경 후 그 값을 읽는지, 더 높은 OS identity로 실행되는 shell 또는 동등한 명령 실행기에 값이 전달되는지 확인하세요. database 쓰기 권한이나 명령처럼 보이는 값만으로는 실행이 입증되지 않습니다. 수동 열거 중에는 행을 변경하지 말고 job과 권한을 확인하세요.

대기 중인 메시지에는 code 대신 URL이 들어갈 수도 있습니다. privileged consumer가 해당 URL을 가져와 응답을 Lua 또는 다른 실행 가능한 plugin으로 불러오는 경우, publisher가 정확한 exchange와 routing key에 대해 가진 권한, 소비되는 queue로의 binding, fetch 및 plugin-load 경로, worker의 유효 identity를 확인하세요. [RabbitMQ는 exchange를 통해 게시된 메시지를 라우팅합니다](https://www.rabbitmq.com/docs/exchanges). broker listener나 유효한 로그인만으로는 이 worker에 메시지가 전달된다는 사실이 입증되지 않습니다. 캡처한 평문 broker credential은 실제 packet-capture 접근 권한과 읽을 수 있는 traffic이 필요한 별도의 단서이며, publish authorization을 입증하지 않습니다. Lua plugin은 runtime에서 해당 API를 사용할 수 있는 경우에만 [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute)를 통해 shell 명령을 실행할 수 있습니다. 수동 열거 중에는 traffic을 캡처하거나 메시지를 게시하거나 plugin을 가져오지 말고 설정과 code를 검토하세요.

privileged Python service가 로컬 HTTP 또는 socket endpoint를 노출하는 경우, 파일 권한상 수정할 수 없는 읽기 전용 script에서도 입력이 code로 이어지는 경로가 드러날 수 있습니다. 활성 process와 unit identity를 정확한 script, listener, route authorization, 호출자가 제어하는 필드와 대조하세요. 그런 다음 parsing 및 validation부터 동적 `eval()` 또는 `exec()` sink까지 해당 필드를 추적하세요. 특히 request text로 새 f-string을 만들고 이를 평가하면 공격자가 제공한 replacement field가 Python expression으로 해석될 수 있습니다([Python `eval` 경고](https://docs.python.org/3/library/functions.html#eval); [f-string 의미](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). `eval`이 단순히 검색되거나 loopback에 binding되어 있다는 사실만으로는 신뢰할 수 없는 호출자가 sink에 도달한다는 점이 입증되지 않습니다. 열거 중에는 test payload를 보내지 말고 실제 dataflow와 접근 제어를 검토하세요.

해당 route의 signed-request gate도 별도로 검토해야 합니다. 읽을 수 있는 source에서 signing key가 명백히 작은 값의 집합이나 예측 가능한 output 공간을 통해 도출되고, service가 유효한 서명 샘플을 노출한다면 signature가 privileged `eval()` sink를 더는 보호하지 못할 수 있습니다. 정확한 key 도출 방식과 verifier, 실행 중인 service identity와 로컬 호출자 접근 권한, 서명된 필드가 sink에 도달하는지 확인하세요. Python의 [`random` module](https://docs.python.org/3/library/random.html)을 import하거나 signature 샘플이 있다는 사실만으로는 이러한 조건 중 어느 것도 입증되지 않습니다. Python은 `__builtins__` 제한이 신뢰할 수 없는 `eval()` 입력에 대한 [보안 경계가 아니라고도 경고합니다](https://docs.python.org/3/library/functions.html#eval). key 분석은 오프라인에서 수행하고, 수동 열거 중에는 위조 request를 제출하지 마세요.

비어 있지만 쓰기 가능한 `/etc/systemd/system/<unit>.service.d` 디렉터리는 unit 파일과 기존 drop-in이 모두 보호되어 있더라도 문제가 될 수 있습니다. 사용자가 새 `.conf` override를 만들 수 있기 때문입니다. 현재 identity에 해당 디렉터리의 쓰기 및 search 권한이 있는지, unit이 로드되어 root로 실행되는지, daemon reload 후 restart가 발생할지 확인하세요. reload 또는 restart 권한, timer, 이후의 boot로 변경 사항이 적용될 수 있지만 디렉터리에 쓰기 권한이 있다는 사실만으로 즉시 실행되지는 않습니다.

실행 중인 service의 경우, unit의 `[Service]` 섹션에 있는 literal `EnvironmentFile=` 경로를 따라가세요. 이름이 `.env`로 시작하지 않는 파일도 포함됩니다. 낮은 권한의 사용자가 파일을 읽을 수 있다면 `API_TOKEN`이나 `APP_SECRET_KEY`와 같은 credential 관련 key 이름을 확인하되, 공유 로그에 값은 출력하지 마세요. 유효한 unit을 평가할 때 drop-in override와 선택적인 `-` prefix도 확인하세요. 파일을 읽을 수 있다는 것은 credential 노출 단서일 뿐이며, 권한 상승으로 이어지려면 해당 값이 privileged 작업에 여전히 유효해야 합니다.

### 신뢰할 수 없는 업로드의 privileged 처리

root로 실행되는 file watcher가 사용자 쓰기 가능 업로드 디렉터리의 파일을 단시간 실행되는 parser나 extractor에 전달할 수 있습니다. 실행 중인 watcher의 상위 script나 service를 추적하고, 정확한 디렉터리, 파일을 둘 수 있는 사용자, 자식 명령과 인수, 자식이 실행되는 identity를 확인하세요. process snapshot에는 watcher가 표시되어도 업로드 사이에 실행되는 extractor는 놓칠 수 있습니다. 수동 열거 중에는 test payload를 넣거나 watcher를 실행하지 마세요.

구체적인 예로 Binwalk의 extraction mode(`-e`)가 공격자가 제어하는 PFS 데이터를 처리하는 경우가 있습니다. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617)으로 인해 PFS extractor가 의도된 디렉터리 외부에 쓸 수 있었으며, Binwalk가 나중에 불러올 수 있는 plugin 경로에도 쓸 수 있었습니다. upstream은 [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4)에서 수정했지만, 배포판의 backport 때문에 표시되는 버전은 이전 버전일 수 있습니다. 적용 여부를 판단하기 전에 [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)와 같은 경로로 설치 package의 보안 상태를 확인하세요. Binwalk가 설치되어 있다는 사실만으로 privilege-escalation 경로가 입증되지는 않습니다. 낮은 권한의 사용자가 제어할 수 있는 입력을 더 높은 권한의 process가 실제로 처리해야 합니다.

### 로컬 의존성을 사용하는 예약 빌드

예약된 `cargo run`은 job의 run-as 사용자로 source를 다시 컴파일합니다. manifest의 로컬 `{ path = "..." }` 의존성과 각 의존성의 source 및 상위 디렉터리 권한을 확인하세요. 주 crate만 확인해서는 안 됩니다. 낮은 권한의 사용자가 Cargo가 컴파일하는 의존성을 수정할 수 있고 예약된 job이 그 결과물을 실행한다면, 컴파일된 code가 해당 run-as 사용자로 실행될 수 있습니다. 유효한 scheduler 명령, 작업 디렉터리, 의존성 resolution, 재빌드 여부를 확인하세요. 다른 위치에 쓰기 가능한 Rust source 파일이 있다는 사실만으로는 단서일 뿐입니다. 수동 triage에는 manifest와 경로 metadata를 읽는 것으로 충분합니다. [Cargo path-dependency 문서](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)를 참고하세요.

## Xvfb framebuffer 파일

`Xvfb -fbdir <directory>`는 가상 화면을 위해 `Xvfb_screen<n>`이라는 memory-mapped 파일을 사용합니다. 다른 사용자의 실행 중인 Xvfb process가 지정한 디렉터리에 현재 사용자가 읽을 수 있는 screen 파일이 있다면 framebuffer에 해당 사용자의 데스크톱 콘텐츠가 노출될 수 있습니다. process, 파일 소유권, 권한을 함께 확인하세요. 파일을 읽을 수 있다는 사실만으로 유용한 콘텐츠가 화면에 있다는 점이 입증되지는 않습니다. 공유 열거 결과에 이미지 데이터를 복사하지 말고 우선 경로와 metadata를 확인하세요. [Xvfb 매뉴얼](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)에서 `-fbdir` 동작을 설명합니다.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` 매뉴얼](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` 매뉴얼](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` 매뉴얼](https://man.openbsd.org/ipcs.1)
4. [Consul 에이전트 구성: 스크립트 검사](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul 에이전트 서비스 등록 API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL 구성](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice 도움말: 외부 API 클라이언트를 위한 소켓 열기](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
