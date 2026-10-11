# SUID, SGID, ACL 및 민감한 파일

{{#include ../../banners/hacktricks-training.md}}

SUID와 SGID는 실행 파일의 유효 사용자 ID를 변경하고, ACL은 일반적인 `ls -l` 권한 비트로는 보이지 않는 접근 권한을 부여할 수 있습니다. 사용자가 겉으로 드러난 소유자 및 그룹 권한보다 더 많은 권한으로 읽기, 쓰기 또는 실행을 할 수 있다면 두 항목을 모두 검토하세요.

## 권한이 있는 실행 파일 열거하기

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

커스텀 실행 파일이나 최근 변경된 실행 파일, 특이한 소유자, 쓰기 가능한 마운트에 있는 파일에 집중하세요. `nosuid` 마운트는 set-ID 동작을 억제할 수 있습니다. 파일 capabilities는 [Linux capabilities](linux-capabilities.md)에 설명된 별도의 권한 메커니즘입니다. 의심스러운 바이너리를 해당 패키지의 바이너리와 비교하고, 상승된 권한으로 어떤 명령을 실행하고, 어떤 파일을 열거나, 무엇을 로드하는지 확인하세요.

호출자의 입력을 받는 생소한 root 소유 SUID 실행 파일은 바이너리의 사본을 오프라인에서 검토해 메모리 안전성이 보장되지 않는 인자 처리와 그 코드 경로를 살펴보세요. 유효 ID 동작과 스택 카나리, 비실행 메모리, 위치 독립 코드, 주소 무작위화 같은 완화 기법을 기록하세요. 안전하지 않은 함수 이름이나 완화 기법의 부재는 검토를 시작할 단서일 뿐입니다. 악용 가능성은 실제 입력 범위, 도달 가능한 제어 흐름, 오류 발생 시의 유효 ID에 따라 달라집니다. 수동 열거 중에 충돌을 시험해 보겠다는 이유로 실행 중인 권한 상승 실행 파일에 긴 인자를 전달하지 마세요.

익숙한 SUID 프로그램도 교체되거나 백도어가 삽입되었을 수 있습니다. 최근 수정 시각은 단서이지 증거가 아닙니다. **특정 의심 패키지 바이너리**의 경우, 소유 패키지를 확인하고 일상적인 열거 중 모든 패키지를 검증하는 대신 설치된 파일을 패키지 메타데이터와 비교하세요:

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify`는 패키지 데이터베이스에 체크섬이 기록된 파일의 내용만 확인합니다. RPM은 모드와 소유권 같은 메타데이터도 비교합니다. **권한이 부여된 실행 파일 자체**의 불일치에 집중하세요. stripped 설치에서는 같은 패키지의 다른 위치에 있는 문서나 로케일 파일이 없다는 보고가 나올 수 있습니다. 의심스러운 실행 파일을 신뢰할 수 있는 vendor 패키지와 비교하고, 정확히 어떤 코드가 변경됐는지 검토하세요. 정당한 로컬 변경, 체크섬 부재, 손상된 패키지 메타데이터 때문에 두 명령 모두 증명할 수 있는 범위에는 한계가 있습니다. 수동 triage의 일부로 의심스러운 SUID 프로그램이나 패키지 검증 스크립트를 실행하지 마세요. [dpkg 검증 매뉴얼](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html)과 [RPM 검증 매뉴얼](https://rpm.org/docs/4.20.x/man/rpm.8)을 참조하세요.

셸, 상대 경로 명령 또는 쓰기 가능한 경로의 라이브러리를 호출하는 SUID 프로그램은 trust boundary를 넘을 수 있습니다. [SUID shared-library 및 linker 악용](suid-shared-library-and-linker-abuse.md), [PATH 지침](../linux-basics/linux-environment-variables.md#path), [user-ID 설명](../user-information/euid-ruid-suid.md)을 참조하세요. 특정 명령에서 알려진 escape가 있는지 확인하려면, 호스트에서 허용되는 정확한 바이너리와 호출 방식을 [GTFOBins](https://gtfobins.github.io/)에서 확인하세요.

set-user-ID 실행 파일에서는 호출자의 **real UID**와 파일 소유자의 **effective UID**를 구분하세요. [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html)는 real UID를 그대로 두고, set-ID 변경 후 effective UID를 saved UID에 복사합니다. [`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html)은 `/bin/sh -c`를 통해 명령을 실행합니다. 해당 경로에서 선택되는 셸에 따라 자식 프로세스가 effective identity를 유지하는지가 달라집니다. 특히 [Bash privileged-mode 규칙](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)에 따르면 Bash가 `-p` 없이 시작할 때 effective UID가 real UID와 다르면 effective UID를 real UID로 재설정합니다. 실제 helper의 UID 변경과 자식 프로세스 호출 방식, 소유자, 실행 접근 권한, mount의 `nosuid` 설정, 프로세스의 `no_new_privs` 상태를 확인하세요. SUID 비트나 셸 호출만으로는 실제로 더 높은 권한을 얻을 수 있다고 단정할 수 없습니다.

특이한 root 소유 SUID `jjs`를 현재 사용자가 실행할 수 있다면, 파일 접근을 별도로 검토해야 합니다. 레거시 Nashorn 도구는 자식 셸이 effective UID를 낮추더라도 Java 파일 API에 접근할 수 있습니다. 이를 권한 있는 읽기 또는 쓰기로 간주하기 전에 설치된 JVM의 동작, 파일 작업 시 effective identity, `nosuid`/`no_new_privs`를 확인하세요. [Oracle은 JDK 15에서 `jjs`를 제거했습니다](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html). 설치된 경로는 이전 버전이거나 별도로 패키징된 빌드일 수 있습니다. [GTFOBins는 파일 API를 설명합니다](https://gtfobins.org/gtfobins/jjs/). 하지만 해당 sudo 예시만으로 모든 빌드의 SUID 동작이 입증되지는 않습니다. 수동 열거 중에는 이 도구를 실행하지 마세요.

root 소유 SUID `gosu` 실행 파일에 낮은 권한의 사용자가 접근할 수 있다면 검토가 필요합니다. 문서화된 인터페이스는 대상 사용자와 명령을 인자로 받지만, 일반적인 컨테이너 사용에서는 root로 실행해 권한을 낮춥니다. 권한 상승을 주장하기 전에 설치된 빌드의 SUID 동작, effective identity와 user-namespace 매핑, `nosuid`, `no_new_privs`를 확인하세요. 컨테이너의 root가 호스트의 root를 의미하지는 않습니다. 파일 이름이나 SUID 비트만으로 실제 권한 전환이 입증되지는 않습니다. [upstream 사용법](https://github.com/tianon/gosu)과 [maintainer의 SUID 경고](https://github.com/tianon/gosu/issues/11)를 참조하세요. 수동 인벤토리 중에는 helper를 실행하지 마세요.

사용자 지정 set-user-ID 백업 wrapper가 호출자가 선택한 경로를 받아 archive 명령에 삽입한 뒤 `system(3)`으로 전달할 수 있습니다. 구성된 명령에서 해당 경로를 인용하지 않으면 자식 셸이 [ `HOME`을 사용하는 tilde expansion, `?` 및 `*` 같은 pathname pattern, 줄바꿈을 통한 명령 분리](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)를 적용할 수 있습니다. denylist에서 흔한 문장 부호만 거부해도 경로가 리터럴로 처리되는 것은 아닙니다. 정확한 인자 흐름, 상속된 환경, 자식 셸과 effective identity, 파일 시스템 접근, archive 출력이 호출자에게 보이는지를 확인하세요. SUID 비트, archive 도구 문자열 또는 `/root` 리터럴의 차단만으로는 정보 노출이나 코드 실행이 입증되지 않습니다. 수동 열거 중에는 비공개 파일을 archive하거나 crash 입력을 보내지 말고, wrapper 사본을 오프라인에서 검토하세요.

`$(...)` 같은 셸 [command substitution](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)도 metacharacter denylist의 허점이 될 수 있습니다. 허용된 명령 접두부가 고정되어 있어도 이후의 호출자 제어 인자가 `/bin/sh -c`를 거칠 수 있습니다. 정확한 인용 방식, parser, effective identity를 오프라인에서 확인하세요. `system()` 문자열이나 불완전한 denylist만으로 실행이 입증된다고 간주하지 마세요.

**호출 프로세스 트리**도 중요합니다. 웹 worker가 UID 변경 system call을 제한하는 seccomp filter를 설치할 수 있습니다. [seccomp filter는 자식 프로세스에 전달되고 `execve` 이후에도 유지됩니다](https://docs.kernel.org/userspace-api/seccomp_filter.html). 예를 들어 Apache의 [mpm-itk `LimitUIDRange` 및 `LimitGIDRange` 지시어](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/)는 하위 프로세스가 사용할 수 있는 identity를 제한할 수 있습니다. `/proc/self/status`의 `Seccomp: 2`는 filter 모드만 보여줄 뿐, 정책이나 이 helper가 소유자의 identity를 얻을 수 있는지는 보여주지 않습니다. 실제 호출의 상위 프로세스와 effective filter를 SUID, mount, `no_new_privs` 조건과 함께 검토하세요. 별도의 로그인 세션에는 다른 정책이 적용될 수 있지만, 그 세션에도 유효한 접근 경로가 필요합니다.

사용자 지정 SUID 실행 파일이 별도의 읽기 가능한 Python 스크립트를 호출할 수 있습니다. 실제로 Python **2**를 사용한다면 [`input()`은 입력된 표현식을 평가합니다](https://docs.python.org/2/library/functions.html#input). Python 3의 `input()`은 텍스트를 반환합니다. 소스 코드 한 줄을 실행 경로로 간주하기 전에 wrapper의 effective identity, interpreter 경로와 버전, 스크립트 경로, 신뢰할 수 없는 입력이 해당 호출에 도달하는지를 확인하세요. 스크립트 자체의 set-ID 비트나 권한 있는 wrapper 없이 존재하는 `input()` 호출만으로는 같은 경계가 성립하지 않습니다. 열거 중에는 바이너리가 참조하는 경로와 제한된 범위의 스크립트 소스를 검토하되 실행하지 마세요.

특이한 SUID 실행 파일과 함께 읽을 수 있는 소스가 있다면, 호출자가 제어하는 각 파일 읽기에서 요청한 바이트 수와 대상 버퍼 크기를 비교하고 이후의 제어 흐름 검사도 살펴보세요. [`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html)는 요청된 항목을 전달받은 포인터에 저장하며, 대상 객체의 용량을 알지 못합니다. 크기 불일치는 정적 메모리 안전성 검토의 단서일 뿐, 사용 가능한 권한 상승의 증거는 아닙니다. 해당 소스가 설치된 바이너리와 일치하는지, 호출자가 입력을 제공할 수 있는지, 해당 맥락에서 SUID 실행이 유효한지, 관련 코드 경로에 도달할 수 있는지를 확인하세요. 열거 중에는 권한 있는 프로그램에 crash 입력을 보내지 말고, 제한된 범위의 소스 또는 바이너리 사본을 오프라인에서 검토하세요.

사용자 지정 SUID helper는 파일 내용을 출력하지 않고도 보호된 파일을 노출할 수 있습니다. 호출자가 경로와 정규식을 모두 선택하고 helper가 effective UID로 검색한 일치 항목 수를 표시한다면, 접두부를 고정한 테스트로 문자 단위 oracle을 구성할 수 있습니다. 이를 주장하기 전에 helper의 소유자, effective-ID 동작, 실행 접근 권한, 경로 제한, regex semantics, 응답의 가시성, 호출자가 다른 방법으로는 읽을 수 없는 구체적인 상위 권한 파일을 확인하세요. SUID 비트나 regex 라이브러리 문자열만으로는 이 흐름이 입증되지 않습니다. 수동 열거 중에는 특이한 실행 파일을 기록하고 제한된 범위의 disassembly 또는 소스 사본을 검토하세요. 실행 중인 helper에 반복 추측을 보내거나 복구된 비밀을 출력하지 마세요.

OpenBSD에서 호출자가 선택한 경로를 받는 사용자 지정 set-user-ID reader는 effective identity로 `/var/backups`의 파일을 읽을 수 있고 내용을 호출자에게 반환한다면 해당 파일을 노출할 수 있습니다. [OpenBSD의 `changelist(5)`](https://man.openbsd.org/changelist.5)는 설정된 경로의 `.current` 및 `.backup` 사본을 설명하지만, `+`로 시작하는 항목은 파일 내용이 아닌 SHA-256 체크섬을 저장합니다. 백업 디렉터리는 root 소유이고 모드는 `0700`이어야 합니다. `/var`에 대한 helper의 [`unveil` 읽기 규칙](https://man.openbsd.org/unveil.2)은 해당 경로 아래의 접근을 허용할 수 있지만, 그 자체로 파일 접근 권한을 부여하거나 입증하지는 않습니다. 권한 상승을 주장하기 전에 실제 effective UID, 현재 사용자의 실행 권한, 허용되는 경로, 백업의 존재와 내용, 별도의 인증 요건을 확인하세요. 수동 열거에서는 helper와 경로 메타데이터를 보고하고, reader를 실행하거나 백업 데이터를 출력하지 마세요.

호출자가 선택한 경로를 [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html)로 확인한 뒤 나중에 여는 사용자 지정 SUID 프로그램은 호출자가 쓸 수 있는 디렉터리에서 파일이나 심볼릭 링크를 바꾸는 race condition에 취약할 수 있습니다. 검사는 이전 객체에 적용되지만, 이후의 [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html)는 다른 객체를 가리킬 수 있습니다. 이 helper가 상승된 effective identity로 실행 가능하고, 도달 가능한 코드 경로가 선택된 파일을 읽으며, 호출자가 검사와 열기 사이에 경로를 바꿀 수 있는지 확인하세요. SUID 비트, 쓰기 가능한 디렉터리, `stat` 문자열만으로는 이 조건 중 어느 것도 입증되지 않습니다. 정보 노출 경로가 성립하려면 출력이 보이거나 호출자가 읽을 수 있는 대상이 있어야 합니다. 바이너리와 경로 메타데이터를 오프라인에서 검토하고, 수동 열거 중에는 실행 중인 helper에 race를 시도하지 마세요.

SGID wrapper에도 같은 dependency 검토를 적용하세요. 절대 경로로 셸이나 helper를 실행하는 wrapper도 낮은 권한의 사용자가 해당 파일을 바꿀 수 있다면 안전하지 않을 수 있습니다. 생성된 코드는 wrapper의 effective group을 상속할 수 있습니다. 정확한 호출 경로, ACL을 포함한 쓰기 권한, wrapper의 effective group, 자식 프로세스 실행 전에 권한을 낮추는지를 확인하세요. interpreter가 상속된 effective ID를 버릴 수도 있으므로, 검토 대상과 입증된 권한 전환을 구분하세요. 호스트 어딘가에 쓰기 가능한 셸이 있다는 것만으로 권한 있는 wrapper가 그 셸을 호출한다고 입증되지는 않습니다.

### SQLite CLI에 SQL을 전달하는 권한 있는 wrapper

사용자 지정 SUID 프로그램이 사용자가 제어하는 SQL을 **`sqlite3` command-line program**에 전달한다면, 쿼리가 읽기 전용이라고 판단하기 전에 정확한 명령과 effective identity를 확인하세요. CLI의 `edit()` SQL function은 편집기(두 번째 인자 또는 `VISUAL`)를 실행하며, SQL의 `load_extension()` function은 extension loading이 활성화된 경우 shared library를 로드할 수 있습니다. wrapper가 `PATH`를 고정하거나 절대 경로의 `sqlite3`를 사용하더라도 CLI 프로세스의 identity로 코드 실행이 가능한 경로입니다. SQL이 실제로 해당 function에 전달되고 CLI가 관련 기능을 유지해야 합니다. 바이너리나 호스트에서 `sqlite3`를 발견하는 것만으로는 권한 상승이 입증되지 않습니다. SQLite **library**에서는 extension loading이 기본적으로 비활성화되어 있으므로 CLI와 구분하세요. 권한 있는 애플리케이션에서 신뢰할 수 없는 SQL을 처리해야 한다면 SQLite CLI의 `--safe` 모드를 사용하세요. 이 모드는 `edit()`, `load_extension()` 및 기타 부작용이 있는 function을 비활성화합니다. [SQLite CLI 문서](https://www.sqlite.org/cli.html#the_edit_sql_function), [safe-mode 문서](https://www.sqlite.org/cli.html#the_safe_command_line_option), [extension-loading 문서](https://www.sqlite.org/loadext.html#loading_an_extension)를 참조하세요.

### verbose client로 파일을 전달하는 권한 있는 reader

사용자 지정 SUID/SGID wrapper가 호출자가 선택한 경로의 접근 권한을 확인한 뒤 해당 파일을 다른 명령에 전달할 수 있습니다. 접근 검사와 이후의 파일 열기 모두에서 effective identity를 검토하고, `../` 구성 요소를 실제 기준 디렉터리에 따라 해석하며, 자식 프로세스가 잘못된 입력을 처리하는 방식을 확인하세요. 데이터베이스 client가 비공개 파일을 SQL로 읽고 verbose 출력을 사용하면 SQL이 유효하지 않더라도 오류 메시지에 파일 내용이 포함될 수 있습니다. 자식 프로세스가 호출자가 읽을 수 없는 파일을 읽을 수 있고, wrapper를 통해 호출자가 해당 파일을 선택할 수 있으며, 출력이 보이는 경우에만 사용자 간 정보 노출이 성립합니다. `mysql` 또는 다른 client 문자열이 있다는 것만으로는 이 조건이 입증되지 않습니다.

### Netdata `ndsudo` 검색 경로

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)는 일부 Netdata `ndsudo` 빌드에 영향을 미쳤습니다. root 소유 SUID helper는 호출자가 제공한 `PATH`를 사용해 허용된 외부 명령을 찾았습니다. 현재 계정이 실행할 수 있는 경우에만, 호출자의 일반적인 `PATH` 밖에 있는 것을 포함해 설치된 helper를 검토하세요. 소유자, SUID 비트, 그룹/ACL 허가를 포함한 실행 접근 권한, 설치된 빌드와 vendor 패치 상태, `NoNewPrivs` 또는 `nosuid` mount가 identity 변경을 막는지 확인하세요. Netdata는 패치된 빌드로 `v1.45.3` 및 `v1.45.0-169`를 제시합니다. 배포판 backport는 별도로 확인해야 합니다. 대시보드 버전이나 `ndsudo`가 있다는 사실만으로 권한 상승이 가능하다고 입증되지는 않습니다. 이 경로 문제가 성립하려면 helper가 호출자가 제어하는 위치에서 외부 명령을 찾아야 합니다.

### Firejail join 권한 경계

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188)는 Firejail의 권한 있는 `--join` 로직에 영향을 미쳤습니다. 조작된 join 대상이 setuid-root helper를 속여 공격자가 제어하는 mount namespace를 받아들이게 하고 안전하지 않은 보안 상태를 복사하게 할 수 있었습니다. 수동 triage에서는 **현재 identity로** root 소유 setuid Firejail 바이너리를 실행할 수 있는지, mount 및 프로세스 맥락에서 setuid가 유효한지, 설치된 빌드에 수정 사항이 없는지 확인하세요. upstream은 [0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70)에서 문제를 수정했습니다. 배포판 패키지는 [수정 사항을 backport](https://github.com/netblue30/firejail/issues/5191)하면서도 이전 버전을 표시할 수 있습니다. 이러한 전제 조건은 검토 대상을 식별할 뿐, join 성공이나 root shell을 입증하지 않습니다. 열거 중에는 가짜 jail을 만들거나 `--join`을 실행하지 마세요.

### GNU Screen logfile 권한

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html)은 Screen 4.5.0이 호출자가 선택한 logfile을 상승된 권한으로 열었던 문제입니다. SUID 인벤토리에 `screen` 또는 버전이 붙은 바이너리가 있다는 것은 검토 단서일 뿐입니다. root 소유 여부, 현재 사용자에게 effective SUID 실행이 가능한지, 설치된 빌드와 배포판 패치 상태, 영향을 받는 logfile 동작을 확인하세요. [Debian은 backport로 4.5.0 패키지를 수정했습니다](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484). 따라서 버전 문자열이나 파일 이름만으로 취약성이 입증되지는 않습니다. 일상적인 열거 과정에서 logfile을 만들지 마세요.

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899)는 호출자가 제어하는 경로 구성 요소가 디렉터리를 탐색해 임의 파일 쓰기로 이어질 수 있었던, 권한 있는 S-nail mail-lock helper에 영향을 미쳤습니다. 현재 사용자가 설치된 root 소유 setuid helper를 실행할 수 있는지, mount 및 프로세스 정책에 따라 setuid identity가 유효한지, 정확한 패키지 빌드와 vendor 수정 사항을 검토하세요. [Ubuntu 보안 공지](https://ubuntu.com/security/notices/USN-4820-1)에는 Ubuntu 16.04 패키지용 backport 수정 사항이 나와 있으므로, upstream 버전처럼 보이는 버전만으로는 결론을 내릴 수 없습니다. helper가 있다는 사실만으로 영향을 받는 경로에 접근 가능하거나 파일 쓰기가 root 실행으로 이어진다고 입증되지는 않습니다. 열거 중에는 helper를 실행하거나 race를 시도하지 말고, 메타데이터와 패키지 상태를 확인하세요.

### snap-confine 및 tmpfiles 정리

CVE-2026-3888은 권한 있는 `snap-confine`과 systemd-tmpfiles의 `/tmp` 정리 작업이 연관된 race입니다. 수동 검토에서는 `snap-confine`이 setuid인지 또는 file capabilities가 있는지 확인하고, 설치된 `snapd` 패키지를 해당 **Ubuntu 릴리스**의 수정 버전과 비교하며, 적용되는 `/tmp` age rule과 정리 timer를 살펴볼 수 있습니다. 패키지와 규칙이 일치하는 것은 전제 조건일 뿐, race에 접근할 수 있다는 증거는 아닙니다. runtime timer 상태, snap 레이아웃, 패키지 backport, 규칙 재정의도 영향을 줍니다. 이전 릴리스에서는 기본값이 아닌 설정이 필요할 수 있습니다. 일상적인 열거 중에는 race probe를 실행하지 마세요. 릴리스별 패키지 상태는 [Ubuntu CVE 기록](https://ubuntu.com/security/CVE-2026-3888)을, 구성 요소 간 상호작용은 [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)를 참조하세요.

## ACL 및 민감한 경로 검사하기

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

쓰기 가능한 상위 디렉터리가 있으면 파일 자체가 root 소유여도 파일을 교체할 수 있습니다. ACL이 sudoers drop-in, 서비스 유닛, cron 스크립트, 라이브러리 경로 또는 자격 증명 파일에 조용히 접근 권한을 부여할 수도 있습니다. ACL과 전체 경로를 모두 확인하세요. 임의의 권한 있는 파일 쓰기가 가능하다면 [Arbitrary File Write to Root](write-to-root.md)를 참고하고, linker 설정 및 preload 사례는 [`ld.so` 예제](ld.so.conf-example.md)를 참고하세요. 노출된 백업 파일, `.env` 파일, 데이터베이스 설정, SSH 자료 및 히스토리를 자격 증명 출처일 가능성이 있는 항목으로 취급하되, 각 파일의 실제 권한을 기준으로 접근 가능 여부를 판단하세요.
{{#include ../../banners/hacktricks-training.md}}
