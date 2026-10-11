# SUID, SGID, ACL 및 민감한 파일

{{#include ../../banners/hacktricks-training.md}}

SUID와 SGID는 실행 파일의 유효 ID를 변경하고, ACL은 일반 `ls -l` 권한 비트에 표시되지 않는 접근 권한을 부여할 수 있습니다. 사용자에게 표시된 소유자 및 그룹 권한보다 더 많은 읽기, 쓰기 또는 실행 권한이 있는 경우 두 가지를 모두 확인하세요.

## 권한이 있는 실행 파일 열거하기

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

사용자 지정 또는 최근 변경된 실행 파일, 비정상적인 소유자, 쓰기 가능한 마운트에 있는 파일에 주목하세요. `nosuid` 마운트는 set-ID 동작을 억제할 수 있습니다. 파일 capabilities는 [Linux capabilities](linux-capabilities.md)에 설명된 별도의 권한 메커니즘입니다. 의심스러운 바이너리를 패키지의 원본과 비교하고, 높은 권한으로 실행될 때 어떤 항목을 실행하고, 열고, 로드하는지 확인하세요.

호출자 입력을 받는 생소한 root 소유 SUID 실행 파일이라면, 바이너리 사본을 오프라인에서 검토해 메모리 안전하지 않은 인자 처리와 해당 코드 경로를 확인하세요. effective-ID 동작과 스택 canary, 비실행 메모리, position-independent code, address randomization 같은 완화 기법을 기록하세요. 안전하지 않은 함수 이름이나 완화 기법의 부재는 검토의 단서일 뿐입니다. 실제 악용 가능성은 입력 크기 제한, 도달 가능한 제어 흐름, 오류 발생 시의 effective identity에 따라 달라집니다. 수동 열거 중 단순히 충돌을 시험하려고 실행 중인 권한 상승 실행 파일에 긴 인자를 전달하지 마세요.

익숙한 SUID 프로그램도 교체되거나 백도어가 심어졌을 수 있습니다. 최근 수정 시각은 단서이지 증거가 아닙니다. **특정 패키지 바이너리가 의심스러운 경우**, 소유 패키지를 확인하고 설치된 파일을 패키지 메타데이터와 비교하세요. 일상적인 열거 중 모든 패키지의 무결성을 검사하지 마세요:

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify`는 패키지 데이터베이스에 체크섬이 기록된 파일의 내용만 검사합니다. RPM은 모드와 소유권 같은 메타데이터도 비교합니다. **권한이 있는 실행 파일 자체**의 불일치에 집중하세요. 설치 공간을 줄인 환경에서는 같은 패키지의 문서나 로케일 파일이 없어도 보고될 수 있습니다. 의심스러운 실행 파일을 신뢰할 수 있는 공급업체 패키지와 비교하고, 정확히 어떤 코드가 변경되었는지 검토하세요. 정당한 로컬 변경, 체크섬 부재, 패키지 메타데이터 손상은 두 명령으로 확인할 수 있는 범위를 제한합니다. 수동 triage의 일부로 의심스러운 SUID 프로그램이나 패키지 검증 스크립트를 실행하지 마세요. [dpkg 검증 매뉴얼](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html)과 [RPM 검증 매뉴얼](https://rpm.org/docs/4.20.x/man/rpm.8)을 참조하세요.

셸, 상대 경로의 명령 또는 쓰기 가능한 경로의 라이브러리를 실행하는 SUID 프로그램은 신뢰 경계를 넘을 수 있습니다. [SUID shared-library 및 linker 악용](suid-shared-library-and-linker-abuse.md), [PATH 안내](../linux-basics/linux-environment-variables.md#path), [user ID 설명](../user-information/euid-ruid-suid.md)을 참조하세요. 특정 명령에서 알려진 탈출 방법은 호스트에서 허용되는 정확한 바이너리와 호출 방식을 기준으로 [GTFOBins](https://gtfobins.github.io/)에서 확인하세요.

set-user-ID 실행 파일에서는 호출자의 **real UID**와 파일 소유자의 **effective UID**를 구분하세요. [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html)는 real UID를 변경하지 않고, set-ID 변경 후 effective UID를 saved UID에 복사합니다. [`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html)은 `/bin/sh -c`를 통해 명령을 실행합니다. 해당 경로에서 선택되는 셸에 따라 자식 프로세스가 effective identity를 유지하는지가 달라집니다. 특히 [Bash privileged-mode 규칙](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)에 따르면, Bash가 `-p` 없이 시작될 때 effective UID와 real UID가 다르면 effective UID를 real UID로 재설정합니다. 실제 helper의 UID 변경과 자식 프로세스 호출 방식, 소유자, 실행 권한, 마운트의 `nosuid` 설정, 프로세스의 `no_new_privs` 상태를 함께 확인하세요. SUID bit나 셸 호출만으로 사용 가능한 고권한 전환이 입증되지는 않습니다.

이례적인 root 소유 SUID `jjs`를 현재 사용자가 실행할 수 있다면, 파일 접근을 별도로 검토할 만합니다. 레거시 Nashorn 도구는 실행된 셸의 effective UID가 낮아지더라도 Java 파일 API에 접근할 수 있습니다. 이를 권한 있는 읽기 또는 쓰기로 판단하기 전에 설치된 JVM의 동작, 파일 작업의 effective identity, `nosuid`/`no_new_privs`를 확인하세요. [Oracle은 JDK 15에서 `jjs`를 제거했습니다](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html). 설치 경로의 바이너리는 이전 버전이거나 별도로 패키징된 빌드일 수 있습니다. [GTFOBins에는 파일 API가 문서화되어 있습니다](https://gtfobins.org/gtfobins/jjs/). 하지만 sudo 예제가 모든 빌드의 SUID 동작을 입증하지는 않습니다. 수동 열거 중에는 이 도구를 실행하지 마세요.

낮은 권한의 사용자가 실행할 수 있는 root 소유 SUID `gosu` 실행 파일은 검토가 필요합니다. 문서화된 인터페이스는 대상 사용자와 명령을 인수로 받지만, 일반적인 컨테이너 사용에서는 root로 시작해 권한을 낮춥니다. 이를 판단하려면 설치된 빌드의 SUID 동작, effective identity와 user-namespace 매핑, `nosuid` 및 `no_new_privs`를 확인하세요. 컨테이너의 root가 호스트의 root를 의미하지는 않습니다. 파일 이름이나 SUID bit만으로 동작하는 권한 전환이 입증되지는 않습니다. [업스트림 사용법](https://github.com/tianon/gosu)과 [관리자의 SUID 경고](https://github.com/tianon/gosu/issues/11)를 참조하세요. 수동 인벤토리 중에는 helper를 실행하지 마세요.

사용자가 선택한 경로를 받아 그 경로를 `system(3)`에 전달하는 아카이브 명령에 삽입하는 사용자 지정 set-user-ID 백업 wrapper는 주의해야 합니다. 구성된 명령에서 해당 경로를 따옴표로 묶지 않으면 자식 셸이 [ `HOME`을 사용한 tilde 확장, `?`와 `*` 같은 경로명 패턴, 줄바꿈을 이용한 명령 분리](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)를 적용할 수 있습니다. 익숙한 문장부호만 denylist로 차단해도 경로가 문자 그대로 처리되는 것은 아닙니다. 정확한 인수 흐름, 상속된 환경, 자식 셸과 effective identity, 파일 시스템 접근, 아카이브 출력이 호출자에게 보이는지를 확인하세요. SUID bit, 아카이브 도구 문자열, `/root`를 직접 지정하지 못하게 차단하는 것만으로는 정보 노출이나 코드 실행이 입증되지 않습니다. 수동 열거 중에는 비공개 파일을 아카이브하거나 충돌을 유발하는 입력을 보내지 말고, wrapper 사본을 오프라인에서 검토하세요.

`$(...)`와 같은 셸 [command substitution](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)도 metacharacter denylist의 또 다른 허점일 수 있습니다. 허용된 명령 접두부가 고정되어 있어도 이후의 호출자 제어 인수가 `/bin/sh -c`를 통해 전달될 수 있습니다. 정확한 quoting, parser, effective identity를 오프라인에서 확인하세요. `system()` 문자열이나 불완전한 denylist만으로 실행을 입증된 것으로 간주하지 마세요.

**호출 프로세스 트리**도 중요합니다. 웹 worker는 UID 변경 시스템 호출을 제한하는 seccomp 필터를 설치할 수 있습니다. [seccomp 필터는 자식 프로세스에 상속되고 `execve` 후에도 유지됩니다](https://docs.kernel.org/userspace-api/seccomp_filter.html). 예를 들어 Apache의 [mpm-itk `LimitUIDRange` 및 `LimitGIDRange` 지시문](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/)은 자손 프로세스가 도달할 수 있는 identity를 제한할 수 있습니다. `/proc/self/status`의 `Seccomp: 2`는 필터 모드를 나타낼 뿐, 정책이나 이 helper가 소유자의 identity를 얻을 수 있는지는 보여주지 않습니다. 실제 호출의 조상 프로세스와 effective filter를 SUID, 마운트, `no_new_privs` 조건과 함께 검토하세요. 별도의 로그인 세션은 다른 정책을 적용받을 수 있지만, 그 세션에 접근할 수 있는 유효한 경로가 따로 필요합니다.

사용자 지정 SUID 실행 파일은 별도로 읽을 수 있는 Python 스크립트를 호출할 수 있습니다. 실제로 Python **2**를 사용한다면 [`input()`은 입력된 식을 평가합니다](https://docs.python.org/2/library/functions.html#input). Python 3의 `input()`은 텍스트를 반환합니다. 소스 코드 한 줄을 실행 경로로 판단하기 전에 wrapper의 effective identity, 인터프리터 경로와 버전, 스크립트 경로, 신뢰할 수 없는 입력이 해당 호출에 도달하는지를 확인하세요. 스크립트 자체의 set-ID bit나 권한 있는 wrapper 없이 사용되는 `input()` 호출만으로는 동일한 경계가 성립하지 않습니다. 열거 중에는 바이너리가 참조하는 경로와 제한된 범위의 스크립트 소스를 검토하되 실행하지 마세요.

이례적인 SUID 실행 파일과 함께 읽을 수 있는 소스가 있다면, 호출자가 제어하는 파일을 읽을 때 요청하는 바이트 수를 대상 버퍼 크기와 비교하고 이후의 제어 흐름 검사를 살펴보세요. [`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html)는 요청한 항목을 지정된 포인터에 저장하며, 대상 객체의 용량은 알지 못합니다. 크기 불일치는 정적 메모리 안전성 검토의 단서일 뿐, 사용 가능한 권한 상승의 증거는 아닙니다. 소스가 설치된 바이너리와 일치하는지, 호출자가 입력을 제공할 수 있는지, 해당 맥락에서 SUID 실행이 유효한지, 관련 경로에 도달할 수 있는지를 확인하세요. 열거 중에는 권한 있는 프로그램에 충돌 입력을 보내지 말고, 제한된 범위의 소스 또는 바이너리 사본을 오프라인에서 검토하세요.

사용자 지정 SUID helper는 내용을 출력하지 않고도 보호된 파일을 노출할 수 있습니다. 호출자가 경로명과 정규식을 모두 선택할 수 있고 helper가 effective UID로 일치 횟수를 반환한다면, 시작 위치를 고정한 prefix 검사를 통해 문자 단위 oracle을 구성할 수 있습니다. helper의 소유자, effective ID 동작, 실행 권한, 경로명 제한, 정규식 의미, 응답의 가시성, 호출자가 다른 방법으로는 읽을 수 없는 구체적인 고권한 파일이 있는지 확인하세요. SUID bit나 정규식 라이브러리 문자열만으로는 이 흐름이 입증되지 않습니다. 수동 열거 중에는 이례적인 실행 파일을 기록하고 제한된 범위의 disassembly 또는 소스 사본을 검토하세요. 실제 helper에 반복적으로 추측값을 보내거나 복구된 비밀을 출력하지 마세요.

OpenBSD에서 호출자가 선택한 경로명을 받는 사용자 지정 set-user-ID reader는 effective identity로 읽을 수 있고 내용을 호출자에게 반환하는 경우 `/var/backups` 아래 파일을 노출할 수 있습니다. [OpenBSD의 `changelist(5)`](https://man.openbsd.org/changelist.5)는 설정된 경로의 `.current` 및 `.backup` 사본을 설명하지만, `+`로 시작하는 항목은 파일 내용이 아니라 SHA-256 체크섬을 저장합니다. 백업 디렉터리는 root 소유이고 모드는 `0700`이어야 합니다. `/var`에 대한 helper의 [`unveil` 읽기 규칙](https://man.openbsd.org/unveil.2)은 해당 경로 아래 접근을 허용할 수 있지만, 그 자체로 파일 접근 권한을 부여하거나 입증하지는 않습니다. 권한 상승을 주장하기 전에 실제 effective UID, 현재 사용자의 실행 권한, 허용되는 경로, 백업의 존재와 내용, 별도의 인증 요건을 확인하세요. 수동 열거에서는 helper와 경로 메타데이터를 보고하고, reader를 실행하거나 백업 데이터를 출력하지 마세요.

사용자가 선택한 경로명을 [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html)으로 확인한 뒤 나중에 그 경로를 여는 사용자 지정 SUID 프로그램은 호출자가 쓰기 가능한 디렉터리에서 파일이나 symlink를 바꾸는 경쟁 상태에 취약할 수 있습니다. 검사는 앞서 확인한 객체에 적용되지만, 이후의 [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html)은 다른 객체를 가리킬 수 있습니다. 이를 확인하려면 helper가 높은 effective identity로 실행 가능한지, 다른 방법으로 도달 가능한 코드 경로가 선택한 파일을 읽는지, 검사와 열기 사이에 호출자가 경로명을 바꿀 수 있는지 확인하세요. SUID bit, 쓰기 가능한 디렉터리, `stat` 문자열만으로는 이 중 어느 것도 입증되지 않습니다. 정보 노출 경로라면 출력이 보이거나 호출자가 읽을 수 있는 대상도 필요합니다. 바이너리와 경로 메타데이터를 오프라인에서 검토하고, 수동 열거 중에 실제 helper를 대상으로 경쟁 상태를 시도하지 마세요.

SGID wrapper에도 같은 의존성 검토를 적용하세요. 절대 경로로 셸이나 helper를 실행하는 wrapper도 낮은 권한의 사용자가 해당 파일을 바꿀 수 있다면 안전하지 않을 수 있습니다. 실행된 코드는 wrapper의 effective group을 상속할 수 있습니다. 호출되는 정확한 경로, ACL을 포함한 쓰기 권한, wrapper의 effective group, 자식 프로세스를 시작하기 전에 권한을 낮추는지를 확인하세요. 인터프리터가 상속된 effective ID를 버릴 수도 있으므로, 검토 대상과 입증된 전환을 구분하세요. 호스트의 다른 곳에 쓰기 가능한 셸이 있다는 사실만으로 권한 있는 wrapper가 그 셸을 호출한다고 입증되지는 않습니다.

### SQLite CLI에 SQL을 전달하는 권한 있는 wrapper

사용자 지정 SUID 프로그램이 사용자가 제어하는 SQL을 **`sqlite3` command-line 프로그램**에 전달한다면, 해당 쿼리를 읽기 전용으로 간주하기 전에 정확한 명령과 effective identity를 살펴보세요. CLI의 `edit()` SQL 함수는 편집기(두 번째 인수 또는 `VISUAL`)를 실행하고, SQL의 `load_extension()` 함수는 확장 로딩이 활성화된 경우 shared library를 로드할 수 있습니다. wrapper가 `PATH`를 고정하거나 절대 경로의 `sqlite3`를 사용하더라도, CLI 프로세스의 identity로 코드 실행이 가능한 경로입니다. SQL이 실제로 해당 함수에 도달하고 CLI에서 관련 기능을 사용할 수 있어야 합니다. 바이너리나 호스트에서 `sqlite3`를 찾았다는 사실만으로 권한 상승이 입증되지는 않습니다. SQLite **library**에서는 확장 로딩이 기본적으로 비활성화되어 있으므로 CLI와 구분하세요. 권한 있는 애플리케이션이 신뢰할 수 없는 SQL을 처리해야 한다면 SQLite CLI의 `--safe` 모드는 `edit()`, `load_extension()` 및 기타 부작용이 있는 함수를 비활성화합니다. [SQLite CLI 문서](https://www.sqlite.org/cli.html#the_edit_sql_function), [safe-mode 문서](https://www.sqlite.org/cli.html#the_safe_command_line_option), [확장 로딩 문서](https://www.sqlite.org/loadext.html#loading_an_extension)를 참조하세요.

### 자세한 출력을 내는 클라이언트에 파일을 전달하는 권한 있는 reader

사용자 지정 SUID/SGID wrapper는 호출자가 선택한 경로명의 접근 권한을 확인한 뒤 해당 파일을 다른 명령에 전달할 수 있습니다. 접근 검사 시점과 이후 파일을 여는 시점의 effective identity를 모두 검토하고, 실제 기준 디렉터리를 기준으로 `../` 구성 요소를 해석하며, 자식 프로세스가 잘못된 입력을 처리하는 방식을 살펴보세요. 데이터베이스 클라이언트가 비공개 파일을 SQL로 읽고 자세한 출력을 내면, SQL이 잘못된 경우에도 오류 메시지에 파일 내용이 반복 출력될 수 있습니다. 자식 프로세스가 호출자가 읽을 수 없는 파일을 읽을 수 있고, 호출자가 wrapper를 통해 그 파일을 선택할 수 있으며, 출력이 호출자에게 보여야만 사용자 간 정보 노출이 성립합니다. `mysql`이나 다른 클라이언트 문자열이 있다는 사실만으로는 이 조건 중 어느 것도 입증되지 않습니다.

### Netdata `ndsudo` 검색 경로

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)는 일부 Netdata `ndsudo` 빌드에 영향을 주었습니다. root 소유 SUID helper는 호출자가 제공한 `PATH`를 사용해 허용된 외부 명령을 검색했습니다. 현재 계정이 실행할 수 있는 경우에만, 호출자가 일반적으로 사용하는 `PATH` 밖에 있는 것을 포함해 설치된 helper를 검토하세요. 소유자, SUID bit, 실행 권한(그룹/ACL 권한 포함), 설치된 빌드와 공급업체 패치 상태, `NoNewPrivs` 또는 `nosuid` 마운트가 identity 변경을 차단하는지 확인하세요. Netdata는 패치된 빌드로 `v1.45.3` 및 `v1.45.0-169`를 제시합니다. 배포판 backport 여부는 별도로 확인해야 합니다. 대시보드 버전이나 `ndsudo`가 있다는 사실만으로 도달 가능한 권한 상승이 입증되지는 않습니다. 이 경로 문제는 helper가 호출자가 제어하는 위치에서 외부 명령을 찾는 경우에만 성립합니다.

### Firejail join 권한 경계

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188)는 Firejail의 권한 있는 `--join` 로직에 영향을 주었습니다. 조작된 join 대상은 setuid-root helper가 공격자 제어 mount namespace를 받아들이고 안전하지 않은 보안 상태를 복사하도록 만들 수 있었습니다. 수동 triage에서는 **현재 identity로** root 소유 setuid Firejail 바이너리를 실행할 수 있는지, 마운트와 프로세스 맥락에서 setuid가 유효한지, 설치된 빌드에 수정 사항이 없는지를 확인하세요. 업스트림은 [0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70)에서 이 문제를 수정했습니다. 배포판 패키지는 [backport](https://github.com/netblue30/firejail/issues/5191)했으면서도 이전 버전을 표시할 수 있습니다. 이러한 전제 조건은 검토 대상을 가려낼 뿐, join 성공이나 root 셸을 입증하지는 않습니다. 열거 중에는 가짜 jail을 만들거나 `--join`을 실행하지 마세요.

### GNU Screen 로그 파일 권한

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html)은 Screen 4.5.0이 호출자가 지정한 로그 파일을 높은 권한으로 열던 문제입니다. SUID 인벤토리에 `screen` 또는 버전 접미사가 붙은 바이너리가 있다는 사실은 검토 단서일 뿐입니다. root 소유 여부, 현재 사용자의 effective SUID 실행 여부, 설치된 빌드와 배포판 패치 상태, 영향을 받는 로그 파일 동작을 확인하세요. [Debian은 backport로 4.5.0 패키지를 수정했습니다](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484). 따라서 버전 문자열이나 파일 이름만으로 취약성이 입증되지는 않습니다. 일반적인 열거 과정에서 로그 파일을 만들지 마세요.

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899)는 호출자가 제어하는 경로 구성 요소가 디렉터리를 순회해 임의 파일 쓰기로 이어질 수 있을 때, 권한 있는 S-nail mail-lock helper에 영향을 주었습니다. 현재 사용자가 설치된 root 소유 setuid helper를 실행할 수 있는지, 마운트 및 프로세스 정책에 따라 setuid identity가 유효한지, 정확한 패키지 빌드와 공급업체 수정 사항을 검토하세요. [Ubuntu 보안 공지](https://ubuntu.com/security/notices/USN-4820-1)에는 16.04 패키지의 backport 수정 사항이 있으므로, 업스트림처럼 보이는 버전만으로는 판단할 수 없습니다. helper가 있다는 사실만으로 영향을 받는 경로에 도달할 수 있거나 파일 쓰기가 root 코드 실행으로 이어진다고 입증되지는 않습니다. 열거 중에는 helper를 실행하거나 경쟁 상태를 시도하지 말고 메타데이터와 패키지 상태를 확인하세요.

### snap-confine 및 tmpfiles 정리

CVE-2026-3888은 권한 있는 `snap-confine`과 systemd-tmpfiles의 `/tmp` 정리 사이에서 발생하는 경쟁 상태입니다. 수동 검토에서는 `snap-confine`에 setuid 또는 file capabilities가 있는지, 설치된 `snapd` 패키지가 해당 **Ubuntu 릴리스**의 수정 버전과 일치하는지, 유효한 `/tmp` age rule과 정리 timer를 확인할 수 있습니다. 패키지와 규칙이 일치하는 것은 전제 조건일 뿐, 경쟁 상태에 도달할 수 있다는 증거는 아닙니다. 런타임 timer 상태, snap 레이아웃, 패키지 backport, 규칙 재정의도 중요합니다. 이전 릴리스에서는 기본값이 아닌 설정이 필요할 수 있습니다. 일반적인 열거 중에는 경쟁 상태 probe를 실행하지 마세요. 릴리스별 패키지 상태는 [Ubuntu CVE 기록](https://ubuntu.com/security/CVE-2026-3888)을, 구성 요소 간 상호작용은 [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)를 참조하세요.

## ACL 및 민감한 경로 검사하기

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

쓰기 가능한 상위 디렉터리가 있으면 파일 자체가 root 소유여도 파일을 교체할 수 있습니다. ACL이 sudoers 추가 설정 파일, 서비스 유닛, cron 스크립트, 라이브러리 경로 또는 자격 증명 파일에 조용히 접근 권한을 부여할 수도 있습니다. ACL과 전체 경로를 모두 확인하세요. 임의의 권한 있는 파일 쓰기가 가능하다면 [Arbitrary File Write to Root](write-to-root.md)를 따르세요. 링커 설정 및 preload 사례는 [`ld.so` example](ld.so.conf-example.md)을 참조하세요. 노출된 백업, `.env` 파일, 데이터베이스 설정, SSH 자료 및 히스토리를 잠재적인 자격 증명 출처로 취급하되, 접근 가능 여부는 각 파일의 실제 권한에 따라 판단하세요.
{{#include ../../banners/hacktricks-training.md}}
