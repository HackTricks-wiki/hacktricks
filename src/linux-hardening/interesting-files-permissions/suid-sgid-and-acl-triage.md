# SUID, SGID, ACL 및 민감한 파일

{{#include ../../banners/hacktricks-training.md}}

SUID와 SGID는 실행된 파일의 유효 사용자 ID를 변경하며, ACL은 일반 `ls -l`의 권한 비트에 표시되지 않는 접근 권한을 부여할 수 있습니다. 사용자가 표시된 소유자 및 그룹 권한보다 더 많은 읽기, 쓰기 또는 실행 권한을 가질 수 있다면 두 항목을 모두 검토하세요.

## 권한이 있는 실행 파일 열거하기

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

사용자 지정 또는 최근 변경된 실행 파일, 특이한 소유자, 쓰기 가능한 마운트에 있는 파일에 집중하세요. `nosuid` 마운트는 set-ID 동작을 억제할 수 있습니다. 파일 capabilities는 [Linux capabilities](linux-capabilities.md)에 설명된 별도의 권한 메커니즘입니다. 의심스러운 바이너리를 해당 패키지와 비교하고, 높은 권한으로 어떤 명령을 실행하거나, 파일을 열거나, 라이브러리를 로드하는지 확인하세요.

호출자가 입력값을 전달할 수 있는, 익숙하지 않은 root 소유 SUID 실행 파일이라면 바이너리 복사본을 오프라인에서 검토해 메모리 안전하지 않은 인자 처리와 해당 코드에 도달하는 경로를 확인하세요. 유효 ID 동작과 스택 카나리, 비실행 메모리, 위치 독립 코드, 주소 무작위화 같은 완화 기법을 기록하세요. 안전하지 않은 함수 이름이나 완화 기법의 부재는 검토의 단서일 뿐입니다. 실제 악용 가능성은 입력값의 실제 범위, 도달 가능한 제어 흐름, 오류 발생 시의 유효 ID에 달려 있습니다. 수동 열거 중 단순히 충돌을 테스트하려고 긴 인자를 실제 권한 있는 실행 파일에 전달하지 마세요.

익숙한 SUID 프로그램도 교체되거나 백도어가 삽입되었을 수 있습니다. 최근 수정 시간은 단서이지 증거가 아닙니다. **특정 의심 패키지 바이너리**의 경우, 소유 패키지를 확인하고 설치된 파일을 패키지 메타데이터와 비교하세요. 일상적인 열거 중 모든 패키지를 검증하지는 마세요:

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify`는 패키지 데이터베이스에 체크섬이 기록된 파일의 내용만 확인합니다. RPM은 모드와 소유권 같은 메타데이터도 비교합니다. **권한이 있는 실행 파일 자체**의 불일치에 집중하세요. 설치 과정에서 문서나 로케일 파일이 제거되면 같은 패키지의 다른 파일에서 누락 항목이 보고될 수 있습니다. 의심스러운 실행 파일을 신뢰할 수 있는 공급업체 패키지와 비교하고, 변경된 코드를 정확히 검토하세요. 정당한 로컬 변경, 체크섬 부재, 손상된 패키지 메타데이터 때문에 두 명령으로 입증할 수 있는 범위는 제한됩니다. 수동 triage 중에는 의심스러운 SUID 프로그램이나 패키지 검증 스크립트를 실행하지 마세요. [dpkg 검증 매뉴얼](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html)과 [RPM 검증 매뉴얼](https://rpm.org/docs/4.20.x/man/rpm.8)을 참조하세요.

셸, 상대 경로 명령 또는 쓰기 가능한 경로의 라이브러리를 호출하는 SUID 프로그램은 신뢰 경계를 넘을 수 있습니다. [SUID shared-library 및 linker 악용](suid-shared-library-and-linker-abuse.md), [PATH 안내](../linux-basics/linux-environment-variables.md#path), [user-ID 설명](../user-information/euid-ruid-suid.md)을 참조하세요. 알려진 명령별 탈출 기법은 [GTFOBins](https://gtfobins.github.io/)에서 해당 호스트에서 허용되는 정확한 바이너리와 호출 방식을 확인하세요.

set-user-ID 실행 파일에서는 호출자의 **real UID**와 파일 소유자의 **effective UID**를 구분하세요. [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html)는 real UID를 그대로 두고, set-ID 변경 후 effective UID를 saved UID로 복사합니다. [`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html)은 `/bin/sh -c`를 통해 명령을 실행합니다. 해당 경로에서 선택된 셸에 따라 자식 프로세스가 effective identity를 유지하는지가 달라집니다. 특히 [Bash privileged-mode 규칙](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)에 따르면 Bash가 `-p` 없이 시작되면 effective UID가 real UID와 다를 경우 effective UID를 real UID로 재설정합니다. 실제 helper의 UID 변경과 자식 프로세스 호출 방식, 소유자, 실행 권한, 마운트의 `nosuid` 설정, 프로세스의 `no_new_privs` 상태를 함께 확인하세요. SUID 비트나 셸 호출만으로 사용 가능한 상위 권한 전환이 입증되지는 않습니다.

특이한 root 소유 SUID `jjs`가 있고 현재 사용자가 실행할 수 있다면 별도로 파일 접근을 검토해야 합니다. 레거시 Nashorn 도구는 생성된 셸의 effective UID가 강등되더라도 Java 파일 API에 접근할 수 있습니다. 이를 권한 있는 읽기 또는 쓰기로 간주하기 전에 설치된 JVM의 동작, 파일 작업 시 effective identity, `nosuid`/`no_new_privs`를 확인하세요. [Oracle은 JDK 15에서 `jjs`를 제거했습니다](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html). 설치 경로에는 이전 버전이나 별도로 패키징된 빌드가 남아 있을 수 있습니다. [GTFOBins는 파일 API를 설명합니다](https://gtfobins.org/gtfobins/jjs/). 하지만 해당 sudo 예시는 모든 빌드에서 SUID 동작이 가능하다는 증거가 아닙니다. 수동 열거 중에는 이 도구를 실행하지 마세요.

하위 권한 사용자가 접근할 수 있는 root 소유 SUID `gosu` 실행 파일은 검토할 가치가 있습니다. 문서화된 인터페이스는 대상 사용자와 명령을 받지만, 일반적인 컨테이너 사용에서는 root로 실행해 권한을 강등합니다. 권한 전환을 입증하기 전에 설치된 빌드의 SUID 동작, effective identity와 user-namespace 매핑, `nosuid`, `no_new_privs`를 확인하세요. 컨테이너의 root가 호스트의 root를 뜻하지는 않습니다. 파일명이나 SUID 비트만으로 실제 권한 전환이 입증되지는 않습니다. [upstream 사용법](https://github.com/tianon/gosu)과 [maintainer의 SUID 경고](https://github.com/tianon/gosu/issues/11)를 참조하세요. 수동 인벤토리 중에는 helper를 실행하지 마세요.

사용자 정의 set-user-ID 백업 wrapper가 호출자가 선택한 경로를 받아 아카이브 명령에 삽입한 뒤 `system(3)`에 전달할 수 있습니다. 구성된 명령에서 경로를 따옴표로 감싸지 않으면 자식 셸이 [tilde 확장(`HOME` 사용), `?` 및 `*` 같은 경로명 패턴, 개행을 통한 명령 분리](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)를 적용할 수 있습니다. 익숙한 문장부호만 거부 목록으로 차단해도 경로가 리터럴로 처리되는 것은 아닙니다. 수동 열거 중에는 정확한 인자 흐름, 상속된 환경 변수, 자식 셸과 effective identity, 파일시스템 접근, 아카이브 출력이 호출자에게 보이는지를 확인하세요. SUID 비트, 아카이브 도구 문자열, `/root` 리터럴 차단만으로는 정보 공개나 코드 실행이 입증되지 않습니다. 비공개 파일을 아카이브하거나 충돌 입력을 보내는 대신 wrapper 사본을 오프라인에서 검토하세요.

`$(...)` 같은 셸 [명령 치환](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)도 메타문자 거부 목록의 잠재적인 누락 지점입니다. 허용된 명령 접두부가 고정되어 있어도 이후 호출자 제어 인자가 `/bin/sh -c`를 거쳐 전달될 수 있습니다. 정확한 인용 처리, 파서, effective identity를 오프라인에서 확인하세요. `system()` 문자열이나 불완전한 거부 목록만으로 실행을 입증된 것으로 간주하지 마세요.

**호출 프로세스 트리**도 중요합니다. 웹 worker는 UID 변경 시스템 호출을 제한하는 seccomp filter를 설치할 수 있습니다. [seccomp filter는 자식 프로세스에 전달되며 `execve` 후에도 유지됩니다](https://docs.kernel.org/userspace-api/seccomp_filter.html). 예를 들어 Apache의 [mpm-itk `LimitUIDRange` 및 `LimitGIDRange` 지시어](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/)는 하위 프로세스가 사용할 수 있는 identity를 제한할 수 있습니다. `/proc/self/status`의 `Seccomp: 2`는 필터 모드만 보여줄 뿐, 정책이나 해당 helper가 소유자의 identity를 얻을 수 있는지는 알려주지 않습니다. 실제 호출의 조상 프로세스와 effective filter를 SUID, 마운트, `no_new_privs` 조건과 함께 검토하세요. 별도의 로그인 세션에는 다른 정책이 적용될 수 있지만, 해당 세션으로 접근할 수 있는 유효한 경로가 별도로 필요합니다.

사용자 정의 SUID 실행 파일이 별도로 읽을 수 있는 Python 스크립트를 호출할 수 있습니다. 실제로 Python **2**를 사용한다면 [`input()`은 입력한 표현식을 평가합니다](https://docs.python.org/2/library/functions.html#input). Python 3의 `input()`은 텍스트를 반환합니다. 소스 코드 한 줄을 실행 경로로 간주하기 전에 wrapper의 effective identity, 인터프리터 경로와 버전, 스크립트 경로, 신뢰할 수 없는 입력이 해당 호출에 도달하는지 확인하세요. 스크립트 자체의 set-ID 비트나 권한 있는 wrapper 없이 사용되는 `input()` 호출은 같은 경계를 형성하지 않습니다. 열거 중에는 바이너리가 참조하는 경로와 제한된 범위의 스크립트 소스를 검토하되 실행하지 마세요.

특이한 SUID 실행 파일과 함께 읽을 수 있는 소스가 있다면, 호출자가 제어하는 각 파일 읽기의 요청 바이트 수를 대상 버퍼 크기와 비교하고 이후의 제어 흐름 검사를 살펴보세요. [`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html)은 지정된 포인터에 요청한 항목을 저장할 뿐, 대상 객체의 용량은 알지 못합니다. 크기 불일치는 정적 메모리 안전성 검토의 단서이지, 사용 가능한 권한 상승의 증거는 아닙니다. 소스가 설치된 바이너리와 일치하는지, 호출자가 입력을 제공할 수 있는지, 해당 맥락에서 SUID 실행이 유효한지, 관련 경로에 도달할 수 있는지 확인하세요. 열거 중에는 권한 있는 프로그램에 충돌 입력을 보내지 말고, 제한된 범위의 소스나 바이너리 사본을 오프라인에서 검토하세요.

사용자 정의 SUID helper는 내용을 출력하지 않고도 보호된 파일을 노출할 수 있습니다. 호출자가 경로명과 정규식을 모두 선택하고 helper가 effective UID로 일치 항목 수를 반환한다면, 시작 부분에 고정된 패턴 검사가 문자 단위 oracle을 구성할 수 있습니다. 해당 helper의 소유자, effective-ID 동작, 실행 접근 권한, 경로 제한, 정규식 의미, 응답의 가시성, 호출자가 다른 방법으로는 읽을 수 없는 특정 상위 권한 파일을 확인하세요. SUID 비트나 정규식 라이브러리 문자열만으로는 이러한 흐름이 입증되지 않습니다. 수동 열거 중에는 특이한 실행 파일을 기록하고 제한된 범위의 디스어셈블리나 소스 사본을 검토하세요. 실행 중인 helper에 반복적으로 추측값을 넣거나 복구한 비밀을 출력하지 마세요.

OpenBSD에서 호출자가 선택한 경로명을 받는 사용자 정의 set-user-ID reader는 effective identity로 읽을 수 있는 `/var/backups` 아래 파일을 호출자에게 반환할 수 있습니다. [OpenBSD의 `changelist(5)`](https://man.openbsd.org/changelist.5)는 설정된 경로의 `.current` 및 `.backup` 사본을 설명하지만, `+` 접두사가 붙은 항목에는 파일 내용이 아니라 SHA-256 체크섬이 저장됩니다. 백업 디렉터리의 소유자는 root여야 하며 모드는 `0700`이어야 합니다. `/var`에 대한 helper의 [`unveil` 읽기 규칙](https://man.openbsd.org/unveil.2)은 해당 경로 아래의 접근을 허용할 수 있지만, 그 자체로 파일 접근을 부여하거나 입증하지는 않습니다. 권한 상승을 주장하기 전에 실제 effective UID, 현재 사용자의 실행 권한, 허용되는 경로, 백업의 존재 여부와 내용, 별도의 인증 요건을 확인하세요. 수동 열거에서는 helper와 경로 메타데이터를 보고하되 reader를 실행하거나 백업 데이터를 출력하지 마세요.

호출자가 선택한 경로명을 [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html)으로 확인한 뒤 나중에 여는 사용자 정의 SUID 프로그램은 호출자가 쓸 수 있는 디렉터리에서 파일이나 심볼릭 링크가 바뀌는 경쟁 상태에 취약할 수 있습니다. 검사는 이전 객체에 적용되지만, 나중의 [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html)은 다른 객체를 확인할 수 있습니다. SUID 비트, 쓰기 가능한 디렉터리, `stat` 문자열만으로는 아무것도 입증되지 않습니다. helper가 상승된 effective identity로 실행 가능한지, 도달 가능한 코드 경로가 선택한 파일을 읽는지, 호출자가 검사와 열기 사이에 경로명을 바꿀 수 있는지 확인하세요. 정보 공개 경로라면 출력이 보이거나 호출자가 읽을 수 있는 대상도 필요합니다. 실행 중인 helper에 경쟁 상태를 유발하지 말고 바이너리와 경로 메타데이터를 오프라인에서 검토하세요.

SGID wrapper에도 같은 의존성 검토를 적용하세요. 셸이나 helper를 절대 경로로 실행하는 wrapper라도 하위 권한 사용자가 해당 파일을 바꿀 수 있으면 안전하지 않을 수 있습니다. 생성된 코드는 wrapper의 effective group을 상속할 수 있습니다. 정확한 호출 경로, ACL을 포함한 쓰기 권한, wrapper의 effective group, 자식 프로세스를 실행하기 전에 권한을 강등하는지 확인하세요. 인터프리터가 상속된 effective ID를 버릴 수도 있으므로 검토 대상과 실제 권한 전환을 구분하세요. 호스트 어딘가에 쓰기 가능한 셸이 있다는 사실만으로 권한 있는 wrapper가 그 셸을 호출한다고 입증되지는 않습니다.

### SQLite CLI에 SQL을 전달하는 권한 있는 wrapper

사용자 정의 SUID 프로그램이 사용자 제어 SQL을 **`sqlite3` 명령줄 프로그램**에 전달한다면, 해당 쿼리를 읽기 전용으로 간주하기 전에 정확한 명령과 effective identity를 확인하세요. CLI의 `edit()` SQL 함수는 편집기(두 번째 인자 또는 `VISUAL`)를 호출하며, SQL `load_extension()` 함수는 확장 로딩이 활성화되어 있을 때 공유 라이브러리를 로드할 수 있습니다. wrapper가 `PATH`를 고정하거나 절대 경로의 `sqlite3`를 사용하더라도 CLI 프로세스의 identity로 코드 실행이 발생할 가능성이 있습니다. SQL이 실제로 해당 함수에 전달되어야 하며 CLI에서 관련 기능이 유지되어 있어야 합니다. 바이너리나 호스트에서 `sqlite3`를 찾았다는 사실만으로 권한 상승이 입증되지는 않습니다. SQLite **library**는 기본적으로 확장 로딩이 비활성화되어 있으므로 CLI와 구분하세요. 권한 있는 애플리케이션이 신뢰할 수 없는 SQL을 처리해야 한다면 SQLite CLI의 `--safe` 모드는 `edit()`, `load_extension()` 및 기타 부작용을 일으키는 함수를 비활성화합니다. [SQLite CLI 문서](https://www.sqlite.org/cli.html#the_edit_sql_function), [safe-mode 문서](https://www.sqlite.org/cli.html#the_safe_command_line_option), [확장 로딩 문서](https://www.sqlite.org/loadext.html#loading_an_extension)를 참조하세요.

### 상세 출력을 내는 클라이언트에 파일을 전달하는 권한 있는 reader

사용자 정의 SUID/SGID wrapper는 호출자가 선택한 경로의 접근 권한을 확인한 뒤 해당 파일을 다른 명령에 전달할 수 있습니다. 접근 확인과 이후 파일 열기 시점의 effective identity를 검토하고, `../` 구성 요소가 실제 기준 디렉터리에 대해 어떻게 해석되는지 확인하며, 자식 프로세스가 잘못된 입력을 처리하는 방식도 살펴보세요. 데이터베이스 클라이언트가 비공개 파일을 SQL로 읽고 상세 출력을 내면 SQL이 유효하지 않더라도 오류에 파일 내용을 표시할 수 있습니다. 자식 프로세스가 호출자가 읽을 수 없는 파일을 읽을 수 있고, 호출자가 wrapper를 통해 해당 파일을 선택할 수 있으며, 출력이 호출자에게 보여야만 사용자 간 정보 공개가 성립합니다. `mysql` 또는 다른 클라이언트 문자열이 있다는 사실만으로는 이러한 조건이 입증되지 않습니다.

### Netdata `ndsudo` 검색 경로

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)는 일부 Netdata `ndsudo` 빌드에 영향을 주었습니다. root 소유 SUID helper는 호출자가 제공한 `PATH`를 사용해 허용된 외부 명령을 검색했습니다. 설치된 helper가 호출자의 일반적인 `PATH` 밖에 있더라도 현재 계정이 실행할 수 있는 경우 검토하세요. 소유자, SUID 비트, 그룹/ACL 권한을 포함한 실행 접근 권한, 설치된 빌드와 공급업체 패치 상태, `NoNewPrivs` 또는 `nosuid` 마운트가 identity 변경을 막는지 확인하세요. Netdata는 패치된 빌드로 `v1.45.3`과 `v1.45.0-169`을 제시합니다. 배포판의 backport 여부는 별도로 확인해야 합니다. 대시보드 버전이나 `ndsudo`의 존재만으로는 접근 가능한 권한 상승이 입증되지 않습니다. 경로 문제로 권한 상승이 가능하려면 helper가 호출자가 제어하는 위치에서 외부 명령을 찾아야 합니다.

### Firejail join 권한 경계

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188)는 Firejail의 권한 있는 `--join` 로직에 영향을 주었습니다. 조작된 join 대상이 setuid-root helper로 하여금 공격자가 제어하는 mount namespace를 받아들이고 안전하지 않은 보안 상태를 복사하게 만들 수 있었습니다. 수동 triage에서는 **현재 identity가** root 소유 setuid Firejail 바이너리를 실행할 수 있는지, 마운트와 프로세스 맥락에서 setuid가 유효한지, 설치된 빌드에 수정 사항이 없는지 확인하세요. upstream은 [0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70)에서 문제를 수정했습니다. 배포판 패키지는 [backport](https://github.com/netblue30/firejail/issues/5191)했으면서 이전 버전을 표시할 수 있습니다. 이러한 전제 조건은 검토 대상임을 나타낼 뿐, 성공적인 join이나 root 셸을 입증하지는 않습니다. 열거 중에는 가짜 jail을 만들거나 `--join`을 호출하지 마세요.

### GNU Screen 로그 파일 권한

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html)은 Screen 4.5.0이 호출자가 지정한 로그 파일을 상승된 권한으로 열던 문제입니다. SUID 인벤토리에서 `screen` 또는 버전이 붙은 바이너리를 찾는 것은 검토 단서일 뿐입니다. root 소유인지, 현재 사용자에게 effective SUID 실행이 가능한지, 설치된 빌드와 배포판 패치 상태가 어떤지, 취약한 로그 파일 동작이 있는지 확인하세요. [Debian은 backport를 통해 4.5.0 패키지를 수정했습니다](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484). 따라서 버전 문자열이나 파일명만으로는 취약성이 입증되지 않습니다. 일반적인 열거 과정에서 로그 파일을 만들지 마세요.

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899)는 호출자가 제어하는 경로 구성 요소가 디렉터리를 탐색해 임의 파일 쓰기로 이어질 수 있었던, 권한 있는 S-nail mail-lock helper에 영향을 주었습니다. 현재 사용자가 설치된 root 소유 setuid helper를 실행할 수 있는지, 마운트 및 프로세스 정책에서 setuid identity가 유효한지, 정확한 패키지 빌드와 공급업체 수정 사항이 무엇인지 검토하세요. [Ubuntu 보안 공지](https://ubuntu.com/security/notices/USN-4820-1)에는 16.04 패키지용 backport 수정이 나와 있으므로 upstream 버전처럼 보이는 문자열만으로는 판단할 수 없습니다. helper가 있다는 사실만으로 취약한 경로에 도달할 수 있거나 파일 쓰기가 root 코드 실행으로 이어진다고 입증되지는 않습니다. 열거 중에는 helper를 실행하거나 경쟁 상태를 시도하지 말고 메타데이터와 패키지 상태를 확인하세요.

### snap-confine 및 tmpfiles 정리

CVE-2026-3888은 권한 있는 `snap-confine`과 `/tmp`의 systemd-tmpfiles 정리 작업 간 경쟁 상태입니다. 수동 검토에서는 `snap-confine`이 setuid인지 또는 파일 capability가 있는지 확인하고, 설치된 `snapd` 패키지를 해당 **Ubuntu 릴리스**의 수정 버전과 비교하며, 유효한 `/tmp` 보존 기간 규칙과 정리 timer를 살펴볼 수 있습니다. 패키지와 규칙이 일치하는 것은 전제 조건일 뿐, 경쟁 상태에 도달 가능하다는 증거는 아닙니다. 런타임 timer 상태, snap 레이아웃, 패키지 backport, 규칙 재정의도 고려해야 합니다. 이전 릴리스는 기본값이 아닌 설정이 필요할 수 있습니다. 일반적인 열거 중에는 경쟁 상태를 시험하지 마세요. 릴리스별 패키지 상태는 [Ubuntu CVE 기록](https://ubuntu.com/security/CVE-2026-3888)을, 구성 요소 간 상호작용은 [Qualys 권고문](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)을 참조하세요.

## ACL 및 민감한 경로 확인

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

쓰기 가능한 상위 디렉터리가 있으면 파일 자체가 root 소유여도 파일을 교체할 수 있습니다. ACL이 sudoers drop-in 파일, 서비스 유닛, cron 스크립트, 라이브러리 경로 또는 자격 증명 파일에 대한 접근 권한을 조용히 부여할 수 있습니다. ACL과 전체 경로를 모두 확인하세요. 권한이 있는 파일을 임의로 쓸 수 있다면 [Arbitrary File Write to Root](write-to-root.md)를 참고하세요. 링커 설정 및 preload 사례는 [`ld.so` example](ld.so.conf-example.md)을 참고하세요. 노출된 백업 파일, `.env` 파일, 데이터베이스 설정, SSH 자료 및 셸 기록은 잠재적인 자격 증명 출처로 간주하되, 접근 가능 여부는 각 파일의 실제 권한에 따라 판단하세요.
{{#include ../../banners/hacktricks-training.md}}
