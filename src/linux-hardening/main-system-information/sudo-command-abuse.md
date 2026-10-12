# Sudo 명령어 악용

{{#include ../../banners/hacktricks-training.md}}

## Sudo가 허용하는 인터프리터

`sudo -l`에서 사용자가 root 권한으로 인터프리터를 실행할 수 있다면, 이를 직접적인 코드 실행으로 간주하세요. 인터프리터는 임의의 코드를 실행하도록 설계되어 있으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 유사한 바이너리의 실행을 허용하는 규칙은 인수가 엄격하게 제한되고 검증되지 않는 한 대개 root 명령 실행과 동일합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

일반적인 검토 절차: 먼저 사용자의 권한을 확인한 다음, 인터프리터의 `-c` 옵션을 사용해 Python 문을 실행합니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

다른 인터프리터 예시는 아래와 같으며, 나열된 인터프리터의 문서에는 인라인 코드 실행 또는 자식 프로세스 API가 설명되어 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

정확한 경로가 중요합니다. sudo 규칙이 `/usr/bin/python3`을 허용한다면, 검증할 때도 해당 경로를 그대로 사용하세요.<sup>[[2]](#references)</sup>

`/usr/bin/python*`와 같은 sudo 실행 파일 glob은 Python 3용으로 작성된 스크립트에 Python 2도 허용할 수 있습니다. 호출자가 제어하는 텍스트로 `input()`에 도달하는 경우, [Python 2는 해당 텍스트를 표현식으로 평가합니다](https://docs.python.org/2/library/functions.html#input). 인터프리터를 명시적으로 호출하면 스크립트의 shebang은 무시됩니다. 이를 실행 경로로 간주하기 전에 설치된 일치 바이너리, 유효한 RunAs 및 인자 정책, 거부 규칙, 도달 가능한 입력 지점을 확인하세요.

root 권한으로 실행할 수 있는 sudo 규칙에 스크립트 경로가 고정되어 있어도 스크립트가 실행하는 내용까지 제한되는 것은 아닙니다. 읽을 수 있는 Bash 래퍼라면 sudo가 호출자 지정 인자를 허용하는 상황에서 첫 번째 실행 명령이 `$1`과 같은 인용되지 않은 위치 매개변수를 **명령어**로 사용하는지 확인하세요. 실제 결과는 유효한 RunAs ID, 비밀번호 및 인자 정책, 이후의 거부 규칙, 실제 스크립트 분기에 따라 달라질 수 있습니다. `NOEXEC`, 고정된 안전 인자 목록 또는 명령어를 검증하는 래퍼도 결과를 바꿀 수 있습니다. 열거 중에는 테스트 명령으로 실행하지 말고 짧은 스크립트를 정적으로 검사하세요.

제한 없이 root 권한으로 실행할 수 있는 `dotnet` sudo 규칙도 인터프리터 관점에서 검토할 필요가 있습니다. .NET SDK가 설치되어 있다면 [`dotnet fsi`는 F# 코드를 대화형으로 실행하거나 스크립트에서 실행합니다](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/). 또한 [`dotnet run`은 소스에서 프로젝트를 실행합니다](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run). 먼저 유효한 RunAs ID와 정확한 인자 정책을 확인하세요. 특정 안전한 하위 명령이나 신뢰할 수 있는 애플리케이션으로 고정된 규칙은 권한 부여 내용이 다르며, 런타임 전용 설치에는 SDK 명령이 없을 수 있습니다. 실행 파일 이름은 검토할 단서일 뿐, 코드 실행의 증거는 아닙니다.

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed `tee`: 임의의 권한 파일 쓰기

GNU `tee`는 표준 입력을 파일 피연산자로 지정된 모든 경로에 복사합니다. 따라서 호출자가 인수를 제어할 수 있는 상태에서 `/usr/bin/tee`를 root로 실행하도록 허용하는 sudo 규칙은 임의의 파일을 root 권한으로 생성하거나 덮어쓸 수 있는 기능을 부여합니다. `-a`를 추가하면 파일에 내용을 덧붙이는 기능으로 바뀝니다. `PASSWD:` 태그는 sudo 인증과 관련이 있으며, 그 자체로 대상 경로나 표준 입력에서 읽어 들이는 바이트를 제한하지 않습니다.<sup>[[2]](#references)[[27]](#references)[[28]](#references)</sup>

먼저 정확한 규칙을 확인하세요. 승인된 테스트 시스템에서 안전하게 생성할 수 있는 임시 대상에만 이 기능이 동작하는지 검증하세요. 마지막의 `>/dev/null`은 `tee`가 표준 출력으로 복사하는 내용만 억제합니다.<sup>[[28]](#references)</sup>

```bash
sudo -l
printf '%s\n' 'controlled-write' | sudo /usr/bin/tee /root/tee-proof >/dev/null
printf '%s\n' 'appended-line' | sudo /usr/bin/tee -a /root/tee-proof >/dev/null
```

`sudo`를 producer 앞에 붙여도 뒤에 오는 shell redirection의 권한은 상승하지 않습니다. 대상 파일을 여는 것은 호출자의 shell이기 때문입니다. 위 파이프라인처럼 권한이 상승된 프로세스가 writer여야 합니다.<sup>[[1]](#references)[[15]](#references)</sup>

쓰기 작업을 확인한 뒤 [Arbitrary File Write to Root](../interesting-files-permissions/write-to-root.md)에서 적절한 root-code-execution sink를 선택합니다. 관찰된 한 체인에서는 root `tee`로 `/etc/cron.d/` 아래에 수명이 짧은 파일을 만들고, 사용자가 제어하는 스크립트를 통해 백도어를 실행한 뒤 실행 후 cron 파일을 삭제했습니다. cron 파일을 삭제하면 장기적인 persistence 항목으로 남는 것을 막을 수 있지만, 시스템 로그에는 여전히 해당 활동의 흔적이 남았습니다.<sup>[[27]](#references)</sup>

## Sudo-allowed editors

`sudo -l`에서 사용자가 root 권한으로 대화형 editor를 실행할 수 있다고 나오면, 이를 무해한 파일 편집 권한이 아니라 command-execution surface로 취급합니다. Editor에서는 shell command를 실행하거나, 임의의 파일을 읽고 쓰거나, editor 내부에서 외부 helper를 호출할 수 있는 경우가 많습니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

일반적인 점검 흐름: 사용자의 권한을 확인한 다음, sudo로 허용된 각 editor 또는 pager를 실행합니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nano 명령 실행

`nano`를 sudo로 실행할 수 있으면 편집기 인터페이스에서 명령을 실행할 수 있습니다.<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

그런 다음 `id` 또는 `/bin/sh`와 같은 명령을 nano 명령 프롬프트에 입력합니다.<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

대화형 셸에 사용할 수 있는 터미널 스트림이 없으면, 이 리디렉션 형식은 표준 출력과 표준 오류를 디스크립터 0에 매핑합니다.<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

nano 버전과 빌드 옵션에 따라 정확한 키 입력 순서는 달라질 수 있지만, 보안 문제는 동일합니다. 편집기가 root 권한으로 실행 중이며 외부 명령을 호출할 수 있습니다.<sup>[[1]](#references)[[12]](#references)</sup>

### 다른 일반적인 편집기 탈출 방법

Vim 계열 편집기는 일반적으로 `:!`를 통해 명령을 실행할 수 있습니다.<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

`less`와 같은 pager도 셸 실행을 노출할 수 있습니다.<sup>[[14]](#references)</sup>

root 권한으로 `apport-cli`를 실행하도록 허용하는 sudo 규칙이 있다면 pager도 동일하게 검토해야 합니다. 영향을 받는 Apport 버전에서는 공격자가 조정할 수 있는 터미널 크기로 `less`에서 crash report를 열 수 있었으며, 특수한 sudo 및 pager 조건이 충족되면 pager를 통해 root shell을 얻을 수 있었습니다. 버전만으로 취약하다고 판단하기 전에 유효한 sudo 규칙, pager 설정, 배포판 패키지 수정 여부를 확인하세요. 수동 열거 중에는 crash를 발생시키거나 권한이 높은 report를 열지 말고 패키지 및 정책 메타데이터를 읽으세요. [Ubuntu의 CVE 기록](https://ubuntu.com/security/CVE-2023-1326)에는 backported fix를 포함한 릴리스별 수정 패키지 버전이 나와 있습니다.

```text
!/bin/sh
```

## 기타 sudo 및 doas 규칙의 위험 요소

먼저 `sudo -l`, `sudo -V` 및 해당하는 `doas` 정책을 확인합니다. 허용된 명령, 실행 대상 사용자, 인수, 환경 및 기본값을 함께 살펴봅니다. root가 아닌 서비스 계정으로 실행할 권한만 있어도 해당 계정의 파일에 접근하거나 root 권한으로 이어지는 경로를 찾을 수 있습니다.

sudo에서 허용한 고정 Python 스크립트도 대화형 사용자 입력을 [`os.system()`](https://docs.python.org/3/library/os.html#os.system)에 연결하면 RunAs 사용자 권한으로 셸 명령을 실행할 수 있습니다. 셸 문장부호 denylist만으로 안전성을 입증할 수는 없습니다. [셸은 `$(...)` 명령 치환도 인식합니다](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html). 허용된 인수가 입력을 처리하는 분기에 도달하는지, 입력이 안전한 검증 없이 셸 명령에 전달되는지, 유효한 sudo 정책이 의도한 RunAs 사용자를 허용하는지 확인합니다. 스크립트 경로나 `os.system()` 호출만으로는 검토 단서일 뿐입니다. 권한 있는 스크립트를 실행하지 말고 소스 코드를 살펴봅니다.

`chattr`에 대한 유효한 root sudo 권한으로 immutable (`i`) 파일 속성을 해제할 수는 있지만, 이것만으로 쓰기 권한이나 새로운 사용자 ID가 주어지지는 않습니다. [`chattr` 매뉴얼](https://man7.org/linux/man-pages/man1/chattr.1.html)에 따르면 해당 속성은 수정을 막으며, root 또는 `CAP_LINUX_IMMUTABLE` 권한이 있는 프로세스만 변경할 수 있습니다. 정확한 sudo 인수 정책과 파일시스템 지원 여부를 확인한 다음, 속성을 해제한 뒤 호출자가 파일에 쓸 수 있는지, 더 높은 권한의 프로세스가 해당 파일을 사용하는지 별도로 검증합니다. 예를 들어 로그인 셸을 바꾸려면 대상 계정의 유효한 자격 증명과 해당 셸을 통한 실제 로그인이 필요합니다. 열거 중에는 정책, 파일 속성 및 권한을 변경하지 말고 검토합니다.

sudo가 비밀번호와 일회용 코드 모두를 요구한다면, 이 전제 조건은 명령 권한과 별도로 다룹니다. 읽을 수 있는 `.google_authenticator` 파일에는 민감한 seed 자료가 들어 있지만, 오래된 애플리케이션 또는 데이터베이스 비밀번호 해시는 현재 계정 비밀번호의 후보일 뿐입니다. 어느 쪽도 유효한 PAM 설정에서 다른 인증 요소가 허용된다는 사실을 입증하지 않습니다. 권한이 있는 경우 정확한 RunAs 사용자와 인수를 검토합니다. RubyGems `gem`에 대한 제한 없는 root 권한은 편집기 명령을 노출할 수 있지만([GTFOBins](https://gtfobins.github.io/gtfobins/gem/)), 제한된 권한이나 인증 실패로는 그렇지 않습니다. 수동 열거에서는 seed를 출력하거나, 비밀번호를 복구하거나, 코드를 생성하거나, 권한 있는 명령을 실행하지 말고 경로와 정책만 보고합니다.

Chef의 `knife`에 대한 제한 없는 root 가능 sudo 권한은 인터프리터 수준에서 검토해야 합니다. [Chef 문서에 따르면 `knife exec -E`는 로컬에서 Ruby 문자열을 평가합니다](https://docs.chef.io/workstation/26/tools/knife/knife_exec/). 유효한 sudo 규칙이 `exec` 하위 명령과 호출자가 제공한 `-E` 인수, 의도한 RunAs ID를 허용하는지, 일치하는 명령 거부 규칙이나 고정 인수가 있는지 확인합니다. 설치된 바이너리나 다른 하위 명령으로 제한된 규칙은 단지 검토 단서일 뿐입니다. 수동 열거에서는 `knife`를 실행하지 말고 규칙만 보고합니다.

대화형 `msfconsole`에 대한 root 가능 sudo 권한도 마찬가지로 민감합니다. [GTFOBins에는 해당 도구의 `irb` 콘솔이 설명되어 있으며](https://gtfobins.org/gtfobins/msfconsole/), 이 콘솔은 sudo ID를 상속할 수 있습니다. 유효한 RunAs 사용자, 허용된 인수 목록, 명령 거부 규칙, `NOEXEC` 또는 기타 제한, 설치된 콘솔 동작, 호출자가 대화형 입력을 제공할 수 있는지 확인합니다. 경로가 강조 표시되는 것만으로는 검토 단서일 뿐입니다. 수동 열거에서 콘솔을 실행하지 않습니다.

FreeBSD에서 root 권한으로 실행되는 `pkg update`와 `pkg install *`만 허용하는 sudo 규칙도 저장소 신뢰 검토가 필요합니다. 호출자가 `/etc/hosts`를 쓸 수 있는지, 그리고 *유효하게 활성화된* 저장소 설정이 `signature_type: none`인 HTTP 호스트 이름을 사용하는지 확인합니다. [FreeBSD의 `pkg.conf` 매뉴얼](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)에 따르면 `none`은 서명 검사를 비활성화합니다. `pkg+http`만으로는 이를 입증할 수 없습니다. 패키지에는 설치 스크립트가 포함될 수 있으므로([FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)), 호출자가 실제로 저장소 엔드포인트를 제어하고 패키지를 선택할 수 있다면 root 경계를 넘을 수 있습니다. 결론을 내리기 전에 저장소 재정의, SRV/미러 확인, 유효한 sudo 인수, 패키지 선택 및 스크립트 실행 여부를 검증합니다. 열거 중에는 이름을 다른 대상으로 돌리거나 `pkg`를 실행하지 말고 정책과 작은 로컬 설정 파일만 살펴봅니다.

`apt-get update`와 `apt-get upgrade`에 대한 root 가능 sudo 권한이 있고 sudo가 호출자 제어 `http_proxy`를 보존한다면 저장소 신뢰도 검토해야 합니다. 유효한 APT proxy 설정이 실제로 해당 변수를 사용하는지, 활성 저장소 중 어떤 요청에 영향을 줄 수 있는지 확인합니다. proxy만으로는 신뢰할 수 있는 서명 키로 인증된 아카이브의 패키지를 대체할 수 없습니다. [APT의 HTTP 전송 매뉴얼](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)에는 proxy 우선순위가 설명되어 있고, [apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)에는 서명 검사, 안전하지 않은 저장소 재정의 및 인증되지 않은 패키지에 대한 확인 절차가 설명되어 있습니다. 정확한 sudo RunAs 사용자와 인수, 저장소 인증 정책, 필요한 대화형 승인, 선택된 업그레이드가 root 권한으로 패키지 스크립트를 실행하는지 확인합니다. 정책과 로컬 설정은 수동으로 살펴보고, 열거 중에는 패키지 트래픽을 다른 곳으로 돌리거나 업그레이드를 실행하지 않습니다.

` snap install`에 대한 root 가능 sudo 규칙은 인수로 호출자가 로컬 snap과 허용적인 설치 모드를 선택할 수 있으면 패키지-코드 경계가 될 수 있습니다. [Snap 문서](https://snapcraft.io/docs/explanation/snap-development/install-modes/)에 따르면 `--dangerous`는 로컬 snap의 assertion 검사를 건너뛰고 `--devmode`는 confinement을 완화합니다. [설치 hook은 최초 설치 시 실행될 수 있습니다](https://snapcraft.io/docs/reference/development/supported-snap-hooks/). 보호된 호스트 파일에 접근할 수 있다고 주장하기 전에 정확한 sudo 인수/RunAs 정책, snap 파일의 제어 주체, 설치된 snapd가 해당 모드를 허용하는지, hook의 유효 ID 및 confinement을 확인합니다. `snap` 바이너리나 와일드카드처럼 보이는 규칙만으로는 이 연결이 입증되지 않습니다. 수동 열거에서는 패키지를 설치하거나 hook을 실행하지 않습니다.

**root가 아닌** 계정의 사용자 지정 자격 증명 판독 바이너리에 대한 정확한 sudo 권한이 있다면, 먼저 실행하지 말고 해당 바이너리와 파일 권한을 살펴봅니다. 내장된 비밀번호 검사는 넓은 문자로 표시해야만 보일 수 있습니다. [GNU `strings`에는 16비트 little-endian 추출 방법이 설명되어 있습니다](https://sourceware.org/binutils/docs/binutils/strings.html). 문자열이 보인다고 해서 그것이 유효한 비밀번호이거나 성공 분기에서 현재 자격 증명이 노출된다는 뜻은 아닙니다. 바이너리의 동작, 보호된 데이터에 대한 대상 계정의 접근 권한, 자격 증명 유효성, 이후의 계정 또는 그룹 전환을 각각 확인합니다. 해당 계정이 `docker` 그룹에 속한다면 socket 접근 권한과 daemon의 rootful 또는 rootless ID를 확인한 뒤 호스트 root 접근을 추정합니다. [Docker는 해당 그룹이 root 수준에서 미치는 영향을 설명합니다](https://docs.docker.com/engine/install/linux-postinstall/). 일반적인 열거에서는 바이너리를 실행하거나 문자열을 덤프하지 말고 sudo 규칙과 그룹 멤버십만 보고합니다.

애플리케이션의 유지보수 스크립트에 대한 와일드카드 sudo 규칙은 스크립트 경로만 볼 것이 아니라 더 자세히 검토해야 합니다. 허용된 스크립트가 제한 없는 인수를 받는지, 낮은 권한의 애플리케이션 계정이 쓸 수 있는 설정을 읽는지 확인한 다음, 그 값이 셸 명령이나 subprocess 환경으로 전달되는지 추적합니다. 예를 들어 ZoneMinder의 [`zmupdate.pl`은 `mysqldump` 명령을 구성해 `qx`로 실행하고](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in), [`zmdc.pl`은 daemon을 시작하기 전에 `ZM_LD_PRELOAD` 설정을 `LD_PRELOAD`에 복사합니다](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in). 해당 스크립트 중 하나를 root로 허용하는 sudo 규칙은 입력을 제어할 수 있고 설치된 버전의 해당 코드에 도달하는 경우 신뢰 경계를 넘을 수 있습니다. 유효한 sudo 규칙, 애플리케이션 설정 권한 및 스크립트 소스를 살펴봅니다. 와일드카드나 설정값만으로는 실행이 입증되지 않으며 검토 단서일 뿐입니다.

- `SETENV`, `env_keep`, `secure_path` 및 `LD_PRELOAD`는 범위가 좁은 명령을 import, library 또는 PATH hijack으로 바꿀 수 있습니다. [환경 변수 가이드](../linux-basics/linux-environment-variables.md)와 [SUID/linker 악용](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)을 참조하세요.

셸 wrapper가 고정 Python 스크립트를 리터럴 import와 함께 시작하는 경우, root 가능 `SETENV` 권한을 정확히 부여하는 규칙도 한 단계 안에서 검토해야 합니다. `secure_path`는 셸의 명령 검색 경로를 제한할 뿐 Python의 [`PYTHONPATH` 모듈 검색](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)은 제한하지 않습니다. [`-E`와 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E)는 Python이 해당 환경 변수를 무시하게 합니다. 이를 코드 실행으로 판단하기 전에 유효한 sudo tag 및 거부 규칙, wrapper 분기, 인터프리터 옵션, import 해석, 호출자가 쓸 수 있는 검색 디렉터리를 확인합니다. 짧은 스크립트는 정적으로 살펴보고 권한 있는 wrapper를 실행하지 않습니다.

정확히 `neofetch ""`를 root 권한으로 실행할 수 있는 sudo 규칙도 해당 sudo 기본값이 호출자 제어 `XDG_CONFIG_HOME`을 보존하면 셸 설정 파일을 불러올 수 있습니다. [Neofetch의 설정 로더](https://github.com/dylanaraps/neofetch/blob/master/neofetch)는 해당 디렉터리 아래의 `neofetch/config.conf` 또는 `neofetch/config`를 source 처리합니다. 인수 목록이 비어 있어도 이 검색은 막히지 않습니다. 권한 있는 명령이나 설정 내용을 출력하지 말고, 설치된 로더, 유효한 RunAs 및 인수 정책, 명령 거부 규칙, sudo가 이 명령에 대해 실제로 해당 변수를 보존하는지, 호출자가 읽을 수 있는 설정 경로를 제어하는지 확인합니다. 변수가 보존되거나 Neofetch가 설치되어 있다는 사실만으로는 검토 단서일 뿐입니다. [sudoers 환경 처리](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)를 참조하세요.

`facter`에 대한 제한 없는 root 가능 sudo 규칙은 사용자 지정 fact를 별도로 검토해야 합니다. [Puppet 문서](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)에 따르면 `--custom-dir`은 선택한 디렉터리에서 Ruby fact 파일을 불러옵니다. 정확한 sudo 규칙이 해당 옵션을 허용하는지, 설치된 Facter가 이를 지원하는지, 호출자가 디렉터리를 제어하는지 확인합니다. 고정 인수 권한, 명시적 명령 거부 또는 사용자 지정 fact 비활성화 여부에 따라 결과가 달라질 수 있습니다. 수동 열거에서는 Facter를 실행하거나 fact 내용을 읽지 말고, 정책상 검토 대상만 보고합니다.

`SETENV`가 포함된 root 가능 스크립트에 대한 정확한 sudo 권한에서는 `find` 같은 단순 명령 이름과 sudo 정책 및 스크립트 초기화 후의 유효한 `PATH`를 살펴봅니다. source된 Bash 파일이 `enable -n [`를 실행할 수도 있습니다. [그러면 Bash는 이후 스크립트가 해당 명령을 사용할 때 `PATH`에서 외부 `[`를 검색합니다](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html). 권한 있는 실행으로 판단하기 전에 해당하는 [sudoers 환경 및 `secure_path` 규칙](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf), `NOSETENV`/`NOEXEC` 또는 거부 규칙, 스크립트와 source 파일의 실행 흐름, 호출자가 제어하는 실행 가능 검색 디렉터리를 확인합니다. 단순 명령이 포함된 읽을 수 있는 스크립트는 검토 단서일 뿐 권한 있는 실행의 증거가 아닙니다. sudo 규칙을 실행하지 말고 내용을 살펴봅니다.
- 고정 URL을 `curl`로 가져오는 권한 있는 스크립트도 해당 sudo 규칙이 `http_proxy`를 보존하고 요청이 그 proxy를 통과한다면 호출자가 선택한 응답을 받을 수 있습니다. 이후 스크립트가 외부 entity를 확인하는 XML parser에 응답을 전달하면 악성 응답이 권한 있는 프로세스가 읽을 수 있는 파일을 노출할 수 있습니다. 정확한 sudo 환경 정책, `no_proxy` 제외 항목, 요청 URL, parser 설정 및 출력 경로를 확인합니다. proxy 변수나 XML parser만으로는 취약성이 입증되지 않습니다. [curl proxy 환경 문서](https://everything.curl.dev/usingcurl/proxies/env.html)에는 변수 동작이 설명되어 있습니다. 수동 열거 중에는 네트워크 요청을 보내거나 악성 XML을 파싱하지 않습니다.
- 호출자 영향 데이터로 PostScript 파일을 만든 뒤 `ps2pdf -dNOSAFER`를 실행하는 root 가능 sudo 스크립트는 입력 흐름을 별도로 검토해야 합니다. Ghostscript 문서에 따르면 이 flag는 `.setsafe`가 호출될 때까지 SAFER를 비활성화하여 프로세스의 OS 권한 범위 안에서 PostScript 파일 작업을 허용합니다. 호출자 인수로 조합한 SQL 쿼리가 공격자가 제어하는 행을 PostScript 템플릿에 전달할 수는 있지만, 쿼리 문자열이나 `ps2pdf` 호출만으로 데이터가 실행 가능한 PostScript 구문에 도달한다는 뜻은 아닙니다. 유효한 sudo 규칙, 입력에서 템플릿까지의 정확한 경로, escaping 여부, 설치된 Ghostscript의 동작, 문서 해석 전에 SAFER가 다시 활성화되는지 확인합니다. 수동 열거 중에는 권한 있는 변환을 실행하지 않습니다. [Ghostscript의 `-dNOSAFER` 문서](https://ghostscript.readthedocs.io/en/master/Use.html)를 참조하세요.
- 셸 스크립트를 실행하는 sudo 규칙에서는 보존된 변수와 스크립트 자체를 함께 살펴봅니다. `if $CHECK_CONTENT; then` 같은 구문은 확장된 값을 명령으로 실행하므로, `CHECK_CONTENT`를 보존하면 스크립트 경로와 인수가 고정되어 있어도 명령 실행이 가능할 수 있습니다. 특정 규칙에서 해당 분기에 도달할 수 있는지, 환경 변수가 실제로 보존되는지 확인해야 합니다.<sup>[[2]](#references)[[22]](#references)</sup>
- sudo에서 허용된 Python 스크립트가 쓰기 가능한 디렉터리나 캐시된 `.pyc` 파일에서 코드를 import할 수 있습니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md)에서 캐시 사례를 자세히 설명합니다.
- root로 실행할 수 있도록 sudo에서 허용된 고정 Python 스크립트도 대화형 debugger를 노출할 수 있습니다. `pdb.set_trace()` 또는 `pdb.post_mortem()` 같은 호출은 호출자가 breakpoint나 예외 처리기에 도달할 수 있고 **debugger의 입력 스트림을 제어할 수 있다면**, 디버깅 중인 프로세스의 컨텍스트에서 Python 구문을 허용합니다. 정확한 sudo RunAs 규칙, 인증과 분기 조건, 예외 발생 가능성, terminal/input 소유권, debugger가 같은 권한 프로세스에서 실행되는지 확인합니다. 다른 terminal에 연결된 debugger는 socket 요청으로 예외를 발생시킨다고 해서 접근할 수 있는 것이 아닙니다. [Python 문서에는 debugger의 구문 평가와 사후 분석 모드가 설명되어 있습니다](https://docs.python.org/3/library/pdb.html). 열거 중 권한 있는 handler를 트리거하지 말고 스크립트를 정적으로 살펴봅니다.
- sudo에서 허용된 고정 Python 스크립트가 데이터베이스나 Unix socket에서 프로필 필드를 읽어 나중에 `str.format()`의 **format string**이 되는 문자열에 덧붙일 수도 있습니다. [대체 필드는 속성과 mapping 키를 지정할 수 있습니다](https://docs.python.org/3/library/string.html#format-string-syntax). 따라서 공격자가 제어하는 필드는 `format()`에 전달된 객체를 살펴보고 결과가 출력되거나 호출자가 읽을 수 있는 위치에 저장되면 해당 객체에서 접근 가능한 데이터를 노출할 수 있습니다. 이를 확인하려면 유효한 sudo RunAs ID, 특정 레코드에 대한 쓰기 권한, format string으로 이어지는 데이터 흐름, 전달되는 객체 및 출력 가시성을 살펴봅니다. 이는 자동 코드 실행이 아니며, 신뢰할 수 있는 리터럴 format string에 공격자가 제어하는 *값*을 전달하는 경우와는 다릅니다. 노출된 비밀이 OS 계정 전환으로 이어지려면 해당 계정이 그 비밀을 받아들여야 합니다. 권한 있는 작업을 실행하지 말고 스크립트와 socket 권한을 검토합니다.
- root 권한이 있는 Python wrapper가 호출자 선택 URL을 GitPython의 `Repo.clone_from`에 전달할 수 있습니다. wrapper가 Git의 `protocol.ext.allow=always`도 활성화한다면 `ext::` remote가 외부 helper를 호출할 수 있습니다. 정확한 sudo 인수, URL 출처, GitPython 패키지 버전과 vendor patch 여부, wrapper가 위험한 protocol을 명시적으로 허용하는지 확인합니다. GitPython 3.1.30에는 [기본 unsafe-protocol guard가 추가되었습니다](https://github.com/gitpython-developers/GitPython/commit/2625ed9). `git` 실행 파일 버전은 별도로 확인해야 합니다. 수동 검토에서는 규칙과 제한된 범위의 소스만 읽고 clone을 실행하지 않습니다.
- 저장소를 clone하는 CLI에 대한 사용자 간 sudo 권한은 별도의 shell-string injection 경로를 노출할 수 있습니다. 호출자 선택 저장소 인수가 안전한 인수 분리 없이 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback)나 다른 셸 명령 조립기로 전달되는지 추적합니다. Node의 `exec`는 명령 문자열을 셸에 전달합니다. 결론을 내리기 전에 정확한 RunAs 사용자, 허용된 하위 명령과 인수, 설치된 wrapper 코드 및 입력 검증을 확인합니다. 저장소 도구의 이름이나 제한 없는 sudo 규칙만으로는 명령 주입이 입증되지 않습니다. 열거 중에는 권한 있는 clone을 실행하지 말고 wrapper를 살펴봅니다.
- 사용자 지정 root 소유 wrapper는 바이너리와 스크립트가 쓰기 불가능해서 안전해 보여도, 권한 있는 작업을 실행할지 결정하는 기준이 낮은 권한 사용자가 변경할 수 있는 flag, 로컬 API 값 또는 서비스 상태에 달려 있을 수 있습니다. 각 gate의 입력과 권한 검사를 거슬러 추적합니다. 열거 중에는 운영 상태를 변경하지 말고 설정과 권한을 살펴봅니다. wrapper 안의 `systemd-run` 호출도 gate에 영향을 줄 수 있을 때만 관련이 있습니다.
- sudo로 root 권한으로 허용된 백업 클라이언트가 호출자 선택 설정 파일을 받을 수 있습니다(예: `npbackup-cli -c`). 정확한 RunAs 사용자와 허용된 인수를 확인한 다음, 호출자가 설정 경로, 백업 원본 경로, 저장소 또는 읽기/복구 옵션을 제어할 수 있는지 살펴봅니다. 읽을 수 있는 설정에 암호화된 저장소 비밀이 있어도 클라이언트가 이를 사용할 수는 있지만, 규칙만으로 저장소 접근이나 root 파일 공개가 입증되지는 않습니다. 백업을 실행하거나 내용을 덤프하지 말고 권한을 검증합니다.
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst)은 저장소 비밀번호를 얻기 위해 프로그램을 호출하는 `--password-command`를 지원합니다. sudo 규칙이 낮은 권한 사용자에게 호출자 선택 비밀번호 명령과 비밀번호가 필요한 하위 명령을 root로 실행하도록 허용한다면 helper가 root로 실행될 수 있습니다. 정확한 sudo 인수와 제외 규칙을 검토하고, 이 조건을 열거하려고 helper나 백업 명령을 실행하지 않습니다.
- root 권한으로 `restic backup`을 실행할 수 있는 권한 있는 규칙은 sudo 인수 패턴이 호출자에게 원본과 나중에 읽고 복호화할 수 있는 저장소를 모두 선택하도록 허용하는 경우 파일 읽기 경계를 넘을 수도 있습니다. [Sudoers 인수 와일드카드는 공백과 슬래시를 매칭할 수 있으므로](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf), 후행 와일드카드가 원본 경로를 제한한다고 가정하지 말고 살펴봅니다. [Restic은 로컬 및 원격 저장소에 백업할 수 있지만](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html), 로컬 저장소에는 새로 기록된 root 전용 객체가 있을 수 있습니다. 이를 정보 노출로 판단하기 전에 유효한 sudo 정책, backend 접근 권한, 저장소 비밀번호 및 결과 객체 권한을 확인합니다. 백업된 SSH key는 대상 계정이 이를 허용할 때만 접근을 허용합니다. 수동 검토 중 이 가능성을 시험하려고 백업을 실행하지 않습니다.
- 제한 없는 사용자 지정 유지보수 또는 백업 명령은 출력 경로를 받거나 자체 job scheduler를 제공할 수 있습니다. 파일 쓰기 경로라면 정확한 sudo 규칙과 RunAs 사용자를 확인한 다음, 호출자가 데이터와 대상을 모두 제어하는지 살펴봅니다. 예약 명령 경로라면 scheduler의 실행 ID, 명령 입력 및 추가 비밀번호나 권한 검사 여부를 확인합니다. 명령 이름이나 `NOPASSWD`만으로는 어느 경로도 입증되지 않습니다. [root 소유 파일에 쓰기](../interesting-files-permissions/write-to-root.md)와 [cron 및 systemd timer](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)를 참조하세요.
- 고정 sudo 명령도 공유 쓰기 가능 디렉터리에서 예측 가능한 설정 파일을 불러올 수 있습니다. 호출자가 해당 파일을 바꿀 수 있는지, 파일의 source 및 destination 필드가 권한 있는 fetch나 copy를 제어하는지 추적합니다. 로컬 파일 URL은 sudo RunAs 계정만 읽을 수 있는 데이터를 노출할 수 있고, 호출자 제어 source와 보호된 destination을 조합하면 쓰기 경로가 생길 수 있습니다. 설치된 프로그램의 URL 처리, destination 경로 검사, 유효한 sudo 규칙 및 출력 접근성을 확인합니다. 쓰기 가능한 `/tmp` 설정 경로만으로는 검토 단서일 뿐입니다. 권한 있는 전송을 실행하지 말고 바이너리와 파일 메타데이터를 살펴봅니다.
- `git apply`에 대한 sudo 규칙은 RunAs 계정이 호출자 제어 patch로 선택된 파일을 쓰게 할 수 있습니다. [CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)은 명령이 `--unsafe-paths`를 허용하지 않더라도 조작된 patch가 symlink를 만든 뒤 작업 트리 밖에 쓸 수 있게 했습니다. 유효한 sudo 인수 규칙, patch 출처, RunAs 계정의 작업 디렉터리 접근 권한, 설치된 Git의 수정 여부 또는 vendor backport를 확인합니다. `--unsafe-paths`를 허용하는 제한 없는 규칙은 별도의 명시적 옵션 위험입니다. Git 버전이나 `git apply` 권한만으로는 보호된 파일을 변경할 수 있다고 입증되지 않습니다. 수동 열거 중에는 신뢰할 수 없는 patch를 적용하지 않습니다.
- root 권한으로 `clamscan --debug`를 실행할 수 있는 sudo 규칙은 낮은 권한 사용자가 DMG 이미지를 제공할 수 있고 설치된 parser가 [CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)의 영향을 받는 경우 읽기 경계를 넘을 수 있습니다. 이 취약점은 debug 출력으로 파일 내용을 노출할 수 있습니다. 정확히 허용된 인수와 scan 경로, 입력 제어 권한, 유효한 RunAs 계정, 엔진 수정 또는 backport, 출력이 호출자에게 보이는지 확인합니다. 더 넓은 규칙이 `--file-list`/`-f`를 허용한다면 해당 파일 목록 동작은 별도로 검토합니다. `--debug <scan-path>`로 고정된 정책은 이를 허용하지 않습니다. 열거 중에는 조작된 파일을 검사하거나 보호된 출력을 인쇄하지 말고 정책과 패키지 메타데이터를 살펴봅니다.
- 호출자 선택 암호화 디스크 이미지를 여는 root 가능 sudo 규칙과, 그 결과 생성된 mapper를 mount하는 두 번째 규칙이 있으면 호출자 제어 파일을 호스트의 mount namespace에 가져올 수 있습니다. 두 규칙 모두의 유효성 및 인수, 이미지와 mapper 이름의 제어 여부, 실제 mount 대상, 결과 파일의 소유자와 mode를 확인합니다. set-user-ID 전환이 가능하려면 접근 가능한 실행 파일, 이를 허용하는 mount 옵션(`nosuid`는 차단), 적용되는 프로세스 또는 MAC 정책이 추가로 필요합니다. 이미지를 열거나 mount하는 것만으로는 검토 단서일 뿐입니다. 기존 백업을 통한 별도 경로라면 실제 key와 그 안에 있는 유용하고 읽을 수 있는 비밀이 필요합니다. 수동 열거 중에는 이미지를 열거나 mount하지 말고 정책과 경로를 살펴봅니다. [cryptsetup 매뉴얼](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)과 [mount 옵션](https://man7.org/linux/man-pages/man8/mount.8.html)을 참조하세요.
- 셸 또는 Python 스크립트에 대한 root 가능 sudo 규칙이 있고 스크립트가 고정 디렉터리로 이동하기 전에 `./helper`를 실행한다면 작업 디렉터리를 검토해야 합니다. `subprocess.run`에 전달된 `['./helper']` 같은 Python list도 호출자가 선택한 작업 디렉터리에서 실행될 수 있습니다. 호출자는 쓰기 가능한 디렉터리를 선택하고 그곳에 해당 상대 이름의 실행 파일을 둘 수 있습니다. 스크립트의 다른 곳에 절대 경로가 있어도 이 호출은 보호되지 않습니다. 이를 코드 실행으로 판단하기 전에 유효한 규칙, `runchdir` 또는 기타 디렉터리 변경 정책, 스크립트 흐름과 분기 도달 가능성, 쓰기 및 실행 가능한 디렉터리, mount/`NOEXEC` 제한을 확인합니다. 스크립트를 읽을 수 없다면 승인된 경로로 소스를 검토하기 전까지 동작은 알 수 없습니다. helper를 실행하지 말고 스크립트를 정적으로 살펴봅니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)에는 작업 디렉터리 정책이 설명되어 있습니다.
- root 권한으로 실행할 수 있는 고정 Python validator도 호출자가 선택한 데이터 파일을 평가할 수 있습니다. [Python의 `eval()` 문서는 신뢰할 수 없는 입력에 사용하지 말라고 경고합니다](https://docs.python.org/3/library/functions.html#eval). 입력 접미사 검사, 산술식 접두어 또는 검증 분기가 있어도 나머지 표현식이 `eval`에 도달한다면 sandbox가 아닙니다. 이를 실행 경로라고 판단하기 전에 유효한 sudo 규칙, 호출자가 정확한 파일을 선택하고 제어할 수 있는지, parser의 분기 조건과 표현식 구성, 권한 있는 프로세스 ID를 확인합니다. 읽을 수 있는 스크립트에 `eval`이 있다는 것만으로는 검토 단서일 뿐입니다. 열거 중에는 validator를 실행하거나 테스트 표현식을 제출하지 말고 소스와 파일 권한을 살펴봅니다.
- `YAML.load(File.read("dependencies.yml"))`처럼 상대 YAML 파일을 읽는 root 가능 sudo Ruby wrapper는 wrapper나 sudo 정책이 디렉터리를 고정하지 않는 한 호출자의 작업 디렉터리에서 입력을 가져올 수 있습니다. 정확히 허용된 인수, 디렉터리 및 파일 권한, 설치된 Psych 동작을 확인합니다. 이전 `YAML.load` 구현은 임의의 Ruby 객체를 역직렬화할 수 있었지만 최신 릴리스는 기본적으로 클래스를 제한합니다. 정적 호출 지점은 검토 단서일 뿐입니다. 실제 파일이 호출자가 쓸 수 있는 디렉터리에 있는지, 설치된 loader가 위험한 클래스를 허용하는지 확인합니다. 신뢰할 수 없는 입력에는 명시적으로 최소 클래스만 허용하는 `safe_load`를 우선 사용합니다. [Ruby 3.0 Psych 문서](https://docs.ruby-lang.org/en/3.0/Psych.html)와 [Ruby 3.1 Psych 문서](https://ruby-doc.org/core-3.1.2/Psych.html)를 참조하세요.

- `sudo go run /absolute/file.go`를 정확히 허용하는 root 가능 규칙은 Go 소스가 상대 경로의 WASM 파일을 읽고 그 결과를 검사한 뒤 상대 경로 셸 스크립트를 실행할 수 있다면 작업 디렉터리를 검토해야 합니다. 유효한 RunAs 사용자, 명령 인수와 거부 규칙, 호출자가 쓸 수 있는 현재 디렉터리, WASM에서 분기로 이어지는 데이터 흐름, 해당 분기가 helper를 호출하는지 확인합니다. 고정된 sudo `runchdir`, `os.Chdir` 또는 [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec)는 검색 위치를 바꿀 수 있습니다. 소스에 함께 등장한다는 사실만으로는 후보일 뿐입니다. Go, WASM 또는 helper를 실행하지 말고 소스를 살펴봅니다.
- `sudoedit` 및 인수 와일드카드는 정확한 버전과 규칙을 확인해야 합니다. [체크리스트](linux-privilege-escalation-checklist.md)에는 sudoedit 파일 편집 문제가 포함되어 있습니다. 사용자 간 와일드카드 경로에 대한 `sudoedit` 권한은 유효한 `sudoedit_follow` 또는 `FOLLOW` 설정, `sudoedit_checkdir`, 해석된 대상, 상위 경로의 각 항목을 바꿀 수 있는 사용자를 확인합니다. 전자는 symlink 추적을 허용할 수 있고, 후자를 비활성화하면 쓰기 가능한 디렉터리 검사가 제거되지만 둘 중 어느 것도 다른 사용자의 파일을 쓸 수 있다고 단독으로 입증하지는 않습니다. 결론을 내리기 전에 설치된 sudo 정책과 실제 매칭되는 인수를 확인합니다. [sudoers 옵션 정의](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)를 참조하세요.
- sudoers 명령 규칙의 인수 와일드카드는 경로 문자뿐 아니라 공백에도 매칭될 수 있습니다. `/restricted/*` 같은 인수를 받는 읽기 가능 명령 규칙은 일치하는 접두어 뒤에 추가 파일 인수를 허용할 수 있습니다. 정확한 RunAs 사용자, 명령 경로, 인수 패턴 및 이후 거부 규칙을 검토합니다. 파일 읽기가 입증되어도 명령 실행이 입증되는 것은 아닙니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)에는 인수 glob과 명령 경로 glob의 차이가 설명되어 있습니다.
- 경로처럼 보이는 인수 glob도 `../`와 매칭될 수 있습니다. 예를 들어 root 가능 `node /opt/scripts/*.js` 규칙은 입력 경로가 여전히 `/opt/scripts/`로 시작하고 상위 디렉터리 요소를 통해 해석되는 경우 호출자 제어 JavaScript 파일이 `/opt/scripts` 바깥에 있어도 허용할 수 있습니다. 이는 **인수** glob입니다. Node 실행 파일의 명령 경로 glob에는 다른 슬래시 매칭 규칙이 적용됩니다. 코드 실행을 결론 내리기 전에 유효한 규칙, 이후 거부 규칙, 경로 해석, 대상 파일 제어 권한, sudoers 정규식 또는 digest 제한을 확인합니다. [sudoers 와일드카드 규칙](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)과 [Node 명령줄 문서](https://nodejs.org/api/cli.html)를 참조하세요.
- Archiver와 다른 유틸리티 프로그램에는 실행 hook이 있을 수 있습니다. 셸이나 인터프리터만 명령을 실행한다고 가정하지 말고 [GTFOBins](https://gtfobins.github.io/)에서 정확히 허용된 인수를 확인합니다.
- `qpdf`에 대한 제한 없는 root 가능 규칙은 PDF 첨부 파일을 통해 권한 있는 파일을 노출할 수 있습니다. qpdf 10.2 이상은 출력 PDF와 함께 `--empty` 및 `--add-attachment file ... --`을 지원합니다. 권한 있는 프로세스가 선택한 원본을 읽을 수 있고 호출자가 접근 가능한 경로에 PDF를 쓸 수 있다면, 결과 파일에 원본 바이트가 포함될 수 있습니다. 파일 공개가 가능하다고 결론 내리기 전에 유효한 sudo 인수와 제외 규칙, qpdf 버전, 원본 접근 권한 및 출력 경로를 검토합니다. root SSH key를 읽어도 해당 key가 유효하고 root SSH 인증이 허용될 때만 로그인에 유용합니다. [qpdf 첨부 옵션](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)을 참조하세요.
- sudo timestamp 재사용 여부는 cache 정책, 소유 사용자, terminal/session 및 권한에 달려 있습니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)에서 확인 사항을 다룹니다.
- `doas`에는 자체 규칙과 설정이 있습니다. [doas 섹션](../linux-basics/linux-privilege-escalation/README.md#doas)에 설명된 대로 허용된 명령과 쓰기 가능한 설정 경로를 확인합니다.

### sudo로 실행되는 빌드 및 패키지 도구

Foundry의 `forge`에 대한 제한 없는 sudo 권한은 RunAs ID가 root가 아닌 다른 사용자여도 문제가 될 수 있습니다. `--use` 같은 compiler 옵션으로 로컬 실행 파일을 선택할 수 있고 `forge flatten -o`는 출력 파일을 지정합니다. 이 권한을 악용 가능하다고 판단하기 전에 설치된 Forge 버전, 정확한 sudo 인수, 접근 가능한 프로젝트 및 compiler 경로, 출력 권한, 유효한 환경을 확인합니다. `PATH`를 통해 찾은 상대 helper 실행 파일 경로는 버전과 환경에 따라 달라지므로 모든 Forge 빌드에 해당한다고 가정하지 않습니다.<sup>[[23]](#references)[[24]](#references)</sup>

root 가능 `pacman`에 대한 제한 없는 sudo 권한은 패키지 조회 이상을 허용합니다. `-U`는 로컬 패키지를 받으며 패키지에는 설치 스크립트가 포함될 수 있고, `--hookdir`은 다른 hook 디렉터리를 지정합니다. 테스트하기 전에 유효한 sudo 규칙과 인수 제한 및 제외 규칙을 검토합니다. 수동 열거에서는 패키지를 설치하거나 hook을 실행할 필요가 없습니다.<sup>[[25]](#references)[[26]](#references)</sup>

고정 sudo 셸 wrapper는 이름이 지정된 npm 의존성을 설치한 다음 Node 애플리케이션을 시작할 수도 있습니다. 정확한 RunAs 규칙, 패키지가 이미 설치되어 있는지, 유효한 `HOME`과 npm `userconfig`, 프로젝트 설정이나 명령줄 재정의, 낮은 권한 사용자가 해당 이름으로 반환되는 registry 또는 패키지를 제어하는지 검토합니다. [npm에는 사용자별 및 프로젝트별 `.npmrc` 검색 규칙이 설명되어 있습니다](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/). sudo의 `HOME` 동작은 설치된 정책과 배포판에 따라 다르므로 사용자 소유 `.npmrc`를 권한 있는 npm 프로세스가 읽을 수도, 읽지 않을 수도 있습니다. 새로 설치된 패키지를 권한 있는 애플리케이션이 import하면 해당 애플리케이션 ID로 모듈 코드가 실행될 수 있습니다. 설치 시 스크립트는 별도의 경로이며 버전과 설정에 따라 다릅니다. [npm에는 해당 스크립트의 생명주기와 사용자 처리 방식이 설명되어 있습니다](https://docs.npmjs.com/cli/v6/using-npm/scripts/). `.npmrc` 경로나 `npm install` 행만으로는 검토 단서일 뿐입니다. 수동 열거 중에는 설치하거나 애플리케이션을 시작하지 말고 규칙, 짧은 wrapper, 설정 경로 및 패키지 출처를 살펴봅니다.

root 가능 `pip` 또는 `pip3 download` 권한도 인수로 호출자가 신뢰할 수 없는 source distribution을 선택할 수 있다면 패키지 빌드 검토 단서입니다. URL 패턴이 로컬 서비스와 `.tar.gz` 접미사로 제한되어 있어도 마찬가지입니다. `pip download`는 아카이브 URL을 받고 패키지 메타데이터를 확인합니다. sdist 준비 과정에서는 아카이브를 단순히 저장하기 전에 build backend 또는 기존 `setup.py` 코드가 실행될 수 있습니다. 정확한 sudo RunAs 및 인수 규칙, 호출자가 선택된 아카이브를 게시하거나 바꿀 수 있는지, 해당 pip 버전이 실제로 메타데이터를 준비하는지 확인합니다. 고정된 신뢰 아카이브나 wheel만으로는 이 경로가 성립하지 않습니다. 수동 열거 중에는 신뢰할 수 없는 패키지를 가져오거나 빌드하지 않습니다. pip의 [download 명령](https://pip.pypa.io/en/stable/cli/pip_download/), [build-system 인터페이스](https://pip.pypa.io/en/stable/reference/build-system/), [안전한 설치 지침](https://pip.pypa.io/en/stable/topics/secure-installs/)을 참조하세요.

호출자 선택 로컬 프로젝트 경로로 `pip install`을 허용하는 sudo 규칙은 더 직접적인 빌드 경계입니다. [pip은 로컬 프로젝트 디렉터리를 허용하며](https://pip.pypa.io/en/stable/topics/local-project-installs/), 해당 프로젝트의 빌드 시스템을 호출합니다. [build backend는 프로젝트가 제어하는 빌드 hook을 실행합니다](https://pip.pypa.io/en/stable/reference/build-system/). 이 규칙을 권한 있는 코드 실행으로 판단하기 전에 유효한 RunAs ID, 정확한 인수 제한 및 거부 규칙, 선택된 프로젝트를 제어할 수 있는지, 설치된 pip/backend의 동작을 확인합니다. 고정된 신뢰 프로젝트나 호출자 선택 경로를 제외하는 규칙으로는 이 경로가 성립하지 않습니다. 수동 열거 중에는 패키지를 설치하지 말고 규칙과 프로젝트 메타데이터를 검토합니다.

root 가능 `easy_install`에 대한 제한 없는 권한은 관련된 기존 패키지 빌드 검토 단서입니다. [Setuptools 문서](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)에 따르면 Easy Install은 로컬 프로젝트 디렉터리를 받고 source distribution을 빌드합니다. 호출자 제어 프로젝트는 sudo ID로 빌드되는 동안 `setup.py`를 실행할 수 있습니다. 유효한 RunAs 계정, 정확한 명령 및 인수 제한(이후 거부 규칙 포함), 선택된 프로젝트를 제어할 수 있는지, 설치된 도구의 동작을 확인합니다. 고정된 신뢰 프로젝트나 호출자 선택 source를 허용하지 않는 정책으로는 이 경로가 성립하지 않습니다. 열거 중에는 패키지를 설치하지 말고 규칙과 프로젝트 메타데이터를 살펴봅니다.

호출자 선택 URL을 사용하는 `setuptools.package_index.PackageIndex.download` 기반 sudo 허용 Python wrapper는 `pip download`와 다른 검토 사례입니다. [setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)는 78.1.1 이전의 영향을 받는 릴리스에서 URL에서 파생한 파일 이름이 의도된 다운로드 디렉터리 바깥을 가리켜 프로세스 권한으로 파일을 쓸 수 있음을 설명합니다. 유효한 sudo RunAs 및 인수 규칙, wrapper가 호출자 URL을 정확히 이 API에 전달하는지, 설치된 빌드 또는 vendor backport, 결과 경로가 어디에 해석되는지 확인합니다. 버전 문자열이나 쓰기 가능한 다운로드 디렉터리만으로는 임의 쓰기가 입증되지 않습니다. 열거 중에는 URL을 가져오거나 파일을 쓰지 말고 짧은 wrapper와 패키지 메타데이터를 검토합니다.

PyInstaller에 호출자 선택 `.spec` 파일을 전달하는 sudo 허용 빌드 wrapper도 같은 신뢰 경계 검토가 필요합니다. PyInstaller spec은 **빌드** 중 실행되는 Python 코드이며, `datas` 항목은 빌드 ID가 읽을 수 있는 파일을 산출물에 포함할 수 있습니다. 정확한 RunAs 사용자, sudo 인수 및 거부 규칙, wrapper의 경로와 분기 처리, 선택된 spec 파일을 제어할 수 있는지, 결과 산출물에 접근할 수 있는지 확인합니다. `.py` 입력만 허용하거나 PyInstaller가 설치되어 있다는 사실만으로는 spec 파일을 제어하거나 권한 있는 실행을 할 수 있다고 볼 수 없습니다. 수동 검토에서는 범위를 제한한 wrapper 파일과 메타데이터만 읽고 빌드를 실행하지 않습니다. [PyInstaller spec 파일 문서](https://pyinstaller.org/en/stable/spec-files.html)를 참조하세요.

### sudo로 실행되는 preset 및 plugin loader

호출자 선택 preset 또는 plugin 디렉터리를 받는 Python 도구는 sudo가 부여한 권한으로 코드를 import할 수 있습니다. 예를 들어 BBOT은 `-p`로 preset을 받을 수 있으며, [사용자 지정 모듈 문서](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)에는 추가 Python 모듈 디렉터리를 선택하는 `module_dirs` 항목이 설명되어 있습니다. 유효한 sudo 규칙이 호출자 선택 preset을 허용하고 호출자가 선택된 디렉터리의 모듈을 제어한다면, 도구가 잘못된 모듈을 거부하기 전에도 해당 import가 권한 있는 사용자로 코드를 실행할 수 있습니다. 열거 중에는 모듈을 불러오지 말고 설치된 버전, 정확한 sudo RunAs 및 인수 정책, preset 및 모듈 경로의 소유권을 확인합니다.

### sudo로 실행되는 Backdrop 명령줄 도구

[Bee](https://github.com/backdrop-contrib/bee)는 Backdrop CMS용 PHP 명령줄 도구입니다. `eval` (`php-eval`) 및 `php-script` 명령은 호출자가 제공한 PHP를 실행할 수 있습니다. 따라서 제한 없는 인수를 허용하는 root 실행 Bee sudo 규칙은 Bee가 Backdrop 설치를 초기화할 수 있을 때 root 코드 실행으로 이어질 수 있습니다. 사이트 디렉터리에서 실행하거나 전역 `--root=<directory>` 옵션으로 사이트를 지정합니다. Bee가 설치되어 있거나 Backdrop `settings.php` 파일이 발견되는 것만으로는 sudo 권한, 사용할 수 있는 사이트 또는 성공적인 초기화가 입증되지 않습니다. 테스트하기 전에 유효한 sudo 규칙, 명령 제외 규칙, 실행 파일의 ID, 사이트 접근 권한을 검토합니다. 수동 열거에서는 Bee를 실행하지 말고 규칙과 파일 경로를 살펴봅니다. PHP 명령 추가 사항은 [Bee 명령 변경 기록](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)을 참조하세요.

### sudo로 실행되는 terminal server

`mosh-server`는 이를 실행한 사용자의 대화형 terminal server를 시작합니다. 높은 UDP 포트와 session key를 선택해 둘 다 호출자에게 알리며, client가 연결되면 일반적으로 해당 사용자의 로그인 셸을 실행합니다. 따라서 root 가능 `mosh-server`에 대한 제한 없는 sudo 권한은 server 명령 자체가 detach되더라도 셸 실행 검토 대상입니다. 유효한 RunAs ID, 허용 인수와 제외 규칙, 설치된 바이너리, 셸, client 사용 가능 여부 및 UDP 접근을 확인합니다. 수동 열거에서는 server를 시작하거나 활성 session key를 출력하지 말고 sudo 규칙을 살펴봅니다. [Mosh server 매뉴얼](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)과 [upstream 설계 노트](https://github.com/mobile-shell/mosh#how-it-works)를 참조하세요.

### 호출자 task 파일을 다시 쓰는 권한 있는 백업 wrapper

root로 실행되는 셸 wrapper가 호출자 선택 task 파일을 받아 source 경로에서 `../`를 제거하고, 각 결과가 허용된 디렉터리로 시작하는지 확인하고, task 파일을 다시 쓴 다음 그 *경로명*을 백업 프로그램에 전달할 수 있습니다. 완전히 정규화한 뒤 변환된 경로를 검토합니다. 문자열을 한 번 바꾸는 과정에서 어휘적 접두어 검사를 통과하는 새로운 traversal 시퀀스가 생길 수 있습니다. 또한 백업 프로그램이 메모리에 변환된 데이터를 사용하는지, 파일을 다시 여는지 확인합니다. 파일을 다시 연다면 재작성 실패 후에도 원래 입력이 남아 있을 수 있습니다.

Linux에서 `fs.protected_regular`은 world-writable sticky 디렉터리 안의 다른 사용자 소유 일반 파일에 대한 `O_CREAT` 쓰기를 거부할 수 있습니다. 이는 보호 기능이지만, 쓰기 오류를 무시하는 셸 wrapper는 원래 task 파일로 계속 진행할 수 있습니다. 설정, 파일 소유자와 디렉터리, wrapper가 실패 시 중단되는지 확인합니다. 유효한 sudo 규칙이 권한 있는 사용자로 wrapper를 실행하도록 허용하고, 호출자가 task 입력과 읽을 수 있는 백업 대상을 제어할 수 있고, 백업 유틸리티가 실제로 보호된 source를 포함하는 경우에만 이 경로가 파일 공개 후보가 됩니다. 열거 중에는 백업을 실행하지 말고 해당 조건을 살펴봅니다.

### 권한 있는 packet 도구의 인수 와일드카드

`tcpdump`의 sudo 규칙에서 **인수 패턴**의 `*`는 공백과 슬래시에 매칭될 수 있으므로, 경로처럼 보이는 제한이 추가 옵션 문자열을 허용할 수도 있습니다. 이는 명령 실행 파일 경로의 와일드카드와 다릅니다. 전체 RunAs 규칙과 이후의 거부 규칙을 살펴봅니다. 옵션 주입이 가능하다면 허용된 실행 방식과 설치된 [`tcpdump` 옵션 의미](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)에 따라 `-F`, `-V`, `-r`, `-w` 또는 `-Z`가 유용한 읽기/쓰기 기능을 제공하는지 결정됩니다. `-V`는 일반적인 임의 파일 덤프가 아니라 capture 파일 이름 목록을 읽습니다. sudo가 명령을 허용해도 AppArmor 또는 다른 MAC 정책이 파일 접근을 막을 수 있습니다. 디스크에 profile 파일이 있다고 해서 해당 profile이 로드되어 적용 중인 것은 아닙니다. 결론을 내리기 전에 권한과 정책을 수동으로 검토합니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)에는 와일드카드의 차이가 설명되어 있습니다.

인수 제한 없이 `tcpdump` 실행 파일만 나열한 root 가능 sudo 규칙도 검토해야 합니다. [`tcpdump` 매뉴얼](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)에 따르면 `-C` 또는 `-G`로 저장된 capture를 순환할 때 `-z`는 순환 후 명령을 실행합니다. `-Z` 또는 컴파일 시 기본 설정은 해당 명령이 실행되기 전에 권한을 낮출 수 있습니다. 이 규칙을 권한 상승 경로로 판단하기 전에 유효한 sudo 규칙, 설치된 빌드, 권한 하향 동작 및 순환이 발생할 수 있는지 확인합니다. 강조 표시된 규칙은 후보일 뿐 root 명령 실행의 증거가 아닙니다.

### sudo로 실행되는 Nmap wrapper

sudo에서 허용된 `nmap` 경로가 셸 wrapper라면, 허용된 정확한 경로와 전달하는 모든 옵션을 살펴봅니다. 익숙한 `--script` 표기를 차단해도 NSE 코드 로드를 막지 못할 수 있습니다. Nmap의 [`--datadir`](https://nmap.org/book/man-misc-options.html)는 데이터 파일을 선택하며, 스크립팅이 활성화되면 NSE는 선택된 데이터 디렉터리에서 [`nse_main.lua`를 불러옵니다](https://nmap.org/book/nse-implementation.html). 설치된 빌드 중에는 대체 long-option 표기도 허용하는 것이 있으므로 해당 바이너리의 실제 parser와 제한을 비교합니다. [`--excludefile`](https://nmap.org/book/man-target-specification.html)은 별도의 파일 읽기 경로이며, parser 오류가 텍스트를 노출할 수도 있습니다. 열거 중에는 scan을 실행하지 말고 유효한 sudo 규칙, wrapper 로직, Nmap 버전, 디렉터리 제어 권한 및 MAC 정책을 확인합니다.

### sudo로 실행되는 Mercurial pull hook

고정 source를 지정한 `sudo hg pull /fixed/source`도 명령이 `-R`로 지정하지 않는 한 **수신** 저장소는 현재 작업 디렉터리에서 선택됩니다. 호출자 제어 수신 저장소는 `.hg/hgrc`에서 hook을 정의할 수 있으며, hook은 sudo RunAs 사용자로 실행될 수 있습니다. [Mercurial은 신뢰할 수 없는 사용자나 그룹 소유의 저장소 설정을 무시합니다](https://mercurial-scm.org/help/topics/config). 코드 실행으로 판단하기 전에 RunAs 계정의 신뢰 사용자/그룹과 정확한 작업 디렉터리를 살펴봅니다. 수동 검토에서는 정책과 설정을 읽는 것으로 충분합니다. 열거 중에는 이를 확인하려고 pull하거나 hook을 실행하지 않습니다.

### sudo로 실행되는 Git pull hook

정확히 root 권한의 `sudo git pull`을 허용하는 규칙에서는 작업 디렉터리로 선택되는 **수신** 저장소도 확인합니다. 호출자 소유 저장소에는 실행 가능한 `post-merge` hook이 있을 수 있으며 pull이 성공적인 merge를 수행하면 Git 프로세스 ID로 실행됩니다. [Git에는 이 hook이 설명되어 있고](https://git-scm.com/docs/githooks), [pull의 merge와 rebase 동작도 문서화되어 있습니다](https://git-scm.com/docs/git-pull). 유효한 sudo 규칙과 CWD, 활성 hook 경로와 권한, 새 commit이 있는 merge가 가능한지 확인합니다. 실패하거나 아무 작업도 하지 않거나 rebase만 수행하는 pull은 이 hook 경로를 입증하지 않습니다. 권한 있는 pull을 실행하지 말고 정책과 저장소 메타데이터를 살펴봅니다.

### sudo로 실행되는 rsync archive copy

`sudo rsync -a ... /writable/source/* /fixed/destination/`에서 **sudoers 인수 패턴**의 `*`는 공백에 매칭되어 source와 destination 사이에 추가 옵션을 허용할 수 있습니다. 이는 파일 이름에 대한 셸 확장과 다릅니다. 호출자가 source를 채울 수 있고 destination을 권한 있는 rsync 프로세스가 쓸 수 있다면 [`--chown`](https://download.samba.org/pub/rsync/rsync.1)으로 권한 있는 소유권을 요청하고 archive mode로 permission bit를 보존하여, 소유자가 지정된 SetUID 파일을 만들 가능성이 있습니다. 정확한 [sudoers 와일드카드 의미](https://man7.org/linux/man-pages/man5/sudoers.5.html), rsync 버전, 이후 거부 규칙, 파일시스템 `nosuid` 및 MAC 정책을 확인합니다. 규칙이 일치한다는 것만으로 성공적인 권한 상승이 입증되지는 않으며 검토 후보일 뿐입니다.

### sudo로 실행되는 packet-filter 규칙 내보내기

`iptables`와 `iptables-save`(또는 해당하는 `ip6tables` 쌍) 모두에 대한 제한 없는 root 가능 권한은 파일 쓰기를 검토해야 합니다. `comment` match는 호출자가 선택한 규칙 텍스트를 받고, `iptables-save -f`는 직렬화된 규칙 집합을 지정한 경로에 씁니다.<sup>[[20]](#references)[[21]](#references)</sup> 유용한 payload가 되려면 설치된 backend가 comment를 직렬화하는 방식과 대상 파일이 내보낸 결과의 다른 행을 허용하는지에 달려 있습니다. `iptables-save`만으로는 임의의 지정 콘텐츠를 쓸 수 없습니다. 정확한 sudo RunAs ID, 인수와 제외 규칙, 사용 가능한 match 확장, backend 및 대상 권한을 확인합니다. 열거 중에는 firewall 규칙을 변경하거나 파일을 쓰지 말고 권한을 살펴봅니다.

### 권한 있는 Below 로깅 디렉터리

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)은 0.9.0 이전 Below 릴리스에서 world-writable `/var/log/below` 디렉터리를 만들던 문제입니다. 서비스 또는 sudo에서 허용된 명령이 영향을 받는 빌드를 root로 실행하는 경우, sticky bit가 없는 log 디렉터리에 쓰고 접근할 수 있는 사용자는 권한 있는 프로세스가 열기 전에 로그 항목을 symlink로 바꿀 수 있습니다. 설치된 패키지의 수정 여부, 정확한 권한 있는 실행 경로, 유효한 디렉터리 접근 권한, sticky bit와 ACL, `/var/log/below/error_root.log`의 메타데이터를 살펴봅니다. world-writable 경로나 sudo 규칙만으로는 전체 연결이 성립하지 않습니다. sticky 디렉터리나 vendor backport가 있으면 평가가 달라집니다. 수동 열거에서는 메타데이터만 확인하면 되며 link를 만들거나 권한 있는 프로그램을 실행할 필요가 없습니다.

### 쓰기 가능한 입력에서 권한 있는 support bundle 수집

sudo에서 허용된 support-profile 스크립트는 root로 고정된 log 경로를 읽고 그 내용을 profile 아카이브로 복사할 수 있습니다. 실제 스크립트의 파일 읽기를 살펴본 다음, 호출자가 source 경로 또는 상위 디렉터리 항목을 symlink로 바꿀 수 있는지 확인합니다. 권한 있는 읽기가 해당 link를 따라가고 결과 아카이브를 호출자가 읽을 수 있다면 보호된 파일이 노출될 수 있습니다. sudo 권한, 쓰기 가능한 source 경로, 권한 있는 읽기, 읽을 수 있는 출력이 모두 있어야 합니다. 쓰기 가능한 log나 profile 파일 이름만으로는 충분하지 않습니다. 열거 중에는 파일을 바꾸거나 profile을 생성하지 말고 유효한 권한과 link 메타데이터를 살펴봅니다. [Nagios XI 지원 지침](https://support.nagios.com/forum/viewtopic.php?t=62758)에는 root로 실행되는 profile 스크립트와 출력 아카이브가 설명되어 있어, 이러한 bundle의 입력과 출력 접근을 제한해야 하는 이유를 보여줍니다.

### root로 실행되는 Python 아카이브 복구 스크립트

범위가 엄격하게 제한된 Python 복구 스크립트 sudo 규칙도 아카이브 입력을 검토해야 합니다. 호출자가 아카이브를 선택하거나 바꿀 수 있고 스크립트가 root로 `tarfile.extractall(filter="data")`를 실행한다면, 해당 filter를 신뢰하기 전에 인터프리터의 보안 업데이트를 확인합니다. CPython은 CVE-2025-4517을 비롯한 여러 symlink 및 hard-link filter 우회 문제를 3.9.23, 3.10.18, 3.11.13, 3.12.11 및 3.13.4에서 수정했습니다. 배포판의 backport로 이전 버전도 수정되었을 수 있으므로 표시되는 인터프리터 버전만으로는 취약성이 입증되지 않습니다.<sup>[[16]](#references)[[17]](#references)</sup>

수동 검토에서는 정확한 sudo 명령과 스크립트를 읽고, 어떤 인수가 아카이브를 선택하는지 추적한 다음 현재 사용자가 아카이브나 그 상위 디렉터리에 쓸 수 있는지 확인합니다. 설치된 vendor 수정 사항과 압축 해제 대상은 별도로 확인합니다. `filter="data"`가 모든 신뢰할 수 없는 아카이브를 안전하게 만드는 것은 아닙니다.<sup>[[16]](#references)[[17]](#references)</sup>

### sudo로 실행되는 machine-learning model loader

호출자 선택 `.pt`, `.pth` 또는 `.ckpt` 파일을 허용하는 sudo 규칙은 권한 있는 스크립트가 해당 파일을 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html), `pickle.load` 또는 다른 pickle 기반 loader에 전달할 때 검토해야 합니다. 유효한 RunAs 규칙, 호출자가 선택된 model을 만들거나 교체할 수 있는지, shell wrapper를 거쳐 Python helper로 전달되는 실제 인수 흐름을 확인합니다. `.pth` 확장자는 관련 없는 Python site 설정 파일에도 사용되므로 확장자만으로는 model이 로드된다는 증거가 아닙니다. 아카이브 검사나 정적 pickle 검사만으로 이후 load가 안전한지 입증되지 않습니다. loader의 [버전에 따른 `weights_only` 동작](https://docs.pytorch.org/docs/stable/notes/serialization.html)과 allowlisting 여부를 살펴봅니다. [ML pickle 및 Fickling 참고 자료](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)를 참조하세요. 수동 열거에서 model을 로드하거나 압축 해제하지 않습니다.

### 저장된 입력을 sudo로 실행되는 표현식 parser가 처리하는 경우

sudo를 통해 root로 실행되는 고정 Python 스크립트도 낮은 권한 사용자가 애플리케이션 데이터베이스에 저장할 수 있는 텍스트를 평가할 수 있습니다. TensorFlow에서 `preprocess_input_exprs_arg_string(value, safe=False)` 호출은 `eval` 경로를 선택합니다. [TensorFlow 권고문](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)에는 안전하지 않은 parser와 명령줄 호출자 수정 사항이 설명되어 있습니다. 애플리케이션이 `safe=False`를 명시적으로 호출한다면 해당 명령줄 호출자가 패치된 경우에도 별도로 검토해야 합니다. 유효한 sudo 규칙, 누가 정확한 입력 행을 수정할 수 있는지, filtering 또는 scoring 과정에서 해당 행이 호출에 도달할 수 있는지, 설치된 함수의 동작을 확인합니다. TensorFlow 버전, sudo 권한 또는 하드코딩된 model 파일만으로는 연결이 입증되지 않습니다. 수동으로 스크립트와 데이터 흐름을 살펴보고, 열거 중에는 권한 있는 helper를 실행하거나 테스트 표현식을 제출하지 않습니다.

### sudo에서 허용된 needrestart 설정

`needrestart -c`는 호출자가 선택한 Perl 설정 파일을 불러와 평가합니다. `sudo -l`이 `needrestart`를 root로 실행하도록 허용하고 인수로 `-c`를 허용하며 호출자가 쓰기 가능한 위치에서 읽을 수 있는 설정 파일을 선택할 수 있다면 root 코드 실행으로 이어질 수 있습니다. 정확한 sudo RunAs 및 인수 규칙을 확인합니다. 고정 인수 목록만 허용하는 규칙은 이 경로를 막을 수 있습니다. 이는 needrestart의 interpreter scanning 취약성과 별개입니다. 패키지를 업데이트하거나 `interpscan`을 비활성화해도 제한 없는 root `-c` 권한이 안전해지는 것은 아닙니다.<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 다른 계정으로 실행되는 sudo Python import

고정 Python entry point도 호출자가 수정하거나 바꿀 수 있는 모듈을 import할 수 있습니다. sudo가 스크립트를 **root가 아닌** 서비스 사용자로 실행하는 경우도 마찬가지입니다. `from utils import status`처럼 리터럴 import가 있다면 로컬 `utils/__init__.py`와 `utils/status.py`, 패키지 디렉터리 권한을 모두 살펴봅니다. 쓰기 가능한 파일을 실행 경로라고 판단하기 전에 스크립트의 import 경로, 정확히 허용된 sudo 인수, 해당 작업이 import에 도달하는지 확인합니다. 열거 중에는 파일과 권한을 살펴보되 스크립트를 import하거나 실행하지 않습니다.<sup>[[2]](#references)[[3]](#references)</sup>

`python3 /absolute/script.py`에 대한 정확한 sudo 규칙은 스크립트를 읽을 수 있기만 하면 됩니다. 실행 권한이나 shebang은 필요하지 않습니다. 로컬에 **없는** 모듈도 검토합니다. 스크립트가 import하는 모듈의 파일 이름을 호출자가 쓸 수 있는 스크립트 디렉터리에 만들 수 있다면 Python은 RunAs ID로 해당 파일을 로드할 수 있습니다. 유효한 sudo 규칙, 인터프리터의 실제 [모듈 검색 경로](https://docs.python.org/3/library/sys_path_init.html), 모듈이 builtin이거나 frozen인지, import에 도달하는지 확인합니다. 스크립트에 대한 직접 sudo 규칙은 실행 비트와 shebang 요건이 다릅니다. `sudo -u account` 뒤에 호출자 제공 token을 추가하는 별도 wrapper도 인수 흐름을 검토해야 합니다. 추가 `-u`는 실행되는 sudo 정책이 결과 ID를 허용하는 경우에만 중요합니다. 정적 문자열만으로는 어느 경로도 입증되지 않습니다.

### 호출자 제어 설정으로 실행되는 sudo Apache

sudo 규칙이 권한 있는 `apachectl`, `apache2ctl` 또는 `httpd` 실행에서 호출자 제어 `-f` 설정 파일을 허용한다면 해당 파일과 상위 디렉터리의 권한을 검토합니다. Apache의 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) 지시어에는 모듈 이름과 **모듈 파일 이름**이 필요하며 [`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile)도 파일을 불러옵니다. [`Include`와 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include)은 설정을 확장하거나 오류를 통해 파일 내용을 노출할 수 있습니다. 사용자 지정 wrapper가 경로를 검증하거나 권한을 내리거나 인수를 제한할 수도 있으므로, 쓰기 가능한 설정만으로는 코드 실행 증거가 아니라 검토 후보일 뿐입니다. 결론을 내리기 전에 경로 정규화, symlink 및 지시어 파싱을 확인합니다.

### 호출자 제어 설정으로 실행되는 sudo nginx

root 가능 `nginx`에 대한 제한 없는 규칙으로 [`-c`를 사용해 다른 설정을 선택할 수 있습니다](https://nginx.org/en/docs/switches.html). 정확한 sudo 인수와 제외 규칙, 호출자가 설정을 제공할 수 있는지, 결과 master 또는 worker가 보호된 경로에 접근할 수 있는지 살펴봅니다. 선택한 `root`와 `autoindex`를 조합하면 새 listener를 통해 파일을 노출할 수 있습니다. [`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html)은 권한 있는 파일 쓰기 경로를 제공할 수 있지만 DAV module은 기본적으로 빌드되지 않습니다. 그 존재 여부, listener 접근 가능성, 파일 권한 및 임시 파일 동작을 확인해야 합니다. [`error_log` 지시어](https://nginx.org/en/docs/ngx_core_module.html#error_log)로 파일을 선택할 수도 있습니다. `/etc/ld.so.preload` 같은 민감한 설정 파일에 로그를 쓰려면 권한 있는 writer와 제어 가능한 log record가 있어야 권한 상승 경로가 됩니다. `sudo -l`에서 실행 파일이 강조 표시되는 것은 검토 단서일 뿐, 이 경로 중 어느 것이든 작동한다는 증거가 아닙니다. 수동 열거에서 nginx를 시작하거나 재설정하지 않습니다.

### 권한 있는 Bash prompt의 패턴 비교

sudo에서 허용된 Bash 스크립트가 호출자에게 값을 입력받고 `[[ "$expected" == $entered ]]`로 검사하면 Bash는 따옴표로 묶이지 않은 우변을 pattern으로 해석합니다. 따라서 wildcard를 사용하면 expected 값을 모른 채 비교를 통과할 수 있습니다. 우변을 인용하면(`[[ "$expected" == "$entered" ]]`) 리터럴 문자열 비교가 됩니다. 해당 구문만으로 악용 가능한 경로가 성립하지는 않으므로 정확한 sudo 규칙, prompt에 도달할 수 있는지, 비교 이후 스크립트가 무엇을 하는지 검토합니다. 열거 중에는 expected 값을 출력하지 않습니다. [Bash 조건문 참고 문서](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)를 참조하세요.

### 파일을 다운로드해 실행하는 sudo helper

호출자 선택 URL을 받아 응답을 디스크에 쓰고 나중에 해당 파일을 인터프리터나 셸로 실행하는 사용자 지정 helper에 대한 제한 없는 root 가능 sudo 권한은 데이터 흐름을 검토해야 합니다. [Sudoers에서 명령 항목에 인수를 적지 않으면 임의의 인수가 허용됩니다](https://man7.org/linux/man-pages/man5/sudoers.5.html). 실행 파일 경로가 고정되어 있어도 인수로 선택할 수 있는 항목은 제한되지 않습니다. 설치된 helper에서 실제 URL 검증, 출력 경로, 성공 분기 및 이후 실행을 확인합니다. libcurl import나 출력 가능한 문자열만으로는 이 연결이 입증되지 않습니다.

고정 출력 파일 이름도 helper가 **호출자가 제어하는 작업 디렉터리의 상대 경로**를 사용하면 쓰기와 실행 사이에 바뀔 수 있습니다. root 소유 파일을 이름 변경하거나 대체할 수 있는지는 파일 mode뿐 아니라 디렉터리 쓰기/검색 권한과 sticky-bit 제한에 달려 있습니다. [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)을 참조하세요. helper가 경로를 다시 여는지 이미 열린 descriptor를 사용하는지, 쓰기 전에 신뢰된 디렉터리로 이동하는지 확인합니다. 열거 중에는 권한 있는 다운로드를 실행하거나 race를 시도하지 말고 sudo 정책, helper 및 디렉터리 메타데이터를 살펴봅니다.

root sudo 다운로드 helper가 `curl <caller input> -o <fixed output>` 같은 Bash 명령 문자열을 조립한다면 **인수** 주입도 발생할 수 있습니다. 공백을 거부하는 filter만으로는 [Bash brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)이 막히지 않습니다. 인용되지 않은 쉼표 구분 요소가 여러 curl 인수로 나뉠 수 있습니다. 고정된 `-o`보다 앞서 입력이 curl에 도달한다면 호출자 제공 출력 옵션이 첫 URL의 대상을 helper ID로 지정할 수 있습니다. [curl은 출력 옵션을 URL 순서에 연결합니다](https://curl.se/docs/manpage.html#-o). 정확한 셸, 인용 방식, 입력 검증, 유효한 sudo 규칙, curl 인수 순서와 지원 URL scheme, 호출자가 가져올 바이트를 제어하거나 결과를 읽을 수 있는지 확인합니다. PyInstaller 패키징 실행 파일에 Python 애플리케이션 로직이 포함될 수 있지만, 패키징 표식이나 `curl` 문자열만으로는 이 데이터 흐름이 입증되지 않습니다. 권한이 허용되는 경우 범위를 제한한 오프라인 사본을 검토합니다. 일반적인 열거에서는 helper를 실행하거나 공격자가 선택한 데이터를 가져오지 않습니다.

root sudo 셸 스크립트가 [`mktemp -u` / `--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)을 호출해도 사용하지 않는 이름만 선택할 뿐 파일을 **만들지는 않습니다**. 스크립트가 이후 다른 사용자가 영향을 줄 수 있는 디렉터리에 해당 파일을 만들고 다시 연 다음 root의 `authorized_keys` 같은 보호된 대상에 내용을 덧붙인다면 임시 파일 race를 검토해야 합니다. 정확한 sudo 규칙, 디렉터리와 파일 소유권, 생성 및 재개방 순서, kernel 보호 기능, 권한 있는 쓰기가 공격자 제어 바이트를 실제로 사용하는지 확인합니다. `mktemp -u` 문자열이나 쓰기 가능한 `/tmp`만으로는 race가 입증되지 않습니다. 열거 중에는 스크립트와 경로 메타데이터를 살펴보되 실행하거나 임시 파일 race를 시도하지 않습니다.

## 방어 참고 사항

- sudo로 인터프리터나 대화형 편집기를 허용하지 않습니다.<sup>[[1]](#references)</sup>
- `tee`처럼 인수를 제한하지 않는 일반 파일 쓰기 도구를 허용하지 않습니다. 대상 경로를 고정하고 호출자 제어 경로를 거부하는 root 소유 wrapper를 사용합니다.<sup>[[2]](#references)</sup>
- 좁은 관리 작업 하나만 수행하는 고정된 root 소유 wrapper를 우선 사용합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 인터프리터가 불가피하다면 정확한 스크립트 경로를 제한하고 사용자 제어 인수, 쓰기 가능한 import, `PYTHONPATH`, 안전하지 않은 환경 변수 보존을 차단합니다.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 파일 편집이 필요하다면 정확한 파일 경로를 제한하고, 패치된 sudo 버전 및 엄격한 환경 처리를 적용한 `sudoedit` 사용을 고려합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, 쓰기 가능한 작업 디렉터리, 쓰기 가능한 모듈/import 경로, `NOEXEC`, `use_pty` 및 logging을 검토하되 이를 완전한 sandbox로 간주하지 않습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [명령줄 및 환경 — Python 문서](https://docs.python.org/3/using/cmdline.html)
- [4] [os — 기타 운영체제 인터페이스 — Python 문서](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl 인터프리터 실행 방법](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl 문서](https://perldoc.perl.org/functions/exec)
- [7] [Ruby 명령줄 옵션](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby 문서](https://ruby-doc.org/3.4/Kernel.html)
- [9] [명령줄 API — Node.js 문서](https://nodejs.org/api/cli.html)
- [10] [하위 프로세스 — Node.js 문서](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua 매뉴얼 페이지](https://www.lua.org/manual/5.4/lua.html)
- [12] [GNU nano 텍스트 편집기](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [리디렉션 — Bash 참고 매뉴얼](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 보안 릴리스](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile 압축 해제 filter — Python 문서](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart 설정 옵션 및 평가 — upstream 소스](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart 명령 동작 — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [단순 명령 확장 — Bash 참고 매뉴얼](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge compiler 옵션 — Foundry 문서](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry 문서](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch 매뉴얼 페이지](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) 설치 스크립트 — Arch 매뉴얼 페이지](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
- [27] [Volexity — VerdantBamboo: 방화벽 속 또 다른 BRICKSTORM](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/)
- [28] [GNU Coreutils — `tee`: 여러 파일 또는 프로세스로 출력 리디렉션](https://www.gnu.org/software/coreutils/manual/html_node/tee-invocation.html)
{{#include ../../banners/hacktricks-training.md}}
