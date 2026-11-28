# Sudo 명령어 악용

{{#include ../../banners/hacktricks-training.md}}

## Sudo로 허용된 인터프리터

`sudo -l`에서 사용자가 인터프리터를 root로 실행할 수 있도록 허용한다면, 이를 직접적인 코드 실행으로 간주하세요. 인터프리터는 임의의 코드를 실행하도록 설계되었으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 유사한 바이너리를 허용하는 규칙은 인수가 엄격하게 제한되고 검증되지 않는 한 일반적으로 root 명령어 실행과 같습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

일반적인 검토 절차는 먼저 사용자의 권한을 나열한 다음, 인터프리터의 `-c` 옵션으로 Python 문을 실행하는 것입니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

다른 interpreter 예시는 아래와 같습니다. 나열된 interpreter는 inline-code 실행 또는 child-process API를 문서화합니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

정확한 경로가 중요합니다. sudo 규칙이 `/usr/bin/python3`을 허용한다면 검증할 때도 해당 경로를 그대로 사용하세요.<sup>[[2]](#references)</sup>

`/usr/bin/python*`와 같은 sudo 실행 파일 glob은 Python 3용으로 작성된 스크립트에 Python 2도 허용할 수 있습니다. 스크립트가 호출자가 제어하는 텍스트로 `input()`에 도달하면 [Python 2는 해당 텍스트를 표현식으로 평가합니다](https://docs.python.org/2/library/functions.html#input). 인터프리터를 명시적으로 호출하면 스크립트의 shebang이 무시됩니다. 실행 경로로 간주하기 전에 설치되어 glob에 일치하는 바이너리, 유효한 RunAs 및 인수 정책, 거부 규칙, 그리고 입력 지점에 도달할 수 있는지 확인하세요.

root 권한을 부여할 수 있는 sudo 규칙에서 스크립트 경로를 고정해도 스크립트가 실행하는 내용까지 제한되지는 않습니다. 읽을 수 있는 Bash 래퍼라면 sudo에서 호출자가 인수를 선택할 수 있을 때 첫 번째 실행 명령이 `$1`과 같은 따옴표로 감싸지 않은 위치 매개변수를 **명령어 위치**에 사용하는지 확인하세요. 유효한 RunAs ID, 비밀번호 및 인수 정책, 이후의 거부 규칙, 실제 스크립트 분기를 확인하세요. `NOEXEC`, 안전한 인수 목록의 고정, 또는 명령어를 검증하는 래퍼가 결과를 바꿀 수 있습니다. 열거 중에 짧은 스크립트를 정적으로 살펴보고 테스트 명령으로 실행하지 마세요.

제한 없는 root 권한 sudo 규칙에서 `dotnet`도 인터프리터 관점에서 검토할 필요가 있습니다. .NET SDK가 설치되어 있으면 [`dotnet fsi`는 F# 코드를 대화형으로 실행하거나 스크립트에서 실행합니다](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/). [`dotnet run`은 소스에서 프로젝트를 실행합니다](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run). 먼저 유효한 RunAs ID와 정확한 인수 정책을 확인하세요. 특정한 안전한 하위 명령이나 신뢰할 수 있는 애플리케이션으로 고정된 규칙은 다른 권한 부여이며, 런타임만 설치된 환경에는 SDK 명령이 없을 수 있습니다. 실행 파일 이름만으로는 검토가 필요하다는 뜻일 뿐, 코드 실행의 증거는 아닙니다.

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed `tee`: 임의의 권한 상승 파일 쓰기

GNU `tee`는 표준 입력을 파일 피연산자로 지정된 모든 경로에 복사합니다. 따라서 호출자가 제어하는 인수를 사용해 `/usr/bin/tee`를 root로 실행하도록 허용하는 sudo 규칙은 임의의 root 파일을 생성하거나 덮어쓸 수 있는 기능을 부여합니다. `-a`를 추가하면 파일에 내용을 덧붙입니다. `PASSWD:` 태그는 sudo 인증과 관련된 것으로, 그 자체로 대상 경로나 표준 입력에서 읽을 바이트를 제한하지 않습니다.<sup>[[2]](#references)[[27]](#references)[[28]](#references)</sup>

먼저 정확한 규칙을 확인합니다. 권한이 있는 테스트 시스템에서는 안전하게 생성할 수 있는 임시 대상에 대해서만 이 기능을 검증합니다. 마지막의 `>/dev/null`은 `tee`가 표준 출력에 복사하는 내용만 억제합니다.<sup>[[28]](#references)</sup>

```bash
sudo -l
printf '%s\n' 'controlled-write' | sudo /usr/bin/tee /root/tee-proof >/dev/null
printf '%s\n' 'appended-line' | sudo /usr/bin/tee -a /root/tee-proof >/dev/null
```

`sudo`를 producer 앞에 붙여도 이후의 셸 리디렉션은 권한 상승되지 않습니다. 호출한 셸이 대상 파일을 열기 때문입니다. 위 파이프라인처럼 권한이 있는 프로세스가 파일을 써야 합니다.<sup>[[1]](#references)[[15]](#references)</sup>

쓰기 권한을 확인한 다음 [Arbitrary File Write to Root](../interesting-files-permissions/write-to-root.md)에서 적절한 root 코드 실행 sink를 선택하세요. 관찰된 한 체인에서는 root 권한의 `tee`로 `/etc/cron.d/` 아래에 수명이 짧은 파일을 만든 뒤, 사용자가 제어하는 스크립트를 통해 backdoor를 실행하고 실행 후 cron 파일을 삭제했습니다. cron 파일을 삭제하면 장기 persistence 항목으로 남는 것을 막을 수 있지만, 시스템 로그에는 여전히 해당 활동의 증거가 남았습니다.<sup>[[27]](#references)</sup>

## Sudo가 허용하는 편집기

`sudo -l`에서 사용자가 root 권한으로 대화형 편집기를 실행할 수 있다고 나온다면, 이를 무해한 파일 편집 권한이 아니라 명령 실행 표면으로 간주하세요. 편집기 내부에서 셸 명령을 실행하거나, 임의의 파일을 읽고 쓰거나, 외부 helper를 호출할 수 있는 경우가 많습니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

일반적인 검토 절차: 사용자의 권한을 확인한 다음, 허용된 각 편집기나 pager를 sudo로 실행합니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nano 명령 실행

`nano`를 sudo를 통해 사용할 수 있는 경우, 편집기 인터페이스에서 명령을 실행할 수 있습니다.<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

그런 다음 nano 명령 프롬프트에 `id` 또는 `/bin/sh`와 같은 명령을 입력합니다.<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

대화형 셸에서 사용할 수 있는 터미널 스트림이 없다면, 이 리디렉션 형식은 표준 출력과 오류를 디스크립터 0에 매핑합니다.<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

정확한 키 입력 순서는 nano 버전과 빌드 옵션에 따라 다를 수 있지만, 보안 문제는 동일합니다. 편집기가 root 권한으로 실행되며 외부 명령을 호출할 수 있습니다.<sup>[[1]](#references)[[12]](#references)</sup>

### 기타 흔한 편집기 탈출 방법

Vim 스타일 편집기에서는 일반적으로 `:!`를 통해 명령을 실행할 수 있습니다.<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

`less`와 같은 pager를 통해서도 shell 실행이 가능할 수 있습니다.<sup>[[14]](#references)</sup>

`apport-cli`를 root로 실행하도록 허용하는 sudo 규칙도 동일하게 pager를 검토해야 합니다. 영향을 받는 Apport 버전에서는 공격자가 조정할 수 있는 터미널 크기로 crash report를 `less`에서 열 수 있었으며, 특수한 sudo 및 pager 조건이 충족되면 pager를 통해 root shell을 얻을 수 있었습니다. 버전만 보고 취약하다고 판단하기 전에 유효한 sudo 규칙, pager 설정, 배포판 패키지의 수정 여부를 확인하세요. 수동 열거 단계에서는 crash를 발생시키거나 권한이 높은 report를 열지 말고 패키지 및 정책 메타데이터를 읽으세요. [Ubuntu의 CVE 기록](https://ubuntu.com/security/CVE-2023-1326)에는 백포트 수정 사항을 포함해 릴리스별 수정 패키지 버전이 나와 있습니다.

```text
!/bin/sh
```

## 기타 sudo 및 doas 규칙의 위험 요소

`sudo -l`, `sudo -V`, 그리고 해당하는 `doas` 정책부터 확인하세요. 허용된 명령, 실행 대상 사용자, 인수, 환경, 기본값을 함께 살펴보세요. root가 아닌 서비스 계정으로 실행할 권한도 해당 계정의 파일에 접근하거나 root로 이어지는 경로를 노출할 수 있습니다.

sudo에서 허용한 고정 Python 스크립트라도 대화형 입력이나 호출자가 제어하는 입력을 [`os.system()`](https://docs.python.org/3/library/os.html#os.system)에 이어 붙이면 RunAs 사용자 권한으로 shell 명령을 실행할 수 있습니다. shell 구두점을 차단 목록으로 막는 것만으로는 안전성을 입증할 수 없습니다. [shell은 `$(...)` 명령 치환도 인식합니다](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html). 허용된 인수가 입력 분기로 전달되는지, 입력이 안전한 검증 없이 shell 명령에 전달되는지, 유효한 sudo 정책이 의도한 RunAs 사용자를 허용하는지 확인하세요. 스크립트 경로나 `os.system()` 호출만으로는 검토할 단서일 뿐입니다. 권한이 필요한 스크립트는 실행하지 말고 소스를 확인하세요.

`chattr`에 대한 root 권한의 유효한 sudo 허가는 immutable (`i`) 파일 속성을 제거할 수 있지만, 이것만으로 쓰기 권한이나 새로운 신원이 부여되지는 않습니다. [`chattr` 매뉴얼](https://man7.org/linux/man-pages/man1/chattr.1.html)에 따르면 이 속성은 수정을 차단하며, root 또는 `CAP_LINUX_IMMUTABLE` 권한이 있는 프로세스만 변경할 수 있습니다. 정확한 sudo 인수 정책과 파일시스템 지원 여부를 확인한 뒤, 속성을 해제한 후 호출자가 파일에 쓸 수 있는지, 더 높은 권한의 프로세스가 해당 파일을 사용하는지 별도로 확인하세요. 예를 들어 로그인 shell을 바꾸려면 대상 계정에서 허용하는 자격 증명이 있어야 하고, 실제로 해당 shell을 통해 로그인해야 합니다. 열거 과정에서는 정책, 파일 속성, 권한을 변경하지 말고 검토하세요.

sudo가 비밀번호와 일회용 코드 모두를 요구한다면, 두 요건을 명령 허가와 별개로 다루세요. 읽을 수 있는 `.google_authenticator` 파일에는 민감한 seed 자료가 들어 있고, 오래된 애플리케이션 또는 데이터베이스 비밀번호 hash는 현재 계정 비밀번호 후보일 뿐입니다. 어느 쪽도 유효한 PAM 설정이 다른 인증 요소를 허용한다는 증거가 아닙니다. 권한이 확인되면 정확한 RunAs와 인수를 검토하세요. RubyGems `gem`에 대한 제한 없는 root 권한 허가는 편집기 명령을 노출할 수 있지만([GTFOBins](https://gtfobins.github.io/gtfobins/gem/)), 제한된 허가나 인증 실패로는 그렇지 않습니다. 수동 열거에서는 seed를 출력하거나, 비밀번호를 복구하거나, 코드를 생성하거나, 권한 명령을 실행하지 말고 경로와 정책만 보고하세요.

Chef의 `knife`에 대한 제한 없는 root 권한 sudo 허가는 interpreter 수준의 검토가 필요합니다. [Chef 문서에 따르면 `knife exec -E`는 로컬에서 Ruby 문자열을 평가합니다](https://docs.chef.io/workstation/26/tools/knife/knife_exec/). 유효한 sudo 규칙이 `exec` 하위 명령과 호출자 제공 `-E` 인수, 의도한 RunAs 신원, 그리고 일치하는 명령 거부 규칙이나 고정 인수를 허용하는지 확인하세요. 설치된 바이너리나 다른 하위 명령으로 제한된 규칙은 검토 단서일 뿐입니다. 수동 열거에서는 `knife`를 실행하지 말고 정책만 보고하세요.

대화형 `msfconsole`에 대한 root 권한의 정확한 sudo 허가도 마찬가지로 민감합니다. [GTFOBins는 `irb` console을 문서화하고 있으며](https://gtfobins.org/gtfobins/msfconsole/), 이 console은 sudo 신원을 상속할 수 있습니다. 유효한 RunAs 사용자, 허용된 인수 목록, 명령 거부 규칙, `NOEXEC` 또는 기타 제한, 설치된 console의 동작, 호출자가 대화형 입력을 제공할 수 있는지 확인하세요. 경로가 강조 표시된 것만으로는 검토 단서일 뿐입니다. 수동 열거에서는 console을 실행하지 마세요.

FreeBSD에서는 root 권한으로 `pkg update`와 `pkg install *`만 허용하는 sudo 규칙도 저장소 신뢰 검토가 필요합니다. `/etc/hosts`를 호출자가 쓸 수 있는지, 그리고 *유효하게* 활성화된 저장소 설정이 `signature_type: none`인 HTTP hostname을 사용하는지 확인하세요. [FreeBSD `pkg.conf` 매뉴얼](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)에 따르면 `none`은 서명 검사를 비활성화합니다. `pkg+http`만으로는 이를 입증할 수 없습니다. 패키지에는 설치 스크립트가 포함될 수 있으므로([FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)), 저장소 endpoint를 실제로 제어하고 패키지를 선택할 수 있는 호출자는 root 경계를 넘을 수 있습니다. 결론을 내리기 전에 저장소 재정의, SRV/미러 해석, 유효한 sudo 인수, 패키지 선택, 스크립트 실행 여부를 확인하세요. 열거 중에는 이름을 다른 곳으로 리디렉션하거나 `pkg`를 실행하지 말고 정책과 작은 로컬 설정 파일만 확인하세요.

root 권한의 `apt-get update` 및 `apt-get upgrade` sudo 허가도 sudo가 호출자 제어 `http_proxy`를 보존한다면 저장소 신뢰 검토가 필요합니다. 유효한 APT proxy 설정이 실제로 해당 변수를 사용하고, 활성화된 저장소 요청 중 어떤 요청에 영향을 줄 수 있는지 확인하세요. 신뢰된 서명 키로 인증된 archive의 패키지를 proxy만으로 바꿀 수는 없습니다. [APT HTTP transport 매뉴얼](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)은 proxy 우선순위를 설명하고, [apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)는 서명 검사, 안전하지 않은 저장소 재정의, 인증되지 않은 패키지에 대한 확인 절차를 설명합니다. 정확한 sudo RunAs 및 인수, 저장소 인증 정책, 필요한 대화형 승인, 선택한 업그레이드가 root로 패키지 스크립트를 실행하는지 확인하세요. 수동으로 정책과 로컬 설정을 검토하고, 열거 중에는 패키지 트래픽을 리디렉션하거나 업그레이드를 실행하지 마세요.

root 권한의 `snap install` sudo 규칙은 인수가 호출자가 로컬 snap과 완화된 설치 모드를 선택할 수 있게 한다면 패키지에서 코드로 이어지는 경계가 될 수 있습니다. [Snap 문서](https://snapcraft.io/docs/explanation/snap-development/install-modes/)에 따르면 `--dangerous`는 로컬 snap의 assertion 검사를 건너뛰고 `--devmode`는 confinement을 완화합니다. [설치 hook은 최초 설치 시 실행될 수 있습니다](https://snapcraft.io/docs/reference/development/supported-snap-hooks/). 정확한 sudo 인수/RunAs 정책, snap 파일의 제어 주체, 설치된 snapd가 해당 모드를 허용하는지, 보호된 host 파일에 접근한다고 주장하기 전에 hook의 유효 신원과 confinement을 확인하세요. `snap` 바이너리나 wildcard처럼 보이는 규칙만으로는 이 과정이 입증되지 않습니다. 수동 열거에서는 패키지를 설치하거나 hook을 실행하지 마세요.

**root가 아닌** 계정의 자격 증명을 읽는 사용자 지정 바이너리에 대한 정확한 sudo 허가라면, 먼저 실행하지 말고 허가된 바이너리와 파일 권한을 확인하세요. 내장된 비밀번호 검사는 넓은 문자 단위로만 보일 수 있습니다. [GNU `strings`는 16-bit little-endian 추출을 문서화합니다](https://sourceware.org/binutils/docs/binutils/strings.html). 문자열이 보인다고 해서 그것이 허용되는 비밀번호이거나 성공 분기가 현재 자격 증명을 노출한다는 증거는 아닙니다. 바이너리 동작, 대상 계정의 보호 데이터 접근 권한, 자격 증명 유효성, 이후 계정 또는 그룹 전환을 각각 확인하세요. 해당 계정이 `docker` 그룹에 속한다면 socket 접근과 daemon의 rootful 또는 rootless 신원을 확인한 뒤 host-root 접근을 추론하세요. [Docker는 해당 그룹의 root 수준 영향을 문서화합니다](https://docs.docker.com/engine/install/linux-postinstall/). 일반적인 열거에서는 바이너리를 실행하거나 문자열을 덤프하지 말고 sudo 규칙과 그룹 멤버십만 보고하세요.

애플리케이션 유지 관리 스크립트에 대한 wildcard sudo 규칙은 스크립트 경로만으로 판단하지 말고 추가 검토해야 합니다. 허용된 스크립트가 제한 없는 인수를 받거나 권한이 낮은 애플리케이션 계정이 쓸 수 있는 설정을 읽는지 확인한 뒤, 해당 값이 shell 명령이나 subprocess 환경으로 이어지는지 추적하세요. 예를 들어 ZoneMinder의 [`zmupdate.pl`은 `mysqldump` 명령을 구성해 `qx`로 실행하고](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in), [`zmdc.pl`은 daemon을 시작하기 전에 `ZM_LD_PRELOAD` 설정을 `LD_PRELOAD`에 복사합니다](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in). 대응하는 입력을 제어할 수 있고 설치된 버전의 해당 코드에 도달한다면 둘 중 하나를 root로 허용하는 sudo 규칙은 신뢰 경계를 넘을 수 있습니다. 유효한 sudo 규칙, 애플리케이션 설정 권한, 스크립트 소스를 확인하세요. wildcard나 설정만으로는 실행이 입증되지 않으며, 검토 단서일 뿐입니다.

- `SETENV`, `env_keep`, `secure_path`, `LD_PRELOAD`는 제한된 명령을 import, library 또는 PATH hijack으로 바꿀 수 있습니다. [환경 변수 가이드](../linux-basics/linux-environment-variables.md)와 [SUID/linker 악용](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)을 참고하세요.

shell wrapper에 대한 root 권한의 정확한 `SETENV` 허가는 wrapper가 literal import를 사용해 고정 Python 스크립트를 시작하는 경우 한 단계만 추가로 검토해도 충분할 수 있습니다. `secure_path`는 shell 명령 조회를 제한할 뿐 Python의 [`PYTHONPATH` 모듈 검색](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)은 제한하지 않습니다. [`-E`와 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E)를 사용하면 Python이 해당 환경 변수를 무시합니다. 이를 코드 실행으로 판단하기 전에 유효한 sudo tag와 거부 규칙, wrapper 분기, interpreter 옵션, import 해석, 호출자가 쓸 수 있는 검색 디렉터리를 확인하세요. 짧은 스크립트는 정적으로 검토하고, 권한이 필요한 wrapper는 실행하지 마세요.

`neofetch ""`에 대한 root 권한의 정확한 sudo 허가도 해당 sudo 기본값이 호출자 제어 `XDG_CONFIG_HOME`을 보존한다면 shell 설정을 불러올 수 있습니다. [Neofetch의 설정 loader](https://github.com/dylanaraps/neofetch/blob/master/neofetch)는 해당 디렉터리 아래의 `neofetch/config.conf` 또는 `neofetch/config`를 불러옵니다. 빈 인수 목록도 이 조회를 막지 않습니다. 설치된 loader, 유효한 RunAs 및 인수 정책, 명령 거부 규칙, sudo가 실제로 이 명령에서 선택된 변수를 보존하는지, 호출자가 읽을 수 있는 설정 경로를 제어하는지 확인하세요. 변수가 보존되거나 Neofetch가 설치된 사실만으로는 검토 단서일 뿐입니다. 권한이 필요한 명령을 실행하거나 설정 내용을 출력하지 말고 정책과 파일 metadata를 확인하세요. [sudoers 환경 처리](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)를 참고하세요.

제한 없는 root 권한 `facter` sudo 규칙은 사용자 지정 fact를 별도로 검토해야 합니다. [Puppet 문서](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)에 따르면 `--custom-dir`은 선택된 디렉터리의 Ruby fact 파일을 불러옵니다. 정확한 sudo 규칙이 해당 옵션을 허용하는지, 설치된 Facter가 이를 지원하는지, 호출자가 디렉터리를 제어하는지 확인하세요. 고정 인수 허가, 명시적 명령 거부, 사용자 지정 fact 비활성화 여부에 따라 결과가 달라질 수 있습니다. 수동 열거에서는 Facter를 실행하거나 fact 내용을 읽지 말고 정책상 가능성만 보고하세요.

`SETENV`가 있는 root 권한의 정확한 sudo 스크립트 허가라면 `find` 같은 bare command name과 sudo 정책 및 스크립트 초기화 후의 유효한 `PATH`를 확인하세요. source된 Bash 파일에서 `enable -n [`을 실행할 수도 있습니다. 이후 스크립트가 해당 명령을 사용할 때 [Bash는 `PATH`에서 외부 `[` 명령을 찾습니다](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html). 적용되는 [sudoers 환경 및 `secure_path` 규칙](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf), `NOSETENV`/`NOEXEC` 또는 거부 규칙, 스크립트 및 source 파일의 흐름, 호출자가 제어하는 실행 가능 검색 디렉터리를 확인하세요. bare command가 포함된 읽을 수 있는 스크립트는 검토 단서이지 권한 실행의 증거가 아닙니다. sudo 규칙을 실행하지 말고 확인하세요.
- 고정 URL을 `curl`로 가져오는 권한 스크립트라도 적용되는 sudo 규칙이 `http_proxy`를 보존하고 요청이 해당 proxy를 통한다면 호출자가 응답을 선택할 수 있습니다. 이어서 스크립트가 응답을 외부 entity를 해석하는 XML parser에 전달하면 악성 응답으로 권한 프로세스가 읽을 수 있는 파일을 유출할 수 있습니다. 정확한 sudo 환경 정책, `no_proxy` 제외 설정, 요청 URL, parser 설정, 출력 위치를 확인하세요. proxy 변수나 XML parser만으로는 취약점이 성립하지 않습니다. [curl proxy 환경 문서](https://everything.curl.dev/usingcurl/proxies/env.html)는 변수 동작을 설명합니다. 수동 열거 중에는 네트워크 요청을 보내거나 악성 XML을 파싱하지 마세요.
- 호출자 영향 데이터로 PostScript 파일을 만들고 `ps2pdf -dNOSAFER`를 실행하는 root 권한 스크립트는 입력 흐름을 별도로 검토해야 합니다. Ghostscript 문서에 따르면 이 flag는 `.setsafe`가 호출될 때까지 SAFER를 비활성화해 프로세스의 OS 권한 범위에서 PostScript 파일 작업을 허용합니다. 호출자 인수로 조립한 SQL query가 공격자 제어 행을 PostScript template에 넣을 수는 있지만, query 문자열이나 `ps2pdf` 호출만으로 데이터가 실행 가능한 PostScript 구문에 도달한다고 입증되지는 않습니다. 권한이 필요한 변환을 수동 열거 중 실행하지 마세요. 유효한 sudo 규칙, 입력에서 template까지의 정확한 경로, escaping 여부, 설치된 Ghostscript의 동작, 문서 해석 전에 SAFER가 다시 활성화되는지 확인하세요. [Ghostscript의 `-dNOSAFER` 문서](https://ghostscript.readthedocs.io/en/master/Use.html)를 참고하세요.
- shell 스크립트를 실행하는 sudo 규칙이라면 보존된 변수를 스크립트 자체와 비교하세요. `if $CHECK_CONTENT; then` 같은 구문은 확장된 값을 명령으로 실행하므로, 스크립트 경로와 인수가 고정되어 있어도 `CHECK_CONTENT`를 보존하면 명령 실행이 가능할 수 있습니다. 해당 분기가 도달 가능한지, 환경이 실제로 보존되는지 구체적인 규칙에 따라 확인해야 합니다.<sup>[[2]](#references)[[22]](#references)</sup>
- sudo에서 허용한 Python 스크립트는 쓰기 가능한 디렉터리나 cache된 `.pyc` 파일에서 코드를 import할 수 있습니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md)는 cache 사례를 설명합니다.
- root 권한으로 실행이 허용된 고정 Python 스크립트도 대화형 debugger를 노출할 수 있습니다. 호출자가 breakpoint나 예외 처리기에 도달할 수 **있고 debugger 입력 스트림도 제어할 수 있다면**, `pdb.set_trace()` 또는 `pdb.post_mortem()` 같은 호출로 디버깅 대상 프로세스의 컨텍스트에서 Python 구문을 실행할 수 있습니다. 정확한 sudo RunAs 규칙, 인증 및 분기 조건, 예외 도달 가능성, terminal/input 소유권, debugger가 동일한 권한 프로세스에서 실행되는지 확인하세요. 다른 terminal에 연결된 debugger는 socket 요청이 예외를 일으키는 것만으로 접근할 수 없습니다. [Python 문서](https://docs.python.org/3/library/pdb.html)는 debugger의 구문 평가와 post-mortem 모드를 설명합니다. 열거 중에는 권한 handler를 유발하지 말고 스크립트를 정적으로 검토하세요.
- sudo에서 허용한 고정 Python 스크립트가 데이터베이스나 Unix socket에서 profile 필드를 읽어 나중에 `str.format()`의 **format string**이 되는 문자열에 덧붙일 수도 있습니다. [replacement field는 attribute와 mapping key를 따라갈 수 있으므로](https://docs.python.org/3/library/string.html#format-string-syntax), 공격자 제어 필드가 `format()`에 전달된 객체를 조회하고 결과가 출력되거나 호출자가 읽을 수 있는 곳에 저장되면 해당 객체에서 접근 가능한 데이터를 노출할 수 있습니다. 유효한 sudo RunAs 신원, 특정 record에 대한 쓰기 권한, format string으로 이어지는 데이터 흐름, 전달되는 객체, 출력의 가시성을 확인하세요. 이것은 자동으로 코드 실행을 뜻하지 않으며, 신뢰된 literal format string에 공격자 제어 *값*을 전달하는 경우와는 다릅니다. 노출된 secret이 OS 계정 전환으로 이어지려면 해당 계정에서 이를 허용해야 합니다. 권한 작업을 실행하지 말고 스크립트와 socket 권한을 검토하세요.
- root 권한 Python wrapper가 호출자 선택 URL을 GitPython의 `Repo.clone_from`에 전달할 수 있습니다. wrapper가 Git의 `protocol.ext.allow=always`도 활성화한다면 `ext::` remote로 외부 helper를 실행할 수 있습니다. 정확한 sudo 인수, URL의 출처, GitPython package 버전 및 vendor patch 적용 여부, wrapper가 안전하지 않은 protocol을 명시적으로 허용하는지 확인하세요. GitPython은 3.1.30에서 [기본 unsafe-protocol guard](https://github.com/gitpython-developers/GitPython/commit/2625ed9)를 추가했습니다. `git` 실행 파일의 버전은 별개의 사실입니다. 수동 검토에서는 clone을 실행하지 말고 규칙과 제한된 범위의 소스만 확인하세요.
- 저장소를 clone하는 CLI에 대한 사용자 간 sudo 허가는 별도의 shell 문자열 injection 경로를 노출할 수 있습니다. 호출자 선택 저장소 인수가 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) 또는 안전한 인수 분리를 하지 않는 다른 shell 명령 구성기에 전달되는지 추적하세요. Node의 `exec`는 명령 문자열을 shell에 전달합니다. 정확한 RunAs 사용자, 허용된 하위 명령 및 인수, 설치된 wrapper 코드, 입력 검증을 확인하세요. 저장소 도구의 이름이나 제한 없는 sudo 규칙만으로 명령 injection이 입증되지는 않습니다. 열거 중 권한 clone을 실행하지 말고 wrapper를 확인하세요.
- 사용자 지정 root 소유 wrapper는 바이너리와 스크립트에 쓰기 권한이 없어 안전해 보여도, 권한 작업을 실행할지 여부가 권한이 낮은 사용자가 바꿀 수 있는 flag, 로컬 API 값 또는 서비스 상태에 따라 결정될 수 있습니다. 각 조건을 입력과 권한 검사까지 추적하세요. 열거 중 운영 상태를 바꾸지 말고 설정과 권한을 확인하세요. wrapper 안의 `systemd-run` 호출은 조건을 조작할 수 있을 때만 관련이 있습니다.
- root로 sudo를 통해 허용된 백업 클라이언트가 호출자 선택 설정 파일(예: `npbackup-cli -c`)을 받을 수 있습니다. 정확한 실행 대상 사용자와 허용 인수를 확인한 뒤, 호출자가 설정 경로, 백업 소스 경로, 저장소 또는 읽기/복원 옵션을 제어하는지 살펴보세요. 읽을 수 있는 설정에 암호화된 저장소 secret이 있더라도 클라이언트에서 이를 사용할 수는 있지만, 규칙만으로 저장소 접근이나 root 파일 유출이 입증되지는 않습니다. 백업을 실행하거나 내용을 덤프하지 말고 권한만 확인하세요.
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst)은 저장소 비밀번호를 얻기 위해 프로그램을 호출하는 `--password-command`를 지원합니다. sudo 규칙이 권한이 낮은 사용자에게 호출자 선택 비밀번호 명령과 비밀번호가 필요한 하위 명령을 사용해 root로 restic을 실행하도록 허용한다면, 해당 helper는 root로 실행될 수 있습니다. 정확한 sudo 인수와 제외 규칙을 검토하세요. 이 조건을 열거하려고 helper나 백업 명령을 실행하지 마세요.
- root 권한의 `restic backup` 허가는 sudo 인수 패턴이 호출자에게 source와 나중에 읽고 복호화할 수 있는 저장소를 모두 선택하게 한다면 파일 읽기 경계를 넘을 수도 있습니다. [Sudoers 인수 wildcard는 공백과 slash를 일치시킬 수 있으므로](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf), 고정 저장소 접두사가 source를 제한한다고 가정하지 말고 뒤쪽 wildcard를 확인하세요. [Restic은 로컬 및 원격 저장소에 백업할 수 있습니다](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html). 하지만 로컬 저장소에는 새로 기록된 root 전용 객체가 있을 수 있습니다. 이를 정보 노출로 판단하기 전에 유효한 sudo 정책, backend 접근, 저장소 비밀번호, 생성되는 객체의 권한을 확인하세요. 백업한 SSH key는 대상 계정이 이를 허용할 때만 접근을 허가합니다. 수동 검토 중에는 이를 시험하려고 백업을 실행하지 마세요.
- 제한 없는 사용자 지정 유지 관리 또는 백업 명령은 출력 경로를 받거나 자체 작업 scheduler를 제공할 수 있습니다. 파일 쓰기 경로라면 정확한 sudo 규칙과 RunAs 사용자를 확인한 뒤, 호출자가 데이터와 대상 경로를 모두 제어하는지 살펴보세요. 예약 명령 경로라면 scheduler의 실행 신원, 명령 입력, 추가 비밀번호 또는 권한 확인 절차를 확인하세요. 명령 이름이나 `NOPASSWD`만으로는 어느 경로도 입증되지 않습니다. [root 소유 파일에 쓰기](../interesting-files-permissions/write-to-root.md) 및 [cron과 systemd timer](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)를 참고하세요.
- 고정 sudo 명령도 공유된 쓰기 가능 디렉터리에서 예측 가능한 설정 파일을 불러올 수 있습니다. 호출자가 해당 파일을 바꿀 수 있는지, 그 파일의 source 및 destination 필드가 권한 프로세스의 fetch 또는 copy를 제어하는지 추적하세요. 로컬 파일 URL은 sudo RunAs 계정만 읽을 수 있는 데이터를 노출할 수 있고, 호출자 제어 source와 보호된 destination을 조합하면 쓰기 경로가 될 수 있습니다. 설치된 프로그램의 URL 처리, destination 경로 검사, 유효한 sudo 규칙, 출력 접근성을 확인하세요. 쓰기 가능한 `/tmp` 설정 경로만으로는 검토 단서일 뿐입니다. 권한이 필요한 전송을 실행하지 말고 바이너리와 파일 metadata를 확인하세요.
- `git apply` sudo 규칙은 RunAs 계정이 호출자 제어 patch에서 선택한 파일을 쓰게 할 수 있습니다. [CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)에서는 명령이 `--unsafe-paths`를 허용하지 않아도 조작된 patch로 symlink를 만든 뒤 working tree 밖에 쓸 수 있었습니다. 유효한 sudo 인수 규칙, patch 출처, RunAs 계정의 working-directory 접근 권한, 설치된 Git의 수정 여부 또는 vendor backport를 확인하세요. `--unsafe-paths`를 허용하는 제한 없는 규칙은 별도의 명시적 옵션 위험입니다. Git 버전이나 `git apply` 허가만으로 보호된 파일을 변경할 수 있다고 입증되지는 않습니다. 수동 열거 중에는 신뢰할 수 없는 patch를 적용하지 마세요.
- root 권한의 `clamscan --debug` 규칙은 권한이 낮은 사용자가 DMG 이미지를 제공할 수 있고 설치된 parser가 [CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)의 영향을 받는다면 읽기 경계를 넘을 수 있습니다. 이 취약점은 debug 출력으로 파일 내용을 노출할 수 있었습니다. 정확한 허용 인수와 scan 경로, 입력 제어, 유효한 RunAs 계정, engine patch/backport, 출력이 호출자에게 보이는지 확인하세요. 더 광범위한 규칙이 `--file-list`/`-f`를 허용한다면 해당 file-list 동작은 별도로 검토하세요. `--debug <scan-path>`로 고정된 정책은 이를 허용하지 않습니다. 열거 중에는 조작된 파일을 검사하거나 보호된 출력을 출력하지 말고 정책과 패키지 metadata를 확인하세요.
- root 권한의 sudo 규칙이 호출자 선택 암호화된 디스크 이미지를 여는 명령과 결과 mapper를 mount하는 두 번째 규칙을 허용한다면, 호출자 제어 파일을 host의 mount namespace로 가져올 수 있습니다. 두 유효 규칙과 인수, 이미지 및 mapper 이름의 제어 여부, 실제 mount 대상, 결과 파일의 소유자와 mode를 확인하세요. set-user-ID 전환에는 접근 가능한 실행 파일, 해당 속성을 허용하는 mount 옵션(`nosuid`는 이를 차단함), 적용되는 프로세스 또는 MAC 정책도 필요합니다. 이미지 열기나 mount만으로는 검토 단서일 뿐입니다. 기존 백업을 통한 별도 경로에는 실제 key와 그 안에 있는 유용하고 읽을 수 있는 secret이 필요합니다. 수동 열거 중에는 이미지를 열거나 mount하지 말고 정책과 경로를 검토하세요. [cryptsetup 매뉴얼](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) 및 [mount 옵션](https://man7.org/linux/man-pages/man8/mount.8.html)을 참고하세요.
- shell 또는 Python 스크립트에 대한 root 권한 sudo 규칙은 스크립트가 고정 디렉터리로 이동하지 않은 채 `./helper`를 호출한다면 working directory를 검토해야 합니다. `subprocess.run`에 전달한 `['./helper']` 같은 Python list도 호출자가 working directory를 선택하는 동일한 동작을 할 수 있습니다. 호출자는 쓰기 가능한 디렉터리를 선택하고 그곳에 해당 상대 이름의 실행 파일을 둘 수 있습니다. 스크립트의 다른 위치에서 절대 경로를 사용하는 것만으로는 이 호출이 보호되지 않습니다. 코드 실행으로 판단하기 전에 유효한 규칙, `runchdir` 또는 다른 디렉터리 변경 정책, 스크립트 흐름과 분기 도달 가능성, 쓰기 및 실행 가능한 디렉터리, mount/`NOEXEC` 제한을 확인하세요. 스크립트를 읽을 수 없다면 승인된 경로로 소스를 검토할 때까지 동작은 알 수 없습니다. helper를 실행하지 말고 스크립트를 정적으로 검토하세요. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)은 working-directory 정책을 설명합니다.
- root 권한의 고정 Python validator도 호출자 선택 데이터 파일을 평가할 수 있습니다. [Python의 `eval()` 문서는 신뢰할 수 없는 입력에 사용하지 말라고 경고합니다](https://docs.python.org/3/library/functions.html#eval). 입력 접미사 검사, 산술식 접두사, 검증 분기는 나머지 표현식이 `eval`에 도달한다면 sandbox가 아닙니다. 이를 실행 경로로 판단하기 전에 유효한 sudo 규칙, 호출자가 정확한 파일을 선택하고 제어할 수 있는지, parser의 분기 조건과 표현식 구성, 권한 프로세스 신원을 확인하세요. 읽을 수 있는 스크립트에 `eval`이 있다는 것만으로는 검토 단서일 뿐입니다. 열거 중에는 validator를 실행하거나 시험 표현식을 제출하지 말고 소스와 파일 권한을 확인하세요.
- root 권한 Ruby wrapper가 `YAML.load(File.read("dependencies.yml"))`처럼 상대 YAML 파일명을 읽는다면, wrapper 또는 sudo 정책이 해당 디렉터리를 고정하지 않는 한 호출자의 working directory에서 입력을 가져올 수 있습니다. 정확한 허용 인수, 디렉터리 및 파일 권한, 설치된 Psych 동작을 확인하세요. 예전 `YAML.load` 구현은 임의 Ruby 객체를 역직렬화할 수 있었지만, 최신 release는 기본적으로 허용 class를 제한합니다. 정적 호출 지점만으로는 검토 단서일 뿐입니다. 파일이 실제로 호출자 쓰기 가능 디렉터리에서 오는지, 설치된 loader가 위험한 class를 허용하는지 확인하세요. 신뢰할 수 없는 입력에는 명시적인 최소 class allowlist를 지정한 `safe_load`를 선호하세요. [Ruby 3.0 Psych 문서](https://docs.ruby-lang.org/en/3.0/Psych.html) 및 [Ruby 3.1 Psych 문서](https://ruby-doc.org/core-3.1.2/Psych.html)를 참고하세요.

- `sudo go run /absolute/file.go`에 대한 root 권한의 정확한 허가는 Go 소스가 상대 WASM 파일을 읽고 그 결과를 검사한 뒤 상대 shell 스크립트를 실행할 수 있다면 working directory 검토가 필요합니다. 유효한 RunAs, 명령 인수와 거부 규칙, 호출자 쓰기 가능 현재 디렉터리, WASM에서 분기로 이어지는 데이터 흐름, 해당 분기가 helper를 호출하는지 확인하세요. 고정 sudo `runchdir`, `os.Chdir` 또는 [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec)은 조회 위치를 바꿀 수 있습니다. 정적인 동시 출현만으로는 후보일 뿐입니다. Go, WASM 또는 helper를 실행하지 말고 소스를 확인하세요.
- `sudoedit`와 인수 wildcard는 정확한 버전 및 규칙 확인이 필요합니다. [체크리스트](linux-privilege-escalation-checklist.md)에 sudoedit 파일 편집 문제가 포함되어 있습니다. wildcard 경로에 대한 사용자 간 `sudoedit` 허가라면 유효한 `sudoedit_follow` 또는 `FOLLOW` 설정, `sudoedit_checkdir`, 해석된 대상, 각 상위 경로 항목을 바꿀 수 있는 사용자를 확인하세요. 전자는 symlink를 따라가게 할 수 있고, 후자를 비활성화하면 쓰기 가능한 디렉터리 검사가 제거됩니다. 어느 설정만으로도 다른 사용자 파일에 쓸 수 있다고 입증되지는 않습니다. 결론을 내리기 전에 설치된 sudo 정책과 정확히 일치한 인수를 확인하세요. [sudoers 옵션 정의](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)를 참고하세요.
- sudoers 명령 규칙에서 인수 wildcard는 경로 문자뿐 아니라 공백도 일치시킬 수 있습니다. `/restricted/*` 같은 인수를 받는 읽기 가능 명령 규칙은 일치하는 접두사 뒤에 추가 파일 인수를 허용할 수 있습니다. 정확한 RunAs 사용자, 명령 경로, 인수 패턴, 이후의 거부 규칙을 검토하세요. 파일을 읽을 수 있다는 증거가 명령 실행을 뜻하지는 않습니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)은 인수 glob과 명령 경로 glob을 구분합니다.
- 경로처럼 보이는 인수 glob도 `../`와 일치할 수 있습니다. 예를 들어 root 권한의 `node /opt/scripts/*.js` 규칙은 제공한 경로가 `/opt/scripts/`로 시작하고 상위 디렉터리 구간을 통해 해석되더라도 `/opt/scripts` 밖의 호출자 제어 JavaScript 파일을 허용할 수 있습니다. 이는 **인수** glob입니다. Node 실행 파일의 명령 경로 glob은 slash를 다르게 일치시킵니다. 코드 실행을 결론 내리기 전에 유효한 규칙, 이후의 거부 규칙, 경로 해석, 대상 파일 제어, sudoers 정규식 또는 digest 제한을 확인하세요. [sudoers wildcard 규칙](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)과 [Node 명령줄 문서](https://nodejs.org/api/cli.html)를 참고하세요.
- Archiver와 기타 utility 프로그램에는 실행 hook이 있을 수 있습니다. shell이나 interpreter만 명령을 실행한다고 가정하지 말고 정확히 허용된 인수를 [GTFOBins](https://gtfobins.github.io/)와 대조하세요.
- 제한 없는 root 권한 `qpdf` 규칙은 PDF 첨부 파일을 통해 권한 파일을 노출할 수 있습니다. qpdf 10.2 이상은 출력 PDF와 함께 `--empty` 및 `--add-attachment file ... --`을 지원합니다. 권한 프로세스가 선택된 source를 읽고 호출자가 접근 가능한 경로에 PDF를 쓸 수 있다면 출력에 source 데이터가 포함될 수 있습니다. 파일 노출 가능성을 결론 내리기 전에 유효한 sudo 인수와 제외 규칙, qpdf 버전, source 접근, 출력 경로를 검토하세요. root SSH key를 읽는 것이 로그인에 유용하려면 해당 key가 유효하고 root SSH 인증이 허용되어야 합니다. [qpdf 첨부 옵션](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)을 참고하세요.
- sudo timestamp 재사용은 cache 정책, 소유 사용자, terminal/session, 권한에 따라 달라집니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)에서 확인 방법을 설명합니다.
- `doas`에는 자체 규칙과 설정이 있습니다. [doas 섹션](../linux-basics/linux-privilege-escalation/README.md#doas)에 설명된 대로 허용된 명령과 쓰기 가능한 설정 경로를 확인하세요.

### Sudo로 실행되는 build 및 package 도구

Foundry의 `forge`에 대한 제한 없는 sudo 허가는 RunAs 신원이 다른 비root 사용자라도 중요할 수 있습니다. `--use` 같은 compiler 옵션으로 로컬 실행 파일을 선택할 수 있고, `forge flatten -o`는 출력 파일을 선택합니다. 허가를 악용 가능하다고 판단하기 전에 설치된 Forge 버전, 정확한 sudo 인수, 접근 가능한 프로젝트 및 compiler 경로, 출력 권한, 유효한 환경을 확인하세요. `PATH`를 통해 찾은 상대 helper 실행 파일은 버전과 환경에 따라 달라지는 경로이므로 모든 Forge 빌드에서 가능하다고 가정하면 안 됩니다.<sup>[[23]](#references)[[24]](#references)</sup>

root 권한의 제한 없는 `pacman` 허가는 패키지 query만 허용하지 않습니다. `-U`는 로컬 패키지를 받고, 패키지에는 설치 스크립트가 포함될 수 있으며, `--hookdir`은 다른 hook 디렉터리를 선택합니다. 테스트하기 전에 유효한 sudo 규칙, 인수 제한 및 제외 규칙을 검토하세요. 수동 열거에서는 패키지를 설치하거나 hook을 실행할 필요가 없습니다.<sup>[[25]](#references)[[26]](#references)</sup>

고정 sudo shell wrapper는 이름이 지정된 npm dependency를 설치한 뒤 Node 애플리케이션을 시작할 수도 있습니다. 정확한 RunAs 규칙, 패키지가 이미 설치되어 있는지, 유효한 `HOME`과 npm `userconfig`, 프로젝트 설정 또는 명령줄 재정의, 권한이 낮은 사용자가 해당 이름의 registry나 반환 패키지를 제어하는지 검토하세요. [npm 문서](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/)는 사용자별 및 프로젝트별 `.npmrc` 조회를 설명합니다. sudo의 `HOME` 동작은 설치된 정책과 배포판에 따라 다르므로, 권한 있는 npm 프로세스가 사용자의 쓰기 가능한 `.npmrc`를 읽을 수도 있고 읽지 않을 수도 있습니다. 새로 설치한 패키지를 권한 애플리케이션이 import하면 해당 모듈 코드는 애플리케이션 신원으로 실행될 수 있습니다. 설치 시 스크립트는 별도의 경로이며 버전과 설정에 따라 달라집니다. [npm은 해당 스크립트의 lifecycle과 사용자 처리를 문서화합니다](https://docs.npmjs.com/cli/v6/using-npm/scripts/). `.npmrc` 경로나 `npm install` 행만으로는 검토 단서일 뿐입니다. 수동 열거 중에는 설치하거나 애플리케이션을 시작하지 말고 규칙, 짧은 wrapper, 설정 경로, 패키지 출처를 확인하세요.

root 권한의 `pip` 또는 `pip3 download` 허가는 인수가 신뢰할 수 없는 source distribution을 선택할 수 있다면 package build 검토 단서입니다. URL 패턴이 로컬 서비스와 `.tar.gz` 접미사로 제한되어도 마찬가지입니다. `pip download`는 archive URL을 받고 package metadata를 해석합니다. sdist를 준비하는 과정에서 archive를 단순 저장하기 전에 build backend나 구형 `setup.py` 코드가 실행될 수 있습니다. 정확한 sudo RunAs 및 인수 규칙, 호출자가 선택한 archive를 게시하거나 바꿀 수 있는지, 해당 pip 버전이 metadata를 실제로 준비하는지 확인하세요. 고정된 신뢰 archive나 wheel만으로는 이 경로가 성립하지 않습니다. 수동 열거 중에는 신뢰할 수 없는 패키지를 가져오거나 build하지 마세요. pip의 [download 명령](https://pip.pypa.io/en/stable/cli/pip_download/), [build-system interface](https://pip.pypa.io/en/stable/reference/build-system/), [secure-install 안내](https://pip.pypa.io/en/stable/topics/secure-installs/)를 참고하세요.

호출자 선택 로컬 프로젝트 경로를 받는 `pip install` sudo 규칙은 더 직접적인 build 경계입니다. [pip는 로컬 프로젝트 디렉터리를 허용하고](https://pip.pypa.io/en/stable/topics/local-project-installs/) build system을 호출합니다. [build backend는 프로젝트가 제어하는 build hook을 실행합니다](https://pip.pypa.io/en/stable/reference/build-system/). 해당 규칙을 권한 코드 실행으로 판단하기 전에 유효한 RunAs 신원, 정확한 인수 제한과 거부 규칙, 선택된 프로젝트에 대한 제어권, 설치된 pip/backend 동작을 확인하세요. 고정된 신뢰 프로젝트나 호출자 선택 경로를 제외하는 규칙으로는 이 경로가 성립하지 않습니다. 수동 열거 중에는 패키지를 설치하지 말고 규칙과 프로젝트 metadata를 검토하세요.

제한 없는 root 권한 `easy_install` 허가는 관련된 구형 package-build 검토 단서입니다. [Setuptools 문서](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)에 따르면 Easy Install은 로컬 프로젝트 디렉터리를 받고 source distribution을 build합니다. 호출자가 제어하는 프로젝트라면 sudo 신원으로 build하는 동안 `setup.py`를 실행할 수 있습니다. 유효한 RunAs 계정, 정확한 명령 및 인수 제한(이후 거부 규칙 포함), 선택된 프로젝트에 대한 제어권, 설치된 도구의 동작을 확인하세요. 고정된 신뢰 프로젝트나 호출자 선택 source를 허용하지 않는 정책으로는 이 경로가 성립하지 않습니다. 열거 중에는 패키지를 설치하지 말고 규칙과 프로젝트 metadata를 확인하세요.

호출자 선택 URL로 `setuptools.package_index.PackageIndex.download`를 사용하는 sudo 허용 Python wrapper는 `pip download`와 다른 검토 사례입니다. [setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)는 78.1.1 이전의 영향을 받는 release에서 URL로 생성한 파일명이 의도된 download 디렉터리를 벗어나고 프로세스 권한으로 쓰기할 수 있다고 설명합니다. 유효한 sudo RunAs 및 인수 규칙, wrapper가 호출자 URL을 이 정확한 API에 전달하는지, 설치된 build 또는 vendor backport, 결과 경로의 해석 위치를 확인하세요. 버전 문자열이나 쓰기 가능한 download 디렉터리만으로는 임의 쓰기가 입증되지 않습니다. 열거 중 URL을 가져오거나 파일을 쓰지 말고 짧은 wrapper와 패키지 metadata를 검토하세요.

호출자 선택 `.spec` 파일을 PyInstaller에 전달하는 sudo 허용 build wrapper도 동일한 신뢰 경계 검토가 필요합니다. PyInstaller spec은 **build 중** 실행되는 Python이며, `datas` 항목은 build 신원이 읽을 수 있는 파일을 artifact에 묶을 수 있습니다. 정확한 RunAs 사용자, sudo 인수 및 거부 규칙, wrapper의 경로 및 분기 처리, 선택된 spec 파일에 대한 제어권, 결과 artifact에 대한 접근을 확인하세요. `.py` 입력만 허용하거나 PyInstaller가 설치된 사실만으로는 spec 파일 제어 또는 권한 실행이 입증되지 않습니다. 수동 검토에서는 제한된 범위의 wrapper 파일과 metadata만 읽고 build를 실행하지 마세요. [PyInstaller spec 파일 문서](https://pyinstaller.org/en/stable/spec-files.html)를 참고하세요.

### Sudo로 실행되는 preset 및 plugin loader

호출자 선택 preset 또는 plugin 디렉터리를 받는 Python 도구는 sudo가 부여한 권한으로 코드를 import할 수 있습니다. 예를 들어 BBOT는 `-p`로 preset을 받고, [사용자 지정 module 문서](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)는 추가 Python module 디렉터리를 선택하는 `module_dirs` 항목을 설명합니다. 유효한 sudo 규칙이 호출자 선택 preset을 허용하고 호출자가 선택된 디렉터리의 module을 제어한다면, 도구가 잘못된 module을 거부하기 전에도 import가 권한 사용자로 코드를 실행할 수 있습니다. 열거 중 module을 불러오지 말고 설치된 버전, 정확한 sudo RunAs 및 인수 정책, preset과 module 경로의 소유권을 확인하세요.

### Sudo로 실행되는 Backdrop 명령줄 도구

[Bee](https://github.com/backdrop-contrib/bee)는 Backdrop CMS용 PHP 명령줄 도구입니다. `eval` (`php-eval`) 및 `php-script` 명령은 호출자 제공 PHP를 실행할 수 있습니다. 따라서 Bee 실행 파일을 제한 없는 인수로 root 실행하도록 허용하는 sudo 규칙은 Bee가 Backdrop 설치를 초기화할 수 있을 때 root 코드 실행을 노출할 수 있습니다. 사이트 디렉터리에서 실행하거나 전역 `--root=<directory>` 옵션으로 사이트를 지정하세요. Bee나 Backdrop `settings.php` 파일을 찾았다고 해서 sudo 권한, 사용 가능한 사이트, 초기화 성공이 입증되지는 않습니다. 테스트 전에 유효한 sudo 규칙, 명령 제외 규칙, 실행 파일 신원, 사이트 접근 권한을 검토하세요. 수동 열거에서는 Bee를 실행하지 말고 규칙과 파일 경로를 확인하세요. PHP 명령 추가 사항은 [Bee 명령 변경 기록](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)을 참고하세요.

### Sudo로 실행되는 terminal server

`mosh-server`는 호출 사용자로 대화형 terminal server를 시작합니다. 높은 UDP port와 session key를 선택해 둘 다 호출자에게 보고하고, client가 연결되면 보통 해당 사용자의 로그인 shell을 실행합니다. 따라서 root 권한의 제한 없는 `mosh-server` sudo 허가는 server 명령 자체가 detach되더라도 shell 실행 가능성 검토 대상입니다. 유효한 RunAs 신원, 허용 인수와 제외 규칙, 설치된 바이너리, shell, client 이용 가능성, UDP 접근을 확인하세요. 수동 열거에서는 server를 시작하거나 활성 session key를 출력하지 말고 sudo 규칙을 확인하세요. [Mosh server 매뉴얼](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html) 및 [상위 프로젝트 설계 노트](https://github.com/mobile-shell/mosh#how-it-works)를 참고하세요.

### 호출자 task 파일을 다시 쓰는 권한 백업 wrapper

root로 실행되는 shell wrapper가 호출자 선택 task 파일을 받고 source 경로에서 `../`를 제거한 뒤, 결과가 허용 디렉터리로 시작하는지 확인하고 task 파일을 다시 쓴 후 해당 *경로명*을 백업 프로그램에 전달할 수 있습니다. 전체 canonical 해석 후 변환된 경로를 검토하세요. 문자열을 한 번 치환하면 새로운 traversal 구간이 생겨 lexical prefix 검사를 통과할 수 있습니다. 또한 백업 프로그램이 변환된 메모리 데이터에서 읽는지, 파일을 다시 여는지도 확인하세요. 파일을 다시 연다면 다시 쓰기에 실패해도 원래 입력이 그대로 남을 수 있습니다.

Linux의 `fs.protected_regular`은 world-writable sticky 디렉터리에서 다른 사용자의 일반 파일에 대한 `O_CREAT` 쓰기를 거부할 수 있습니다. 이는 보호 기능이지만, 쓰기 오류를 무시하는 shell wrapper는 원래 task 파일로 계속 진행할 수 있습니다. 해당 설정, 파일 소유자와 디렉터리, wrapper가 실패 시 중단하는지 확인하세요. 유효한 sudo 규칙이 wrapper를 권한 사용자로 허용하고, 호출자가 task 입력과 읽을 수 있는 백업 destination을 제어하며, 백업 utility가 실제로 보호된 source를 포함할 때만 파일 정보 노출 후보가 됩니다. 열거 중에는 백업을 실행하지 말고 해당 조건을 확인하세요.

### 권한 packet tool의 인수 wildcard

`tcpdump` sudo 규칙의 **인수 패턴**에 있는 `*`는 공백과 slash를 일치시킬 수 있으므로, 경로처럼 보이는 제한이 추가 옵션 텍스트를 허용할 수 있습니다. 이는 명령 실행 파일 경로의 wildcard와 다릅니다. 전체 RunAs 규칙과 이후의 거부 규칙을 확인하세요. 옵션을 삽입할 수 있다면 허용된 호출 방식과 설치된 [`tcpdump` 옵션 의미](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)에 따라 `-F`, `-V`, `-r`, `-w` 또는 `-Z`가 유용한 읽기/쓰기 원시 기능을 제공하는지 달라집니다. `-V`는 임의 파일을 일반적으로 덤프하는 것이 아니라 capture 파일명 목록을 읽습니다. sudo가 명령을 허용하더라도 AppArmor 또는 다른 MAC 정책이 파일 접근을 막을 수 있습니다. 디스크에 profile 파일이 있다는 사실만으로 해당 profile이 로드되어 강제 적용 중임을 입증하지는 않습니다. 결론을 내리기 전에 권한과 정책을 수동으로 검토하세요. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)은 wildcard의 차이를 설명합니다.

인수 제한 없이 `tcpdump` 실행 파일만 나열하는 root 권한 sudo 규칙도 검토해야 합니다. [tcpdump 매뉴얼](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)에 따르면 `-z`는 `-C` 또는 `-G`로 저장된 capture를 회전시킨 뒤 실행되는 명령입니다. `-Z` 또는 compile-time 기본값에 따라 해당 명령 실행 전에 권한이 낮아질 수 있습니다. 규칙을 권한 상승 경로로 판단하기 전에 유효한 sudo 규칙, 설치된 build, 권한 하향 동작, 회전이 실제로 발생할 수 있는지 확인하세요. 강조된 규칙은 후보일 뿐 root 명령 실행의 증거가 아닙니다.

### Sudo로 실행되는 Nmap wrapper

sudo에서 허용된 `nmap` 경로가 shell wrapper라면 정확히 허용된 경로와 전달되는 모든 옵션을 확인하세요. 익숙한 `--script` 표기를 차단해도 NSE 코드 로딩을 차단하지 못할 수 있습니다. Nmap의 [`--datadir`](https://nmap.org/book/man-misc-options.html)는 데이터 파일을 선택하고, scripting이 활성화되면 NSE는 선택된 데이터 디렉터리에서 [`nse_main.lua`를 로드합니다](https://nmap.org/book/nse-implementation.html). 설치된 일부 build는 대체 long-option 표기도 허용하므로, 제한 사항을 해당 바이너리의 실제 parser와 비교하세요. [`--excludefile`](https://nmap.org/book/target-specification.html)는 별도의 파일 읽기 표면이며 parser 오류가 텍스트를 노출할 수 있습니다. 수동 열거 중에는 scan을 실행하지 말고 유효한 sudo 규칙, wrapper 로직, Nmap 버전, 디렉터리 제어, MAC 정책을 확인하세요.

### Sudo로 실행되는 Mercurial pull hook

고정 source를 사용하는 `sudo hg pull /fixed/source`도 `-R`로 고정하지 않으면 **받는 쪽** repository는 현재 working directory로 선택됩니다. 호출자 제어 receiving repo는 `.hg/hgrc`에서 hook을 정의할 수 있으며, hook은 sudo RunAs 사용자로 실행될 수 있습니다. [Mercurial은 신뢰할 수 없는 사용자나 그룹이 소유한 repository 설정을 무시합니다](https://mercurial-scm.org/help/topics/config). 따라서 이를 코드 실행으로 판단하기 전에 RunAs 계정의 신뢰 사용자/그룹과 정확한 working directory를 확인하세요. 수동 검토에는 정책과 설정을 읽는 것으로 충분합니다. 열거를 위해 pull하거나 hook을 실행하지 마세요.

### Sudo로 실행되는 Git pull hook

root 권한의 `sudo git pull`에 대한 정확한 허가라면 working directory로 선택되는 **receiving** repository도 확인하세요. 호출자 소유 repository에는 `post-merge` 실행 파일이 있을 수 있으며, pull이 성공적으로 merge를 수행하면 Git 프로세스의 신원으로 실행됩니다. [Git 문서](https://git-scm.com/docs/githooks)는 이 hook을, [pull의 merge/rebase 동작](https://git-scm.com/docs/git-pull)은 관련 동작을 설명합니다. 유효한 sudo 규칙과 CWD, 활성 hook 경로와 권한, 새 commit을 포함한 merge가 가능한지 확인하세요. 실패한 pull, 변경이 없는 pull, rebase만 하는 pull은 이 hook 경로를 입증하지 않습니다. 권한이 필요한 pull을 실행하지 말고 정책과 repository metadata를 확인하세요.

### Sudo로 실행되는 rsync archive 복사

`sudo rsync -a ... /writable/source/* /fixed/destination/`에서 **sudoers 인수 패턴**의 `*`는 공백과 일치하므로 source와 destination 사이에 추가 옵션을 허용할 수 있습니다. 이는 shell이 파일명에 대해 수행하는 expansion과 다릅니다. 호출자가 source를 채울 수 있고 권한이 있는 rsync 프로세스가 destination에 쓸 수 있다면 [`--chown`](https://download.samba.org/pub/rsync/rsync.1)으로 권한 소유자를 지정하면서 archive mode로 permission bit를 보존해 소유권이 설정된 SetUID 파일을 만들 수 있습니다. 정확한 [sudoers wildcard 의미](https://man7.org/linux/man-pages/man5/sudoers.5.html), rsync 버전, 이후 거부 규칙, 파일시스템 `nosuid`, MAC 정책을 확인하세요. 규칙이 일치한다는 사실은 검토 대상일 뿐 권한 상승 성공의 증거가 아닙니다.

### Sudo로 실행되는 packet-filter 규칙 내보내기

`iptables`와 `iptables-save` 모두(또는 이에 대응하는 `ip6tables` 쌍) root 권한의 무제한 허가를 받았다면 파일 쓰기를 검토해야 합니다. `comment` match는 호출자 선택 규칙 텍스트를 허용하고, `iptables-save -f`는 직렬화된 ruleset을 선택한 경로에 씁니다.<sup>[[20]](#references)[[21]](#references)</sup> 유용한 payload가 성립하려면 설치된 backend가 comment를 어떻게 직렬화하는지, destination 파일이 export의 다른 행을 허용하는지에 따라 달라집니다. `iptables-save`만으로는 임의의 선택 콘텐츠를 제공하지 않습니다. 정확한 sudo RunAs 신원, 인수 및 제외 규칙, 사용 가능한 match extension, backend, destination 권한을 확인하세요. 열거 중에는 firewall 규칙을 변경하거나 파일을 쓰지 말고 허가만 확인하세요.

### 권한으로 실행되는 Below logging 디렉터리

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)은 world-writable `/var/log/below` 디렉터리를 만든 0.9.0 이전 Below release에 영향을 미쳤습니다. 서비스나 허용된 sudo 명령이 영향을 받는 build를 root로 실행한다면, sticky bit가 없는 log 디렉터리를 쓰고 탐색할 수 있는 사용자가 권한 프로세스가 열기 전에 log 항목을 symlink로 바꿀 수 있습니다. 설치된 패키지의 patch 적용 여부, 정확한 권한 실행 경로, 유효한 디렉터리 접근, sticky bit 및 ACL, `/var/log/below/error_root.log` metadata를 검토하세요. world-writable 경로나 sudo 규칙만으로는 전체 과정이 입증되지 않습니다. sticky 디렉터리 또는 vendor backport가 있으면 판단이 달라집니다. 수동 열거에서는 metadata만 확인하면 됩니다. 링크를 만들거나 권한 프로그램을 실행할 필요는 없습니다.

### 쓰기 가능한 입력에서 권한 support bundle 수집

sudo에서 허용된 support-profile 스크립트는 root로 고정 log 경로를 읽고 그 내용을 profile archive에 복사할 수 있습니다. 실제 스크립트에서 파일을 읽는지 확인한 뒤, 호출자가 source 경로나 상위 디렉터리 항목을 symlink로 바꿀 수 있는지 살펴보세요. 권한 읽기가 해당 symlink를 따라가고 결과 archive를 호출자가 읽을 수 있다면 보호된 파일이 노출될 수 있습니다. sudo 허가, 쓰기 가능한 source 경로, 권한 읽기, 읽을 수 있는 출력이 모두 있어야 합니다. 쓰기 가능한 log나 profile 파일명만으로는 충분하지 않습니다. 열거 중 파일을 바꾸거나 profile을 생성하지 말고 유효한 권한과 링크 metadata를 확인하세요. [Nagios XI 지원 안내](https://support.nagios.com/forum/viewtopic.php?t=62758)는 root로 실행되는 profile 스크립트와 출력 archive를 설명하며, 이러한 bundle의 입력과 출력 접근을 제한해야 하는 이유를 보여줍니다.

### root로 실행되는 Python archive 복원 스크립트

범위가 엄격히 제한된 Python 복원 스크립트 sudo 규칙도 archive 입력을 검토해야 합니다. 호출자가 archive를 선택하거나 교체할 수 있고 스크립트가 root로 `tarfile.extractall(filter="data")`를 실행한다면, 해당 filter를 신뢰하기 전에 interpreter의 보안 업데이트를 확인하세요. CPython은 CVE-2025-4517을 포함한 여러 symlink 및 hard-link filter 우회 취약점을 3.9.23, 3.10.18, 3.11.13, 3.12.11, 3.13.4에서 수정했습니다. 배포판 backport가 더 이른 버전을 수정할 수도 있으므로, 표시된 interpreter 버전만으로 취약 여부를 판단할 수 없습니다.<sup>[[16]](#references)[[17]](#references)</sup>

수동 검토에서는 정확한 sudo 명령과 스크립트를 읽고, 어떤 인수가 archive를 선택하는지 추적하고, 현재 사용자가 archive 또는 archive가 들어 있는 디렉터리에 쓸 수 있는지 확인하세요. 설치된 vendor patch와 추출 destination을 별도로 확인하세요. `filter="data"`가 모든 신뢰할 수 없는 archive를 안전하게 만드는 것은 아닙니다.<sup>[[16]](#references)[[17]](#references)</sup>

### Sudo로 실행되는 machine-learning model loader

호출자 선택 `.pt`, `.pth` 또는 `.ckpt` 파일을 허용하는 sudo 규칙은 권한 스크립트가 해당 파일을 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html), `pickle.load` 또는 다른 pickle 기반 loader에 전달한다면 검토해야 합니다. 유효한 RunAs 규칙, 호출자가 선택한 model을 만들거나 교체할 수 있는지, shell wrapper를 거쳐 Python helper에 도달하는 실제 인수 흐름을 확인하세요. `.pth` 확장자는 관련 없는 Python site 설정 파일에도 사용되므로 확장자만으로 model 로딩을 입증할 수 없습니다. archive 검사나 정적 pickle 검사만으로 나중의 load가 안전하다고 입증되지 않습니다. loader의 [버전별 `weights_only` 동작](https://docs.pytorch.org/docs/stable/notes/serialization.html)과 allowlist 적용 여부를 확인하세요. [ML pickle 및 Fickling 참고 자료](../../AI/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling)를 참고하세요. 수동 열거에서 model을 load하거나 풀어서는 안 됩니다.

### Sudo로 실행되는 저장 입력의 표현식 parsing

고정 Python 스크립트를 sudo로 root 실행하더라도 권한이 낮은 사용자가 애플리케이션 데이터베이스에 저장할 수 있는 텍스트를 평가할 수 있습니다. TensorFlow에서 `preprocess_input_exprs_arg_string(value, safe=False)` 호출은 `eval` 경로를 선택합니다. [TensorFlow 권고문](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)은 안전하지 않은 parser와 명령줄 호출자의 수정 사항을 설명합니다. 애플리케이션에서 명시적으로 `safe=False`를 호출한다면, 해당 명령줄 호출자가 patch되었더라도 별도로 검토해야 합니다. 유효한 sudo 규칙, 정확한 입력 행을 수정할 수 있는 사용자, 필터링 또는 scoring으로 해당 행이 호출부까지 도달하는지, 설치된 함수의 동작을 확인하세요. TensorFlow 버전, sudo 허가, 하드코딩된 model 파일만으로는 이 과정이 입증되지 않습니다. 수동으로 스크립트와 데이터 흐름을 검토하고, 열거 중에는 권한 helper를 실행하거나 시험 표현식을 제출하지 마세요.

### Sudo로 허용된 needrestart 설정

`needrestart -c`는 호출자 선택 Perl 설정 파일을 불러와 내용을 평가합니다. `sudo -l`에서 root로 `needrestart`를 실행할 수 있고 인수가 `-c`를 허용하며, 호출자가 쓰기 가능한 위치의 읽을 수 있는 설정 파일을 선택할 수 있다면 해당 허가는 root 코드 실행으로 이어질 수 있습니다. 정확한 sudo RunAs 및 인수 규칙을 확인하세요. 고정 인수 목록만 허용하는 규칙은 이 경로를 차단할 수 있습니다. 이는 needrestart interpreter scan 취약점과 별개입니다. 패키지를 업데이트하거나 `interpscan`을 비활성화해도 제한 없는 root `-c` 허가가 안전해지는 것은 아닙니다.<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 다른 계정으로 실행되는 Sudo Python import

고정 Python 진입점도 호출자가 편집하거나 교체할 수 있는 module을 import할 수 있습니다. sudo가 **root가 아닌** 서비스 사용자로 스크립트를 실행하는 경우도 마찬가지입니다. `from utils import status`처럼 literal import를 사용한다면 package 디렉터리 권한뿐 아니라 로컬 `utils/__init__.py`와 `utils/status.py`도 검토하세요. 쓰기 가능한 파일을 실행 경로로 판단하기 전에 스크립트의 import 경로, 정확한 허용 sudo 인수, 관련 동작이 해당 import에 도달하는지 확인하세요. 열거 중 파일을 import하거나 스크립트를 실행하지 말고 파일과 권한을 확인하세요.<sup>[[2]](#references)[[3]](#references)</sup>

`python3 /absolute/script.py`에 대한 정확한 sudo 규칙에는 스크립트를 읽을 수만 있으면 됩니다. 파일에 실행 권한이 있거나 shebang이 있을 필요는 없습니다. **누락된** 로컬 module도 검토하세요. 스크립트가 호출자 쓰기 가능 디렉터리에 파일명을 만들 수 있는 module을 import한다면 Python은 해당 파일을 RunAs 신원으로 불러올 수 있습니다. 유효한 sudo 규칙, interpreter의 실제 [module 검색 경로](https://docs.python.org/3/library/sys_path_init.html), module이 built-in 또는 frozen인지, import에 도달하는지 확인하세요. 스크립트에 대한 직접 sudo 규칙은 실행 비트와 shebang 요건이 다릅니다. `sudo -u account` 뒤에 호출자 제공 token을 덧붙이는 별도 wrapper도 인수 흐름 검토가 필요합니다. 해당 token에 있는 또 다른 `-u`는 호출된 sudo 정책이 결과 신원을 허용할 때만 중요합니다. 정적 문자열만으로는 어느 경로도 입증되지 않습니다.

### 호출자 제어 설정을 사용하는 Sudo Apache

sudo 규칙이 권한 있는 `apachectl`, `apache2ctl` 또는 `httpd` 호출에 호출자 제어 `-f` 설정 파일을 허용한다면 해당 파일과 상위 디렉터리 권한을 검토하세요. Apache의 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) directive는 module 이름 다음에 **module 파일명**을 받습니다. [`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile)도 파일을 불러옵니다. [`Include`와 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include)은 설정을 확장하거나 오류를 통해 파일 내용을 노출할 수 있습니다. 사용자 지정 wrapper는 경로를 검증하거나 권한을 낮추거나 인수를 제한할 수 있으므로, 쓰기 가능한 설정 파일만으로는 코드 실행이 입증되지 않고 검토 후보일 뿐입니다. 결론을 내리기 전에 경로 canonicalization, symlink, directive parsing을 확인하세요.

### 호출자 제어 설정을 사용하는 Sudo nginx

root 권한의 제한 없는 `nginx` 규칙은 [`-c`로 다른 설정을 선택할 수 있게 합니다](https://nginx.org/en/docs/switches.html). 정확한 sudo 인수와 제외 규칙, 호출자가 설정을 제공할 수 있는지, 결과 master 또는 worker가 보호된 경로에 계속 접근할 수 있는지 검토하세요. 선택한 `root`와 `autoindex`로 새 listener를 통해 파일을 노출할 수 있습니다. [`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html)은 권한 파일 쓰기 경로를 제공할 수 있지만, DAV module은 기본적으로 build되지 않습니다. module 존재 여부, listener 접근성, 파일 권한, 임시 파일 동작을 확인해야 합니다. [`error_log` directive](https://nginx.org/en/docs/ngx_core_module.html#error_log)도 선택한 파일을 대상으로 할 수 있습니다. `/etc/ld.so.preload` 같은 민감한 설정 파일에 log를 쓰려면 권한 있는 writer와 제어 가능한 log record가 있어야 권한 상승 경로가 됩니다. `sudo -l`에서 실행 파일이 강조된 것만으로는 이런 경로가 작동한다고 입증되지 않습니다. 수동 열거에서는 nginx를 시작하거나 재설정하지 마세요.

### 권한 Bash prompt의 패턴 비교

sudo에서 허용된 Bash 스크립트가 호출자로부터 값을 읽고 `[[ "$expected" == $entered ]]`로 확인하면, 인용되지 않은 오른쪽 피연산자를 Bash가 pattern으로 해석합니다. 따라서 wildcard로 실제 기대값을 모른 채 비교를 통과할 수 있습니다. 피연산자를 인용하면(`[[ "$expected" == "$entered" ]]`) literal 문자열 비교가 됩니다. 해당 문법만으로 악용 가능한 경로가 성립하지는 않습니다. 정확한 sudo 규칙, prompt에 도달할 수 있는지, 비교 후 스크립트가 무엇을 하는지 검토하세요. 열거 중에는 기대값을 출력하지 마세요. [Bash conditional constructs 참고 자료](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)를 참고하세요.

### 파일을 다운로드해 실행하는 Sudo helper

호출자 선택 URL을 받고 응답을 디스크에 쓴 뒤 나중에 interpreter나 shell로 해당 파일을 실행한다면, 사용자 지정 helper에 대한 root 권한의 제한 없는 sudo 허가는 데이터 흐름 검토가 필요합니다. [Sudoers는 명령 항목에 인수를 적지 않으면 임의 인수를 허용합니다](https://man7.org/linux/man-pages/man5/sudoers.5.html). 고정 실행 파일 경로라고 해서 인수로 선택 가능한 항목이 제한되지는 않습니다. 설치된 helper에서 실제 URL 검증, 출력 경로, 성공 분기, 이후 실행을 확인하세요. libcurl import나 출력 가능한 문자열만으로는 이 과정이 입증되지 않습니다.

고정된 출력 basename도 helper가 **호출자 제어 working directory의 상대 경로**를 사용하면 쓰기와 실행 사이에 교체될 수 있습니다. root 소유 파일의 이름 변경 또는 교체 여부는 파일 mode뿐 아니라 디렉터리 쓰기/탐색 권한과 sticky bit 제한의 영향을 받습니다. [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)을 참고하세요. helper가 나중에 경로를 다시 여는지 아니면 이미 열린 descriptor를 사용하는지, 쓰기 전에 신뢰할 수 있는 디렉터리로 이동하는지 확인하세요. 열거 중에는 권한 다운로드를 실행하거나 race를 시도하지 말고 sudo 정책, helper, 디렉터리 metadata를 확인하세요.

root sudo 다운로드 helper는 `curl <caller input> -o <fixed output>` 같은 Bash 명령 문자열을 구성하면 **인수** injection도 노출할 수 있습니다. 공백을 거부하는 filter로도 [Bash brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)은 막을 수 없습니다. 인용되지 않은 쉼표 구분 항목은 별도의 curl 인수가 될 수 있습니다. 입력이 고정 `-o`보다 앞서 curl에 도달한다면 호출자가 제공한 출력 옵션이 helper 신원으로 첫 번째 URL의 destination을 선택할 수 있습니다. [curl은 URL 순서에 따라 출력 옵션을 연결합니다](https://curl.se/docs/manpage.html#-o). 정확한 shell, quoting, 입력 검증, 유효한 sudo 규칙, curl 인수 순서와 지원 URL scheme, 호출자가 가져오는 바이트를 제어하거나 결과를 읽을 수 있는지 확인하세요. PyInstaller로 패키징된 실행 파일에 Python 애플리케이션 로직이 들어 있을 수 있지만, 패키징 표시나 `curl` 문자열만으로 데이터 흐름이 입증되지는 않습니다. 승인된 경우 제한된 범위의 오프라인 복사본을 검토하세요. 일반적인 열거에서는 helper를 실행하거나 공격자 선택 데이터를 가져오지 마세요.

`mktemp -u` / `--dry-run`을 호출하는 root sudo shell 스크립트는 사용되지 않은 이름만 선택할 뿐 파일을 **만들지 않습니다**. 스크립트가 이후 다른 사용자가 영향을 줄 수 있는 디렉터리에서 해당 이름의 파일을 만들고, 다시 열어 내용을 root의 `authorized_keys` 같은 보호된 destination에 덧붙인다면 임시 파일 race 가능성을 검토하세요. 정확한 sudo 규칙, 디렉터리와 파일 소유권, 생성 및 재열기 순서, kernel 보호, 권한 쓰기가 실제로 공격자 제어 바이트를 사용하는지 확인하세요. `mktemp -u` 문자열이나 쓰기 가능한 `/tmp`만으로는 race가 입증되지 않습니다. 열거 중 스크립트와 경로 metadata를 확인하고, 실행하거나 임시 파일 race를 시도하지 마세요.

## 방어 참고 사항

- sudo를 통해 interpreter나 대화형 편집기를 허용하지 마세요.<sup>[[1]](#references)</sup>
- `tee`처럼 일반적인 파일 writer를 피연산자 제한 없이 허용하지 마세요. 고정 destination을 선택하고 호출자 제어 경로를 거부하는 root 소유 wrapper를 사용하세요.<sup>[[2]](#references)</sup>
- 하나의 제한된 관리 작업만 수행하는 고정 root 소유 wrapper를 선호하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- interpreter가 불가피하다면 정확한 스크립트 경로를 제한하고 사용자 제어 인수, 쓰기 가능한 import, `PYTHONPATH`, 안전하지 않은 환경 변수 보존을 차단하세요.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 파일 편집이 필요하다면 정확한 파일 경로를 제한하고 patch된 sudo 버전과 엄격한 환경 처리를 적용한 `sudoedit` 사용을 고려하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, 쓰기 가능한 working directory, 쓰기 가능한 module/import 경로, `NOEXEC`, `use_pty`, logging을 검토하되 이를 완전한 sandbox로 간주하지 마세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [명령줄과 환경 — Python 문서](https://docs.python.org/3/using/cmdline.html)
- [4] [os — 다양한 운영체제 인터페이스 — Python 문서](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl interpreter 실행 방법](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl 문서](https://perldoc.perl.org/functions/exec)
- [7] [Ruby 명령줄 옵션](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby 문서](https://ruby-doc.org/3.4/Kernel.html)
- [9] [명령줄 API — Node.js 문서](https://nodejs.org/api/cli.html)
- [10] [자식 프로세스 — Node.js 문서](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua 매뉴얼 페이지](https://www.lua.org/manual/5.4/lua.html)
- [12] [GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [리디렉션 — Bash 참고 매뉴얼](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 보안 release](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile 추출 filter — Python 문서](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart 설정 옵션 및 평가 — 상위 프로젝트 소스](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart 명령 동작 — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [간단한 명령 확장 — Bash 참고 매뉴얼](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge compiler 옵션 — Foundry 문서](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry 문서](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch 매뉴얼 페이지](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) 설치 스크립트 — Arch 매뉴얼 페이지](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
- [27] [Volexity — VerdantBamboo: 방화벽에서 발견된 또 다른 BRICKSTORM](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/)
- [28] [GNU Coreutils — `tee`: 여러 파일 또는 프로세스로 출력 리디렉션](https://www.gnu.org/software/coreutils/manual/html_node/tee-invocation.html)
{{#include ../../banners/hacktricks-training.md}}
