# Sudo 명령어 악용

{{#include ../../banners/hacktricks-training.md}}

## Sudo에서 허용된 인터프리터

`sudo -l`에서 사용자가 인터프리터를 root로 실행할 수 있다고 허용한다면, 이를 직접적인 code execution으로 간주하세요. 인터프리터는 임의의 코드를 실행하도록 설계되었으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 이와 유사한 바이너리를 허용하는 규칙은 인수가 엄격하게 제한되고 검증되지 않는 한 대개 root 명령어 실행과 동일합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

일반적인 검토 순서는 먼저 사용자의 권한을 확인한 다음, 인터프리터의 `-c` 옵션으로 Python 구문을 실행하는 것입니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

다른 인터프리터 예시는 아래와 같습니다. 나열된 인터프리터의 문서에는 인라인 코드 실행 또는 자식 프로세스 API가 설명되어 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

정확한 경로가 중요합니다. sudo 규칙이 `/usr/bin/python3`을 허용한다면 검증할 때도 해당 경로를 그대로 사용하세요.<sup>[[2]](#references)</sup>

`/usr/bin/python*`와 같은 sudo 실행 파일 glob은 Python 3용으로 작성된 스크립트에 Python 2도 허용할 수 있습니다. 스크립트가 호출자가 제어하는 텍스트를 `input()`으로 받는다면, [Python 2는 해당 텍스트를 표현식으로 평가합니다](https://docs.python.org/2/library/functions.html#input). 인터프리터를 명시적으로 호출하면 스크립트의 shebang은 무시됩니다. 이 경로를 실행 경로로 간주하기 전에 설치된 일치 바이너리, 유효한 RunAs 및 인수 정책, 거부 규칙, 입력에 도달할 수 있는지 확인하세요.

root 권한으로 실행 가능한 sudo 규칙에 스크립트 경로가 고정되어 있어도 스크립트가 실행하는 내용까지 제한되는 것은 아닙니다. 읽을 수 있는 Bash 래퍼라면, sudo가 호출자 지정 인수를 허용하는 경우 첫 번째 실행 명령에서 인용되지 않은 위치 매개변수(예: `$1`)를 **명령어**로 사용하는지 확인하세요. 유효한 RunAs ID, 비밀번호 및 인수 정책, 이후의 거부 규칙, 실제 스크립트 분기를 확인하세요. `NOEXEC`, 안전한 인수 목록의 고정, 또는 명령어를 검증하는 래퍼에 따라 결과가 달라질 수 있습니다. 테스트 명령으로 실행하지 말고 열거 단계에서 짧은 스크립트를 정적으로 검사하세요.

제한 없이 root 권한으로 실행 가능한 `dotnet` sudo 규칙도 인터프리터 관점에서 검토할 필요가 있습니다. .NET SDK가 설치되어 있다면 [`dotnet fsi`는 F# 코드를 대화형으로 또는 스크립트에서 실행합니다](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/). [`dotnet run`은 소스에서 프로젝트를 실행합니다](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run). 먼저 유효한 RunAs ID와 정확한 인수 정책을 확인하세요. 특정한 안전한 하위 명령이나 신뢰할 수 있는 애플리케이션으로 제한된 규칙은 다른 권한 부여이며, 런타임만 설치된 경우 SDK 명령이 없을 수 있습니다. 실행 파일 이름만으로는 검토할 이유일 뿐, 코드 실행의 증거가 되지는 않습니다.

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed editors

`sudo -l`에서 사용자가 root로 인터랙티브 에디터를 실행할 수 있도록 허용한다면, 이를 무해한 파일 편집 권한이 아니라 명령 실행이 가능한 공격 표면으로 간주하세요. 에디터에서는 셸 명령을 실행하거나, 임의의 파일을 읽고 쓰거나, 에디터 내부에서 외부 헬퍼를 호출할 수 있는 경우가 많습니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

일반적인 검토 절차: 먼저 사용자의 권한을 나열한 다음, 허용된 각 에디터나 페이저를 sudo로 실행합니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

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

그런 다음 nano 명령 프롬프트에 `id` 또는 `/bin/sh`와 같은 명령을 입력합니다.<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

대화형 셸에서 사용할 수 있는 터미널 스트림이 없으면, 이 리디렉션 형식은 표준 출력과 표준 오류를 파일 디스크립터 0에 매핑합니다.<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

정확한 키 입력 순서는 nano 버전과 빌드 옵션에 따라 달라질 수 있지만, 보안 문제는 동일합니다. 편집기가 root 권한으로 실행되고 외부 명령을 호출할 수 있습니다.<sup>[[1]](#references)[[12]](#references)</sup>

### 기타 흔한 편집기 탈출 방법

Vim 계열 편집기에서는 일반적으로 `:!`를 통해 명령을 실행할 수 있습니다.<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

`less` 같은 pager도 shell 실행을 노출할 수 있습니다.<sup>[[14]](#references)</sup>

`apport-cli`를 root로 실행하도록 허용하는 sudo 규칙도 pager를 동일하게 검토해야 합니다. 영향을 받는 Apport 버전에서는 공격자가 조정할 수 있는 터미널 크기로 `less`에서 crash report를 열 수 있었으며, 특수한 sudo 및 pager 조건이 충족되면 pager를 통해 root shell을 얻을 수 있었습니다. 버전만 보고 취약하다고 판단하기 전에 유효한 sudo 규칙, pager 설정, 배포판 패키지 수정 사항을 확인하세요. 수동 열거 중에는 crash를 발생시키거나 권한이 필요한 report를 열지 말고 패키지 및 정책 메타데이터를 읽으세요. [Ubuntu의 CVE 기록](https://ubuntu.com/security/CVE-2023-1326)에는 backport된 수정 사항을 포함해 릴리스별 수정 패키지 버전이 나와 있습니다.

```text
!/bin/sh
```

## 기타 sudo 및 doas 규칙의 위험 요소

먼저 `sudo -l`, `sudo -V`와 해당되는 `doas` 정책을 확인합니다. 허용된 명령, 실행 사용자, 인수, 환경, 기본값을 함께 검토합니다. root가 아닌 서비스 계정으로 실행할 권한도 해당 계정의 파일에 접근하거나 root로 이어지는 경로를 제공할 수 있습니다.

sudo에서 허용된 고정 Python 스크립트도 대화형 사용자 입력을 [`os.system()`](https://docs.python.org/3/library/os.html#os.system)에 연결하면 RunAs 권한으로 셸 명령을 실행할 수 있습니다. 셸 문장부호를 거부하는 denylist만으로 안전성이 입증되지는 않습니다. [셸은 `$(...)` 명령 치환도 인식합니다](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html). 허용된 인수가 입력 처리 분기에 도달하는지, 안전한 검증 없이 입력이 셸 명령에 전달되는지, 유효한 sudo 정책이 의도한 RunAs 사용자를 허용하는지 확인합니다. 스크립트 경로나 `os.system()` 호출은 검토를 시작할 단서일 뿐입니다. 권한이 부여된 스크립트를 실행하지 말고 소스를 검사합니다.

`chattr`에 대한 유효한 root sudo 권한으로 불변(`i`) 파일 속성을 제거할 수 있지만, 이것만으로 쓰기 권한이나 새 ID가 부여되지는 않습니다. [`chattr` 매뉴얼](https://man7.org/linux/man-pages/man1/chattr.1.html)에 따르면 이 속성은 수정을 차단하며, root 또는 `CAP_LINUX_IMMUTABLE` 권한이 있는 프로세스만 변경할 수 있습니다. 정확한 sudo 인수 정책과 파일시스템 지원 여부를 확인한 다음, 속성을 해제한 뒤 호출자가 해당 파일에 쓸 수 있는지와 더 높은 권한의 소비자가 그 파일을 사용하는지 별도로 검증합니다. 예를 들어 로그인 셸을 바꾸려면 대상 계정이 인증 정보를 받아들이고 실제로 해당 셸을 통해 로그인해야 합니다. 열거 중에는 정책, 파일 속성, 권한을 검토하되 변경하지 않습니다.

sudo가 암호와 일회용 코드 모두를 요구한다면, 이 전제 조건들을 명령 권한과 구분합니다. 읽을 수 있는 `.google_authenticator` 파일에는 민감한 seed 정보가 들어 있으며, 오래된 애플리케이션 또는 데이터베이스 암호 해시는 현재 계정 암호의 후보일 뿐입니다. 어느 쪽도 유효한 PAM 설정에서 다른 인증 요소를 받아들인다는 증거는 아닙니다. 권한이 부여된 경우 정확한 RunAs 사용자와 인수를 검토합니다. RubyGems `gem`에 대한 제한 없는 root 권한은 편집기 명령을 노출할 수 있지만([GTFOBins](https://gtfobins.github.io/gtfobins/gem/)), 제한된 권한 규칙이나 인증 실패로는 그렇지 않습니다. 수동 열거에서는 seed를 출력하거나, 암호를 복구하거나, 코드를 생성하거나, 권한이 부여된 명령을 실행하지 말고 경로와 정책만 보고합니다.

Chef의 `knife`에 대한 root 실행 가능하고 제한 없는 sudo 권한은 인터프리터 수준에서 검토해야 합니다. [Chef 문서에 따르면 `knife exec -E`는 로컬에서 Ruby 문자열을 평가합니다](https://docs.chef.io/workstation/26/tools/knife/knife_exec/). 유효한 sudo 규칙이 `exec` 하위 명령과 호출자가 제공한 `-E` 인수, 의도한 RunAs ID를 허용하는지, 일치하는 명령 거부나 고정 인수가 있는지 확인합니다. 설치된 바이너리나 다른 하위 명령으로 제한된 규칙은 단서일 뿐입니다. 수동 열거에서는 `knife`를 실행하지 말고 정책만 보고합니다.

대화형 `msfconsole`에 대한 정확한 root 실행 가능 sudo 권한도 마찬가지로 민감합니다. [GTFOBins에는 `irb` 콘솔이 문서화되어 있으며](https://gtfobins.org/gtfobins/msfconsole/), 이 콘솔은 sudo ID를 상속할 수 있습니다. 유효한 RunAs 사용자, 허용된 인수 목록, 명령 거부, `NOEXEC` 등의 제한, 설치된 콘솔의 동작, 호출자가 대화형 입력을 제공할 수 있는지 확인합니다. 경로가 강조 표시된 것만으로는 검토 단서일 뿐입니다. 수동 열거 중에는 콘솔을 실행하지 않습니다.

FreeBSD에서는 root 권한으로 `pkg update`와 `pkg install *`만 허용하는 sudo 규칙도 저장소 신뢰 검토가 필요합니다. 호출자가 `/etc/hosts`에 쓸 수 있는지, 그리고 *유효한* 활성 저장소 설정에서 `signature_type: none`인 HTTP 호스트 이름을 사용하는지 확인합니다. [FreeBSD `pkg.conf` 매뉴얼](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)에 따르면 `none`은 서명 검사를 비활성화합니다. `pkg+http`만으로는 그런 설정임을 입증할 수 없습니다. 패키지에는 설치 스크립트가 포함될 수 있으므로([FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)), 호출자가 실제로 저장소 엔드포인트를 제어하고 패키지를 선택할 수 있다면 root 경계를 넘을 수 있습니다. 결론을 내리기 전에 저장소 재정의, SRV/미러 확인, 유효한 sudo 인수, 패키지 선택, 스크립트 실행을 검증합니다. 열거 중에는 이름을 다른 곳으로 돌리거나 `pkg`를 실행하지 말고 정책과 작은 로컬 설정 파일만 검사합니다.

`apt-get update`와 `apt-get upgrade`에 대한 root 실행 가능 sudo 권한에서 sudo가 호출자 제어 `http_proxy`를 보존한다면 저장소 신뢰도 검토해야 합니다. 유효한 APT 프록시 설정이 실제로 해당 변수를 사용하며, 활성화된 저장소 요청 중 어떤 요청이 영향을 받는지 확인합니다. 프록시만으로 신뢰된 서명 키로 인증된 아카이브의 패키지를 대체할 수는 없습니다. [APT HTTP 전송 매뉴얼](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)은 프록시 우선순위를 설명하고, [apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)는 서명 검사, 안전하지 않은 저장소 재정의, 인증되지 않은 패키지에 대한 확인 절차를 설명합니다. 정확한 sudo RunAs 사용자와 인수, 저장소 인증 정책, 필요한 대화형 승인, 선택된 업그레이드가 root로 패키지 스크립트를 실행하는지 확인합니다. 열거 중에는 정책과 로컬 설정을 수동으로 검사하고, 패키지 트래픽을 다른 곳으로 돌리거나 업그레이드를 실행하지 않습니다.

` snap install`에 대한 root 실행 가능 sudo 권한은 호출자가 로컬 snap과 완화된 설치 모드를 선택할 수 있는 경우 패키지에서 코드 실행으로 이어질 수 있습니다. [Snap 문서](https://snapcraft.io/docs/explanation/snap-development/install-modes/)에 따르면 `--dangerous`는 로컬 snap assertion 검사를 건너뛰고 `--devmode`는 confinement을 완화합니다. [설치 hook은 초기 설치 중 실행될 수 있습니다](https://snapcraft.io/docs/reference/development/supported-snap-hooks/). 보호된 호스트 파일에 접근할 수 있다고 주장하기 전에 정확한 sudo 인수/RunAs 정책, snap 파일의 제어 주체, 설치된 snapd가 이 모드를 허용하는지, hook의 유효 ID와 confinement을 확인합니다. `snap` 바이너리나 와일드카드처럼 보이는 규칙만으로는 이 경로가 입증되지 않습니다. 수동 열거 중에는 패키지를 설치하거나 hook을 실행하지 않습니다.

**root가 아닌** 계정의 사용자 지정 자격 증명 읽기 바이너리에 대한 정확한 sudo 권한은 먼저 바이너리와 파일 권한을 실행하지 않고 검사합니다. 내장된 암호 확인 문자열은 와이드 문자로만 보일 수 있습니다. [GNU `strings`는 16비트 little-endian 추출을 문서화합니다](https://sourceware.org/binutils/docs/binutils/strings.html). 문자열이 보인다고 해서 그것이 허용되는 암호이거나 성공 분기가 현재 자격 증명을 노출한다는 뜻은 아닙니다. 바이너리 동작, 보호된 데이터에 대한 대상 계정의 접근 권한, 자격 증명의 유효성, 이후의 계정 또는 그룹 전환을 각각 확인합니다. 해당 계정이 `docker` 그룹에 속한다면 소켓 접근 권한과 데몬이 rootful인지 rootless인지 확인한 뒤 호스트 root 접근 가능성을 판단합니다. [Docker는 해당 그룹이 root 수준에서 미치는 영향을 문서화합니다](https://docs.docker.com/engine/install/linux-postinstall/). 일반적인 열거에서는 바이너리를 실행하거나 문자열을 덤프하지 말고 sudo 규칙과 그룹 소속만 보고합니다.

애플리케이션 유지보수 스크립트에 대한 와일드카드 sudo 규칙은 스크립트 경로만 확인해서는 부족합니다. 허용된 스크립트가 제한 없는 인수를 받거나 권한이 낮은 애플리케이션 계정이 쓸 수 있는 설정을 읽는지 확인한 다음, 해당 값이 셸 명령이나 하위 프로세스 환경에 전달되는지 추적합니다. 예를 들어 ZoneMinder의 [`zmupdate.pl`은 `mysqldump` 명령을 조합해 `qx`로 실행하고](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in), [`zmdc.pl`은 데몬을 시작하기 전에 `ZM_LD_PRELOAD` 설정을 `LD_PRELOAD`에 복사합니다](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in). 두 스크립트 중 하나를 root로 허용하는 sudo 규칙은 해당 입력을 제어할 수 있고 설치된 버전에서 그 입력이 코드에 도달한다면 신뢰 경계를 넘을 수 있습니다. 유효한 sudo 규칙, 애플리케이션 설정 권한, 스크립트 소스를 검사합니다. 와일드카드나 설정만으로는 실행이 입증되지 않으며, 검토를 시작할 단서일 뿐입니다.

- `SETENV`, `env_keep`, `secure_path`, `LD_PRELOAD`는 범위가 좁은 명령을 import, 라이브러리 또는 PATH hijack으로 이어지게 할 수 있습니다. [환경 변수 가이드](../linux-basics/linux-environment-variables.md)와 [SUID/linker 악용](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)을 참조하세요.

root 실행 가능하고 정확한 `SETENV` 권한으로 셸 wrapper를 허용한다면, wrapper가 고정 Python 스크립트를 실행하며 리터럴 import를 사용하는 경우 한 단계 더 검토해야 합니다. `secure_path`는 셸 명령 탐색을 제한할 뿐 Python의 [`PYTHONPATH` 모듈 검색](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)은 제한하지 않습니다. [`-E`와 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E)는 Python이 해당 환경 변수를 무시하게 합니다. 코드 실행으로 판단하기 전에 유효한 sudo 태그와 거부 규칙, wrapper 분기, 인터프리터 옵션, import 해석, 호출자가 쓸 수 있는 검색 디렉터리를 확인합니다. 짧은 스크립트는 정적으로 검사하고 권한이 부여된 wrapper는 실행하지 않습니다.

`neofetch ""`에 대한 root 실행 가능하고 정확한 sudo 권한도, 해당 sudo 기본값이 호출자가 제어하는 `XDG_CONFIG_HOME`을 보존한다면 셸 설정 파일을 불러올 수 있습니다. [Neofetch의 설정 로더](https://github.com/dylanaraps/neofetch/blob/master/neofetch)는 해당 디렉터리 아래의 `neofetch/config.conf` 또는 `neofetch/config`를 source합니다. 빈 인수 목록도 이 조회를 막지 못합니다. 설치된 로더, 유효한 RunAs 및 인수 정책, 명령 거부 규칙, sudo가 실제로 이 명령에 대해 해당 변수를 보존하는지, 호출자가 읽을 수 있는 설정 경로를 제어하는지 확인합니다. 변수 보존이나 Neofetch 설치 여부만으로는 검토 단서일 뿐입니다. 권한이 부여된 명령을 실행하거나 설정 내용을 출력하지 말고 정책과 파일 메타데이터를 검사합니다. [sudoers 환경 처리](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)를 참조하세요.

root 실행 가능하고 제한 없는 `facter` sudo 규칙은 사용자 지정 fact를 별도로 검토해야 합니다. [Puppet 문서](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)에 따르면 `--custom-dir`은 선택한 디렉터리에서 Ruby fact 파일을 불러옵니다. 정확한 sudo 규칙이 해당 옵션을 허용하는지, 설치된 Facter가 이를 지원하는지, 호출자가 디렉터리를 제어하는지 확인합니다. 고정 인수 권한, 명시적 명령 거부, 사용자 지정 fact 비활성화는 결과를 바꿀 수 있습니다. 수동 열거에서는 Facter를 실행하거나 fact 내용을 읽지 말고 정책상 가능한 후보만 보고합니다.

root 실행 가능하고 정확한 sudo 스크립트 권한에 `SETENV`가 있다면 `find` 같은 bare command와 sudo 정책 및 스크립트 초기화 후의 유효한 `PATH`를 검사합니다. source된 Bash 파일은 `enable -n [`을 실행할 수도 있습니다. [그러면 Bash는 `PATH`에서](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html) 이후 스크립트가 사용하는 외부 `[`를 찾습니다. 적용되는 [sudoers 환경 및 `secure_path` 규칙](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf), `NOSETENV`/`NOEXEC` 또는 거부 항목, 스크립트와 source 파일의 흐름, 호출자가 제어할 수 있는 실행 파일 검색 디렉터리를 확인합니다. bare command가 들어 있는 읽을 수 있는 스크립트는 검토 단서일 뿐, 권한 있는 실행의 증거는 아닙니다. sudo 규칙을 실행하지 말고 검사합니다.
- 고정 URL을 `curl`로 가져오는 권한 있는 스크립트도, 적용되는 sudo 규칙이 `http_proxy`를 보존하고 요청이 프록시를 통한다면 호출자가 응답을 선택할 수 있습니다. 스크립트가 그 응답을 외부 엔티티를 해석하는 XML 파서에 전달하면 악성 응답이 권한 있는 프로세스가 읽을 수 있는 파일을 유출할 수 있습니다. 정확한 sudo 환경 정책, `no_proxy` 제외 항목, 요청 URL, 파서 설정, 출력 대상을 확인합니다. 프록시 변수나 XML 파서만으로는 취약점이 입증되지 않습니다. [curl 프록시 환경 문서](https://everything.curl.dev/usingcurl/proxies/env.html)는 변수 동작을 설명합니다. 수동 열거 중에는 네트워크 요청을 보내거나 악성 XML을 파싱하지 않습니다.
- 호출자 영향 데이터로 PostScript 파일을 만든 뒤 `ps2pdf -dNOSAFER`를 실행하는 root 실행 가능 sudo 스크립트는 입력 흐름을 별도로 검토해야 합니다. Ghostscript 문서에 따르면 이 플래그는 `.setsafe`가 호출될 때까지 SAFER를 비활성화해 프로세스의 OS 권한 범위 내에서 PostScript 파일 작업을 허용합니다. 호출자 인수를 사용해 조합한 SQL 쿼리가 공격자 제어 행을 PostScript 템플릿에 전달할 수 있지만, 쿼리 문자열이나 `ps2pdf` 호출만으로 해당 데이터가 실행 가능한 PostScript 문법에 도달한다고 입증되지는 않습니다. 유효한 sudo 규칙, 입력에서 템플릿까지의 정확한 경로, escaping 여부, 설치된 Ghostscript 동작, 문서가 해석되기 전에 SAFER가 다시 활성화되는지 확인합니다. 수동 열거 중에는 권한이 부여된 변환을 실행하지 않습니다. [Ghostscript의 `-dNOSAFER` 문서](https://ghostscript.readthedocs.io/en/master/Use.html)를 참조하세요.
- 셸 스크립트를 실행하는 sudo 규칙에서는 보존된 변수와 스크립트 자체를 함께 비교합니다. `if $CHECK_CONTENT; then` 같은 구문은 확장된 값을 명령으로 실행하므로, `CHECK_CONTENT`를 보존하면 스크립트 경로와 인수가 고정되어 있어도 명령 실행을 허용할 수 있습니다. 해당 분기에 도달할 수 있는지와 환경이 실제로 보존되는지를 구체적인 규칙에 대해 확인해야 합니다.<sup>[[2]](#references)[[22]](#references)</sup>
- sudo에서 허용된 Python 스크립트는 호출자가 쓸 수 있는 디렉터리나 캐시된 `.pyc` 파일에서 코드를 import할 수 있습니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md)에서 캐시 사례를 설명합니다.
- root로 실행하도록 허용된 고정 Python 스크립트도 대화형 debugger를 노출할 수 있습니다. `pdb.set_trace()` 또는 `pdb.post_mortem()` 같은 호출은 호출자가 중단점이나 예외 처리기에 도달할 수 있고 **debugger 입력 스트림도 제어할 수 있을 때**, 디버깅 중인 프로세스의 컨텍스트에서 Python 문을 실행하게 합니다. 정확한 sudo RunAs 규칙, 인증 및 분기 조건, 예외 발생 가능성, 터미널/입력 소유권, debugger가 동일한 권한 프로세스에서 실행되는지 확인합니다. 다른 터미널에 연결된 debugger는 소켓 요청이 예외를 일으켰다는 것만으로 접근할 수 없습니다. [Python 문서는 debugger의 문 평가와 사후 분석 모드를 설명합니다](https://docs.python.org/3/library/pdb.html). 열거 중에는 권한이 부여된 handler를 트리거하지 말고 스크립트를 정적으로 검사합니다.
- sudo에서 허용된 고정 Python 스크립트는 데이터베이스나 Unix socket에서 프로필 필드를 읽어 나중에 `str.format()`의 **format string**이 되는 문자열에 추가할 수도 있습니다. [대체 필드는 속성과 매핑 키를 따라갈 수 있으므로](https://docs.python.org/3/library/string.html#format-string-syntax), 공격자가 제어하는 필드는 `format()`에 전달된 객체를 검사하고 결과가 출력되거나 호출자가 읽을 수 있는 곳에 저장되는 경우 그 객체에서 접근할 수 있는 데이터를 노출할 수 있습니다. 유효한 sudo RunAs ID, 특정 레코드에 대한 쓰기 권한, format string으로 이어지는 데이터 흐름, 전달되는 객체, 출력 접근성을 확인합니다. 이는 자동으로 코드 실행을 의미하지 않으며, 공격자가 제어하는 *값*에 신뢰된 리터럴 format string을 적용하는 경우와는 다릅니다. 노출된 비밀이 OS 계정 전환으로 이어지려면 해당 계정이 그 비밀을 받아들여야 합니다. 권한이 부여된 작업은 실행하지 말고 스크립트와 socket 권한을 검토합니다.
- root 실행 가능한 Python wrapper가 호출자 선택 URL을 GitPython의 `Repo.clone_from`에 전달할 수 있습니다. wrapper가 Git의 `protocol.ext.allow=always`도 활성화한다면 `ext::` 원격 URL이 외부 helper를 실행할 수 있습니다. 정확한 sudo 인수, URL의 출처, GitPython 패키지 버전과 공급업체 패치 여부, wrapper가 안전하지 않은 프로토콜을 명시적으로 허용하는지 확인합니다. GitPython은 3.1.30에서 [기본 unsafe-protocol 차단 기능](https://github.com/gitpython-developers/GitPython/commit/2625ed9)을 추가했습니다. `git` 실행 파일의 버전은 별개의 정보입니다. 수동 검토에서는 clone을 실행하지 말고 규칙과 범위가 제한된 소스만 읽습니다.
- 저장소를 clone하는 CLI에 대한 교차 사용자 sudo 권한은 별도의 셸 문자열 injection 경로를 노출할 수 있습니다. 호출자가 선택한 저장소 인수가 안전한 인수 분리 없이 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) 또는 다른 셸 명령 생성기에 도달하는지 추적합니다. Node의 `exec`는 명령 문자열을 셸에 전달합니다. 정확한 RunAs 사용자, 허용된 하위 명령과 인수, 설치된 wrapper 코드, 입력 검증을 확인합니다. 저장소 도구 이름이나 제한 없는 sudo 규칙만으로는 명령 injection이 입증되지 않습니다. 열거 중에는 권한이 부여된 clone을 실행하지 말고 wrapper를 검사합니다.
- root 소유의 사용자 지정 wrapper는 바이너리와 스크립트가 쓰기 불가능해 안전해 보여도, 권한 있는 작업의 실행 여부가 권한이 낮은 사용자가 변경할 수 있는 플래그, 로컬 API 값, 서비스 상태에 달려 있을 수 있습니다. 각 gate의 입력과 인증 검사를 추적합니다. 열거 중에는 동작 상태를 변경하지 말고 설정과 권한을 검사합니다. wrapper 안의 `systemd-run` 호출은 gate에 영향을 줄 수 있을 때만 관련이 있습니다.
- sudo로 root 권한 실행이 허용된 백업 클라이언트는 호출자가 구성 파일(예: `npbackup-cli -c`)을 선택할 수 있습니다. 정확한 실행 사용자와 허용 인수를 확인한 뒤, 호출자가 설정 경로, 백업 소스 경로, 저장소 또는 읽기/복원 옵션을 제어하는지 확인합니다. 읽을 수 있는 설정에 암호화된 저장소 비밀이 있어도 클라이언트에서 사용할 수는 있지만, 규칙만으로 저장소 접근이나 root 파일 유출이 입증되지는 않습니다. 백업을 실행하거나 내용을 덤프하지 말고 권한을 검증합니다.
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst)은 저장소 암호를 가져오는 프로그램을 호출하는 `--password-command`를 지원합니다. sudo 규칙이 권한이 낮은 사용자가 root로 restic을 실행하면서 호출자 지정 암호 명령과 암호가 필요한 하위 명령을 사용할 수 있게 한다면, 해당 helper는 root로 실행될 수 있습니다. 정확한 sudo 인수와 제외 규칙을 검토합니다. 이 조건을 열거하려고 helper나 백업 명령을 실행하지 않습니다.
- 권한 있는 `restic backup` 권한은 sudo 인수 패턴이 호출자에게 소스와 나중에 읽고 복호화할 수 있는 저장소를 모두 선택하게 한다면 파일 읽기 경계를 넘을 수도 있습니다. [sudoers 인수 와일드카드는 공백과 슬래시를 매칭할 수 있으므로](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf), 고정 저장소 접두사가 소스를 제한한다고 가정하지 말고 뒤따르는 와일드카드를 검사합니다. [Restic은 로컬 및 원격 저장소에 백업할 수 있지만](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html), 로컬 저장소에는 root만 읽을 수 있는 새 객체가 포함될 수 있습니다. 이를 정보 유출로 판단하기 전에 유효한 sudo 정책, 백엔드 접근, 저장소 암호, 결과 객체의 권한을 확인합니다. 백업된 SSH 키는 대상 계정이 해당 키를 받아들일 때만 접근 권한을 줍니다. 수동 검토 중에는 이를 시험하려고 백업을 실행하지 않습니다.
- 제한 없는 사용자 지정 유지보수 또는 백업 명령은 출력 경로를 받거나 자체 작업 스케줄러를 제공할 수 있습니다. 파일 쓰기 경로에서는 정확한 sudo 규칙과 실행 사용자를 확인한 다음, 호출자가 데이터와 대상을 모두 제어하는지 확인합니다. 예약 명령 경로에서는 스케줄러의 실행 ID, 명령 입력, 추가 암호 또는 인증 gate를 확인합니다. 명령 이름이나 `NOPASSWD`만으로 어느 경로도 입증되지 않습니다. [root 소유 파일에 쓰기](../interesting-files-permissions/write-to-root.md)와 [cron 및 systemd timer](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)를 참조하세요.
- 고정 sudo 명령도 공유 쓰기 가능 디렉터리에서 예측 가능한 설정 파일을 불러올 수 있습니다. 호출자가 해당 파일을 대체할 수 있는지, 파일의 source와 destination 필드가 권한 있는 fetch 또는 copy를 제어하는지 추적합니다. 로컬 파일 URL은 sudo RunAs 계정만 읽을 수 있는 데이터를 노출할 수 있고, 호출자 제어 source와 보호된 destination을 함께 사용하면 쓰기 경로가 생길 수 있습니다. 결론을 내리기 전에 설치된 프로그램의 URL 처리, destination 경로 검사, 유효한 sudo 규칙, 출력 접근성을 확인합니다. 쓰기 가능한 `/tmp` 설정 경로만으로는 검토 단서일 뿐이므로, 권한이 부여된 전송을 실행하지 말고 바이너리와 파일 메타데이터를 검사합니다.
- `git apply`에 대한 sudo 규칙은 RunAs 계정이 호출자 제어 patch에서 선택한 파일을 쓰게 할 수 있습니다. [CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)에서는 명령이 `--unsafe-paths`를 허용하지 않아도 조작된 patch가 symlink를 만든 뒤 작업 트리 밖에 쓸 수 있었습니다. 유효한 sudo 인수 규칙, patch 출처, RunAs 계정의 작업 디렉터리 접근 권한, 설치된 Git의 수정 또는 공급업체 backport를 확인합니다. `--unsafe-paths`를 허용하는 제한 없는 규칙은 별도의 명시적 옵션 위험입니다. Git 버전이나 `git apply` 권한만으로 보호된 파일을 변경할 수 있다고 입증되지는 않습니다. 수동 열거 중에는 신뢰할 수 없는 patch를 적용하지 않습니다.
- root 실행 가능한 `clamscan --debug` 규칙은 권한이 낮은 사용자가 DMG 이미지를 제공할 수 있고 설치된 파서가 debug 출력으로 파일 내용을 노출할 수 있었던 [CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)의 영향을 받는 경우 읽기 경계를 넘을 수 있습니다. 정확한 허용 인수와 검사 경로, 입력 제어, 유효한 RunAs 계정, 엔진 수정/backport, 출력이 호출자에게 보이는지 확인합니다. 더 넓은 규칙에서 `--file-list`/`-f`를 허용한다면 그 동작은 별도로 검토합니다. `--debug <scan-path>`로 고정된 정책은 이를 허용하지 않습니다. 열거 중에는 조작된 파일을 검사하거나 보호된 출력을 출력하지 말고 정책과 패키지 메타데이터를 확인합니다.
- 호출자가 선택한 암호화 디스크 이미지를 여는 root 실행 가능 sudo 규칙과 결과 mapper를 마운트하는 두 번째 규칙은 호출자 제어 파일을 호스트의 mount namespace로 가져올 수 있습니다. 유효한 두 규칙과 인수, 이미지 및 mapper 이름 제어, 실제 마운트 대상, 결과 파일의 소유자와 모드를 확인합니다. set-user-ID 전환에는 접근 가능한 실행 파일, 이를 허용하는 마운트 옵션(`nosuid`는 차단함), 적용되는 프로세스 또는 MAC 정책이 추가로 필요합니다. 이미지를 열거나 마운트하는 것만으로는 검토 단서일 뿐입니다. 기존 백업을 이용한 별도 경로에는 실제 키와 그 안의 유용하며 읽을 수 있는 비밀이 필요합니다. 수동 열거 중에는 정책과 경로를 검사하되 이미지를 열거나 마운트하지 않습니다. [cryptsetup 매뉴얼](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)과 [mount 옵션](https://man7.org/linux/man-pages/man8/mount.8.html)을 참조하세요.
- root 실행 가능 sudo 규칙으로 셸 또는 Python 스크립트를 실행할 때, 스크립트가 고정 디렉터리로 이동하지 않고 `./helper`를 호출한다면 작업 디렉터리를 검토합니다. `subprocess.run`에 전달하는 `['./helper']` 같은 Python 목록도 호출자가 선택한 작업 디렉터리에서 실행될 수 있습니다. 호출자가 쓰기 가능한 디렉터리를 선택해 그 안에 해당 상대 경로 이름의 실행 파일을 둘 수 있습니다. 스크립트의 다른 곳에서 절대 경로를 사용해도 이 호출은 보호되지 않습니다. 코드 실행으로 판단하기 전에 유효한 규칙, `runchdir` 또는 다른 디렉터리 변경 정책, 스크립트 흐름과 분기 도달 가능성, 쓰기 및 실행 가능한 디렉터리, mount/`NOEXEC` 제한을 확인합니다. 스크립트를 읽을 수 없다면 승인된 경로로 소스를 검토하기 전까지 동작을 알 수 없습니다. helper를 실행하지 말고 스크립트를 정적으로 검토합니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)은 작업 디렉터리 정책을 설명합니다.
- 고정된 root 실행 가능 Python validator도 호출자 선택 데이터 파일을 평가할 수 있습니다. [Python의 `eval()` 문서는 신뢰할 수 없는 입력에 사용하지 말라고 경고합니다](https://docs.python.org/3/library/functions.html#eval). 입력 접미사 검사, 산술식 접두사, 검증 분기는 남은 식이 `eval`에 전달되면 sandbox가 아닙니다. 실행 경로라고 판단하기 전에 유효한 sudo 규칙, 호출자가 정확한 파일을 선택하고 제어할 수 있는지, 파서의 분기 조건과 식 구성, 권한 프로세스의 ID를 확인합니다. 읽을 수 있는 스크립트에 `eval`이 있다는 사실은 검토 단서일 뿐입니다. 열거 중에는 validator를 실행하거나 시험 식을 제출하지 말고 소스와 파일 권한을 검사합니다.
- root 실행 가능 sudo Ruby wrapper가 `YAML.load(File.read("dependencies.yml"))`처럼 상대 YAML 파일을 읽으면 wrapper나 sudo 정책이 디렉터리를 고정하지 않는 한 호출자의 현재 작업 디렉터리에서 입력을 가져올 수 있습니다. 정확한 허용 인수, 디렉터리와 파일 권한, 설치된 Psych 동작을 확인합니다. 구버전 `YAML.load`는 임의의 Ruby 객체를 역직렬화할 수 있었지만, 최신 릴리스는 기본적으로 허용 클래스를 제한합니다. 정적 호출 지점은 검토 단서일 뿐입니다. 실제로 호출자가 쓸 수 있는 디렉터리에서 파일을 가져오고 설치된 loader가 위험한 클래스를 허용하는지 확인합니다. 신뢰할 수 없는 입력에는 명시적인 최소 클래스 allowlist를 사용한 `safe_load`를 우선합니다. [Ruby 3.0 Psych 문서](https://docs.ruby-lang.org/en/3.0/Psych.html)와 [Ruby 3.1 Psych 문서](https://ruby-doc.org/core-3.1.2/Psych.html)를 참조하세요.

- root 실행 가능하고 정확한 `sudo go run /absolute/file.go` 권한은 Go 소스가 상대 경로의 WASM 파일을 읽고 결과를 검사한 뒤 상대 경로의 셸 스크립트를 실행할 수 있는 경우 작업 디렉터리를 검토해야 합니다. 유효한 RunAs 사용자, 명령 인수와 거부 규칙, 호출자가 쓸 수 있는 현재 디렉터리, WASM에서 분기로 이어지는 데이터 흐름, 해당 분기가 helper를 호출하는지 확인합니다. 고정 sudo `runchdir`, `os.Chdir`, [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec)는 조회 위치를 바꿀 수 있습니다. 정적 요소의 동시 존재만으로는 후보일 뿐입니다. Go, WASM, helper를 실행하지 말고 소스를 검사합니다.
- `sudoedit`와 인수 와일드카드는 정확한 버전 및 규칙 검사가 필요합니다. [체크리스트](linux-privilege-escalation-checklist.md)에 sudoedit 파일 편집 문제가 포함되어 있습니다. 와일드카드 경로의 교차 사용자 `sudoedit` 권한에서는 유효한 `sudoedit_follow` 또는 `FOLLOW` 설정, `sudoedit_checkdir`, 해석된 대상, 각 상위 경로 항목을 바꿀 수 있는 사용자를 검사합니다. 전자는 symlink 추적을 허용할 수 있고, 후자를 비활성화하면 쓰기 가능한 디렉터리 검사를 제거하지만 어느 설정도 다른 사용자의 파일에 쓸 수 있음을 단독으로 입증하지는 않습니다. 결론을 내리기 전에 설치된 sudo 정책과 실제로 일치하는 인수를 확인합니다. [sudoers 옵션 정의](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)를 참조하세요.
- sudoers 명령 규칙에서 인수 와일드카드는 공백과 경로 문자를 모두 매칭할 수 있습니다. `/restricted/*` 같은 인수를 받는 읽기 가능 명령 규칙은 일치하는 접두사 뒤에 추가 파일 인수를 허용할 수 있습니다. 정확한 실행 사용자, 명령 경로, 인수 패턴, 이후의 거부 규칙을 검토합니다. 파일 읽기를 입증해도 명령 실행이 따라오는 것은 아닙니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)은 인수 glob과 명령 경로 glob을 구분합니다.
- 경로처럼 보이는 인수 glob도 `../`를 매칭할 수 있습니다. 예를 들어 root 실행 가능 `node /opt/scripts/*.js` 규칙은 제공된 경로가 `/opt/scripts/`로 시작하더라도 상위 디렉터리 구간을 통해 해석되는 경우 호출자가 `/opt/scripts` 바깥의 JavaScript 파일을 선택하도록 허용할 수 있습니다. 이는 **인수** glob입니다. Node 실행 파일의 명령 경로 glob은 슬래시를 다르게 매칭합니다. 코드 실행으로 결론 내리기 전에 유효한 규칙, 이후 거부 규칙, 경로 해석, 대상 파일 제어, sudoers 정규식 또는 digest 제한을 확인합니다. [sudoers 와일드카드 규칙](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)과 [Node 명령줄 문서](https://nodejs.org/api/cli.html)를 참조하세요.
- Archiver와 기타 유틸리티 프로그램에는 실행 hook이 있을 수 있습니다. 셸이나 인터프리터만 명령을 실행한다고 가정하지 말고 정확히 허용된 인수를 [GTFOBins](https://gtfobins.github.io/)와 대조합니다.
- root 실행 가능하고 제한 없는 `qpdf` 규칙은 PDF attachment를 통해 권한 있는 파일을 노출할 수 있습니다. qpdf 10.2 이상은 출력 PDF와 함께 `--empty` 및 `--add-attachment file ... --`를 지원합니다. 권한 있는 프로세스가 선택한 source를 읽고 PDF를 호출자가 접근 가능한 경로에 쓸 수 있다면, 결과 PDF에 source 바이트가 들어갈 수 있습니다. 파일 유출이 가능하다고 결론 내리기 전에 유효한 sudo 인수와 제외 규칙, qpdf 버전, source 접근 권한, 출력 경로를 검토합니다. root SSH 키를 읽어도 키가 유효하고 root SSH 인증이 허용된 경우에만 로그인에 유용합니다. [qpdf attachment 옵션](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)을 참조하세요.
- sudo timestamp 재사용은 캐시 정책, 소유 사용자, 터미널/세션, 권한에 따라 달라집니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)에 확인 항목이 있습니다.
- `doas`에는 자체 규칙과 설정이 있습니다. [doas 섹션](../linux-basics/linux-privilege-escalation/README.md#doas)에 설명된 대로 허용된 명령과 쓰기 가능한 설정 경로를 확인합니다.

### sudo로 실행되는 빌드 및 패키지 도구

Foundry의 `forge`에 대한 제한 없는 sudo 권한은 RunAs ID가 다른 비root 사용자여도 문제가 될 수 있습니다. `--use` 같은 compiler 옵션으로 로컬 실행 파일을 선택하고, `forge flatten -o`로 출력 파일을 선택할 수 있습니다. 악용 가능하다고 판단하기 전에 설치된 Forge 버전, 정확한 sudo 인수, 접근 가능한 프로젝트와 compiler 경로, 출력 권한, 유효한 환경을 확인합니다. `PATH`를 통해 찾은 상대 경로 helper 실행 파일은 버전과 환경에 따라 달라지는 경로이며, 모든 Forge 빌드에서 당연히 가능하다고 가정해서는 안 됩니다.<sup>[[23]](#references)[[24]](#references)</sup>

root 실행 가능하고 제한 없는 `pacman` 권한은 패키지 조회 이상을 허용합니다. `-U`는 로컬 패키지를 받으며 패키지에는 설치 스크립트가 포함될 수 있고 `--hookdir`은 다른 hook 디렉터리를 선택합니다. 시험하기 전에 유효한 sudo 규칙, 인수 제한 및 제외 규칙을 검토합니다. 수동 열거에서는 패키지를 설치하거나 hook을 실행할 필요가 없습니다.<sup>[[25]](#references)[[26]](#references)</sup>

고정 sudo 셸 wrapper가 이름으로 지정된 npm dependency를 설치한 뒤 Node 애플리케이션을 시작할 수도 있습니다. 정확한 RunAs 규칙, 패키지의 기존 설치 여부, 유효한 `HOME`과 npm `userconfig`, 프로젝트 설정 또는 명령줄 재정의, 권한이 낮은 사용자가 해당 이름에 대해 반환되는 registry나 패키지를 제어하는지 검토합니다. [npm 문서는 사용자별 및 프로젝트별 `.npmrc` 조회를 설명합니다](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/). sudo의 `HOME` 동작은 설치된 정책과 배포판에 따라 달라지므로, 권한이 낮은 사용자의 쓰기 가능한 `.npmrc`를 권한 있는 npm 프로세스가 읽을 수도 있고 읽지 않을 수도 있습니다. 새로 설치된 패키지를 권한 있는 애플리케이션이 import한다면 해당 모듈 코드는 애플리케이션의 ID로 실행될 수 있습니다. 설치 시 스크립트는 별도의 경로이며 버전과 설정에 따라 달라집니다. [npm은 해당 스크립트의 lifecycle과 사용자 처리를 설명합니다](https://docs.npmjs.com/cli/v6/using-npm/scripts/). `.npmrc` 경로나 `npm install` 행만으로는 검토 단서일 뿐입니다. 수동 열거 중에는 설치하거나 애플리케이션을 시작하지 말고 규칙, 짧은 wrapper, 설정 경로, 패키지 출처를 검사합니다.

root 실행 가능 `pip` 또는 `pip3 download` 권한도, 인수가 호출자에게 신뢰할 수 없는 source distribution을 선택하게 한다면 패키지 빌드 검토 단서입니다. URL 패턴이 로컬 서비스와 `.tar.gz` 접미사로 제한되어도 마찬가지입니다. `pip download`는 아카이브 URL을 받고 패키지 메타데이터를 확인합니다. sdist를 준비하는 과정은 아카이브를 저장하기 전에 build backend 또는 기존 `setup.py` 코드를 실행할 수 있습니다. 정확한 sudo RunAs와 인수 규칙, 호출자가 선택한 아카이브를 게시하거나 대체할 수 있는지, 해당 pip 버전이 실제로 메타데이터를 준비하는지 확인합니다. 신뢰할 수 있는 고정 아카이브나 wheel만으로는 이 경로가 성립하지 않습니다. 수동 열거 중에는 신뢰할 수 없는 패키지를 가져오거나 빌드하지 않습니다. pip의 [download 명령](https://pip.pypa.io/en/stable/cli/pip_download/), [build-system 인터페이스](https://pip.pypa.io/en/stable/reference/build-system/), [안전한 설치 지침](https://pip.pypa.io/en/stable/topics/secure-installs/)을 참조하세요.

호출자 선택 로컬 프로젝트 경로와 함께 `pip install`을 허용하는 sudo 규칙은 더 직접적인 빌드 경계입니다. [pip는 로컬 프로젝트 디렉터리를 받을 수 있으며](https://pip.pypa.io/en/stable/topics/local-project-installs/), 해당 빌드 시스템을 호출합니다. [build backend는 프로젝트가 제어하는 build hook을 실행합니다](https://pip.pypa.io/en/stable/reference/build-system/). 규칙을 권한 있는 코드 실행으로 판단하기 전에 유효한 RunAs ID, 정확한 인수 제한과 거부 규칙, 선택된 프로젝트에 대한 제어 권한, 설치된 pip/backend 동작을 확인합니다. 신뢰할 수 있는 고정 프로젝트나 호출자 선택 경로를 제외하는 규칙으로는 이 경로가 성립하지 않습니다. 수동 열거 중에는 패키지를 설치하지 말고 규칙과 프로젝트 메타데이터를 검토합니다.

root 실행 가능하고 제한 없는 `easy_install` 권한도 유사한 레거시 패키지 빌드 검토 단서입니다. [Setuptools 문서](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)에 따르면 Easy Install은 로컬 프로젝트 디렉터리를 받아 source distribution을 빌드합니다. 호출자가 제어하는 프로젝트는 sudo ID로 빌드되는 동안 `setup.py`를 실행할 수 있습니다. 유효한 RunAs 계정, 정확한 명령과 인수 제한(이후 거부 규칙 포함), 선택한 프로젝트에 대한 제어 권한, 설치된 도구의 동작을 확인합니다. 신뢰할 수 있는 고정 프로젝트나 호출자가 source를 선택할 수 없는 정책으로는 이 경로가 성립하지 않습니다. 열거 중에는 패키지를 설치하지 말고 규칙과 프로젝트 메타데이터를 검사합니다.

호출자 선택 URL을 사용하는 `setuptools.package_index.PackageIndex.download` 호출 Python wrapper는 `pip download`와 다른 검토 사례입니다. [setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)는 78.1.1 이전의 취약한 릴리스에서 URL로부터 만든 파일명이 의도된 다운로드 디렉터리를 벗어나 프로세스 권한으로 파일을 쓸 수 있다고 설명합니다. 유효한 sudo RunAs 및 인수 규칙, wrapper가 호출자의 URL을 이 정확한 API에 전달하는지, 설치된 빌드 또는 공급업체 backport, 결과 경로의 해석을 확인합니다. 버전 문자열이나 쓰기 가능한 다운로드 디렉터리만으로 임의 쓰기가 입증되지는 않습니다. 열거 중에는 URL을 가져오거나 파일을 쓰지 말고 짧은 wrapper와 패키지 메타데이터를 검토합니다.

호출자 선택 `.spec` 파일을 PyInstaller에 전달하는 sudo 허용 빌드 wrapper도 같은 신뢰 경계 검토가 필요합니다. PyInstaller spec은 **빌드 중** 실행되는 Python이며 `datas` 항목을 통해 빌드 ID가 읽을 수 있는 파일을 아티팩트에 포함할 수 있습니다. 정확한 RunAs 사용자, sudo 인수 및 거부 규칙, wrapper의 경로와 분기 처리, 선택된 spec 파일에 대한 제어 권한, 결과 아티팩트 접근성을 확인합니다. `.py` 입력 허용이나 PyInstaller 설치만으로 spec 파일 제어 또는 권한 있는 실행이 입증되지는 않습니다. 수동 검토에서는 범위가 제한된 wrapper 파일과 메타데이터만 읽고 빌드를 실행하지 않습니다. [PyInstaller spec 파일 문서](https://pyinstaller.org/en/stable/spec-files.html)를 참조하세요.

### sudo로 실행되는 preset 및 plugin loader

호출자가 선택한 preset 또는 plugin 디렉터리를 받는 Python 도구는 sudo로 부여된 권한으로 코드를 import할 수 있습니다. 예를 들어 BBOT은 `-p`로 preset을 받고, [사용자 지정 모듈 문서](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)에는 추가 Python 모듈 디렉터리를 선택하는 `module_dirs` 항목이 설명되어 있습니다. 유효한 sudo 규칙이 호출자 선택 preset을 허용하고 호출자가 선택된 디렉터리의 모듈을 제어한다면, 도구가 잘못된 모듈을 거부하기 전에도 import를 통해 권한 있는 사용자로 코드를 실행할 수 있습니다. 열거 중에는 모듈을 로드하지 말고 설치된 버전, 정확한 sudo 실행 사용자 및 인수 정책, preset과 모듈 경로의 소유권을 확인합니다.

### sudo로 실행되는 Backdrop 명령줄 도구

[Bee](https://github.com/backdrop-contrib/bee)는 Backdrop CMS용 PHP 명령줄 도구입니다. `eval` (`php-eval`)과 `php-script` 명령은 호출자가 제공한 PHP를 실행할 수 있습니다. 따라서 제한 없는 인수로 Bee 실행 파일을 root로 허용하는 sudo 규칙은 Bee가 Backdrop 설치를 초기화할 수 있을 때 root 코드 실행으로 이어질 수 있습니다. 사이트 디렉터리에서 실행하거나 전역 `--root=<directory>` 옵션으로 사이트를 선택합니다. Bee나 Backdrop `settings.php` 파일을 찾았다는 사실만으로 sudo 권한, 사용 가능한 사이트, 초기화 성공이 입증되지는 않습니다. 시험하기 전에 유효한 sudo 규칙, 명령 제외 항목, 실행 파일의 ID, 사이트 접근 권한을 검토합니다. 수동 열거 중에는 Bee를 실행하지 말고 규칙과 파일 경로를 검사합니다. PHP 명령 추가 사항은 [Bee 명령 변경 로그](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)를 참조하세요.

### sudo로 실행되는 terminal server

`mosh-server`는 호출 사용자로 대화형 terminal server를 시작합니다. 높은 UDP 포트와 세션 키를 선택해 호출자에게 보고하며, 클라이언트가 연결되면 보통 해당 사용자의 로그인 셸을 실행합니다. 따라서 명령 자체가 분리 실행되더라도 `mosh-server`에 대한 제한 없는 root 실행 가능 sudo 권한은 셸 검토 후보입니다. 유효한 RunAs ID, 허용된 인수와 제외 규칙, 설치된 바이너리, 셸, 클라이언트 사용 가능 여부, UDP 접근을 확인합니다. 수동 열거 중에는 서버를 시작하거나 활성 세션 키를 출력하지 말고 sudo 규칙을 검사합니다. [Mosh server 매뉴얼](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)과 [upstream 설계 노트](https://github.com/mobile-shell/mosh#how-it-works)를 참조하세요.

### 호출자의 작업 파일을 다시 쓰는 권한 있는 백업 wrapper

root로 실행되는 셸 wrapper가 호출자 선택 작업 파일을 받아 source 경로에서 `../`를 제거하고, 결과가 허용된 디렉터리로 시작하는지 확인한 다음, 작업 파일을 다시 쓰고 그 *경로명*을 백업 프로그램에 전달할 수 있습니다. 전체 경로를 정규화한 뒤 변환 결과를 검토합니다. 문자열을 한 번 치환하면 lexical prefix 검사를 통과하는 새로운 경로 순회 구간이 만들어질 수 있습니다. 또한 백업 프로그램이 메모리상의 변환된 데이터를 읽는지, 파일을 다시 여는지 확인합니다. 파일을 다시 연다면 쓰기에 실패한 뒤에도 원본 입력 파일이 그대로 남아 있을 수 있습니다.

Linux에서 `fs.protected_regular`은 world-writable sticky 디렉터리에 있는 다른 사용자의 일반 파일에 대한 `O_CREAT` 쓰기를 거부할 수 있습니다. 이 거부는 보호 기능이지만, 쓰기 오류를 무시하는 셸 wrapper는 원래 작업 파일을 계속 사용할 수 있습니다. 이 설정, 파일 소유자와 디렉터리, wrapper가 실패 시 중단하는지 확인합니다. 경로가 파일 유출 후보가 되려면 유효한 sudo 규칙이 wrapper를 권한 있는 사용자로 실행하도록 허용하고, 호출자가 작업 입력과 읽을 수 있는 백업 대상을 제어하며, 백업 유틸리티가 실제로 보호된 source를 포함해야 합니다. 열거 중에는 백업을 실행하지 말고 이러한 조건을 검사합니다.

### 권한 있는 packet 도구의 인수 와일드카드

`tcpdump` sudo 규칙에서 **인수 패턴**의 `*`는 공백과 슬래시를 매칭하므로 경로처럼 보이는 제한도 추가 옵션 텍스트를 허용할 수 있습니다. 이는 명령 실행 파일 경로의 와일드카드와 다릅니다. 전체 RunAs 규칙과 이후 거부 항목을 검사합니다. 옵션을 주입할 수 있다면 허용된 호출과 설치된 [`tcpdump` 옵션 의미](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)에 따라 `-F`, `-V`, `-r`, `-w`, `-Z`가 유용한 읽기/쓰기 primitive를 제공하는지 결정됩니다. `-V`는 일반적인 임의 파일 덤프가 아니라 capture 파일 이름 목록을 읽습니다. sudo가 명령을 허용해도 AppArmor나 다른 MAC 정책이 파일 접근을 차단할 수 있습니다. 디스크에 있는 profile 파일만으로 로드되거나 강제 적용 중임을 입증할 수는 없습니다. 결론을 내리기 전에 권한과 정책을 수동으로 검토합니다. [sudoers 매뉴얼](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)은 와일드카드의 차이를 설명합니다.

인수 제한 없이 `tcpdump` 실행 파일만 나열한 root 실행 가능 sudo 규칙도 검토해야 합니다. [tcpdump 매뉴얼](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)에 따르면 `-z`는 `-C` 또는 `-G`로 저장된 capture를 회전할 때 실행되는 사후 회전 명령입니다. `-Z` 또는 컴파일 시 기본값은 이 명령이 실행되기 전에 권한을 낮출 수 있습니다. 해당 규칙을 권한 상승 경로로 판단하기 전에 유효한 sudo 규칙, 설치된 빌드, 권한 강하 동작, 회전 발생 가능성을 확인합니다. 강조 표시된 규칙은 후보일 뿐 root 명령 실행의 증거는 아닙니다.

### sudo로 실행되는 Nmap wrapper

sudo에서 허용된 `nmap` 경로가 셸 wrapper라면, 허용된 정확한 경로와 전달되는 모든 옵션을 검사합니다. 익숙한 `--script` 표기를 막아도 NSE 코드 로딩이 반드시 차단되는 것은 아닙니다. Nmap의 [`--datadir`](https://nmap.org/book/man-misc-options.html)은 데이터 파일을 선택하고, 스크립팅이 활성화되면 NSE가 선택된 데이터 디렉터리에서 [`nse_main.lua`를 로드합니다](https://nmap.org/book/nse-implementation.html). 설치된 빌드 중 일부는 대체 long-option 표기도 허용하므로 해당 바이너리의 실제 parser와 제한을 비교합니다. [`--excludefile`](https://nmap.org/book/man-target-specification.html)은 별도의 파일 읽기 공격면이며 parser 오류가 내용을 노출할 수 있습니다. 열거 중에는 scan을 실행하지 말고 유효한 sudo 규칙, wrapper 로직, Nmap 버전, 디렉터리 제어, MAC 정책을 확인합니다.

### sudo로 실행되는 Mercurial pull hook

고정된 source를 사용하는 `sudo hg pull /fixed/source`도 `-R`로 저장소를 고정하지 않으면 현재 작업 디렉터리의 **수신** 저장소를 사용합니다. 호출자가 제어하는 수신 저장소는 `.hg/hgrc`에 hook을 정의할 수 있으며, hook은 sudo RunAs 사용자로 실행될 수 있습니다. [Mercurial은 신뢰할 수 없는 사용자가 소유한 저장소 설정을 무시하므로](https://mercurial-scm.org/help/topics/config), 이를 코드 실행으로 판단하기 전에 RunAs 계정의 신뢰 사용자/그룹과 정확한 작업 디렉터리를 검사합니다. 수동 검토에는 정책과 설정을 읽는 것으로 충분합니다. 열거를 위해 pull하거나 hook을 실행하지 않습니다.

### sudo로 실행되는 Git pull hook

root 실행 가능하고 정확한 `sudo git pull` 권한에서는 작업 디렉터리로 선택되는 **수신** 저장소도 확인합니다. 호출자 소유 저장소에는 실행 가능한 `post-merge` hook이 있을 수 있으며, pull이 성공적인 merge를 실제로 수행하면 Git 프로세스의 ID로 실행됩니다. [Git은 이 hook을 문서화하고](https://git-scm.com/docs/githooks), [pull의 merge/rebase 동작](https://git-scm.com/docs/git-pull)도 설명합니다. 유효한 sudo 규칙과 CWD, 활성 hook 경로 및 권한, 새 commit을 포함한 merge가 발생할 수 있는지 확인합니다. 실패하거나 변경이 없거나 rebase만 수행하는 pull은 이 hook 경로를 입증하지 않습니다. 권한이 부여된 pull은 실행하지 말고 정책과 저장소 메타데이터를 검사합니다.

### sudo로 실행되는 rsync archive 복사

`sudo rsync -a ... /writable/source/* /fixed/destination/`에서 **sudoers 인수 패턴**의 `*`는 공백을 매칭해 source와 destination 사이에 추가 옵션을 허용할 수 있습니다. 이는 파일명에 대한 셸 확장과 다릅니다. 호출자가 source를 채울 수 있고 권한 있는 rsync 프로세스가 destination에 쓸 수 있다면, [`--chown`](https://download.samba.org/pub/rsync/rsync.1)으로 권한 있는 소유자를 지정하면서 archive 모드가 권한 비트를 보존하게 해 소유권이 설정된 SetUID 파일을 만들 수도 있습니다. 정확한 [sudoers 와일드카드 의미](https://man7.org/linux/man-pages/man5/sudoers.5.html), rsync 버전, 이후 거부 규칙, 파일시스템 `nosuid`, MAC 정책을 확인합니다. 일치하는 규칙은 검토 후보일 뿐 성공적인 권한 상승의 증거는 아닙니다.

### sudo로 실행되는 packet-filter 규칙 내보내기

`iptables`와 `iptables-save`(또는 해당 `ip6tables` 쌍)를 모두 허용하는 root 실행 가능하고 제한 없는 권한은 파일 쓰기 검토가 필요합니다. `comment` match는 호출자 지정 규칙 텍스트를 받고, `iptables-save -f`는 직렬화한 ruleset을 선택한 경로에 씁니다.<sup>[[20]](#references)[[21]](#references)</sup> 유용한 payload가 가능한지는 설치된 backend가 주석을 직렬화하는 방식과 대상 파일이 내보내기 결과에서 다른 행을 허용하는지에 따라 달라집니다. `iptables-save`만으로 임의의 선택 콘텐츠를 작성할 수는 없습니다. 정확한 sudo RunAs ID, 인수와 제외 규칙, 사용 가능한 match extension, backend, 대상 권한을 확인합니다. 열거 중에는 방화벽 규칙을 변경하거나 파일을 쓰지 말고 권한만 검사합니다.

### 권한 있는 Below 로그 디렉터리

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)은 world-writable `/var/log/below` 디렉터리를 만들던 0.9.0 이전 Below 릴리스에 영향을 줬습니다. 서비스나 허용된 sudo 명령이 취약한 빌드를 root로 실행한다면, sticky bit가 없는 로그 디렉터리에 쓰고 탐색할 수 있는 사용자는 권한 있는 프로세스가 열기 전에 로그 항목을 symlink로 바꿀 수 있습니다. 설치된 패키지의 수정 여부, 정확한 권한 실행 경로, 유효한 디렉터리 접근 권한, sticky bit와 ACL, `/var/log/below/error_root.log`의 메타데이터를 검토합니다. world-writable 경로나 sudo 규칙만으로 전체 경로가 입증되지는 않습니다. sticky 디렉터리나 공급업체 backport는 판단을 바꿉니다. 수동 열거에서는 메타데이터만 확인하면 되며 symlink를 만들거나 권한이 부여된 프로그램을 실행할 필요는 없습니다.

### 쓰기 가능한 입력에서 권한 있는 support bundle 수집

sudo에서 허용된 support-profile 스크립트는 root로 고정 로그 경로를 읽어 내용을 profile archive에 복사할 수 있습니다. 실제 스크립트가 파일을 읽는지 확인한 다음, 호출자가 source 경로나 상위 디렉터리 항목을 symlink로 바꿀 수 있는지 검사합니다. 권한 있는 읽기 작업이 해당 링크를 따라가고 결과 archive를 호출자가 읽을 수 있다면 보호된 파일이 유출될 수 있습니다. sudo 권한, 쓰기 가능한 source 경로, 권한 있는 읽기, 읽을 수 있는 출력이 모두 필요합니다. 쓰기 가능한 로그나 profile 파일명만으로는 충분하지 않습니다. 열거 중에는 파일을 대체하거나 profile을 생성하지 말고 유효한 권한과 링크 메타데이터를 검사합니다. [Nagios XI support 지침](https://support.nagios.com/forum/viewtopic.php?t=62758)은 root로 실행되는 profile 스크립트와 출력 archive를 문서화하며, 이런 bundle에서 입력과 출력 접근을 제한해야 하는 이유를 보여줍니다.

### root로 실행되는 Python archive 복원 스크립트

범위가 엄격하게 제한된 Python 복원 스크립트에 대한 sudo 규칙도 archive 입력을 검토해야 합니다. 호출자가 archive를 선택하거나 대체할 수 있고 스크립트가 root로 `tarfile.extractall(filter="data")`를 사용해 압축을 푼다면, 이 filter가 포함된 인터프리터의 보안 업데이트를 확인합니다. CPython은 symlink 및 hard-link filter 우회 취약점을 여러 건 수정했으며, CVE-2025-4517은 3.9.23, 3.10.18, 3.11.13, 3.12.11, 3.13.4에서 수정되었습니다. 배포판 backport가 이전 버전에도 수정 사항을 적용할 수 있으므로 표시된 인터프리터 버전만으로 취약성을 입증할 수는 없습니다.<sup>[[16]](#references)[[17]](#references)</sup>

수동 검토에서는 정확한 sudo 명령과 스크립트를 읽고, 어떤 인수가 archive를 선택하는지 추적하며, 현재 사용자가 archive 또는 archive가 있는 디렉터리에 쓸 수 있는지 확인합니다. 설치된 공급업체 패치와 압축 해제 대상을 별도로 확인합니다. `filter="data"`가 모든 신뢰할 수 없는 archive를 안전하게 만드는 것은 아닙니다.<sup>[[16]](#references)[[17]](#references)</sup>

### sudo로 실행되는 machine-learning model loader

호출자가 선택한 `.pt`, `.pth`, `.ckpt` 파일을 허용하는 sudo 규칙은 권한 있는 스크립트가 해당 파일을 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html), `pickle.load` 또는 다른 pickle 기반 loader에 전달할 때 검토해야 합니다. 유효한 RunAs 규칙, 호출자가 선택한 model을 만들거나 대체할 수 있는지, 셸 wrapper를 거쳐 Python helper에 전달되는 실제 인수 흐름을 확인합니다. `.pth` 확장자는 관련 없는 Python site 설정 파일에도 사용되므로 확장자만으로 model을 불러온다는 증거가 되지는 않습니다. archive scan이나 정적 pickle scan만으로 이후의 load가 안전하다고 입증되지는 않습니다. loader의 [버전에 따른 `weights_only` 동작](https://docs.pytorch.org/docs/stable/notes/serialization.html)과 allowlisting을 검사합니다. [ML pickle 및 Fickling 노트](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)를 참조하세요. 수동 열거 중에는 model을 불러오거나 압축을 풀지 않습니다.

### 저장된 입력을 sudo로 실행되는 식으로 파싱

sudo를 통해 root로 실행되는 고정 Python 스크립트도 권한이 낮은 사용자가 애플리케이션 데이터베이스에 저장할 수 있는 텍스트를 평가할 수 있습니다. TensorFlow에서 `preprocess_input_exprs_arg_string(value, safe=False)` 호출은 `eval` 경로를 선택합니다. [TensorFlow 권고문](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)은 안전하지 않은 parser와 이를 호출하는 명령줄 코드의 수정 사항을 설명합니다. 애플리케이션에서 명시적으로 `safe=False`를 호출하는 경우에는 명령줄 코드가 패치되어 있어도 별도로 검토해야 합니다. 유효한 sudo 규칙, 정확한 입력 행을 수정할 수 있는 사용자, 필터링이나 scoring을 통과해 해당 행이 호출에 도달하는지, 설치된 함수의 동작을 확인합니다. TensorFlow 버전, sudo 권한, 하드코딩된 model 파일만으로는 전체 경로가 입증되지 않습니다. 열거 중에는 권한이 부여된 helper를 실행하거나 시험 식을 제출하지 말고 스크립트와 데이터 흐름을 수동으로 검사합니다.

### sudo에서 허용된 needrestart 설정

`needrestart -c`는 호출자가 선택한 Perl 설정 파일을 불러와 내용을 평가합니다. `sudo -l`에서 인수에 `-c`를 허용하는 root 실행 권한이 있고 호출자가 쓰기 가능한 위치의 읽을 수 있는 설정 파일을 선택할 수 있다면, 해당 권한은 root 코드 실행으로 이어질 수 있습니다. 정확한 sudo 실행 사용자와 인수 규칙을 확인합니다. 고정 인수 목록만 허용하는 규칙은 이 경로를 차단할 수 있습니다. 이는 needrestart의 interpreter-scanning 취약점과 별개입니다. 패키지를 업데이트하거나 `interpscan`을 비활성화해도 root `-c`에 대한 제한 없는 권한이 안전해지는 것은 아닙니다.<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 다른 계정으로 sudo 실행되는 Python import

고정 Python 진입점도 호출자가 편집하거나 대체할 수 있는 모듈을 import할 수 있습니다. sudo가 **root가 아닌** 서비스 사용자로 스크립트를 실행하는 경우도 마찬가지입니다. `from utils import status`처럼 리터럴로 import한다면 패키지 디렉터리 권한뿐 아니라 로컬 `utils/__init__.py`와 `utils/status.py`도 검토합니다. 쓰기 가능한 파일을 실행 경로라고 판단하기 전에 스크립트의 import 경로, 정확한 sudo 허용 인수, 해당 동작이 import에 도달하는지 확인합니다. 열거 중에는 파일과 권한을 검사하되 스크립트를 import하거나 실행하지 않습니다.<sup>[[2]](#references)[[3]](#references)</sup>

`python3 /absolute/script.py`에 대한 정확한 sudo 규칙은 스크립트를 읽을 수 있기만 하면 됩니다. 파일에 실행 권한이나 shebang이 필요하지 않습니다. 로컬 모듈이 **누락된** 경우도 검토합니다. 스크립트가 import하는 모듈의 파일명을 호출자가 쓸 수 있는 스크립트 디렉터리에 만들 수 있다면 Python은 해당 파일을 RunAs ID로 불러올 수 있습니다. 유효한 sudo 규칙, 인터프리터의 실제 [모듈 검색 경로](https://docs.python.org/3/library/sys_path_init.html), 해당 모듈이 built-in 또는 frozen인지, import에 도달하는지를 확인합니다. 스크립트에 대한 직접 sudo 규칙은 실행 비트와 shebang 요구사항이 다릅니다. `sudo -u account` 뒤에 호출자 제공 토큰을 추가하는 별도 wrapper도 인수 흐름 검토가 필요합니다. 추가 `-u`가 의미 있으려면 호출되는 sudo 정책이 결과 ID를 허용해야 합니다. 정적 문자열만으로 어느 경로도 입증되지 않습니다.

### 호출자 제어 설정으로 sudo 실행되는 Apache

sudo 규칙이 호출자 제어 `-f` 설정 파일을 지정하는 권한 있는 `apachectl`, `apache2ctl`, `httpd` 실행을 허용한다면 해당 파일과 상위 디렉터리 권한을 검토합니다. Apache의 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) 지시어는 모듈 이름 뒤에 **모듈 파일명**을 받으며, [`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile)도 파일을 불러옵니다. [`Include`와 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include)은 설정을 추가하거나 오류를 통해 파일 내용을 노출할 수 있습니다. 사용자 지정 wrapper가 경로를 검증하거나 권한을 낮추거나 인수를 제한할 수 있으므로, 쓰기 가능한 설정만으로는 코드 실행이 입증되지 않으며 검토 후보일 뿐입니다. 결론을 내리기 전에 경로 정규화, symlink, 지시어 parsing을 확인합니다.

### 호출자 제어 설정으로 sudo 실행되는 nginx

root 실행 가능하고 제한 없는 `nginx` 규칙은 [`-c`로 다른 설정을 선택하도록 허용할 수 있습니다](https://nginx.org/en/docs/switches.html). 정확한 sudo 인수와 제외 규칙, 호출자가 설정을 제공할 수 있는지, 결과 master 또는 worker가 보호된 경로에 계속 접근할 수 있는지 검토합니다. 선택한 `root`와 `autoindex`로 새 listener를 통해 파일을 노출할 수 있습니다. [`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html)은 권한 있는 파일 쓰기 경로를 제공할 수 있지만, DAV 모듈은 기본 빌드에 포함되지 않으므로 해당 모듈의 존재, listener 접근 가능성, 파일 권한, 임시 파일 동작을 확인해야 합니다. [`error_log` 지시어](https://nginx.org/en/docs/ngx_core_module.html#error_log)도 선택한 파일을 대상으로 지정할 수 있습니다. `/etc/ld.so.preload` 같은 민감한 설정 파일에 로그를 쓰는 경로가 권한 상승으로 이어지려면 권한 있는 writer와 제어 가능한 로그 레코드가 있어야 합니다. `sudo -l`에서 실행 파일이 강조되었다고 해서 이런 경로가 작동한다는 증거는 아닙니다. 수동 열거 중에는 nginx를 시작하거나 재설정하지 않습니다.

### 권한 있는 Bash prompt의 패턴 비교

sudo에서 허용된 Bash 스크립트가 호출자에게 값을 입력받고 `[[ "$expected" == $entered ]]`로 비교하면, Bash는 인용되지 않은 오른쪽 피연산자를 pattern으로 해석합니다. 따라서 wildcard로 예상 값을 몰라도 비교를 통과할 수 있습니다. 피연산자를 인용하면(`[[ "$expected" == "$entered" ]]`) 리터럴 문자열 비교가 됩니다. 해당 문법만으로 악용 경로가 입증되지는 않으므로 정확한 sudo 규칙, prompt 도달 여부, 비교 이후 스크립트가 수행하는 작업을 검토합니다. 열거 중에는 예상 값을 출력하지 않습니다. [Bash 조건식 구성 참조](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)를 참조하세요.

### 파일을 다운로드해 실행하는 sudo 허용 helper

호출자 선택 URL을 받아 응답을 디스크에 쓰고 나중에 인터프리터나 셸로 해당 파일을 실행하는 사용자 지정 helper에 root 실행 가능하고 제한 없는 sudo 권한이 있다면 데이터 흐름을 검토합니다. [sudoers에서 명령 항목에 인수를 지정하지 않으면 임의의 인수를 허용합니다](https://man7.org/linux/man-pages/man5/sudoers.5.html). 실행 파일 경로가 고정되어 있어도 인수로 선택할 수 있는 항목까지 제한되지는 않습니다. 설치된 helper에서 실제 URL 검증, 출력 경로, 성공 분기, 후속 실행을 확인합니다. 일치하는 libcurl import나 출력 가능한 문자열만으로는 이 경로가 입증되지 않습니다.

helper가 **호출자 제어 작업 디렉터리에서 상대 경로**를 사용한다면 고정된 출력 파일명도 쓰기와 실행 사이에 대체될 수 있습니다. root 소유 파일의 이름을 바꾸거나 대체할 수 있는지는 파일 모드만이 아니라 디렉터리 쓰기/검색 권한과 sticky bit 제한에 따라 달라집니다. [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)를 참조하세요. helper가 이미 열린 descriptor를 쓰는지, 나중에 경로를 다시 여는지, 쓰기 전에 신뢰된 디렉터리로 이동하는지 확인합니다. 수동으로 sudo 정책, helper, 디렉터리 메타데이터를 검사하되 열거 중에는 권한이 부여된 다운로드를 실행하거나 race를 시도하지 않습니다.

root sudo 다운로드 helper가 `curl <caller input> -o <fixed output>` 같은 Bash 명령 문자열을 만들면 **인수** injection이 발생할 수도 있습니다. 공백을 거부하는 필터로도 [Bash brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)은 막을 수 없습니다. 인용되지 않은 쉼표 구분 요소가 별도 curl 인수가 될 수 있습니다. 입력이 고정된 `-o`보다 앞에서 curl에 전달된다면 호출자가 지정한 출력 옵션으로 첫 번째 URL의 대상 경로를 helper ID로 선택할 수 있습니다. [curl은 URL 순서에 따라 출력 옵션을 적용합니다](https://curl.se/docs/manpage.html#-o). 정확한 셸, 인용 방식, 입력 검증, 유효한 sudo 규칙, curl 인수 순서와 지원 URL scheme, 호출자가 가져오는 바이트를 제어하거나 결과를 읽을 수 있는지 확인합니다. PyInstaller로 패키징한 실행 파일에 Python 애플리케이션 로직이 들어 있을 수 있지만, 패키징 표시나 `curl` 문자열만으로 데이터 흐름이 입증되지는 않습니다. 권한이 있는 경우 범위가 제한된 오프라인 사본을 검토합니다. 일반적인 열거에서는 helper를 실행하거나 공격자가 선택한 데이터를 가져오지 않습니다.

`mktemp -u` / `--dry-run`을 호출하는 root sudo 셸 스크립트는 사용되지 않은 이름만 선택하며 파일을 만들지는 **않습니다**. 스크립트가 나중에 다른 사용자가 영향을 줄 수 있는 디렉터리에서 해당 이름으로 파일을 만든 다음 다시 열어 내용을 root의 `authorized_keys` 같은 보호된 대상에 추가한다면 임시 파일 race 가능성을 검토합니다. 정확한 sudo 규칙, 디렉터리와 파일 소유권, 생성 및 재열기 순서, 커널 보호, 권한 있는 쓰기가 실제로 공격자 제어 바이트를 사용하는지 확인합니다. `mktemp -u` 문자열이나 쓰기 가능한 `/tmp`만으로 race가 입증되지는 않습니다. 열거 중에는 스크립트와 경로 메타데이터를 검사하되 이를 실행하거나 임시 파일 race를 시도하지 않습니다. [GNU `mktemp` 문서](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)를 참조하세요.

## 방어 참고 사항

- sudo로 인터프리터나 대화형 편집기를 허용하지 않습니다.<sup>[[1]](#references)</sup>
- 범위가 좁은 단일 관리 작업만 수행하는, 고정된 root 소유 wrapper를 우선합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 인터프리터가 불가피하다면 정확한 스크립트 경로를 제한하고 사용자 제어 인수, 쓰기 가능한 import, `PYTHONPATH`, 안전하지 않은 환경 보존을 차단합니다.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 파일 편집이 필요하다면 정확한 파일 경로를 제한하고, 패치된 sudo 버전과 엄격한 환경 처리를 적용한 `sudoedit` 사용을 고려합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, 쓰기 가능한 작업 디렉터리, 쓰기 가능한 모듈/import 경로, `NOEXEC`, `use_pty`, 로깅을 검토하되 이를 완전한 sandbox로 간주하지 않습니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python documentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — how to execute the Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl documentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby documentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js documentation](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js documentation](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 security releases](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile extraction filters — Python documentation](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart configuration option and evaluation — upstream source](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart command behavior — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter manual page](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter manual page](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [Simple Command Expansion — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge compiler options — Foundry documentation](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry documentation](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch manual pages](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) install scripts — Arch manual pages](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
{{#include ../../banners/hacktricks-training.md}}
