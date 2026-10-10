# Cron 작업 및 Systemd 타이머

{{#include ../../banners/hacktricks-training.md}}

예약된 작업은 현재 셸과 다른 사용자 ID 및 환경으로 실행될 수 있습니다. cron, `at`, anacron, systemd 타이머를 열거한 다음, 각 예약 명령이 사용하는 스크립트, import, 작업 디렉터리 및 쓰기 가능한 입력을 추적하세요.

## 예약 작업 열거

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

System crontab에는 보통 사용자 필드가 포함되지만, 사용자의 crontab에는 없습니다. 실제 스케줄러의 유효한 PATH와 환경 변수를 확인하세요. `run-parts --test /etc/cron.daily`를 실행하면 해당 호스트에서 선택될 파일 이름을 확인할 수 있습니다. 제어 문자는 일반적인 출력에서 항목을 숨길 수 있으므로, 스케줄이 의심스러우면 `cat -A` 또는 `sed -n l`을 사용하세요.

## 권한이 상승된 파일 및 명령 확인하기

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

예약된 스크립트 체인, `EnvironmentFile=` 경로, drop-in, 심볼릭 링크, 상대 경로 명령, 와일드카드 확장, 권한이 높은 작업이 복사하거나 실행하는 바이너리를 검토합니다. 타이머는 `Unit=` 설정을 통해 이름이 다른 서비스를 활성화할 수 있습니다. 주요 기본 요소는 [PATH](../linux-basics/linux-environment-variables.md#path), [wildcard](../interesting-files-permissions/wildcards-spare-tricks.md), [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 페이지를 참고하세요.

root 권한으로 실행되는 예약된 `chkrootkit` 스크립트의 경우, 설치된 소스에서 오래된 [slapper-loop quoting defect (CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)를 확인합니다. `SLAPPER_FILES` 임시 경로를 검사한 뒤 실행되는 따옴표 없는 `file_port=$file_port $i`는 해당 파일을 실행할 수 있습니다. 실제 스크립트 또는 벤더 패치, root 예약 실행 여부, 하위 사용자에게 정확한 임시 경로에 대한 쓰기 권한이 있는지, 파일이 실행 가능한지, 마운트 정책을 확인합니다. 버전 문자열이나 `chkrootkit`의 존재만으로 해당 경로가 성립한다고 단정할 수는 없습니다. 수동 검토 중에는 임시 파일을 만들거나 실행하지 마세요.

타이머의 root 서비스가 `systemctl restart <other>.service`를 실행한다면, 서비스가 하나 더 이어지는 경로를 추적합니다. 재시작된 유닛이 하위 권한 사용자가 쓸 수 있는 스크립트로 셸을 실행할 수 있습니다. 유효한 `User=`, `DynamicUser=`, `RootDirectory=`/`RootImage=`, 정확한 `ExecStart=` 인수, 스크립트와 상위 경로의 권한을 확인합니다. 쓰기 가능한 스크립트는 해당 실행 컨텍스트에서 타이머와 재시작된 서비스가 활성화되어 있을 때만 실행 후보가 됩니다. 두 서비스 모두 재시작하지 말고 유닛 속성을 확인하세요.

권한이 높은 작업이 호스트 이름으로 스크립트를 가져와 응답을 셸에 전달한다면, 원격 스크립트뿐 아니라 해당 호스트 이름의 해석을 누가 제어하는지도 확인합니다. 그룹이나 ACL을 통한 접근 권한을 포함해 쓰기 가능한 `/etc/hosts` 파일은 작업이 로컬에서 해석하는 이름을 다른 곳으로 연결할 수 있습니다. `curl` 응답이 사용자 간 실행 경로가 되려면 실제 예약 명령이 해당 응답을 실행하고, 작업이 영향을 받는 리졸버 경로를 사용해야 합니다. 작업의 실행 사용자, 정확한 URL과 셸 파이프라인, 유효한 프록시/DNS 동작, 파일 및 상위 디렉터리 권한을 확인합니다. 쓰기 가능한 hosts 파일 자체는 검토 단서일 뿐, 권한이 높은 소비자가 있다는 증거는 아닙니다. 열거 중에는 매핑을 변경하거나 스크립트를 가져오지 말고 예약 설정과 메타데이터만 확인하세요.

권한이 높은 예약 `wget` 가져오기는 다운로드한 본문을 직접 실행하지 않더라도 별도의 파일 쓰기 경계입니다. [GNU Wget 1.18 changed the default HTTP-to-FTP redirect filename handling to fix CVE-2016-4971](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html). 영향을 받는 구버전 빌드는 리디렉션된 FTP 파일 이름을 사용할 수 있었고, `--trust-server-names`는 해당 동작을 명시적으로 요청합니다. 신뢰도가 낮은 사용자가 HTTP 응답과 FTP 리소스를 제어할 수 있다면, 작업이 해당 리디렉션을 따르는지, 실제 Wget 빌드 또는 벤더 백포트, 출력 옵션, 실행 사용자, 작업 디렉터리, 대상 파일 이름이 시작 파일이 될 수 있는지를 확인합니다. [Wget loads `WGETRC` or `$HOME/.wgetrc`](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html), 그리고 [its settings can select a POST source or output path](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html). 이후의 권한이 높은 가져오기는 그 결과로 정보 노출이나 쓰기가 발생하기 위한 별도의 전제 조건입니다. `authbind`를 통한 낮은 포트 접근은 호출자가 작업이 요청하는 URL을 실제로 제공할 수 있을 때만 관련이 있습니다. 리디렉션을 제공하거나 작업을 실행하지 말고 설정과 로그를 수동으로 검토하세요. [Raw block-device access through the `disk` group](../user-information/interesting-groups-linux-pe/README.md#disk-group)는 이 네트워크 가져오기 경로와 별개입니다.

스크립트뿐 아니라 데이터 파일도 추적합니다. 예약된 시뮬레이션 또는 오케스트레이션 도구가 시작할 프로세스를 정의하는 YAML 파일을 읽을 수 있습니다. 하위 권한 사용자가 해당 파일을 수정할 수 있고 작업이 다른 계정으로 실행된다면, 데이터가 작업의 권한으로 실행되는 명령이 될 수 있습니다. 쓰기 가능한 YAML 파일을 실행 경로로 판단하기 전에 정확한 예약 명령, 유효 사용자, 파일 경로, 파서 의미, 쓰기 권한(상위 디렉터리 포함)을 확인합니다. 수동 선별에는 예약 설정과 파일 메타데이터만 읽으면 충분합니다. 열거 중에는 작업을 실행하거나 입력을 수정하지 마세요.

권한이 높은 작업이 하위 권한 사용자가 교체할 수 있는 파일을 대상으로 `ssh -F`를 실행하면 SSH 클라이언트 설정도 실행 가능한 입력입니다. OpenSSH의 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand)는 클라이언트 셸을 통해 로컬 명령을 실행하고, `Host`/`Match` 및 앞서 지정된 옵션에 따라 해당 지시문이 적용되는지가 결정됩니다. 이를 사용자 간 실행 경로로 판단하기 전에 정확한 예약 SSH 호출, 실행 사용자, 선택된 설정 경로, 디렉터리와 파일의 쓰기 권한, 유효 옵션 순서를 대조합니다. 권한이 높은 계정으로 작업을 실행하거나 신뢰할 수 없는 설정을 불러오지 말고 기록을 검토하세요.

예약된 `scp` 이후 복사한 스크립트를 실행하는 `ssh`가 있다면, 하위 권한 사용자가 대상 SSH 서비스를 제어할 수 있는 경우 두 번째 신뢰 경계도 검토해야 합니다. 서비스가 연결을 다른 호스트로 전달할 수 있다면 권한이 높은 클라이언트가 의도하지 않은 대상에 인증할 수 있습니다. [`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking)는 변경된 호스트 키에 대한 보호를 약화하지만, OpenSSH의 나머지 제한과 실제 호스트별 옵션이 적용됩니다. 작업의 실행 사용자, 실제 대상과 인증 방식, 원격 명령의 유효 사용자, 리디렉션된 호스트에서 같은 대상 경로가 쓰기 가능하거나 이미 존재하는지를 확인합니다. 이전 파일 또는 공격자가 제어하는 파일을 실행하려면 복사가 실패하거나 해당 경로를 놓치는 **동시에** 래퍼가 SSH 명령까지 계속 실행해야 합니다. [Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 및 명시적 상태 처리가 이 흐름에 영향을 줍니다. 약한 호스트 키 설정, 눈에 보이는 `sshpass` 프로세스, 쓰기 가능한 임시 디렉터리만으로는 이 체인이 성립하지 않습니다. 열거 중에는 서비스를 리디렉션하거나 작업을 실행하지 말고 예약 설정, 스크립트, SSH 구성, 파일 메타데이터를 확인하세요.

권한이 높은 애플리케이션 스케줄러는 쓰기 가능한 파일 대신 데이터베이스 행에서 작업을 가져올 수 있습니다. 예를 들어 root cron 항목이 Laravel의 [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler)을 호출하면, 작업 행을 읽는 애플리케이션 코드가 실행될 수 있습니다. 하위 권한 계정이 로컬 경로가 담긴 행을 쓸 수 있고 예약된 콜백이 root 권한으로 PHP의 [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php)를 호출한 뒤 반환된 본문을 해당 행에서 지정한 웹훅으로 보낸다면, 이는 권한이 높은 파일 정보 노출 경로입니다. cron 실행 사용자, 실제 스케줄러 콜백과 행에서 경로로 이어지는 데이터 흐름, 데이터베이스 쓰기 권한, 행을 읽은 뒤의 유효성 검사, 외부 전송 대상지를 확인합니다. 읽을 수 있는 애플리케이션 `.env`는 자격 증명 관련 단서일 뿐입니다. 웹 폼 유효성 검사나 데이터베이스 암호만으로는 행 제어 또는 정보 노출이 입증되지 않습니다. 열거 중에는 데이터베이스를 조회하거나 작업을 예약하지 말고 예약 설정, 코드, 자격 증명 파일 권한을 수동으로 검토하세요.

이벤트 기반 `incron` 작업도 같은 방식으로 검토해야 합니다. [incrontab entries](https://manpages.debian.org/testing/incron/incrontab.5.en.html)는 감시 경로 및 이벤트를 테이블 소유자 권한으로 실행되는 명령과 연결합니다. 애플리케이션이 쓰기 가능한 디렉터리의 링크를 따라가 감시 대상에 공격자가 제어하는 텍스트를 쓰면, 하위 권한 사용자가 감시 파일에 간접적으로 영향을 줄 수 있습니다. 실제 테이블 소유자, 이벤트, 대상 및 상위 경로 권한, 애플리케이션의 링크 추적 동작, 해당 텍스트가 명령 인수로 전달되는 방식을 확인합니다. 특히 [GNU Mailutils `mail` accepts `--exec`](https://mailutils.org/manual/html_node/Invoking-Mail.html)이며, 해당 [shell-escape command](https://mailutils.org/manual/html_node/Shell-Escapes.html)는 프로그램을 실행할 수 있습니다. 이 구현에 신뢰할 수 없는 필드가 별도 옵션으로 전달되면 명령 실행으로 이어질 수 있습니다. 다른 `mail` 구현이나 따옴표로 감싸진 고정 인수 경계는 다르게 동작할 수 있습니다. 열거 중에는 감시 파일을 수정하거나 작업을 트리거하지 말고 예약 설정, 애플리케이션 코드, 파일 메타데이터를 확인하세요.

감시 로그도 보조 스크립트를 통해 사용자 경계를 넘을 수 있습니다. 하위 권한 계정이 로그를 쓸 수 있고 `incron` 소유자가 로그에서 읽은 필드를 새 [`sh -c` command string](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)에 넣으면, 셸이 해당 필드를 소유자 권한으로 다시 파싱합니다. 정확히 감시하는 이벤트, 로그와 상위 경로의 권한, 보조 스크립트 경로, 로그 필드의 변환 과정, 결과 명령이 실제로 실행되는지를 확인합니다. 쓰기 가능한 로그와 `incron` 항목만으로는 데이터 흐름이 입증되지 않습니다. 수동 열거 중에는 트리거용 로그 행을 쓰거나 보조 스크립트를 실행하지 마세요.

인증서 갱신 작업도 같은 경계를 넘을 수 있습니다. 권한이 높은 보조 프로그램은 하위 권한 사용자가 쓸 수 있는 디렉터리의 인증서에서 X.509 주체를 읽고 common name을 새 `bash -c` 명령 문자열에 넣을 수 있습니다. [OpenSSL can display a certificate's subject and check its expiry](https://docs.openssl.org/3.3/man1/openssl-x509/). [Bash parses the `-c` string as shell input](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)하므로, 외부 스크립트에서 변수를 따옴표로 감싸더라도 두 번째 파싱은 보호되지 않습니다. 명령 삽입이라고 판단하기 전에 예약 실행 사용자, 정확한 입력 경로와 쓰기 권한, 갱신 분기, `bash -c`까지의 데이터 흐름을 확인합니다. 열거 중에는 갱신을 트리거하지 말고 스크립트와 인증서 메타데이터를 수동으로 확인하세요.

같은 두 번째 파싱은 권한이 높은 예약 작업이 하위 권한 사용자의 아카이브 또는 패키지에서 이름을 추출해 `xargs -I`로 `sh -c` 명령 문자열에 삽입할 때도 발생할 수 있습니다. [GNU `xargs -I` replaces the placeholder in initial arguments](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html), 그리고 [`sh -c` interprets its command string](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html). 외부 스크립트에서 추출된 이름을 따옴표로 감싸더라도, 이후 대체되는 셸 프로그램이 안전해지는 것은 아닙니다. 작업의 실행 사용자, 정확한 입력 경로와 쓰기 권한, 아카이브 검증 및 분기 조건, 이름에서 셸로 이어지는 데이터 흐름을 확인합니다. 업로드 디렉터리가 쓰기 가능하거나 `xargs`가 호출된다는 사실만으로는 단서일 뿐입니다. 열거 중에는 패키지를 제출하거나 작업을 실행하지 말고 예약 설정, 스크립트, 경로 메타데이터를 확인하세요.

예약된 폰트 또는 이미지 가져오기 작업은 업로드 파일의 외부 이름이 제한되어 있더라도 호출자가 제공한 아카이브 내부의 이름을 신뢰할 수 있습니다. FontForge는 [upstream change for CVE-2024-25081 and CVE-2024-25082](https://github.com/fontforge/fontforge/pull/5367)에서 아카이브 멤버 이름을 통한 명령 삽입을 수정했습니다. 권한이 높은 작업이 하위 권한 사용자가 쓸 수 있는 경로의 아카이브를 실제로 여는지, 실행 사용자, 정확한 FontForge 빌드 또는 벤더 백포트, 아카이브 처리 코드 경로를 확인합니다. 버전 문자열이나 허용된 업로드 확장자만으로는 실행이 입증되지 않습니다. 열거 중에는 신뢰할 수 없는 아카이브를 가져오지 말고 예약 설정, 경로 권한, 빌드 메타데이터를 확인하세요.

예약된 네트워크 스캐너가 원격 TLS 인증서의 subject를 로컬 파일 이름으로 처리하면 다른 경계를 넘을 수 있습니다. [Nmap NSE runs selected scripts without a sandbox](https://nmap.org/book/nse-usage.html). 실제 스크립트를 확인하고, 신뢰할 수 없는 subject 필드를 containment 검사 없이 데이터 디렉터리에 결합하는지 살펴봅니다. 파일 정보 노출이 성립하려면 스케줄러가 스캔할 대상, 스캐너의 실행 사용자가 읽을 수 있는 파일로 해석되는 경로, 하위 권한 사용자가 읽을 수 있는 보고서나 로그가 모두 필요합니다. 인증서 필드나 스캐너가 설치되어 있다는 사실만으로는 이 체인이 입증되지 않습니다. 수동 열거 중에는 새 대상을 스캔하지 말고 예약 설정, 스크립트, 경로 해석, 보고서 대상을 검토하세요.

`/path/to/tasks/*.yml` 같은 셸 glob을 Ansible 실행기에 전달하는 권한이 높은 cron 명령은, 기존 playbook이 모두 읽기 전용이더라도 디렉터리 권한을 확인해야 합니다. glob 대상 디렉터리에 쓰기 및 탐색 권한이 있는 사용자는 일치하는 playbook을 추가할 수 있습니다. [Ansible playbooks define tasks that the runner executes](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html). 그러나 사용자 정의 래퍼가 경로를 필터링하거나 다른 사용자로 실행할 수 있으므로 디렉터리를 실행 경로로 판단하기 전에 래퍼 동작, 실제 cron 사용자, 셸 확장, ACL, sticky bit, 마운트 정책을 확인합니다. 메타데이터와 래퍼를 정적으로 검토하고 열거 중에는 예약 작업을 실행하지 마세요.

권한이 높은 cron 래퍼는 glob을 확장한 뒤 업로드 디렉터리의 파일 이름을 Perl 보조 프로그램에 전달할 수 있습니다. Perl의 [`<>` diamond operator uses two-argument `open`](https://perldoc.perl.org/perlop#The-Null-Filehandle)이므로, 파이프 명령으로 해석되는 이름이 일치하면 보조 프로그램의 권한으로 실행될 수 있습니다. [`<<>>` treats arguments as literal filenames](https://perldoc.perl.org/perlop#The-Null-Filehandle). 스케줄러 사용자, 래퍼의 작업 디렉터리와 glob, 보조 프로그램의 실제 `@ARGV` 처리 방식, 파일 이름 제한, 하위 권한 사용자가 파일 시스템 권한 또는 인증된 업로드 서비스를 통해 일치하는 이름을 만들 수 있는지를 확인합니다. cron 항목, Perl 스크립트, 쓰기 가능한 FTP 디렉터리만으로는 전체 체인이 입증되지 않습니다. 열거 중에는 조작된 파일 이름을 제출하거나 작업을 실행하지 말고 소스와 메타데이터를 확인하세요.

예약 계정이 경로명으로 실행하는 스크립트는 읽기 전용이어도, 하위 권한 사용자가 non-sticky 상위 디렉터리에 쓰기 및 탐색 권한을 가지면 교체될 수 있습니다. 스케줄의 실행 사용자, 모든 경로 구성 요소, 디렉터리 sticky bit, ACL 및 마운트 정책을 확인합니다. 파일을 이동하거나 작업을 실행하지 말고 메타데이터를 검토하세요.

권한이 높은 PHP cron 래퍼는 아직 존재하지 않는 보조 프로그램에 연결될 수도 있습니다. PHP [`exec()`](https://www.php.net/manual/en/function.exec.php)으로 고정된 절대 경로의 보조 프로그램을 호출한다면, 하위 권한 사용자는 상위 디렉터리에 해당 이름을 만들 수 있을 때 이후 실행을 제어할 수 있습니다. cron 항목이 래퍼를 실제로 더 높은 권한으로 실행하는지, 정확한 명령 문자열과 PHP 실행 정책, 보조 프로그램 디렉터리의 쓰기 및 탐색 권한, 심볼릭 링크와 sticky bit 동작, 해당 경로에 보조 프로그램이 아직 없는지를 확인합니다. 쓰기 가능한 디렉터리나 누락된 보조 프로그램만으로는 단서일 뿐입니다. 열거 중에는 보조 프로그램을 만들거나 작업을 트리거하지 말고 예약 설정, 소스, 경로 메타데이터를 확인하세요.

예약 작업은 `find`로 입력 스크립트를 찾은 뒤 인터프리터에 전달할 수도 있습니다. 예를 들어 [gnuplot's `system()` function invokes a shell](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf)이므로, 하위 권한 사용자가 쓸 수 있는 디렉터리의 모든 `*.plt` 파일에 `gnuplot`을 실행하는 권한 높은 작업은 작업의 권한으로 명령을 실행할 수 있습니다. [Directory read permission controls listing, while write and search (`x`) control creating and accessing known names](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html). `ls`로 디렉터리 목록을 볼 수 없더라도 쓰기 및 탐색 권한을 확인합니다. 권한 상승이 성립한다고 보기 전에 정확한 스케줄러 사용자와 명령, 인터프리터 동작, 선택되는 파일 패턴, 디렉터리 권한을 대조합니다. 디렉터리가 쓰기 가능하거나 인터프리터가 설치되어 있다는 사실만으로는 충분하지 않습니다. 비공개 예약 작업과 짧게 실행되는 작업은 프로세스 스냅샷 한 번으로 놓칠 수 있으므로, 권한이 있는 경우 이벤트 관찰이 필요할 수 있습니다.

권한이 높은 PHP 작업에서는 실행 가능한 스크립트 체인의 일부로 리터럴 `include`/`require` 문도 확인합니다. [PHP evaluates included files](https://www.php.net/manual/en/function.include.php)이므로, 그룹 쓰기가 가능한 포함 `.php` 파일은 주 스크립트가 읽기 전용이어도 작업의 권한으로 코드를 실행할 수 있습니다. 예약 실행 사용자, 유효한 include 경로 해석, 파일 및 디렉터리 권한, 작업이 실제로 실행되는지를 확인합니다. 주석에 있는 cron 예시는 단서일 뿐입니다. `-S` 및 `-t <document-root>`로 시작한 root 소유 [PHP built-in server](https://www.php.net/commandline.webserver)에도 같은 검토가 적용됩니다. loopback 리스너도 로컬 요청에 대해 애플리케이션 PHP를 실행할 수 있습니다. 열거 중에는 트리거를 실행하지 말고 프로세스와 소스를 확인하세요.

권한이 높은 PHP 작업은 **데이터 파일**을 통해서도 경계를 넘을 수 있습니다. 하위 권한 사용자가 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php)에 전달되는 정확한 파일을 변경할 수 있다면, PHP는 객체를 복원하는 동안 로드된 클래스의 `__wakeup()` 또는 `__unserialize()` 메서드를 호출할 수 있습니다. 작업의 유효 권한, 파일 및 상위 경로 권한, 로드된 클래스, 속성에 따라 파일을 쓰는 등의 실제 메서드 부작용을 검토합니다. 쓰기 가능한 로그나 `unserialize()` 호출만으로 사용 가능한 경로가 입증되지는 않습니다. 열거 중에는 직렬화 입력을 쓰거나 작업을 실행하지 말고 소스와 메타데이터를 확인하세요.

root cron 작업은 웹 서버가 아니라 PHP 애플리케이션의 **CLI page runner**를 호출할 수 있습니다. runner가 선택하는 document root와 URI를 실제 PHP 진입점까지 추적합니다. 해당 진입점을 웹 서비스 계정이 쓸 수 있다면 runner와 cron 래퍼가 읽기 전용이어도 예약된 CLI 요청이 변경된 코드를 root 권한으로 실행할 수 있습니다. 스케줄러 사용자, 정확한 URI-파일 해석, 유효 파일 및 상위 경로 권한, 무결성 검사가 진입점 자체를 보호하는지 확인합니다. 열거 중에는 runner를 호출하거나 페이지를 변경하지 말고 소스와 메타데이터를 확인하세요.

예약 작업 또는 다른 사용자가 공유 작업 디렉터리에서 시작한 `ipython` 프로세스는 시작 파일 검토가 필요합니다. [IPython's security release notes](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699)에 따르면, CVE-2022-21699 수정 전 영향을 받는 빌드는 현재 디렉터리에서 프로필과 설정을 검색했으며 `profile_default/startup` 코드도 포함됩니다. 실제 설치된 빌드 또는 벤더 패치, 명령의 작업 디렉터리, 권한이 높은 프로세스 사용자, 하위 권한 사용자가 정확한 시작 경로에 쓰기 및 탐색할 수 있는지를 대조합니다. `ipython`이 설치되어 있거나 디렉터리가 쓰기 가능하거나 버전 문자열이 있다는 사실만으로 다른 사용자가 그곳의 파일을 불러온다고 입증되지는 않습니다. 열거 중에는 권한이 높은 인터프리터를 실행하지 말고 예약 설정과 경로 메타데이터를 확인하세요.

사용자 정의 native extension의 함수를 호출하는 권한이 높은 PHP 서버를 검토할 때는 확장 모듈을 살펴보기 전에 서비스의 PHP SAPI와 유효한 `php.ini` 및 스캔된 `.ini` 파일을 추적합니다. [PHP loads configured `extension` libraries at startup](https://www.php.net/manual/en/ini.core.php), 그리고 [CLI and web SAPIs can use different configuration files](https://www.php.net/manual/en/configuration.file.php). 따라서 접근 가능한 로그인 폼이나 로컬 리스너는 사용자가 제어하는 문자열을 서비스 권한으로 실행되는 컴파일 코드에 전달할 수 있습니다. 유닛의 `User=`, `ExecStart=`, 작업 디렉터리, 실제 확장 모듈 경로, 호출자가 제어하는 인수를 기록합니다. `.so` 파일이나 loopback 소켓만으로 메모리 손상 취약성이 입증되지는 않습니다. 수동 열거 중에는 프로브를 보내지 말고 사용자 정의 파서를 별도로 분석하세요.

권한이 높은 래퍼가 스크립트를 경로명으로 해시한 뒤 같은 경로를 다시 열어 실행한다면, digest는 첫 번째 열기에서 읽은 객체만 인증합니다. 하위 권한 사용자가 두 번의 열기 사이에 스크립트의 디렉터리 항목을 교체할 수 있다면 원본 스크립트 파일이 root 소유여도 이후 실행에서 다른 객체가 해석될 수 있습니다. FIFO는 검사 단계를 늘릴 수 있지만, 이 경로는 교체 가능한 상위 디렉터리 권한, 실제로 별도로 수행되는 파일 열기, 스케줄러 사용자, sticky bit 및 마운트 규칙, 타이밍에 달려 있습니다. 래퍼와 `namei -l` 출력을 수동 검토 단서로 확인하세요. 체크섬이 일치했다는 사실만으로 이후 경로명이 보호된다고 볼 수 없습니다.

권한이 높은 백업 작업은 공격자가 제공한 명령을 실행하지 않고도 데이터를 **노출**할 수 있습니다. 하위 권한 사용자가 작업이 읽는 제어 파일을 만들 수 있는지, 작업이 그 뒤 `/etc/shadow` 같은 보호된 원본을 여는지, 공격자가 선택한 URL 또는 읽을 수 있는 출력에 결과를 전달하는지 추적합니다. 정보 노출 경로라고 판단하기 전에 세 부분을 모두 확인합니다. 같은 스크립트에 고정 셸 명령이 있다는 사실만으로 해당 제어 파일이 셸 삽입 입력이 되지는 않습니다. 열거 중에는 작업을 실행하거나 제어 파일을 심지 말고 스크립트와 파일 권한을 확인하세요.

권한이 높은 예약 작업이 `curl -K FILE` 또는 `curl --config FILE`을 실행한다면, [curl treats options in that file as command-line arguments](https://curl.se/docs/manpage.html). curl이 해당 파일을 읽는 시점에 하위 권한 사용자가 정확한 파일을 제어할 수 있으면 요청 URL, 로컬 파일 입력, 출력 경로에 영향을 줄 수 있습니다. 보호된 파일 읽기 또는 쓰기를 주장하기 전에 작업의 유효 권한, 파일과 상위 경로의 쓰기 권한, 다른 작업이 파일을 교체하는 시점, 설정 옵션이 고정 명령줄 옵션과 상호작용하는 방식을 확인합니다. 쓰기 가능한 설정 경로나 눈에 보이는 `-K` 플래그만으로는 선택된 옵션이 적용된다고 입증되지 않습니다. 열거 중에는 작업을 실행하거나 URL을 가져오지 말고 예약 설정과 메타데이터를 확인하세요.

cron 항목이 보조 스크립트를 호출한다면 보조 스크립트의 작업 디렉터리와 아카이브 명령도 확인합니다. 다른 사용자가 쓸 수 있는 디렉터리에서 따옴표 없는 와일드카드를 사용하면 파일 이름이 아카이버 옵션으로 처리될 수 있습니다. GNU tar의 checkpoint 동작이 한 예입니다. 사용자 간 명령 실행 경로라고 판단하기 전에 예약 실행 사용자, 쓰기 가능한 입력 디렉터리, 정확한 아카이버와 옵션, 옵션 파싱을 끝내는 `--` 사용 여부를 확인합니다. [wildcard and tar behavior](../interesting-files-permissions/wildcards-spare-tricks.md)를 참고하세요.

권한이 높은 보조 프로그램이 `cd INPUT_DIR; tar ... *`를 실행하면서 `cd` 성공 여부를 확인하지 않으면 별도의 백업 파일 노출이 발생할 수 있습니다. 하위 권한 사용자가 `INPUT_DIR`을 제거하거나 교체할 수 있으면 `cd` 실패 후 셸이 이전 디렉터리에 남아, 이후 아카이브 명령이 그 디렉터리를 읽을 수 있습니다. 작업의 초기 작업 디렉터리, 실제 `cd` 실패 경로, 스크립트가 종료되는지 또는 `&&`를 사용하는지, 정확한 아카이버 옵션, 하위 사용자가 출력 아카이브를 읽을 수 있는지를 확인합니다. 쓰기 가능한 입력 디렉터리나 읽을 수 있는 아카이브만으로는 단서일 뿐입니다. 실행 중인 작업을 변경하지 말고 보조 프로그램과 경로 권한을 확인하세요.

예약된 실행 파일이 신뢰 경계를 없애는 대신 셸 스크립트를 숨길 수도 있습니다. [SHc](https://github.com/neurobin/shc)는 암호화된 스크립트 텍스트를 native binary에 넣고 런타임에 셸을 통해 실행합니다. `.sh.x` 확장자나 식별하기 어려운 ELF는 검토 단서일 뿐입니다. 파일 이름 옵션 삽입 가능성을 평가하려면 권한이 높은 스케줄러 사용자, 보조 프로그램의 실제 작업 디렉터리와 명령, 하위 권한 사용자가 그곳에 일치하는 이름을 만들 수 있는지, 따옴표 없는 glob이 옵션 경계 없이 `rsync` 같은 명령에 도달하는지를 확인합니다. [`rsync` remote-shell option](../interesting-files-permissions/wildcards-spare-tricks.md#rsync)은 해당 명령 경로가 실제로 사용될 때만 관련이 있습니다. `/proc` 접근 제한이나 정적 복호화 실패로 명령을 확인할 수 없다면, 분류를 위해 권한이 높은 보조 프로그램을 실행하지 마세요.

프로세스 명령줄 텍스트도 권한이 높은 보조 프로그램에 전달되는 신뢰할 수 없는 입력입니다. 하위 권한 사용자는 `pgrep -f`에 일치하는 프로세스 제목 또는 `argv[0]`을 선택할 수 있습니다. 이름이 일치한다고 실행 파일이나 소유자가 인증되는 것은 아닙니다. root 권한 스크립트가 해당 텍스트를 가져와 일부를 `apache2ctl`/`httpd`로 다시 작성하고 고정 인수 배열 없이 결과를 실행하면, 공격자가 선택한 옵션이 다른 설정 디렉터리나 오류 로그를 지정할 수 있습니다. Apache 설정 파싱은 모듈을 로드하거나 설정된 보조 프로그램을 호출할 수 있으므로, 열거 중에는 신뢰할 수 없는 설정을 root 권한으로 검증하지 마세요. 스케줄러 소유자, 정확한 보조 프로그램, 프로세스 사용자, 데이터에서 인수로 이어지는 흐름을 확인합니다. 셸 메타문자 실행이 별도로 입증되지 않는 한 이는 옵션/설정 삽입입니다.

권한이 높은 parser가 신뢰할 수 없는 텍스트를 Bash 산술식에 전달하면 해당 텍스트 안의 치환을 실행할 수 있습니다. [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)에 예제가 있습니다. 모든 산술식이 악용 가능하다고 판단하기 전에 입력 출처와 파싱 명령을 확인합니다.

애플리케이션 로그를 파싱하는 권한이 높은 작업에서는 첫 번째 파싱 이후의 신뢰할 수 없는 필드도 추적합니다. 하위 권한 계정은 현재 프로세스 그룹을 통해 로그에 쓸 수 있거나 기록되는 요청 필드에 영향을 줄 수 있습니다. 레코드가 이미지를 선택하고, 이미지 메타데이터가 XML을 여는 두 번째 경로명이 될 수 있습니다. 작업의 유효 권한, 실제 로그 쓰기 권한, 구분자 처리, 정규 경로 containment 검사, 선택된 XML을 공격자가 제어할 수 있는지를 확인합니다. 외부 엔터티 확장은 확장된 결과가 하위 권한 사용자가 읽을 수 있는 출력에 전달될 경우 두 번째 읽기를 통해 권한이 높은 파일을 노출할 수 있습니다. [Java XML processing security guide](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)는 외부 DTD/엔터티 접근 제어를 설명합니다. 설치된 parser와 유효 설정을 확인합니다. 쓰기 가능한 로그나 XML 파일만으로는 단서일 뿐입니다. 열거 중에는 예약 parser에 입력을 제공하지 말고 코드와 메타데이터를 검토하세요.

다른 사용자의 Git 저장소에서 파일을 생성하는 권한이 높은 작업도 확인합니다. 스크립트가 `git checkout` 대신 `git ls-tree`와 `git cat-file`을 사용하더라도, 공격자가 제어하는 tree 경로를 staging 디렉터리에 결합할 때 신뢰할 수 있습니다. 대상 경로를 정규화하고 쓰기 전에 containment를 검사하지 않으면 절대 경로와 `..` 구성 요소가 해당 디렉터리 바깥으로 벗어날 수 있습니다. `git -c safe.directory=*`는 소유자가 다른 저장소에 대한 접근을 허용하지만, 그 자체로 임의 파일 쓰기를 발생시키지는 않습니다.

root 권한으로 실행되는 데이터베이스 백업은 또 다른 소유권 경계를 만들 수 있습니다. PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html)은 원본 데이터 디렉터리에 놓인 추가 일반 파일도 복사하며, 기본 plain 형식은 `-D`에 디렉터리 트리 형태로 파일을 씁니다. 하위 권한 계정이 해당 원본 파일을 만들거나 수정할 수 있다면 결과 대상의 소유자와 모드, 경로를 탐색 및 실행할 수 있는지, 마운트에 `nosuid`가 적용되는지를 확인합니다. set-ID 권한이 유지된 root 소유 복사본은 위험할 수 있습니다. tar 전용 백업, 제거된 권한, 접근할 수 없는 대상 경로는 같은 경로를 성립시키지 않습니다. 백업 명령을 문제로 판단하기 전에 예약 래퍼와 유효 사용자를 추적합니다.

## Observe short-lived work

단일 프로세스 스냅샷으로는 몇 밀리초만 실행되는 작업을 놓칠 수 있습니다. 타이머/cron 선언을 로그와 비교하고, 권한이 있는 경우 `pspy` 또는 audit 같은 프로세스 이벤트 모니터링을 사용합니다. 예약 실행 사용자, 정확한 명령줄, 작업이 읽거나 쓰는 파일을 대조합니다. loopback 스케줄러 웹 UI는 별도의 인터페이스입니다. [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)를 참고하세요.
{{#include ../../banners/hacktricks-training.md}}
