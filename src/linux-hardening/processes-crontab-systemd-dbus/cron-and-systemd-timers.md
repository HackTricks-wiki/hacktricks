# Cron 작업 및 Systemd 타이머

{{#include ../../banners/hacktricks-training.md}}

예약된 작업은 현재 셸과 다른 사용자 ID 및 환경으로 실행될 수 있습니다. cron, `at`, anacron, systemd 타이머를 열거한 다음, 각 예약 명령이 참조하는 스크립트, import, 작업 디렉터리, 쓰기 가능한 입력을 추적하세요.

## 예약 작업 열거하기

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

System crontab에는 보통 사용자 필드가 있지만, 사용자의 crontab에는 없습니다. 실제 스케줄러의 유효한 PATH와 환경을 확인하세요. `run-parts --test /etc/cron.daily`는 해당 호스트에서 선택될 파일 이름을 보여줍니다. 제어 문자는 일반적인 출력에서 항목을 숨길 수 있으므로, 스케줄이 의심스러워 보이면 `cat -A` 또는 `sed -n l`을 사용하세요.

## 권한이 높은 파일 및 명령어의 탐색 과정 추적

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

예약된 root 실행 작업에서 실행되는 스크립트 체인, `EnvironmentFile=` 경로, drop-in, symlink, 상대 경로 명령, wildcard 확장, 그리고 privileged task가 복사하거나 실행하는 바이너리를 검토하세요. 타이머는 `Unit=` 설정을 통해 다른 이름의 service를 활성화할 수 있습니다. 주요 기본 요소는 [PATH](../linux-basics/linux-environment-variables.md#path), [wildcard](../interesting-files-permissions/wildcards-spare-tricks.md), [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 페이지에서 설명합니다.

예약된 root 실행 `chkrootkit` 스크립트의 경우, 설치된 소스에서 오래된 [slapper-loop quoting 결함(CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)을 확인하세요. `SLAPPER_FILES` 임시 경로를 검사한 뒤 실행되는 인용되지 않은 `file_port=$file_port $i`가 해당 파일을 실행할 수 있습니다. 실제 스크립트 또는 vendor patch, root 예약 실행 여부, 낮은 권한 사용자의 정확한 임시 경로 쓰기 권한, 실행 권한, mount 정책을 확인하세요. 버전 문자열이나 `chkrootkit`의 존재만으로는 해당 경로가 성립한다고 볼 수 없습니다. 수동 검토 중에는 임시 파일을 만들거나 실행하지 마세요.

타이머의 root service가 `systemctl restart <other>.service`를 실행한다면 unit을 한 단계 더 추적하세요. 재시작된 unit이 낮은 권한 사용자가 쓸 수 있는 스크립트로 shell을 실행할 수 있습니다. 유효한 `User=`, `DynamicUser=`, `RootDirectory=`/`RootImage=`, 정확한 `ExecStart=` 인수, 스크립트 및 상위 경로의 권한을 확인하세요. 쓰기 가능한 스크립트는 타이머와 재시작된 service가 해당 실행 컨텍스트에서 활성화되어 있어야만 후보가 됩니다. 어느 service도 재시작하지 말고 unit 속성을 확인하세요.

높은 권한의 작업이 hostname으로 스크립트를 가져와 응답을 shell에 전달한다면, 원격 스크립트뿐 아니라 해당 hostname의 이름 해석을 누가 제어하는지도 확인하세요. group 또는 ACL을 통해 접근 권한을 부여받은 경우를 포함해, 쓰기 가능한 `/etc/hosts` 파일은 작업이 로컬에서 해석하는 이름을 다른 곳으로 돌릴 수 있습니다. `curl` 응답이 cross-user 실행 경로가 되려면 실제 예약 명령이 그 응답을 실행하고, 작업이 영향을 받는 resolver 경로를 사용해야 합니다. 작업의 실행 사용자, 정확한 URL과 shell pipeline, 유효한 proxy/DNS 동작, 파일 및 상위 디렉터리 권한을 확인하세요. hosts 파일이 쓰기 가능하다는 사실만으로는 이를 사용하는 privileged consumer가 있다는 증거가 되지 않습니다. 열거 중에는 매핑을 바꾸거나 스크립트를 가져오지 말고 예약 정보와 metadata를 확인하세요.

Privileged `wget` 예약 실행은 다운로드된 내용이 직접 실행되지 않더라도 별도의 파일 쓰기 경계입니다. [GNU Wget 1.18은 CVE-2016-4971 수정을 위해 기본 HTTP-to-FTP redirect 파일명 처리를 변경했습니다](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html). 영향을 받는 이전 빌드는 redirect된 FTP 파일명을 사용할 수 있었으며, `--trust-server-names`는 해당 동작을 명시적으로 요청합니다. 낮은 신뢰도의 주체가 HTTP 응답과 FTP 리소스를 제어한다면 작업이 해당 redirect를 따르는지, 실제 Wget 빌드 또는 vendor backport, 출력 옵션, 실행 사용자, 작업 디렉터리, 대상 파일명이 startup 파일이 될 수 있는지 확인하세요. [Wget은 `WGETRC` 또는 `$HOME/.wgetrc`를 불러옵니다](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html). [해당 설정은 POST 소스나 출력 경로를 지정할 수 있습니다](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html). 이후의 privileged fetch는 그로 인한 정보 노출이나 쓰기에 필요한 별도 전제 조건입니다. `authbind`를 통한 낮은 포트 접근은 호출자가 작업에서 요청하는 URL을 실제로 제공할 수 있을 때만 관련이 있습니다. redirect를 제공하거나 작업을 실행하지 말고 설정과 로그를 수동으로 검토하세요. [`disk` group을 통한 raw block-device 접근](../user-information/interesting-groups-linux-pe/README.md#disk-group)은 이 네트워크 fetch 경로와 별개입니다.

스크립트뿐 아니라 데이터 파일도 추적하세요. 예약된 simulation 또는 orchestration 도구가 시작할 process를 정의하는 YAML 파일을 읽을 수 있습니다. 낮은 권한 사용자가 해당 파일을 수정할 수 있고 작업이 다른 계정으로 실행된다면, 데이터가 작업의 identity로 실행되는 명령이 될 수 있습니다. 쓰기 가능한 YAML 파일을 실행 경로로 판단하기 전에 정확한 예약 명령, 유효 사용자, 파일 경로, parser 의미, 상위 디렉터리를 포함한 쓰기 권한을 확인하세요. 수동 triage에는 예약 정보와 파일 metadata 확인만으로 충분합니다. 열거 중에는 작업을 실행하거나 입력을 수정하지 마세요.

높은 권한의 작업이 낮은 권한 사용자가 교체할 수 있는 파일을 대상으로 `ssh -F`를 실행한다면 SSH client 설정도 실행 가능한 입력입니다. OpenSSH의 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand)는 client shell을 통해 로컬 명령을 실행하며, `Host`/`Match`와 앞선 옵션에 따라 해당 지시어의 적용 여부가 달라집니다. 이를 cross-user 실행 경로로 판단하기 전에 정확한 예약 SSH 호출, 실행 사용자, 선택된 설정 경로, 디렉터리와 파일 쓰기 권한, 유효한 옵션 적용 순서를 대조하세요. 작업을 실행하거나 privileged 계정으로 신뢰할 수 없는 설정을 불러오지 말고 관련 기록을 검토하세요.

예약된 `scp` 뒤에 `ssh`로 복사된 스크립트를 실행하는 경우, 낮은 권한 사용자가 대상 SSH service를 제어한다면 두 번째 신뢰 경계도 검토해야 합니다. 해당 service가 연결을 다른 host로 전달할 수 있다면 privileged client가 의도하지 않은 endpoint에 인증할 수 있습니다. [`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking)는 host key 변경 보호를 약화하지만, OpenSSH의 나머지 제한과 유효한 host별 옵션은 여전히 적용됩니다. 작업의 실행 사용자, 실제 대상과 인증 방법, 원격 명령의 유효 identity, 리디렉션된 host에서 동일한 대상 경로를 쓸 수 있는지 또는 해당 경로에 파일이 이미 있는지 확인하세요. 이전 파일이나 공격자가 제어하는 파일을 실행하려면 복사가 실패하거나 해당 경로를 놓쳐야 **하며**, wrapper도 SSH 명령까지 계속 실행해야 합니다. [Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)와 명시적 상태 처리가 이 흐름에 영향을 줍니다. 취약한 host key 설정, 눈에 보이는 `sshpass` process, 쓰기 가능한 임시 디렉터리만으로는 이 체인이 성립하지 않습니다. 열거 중에는 service를 리디렉션하거나 작업을 실행하지 말고 예약 정보, 스크립트, SSH 설정, 파일 metadata를 확인하세요.

Privileged application scheduler는 쓰기 가능한 파일 대신 database row에서 작업을 가져올 수 있습니다. 예를 들어 root cron 항목이 Laravel의 [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler)을 실행하면 task row를 읽는 application 코드에 도달할 수 있습니다. 낮은 권한 계정이 로컬 경로가 포함된 row를 쓸 수 있고 예약된 callback이 root 권한으로 PHP의 [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php)를 호출한 뒤 반환된 내용을 row에서 지정한 webhook으로 보낸다면, 이는 privileged 파일 노출 경로입니다. cron 실행 identity, 실제 scheduler callback과 row에서 경로로 이어지는 데이터 흐름, database 쓰기 권한, row를 읽은 뒤의 validation, outbound 대상을 확인하세요. 읽을 수 있는 application `.env`는 자격 증명 단서일 뿐입니다. web form validation이나 database password만으로는 row 제어 또는 정보 노출을 입증할 수 없습니다. 열거 중에는 database를 조회하거나 task를 예약하지 말고 예약 정보, 코드, 자격 증명 파일 권한을 수동으로 확인하세요.

Event-driven `incron` 작업도 같은 방식으로 검토해야 합니다. [incrontab 항목](https://manpages.debian.org/testing/incron/incrontab.5.en.html)은 감시 경로와 이벤트를 연결하고, table 소유자의 identity로 명령을 실행합니다. application이 쓰기 가능한 디렉터리의 링크를 따라가 감시 대상에 공격자가 제어하는 텍스트를 쓸 경우, 낮은 권한 사용자가 감시 파일에 간접적으로 영향을 줄 수 있습니다. 실제 table 소유자, 이벤트, 대상과 상위 경로 권한, application의 link-following 동작, 해당 텍스트가 명령 인수가 되는 방식을 확인하세요. 특히 [GNU Mailutils `mail`은 `--exec`를 허용합니다](https://mailutils.org/manual/html_node/Invoking-Mail.html). 해당 [shell-escape 명령](https://mailutils.org/manual/html_node/Shell-Escapes.html)은 프로그램을 실행할 수 있습니다. 해당 구현에서 신뢰할 수 없는 필드가 별도 옵션으로 전달되면 명령 실행으로 이어질 수 있습니다. 다른 `mail` 구현이나 인용된 고정 인수 경계에서는 동작이 다를 수 있습니다. 열거 중에는 감시 파일을 수정하거나 작업을 실행하지 말고 예약 정보, application 코드, 파일 metadata를 확인하세요.

감시 로그도 helper script를 통해 사용자 경계를 넘을 수 있습니다. 낮은 권한 계정이 로그에 쓸 수 있고 `incron` 소유자가 로그의 필드를 새 [`sh -c` 명령 문자열](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)에 읽어 넣는다면, shell은 해당 필드를 소유자의 identity로 다시 파싱합니다. 정확한 감시 이벤트, 로그와 상위 경로 권한, helper 경로, 로그 필드의 변환 방식, 결과 명령이 실제로 실행되는지 확인하세요. 쓰기 가능한 로그와 `incron` 항목이 있다는 사실만으로는 데이터 흐름이 입증되지 않습니다. 수동 열거 중에는 trigger 행을 쓰거나 helper를 실행하지 마세요.

인증서 갱신 작업도 같은 경계를 넘을 수 있습니다. Privileged helper가 낮은 권한 사용자의 쓰기 가능한 디렉터리에 있는 인증서에서 X.509 subject를 읽고 common name을 새 `bash -c` 명령 문자열에 삽입할 수 있습니다. [OpenSSL은 인증서 subject를 표시하고 만료 여부를 확인할 수 있습니다](https://docs.openssl.org/3.3/man1/openssl-x509/). [Bash는 `-c` 문자열을 shell 입력으로 파싱합니다](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html). 따라서 바깥 스크립트에서 변수를 인용해도 두 번째 파싱은 보호되지 않습니다. 이를 command injection으로 판단하기 전에 예약 실행 identity, 정확한 입력 경로와 쓰기 권한, 갱신 분기, `bash -c`로 이어지는 데이터 흐름을 확인하세요. 열거 중에는 갱신을 실행하지 말고 스크립트와 인증서 metadata를 수동으로 확인하세요.

privileged 예약 작업이 낮은 권한 사용자 아카이브 또는 package에서 이름을 추출해 `xargs -I`로 `sh -c` 명령 문자열에 삽입할 때도 같은 두 번째 파싱이 발생할 수 있습니다. [GNU `xargs -I`는 초기 인수에서 placeholder를 바꿉니다](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html). [`sh -c`는 명령 문자열을 해석합니다](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html). 바깥 스크립트가 추출한 이름을 인용하더라도 나중에 치환되는 shell program이 안전해지는 것은 아닙니다. 작업의 실행 사용자, 정확히 허용되는 입력 경로와 쓰기 권한, archive validation과 분기 조건, 이름에서 shell로 이어지는 데이터 흐름을 확인하세요. 쓰기 가능한 upload 디렉터리나 `xargs` 호출만으로는 단서일 뿐입니다. 열거 중에는 package를 제출하거나 작업을 실행하지 말고 예약 정보, 스크립트, 경로 metadata를 확인하세요.

예약된 font 또는 image importer도 upload의 바깥 파일명이 제한되어 있더라도 사용자가 제공한 archive 내부의 이름을 신뢰할 수 있습니다. FontForge는 [CVE-2024-25081 및 CVE-2024-25082에 대한 upstream 변경](https://github.com/fontforge/fontforge/pull/5367)에서 archive member 이름을 통한 command injection을 수정했습니다. 높은 권한의 작업이 실제로 낮은 권한 사용자의 쓰기 가능한 경로에 있는 archive를 여는지, 실행 identity, 정확한 FontForge 빌드 또는 vendor backport, archive 처리 코드 경로를 확인하세요. 버전 문자열이나 허용된 upload suffix만으로는 실행을 입증할 수 없습니다. 열거 중에는 신뢰할 수 없는 archive를 가져오지 말고 예약 정보, 경로 권한, 빌드 metadata를 확인하세요.

예약된 network scanner는 custom script가 원격 TLS certificate subject를 로컬 파일명으로 취급할 때 다른 경계를 넘을 수 있습니다. [Nmap NSE는 선택된 스크립트를 sandbox 없이 실행합니다](https://nmap.org/book/nse-usage.html). 따라서 실제 스크립트와 containment 검사 없이 신뢰할 수 없는 subject 필드를 data 디렉터리에 결합하는지 확인하세요. 파일 노출이 성립하려면 scheduler가 스캔할 대상, scanner의 실행 identity가 읽을 수 있는 파일로 해석되는 경로, 낮은 권한 사용자가 읽을 수 있는 보고서 또는 로그가 필요합니다. certificate 필드나 설치된 scanner만으로는 해당 체인이 입증되지 않습니다. 수동 열거 중에는 새 대상을 스캔하지 말고 예약 정보, 스크립트, 경로 해석, 보고서 대상을 검토하세요.

privileged cron 명령이 `/path/to/tasks/*.yml` 같은 shell glob을 Ansible runner에 전달한다면, 기존 playbook이 모두 read-only여도 디렉터리 권한을 확인해야 합니다. glob 대상 디렉터리에 쓰기와 search 권한이 있는 사용자는 일치하는 playbook을 추가할 수 있습니다. [Ansible playbook은 runner가 실행하는 task를 정의합니다](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html). 다만 custom wrapper가 경로를 필터링하거나 다른 identity를 사용할 수 있습니다. 해당 디렉터리를 실행 경로로 판단하기 전에 wrapper 동작, 실제 cron 사용자, shell 확장, ACL, sticky bit, mount 정책을 확인하세요. 열거 중에는 작업을 실행하지 말고 metadata와 wrapper를 정적으로 검토하세요.

Privileged cron wrapper는 glob을 확장한 뒤 upload 디렉터리의 파일명을 Perl helper에 전달할 수 있습니다. Perl의 [`<>` diamond operator는 두 인수 형태의 `open`을 사용합니다](https://perldoc.perl.org/perlop#The-Null-Filehandle). 따라서 일치하는 파일명이 pipe 명령으로 해석되면 helper의 identity로 실행될 수 있습니다. [`<<>>`는 인수를 리터럴 파일명으로 취급합니다](https://perldoc.perl.org/perlop#The-Null-Filehandle). scheduler identity, wrapper의 작업 디렉터리와 glob, helper의 실제 `@ARGV` 처리, 파일명 제한, 낮은 권한 identity가 파일시스템 권한 또는 인증된 upload service를 통해 일치하는 이름을 배치할 수 있는지 확인하세요. cron 항목, Perl script, 쓰기 가능한 FTP 디렉터리만으로는 전체 체인이 입증되지 않습니다. 열거 중에는 조작된 파일명을 제출하거나 작업을 실행하지 말고 소스와 metadata를 확인하세요.

예약 계정이 pathname으로 실행하는 read-only cron script도 낮은 권한 사용자가 non-sticky 상위 디렉터리에 쓰기와 traverse 권한이 있으면 교체할 수 있습니다. 예약 실행 identity, 모든 경로 구성 요소, 디렉터리 sticky bit, ACL, mount 정책을 확인하세요. 파일을 옮기거나 작업을 실행하지 말고 metadata를 검토하세요.

Privileged PHP cron wrapper는 아직 존재하지 않는 helper를 실행할 수도 있습니다. PHP [`exec()`](https://www.php.net/manual/en/function.exec.php)에 고정된 절대 helper 경로를 전달한다면, 해당 상위 디렉터리에 그 이름의 파일을 만들 수 있는 낮은 권한 사용자가 이후 실행될 파일을 제어할 수 있습니다. cron 항목이 실제로 더 높은 identity로 wrapper를 실행하는지, 정확한 명령 문자열과 PHP 실행 정책, helper 디렉터리의 쓰기 및 search 권한, symlink와 sticky-bit 동작, helper 경로가 여전히 없는지 확인하세요. 쓰기 가능한 디렉터리나 없는 helper만으로는 단서일 뿐입니다. 열거 중에는 helper를 만들거나 작업을 실행하지 말고 예약 정보, 소스, 경로 metadata를 확인하세요.

예약 작업은 `find`로 입력 스크립트를 찾아 interpreter에 전달할 수도 있습니다. 예를 들어 [gnuplot의 `system()` 함수는 shell을 호출합니다](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf). 따라서 낮은 권한 사용자의 쓰기 가능한 디렉터리에서 모든 `*.plt` 파일에 `gnuplot`을 실행하는 privileged 작업은 작업의 identity로 명령을 실행할 수 있습니다. [디렉터리의 read 권한은 목록 조회를 제어하고, write 및 search(`x`) 권한은 알려진 이름을 만들고 접근하는 것을 제어합니다](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html). `ls`로 디렉터리 내용을 볼 수 없더라도 write와 search 권한을 확인하세요. 정확한 scheduler identity와 명령, interpreter 동작, 선택된 파일 패턴, 디렉터리 권한을 대조하세요. 쓰기 가능한 디렉터리나 설치된 interpreter만으로는 privilege escalation이 입증되지 않습니다. 비공개 예약 작업과 짧게 실행되는 작업은 한 번의 process snapshot으로 놓칠 수 있으므로, 권한이 부여된 경우 event 관찰이 필요할 수 있습니다.

Privileged PHP 작업에서는 executable script 체인의 일부로 명시적인 `include`/`require` 문도 확인하세요. [PHP는 포함된 파일을 평가합니다](https://www.php.net/manual/en/function.include.php). 따라서 group-writable `.php` 파일은 main script가 read-only여도 작업의 identity로 코드를 실행할 수 있습니다. 예약 identity, 유효한 include-path 해석, 파일 및 디렉터리 권한, 작업의 실제 실행 여부를 확인하세요. 주석에 있는 cron 예시는 단서일 뿐입니다. 같은 검토는 `-S`와 `-t <document-root>`로 실행되는 root 소유 [PHP built-in server](https://www.php.net/commandline.webserver)에도 적용됩니다. loopback listener도 로컬 요청에 대해 application PHP를 실행할 수 있습니다. 열거 중에는 trigger를 실행하지 말고 process와 소스를 확인하세요.

Privileged PHP 작업은 **데이터 파일**을 통해서도 경계를 넘을 수 있습니다. 낮은 권한 사용자가 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php)에 전달되는 정확한 파일을 바꿀 수 있다면, PHP가 객체를 복원하는 동안 로드된 class의 `__wakeup()` 또는 `__unserialize()` 메서드를 호출할 수 있습니다. 작업의 유효 identity, 파일과 상위 경로 권한, 로드된 class, property가 지정한 파일 쓰기 같은 실제 메서드의 부작용을 검토하세요. 쓰기 가능한 로그나 `unserialize()` 호출만으로는 이용 가능한 경로가 입증되지 않습니다. 열거 중에는 직렬화된 입력을 쓰거나 작업을 실행하지 말고 소스와 metadata를 확인하세요.

root cron 작업은 web server 대신 PHP application의 **CLI page runner**를 호출할 수 있습니다. runner가 선택한 document root와 URI를 실제 PHP entrypoint까지 추적하세요. 해당 entrypoint를 web-service 계정이 쓸 수 있다면 runner와 cron wrapper가 read-only여도 예약된 CLI 요청이 변경된 코드를 root 권한으로 실행할 수 있습니다. scheduler identity, 정확한 URI-to-file 해석, 유효한 파일 및 상위 경로 권한, integrity check가 entrypoint 자체를 보호하는지 확인하세요. 열거 중에는 runner를 호출하거나 페이지를 변경하지 말고 소스와 metadata를 검토하세요.

공유 작업 디렉터리에서 예약 작업 또는 다른 사용자가 시작한 `ipython` process는 startup 파일 검토 대상입니다. [IPython 보안 릴리스 노트](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699)에 따르면 CVE-2022-21699 수정 전 영향을 받은 빌드는 현재 디렉터리에서 profile과 설정을 찾았으며 `profile_default/startup` 코드도 포함됩니다. 실제 설치 빌드 또는 vendor patch, 명령 작업 디렉터리, 높은 권한 process identity, 낮은 권한 사용자가 정확한 startup 경로에 쓰고 search할 수 있는지를 대조하세요. 설치된 `ipython`, 쓰기 가능한 디렉터리, 버전 문자열만으로는 다른 identity가 그곳의 파일을 불러온다는 사실이 입증되지 않습니다. 높은 권한 interpreter를 실행하지 말고 예약 정보와 경로 metadata를 확인하세요.

Custom native extension의 함수를 호출하는 privileged PHP server의 경우 extension을 검토하기 전에 service의 PHP SAPI와 유효한 `php.ini`, 그리고 스캔되는 `.ini` 파일을 추적하세요. [PHP는 시작 시 설정된 `extension` library를 불러옵니다](https://www.php.net/manual/en/ini.core.php). [CLI와 web SAPI는 서로 다른 설정 파일을 사용할 수 있습니다](https://www.php.net/manual/en/configuration.file.php). 따라서 접근 가능한 login form이나 local listener가 사용자 제어 문자열을 service identity로 실행되는 compiled code에 전달할 수 있습니다. unit의 `User=`, `ExecStart=`, 작업 디렉터리, 실제 extension 경로, 호출자가 제어하는 인수를 기록하세요. `.so` 파일이나 loopback socket이 있다는 사실만으로는 memory corruption 취약점이 입증되지 않습니다. 수동 열거 중에는 probe를 보내지 말고 custom parser를 별도로 분석하세요.

Privileged wrapper가 pathname으로 스크립트의 hash를 계산한 뒤 같은 pathname을 다시 열어 실행한다면, digest가 인증하는 것은 첫 번째 open에서 읽은 객체뿐입니다. 낮은 권한 사용자가 두 open 사이에 스크립트의 디렉터리 항목을 교체할 수 있다면 원래 스크립트 파일이 root 소유여도 두 번째 실행에서 다른 객체가 해석될 수 있습니다. FIFO가 check 단계를 늘릴 수 있지만, 경로가 성립하려면 교체 가능한 상위 디렉터리 권한, 실제로 분리된 open, scheduler identity, sticky-bit 및 mount 규칙, 타이밍이 필요합니다. wrapper와 `namei -l` 출력을 수동 단서로 확인하세요. checksum이 성공했다는 사실만으로 이후 pathname이 보호된다고 볼 수 없습니다.

Privileged backup 작업은 공격자가 제공한 명령을 실행하지 않고도 데이터를 **노출**할 수 있습니다. 낮은 권한 사용자가 작업이 읽는 control file을 만들 수 있는지, 작업이 이어서 `/etc/shadow` 같은 보호된 source를 여는지, 공격자가 선택한 URL이나 읽을 수 있는 출력으로 결과를 전달하는지 추적하세요. 정보 노출 경로로 판단하기 전에 세 가지를 모두 확인해야 합니다. 같은 스크립트의 고정 shell 명령만으로는 해당 control file이 shell-injection 입력이 되지 않습니다. 열거 중에는 작업을 실행하거나 control file을 심지 말고 스크립트와 파일 권한을 확인하세요.

Privileged 예약 작업이 `curl -K FILE` 또는 `curl --config FILE`을 실행한다면, [curl은 해당 파일의 옵션을 명령줄 인수처럼 취급합니다](https://curl.se/docs/manpage.html). curl이 파일을 읽는 시점에 낮은 권한 사용자가 정확한 파일을 제어할 수 있으면 요청 URL, 로컬 파일 입력, 출력 경로에 영향을 줄 수 있습니다. 보호된 읽기 또는 쓰기가 가능하다고 주장하기 전에 작업의 유효 identity, 파일과 상위 경로의 쓰기 권한, 파일을 교체하는 다른 작업의 실행 시점, config 옵션과 고정 명령줄 옵션의 상호 작용을 확인하세요. 쓰기 가능한 config 경로나 보이는 `-K` flag만으로 선택한 옵션이 적용된다고 볼 수 없습니다. 열거 중에는 작업을 실행하거나 URL을 가져오지 말고 예약 정보와 metadata를 확인하세요.

cron 항목이 helper script를 호출한다면 helper의 작업 디렉터리와 archive 명령도 확인하세요. 다른 사용자가 쓸 수 있는 디렉터리에서 인용되지 않은 wildcard를 사용하면 파일명이 archiver 옵션으로 해석될 수 있습니다. GNU tar의 checkpoint action이 한 예입니다. cross-user 명령 경로라고 주장하기 전에 예약 실행 identity, 쓰기 가능한 입력 디렉터리, 정확한 archiver와 옵션, `--`가 옵션 파싱을 종료하는지 확인하세요. [wildcard 및 tar 동작](../interesting-files-permissions/wildcards-spare-tricks.md)을 참조하세요.

Privileged helper가 `cd INPUT_DIR; tar ... *`를 실행하면서 `cd` 성공 여부를 확인하지 않을 때는 별도의 backup 파일 노출이 발생할 수 있습니다. 낮은 권한 사용자가 `INPUT_DIR`을 제거하거나 교체할 수 있다면 `cd` 실패 후에도 shell이 이전 디렉터리에 남을 수 있고, 이후 archive 명령이 그 디렉터리를 읽을 수 있습니다. helper의 초기 작업 디렉터리, 실제 `cd` 실패 경로, 스크립트가 종료되거나 `&&`를 사용하는지, 정확한 archiver 옵션, 낮은 권한 사용자가 출력 archive를 읽을 수 있는지 확인하세요. 쓰기 가능한 입력 디렉터리나 읽을 수 있는 archive만으로는 단서일 뿐입니다. live 작업을 변경하지 말고 helper와 경로 권한을 검토하세요.

예약된 executable이 shell script를 숨긴다고 해서 신뢰 경계가 없어지는 것은 아닙니다. [SHc](https://github.com/neurobin/shc)는 암호화된 script 텍스트를 native binary로 감싸고 runtime에 shell을 통해 실행합니다. `.sh.x` suffix나 불투명한 ELF 파일은 검토 단서일 뿐입니다. 파일명 옵션 injection을 평가하려면 privileged scheduler identity, helper의 실제 작업 디렉터리와 명령, 낮은 권한 사용자가 그곳에 일치하는 이름을 만들 수 있는지, 인용되지 않은 glob이 옵션 경계 없이 `rsync` 같은 명령에 전달되는지 확인하세요. [`rsync` remote-shell 옵션](../interesting-files-permissions/wildcards-spare-tricks.md#rsync)은 해당 명령 경로가 실제로 사용될 때만 관련이 있습니다. `/proc` 접근 제한이나 정적 복호화 실패로 명령을 알 수 없다면 privileged helper를 실행해 분류하지 마세요.

Process 명령줄 텍스트도 privileged helper가 받는 또 다른 신뢰할 수 없는 입력입니다. 낮은 권한 사용자는 `pgrep -f`와 일치하는 process title 또는 `argv[0]`를 선택할 수 있습니다. 이름이 일치한다고 해서 executable이나 소유자가 인증되는 것은 아닙니다. root 실행 스크립트가 해당 텍스트를 가져와 일부를 `apache2ctl`/`httpd`로 다시 쓰고 고정된 인수 배열 없이 결과를 실행하면, 공격자가 선택한 옵션으로 다른 설정 디렉터리나 error log를 지정할 수 있습니다. Apache 설정 파싱은 module을 불러오거나 설정된 helper에 도달할 수 있으므로 열거 중에는 신뢰할 수 없는 설정을 root로 검증하지 마세요. scheduler 소유자, 정확한 helper, process identity, 데이터에서 인수로 이어지는 흐름을 확인하세요. shell metacharacter 실행이 별도로 입증되지 않는 한 이는 option/configuration injection입니다.

root 실행 parser가 신뢰할 수 없는 텍스트를 Bash arithmetic에 전달하면 그 텍스트의 substitution이 실행될 수 있습니다. [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)에 구체적인 예가 있습니다. 모든 arithmetic expression을 악용 가능하다고 보기 전에 입력 출처와 파싱 명령을 확인하세요.

Privileged 작업이 application log를 파싱한다면 첫 번째 파싱 이후에도 신뢰할 수 없는 필드를 추적하세요. 낮은 권한 계정은 현재 process group을 통해 로그에 쓰거나 기록되는 request field에 영향을 줄 수 있습니다. 레코드가 image를 선택하고 그 metadata가 XML을 여는 두 번째 pathname이 될 수 있습니다. 작업의 유효 identity, 실제 로그 쓰기 권한, delimiter 처리, canonical path containment, 선택된 XML을 공격자가 제어할 수 있는지 확인하세요. 확장된 결과가 낮은 권한 사용자가 읽을 수 있는 출력으로 전달된다면 external-entity 확장을 통해 privileged 파일이 노출될 수 있습니다. [Java XML processing 보안 가이드](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)는 external DTD/entity 접근 제어를 설명합니다. 설치된 parser와 유효 설정을 확인하세요. 쓰기 가능한 로그나 XML 파일만으로는 단서일 뿐입니다. 열거 중에는 예약 parser에 입력을 전달하지 말고 코드와 metadata를 검토하세요.

다른 사용자의 Git repository에서 파일을 생성하는 privileged 작업도 확인하세요. 스크립트가 `git checkout` 대신 `git ls-tree`와 `git cat-file`을 사용하더라도 attacker-controlled tree 경로를 staging 디렉터리에 결합할 수 있습니다. 대상이 정규화되고 containment 검사를 거치지 않으면 절대 경로와 `..` 구성 요소가 해당 디렉터리 밖으로 빠져나갈 수 있습니다. `git -c safe.directory=*`는 소유자가 다른 repository에 대한 접근을 허용하지만, 그것만으로 arbitrary write가 발생하지는 않습니다.

root 실행 database backup은 또 다른 소유권 경계를 만들 수 있습니다. PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html)은 source data 디렉터리에 추가로 배치된 일반 파일을 복사하며, 기본 plain format은 `-D`에 디렉터리 트리로 파일을 기록합니다. 낮은 권한 계정이 해당 source 파일을 만들거나 수정할 수 있다면 결과 destination의 소유권과 mode, 경로의 traverse 및 execute 가능 여부, mount에 `nosuid`가 적용되는지 확인하세요. set-ID 권한을 보존한 root 소유 복사본은 위험할 수 있습니다. tar 전용 backup, 제거된 권한, 접근할 수 없는 destination은 같은 경로를 입증하지 않습니다. backup 명령을 finding으로 보기 전에 예약된 wrapper와 유효 사용자를 추적하세요.

## Observe short-lived work

단 한 번의 process snapshot으로는 수 밀리초만 실행되는 작업을 놓칠 수 있습니다. timer/cron 선언을 로그와 비교하고, 권한이 있는 경우 `pspy` 또는 audit 같은 process-event monitoring을 사용하세요. 예약 소유자, 정확한 명령줄, 작업이 읽거나 쓰는 파일을 대조하세요. loopback scheduler web UI는 별도의 인터페이스입니다. [Crontab UI 예시](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)를 참조하세요.
{{#include ../../banners/hacktricks-training.md}}
