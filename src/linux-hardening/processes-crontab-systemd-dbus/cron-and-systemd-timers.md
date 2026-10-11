# Cron 작업 및 Systemd 타이머

{{#include ../../banners/hacktricks-training.md}}

예약된 작업은 현재 셸과 다른 사용자 ID 및 환경에서 실행될 수 있습니다. cron, `at`, anacron, systemd 타이머를 열거한 다음, 각 예약 명령을 스크립트, 가져오기 항목, 작업 디렉터리 및 쓰기 가능한 입력까지 추적하세요.

## 예약 작업 열거하기

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

System crontab에는 보통 사용자 필드가 있지만, 사용자의 crontab에는 없습니다. 실제 scheduler의 유효한 PATH와 환경을 확인하세요. `run-parts --test /etc/cron.daily`는 해당 호스트에서 선택될 파일 이름을 보여 줍니다. 제어 문자는 일반적인 출력에서 항목을 숨길 수 있으므로, schedule이 의심스러우면 `cat -A` 또는 `sed -n l`을 사용하세요.

## 권한이 있는 파일 및 명령 확인 과정 추적하기

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

쓰기 가능한 script 체인, `EnvironmentFile=` 경로, drop-in, symlink, 상대 경로 명령, wildcard 확장, 그리고 권한 있는 작업이 복사하거나 실행하는 바이너리를 확인하세요. timer는 `Unit=` 설정을 통해 이름이 다른 service를 활성화할 수 있습니다. 주요 기본 요소는 [PATH](../linux-basics/linux-environment-variables.md#path), [wildcard](../interesting-files-permissions/wildcards-spare-tricks.md), [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 페이지를 참고하세요.

root로 실행되도록 예약된 `chkrootkit` script라면, 설치된 소스에서 과거의 [slapper-loop quoting 결함(CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)을 확인하세요. `SLAPPER_FILES` 임시 경로를 검사한 뒤 인용되지 않은 `file_port=$file_port $i`가 해당 파일을 실행할 수 있습니다. 실제 script 또는 vendor patch, root 권한으로 실행되는 예약 작업, 낮은 권한 사용자의 정확한 임시 경로 쓰기 권한, 실행 가능 여부, mount 정책을 확인하세요. 버전 문자열이나 `chkrootkit`이 있다는 사실만으로 해당 경로가 입증되지는 않습니다. 수동 검토 중에는 임시 파일을 만들거나 실행하지 마세요.

timer가 실행하는 root service에서 `systemctl restart <other>.service`를 실행한다면 unit을 한 단계 더 추적하세요. 재시작된 unit이 낮은 권한 사용자가 쓸 수 있는 script를 shell로 실행할 수 있습니다. 유효한 `User=`, `DynamicUser=`, `RootDirectory=`/`RootImage=`, 정확한 `ExecStart=` 인수, script와 상위 경로의 권한을 확인하세요. 쓰기 가능한 script는 후보일 뿐입니다. 실행 컨텍스트에서 timer와 재시작되는 service가 활성 상태여야 합니다. service를 재시작하지 말고 unit 속성을 확인하세요.

더 높은 권한의 작업이 hostname으로 script를 가져와 응답을 shell에 전달한다면, 원격 script뿐 아니라 해당 hostname의 이름 해석을 누가 제어하는지도 확인하세요. group 또는 ACL로 권한이 부여된 경우를 포함해 쓰기 가능한 `/etc/hosts` 파일은 작업이 로컬에서 해석하는 이름을 다른 주소로 연결할 수 있습니다. `curl` 응답이 사용자 간 실행 경로가 되려면 실제 예약 명령이 응답을 실행하고, 작업이 영향을 받는 resolver 경로를 사용해야 합니다. 작업의 실행 사용자, 정확한 URL과 shell pipeline, 유효한 proxy/DNS 동작, 파일 및 상위 디렉터리 권한을 확인하세요. hosts 파일이 쓰기 가능하다는 사실만으로 권한 있는 consumer가 있다고 입증되지는 않습니다. 열거 중에는 매핑을 변경하거나 script를 가져오지 말고 예약 작업과 metadata를 확인하세요.

권한 있는 예약 `wget` fetch는 다운로드된 본문이 직접 실행되지 않더라도 별도의 파일 쓰기 경계입니다. [GNU Wget 1.18은 CVE-2016-4971을 해결하기 위해 HTTP에서 FTP로 redirect될 때 기본 파일명 처리 방식을 변경했습니다](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html). 영향을 받는 구버전은 redirect된 FTP 파일명을 사용할 수 있었으며, `--trust-server-names`는 해당 동작을 명시적으로 요청합니다. 낮은 신뢰 수준의 사용자가 HTTP 응답과 FTP 리소스를 모두 제어한다면, 작업이 해당 redirect를 따르는지, 실제 Wget build 또는 vendor backport, 출력 옵션, 실행 사용자, 작업 디렉터리, 대상 파일명이 startup 파일이 될 수 있는지를 확인하세요. [Wget은 `WGETRC` 또는 `$HOME/.wgetrc`를 읽으며](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html), [설정으로 POST 원본이나 출력 경로를 지정할 수 있습니다](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html). 이후 권한 있는 fetch가 실행되는 것도 결과적인 정보 노출이나 쓰기에 별도로 필요합니다. `authbind`를 통한 낮은 포트 접근은 호출자가 작업이 요청하는 URL을 실제로 제공할 수 있을 때만 관련이 있습니다. redirect를 제공하거나 작업을 실행하지 말고 설정과 log를 수동으로 검토하세요. [그룹 `disk`를 통한 raw block-device 접근](../user-information/interesting-groups-linux-pe/README.md#disk-group)은 이 network fetch 경로와 별개입니다.

script뿐 아니라 data 파일도 추적하세요. 예약된 simulation 또는 orchestration 도구가 실행할 process를 정의하는 YAML 파일을 읽을 수 있습니다. 낮은 권한 사용자가 해당 파일을 편집할 수 있고 작업이 다른 계정으로 실행된다면, data가 작업의 권한으로 실행되는 명령이 될 수 있습니다. YAML 파일이 쓰기 가능하다는 이유만으로 실행 경로라고 판단하기 전에 정확한 예약 명령, 유효 사용자, 파일 경로, parser 의미, 쓰기 권한(상위 디렉터리 포함)을 확인하세요. 수동 triage에는 예약 작업과 파일 metadata 확인만으로 충분합니다. 열거 중에는 작업을 실행하거나 입력을 수정하지 마세요.

더 높은 권한의 작업이 낮은 권한 사용자가 바꿀 수 있는 파일을 대상으로 `ssh -F`를 실행한다면 SSH client 설정도 실행 가능한 입력입니다. OpenSSH의 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand)는 client shell을 통해 로컬 명령을 실행하며, `Host`/`Match`와 앞선 옵션에 따라 해당 지시어의 적용 여부가 결정됩니다. 이를 사용자 간 실행 경로라고 판단하기 전에 정확한 예약 SSH 호출, 실행 사용자, 선택된 config 경로, 디렉터리 및 파일 쓰기 권한, 유효한 옵션 순서를 대조하세요. 권한 있는 계정으로 작업을 실행하거나 신뢰할 수 없는 config를 불러오지 말고 관련 기록을 검토하세요.

예약된 `scp` 실행 후 `ssh`로 복사된 script를 실행하는 경우, 낮은 권한 사용자가 대상 SSH service를 제어한다면 두 번째 신뢰 경계도 검토해야 합니다. 해당 service가 연결을 다른 host로 전달할 수 있다면 권한 있는 client가 의도하지 않은 endpoint에 인증할 수 있습니다. [`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking)는 변경된 host key에 대한 보호를 약화하지만, OpenSSH의 나머지 제한과 유효한 host별 옵션은 여전히 적용됩니다. 작업의 실행 사용자, 실제 대상과 인증 방식, 원격 명령의 유효한 실행 사용자, 리디렉션된 host에 동일한 대상 경로가 쓰기 가능하거나 이미 존재하는지를 확인하세요. 오래되었거나 공격자가 제어하는 파일을 실행하려면 복사가 실패하거나 해당 경로를 놓쳐야 **하고**, wrapper가 SSH 명령까지 계속 진행해야 합니다. [Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)와 명시적인 상태 처리가 이 흐름에 영향을 줍니다. 약한 host-key 설정, 눈에 보이는 `sshpass` process, 쓰기 가능한 임시 디렉터리만으로는 이 체인이 입증되지 않습니다. 열거 중에는 service를 리디렉션하거나 작업을 실행하지 말고 예약 작업, script, SSH 설정, 파일 metadata를 확인하세요.

권한 있는 application scheduler는 쓰기 가능한 파일 대신 database row에서 작업을 가져올 수 있습니다. 예를 들어 root cron 항목이 Laravel의 [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler)을 실행하면, task row를 읽는 application code에 도달할 수 있습니다. 낮은 권한 계정이 로컬 경로가 들어 있는 row를 쓸 수 있고 예약 callback이 root 권한으로 PHP의 [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php)를 호출한 뒤 반환된 본문을 row에서 지정한 webhook으로 보내면, 이는 권한 있는 파일 노출 경로입니다. cron 실행 사용자, 실제 scheduler callback과 row에서 경로로 이어지는 data 흐름, database 쓰기 권한, row를 읽은 후의 validation, outbound 대상지를 확인하세요. 읽을 수 있는 application `.env`는 credential 단서일 뿐입니다. web form validation이나 database password만으로 row 제어 또는 정보 노출이 입증되지는 않습니다. 열거 중에는 database에 질의하거나 작업을 예약하지 말고 예약 작업, code, credential 파일 권한을 수동으로 확인하세요.

event 기반 `incron` 작업도 같은 방식으로 검토해야 합니다. [incrontab 항목](https://manpages.debian.org/testing/incron/incrontab.5.en.html)은 감시 경로와 event를 table 소유자의 권한으로 실행되는 명령에 연결합니다. application이 쓰기 가능한 디렉터리의 link를 따라가 감시 대상에 공격자가 제어하는 text를 쓰면, 낮은 권한 사용자가 감시 파일에 간접적으로 영향을 줄 수 있습니다. 실제 table 소유자, event, 대상 및 상위 경로 권한, application의 link 추적 동작, 해당 text가 명령 인수가 되는 방식을 확인하세요. 특히 [GNU Mailutils `mail`은 `--exec`를 지원하며](https://mailutils.org/manual/html_node/Invoking-Mail.html), [shell-escape 명령](https://mailutils.org/manual/html_node/Shell-Escapes.html)으로 프로그램을 실행할 수 있습니다. 해당 구현에서 신뢰할 수 없는 field가 별도의 option으로 전달되면 명령 실행으로 이어질 수 있습니다. 다른 `mail` 구현이나 인용된 고정 인수 경계에서는 동작이 다를 수 있습니다. 열거 중에는 감시 파일을 수정하거나 작업을 trigger하지 말고 예약 작업, application code, 파일 metadata를 확인하세요.

감시 log도 helper script를 통해 사용자 경계를 넘을 수 있습니다. 낮은 권한 계정이 log에 쓸 수 있고 `incron` 소유자가 log의 field를 새 [`sh -c` 명령 문자열](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)에 넣으면, shell은 소유자의 권한으로 해당 field를 다시 parse합니다. 정확한 감시 event, log 및 상위 경로 권한, helper 경로, log field의 변환 과정, 결과 명령의 실행 여부를 확인하세요. 쓰기 가능한 log와 `incron` 항목만으로 data 흐름이 입증되지는 않습니다. 수동 열거 중에는 trigger line을 쓰거나 helper를 실행하지 마세요.

인증서 갱신 작업도 같은 경계를 넘을 수 있습니다. 권한 있는 helper가 낮은 권한 사용자가 쓸 수 있는 디렉터리의 인증서에서 X.509 subject를 읽고 common name을 새 `bash -c` 명령 문자열에 삽입할 수 있습니다. [OpenSSL은 인증서 subject를 표시하고 만료 여부를 확인할 수 있으며](https://docs.openssl.org/3.3/man1/openssl-x509/), [Bash는 `-c` 문자열을 shell 입력으로 parse합니다](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html). 따라서 바깥 script에서 변수를 인용해도 두 번째 parse를 방지하지는 못합니다. 이를 command injection이라고 판단하기 전에 예약 작업의 실행 사용자, 정확한 입력 경로와 쓰기 권한, 갱신 분기, `bash -c`까지 이어지는 data 흐름을 확인하세요. 열거 중에는 갱신을 trigger하지 말고 script와 인증서 metadata를 수동으로 확인하세요.

권한 있는 예약 작업이 낮은 권한 사용자의 archive 또는 package에서 이름을 추출해 `xargs -I`에 전달하고 `sh -c` 명령 문자열에 삽입하는 경우에도 같은 두 번째 parse가 발생할 수 있습니다. [GNU `xargs -I`는 초기 인수의 placeholder를 교체하며](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html), [`sh -c`는 명령 문자열을 해석합니다](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html). 바깥 script가 추출한 이름을 인용하더라도 이후 치환된 shell program이 안전해지는 것은 아닙니다. 작업의 실행 사용자, 정확한 허용 입력 경로와 쓰기 권한, archive validation과 분기 조건, 이름에서 shell까지의 data 흐름을 확인하세요. 업로드 디렉터리가 쓰기 가능하거나 `xargs`가 호출된다는 사실만으로는 단서일 뿐입니다. 열거 중에는 package를 제출하거나 작업을 실행하지 말고 예약 작업, script, 경로 metadata를 확인하세요.

예약된 font 또는 image importer는 업로드의 바깥 파일명이 제한되어 있더라도 사용자가 제공한 archive 안의 이름을 신뢰할 수 있습니다. FontForge는 [CVE-2024-25081 및 CVE-2024-25082를 해결하는 upstream 변경](https://github.com/fontforge/fontforge/pull/5367)에서 archive 구성원 이름을 통한 command injection을 수정했습니다. 더 높은 권한의 작업이 실제로 낮은 권한 사용자가 쓸 수 있는 경로의 archive를 여는지, 실행 사용자, 정확한 FontForge build 또는 vendor backport, archive 처리 code 경로를 확인하세요. 버전 문자열이나 허용된 업로드 확장자만으로 실행이 입증되지는 않습니다. 열거 중에는 신뢰할 수 없는 archive를 가져오지 말고 예약 작업, 경로 권한, build metadata를 확인하세요.

예약된 network scanner는 custom script가 원격 TLS 인증서 subject를 로컬 파일명으로 취급할 때 다른 경계를 넘을 수 있습니다. [Nmap NSE는 선택된 script를 sandbox 없이 실행합니다](https://nmap.org/book/nse-usage.html). 따라서 실제 script와, 신뢰할 수 없는 subject field를 containment 검사 없이 data 디렉터리와 결합하는지 확인하세요. 파일 노출이 성립하려면 scheduler가 scan할 대상, scanner의 실행 사용자 권한으로 읽을 수 있는 파일로 해석되는 경로, 낮은 권한 사용자가 읽을 수 있는 report 또는 log가 필요합니다. 인증서 field나 scanner 설치만으로는 이 체인이 입증되지 않습니다. 수동 열거 중에는 새 대상을 scan하지 말고 예약 작업, script, 경로 해석, report 대상을 검토하세요.

`/path/to/tasks/*.yml` 같은 shell glob을 Ansible runner에 전달하는 권한 있는 cron 명령은 기존 playbook이 모두 읽기 전용이어도 디렉터리 권한을 확인해야 합니다. glob 대상 디렉터리에 쓰기 및 search 권한이 있는 사용자는 일치하는 playbook을 추가할 수 있습니다. [Ansible playbook은 runner가 실행하는 task를 정의합니다](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html). 다만 custom wrapper가 경로를 필터링하거나 다른 사용자 권한을 사용할 수 있습니다. 해당 디렉터리를 실행 경로로 판단하기 전에 wrapper 동작, 실제 cron 사용자, shell 확장, ACL, sticky bit, mount 정책을 확인하세요. metadata와 wrapper를 정적으로 검토하고 열거 중에는 예약 작업을 실행하지 마세요.

권한 있는 cron wrapper는 glob을 확장한 뒤 업로드 디렉터리의 파일명을 Perl helper에 전달할 수 있습니다. Perl의 [`<>` diamond operator는 두 인수 형식의 `open`을 사용하므로](https://perldoc.perl.org/perlop#The-Null-Filehandle), 일치하는 파일명이 pipe 명령으로 해석되어 helper의 권한으로 실행될 수 있습니다. [`<<>>`는 인수를 리터럴 파일명으로 취급합니다](https://perldoc.perl.org/perlop#The-Null-Filehandle). scheduler 사용자, wrapper의 작업 디렉터리와 glob, helper의 실제 `@ARGV` 처리 방식, 파일명 제한, 낮은 권한 사용자가 filesystem 권한이나 인증된 업로드 service를 통해 일치하는 이름을 만들 수 있는지 확인하세요. cron 항목, Perl script, 쓰기 가능한 FTP 디렉터리만으로는 전체 체인이 입증되지 않습니다. 열거 중에는 조작된 파일명을 제출하거나 작업을 실행하지 말고 source와 metadata를 확인하세요.

예약된 계정이 경로로 script를 실행하고 낮은 권한 사용자가 해당 파일의 비-sticky 상위 디렉터리에 쓰기 및 traverse 권한을 갖는다면 읽기 전용 cron script도 교체할 수 있습니다. 예약 작업의 실행 사용자, 모든 경로 구성 요소, 디렉터리 sticky bit, ACL, mount 정책을 확인하세요. 파일을 옮기거나 작업을 실행하지 말고 metadata를 검토하세요.

권한 있는 PHP cron wrapper는 아직 존재하지 않는 helper에 도달할 수도 있습니다. 절대 경로가 고정된 PHP [`exec()`](https://www.php.net/manual/en/function.exec.php) 호출이 있고 낮은 권한 사용자가 상위 디렉터리에 해당 이름을 만들 수 있다면, 이후 실행에서 실행 대상을 제어할 수 있습니다. cron 항목이 실제로 더 높은 권한으로 wrapper를 실행하는지, 정확한 명령 문자열과 PHP 실행 정책, helper 디렉터리의 쓰기 및 search 권한, symlink와 sticky bit 동작, helper 경로가 여전히 없는지를 확인하세요. 쓰기 가능한 디렉터리나 helper가 없다는 사실만으로는 단서일 뿐입니다. 열거 중에는 helper를 만들거나 작업을 trigger하지 말고 예약 작업, source, 경로 metadata를 확인하세요.

예약 작업은 `find`로 입력 script를 찾고 interpreter에 전달할 수도 있습니다. 예를 들어 [gnuplot의 `system()` 함수는 shell을 호출합니다](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf). 따라서 낮은 권한 사용자가 쓸 수 있는 디렉터리의 모든 `*.plt` 파일을 권한 있는 작업이 `gnuplot`으로 실행하면 작업의 권한으로 명령을 실행할 수 있습니다. [디렉터리의 read 권한은 목록 조회를 제어하고, write 및 search(`x`) 권한은 알려진 이름의 생성과 접근을 제어합니다](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html). `ls`로 목록을 볼 수 없어도 write 및 search 권한을 확인하세요. 정확한 scheduler 사용자와 명령, interpreter 동작, 선택된 파일 패턴, 디렉터리 권한을 대조하세요. 디렉터리가 쓰기 가능하거나 interpreter가 설치되어 있다는 사실만으로 권한 상승이 입증되지는 않습니다. 비공개 예약 작업과 짧게 실행되는 작업은 권한이 부여된 event 관찰이 필요할 수 있습니다. process snapshot 하나로는 놓칠 수 있습니다.

권한 있는 PHP 작업에서는 실행 가능한 script 체인의 일부로 명시적인 `include`/`require` 문도 확인하세요. [PHP는 포함된 파일을 평가하므로](https://www.php.net/manual/en/function.include.php), group 쓰기 권한이 있는 `.php` 파일은 주 script가 읽기 전용이어도 작업의 권한으로 code를 실행할 수 있습니다. 예약 작업의 실행 사용자, 유효한 include-path 해석, 파일 및 디렉터리 권한, 작업의 실제 실행 여부를 확인하세요. 주석에 있는 예시 cron 줄은 단서일 뿐입니다. root 소유 [PHP built-in server](https://www.php.net/commandline.webserver)를 `-S`와 `-t <document-root>`로 실행하는 경우에도 같은 검토가 필요합니다. loopback listener도 로컬 요청에 대해 application PHP를 실행할 수 있습니다. 열거 중에는 trigger를 호출하지 말고 process와 source를 확인하세요.

권한 있는 PHP 작업은 **data file**을 통해서도 경계를 넘을 수 있습니다. 낮은 권한 사용자가 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php)에 전달되는 정확한 파일을 바꿀 수 있다면, PHP가 object를 복원하는 과정에서 로드된 class의 `__wakeup()` 또는 `__unserialize()` method를 호출할 수 있습니다. 작업의 유효한 실행 사용자, 파일 및 상위 경로 권한, 로드된 class, property가 선택한 파일 쓰기 같은 실제 method 부작용을 검토하세요. 쓰기 가능한 log나 `unserialize()` 호출만으로는 사용 가능한 경로가 입증되지 않습니다. 열거 중에는 직렬화된 입력을 쓰거나 작업을 실행하지 말고 source와 metadata를 확인하세요.

root cron 작업은 web server 대신 PHP application의 **CLI page runner**를 호출할 수 있습니다. runner가 선택한 document root와 URI를 실제 PHP entrypoint까지 추적하세요. entrypoint가 web-service 계정에 쓰기 가능하다면 runner와 cron wrapper가 읽기 전용이어도 예약된 CLI 요청이 변경된 code를 root 권한으로 실행할 수 있습니다. scheduler 사용자, 정확한 URI-to-file 해석, 유효한 파일 및 상위 경로 권한, entrypoint 자체를 보호하는 integrity check가 있는지 확인하세요. 열거 중에는 runner를 호출하거나 page를 변경하지 말고 source와 metadata를 확인하세요.

예약 작업이나 다른 사용자가 공유 작업 디렉터리에서 시작하는 `ipython` process는 startup 파일을 검토해야 합니다. [IPython 보안 릴리스 노트](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699)에 따르면 CVE-2022-21699 수정 전 영향을 받은 build는 현재 디렉터리에서 profile과 설정을 찾았으며, `profile_default/startup` code도 포함됩니다. 실제 설치된 build 또는 vendor patch, 명령의 작업 디렉터리, 더 높은 권한의 process 사용자, 낮은 권한 사용자가 정확한 startup 경로에 쓰기 및 search 권한을 갖는지를 대조하세요. `ipython` 설치 여부, 쓰기 가능한 디렉터리, 버전 문자열만으로는 다른 사용자 권한의 process가 해당 파일을 로드한다고 입증되지 않습니다. 열거 중에는 더 높은 권한의 interpreter를 실행하지 말고 예약 작업과 경로 metadata를 확인하세요.

custom native extension의 함수를 호출하는 권한 있는 PHP server라면 extension을 검토하기 전에 service의 PHP SAPI와 유효한 `php.ini`, scan된 `.ini` 파일을 추적하세요. [PHP는 시작할 때 설정된 `extension` library를 로드하며](https://www.php.net/manual/en/ini.core.php), [CLI와 web SAPI는 서로 다른 설정 파일을 사용할 수 있습니다](https://www.php.net/manual/en/configuration.file.php). 따라서 접근 가능한 login form이나 로컬 listener를 통해 사용자가 제어하는 문자열이 service 사용자 권한으로 실행되는 compiled code에 전달될 수 있습니다. unit의 `User=`, `ExecStart=`, 작업 디렉터리, 실제 extension 경로, 호출자가 제어하는 인수를 기록하세요. `.so` 파일이 있거나 loopback socket이 있다는 사실만으로 memory-corruption 취약점이 입증되지는 않습니다. 수동 열거 중에는 probe를 보내지 말고 custom parser는 별도로 분석하세요.

권한 있는 wrapper가 script를 경로로 hash한 뒤 나중에 같은 경로를 다시 열어 실행하면, digest는 첫 번째 open에서 읽은 object만 인증합니다. 낮은 권한 사용자가 두 open 사이에 script의 디렉터리 항목을 교체할 수 있다면, 원본 script 파일이 root 소유여도 이후 실행에서 다른 object가 해석될 수 있습니다. FIFO는 검사 단계를 늘릴 수 있지만, 이 경로는 교체 가능한 상위 디렉터리 권한, 실제로 분리된 open, scheduler 사용자, sticky bit 및 mount 규칙, 실행 시점에 달려 있습니다. wrapper와 `namei -l` 출력을 수동으로 확인하세요. checksum이 성공했다는 사실만으로 이후 경로가 보호된다고 입증되지는 않습니다.

권한 있는 backup 작업은 공격자가 제공한 명령을 실행하지 않고도 데이터를 **노출**할 수 있습니다. 낮은 권한 사용자가 작업이 읽는 control file을 만들 수 있는지, 작업이 다음으로 `/etc/shadow` 같은 보호된 source를 여는지, 공격자가 선택한 URL이나 읽을 수 있는 output으로 결과가 전달되는지 추적하세요. 이를 정보 노출 경로라고 판단하기 전에 세 가지 모두 확인하세요. 같은 script에 고정된 shell 명령이 있다는 사실만으로 해당 control file이 shell-injection 입력이 되지는 않습니다. 열거 중에는 작업을 실행하거나 control file을 심지 말고 script와 파일 권한을 확인하세요.

권한 있는 예약 작업이 `curl -K FILE` 또는 `curl --config FILE`을 실행한다면, [curl은 해당 파일의 옵션을 명령줄 인수처럼 취급합니다](https://curl.se/docs/manpage.html). curl이 읽는 시점에 낮은 권한 사용자가 정확한 파일을 제어할 수 있다면 요청 URL, 로컬 파일 입력, 출력 경로에 영향을 줄 수 있습니다. 보호된 파일의 read 또는 write를 주장하기 전에 작업의 유효한 실행 사용자, 파일 및 상위 경로의 쓰기 권한, 파일을 교체하는 다른 작업의 시점, config 옵션과 고정 명령줄 옵션의 상호 작용을 확인하세요. config 경로가 쓰기 가능하거나 `-K` flag가 보인다는 사실만으로 선택한 옵션이 적용된다고 입증되지는 않습니다. 열거 중에는 작업을 실행하거나 URL을 가져오지 말고 예약 작업과 metadata를 확인하세요.

cron 항목이 helper script를 호출한다면 helper의 작업 디렉터리와 archive 명령도 확인하세요. 다른 사용자가 쓸 수 있는 디렉터리에서 인용되지 않은 wildcard를 사용하면 파일명이 archiver 옵션으로 해석될 수 있습니다. GNU tar의 checkpoint action이 한 예입니다. 사용자 간 명령 실행 경로라고 판단하기 전에 예약 작업의 실행 사용자, 쓰기 가능한 입력 디렉터리, 정확한 archiver와 옵션, `--`로 option parsing을 종료하는지 확인하세요. [wildcard와 tar 동작](../interesting-files-permissions/wildcards-spare-tricks.md)을 참고하세요.

권한 있는 helper가 `cd INPUT_DIR; tar ... *`를 실행하면서 `cd` 성공 여부를 확인하지 않으면 별도의 backup 파일 노출이 발생할 수 있습니다. 낮은 권한 사용자가 `INPUT_DIR`을 제거하거나 교체할 수 있다면, `cd` 실패 후 shell이 이전 디렉터리에 그대로 남아 이후 archive 명령이 그곳을 읽을 수 있습니다. 작업의 초기 작업 디렉터리, 실제 `cd` 실패 경로, script가 종료되는지 또는 `&&`를 사용하는지, 정확한 archiver 옵션, 낮은 권한 사용자가 output archive를 읽을 수 있는지를 확인하세요. 입력 디렉터리가 쓰기 가능하거나 archive를 읽을 수 있다는 사실만으로는 단서일 뿐입니다. live 작업을 변경하지 말고 helper와 경로 권한을 확인하세요.

예약된 executable이 shell script를 숨기고 있어도 신뢰 경계가 사라지는 것은 아닙니다. [SHc](https://github.com/neurobin/shc)는 암호화된 script text를 native binary로 감싼 뒤 runtime에 shell을 통해 실행합니다. `.sh.x` 확장자나 내용을 알 수 없는 ELF는 검토 단서일 뿐입니다. filename option injection을 평가하려면 권한 있는 scheduler 사용자, helper의 실제 작업 디렉터리와 명령, 낮은 권한 사용자가 그곳에 일치하는 이름을 만들 수 있는지, 인용되지 않은 glob이 option 경계 없이 `rsync` 같은 명령에 전달되는지 확인해야 합니다. [`rsync` remote-shell option](../interesting-files-permissions/wildcards-spare-tricks.md#rsync)은 해당 명령 경로가 실제로 사용될 때만 관련이 있습니다. `/proc` 접근 제한이나 정적 복호화 실패로 명령을 알 수 없다면 불명확한 상태로 남기세요. 분류를 위해 권한 있는 helper를 실행하지 마세요.

process 명령줄 text도 권한 있는 helper에 전달되는 신뢰할 수 없는 입력일 수 있습니다. 낮은 권한 사용자는 `pgrep -f`와 일치하도록 process title이나 `argv[0]`을 지정할 수 있습니다. 이름이 일치한다고 executable이나 소유자가 인증되는 것은 아닙니다. root로 실행되는 script가 해당 text를 가져와 일부를 `apache2ctl`/`httpd`로 바꾼 다음 고정 인수 배열 없이 결과를 실행한다면, 공격자가 선택한 옵션이 다른 설정 디렉터리나 error log를 지정할 수 있습니다. Apache 설정 parsing은 module을 로드하거나 설정된 helper에 도달할 수 있으므로 열거 중에는 root 권한으로 신뢰할 수 없는 설정을 검증하지 마세요. scheduler 소유자, 정확한 helper, process 사용자, data-to-argument 흐름을 확인하세요. shell metacharacter 실행이 별도로 입증되지 않는 한 이는 option/configuration injection입니다.

권한 있는 root parser가 신뢰할 수 없는 text를 Bash 산술식에 전달하면 해당 text의 substitution이 실행될 수 있습니다. [권한 상승 가이드](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)에 구체적인 예가 있습니다. 모든 산술식이 악용 가능하다고 판단하기 전에 입력 출처와 parsing 명령을 확인하세요.

application log를 parse하는 권한 있는 작업에서는 첫 번째 parse 이후의 신뢰할 수 없는 field도 추적하세요. 낮은 권한 계정은 현재 process group을 통해 log에 쓸 수 있거나 log에 기록되는 request field에 영향을 줄 수 있습니다. 이후 record가 image를 선택하고, 그 metadata가 XML을 여는 두 번째 경로가 될 수 있습니다. 작업의 유효한 실행 사용자, 실제 log 쓰기 권한, delimiter 처리, canonical path containment, 선택된 XML이 공격자 제어 대상인지 확인하세요. 외부 entity 확장 결과가 낮은 권한 사용자가 읽을 수 있는 output에 전달된다면 두 번째 read가 권한 있는 파일 노출로 이어질 수 있습니다. [Java XML 처리 보안 가이드](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)는 외부 DTD/entity 접근 제어를 설명합니다. 설치된 parser와 유효한 설정을 확인하세요. 쓰기 가능한 log나 XML 파일만으로는 단서일 뿐입니다. 열거 중에는 예약 parser에 입력을 제공하지 말고 code와 metadata를 검토하세요.

다른 사용자의 Git repository에서 파일을 가져오는 권한 있는 작업도 확인하세요. script가 `git checkout` 대신 `git ls-tree`와 `git cat-file`을 사용하더라도, tree 경로를 staging 디렉터리와 결합할 때 공격자가 제어하는 경로를 신뢰할 수 있습니다. 기록 전에 대상을 정규화하고 containment를 확인하지 않으면 절대 경로와 `..` 구성 요소가 디렉터리 밖으로 빠져나갈 수 있습니다. `git -c safe.directory=*`는 소유자가 다른 repository에 접근할 수 있게 하지만, 그 자체로 임의 파일 쓰기를 발생시키지는 않습니다.

root로 실행되는 database backup에서 또 다른 소유권 경계가 생길 수 있습니다. PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html)은 source data 디렉터리에 추가된 일반 파일을 복사하며, 기본 plain 형식은 `-D`에 디렉터리 트리 형태로 파일을 씁니다. 낮은 권한 계정이 해당 source 파일을 만들거나 수정할 수 있다면, 결과 destination의 소유권과 mode, 경로를 traverse 및 실행할 수 있는지, mount에 `nosuid`가 적용되는지 확인하세요. set-ID 권한이 보존된 root 소유 복사본은 위험할 수 있습니다. tar 전용 backup, 권한 제거, 접근할 수 없는 destination은 같은 경로를 입증하지 않습니다. backup 명령을 finding으로 판단하기 전에 예약 wrapper와 유효한 사용자를 추적하세요.

## 짧게 실행되는 작업 관찰

단일 process snapshot으로는 몇 밀리초 동안만 실행되는 작업을 놓칠 수 있습니다. timer/cron 선언을 log와 비교하고, 권한이 있는 경우 `pspy` 또는 audit 같은 process-event monitoring을 사용하세요. 예약 사용자, 정확한 명령줄, 작업이 읽거나 쓰는 파일을 대조하세요. loopback scheduler web UI는 별도 인터페이스입니다. [Crontab UI 예제](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)를 참고하세요.
{{#include ../../banners/hacktricks-training.md}}
