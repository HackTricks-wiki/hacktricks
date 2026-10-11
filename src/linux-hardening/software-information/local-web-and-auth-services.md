# 로컬 웹 및 인증 서비스

{{#include ../../banners/hacktricks-training.md}}

Linux shell은 웹 및 인증 서비스에 대한 호스트 측 관점을 제공합니다. 여기에는 프로세스 인수, 리스너, unit 파일, 구성, 로그, 로컬 전용 인터페이스가 포함됩니다. 이 관점을 활용해 접근 가능한 서비스와 실제로 사용하는 계정 및 파일을 연결하세요.

## 로컬 웹 스택 파악

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

가상 호스트 이름, document root, proxy route, 업로드 디렉터리, PHP 실행 설정, 자격 증명이 포함된 구성 파일을 확인하세요. loopback listener에 proxy나 SSH tunnel을 통해 접근할 수 있을 수도 있습니다. 로컬 listener에 지정된 가상 호스트로 요청을 보내려면 의도한 `Host` 헤더를 보내거나 올바른 주소와 포트로 `curl --resolve`를 사용하세요. 가상 호스트 열거를 통해 기본 응답에 나타나지 않는 이름도 찾을 수 있습니다. Apache에서 `.htaccess` 재정의를 허용하는지, 업로드 경로에서 PHP를 실행할 수 있는지 확인한 뒤에야 쓰기 가능한 업로드 디렉터리를 code execution으로 판단하세요. 배포된 JavaScript source map에서 소스 경로나 클라이언트 측 secret이 드러날 수 있습니다. 복구한 값은 단서로 취급하고 실제 권한을 확인하세요. 웹 관련 검사는 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 및 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)를 참조하세요.

[mpm-itk](https://mpm-itk.sesse.net/)을 사용하는 Apache에서 활성화된 `AssignUserID`는 가상 호스트를 다른 사용자와 그룹으로 실행할 수 있습니다. 권한이 낮은 계정이 해당 호스트의 `DocumentRoot`에 스크립트를 쓸 수 있다면, 접근 가능한 route에서 실제로 할당된 identity로 스크립트가 실행되는지 확인하세요. 모듈이 로드되었는지, 유효한 가상 호스트 설정(표현식 기반 identity 재정의 포함), 디렉터리의 쓰기 및 탐색 권한, script handler, listener 접근성을 확인하세요. 눈에 띄는 지시문이나 쓰기 가능한 디렉터리만으로는 사용자 간 실행이 증명되지 않습니다.

웹 서버를 통해 공개된 홈 디렉터리에서 활성 `.ssh` 디렉터리가 비공개여도 SSH identity 파일의 백업 archive가 노출될 수 있습니다. 예를 들어, [Nostromo의 `homedirs_public` 설정](https://www.nazgul.ch/dev/nostromo_man.html)은 사용자 홈에서 제공할 하위 디렉터리를 지정합니다. 경로만 확인된 archive는 단서일 뿐입니다. 서버의 유효한 매핑, 로컬에서 읽을 수 있는지 또는 HTTP 인증이 필요한지, archive 내용, private key의 passphrase, 해당 계정이 실제로 그 key를 허용하는지 확인하세요. 일반적인 호스트 열거 중에는 archive를 풀거나 key 내용을 출력하지 마세요.

권한이 더 높은 로컬 웹 앱의 백업을 읽을 수 있다면, 실제 소스에 접근할 수 없어도 인증 및 파일 읽기 로직이 드러날 수 있습니다. 백업을 신뢰하기 전에 배포된 서비스와 비교하세요. 특히 호출자가 제어하는 텍스트 뒤에 secret과 role flag를 붙여 암호화해 cookie를 만들고, 앱이 결정적인 ECB block을 사용하며, 선택한 텍스트에 대해 새로운 cookie를 반환하고, 나중에 복호화한 값을 escape되지 않은 구분자로 분리한다면 검토가 필요합니다. [NIST는 ECB의 독립적이고 반복 가능한 block 매핑을 설명합니다](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a). 이 특성은 선택 입력 비교에 활용될 수 있지만, 그 자체로 더 높은 role을 부여하지는 않습니다. 실제 route, session 사전 조건, 정확한 parser/data flow, 서비스 identity, 별도의 권한 상승 동작 또는 파일 읽기 경로를 확인하세요. 수동 인벤토리에서는 archive 내용을 읽거나 인증 probe를 보내지 말고 백업 metadata와 listener 소유권을 보고하세요.

같은 소스 검토 방식은 사용자 지정 SSH 기반 인터페이스와 같은 권한이 높은 **HTTP가 아닌** loopback 서비스에도 적용됩니다. 접근 가능한 소스 백업에 호출자가 파일 경로를 지정할 수 있는 명령이 있다면, 인증 절차, 경로 해석 방식, 파일을 열기 전에 해석된 파일이 의도된 디렉터리 아래에 있는지 확인하는지 검토하세요. Go의 [`filepath.Join`](https://pkg.go.dev/path/filepath#Join)은 경로를 정리하지만 해당 디렉터리 내부에 머무는 것을 강제하지는 않습니다. 백업이 실행 중인 build와 일치하는지, listener에 접근 가능한지, 권한이 낮은 계정이 명령을 사용할 수 있는지, 프로세스가 대상 파일을 읽을 수 있는지 확인하세요. 읽을 수 있는 SSH key를 보유하고 있다는 점은 별도의 로그인 정책 문제입니다. archive 내용을 추출하거나 key를 자동화된 출력에 포함하지 말고 소스 archive 경로와 서비스 소유권을 보고하세요.

TCP loopback에서 수신 대기하는 PHP-FPM pool은 웹사이트에 인증이 설정되어 있어도 다른 로컬 계정에서 접근할 수 있습니다. [PHP는 FastCGI에 연결할 수 있는 클라이언트가 `auto_prepend_file`을 포함한 request 설정을 제어할 수 있다고 경고합니다](https://www.php.net/manual/en/install.fpm.php). pool의 `listen` 및 `listen.allowed_clients` 설정을 실제 listener, worker UID, 기존 script 경로, `security.limit_extensions` 또는 `php_admin_value` 제한과 함께 검토하세요. Pool 구성 파일의 `env[...]` 지시문에 자격 증명이 포함될 수 있으므로 자동화된 인벤토리에서는 내용을 출력하지 말고 경로만 보고하세요. 구성 파일이나 포트만으로는 사용자 간 실행 경로가 증명되지 않습니다. 프로토콜 세부 정보는 [FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)를 참조하세요.

권한이 높은 로컬 API에서는 code execution뿐 아니라 권한 부여도 추적하세요. 권한이 낮은 계정이 변경할 수 있는 database role이 API route를 열어 줄 수 있지만, 다음 경계는 해당 route의 구현 방식에 따라 달라집니다. 예를 들어, 요청 JSON을 JavaScript object에 병합한 뒤 [`child_process.exec`](https://nodejs.org/api/child_process.html)을 호출한다면 [prototype-pollution-to-execution dataflow](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)를 검토해야 합니다. 실제 병합 library/version, 입력 검증, 접근 가능한 route, 프로세스 identity, child-process 옵션을 확인하세요. root 소유의 Node listener나 취약한 dependency 이름만으로는 단서에 그칩니다.

파일 기반 CMS는 일반적인 `.php` 구성 파일 이외의 위치에 관리자 password verifier를 저장할 수 있습니다. 예를 들면 사이트의 `data/database.js` 또는 `data/settings/pass.php`가 있습니다. 직접 검토하기 전에 파일 소유권과 읽기 권한을 확인하고, 자동화된 공유 출력에 hash를 포함하지 마세요. 복구 가능한 애플리케이션 password는 Unix 계정과 별개의 권한 경계입니다. 재사용 가능성이 제기된 경우 해당 계정과 허용된 인증 방식에서 실제로 확인하세요.

애플리케이션의 authentication controller에는 구성 파일이 아닌 소스 코드에 로그인 password가 그대로 포함될 수도 있습니다. 권한이 낮은 사용자가 배포된 controller를 읽을 수 있다면, 로컬에서 인증 비교 로직을 검토하고 공유 열거 출력에는 값을 포함하지 마세요. 해당 code path가 활성화되어 있는지, 애플리케이션에서 password가 유효한지, 권한이 더 높은 별도의 Unix 계정이 동일한 password를 실제로 허용하는지 확인한 뒤에야 로컬 권한 상승이라고 판단하세요. controller 파일 이름만으로는 검토 단서에 불과합니다.

Dolibarr는 `htdocs/conf/conf.php`에 `dolibarr_main_db_pass`를 비롯한 database 연결 설정을 저장합니다([구성 참조](https://wiki.dolibarr.org/index.php/Configuration_file)). 읽을 수 있는 파일은 자격 증명 단서일 뿐입니다. 별도로 확인된 계정 password 재사용이나 다른 database 권한이 있어야 로컬 권한 상승으로 이어집니다. 먼저 권한을 확인하고 자동화된 출력에 값을 표시하지 마세요.

GitLab Linux package의 구성 파일은 일반적으로 `/etc/gitlab/gitlab.rb`이며, 배포 환경에 따라 읽을 수 있는 사본이 다른 위치에 남아 있을 수 있습니다. [GitLab 문서](https://docs.gitlab.com/omnibus/settings/smtp/)에 따르면 이 파일에 `gitlab_rails['smtp_password']`가 포함될 수 있지만, 암호화된 SMTP 설정에서는 password가 평문 파일 밖에 저장될 수도 있습니다. 읽을 수 있는 구성은 자격 증명 단서로 취급하세요. password 재사용이라고 판단하기 전에 해당 설정이 활성화되어 있는지, 자격 증명이 현재 유효한지, 권한이 더 높은 특정 계정에서 실제로 허용되는지 확인하세요. 별도로 [GitLab은 `gitlab-ctl reconfigure` 중 root 권한으로 `gitlab.rb`를 Ruby code로 실행합니다](https://docs.gitlab.com/omnibus/settings/configuration/). 쓰기 가능한 활성 파일 또는 포함된 `from_file`을 실행 취약점으로 판단하려면 실제로 권한이 높은 reconfigure 경로가 있어야 합니다. 구성 미리보기에서 자격 증명 값이 노출될 수 있으므로 출력은 민감 정보로 취급하고, 대신 경로와 권한을 공유하세요.

자체 호스팅 Mattermost 설치는 `/opt/mattermost/config/config.json`에 `SqlSettings.DataSource`를 저장할 수 있습니다. [Mattermost 문서](https://docs.mattermost.com/deployment-guide/server/troubleshooting)에는 일반적인 경로와 활성 구성이 대신 database에 저장되는 배포 방식이 모두 설명되어 있습니다. 파일을 읽을 수 있으면 애플리케이션 database 자격 증명이 노출될 수 있지만, 그것만으로 database 접근 권한이나 Unix root 접근 권한이 입증되지는 않습니다. 활성 구성의 출처, database role의 실제 권한, 별도로 복구한 애플리케이션 password, 해당 password가 권한이 더 높은 특정 Unix 계정에서 작동하는지 확인하세요. Password hash 형식은 Mattermost 버전에 따라 달라질 수 있습니다. 열거 중에는 연결 문자열이나 database query 결과를 출력하지 말고 구성 경로와 접근 metadata를 기록하세요.

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

가상 호스트 결과를 기본 응답 크기나 다른 안정적인 기준값과 비교해 필터링하여, 추측한 모든 이름이 유효한 것처럼 보이지 않게 하세요. 소스 맵은 실제로 배포되어 있거나 다른 방식으로 읽을 수 있을 때만 유용합니다.

Reverse proxy는 애플리케이션이 신뢰하는 클라이언트 헤더를 바꿀 수 있습니다. `X-Forwarded-For`, `X-Forwarded-Host` 또는 유사한 헤더가 호출자의 신원을 나타낸다고 가정하기 전에 직접 요청과 프록시를 거친 요청을 비교하세요. 프록시와 애플리케이션 설정을 함께 검토하세요.

PHP가 `$_SERVER['HTTP_X_FORWARDED_FOR']`를 [`system()`](https://www.php.net/manual/en/function.system.php)에 전달되는 문자열에 복사한다면, 요청 경로에서 호출자가 제공한 헤더를 사용할 수 있는지, 그리고 shell 메타문자가 해당 문자열에 그대로 전달되는지 검토하세요. `sudo iptables` 같은 명령이 맨 앞에 포함되어 있어도, 이후 shell로 구분된 명령까지 root 권한으로 실행되는 것은 아닙니다. 별도의 유효한 sudo 규칙으로 권한 상승이 허용되지 않는 한 해당 명령은 웹 worker 계정으로 실행됩니다. root 권한 경로를 주장하기 전에 worker 신원, 정확한 `sudo -l` 허용 항목과 인증 요구 사항, 명령의 인자 경계를 확인하세요. 일상적인 host 열거 중에는 injection probe를 보내지 말고 소스와 정책을 검사하세요.

## 액세스 로그의 로그인 자격 증명

애플리케이션이 로그인 양식을 `GET`으로 제출하면 사용자 이름과 비밀번호가 요청 URI의 query parameter가 될 수 있습니다. `POST` 요청에도 query string이 포함될 수 있습니다. `POST`를 사용하더라도 관련 없는 양식 필드에 입력한 비밀번호를 비롯해 URI에 실수로 포함된 비밀 정보가 숨겨지는 것은 아닙니다. [Apache의 일반적인 access log 요청 라인](https://httpd.apache.org/docs/2.4/logs.html)은 설정된 형식에서 `%r`을 사용하는 경우 query string을 포함해 method와 URI를 기록합니다. 따라서 일부 Linux 시스템의 `adm` 그룹처럼 해당 로그를 읽을 수 있는 계정에서 자격 증명 단서를 찾을 수도 있습니다. 실제 로그 형식과 권한을 확인한 다음, 해당 값이 비밀 정보인지, 계정에서 허용되는지, 권한 경계를 넘는지 검증하세요. 요청 본문이 로그에 기록된다고 가정하지 말고, 후보 값을 공유 출력에 복사하지 마세요.

읽을 수 있는 access log만 검사하고 자격 증명 값은 공유 명령 출력에 포함하지 마세요. 긴 요청 라인에는 referrer와 user agent도 포함될 수 있으므로, 짧은 라인만 필터링하면 확인하려는 요청이 숨겨질 수 있습니다. Apache, httpd, Nginx의 일반적인 access log 위치는 `/var/log/apache2/access.log`, `/var/log/httpd/access_log`, `/var/log/nginx/access.log`입니다. 회전된 로그에는 이전 자격 증명이 남아 있을 수 있습니다. [LFI를 통한 로그 파일 접근](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)은 같은 데이터에 접근하는 관련 경로입니다.

애플리케이션 인증 로그에는 로그인 실패 시 **username** 필드에 실수로 입력한 비밀번호가 노출될 수도 있습니다. 먼저 로그를 읽을 수 있는지, 해당 형식이 제출된 사용자 이름을 기록하는지 확인하세요. 관련된 일부 내용만 로컬에서 확인하고 후보 자격 증명을 공유 출력에 복사하지 마세요. 비밀번호처럼 보이는 사용자 이름은 단서일 뿐, 유효한 비밀번호나 더 높은 권한을 입증하지 않습니다. 전환을 주장하기 전에 의도된 계정과 해당 서비스 또는 Unix 계정에서의 재사용 여부를 확인하세요.

다른 신원으로 실행되는 예약된 클라이언트가 해당 엔드포인트에 자격 증명을 제출하는 경우, 쓰기 가능한 웹 로그인 handler는 별도로 검토해야 합니다. **활성** handler에 대한 쓰기 권한, 클라이언트의 실제 예약 작업과 요청 경로, 클라이언트가 제출하는 자격 증명의 소유자, 애플리케이션 비밀번호가 더 높은 권한의 운영체제 계정에도 유효한지를 확인하세요. 쓰기 가능한 페이지나 반복 실행 프로세스만으로는 그러한 전환이 입증되지 않습니다. 수동 인벤토리에서는 handler를 변경하거나 비밀번호를 수집하지 말고 경로 권한과 작업 메타데이터를 기록하세요.

Suricata의 EVE JSON 로그에는 FTP 이벤트 로깅이 활성화된 경우 FTP `USER` 및 `PASS` 명령과 `command_data`가 기록될 수도 있습니다. 관련 내용을 로컬에서 일부만 확인하기 전에 회전 또는 압축된 파일을 포함해 `/var/log/suricata/eve*.json*`을 읽을 수 있는지 확인하세요. EVE 파일을 읽을 수 있다는 사실은 단서일 뿐입니다. FTP 이벤트가 기록되었는지, 데이터에 사용할 수 있는 자격 증명이 포함되어 있는지, 권한 경계를 넘는지 확인하세요. 공유 열거 출력에 `command_data`를 출력하지 마세요. Suricata 문서에서 [FTP 이벤트 필드](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)와 [EVE 회전 및 파일 이름 변형](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)을 확인할 수 있습니다.

## 생성된 Apache 설정 및 piped log

[remco](https://github.com/HeavyHorst/remco)는 key/value backend를 감시하고 템플릿을 Apache 설정 파일로 렌더링한 다음 reload 명령을 실행할 수 있습니다. 실행 중인 remco 프로세스의 신원, 설정된 템플릿 소스와 대상, 감시 중인 key prefix, backend 값이 `ServerName` 같은 Apache directive에 직접 삽입되는지를 확인하세요. 로컬 backend listener가 있다는 사실만으로 현재 사용자가 감시 대상 key를 쓸 수 있다고 단정할 수는 없습니다. 권한 상승을 주장하기 전에 backend 인증과 권한을 확인하세요.

쓰기 가능한 backend 값에 escape 처리되지 않은 newline이 있으면, 하나의 directive 값이 여러 Apache directive로 나뉠 수 있습니다. 특히 [Apache piped log](https://httpd.apache.org/docs/2.4/logs.html#piped)는 민감합니다. `CustomLog` 또는 `ErrorLog`에 `|` 명령이 있으면 상위 httpd의 신원(대개 root)으로 helper가 실행되며, `|$`는 Apache에 shell을 사용하도록 지시합니다. 열거 중에는 backend 데이터를 변경하거나 서비스를 재시작하지 말고 생성된 설정과 reload 경로를 검토하세요. 인자에 비밀 정보가 포함될 수 있으므로 전체 piped 명령은 비공개로 유지하세요.

## 인증 및 서비스 신원

Monit의 control file은 보통 `~/.monitrc` 또는 `/etc/monitrc`이지만, `monit -c`로 다른 경로를 지정할 수 있습니다. 읽을 수 있는 파일에는 웹 인터페이스용 `set httpd` 및 `allow user:password` 항목이 들어 있을 수 있으며, 해당 인터페이스는 대개 로컬 포트 2812에서 실행됩니다. 검토 전에 파일의 소유자와 권한을 확인하고, 비밀번호 값은 공유 열거 출력에 포함하지 마세요. 웹 자격 증명은 설정된 Monit 역할에만 권한을 부여합니다. 읽기 전용 사용자는 제어 작업을 실행할 수 없습니다. 별도의 Unix 계정 권한 상승을 주장하려면 비밀번호 재사용이 확인되거나 인증된 역할이 실제로 실행할 수 있는 권한 있는 Monit 작업이 있어야 합니다. [Monit control file 및 인증 문서](https://www.mmonit.com/monit/documentation/monit.html)를 참조하세요.

Webmin에서 `/etc/webmin/miniserv.conf`는 서버 설정을 보여주고 `/etc/webmin/webmin.acl`에는 사용자가 접근할 수 있는 모듈이 기록됩니다. [Webmin 문서에는 모듈 권한 부여의 경계가 설명되어 있습니다](https://webmin.com/docs/development/creating-modules/). Unix 비밀번호나 읽을 수 있는 ACL 파일만으로는 Webmin 세션이 허용되지 않습니다. 실제 인증 매핑, 접근 가능한 listener, 인증된 계정, 유효한 Package Updates 모듈 권한, 설치된 코드 또는 vendor 수정 사항, Webmin 프로세스의 신원을 확인하세요. 1.910 이하의 취약한 빌드에서는 [CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840)으로 인해 해당 모듈 권한이 있는 계정이 update handler를 통해 명령을 실행할 수 있었습니다. 수동 열거 중에는 자격 증명을 출력하거나 update를 시도하지 말고 설정 경로와 권한을 보고하세요.

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md)은 서비스별 인증을 관리합니다. 쓰기 가능한 정책 또는 모듈 경로를 통해 로그인 동작을 변경할 수 있습니다.
- LDAP/SSSD 설정에서 디렉터리 엔드포인트, 바인드 계정, 접근 규칙을 확인할 수 있습니다. 복구한 바인드 암호를 사용하면 현재 OS 계정에 허용된 범위를 넘어 LDAP 쿼리를 수행할 수 있습니다. 정확한 바인드 계정과 디렉터리 ACL을 테스트하세요. 비밀 정보를 살펴보기 전에 파일 권한을 검토하세요. 티켓 및 디렉터리 사용은 [Linux Active Directory](../user-information/linux-active-directory.md)와 [FreeIPA](freeipa-pentesting.md)를 참조하세요.
- Postfix 별칭은 수신 메일을 로컬 명령으로 전달할 수 있습니다. 권한이 낮은 사용자가 참조된 스크립트를 변경할 수 있다면, 메일 전달을 통해 해당 사용자의 코드가 전달 계정 권한으로 실행될 수 있습니다. 이 경로를 주장하기 전에 별칭 맵과 스크립트 소유권을 검토하세요. [SMTP 및 메일 서비스 테스트](../../network-services-pentesting/pentesting-smtp/README.md)를 참조하세요.
- Jenkins 및 기타 CI 서비스는 강력한 로컬 계정으로 작업을 실행할 수 있습니다. 파이프라인이나 플러그인을 테스트하기 전에 서비스 사용자, 쓰기 가능한 작업/워크스페이스 경로, 로컬 관리 인터페이스를 확인하세요. 또한 **작업에서 사용할 수 있는 자격 증명**과 해당 자격 증명으로 인증할 수 있는 계정도 검토하세요. [SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/)을 사용하는 Pipeline은 Jenkins 자체가 권한이 더 낮은 Unix 계정으로 실행되더라도 SSH 자격 증명의 사용자로 호스트에 접근할 수 있습니다. 호스트 권한 상승 경로가 있다고 주장하기 전에 현재 Jenkins ID에 `Job/Create`, `Job/Configure` 또는 Pipeline을 변경할 수 있는 다른 유효한 방법이 있는지, 해당 작업 범위에 자격 증명이 포함되는지, 대상 SSH 계정이 해당 키를 허용하는지 확인하세요. 자격 증명의 표시 이름이나 ID만으로는 이러한 조건을 확인할 수 없습니다. Jenkins는 작업 생성자와 대개 작업 설정자가 자신의 범위에서 사용할 수 있는 자격 증명을 임의로 사용할 수 있다고 경고합니다. 따라서 [자격 증명 범위](https://www.jenkins.io/doc/book/security/credentials/)와 [Pipeline 신뢰](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/)는 서비스 UID만큼 중요합니다. 공유 열거 결과에 자격 증명 값과 개인 키를 포함하지 마세요.

## Gogs 저장소 파일 쓰기

로컬 Gogs 서비스의 경우 `gogs web` 프로세스 소유자를 실행 파일 버전 및 `custom/conf/app.ini`와 대조하세요. 설정에서 서비스 ID, 저장소 루트, 리스너 주소, 등록 비활성화 여부를 확인할 수 있습니다. 루프백 전용 리스너도 로컬 사용자가 접근할 수 있습니다. 0.13.3 이하의 Gogs 버전에는 인증된 `PutContents` 심볼릭 링크 파일 쓰기 취약점([CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r))이 있습니다. 저장소에 쓸 수 있는 사용자는 심볼릭 링크를 커밋한 다음 API 쓰기를 해당 링크를 통해 수행하도록 할 수 있습니다. 이로 인해 발생하는 파일 접근 권한은 Gogs 프로세스의 권한을 따르므로, root 소유 인스턴스는 신속히 조치해야 합니다. 악용 가능한 경로가 있다고 주장하기 전에 배포된 수정 사항과 인증 요건을 확인하세요. API 오류가 발생했다고 해서 파일 쓰기가 실패한 것은 아닙니다.

## Gitea 저장소 설명의 XSS 및 권한이 높은 사용자

Gitea 1.22.0에서는 저장소 설명에 JavaScript를 저장할 수 있었습니다([CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)). 1.22.1에서 이 문제가 수정되었습니다. 설명을 수정할 수 있는 사용자가 악성 링크를 활성화하는 저장소 방문자의 브라우저 세션에 영향을 줄 수 있습니다. 이 브라우저 ID를 통해 비공개 저장소 콘텐츠나 다른 애플리케이션 데이터를 노출할 수 있습니다. 이와 별개로 로컬 권한 상승이 성립하려면 재사용된 관리자 암호처럼 해당 콘텐츠를 통해 접근 가능한 자격 증명이나 권한이 필요합니다. Gitea 프로세스 소유자만으로 root 영향이 입증되지는 않습니다. 공격 경로를 주장하기 전에 배포 버전, 설명 편집 권한, 방문자 동작, 실제 브라우저 상호작용을 확인하세요.

## Cobbler 프로비저닝 API

Cobbler 관리 서비스는 XML-RPC API를 노출하며, 일반적으로 포트 `25151`을 사용합니다. 영향을 평가하기 전에 리스너와 `cobblerd` 프로세스 소유자를 확인하세요. 루프백 전용 API도 호스트의 사용자가 접근할 수 있습니다. `/etc/cobbler/modules.conf`의 인증 및 권한 부여 모듈, `/etc/cobbler/settings` 또는 `/etc/cobbler/settings.yaml`의 서비스 설정, `/etc/cobbler/users.conf`, `/etc/cobbler/users.digest`, `/var/lib/cobbler/web.ss`의 권한을 검토하세요. digest 및 공유 비밀 파일에는 자격 증명 정보가 들어 있으므로, 기본적으로 내용을 출력하지 말고 읽기 가능 여부를 기록하세요.

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533**은 Cobbler 3.0.0~3.2.2 및 3.3.0~3.3.6의 XML-RPC 인증 우회 취약점입니다. 공유 비밀값을 읽지 못했을 때 예측 가능한 값인 `-1`이 반환되었고, API는 이를 비밀번호로 받아들였습니다. 이에 대응하는 수정 버전은 3.2.3 및 3.3.7입니다. 패키지 버전은 조사 단서일 뿐입니다. 노출 여부를 보고하기 전에 배포된 코드와 백포트된 수정 사항을 확인하세요.

`cobblerd`가 root로 실행 중이면 인증된 API 세션이 권한 있는 실행 경로가 될 수 있습니다. 영향을 받는 구현에서는 `background_import`가 사용자 제어 `rsync_flags`를 셸 명령에 전달하며, 사용자 제어 Cheetah autoinstall 템플릿을 렌더링하면 Python이 실행될 수 있습니다. 두 경로 중 하나를 테스트하기 전에 API 권한과 설치된 버전을 확인하세요. 관리 API 접근을 제한하고, 인증 우회 취약점을 패치하며, 설정 및 자격 증명 파일은 서비스 관리자만 읽을 수 있도록 하세요.

## Motion 및 motionEye 설정

`/etc/motioneye/motioneye.conf`에서 `conf_path`를 확인한 다음, 해당 디렉터리의 `motion.conf`와 소수의 `camera-*.conf` 파일을 검토하세요. 읽을 수 있는 `# @admin_password` 해시가 존재하는지 보고하되, 해시를 출력하지는 마세요. [이전 motionEye 릴리스에서는 이 파일에 광범위한 읽기 권한이 설정되었습니다](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67). 수정 사항은 0.44.0에 포함되었습니다. Motion의 `webcontrol_port`, `webcontrol_parms`, `webcontrol_auth_method`, `webcontrol_localhost` 설정을 함께 확인하세요. 인증이 비활성화된 상태에서 고급 제어(`2` 또는 `3`)가 활성화되면 루프백 리스너에서도 로컬 사용자가 강력한 작업을 수행할 수 있습니다. [Motion 문서에서 값과 기본값을 확인하세요](https://motion-project.github.io/motion_config.html).

0.43.1b5 이전 motionEye에서 관리자 세션을 사용하면 Motion이 처리하는 카메라 파일 이름 설정을 통해 명령을 실행할 수 있었습니다 ([CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)). 권한 상승을 주장하기 전에 실행 중인 버전, 서비스 계정, 사용 가능한 인증 경로, 카메라 설정 여부를 확인하세요. 설정만으로는 서비스가 실행 중이거나 높은 권한으로 동작한다는 사실을 입증할 수 없습니다.

서비스 이름이나 설치된 패키지는 조사 단서일 뿐입니다. 권한 경계는 접근 가능한 입력, 프로세스 계정, 쓰기 가능한 설정, 그리고 최종적으로 제어되는 명령 또는 파일의 조합으로 결정됩니다.

## 로컬 AWS 에뮬레이터 및 저장된 자격 증명

호스트 사용자는 게시된 루프백 엔드포인트를 통해 컨테이너에서 실행 중인 AWS 호환 에뮬레이터에 접근할 수 있습니다. [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 또는 [KMS](https://docs.localstack.cloud/aws/services/kms/)에 대한 접근을 평가하기 전에, 현재 수신 대기 중인 포트, 클라이언트가 선택한 엔드포인트와 계정, 에뮬레이터에 설치된 권한 부여 설정을 대조하세요. LocalStack에서 [IAM 정책 적용은 별도의 설정입니다](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/). 자격 증명 파일, IAM 정책 또는 수신 대기 포트만으로 유효한 API 권한을 추정하지 마세요. 설치된 릴리스와 설정에서 실제 동작을 확인하세요.

저장된 비밀값은 현재 API ID로 가져올 수 있고, 복구한 자격 증명을 별도의 상위 권한 계정이 받아들일 때만 로컬 권한 상승에 유용합니다. 암호화된 로컬 blob을 사용하려면 파일 읽기 권한, 사용할 수 있는 일치하는 KMS 키와 알고리즘, 유효한 복호화 권한도 필요합니다. [비대칭 KMS 키](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)를 사용하는 경우, 복호화 요청에 blob 암호화에 사용한 알고리즘을 지정해야 합니다. 정기적인 호스트 인벤토리는 프로세스, 수신 대기 포트, 설정 경로, 파일 권한에 대한 증거 수집으로 제한하세요. 일반적인 열거 과정에서 비밀값이나 복호화된 평문을 요청하거나 출력하지 마세요.
{{#include ../../banners/hacktricks-training.md}}
