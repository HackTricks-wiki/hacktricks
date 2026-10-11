# 로컬 웹 및 인증 서비스

{{#include ../../banners/hacktricks-training.md}}

Linux shell은 웹 및 인증 서비스의 호스트 측 정보를 보여 줍니다. 여기에는 프로세스 인수, 리스너, 유닛 파일, 구성, 로그, 로컬 전용 인터페이스가 포함됩니다. 이 정보를 활용해 접근 가능한 서비스를 실제로 사용하는 계정 및 파일과 연결하세요.

## 로컬 웹 스택 파악하기

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

가상 호스트 이름, 문서 루트, 프록시 경로, 업로드 디렉터리, PHP 실행 설정, 자격 증명이 포함된 구성 파일을 확인하세요. 루프백 리스너는 프록시나 SSH 터널을 통해 접근할 수 있습니다. 로컬 리스너에 지정된 가상 호스트로 접근하려면 의도한 `Host` 헤더를 보내거나 올바른 주소와 포트를 지정해 `curl --resolve`를 사용하세요. 가상 호스트 열거를 통해 기본 응답에 없는 이름도 확인할 수 있습니다. Apache에서 `.htaccess` 재정의를 허용하는지, 업로드 경로에서 PHP를 실행할 수 있는지 확인한 다음에야 쓰기 가능한 업로드 디렉터리를 코드 실행 경로로 간주하세요. 배포된 JavaScript 소스 맵은 소스 경로나 클라이언트 측 비밀 정보를 노출할 수 있습니다. 복구한 값은 단서로 취급하고 실제 권한을 확인하세요. 웹 관련 점검은 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 및 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)를 참조하세요.

[mpm-itk](https://mpm-itk.sesse.net/)를 사용하는 Apache에서 `AssignUserID`가 활성화되어 있으면 가상 호스트를 다른 사용자 및 그룹으로 실행할 수 있습니다. 권한이 낮은 계정이 해당 호스트의 `DocumentRoot`에 스크립트를 쓸 수 있다면, 접근 가능한 경로에서 실제로 할당된 ID로 스크립트가 실행되는지 검토하세요. 모듈이 로드되었는지, 실제 적용되는 가상 호스트 설정(표현식 기반 ID 재정의 포함), 디렉터리의 쓰기 및 검색 권한, 스크립트 핸들러, 리스너 접근성을 확인하세요. 강조 표시된 지시문이나 쓰기 가능한 디렉터리만으로는 사용자 간 실행이 입증되지 않습니다.

웹 서버를 통해 공개된 홈 디렉터리에서는 실제 `.ssh` 디렉터리가 비공개여도 SSH 인증 파일의 백업 아카이브가 노출될 수 있습니다. 예를 들어, [Nostromo의 `homedirs_public` 설정](https://www.nazgul.ch/dev/nostromo_man.html)은 사용자 홈에서 제공할 하위 디렉터리를 선택합니다. 경로만 확인된 아카이브는 단서일 뿐입니다. 서버의 실제 매핑, 로컬 읽기 가능 여부 또는 HTTP 인증, 아카이브 내용, 개인 키의 암호문, 해당 계정이 실제로 그 키를 허용하는지 확인하세요. 일반적인 호스트 열거 중에는 아카이브를 추출하거나 키 내용을 출력하지 마세요.

권한이 더 높은 로컬 웹 앱의 백업을 읽을 수 있다면, 실제 소스에 접근할 수 없더라도 인증 및 파일 읽기 로직이 드러날 수 있습니다. 백업에 의존하기 전에 배포된 서비스와 비교하세요. 특히 앱이 호출자가 제어하는 텍스트 뒤에 비밀 값과 역할 플래그를 붙여 암호화해 쿠키를 만들고, 결정론적 ECB 블록을 사용하며, 선택한 텍스트에 대해 새 쿠키를 반환하고, 나중에 복호화된 값을 이스케이프되지 않은 구분자로 나눈다면 검토가 필요합니다. [NIST는 ECB의 독립적이고 반복 가능한 블록 매핑을 설명합니다](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a). 이 특성은 선택한 입력을 비교하는 데 활용될 수 있지만, 그 자체로 더 높은 역할을 부여하지는 않습니다. 실제 경로, 세션 선행 조건, 정확한 파서 및 데이터 흐름, 서비스 ID, 별도의 권한 작업 또는 파일 읽기 경로를 확인하세요. 수동 인벤토리에서는 백업 메타데이터와 리스너 소유권을 보고하고, 아카이브 내용을 읽거나 인증 프로브를 보내지 마세요.

동일한 소스 검토 방식은 사용자 지정 SSH 기반 인터페이스와 같은 권한이 있는 **비 HTTP** 루프백 서비스에도 적용됩니다. 접근 가능한 소스 백업에서 호출자가 파일 경로를 지정할 수 있는 명령을 확인했다면 인증 게이트, 경로 처리 방식, 파일을 열기 전에 해석된 경로가 의도한 디렉터리 내부에 있는지 검증하는지 확인하세요. Go의 [`filepath.Join`](https://pkg.go.dev/path/filepath#Join)은 경로를 정리하지만 그 경로가 지정된 범위 안에 있도록 강제하지는 않습니다. 백업이 실행 중인 빌드와 일치하는지, 리스너에 접근할 수 있는지, 권한이 낮은 계정이 해당 명령을 사용할 수 있는지, 프로세스가 대상 파일을 읽을 수 있는지 확인하세요. 읽을 수 있는 SSH 키를 보유한 사실은 별도의 로그인 정책 문제입니다. 자동화된 출력에 아카이브 내용을 추출하거나 키를 넣지 말고 소스 아카이브 경로와 서비스 소유권을 보고하세요.

TCP 루프백에서 수신 대기하는 PHP-FPM 풀은 웹사이트에 인증이 설정되어 있어도 다른 로컬 계정에서 접근할 수 있습니다. [PHP는 FastCGI에 연결할 수 있는 클라이언트가 `auto_prepend_file`을 포함한 요청 설정을 제어할 수 있다고 경고합니다](https://www.php.net/manual/en/install.fpm.php). 풀의 `listen` 및 `listen.allowed_clients` 설정과 실제 리스너, 워커 UID, 기존 스크립트 경로, `security.limit_extensions` 또는 `php_admin_value` 제한을 함께 검토하세요. 풀 구성 파일의 `env[...]` 지시문에는 자격 증명이 포함될 수 있으므로 자동 인벤토리에서는 내용 대신 경로를 보고해야 합니다. 구성 파일이나 포트만으로 사용자 간 실행 경로가 입증되지는 않습니다. 프로토콜 세부 정보는 [FastCGI 가이드](../../network-services-pentesting/9000-pentesting-fastcgi.md)를 참조하세요.

권한이 있는 로컬 API에서는 코드 실행뿐 아니라 권한 부여 흐름도 추적하세요. 권한이 낮은 계정이 변경할 수 있는 데이터베이스 역할이 API 경로를 열어줄 수 있지만, 그다음 경계는 해당 경로의 구현에 달려 있습니다. 예를 들어 요청 JSON을 JavaScript 객체에 병합한 다음 [`child_process.exec`](https://nodejs.org/api/child_process.html)를 호출한다면 [prototype-pollution-to-execution 데이터 흐름](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)을 검토해야 합니다. 실제 병합 라이브러리 및 버전, 입력 검증, 접근 가능한 경로, 프로세스 ID, 자식 프로세스 옵션을 확인하세요. root 소유 Node 리스너나 취약할 수 있는 의존성 이름만으로는 단서일 뿐입니다.

파일 기반 CMS 저장소에는 일반적인 `.php` 구성 파일 외부에 관리자 암호 검증 정보가 있을 수 있습니다. 예를 들면 사이트의 `data/database.js` 또는 `data/settings/pass.php`입니다. 수동으로 검토하기 전에 파일 소유권과 읽기 가능 여부를 확인하고, 자동화된 공유 출력에 해시를 포함하지 마세요. 복구 가능한 애플리케이션 암호는 Unix 계정과는 별개의 권한 경계입니다. 재사용이 주장되면 해당 계정과 허용된 인증 방식을 대상으로 확인하세요.

애플리케이션의 인증 컨트롤러에는 구성 파일이 아니라 소스 코드에 로그인 암호가 그대로 들어 있을 수도 있습니다. 권한이 낮은 사용자가 배포된 컨트롤러를 읽을 수 있다면, 로컬에서 인증 비교 로직을 검토하고 공유 열거 출력에는 값을 포함하지 마세요. 해당 코드 경로가 활성 상태인지, 암호가 애플리케이션에서 유효한지, 권한이 더 높은 별도의 Unix 계정이 같은 암호를 실제로 허용하는지 확인한 뒤에야 로컬 권한 상승을 주장할 수 있습니다. 컨트롤러 파일 이름만으로는 검토할 단서일 뿐입니다.

Dolibarr는 `htdocs/conf/conf.php`에 `dolibarr_main_db_pass`를 포함한 데이터베이스 연결 설정을 저장합니다([구성 참조](https://wiki.dolibarr.org/index.php/Configuration_file)). 읽을 수 있는 파일은 자격 증명의 단서일 뿐입니다. 별도로 확인된 계정 암호 재사용이나 다른 데이터베이스 권한이 있어야 로컬 권한 상승으로 이어집니다. 먼저 권한을 확인하고 자동화된 출력에 값을 표시하지 마세요.

GitLab Linux 패키지의 구성 파일은 일반적으로 `/etc/gitlab/gitlab.rb`이지만 배포 환경에 따라 다른 위치에 읽을 수 있는 사본이 남아 있을 수 있습니다. [GitLab 문서](https://docs.gitlab.com/omnibus/settings/smtp/)에 따르면 이 파일에는 `gitlab_rails['smtp_password']`가 들어갈 수 있지만, 암호화된 SMTP 설정에서는 암호가 일반 텍스트 파일 외부에 저장될 수도 있습니다. 읽을 수 있는 구성은 자격 증명의 단서로 취급하세요. 암호 재사용을 주장하기 전에 해당 설정이 활성 상태인지, 자격 증명이 현재 유효한지, 권한이 더 높은 특정 계정이 이를 허용하는지 확인하세요. 별도로, [GitLab은 `gitlab-ctl reconfigure` 중 root 권한으로 `gitlab.rb`를 Ruby 코드로 실행합니다](https://docs.gitlab.com/omnibus/settings/configuration/). 쓰기 가능한 활성 파일이나 포함된 `from_file`은 실제 권한 있는 재구성 경로가 있어야 실행 취약점으로 판단할 수 있습니다. 구성 미리보기에는 자격 증명 값이 노출될 수 있으므로 출력을 민감 정보로 취급하고, 대신 경로와 권한을 공유하세요.

자체 호스팅 Mattermost 설치는 `/opt/mattermost/config/config.json`에 `SqlSettings.DataSource`를 저장할 수 있습니다. [Mattermost 문서](https://docs.mattermost.com/deployment-guide/server/troubleshooting)는 이 일반적인 경로와 활성 구성을 데이터베이스에 저장하는 배포 방식도 설명합니다. 읽을 수 있는 파일은 애플리케이션 데이터베이스 자격 증명을 노출할 수 있지만, 데이터베이스 접근이나 Unix root 접근이 입증되는 것은 아닙니다. 활성 구성의 출처, 데이터베이스 역할의 실제 권한, 별도로 복구한 애플리케이션 암호의 존재 여부, 해당 암호가 권한이 더 높은 특정 Unix 계정에서 작동하는지 확인하세요. 암호 해시 형식은 Mattermost 버전에 따라 달라질 수 있습니다. 열거 중에는 연결 문자열을 출력하거나 데이터베이스에 쿼리하지 말고 구성 경로와 접근 메타데이터를 기록하세요.

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

기본 응답 크기 또는 다른 안정적인 기준과 가상 호스트 결과를 비교해, 추측한 이름이 모두 유효한 것처럼 보이지 않도록 하세요. 소스 맵은 실제로 배포되어 있거나 다른 방식으로 읽을 수 있을 때만 유용합니다.

Reverse proxy는 애플리케이션이 신뢰하는 클라이언트 헤더를 바꿀 수 있습니다. `X-Forwarded-For`, `X-Forwarded-Host` 또는 유사한 헤더가 요청자의 신원을 확립한다고 가정하기 전에 직접 요청과 proxy를 거친 요청을 비교하세요. Proxy와 애플리케이션 설정을 함께 검토하세요.

PHP가 `$_SERVER['HTTP_X_FORWARDED_FOR']`를 [`system()`](https://www.php.net/manual/en/function.system.php)에 전달되는 문자열에 복사한다면, 요청 경로에서 호출자가 제공한 헤더를 전달할 수 있는지, 그리고 shell 메타문자가 해당 문자열에 그대로 들어가는지 검토하세요. `sudo iptables` 같은 명령이 문자열 앞에 포함되어 있어도, 뒤에 shell 구분자로 연결된 명령이 root 권한으로 실행되는 것은 아닙니다. 별도의 유효한 sudo 규칙이 권한 상승을 허용하지 않는 한 해당 명령은 웹 worker 권한으로 실행됩니다. root 경로를 주장하기 전에 worker의 신원, 정확한 `sudo -l` 권한과 인증 요건, 명령의 인수 경계를 확인하세요. 일반적인 호스트 열거 중에는 injection probe를 보내지 말고 소스와 정책을 검사하세요.

## 액세스 로그의 로그인 자격 증명

애플리케이션이 `GET`으로 로그인 양식을 제출하면 사용자 이름과 비밀번호가 요청 URI의 query parameter가 될 수 있습니다. `POST` 요청에도 query string이 포함될 수 있습니다. `POST`를 사용하더라도 관련 없는 양식 필드에 입력한 비밀번호 등 URI에 실수로 들어간 비밀 정보가 숨겨지는 것은 아닙니다. 설정된 형식에서 `%r`을 사용하는 경우, [Apache의 일반적인 액세스 로그 요청 행](https://httpd.apache.org/docs/2.4/logs.html)에는 query string을 포함한 method와 URI가 기록됩니다. 따라서 일부 Linux 시스템의 `adm` 그룹처럼 해당 로그를 읽을 수 있는 계정에서 자격 증명의 단서를 찾을 수 있습니다. 실제 로그 형식과 권한을 확인한 다음, 해당 값이 비밀 정보인지, 계정이 이를 허용하는지, 권한 경계를 넘는지 검증하세요. 요청 본문이 로그에 기록되었다고 가정하지 말고, 후보 값을 공유 출력에 복사하지 마세요.

읽을 수 있는 액세스 로그만 확인하고 자격 증명 값이 공유 명령 출력에 포함되지 않도록 하세요. 긴 요청 행에는 referrer와 user agent도 포함될 수 있으므로, 짧은 행만 필터링하면 찾으려는 요청을 놓칠 수 있습니다. Apache, httpd, Nginx의 일반적인 액세스 로그 위치는 `/var/log/apache2/access.log`, `/var/log/httpd/access_log`, `/var/log/nginx/access.log`입니다. 순환된 로그에 이전 자격 증명이 남아 있을 수 있습니다. [LFI를 통한 로그 파일 액세스](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)도 같은 데이터에 접근할 수 있는 관련 경로입니다.

애플리케이션 인증 로그에는 로그인 실패 시 **사용자 이름** 필드에 실수로 입력한 비밀번호가 노출될 수도 있습니다. 먼저 해당 로그를 읽을 수 있는지, 로그 형식에 제출된 사용자 이름이 기록되는지 확인하세요. 관련된 부분만 로컬에서 조금 확인하고 후보 자격 증명을 공유 출력에 복사하지 마세요. 비밀번호처럼 보이는 사용자 이름은 단서일 뿐, 유효한 비밀번호나 더 높은 권한을 입증하지는 않습니다. 권한 전환을 주장하기 전에 해당 계정을 확인하고, 특정 서비스 또는 Unix 계정에서 자격 증명이 재사용되는지 검증하세요.

다른 신원으로 실행되는 예약된 클라이언트가 웹 로그인 handler에 자격 증명을 제출한다면, 쓰기 가능한 handler를 별도로 검토해야 합니다. **활성화된** handler에 대한 쓰기 권한, 클라이언트의 실제 일정과 요청 경로, 클라이언트가 보내는 자격 증명, 그리고 해당 애플리케이션 비밀번호가 더 높은 권한의 운영체제 계정에도 유효한지 확인하세요. 쓰기 가능한 페이지나 반복 실행되는 프로세스만으로는 해당 권한 전환이 입증되지 않습니다. 수동 인벤토리에서는 handler를 변경하거나 비밀번호를 수집하지 말고 경로 권한과 작업 메타데이터를 보고하세요.

FTP event logging이 활성화되어 있으면 Suricata의 EVE JSON 로그에도 FTP `USER` 및 `PASS` 명령과 해당 `command_data`가 기록될 수 있습니다. 관련된 부분만 로컬에서 조금 검토하기 전에 순환되거나 압축된 파일을 포함해 `/var/log/suricata/eve*.json*`을 읽을 수 있는지 확인하세요. EVE 파일을 읽을 수 있다는 것은 단서일 뿐입니다. FTP event가 기록되었는지, 데이터에 사용할 수 있는 자격 증명이 포함되어 있는지, 권한 경계를 넘는지 확인하세요. 공유 열거 출력에 `command_data`를 표시하지 마세요. Suricata 문서에는 [FTP event 필드](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)와 [EVE 순환 및 파일 이름 변형](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)이 설명되어 있습니다.

## 생성된 Apache 설정과 piped log

[remco](https://github.com/HeavyHorst/remco)는 key/value backend를 감시하고, template을 Apache 설정 파일로 렌더링한 뒤 reload 명령을 실행할 수 있습니다. 실행 중인 remco 프로세스의 신원, 설정된 template 소스와 대상, 감시하는 key prefix, 그리고 backend 값이 `ServerName` 같은 Apache directive에 직접 삽입되는지 확인하세요. 로컬 backend listener만으로 현재 사용자가 감시 중인 key를 쓸 수 있다고 단정할 수 없습니다. 권한 상승을 주장하기 전에 backend 인증 및 권한을 확인하세요.

쓰기 가능한 backend 값에 escape되지 않은 줄바꿈이 있으면 하나의 directive 값이 여러 Apache directive로 바뀔 수 있습니다. [Apache piped log](https://httpd.apache.org/docs/2.4/logs.html#piped)는 특히 민감합니다. `CustomLog` 또는 `ErrorLog`에 `|` 명령을 설정하면 보통 root인 상위 httpd의 신원으로 helper가 시작되며, `|$`를 사용하면 Apache가 shell을 사용합니다. 열거 중에는 backend 데이터를 변경하거나 서비스를 재시작하지 말고, 생성된 설정과 reload 경로를 검토하세요. 인수에 비밀 정보가 포함될 수 있으므로 전체 piped 명령은 비공개로 유지하세요.

## 인증 및 서비스 신원

Monit의 제어 파일은 보통 `~/.monitrc` 또는 `/etc/monitrc`이지만, `monit -c`로 다른 경로를 지정할 수 있습니다. 읽을 수 있는 파일에는 웹 인터페이스를 위한 `set httpd` 및 `allow user:password` 항목이 있을 수 있으며, 보통 로컬 포트 2812를 사용합니다. 파일을 검토하기 전에 소유자와 권한을 확인하고, 비밀번호 값이 공유 열거 출력에 포함되지 않도록 하세요. 웹 자격 증명은 설정된 Monit 역할에만 권한을 부여하며, 읽기 전용 사용자는 제어 작업을 실행할 수 없습니다. 별도의 Unix 계정 권한 상승을 주장하려면 비밀번호 재사용이 확인되거나, 인증된 역할이 실제로 실행할 수 있는 권한 있는 Monit 작업이 확인되어야 합니다. [Monit 제어 파일 및 인증 문서](https://www.mmonit.com/monit/documentation/monit.html)를 참조하세요.

Webmin의 경우 `/etc/webmin/miniserv.conf`에는 서버 설정이, `/etc/webmin/webmin.acl`에는 사용자가 액세스할 수 있는 모듈이 기록됩니다. [Webmin 문서에는 모듈 권한 경계](https://webmin.com/docs/development/creating-modules/)가 설명되어 있습니다. Unix 비밀번호나 읽을 수 있는 ACL 파일만으로는 Webmin 세션 권한이 부여되지 않습니다. 실제 인증 매핑, 접근 가능한 listener, 인증된 계정, 유효한 Package Updates 모듈 권한, 설치된 코드 또는 공급업체 수정 사항, Webmin 프로세스의 신원을 확인하세요. 영향을 받는 1.910 이하 빌드에서는 [CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840)으로 인해 해당 모듈 권한이 있는 계정이 업데이트 handler를 통해 명령을 실행할 수 있었습니다. 수동 열거 중에는 자격 증명을 출력하거나 업데이트를 시도하지 말고 설정 경로와 권한을 보고하세요.

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md)는 서비스별 인증을 관리합니다. 쓰기 가능한 정책 또는 모듈 경로를 통해 로그인 동작을 변경할 수 있습니다.
- LDAP/SSSD 설정에서 디렉터리 엔드포인트, bind identity, 액세스 규칙을 확인할 수 있습니다. 복구한 bind password로 현재 OS 계정의 권한을 넘어 LDAP 쿼리를 수행할 수 있습니다. 정확한 bind identity와 디렉터리 ACL을 테스트하세요. 비밀 정보를 확인하기 전에 파일 권한을 검토하세요. 티켓 및 디렉터리 사용에 대해서는 [Linux Active Directory](../user-information/linux-active-directory.md)와 [FreeIPA](freeipa-pentesting.md)를 참고하세요.
- Postfix alias는 수신된 메일을 로컬 명령으로 전달할 수 있습니다. 권한이 낮은 사용자가 참조된 스크립트를 변경할 수 있다면, 메일 전달로 해당 사용자의 코드가 전달 identity 권한으로 실행될 수 있습니다. 이 경로가 가능하다고 판단하기 전에 alias map과 스크립트 소유권을 확인하세요. [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md)을 참고하세요.
- Jenkins 및 기타 CI 서비스는 강력한 로컬 계정으로 job을 실행할 수 있습니다. Pipeline이나 plugin을 테스트하기 전에 서비스 사용자, 쓰기 가능한 job/workspace 경로, 로컬 관리 인터페이스를 확인하세요. 또한 **job에서 사용할 수 있는 credentials**와 해당 credentials로 인증할 수 있는 계정도 검토하세요. [SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/)을 사용하는 Pipeline은 Jenkins 자체가 권한이 더 낮은 Unix 계정으로 실행되더라도 SSH credential의 사용자로 호스트에 접근할 수 있습니다. 현재 Jenkins identity에 `Job/Create`, `Job/Configure` 또는 Pipeline을 변경할 수 있는 다른 유효한 권한 경로가 있는지, 해당 job에서 credential을 사용할 수 있는지, 대상 SSH 계정이 키를 허용하는지 확인한 후에 호스트 권한 상승이 가능하다고 판단하세요. credential의 표시 이름이나 ID만으로는 이 조건 중 어느 것도 확인할 수 없습니다. Jenkins는 job 생성자와, 흔히 job 설정 권한자도 자신의 범위에서 사용할 수 있는 credentials를 임의로 이용할 수 있다고 경고합니다. 따라서 [credential scope](https://www.jenkins.io/doc/book/security/credentials/)와 [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/)는 서비스 UID만큼 중요합니다. 공유되는 열거 결과에 credential 값과 private key를 포함하지 마세요.

## Gogs repository file writes

로컬 Gogs 서비스의 경우 `gogs web` 프로세스 소유자와 실행 파일 버전, `custom/conf/app.ini`를 함께 확인하세요. 설정에서 서비스 identity, repository root, listener 주소, 등록 비활성화 여부를 확인할 수 있습니다. loopback 전용 listener도 로컬 사용자가 접근할 수 있습니다. 0.13.3 이하 Gogs 버전에는 인증된 `PutContents` symlink 파일 쓰기 취약점이 있습니다([CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)). repository writer는 symlink를 commit한 다음 API 쓰기 작업이 해당 symlink를 거치도록 할 수 있습니다. 파일 접근은 Gogs 프로세스의 권한으로 수행되므로 root 소유 인스턴스라면 신속히 대응해야 합니다. 해당 경로를 실제로 사용할 수 있다고 판단하기 전에 배포된 수정 사항과 인증 요구 사항을 확인하세요. API 오류가 발생했다고 해서 파일 쓰기가 실패했다는 뜻은 아닙니다.

## Gitea repository-description XSS and privileged viewers

Gitea 1.22.0에서는 repository description에 저장된 JavaScript를 사용할 수 있었습니다([CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)). 1.22.1에서 수정되었습니다. description을 편집할 수 있는 사용자는 더 높은 권한을 가진 사용자가 repository를 보고 악성 링크를 활성화할 경우 해당 브라우저 세션에 영향을 줄 수 있습니다. 그러면 해당 브라우저 identity를 통해 비공개 repository 콘텐츠나 기타 애플리케이션 데이터가 노출될 수 있습니다. 별도의 로컬 권한 상승이 이루어지려면 재사용된 관리자 password와 같이 해당 콘텐츠를 통해 접근 가능한 credential 또는 권한이 필요합니다. Gitea 프로세스 소유자만으로는 root 영향이 입증되지 않습니다. 이 공격 경로가 성립한다고 판단하기 전에 배포된 버전, description 편집 권한, viewer의 사용 흐름, 실제 브라우저 상호작용을 확인하세요.

## Cobbler provisioning API

Cobbler의 관리 서비스는 XML-RPC API를 노출하며, 일반적으로 포트 `25151`을 사용합니다. 영향을 평가하기 전에 listener와 `cobblerd` 프로세스 소유자를 확인하세요. loopback 전용 API도 호스트의 사용자가 접근할 수 있습니다. `/etc/cobbler/modules.conf`의 인증 및 권한 부여 모듈, `/etc/cobbler/settings` 또는 `/etc/cobbler/settings.yaml`의 서비스 설정, 그리고 `/etc/cobbler/users.conf`, `/etc/cobbler/users.digest`, `/var/lib/cobbler/web.ss`의 권한을 검토하세요. digest 및 공유 비밀 파일에는 credential 정보가 있으므로, 기본적으로 내용을 출력하지 말고 읽기 가능 여부만 기록하세요.

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533**은 Cobbler 3.0.0~3.2.2 및 3.3.0~3.3.6의 XML-RPC 인증 우회 취약점입니다. 공유 secret을 읽는 과정에서 오류가 발생하면 예측 가능한 값인 `-1`이 반환되었고, API는 이를 password로 허용했습니다. 수정 버전은 각각 3.2.3 및 3.3.7입니다. 패키지 버전은 단서일 뿐이므로, 노출을 보고하기 전에 배포된 코드와 backport된 수정 사항이 있는지 확인하세요.

`cobblerd`가 root로 실행될 때 인증된 API 세션은 권한이 높은 코드 실행 경로가 될 수 있습니다. 취약한 구현에서는 `background_import`가 사용자가 제어하는 `rsync_flags`를 shell command에 전달하며, 사용자가 제어하는 Cheetah autoinstall template을 렌더링하면 Python이 실행될 수 있습니다. 두 경로 중 어느 하나를 테스트하기 전에 API 권한과 설치된 버전을 확인하세요. 관리 API에 대한 접근을 제한하고, 인증 우회 취약점을 패치하며, configuration 및 credential 파일은 service 관리자만 읽을 수 있도록 하세요.

## Motion 및 motionEye configuration

`/etc/motioneye/motioneye.conf`에서 `conf_path`를 확인한 다음, 해당 디렉터리의 `motion.conf`와 소수의 `camera-*.conf` 파일을 검토하세요. 읽을 수 있는 `# @admin_password` hash가 있는지 보고하되, 값을 출력하지 마세요. [이전 motionEye release에서는 이 파일에 광범위한 읽기 권한이 설정되었습니다](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67). 수정 사항은 0.44.0에 포함되어 있습니다. Motion의 `webcontrol_port`, `webcontrol_parms`, `webcontrol_auth_method`, `webcontrol_localhost` 설정을 함께 확인하세요. 인증이 비활성화된 상태에서 고급 제어(`2` 또는 `3`)가 활성화되어 있으면, loopback listener에서도 로컬 사용자가 강력한 작업을 수행할 수 있습니다. [Motion 문서에서 값과 기본값을 확인할 수 있습니다](https://motion-project.github.io/motion_config.html).

0.43.1b5 이전 motionEye에서 admin session을 보유한 사용자는 Motion이 처리하는 camera filename 설정을 통해 command execution을 일으킬 수 있었습니다([CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)). 권한 상승이라고 단정하기 전에 실행 중인 버전, service identity, 사용 가능한 인증 경로, camera가 구성되어 있는지 확인하세요. configuration만으로는 service가 실행 중이거나 권한이 높다는 사실을 입증할 수 없습니다.

service 이름이나 설치된 package는 단서일 뿐입니다. 권한 경계는 접근 가능한 입력, process identity, 쓰기 가능한 configuration, 그리고 최종적으로 제어되는 command 또는 파일이 함께 결정합니다.

## 로컬 AWS emulator 및 저장된 credential

호스트 사용자는 container에서 실행 중인 AWS 호환 emulator에 공개된 loopback endpoint를 통해 접근할 수 있습니다. [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 또는 [KMS](https://docs.localstack.cloud/aws/services/kms/)에 대한 접근을 평가하기 전에, 현재 활성화된 listener, client가 선택한 endpoint와 account, emulator에 설치된 authorization 설정을 대조 확인하세요. LocalStack에서 [IAM policy enforcement는 별도의 설정입니다](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/). credential 파일, IAM policy 또는 listener만으로 유효한 API 권한을 추론하지 마세요. 설치된 release 및 configuration에서 실제 동작을 확인하세요.

저장된 secret은 현재 API identity로 가져올 수 있고 별도의 권한이 더 높은 account가 복구한 credential을 받아들일 때만 로컬 권한 상승에 유용합니다. 암호화된 로컬 blob도 파일 읽기 권한, 일치하는 사용 가능한 KMS key 및 algorithm, 유효한 decrypt 권한이 있어야 합니다. [비대칭 KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)의 경우 decrypt 요청에 blob을 암호화할 때 사용한 algorithm을 지정해야 합니다. 자동화된 호스트 inventory에서는 process, listener, configuration 경로, 파일 권한에 대한 증거만 수집하세요. 일반적인 열거 과정에서 secret 값이나 복호화된 평문을 요청하거나 출력하지 마세요.
{{#include ../../banners/hacktricks-training.md}}
