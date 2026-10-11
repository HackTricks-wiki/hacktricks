# 로컬 웹 및 인증 서비스

{{#include ../../banners/hacktricks-training.md}}

Linux 셸을 사용하면 프로세스 인수, 리스너, 유닛 파일, 설정, 로그, 로컬 전용 인터페이스 등 호스트 측에서 웹 및 인증 서비스를 살펴볼 수 있습니다. 이 정보를 활용해 접근 가능한 서비스가 실제로 사용하는 계정과 파일을 확인하세요.

## 로컬 웹 스택 파악하기

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

가상 호스트 이름, 문서 루트, 프록시 라우트, 업로드 디렉터리, PHP 실행 설정, 자격 증명이 포함된 설정 파일을 확인하세요. 루프백 리스너는 프록시나 SSH 터널을 통해 접근할 수 있습니다. 로컬 리스너에 지정된 가상 호스트로 요청을 보내려면 원하는 `Host` 헤더를 보내거나 올바른 주소와 포트로 `curl --resolve`를 사용하세요. 가상 호스트 열거를 통해 기본 응답에 없는 이름도 발견할 수 있습니다. Apache가 `.htaccess` 재정의를 허용하는지, 업로드 경로에서 PHP를 실행할 수 있는지 확인한 뒤에야 쓰기 가능한 업로드 디렉터리를 코드 실행 경로로 판단하세요. 배포된 JavaScript 소스 맵은 소스 경로나 클라이언트 측 비밀을 노출할 수 있습니다. 복구한 값은 단서로 취급하고 실제 권한을 확인하세요. 웹 관련 점검은 [Apache](../../network-services-pentesting/pentesting-web/apache.md) 및 [Nginx](../../network-services-pentesting/pentesting-web/nginx.md)를 참조하세요.

Apache에서 [mpm-itk](https://mpm-itk.sesse.net/)을 사용하는 경우 활성화된 `AssignUserID`가 가상 호스트를 다른 사용자 및 그룹으로 실행할 수 있습니다. 권한이 낮은 계정이 해당 호스트의 `DocumentRoot`에 스크립트를 쓸 수 있다면, 실제로 접근 가능한 라우트가 그 스크립트를 할당된 ID로 실행하는지 검토하세요. 모듈이 로드되었는지, 가상 호스트의 유효 설정(표현식 기반 ID 재정의 포함), 디렉터리의 쓰기 및 검색 권한, 스크립트 핸들러, 리스너 접근성을 확인하세요. 강조된 지시문이나 쓰기 가능한 디렉터리만으로는 사용자 간 실행이 입증되지 않습니다.

웹 서버를 통해 공개된 홈 디렉터리에서는 실제 `.ssh` 디렉터리가 비공개여도 SSH ID 파일의 백업 아카이브가 노출될 수 있습니다. 예를 들어 [Nostromo의 `homedirs_public` 설정](https://www.nazgul.ch/dev/nostromo_man.html)은 사용자 홈에서 제공할 하위 디렉터리를 지정합니다. 경로만 일치하는 아카이브는 조사 단서일 뿐입니다. 서버의 유효한 매핑, 로컬에서 읽을 수 있는지 또는 HTTP 인증이 적용되는지, 아카이브 내용, 개인 키의 암호문, 해당 계정이 실제로 그 키를 허용하는지 확인하세요. 일반적인 호스트 열거 중에는 아카이브를 추출하거나 키 내용을 출력하지 마세요.

권한이 더 높은 로컬 웹 앱의 백업을 읽을 수 있으면, 실행 중인 소스에 접근할 수 없어도 인증 및 파일 읽기 로직이 드러날 수 있습니다. 백업을 신뢰하기 전에 배포된 서비스와 비교하세요. 특히 호출자가 제어하는 텍스트 뒤에 비밀값과 역할 플래그를 붙여 암호화해 쿠키를 만들고, 앱이 결정적 ECB 블록을 사용하며, 선택한 텍스트에 대한 새 쿠키를 반환하고, 나중에 복호화된 값을 이스케이프되지 않은 구분자로 분할한다면 검토가 필요합니다. [NIST는 ECB의 독립적이고 반복 가능한 블록 매핑을 설명합니다](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a). 이 특성은 선택 입력 비교에 활용될 수 있지만, 그 자체로 상위 역할을 부여하지는 않습니다. 실제 라우트, 세션 전제 조건, 정확한 파서 및 데이터 흐름, 서비스 ID, 별도의 권한 상승 작업 또는 파일 읽기 경로를 확인하세요. 수동 인벤토리에서는 백업 메타데이터와 리스너 소유권을 보고하되, 아카이브 내용을 읽거나 인증 프로브를 보내지 마세요.

동일한 소스 검토 방식은 사용자 지정 SSH 기반 인터페이스 같은 권한이 높은 **비 HTTP** 루프백 서비스에도 적용됩니다. 접근 가능한 소스 백업에서 호출자가 파일 경로를 지정할 수 있는 명령을 발견했다면 인증 게이트, 경로 해석 방식, 그리고 파일을 열기 전에 해석된 경로가 의도된 디렉터리 아래에 있는지 검증하는지 확인하세요. Go의 [`filepath.Join`](https://pkg.go.dev/path/filepath#Join)은 경로를 정리하지만 해당 디렉터리 내부로 경로를 제한하지는 않습니다. 백업이 실행 중인 빌드와 일치하는지, 리스너에 접근할 수 있는지, 권한이 낮은 계정이 명령을 사용할 수 있는지, 프로세스가 대상 파일을 읽을 수 있는지 확인하세요. 읽을 수 있는 SSH 키를 가지고 있다는 사실은 별개의 로그인 정책 문제입니다. 소스 아카이브 경로와 서비스 소유권을 보고하되, 자동화된 출력에 아카이브 내용이나 키를 추출하지 마세요.

TCP 루프백에서 수신 대기하는 PHP-FPM 풀은 웹사이트에 인증이 설정되어 있어도 다른 로컬 계정에서 접근할 수 있습니다. [PHP는 FastCGI에 연결할 수 있는 클라이언트가 `auto_prepend_file`을 포함한 요청 설정을 제어할 수 있다고 경고합니다](https://www.php.net/manual/en/install.fpm.php). 풀의 `listen` 및 `listen.allowed_clients` 설정을 실제 리스너, 워커 UID, 기존 스크립트 경로, `security.limit_extensions` 또는 `php_admin_value` 제한과 함께 검토하세요. 풀 설정 파일의 `env[...]` 지시문에는 자격 증명이 포함될 수 있으므로 자동 인벤토리에서는 파일 내용을 출력하지 말고 경로만 보고해야 합니다. 설정 파일이나 포트가 있다는 사실만으로는 사용자 간 실행 경로가 입증되지 않습니다. 프로토콜 세부 정보는 [FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)를 참조하세요.

권한이 높은 로컬 API에서는 코드 실행뿐 아니라 권한 부여도 추적하세요. 권한이 낮은 계정이 변경할 수 있는 데이터베이스 역할로 API 라우트를 사용할 수 있게 되더라도, 다음 경계는 라우트의 구현에 달려 있습니다. 예를 들어 요청 JSON을 JavaScript 객체에 병합한 뒤 [`child_process.exec`](https://nodejs.org/api/child_process.html)를 호출한다면 [prototype-pollution-to-execution dataflow](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)를 검토해야 합니다. 실제 병합 라이브러리 및 버전, 입력 검증, 접근 가능한 라우트, 프로세스 ID, 자식 프로세스 옵션을 확인하세요. root 소유 Node 리스너나 취약한 의존성 이름만으로는 조사 단서에 불과합니다.

파일 기반 CMS 저장소에는 일반적인 `.php` 설정 파일 외부에 관리자 비밀번호 검증값이 저장될 수 있습니다. 예를 들어 사이트의 `data/database.js`나 `data/settings/pass.php`가 이에 해당합니다. 수동 검토 전에 파일 소유권과 읽기 권한을 확인하고, 해시는 자동화된 공유 출력에 포함하지 마세요. 복구 가능한 애플리케이션 비밀번호와 Unix 계정은 별개의 권한 경계입니다. 재사용이 확인되었다면 해당 계정 및 허용된 인증 방식에 대해 검증하세요.

애플리케이션의 인증 컨트롤러에는 설정 파일이 아니라 소스 코드에 로그인 비밀번호가 그대로 들어 있을 수도 있습니다. 권한이 낮은 사용자가 배포된 컨트롤러를 읽을 수 있다면 인증 비교 로직을 로컬에서 검토하고, 값을 공유용 열거 출력에 포함하지 마세요. 로컬 권한 상승이라고 주장하기 전에 해당 코드 경로가 활성 상태인지, 애플리케이션에서 비밀번호가 유효한지, 별도의 권한이 더 높은 Unix 계정이 같은 비밀번호를 실제로 허용하는지 확인하세요. 컨트롤러 파일명만으로는 검토할 단서일 뿐입니다.

Dolibarr는 데이터베이스 연결 설정을 비롯해 `dolibarr_main_db_pass`를 `htdocs/conf/conf.php`에 저장합니다([configuration reference](https://wiki.dolibarr.org/index.php/Configuration_file)). 읽을 수 있는 파일은 자격 증명에 관한 단서일 뿐입니다. 별도로 확인된 계정 비밀번호 재사용이나 다른 데이터베이스 권한이 있어야 로컬 권한 상승으로 이어질 수 있습니다. 먼저 권한을 확인하고 자동화된 출력에 값을 표시하지 마세요.

GitLab의 Linux 패키지 설정 파일은 일반적으로 `/etc/gitlab/gitlab.rb`이지만, 배포 환경에 따라 읽을 수 있는 사본이 다른 곳에 남아 있을 수 있습니다. [GitLab 문서](https://docs.gitlab.com/omnibus/settings/smtp/)에 따르면 이 파일에는 `gitlab_rails['smtp_password']`가 포함될 수 있지만, 암호화된 SMTP 설정은 비밀번호를 평문 파일 외부에 저장할 수도 있습니다. 읽을 수 있는 설정은 자격 증명에 관한 단서로 취급하세요. 비밀번호 재사용이라고 주장하기 전에 설정이 활성 상태인지, 자격 증명이 현재 유효한지, 특정 권한이 더 높은 계정에서 허용되는지 확인하세요. 별개로 [GitLab은 `gitlab-ctl reconfigure` 중 root 권한으로 `gitlab.rb`를 Ruby 코드로 실행합니다](https://docs.gitlab.com/omnibus/settings/configuration/). 따라서 쓰기 가능한 활성 파일이나 포함된 `from_file`은 실제로 권한이 높은 재구성 경로가 있어야 실행 취약점으로 볼 수 있습니다. 설정 미리보기에서 자격 증명 값이 노출될 수 있으므로 출력은 민감 정보로 취급하고, 경로와 권한만 공유하세요.

자체 호스팅 Mattermost 설치에서는 `/opt/mattermost/config/config.json`에 `SqlSettings.DataSource`가 있을 수 있습니다. [Mattermost 문서](https://docs.mattermost.com/deployment-guide/server/troubleshooting)는 이 일반적인 경로와 활성 설정을 대신 데이터베이스에 저장하는 배포 방식도 설명합니다. 읽을 수 있는 파일은 애플리케이션 데이터베이스 자격 증명을 노출할 수 있지만, 데이터베이스 접근이나 Unix root 접근이 입증되는 것은 아닙니다. 활성 설정의 출처, 데이터베이스 역할의 실제 권한, 별도로 복구된 애플리케이션 비밀번호, 해당 비밀번호가 특정 권한이 더 높은 Unix 계정에서 작동하는지 확인하세요. 비밀번호 해시 형식은 Mattermost 버전에 따라 달라질 수 있습니다. 열거 중에는 연결 문자열이나 데이터베이스 쿼리를 출력하지 말고 설정 경로와 접근 메타데이터를 기록하세요.

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

기본 응답 크기나 다른 안정적인 기준과 가상 호스트 검색 결과를 비교해, 추측한 이름이 모두 유효한 것처럼 보이지 않도록 하세요. 소스 맵은 실제로 배포되어 있거나 다른 방식으로 읽을 수 있을 때만 유용합니다.

Reverse proxy는 애플리케이션이 신뢰하는 클라이언트 헤더를 바꿀 수 있습니다. `X-Forwarded-For`, `X-Forwarded-Host` 또는 유사한 헤더가 호출자의 신원을 입증한다고 가정하기 전에 직접 요청과 proxy를 거친 요청을 비교하세요. Proxy와 애플리케이션 설정을 함께 검토하세요.

PHP가 `$_SERVER['HTTP_X_FORWARDED_FOR']`를 [`system()`](https://www.php.net/manual/en/function.system.php)에 전달되는 문자열에 복사한다면, 요청 경로상 호출자가 직접 제공한 헤더를 보낼 수 있는지, shell 메타문자가 해당 문자열에 변경 없이 전달되는지 검토하세요. 명령 맨 앞에 `sudo iptables`가 포함되어 있다고 해서 뒤에 shell 구분자로 연결된 명령까지 root 권한으로 실행되는 것은 아닙니다. 별도의 유효한 sudo 규칙으로 권한 상승이 허용되지 않는 한, 이후 명령은 web worker 권한으로 실행됩니다. root 경로를 주장하기 전에 worker의 신원, 정확한 `sudo -l` 권한과 인증 요구 사항, 명령 인자 경계를 확인하세요. 일상적인 호스트 열거 중에는 injection probe를 보내지 말고 소스와 정책을 점검하세요.

## 액세스 로그의 로그인 자격 증명

애플리케이션이 `GET`으로 로그인 양식을 제출하면 사용자 이름과 비밀번호가 요청 URI의 query parameter가 될 수 있습니다. `POST` 요청에도 query string이 포함될 수 있습니다. `POST`를 사용해도 관련 없는 양식 필드에 입력한 비밀번호를 포함해 URI에 실수로 들어간 비밀 정보가 숨겨지지는 않습니다. [Apache의 일반적인 액세스 로그 요청 줄](https://httpd.apache.org/docs/2.4/logs.html)은 설정된 형식에서 `%r`을 사용하는 경우 query string을 포함한 method와 URI를 기록합니다. 따라서 일부 Linux 시스템의 `adm` 그룹처럼 해당 로그를 읽을 수 있는 계정에서 자격 증명 단서를 찾을 수 있습니다. 실제 로그 형식과 권한을 확인한 다음, 해당 값이 비밀 정보인지, 계정에서 허용되는지, 권한 경계를 넘는지 검증하세요. 요청 본문이 로그에 기록되었다고 가정하지 말고, 후보 값을 공유 출력에 복사하지 마세요.

읽을 수 있는 액세스 로그만 살펴보고 자격 증명 값은 공유 명령 출력에 포함하지 마세요. 긴 요청 줄에는 referrer와 user agent도 포함될 수 있으므로, 짧은 줄만 필터링하면 찾으려는 요청을 놓칠 수 있습니다. Apache, httpd, Nginx의 일반적인 액세스 로그 위치는 `/var/log/apache2/access.log`, `/var/log/httpd/access_log`, `/var/log/nginx/access.log`입니다. Rotated log에는 오래된 자격 증명이 남아 있을 수 있습니다. [LFI를 통한 로그 파일 접근](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)은 같은 데이터에 접근하는 관련 경로입니다.

애플리케이션 인증 로그에는 로그인 실패 시 **사용자 이름** 필드에 실수로 입력한 비밀번호가 노출될 수도 있습니다. 먼저 로그를 읽을 수 있는지, 형식에 제출된 사용자 이름이 기록되는지 확인하세요. 관련 부분만 소량 로컬에서 살펴보고 후보 자격 증명을 공유 출력에 복사하지 마세요. 비밀번호처럼 보이는 사용자 이름은 단서일 뿐, 유효한 비밀번호나 더 높은 권한의 증거가 아닙니다. 권한 전환을 주장하기 전에 의도된 계정과 특정 서비스 또는 Unix 계정에서의 재사용 여부를 확인하세요.

다른 신원으로 실행되는 예약된 클라이언트가 해당 endpoint에 자격 증명을 제출하는 경우, 쓰기 가능한 web 로그인 handler는 별도로 검토해야 합니다. **활성** handler에 대한 쓰기 권한, 클라이언트의 실제 일정과 요청 경로, 클라이언트가 제출하는 자격 증명의 소유자, 해당 애플리케이션 비밀번호가 더 높은 권한의 운영 체제 계정에서도 독립적으로 유효한지 확인하세요. 쓰기 가능한 페이지나 반복 프로세스만으로는 권한 전환이 입증되지 않습니다. 수동 인벤토리에서는 handler를 변경하거나 비밀번호를 수집하지 말고 경로 권한과 작업 메타데이터를 보고하세요.

Suricata의 EVE JSON 로그에는 FTP event logging이 활성화된 경우 FTP `USER` 및 `PASS` 명령과 `command_data`가 기록될 수도 있습니다. 관련 부분을 소량 로컬에서 살펴보기 전에, rotated 또는 compressed 파일을 포함해 `/var/log/suricata/eve*.json*`을 읽을 수 있는지 확인하세요. EVE 파일을 읽을 수 있다는 사실은 단서일 뿐입니다. FTP event가 기록되었는지, 데이터에 사용 가능한 자격 증명이 포함되어 있는지, 권한 경계를 넘는지 확인하세요. 공유 열거 출력에는 `command_data`를 표시하지 마세요. Suricata 문서에서 [FTP event 필드](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)와 [EVE rotation 및 파일 이름 변형](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)을 확인하세요.

## 생성된 Apache 설정 및 파이프 로그

[remco](https://github.com/HeavyHorst/remco)는 key/value backend를 감시하고, template을 Apache 설정 파일로 렌더링한 뒤 reload 명령을 실행할 수 있습니다. 실행 중인 remco 프로세스의 신원, 설정된 template 소스와 대상, 감시하는 key prefix, backend 값이 `ServerName` 같은 Apache directive에 직접 삽입되는지 확인하세요. 로컬 backend listener가 있다는 사실만으로 현재 사용자가 감시 대상 key를 쓸 수 있다고 볼 수는 없습니다. 권한 상승을 주장하기 전에 backend 인증과 권한을 확인하세요.

쓰기 가능한 backend 값에 escape 처리되지 않은 개행 문자가 있으면, 의도한 directive 값 하나가 추가 Apache directive로 바뀔 수 있습니다. [Apache 파이프 로그](https://httpd.apache.org/docs/2.4/logs.html#piped)는 특히 민감합니다. `|` 명령이 포함된 `CustomLog` 또는 `ErrorLog`는 상위 httpd의 신원으로 helper를 시작하며, 이 신원은 흔히 root입니다. `|$`를 사용하면 Apache는 shell을 사용합니다. 열거 중에는 backend 데이터를 변경하거나 서비스를 재시작하지 말고, 생성된 설정과 reload 경로를 검토하세요. 인자에 비밀 정보가 포함될 수 있으므로 파이프 명령 전체를 비공개로 유지하세요.

## 인증 및 서비스 신원

Monit의 제어 파일은 보통 `~/.monitrc` 또는 `/etc/monitrc`이지만, `monit -c`로 다른 경로를 지정할 수 있습니다. 읽을 수 있는 파일에는 web interface용 `set httpd` 및 `allow user:password` 항목이 있을 수 있으며, 대개 로컬 포트 2812를 사용합니다. 파일을 살펴보기 전에 소유자와 권한을 확인하고, 비밀번호 값을 공유 열거 출력에 포함하지 마세요. Web 자격 증명은 설정된 Monit 역할에만 권한을 부여하며, 읽기 전용 사용자는 제어 작업을 실행할 수 없습니다. 별도의 Unix 계정 권한 상승을 주장하려면 비밀번호 재사용이 확인되거나, 인증된 역할이 실제로 실행할 수 있는 권한 있는 Monit 작업이 있어야 합니다. [Monit 제어 파일 및 인증 문서](https://www.mmonit.com/monit/documentation/monit.html)를 참조하세요.

Webmin의 경우 `/etc/webmin/miniserv.conf`에 서버 설정이 있고 `/etc/webmin/webmin.acl`에는 사용자가 접근할 수 있는 module이 기록됩니다. [Webmin은 module 권한 부여 경계를 문서화하고 있습니다](https://webmin.com/docs/development/creating-modules/). Unix 비밀번호나 읽을 수 있는 ACL 파일만으로는 Webmin session을 얻을 수 없습니다. 실제 인증 매핑, 접근 가능한 listener, 인증된 계정, 유효한 Package Updates module 권한, 설치된 코드 또는 vendor fix, Webmin 프로세스의 신원을 확인하세요. 영향을 받는 1.910 이하 빌드에서는 [CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840)으로 인해 해당 module 권한이 있는 계정이 update handler를 통해 명령을 실행할 수 있었습니다. 수동 열거 중에는 자격 증명을 출력하거나 update를 시도하지 말고 설정 경로와 권한을 보고하세요.

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md)은 서비스별 인증을 관리합니다. 쓰기 가능한 정책 또는 모듈 경로를 통해 로그인 동작을 변경할 수 있습니다.
- LDAP/SSSD 구성에서 디렉터리 엔드포인트, bind identity, 접근 규칙을 확인할 수 있습니다. 복구한 bind password를 사용하면 현재 OS 계정 범위를 넘어 LDAP 쿼리를 실행할 수 있습니다. 정확한 bind identity와 디렉터리 ACL을 테스트하세요. secret을 살펴보기 전에 파일 권한을 검토하세요. 티켓 및 디렉터리 사용은 [Linux Active Directory](../user-information/linux-active-directory.md)와 [FreeIPA](freeipa-pentesting.md)를 참조하세요.
- Postfix alias는 수신 메일을 로컬 명령으로 전달할 수 있습니다. 권한이 낮은 사용자가 지정된 script를 변경할 수 있다면, 메일 전달 시 해당 사용자의 코드가 전달 identity 권한으로 실행될 수 있습니다. 해당 경로를 주장하기 전에 alias map과 script 소유권을 검토하세요. [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md)을 참조하세요.
- Jenkins 및 기타 CI 서비스는 권한이 높은 로컬 계정으로 job을 실행할 수 있습니다. pipeline이나 plugin을 테스트하기 전에 서비스 사용자, 쓰기 가능한 job/workspace 경로, 로컬 관리 인터페이스를 확인하세요. 또한 **job에서 사용할 수 있는 credentials**와 해당 credentials로 인증할 수 있는 계정도 검토하세요. [SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/)을 사용하는 Pipeline은 Jenkins 자체가 권한이 더 낮은 Unix 계정으로 실행되더라도 SSH credential의 사용자로 호스트에 접근할 수 있습니다. 호스트 권한 상승을 주장하기 전에 현재 Jenkins identity에 Pipeline을 변경할 수 있는 `Job/Create`, `Job/Configure` 또는 다른 유효한 방법이 있는지, 해당 job에서 credential을 사용할 수 있는지, 대상 SSH 계정이 해당 key를 허용하는지 확인하세요. credential의 표시 이름이나 ID만으로는 이러한 조건을 입증할 수 없습니다. Jenkins는 job 생성자와 흔히 job 구성자가 자신의 범위에서 사용할 수 있는 credentials를 임의로 사용할 수 있다고 경고합니다. 따라서 [credential scope](https://www.jenkins.io/doc/book/security/credentials/)와 [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/)는 서비스 UID만큼 중요합니다. 공유되는 열거 결과에 credential 값과 private key를 포함하지 마세요.

## Gogs repository file writes

로컬 Gogs 서비스의 경우 `gogs web` 프로세스 소유자와 실행 파일 버전, `custom/conf/app.ini`를 대조하세요. 구성에서 서비스 identity, repository root, listener 주소, 등록 비활성화 여부를 확인할 수 있습니다. loopback 전용 listener도 로컬 사용자가 접근할 수 있습니다. 0.13.3까지의 Gogs 버전에는 인증된 `PutContents` symlink 파일 쓰기 취약점이 있습니다([CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)). repository 작성자는 symlink를 commit한 다음 이를 통해 API 쓰기를 전달할 수 있습니다. 이로 인해 발생하는 파일 접근 권한은 Gogs 프로세스의 권한을 따르므로, root 소유 인스턴스는 신속히 조치해야 합니다. 사용 가능한 경로라고 주장하기 전에 배포된 수정 사항과 인증 요건을 확인하세요. API 오류가 파일 쓰기 실패를 입증하는 것은 아닙니다.

## Gitea repository-description XSS and privileged viewers

Gitea 1.22.0에서는 repository 설명에 저장형 JavaScript를 삽입할 수 있었습니다([CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)). 1.22.1에서 수정되었습니다. 설명을 수정할 수 있는 사용자는 더 높은 권한을 가진 사용자가 repository를 열고 악성 링크를 활성화할 경우 해당 브라우저 세션에 영향을 줄 수 있습니다. 그러면 해당 브라우저 identity를 통해 비공개 repository 콘텐츠나 다른 애플리케이션 데이터를 노출할 수 있습니다. 별도의 로컬 권한 상승을 입증하려면 재사용된 관리자 password처럼 해당 콘텐츠를 통해 접근할 수 있는 credential 또는 권한이 필요합니다. Gitea 프로세스 소유자만으로는 root 권한 영향을 입증할 수 없습니다. 이 공격 경로를 주장하기 전에 배포 버전, 설명 수정 권한, viewer workflow, 실제 브라우저 상호작용을 확인하세요.

## Cobbler provisioning API

Cobbler의 관리 서비스는 일반적으로 `25151` 포트에서 XML-RPC API를 노출합니다. 영향을 평가하기 전에 listener와 `cobblerd` 프로세스 소유자를 확인하세요. loopback 전용 API도 호스트 사용자가 접근할 수 있습니다. `/etc/cobbler/modules.conf`의 인증 및 권한 부여 모듈, `/etc/cobbler/settings` 또는 `/etc/cobbler/settings.yaml`의 서비스 설정, `/etc/cobbler/users.conf`, `/etc/cobbler/users.digest`, `/var/lib/cobbler/web.ss`의 권한을 검토하세요. digest 및 shared-secret 파일에는 credential 정보가 들어 있으므로, 기본적으로 내용을 출력하지 말고 읽기 가능 여부만 기록하세요.

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533**은 Cobbler 3.0.0~3.2.2 및 3.3.0~3.3.6의 XML-RPC 인증 우회 취약점입니다. 공유 비밀값을 읽는 중 오류가 발생하면 예측 가능한 값인 `-1`이 반환되었고, API는 이를 비밀번호로 받아들였습니다. 이에 대한 수정 버전은 3.2.3 및 3.3.7입니다. 패키지 버전은 조사 단서일 뿐입니다. 노출 여부를 보고하기 전에 실제 배포된 코드와 백포트된 수정 사항이 있는지 확인하세요.

`cobblerd`가 root로 실행되는 경우 인증된 API 세션은 권한 있는 코드 실행 경로가 될 수 있습니다. 취약한 구현에서는 `background_import`가 사용자가 제어하는 `rsync_flags`를 셸 명령에 전달하고, 사용자가 제어하는 Cheetah autoinstall 템플릿을 렌더링할 때 Python을 평가할 수 있습니다. 두 경로 중 하나를 테스트하기 전에 API 권한과 설치된 버전을 확인하세요. 관리 API에 대한 접근을 제한하고, 인증 우회 취약점을 패치하며, 설정 및 자격 증명 파일을 서비스 관리자만 읽을 수 있도록 하세요.

## Motion 및 motionEye 설정

`/etc/motioneye/motioneye.conf`에서 `conf_path`를 확인한 다음, 해당 디렉터리의 `motion.conf`와 소수의 `camera-*.conf` 파일을 검토하세요. 읽을 수 있는 `# @admin_password` 해시가 있는지만 확인하고, 해시를 출력하지 마세요. [이전 motionEye 릴리스에서는 읽기 권한이 광범위하게 허용된 상태로 파일을 작성했습니다](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67). 이 문제는 0.44.0에서 수정되었습니다. Motion의 `webcontrol_port`, `webcontrol_parms`, `webcontrol_auth_method`, `webcontrol_localhost` 설정을 함께 확인하세요. 인증이 비활성화된 상태에서 고급 제어(`2` 또는 `3`)가 설정되어 있으면, 루프백 리스너에서도 로컬 사용자가 강력한 작업을 수행할 수 있습니다. [Motion 문서에서 값과 기본값을 확인할 수 있습니다](https://motion-project.github.io/motion_config.html).

0.43.1b5 이전 버전의 motionEye에서는 관리 세션을 통해 카메라 파일명 설정을 명령 실행으로 이어지게 할 수 있었습니다. Motion이 해당 설정을 처리할 때 발생하는 문제입니다([CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)). 권한 상승을 주장하기 전에 실행 중인 버전, 서비스의 실행 계정, 실제로 사용할 수 있는 인증 경로, 카메라 설정 여부를 확인하세요. 설정만으로는 서비스가 실행 중이거나 높은 권한으로 동작한다는 점을 입증할 수 없습니다.

서비스 이름이나 설치된 패키지는 조사 단서일 뿐입니다. 권한 경계는 입력에 접근할 수 있는지, 프로세스가 어떤 계정으로 실행되는지, 설정을 쓸 수 있는지, 그리고 해당 입력이 궁극적으로 어떤 명령이나 파일을 제어하는지에 따라 결정됩니다.

## 로컬 AWS 에뮬레이터 및 저장된 자격 증명

호스트 사용자는 게시된 루프백 엔드포인트를 통해 컨테이너에서 실행 중인 AWS 호환 에뮬레이터에 접근할 수 있습니다. [Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) 또는 [KMS](https://docs.localstack.cloud/aws/services/kms/)에 대한 접근을 평가하기 전에 실제 리스너, 클라이언트가 선택한 엔드포인트와 계정, 에뮬레이터에 설치된 권한 설정을 함께 확인하세요. LocalStack에서는 [IAM 정책 적용이 별도의 설정입니다](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/). 자격 증명 파일, IAM 정책 또는 리스너만으로 실제 API 권한을 추정하지 마세요. 설치된 릴리스와 설정에서 실제 동작을 확인하세요.

저장된 시크릿을 로컬 권한 상승에 활용하려면 현재 API ID로 해당 시크릿을 가져올 수 있어야 하며, 별도의 더 높은 권한을 가진 계정이 복구한 자격 증명을 받아들여야 합니다. 로컬 암호화 blob을 사용하려면 파일 읽기 권한, 일치하는 사용 가능한 KMS 키와 알고리즘, 그리고 실제 복호화 권한도 필요합니다. [비대칭 KMS 키](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)를 사용하는 경우, 복호화 요청에 blob을 암호화할 때 사용한 알고리즘을 지정해야 합니다. 호스트를 자동으로 인벤토리화할 때는 프로세스, 리스너, 설정 경로, 파일 권한에 대한 증거만 수집하세요. 일반적인 열거 과정에서 시크릿 값이나 복호화된 평문을 요청하거나 출력하지 마세요.
{{#include ../../banners/hacktricks-training.md}}
