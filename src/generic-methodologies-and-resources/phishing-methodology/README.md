# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. Recon으로 피해자 조사
1. **victim domain** 선택.
2. 피해자가 사용하는 로그인 포털을 **검색하는** 기본적인 웹 열거를 수행하고, 어떤 포털을 **사칭할지** **결정**하세요.
3. 일부 **OSINT**를 사용하여 **이메일을 찾기**.
2. 환경 준비
1. 피싱 평가에 사용할 **도메인 구매**
2. **이메일 서비스 관련 레코드 구성** (SPF, DMARC, DKIM, rDNS)
3. VPS에 **gophish** 구성
3. 캠페인 준비
1. **이메일 템플릿** 준비
2. 자격 증명을 훔치기 위한 **웹 페이지** 준비
4. 캠페인 시작!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: 도메인 이름이 원본 도메인의 중요한 **키워드**를 **포함**합니다 (예: zelster.com-management.com).
- **hypened subdomain**: 서브도메인의 **점(.)을 하이픈(-)으로 변경** (예: www-zelster.com).
- **New TLD**: 동일한 도메인에 **새 TLD** 사용 (예: zelster.org)
- **Homoglyph**: 도메인 이름의 문자를 **비슷해 보이는 문자**로 **대체**합니다 (예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내에서 두 글자를 **교환**합니다 (예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 이름 끝에 “s”를 추가하거나 제거합니다 (예: zeltsers.com).
- **Omission**: 도메인 이름에서 글자 하나를 **제거**합니다 (예: zelser.com).
- **Repetition:** 도메인 이름에서 글자 하나를 **반복**합니다 (예: zeltsser.com).
- **Replacement**: homoglyph보다 덜 은밀하게 문자를 교체합니다. 도메인 이름의 문자 하나를 원래 문자와 키보드상 근접한 문자로 교체할 수 있습니다 (예: zektser.com).
- **Subdomained**: 도메인 이름 안에 **점(.)**을 도입합니다 (예: ze.lster.com).
- **Insertion**: 도메인 이름에 글자 하나를 **삽입**합니다 (예: zerltser.com).
- **Missing dot**: 도메인 이름에 TLD를 붙여 넣습니다. (예: zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

저장되거나 통신 중인 비트 중 일부가 태양 플레어, 우주선, 또는 하드웨어 오류 등 다양한 요인으로 인해 자동으로 반전될 **가능성**이 있습니다.

이 개념을 **DNS 요청에 적용**하면, DNS 서버가 수신한 **도메인**이 최초로 요청한 도메인과 동일하지 않을 수 있습니다.

예를 들어, "windows.com" 도메인에서 한 비트가 바뀌면 "windnws.com"으로 변경될 수 있습니다.

공격자는 피해자 도메인과 유사한 여러 개의 bit-flipping 도메인을 등록하여 이점을 **악용할 수 있습니다**. 그들의 의도는 정상 사용자를 자신들의 인프라로 리디렉션하는 것입니다.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

사용할 수 있는 만료된 도메인을 [https://www.expireddomains.net/](https://www.expireddomains.net)에서 검색할 수 있습니다.\
구매하려는 만료 도메인이 이미 **좋은 SEO를 가지고 있는지** 확인하려면 다음에서 해당 도메인의 분류를 확인할 수 있습니다:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한, 사용자가 **메일 접근을 위해 어떤 웹 포털을 사용하는 경우**, 해당 포털이 **username brute force**에 취약한지 확인하고 가능하다면 해당 취약점을 이용하세요.

## Configuring GoPhish

### 설치

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
출력에서 포트 3333의 admin 사용자 비밀번호가 제공됩니다. 따라서 해당 포트에 접속하여 해당 자격증명을 사용해 admin 비밀번호를 변경하세요. 로컬로 포트를 터널링해야 할 수 있습니다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계에 앞서 사용하려는 **도메인을 이미 구매했어야** 하며, 해당 도메인은 **gophish**를 구성하는 **VPS의 IP**를 **가리키고** 있어야 합니다.
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

그런 다음 도메인을 다음 파일들에 추가하세요:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 내부의 다음 변수 값들도 변경하세요

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작하세요.**

이제 VPS의 **ip 주소**를 가리키도록 `mail.<domain>`의 **DNS A record**를 생성하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드를 추가하세요.

이제 이메일 전송을 테스트해봅시다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 설정**

gophish의 실행을 중지하고 설정을 구성합니다.\
다음과 같이 `/opt/gophish/config.json`을 수정하세요 (https 사용에 유의):
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

gophish 서비스를 자동으로 시작하고 서비스로서 관리할 수 있도록, 다음 내용으로 파일 `/etc/init.d/gophish` 를 생성하십시오:
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
서비스 구성을 완료하고 다음을 확인하세요:
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
## 메일 서버 및 도메인 구성

### 기다리기 & 정상적으로 보이기

도메인이 오래될수록 스팸으로 분류될 확률이 낮아집니다. 따라서 phishing 평가 전에 가능한 오래(최소 1주일) 기다려야 합니다. 또한 평판 관련 섹터에 대한 페이지를 두면 얻는 평판이 더 좋아집니다.

참고: 일주일을 기다려야 하더라도 지금 모든 설정을 완료할 수 있습니다.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 역방향 해석되도록 rDNS (PTR) 레코드를 설정하세요.

### Sender Policy Framework (SPF) 레코드

새 도메인에 대해 **SPF 레코드를 구성해야 합니다**. SPF 레코드가 무엇인지 모르면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF 정책을 생성하려면 [https://www.spfwizard.net/](https://www.spfwizard.net)를 사용할 수 있습니다 (VPS 머신의 IP를 사용하세요)

![](<../../images/image (1037).png>)

다음은 도메인 내 TXT 레코드에 설정해야 하는 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 도메인 기반 메시지 인증, 리포팅 및 준수 (DMARC) 레코드

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

다음 내용을 사용하여 호스트 이름 `_dmarc.<domain>`을 가리키는 새 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
페이지에 접속해 그들이 제공하는 주소로 이메일을 보내면 됩니다:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 `check-auth@verifier.port25.com`으로 이메일을 보내 **이메일 구성을 확인**하고 응답을 **읽을 수 있습니다** (이를 위해서는 port **25**를 **열어야** 하며, 이메일을 root로 보낼 경우 파일 _/var/mail/root_에서 응답을 확인해야 합니다).\\
모든 테스트를 통과했는지 확인하세요:
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
**당신이 제어하는 Gmail로 메시지를 보내고**, 받은편지함에서 **이메일 헤더**를 확인하세요. `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse 블랙리스트에서 제거

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft 블랙리스트에서 제거

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## GoPhish 캠페인 생성 및 실행

### 발송 프로필

- 송신 프로필을 식별할 수 있는 **이름**을 설정하세요
- 피싱 이메일을 보낼 계정을 선택하세요. 제안: _noreply, support, servicedesk, salesforce..._
- 사용자 이름과 비밀번호는 비워둘 수 있지만, **Ignore Certificate Errors**를 체크했는지 확인하세요

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 작동 여부를 확인하기 위해 "**Send Test Email**" 기능을 사용하는 것을 권장합니다.\
> 테스트 중 블랙리스트에 오르는 것을 피하기 위해 **send the test emails to 10min mails addresses**로 테스트 이메일을 보내는 것을 권합니다.

### 이메일 템플릿

- 템플릿을 식별할 수 있는 **이름**을 설정하세요
- 그런 다음 **subject**를 작성하세요 (낯설지 않은, 일반 이메일에서 볼 법한 제목)
- "**Add Tracking Image**"가 체크되어 있는지 확인하세요
- **이메일 템플릿**을 작성하세요 (다음 예처럼 변수를 사용할 수 있습니다):
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
참고: **이메일의 신뢰도를 높이기 위해**, 클라이언트 이메일에 있는 서명 일부를 사용하는 것이 권장됩니다. 제안:

- **존재하지 않는 주소**로 이메일을 보내 응답에 서명이 있는지 확인하세요.
- info@ex.com, press@ex.com, public@ex.com 같은 **공용 이메일**을 찾아 이메일을 보내고 응답을 기다리세요.
- 발견된 **유효한 이메일**에 연락해 응답을 기다려보세요.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template에서는 **첨부 파일을 함께 보낼 수 있습니다**. 또한 특수하게 제작한 파일/문서로 NTLM challenge를 탈취하려면 이 페이지를 [읽어보세요](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- **이름**을 작성하세요
- 웹 페이지의 **HTML 코드를 작성하세요**. 웹 페이지를 **import**할 수 있습니다.
- **Capture Submitted Data** 및 **Capture Passwords**를 선택하세요
- **리디렉션**을 설정하세요

![](<../../images/image (826).png>)

> [!TIP]
> 보통 HTML 코드를 수정하고 로컬(Apache 같은 서버 사용)에서 여러 번 테스트한 뒤 **원하는 결과가 나올 때까지** 조정합니다. 그런 다음 그 HTML 코드를 박스에 붙여넣으세요.\
> HTML에 사용할 정적 리소스(예: CSS, JS)가 필요하면 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/\<filename>**_에서 접근할 수 있습니다.

> [!TIP]
> 리디렉션의 경우 사용자를 피해자의 실제 메인 웹 페이지로 **리디렉트**하거나 예를 들어 _/static/migration.html_로 리디렉트하고, 5초간 **스피닝 휠**([https://loading.io/](https://loading.io/))을 보여준 뒤 프로세스가 성공했다고 표시할 수 있습니다.

### Users & Groups

- 이름을 설정하세요
- 데이터를 **import**하세요 (템플릿을 사용하려면 예제에 대해 각 사용자별 firstname, last name, email address가 필요합니다)

![](<../../images/image (163).png>)

### Campaign

마지막으로 캠페인을 생성할 때 이름, email template, landing page, URL, sending profile 및 그룹을 선택하세요. URL은 피해자에게 전송될 링크가 됩니다.

참고: **Sending Profile은 최종 phishing 이메일이 어떻게 보일지 확인하기 위해 테스트 이메일을 보낼 수 있게 합니다**:

![](<../../images/image (192).png>)

> [!TIP]
> 테스트를 할 때 블랙리스트에 오르는 것을 피하기 위해 테스트 이메일은 **10min mails 주소**로  보내는 것을 권장합니다.

모든 준비가 끝나면 캠페인을 시작하세요!

## Website Cloning

어떤 이유로 웹사이트를 클론(clone)하고 싶다면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing 평가(주로 Red Teams)에서는 **백도어가 포함된 파일**(예: C2 또는 인증을 유발하는 파일)을 전송해야 할 때가 있습니다. 예시를 보려면 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

이전 공격은 실제 웹사이트를 가장해 사용자가 설정한 정보를 수집하기 때문에 꽤 교묘합니다. 불행히도 사용자가 올바른 비밀번호를 입력하지 않았거나 당신이 가장한 애플리케이션이 2FA로 설정되어 있다면, **이 정보만으로는 속은 사용자를 가장할 수 없습니다**.

여기서 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena)와 같은 도구가 유용합니다. 이 도구들은 MitM 형태의 공격을 가능하게 합니다. 기본 동작은 다음과 같습니다:

1. 실제 웹페이지의 로그인 폼을 **가로챕니다**.
2. 사용자가 가짜 페이지에 **자격증명**을 전송하면 해당 도구가 이를 실제 웹페이지로 전달하고 **자격증명이 유효한지 확인**합니다.
3. 계정이 **2FA**로 설정되어 있으면 MitM 페이지가 이를 요구하고, 사용자가 입력하면 도구가 이를 실제 웹페이지로 전송합니다.
4. 사용자가 인증되면 공격자는 MitM 동안 도구가 수행하는 모든 상호작용에서 **credentials, 2FA, cookie 및 기타 정보를 캡처**하게 됩니다.

### Via VNC

정상 사이트와 동일한 모양의 악성 페이지로 사용자를 보내는 대신, 브라우저가 실제 웹페이지에 접속된 VNC 세션으로 사용자를 보낸다면 어떻게 될까요? 사용자가 무엇을 하는지 실시간으로 보고 비밀번호, MFA, 쿠키 등을 탈취할 수 있습니다. 이를 위해 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)를 사용할 수 있습니다.

## Detecting the detection

가장 명확한 방법 중 하나는 자신의 도메인을 블랙리스트에서 **검색하는 것**입니다. 만약 목록에 올라가 있다면 어떤 식으로든 당신의 도메인이 의심스럽다고 탐지된 것입니다. 도메인이 블랙리스트에 올라갔는지 확인하는 쉬운 방법 중 하나는 [https://malwareworld.com/](https://malwareworld.com)을 사용하는 것입니다.

하지만, 피해자가 **활동적으로 의심스러운 phishing 활동을 찾고 있는지**를 알아내는 다른 방법들도 있습니다. 자세한 내용은 다음을 확인하세요:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 도메인과 매우 비슷한 이름의 도메인을 구매하거나, 여러분이 제어하는 도메인의 **서브도메인**에 대해 피해자 도메인의 **키워드**를 포함한 인증서를 **발급**받을 수 있습니다. 피해자가 해당 도메인들과 어떤 종류의 **DNS나 HTTP 상호작용**을 한다면, 그가 **활동적으로 의심스러운 도메인을 탐색하고 있다**는 사실을 알 수 있고 매우 은밀하게 행동해야 합니다.

### Evaluate the phishing

이메일이 스팸 폴더에 들어갈지, 차단될지 또는 성공할지 평가하려면 [**Phishious**](https://github.com/Rices/Phishious)를 사용하세요.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

최근 침입 집단은 이메일 유혹을 완전히 건너뛰고 **서비스 데스크/identity-recovery 워크플로우를 직접 공격**하여 MFA를 무력화하는 경우가 늘고 있습니다. 이 공격은 완전히 "living-off-the-land" 방식으로 진행됩니다: 운영자가 유효한 자격증명을 확보하면 내장 관리자 도구로 피벗하며 – 악성코드가 필요 없습니다.

### Attack flow
1. 대상 정보 수집
   * LinkedIn, 데이터 유출, 공개 GitHub 등에서 개인 및 회사 정보를 수집합니다.
   * 고가치 식별자(임원, IT, 재무)를 파악하고 비밀번호/MFA 재설정에 대한 **정확한 help-desk 절차**를 열거합니다.
2. 실시간 소셜 엔지니어링
   * 대상자를 가장하여 전화, Teams 또는 채팅으로 help-desk에 연락합니다(종종 **spoofed caller-ID** 또는 **cloned voice** 사용).
   * 사전에 수집한 PII를 제공하여 지식 기반 인증을 통과합니다.
   * 상담원에게 **MFA 시크릿을 리셋**하거나 등록된 휴대전화 번호에 대해 **SIM-swap**을 수행하도록 설득합니다.
3. 즉시 후속 액션 (실제 사례에서 ≤60 min)
   * 웹 SSO 포털을 통해 발판을 마련합니다.
   * 내장 도구로 AD / AzureAD를 열거합니다(바이너리 설치 없음):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
   * 이미 환경에서 허용된 정당한 **RMM** 에이전트나 **WMI**, **PsExec** 등을 이용한 횡적 이동 수행.

### Detection & Mitigation
* help-desk identity recovery를 **권한이 필요한 작업(privileged operation)**으로 취급하세요 — step-up 인증 및 관리자 승인 요구.
* **Identity Threat Detection & Response (ITDR)** / **UEBA** 규칙을 배치하여 다음을 탐지하도록 알림 설정:
  * MFA 방법 변경 + 새로운 디바이스/지오에서의 인증
  * 동일 주체의 즉각적인 권한 상승(user → admin)
* 도움 데스크 통화를 녹음하고 어떤 리셋 작업 전에 **이미 등록된 번호로 콜백을 수행**하도록 강제하세요.
* 새로 리셋된 계정이 자동으로 고권한 토큰을 상속받지 않도록 **Just-In-Time (JIT) / Privileged Access**를 구현하세요.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
일부 그룹은 고수준 작업의 비용을 보상하기 위해 대량 공격을 수행하여 **검색엔진 및 광고 네트워크를 배포 채널로 전환**합니다.

1. **SEO poisoning / malvertising**는 `chromium-update[.]site`와 같은 가짜 결과를 검색 광고 상단에 올립니다.
2. 피해자는 작은 **1단계 로더**(종종 JS/HTA/ISO)를 다운로드합니다. Unit 42가 관찰한 예:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. 로더는 브라우저 쿠키 및 자격증명 DB를 탈취한 뒤 **무음 로더**를 내려받아 실시간으로 다음을 결정합니다:
   * RAT (예: AsyncRAT, RustDesk)
   * 랜섬웨어 / 와이퍼
   * 영구화 컴포넌트(레지스트리 Run 키 + scheduled task)

### Hardening tips
* 새로 등록된 도메인을 차단하고 검색 광고뿐 아니라 이메일에 대해서도 **고급 DNS / URL 필터링**을 적용하세요.
* 소프트웨어 설치를 서명된 MSI / Store 패키지로 제한하고, 정책으로 `HTA`, `ISO`, `VBS` 실행을 차단하세요.
* 브라우저의 자식 프로세스가 설치 프로그램을 여는지를 모니터링하세요:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 1단계 로더가 자주 악용하는 LOLBins(예: `regsvr32`, `curl`, `mshta`)를 헌팅하세요.

---

## AI-Enhanced Phishing Operations
공격자들은 이제 **LLM & voice-clone API**를 연결해 완전 개인화된 유인책과 실시간 상호작용을 구현합니다.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• ARC/DKIM 이상 징후(비신뢰 자동화로부터 전송된 메시지를 강조하는) **다이나믹 배너**를 추가하세요.  
• 고위험 전화 요청에 대해 **음성 생체 인증용 챌린지 문구**를 배포하세요.  
• 정적 템플릿은 구식이므로 인식 프로그램에서 AI 생성 유인책을 지속적으로 시뮬레이션하세요.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
클래식한 push-bombing 외에, 운영자는 단순히 help-desk 통화 중에 **새 MFA 등록을 강제**하여 사용자의 기존 토큰을 무효화합니다. 이후 나타나는 로그인 프롬프트는 피해자에게 합법적으로 보입니다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta 이벤트에서 **`deleteMFA` + `addMFA`**가 **같은 IP에서 몇 분 내에** 발생하는지 모니터링하세요.



## Clipboard Hijacking / Pastejacking

공격자는 손상되었거나 typosquatted된 웹 페이지에서 피해자의 클립보드로 악성 명령을 몰래 복사한 다음, 사용자를 속여 **Win + R**, **Win + X** 또는 terminal 창에 붙여넣게 하여 다운로드나 첨부파일 없이 임의의 코드를 실행할 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## 참고자료

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
