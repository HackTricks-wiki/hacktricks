# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. Recon 대상 파악
1. **victim domain** 선택.
2. 피해자가 사용하는 로그인 포털을 찾기 위한 기본적인 웹 열거를 수행하고, 어느 포털을 **impersonate**할지 **decide**.
3. 일부 **OSINT**를 사용해 **이메일을 찾기**.
2. 환경 준비
1. 평가에 사용할 **도메인 구입**
2. 이메일 서비스 관련 레코드 구성 (SPF, DMARC, DKIM, rDNS)
3. **gophish**를 설치한 VPS 구성
3. 캠페인 준비
1. **email template** 준비
2. 자격증명을 훔칠 **web page** 준비
4. 캠페인 실행!

## 유사 도메인 생성 또는 신뢰받는 도메인 구매

### Domain Name Variation Techniques

- **Keyword**: 도메인 이름에 원본 도메인의 중요한 **keyword**가 포함됨 (예: zelster.com-management.com).
- **hypened subdomain**: 서브도메인의 **dot을 하이픈으로 변경** (예: www-zelster.com).
- **New TLD**: 동일 도메인을 **새로운 TLD**로 사용 (예: zelster.org)
- **Homoglyph**: 도메인 내의 글자를 **비슷하게 보이는 문자로 대체** (예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내에서 **두 글자를 바꿈** (예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 끝에 “s”를 추가하거나 제거 (예: zeltsers.com).
- **Omission**: 도메인 이름에서 한 글자를 **제거** (예: zelser.com).
- **Repetition:** 도메인 이름의 한 글자를 **반복** (예: zeltsser.com).
- **Replacement**: homoglyph와 유사하지만 덜 은밀함. 도메인 내 한 글자를 교체하며, 키보드상 인접한 글자 등으로 바꿈 (예: zektser.com).
- **Subdomained**: 도메인 이름 내부에 **dot 추가** (예: ze.lster.com).
- **Insertion**: 도메인 이름에 **문자 삽입** (예: zerltser.com).
- **Missing dot**: 도메인 이름에 TLD를 붙여서 사용. (예: zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

저장되거나 통신 중인 일부 비트가 태양 플레어, 우주선 입자, 하드웨어 오류 등 여러 요인으로 인해 **자동으로 뒤집힐 가능성**이 있습니다.

이 개념을 **DNS 요청에 적용하면**, DNS 서버가 수신한 도메인이 원래 요청한 도메인과 **다를 수 있습니다**.

예를 들어, "windows.com"에서 단일 비트가 수정되면 "windnws.com"으로 변경될 수 있습니다.

공격자는 피해자 도메인과 유사한 여러 bit-flipping 도메인을 **등록하여** 합법적인 사용자를 자사 인프라로 리다이렉트하려 할 수 있습니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)를 참고하세요.

### Buy a trusted domain

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 만한 만료된 도메인을 검색할 수 있습니다.\
구입하려는 만료된 도메인이 **이미 좋은 SEO를 가지고 있는지** 확인하려면 다음에서 어떻게 분류되는지 확인하세요:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 이메일 주소를 **발견하거나** 이미 발견한 주소를 **검증**하려면 피해자의 SMTP 서버에 대해 사용자명 브루트포스를 수행해 확인할 수 있습니다. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한, 사용자가 **웹 포털을 통해 메일에 접근**한다면 해당 포털이 **username brute force**에 취약한지 확인하고, 가능하다면 취약점을 악용하세요.

## Configuring GoPhish

### Installation

다음에서 다운로드할 수 있습니다: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

다운로드하여 `/opt/gophish`에 압축 해제하고 `/opt/gophish/gophish`를 실행하세요.\
출력에 admin 사용자 비밀번호가 포트 3333에 대해 제공됩니다. 따라서 해당 포트에 접속하여 해당 자격증명으로 관리자 비밀번호를 변경하세요. 로컬로 해당 포트를 터널링해야 할 수 있습니다.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 전에 사용하려는 **이미 구매한 domain**이 있어야 하며, 해당 domain은 **gophish**를 구성 중인 **VPS의 IP**를 **가리키고 있어야** 합니다.
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

설치 시작: `apt-get install postfix`

그런 다음 다음 파일들에 도메인을 추가하세요:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**또한 /etc/postfix/main.cf 안의 다음 변수 값도 변경하세요**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작하세요.**

이제 VPS의 **ip address**를 가리키도록 `mail.<domain>`의 **DNS A record**를 생성하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드를 생성하세요.

이제 이메일 전송을 테스트해봅시다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 설정**

gophish 실행을 중지하고 설정합시다.\
`/opt/gophish/config.json`을 다음 내용으로 수정하세요 (https 사용에 주의):
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

gophish 서비스를 자동으로 시작하고 서비스로 관리할 수 있도록, 다음 내용을 가진 파일 `/etc/init.d/gophish` 를 생성하면 됩니다:
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
서비스 구성 마무리 및 작동 확인:
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

### 기다리고 정당해 보이기

도메인이 오래될수록 스팸으로 분류될 가능성이 낮아집니다. 따라서 피싱 평가 전에 가능한 한 오래(최소 1주) 기다려야 합니다. 또한 평판이 좋은 분야에 대한 페이지를 넣으면 얻는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 구성을 완료할 수 있다는 점을 기억하세요.

### Reverse DNS (rDNS) 레코드 구성

IP 주소가 도메인 이름으로 해석되도록 rDNS (PTR) 레코드를 설정하세요.

### Sender Policy Framework (SPF) Record

당신은 **새 도메인에 대해 SPF 레코드를 설정해야 합니다**. 만약 SPF 레코드가 무엇인지 모른다면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

https://www.spfwizard.net/ 를 사용하여 SPF 정책을 생성할 수 있습니다 (VPS 기계의 IP를 사용하세요)

![](<../../images/image (1037).png>)

이 내용은 도메인 내 TXT 레코드에 설정되어야 합니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

새 도메인에 대해 **DMARC record를 구성해야 합니다**. DMARC record가 무엇인지 모른다면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

다음 내용을 사용하여 호스트명 `_dmarc.<domain>`를 가리키는 새 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 **DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**이 페이지를 읽으세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 B64 값을 이어붙여야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
페이지에 접속하여 그들이 제공하는 주소로 이메일을 보내면 됩니다:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 **이메일 설정을 확인하려면** `check-auth@verifier.port25.com`로 이메일을 보내고 **응답을 읽어보세요** (이를 위해서는 포트 **25**를 **열어야** 하고 root로 이메일을 보낼 경우 _/var/mail/root_ 파일에서 응답을 확인해야 합니다).\
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
또한 본인이 제어하는 **Gmail 계정으로의 메시지**를 보내고, Gmail 받은편지함에서 **이메일의 헤더**를 확인하세요. `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### 발신 프로필

- 발신자 프로필을 식별할 수 있는 **이름을 설정**
- 어떤 계정에서 phishing 이메일을 보낼지 결정합니다. 제안: _noreply, support, servicedesk, salesforce..._
- username과 password는 비워둘 수 있지만, 반드시 Ignore Certificate Errors를 체크하세요

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 것이 정상인지 테스트하려면 "**Send Test Email**" 기능을 사용하는 것이 권장됩니다.\
> 블랙리스트에 오르는 것을 피하기 위해 테스트 이메일은 **10min mails 주소로 보내는 것**을 권장합니다.

### 이메일 템플릿

- 템플릿을 식별할 수 있는 **이름을 설정**
- 그런 다음 **subject**를 작성합니다 (특이한 내용이 아닌 일반 이메일에서 기대할 만한 제목)
- 반드시 "**Add Tracking Image**"를 체크했는지 확인하세요
- 이메일 템플릿을 작성하세요 (다음 예시처럼 변수를 사용할 수 있습니다):
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
다음 사항에 유의하세요: 이메일의 신뢰성을 높이기 위해 클라이언트의 실제 이메일 서명 일부를 사용하는 것이 권장됩니다. 제안:

- **존재하지 않는 주소**로 이메일을 보내 응답에 서명이 있는지 확인하세요.
- info@ex.com, press@ex.com, public@ex.com 같은 **공개 이메일**을 찾아 이메일을 보내고 응답을 기다리세요.
- **발견한 유효한 이메일**로 연락을 시도하고 응답을 기다리세요.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template에서는 **보낼 파일을 첨부**할 수도 있습니다. 특수하게 조작된 파일/문서로 NTLM 챌린지를 탈취하고 싶다면 [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### 랜딩 페이지

- **이름**을 작성하세요
- 웹 페이지의 **HTML 코드를 작성**하세요. 웹 페이지를 **가져올(import)** 수 있습니다.
- **제출된 데이터 캡처** 및 **비밀번호 캡처**를 선택하세요
- **리디렉션**을 설정하세요

![](<../../images/image (826).png>)

> [!TIP]
> 보통 페이지의 HTML 코드를 수정하고 로컬(예: Apache 서버 사용)에서 몇 차례 테스트를 진행하여 **원하는 결과가 나올 때까지** 조정해야 합니다. 그런 다음 그 HTML 코드를 상자에 입력하세요.\
> HTML에 **정적 리소스**(예: CSS, JS)가 필요하면 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/\<filename>**_에서 접근할 수 있습니다.

> [!TIP]
> 리디렉션의 경우 사용자를 피해자의 실제 메인 웹페이지로 **리디렉트**하거나 예를 들어 _/static/migration.html_로 리디렉트하여 **스피닝 휠 (**[**https://loading.io/**](https://loading.io)**)을 5초 동안 보여준 후 프로세스가 성공했다고 표시**할 수 있습니다.

### 사용자 및 그룹

- 이름을 설정하세요
- **데이터 가져오기** (예제 템플릿을 사용하려면 각 사용자에 대해 firstname, last name 및 email address가 필요합니다)

![](<../../images/image (163).png>)

### 캠페인

마지막으로 이름, email template, 랜딩 페이지, URL, Sending Profile 및 그룹을 선택하여 캠페인을 생성하세요. URL은 피해자에게 전송될 링크가 됩니다.

Sending Profile를 통해 테스트 이메일을 보내 최종 피싱 이메일이 어떻게 보이는지 확인할 수 있습니다:

![](<../../images/image (192).png>)

> [!TIP]
> 테스트 중 블랙리스트에 오르는 것을 피하려면 테스트 이메일을 **10min mails 주소**로 보내는 것을 권장합니다.

준비가 끝나면 캠페인을 시작하세요!

## 웹사이트 클로닝

웹사이트를 복제하려면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## 백도어 문서 및 파일

일부 피싱 평가(주로 Red Teams)에서는 **백도어가 포함된 파일 전송**(예: C2 또는 인증을 트리거하는 것)을 함께 수행하기도 합니다. 예시들은 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## 피싱 MFA

### Via Proxy MitM

앞서 설명한 공격은 실제 웹사이트를 가장하여 사용자가 입력한 정보를 수집하는 영리한 방법입니다. 그러나 사용자가 올바른 비밀번호를 입력하지 않았거나, 당신이 가장한 애플리케이션이 2FA로 설정되어 있다면 **이 정보만으로는 기만된 사용자를 가장할 수 없습니다**.

이럴 때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena) 같은 도구가 유용합니다. 이 도구들은 MitM 공격을 가능하게 합니다. 기본적인 동작은 다음과 같습니다:

1. 실제 웹페이지의 로그인 폼을 **사칭**합니다.
2. 사용자가 가짜 페이지에 **자격 증명(credentials)**를 전송하면 도구가 이를 실제 웹페이지로 전송하여 **자격 증명이 동작하는지 확인**합니다.
3. 계정이 **2FA**로 설정되어 있다면 MitM 페이지가 이를 요청하고 사용자가 입력하면 도구는 이를 실제 웹페이지로 전송합니다.
4. 사용자가 인증되면 공격자는 MitM 수행 중 발생한 모든 상호작용의 **자격 증명, 2FA, 쿠키 및 기타 정보**를 캡처하게 됩니다.

### Via VNC

원래 페이지와 같은 모양의 악성 페이지로 사용자를 보내는 대신, 브라우저가 실제 웹페이지에 접속된 상태의 **VNC 세션**으로 사용자를 보내면 어떨까요? 사용자가 무엇을 하는지 실시간으로 볼 수 있고, 비밀번호, MFA, 쿠키 등을 탈취할 수 있습니다. 이를 위해 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)를 사용할 수 있습니다.

## 탐지 여부 확인

자신이 적발되었는지 확인하는 가장 좋은 방법 중 하나는 **자신의 도메인이 블랙리스트에 올라 있는지 검색**하는 것입니다. 목록에 나타난다면 어떤 방식으로든 도메인이 의심 대상으로 감지된 것입니다.\
도메인이 블랙리스트에 있는지 확인하는 쉬운 방법 중 하나는 [https://malwareworld.com/](https://malwareworld.com)을 사용하는 것입니다.

그러나 피해자가 **활발히 의심스러운 피싱 활동을 찾고 있는지**를 알 수 있는 다른 방법들도 있습니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자 도메인과 매우 유사한 이름의 도메인을 구매하거나, 당신이 컨트롤하는 도메인의 **서브도메인**에 대해 피해자 도메인의 **키워드**를 포함한 인증서를 **발급**할 수 있습니다. 피해자가 해당 도메인들과 DNS 또는 HTTP 상호작용을 한다면 **그가 의심스러운 도메인을 적극적으로 탐지하고 있다는 것**을 알 수 있으며, 매우 은밀하게 행동해야 합니다.

### 피싱 평가

이메일이 스팸 폴더로 들어가거나 차단될지 성공할지를 평가하려면 [**Phishious**](https://github.com/Rices/Phishious)를 사용하세요.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

최근 침해 그룹들은 이메일 유인 없이 서비스 데스크/신원 복구 워크플로우를 직접 공략하여 MFA를 무력화하는 경향이 증가하고 있습니다. 공격은 완전히 “living-off-the-land” 방식으로 진행됩니다: 오퍼레이터가 유효한 자격증명을 확보하면 내장된 관리자 도구로 피벗하고 – 악성코드는 필요 없습니다.

### 공격 흐름
1. 대상 정찰
* LinkedIn, 데이터 유출, 공개 GitHub 등에서 개인 및 회사 관련 정보를 수집합니다.
* 고가치 신원(임원, IT, 재무)을 식별하고 비밀번호/MFA 재설정에 대한 **정확한 헬프데스크 절차**를 열거합니다.
2. 실시간 소셜 엔지니어링
* 전화, Teams 또는 채팅으로 헬프데스크에 실시간으로 연락하여 대상자를 사칭합니다(종종 **spoofed caller-ID** 또는 **cloned voice** 사용).
* 이전에 수집한 PII를 제공하여 지식 기반 인증을 통과합니다.
* 상담원을 설득하여 **MFA 시크릿을 재설정**하거나 등록된 휴대전화에 대해 **SIM-swap**을 수행하도록 만듭니다.
3. 즉시 후속 액세스 조치(실제 사례에서 ≤60분)
* 웹 SSO 포털을 통해 발판을 확보합니다.
* 내장 도구로 AD / AzureAD를 열거(바이너리 배포 없이)합니다:
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**, **PsExec**, 또는 환경에서 이미 허용된 합법적인 **RMM** 에이전트를 이용해 횡적 이동을 수행합니다.

### 탐지 및 완화
* 헬프데스크 신원 복구를 **권한이 필요한 작업(privileged operation)**으로 취급하고—스텝업 인증 및 관리자 승인을 요구하세요.
* **Identity Threat Detection & Response (ITDR)** / **UEBA** 규칙을 배포하여 다음을 탐지하도록 알림을 설정하세요:
* MFA 방식 변경 + 새로운 디바이스/지리적 위치에서의 인증.
* 동일 계정의 즉각적인 권한 상승(user → admin).
* 헬프데스크 통화를 녹음하고 리셋 전에 **이미 등록된 번호로 콜백**을 강제하세요.
* Just-In-Time (JIT) / Privileged Access를 구현하여 새로 재설정된 계정이 자동으로 고권한 토큰을 상속받지 않도록 하세요.

---

## 대규모 기만 – SEO Poisoning 및 “ClickFix” 캠페인
일부 대규모 조직은 고접촉 작업의 비용을 상쇄하기 위해 **검색 엔진 및 광고 네트워크를 전달 채널로 전환**하는 대량 공격을 수행합니다.

1. **SEO poisoning / malvertising**가 `chromium-update[.]site`와 같은 가짜 결과를 검색 광고 상단에 띄웁니다.
2. 피해자는 작은 **1단계 로더**(주로 JS/HTA/ISO)를 다운로드합니다. Unit 42가 확인한 예:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 로더는 브라우저 쿠키 + 자격 증명 DB를 유출한 뒤 **무음 로더(silent loader)**를 불러와 실시간으로 배포 여부를 결정합니다:
* RAT (예: AsyncRAT, RustDesk)
* ransomware / wiper
* 영속성 컴포넌트(레지스트리 Run 키 + 예약 작업)

### 하드닝 팁
* 새로 등록된 도메인을 차단하고 검색 광고뿐 아니라 이메일에 대해서도 **Advanced DNS / URL Filtering**을 적용하세요.
* 소프트웨어 설치를 서명된 MSI / Store 패키지로 제한하고, 정책으로 `HTA`, `ISO`, `VBS` 실행을 차단하세요.
* 브라우저의 자식 프로세스가 설치 프로그램을 여는지 모니터링하세요:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 1단계 로더에 의해 자주 악용되는 LOLBins(`regsvr32`, `curl`, `mshta` 등)를 헌팅하세요.

---

## AI 강화 피싱 작전
공격자들은 이제 **LLM 및 음성 합성 API**를 연계해 완전히 개인화된 미끼와 실시간 상호작용을 만듭니다.

| 레이어 | 위협 행위자의 사용 예 |
|-------|-----------------------------|
|Automation|랜덤화된 문구와 추적 링크로 >100k 이메일/SMS를 생성 및 발송.|
|Generative AI|공개된 M&A, 소셜 미디어의 내부 농담을 참조한 일회성 이메일 생성; 콜백 사기에서 CEO의 합성 음성 사용.|
|Agentic AI|도메인 자율 등록, 오픈소스 인텔 수집, 피해자가 클릭했지만 자격증명을 제출하지 않을 때 다음 단계 이메일을 자동 제작.|

**방어:**
• ARC/DKIM 이상 징후를 통해 비신뢰 자동화에서 보낸 메시지를 강조하는 **동적 배너**를 추가하세요.  
• 고위험 전화 요청에 대해 **음성 생체 인증 도전 구문(voice-biometric challenge phrases)**을 도입하세요.  
• 인식 교육 프로그램에서 AI가 생성한 미끼를 지속적으로 시뮬레이션하세요 — 정적 템플릿은 구식입니다.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA 피로 / Push Bombing 변형 – 강제 재등록
고전적인 push-bombing 외에도 운영자는 헬프데스크 통화 중 단순히 **새 MFA 등록을 강제(force a new MFA registration)**하여 사용자의 기존 토큰을 무효화합니다. 이후의 모든 로그인 프롬프트는 피해자에게 합법적으로 보입니다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.
  
## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자들은 점점 자신의 phishing 흐름을 단순한 디바이스 검사 뒤에 숨겨 데스크탑 crawlers가 최종 페이지에 도달하지 못하도록 합니다. 흔한 패턴은 터치 지원 DOM을 검사하고 그 결과를 서버 endpoint로 전송하는 작은 스크립트입니다; non‑mobile 클라이언트는 HTTP 500(또는 빈 페이지)을 받는 반면, mobile 사용자는 전체 흐름을 제공합니다.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 로직(단순화됨):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
서버에서 자주 관찰되는 동작:
- 첫 로드 시 세션 쿠키를 설정한다.
- `POST /detect {"is_mobile":true|false}` 요청을 수락한다.
- 이후 GET 요청에 대해 `is_mobile=false`일 때 500(또는 플레이스홀더)을 반환하고, `true`일 때만 phishing을 제공한다.

Hunting and detection heuristics:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 비모바일에 대해 HTTP 500; 정당한 모바일 피해자 경로는 후속 HTML/JS와 함께 200을 반환한다.
- `ontouchstart` 또는 유사한 디바이스 검사로만 콘텐츠를 결정하는 페이지는 차단하거나 면밀히 검토하라.

방어 팁:
- 모바일 유사 지문을 사용하고 JS를 활성화한 크롤러를 실행하여 게이트된 콘텐츠를 노출시켜라.
- 신규 등록 도메인에서 `POST /detect` 이후의 의심스러운 500 응답에 대해 경보를 설정하라.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
