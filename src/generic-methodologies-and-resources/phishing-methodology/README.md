# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 이전에 **이미 구매한 도메인**을 가지고 있어야 하며, 해당 도메인은 **gophish**를 구성하는 **VPS의 IP**를 **가리키고 있어야 합니다**.
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
**메일 구성**

설치를 시작하세요: `apt-get install postfix`

그런 다음 도메인을 다음 파일들에 추가하세요:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 안의 다음 변수들의 값도 변경하세요

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`**와 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작**하세요.

이제 `mail.<domain>`의 **DNS A record**를 VPS의 **ip address**로 설정하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드를 만드세요.

이제 이메일 전송을 테스트해봅시다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 설정**

gophish의 실행을 중지하고 설정합시다.\
`/opt/gophish/config.json`을 다음과 같이 수정하세요 (https 사용에 유의):
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

gophish 서비스를 자동으로 시작하고 서비스로 관리하려면 다음 내용을 가진 파일 `/etc/init.d/gophish` 를 생성하세요:
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
서비스 구성을 완료하고 동작을 확인하세요:
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

### 기다리고 신뢰를 쌓으세요

도메인이 오래될수록 스팸으로 분류될 가능성이 낮아집니다. 따라서 phishing assessment 전에 가능한 한 오래(최소 1주일) 기다려야 합니다. 또한 평판이 중요한 분야에 관한 페이지를 넣으면 얻는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 구성을 마쳐둘 수 있다는 점을 유의하세요.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 해석되도록 rDNS (PTR) 레코드를 설정하세요.

### Sender Policy Framework (SPF) 레코드

새 도메인에 대해 반드시 **SPF 레코드를 구성해야 합니다**. SPF 레코드가 무엇인지 모른다면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

이것은 도메인의 TXT 레코드에 설정해야 하는 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 도메인 기반 메시지 인증, 보고 및 준수 (DMARC) 레코드

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

다음 내용을 사용하여 호스트명 `_dmarc.<domain>`를 가리키는 새 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 **DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 개의 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 구성 점수 테스트

이를 확인하려면 [https://www.mail-tester.com/](https://www.mail-tester.com/)\\ 페이지에 접속하여 그들이 제공한 주소로 이메일을 보내세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 **이메일 구성을 확인하려면** `check-auth@verifier.port25.com`로 이메일을 보내고 **응답을 읽어보세요** (이를 위해 **포트 25를 열어야** 하며, 이메일을 root로 보낸 경우 응답을 _/var/mail/root_에서 확인하면 됩니다).\
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
또는 **자신이 제어하는 Gmail 계정으로 메시지 보내기**를 하고, Gmail 받은편지함에서 **이메일의 헤더**를 확인하세요. `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist에서 제거

페이지 [www.mail-tester.com](https://www.mail-tester.com)은 도메인이 spamhouse에 의해 차단되었는지 알려줍니다. 도메인/IP 제거를 요청하려면 다음에서 요청하세요: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist에서 제거

​​도메인/IP 제거를 다음에서 요청할 수 있습니다: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- 발신자 프로필을 식별할 수 있는 **이름을 설정**하세요
- 어떤 계정에서 피싱 이메일을 보낼지 결정하세요. 제안: _noreply, support, servicedesk, salesforce..._
- username과 password를 비워둘 수 있지만, Ignore Certificate Errors를 체크했는지 확인하세요

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 것이 정상 작동하는지 테스트하려면 "**Send Test Email**" 기능을 사용하는 것이 권장됩니다.\
> 테스트 중 블랙리스트에 오르는 것을 피하기 위해 **테스트 이메일을 10min mails 주소들로 보내는 것**을 권합니다.

### Email Template

- 템플릿을 식별할 수 있는 **이름을 설정**하세요
- 그런 다음 **subject**를 작성하세요 (특이하지 않은, 평범한 이메일에서 볼 수 있는 제목)
- **Add Tracking Image**를 체크했는지 확인하세요
- 이메일 **template**을 작성하세요 (다음 예시처럼 변수를 사용할 수 있습니다):
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- 존재하지 않는 주소로 email을 보내 응답에 서명이 있는지 확인하세요.
- info@ex.com, press@ex.com, public@ex.com 등과 같은 **공개 email 주소**를 찾아 그들에게 email을 보내고 응답을 기다리세요.
- 발견된 유효한 email로 연락을 시도하고 응답을 기다리세요.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template에서도 **보낼 파일을 첨부**할 수 있습니다. 만약 특수 제작된 파일/문서로 NTLM challenges를 훔치고 싶다면 [이 페이지](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)를 참고하세요.

### 랜딩 페이지

- **이름**을 작성하세요
- 웹 페이지의 **HTML 코드 작성**. 웹 페이지를 **import**할 수 있다는 점을 유의하세요.
- **Capture Submitted Data**와 **Capture Passwords**를 체크하세요
- **리디렉션**을 설정하세요

![](<../../images/image (826).png>)

> [!TIP]
> 보통은 HTML 코드를 수정하고 로컬(예: Apache)을 사용해 **원하는 결과가 나올 때까지** 테스트해야 합니다. 그런 다음 그 HTML 코드를 입력란에 복사하세요.\
> 정적 리소스(예: CSS, JS)가 필요하면 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/<filename>**_에서 접근할 수 있습니다

> [!TIP]
> 리디렉션의 경우 사용자를 피해자의 정식 메인 웹페이지로 **리디렉션**하거나 예를 들어 _/static/migration.html_로 리디렉션하여 **스피닝 휠(**[**https://loading.io/**](https://loading.io)**)**을 5초 동안 보여준 뒤 프로세스가 성공했다고 표시할 수 있습니다.

### Users & Groups

- 이름 설정
- 데이터를 import하세요 (예제 템플릿을 사용하려면 각 사용자에 대해 firstname, last name 및 email address가 필요합니다)

![](<../../images/image (163).png>)

### Campaign

마지막으로 이름, email template, 랜딩 페이지, URL, sending profile 및 그룹을 선택하여 캠페인을 생성하세요. URL은 피해자에게 전송되는 링크가 됩니다.

Sending Profile을 통해 최종 phishing email이 어떻게 보일지 확인하기 위해 테스트 email을 보낼 수 있습니다:

![](<../../images/image (192).png>)

> [!TIP]
> 테스트를 할 때 블랙리스트에 오르는 것을 피하려면 테스트 email을 10min mails 주소로 전송하는 것을 권합니다.

모든 준비가 완료되면 캠페인을 실행하세요!

## Website Cloning

웹사이트를 클론해야 하는 이유가 있다면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing 평가(주로 Red Teams)에서는 **백도어가 포함된 파일**(예: C2 또는 인증을 유발하는 것)을 전송해야 할 때가 있습니다. 예제는 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

앞의 공격은 실제 웹사이트를 가장하여 사용자가 입력한 정보를 수집하기 때문에 꽤 효과적입니다. 하지만 사용자가 올바른 비밀번호를 입력하지 않았거나 피싱한 애플리케이션이 2FA로 구성되어 있다면 **해당 정보만으로는 피싱된 사용자를 가장할 수 없습니다**.

이때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena) 같은 도구가 유용합니다. 이 도구들은 MitM 형태의 공격을 구현해줍니다. 기본적인 동작은 다음과 같습니다:

1. 실제 웹페이지의 로그인 폼을 가장합니다.
2. 사용자가 자신의 **credentials**를 가짜 페이지에 전송하면 도구는 이를 실제 웹페이지로 전송하여 **credentials가 유효한지 확인**합니다.
3. 계정에 **2FA**가 설정되어 있으면 MitM 페이지에서 2FA를 요청하고 사용자가 이를 입력하면 도구는 실제 웹페이지로 전달합니다.
4. 사용자가 인증되면 공격자는 MitM이 수행되는 동안의 모든 상호작용에서 **캡처된 credentials, 2FA, cookie 및 기타 정보**를 확보합니다.

### Via VNC

원본과 동일한 모양의 악성 페이지로 피해자를 유도하는 대신, 브라우저가 실제 웹페이지에 접속된 VNC 세션으로 보낼 수 있다면 어떨까요? 이 경우 사용자가 무엇을 하는지 실시간으로 볼 수 있으며 비밀번호, MFA, 쿠키 등을 훔칠 수 있습니다. 이를 위해 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)를 사용할 수 있습니다.

## Detecting the detection

자신이 발각되었는지 확인하는 가장 쉬운 방법 중 하나는 **자신의 도메인을 블랙리스트에서 검색**하는 것입니다. 만약 목록에 올라와 있다면 어떤 식으로든 도메인이 의심 대상으로 감지된 것입니다. 도메인이 블랙리스트에 올라와 있는지 확인하는 간단한 방법은 [https://malwareworld.com/](https://malwareworld.com)을 이용하는 것입니다.

하지만 피해자가 **능동적으로 의심스러운 phishing 활동을 검색**하고 있는지 알 수 있는 다른 방법들도 있습니다. 자세한 내용은 다음을 참조하세요:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 도메인과 거의 동일한 이름의 도메인을 구매하거나, 본인이 제어하는 도메인의 서브도메인에 대해 피해자 도메인의 키워드를 포함하는 인증서를 **생성**할 수 있습니다. 피해자가 이들과 어떤 형태로든 **DNS 또는 HTTP 상호작용**을 한다면 그가 **능동적으로 의심 도메인을 탐지하고 있다**는 것을 알 수 있으며 매우 은밀하게 행동해야 합니다.

### Evaluate the phishing

이메일이 스팸 폴더로 갈지 차단될지 성공할지 평가하려면 [**Phishious**](https://github.com/Rices/Phishious)를 사용하세요.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

현대의 침입 그룹은 점점 이메일 미끼를 건너뛰고 **서비스 데스크 / identity-recovery 워크플로우를 직접 타깃**으로 하여 MFA를 우회합니다. 이 공격은 완전히 "living-off-the-land" 방식입니다: 운영자가 유효한 자격증명을 확보하면 내장 관리 툴로 피벗하며 – 멀웨어는 필요하지 않습니다.

### Attack flow
1. 피해자 정찰
- LinkedIn, 데이터 유출, 공개 GitHub 등에서 개인 및 기업 정보를 수집합니다.
- 고가치 식별자(임원, IT, 재무 등)를 식별하고 **정확한 help-desk의 비밀번호/MFA 리셋 절차**를 열거합니다.
2. 실시간 소셜 엔지니어링
- 전화, Teams 또는 채팅으로 help-desk에 접촉하여 대상자를 가장합니다(종종 **spoofed caller-ID**나 **클론 음성** 사용).
- 이전에 수집한 PII를 제공하여 지식 기반 인증을 통과합니다.
- 상담원을 설득하여 **MFA 시크릿을 재설정**하거나 등록된 휴대폰 번호에 대해 **SIM-swap**을 수행하게 합니다.
3. 즉각적인 접근 후 조치(실제 사례에서는 ≤60분)
- 웹 SSO 포털을 통해 발판을 마련합니다.
- 내장 도구로 AD / AzureAD를 열거합니다(바이너리 설치 없음):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
- 이미 환경에서 허용된 합법적인 RMM 에이전트 또는 **WMI**, **PsExec** 등을 사용해 lateral movement을 수행합니다.

### Detection & Mitigation
- help-desk identity recovery를 **권한 있는 작업(privileged operation)**으로 처리하세요 – step-up 인증 및 관리자 승인 요구.
- **Identity Threat Detection & Response (ITDR)** / **UEBA** 규칙을 배치하여 다음과 같은 사안을 경보하도록 하세요:
- MFA 방법 변경 + 새로운 장치/지리적 위치에서의 인증.
- 동일한 주체(user → admin)의 즉각적인 권한 상승.
- help-desk 통화를 기록하고 어떤 리셋 이전에 **이미 등록된 번호로 콜백**을 강제하세요.
- Just-In-Time (JIT) / Privileged Access를 구현하여 새로 리셋된 계정이 **자동으로 높은 권한 토큰을 상속하지 않도록** 하세요.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
대규모 조직들은 고접촉 작업의 비용을 보전하기 위해 **검색엔진 및 광고 네트워크를 전달 채널로 전환**하는 대량 공격을 실행합니다.

1. **SEO poisoning / malvertising**로 `chromium-update[.]site` 같은 가짜 결과를 검색 광고 상단에 올립니다.
2. 피해자는 작은 **1단계 로더**(주로 JS/HTA/ISO)를 다운로드합니다. Unit 42가 관찰한 예:
- `RedLine stealer`
- `Lumma stealer`
- `Lampion Trojan`
3. 로더는 브라우저 쿠키 + credential DB를 유출한 뒤 **무음 로더**를 내려받아 실시간으로 다음을 결정합니다:
- RAT (예: AsyncRAT, RustDesk)
- ransomware / wiper
- 영속성 컴포넌트(레지스트리 Run 키 + 예약 작업)

### Hardening tips
- 새로 등록된 도메인을 차단하고 *search-ads*에 대해 Advanced DNS / URL Filtering을 적용하세요.
- 소프트웨어 설치를 서명된 MSI / Store 패키지로 제한하고 정책으로 `HTA`, `ISO`, `VBS` 실행을 차단하세요.
- 브라우저의 자식 프로세스가 설치 프로그램을 여는 것을 모니터링하세요:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
- 1단계 로더에 자주 악용되는 LOLBins(e.g. `regsvr32`, `curl`, `mshta`)를 헌팅하세요.

---

## AI-Enhanced Phishing Operations
공격자들은 이제 **LLM & voice-clone APIs**를 연계하여 완전히 개인화된 미끼와 실시간 상호작용을 만듭니다.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**방어:**
• ARC/DKIM 이상으로부터 오는 메시지(비신뢰 자동화 발송)의 출처를 강조하는 **동적 배너**를 추가하세요.  
• 고위험 전화 요청에 대해 **음성 생체인식 챌린지 문구**를 배치하세요.  
• 인식 프로그램에서 AI 생성 미끼를 지속적으로 시뮬레이션하세요 – 정적 템플릿은 더 이상 충분하지 않습니다.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
클래식한 push-bombing 외에도, 운영자는 단순히 help-desk 통화 중에 **새로운 MFA 등록을 강제(reset)**하여 사용자의 기존 토큰을 무효화할 수 있습니다. 이후의 로그인 프롬프트는 피해자에게 합법적으로 보입니다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

공격자는 손상되었거나 typosquatted된 웹 페이지에서 피해자의 클립보드로 악성 명령을 조용히 복사한 뒤, 사용자가 **Win + R**, **Win + X** 또는 터미널 창에 붙여넣도록 속여 다운로드나 첨부 없이 임의의 코드를 실행시킬 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자들은 데스크탑 crawlers가 최종 페이지에 도달하지 못하도록 간단한 디바이스 체크 뒤에 phishing 흐름을 두는 경우가 늘고 있습니다. 일반적인 패턴은 touch-capable DOM을 테스트하고 그 결과를 server endpoint로 전송하는 작은 스크립트입니다; non‑mobile 클라이언트는 HTTP 500(또는 빈 페이지)을 받는 반면, 모바일 사용자는 전체 흐름을 제공받습니다.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 로직(단순화):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
서버에서 자주 관찰되는 동작:
- 첫 로드 시 세션 쿠키를 설정.
- Accepts `POST /detect {"is_mobile":true|false}`.
- `is_mobile=false`일 때 이후의 GET 요청에 500(또는 플레이스홀더)을 반환; `true`일 때만 phishing을 제공.

헌팅 및 탐지 휴리스틱:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- 웹 텔레메트리: `GET /static/detect_device.js` → `POST /detect` → 비모바일에 대해 HTTP 500; 정상 모바일 피해자 경로는 200과 후속 HTML/JS를 반환.
- 콘텐츠를 오직 `ontouchstart`나 유사한 디바이스 체크에만 의존해 조건부 제공하는 페이지는 차단하거나 면밀히 검토.

방어 팁:
- 모바일 유사 지문을 가진 크롤러로 JS를 활성화하여 차단된(게이티드) 콘텐츠를 노출.
- 신규 등록 도메인에서 `POST /detect` 후 발생한 의심스러운 500 응답에 대해 경보를 설정.

## 참고 자료

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
