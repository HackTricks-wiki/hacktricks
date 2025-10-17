# Phishing 방법론

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. Recon 대상 조사
1. **victim domain**를 선택합니다.
2. 대상이 사용하는 기본적인 웹 열거를 수행하여 **로그인 포털 검색(searching for login portals)**을 하고, 어떤 포털을 **사칭(impersonate)**할지 **결정(decide)** 합니다.
3. 일부 **OSINT**를 사용하여 **이메일 찾기(find emails)**를 합니다.
2. 환경 준비
1. phishing 평가에 사용할 도메인을 **구매(Buy the domain)** 합니다
2. 이메일 서비스 관련 레코드(SPF, DMARC, DKIM, rDNS)를 **구성(Configure the email service)** 합니다
3. VPS에 **gophish** 구성
3. 캠페인 준비
1. **이메일 템플릿(email template)** 준비
2. 자격 증명 탈취를 위한 **웹 페이지(web page)** 준비
4. 캠페인 시작!

## 유사 도메인 생성 또는 신뢰할 수 있는 도메인 구매

### Domain Name Variation Techniques

- **Keyword**: 도메인 이름이 원본 도메인의 중요한 **키워드**를 포함합니다 (예: zelster.com-management.com).
- **hypened subdomain**: 서브도메인의 **점(.)을 하이픈(-)**으로 변경합니다 (예: www-zelster.com).
- **New TLD**: 동일한 도메인에 **새 TLD** 사용 (예: zelster.org)
- **Homoglyph**: 도메인 이름의 문자를 **비슷하게 보이는 문자**로 대체합니다 (예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내에서 **두 글자를 서로 교환**합니다 (예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 끝에 “s”를 추가하거나 제거합니다 (예: zeltsers.com).
- **Omission**: 도메인 이름에서 **문자 하나를 제거**합니다 (예: zelser.com).
- **Repetition:** 도메인 이름의 문자 중 하나를 **중복**합니다 (예: zeltsser.com).
- **Replacement**: homoglyph와 유사하나 더 노골적입니다. 도메인 문자 중 하나를 키보드 상에서 인접한 문자 등으로 **대체**합니다 (예: zektser.com).
- **Subdomained**: 도메인 이름 안에 **점(.)을 추가**합니다 (예: ze.lster.com).
- **Insertion**: 도메인 이름에 **문자 하나를 삽입**합니다 (예: zerltser.com).
- **Missing dot**: 도메인 이름 뒤에 TLD를 붙여 단일 문자열로 만듭니다 (예: zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

태양흑점, 우주선 방사선, 하드웨어 오류 등 다양한 요인으로 저장되었거나 통신 중인 일부 비트가 **자동으로 뒤바뀔(bit flip)** 가능성이 있습니다.

이 개념이 **DNS 요청에 적용**될 경우, **DNS 서버가 수신한 도메인**이 처음 요청된 도메인과 동일하지 않을 수 있습니다.

예를 들어, "windows.com" 도메인에서 단일 비트가 수정되면 "windnws.com"으로 바뀔 수 있습니다.

공격자는 이러한 점을 이용해 피해자의 도메인과 유사한 여러 bit-flipping 도메인을 등록하여 합법적인 사용자를 자신의 인프라로 리디렉션하려 할 수 있습니다.

자세한 내용은 다음을 참조하세요: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 신뢰할 수 있는 도메인 구매

만료된 도메인을 찾으려면 [https://www.expireddomains.net/](https://www.expireddomains.net)에서 검색할 수 있습니다.\
구매하려는 만료 도메인이 **이미 좋은 SEO를 보유**하고 있는지 확인하려면 다음 서비스에서 분류 상태를 확인하세요:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 주소 발견

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 이메일 주소를 찾아내거나 이미 발견한 주소를 검증하려면, 대상의 SMTP 서버에 대해 사용자명 브루트포스를 시도해 확인할 수 있습니다. [여기에서 이메일 주소 검증/발견 방법을 알아보세요](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 **웹 포털을 통해 메일에 접근**하는 경우 해당 포털이 **username brute force**에 취약한지 확인하고, 가능하다면 그 취약점을 악용하는 것을 잊지 마세요.

## GoPhish 구성

### 설치

다음에서 다운로드할 수 있습니다: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

`/opt/gophish`에 다운로드하여 압축을 풀고 `/opt/gophish/gophish`를 실행하세요.\
출력에 포트 3333의 admin 사용자 비밀번호가 표시됩니다. 따라서 해당 포트에 접속하여 그 자격 증명을 사용해 admin 비밀번호를 변경하세요. 로컬로 포트를 터널링해야 할 수 있습니다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 전에 사용하려는 **도메인을 이미 구매**했어야 하며, 해당 도메인은 **gophish**를 구성하고 있는 **VPS의 IP**를 **가리키고 있어야 합니다**.
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

또한 /etc/postfix/main.cf 내부의 다음 변수 값들도 변경하세요

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작**하세요.

이제 `mail.<domain>`에 대한 **DNS A record**를 생성하여 VPS의 **IP 주소**를 가리키게 하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드를 생성하세요.

이제 이메일 전송을 테스트해봅니다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 설정**

gophish의 실행을 중지하고 구성합시다.\\
`/opt/gophish/config.json`을(를) 다음 내용으로 수정하십시오(https 사용에 유의):
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

gophish 서비스를 자동으로 시작하고 서비스로 관리할 수 있도록 다음 내용을 가진 파일 `/etc/init.d/gophish` 를 생성하면 됩니다:
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
서비스 구성을 마치고 다음을 확인하세요:
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

### 기다리고 정상적으로 보이기

도메인이 오래될수록 스팸으로 분류될 가능성이 낮아집니다. 따라서 phishing assessment 전에 가능한 한 오래(최소 1주) 기다리는 것이 좋습니다. 또한 평판이 중요한 분야에 대한 페이지를 넣으면 얻는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 설정을 완료할 수 있다는 점을 유의하세요.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 해석되도록 rDNS (PTR) 레코드를 설정하세요.

### Sender Policy Framework (SPF) 레코드

새 도메인에 대해 **SPF 레코드를 반드시 구성해야 합니다**. SPF 레코드가 무엇인지 모르면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF 정책을 생성하려면 [https://www.spfwizard.net/](https://www.spfwizard.net)을 사용할 수 있습니다 (VPS 머신의 IP를 사용하세요)

![](<../../images/image (1037).png>)

다음은 도메인의 TXT 레코드에 설정해야 할 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 도메인 기반 메시지 인증, 보고 및 적합성 (DMARC) 레코드

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**이 페이지를 읽으세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

다음 내용으로 호스트명 `_dmarc.<domain>`에 대한 새 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 **DKIM을 반드시 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**이 페이지를 읽으세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 개의 B64 값을 이어붙여야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

다음 사이트를 사용해 확인할 수 있습니다: [https://www.mail-tester.com/](https://www.mail-tester.com/)\
페이지에 접속해 그들이 제공하는 주소로 이메일을 보내면 됩니다:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 `check-auth@verifier.port25.com`으로 이메일을 보내 **이메일 구성을 확인**하고 **응답을 읽어보세요** (이 작업을 위해서는 **open** port **25** 상태여야 하며, 이메일을 root로 보낼 경우 응답을 _/var/mail/root_ 파일에서 확인하세요).\
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
**자신이 제어하는 Gmail 계정으로 메시지를** 보내고, Gmail 받은편지함에서 **이메일 헤더**를 확인할 수도 있습니다. `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse 블랙리스트에서 제거하기

The page [www.mail-tester.com](https://www.mail-tester.com)에서 도메인이 spamhouse에 의해 차단되었는지 확인할 수 있습니다. 도메인/IP 제거 요청은 다음에서 할 수 있습니다: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft 블랙리스트에서 제거하기

​​도메인/IP 제거 요청은 [https://sender.office.com/](https://sender.office.com)에서 할 수 있습니다.

## Create & Launch GoPhish Campaign

### Sending Profile

- 발신자 프로필을 식별할 수 있는 **이름 설정**
- 어떤 계정에서 피싱 이메일을 보낼지 결정하세요. 제안: _noreply, support, servicedesk, salesforce..._
- 사용자명(username)과 비밀번호(password)는 비워둘 수 있지만, 반드시 "Ignore Certificate Errors"을 체크하세요.

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 기능이 정상 작동하는지 확인하려면 "**Send Test Email**" 기능을 사용하는 것이 권장됩니다.\
> 테스트 중 블랙리스트에 오르는 것을 피하려면 **테스트 이메일을 10min mails 주소들로 보내는 것**을 권장합니다.

### Email Template

- 템플릿을 식별할 수 있는 **이름 설정**
- 그런 다음 **subject**를 작성하세요 (너무 이상하지 않고 일반 이메일에서 볼 법한 제목).
- 반드시 "**Add Tracking Image**"을 체크했는지 확인하세요.
- **email template**을 작성하세요 (다음 예시처럼 변수를 사용할 수 있습니다):
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

- Send an email to a **non existent address** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![](<../../images/image (80).png>)

> [!TIP]
> Email Template은 **보낼 파일을 첨부**할 수도 있습니다. 만약 특수 제작된 파일/문서로 NTLM challenge를 탈취하고 싶다면 [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> 보통은 페이지의 HTML 코드를 수정하고 로컬에서(예: Apache 서버를 사용해) 여러 번 테스트를 해서 **결과에 만족할 때까지** 조정합니다. 그런 다음 그 HTML 코드를 입력란에 붙여넣으세요.\
> HTML에 필요한 정적 리소스(예: CSS, JS)가 있다면 이를 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/\<filename>**_에서 접근할 수 있습니다.

> [!TIP]
> 리디렉션의 경우 **피해자 조직의 정상 메인 웹페이지로 리다이렉트**하거나 예를 들어 _/static/migration.html_로 리다이렉트하여 **스피닝 휠(**[**https://loading.io/**](https://loading.io)**)을 5초간 보여준 뒤 작업이 성공했다는 표시**를 하는 식으로 처리할 수 있습니다.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> 테스트 중 블랙리스트에 오르는 것을 피하려면 테스트 이메일은 **10min mails** 주소로 보내는 것을 권장합니다.

Once everything is ready, just launch the campaign!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In some phishing assessments (mainly for Red Teams) you will want to also **send files containing some kind of backdoor** (maybe a C2 or maybe just something that will trigger an authentication).\
Check out the following page for some examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

The previous attack is pretty clever as you are faking a real website and gathering the information set by the user. Unfortunately, if the user didn't put the correct password or if the application you faked is configured with 2FA, **this information won't allow you to impersonate the tricked user**.

This is where tools like [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) and [**muraena**](https://github.com/muraenateam/muraena) are useful. This tool will allow you to generate a MitM like attack. Basically, the attacks works in the following way:

1. You **impersonate the login** form of the real webpage.
2. The user **send** his **credentials** to your fake page and the tool send those to the real webpage, **checking if the credentials work**.
3. If the account is configured with **2FA**, the MitM page will ask for it and once the **user introduces** it the tool will send it to the real web page.
4. Once the user is authenticated you (as attacker) will have **captured the credentials, the 2FA, the cookie and any information** of every interaction your while the tool is performing a MitM.

### Via VNC

What if instead of **sending the victim to a malicious page** with the same looks as the original one, you send him to a **VNC session with a browser connected to the real web page**? You will be able to see what he does, steal the password, the MFA used, the cookies...\
You can do this with [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviously one of the best ways to know if you have been busted is to **search your domain inside blacklists**. If it appears listed, somehow your domain was detected as suspicions.\
One easy way to check if you domain appears in any blacklist is to use [https://malwareworld.com/](https://malwareworld.com)

However, there are other ways to know if the victim is **actively looking for suspicions phishing activity in the wild** as explained in:


{{#ref}}
detecting-phising.md
{{#endref}}

You can **buy a domain with a very similar name** to the victims domain **and/or generate a certificate** for a **subdomain** of a domain controlled by you **containing** the **keyword** of the victim's domain. If the **victim** perform any kind of **DNS or HTTP interaction** with them, you will know that **he is actively looking** for suspicious domains and you will need to be very stealth.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** pushes a fake result such as `chromium-update[.]site` to the top search ads.
2. Victim downloads a small **first-stage loader** (often JS/HTA/ISO).  Examples seen by Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Restrict software installation to signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution by policy.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Attackers now chain **LLM & voice-clone APIs** for fully personalised lures and real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Add **dynamic banners** highlighting messages sent from untrusted automation (via ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** for high-risk phone requests.
• Continuously simulate AI-generated lures in awareness programmes – static templates are obsolete.

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
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

공격자는 손상되거나 타이포스쿼팅된 웹 페이지에서 피해자의 클립보드에 악성 명령을 몰래 복사한 다음 사용자가 **Win + R**, **Win + X** 또는 터미널 창에 붙여넣도록 유도해, 다운로드나 첨부 파일 없이 임의 코드를 실행시킬 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자들은 데스크톱 크롤러가 최종 페이지에 도달하지 못하도록 간단한 디바이스 검사 뒤에 phishing 흐름을 점점 더 숨깁니다. 흔한 패턴은 터치 가능 DOM을 검사하고 결과를 서버 엔드포인트에 전송하는 작은 스크립트입니다; 비‑모바일 클라이언트는 HTTP 500(또는 빈 페이지)을 받는 반면 모바일 사용자는 전체 흐름을 제공받습니다.

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
Server behaviour often observed:
- 첫 로드 시 세션 쿠키를 설정한다.
- `POST /detect {"is_mobile":true|false}` 를 수신한다.
- 이후의 GET 요청에 대해 `is_mobile=false` 일 때 500(또는 플레이스홀더)을 반환한다; `true`인 경우에만 피싱을 제공한다.

Hunting and detection heuristics:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- 웹 텔레메트리: `GET /static/detect_device.js` → `POST /detect` → 비모바일의 경우 HTTP 500; 실제 모바일 피해자 경로는 200과 후속 HTML/JS를 반환한다.
- 콘텐츠를 오직 `ontouchstart` 또는 유사한 디바이스 검사에만 기반해 표시하는 페이지는 차단하거나 면밀히 검토하라.

Defence tips:
- 모바일 유사 지문을 가진 크롤러를 JS 활성화 상태로 실행해 게이트된 콘텐츠를 노출시켜라.
- 새로 등록된 도메인에서 `POST /detect` 이후 발생하는 의심스러운 500 응답에 대해 경보를 설정하라.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
