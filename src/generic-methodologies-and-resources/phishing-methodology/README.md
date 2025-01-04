# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 피해자 조사
1. **피해자 도메인** 선택.
2. 피해자가 사용하는 **로그인 포털**을 찾기 위해 기본 웹 열거 수행하고 **사칭할** 포털 결정.
3. **OSINT**를 사용하여 **이메일** 찾기.
2. 환경 준비
1. 피싱 평가에 사용할 **도메인 구매**
2. 관련 기록(SPF, DMARC, DKIM, rDNS)으로 **이메일 서비스 구성**
3. **gophish**로 VPS 구성
3. 캠페인 준비
1. **이메일 템플릿** 준비
2. 자격 증명을 훔치기 위한 **웹 페이지** 준비
4. 캠페인 시작!

## 유사 도메인 이름 생성 또는 신뢰할 수 있는 도메인 구매

### 도메인 이름 변형 기법

- **키워드**: 도메인 이름에 원래 도메인의 중요한 **키워드** 포함 (예: zelster.com-management.com).
- **하이픈 서브도메인**: 서브도메인의 **점**을 **하이픈**으로 변경 (예: www-zelster.com).
- **새 TLD**: **새 TLD**를 사용하는 동일 도메인 (예: zelster.org)
- **호모글리프**: 도메인 이름의 문자를 **비슷하게 보이는 문자**로 **대체** (예: zelfser.com).
- **전치**: 도메인 이름 내에서 두 문자를 **교환** (예: zelsetr.com).
- **단수화/복수화**: 도메인 이름 끝에 “s”를 추가하거나 제거 (예: zeltsers.com).
- **생략**: 도메인 이름에서 **하나의 문자**를 **제거** (예: zelser.com).
- **반복**: 도메인 이름에서 **하나의 문자**를 **반복** (예: zeltsser.com).
- **대체**: 호모글리프와 유사하지만 덜 은밀함. 도메인 이름의 문자 중 하나를 원래 문자와 키보드에서 가까운 문자로 대체 (예: zektser.com).
- **서브도메인화**: 도메인 이름 내에 **점**을 추가 (예: ze.lster.com).
- **삽입**: 도메인 이름에 **문자**를 **삽입** (예: zerltser.com).
- **누락된 점**: 도메인 이름에 TLD를 추가 (예: zelstercom.com)

**자동 도구**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**웹사이트**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### 비트 플리핑

**저장되거나 통신 중인 일부 비트가 자동으로 뒤집힐 가능성**이 있습니다. 이는 태양 플레어, 우주선, 하드웨어 오류와 같은 다양한 요인으로 인해 발생할 수 있습니다.

이 개념이 **DNS 요청에 적용될 때**, **DNS 서버에서 수신된 도메인**이 처음 요청한 도메인과 다를 수 있습니다.

예를 들어, "windows.com"의 단일 비트 수정은 "windnws.com"으로 변경될 수 있습니다.

공격자는 **피해자의 도메인과 유사한 여러 비트 플리핑 도메인을 등록하여 이를 이용할 수 있습니다**. 그들의 의도는 합법적인 사용자를 자신의 인프라로 리디렉션하는 것입니다.

자세한 내용은 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)을 읽어보세요.

### 신뢰할 수 있는 도메인 구매

[https://www.expireddomains.net/](https://www.expireddomains.net)에서 사용할 수 있는 만료된 도메인을 검색할 수 있습니다.\
구매할 만료된 도메인이 **이미 좋은 SEO**를 가지고 있는지 확인하기 위해 다음에서 분류를 검색할 수 있습니다:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 이메일 발견

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 무료)
- [https://phonebook.cz/](https://phonebook.cz) (100% 무료)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

**더 많은** 유효한 이메일 주소를 **발견하거나** 이미 발견한 이메일 주소를 **검증**하기 위해 피해자의 SMTP 서버를 브루트포스할 수 있는지 확인할 수 있습니다. [이메일 주소를 검증/발견하는 방법은 여기에서 확인하세요](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
또한 사용자가 **메일에 접근하기 위해 웹 포털을 사용하는 경우**, 해당 포털이 **사용자 이름 브루트포스**에 취약한지 확인하고 가능하다면 취약점을 악용하는 것을 잊지 마세요.

## GoPhish 구성

### 설치

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)에서 다운로드할 수 있습니다.

다운로드 후 `/opt/gophish`에 압축을 풀고 `/opt/gophish/gophish`를 실행하세요.\
출력에서 포트 3333의 관리자 사용자 비밀번호가 제공됩니다. 따라서 해당 포트에 접근하고 해당 자격 증명을 사용하여 관리자 비밀번호를 변경하세요. 이 포트를 로컬로 터널링해야 할 수도 있습니다.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 구성

**TLS 인증서 구성**

이 단계 전에 **사용할 도메인을 이미 구매**해야 하며, 해당 도메인은 **gophish**를 구성하는 **VPS의 IP**를 **가리켜야** 합니다.
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

그런 다음 도메인을 다음 파일에 추가합니다:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 내부의 다음 변수 값도 변경합니다.

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

마지막으로 **`/etc/hostname`** 및 **`/etc/mailname`** 파일을 도메인 이름으로 수정하고 **VPS를 재시작합니다.**

이제 **DNS A 레코드**를 `mail.<domain>`으로 생성하고 **VPS의 IP 주소**를 가리키며, **DNS MX** 레코드를 `mail.<domain>`으로 설정합니다.

이제 이메일을 보내는 테스트를 해봅시다:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 구성**

gophish의 실행을 중지하고 구성합시다.\
`/opt/gophish/config.json`을 다음과 같이 수정합니다 (https 사용에 유의하세요):
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

gophish 서비스를 자동으로 시작하고 관리할 수 있도록 하려면 다음 내용을 포함한 파일 `/etc/init.d/gophish`를 생성할 수 있습니다:
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
## 메일 서버 및 도메인 구성

### 기다리고 합법적으로 행동하기

도메인이 오래될수록 스팸으로 잡힐 가능성이 낮아집니다. 따라서 피싱 평가 전에 가능한 한 오랫동안 (최소 1주일) 기다려야 합니다. 또한, 평판이 좋은 분야에 대한 페이지를 만들면 얻는 평판이 더 좋습니다.

1주일을 기다려야 하더라도 지금 모든 구성을 마칠 수 있다는 점에 유의하세요.

### 리버스 DNS (rDNS) 레코드 구성

VPS의 IP 주소를 도메인 이름으로 해석하는 rDNS (PTR) 레코드를 설정하세요.

### 발신자 정책 프레임워크 (SPF) 레코드

새 도메인에 대해 **SPF 레코드를 구성해야 합니다**. SPF 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

[https://www.spfwizard.net/](https://www.spfwizard.net) 를 사용하여 SPF 정책을 생성할 수 있습니다 (VPS 머신의 IP를 사용하세요).

![](<../../images/image (1037).png>)

도메인 내 TXT 레코드에 설정해야 하는 내용은 다음과 같습니다:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

새 도메인에 대해 **DMARC 레코드를 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

다음 내용을 포함하여 호스트 이름 `_dmarc.<domain>`을 가리키는 새로운 DNS TXT 레코드를 생성해야 합니다:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

새 도메인에 대해 **DKIM을 구성해야 합니다**. DMARC 레코드가 무엇인지 모른다면 [**이 페이지를 읽어보세요**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

이 튜토리얼은 다음을 기반으로 합니다: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> DKIM 키가 생성하는 두 B64 값을 연결해야 합니다:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 이메일 구성 점수 테스트

[https://www.mail-tester.com/](https://www.mail-tester.com) 를 사용하여 테스트할 수 있습니다.\
페이지에 접속하여 그들이 제공하는 주소로 이메일을 보내세요:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
당신은 또한 **이메일 구성을 확인할 수 있습니다** `check-auth@verifier.port25.com`으로 이메일을 보내고 **응답을 읽는 것** (이를 위해서는 **포트 25**를 **열고** 이메일을 루트로 보냈을 경우 _/var/mail/root_ 파일에서 응답을 확인해야 합니다).\
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
당신은 또한 **당신이 제어하는 Gmail로 메시지를 보낼 수** 있으며, Gmail 받은편지함에서 **이메일의 헤더**를 확인할 수 있습니다. `dkim=pass`는 `Authentication-Results` 헤더 필드에 있어야 합니다.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​스팸하우스 블랙리스트에서 제거하기

페이지 [www.mail-tester.com](https://www.mail-tester.com)은 귀하의 도메인이 스팸하우스에 의해 차단되고 있는지 확인할 수 있습니다. 귀하의 도메인/IP를 제거 요청할 수 있는 곳: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 마이크로소프트 블랙리스트에서 제거하기

​​귀하의 도메인/IP를 제거 요청할 수 있는 곳: [https://sender.office.com/](https://sender.office.com).

## GoPhish 캠페인 생성 및 시작

### 발신자 프로필

- 발신자 프로필을 식별할 **이름**을 설정합니다.
- 피싱 이메일을 보낼 계정을 결정합니다. 제안: _noreply, support, servicedesk, salesforce..._
- 사용자 이름과 비밀번호는 비워둘 수 있지만, 인증서 오류 무시를 체크하는 것을 잊지 마세요.

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> "**테스트 이메일 보내기**" 기능을 사용하여 모든 것이 작동하는지 테스트하는 것이 좋습니다.\
> 테스트를 진행할 때 블랙리스트에 올라가는 것을 피하기 위해 **10분 메일 주소로 테스트 이메일을 보내는 것을 추천합니다.**

### 이메일 템플릿

- 템플릿을 식별할 **이름**을 설정합니다.
- 그런 다음 **제목**을 작성합니다 (이상한 것이 아닌, 일반 이메일에서 읽을 수 있는 내용).
- "**추적 이미지 추가**"를 체크했는지 확인합니다.
- **이메일 템플릿**을 작성합니다 (다음 예제와 같이 변수를 사용할 수 있습니다):
```markup
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
**이메일의 신뢰성을 높이기 위해** 클라이언트의 이메일 서명을 사용하는 것이 권장됩니다. 제안 사항:

- **존재하지 않는 주소**로 이메일을 보내고 응답에 서명이 있는지 확인합니다.
- info@ex.com, press@ex.com 또는 public@ex.com과 같은 **공개 이메일**을 검색하고 이메일을 보내고 응답을 기다립니다.
- **유효한 발견된** 이메일에 연락을 시도하고 응답을 기다립니다.

![](<../../images/image (80).png>)

> [!NOTE]
> 이메일 템플릿은 **전송할 파일을 첨부**할 수 있습니다. NTLM 챌린지를 도용하기 위해 특별히 제작된 파일/문서를 사용하고 싶다면 [이 페이지를 읽어보세요](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### 랜딩 페이지

- **이름**을 작성합니다.
- 웹 페이지의 **HTML 코드를 작성**합니다. 웹 페이지를 **가져올** 수 있습니다.
- **제출된 데이터 캡처** 및 **비밀번호 캡처**를 선택합니다.
- **리디렉션**을 설정합니다.

![](<../../images/image (826).png>)

> [!NOTE]
> 일반적으로 페이지의 HTML 코드를 수정하고 로컬에서 몇 가지 테스트를 수행해야 합니다(아마도 Apache 서버를 사용하여) **결과가 마음에 들 때까지**. 그런 다음 해당 HTML 코드를 상자에 작성합니다.\
> HTML에 **정적 리소스**(아마도 CSS 및 JS 페이지)를 사용해야 하는 경우 _**/opt/gophish/static/endpoint**_에 저장한 다음 _**/static/\<filename>**_에서 액세스할 수 있습니다.

> [!NOTE]
> 리디렉션을 위해 **사용자를 피해자의 합법적인 메인 웹 페이지로 리디렉션**하거나 예를 들어 _/static/migration.html_로 리디렉션하여 **5초 동안 회전하는 휠**([**https://loading.io/**](https://loading.io)**)을 표시한 후 프로세스가 성공적으로 완료되었음을 알릴 수 있습니다.**

### 사용자 및 그룹

- 이름을 설정합니다.
- **데이터를 가져옵니다**(예제를 위한 템플릿을 사용하려면 각 사용자의 이름, 성 및 이메일 주소가 필요합니다).

![](<../../images/image (163).png>)

### 캠페인

마지막으로 이름, 이메일 템플릿, 랜딩 페이지, URL, 전송 프로필 및 그룹을 선택하여 캠페인을 생성합니다. URL은 피해자에게 전송될 링크가 됩니다.

**전송 프로필은 최종 피싱 이메일이 어떻게 보일지 테스트 이메일을 보낼 수 있게 해줍니다**:

![](<../../images/image (192).png>)

> [!NOTE]
> 테스트 이메일을 **10분 메일 주소**로 보내는 것이 좋습니다. 테스트를 하면서 블랙리스트에 올라가는 것을 피할 수 있습니다.

모든 준비가 완료되면 캠페인을 시작하세요!

## 웹사이트 클로닝

어떤 이유로 웹사이트를 클론하고 싶다면 다음 페이지를 확인하세요:

{{#ref}}
clone-a-website.md
{{#endref}}

## 백도어가 포함된 문서 및 파일

일부 피싱 평가(주로 레드 팀의 경우)에서는 **백도어가 포함된 파일을 전송**하고 싶을 수 있습니다(아마도 C2 또는 인증을 트리거하는 것일 수 있습니다).\
다음 페이지에서 몇 가지 예를 확인하세요:

{{#ref}}
phishing-documents.md
{{#endref}}

## 피싱 MFA

### 프록시 MitM를 통한

이전 공격은 실제 웹사이트를 가장하고 사용자가 설정한 정보를 수집하는 매우 영리한 방법입니다. 불행히도 사용자가 올바른 비밀번호를 입력하지 않거나 가장한 애플리케이션이 2FA로 구성된 경우, **이 정보로는 속은 사용자를 가장할 수 없습니다**.

이럴 때 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 및 [**muraena**](https://github.com/muraenateam/muraena)와 같은 도구가 유용합니다. 이 도구는 MitM과 같은 공격을 생성할 수 있게 해줍니다. 기본적으로 공격은 다음과 같이 작동합니다:

1. 실제 웹페이지의 로그인 양식을 **가장합니다**.
2. 사용자가 **자신의 자격 증명**을 가짜 페이지로 **보내고**, 도구는 이를 실제 웹페이지로 전송하여 **자격 증명이 작동하는지 확인합니다**.
3. 계정이 **2FA**로 구성된 경우, MitM 페이지는 이를 요청하고 사용자가 **입력**하면 도구가 이를 실제 웹페이지로 전송합니다.
4. 사용자가 인증되면 공격자는 **자격 증명, 2FA, 쿠키 및 도구가 MitM을 수행하는 동안의 모든 상호작용 정보를 캡처**하게 됩니다.

### VNC를 통한

**피해자를 원래와 동일한 모습의 악성 페이지로 보내는 대신**, **실제 웹 페이지에 연결된 브라우저가 있는 VNC 세션으로 보내는** 것은 어떨까요? 사용자가 하는 일을 보고 비밀번호, 사용된 MFA, 쿠키 등을 도용할 수 있습니다.\
이것은 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)로 수행할 수 있습니다.

## 탐지 감지

당연히 자신이 발각되었는지 아는 가장 좋은 방법 중 하나는 **블랙리스트에서 자신의 도메인을 검색하는 것**입니다. 목록에 나타나면, 어떤 식으로든 귀하의 도메인이 의심스러운 것으로 감지된 것입니다.\
도메인이 블랙리스트에 나타나는지 확인하는 쉬운 방법은 [https://malwareworld.com/](https://malwareworld.com) 를 사용하는 것입니다.

그러나 피해자가 **실제로 의심스러운 피싱 활동을 찾고 있는지** 아는 다른 방법도 있습니다. 이는 다음과 같이 설명됩니다:

{{#ref}}
detecting-phising.md
{{#endref}}

피해자의 도메인과 **매우 유사한 이름의 도메인을 구매**하거나 **귀하가 제어하는 도메인의 서브도메인에 대한 인증서를 생성**할 수 있습니다. 피해자의 도메인의 **키워드**를 포함하는 경우입니다. **피해자**가 이들과 어떤 종류의 **DNS 또는 HTTP 상호작용**을 수행하면, **그가 의심스러운 도메인을 적극적으로 찾고 있다는 것을 알 수 있으며**, 매우 은밀해야 합니다.

### 피싱 평가

[**Phishious**](https://github.com/Rices/Phishious)를 사용하여 이메일이 스팸 폴더에 들어갈지, 차단될지, 성공할지를 평가하세요.

## 참고 문헌

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
