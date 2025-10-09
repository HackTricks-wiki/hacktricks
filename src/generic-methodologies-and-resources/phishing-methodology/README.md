# Методологія Phishing

{{#include ../../banners/hacktricks-training.md}}

## Методологія

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
### Налаштування

**Конфігурація TLS сертифіката**

Перед цим кроком ви повинні **вже купити домен**, який збираєтеся використовувати, і він має **вказувати** на **IP of the VPS**, де ви налаштовуєте **gophish**.
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
**Налаштування пошти**

Почніть встановлення: `apt-get install postfix`

Потім додайте домен у наступні файли:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення наступних змінних у /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваш домен і **перезапустіть ваш VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, що вказує на **ip address** вашого VPS, і **DNS MX** запис, що вказує на `mail.<domain>`

Тепер перевіримо відправку електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish конфігурація**

Зупиніть виконання gophish і давайте його налаштуємо.\
Змініть `/opt/gophish/config.json` на наступне (зверніть увагу на використання https):
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
**Налаштування сервісу gophish**

Щоб створити сервіс gophish так, щоб його можна було запускати автоматично та керувати ним як сервісом, створіть файл `/etc/init.d/gophish` з таким вмістом:
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
Завершіть налаштування сервісу та перевірте його, виконавши:
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
## Налаштування поштового сервера та домену

### Зачекайте й будьте легітимними

Чим старший домен, тим менш імовірно, що його визнають спамом. Тому слід чекати якомога довше (щонайменше 1 тиждень) перед phishing assessment. Крім того, якщо розмістити сторінку про репутаційний сектор, отримана репутація буде кращою.

Зауважте, що навіть якщо доведеться чекати тиждень, ви можете завершити конфігурацію вже зараз.

### Configure Reverse DNS (rDNS) record

Встановіть rDNS (PTR) запис, який зв'язує IP-адресу VPS з ім'ям домену.

### Sender Policy Framework (SPF) Record

Ви повинні **налаштувати SPF запис для нового домену**. Якщо ви не знаєте, що таке SPF запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF політики (використайте IP-адресу VPS)

![](<../../images/image (1037).png>)

Це вміст, який потрібно встановити в TXT записі домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Запис DMARC (Domain-based Message Authentication, Reporting & Conformance)

Ви повинні **налаштувати DMARC-запис для нового домену**. Якщо ви не знаєте, що таке DMARC-запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Ви маєте створити новий DNS TXT-запис, що вказує на хостнейм `_dmarc.<domain>` з таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Вам потрібно об'єднати обидва B64-значення, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронний лист на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити налаштування електронної пошти**, надіславши листа на `check-auth@verifier.port25.com` і **переглянути відповідь** (для цього потрібно **відкрити** порт **25** та подивитися відповідь у файлі _/var/mail/root_, якщо ви надсилаєте лист від імені root).\
Переконайтеся, що ви проходите всі тести:
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
Ви також можете надіслати **лист на Gmail під вашим контролем**, і перевірити **заголовки електронного листа** у своїй поштовій скриньці Gmail, `dkim=pass` має бути присутнім у полі заголовка `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Видалення з чорного списку Spamhouse

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може вказати вам, чи ваш домен блокується spamhouse. Ви можете запросити видалення вашого домену/IP за адресою: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з чорного списку Microsoft

Ви можете запросити видалення вашого домену/IP на [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль відправника

- Вкажіть **назву для ідентифікації** профілю відправника
- Визначте, з якого облікового запису ви будете надсилати phishing emails. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити порожніми ім'я користувача та пароль, але обов'язково поставте галочку Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**" щоб перевірити, чи все працює.\
> Раджу **надсилати тестові листи на адреси 10min mails** щоб уникнути потрапляння в чорний список під час тестів.

### Шаблон листа

- Вкажіть **назву для ідентифікації** шаблону
- Потім напишіть **тему** (нічого дивного, просто те, що ви могли б очікувати в звичайному листі)
- Переконайтеся, що встановлено "**Add Tracking Image**"
- Напишіть **шаблон листа** (ви можете використовувати змінні, як у наведеному прикладі):
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
Зауважте, що **щоб підвищити правдоподібність листа**, рекомендується використати якийсь підпис із реального листа від клієнта. Пропозиції:

- Надішліть листа на **неіснуючу адресу** і перевірте, чи відповідь містить підпис.
- Знайдіть **публічні email** типу info@ex.com або press@ex.com чи public@ex.com і надішліть їм листа, дочекавшись відповіді.
- Спробуйте зв’язатися з **якою-небудь виявленою дійсною** адресою і дочекайтеся відповіді

![](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **додавати файли до відправки**. Якщо ви також хочете вкрасти NTLM challenges за допомогою спеціально сконструйованих файлів/документів, [читайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **ім'я**
- **Напишіть HTML-код** веб-сторінки. Зверніть увагу, що ви можете **імпортувати** веб-сторінки.
- Позначте **Capture Submitted Data** та **Capture Passwords**
- Встановіть **редирект**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам доведеться відредагувати HTML-код сторінки і протестувати локально (можливо, використовуючи Apache) **доки результат вас не влаштує.** Потім вставте цей HTML-код у поле.\
> Зауважте, якщо вам потрібно **використати якісь статичні ресурси** для HTML (наприклад CSS або JS), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім звертатися до них з _**/static/\<filename>**_

> [!TIP]
> Для редиректу ви можете **перенаправити користувачів на легітимну головну сторінку** жертви, або на _/static/migration.html_, наприклад, показати **спіннер** ([https://loading.io/](https://loading.io)) протягом 5 секунд, а потім повідомити, що процес пройшов успішно.

### Users & Groups

- Задайте ім'я
- **Імпортуйте дані** (зауважте, що щоб використати шаблон як приклад, вам потрібні firstname, last name та email address кожного користувача)

![](<../../images/image (163).png>)

### Campaign

Нарешті, створіть кампанію, обравши назву, email template, landing page, URL, sending profile та group. Зауважте, що URL буде лінком, який буде надіслано жертвам.

Зверніть увагу, що **Sending Profile дозволяє надіслати тестовий лист, щоб побачити, як виглядатиме фінальний фішинг-лист**:

![](<../../images/image (192).png>)

> [!TIP]
> Рекомендую **надсилати тестові листи на адреси 10min mails**, щоб уникнути блокування під час тестів.

Коли все готово — просто запустіть кампанію!

## Website Cloning

Якщо з якоїсь причини ви хочете клонувати вебсайт, перегляньте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких фішингових оцінках (головним чином для Red Teams) ви також захочете **надіслати файли, що містять бекдор** (наприклад C2 або щось, що спровокує автентифікацію).\
Дивіться наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака досить витончена, оскільки ви підробляєте реальний вебсайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний пароль або якщо додаток, який ви підробили, налаштований з 2FA, **ця інформація не дозволить вам видати себе за обдуреного користувача**.

Тут корисні інструменти на кшталт [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Ці інструменти дозволяють реалізувати MitM-атаку. По суті, атака працює так:

1. Ви **підроблюєте форму входу** реальної веб-сторінки.
2. Користувач **надсилає** свої **облікові дані** на вашу фальшиву сторінку, і інструмент пересилає їх на реальний сайт, **перевіряючи, чи працюють дані**.
3. Якщо акаунт налаштований з **2FA**, сторінка MitM попросить його, і коли **користувач введе** код, інструмент передасть його на реальний вебсайт.
4. Після автентифікації користувача ви (як атакуючий) отримаєте **захоплені credentials, 2FA, cookie та будь-яку інформацію** про кожну взаємодію, поки інструмент здійснює MitM.

### Via VNC

А що як замість того, щоб **надсилати жертву на зловмисну сторінку**, яка виглядає як оригінальна, ви відправите її в **VNC-сесію з браузером, підключеним до реальної сторінки**? Ви зможете бачити його дії, вкрасти пароль, MFA, кукі...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із найпростіших способів дізнатися, що вас викрили — це **перевірити свій домен у чорних списках**. Якщо він вказаний, значить ваш домен був позначений як підозрілий.\
Простий спосіб перевірити, чи з'являється ваш домен у чорних списках — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи жертва **активно шукає підозрілу фішингову активність у мережі**, як описано в:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити домен із дуже схожою назвою** на домен жертви **і/або згенерувати сертифікат** для **субдомену** домену, яким ви керуєте, **що містить ключове слово** домену жертви. Якщо **жертва** виконає будь-яку DNS або HTTP взаємодію з ними, ви дізнаєтеся, що **вона активно шукає** підозрілі домени, і вам потрібно буде діяти дуже обережно.

### Оцінка фішингу

Використовуйте [**Phishious**](https://github.com/Rices/Phishious), щоб оцінити, чи ваш лист потрапить у спам, буде заблокований або вважатиметься успішним.

## High- Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні групи зловмисників усе частіше повністю відмовляються від email-lures і **безпосередньо атакують службу підтримки / workflow відновлення ідентичності**, щоб обійти MFA. Атака повністю «living-off-the-land»: коли оператор має дійсні облікові дані, він перемикається на вбудовані адмін-інструменти — шкідливе ПЗ не потрібне.

### Схема атаки
1. Recon жертви
* Збирайте персональні та корпоративні дані з LinkedIn, витоків даних, публічного GitHub тощо.
* Визначте цінні ідентичності (керівники, IT, фінанси) і перелічіть **точний процес help-desk** для скидання пароля / MFA.
2. Соціальна інженерія в реальному часі
* Дзвінки, Teams або чат службі підтримки, прикидаючись ціллю (часто з **підробленим Caller-ID** або **клонованим голосом**).
* Надайте заздалегідь зібрані PII для проходження перевірки знанням.
* Переконайте агента **скинути MFA-секрет** або виконати **SIM-swap** на зареєстрований мобільний номер.
3. Негайні дії після доступу (≤60 хв у реальних випадках)
* Встановіть плацдарм через будь-який web SSO портал.
* Перелічіть AD / AzureAD за допомогою вбудованих інструментів (без завантаження бінарників):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Рух латерально з використанням **WMI**, **PsExec**, або легітимних **RMM** агентів, які вже внесені до білого списку в середовищі.

### Виявлення та пом’якшення
* Розглядайте відновлення ідентичності через help-desk як **привілейовану операцію** — вимагайте step-up auth та затвердження менеджера.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, що сигналізують про:
* Зміну методу MFA + автентифікацію з нового пристрою / гео.
* Негайне підвищення привілеїв того самого принципала (user → admin).
* Записуйте дзвінки до служби підтримки і вимагайте **повернесь на вже зареєстрований номер** перед будь-яким скиданням.
* Впровадьте **Just-In-Time (JIT) / Privileged Access**, щоб не дозволяти недавно скинутим акаунтам автоматично отримувати високопривілейовані токени.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Масові групи покривають витрати на високоточні операції масовими атаками, які перетворюють **пошукові системи та рекламні мережі на канал доставки**.

1. **SEO poisoning / malvertising** просуває фальшивий результат, наприклад `chromium-update[.]site`, у верхні рекламні позиції.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, що були виявлені Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader викачує cookies браузера + credential DBs, потім тягне **silent loader**, який у режимі реального часу вирішує, чи розгортати:
* RAT (наприклад AsyncRAT, RustDesk)
* ransomware / wiper
* компонент персистентності (registry Run key + scheduled task)

### Поради з жорсткості
* Блокуйте новозареєстровані домени та впровадьте **Advanced DNS / URL Filtering** для *search-ads*, а також для email.
* Обмежте встановлення ПЗ лише підписаними MSI / Store пакетами, забороніть виконання `HTA`, `ISO`, `VBS` політикою.
* Моніторте дочірні процеси браузерів, що відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Шукайте LOLBins, які часто використовуються першими лоадерами (наприклад `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Атакуючі тепер поєднують **LLM & voice-clone APIs** для повністю персоналізованих приманок та взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Генерують і надсилають >100k листів / SMS з рандомізованими формулюваннями та трекінговими лінками.|
|Generative AI|Створюють одноразові листи, що посилаються на публічні M&A, внутрішні жарти з соцмереж; deep-fake голос CEO у callback-шахрайстві.|
|Agentic AI|Автономно реєструють домени, збирають open-source intel, готують наступні листи, якщо жертва клікнула, але не відправила credentials.|

**Захист:**
• Додавайте **динамічні банери**, які виділяють повідомлення, надіслані з недовіреної автоматизації (через аномалії ARC/DKIM).  
• Впроваджуйте **voice-biometric challenge phrases** для запитів по телефону з високим ризиком.  
• Постійно імітуйте AI-згенеровані приманки в програмах підвищення обізнаності — статичні шаблони застарівають.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Окрім класичного push-bombing, оператори просто **примушують до нової реєстрації MFA** під час дзвінка в help-desk, анулюючи існуючий токен користувача. Будь-який наступний запит входу виглядатиме для жертви легітимно.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Моніторити події AzureAD/AWS/Okta, де **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї самої IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди у буфер обміну жертви з скомпрометованої або typosquatted веб-сторінки, а потім обманути користувача, щоб він вставив їх у **Win + R**, **Win + X** або в термінал, що призведе до виконання довільного коду без завантаження чи вкладень.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори все частіше ховають свої phishing flows за простою перевіркою пристрою, щоб desktop crawlers ніколи не потрапляли на кінцеві сторінки. Поширений патерн — невеликий скрипт, який перевіряє наявність touch-capable DOM і відправляє результат на server endpoint; non‑mobile клієнти отримують HTTP 500 (або порожню сторінку), тоді як mobile користувачам подається повний flow.

Мінімальний клієнтський фрагмент (типова логіка):
```html
<script src="/static/detect_device.js"></script>
```
Логіка `detect_device.js` (спрощено):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Часто спостережувана поведінка сервера:
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або заглушку) на подальні GET-запити коли `is_mobile=false`; показує фішинг лише якщо `true`.

Пошук і евристики виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Веб-телеметрія: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для немобільних; легітимні мобільні шляхи жертви повертають 200 з подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які умовно відображають вміст виключно на основі `ontouchstart` або подібних перевірок пристрою.

Поради щодо захисту:
- Запускайте краулери з мобільно-подібними fingerprints та увімкненим JS, щоб виявити закритий контент.
- Налаштуйте сповіщення про підозрілі відповіді 500, що слідують за `POST /detect` на нещодавно зареєстрованих доменах.

## Джерела

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
