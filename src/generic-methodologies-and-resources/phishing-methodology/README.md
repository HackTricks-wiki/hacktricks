# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Recon жертви
1. Select the **victim domain**.
2. Perform some basic web enumeration **шукаючи портали для входу** used by the victim and **вирішіть** which one you will **імітовати**.
3. Use some **OSINT** to **знайти електронні адреси**.
2. Підготуйте середовище
1. **Купіть домен** you are going to use for the phishing assessment
2. **Налаштуйте записи поштового сервісу** related records (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон листа**
2. Підготуйте **веб-сторінку** щоб вкрасти облікові дані
4. Запустіть кампанію!

## Generate similar domain names or buy a trusted domain

### Техніки варіювання імен доменів

- **Keyword**: Ім'я домену **містить** важливе **ключове слово** оригінального домену (e.g., zelster.com-management.com).
- **hypened subdomain**: Замініть **крапку на дефіс** у субдомені (e.g., www-zelster.com).
- **New TLD**: Той самий домен з **новим TLD** (e.g., zelster.org)
- **Homoglyph**: Він **замінює** букву в імені домену на **літери, які виглядають схоже** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Він **міняє місцями дві літери** в імені домену (e.g., zelsetr.com).
- **Singularization/Pluralization**: Додає або видаляє “s” в кінці імені домену (e.g., zeltsers.com).
- **Omission**: Він **видаляє одну** з літер з імені домену (e.g., zelser.com).
- **Repetition:** Він **повторює одну** з літер в імені домену (e.g., zeltsser.com).
- **Replacement**: Як homoglyph, але менш приховано. Він замінює одну з літер в імені домену, можливо на літеру поруч з оригіналом на клавіатурі (e.g, zektser.com).
- **Subdomained**: Вставляє **крапку** всередину імені домену (e.g., ze.lster.com).
- **Insertion**: Він **вставляє літеру** в ім'я домену (e.g., zerltser.com).
- **Missing dot**: Додає TLD до імені домену без крапки. (e.g., zelstercom.com)

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **можливість, що один або декілька бітів, збережених або під час передачі, можуть автоматично змінитися** через різні фактори, такі як сонячні спалахи, космічні промені або апаратні помилки.

Коли цей концепт **застосовується до DNS-запитів**, можливо, що **домен, який отримує DNS-сервер**, не той самий, що й домен, запрошений спочатку.

Наприклад, модифікація одного біта в домені "windows.com" може змінити його на "windnws.com."

Зловмисники можуть **використати це, зареєструвавши кілька bit-flipping domains**, що схожі на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Для детальнішої інформації читайте [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Придбайте довірений домен

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який можна використати.\
Щоб упевнитися, що прострочений домен, який ви збираєтесь купити, **вже має хороший SEO**, ви можете перевірити, як він класифікований у:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Пошук електронних адрес

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** дійсних електронних адрес або **підтвердити ті**, що ви вже знайшли, ви можете перевірити, чи можете brute-force SMTP-сервери жертви. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують **будь-який веб-портал для доступу до своєї пошти**, ви можете перевірити, чи вразливий він до **username brute force**, і, якщо можливо, експлуатувати цю вразливість.

## Configuring GoPhish

### Встановлення

Ви можете завантажити його з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Вам буде виведено пароль для адміністратора в порті 3333 у виводі. Тому отримайте доступ до цього порту і використайте ці облікові дані, щоб змінити пароль адміністратора. Можливо, вам доведеться tunnel цей порт на локальний:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Конфігурація

**Налаштування TLS сертифіката**

Перед цим кроком ви повинні **вже придбати домен**, який будете використовувати, і він має **вказувати** на **IP VPS**, де ви налаштовуєте **gophish**.
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

Почніть інсталяцію: `apt-get install postfix`

Потім додайте домен до наступних файлів:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення наступних змінних у файлі /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваш домен і **перезапустіть ваш VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, яка вказує на **IP-адресу** VPS, та **DNS MX** record, що вказує на `mail.<domain>`

Тепер перевіримо відправку електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Налаштування Gophish**

Зупиніть виконання gophish і налаштуємо його.\
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

Щоб створити сервіс gophish так, щоб його можна було автоматично запускати та керувати ним як сервісом, створіть файл `/etc/init.d/gophish` зі наступним вмістом:
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
Завершіть налаштування сервісу та перевірте його, зробивши:
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

### Почекайте й дійте легітимно

Чим старіший домен, тим менша ймовірність, що його буде позначено як spam. Тому слід чекати якомога довше (at least 1week) перед phishing assessment. Крім того, якщо ви розмістите сторінку про репутаційну сферу, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо потрібно чекати тиждень, ви можете завершити налаштування вже зараз.

### Налаштуйте Reverse DNS (rDNS) запис

Створіть rDNS (PTR) запис, який резолвить IP address VPS на доменне ім'я.

### Sender Policy Framework (SPF) запис

Ви повинні **налаштувати SPF запис для нового домену**. Якщо ви не знаєте, що таке SPF запис [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використовувати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Ось вміст, який потрібно встановити в TXT записі домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) запис

Ви повинні **налаштувати DMARC запис для нового домену**. Якщо ви не знаєте, що таке DMARC запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT запис для імені хоста `_dmarc.<domain>` зі наступним вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей підручник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Потрібно з'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть імейл на адресу, яку вони вам дадуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, відправивши листа на `check-auth@verifier.port25.com` та **прочитати відповідь** (для цього вам потрібно **відкрити** port **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви відправите лист як root).\
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем** і перевірити **заголовки електронної пошти** у вашій поштовій скриньці Gmail — у полі заголовка `Authentication-Results` має бути присутнім `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення з Spamhouse Blacklist

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може показати, чи ваш домен блокується spamhouse. Ви можете запросити видалення вашого домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з Microsoft Blacklist

​​Ви можете запросити видалення вашого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Sending Profile

- Вкажіть деяку **назву для ідентифікації** профілю відправника
- Визначте, з якого акаунта ви будете надсилати phishing emails. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити порожніми username та password, але обов'язково поставте галочку на Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**" щоб перевірити, що все працює.\
> Я рекомендую **відправляти тестові листи на 10min mails addresses**, щоб уникнути потрапляння в чорний список під час тестів.

### Email Template

- Вкажіть деяку **назву для ідентифікації** шаблону
- Потім введіть **тему** (нічого дивного, просто те, що ви могли б очікувати побачити в звичайному листі)
- Переконайтеся, що ви поставили галочку на "**Add Tracking Image**"
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
Зверніть увагу, що **щоб підвищити достовірність листа**, рекомендується використати якийсь підпис із реального листа від клієнта. Пропозиції:

- Надішліть лист на **неіснуючу адресу** і перевірте, чи відповідь містить який-небудь підпис.
- Пошукайте **публічні email** типу info@ex.com або press@ex.com чи public@ex.com і надішліть їм лист, зачекавши на відповідь.
- Спробуйте зв’язатися з **якоюсь валідною знайденою** адресою та зачекайте на відповідь

![](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **додавати файли для відправки**. Якщо ви також хочете вкрасти NTLM challenges, використовуючи спеціально підготовлені файли/документи, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **назву**
- **Write the HTML code** веб-сторінки. Зверніть увагу, що ви можете **імпортувати** веб-сторінки.
- Позначте **Capture Submitted Data** та **Capture Passwords**
- Встановіть **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам потрібно буде змінити HTML code сторінки і протестувати локально (можливо використовуючи якийсь Apache server), **доки результат вас не влаштує.** Потім вставте цей HTML code у поле.\
> Зверніть увагу, що якщо вам потрібно **використати статичні ресурси** для HTML (наприклад CSS або JS), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім звертатися до них через _**/static/\<filename>**_

> [!TIP]
> Для редиректу ви можете **перенаправляти користувачів на легітимну головну сторінку** жертви, або направляти їх на _/static/migration.html_, наприклад показати **spinning wheel** ([https://loading.io/](https://loading.io)) протягом 5 секунд, а потім вказати, що процес пройшов успішно.

### Users & Groups

- Вкажіть назву
- **Import the data** (зверніть увагу, що для використання шаблону у прикладі вам потрібні firstname, last name та email address кожного користувача)

![](<../../images/image (163).png>)

### Campaign

Нарешті, створіть кампанію, задавши назву, email template, landing page, URL, sending profile та групу. Зверніть увагу, що URL буде посиланням, яке відправляється жертвам.

Зверніть увагу, що **Sending Profile дозволяє надіслати тестовий лист, щоб побачити, як виглядатиме фінальний фішинг-лист**:

![](<../../images/image (192).png>)

> [!TIP]
> Рекомендую **надсилати тестові листи на адреси 10min mails**, щоб уникнути потрапляння до чорних списків під час тестів.

Коли все готово — просто запустіть кампанію!

## Website Cloning

Якщо з якоїсь причини ви хочете клонувати вебсайт, перевірте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких фішингових тестах (головним чином для Red Teams) ви також захочете **відправляти файли, що містять якийсь backdoor** (можливо C2 або просто щось, що спровокує автентифікацію).\
Перегляньте наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака доволі хитра, оскільки ви підробляєте реальний сайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний пароль або якщо додаток, який ви підробили, налаштований з 2FA, **ця інформація не дозволить вам видавати себе за ошуканого користувача**.

Тут корисні інструменти на кшталт [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Ці інструменти дозволяють реалізувати MitM-атаку. Загалом атака працює так:

1. Ви **імітуєте форму логіну** справжньої веб-сторінки.
2. Користувач **надішле** свої **credentials** на вашу підроблену сторінку, а інструмент переадресує їх на реальний сайт, **перевіряючи, чи працюють credentials**.
3. Якщо акаунт налаштований з **2FA**, MitM-сторінка запросить його, і як тільки **користувач введе** його, інструмент передасть його на реальний сайт.
4. Коли користувач автентифікований, ви (як атакуючий) отримаєте **захоплені credentials, 2FA, cookie та будь-яку інформацію** про кожну взаємодію під час виконання MitM.

### Via VNC

Що, якщо замість того, щоб **направляти жертву на зловмисну сторінку** з виглядом оригіналу, ви направите її в **VNC-сесію з браузером, підключеним до реального сайту**? Ви зможете бачити, що робить користувач, вкрасти пароль, MFA, cookies...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із найпростіших способів дізнатися, чи вас зловили — це **перевірити ваш домен у чорних списках**. Якщо він там є, значить ваш домен визнали підозрілим.\
Один із простих способів перевірити, чи ваш домен знаходиться у чорному списку, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак існують й інші способи дізнатися, чи **жертва активно шукає підозрілі фішингові домени в інтернеті**, як пояснено в:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити домен з дуже схожою назвою** на домен жертви **і/або згенерувати сертифікат** для **субдомену** домену, яким ви володієте, що **містить** ключове **слово** від домену жертви. Якщо **жертва** виконає будь-яку DNS чи HTTP взаємодію з ними, ви дізнаєтесь, що **вона активно шукає** підозрілі домени, і вам доведеться діяти дуже обережно.

### Evaluate the phishing

Використайте [**Phishious**](https://github.com/Rices/Phishious), щоб оцінити, чи ваш лист потрапить у спам, буде заблокований або буде успішним.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні групи зловмисників дедалі частіше зовсім відмовляються від email-lures і **безпосередньо атакують service-desk / identity-recovery workflow**, щоб обійти MFA. Атака повністю «living-off-the-land»: коли оператор отримує валідні credentials, він перемикається на вбудовані адміністраторські інструменти — без необхідності в malware.

### Attack flow
1. Recon the victim
* Збирайте персональні та корпоративні дані з LinkedIn, витоків даних, публічного GitHub тощо.
* Ідентифікуйте цінні особи (керівники, IT, фінанси) та виявіть **точний процес help-desk** для скидання пароля / MFA.
2. Real-time social engineering
* Дзвінок, Teams або чат з help-desk, прикидаючись цільовою особою (часто з **підробленим caller-ID** або **клонованим голосом**).
* Надайте раніше зібрану PII для проходження верифікації за знанням.
* Переконайте агента **скинути MFA secret** або виконати **SIM-swap** на зареєстрований мобільний номер.
3. Immediate post-access actions (≤60 min in real cases)
* Встановіть foothold через будь-який web SSO портал.
* Перерахуйте AD / AzureAD за допомогою вбудованих інструментів (без завантаження бінарів):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Рух латерально з використанням **WMI**, **PsExec**, або легітимних **RMM**-агентів, які вже дозволені в середовищі.

### Detection & Mitigation
* Розглядайте identity recovery через help-desk як **привілейовану операцію** — вимагайте step-up auth та затвердження менеджера.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, що сповіщають про:
* Зміну методу MFA + автентифікацію з нового пристрою / геолокації.
* Миттєве підвищення привілеїв того ж самого принципалу (user → admin).
* Записуйте дзвінки до help-desk і вимагайте **call-back на раніше зареєстрований номер** перед будь-яким скиданням.
* Впровадьте **Just-In-Time (JIT) / Privileged Access**, щоб не допустити автоматичного наслідування високопривілейованих токенів ново скинутими акаунтами.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Комерційні групи компенсують витрати на high-touch операції масовими атаками, які перетворюють **search engines & ad networks у канал доставки**.

1. **SEO poisoning / malvertising** просуває фейковий результат, наприклад `chromium-update[.]site`, у верхні оголошення пошуку.
2. Жертва завантажує невеликий **перший ланцюговий лоадер** (часто JS/HTA/ISO). Приклади, виявлені Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Лоадер вивантажує браузерні cookies + credential DBs, потім завантажує **тихий лоадер**, який у реальному часі вирішує, чи розгортати:
* RAT (наприклад AsyncRAT, RustDesk)
* ransomware / wiper
* компонент для persistence (ключ Run у реєстрі + scheduled task)

### Hardening tips
* Блокуйте новозареєстровані домени і застосовуйте **Advanced DNS / URL Filtering** як для пошукових оголошень, так і для e-mail.
* Обмежте встановлення програм до підписаних MSI / Store-пакетів, забороніть виконання `HTA`, `ISO`, `VBS` політикою.
* Моніторте дочірні процеси браузерів, що відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Шукайте LOLBins, які часто зловживають перші ланцюгові лоадери (напр., `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Атакуючі тепер ланцюжать **LLM & voice-clone APIs** для повністю персоналізованих приманок та взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Додавайте **динамічні банери**, що підкреслюють повідомлення, надіслані з неперевіреної автоматизації (через ARC/DKIM anomalies).  
• Впровадьте **voice-biometric challenge phrases** для запитів високого ризику по телефону.  
• Постійно симулюйте AI-згенеровані приманки в програмах підвищення обізнаності — статичні шаблони застаріли.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Окрім класичного push-bombing, оператори просто **примушують до нової реєстрації MFA** під час дзвінка до help-desk, зневажаючи існуючий токен користувача. Будь-який наступний запит на логін виглядає легітимним для жертви.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Моніторте події AzureAD/AWS/Okta, де **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї ж IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть тихо скопіювати шкідливі команди в буфер обміну жертви з компрометованої або typosquatted веб-сторінки, а потім обманом змусити користувача вставити їх у **Win + R**, **Win + X** або вікно терміналу, виконуючи довільний код без будь-яких завантажень чи вкладень.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Джерела

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
