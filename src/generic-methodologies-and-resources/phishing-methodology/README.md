# Методологія фішингу

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Recon жертви
1. Виберіть **домен жертви**.
2. Проведіть базову веб-енумерацію, **шукаючи портали входу**, які використовує жертва, і **вирішіть**, який із них ви будете **підробляти**.
3. Використайте **OSINT**, щоб **знайти електронні адреси**.
2. Підготуйте середовище
1. **Купіть домен**, який ви збираєтеся використовувати для оцінки фішингу
2. **Налаштуйте записи**, пов'язані з email-сервісом (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон листа**
2. Підготуйте **веб-сторінку** для викрадення облікових даних
4. Запустіть кампанію!

## Генерація схожих доменних імен або купівля довіреного домену

### Техніки варіації доменних імен

- **Keyword**: Ім'я домену **містить** важливе **ключове слово** оригінального домену (e.g., zelster.com-management.com).
- **hypened subdomain**: Замініть **крапку на дефіс** у субдомені (e.g., www-zelster.com).
- **New TLD**: Той же домен із **новим TLD** (e.g., zelster.org)
- **Homoglyph**: Він **замінює** літеру в імені домену на **літери, що виглядають схоже** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Він **міняє місцями дві літери** в імені домену (e.g., zelsetr.com).
- **Singularization/Pluralization**: Додає або видаляє «s» наприкінці імені домену (e.g., zeltsers.com).
- **Omission**: Він **видаляє одну** з літер у імені домену (e.g., zelser.com).
- **Repetition:** Він **повторює одну** з літер у імені домену (e.g., zeltsser.com).
- **Replacement**: Схоже на homoglyph, але менш приховано. Він замінює одну з літер у імені домену, можливо на літеру поруч із оригінальною на клавіатурі (e.g, zektser.com).
- **Subdomained**: Вставляє **крапку** всередині імені домену (e.g., ze.lster.com).
- **Insertion**: Він **вставляє літеру** в ім'я домену (e.g., zerltser.com).
- **Missing dot**: Приклеює TLD до імені домену. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність, що один або кілька бітів, що зберігаються або передаються, можуть бути автоматично інвертовані** через різні фактори, такі як сонячні спалахи, космічні промені або помилки апаратного забезпечення.

Коли цей концепт **застосувати до DNS-запитів**, можливо, що **домен, який отримує DNS-сервер**, не той, який було спочатку запрошено.

Наприклад, одноразова зміна біту в домені "windows.com" може змінити його на "windnws.com."

Атакувальники можуть **використати це, зареєструвавши кілька bit-flipping доменів**, схожих на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Для додаткової інформації читайте [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Купівля довіреного домену

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який ви могли б використати.\
Щоб переконатися, що домен, який ви збираєтеся купити, **вже має хороший SEO**, ви можете перевірити, як він класифікований у:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення електронних адрес

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** дійсних електронних адрес або **перевірити ті**, що ви вже виявили, ви можете перевірити, чи можете виконати брутфорс SMTP-серверів жертви. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують **будь-який веб-портал для доступу до своїх поштових скриньок**, ви можете перевірити, чи вразливий він до **брутфорсу імен користувачів**, і при можливості експлуатувати цю вразливість.

## Налаштування GoPhish

### Встановлення

Ви можете завантажити його з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте і розархівуйте його всередині `/opt/gophish` і запустіть `/opt/gophish/gophish`\
У виводі вам буде надано пароль для admin-користувача на порту 3333. Тому отримайте доступ до цього порту і використайте ці облікові дані, щоб змінити пароль адміністратора. Можливо, вам доведеться пробросити цей порт локально:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Налаштування

**Налаштування TLS-сертифіката**

Перед цим кроком ви повинні мати **вже придбаний домен**, який збираєтеся використовувати, і він має **вказувати** на **IP of the VPS**, де ви налаштовуєте **gophish**.
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

Нарешті змініть файли **`/etc/hostname`** і **`/etc/mailname`** на ваш домен і **перезавантажте ваш VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, що вказує на **IP-адресу** VPS, і **DNS MX** запис, що вказує на `mail.<domain>`

Тепер перевіримо відправку електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish конфігурація**

Зупиніть виконання gophish і налаштуйте його.\
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

Щоб створити сервіс gophish, який можна запускати автоматично та керувати ним як сервісом, створіть файл `/etc/init.d/gophish` з таким вмістом:
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
Закінчіть налаштування служби та перевірте її роботу, виконавши:
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

### Почекайте та будьте легітимними

Чим старіший домен, тим менша ймовірність, що його позначать як спам. Тому вам слід чекати якомога довше (принаймні 1 тиждень) перед phishing assessment. Більше того, якщо ви розмістите сторінку про репутаційний сектор, здобута репутація буде кращою.

Зауважте, навіть якщо доведеться чекати тиждень, ви можете завершити налаштування вже зараз.

### Налаштуйте запис Reverse DNS (rDNS)

Створіть rDNS (PTR)-запис, який відображає IP-адресу VPS на доменне ім'я.

### Sender Policy Framework (SPF) Record

Ви повинні **налаштувати SPF-запис для нового домену**. Якщо ви не знаєте, що таке SPF-запис [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використовувати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF-політики (використайте IP VPS-машини)

![](<../../images/image (1037).png>)

Це вміст, який потрібно встановити в TXT-записі домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Аутентифікація повідомлень на основі домену, звітність та відповідність (DMARC) — запис

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT-запис з іменем хоста `_dmarc.<domain>` із наступним вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви маєте **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей підручник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Потрібно об'єднати обидва B64-значення, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть листа на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, відправивши лист на `check-auth@verifier.port25.com` та **прочитавши відповідь** (для цього вам потрібно буде **відкрити** порт **25** і подивитися відповідь у файлі _/var/mail/root_, якщо ви відправляєте лист як root).\
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем**, і перевірити **заголовки електронного листа** у вашій поштовій скриньці Gmail, `dkim=pass` має бути присутнім у полі заголовка `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Видалення зі Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) може вказати, чи ваш домен блокується Spamhouse. Ви можете запросити видалення домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з Microsoft Blacklist

​​Ви можете запросити видалення домену/IP на [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Профіль відправника

- Вкажіть **ім'я для ідентифікації** профілю відправника
- Вирішіть, з якого акаунта ви будете надсилати phishing emails. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Можете залишити порожніми username and password, але обов'язково поставте галочку на Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити, що все працює.\
> Рекомендую **надсилати тестові листи на адреси 10min mails**, щоб уникнути занесення в чорний список під час тестів.

### Email Template

- Задайте **ім'я для ідентифікації** шаблону
- Потім напишіть **subject** (нічого дивного, просто те, що ви очікували б прочитати у звичайному листі)
- Переконайтеся, що ви поставили галочку на "**Add Tracking Image**"
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
Зверніть увагу, що **щоб підвищити достовірність листа**, рекомендується використати якийсь підпис з реального листа від клієнта. Пропозиції:

- Відправте лист на **неіснуючу адресу** та перевірте, чи відповідь містить якийсь підпис.
- Пошукайте **публічні адреси** типу info@ex.com або press@ex.com чи public@ex.com і відправте їм лист, зачекайте на відповідь.
- Спробуйте зв’язатися з **якоюсь валідною знайденою** адресою електронної пошти і дочекайтесь відповіді

![](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **додавати файли для відправки**. Якщо ви також хочете вкрасти NTLM challenges за допомогою спеціально сформованих файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **ім’я**
- **Напишіть HTML code** веб-сторінки. Зауважте, що ви можете **імпортувати** веб-сторінки.
- Позначте **Capture Submitted Data** і **Capture Passwords**
- Налаштуйте **редирект**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам доведеться змінювати HTML code сторінки і робити тести локально (можливо використовуючи якийсь Apache server) **доки вам не сподобається результат.** Потім вставте цей HTML code у відповідне поле.\
> Зауважте, що якщо вам потрібно **використовувати статичні ресурси** для HTML (напр., CSS чи JS), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім звертатися до них з _**/static/\<filename>**_

> [!TIP]
> Для редиректу ви можете **перенаправляти користувачів на легітимну головну сторінку** жертви, або перенаправляти на _/static/migration.html_, наприклад показати **spinning wheel** ([https://loading.io/](https://loading.io)) протягом 5 секунд, а потім вказати, що процес був успішним.

### Users & Groups

- Вкажіть назву
- **Імпортуйте дані** (зауважте, що щоб використати шаблон для прикладу, вам потрібні firstname, last name та email address кожного користувача)

![](<../../images/image (163).png>)

### Campaign

Нарешті, створіть кампанію, вибравши назву, email template, landing page, URL, sending profile та групу. Зауважте, що URL буде посиланням, яке надсилається жертвам

Зауважте, що **Sending Profile дозволяє відправити тестовий лист, щоб побачити, як фінальний phishing email виглядатиме**:

![](<../../images/image (192).png>)

> [!TIP]
> Рекомендую **відправляти тестові листи на 10min mails addresses**, щоб уникнути потрапляння до чорних списків під час тестів.

Коли все готово — просто запустіть кампанію!

## Website Cloning

Якщо з якоїсь причини ви хочете клонути сайт, перегляньте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких phishing-оцінках (головним чином для Red Teams) ви також захочете **відправляти файли, що містять якийсь backdoor** (можливо C2 або просто щось, що спричинить автентифікацію).\
Перегляньте наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака досить хитра, оскільки ви підробляєте реальний вебсайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач ввів неправильний пароль або якщо застосунок, який ви підробили, налаштований з 2FA, **ця інформація не дозволить вам видавати себе за скомпрометованого користувача**.

Ось де корисні інструменти типу [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Ці інструменти дозволяють реалізувати MitM-подібну атаку. По суті, атака працює таким чином:

1. Ви **імітуєте форму логіну** реальної веб-сторінки.
2. Користувач **відправляє** свої **credentials** на вашу фейкову сторінку, а інструмент пересилає їх на реальну сторінку, **перевіряючи, чи працюють credentials**.
3. Якщо акаунт налаштований з **2FA**, MitM-сторінка запитає його і, щойно **користувач введе** код, інструмент надішле його на реальну сторінку.
4. Після автентифікації ви (як атакуючий) отримаєте **captured credentials, 2FA, cookie та будь-яку інформацію** про взаємодії, що відбуваються, поки інструмент виконує MitM.

### Via VNC

А що, як замість того, щоб **перенаправляти жертву на шкідливу сторінку** з виглядом оригіналу, ви відправите її в **VNC-сесію з браузером, підключеним до реальної сторінки**? Ви зможете бачити, що вона робить, вкрасти пароль, MFA, cookies...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один із кращих способів дізнатися, чи вас викрили — це **перевірити свій домен у чорних списках**. Якщо він там з’явився, значить ваш домен було виявлено як підозрілий.\
Простий спосіб перевірити, чи з’являється ваш домен у чорному списку — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи жертва **активно шукає підозрілу фішингову активність у мережі**, як пояснено у:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити домен з дуже схожою назвою** до домену жертви **та/або згенерувати сертифікат** для **піддомену** домену, яким ви керуєте, що **містить ключове слово** домену жертви. Якщо **жертва** здійснить будь-яку DNS або HTTP взаємодію з ними, ви дізнаєтесь, що **вона активно шукає** підозрілі домени і вам слід бути дуже обережним.

### Evaluate the phishing

Використайте [**Phishious**](https://github.com/Rices/Phishious), щоб оцінити, чи ваше письмо потрапить у папку spam, буде заблоковане або успішне.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні intrusion sets дедалі частіше зовсім уникають email-lures і **безпосередньо атакують service-desk / identity-recovery workflow**, щоб обійти MFA. Атака повністю «living-off-the-land»: коли оператор має валідні credentials, він пересувається з вбудованими admin інструментами — без необхідності в malware.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Комерційні групи компенсують витрати на high-touch операції масовими атаками, які перетворюють **пошукові системи та рекламні мережі на канал доставки**.

1. **SEO poisoning / malvertising** виводить фейковий результат, наприклад `chromium-update[.]site`, в топ рекламних результатів пошуку.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, виявлені Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader вивантажує browser cookies + credential DBs, потім завантажує **silent loader**, який вирішує — *у реальному часі* — чи розгортати:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** на *search-ads* так само, як і у e-mail.
* Обмежте встановлення ПО до підписаних MSI / Store пакетів, забороніть виконання `HTA`, `ISO`, `VBS` політикою.
* Моніторте дочірні процеси браузерів, що відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Полюйте за LOLBins, які часто використовують перші-stage loaders (наприклад `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Атакувальники тепер поєднують **LLM & voice-clone APIs** для повністю персоналізованих приманок і взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Додайте **динамічні банери**, що підкреслюють повідомлення, надіслані з неперевіреної автоматизації (через ARC/DKIM аномалії).  
• Впровадьте **voice-biometric challenge phrases** для запитів по телефону високого ризику.  
• Постійно симулюйте AI-згенеровані приманки в програмах підвищення обізнаності — статичні шаблони застаріли.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Окрім класичного push-bombing, оператори просто **змушують реєстрацію нового MFA** під час дзвінка в help-desk, анулюючи існуючий токен користувача. Будь-який наступний запит на логін виглядатиме легітимно для жертви.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **протягом кількох хвилин з тієї ж IP-адреси**.



## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори все частіше приховують свої phishing flows за простою перевіркою пристрою, щоб desktop crawlers ніколи не дісталися фінальних сторінок. Поширений шаблон — невеликий скрипт, який тестує touch-capable DOM і надсилає результат на server endpoint; non‑mobile clients отримують HTTP 500 (або порожню сторінку), тоді як mobile users бачать повний flow.

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
Поведінка сервера, що часто спостерігається:
- Встановлює cookie сесії під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або плейсхолдер) на подальші GET-запити, коли `is_mobile=false`; сервісує фішинг лише якщо `true`.

Пошук та евристики виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Веб‑телеметрія: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non‑mobile; легітимні мобільні шляхи жертви повертають 200 з подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які умовно відображають контент виключно на основі `ontouchstart` або подібних перевірок пристрою.

Поради з захисту:
- Запускайте краулери з мобільними імітаціями fingerprint і з увімкненим JS, щоб виявити контент за гейтом.
- Налаштуйте оповіщення про підозрілі відповіді 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## Посилання

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
