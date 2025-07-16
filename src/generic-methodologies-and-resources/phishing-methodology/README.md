# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Розвідка жертви
1. Виберіть **домен жертви**.
2. Виконайте базову веб-енумерацію **в пошуках порталів для входу**, які використовує жертва, і **вирішіть**, який з них ви будете **імітувати**.
3. Використовуйте **OSINT** для **пошуку електронних адрес**.
2. Підготуйте середовище
1. **Купіть домен**, який ви будете використовувати для фішингової оцінки
2. **Налаштуйте записи** служби електронної пошти (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Підготуйте кампанію
1. Підготуйте **шаблон електронної пошти**
2. Підготуйте **веб-сторінку** для крадіжки облікових даних
4. Запустіть кампанію!

## Генерація подібних доменних імен або купівля надійного домену

### Техніки варіації доменних імен

- **Ключове слово**: Доменне ім'я **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).
- **Гіпенований піддомен**: Змініть **крапку на дефіс** піддомену (наприклад, www-zelster.com).
- **Новий TLD**: Той самий домен з використанням **нового TLD** (наприклад, zelster.org)
- **Гомогліф**: Він **замінює** літеру в доменному імені на **літери, які виглядають подібно** (наприклад, zelfser.com).
- **Транспозиція:** Він **міняє місцями дві літери** в доменному імені (наприклад, zelsetr.com).
- **Сингуларизація/Плюралізація**: Додає або видаляє “s” в кінці доменного імені (наприклад, zeltsers.com).
- **Виключення**: Він **видаляє одну** з літер з доменного імені (наприклад, zelser.com).
- **Повторення:** Він **повторює одну** з літер у доменному імені (наприклад, zeltsser.com).
- **Замінювання**: Як гомогліф, але менш непомітно. Він замінює одну з літер у доменному імені, можливо, на літеру, що знаходиться поруч з оригінальною літерою на клавіатурі (наприклад, zektser.com).
- **Піддомен**: Введіть **крапку** всередині доменного імені (наприклад, ze.lster.com).
- **Вставка**: Він **вставляє літеру** в доменне ім'я (наприклад, zerltser.com).
- **Відсутня крапка**: Додайте TLD до доменного імені. (наприклад, zelstercom.com)

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **можливість, що один з бітів, збережених або в комунікації, може автоматично змінитися** через різні фактори, такі як сонячні спалахи, космічні промені або апаратні помилки.

Коли цей концепт **застосовується до DNS-запитів**, можливо, що **домен, отриманий DNS-сервером**, не є тим самим доменом, який спочатку запитувався.

Наприклад, одна зміна біта в домені "windows.com" може змінити його на "windnws.com."

Зловмисники можуть **використовувати це, реєструючи кілька доменів з битфліпом**, які схожі на домен жертви. Їх намір - перенаправити легітимних користувачів на свою інфраструктуру.

Для отримання додаткової інформації читайте [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Купівля надійного домену

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) за простроченим доменом, який ви могли б використовувати.\
Щоб переконатися, що прострочений домен, який ви збираєтеся купити, **вже має хороший SEO**, ви можете перевірити, як він категоризується в:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення електронних адрес

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (100% безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **виявити більше** дійсних електронних адрес або **перевірити ті, які** ви вже виявили, ви можете перевірити, чи можете ви брутфорсити їх smtp-сервери жертви. [Дізнайтеся, як перевірити/виявити електронну адресу тут](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують **будь-який веб-портал для доступу до своїх електронних листів**, ви можете перевірити, чи він вразливий до **брутфорсу імені користувача**, і експлуатувати вразливість, якщо це можливо.

## Налаштування GoPhish

### Встановлення

Ви можете завантажити його з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розпакуйте його в `/opt/gophish` і виконайте `/opt/gophish/gophish`\
Вам буде надано пароль для адміністратора на порту 3333 виводу. Тому отримайте доступ до цього порту та використовуйте ці облікові дані, щоб змінити пароль адміністратора. Вам може знадобитися тунелювати цей порт на локальний:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Налаштування

**Налаштування TLS сертифіката**

Перед цим кроком ви повинні **вже купити домен**, який ви збираєтеся використовувати, і він повинен **вказувати** на **IP вашого VPS**, де ви налаштовуєте **gophish**.
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

Почніть установку: `apt-get install postfix`

Потім додайте домен до наступних файлів:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення наступних змінних у файлі /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті, змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваше ім'я домену та **перезавантажте ваш VPS.**

Тепер створіть **DNS A запис** для `mail.<domain>`, що вказує на **ip-адресу** VPS, та **DNS MX** запис, що вказує на `mail.<domain>`

Тепер давайте протестуємо відправку електронної пошти:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Конфігурація Gophish**

Зупиніть виконання gophish і давайте налаштуємо його.\
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
**Налаштуйте сервіс gophish**

Щоб створити сервіс gophish, щоб його можна було запускати автоматично та керувати ним як сервісом, ви можете створити файл `/etc/init.d/gophish` з наступним вмістом:
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

### Чекайте та будьте легітимними

Чим старіший домен, тим менше ймовірно, що його сприймуть як спам. Тому вам слід чекати якомога довше (принаймні 1 тиждень) перед оцінкою фішингу. Більше того, якщо ви створите сторінку про репутаційний сектор, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо вам потрібно почекати тиждень, ви можете закінчити налаштування всього зараз.

### Налаштування зворотного DNS (rDNS) запису

Встановіть запис rDNS (PTR), який перетворює IP-адресу VPS на доменне ім'я.

### Запис політики відправника (SPF)

Вам потрібно **налаштувати запис SPF для нового домену**. Якщо ви не знаєте, що таке запис SPF [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використовувати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF політики (використовуйте IP-адресу машини VPS)

![](<../../images/image (1037).png>)

Це вміст, який потрібно встановити в TXT записі всередині домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT запис, вказуючи ім'я хоста `_dmarc.<domain>` з наступним вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Вам потрібно **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей посібник оснований на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Вам потрібно об'єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте свій бал конфігурації електронної пошти

Ви можете зробити це, використовуючи [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто перейдіть на сторінку та надішліть електронний лист на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити свою конфігурацію електронної пошти**, надіславши електронний лист на `check-auth@verifier.port25.com` та **прочитавши відповідь** (для цього вам потрібно буде **відкрити** порт **25** і побачити відповідь у файлі _/var/mail/root_, якщо ви надішлете електронний лист як root).\
Перевірте, що ви пройшли всі тести:
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем** і перевірити **заголовки електронної пошти** у вашій поштовій скриньці Gmail, `dkim=pass` має бути присутнім у полі заголовка `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Видалення з чорного списку Spamhouse

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може вказати, чи ваш домен заблоковано Spamhouse. Ви можете запросити видалення вашого домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення з чорного списку Microsoft

​​Ви можете запросити видалення вашого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль відправника

- Встановіть **ім'я для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви будете надсилати фішингові електронні листи. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити ім'я користувача та пароль порожніми, але обов'язково перевірте "Ігнорувати помилки сертифіката"

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Надіслати тестовий електронний лист**", щоб перевірити, чи все працює.\
> Я б рекомендував **надсилати тестові електронні листи на адреси 10min mails**, щоб уникнути потрапляння в чорний список під час тестування.

### Шаблон електронного листа

- Встановіть **ім'я для ідентифікації** шаблону
- Потім напишіть **тему** (нічого дивного, просто щось, що ви могли б очікувати прочитати в звичайному електронному листі)
- Переконайтеся, що ви відмітили "**Додати трекінгове зображення**"
- Напишіть **шаблон електронного листа** (ви можете використовувати змінні, як у наступному прикладі):
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
Зверніть увагу, що **для підвищення достовірності електронного листа** рекомендується використовувати підпис з електронного листа клієнта. Пропозиції:

- Відправте електронний лист на **неіснуючу адресу** та перевірте, чи є у відповіді якась підпис.
- Шукайте **публічні електронні адреси** такі як info@ex.com або press@ex.com або public@ex.com і надішліть їм електронний лист, а потім чекайте на відповідь.
- Спробуйте зв'язатися з **якою-небудь дійсною виявленою** електронною адресою та чекайте на відповідь.

![](<../../images/image (80).png>)

> [!TIP]
> Шаблон електронного листа також дозволяє **додавати файли для відправки**. Якщо ви також хочете вкрасти NTLM виклики, використовуючи спеціально підготовлені файли/документи [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Лендінг Пейдж

- Напишіть **ім'я**
- **Напишіть HTML код** веб-сторінки. Зверніть увагу, що ви можете **імпортувати** веб-сторінки.
- Позначте **Захопити надіслані дані** та **Захопити паролі**
- Встановіть **перенаправлення**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам потрібно буде змінити HTML код сторінки та провести деякі тести локально (можливо, використовуючи якийсь Apache сервер) **поки вам не сподобаються результати.** Потім напишіть цей HTML код у вікно.\
> Зверніть увагу, що якщо вам потрібно **використовувати деякі статичні ресурси** для HTML (можливо, деякі CSS та JS сторінки), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і потім отримати до них доступ з _**/static/\<filename>**_

> [!TIP]
> Для перенаправлення ви можете **перенаправити користувачів на легітимну основну веб-сторінку** жертви або перенаправити їх на _/static/migration.html_, наприклад, поставити **крутильне колесо** (**[**https://loading.io/**](https://loading.io)**) на 5 секунд, а потім вказати, що процес був успішним**.

### Користувачі та Групи

- Встановіть ім'я
- **Імпортуйте дані** (зверніть увагу, що для використання шаблону для прикладу вам потрібні ім'я, прізвище та електронна адреса кожного користувача)

![](<../../images/image (163).png>)

### Кампанія

Нарешті, створіть кампанію, вибравши ім'я, шаблон електронного листа, лендінг пейдж, URL, профіль відправлення та групу. Зверніть увагу, що URL буде посиланням, надісланим жертвам.

Зверніть увагу, що **Профіль відправлення дозволяє надіслати тестовий електронний лист, щоб побачити, як виглядатиме фінальний фішинговий електронний лист**:

![](<../../images/image (192).png>)

> [!TIP]
> Я б рекомендував **надсилати тестові електронні листи на адреси 10min mails**, щоб уникнути потрапляння в чорний список під час тестування.

Коли все буде готово, просто запустіть кампанію!

## Клонування веб-сайту

Якщо з якоїсь причини ви хочете клонувати веб-сайт, перегляньте наступну сторінку:

{{#ref}}
clone-a-website.md
{{#endref}}

## Документи та файли з бекдором

У деяких фішингових оцінках (в основному для Red Teams) ви також захочете **надсилати файли, що містять якийсь вид бекдору** (можливо, C2 або просто щось, що викликає аутентифікацію).\
Перегляньте наступну сторінку для деяких прикладів:

{{#ref}}
phishing-documents.md
{{#endref}}

## Фішинг MFA

### Через Proxy MitM

Попередня атака досить хитра, оскільки ви підробляєте реальний веб-сайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний пароль або якщо програма, яку ви підробили, налаштована на 2FA, **ця інформація не дозволить вам видавати себе за обманутого користувача**.

Ось де корисні інструменти, такі як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Цей інструмент дозволить вам згенерувати атаку типу MitM. В основному, атака працює наступним чином:

1. Ви **підробляєте форму входу** реальної веб-сторінки.
2. Користувач **надсилає** свої **облікові дані** на вашу підроблену сторінку, а інструмент надсилає їх на реальну веб-сторінку, **перевіряючи, чи працюють облікові дані**.
3. Якщо обліковий запис налаштований на **2FA**, сторінка MitM запитає про це, і як тільки **користувач введе** його, інструмент надішле його на реальну веб-сторінку.
4. Як тільки користувач аутентифікований, ви (як атакуючий) отримаєте **захоплені облікові дані, 2FA, куки та будь-яку інформацію** про кожну взаємодію, поки інструмент виконує MitM.

### Через VNC

А що, якщо замість **відправлення жертви на шкідливу сторінку** з таким же виглядом, як у оригіналу, ви відправите його на **сесію VNC з браузером, підключеним до реальної веб-сторінки**? Ви зможете бачити, що він робить, вкрасти пароль, використане MFA, куки...\
Ви можете зробити це за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Виявлення виявлення

Очевидно, один з найкращих способів дізнатися, чи вас викрили, це **шукати ваш домен у чорних списках**. Якщо він з'являється в списку, ваш домен був виявлений як підозрілий.\
Один простий спосіб перевірити, чи ваш домен з'являється в будь-якому чорному списку, це використовувати [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи жертва **активно шукає підозрілу фішингову активність у мережі**, як пояснено в:

{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **придбати домен з дуже схожою назвою** на домен жертви **та/або згенерувати сертифікат** для **субдомену** домену, контрольованого вами, **який містить** **ключове слово** домену жертви. Якщо **жертва** виконує будь-який вид **DNS або HTTP взаємодії** з ними, ви дізнаєтеся, що **він активно шукає** підозрілі домени, і вам потрібно буде бути дуже обережним.

### Оцінка фішингу

Використовуйте [**Phishious**](https://github.com/Rices/Phishious), щоб оцінити, чи ваш електронний лист потрапить у папку спаму або буде заблокований чи успішним.

## Перехоплення буфера обміну / Pastejacking

Атакуючі можуть безшумно копіювати шкідливі команди в буфер обміну жертви з компрометованої або неправильно написаної веб-сторінки, а потім обманути користувача вставити їх у **Win + R**, **Win + X** або вікно терміналу, виконуючи довільний код без будь-якого завантаження або вкладення.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Посилання

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
