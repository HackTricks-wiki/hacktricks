# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Методологія

1. Recon the victim
1. Select the **домен жертви**.
2. Виконайте базову веб-енумерацію, **шукаючи login portals**, які використовує жертва, і **вирішіть**, який із них ви будете **impersonate**.
3. Використайте **OSINT**, щоб **знайти електронні адреси**.
2. Підготуйте середовище
1. **Придбайте домен**, який ви збираєтесь використовувати для phishing assessment
2. **Налаштуйте записи**, пов'язані з email-сервісом (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Підготуйте кампанію
1. Підготуйте **email template**
2. Підготуйте **web page** для викрадення облікових даних
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Ім'я домену **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).
- **hypened subdomain**: Змініть **крапку на дефіс** у субдомені (наприклад, www-zelster.com).
- **New TLD**: Той самий домен з іншим **TLD** (наприклад, zelster.org)
- **Homoglyph**: Воно **замінює** літеру в імені домену на **літери, що виглядають схоже** (наприклад, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Воно **міняє місцями дві літери** в імені домену (наприклад, zelsetr.com).
- **Singularization/Pluralization**: Додає або видаляє “s” в кінці імені домену (наприклад, zeltsers.com).
- **Omission**: Видаляє **одну** з літер в імені домену (наприклад, zelser.com).
- **Repetition:** **Повторює одну** з літер в імені домену (наприклад, zeltsser.com).
- **Replacement**: Як homoglyph, але менш приховано. Замінює одну з літер в імені домену, можливо на літеру, що знаходиться поруч на клавіатурі (наприклад, zektser.com).
- **Subdomained**: Вводить **крапку** всередині імені домену (наприклад, ze.lster.com).
- **Insertion**: **Вставляє літеру** в ім'я домену (наприклад, zerltser.com).
- **Missing dot**: Приклеює TLD до імені домену (наприклад, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **ймовірність**, що деякі біти, що зберігаються або передаються, можуть автоматично змінити свій стан через різні фактори, такі як сонячні спалахи, космічні промені або апаратні помилки.

Коли ця концепція **застосовується до DNS-запитів**, можливо, що **домен, який отримує DNS-сервер**, відрізняється від домену, який було запрошено спочатку.

Наприклад, одиночна зміна біта в домені "windows.com" може перетворити його на "windnws.com."

Атакувальники можуть **скористатися цим, зареєструвавши кілька bit-flipping доменів**, схожих на домен жертви. Їхня мета — перенаправити легітимних користувачів на власну інфраструктуру.

Детальніше читайте: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочений домен, який можна використати.\
Щоб переконатися, що прострочений домен, який ви збираєтесь придбати, **вже має хороший SEO**, ви можете перевірити, як він класифікується у:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** дійсних електронних адрес або **перевірити ті**, які ви вже виявили, ви можете перевірити, чи можна brute-force SMTP-сервери жертви. [Дізнайтесь, як перевіряти/виявляти електронні адреси тут](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують будь-який веб-портал для доступу до пошти, ви можете перевірити, чи вразливий він до username brute force, і експлуатувати цю вразливість за наявності можливості.

## Configuring GoPhish

### Встановлення

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Завантажте та розпакуйте його в `/opt/gophish` і виконайте `/opt/gophish/gophish`\
У виводі вам буде видано пароль для admin user на порту 3333. Тому підключіться до цього порту і використайте ці облікові дані, щоб змінити пароль адміна. Можливо, вам доведеться тунелювати цей порт локально:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Конфігурація

**Конфігурація сертифіката TLS**

Перед цим кроком ви вже повинні були придбати домен, який плануєте використовувати, і він має вказувати на IP-адресу VPS, на якому ви налаштовуєте gophish.
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

**Змініть також значення наступних змінних у /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваш домен і **перезапустіть VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, який вказує на **ip address** VPS, та **DNS MX** запис, що вказує на `mail.<domain>`

Тепер перевіримо відправлення електронного листа:
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
**Налаштування служби gophish**

Щоб створити сервіс gophish, щоб його можна було запускати автоматично та керувати ним як службою, ви можете створити файл `/etc/init.d/gophish` з таким вмістом:
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

### Зачекайте й будьте легітимними

Чим старіший домен, тим менше ймовірність, що він буде помічений як спам. Тому слід чекати якомога довше (принаймні 1 тиждень) перед phishing assessment. Крім того, якщо розмістити сторінку, пов'язану з репутаційною сферою, отримана репутація буде кращою.

Зауважте, що навіть якщо вам доведеться чекати тиждень, ви можете завершити налаштування вже зараз.

### Налаштуйте rDNS (PTR) запис

Налаштуйте rDNS (PTR) запис, який відображає IP-адресу VPS як доменне ім'я.

### Запис Sender Policy Framework (SPF)

Ви повинні **налаштувати SPF запис для нового домену**. Якщо ви не знаєте, що таке SPF запис [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використовувати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF-політики (використовуйте IP VPS)

![](<../../images/image (1037).png>)

Це вміст, який потрібно встановити всередині TXT-запису домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Аутентифікація повідомлень на основі домену, звітність та відповідність (DMARC) — запис

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Вам потрібно створити новий DNS TXT запис, вказавши ім'я хоста `_dmarc.<domain>` з таким вмістом:
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

### Перевірте оцінку налаштування електронної пошти

Ви можете зробити це за допомогою [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть листа на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити налаштування електронної пошти**, відправивши листа на `check-auth@verifier.port25.com` і **прочитати відповідь** (для цього потрібно **відкрити** порт **25** та побачити відповідь у файлі _/var/mail/root_, якщо ви відправляєте лист як root).\
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем**, і перевірити **заголовки електронної пошти** у вашій поштовій скриньці Gmail, у полі заголовка `Authentication-Results` має бути `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Сторінка [www.mail-tester.com](https://www.mail-tester.com) може показати, чи ваш домен блокується spamhouse. Ви можете запросити видалення вашого домену/IP за адресою: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Ви можете запросити видалення вашого домену/IP за адресою [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Вкажіть **назву для ідентифікації** профілю відправника
- Вирішіть, з якого облікового запису ви будете відправляти phishing-листи. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Ви можете залишити порожніми username та password, але переконайтеся, що відмічено Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**", щоб перевірити, що все працює.\
> Рекомендую **send the test emails to 10min mails addresses**, щоб уникнути блокування під час тестів.

### Email Template

- Вкажіть **назву для ідентифікації** шаблону
- Потім напишіть **subject** (нічого дивного, просто те, що ви могли б очікувати прочитати в звичайному листі)
- Переконайтеся, що відмічено "**Add Tracking Image**"
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
Зауважте, що **щоб підвищити достовірність листа**, рекомендується використовувати підпис із реального листа від клієнта. Пропозиції:

- Надішліть лист на **неіснуючу адресу** і перевірте, чи відповідь містить якийсь підпис.
- Шукайте **публічні адреси**, такі як info@ex.com або press@ex.com або public@ex.com, надішліть їм листа і дочекайтеся відповіді.
- Спробуйте зв'язатися з **якою-небудь виявленою дійсною** електронною адресою і почекайте на відповідь

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Вкажіть **назву**
- **Напишіть HTML код** веб-сторінки. Зауважте, що ви можете **import** веб-сторінки.
- Відмітьте **Capture Submitted Data** та **Capture Passwords**
- Встановіть **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Зазвичай вам доведеться модифікувати HTML-код сторінки і робити тести локально (наприклад, використовуючи Apache) **доки вас не влаштує результат.** Потім вставте цей HTML-код у відповідне поле.\
> Зауважте, що якщо потрібно **використати статичні ресурси** для HTML (наприклад CSS і JS), ви можете зберегти їх у _**/opt/gophish/static/endpoint**_ і звертатися до них з _**/static/\<filename>**_

> [!TIP]
> Для редиректу ви можете **перенаправляти користувачів на легітимну головну сторінку** жертви, або перенаправити їх, наприклад, на _/static/migration.html_, показати **spinning wheel (**[**https://loading.io/**](https://loading.io)**) протягом 5 секунд, а потім повідомити, що процес пройшов успішно**.

### Users & Groups

- Вкажіть ім'я
- **Import the data** (зауважте, що для використання шаблону в прикладі вам потрібні firstname, last name та email address кожного користувача)

![](<../../images/image (163).png>)

### Campaign

Нарешті, створіть кампанію, вказавши назву, email template, landing page, URL, sending profile та групу. Зауважте, що URL буде посиланням, надісланим жертвам

Зауважте, що **Sending Profile дозволяє відправити тестовий лист, щоб побачити, як виглядатиме фінальний фішинговий лист**:

![](<../../images/image (192).png>)

> [!TIP]
> Рекомендував би **відправляти тестові листи на адреси 10min mails**, щоб уникнути блокування під час тестування.

Коли все готово, просто запустіть кампанію!

## Website Cloning

Якщо з будь-якої причини ви хочете клонувати сайт, перегляньте наступну сторінку:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

У деяких фішингових тестах (насамперед для Red Teams) ви також захочете **відправляти файли, що містять певний backdoor** (можливо C2 або щось, що спровокує автентифікацію).\
Перегляньте наступну сторінку для прикладів:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Попередня атака доволі хитра, оскільки ви підроблюєте реальний вебсайт і збираєте інформацію, введену користувачем. На жаль, якщо користувач не ввів правильний пароль або якщо додаток, який ви підробили, налаштований з 2FA, **ця інформація не дозволить вам видаватися за обманутого користувача**.

Тут стають у пригоді інструменти, як-от [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) та [**muraena**](https://github.com/muraenateam/muraena). Ці інструменти дозволяють реалізувати MitM-атаку. В основному атака працює таким чином:

1. Ви **імітуєте форму входу** реальної веб-сторінки.
2. Користувач **надсилає** свої **credentials** на вашу фейкову сторінку, і інструмент пересилає їх на реальну сторінку, **перевіряючи, чи працюють ці credentials**.
3. Якщо обліковий запис налаштований з **2FA**, MitM-сторінка запросить його, і як тільки **користувач введе** код, інструмент перешле його на реальну сторінку.
4. Після аутентифікації користувача ви (як атакуючий) отримаєте **захоплені credentials, 2FA, cookie та іншу інформацію** про всі взаємодії під час роботи MitM.

### Via VNC

А що як замість того, щоб **перенаправляти жертву на шкідливу сторінку**, яка виглядає як оригінальна, ви відправите її до **VNC-сесії з браузером, підключеним до реальної сторінки**? Ви зможете бачити, що вона робить, вкрасти пароль, використане MFA, cookie...\
Це можна зробити за допомогою [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Очевидно, один з найкращих способів дізнатися, чи вас викрили — **перевірити ваш домен у чорних списках**. Якщо він вказаний у списку, то ваш домен був визначений як підозрілий.\
Один простий спосіб перевірити, чи ваш домен у будь-якому чорному списку — використати [https://malwareworld.com/](https://malwareworld.com)

Однак є й інші способи дізнатися, чи жертва **активно шукає підозрілу фішингову активність у мережі**, як пояснено в:


{{#ref}}
detecting-phising.md
{{#endref}}

Ви можете **купити домен з дуже схожою назвою** на домен жертви **і/або згенерувати сертифікат** для **субдомену** домену, яким ви керуєте, **що містить** **ключове слово** з домену жертви. Якщо **жертва** виконає будь-яку **DNS або HTTP взаємодію** з ними, ви дізнаєтесь, що **вона активно шукає** підозрілі домени, і вам потрібно буде діяти дуже обережно.

### Evaluate the phishing

Використайте [**Phishious**](https://github.com/Rices/Phishious), щоб оцінити, чи ваш лист потрапить у папку спам, буде заблокований або пройде успішно.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Сучасні набори атак усе частіше взагалі уникають email-приманок і **безпосередньо атакують workflow служби підтримки / відновлення ідентичності**, щоб обійти MFA. Атака повністю «living-off-the-land»: як тільки оператор отримує дійсні облікові дані, він використовує вбудовані адміністративні інструменти — без необхідності шкідливого ПО.

### Attack flow
1. Розвідка жертви
* Збирайте персональні та корпоративні дані з LinkedIn, data breaches, публічного GitHub тощо.
* Визначайте цінні облікові записи (керівники, IT, фінанси) і перелічуйте **точний процес help-desk** для скидання пароля / MFA.
2. Соціальна інженерія в реальному часі
* Дзвоніть, пиши в Teams або чат службі підтримки, видаючи себе за ціль (часто з **підробленим caller-ID** або **клонованим голосом**).
* Надавайте зібрані раніше PII для проходження перевірки за знанням.
* Переконуйте агента **скинути MFA secret** або виконати **SIM-swap** на зареєстрований мобільний номер.
3. Негайні дії після доступу (≤60 хв у реальних випадках)
* Закріпіться через будь-який web SSO портал.
* Перелічіть AD / AzureAD за допомогою вбудованих інструментів (без завантаження бінарників):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Бічний рух з використанням **WMI**, **PsExec**, або легітимних **RMM**-агентів, що вже в білому списку в середовищі.

### Detection & Mitigation
* Розглядайте відновлення ідентичності через help-desk як **привілейовану операцію** – вимагайте підвищеної автентифікації та погодження менеджера.
* Розгорніть правила **Identity Threat Detection & Response (ITDR)** / **UEBA**, що сповіщають про:
* зміну методу MFA + аутентифікація з нового пристрою / геолокації.
* негайне підвищення привілеїв того ж самого принципалу (user → admin).
* Записуйте дзвінки в help-desk і вимагайте **call-back на вже зареєстрований номер** перед будь-яким скиданням.
* Впровадьте **Just-In-Time (JIT) / Privileged Access**, щоб нещодавно скинуті облікові записи **не** автоматично не успадковували високі привілеї.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Комодифіковані групи компенсують витрати на high-touch операції масовими атаками, що перетворюють **пошукові системи та рекламні мережі на канал доставки**.

1. **SEO poisoning / malvertising** витісняє фейковий результат, наприклад `chromium-update[.]site`, у верхні рекламні результати пошуку.
2. Жертва завантажує невеликий **first-stage loader** (часто JS/HTA/ISO). Приклади, зафіксовані Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader ексфільтрує cookie браузера + бази даних креденшалів, потім завантажує **silent loader**, який у реальному часі вирішує, чи розгорнути:
* RAT (наприклад AsyncRAT, RustDesk)
* ransomware / wiper
* компонент для персистенції (Run key у реєстрі + scheduled task)

### Hardening tips
* Блокуйте недавно зареєстровані домени та впровадьте **Advanced DNS / URL Filtering** як для пошукових оголошень, так і для e-mail.
* Обмежте встановлення ПЗ лише підписаними MSI / Store пакетами, забороніть виконання `HTA`, `ISO`, `VBS` політиками.
* Моніторьте дочірні процеси браузерів, що відкривають інсталятори:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Полюйте на LOLBins, які часто зловживають перші стадії лоадерів (наприклад `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Атакувальники тепер ланцюжать **LLM & voice-clone APIs** для повністю персоналізованих приманок і взаємодії в реальному часі.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Захист:**
• Додайте **динамічні банери**, що виділяють повідомлення, надіслані з неперевіреної автоматизації (через ARC/DKIM anomalіes).  
• Впровадьте **voice-biometric challenge phrases** для запитів високого ризику по телефону.  
• Постійно імітуйте AI-згенеровані приманки у програмах підвищення обізнаності — статичні шаблони застаріли.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Окрім класичного push-bombing, оператори просто **примусово реєструють нову MFA** під час дзвінка до служби підтримки, анулюючи існуючий токен користувача. Будь-який наступний запит на вхід виглядатиме для жертви легітимним.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Моніторити події AzureAD/AWS/Okta, де **`deleteMFA` + `addMFA`** відбуваються **протягом кількох хвилин з тієї ж IP-адреси**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди в буфер обміну жертви з скомпрометованої або typosquatted веб-сторінки, а потім обдурити користувача, щоб той вставив їх у **Win + R**, **Win + X** або вікно терміналу, виконуючи довільний код без будь‑якого завантаження або вкладення.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори все частіше обмежують доступ до своїх phishing flows простою перевіркою пристрою, щоб десктопні краулери ніколи не дісталися до фінальних сторінок. Поширений шаблон — невеликий скрипт, який перевіряє наявність touch-capable DOM і відправляє результат на server endpoint; немобільні клієнти отримують HTTP 500 (або порожню сторінку), тоді як мобільним користувачам показується повний flow.

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
Поведінка серверу, яка часто спостерігається:
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або заглушку) для наступних GET-запитів, коли `is_mobile=false`; подає phishing лише якщо `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Веб-телеметрія: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non‑mobile; легітимні mobile victim шляхи повертають 200 з подальшим HTML/JS.
- Блокувати або ретельно перевіряти сторінки, які обмежують контент виключно на основі `ontouchstart` або подібних перевірок пристрою.

Defence tips:
- Запускайте crawlers з mobile-like fingerprints і з увімкненим JS, щоб виявити gated content.
- Налаштуйте оповіщення про підозрілі відповіді 500 після `POST /detect` на щойно зареєстрованих доменах.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
