# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Select the **домен жертви**.
2. Виконайте базову веб-енумерацію, **шукаючи портали входу**, які використовує ціль, і **вирішіть**, який із них ви будете **імітувати**.
3. Використайте **OSINT**, щоб **знайти email-адреси**.
2. Prepare the environment
1. **Купіть домен**, який ви збираєтесь використовувати для phishing-оцінки
2. **Налаштуйте записи**, пов’язані з email-сервісом (SPF, DMARC, DKIM, rDNS)
3. Налаштуйте VPS з **gophish**
3. Prepare the campaign
1. Підготуйте **шаблон листа**
2. Підготуйте **веб-сторінку** для крадіжки облікових даних
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Ім'я домену **містить** важливе **ключове слово** оригінального домену (наприклад, zelster.com-management.com).
- **hypened subdomain**: Замініть **крапку на дефіс** у субдомені (наприклад, www-zelster.com).
- **New TLD**: Та ж доменна назва з **іншою TLD** (наприклад, zelster.org)
- **Homoglyph**: Воно **замінює** літеру в імені домену на **літери, що виглядають подібно** (наприклад, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Воно **міняє місцями дві літери** в імені домену (наприклад, zelsetr.com).
- **Singularization/Pluralization**: Додає або видаляє “s” в кінці імені домену (наприклад, zeltsers.com).
- **Omission**: **Видаляє одну** літеру з імені домену (наприклад, zelser.com).
- **Repetition:** **Повторює одну** із літер в імені домену (наприклад, zeltsser.com).
- **Replacement**: Схоже на homoglyph, але менш приховано. Замінює одну із літер у домені, можливо на літеру поруч на клавіатурі (наприклад, zektser.com).
- **Subdomained**: Вводить **крапку** всередині імені домену (наприклад, ze.lster.com).
- **Insertion**: **Вставляє літеру** у домен (наприклад, zerltser.com).
- **Missing dot**: Додає TLD без крапки до імені домену (наприклад, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Існує **можливість, що деякі біти**, збережені або передані, можуть **автоматично змінитись** через різні фактори, як-от сонячні спалахи, космічні промені або апаратні помилки.

Коли цей концепт **застосовується до DNS-запитів**, можливо, що **домен, отриманий DNS-сервером**, відрізнятиметься від домену, що був запитаний спочатку.

Наприклад, одно-бітова модифікація в домені "windows.com" може змінити його на "windnws.com."

Атакувальники можуть **скористатися цим, зареєструвавши кілька доменів з bit-flipping**, схожих на домен жертви, з наміром перенаправити легітимних користувачів на власну інфраструктуру.

Для додаткової інформації прочитайте [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Ви можете шукати на [https://www.expireddomains.net/](https://www.expireddomains.net) прострочені домени, які можна придбати.\
Щоб переконатися, що прострочений домен, який ви збираєтесь купити, **вже має хороший SEO**, ви можете перевірити, як він категоризований у:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Щоб **знайти більше** валідних email-адрес або **перевірити ті**, що ви вже знайшли, ви можете спробувати brute-force smtp-сервери жертви. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Крім того, не забувайте, що якщо користувачі використовують будь-який веб-портал для доступу до пошти, ви можете перевірити, чи вразливий він до username brute force, і експлуатувати цю вразливість за можливості.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Конфігурація

**Налаштування TLS сертифіката**

Перш ніж переходити до цього кроку, ви повинні вже **придбати домен**, який будете використовувати, і він має **вказувати** на **IP VPS**, де ви налаштовуєте **gophish**.
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

Потім додайте домен у наступні файли:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Також змініть значення наступних змінних у /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Нарешті змініть файли **`/etc/hostname`** та **`/etc/mailname`** на ваш домен і **перезапустіть ваш VPS.**

Тепер створіть **DNS A record** для `mail.<domain>`, який вказує на **ip address** вашого VPS, та **DNS MX** record, що вказує на `mail.<domain>`

Тепер протестуємо відправлення електронного листа:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish конфігурація**

Зупиніть виконання gophish і налаштуємо його.\
Змініть `/opt/gophish/config.json` на наступний вміст (зверніть увагу на використання https):
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

Щоб створити сервіс gophish, щоб його можна було автоматично запускати та керувати ним як сервісом, створіть файл `/etc/init.d/gophish` з таким вмістом:
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

### Почекайте та будьте легітимними

Чим старший домен, тим менш імовірно, що він буде визнаний спамом. Тому слід зачекати якомога довше (не менше 1 тижня) перед phishing assessment. До того ж, якщо ви розмістите сторінку про репутаційно важливий сектор, отримана репутація буде кращою.

Зверніть увагу, що навіть якщо доведеться чекати тиждень, ви можете завершити налаштування вже зараз.

### Налаштуйте Reverse DNS (rDNS) запис

Створіть rDNS (PTR) запис, який зв'язує IP-адресу VPS з ім'ям домену.

### Запис Sender Policy Framework (SPF)

Ви повинні **налаштувати SPF record для нового домену**. Якщо ви не знаєте, що таке SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Ви можете використати [https://www.spfwizard.net/](https://www.spfwizard.net) для генерації вашої SPF політики (використайте IP VPS)

![](<../../images/image (1037).png>)

Ось вміст, який має бути встановлений у TXT record домену:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Ви повинні **налаштувати запис DMARC для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Потрібно створити новий DNS TXT запис з іменем хосту `_dmarc.<domain>` зі наступним вмістом:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Ви повинні **налаштувати DKIM для нового домену**. Якщо ви не знаєте, що таке запис DMARC [**прочитайте цю сторінку**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Вам потрібно конкатенувати обидва B64 значення, які генерує DKIM ключ:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Перевірте оцінку конфігурації електронної пошти

Ви можете зробити це, використовуючи [https://www.mail-tester.com/](https://www.mail-tester.com)\
Просто відкрийте сторінку та надішліть електронного листа на адресу, яку вони вам нададуть:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ви також можете **перевірити конфігурацію електронної пошти** надіславши лист на `check-auth@verifier.port25.com` і **прочитавши відповідь** (для цього вам потрібно буде **відкрити** порт **25** і побачити відповідь у файлі _/var/mail/root_, якщо ви надішлете лист від імені root).\
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
Ви також можете надіслати **повідомлення на Gmail під вашим контролем** і перевірити **заголовки електронного листа** у своїй папці «Вхідні» в Gmail — `dkim=pass` має бути присутнім у полі заголовка `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Задайте **назву для ідентифікації** профілю відправника
- Визначте, з якого аккаунта ви будете надсилати фішингові листи. Пропозиції: _noreply, support, servicedesk, salesforce..._
- Можна залишити порожніми username і password, але обов'язково поставте галочку Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Рекомендується використовувати функцію "**Send Test Email**" щоб перевірити, що все працює.\
> Рекомендую **надсилати тестові листи на адреси 10min mails**, щоб уникнути блокування під час тестів.

### Email Template

- Задайте **назву для ідентифікації** шаблону
- Потім напишіть **subject** (нічого дивного, просто те, що можна очікувати в звичайному листі)
- Переконайтеся, що ви поставили галочку "**Add Tracking Image**"
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

- Send an email to a **non existent address** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

Once everything is ready, just launch the campaign!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In some phishing assessments (mainly for Red Teams) you will want to also **send files containing some kind of backdoor** (maybe a C2 or maybe just something that will trigger an authentication).\
Check out the following page for some examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

The previous attack is pretty clever as you are faking a real website and gathering the information set by the user. Unfortunately, if the user didn't put the correct password or if the application you faked is configured with 2FA, **this information won't allow you to impersonate the tricked user**.

This is where tools like [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) and [**muraena**](https://github.com/muraenateam/muraena) are useful. This tool will allow you to generate a MitM like attack. Basically, the attacks works in the following way:

1. You **impersonate the login** form of the real webpage.
2. The user **send** his **credentials** to your fake page and the tool send those to the real webpage, **checking if the credentials work**.
3. If the account is configured with **2FA**, the MitM page will ask for it and once the **user introduces** it the tool will send it to the real web page.
4. Once the user is authenticated you (as attacker) will have **captured the credentials, the 2FA, the cookie and any information** of every interaction your while the tool is performing a MitM.

### Via VNC

What if instead of **sending the victim to a malicious page** with the same looks as the original one, you send him to a **VNC session with a browser connected to the real web page**? You will be able to see what he does, steal the password, the MFA used, the cookies...\
You can do this with [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviously one of the best ways to know if you have been busted is to **search your domain inside blacklists**. If it appears listed, somehow your domain was detected as suspicions.\
One easy way to check if you domain appears in any blacklist is to use [https://malwareworld.com/](https://malwareworld.com)

However, there are other ways to know if the victim is **actively looking for suspicions phishing activity in the wild** as explained in:


{{#ref}}
detecting-phising.md
{{#endref}}

You can **buy a domain with a very similar name** to the victims domain **and/or generate a certificate** for a **subdomain** of a domain controlled by you **containing** the **keyword** of the victim's domain. If the **victim** perform any kind of **DNS or HTTP interaction** with them, you will know that **he is actively looking** for suspicious domains and you will need to be very stealth.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

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
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** pushes a fake result such as `chromium-update[.]site` to the top search ads.
2. Victim downloads a small **first-stage loader** (often JS/HTA/ISO).  Examples seen by Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Restrict software installation to signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution by policy.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Attackers now chain **LLM & voice-clone APIs** for fully personalised lures and real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Add **dynamic banners** highlighting messages sent from untrusted automation (via ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** for high-risk phone requests.
• Continuously simulate AI-generated lures in awareness programmes – static templates are obsolete.

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
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.



## Clipboard Hijacking / Pastejacking

Зловмисники можуть непомітно скопіювати шкідливі команди в буфер обміну жертви з компрометованої або typosquatted веб-сторінки, а потім обманом змусити користувача вставити їх у **Win + R**, **Win + X** або вікно терміналу, виконуючи довільний код без будь-яких завантажень або вкладень.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Оператори все частіше розміщують phishing flows за простою перевіркою пристрою, щоб десктопні crawlers ніколи не дістались фінальних сторінок. Типовий шаблон — невеликий скрипт, який перевіряє, чи підтримує DOM сенсорний ввід, і відправляє результат на server endpoint; немобільні клієнти отримують HTTP 500 (або порожню сторінку), тоді як мобільним користувачам подається повний flow.

Minimal client snippet (typical logic):
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
- Встановлює session cookie під час першого завантаження.
- Приймає `POST /detect {"is_mobile":true|false}`.
- Повертає 500 (або placeholder) на наступні GET-запити, коли `is_mobile=false`; показує phishing лише якщо `true`.

Пошук і евристики виявлення:
- Запит в urlscan: `filename:"detect_device.js" AND page.status:500`
- Веб-телеметрія: послідовність `GET /static/detect_device.js` → `POST /detect` → HTTP 500 для non‑mobile; легітимні мобільні сторінки жертви повертають 200 з подальшим HTML/JS.
- Блокуйте або ретельно перевіряйте сторінки, що умовно відображають контент виключно за `ontouchstart` або подібними перевірками пристрою.

Поради з захисту:
- Запускайте краулери з підписами пристрою, схожими на мобільні, і з увімкненим JS, щоб розкрити захищений контент.
- Повідомляйте про підозрілі відповіді 500 після `POST /detect` на нещодавно зареєстрованих доменах.

## Джерела

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
