# Phishing Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Metodoloji

1. Hedef üzerinde keşif yapın
1. Seçin **hedef alan adını**.
2. Hedefin kullandığı giriş portallarını **aranarak** bazı temel web keşifleri yapın ve hangi portalı **taklit edeceğinize karar verin**.
3. Bazı **OSINT** kullanarak **e-postaları bulun**.
2. Ortamı hazırlayın
1. Phishing değerlendirmesi için kullanacağınız **alan adını satın alın**
2. E-posta servisi ile ilgili kayıtları **yapılandırın** (SPF, DMARC, DKIM, rDNS)
3. VPS'i **gophish** ile yapılandırın
3. Kampanyayı hazırlayın
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Benzer alan adları oluşturma veya güvenilir bir alan adı satın alma

### Alan Adı Varyasyon Teknikleri

- **Anahtar kelime**: Alan adı orijinal domainin önemli bir **anahtar kelimesini içerir** (ör. zelster.com-management.com).
- **Tireli alt alan adı**: Bir alt alan adındaki **nokta yerine tire** kullanın (ör. www-zelster.com).
- **Yeni TLD**: Aynı alan adı farklı bir **TLD** ile (ör. zelster.org)
- **Homoglyph**: Alan adındaki bir harfi **benzer görünen harflerle** değiştirir (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Yer değiştirme (Transposition):** Alan adındaki iki harfi **değiştirir** (ör. zelsetr.com).
- **Tekil/Çoğul yapma**: Alan adının sonuna “s” ekler veya kaldırır (ör. zeltsers.com).
- **Atlama (Omission)**: Alan adından bir harfi **çıkarır** (ör. zelser.com).
- **Tekrar (Repetition):** Alan adındaki bir harfi **tekrar eder** (ör. zeltsser.com).
- **Değiştirme (Replacement)**: Homoglyph’e benzer fakat daha az gizli. Alan adındaki harfi, klavyede yakın bir harfle değiştirir (ör. zektser.com).
- **Alt alan ayrımı (Subdomained)**: Alan adının içine bir **nokta** ekler (ör. ze.lster.com).
- **Ekleme (Insertion)**: Alan adına bir **harf ekler** (ör. zerltser.com).
- **Eksik nokta (Missing dot)**: TLD’yi alan adına ekler. (ör. zelstercom.com)

**Otomatik Araçlar**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websiteleri**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Bazı durumlarda depolanan veya iletişim halindeki bazı bitlerin, güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörler nedeniyle **otomatik olarak tersine çevrilme (fliplenme)** olasılığı vardır.

Bu kavram DNS isteklerine **uygulandığında**, DNS sunucusu tarafından **alınan alan adının**, başlangıçta istenen alan adıyla aynı olmama ihtimali vardır.

Örneğin, "windows.com" alan adında tek bir bit değişikliği onu "windnws.com" haline getirebilir.

Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek amacıyla hedefin alan adına benzeyen birden fazla bit-flipping domain **kaydederek** bundan **faydalanabilirler**.

Daha fazla bilgi için okuyun [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Güvenilir bir alan adı satın alma

Kullanabileceğiniz süresi dolmuş bir alan adını bulmak için [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arama yapabilirsiniz.\
Satın almayı düşündüğünüz süresi dolmuş alan adının **zaten iyi bir SEO'ya sahip olduğundan** emin olmak için nasıl kategorize edildiğini şu kaynaklarda kontrol edebilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posta Keşfi

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya zaten keşfettiğiniz adresleri **doğrulamak** için hedefin SMTP sunucularına karşı bunları brute-force edip edemeyeceğinizi kontrol edebilirsiniz. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcılar e-postalarına erişmek için **herhangi bir web portalı** kullanıyorsa, portalın **username brute force** saldırılarına karşı zafiyetli olup olmadığını kontrol etmeyi ve mümkünse bu zafiyeti kullanmayı unutmayın.

## GoPhish Yapılandırma

### Kurulum

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

İndirin ve `/opt/gophish` içine açın ve `/opt/gophish/gophish` çalıştırın.\
Çıktıda admin kullanıcı için bir parola verilecektir ve yönetim için port 3333'te bu bilgileri kullanmanız gerekir. Bu nedenle o porta erişin ve admin parolasını değiştirin. Bu portu yerelinize tünellemeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **alan adını zaten satın almış** olmalısınız ve bu alan adı **gophish**'i yapılandırdığınız **VPS'in IP'sine** **işaret ediyor** olmalıdır.
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
**Mail yapılandırması**

Yüklemeye başla: `apt-get install postfix`

Sonra alan adını aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınıza göre değiştirin ve **VPS'inizi yeniden başlatın.**

Şimdi, `mail.<domain>` için VPS'in **IP adresini** gösteren bir **DNS A record** ve `mail.<domain>`'i işaret eden bir **DNS MX** kaydı oluşturun

Şimdi e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

gophish'in çalışmasını durdurun ve yapılandırın.  
`/opt/gophish/config.json` dosyasını aşağıdaki gibi değiştirin (https kullanıldığına dikkat edin):
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
**gophish servisini yapılandırma**

gophish servisini oluşturmak ve otomatik başlatılıp bir servis olarak yönetilmesini sağlamak için, `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:
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
Hizmeti yapılandırmayı tamamlayın ve aşağıdakileri yaparak kontrol edin:
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
## Mail sunucusu ve domain yapılandırma

### Bekleyin & meşru olun

Bir domain ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu yüzden phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibar olan bir sektöre ait bir sayfa koyarsanız elde edilen itibar daha iyi olur.

Bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı bitirebileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırın

VPS'nin IP adresini domain adına çözecek bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Record

Yeni domain için **bir SPF kaydı yapılandırmalısınız**. Eğer SPF kaydının ne olduğunu bilmiyorsanız [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![](<../../images/image (1037).png>)

Bu, domain içinde bir TXT kaydına girilmesi gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

Yeni domain için **DMARC kaydı yapılandırmalısınız**. Bir DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriğe sahip olacak şekilde `_dmarc.<domain>` ana bilgisayar adına işaret eden yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan adı için **bir DKIM yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM anahtarının oluşturduğu iki B64 değerini birleştirmeniz gerekiyor:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Sadece sayfaya girip size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Email yapılandırmanızı ayrıca `check-auth@verifier.port25.com` adresine bir e-posta göndererek **kontrol edebilirsiniz** ve **cevabı okuyabilirsiniz** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz cevabı _/var/mail/root_ dosyasında görmeniz gerekir).\
Tüm testleri geçtiğinizi kontrol edin:
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
Ayrıca **kontrolünüzdeki bir Gmail hesabına mesaj** gönderebilir ve Gmail gelen kutunuzdaki **e-posta başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) domainunuzun spamhouse tarafından engellenip engellenmediğini gösterebilir. Domain/IP'nizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Domain/IP'nizin kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## Create & Launch GoPhish Campaign

### Sending Profile

- Gönderici profilini tanımlamak için bir **name to identify** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve şifreyi boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Testler sırasında kara listeye alınmamak için test e-postalarını **10min mails adreslerine** göndermenizi tavsiye ederim.

### Email Template

- Şablonu tanımlamak için bir **name to identify** belirleyin
- Ardından bir **subject** yazın (garip olmayan, normal bir e-postada görebileceğiniz türden bir şey)
- "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
- **email template**'ini yazın (aşağıdaki örnekteki gibi değişkenler kullanabilirsiniz):
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
AzureAD/AWS/Okta olaylarında **`deleteMFA` + `addMFA`** işlemlerinin **aynı IP'den dakikalar içinde** gerçekleşip gerçekleşmediğini izleyin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kurbanın panosuna kötü amaçlı komutları sessizce kopyalayabilir ve sonra kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak herhangi bir indirme veya ek olmadan keyfi kod çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatörler giderek phishing akışlarını basit bir cihaz kontrolünün arkasına alıyor; böylece masaüstü crawlers son sayfalara asla ulaşamıyor. Yaygın bir örüntü, touch-capable DOM'u test eden küçük bir script'in sonucunu bir server endpoint'ine post etmektir; mobil olmayan istemciler HTTP 500 (veya boş bir sayfa) alırken, mobil kullanıcılar tam akışı görür.

Minimal client snippet (typik mantık):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantığı (basitleştirilmiş):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Sıkça gözlemlenen sunucu davranışı:
- İlk yüklemede bir session cookie ayarlar.
- Kabul eder `POST /detect {"is_mobile":true|false}`.
- Sonraki GET'lere `is_mobile=false` olduğunda 500 (veya placeholder) döndürür; yalnızca `true` ise phishing sunar.

Av ve tespit heuristikleri:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → non-mobile için HTTP 500; meşru mobil hedef yolları 200 döndürür ve sonrasında HTML/JS sunar.
- İçeriği yalnızca `ontouchstart` veya benzeri cihaz kontrollerine göre koşullayan sayfaları engelleyin veya inceleyin.

Savunma ipuçları:
- Kapalı içeriği ortaya çıkarmak için, JS etkin ve mobil benzeri parmak izine sahip crawlers çalıştırın.
- Yeni kayıtlı alan adlarında `POST /detect` sonrasında şüpheli HTTP 500 yanıtları için alarm oluşturun.

## Referanslar

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
