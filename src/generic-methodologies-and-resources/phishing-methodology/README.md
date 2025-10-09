# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Select the **hedef alan adı**.
2. Hedefin kullandığı **login portalları arayarak** temel web keşfi yapın ve hangi portalı **taklit edeceğinize karar verin**.
3. **OSINT** kullanarak **e-posta adresleri bulun**.
2. Prepare the environment
1. **Phishing değerlendirmesinde kullanacağınız alan adını satın alın**
2. **E-posta servisiyle ilgili kayıtları yapılandırın** (SPF, DMARC, DKIM, rDNS)
3. VPS'i **gophish** ile yapılandırın
3. Prepare the campaign
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Alan adı, orijinal domainin önemli bir **anahtar kelimesini** içerir (ör. zelster.com-management.com).
- **hypened subdomain**: Bir alt alan adındaki **noktayı tıraç ile değiştirin** (ör. www-zelster.com).
- **New TLD**: Aynı domainin **yeni bir TLD** ile kullanımı (ör. zelster.org)
- **Homoglyph**: Alan adındaki bir harfi **benzer görünen harflerle** değiştirir (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Alan adı içinde iki harfi **değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Alan adının sonuna “s” ekler veya kaldırır (ör. zeltsers.com).
- **Omission**: Alan adından bir harfi **çıkarır** (ör. zelser.com).
- **Repetition:** Alan adındaki bir harfi **tekrar eder** (ör. zeltsser.com).
- **Replacement**: Homoglyph'e benzer fakat daha az gizli. Alan adındaki bir harfi, klavyede komşu olabilecek başka bir harfle değiştirir (ör. zektser.com).
- **Subdomained**: Alan adı içine bir **nokta** ekler (ör. ze.lster.com).
- **Insertion**: Alan adına bir **harf ekler** (ör. zerltser.com).
- **Missing dot**: TLD'yi alan adına ekler. (ör. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web siteleri**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörler nedeniyle saklanan veya iletişim halindeki bazı bitlerin **otomatik olarak tersine dönebileceği** bir olasılık vardır.

Bu kavram **DNS isteklerine uygulandığında**, DNS sunucusunun aldığı **domain'in başlangıçta istenen domain ile aynı olmama ihtimali** vardır.

Örneğin, "windows.com" domainindeki tek bir bit değişikliği onu "windnws.com" haline getirebilir.

Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek amacıyla hedef domain ile benzer **birden fazla bit-flipping domaini kaydederek** bundan yararlanabilirler.

Daha fazla bilgi için bkz. [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Kullanabileceğiniz süresi dolmuş bir domaini bulmak için [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arama yapabilirsiniz.\
Satın almayı düşündüğünüz süresi dolmuş domainin **zaten iyi bir SEO'ya** sahip olduğundan emin olmak için aşağıdaki servislerde nasıl kategorize edildiğini kontrol edebilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya zaten keşfettiklerinizi **doğrulamak** için, hedefin SMTP sunucularına karşı bu adresleri brute-force ile deneyebilirsiniz. [E-posta adreslerini doğrulama/keşfetmeyi burada öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, eğer kullanıcılar maillerine erişmek için herhangi bir web portalı kullanıyorsa, bu portalın **username brute force**'a karşı zafiyeti olup olmadığını kontrol etmeyi ve mümkünse bu zafiyeti sömürmeyi unutmayın.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **alan adını zaten satın almış** olmalısınız ve bu alan adının, **gophish**'ı yapılandırdığınız **VPS'in IP adresine** **işaret ediyor** olması gerekir.
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

Daha sonra alan adını şu dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınız ile güncelleyin ve **VPS'inizi yeniden başlatın.**

Şimdi VPS'in IP adresini işaret eden `mail.<domain>` için bir **DNS A record** oluşturun ve `mail.<domain>`'i işaret eden bir **DNS MX** kaydı oluşturun.

Şimdi e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandırmasını yapalım.\
`/opt/gophish/config.json` dosyasını aşağıdaki gibi değiştirin (https kullanımına dikkat):
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

gophish servisinin otomatik olarak başlatılabilmesi ve bir servis olarak yönetilebilmesi için, aşağıdaki içeriğe sahip `/etc/init.d/gophish` dosyasını oluşturabilirsiniz:
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
Hizmeti yapılandırmayı tamamlayın ve çalıştığını şu şekilde kontrol edin:
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

Ne kadar eski bir domain olursa spam olarak yakalanma olasılığı o kadar düşüktür. Bu yüzden phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibar gerektiren bir sektöre ait bir sayfa eklerseniz elde edilen itibar daha iyi olur.

Unutmayın, bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı bitirebilirsiniz.

### Reverse DNS (rDNS) record yapılandırması

VPS'in IP adresini domain adına çözecek bir rDNS (PTR) record ayarlayın.

### Sender Policy Framework (SPF) Record

Yeni domain için **bir SPF record yapılandırmalısınız**. Eğer SPF record'un ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![](<../../images/image (1037).png>)

Bu, domain içindeki bir TXT record içine konması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

Yeni alan adı için **bir DMARC kaydı yapılandırmalısınız**. Bir DMARC kaydının ne olduğunu bilmiyorsanız [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriğe sahip olacak şekilde `_dmarc.<domain>` host adına işaret eden yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan adı için **DKIM yapılandırması yapmalısınız**. Bir DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu öğretici şu kaynağa dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com/)\ kullanarak yapabilirsiniz. Sayfaya girip size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca **e-posta yapılandırmanızı kontrol etmek** için `check-auth@verifier.port25.com` adresine bir e-posta gönderip **yanıtı okuyabilirsiniz** (bunun için port **25**'i **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Kontrolünüzdeki bir **Gmail hesabına mesaj** da gönderebilir ve Gmail gelen kutunuzda **e-postanın başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Kara Listesinden Kaldırma

The page [www.mail-tester.com](https://www.mail-tester.com) alan adınızın Spamhouse tarafından engellenip engellenmediğini gösterebilir. Alan adınız/IP'nizin kaldırılmasını şu adresten talep edebilirsiniz: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Kaldırma

Alan adınız/IP'nizin kaldırılmasını şu adresten talep edebilirsiniz: [https://sender.office.com/](https://sender.office.com).

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderici Profili

- Gönderici profilini tanımlamak için bir **isim belirleyin**
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve şifreyi boş bırakabilirsiniz, ancak **Ignore Certificate Errors** seçeneğinin işaretli olduğundan emin olun

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" özelliğini kullanmanız tavsiye edilir.\
> Testler sırasında kara listeye alınmamak için test e-postalarını **10min mails adreslerine göndermenizi** öneririm.

### E-posta Şablonu

- Şablonu tanımlamak için bir **isim belirleyin**
- Sonra bir **subject** yazın (tuhaf olmayan, normal bir e-postada görebileceğiniz türden bir şey)
- Mutlaka "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
- E-posta **şablonunu** yazın (aşağıdaki örnekte olduğu gibi değişkenler kullanabilirsiniz):
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
Not: E-postanın güvenilirliğini artırmak için, müşterinin bir e-postasından bazı imzaları kullanmanız önerilir. Öneriler:

- Bir **var olmayan adrese** e-posta gönderin ve yanıtın bir imza içerip içermediğini kontrol edin.
- info@ex.com veya press@ex.com veya public@ex.com gibi **genel e-posta adreslerini** arayın, onlara bir e-posta gönderin ve yanıtı bekleyin.
- Keşfettiğiniz **geçerli bir e-posta adresiyle** iletişime geçmeyi deneyin ve yanıtı bekleyin.

![](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca **gönderilecek dosyalar eklemenize** izin verir. Eğer özel hazırlanmış dosya/belgeler kullanarak NTLM challenge'larını çalmak isterseniz [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Sayfası

- Bir **isim** yazın
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin
- Bir **yeniden yönlendirme** ayarlayın

![](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve yerelde bazı testler yapmanız (ör. bir Apache sunucusu kullanarak) **sonuçtan memnun kalana kadar** gerekir. Ardından o HTML kodunu kutuya yapıştırın.\
> Eğer HTML için **bazı statik kaynakları kullanmanız** gerekiyorsa (ör. bazı CSS ve JS dosyaları) bunları _**/opt/gophish/static/endpoint**_ dizinine kaydedebilir ve sonra _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Yönlendirme için kullanıcıları hedefin gerçek ana web sayfasına yönlendirebilir veya örneğin _/static/migration.html_’e yönlendirip [https://loading.io/](https://loading.io/) gibi bir **spinning wheel** 5 saniye gösterip sonra işlemin başarılı olduğunu belirtebilirsiniz.

### Kullanıcılar & Gruplar

- Bir ad belirleyin
- **Import the data** (örnek şablonu kullanmak için her kullanıcının firstname, last name ve email address bilgilerine ihtiyacınız olduğunu unutmayın)

![](<../../images/image (163).png>)

### Kampanya

Son olarak bir isim, email template, landing page, URL, sending profile ve group seçerek bir kampanya oluşturun. URL'nin kurbana gönderilecek link olduğunu unutmayın

Not: **Sending Profile**, final phishing e-postanın nasıl görüneceğini görmek için bir test e-postası göndermeye izin verir:

![](<../../images/image (192).png>)

> [!TIP]
> Testler sırasında kara listeye alınmayı önlemek için test e-postalarını **10min mail adreslerine** göndermenizi öneririm.

Her şey hazır olduğunda, kampanyayı başlatın!

## Web Sitesi Klonlama

Herhangi bir nedenle web sitesini klonlamak isterseniz aşağıdaki sayfayı kontrol edin:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoor'lu Belgeler ve Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Red Teams için) ayrıca **backdoor içeren dosyalar göndermek** isteyebilirsiniz (örneğin bir C2 veya sadece bir kimlik doğrulamayı tetikleyecek bir şey olabilir).\
Bazı örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing ile MFA

### Proxy MitM ile

Önceki saldırı, gerçek bir web sitesini taklit edip kullanıcının girdiği bilgileri topladığınız için oldukça zekicedir. Ne yazık ki, kullanıcı doğru parolayı girmezse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgiler sizi kandırılan kullanıcının yerine geçmeye yetmeyecektir**.

Bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar faydalıdır. Bu araçlar size bir MitM türü saldırı oluşturma imkanı verir. Temelde saldırı şu şekilde çalışır:

1. Gerçek web sayfasının **giriş formunu taklit edersiniz**.
2. Kullanıcı kimlik bilgilerini sahte sayfanıza gönderir ve araç bunları gerçek web sayfasına göndererek **bilgilerin geçerli olup olmadığını kontrol eder**.
3. Hesap **2FA** ile yapılandırılmışsa, MitM sayfası bunu isteyecek ve kullanıcı girdikten sonra araç bunu gerçek web sayfasına iletecektir.
4. Kullanıcı doğrulandıktan sonra saldırgan olarak **kimlik bilgilerini, 2FA kodunu, cookie'yi ve araç MitM sırasında gerçekleşen her etkileşimin bilgisini** yakalamış olursunuz.

### VNC ile

Kurbanı orijinaline benzeyen kötü amaçlı bir sayfaya göndermek yerine, onu gerçek web sayfasına bağlı bir tarayıcıya sahip bir **VNC oturumuna** gönderirseniz ne olur? Ne yaptığını görebilir, parolayı, kullanılan MFA’yı, çerezleri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz

## Tespitin tespiti

Birinin sizi yakalayıp yakalamadığını anlamanın en iyi yollarından biri, alan adınızı karaliste içinde aramaktır. Alan adınız listeleniyorsa, bir şekilde alan adınız şüpheli olarak tespit edilmiştir.\
Alan adınızın herhangi bir karalisteye girip girmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) adresini kullanmaktır.

Ancak, kurbanın **yabanda şüpheli phishing etkinlikleri arayıp aramadığını** bilmenin başka yolları da vardır; bunlar şu sayfada açıklandığı gibidir:


{{#ref}}
detecting-phising.md
{{#endref}}

Kurbanın alan adına çok benzer bir isimle bir domain satın alabilir ve/veya sizin kontrolünüzdeki bir domainin **alt alanı** için kurbanın alan adı anahtar kelimesini içeren bir sertifika oluşturabilirsiniz. Eğer **kurban** bu domainlerle herhangi bir DNS veya HTTP etkileşimi yaparsa, aktif olarak şüpheli domainler aradığını anlarsınız ve çok daha gizli hareket etmeniz gerekir.

### Phishing'i değerlendirme

E-postanızın spam klasörüne düşüp düşmeyeceğini, engellenip engellenmeyeceğini veya başarılı olup olmayacağını değerlendirmek için [**Phishious**](https://github.com/Rices/Phishious) kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion setleri giderek daha fazla e-posta tuzaklarını tamamen atlayıp **doğrudan service-desk / identity-recovery iş akışını** hedefleyerek MFA'yı aşmayı tercih ediyor. Bu saldırı tamamen "living-off-the-land": operatör geçerli kimlik bilgilerini ele geçirdikten sonra yerleşik admin araçlarıyla pivot yapar – herhangi bir malware gerekli değildir.

### Saldırı akışı
1. Hedefi keşfetme
* LinkedIn, veri sızıntıları, açık GitHub, vb. kaynaklardan kişisel ve kurumsal bilgileri toplama.
* Yüksek değerli kimlikleri (yöneticiler, IT, finans) belirleyin ve parola / MFA sıfırlama için **tam yardım masası sürecini** tespit edin.
2. Gerçek zamanlı sosyal mühendislik
* Hedefi taklit ederek telefon, Teams veya chat üzerinden help-desk ile iletişim kurun (çoğunlukla **spoofed caller-ID** veya **klonlanmış ses** ile).
* Önceden toplanmış PII bilgilerini vererek bilgi-temelli doğrulamayı geçin.
* Görevliden **MFA secret'ı sıfırlamasını** veya kayıtlı bir mobil numarada **SIM-swap** yapmasını sağlayın.
3. Erişim sonrası anlık eylemler (gerçek vakalarda ≤60 dk)
* Herhangi bir web SSO portalı üzerinden foothold oluşturun.
* Yerleşik araçlarla AD / AzureAD keşfi yapın (ikili dosya bırakmaya gerek yok):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortaya hareket için **WMI**, **PsExec** veya ortamda zaten beyaz listeye alınmış meşru **RMM** ajanlarını kullanın.

### Tespit & Hafifletme
* Help-desk identity recovery işlemini **ayrıcalıklı bir operasyon** olarak ele alın – step-up auth ve yönetici onayı gerektirin.
* Aşağıdaki durumlarda uyarı veren **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları dağıtın:
  * MFA yöntemi değişti + yeni cihaz / coğrafyadan kimlik doğrulama.
  * Aynı prensibin (user → admin) anında yükseltilmesi.
* Help-desk aramalarını kaydedin ve herhangi bir sıfırlamadan önce **önceden kayıtlı bir numaraya geri dönüş (call-back)** zorunlu kılın.
* Yeni sıfırlanan hesapların otomatik olarak yüksek ayrıcalıklı token'lar edinmemesi için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## Büyük Ölçekli Aldatma – SEO Poisoning & “ClickFix” Kampanyaları
Hammadde ekipleri, yüksek dokunuşlu operasyonların maliyetini, **arama motorlarını ve reklam ağlarını teslimat kanalı haline getiren** kitlesel saldırılarla dengelerler.

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi sahte bir sonucu üst sıradaki arama reklamlarına iter.
2. Kurban küçük bir **first-stage loader** indirir (çoğunlukla JS/HTA/ISO). Unit 42 tarafından görülen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader tarayıcı çerezlerini + kimlik bilgileri veritabanlarını dışarı aktarır, sonra **sessiz bir loader** çeker ve bu loader *gerçek zamanlı* olarak karar verir – dağıtılacak mı:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence bileşeni (registry Run anahtarı + scheduled task)

### Sertleştirme ipuçları
* Yeni kayıtlı domainleri engelleyin ve *arama reklamları* için Advanced DNS / URL Filtering uygulayın.
* Yazılım kurulumunu imzalı MSI / Store paketleri ile kısıtlayın, `HTA`, `ISO`, `VBS` çalıştırmayı politika ile engelleyin.
* Tarayıcıların child process olarak kurulum açan süreçlerini izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* İlk aşama loader'lar tarafından sıkça kötüye kullanılan LOLBins için hunt yapın (ör. `regsvr32`, `curl`, `mshta`).

---

## AI Destekli Phishing Operasyonları
Saldırganlar artık tam kişiselleştirilmiş tuzaklar ve gerçek zamanlı etkileşim için **LLM & voice-clone API'lerini** zincirliyor.

| Katman | Tehdit aktörü tarafından örnek kullanım |
|-------|-----------------------------|
|Automation|>100k e-posta / SMS üretebilir ve gönderebilir, rastgeleleştirilmiş ifadeler ve takip linkleri kullanır.|
|Generative AI|Kamuya açık M&A, sosyal medyadan şaka vb. referanslar içeren *tek seferlik* e-postalar üretir; geri aramada CEO deep-fake sesi kullanır.|
|Agentic AI|Otonom olarak domain kaydeder, açık kaynak istihbaratı tarar, bir kurban tıkladığında fakat kimlik bilgilerini göndermediğinde bir sonraki aşama e-postasını hazırlar.|

**Savunma:**
• ARC/DKIM anomalileri yoluyla otomasyondan gönderilen mesajları vurgulayan **dinamik bantlar** ekleyin.  
• Yüksek riskli telefon talepleri için **ses-biyometrik meydan okuma ifadeleri** uygulayın.  
• Farkındalık programlarında AI üretimli tuzakları sürekli simüle edin – statik şablonlar artık güncel değil.

Ayrıca bkz. – credential phishing için agentic browsing istismarları:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Yorgunluğu / Push Bombing Varyantı – Zorunlu Sıfırlama
Klasik push-bombing dışında operatörler basitçe help-desk görüşmesi sırasında yeni bir MFA kaydı zorlar ve kullanıcının mevcut token'ını geçersiz kılar. Sonraki herhangi bir giriş istemi kurbana meşru gibi görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarında aynı IP'den birkaç dakika içinde **`deleteMFA` + `addMFA`** gerçekleşen durumları izleyin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kurbanın clipboard'ına gizlice kötü amaçlı komutlar kopyalayabilir ve sonra kullanıcıyı **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak herhangi bir indirme veya ek olmadan rastgele kod çalıştırabilirler.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatörler, desktop crawler'ların son sayfalara asla ulaşmaması için phishing akışlarını giderek basit bir cihaz kontrolünün arkasına alıyor. Yaygın bir örüntü, dokunmatik özellikli bir DOM'u test eden ve sonucu bir server endpoint'ine gönderen küçük bir script'tir; non‑mobile istemciler HTTP 500 (veya boş bir sayfa) alırken, mobile kullanıcılara tam akış sunulur.

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
Sıkça gözlemlenen sunucu davranışı:
- İlk yüklemede bir session cookie ayarlar.
- Kabul eder: `POST /detect {"is_mobile":true|false}`.
- Sonraki GET'lere `is_mobile=false` olduğunda 500 (veya placeholder) döner; sadece `true` ise phishing sunar.

Hunting ve tespit heuristikleri:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → non‑mobile için HTTP 500; gerçek mobil kurban yolları 200 döner ve takip eden HTML/JS sunar.
- İçeriği yalnızca `ontouchstart` veya benzeri cihaz kontrollerine göre koşullandıran sayfaları engelleyin veya yakından inceleyin.

Savunma ipuçları:
- Crawler'ları mobil benzeri fingerprint'lerle ve JS etkin olarak çalıştırarak kısıtlı içeriği ortaya çıkarın.
- Yeni kayıtlı domainlerde `POST /detect` sonrası gelen şüpheli 500 yanıtları için uyarı oluşturun.

## Referanslar

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
