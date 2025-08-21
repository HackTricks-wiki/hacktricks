# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Kurbanı araştır
1. **Kurban alan adını** seç.
2. Kurbanın kullandığı **giriş portallarını** bulmak için bazı temel web taramaları yap ve hangi portaldan **taklit yapacağına** **karar ver**.
3. Bazı **OSINT** kullanarak **e-postaları bul**.
2. Ortamı hazırla
1. Phishing değerlendirmesi için kullanacağın **alan adını satın al**.
2. İlgili kayıtları **e-posta hizmetini yapılandır** (SPF, DMARC, DKIM, rDNS).
3. **gophish** ile VPS'yi yapılandır.
3. Kampanyayı hazırla
1. **E-posta şablonunu** hazırla.
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırla.
4. Kampanyayı başlat!

## Benzer alan adları oluştur veya güvenilir bir alan adı satın al

### Alan Adı Varyasyon Teknikleri

- **Anahtar kelime**: Alan adı, orijinal alan adının önemli bir **anahtar kelimesini** **içerir** (örneğin, zelster.com-management.com).
- **tireli alt alan**: Bir alt alanın **noktasını tire ile değiştir** (örneğin, www-zelster.com).
- **Yeni TLD**: Aynı alan adı, **yeni bir TLD** kullanarak (örneğin, zelster.org).
- **Homoglif**: Alan adındaki bir harfi, **benzer görünen harflerle** **değiştirir** (örneğin, zelfser.com).

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transpozisyon:** Alan adındaki iki harfi **değiştirir** (örneğin, zelsetr.com).
- **Tekil/Çoğul**: Alan adının sonuna “s” ekler veya çıkarır (örneğin, zeltsers.com).
- **Atlama**: Alan adından bir harfi **çıkarır** (örneğin, zelser.com).
- **Tekrar:** Alan adındaki bir harfi **tekrarlar** (örneğin, zeltsser.com).
- **Değiştirme**: Homoglif gibi ama daha az gizli. Alan adındaki bir harfi, belki de klavye üzerindeki orijinal harfe yakın bir harfle değiştirir (örneğin, zektser.com).
- **Alt alan**: Alan adı içinde bir **nokta** ekle (örneğin, ze.lster.com).
- **Ekleme**: Alan adına bir harf **ekler** (örneğin, zerltser.com).
- **Eksik nokta**: Alan adına TLD'yi ekle. (örneğin, zelstercom.com)

**Otomatik Araçlar**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web Siteleri**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**İletim sırasında saklanan veya iletişimde olan bazı bitlerin otomatik olarak değişme olasılığı vardır**; bu, güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörlerden kaynaklanabilir.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusu tarafından alınan alan adının**, başlangıçta talep edilen alan adıyla aynı olmaması mümkündür.

Örneğin, "windows.com" alan adındaki tek bir bit değişikliği, onu "windnws.com" haline getirebilir.

Saldırganlar, kurbanın alan adına benzer **birden fazla bit-flipping alan adı kaydederek** bundan **yararlanabilirler**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.

### Güvenilir bir alan adı satın al

Kullanabileceğin bir süresi dolmuş alan adı aramak için [https://www.expireddomains.net/](https://www.expireddomains.net) adresini ziyaret edebilirsin.\
Satın almayı düşündüğün süresi dolmuş alan adının **zaten iyi bir SEO'ya sahip olduğundan emin olmak için** şu kategorilere bakabilirsin:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-postaları Keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **bulmak veya** zaten keşfettiğin e-posta adreslerini **doğrulamak için**, kurbanın smtp sunucularını brute-force ile kontrol edebilirsin. [E-posta adresini doğrulama/keşfetme hakkında buradan bilgi al](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcıların **e-postalarına erişmek için herhangi bir web portalı kullanıp kullanmadığını** unutma; eğer kullanıyorsa, **kullanıcı adı brute force** saldırısına karşı savunmasız olup olmadığını kontrol edebilir ve mümkünse bu zafiyeti istismar edebilirsin.

## GoPhish'i Yapılandırma

### Kurulum

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsin.

İndirin ve `/opt/gophish` dizinine çıkarın ve `/opt/gophish/gophish` komutunu çalıştırın.\
Çıktıda, 3333 numaralı portta admin kullanıcı için bir şifre verilecektir. Bu nedenle, o porta erişin ve admin şifresini değiştirmek için bu kimlik bilgilerini kullanın. O portu yerel olarak tünellemeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigürasyon

**TLS sertifika konfigürasyonu**

Bu adımdan önce **kullanacağınız alan adını zaten satın almış olmalısınız** ve bu alan adı **gophish'i yapılandırdığınız VPS'nin IP'sine** **işaret etmelidir**.
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

Başlamak için: `apt-get install postfix`

Sonra alan adını aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınızla değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<domain>` için **DNS A kaydı** oluşturun ve VPS'nin **ip adresine** işaret edin ve `mail.<domain>` için bir **DNS MX** kaydı oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandırmasını yapalım.\
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
**Gophish hizmetini yapılandırın**

Gophish hizmetini otomatik olarak başlatılabilir ve bir hizmet olarak yönetilebilir hale getirmek için `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:
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
Hizmeti yapılandırmayı tamamlayın ve kontrol edin:
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

### Bekleyin ve meşru olun

Bir alan adı ne kadar eskiyse, spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle, phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektörde bir sayfa oluşturursanız, elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile, her şeyi şimdi yapılandırmayı bitirebileceğinizi unutmayın.

### Ters DNS (rDNS) kaydını yapılandırın

VPS'nin IP adresini alan adıyla çözen bir rDNS (PTR) kaydı ayarlayın.

### Gönderen Politika Çerçevesi (SPF) Kaydı

Yeni alan adı için **bir SPF kaydı yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın).

![](<../../images/image (1037).png>)

Bu, alan adı içindeki bir TXT kaydına yerleştirilmesi gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

Yeni alan için **bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriği içeren `_dmarc.<domain>` ana bilgisayar adına işaret eden yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan için **bir DKIM yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu eğitim, [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy) adresine dayanmaktadır.

> [!TIP]
> DKIM anahtarının ürettiği her iki B64 değerini birleştirmeniz gerekiyor:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz.\
Sadece sayfaya erişin ve size verilen adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca **e-posta yapılandırmanızı kontrol edebilirsiniz** `check-auth@verifier.port25.com` adresine bir e-posta göndererek ve **yanıtı okuyarak** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekecek).\
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
Kontrolünüz altındaki bir **Gmail'e mesaj gönderebilir** ve Gmail gelen kutunuzdaki **e-posta başlıklarını** kontrol edebilirsiniz, `dkim=pass` `Authentication-Results` başlık alanında bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Kara Listesinden Çıkarma

Sayfa [www.mail-tester.com](https://www.mail-tester.com) alan adınızın spamhouse tarafından engellenip engellenmediğini gösterebilir. Alan adınızın/IP'nizin kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Çıkarma

Alan adınızın/IP'nizin kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderici Profili

- Gönderici profilini tanımlamak için bir **isim belirleyin**
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve şifreyi boş bırakabilirsiniz, ancak Sertifika Hatalarını Yoksay'ı kontrol ettiğinizden emin olun.

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Test E-postası Gönder**" işlevini kullanmanız önerilir.\
> Test yaparken kara listeye alınmamak için **test e-postalarını 10 dakikalık e-posta adreslerine göndermeyi** öneririm.

### E-posta Şablonu

- Şablonu tanımlamak için bir **isim belirleyin**
- Ardından bir **konu** yazın (olağan bir e-postada okuyabileceğiniz bir şey olsun)
- "**İzleme Resmi Ekle**" seçeneğini işaretlediğinizden emin olun
- **e-posta şablonunu** yazın (aşağıdaki örnekte olduğu gibi değişkenler kullanabilirsiniz):
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
Not edin ki **e-postanın güvenilirliğini artırmak için**, müşteriden gelen bir e-posta imzası kullanılması önerilir. Öneriler:

- **Mevcut olmayan bir adrese** e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
- **Açık e-postalar** arayın, örneğin info@ex.com veya press@ex.com veya public@ex.com ve onlara bir e-posta gönderin ve yanıtı bekleyin.
- **Geçerli bulunan** bir e-posta ile iletişim kurmaya çalışın ve yanıtı bekleyin.

![](<../../images/image (80).png>)

> [!TIP]
> E-posta Şablonu ayrıca **göndermek için dosyalar eklemeye** de olanak tanır. Eğer bazı özel hazırlanmış dosyalar/dokümanlar kullanarak NTLM zorluklarını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Açılış Sayfası

- Bir **isim** yazın.
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
- **Gönderilen Verileri Yakala** ve **Şifreleri Yakala** seçeneklerini işaretleyin.
- Bir **yönlendirme** ayarlayın.

![](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve yerel olarak bazı testler yapmanız gerekecektir (belki bazı Apache sunucusu kullanarak) **sonuçlardan memnun kalana kadar.** Sonra, o HTML kodunu kutuya yazın.\
> Eğer HTML için **bazı statik kaynaklar** kullanmanız gerekiyorsa (belki bazı CSS ve JS sayfaları) bunları _**/opt/gophish/static/endpoint**_ dizinine kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Yönlendirme için kullanıcıları **kurbanın gerçek ana web sayfasına yönlendirebilir** veya örneğin _/static/migration.html_ adresine yönlendirebilir, 5 saniye boyunca bir **dönme tekerleği** (**[**https://loading.io/**](https://loading.io)**) koyabilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz.

### Kullanıcılar ve Gruplar

- Bir isim belirleyin.
- **Verileri içe aktarın** (örneğin, şablonu kullanmak için her kullanıcının adı, soyadı ve e-posta adresine ihtiyacınız olduğunu unutmayın).

![](<../../images/image (163).png>)

### Kampanya

Son olarak, bir isim, e-posta şablonu, açılış sayfası, URL, gönderim profili ve grup seçerek bir kampanya oluşturun. URL'nin kurbanlara gönderilecek bağlantı olacağını unutmayın.

**Gönderim Profili, test e-postası göndererek son phishing e-postasının nasıl görüneceğini görmenizi sağlar**:

![](<../../images/image (192).png>)

> [!TIP]
> Test e-postalarını **10 dakikalık e-posta adreslerine** göndermeyi öneririm, böylece test yaparken kara listeye alınmaktan kaçınabilirsiniz.

Her şey hazır olduğunda, kampanyayı başlatın!

## Web Sitesi Klonlama

Herhangi bir nedenle web sitesini klonlamak isterseniz, aşağıdaki sayfayı kontrol edin:

{{#ref}}
clone-a-website.md
{{#endref}}

## Arka Kapılı Belgeler ve Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Kırmızı Takımlar için) **bir tür arka kapı içeren dosyalar göndermek** isteyebilirsiniz (belki bir C2 veya belki de bir kimlik doğrulamasını tetikleyecek bir şey).\
Bazı örnekler için aşağıdaki sayfayı kontrol edin:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Proxy MitM Üzerinden

Önceki saldırı oldukça zekice, çünkü gerçek bir web sitesini taklit ediyor ve kullanıcının belirlediği bilgileri topluyorsunuz. Ne yazık ki, kullanıcı doğru şifreyi girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgi sizi kandırılan kullanıcı gibi göstermez**.

Bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar faydalıdır. Bu araç, MitM benzeri bir saldırı gerçekleştirmenizi sağlar. Temelde, saldırılar şu şekilde çalışır:

1. Gerçek web sayfasının **giriş** formunu taklit edersiniz.
2. Kullanıcı **kimlik bilgilerini** sahte sayfanıza gönderir ve araç bunları gerçek web sayfasına gönderir, **kimlik bilgilerin çalışıp çalışmadığını kontrol eder**.
3. Hesap **2FA** ile yapılandırılmışsa, MitM sayfası bunu isteyecek ve kullanıcı bunu girdikten sonra araç bunu gerçek web sayfasına gönderecektir.
4. Kullanıcı kimlik doğrulandıktan sonra siz (saldırgan olarak) **kimlik bilgilerini, 2FA'yı, çerezi ve aracın gerçekleştirdiği her etkileşimdeki bilgileri** yakalamış olacaksınız.

### VNC Üzerinden

Kurbanı **orijinaline benzer görünen kötü niyetli bir sayfaya göndermek yerine**, onu **gerçek web sayfasına bağlı bir tarayıcı ile VNC oturumuna** göndermeyi düşünsenize? Ne yaptığını görebilir, şifreyi, kullanılan MFA'yı, çerezleri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.

## Tespiti Tespit Etme

Elbette, yakalandığınızı anlamanın en iyi yollarından biri, **alan adınızı kara listelerde aramaktır**. Eğer listelenmişse, bir şekilde alan adınız şüpheli olarak tespit edilmiştir.\
Alan adınızın herhangi bir kara listede görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak, kurbanın **şüpheli phishing faaliyetlerini aktif olarak arayıp aramadığını** anlamanın başka yolları da vardır, bunlar aşağıda açıklanmıştır:

{{#ref}}
detecting-phising.md
{{#endref}}

**Kurbanın alan adına çok benzer bir isimle bir alan adı satın alabilir** ve/veya **sizin kontrolünüzdeki bir alanın** **alt alanı için bir sertifika oluşturabilirsiniz** **ve kurbanın alan adının** **anahtar kelimesini** içerebilirsiniz. Eğer **kurban** bu alanlarla herhangi bir **DNS veya HTTP etkileşimi** gerçekleştirirse, **şüpheli alan adlarını aktif olarak aradığını** bileceksiniz ve çok dikkatli olmanız gerekecek.

### Phishing'i Değerlendirme

E-postanızın spam klasörüne düşüp düşmeyeceğini veya engellenip engellenmeyeceğini değerlendirmek için [**Phishious**](https://github.com/Rices/Phishious) kullanın.

## Yüksek Temas Kimlik Kompromosu (Yardım Masası MFA Sıfırlama)

Modern saldırı setleri giderek e-posta tuzaklarını tamamen atlayarak **hizmet masası / kimlik kurtarma iş akışını doğrudan hedef alıyor** ve MFA'yı geçersiz kılıyor. Saldırı tamamen "yaşayan kaynaklardan yararlanma": operatör geçerli kimlik bilgilerine sahip olduğunda, yerleşik yönetici araçları ile geçiş yapar - kötü amaçlı yazılım gerektirmez.

### Saldırı Akışı
1. Kurbanı araştırın.
* LinkedIn, veri ihlalleri, kamuya açık GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri toplayın.
* Yüksek değerli kimlikleri (yönetici, BT, finans) belirleyin ve **şifre / MFA sıfırlama için tam yardım masası sürecini** sıralayın.
2. Gerçek zamanlı sosyal mühendislik.
* Hedefi taklit ederek yardım masasına telefon, Teams veya sohbet yoluyla ulaşın (genellikle **sahte arayan kimliği** veya **klonlanmış ses** ile).
* Bilgiye dayalı doğrulamayı geçmek için önceden toplanmış Kişisel Tanımlayıcı Bilgileri (PII) sağlayın.
* Temsilciyi **MFA sırrını sıfırlamaya** veya kayıtlı bir mobil numara üzerinde **SIM değişimi** yapmaya ikna edin.
3. Erişim sonrası hemen yapılacak işlemler (gerçek durumlarda ≤60 dakika)
* Herhangi bir web SSO portalı üzerinden bir yerleşim oluşturun.
* Yerleşik araçlarla AD / AzureAD'yi sıralayın (binaries bırakmadan):
```powershell
# dizin gruplarını ve ayrıcalıklı rolleri listele
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – dizin rollerini listele
Get-MgDirectoryRole | ft DisplayName,Id

# Hesabın giriş yapabileceği cihazları sıralayın
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten beyaz listeye alınmış **WMI**, **PsExec** veya meşru **RMM** ajanları ile yan hareket edin.

### Tespit ve Azaltma
* Yardım masası kimlik kurtarmayı **ayrıcalıklı bir işlem** olarak değerlendirin – adım artırma kimlik doğrulaması ve yönetici onayı gerektirir.
* Aşağıdaki durumlarda uyarı veren **Kimlik Tehdit Tespiti ve Yanıtı (ITDR)** / **UEBA** kuralları uygulayın:
* MFA yöntemi değişti + yeni cihazdan / coğrafyadan kimlik doğrulama.
* Aynı ilkenin (kullanıcı-→-yönetici) hemen yükseltilmesi.
* Yardım masası aramalarını kaydedin ve herhangi bir sıfırlama öncesinde **zaten kayıtlı bir numaraya geri arama** yapılmasını zorunlu kılın.
* Yeni sıfırlanan hesapların **yüksek ayrıcalıklı jetonları otomatik olarak miras almaması** için **Just-In-Time (JIT) / Ayrıcalıklı Erişim** uygulayın.

---

## Ölçekli Aldatma – SEO Zehirleme ve “ClickFix” Kampanyaları
Ticari ekipler, yüksek temaslı operasyonların maliyetini, **arama motorlarını ve reklam ağlarını teslimat kanalı haline getiren** kitlesel saldırılarla dengelemektedir.

1. **SEO zehirleme / kötü reklamcılık**, `chromium-update[.]site` gibi sahte bir sonucu en üst arama reklamlarına itmektedir.
2. Kurban küçük bir **ilk aşama yükleyici** (genellikle JS/HTA/ISO) indirir. Unit 42 tarafından görülen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Yükleyici tarayıcı çerezlerini + kimlik bilgisi veritabanlarını dışarı aktarır, ardından **sessiz bir yükleyici** çeker ve - *gerçek zamanlı* - dağıtılıp dağıtılmayacağına karar verir:
* RAT (örneğin AsyncRAT, RustDesk)
* fidye yazılımı / silici
* kalıcılık bileşeni (kayıt defteri Çalıştır anahtarı + planlı görev)

### Güçlendirme ipuçları
* Yeni kayıtlı alan adlarını engelleyin ve **Gelişmiş DNS / URL Filtreleme** uygulayın *arama reklamları* ve e-posta üzerinde.
* Yazılım yüklemesini imzalı MSI / Mağaza paketleri ile sınırlayın, `HTA`, `ISO`, `VBS` yürütmesini politika ile reddedin.
* Yükleyicileri açan tarayıcıların çocuk süreçlerini izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* İlk aşama yükleyicileri tarafından sıkça kötüye kullanılan LOLBins'i arayın (örneğin `regsvr32`, `curl`, `mshta`).

---

## AI-Gelişmiş Phishing Operasyonları
Saldırganlar artık **LLM ve ses klonlama API'lerini** tamamen kişiselleştirilmiş tuzaklar ve gerçek zamanlı etkileşim için zincirlemektedir.

| Katman | Tehdit aktörü tarafından örnek kullanım |
|-------|-----------------------------|
|Otomasyon| >100 k e-posta / SMS oluşturun ve gönderin, rastgele kelimeler ve izleme bağlantıları ile.|
|Üretken AI| Kamuya açık M&A, sosyal medyadan iç şakalarla referans veren *tek seferlik* e-postalar üretin; geri arama dolandırıcılığında derin sahte CEO sesi.|
|Ajans AI| Otonom olarak alan adları kaydedin, açık kaynak istihbaratını kazıyın, bir kurban tıkladığında ancak kimlik bilgilerini göndermediğinde bir sonraki aşama e-postalarını oluşturun.|

**Savunma:**
• Güvenilmeyen otomasyondan gönderilen mesajları vurgulayan **dinamik afişler** ekleyin (ARC/DKIM anormallikleri aracılığıyla).
• Yüksek riskli telefon talepleri için **ses biyometrik zorlama ifadeleri** uygulayın.
• Farkındalık programlarında AI tarafından üretilen tuzakları sürekli simüle edin – statik şablonlar geçersizdir.

---

## MFA Yorgunluğu / Push Bombing Varyantı – Zorla Sıfırlama
Klasik push-bombing'in yanı sıra, operatörler yardım masası çağrısı sırasında **yeni bir MFA kaydı zorlayarak**, kullanıcının mevcut jetonunu geçersiz kılmaktadır. Herhangi bir sonraki giriş istemi kurban için meşru görünmektedir.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta olaylarını izleyin, **`deleteMFA` + `addMFA`** aynı IP'den **dakikalar içinde** gerçekleştiğinde.

## Clipboard Hijacking / Pastejacking

Saldırganlar, bir hedefin panosuna kötü niyetli komutları sessizce kopyalayabilirler; bu, bir tehlikeli veya yanlış yazılmış web sayfasından yapılır ve ardından kullanıcıyı **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak, herhangi bir indirme veya ek olmadan rastgele kod çalıştırabilirler.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobil Phishing & Kötü Amaçlı Uygulama Dağıtımı (Android & iOS)

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Referanslar

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
