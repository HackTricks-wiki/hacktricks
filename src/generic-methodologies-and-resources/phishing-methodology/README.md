# Phishing Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Metodoloji

1. Recon the victim
1. **victim domain**'i seçin.
2. Hedefin kullandığı portalları bulmak için temel web keşfi yapın, **oturum açma portallarını arayın** ve hangi portalı **taklit edeceğinize karar verin**.
3. Biraz **OSINT** kullanarak **e-posta adresleri bulun**.
2. Ortamı hazırlayın
1. Phishing değerlendirmesinde kullanacağınız **domain**'i satın alın
2. E-posta servisi ile ilgili kayıtları (SPF, DMARC, DKIM, rDNS) yapılandırın
3. VPS'i **gophish** ile yapılandırın
3. Kampanyayı hazırlayın
1. **e-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain adı orijinal domainin önemli bir **keyword**'ünü içerir (ör. zelster.com-management.com).
- **hypened subdomain**: Bir alt alan adındaki **nokta yerine tire** koyun (ör. www-zelster.com).
- **New TLD**: Aynı domainin **yeni TLD** ile kullanılması (ör. zelster.org)
- **Homoglyph**: Domain adındaki bir harfi **benzer görünen** harflerle değiştirir (ör. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain adındaki iki harfi **yer değiştirir** (ör. zelsetr.com).
- **Singularization/Pluralization**: Domain adının sonuna “s” ekler veya çıkarır (ör. zeltsers.com).
- **Omission**: Domain adından bir harfi **çıkarır** (ör. zelser.com).
- **Repetition:** Domain adındaki bir harfi **tekrarlar** (ör. zeltsser.com).
- **Replacement**: Homoglyph'e benzer ama daha az gizli. Domain adındaki bir harfi, genellikle klavyede orijinal harfe yakın bir harfle **değiştirir** (ör. zektser.com).
- **Subdomained**: Domain adının içine bir **nokta** ekler (ör. ze.lster.com).
- **Insertion**: Domain adına bir **harf ekler** (ör. zerltser.com).
- **Missing dot**: TLD'yi domain adına ekler. (ör. zelstercom.com)

**Otomatik Araçlar**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websiteler**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Depolanan veya iletim halindeki bazı bitlerin, güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörler nedeniyle otomatik olarak **fliplenme** ihtimali vardır.

Bu kavram DNS isteklerine **uygulandığında**, DNS sunucusu tarafından **alınan domainin**, başlangıçta istenen domainle aynı olmama ihtimali vardır.

Örneğin, "windows.com" domainindeki tek bir bit değişikliği onu "windnws.com" yapabilir.

Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek amacıyla hedef domainin benzerleri olan birden fazla bit-flipping domaini **kaydettirebilirler**.

Daha fazla bilgi için bakınız: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Kullanabileceğiniz süresi dolmuş bir domaini bulmak için [https://www.expireddomains.net/](https://www.expireddomains.net) üzerinde arama yapabilirsiniz.  
Satın almayı düşündüğünüz süresi dolmuş domainin **zaten iyi bir SEO'ya sahip** olduğunu doğrulamak için nasıl kategorize edildiğini şu servislerde kontrol edebilirsiniz:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **keşfetmek** veya zaten keşfettiğiniz adresleri **doğrulamak** için, hedefin SMTP sunucularına karşı bunları brute-force edip edemeyeceğinizi kontrol edebilirsiniz. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).  
Ayrıca, kullanıcılar maillerine erişmek için **herhangi bir web portalı** kullanıyorsa, bunun **username brute force**'a karşı zafiyeti olup olmadığını kontrol etmeyi ve mümkünse bu zafiyeti istismar etmeyi unutmayın.

## Configuring GoPhish

### Kurulum

İndirmek için: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

İndirin ve `/opt/gophish` içine açın ve `/opt/gophish/gophish` çalıştırın.  
Çıktıda admin kullanıcısı için bir parola verilecektir; admin arayüzü 3333 portunda olacaktır. Bu nedenle o porta erişin ve admin parolasını değiştirmek için verilen kimlik bilgilerini kullanın. Bu portu yerel makinenize tünellemeniz gerekebilir:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adıma geçmeden önce kullanacağınız alan adını zaten satın almış olmalısınız ve alan adının gophish'i yapılandırdığınız VPS'nin IP adresine yönlenmiş olması gerekir.
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

Sonra alan adını aşağıdaki dosyalara ekleyin:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Ayrıca /etc/postfix/main.cf içinde aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınıza göre düzenleyin ve **VPS'inizi yeniden başlatın.**

Şimdi, VPS'in **IP adresine** işaret eden `mail.<domain>` için bir **DNS A record** oluşturun ve `mail.<domain>`'e işaret eden bir **DNS MX** kaydı ekleyin

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

gophish'in çalışmasını durdurun ve yapılandıralım.\
`/opt/gophish/config.json` dosyasını aşağıdaki şekilde düzenleyin (https kullanımına dikkat):
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
Servisin yapılandırmasını tamamlayın ve çalıştığını kontrol edin:
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

Bir alan adının yaşı ne kadar büyükse spam olarak işaretlenme olasılığı o kadar düşüktür. Bu nedenle phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektör hakkında bir sayfa eklerseniz elde edilen itibar daha iyi olacaktır.

Unutmayın, bir hafta beklemeniz gerekse bile şimdi her şeyi yapılandırmayı bitirebilirsiniz.

### Reverse DNS (rDNS) kaydını yapılandırın

VPS'nin IP adresini alan adına çözecek bir rDNS (PTR) kaydı ayarlayın.

### Sender Policy Framework (SPF) Kaydı

**Yeni alan adı için bir SPF kaydı yapılandırmalısınız**. Eğer SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) sitesini kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![](<../../images/image (1037).png>)

Bu, alan adı içinde bir TXT record olarak ayarlanması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Alan Tabanlı Mesaj Doğrulama, Raporlama ve Uyum (DMARC) Kaydı

Yeni etki alanı için **bir DMARC kaydı yapılandırmalısınız**. Eğer DMARC kaydının ne olduğunu bilmiyorsanız [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Aşağıdaki içeriğe sahip olacak şekilde host adı `_dmarc.<domain>` için yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan adı için **DKIM yapılandırması yapmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekir:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com/) kullanarak yapabilirsiniz\
Sadece sayfaya erişin ve size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca `check-auth@verifier.port25.com` adresine bir e-posta göndererek e-posta yapılandırmanızı **kontrol edebilirsiniz** ve **yanıtı okuyabilirsiniz** (bunun için **25** portunu **açmanız** gerekecek ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görürsünüz).\
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
Ayrıca kontrolünüz altındaki bir Gmail'e **mesaj gönderebilir** ve Gmail gelen kutunuzda **e-postanın başlıklarını** kontrol edebilirsiniz; `dkim=pass` ifadesi `Authentication-Results` başlık alanında bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Set some **name to identify** the sender profile  
  Gönderici profilini tanımlamak için bir **isim belirleyin**
- Decide from which account are you going to send the phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._  
  Hangi hesaptan phishing e-postalarını göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
- You can leave blank the username and password, but make sure to check the Ignore Certificate Errors  
  Kullanıcı adı ve parolayı boş bırakabilirsiniz, ancak "**Ignore Certificate Errors**" seçeneğini işaretlediğinizden emin olun.

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.  
> Her şeyin çalıştığını test etmek için "**Send Test Email**" işlevini kullanmanız önerilir.  
> Testler sırasında kara listeye düşmemek için test e-postalarını **10min mails** adreslerine göndermenizi tavsiye ederim.

### Email Template

- Set some **name to identify** the template  
  Şablonu tanımlamak için bir **isim belirleyin**
- Then write a **subject** (nothing estrange, just something you could expect to read in a regular email)  
  Ardından bir **subject** yazın (garip/süpheli olmayan, normal bir e-postada görebileceğiniz bir konu)
- Make sure you have checked "**Add Tracking Image**"  
  "**Add Tracking Image**" seçeneğini işaretlediğinizden emin olun
- Write the **email template** (you can use variables like in the following example):  
  **email template**'i yazın (aşağıdaki örnekteki gibi değişkenler kullanabilirsiniz):
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
Not: **e-postanın güvenilirliğini artırmak için**, müşteriye ait bir e-postadaki bir imzayı kullanmanız önerilir. Öneriler:

- **var olmayan bir adrese** e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
- info@ex.com, press@ex.com veya public@ex.com gibi **herkese açık e-posta adresleri** arayın, onlara e-posta gönderin ve yanıtı bekleyin.
- Keşfedilmiş **geçerli bir e-posta adresiyle** iletişime geçmeyi deneyin ve yanıtı bekleyin.

![](<../../images/image (80).png>)

> [!TIP]
> E-posta Şablonu ayrıca **göndermek için dosya eklemeye** izin verir. Eğer özel hazırlanmış bazı dosyalar/belgeler kullanarak NTLM challenge'larını da çalmak isterseniz [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Açılış Sayfası

- Bir **isim** yazın
- Web sayfasının **HTML kodunu yazın**. Web sayfalarını **import** edebileceğinizi unutmayın.
- **Capture Submitted Data** ve **Capture Passwords** seçeneklerini işaretleyin
- Bir **yönlendirme** ayarlayın

![](<../../images/image (826).png>)

> [!TIP]
> Genellikle HTML kodunu değiştirmeniz ve yerelde (muhtemelen bir Apache sunucu kullanarak) bazı testler yapmanız gerekecektir **ta ki sonuçlardan memnun kalana kadar.** Ardından o HTML kodunu kutuya yapıştırın.\
> HTML için bazı statik kaynaklara (örneğin CSS ve JS sayfaları) ihtiyaç duyarsanız bunları _**/opt/gophish/static/endpoint**_ içine kaydedebilir ve sonra _**/static/\<filename>**_ üzerinden erişebilirsiniz.

> [!TIP]
> Yönlendirme için **kullanıcıları hedefin gerçek ana web sayfasına yönlendirebilir** veya örneğin _/static/migration.html_ sayfasına yönlendirip, 5 saniye boyunca bir **dönen yükleme göstergesi** ([https://loading.io/](https://loading.io)) koyup sonra işlemin başarılı olduğunu belirtebilirsiniz.

### Kullanıcılar & Gruplar

- Bir isim belirleyin
- Verileri **import** edin (şablonu örnek için kullanabilmek adına her kullanıcı için firstname, last name ve email address gereklidir)

![](<../../images/image (163).png>)

### Kampanya

Son olarak, bir isim, e-posta şablonu, açılış sayfası, URL, sending profile ve grup seçerek bir kampanya oluşturun. URL, kurbana gönderilecek bağlantı olacaktır.

Not: **Sending Profile** test e-postası göndermenize izin verir, böylece son phishing e-postasının nasıl görüneceğini görebilirsiniz:

![](<../../images/image (192).png>)

> [!TIP]
> Testleri yaparken kara listeye düşmemek için **test e-postalarını 10min mail adreslerine göndermenizi** öneririm.

Her şey hazır olduğunda, kampanyayı başlatın!

## Web Sitesi Klonlama

Herhangi bir nedenle web sitesini klonlamak isterseniz aşağıdaki sayfayı inceleyin:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoor'lu Belgeler & Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Red Team'ler için) ayrıca **herhangi bir tür backdoor içeren dosyalar göndermek** isteyebilirsiniz (örneğin bir C2 veya sadece bir kimlik doğrulama tetiklemesi). Örnekler için aşağıdaki sayfaya bakın:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Proxy MitM Yoluyla

Önceki saldırı, gerçek bir web sitesini taklit edip kullanıcının girdiği bilgileri toplamaya yönelik oldukça zekicedir. Ne var ki, kullanıcı doğru parolayı girmezse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgiler kandırılan kullanıcı adına taklit yapmanıza izin vermez**.

İşte bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar işe yarar. Bu araçlar size bir MitM benzeri saldırı oluşturma imkanı verir. Temelde saldırı şu şekilde işler:

1. Gerçek web sayfasının giriş formunu taklit edersiniz.
2. Kullanıcı kimlik bilgilerini sahte sayfanıza gönderir ve araç bunları gerçek web sayfasına ileterek kimlik bilgilerinin çalışıp çalışmadığını kontrol eder.
3. Hesap 2FA ile yapılandırılmışsa, MitM sayfası bunu ister ve kullanıcı 2FA'yı girdikten sonra araç onu gerçek web sayfasına iletir.
4. Kullanıcı kimlik doğrulandıktan sonra, siz (saldırgan) MitM işlemi süresince yapılan her etkileşimden kimlik bilgilerini, 2FA'yı, cookie'yi ve tüm bilgileri yakalamış olursunuz.

### VNC Yoluyla

Kurbanı, orijinal sayfayla bağlantılı bir tarayıcıya sahip bir **malicious page** yerine **tarayıcının gerçek web sayfasına bağlı olduğu bir VNC oturumuna** yönlendirirseniz ne olur? Ne yaptığını görebilir, parolayı, kullanılan MFA'yı, cookie'leri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.

## Tespit Edilmenin Algılanması

Tespit edildiğinizi anlamanın en iyi yollarından biri, alan adınızı kara listelerde aramaktır. Eğer listelenmişse, bir şekilde alan adınız şüpheli olarak tespit edilmiştir. Alan adınızın herhangi bir kara listede görünüp görünmediğini kontrol etmenin kolay yollarından biri [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Bununla birlikte, kurbanın **aktif olarak şüpheli phishing etkinliklerini** arayıp aramadığını öğrenmenin başka yolları da vardır; bunlar şu sayfada açıklanmıştır:


{{#ref}}
detecting-phising.md
{{#endref}}

Kurbanın alan adına çok benzer bir isimle bir domain satın alabilir ve/veya sizin kontrolünüzde bir domainin alt alanı için hedefin domain anahtar kelimesini içeren bir sertifika oluşturabilirsiniz. Eğer **hedef** bu domainlerle herhangi bir DNS veya HTTP etkileşimi gerçekleştirirse, aktif olarak şüpheli domainleri aradığını anlarsınız ve çok daha gizli olmanız gerekir.

### Phishing'i Değerlendirme

E-postanızın spam klasöründe mi biteceğini, engelleneceğini veya başarılı olup olmayacağını değerlendirmek için [**Phishious**](https://github.com/Rices/Phishious) kullanın.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion set'leri giderek e-posta tuzaklarını tamamen atlayıp MFA'yı aşmak için doğrudan service-desk / identity-recovery iş akışını hedefliyor. Saldırı tamamen "living-off-the-land" tarzındadır: operatör geçerli kimlik bilgilerine sahip olduğunda yerleşik admin araçlarıyla pivot yapar – herhangi bir malware gerekmez.

### Saldırı akışı
1. Hedefi keşfet
* LinkedIn, data breaches, public GitHub vb. kaynaklardan kişisel ve kurumsal bilgileri toplayın.
* Yüksek değerli kimlikleri (yöneticiler, IT, finans) belirleyin ve parola / MFA sıfırlama için **tam help-desk sürecini** ayrıntılı şekilde çıkarın.
2. Gerçek zamanlı sosyal mühendislik
* Hedefi taklit ederek help-desk ile telefon, Teams veya chat üzerinden iletişim kurun (genellikle **spoofed caller-ID** veya **cloned voice** kullanılarak).
* Önceden toplanmış PII'i vererek bilgi-temelli doğrulamayı geçin.
* Temsilciyi **MFA secret'ını sıfırlamaya** veya kayıtlı mobil numarada **SIM-swap** yapmaya ikna edin.
3. Erişim sonrası anlık işlemler (gerçek vakalarda ≤60 dk)
* Herhangi bir web SSO portalı üzerinden bir foothold sağlayın.
* AD / AzureAD'yi yerleşik araçlarla keşfedin (binary bırakılmadan):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Ortamda zaten beyaz listeye alınmış olan meşru RMM ajanları veya **WMI**, **PsExec** ile lateral hareket gerçekleştirin.

### Tespit & Hafifletme
* Help-desk identity recovery'yi **ayrıcalıklı bir işlem** olarak ele alın – step-up auth ve yönetici onayı gerektirin.
* **Identity Threat Detection & Response (ITDR)** / **UEBA** kuralları dağıtın ve şu durumlarda alarm verin:
* MFA yöntemi değişti + yeni bir cihaz/konumdan kimlik doğrulama.
* Aynı principal'in (kullanıcı→yönetici) hemen yükseltilmesi.
* Help-desk aramalarını kayıt altına alın ve sıfırlama yapmadan önce **zaten kayıtlı bir numaraya geri arama** uygulayın.
* Yeni sıfırlanan hesapların otomatik olarak yüksek ayrıcalıklı token'lar elde etmemesi için **Just-In-Time (JIT) / Privileged Access** uygulayın.

---

## Büyük Ölçekli Aldatma – SEO Poisoning & “ClickFix” Kampanyaları
Hacimli ekipler, yüksek-dokunuşlu operasyonların maliyetini, **arama motorlarını ve reklam ağlarını teslimat kanalı haline getiren** kitlesel saldırılarla dengeleyebilir.

1. **SEO poisoning / malvertising** sahte bir sonuç (ör. `chromium-update[.]site`) arama reklamlarının en üstüne itilir.
2. Kurban küçük bir **first-stage loader** indirir (genellikle JS/HTA/ISO). Unit 42 tarafından gözlemlenen örnekler:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader tarayıcı cookie'lerini + credential DB'leri dışa aktarır, ardından gerçek zamanlı olarak şu kararı veren sessiz bir loader çeker:
* RAT (ör. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence bileşeni (registry Run anahtarı + scheduled task)

### Güçlendirme ipuçları
* Yeni kayıtlı domainleri engelleyin ve **Advanced DNS / URL Filtering** uygulayın; bunu arama-reklamları için de zorunlu kılın.
* Yazılım kurulumunu imzalı MSI / Store paketleri ile sınırlandırın, `HTA`, `ISO`, `VBS` çalıştırılmasını politika ile engelleyin.
* Tarayıcıların çocuk süreçlerinin kurulum açtığını izleyin:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* İlk aşama loader'lar tarafından sıkça suistimal edilen LOLBins (ör. `regsvr32`, `curl`, `mshta`) için av yapın.

---

## AI Destekli Phishing Operasyonları
Saldırganlar artık tamamen kişiselleştirilmiş tuzaklar ve gerçek zamanlı etkileşim için **LLM & voice-clone API'lerini** zincirliyor.

| Katman | Tehdit aktörü tarafından örnek kullanım |
|-------|-----------------------------|
|Automation|Rastgele kelime seçimleri ve izleme linkleriyle >100k e-posta / SMS üretip gönderme.|
|Generative AI|Halka açık M&A, sosyal medyadaki iç şakalara referans veren tek seferlik e-postalar; callback dolandırıcılığında CEO sesinin deep-fake'i.|
|Agentic AI|Otonom olarak domain kaydetme, açık kaynak istihbaratı kazıma, bir kurban tıkladığında ancak kimlik bilgilerini göndermediğinde bir sonraki aşama e-postasını oluşturma.|

**Savunma:**
• ARC/DKIM anormallikleri üzerinden güvenilmeyen otomasyonlardan gönderilen mesajları vurgulayan **dinamik bannerlar** ekleyin.  
• Yüksek riskli telefon talepleri için **ses-biyometrik doğrulama cümleleri** kullanın.  
• Farkındalık programlarında AI ile üretilen tuzakları sürekli simüle edin – statik şablonlar artık geçerli değil.

Ayrıca bkz. – credential phishing için agentic browsing suiistimali:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Yorgunluğu / Push Bombing Varyantı – Zorunlu Sıfırlama
Klasik push-bombing'in yanı sıra operatörler basitçe help-desk görüşmesi sırasında **yeni bir MFA kaydı zorlayarak** kullanıcının mevcut token'ını geçersiz kılar. Sonraki herhangi bir oturum açma istemi kurban için meşru görünür.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Aynı IP'den birkaç dakika içinde **`deleteMFA` + `addMFA`** gerçekleşen AzureAD/AWS/Okta olaylarını izleyin.



## Clipboard Hijacking / Pastejacking

Saldırganlar, ele geçirilmiş veya typosquatted bir web sayfasından kurbanın clipboard'una kötü amaçlı komutları sessizce kopyalayabilir ve ardından kullanıcıyı bunları **Win + R**, **Win + X** veya bir terminal penceresine yapıştırmaya kandırarak herhangi bir indirme veya ek olmadan rastgele kod çalıştırabilir.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatörler phishing akışlarını basit bir cihaz kontrolünün arkasına koyarak masaüstü crawlers'ın son sayfalara ulaşmasını engelliyor. Yaygın bir örüntü, touch-capable DOM'u test eden ve sonucu bir server endpoint'e post eden küçük bir script'tir; non‑mobile clients HTTP 500 (veya boş bir sayfa) alırken, mobile users tam akışı görür.

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
Server davranışı sık gözlemlenir:
- İlk yüklemede bir session cookie ayarlar.
- Accepts `POST /detect {"is_mobile":true|false}`.
- `is_mobile=false` olduğunda sonraki GET'lere 500 (veya placeholder) döner; yalnızca `true` ise phishing sunar.

Avlama ve tespit heuristikleri:
- urlscan sorgusu: `filename:"detect_device.js" AND page.status:500`
- Web telemetri: `GET /static/detect_device.js` → `POST /detect` → mobil olmayan için HTTP 500 dizisi; meşru mobil hedef yolları 200 döner ve takip eden HTML/JS sunar.
- İçeriği yalnızca `ontouchstart` veya benzeri cihaz kontrollerine göre şartlandıran sayfaları engelleyin veya inceleyin.

Savunma ipuçları:
- Gated içeriği ortaya çıkarmak için mobil-benzeri fingerprint'lerle ve JS etkinleştirilmiş crawlers çalıştırın.
- Yeni kayıtlı domainlerde `POST /detect` sonrasında şüpheli 500 yanıtlarına alarm verin.

## Referanslar

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
