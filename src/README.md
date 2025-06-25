# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareket tasarımı_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ tarafından._ 

### HackTricks'i Yerel Olarak Çalıştırın
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Yerel kopyanız **[http://localhost:3337](http://localhost:3337)** adresinde **5 dakika içinde** (kitabı oluşturması gerekiyor, sabırlı olun) **mevcut olacaktır**.

## Kurumsal Sponsorlar

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com), sloganı **HACK THE UNHACKABLE** olan harika bir siber güvenlik şirketidir. Kendi araştırmalarını yapar ve **pentesting, Kırmızı takımlar ve eğitim** gibi birkaç değerli siber güvenlik hizmeti sunmak için kendi hacking araçlarını geliştirir.

**Bloglarını** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinde kontrol edebilirsiniz.

**STM Cyber** ayrıca HackTricks gibi siber güvenlik açık kaynak projelerini desteklemektedir :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Avrupa'nın #1** etik hacking ve **bug bounty platformudur.**

**Bug bounty ipucu**: **Intigriti**'ye **kaydolun**, hackerlar tarafından, hackerlar için oluşturulmuş bir premium **bug bounty platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla **iş akışlarını** kolayca oluşturun ve otomatikleştirin.

Bugün Erişim Alın:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking İçgörüleri:** Hacking'in heyecanı ve zorluklarına dair içeriklerle etkileşimde bulunun
- **Gerçek Zamanlı Hack Haberleri:** Hızla değişen hacking dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın
- **Son Duyurular:** Yeni başlayan bug bounty'ler ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Bugün** [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın ve en iyi hackerlarla iş birliği yapmaya başlayın!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Temel penetrasyon testi araç seti

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Web uygulamalarınız, ağınız ve bulutunuz hakkında bir hacker perspektifi edinin**

**Gerçek iş etkisi olan kritik, istismar edilebilir güvenlik açıklarını bulun ve raporlayın.** Saldırı yüzeyini haritalamak, yetki yükseltmenize izin veren güvenlik sorunlarını bulmak ve temel kanıtları toplamak için 20'den fazla özel aracımızı kullanarak, sıkı çalışmanızı ikna edici raporlara dönüştürün.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **arama motoru sonuçlarına** erişim sağlamak için hızlı ve kolay gerçek zamanlı API'ler sunar. Arama motorlarını tarar, proxy'leri yönetir, captcha'ları çözer ve sizin için tüm zengin yapılandırılmış verileri ayrıştırır.

SerpApi'nın planlarından birine abone olmak, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını taramak için 50'den fazla API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi sadece organik sonuçları taramaz**. SerpApi yanıtları sürekli olarak tüm reklamları, satır içi resimleri ve videoları, bilgi grafiklerini ve arama sonuçlarında bulunan diğer öğeleri ve özellikleri içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunmaktadır.\
Daha fazla bilgi için [**bloglarına**](https://serpapi.com/blog/) göz atın veya [**oyun alanlarında**](https://serpapi.com/playground) bir örnek deneyin.\
**Buradan** [**ücretsiz bir hesap oluşturabilirsiniz**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Derinlemesine Mobil Güvenlik Kursları](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil uygulamaları ve cihazları korumak için güvenlik açığı araştırması, penetrasyon testi ve ters mühendislik yapma yeteneklerini öğrenin. **iOS ve Android güvenliğinde ustalaşın** ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** merkezli profesyonel bir siber güvenlik şirketidir ve **dünyanın dört bir yanındaki** işletmeleri en son siber güvenlik tehditlerine karşı korumak için **ofansif güvenlik hizmetleri** sunmaktadır.

WebSec, Amsterdam ve Wyoming'de ofisleri olan uluslararası bir güvenlik şirketidir. **Pentesting, Güvenlik Denetimleri, Farkındalık Eğitimleri, Phishing Kampanyaları, Kod İncelemesi, İstismar Geliştirme, Güvenlik Uzmanları Dış Kaynak Kullanımı** ve daha fazlasını içeren **hepsi bir arada güvenlik hizmetleri** sunmaktadır.

WebSec'in diğer bir ilginç yanı, sektördeki ortalamadan farklı olarak WebSec'in **yeteneklerine çok güvenmesidir**, o kadar ki **en iyi kalite sonuçları garanti eder**, web sitelerinde "**Eğer hackleyemiyorsak, ödeme yapmazsınız!**" ifadesi yer almaktadır. Daha fazla bilgi için [**web sitelerine**](https://websec.net/en/) ve [**bloglarına**](https://websec.net/blog/) göz atın!

Yukarıdakilere ek olarak WebSec, **HackTricks'in kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons), bir veri ihlali (leak) arama motorudur. \
Küçük ve büyük tüm veri ihlalleri üzerinde (sadece büyük olanlar değil) rastgele dize araması (google gibi) sağlıyoruz. \
İnsan araması, AI araması, organizasyon araması, API (OpenAPI) erişimi, theHarvester entegrasyonu, bir pentesterin ihtiyaç duyduğu tüm özellikler.\
**HackTricks, hepimiz için harika bir öğrenme platformu olmaya devam ediyor ve onu desteklemekten gurur duyuyoruz!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>

**Saha için inşa edildi. Sizin etrafınızda inşa edildi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili siber güvenlik eğitimleri geliştirir ve sunar. Programları, ekipleri derin bir anlayış ve uygulanabilir becerilerle donatmak için teorinin ötesine geçer ve gerçek dünya tehditlerini yansıtan özel ortamlar kullanır. Özel eğitim talepleri için, [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bizimle iletişime geçin.

**Eğitimlerini farklı kılan şey:**
* Özel olarak hazırlanmış içerik ve laboratuvarlar
* Üst düzey araçlar ve platformlarla desteklenmektedir
* Uygulayıcılar tarafından tasarlanmış ve öğretilmiştir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** kurumları için özel siber güvenlik hizmetleri sunmaktadır ve **penetrasyon testi, bulut güvenliği değerlendirmeleri** ve **uyum hazırlığı** (SOC 2, PCI-DSS, NIST) üzerine odaklanmaktadır. Ekibimiz, her angajmana derin teknik uzmanlık ve endüstri standartlarında içgörü getiren **OSCP ve CISSP sertifikalı profesyonellerden** oluşmaktadır.

Otomatik taramaların ötesine geçerek, yüksek riskli ortamlara özel **manuel, istihbarat odaklı testler** gerçekleştiriyoruz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, organizasyonların en önemli olanı savunmalarına yardımcı oluyoruz.

_“Kaliteli bir savunma, saldırıyı bilmekle başlar, biz anlayış yoluyla güvenlik sağlıyoruz.”_

En son siber güvenlik gelişmeleri hakkında bilgi sahibi olmak için [**blogumuzu**](https://www.lasttowersolutions.com/blog) ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

## Lisans & Feragatname

Onları kontrol edin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github İstatistikleri

![HackTricks Github İstatistikleri](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
