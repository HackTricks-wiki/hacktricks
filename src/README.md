# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareketli tasarım tarafından_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
HackTricks'in yerel kopyanız <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde kullanılabilir olacak (kitabı oluşturması gerekiyor, sabırlı olun).

## Kurumsal Sponsorlar

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) mükemmel bir siber güvenlik şirketidir; sloganı **HACK THE UNHACKABLE**. Kendi araştırmalarını yapar ve kendi hacking araçlarını geliştirir; pentesting, Red teams ve eğitim gibi çeşitli değerli siber güvenlik hizmetleri sunarlar.

Bloglarını şu adreste inceleyebilirsiniz: [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** ayrıca HackTricks gibi siber güvenlik açık kaynak projelerini destekliyor :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. Teknik bilginin yayılmasını teşvik etme misyonuyla, bu kongre teknoloji ve siber güvenlik profesyonelleri için her disiplinden yoğun bir buluşma noktasıdır.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** Avrupa'nın #1 etik hacking ve **bug bounty platformu.**

**Bug bounty tavsiyesi**: **Intigriti'ye kaydolun**, hackerlar tarafından hackerlar için oluşturulmuş premium bir **bug bounty platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden bize katılın ve **100.000$**'a kadar ödüller kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları ile güçlendirilmiş iş akışlarını kolayca oluşturmak ve otomatikleştirmek için [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanın.

Bugün erişim alın:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılarak deneyimli hackerlar ve bug bounty avcılarıyla iletişim kurun!

- **Hacking İçgörüleri:** Hacking’in heyecanı ve zorluklarıyla ilgili içeriklerle etkileşime geçin
- **Gerçek Zamanlı Hack Haberleri:** Hızlı gelişen hacking dünyasından gerçek zamanlı haberler ve içgörülerle güncel kalın
- **Son Duyurular:** Yeni açılan bug bounty programları ve kritik platform güncellemeleri hakkında bilgi sahibi olun

**Bize [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden katılın** ve bugün en iyi hackerlarla işbirliğine başlayın!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **mühendislik öncelikli, uygulamalı laboratuvar yaklaşımı** ile **pratik AI Security eğitimi** sunar. Kurslarımız, gerçek AI/LLM destekli uygulamaları **inşa etmek, kırmak ve güvenli hale getirmek** isteyen güvenlik mühendisleri, AppSec profesyonelleri ve geliştiriciler için hazırlanmıştır.

**AI Security Certification** gerçek dünya becerilerine odaklanır; içeriğinde:
- LLM ve AI destekli uygulamaların güvenliği
- AI sistemleri için tehdit modelleme
- Embeddings, vektör veri tabanları ve RAG güvenliği
- LLM saldırıları, kötüye kullanım senaryoları ve pratik savunmalar
- Güvenli tasarım kalıpları ve dağıtım hususları

Tüm kurslar **talep üzerine**, **lab odaklı** ve sadece teori değil **gerçek dünya güvenlik ödünleşmeleri** etrafında tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla detay:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **arama motoru sonuçlarına erişim** sağlayan hızlı ve kolay gerçek zamanlı API'ler sunar. Arama motorlarını tarar, proxy'leri yönetir, captchaları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine abone olmak, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını kazımak için 50'den fazla API'ye erişim sağlar.\
Diğer sağlayıcılardan farklı olarak, **SerpApi sadece organik sonuçları kazımaz**. SerpApi yanıtları tutarlı olarak tüm reklamları, gömülü resimleri ve videoları, bilgi grafikleri ve arama sonuçlarında bulunan diğer öğe ve özellikleri içerir.

SerpApi’nin mevcut müşterileri arasında **Apple, Shopify ve GrubHub** bulunuyor.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larını** inceleyin veya [**playground**](https://serpapi.com/playground)**'da** bir örnek deneyin.\
**Ücretsiz bir hesap** oluşturabilirsiniz [**buradan**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil uygulamaları ve cihazları korumak için zafiyet araştırması, penetration testing ve reverse engineering yapmak için gerekli teknolojileri ve becerileri öğrenin. **iOS ve Android güvenliğini** talep üzerine kurslarımızla ustalaşın ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** merkezli profesyonel bir siber güvenlik şirketidir ve **dünyanın dört bir yanındaki** işletmeleri en son siber güvenlik tehditlerine karşı korumaya yardımcı olur; **offensive-security hizmetleri** ile modern bir yaklaşım sunar.

WebSec, Amsterdam ve Wyoming'de ofisleri olan uluslararası bir güvenlik şirketidir. Hepsi bir arada güvenlik hizmetleri sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Denetimleri, Farkındalık Eğitimleri, Phishing Kampanyaları, Kod İncelemesi, Exploit Geliştirme, Güvenlik Uzmanı Dış Kaynak Kullanımı ve daha fazlası.

WebSec hakkında havalı bir diğer nokta ise, sektördeki ortalamaya kıyasla **kendi yeteneklerine çok güvenmeleri**; web sitelerinde şu garanti yer alır: "**If we can't hack it, You don't pay it!**". Daha fazla bilgi için [**web sitelerine**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/)**'larına** göz atın!

Ayrıca WebSec, HackTricks'in de **kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için tasarlandı. Sizin etrafınızda kuruldu.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili siber güvenlik eğitimleri geliştirir ve sunar. Programları teorinin ötesine geçer; ekipleri gerçek dünya tehditlerini yansıtan özel ortamlar kullanarak derin anlayış ve uygulanabilir becerilerle donatır. Özel eğitim talepleri için bize [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) ulaşın.

**Eğitimlerini farklı kılanlar:**
* Özel hazırlanmış içerik ve laboratuvarlar
* Üst düzey araçlar ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve verilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** kurumları için özel siber güvenlik hizmetleri sunar; odak noktası **penetration testing, cloud security assessments** ve **uyumluluk hazırlığı** (SOC 2, PCI-DSS, NIST) üzerinedir. Ekibimizde **OSCP ve CISSP sertifikalı profesyoneller** bulunur ve her görevde derin teknik uzmanlık ile sektör standardı içgörü sağlar.

Otomatik taramaların ötesine geçerek, yüksek riskli ortamlar için **manuel, istihbarat odaklı testler** gerçekleştiriyoruz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, kuruluşların en önemli varlıklarını savunmalarına yardımcı oluyoruz.

_“İyi bir savunma, saldırıyı bilmeyi gerektirir; biz anlayışla güvenlik sağlıyoruz.”_

Siber güvenlikteki en son gelişmelerden haberdar olmak için [**blog**](https://www.lasttowersolutions.com/blog)**'larını** ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve geliştiricilerin Kubernetes kümelerini verimli bir şekilde yönetmelerini, izlemelerini ve güvenceye almalarını sağlar. AI destekli içgörüleri, gelişmiş güvenlik çerçevesi ve sezgisel CloudMaps GUI ile kümelerinizi görselleştirin, durumlarını anlayın ve güvenle harekete geçin.

Ayrıca, K8Studio **tüm büyük kubernetes dağıtımlarıyla uyumludur** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Lisans & Feragatname

Bunlara bakın:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
