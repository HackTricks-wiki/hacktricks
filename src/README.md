# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve motion tasarımı_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks'i Yerel Olarak Çalıştır
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
Yerel HackTricks kopyanız **[http://localhost:3337](http://localhost:3337)** adresinde 5 dakikadan kısa bir sürede kullanılabilir olacaktır (kitabı derlemesi gerekiyor, sabırlı olun).

## Kurumsal Sponsorlar

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) araştırma yapan ve kendi saldırı araçlarını geliştiren harika bir siber güvenlik şirketidir; sloganları **HACK THE UNHACKABLE**. Pentesting, Red teams ve eğitim gibi **birçok değerli siber güvenlik hizmeti sunarlar**.

Bloglarını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden inceleyebilirsiniz.

**STM Cyber** ayrıca HackTricks gibi açık kaynaklı siber güvenlik projelerini destekliyor :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilginin yayılmasını teşvik etme misyonu** ile bu kongre her disiplinden teknoloji ve siber güvenlik uzmanları için kaynayan bir buluşma noktasıdır.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, Avrupa'nın #1 ethical hacking ve bug bounty platformudur.

**Bug bounty ipucu**: Hackers tarafından, hackerlar için oluşturulmuş premium bir bug bounty platformu olan **Intigriti**'ye **kaydolun**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresine katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca kurmak ve otomatikleştirmek için [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanın.

Bugün Erişim Alın:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcılarıyla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking Insights:** Hacklemenin heyecanı ve zorluklarına dair içeriğe katılın
- **Real-Time Hack News:** Hızla değişen hacking dünyasını gerçek zamanlı haberler ve içgörülerle takip edin
- **Latest Announcements:** Yeni açılan bug bounty'ler ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Bize [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden katılın** ve bugün en iyi hackerlarla işbirliğine başlayın!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Web uygulamalarınız, ağınız ve cloud** hakkında bir hacker bakış açısı edinin

**Gerçek iş etkisi olan kritik, sömürülebilir zafiyetleri bulun ve raporlayın.** Saldırı yüzeyini haritalamak, ayrıcalık yükseltmeye izin veren güvenlik sorunlarını bulmak ve otomatik exploitlerle gerekli delilleri toplamak için 20+ özel aracımızı kullanın; bu sayede sıkı çalışmanız ikna edici raporlara dönüşür.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, arama motoru sonuçlarına gerçek zamanlı erişim için hızlı ve kolay API'ler sunar. Search engine sonuçlarını kazır, proxy'leri yönetir, captchaları çözer ve sizin için tüm zengin yapılandırılmış verileri ayrıştırır.

SerpApi aboneliği, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını kazımak için 50'den fazla API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi sadece organik sonuçları kazımıyor**. SerpApi cevapları tutarlı şekilde tüm reklamları, gömülü görselleri ve videoları, knowledge graph'ları ve arama sonuçlarında bulunan diğer öğe ve özellikleri içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunuyor.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larını** inceleyin veya örnek için [**playground**](https://serpapi.com/playground)'u deneyin.\
**Ücretsiz bir hesap oluşturabilirsiniz** [**buradan**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil uygulamaları ve cihazları korumak için zafiyet araştırması, penetration testing ve reverse engineering yapmak için gereken teknolojileri ve becerileri öğrenin. On-demand kurslarımızla **iOS ve Android güvenliğini uzmanlaşın** ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** merkezli profesyonel bir siber güvenlik şirketidir ve **dünyanın dört bir yanında** işletmeleri en son siber güvenlik tehditlerine karşı korumaya yardımcı olur; **offensive-security hizmetleri** sunarak modern bir yaklaşım benimser.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir güvenlik şirketidir. Hepsi bir arada güvenlik hizmetleri sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Denetimleri, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında başka güzel bir şey ise sektör ortalamasının aksine WebSec'in **yeteneklerine çok güvenmesi**, öyle ki **en kaliteli sonuçları garanti ediyorlar**, web sitelerinde şu ifade yer alıyor: "**If we can't hack it, You don't pay it!**". Daha fazla bilgi için [**web sitesi**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/)'larına göz atın!

Ayrıca WebSec, HackTricks'in de **adana destekçilerinden** biridir.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) bir data breach (leak) arama motorudur. \
Büyük ve küçük her türlü veri sızıntısı üzerinde rasgele string araması (google gibi) sağlıyoruz --sadece büyük sızıntılar değil-- birden fazla kaynaktan gelen veriler üzerinde. \
Kişi aramaları, AI aramaları, organizasyon aramaları, API (OpenAPI) erişimi, theHarvester entegrasyonu; bir pentester'ın ihtiyaç duyduğu tüm özellikler.\
**HackTricks bizim için harika bir öğrenme platformu olmaya devam ediyor ve onu desteklemekten gurur duyuyoruz!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için tasarlandı. Sizin etrafınızda şekillendi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili siber güvenlik eğitimleri geliştirir ve sunar. Programları teorinin ötesine geçer ve ekipleri gerçek dünya tehditlerini yansıtan özel ortamlar kullanarak derin anlayış ve uygulanabilir becerilerle donatır. Özel eğitim talepleri için bize [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) ulaşın.

**Eğitimlerini farklı kılanlar:**
* Özel hazırlanmış içerik ve laboratuvarlar
* Üst düzey araç ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve verilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** kurumları için uzmanlaşmış siber güvenlik hizmetleri sunar; odak alanları arasında **penetration testing, cloud security assessments** ve **compliance readiness** (SOC 2, PCI-DSS, NIST) bulunur. Ekibimizde **OSCP ve CISSP sertifikalı profesyoneller** yer almakta olup, her görevde derin teknik uzmanlık ve endüstri standardı içgörüsü sağlar.

Otomatik taramaların ötesine geçip yüksek riskli ortamlara özel **manuel, istihbarat odaklı testler** yapıyoruz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, kuruluşların en çok önem verdikleri varlıkları savunmalarına yardımcı oluyoruz.

_“Kaliteli bir savunma için saldırıyı bilmek gerekir, biz anlayışla güvenlik sağlıyoruz.”_

Siber güvenlikteki en son gelişmeleri takip etmek için [**blog**](https://www.lasttowersolutions.com/blog)'larını ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve geliştiricilerin Kubernetes cluster'larını verimli bir şekilde yönetmelerini, izlemelerini ve güvenliklerini sağlamalarını güçlendirir. AI destekli içgörülerimizden, gelişmiş güvenlik çerçevemizden ve CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle hareket edin.

Ayrıca K8Studio, tüm büyük kubernetes dağıtımlarıyla **uyumludur** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Lisans & Feragatname

Bunları inceleyin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
