# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve motion design_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Yerel HackTricks kopyanız <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde **kullanılabilir olacak** (kitabın derlenmesi gerekiyor, sabırlı olun).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) **HACK THE UNHACKABLE** sloganına sahip harika bir cybersecurity şirketidir. Kendi araştırmalarını yaparlar ve **pentesting**, Red teams ve training gibi **birkaç değerli cybersecurity hizmeti sunmak** için kendi hacking araçlarını geliştirirler.

Kendi **blog** sayfalarına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) üzerinden bakabilirsiniz

**STM Cyber**, HackTricks gibi cybersecurity açık kaynak projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Avrupa'nın #1** ethical hacking ve **bug bounty platformudur.**

**Bug bounty ipucu**: **hackerlar tarafından, hackerlar için oluşturulmuş premium bir bug bounty platformu** olan **Intigriti**'ye **kayıt olun**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden bize katılın ve **$100,000**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcılarıyla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking Insights:** hacking'in heyecanını ve zorluklarını ele alan içeriklerle etkileşime geçin
- **Real-Time Hack News:** gerçek zamanlı haberler ve içgörülerle hızlı tempolu hacking dünyasını takip edin
- **Latest Announcements:** yeni başlayan bug bounty'lerden ve kritik platform güncellemelerinden haberdar olun

Bugün en iyi hackerlarla iş birliğine başlamak için [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **engineering-first, hands-on lab approach** ile **pratik AI Security training** sunar. Kurslarımız; security engineer'lar, AppSec profesyonelleri ve **gerçek AI/LLM destekli uygulamaları build, break ve secure etmek** isteyen developer'lar için tasarlanmıştır.

**AI Security Certification**, şu alanlar dahil olmak üzere gerçek dünya becerilerine odaklanır:
- LLM ve AI destekli uygulamaları secure etme
- AI sistemleri için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse senaryoları ve pratik savunmalar
- Secure design patterns ve deployment değerlendirmeleri

Tüm kurslar **on-demand**, **lab-driven** ve sadece teoriye değil **gerçek dünya security tradeoff'larına** göre tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla bilgi:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **search engine results**'a erişmek için hızlı ve kolay gerçek zamanlı API'ler sunar. Search engine'leri scrape eder, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine yapılan abonelik, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı search engine'leri scrape etmek için 50'den fazla farklı API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi yalnızca organik sonuçları scrape etmez**. SerpApi yanıtları; reklamları, satır içi görselleri ve videoları, knowledge graph'ları ve search results içinde bulunan diğer öğe ve özellikleri tutarlı şekilde içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larına** bakın veya [**playground**](https://serpapi.com/playground)**'larında** bir örnek deneyin.\
[**buradan**](https://serpapi.com/users/sign_up) **ücretsiz hesap** oluşturabilirsiniz.

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobile uygulamaları ve cihazları korumak için vulnerability research, penetration testing ve reverse engineering yapmak için gereken teknolojileri ve becerileri öğrenin. On-demand kurslarımızla **iOS ve Android security** konusunda ustalaşın ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, saldırganlar yapmadan önce istismar edilebilir vulnerability'leri bulmak için AI destekli bir security platformudur.

**Code security ipucu**: Geliştiriciler ve security team'ler için oluşturulmuş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye kayıt olun! Bugün bize katılın ve gerçek security risklerini production'a ulaşmadan önce **tespit etmek, doğrulamak ve düzeltmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** merkezli profesyonel bir cybersecurity şirketidir ve **modern** bir yaklaşımla **offensive-security services** sunarak işletmeleri **tüm dünyada** en yeni cybersecurity tehditlerine karşı **korumaya** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir security şirketidir. **Hepsi bir arada security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir diğer güzel şey de sektör ortalamasının aksine **becerilerine çok güvenmeleri**, o kadar ki **en iyi kalite sonuçları garanti etmeleridir**; web sitelerinde "**If we can't hack it, You don't pay it!**" yazıyor. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/) sayfalarına bakın!

Yukarıdakilere ek olarak WebSec, HackTricks'in de **kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Sahaya göre tasarlandı. Sizin etrafınızda şekillendirildi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili cybersecurity training geliştirir ve sunar. Programları teorinin ötesine geçerek ekipleri derin anlayış ve uygulanabilir becerilerle donatır; gerçek dünya tehditlerini yansıtan özel ortamlar kullanır. Özel training talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Training'lerini farklı kılan şeyler:**
* Özel olarak oluşturulmuş içerik ve lab'lar
* En üst düzey araçlar ve platformlar tarafından desteklenir
* Uygulayıcılar tarafından tasarlanır ve öğretilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech**
kurumları için **penetration testing, cloud security assessments** ve
**compliance readiness** (SOC 2, PCI-DSS, NIST) odaklı özel cybersecurity hizmetleri sunar. Ekibimizde **OSCP ve CISSP
sertifikalı profesyoneller** bulunur; bu da her çalışmaya derin teknik uzmanlık ve endüstri standardı içgörü getirir.

Yüksek riskli ortamlar için uyarlanmış **manuel, intelligence-driven testing** ile otomatik taramaların ötesine geçiyoruz. Öğrenci kayıtlarını korumaktan finansal işlemleri güvence altına almaya kadar,
kuruluşların en önemli olanı savunmasına yardımcı oluyoruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; güvenliği anlayış yoluyla sağlarız.”_

En son cybersecurity gelişmelerinden haberdar olmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve developer'ların Kubernetes cluster'larını verimli şekilde yönetmesini, izlemesini ve secure etmesini sağlar. AI güdümlü içgörülerimizi, gelişmiş security framework'ümüzü ve sezgisel CloudMaps GUI'mizi kullanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle aksiyon alın.

Ayrıca K8Studio, **tüm büyük kubernetes distribution'larıyla uyumludur** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Şunlara bakın:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
