# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareket tasarımı_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Yerel HackTricks kopyanız <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde **kullanılabilir olacak** (kitabın derlenmesi gerekiyor, lütfen sabırlı olun).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) **HACK THE UNHACKABLE** sloganına sahip harika bir cybersecurity şirketidir. Kendi research çalışmalarını yaparlar ve kendi hacking tools geliştirirler; böylece **pentesting**, Red teams ve training gibi birkaç değerli cybersecurity service sunarlar.

**blog**larını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinde kontrol edebilirsiniz

**STM Cyber** ayrıca HackTricks gibi cybersecurity open source projects'i de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** **Europe's #1** ethical hacking ve **bug bounty platform.**

**Bug bounty tip**: **Intigriti** için **sign up** olun, hackerlar tarafından hackerlar için oluşturulmuş premium bir **bug bounty platform**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **$100,000**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty hunter'larla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking Insights:** hacking'in heyecanını ve zorluklarını ele alan içeriklerle etkileşime geçin
- **Real-Time Hack News:** gerçek zamanlı haberler ve içgörülerle hızlı tempolu hacking dünyasını takip edin
- **Latest Announcements:** yeni başlayan bug bounty'ler ve kritik platform güncellemeleri hakkında bilgi sahibi olun

En iyi hackerlarla bugün iş birliği yapmaya başlamak için [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **engineering-first, hands-on lab approach** ile **pratik AI Security training** sunar. Kurslarımız, security engineer'lar, AppSec profesyonelleri ve gerçek AI/LLM-powered applications'ı **build, break, and secure** etmek isteyen developer'lar için tasarlanmıştır.

**AI Security Certification** şu gerçek dünya becerilerine odaklanır:
- LLM ve AI-powered applications'ı secure etmek
- AI systems için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse scenarios ve pratik defenses
- Secure design patterns ve deployment considerations

Tüm kurslar **on-demand**, **lab-driven** ve sadece teoriye değil, **real-world security tradeoffs** üzerine tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla detay:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **search engine results**'a erişmek için hızlı ve kolay gerçek zamanlı API'ler sunar. Search engine'leri scrape eder, proxy'leri yönetir, captcha'ları çözer ve tüm zengin structured data'yı sizin için parse eder.

SerpApi planlarından birine yapılan abonelik, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı search engine'leri scrape etmek için 50'den fazla farklı API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi yalnızca organic results'ı scrape etmez**. SerpApi responses, search results içinde bulunan tüm ads, inline images ve videos, knowledge graphs ve diğer öğe ve özellikleri tutarlı şekilde içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/) adresine göz atın, ya da [**playground**](https://serpapi.com/playground) içinde bir örnek deneyin.\
[**Buradan**](https://serpapi.com/users/sign_up) **ücretsiz bir hesap** oluşturabilirsiniz.

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil uygulamaları ve cihazları korumak için vulnerability research, penetration testing ve reverse engineering yapmak için gereken technologies ve skills'leri öğrenin. On-demand kurslarımızla **iOS ve Android security** alanında **ustalaşın** ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** merkezli profesyonel bir cybersecurity şirketidir ve **modern** bir yaklaşımla **offensive-security services** sağlayarak işletmelerin dünya çapında en yeni cybersecurity threats'e karşı **korunmasına** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri olan uluslararası bir security şirketidir. **all-in-one security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir diğer harika şey de sektör ortalamasının aksine becerilerine **çok güvenmeleri**, öyle ki **en iyi kalite sonuçları garanti etmeleri**dir; web sitelerinde "**If we can't hack it, You don't pay it!**" yazar. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/) adreslerine bakın!

Yukarıdakilere ek olarak WebSec, HackTricks'in de **kararlı bir destekçisidir**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için üretildi. Sizin etrafınızda tasarlandı.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili cybersecurity training geliştirir ve sunar. Programları theory'nin ötesine geçerek ekipleri derin anlayış ve uygulanabilir skills ile donatır; gerçek dünya threats'lerini yansıtan custom environments kullanır. Özel training talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Training'lerini öne çıkaran şey:**
* Custom-built content ve labs
* Üst seviye tools ve platforms ile desteklenir
* Practitioner'lar tarafından tasarlanır ve öğretilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumları için, **penetration testing, cloud security assessments** ve **compliance readiness** (SOC 2, PCI-DSS, NIST) odaklı özel cybersecurity services sunar. Ekibimiz, derin teknik uzmanlık ve endüstri standardı içgörü getiren **OSCP ve CISSP sertifikalı profesyoneller** içerir.

Yüksek riskli ortamlar için özel olarak uyarlanmış **manual, intelligence-driven testing** ile otomatik taramaların ötesine geçiyoruz. Öğrenci kayıtlarını korumaktan finansal işlemleri güvence altına almaya kadar, kuruluşların en önemli olanı savunmasına yardımcı oluyoruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; biz anlayış yoluyla security sağlıyoruz.”_

Cybersecurity alanındaki en yeni gelişmelerden haberdar ve güncel kalmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve developer'ların Kubernetes cluster'larını verimli şekilde yönetmesini, izlemesini ve secure etmesini sağlar. AI-driven insights, gelişmiş security framework'ümüz ve sezgisel CloudMaps GUI'mizi kullanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle aksiyon alın.

Ayrıca K8Studio, **tüm büyük kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası) ile **uyumludur**.

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Bunları şurada kontrol edin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
