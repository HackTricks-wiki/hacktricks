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
Yerel HackTricks kopyanız <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde **erişilebilir olacak** (kitabın derlenmesi gerekiyor, lütfen sabırlı olun).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) **HACK THE UNHACKABLE** sloganına sahip harika bir cybersecurity şirketidir. Kendi araştırmalarını yapar ve kendi hacking araçlarını geliştirerek **pentesting, Red teams ve training** gibi çeşitli değerli cybersecurity hizmetleri sunar.

**blog**'larını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinde inceleyebilirsiniz

**STM Cyber**, HackTricks gibi açık kaynak cybersecurity projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Europe's #1** ethical hacking ve **bug bounty platform.**

**Bug bounty ipucu**: **sign up** for **Intigriti**, **hackers tarafından, hackers için oluşturulmuş premium bir bug bounty platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden bize katılın ve **$100,000**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackers ve bug bounty hunter'larla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking Insights:** hacking'in heyecanını ve zorluklarını ele alan içeriklerle etkileşime geçin
- **Real-Time Hack News:** gerçek zamanlı haberler ve içgörülerle hızlı tempolu hacking dünyasını takip edin
- **Latest Announcements:** en yeni başlayan bug bounty'ler ve kritik platform güncellemeleri hakkında bilgi sahibi olun

En iyi hackers ile bugün iş birliği yapmaya başlamak için [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **engineering-first, hands-on lab approach** ile **pratik AI Security training** sunar. Kurslarımız, **gerçek AI/LLM-powered applications** oluşturmak, kırmak ve güvence altına almak isteyen security engineer'lar, AppSec profesyonelleri ve developer'lar için tasarlanmıştır.

**AI Security Certification**, aşağıdakiler dahil gerçek dünya becerilerine odaklanır:
- LLM ve AI-powered applications güvence altına alma
- AI systems için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse senaryoları ve pratik savunmalar
- Secure design patterns ve deployment considerations

Tüm kurslar **on-demand**, **lab-driven** ve yalnızca teoriye değil **gerçek dünya security tradeoff'larına** göre tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla bilgi:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **search engine results**'a erişmek için hızlı ve kolay gerçek zamanlı APIs sunar. Search engine'leri scrape eder, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine abone olmak, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil farklı search engine'leri scrape etmek için 50'den fazla farklı API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi yalnızca organic results**'ı scrape etmez. SerpApi yanıtları, search results içinde bulunan tüm reklamları, inline image ve video'ları, knowledge graph'ları ve diğer öğe ve özellikleri tutarlı biçimde içerir.

Güncel SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**,** sayfalarına bakın veya [**playground**](https://serpapi.com/playground)**.** içindeki bir örneği deneyin\
Ücretsiz bir hesap oluşturabilirsiniz [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil applications ve devices'ları korumak için vulnerability research, penetration testing ve reverse engineering yapmak için gereken teknolojileri ve becerileri öğrenin. **iOS ve Android security konusunda uzmanlaşın**; on-demand kurslarımızla **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, attackers'tan önce exploitable vulnerabilities bulmak için tasarlanmış AI-powered bir security platformudur.

**Code security ipucu**: developer'lar ve security team'leri için oluşturulmuş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye **sign up** yapın! Bugün bize katılın ve **gerçek security risks production'a ulaşmadan önce detect, validate ve fix etmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net), **Amsterdam** merkezli profesyonel bir cybersecurity şirketidir ve **modern** bir yaklaşımla **offensive-security services** sağlayarak işletmeleri **tüm dünyada** en yeni cybersecurity tehditlerine karşı **korumaya** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir security şirketidir. **all-in-one security services** sunarlar; yani her şeyi onlar yapar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir diğer havalı şey ise sektör ortalamasının aksine yeteneklerine **çok güvenmeleri** ve bu güveni **en iyi kalite sonuçları garanti etmeleri** ile göstermeleridir; web sitelerinde "**If we can't hack it, You don't pay it!**" yazar. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/) sayfalarına bakın!

Yukarıdakilere ek olarak WebSec, HackTricks'in de **kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için üretildi. Sizin etrafınızda şekillendirildi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili cybersecurity training geliştirir ve sunar. Programları teoriyle sınırlı kalmaz; gerçek dünya tehditlerini yansıtan özel ortamlar kullanarak ekipleri derin anlayış ve uygulanabilir becerilerle donatır. Özel training talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Training'lerini farklı kılan şey:**
* Özel olarak hazırlanmış içerik ve lab'lar
* Üst seviye tools ve platformlar tarafından desteklenir
* Practitioners tarafından tasarlanır ve öğretilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumları için uzmanlaşmış cybersecurity hizmetleri sunar; odak noktası **penetration testing, cloud security assessments** ve **compliance readiness**'dir (SOC 2, PCI-DSS, NIST). Ekibimiz, **OSCP ve CISSP sertifikalı profesyoneller** içerir ve her çalışmaya derin teknik uzmanlık ile sektör standardı içgörü katar.

Yüksek riskli ortamlar için uyarlanmış **manual, intelligence-driven testing** ile otomatik taramaların ötesine geçiyoruz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, kuruluşların en önemli olanı savunmasına yardımcı oluyoruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; anlayış yoluyla security sağlıyoruz.”_

En son cybersecurity gelişmeleriyle ilgili bilgi sahibi olmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve developer'ların Kubernetes cluster'larını verimli bir şekilde yönetmesini, izlemesini ve güvence altına almasını sağlar. AI-driven insights, gelişmiş security framework'ümüz ve sezgisel CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle harekete geçin.

Ayrıca, K8Studio **tüm büyük kubernetes distributions** ile uyumludur (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Şunları şu adreste kontrol edin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
