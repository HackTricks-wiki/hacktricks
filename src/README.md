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
Yerel HackTricks kopyanız, <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde **kullanıma hazır olacak** (kitabın derlenmesi gerekiyor, lütfen sabırlı olun).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) sloganı **HACK THE UNHACKABLE** olan harika bir cybersecurity şirketidir. Kendi araştırmalarını yapar ve kendi hacking tools geliştirir; böylece **pentesting, Red teams ve training** gibi birçok değerli cybersecurity hizmeti sunar.

**blog**larını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinde kontrol edebilirsiniz.

**STM Cyber**, HackTricks gibi açık kaynak cybersecurity projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Europe's #1** ethical hacking ve **bug bounty platform.**

**Bug bounty ipucu**: **kayıt olun** **Intigriti** için, hackerlar tarafından hackerlar için oluşturulmuş premium bir **bug bounty platform**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **$100,000**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **engineering-first, hands-on lab approach** ile **pratik AI Security training** sunar. Kurslarımız, security engineers, AppSec professionals ve gerçek AI/LLM-powered applications inşa etmek, bozmak ve güvenceye almak isteyen developers için tasarlanmıştır.

**AI Security Certification**, şu alanlar dahil olmak üzere gerçek dünya becerilerine odaklanır:
- LLM ve AI-powered applications güvenceye alma
- AI systems için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse scenarios ve pratik savunmalar
- Secure design patterns ve deployment considerations

Tüm kurslar **on-demand**, **lab-driven** ve sadece teoriye değil, **real-world security tradeoffs** etrafında tasarlanmıştır.

👉 AI Security course hakkında daha fazla bilgi:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **search engine results**'a erişmek için hızlı ve kolay gerçek zamanlı API'ler sunar. Search engines tarar, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine abonelik, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı search engines taramak için 50'den fazla farklı API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi sadece organic results** taramaz. SerpApi yanıtları, search results içinde bulunan tüm reklamları, inline images ve videos, knowledge graphs ve diğer öğe ve özellikleri tutarlı şekilde içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**,** sayfasına göz atın veya [**playground**](https://serpapi.com/playground)**.** içinde bir örnek deneyin.\
[**here**](https://serpapi.com/users/sign_up)**.** üzerinden ücretsiz bir hesap **oluşturabilirsiniz**.

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, sizi aktif araştırmacılar tarafından öğretilen offensive mobile ve AI security alanında eğitir; aynı ekip Black Hat, HITB ve Zer0con’daki CVE writeups ve konuşmaların arkasındadır. Kurslar self-paced’tir, gerçek hedefler üzerindeki lab’ler etrafında oluşturulmuştur ve uygulamalı bir certification ile desteklenir.

Katalog iki track içerir:

**Mobile Security** – iOS ve Android’i app layer’dan başlayarak aşağıya doğru ele alır: Ghidra ve LLDB ile reverse engineering, ARM64 exploitation, kernel internals ve modern mitigations (PAC, MTE, SELinux), jailbreak ve rooting mechanics.

**AI Security** – alanı kapsayan iki tam kurs. Practical AI Security, LLMs, RAG pipelines, AI agents ve MCP’nin nasıl çalıştığını ve bunlara nasıl saldırılıp savunma yapılacağını anlatır. Advanced AI Security ise ileri uçta daha çok build odaklıdır: Garak ve PyRIT ile ölçekli AI systems üzerinde red teaming, MCP servers exploit etme, model backdoors yerleştirme ve tespit etme, Apple Silicon üzerinde attacks ve defenses için fine-tuning.

Kurslar ve certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, saldırganlar yapmadan önce exploitable vulnerabilities bulmak için AI-powered bir security platformudur.

**Code security ipucu**: geliştiriciler ve security teams için geliştirilmiş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye kayıt olun! Bugün bize katılın ve **production**'a ulaşmadan önce gerçek security risks'leri **detect etmek, validate etmek ve fix etmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net), **Amsterdam** merkezli profesyonel bir cybersecurity şirketidir ve **modern** bir yaklaşımla **offensive-security services** sağlayarak işletmeleri **dünya genelinde** en son cybersecurity tehditlerine karşı **korumaya** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir security şirketidir. **all-in-one security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir diğer güzel şey de sektör ortalamasının aksine becerileri konusunda **çok özgüvenli** olmalarıdır; o kadar ki **en iyi kalite sonuçları garanti ederler**, web sitelerinde "**If we can't hack it, You don't pay it!**" yazar. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/) sayfalarına göz atın!

Yukarıdakilere ek olarak WebSec, HackTricks'in de **bağlı bir destekçisidir**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili cybersecurity training geliştirir ve sunar. Programları teorinin ötesine geçerek ekipleri derin understanding ve uygulanabilir skills ile donatır; gerçek dünya tehditlerini yansıtan özel environments kullanır. Özel training talepleri için [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) üzerinden bizimle iletişime geçin.

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumları için, **penetration testing, cloud security assessments** ve
**compliance readiness** (SOC 2, PCI-DSS, NIST) odaklı uzmanlaşmış cybersecurity services sunar. Ekibimiz, her çalışmaya derin teknik uzmanlık ve endüstri standardı içgörü getiren **OSCP ve CISSP sertifikalı profesyoneller** içerir.

Otomatik taramaların ötesine geçerek, yüksek riskli ortamlar için uyarlanmış **manual, intelligence-driven testing** yapıyoruz. Öğrenci kayıtlarını güvenceye almaktan finansal işlemleri korumaya kadar,
kuruluşların en önemli olanı savunmasına yardımcı oluyoruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; biz anlayış yoluyla güvenlik sağlıyoruz.”_

En güncel cybersecurity gelişmelerinden haberdar olmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve developers'ların Kubernetes clusters'ı verimli bir şekilde yönetmesini, izlemesini ve güvenceye almasını sağlar. AI-driven insights, advanced security framework ve sezgisel CloudMaps GUI'mizi kullanarak clusters'ınızı görselleştirin, durumlarını anlayın ve güvenle hareket edin.

Ayrıca K8Studio, **all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası) ile **uyumludur**.

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
