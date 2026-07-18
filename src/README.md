# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logo ve hareketli tasarım_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/) _tarafından._

### HackTricks'i Yerel Olarak Çalıştırın
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
HackTricks'in yerel kopyası, kitabın oluşturulması gerektiğinden lütfen sabırlı olun, **5 dakikadan kısa bir süre sonra [http://localhost:3337](http://localhost:3337)** adresinde kullanılabilir olacaktır.

Alternatif olarak, Docker Compose'a sahipseniz repo kök dizininden aşağıdaki komutu çalıştırabilirsiniz:
```bash
docker compose up
```
Bu, birlikte sunulan `docker-compose.yml` dosyasını kullanarak host üzerinde şu anda checkout edilmiş branch'i live reload ile [http://localhost:3337](http://localhost:3337) adresinde sunar. Compose kullanırken dilleri değiştirmek için servisi başlatmadan önce istediğiniz dil branch'ini checkout edin.

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com), sloganı **HACK THE UNHACKABLE** olan harika bir cybersecurity şirketidir. Kendi araştırmalarını yürütür ve kendi hacking araçlarını geliştirerek pentesting, Red teams ve training gibi **birçok değerli cybersecurity hizmeti sunar**.

**blog** sayfalarına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden göz atabilirsiniz.

**STM Cyber**, HackTricks gibi cybersecurity open source projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Avrupa'nın 1 numaralı** etik hacking ve **bug bounty platformudur.**

**Bug bounty ipucu**: **hacker'lar tarafından hacker'lar için oluşturulmuş** premium bir **bug bounty platformu** olan **Intigriti'ye kaydolun**! [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinden bugün bize katılın ve **100.000 $**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **engineering-first ve hands-on lab yaklaşımıyla pratik AI Security eğitimi** sunar. Kurslarımız; security engineer'lar, AppSec profesyonelleri ve **gerçek AI/LLM destekli uygulamalar oluşturmak, bozmak ve güvenli hâle getirmek** isteyen geliştiriciler için hazırlanmıştır.

**AI Security Certification**, aşağıdakiler de dâhil olmak üzere gerçek dünya becerilerine odaklanır:
- LLM ve AI destekli uygulamaların güvenliğini sağlama
- AI sistemleri için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse scenarios ve pratik savunmalar
- Secure design patterns ve deployment considerations

Tüm kurslar **on-demand**, **lab-driven** ve yalnızca teoriye değil, **gerçek dünya security tradeoff'larına** odaklanacak şekilde tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla detay:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **search engine sonuçlarına erişmek** için hızlı ve kolay gerçek zamanlı API'ler sunar. Search engine'leri scrape eder, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine yapılan abonelik; Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dâhil olmak üzere farklı search engine'leri scrape etmek için 50'den fazla API'ye erişim içerir.\
Diğer sağlayıcılardan farklı olarak **SerpApi yalnızca organic results scrape etmez**. SerpApi yanıtları; search results içinde bulunan tüm reklamları, inline images ve videoları, knowledge graph'ları ve diğer öğe ve özellikleri sürekli olarak içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larına** göz atın veya [**playground**](https://serpapi.com/playground)**'larında** bir örnek deneyin.\
[**Buradan**](https://serpapi.com/users/sign_up)** ücretsiz hesap oluşturabilirsiniz.**

---

### [8kSec Academy – Ayrıntılı Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, Black Hat, HITB ve Zer0con'daki CVE writeup'larının ve konuşmaların arkasındaki aynı ekip olan aktif araştırmacılar tarafından verilen offensive mobile ve AI security eğitimleri sunar. Kurslar kendi hızınızda ilerler, gerçek hedefler üzerindeki lab'ler etrafında oluşturulur ve hands-on bir certification ile desteklenir.

Katalog iki track sunar:

**Mobile Security** – iOS ve Android'i app layer'dan aşağıya kadar ele alır: Ghidra ve LLDB ile reverse engineering, ARM64 exploitation, kernel internals ve modern mitigations (PAC, MTE, SELinux), jailbreak ve rooting mekanikleri.

**AI Security** – alanı kapsayan iki tam kurs. Practical AI Security; LLM'lerin, RAG pipeline'larının, AI agent'ların ve MCP'nin nasıl çalıştığını ve bunlara nasıl attack ve defense uygulanacağını ele alır. Advanced AI Security ise frontier seviyesinde build-heavy bir yaklaşım sunar: Garak ve PyRIT ile AI sistemlerinde scale'de red teaming, MCP server'larını exploit etme, model backdoor'ları yerleştirme ve tespit etme ve Apple Silicon üzerinde fine-tuning attacks ve defenses.

Kurslar ve certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, saldırganlar bulmadan önce exploit edilebilir vulnerability'leri tespit etmek için kullanılan AI destekli bir security platformudur.

**Code security ipucu**: geliştiriciler ve security team'ler için oluşturulmuş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye kaydolun! Bugün bize katılın ve **gerçek security risk'lerini production'a ulaşmadan önce tespit etmek, doğrulamak ve düzeltmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net), merkezi **Amsterdam**'da bulunan profesyonel bir cybersecurity şirketidir ve **modern** bir yaklaşımla **offensive-security services** sağlayarak dünyanın **her yerindeki** işletmelerin en güncel cybersecurity threats'lerine karşı **korunmasına** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir security şirketidir. **All-in-one security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkındaki bir diğer harika şey, industry average'ın aksine WebSec'in **becerilerine çok güvenmesi** ve bu güvenin, **en iyi kalitede sonuçları garanti edecek** kadar ileri gitmesidir. Web sitelerinde "**If we can't hack it, You don't pay it!**" ifadesi yer alır. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/) sayfalarına göz atın!

Yukarıdakilere ek olarak WebSec, **HackTricks'in kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için oluşturuldu. Size göre tasarlandı.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), industry uzmanları tarafından geliştirilen ve yönetilen etkili cybersecurity training programları sunar. Programları teorinin ötesine geçerek, gerçek dünya threats'lerini yansıtan özel environment'lar kullanır ve ekiplere derin bir anlayış ile uygulanabilir beceriler kazandırır. Özel training talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bizimle iletişime geçin.

**Training programlarını farklı kılan özellikler:**
* Özel olarak oluşturulmuş içerik ve lab'ler
* Üst düzey araçlar ve platformlarla desteklenir
* Practitioner'lar tarafından tasarlanır ve verilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumları için uzmanlaşmış cybersecurity services sunar; **penetration testing, cloud security assessments** ve **compliance readiness** (SOC 2, PCI-DSS, NIST) alanlarına odaklanır. Ekibimiz, her çalışmaya derin teknik uzmanlık ve industry-standard bakış açısı katan **OSCP ve CISSP sertifikalı profesyonellerden** oluşur.

Otomatik scan'lerin ötesine geçerek **yüksek riskli environment'lara** özel, **manual ve intelligence-driven testing** gerçekleştiriyoruz. Öğrenci kayıtlarını güvenceye almaktan finansal işlemleri korumaya kadar kuruluşların en önemli varlıklarını savunmasına yardımcı oluyoruz.

_“Kaliteli bir defense, offense'u bilmeyi gerektirir; biz anlayış yoluyla security sağlarız.”_

Cybersecurity alanındaki en son gelişmelerden haberdar olmak ve güncel kalmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - Kubernetes'i Yönetmek için Daha Akıllı GUI.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE; DevOps, DevSecOps ve geliştiricilerin Kubernetes cluster'larını verimli şekilde yönetmesine, izlemesine ve güvenli hâle getirmesine olanak tanır. AI destekli içgörülerimizden, gelişmiş security framework'ümüzden ve sezgisel CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle harekete geçin.

Ayrıca K8Studio, **tüm büyük kubernetes dağıtımlarıyla** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası) **uyumludur**.

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Şuradan inceleyin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
