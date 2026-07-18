# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks logoları ve hareketli tasarım_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ tarafından._

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
HackTricks'in yerel kopyasına, kitabın derlenmesi gerektiğinden sabırlı olmanız koşuluyla, **5 dakikadan kısa bir süre sonra [http://localhost:3337](http://localhost:3337)** adresinden erişebilirsiniz.

Alternatif olarak, Docker Compose kullanıyorsanız repo kök dizininden aşağıdaki komutu çalıştırabilirsiniz:
```bash
docker compose up
```
Bu, yerel checkout'unuzu live reload ile [http://localhost:3337](http://localhost:3337) adresinde sunmak için birlikte gelen `docker-compose.yml` dosyasını kullanır.

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com), sloganı **HACK THE UNHACKABLE** olan harika bir cybersecurity şirketidir. Kendi araştırmalarını yürütür ve pentesting, Red teams ve training gibi **çeşitli değerli cybersecurity hizmetleri sunmak** için kendi hacking araçlarını geliştirirler.

[**blog**](https://blog.stmcyber.com) sayfalarına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden göz atabilirsiniz.

**STM Cyber**, HackTricks gibi cybersecurity open source projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Avrupa'nın 1 numaralı** ethical hacking ve **bug bounty platformudur.**

**Bug bounty ipucu**: **Hackerlar tarafından hackerlar için oluşturulmuş** premium bir **bug bounty platformu** olan **Intigriti'ye kaydolun**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden bize katılın ve **100.000 $**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **engineering-first, hands-on lab yaklaşımıyla** **pratik AI Security training** sunar. Kurslarımız; gerçek AI/LLM destekli uygulamalar **oluşturmak, kırmak ve güvenli hâle getirmek** isteyen security engineer'lar, AppSec profesyonelleri ve developer'lar için hazırlanmıştır.

**AI Security Certification**, aşağıdakiler dâhil olmak üzere gerçek dünya becerilerine odaklanır:
- LLM ve AI destekli uygulamaların güvenliğini sağlama
- AI sistemleri için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse scenarios ve pratik savunmalar
- Secure design patterns ve deployment considerations

Tüm kurslar **on-demand**, **lab-driven** olup yalnızca teoriye değil, **gerçek dünya security tradeoff'larına** göre tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla bilgi:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **search engine results'a erişmek** için hızlı ve kullanımı kolay gerçek zamanlı API'ler sunar. Search engine'leri scrape eder, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine yapılan abonelik; Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dâhil olmak üzere farklı search engine'leri scrape etmek için 50'den fazla farklı API'ye erişim sağlar.\
Diğer sağlayıcıların aksine **SerpApi yalnızca organic results scrape etmez**. SerpApi yanıtları; search results içinde bulunan tüm reklamları, inline image ve videoları, knowledge graph'ları ve diğer öğe ve özellikleri sürekli olarak içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/) sayfalarına göz atabilir, [**playground**](https://serpapi.com/playground) üzerinde bir örnek deneyebilir veya [**buradan**](https://serpapi.com/users/sign_up) **ücretsiz hesap oluşturabilirsiniz**.

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, Black Hat, HITB ve Zer0con'daki CVE writeup'larının ve konuşmaların arkasındaki ekiple, aktif araştırmacılar tarafından verilen offensive mobile ve AI security eğitimleri sunar. Kurslar kendi hızınızda ilerler, gerçek hedefler üzerindeki lab'lar etrafında oluşturulur ve hands-on certification ile desteklenir.

Katalog iki track içerir:

**Mobile Security** – App layer'dan aşağıya iOS ve Android: Ghidra ve LLDB ile reverse engineering, ARM64 exploitation, kernel internals ve modern mitigations (PAC, MTE, SELinux), jailbreak ve rooting mechanics.

**AI Security** – Alanı kapsayan iki kapsamlı kurs. Practical AI Security; LLM'lerin, RAG pipeline'larının, AI agent'ların ve MCP'nin nasıl çalıştığını, bunlara nasıl saldırılacağını ve nasıl savunulacağını öğretir. Advanced AI Security ise frontier seviyesinde yoğun uygulama içerir: Garak ve PyRIT ile AI sistemlerini geniş ölçekte red team yapma, MCP server'larını exploit etme, model backdoor'ları yerleştirme ve tespit etme, Apple Silicon üzerinde fine-tuning attacks ve defenses.

Kurslar ve certification'lar:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, saldırganlardan önce exploit edilebilir vulnerability'leri bulmak için AI destekli bir security platformudur.

**Code security ipucu**: Developer'lar ve security team'ler için oluşturulmuş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye kaydolun! Bugün bize katılın ve gerçek security risk'lerini production'a ulaşmadan önce **tespit etmek, doğrulamak ve düzeltmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net), merkezi **Amsterdam**'da bulunan profesyonel bir cybersecurity şirketidir ve **modern** bir yaklaşımla **offensive-security services** sağlayarak dünyanın **her yerindeki** işletmelerin en yeni cybersecurity tehditlerine karşı **korunmasına** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir security şirketidir. **All-in-one security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir diğer güzel nokta, sektör ortalamasının aksine WebSec'in **becerilerine büyük güven duymasıdır**. Öyle ki **en iyi kalite sonuçları garanti ederler**. Web sitelerinde şöyle belirtilir: "**If we can't hack it, You don't pay it!**". Daha fazla bilgi için [**web sitelerine**](https://websec.net/en/) ve [**bloglarına**](https://websec.net/blog/) göz atın!

Yukarıdakilere ek olarak WebSec, **HackTricks'in kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için. Size göre.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından hazırlanıp yürütülen etkili cybersecurity training programları geliştirir ve sunar. Programları teorinin ötesine geçerek, gerçek dünya tehditlerini yansıtan özel ortamlar kullanır ve team'lere derin bir anlayış ile uygulanabilir beceriler kazandırır. Özel training talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Training'lerini farklı kılan özellikler:**
* Özel olarak oluşturulmuş içerik ve lab'lar
* Üst düzey araçlar ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve verilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumlarına özel cybersecurity hizmetleri sunar; **penetration testing, cloud security assessments** ve **compliance readiness** (SOC 2, PCI-DSS, NIST) konularına odaklanır. Ekibimiz, her çalışmaya derin teknik uzmanlık ve sektör standartlarına uygun bakış açısı getiren **OSCP ve CISSP sertifikalı profesyonellerden** oluşur.

Otomatik scan'lerin ötesine geçerek, yüksek riskli ortamlar için uyarlanmış **manuel, istihbarat odaklı testing** gerçekleştiririz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, kuruluşların en önemli varlıklarını savunmasına yardımcı oluruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; anlayış yoluyla security sağlarız.”_

Cybersecurity alanındaki en son gelişmelerden haberdar olmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE; DevOps, DevSecOps ve developer'ların Kubernetes cluster'larını verimli şekilde yönetmesini, izlemesini ve güvenli hâle getirmesini sağlar. AI destekli içgörülerimizden, gelişmiş security framework'ümüzden ve sezgisel CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle aksiyon alın.

Ayrıca K8Studio, **tüm büyük Kubernetes dağıtımlarıyla uyumludur** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Bunları şu bölümde inceleyin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
