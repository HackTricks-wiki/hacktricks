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
Yerel HackTricks kopyanız <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde **kullanılabilir olacak** (kitabın derlenmesi gerekiyor, lütfen bekleyin).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com), sloganı **HACK THE UNHACKABLE** olan harika bir siber güvenlik şirketidir. Kendi araştırmalarını yapar ve kendi hacking araçlarını geliştirir; böylece **pentesting**, Red team'ler ve eğitim gibi çeşitli değerli siber güvenlik hizmetleri sunar.

**blog** sayfalarını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden kontrol edebilirsiniz.

**STM Cyber** ayrıca HackTricks gibi açık kaynak siber güvenlik projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Avrupa'nın #1** etik hacking ve **bug bounty platformudur.**

**Bug bounty ipucu**: **kayıt olun** **Intigriti**'ye, hackerlar tarafından hackerlar için oluşturulmuş premium bir **bug bounty platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden bize katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty hunter'larla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking Insights:** hacking'in heyecanını ve zorluklarını irdeleyen içeriklerle etkileşime geçin
- **Real-Time Hack News:** gerçek zamanlı haberler ve içgörülerle hızlı tempolu hacking dünyasını takip edin
- **Latest Announcements:** yayımlanan en yeni bug bounty'ler ve kritik platform güncellemeleri hakkında bilgi sahibi olun

**Bugün** [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın ve en iyi hackerlarla iş birliği yapmaya başlayın!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **mühendislik odaklı, uygulamalı lab yaklaşımı** ile **pratik AI Security eğitimi** sunar. Kurslarımız, **gerçek AI/LLM destekli uygulamalar kurmak, bozmak ve güvence altına almak** isteyen security engineer'lar, AppSec profesyonelleri ve developer'lar için tasarlanmıştır.

**AI Security Certification** şu konulara odaklanır, bunlar dahil:
- LLM ve AI destekli uygulamaları güvence altına almak
- AI sistemleri için threat modeling
- Embeddings, vector database'ler ve RAG security
- LLM saldırıları, kötüye kullanım senaryoları ve pratik savunmalar
- Güvenli tasarım kalıpları ve dağıtım hususları

Tüm kurslar **on-demand**, **lab odaklı**dır ve yalnızca teoriye değil, **gerçek dünya güvenlik ödünleşimleri** etrafında tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla detay:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **arama motoru sonuçlarına erişmek** için hızlı ve kolay gerçek zamanlı API'ler sunar. Arama motorlarını tarar, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi'nin planlarından birine abonelik, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını taramak için 50'den fazla farklı API'ye erişim içerir.\
Diğer sağlayıcıların aksine, **SerpApi yalnızca organik sonuçları taramaz**. SerpApi yanıtları tutarlı şekilde tüm reklamları, satır içi görselleri ve videoları, knowledge graph'leri ve arama sonuçlarında bulunan diğer öğe ve özellikleri içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunur.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larına** göz atın veya [**playground**](https://serpapi.com/playground)**'larında** bir örnek deneyin.\
[**buradan**](https://serpapi.com/users/sign_up) **ücretsiz bir hesap oluşturabilirsiniz**.

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, aktif araştırmacılar tarafından verilen offensive mobile ve AI security eğitimi sunar; aynı ekip Black Hat, HITB ve Zer0con'daki CVE writeup'ları ve konuşmalarının da arkasındadır. Kurslar kendi hızınızda ilerler, gerçek hedefler üzerindeki lab'lere dayanır ve uygulamalı bir sertifika ile desteklenir.

Katalog iki track içerir:

**Mobile Security** – uygulama katmanından aşağıya kadar iOS ve Android: Ghidra ve LLDB ile reverse engineering, ARM64 exploitation, kernel internals ve modern mitigasyonlar (PAC, MTE, SELinux), jailbreak ve rooting mekanikleri.

**AI Security** – alanı kapsayan iki tam kurs. Practical AI Security, LLM'lerin, RAG pipeline'larının, AI agent'ların ve MCP'nin nasıl çalıştığını ve bunlara nasıl saldırılıp savunulacağını ele alır. Advanced AI Security ise sınırda daha yoğun geliştirme odaklıdır: Garak ve PyRIT ile büyük ölçekte AI sistemlerine red teaming yapmak, MCP server'larını exploit etmek, model backdoor'ları yerleştirmek ve tespit etmek, Apple Silicon üzerinde attack ve defense'leri fine-tuning ile ayarlamak.

Kurslar ve sertifikalar:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, saldırganlar yapmadan önce exploit edilebilir vulnerabilities bulmak için AI destekli bir security platformudur.

**Code security ipucu**: developer'lar ve security team'ler için geliştirilmiş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye kayıt olun! Bugün bize katılın ve gerçek security risklerini **production'a ulaşmadan önce tespit etmek, doğrulamak ve düzeltmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net), **Amsterdam** merkezli profesyonel bir siber güvenlik şirketidir; **modern** bir yaklaşımla **offensive-security services** sunarak işletmelerin **dünya genelinde** en yeni siber güvenlik tehditlerine karşı **korunmasına** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri bulunan uluslararası bir güvenlik şirketidir. **Hepsi bir arada security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir başka havalı şey de sektör ortalamasının aksine becerileri konusunda **çok emin** olmalarıdır; öyle ki **en iyi kalite sonuçları garanti ederler**, web sitelerinde "**If we can't hack it, You don't pay it!**" yazar. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/) sayfalarına göz atın!

Yukarıdakilere ek olarak WebSec, HackTricks'in **bağlı bir destekçisidir**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için tasarlandı. Sizin etrafınızda tasarlandı.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve yönetilen etkili siber güvenlik eğitimleri geliştirir ve sunar. Programları teorinin ötesine geçerek ekipleri derin anlayış ve uygulanabilir becerilerle donatır; gerçek dünya tehditlerini yansıtan özel ortamlar kullanır. Özel eğitim talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Eğitimlerini farklı kılan şey:**
* Özel olarak hazırlanmış içerik ve lab'ler
* En üst düzey araçlar ve platformlar tarafından desteklenir
* Uygulayıcılar tarafından tasarlanır ve öğretilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumları için **penetration testing, cloud security assessments** ve
**compliance readiness** (SOC 2, PCI-DSS, NIST) odaklı uzmanlaşmış siber güvenlik hizmetleri sunar. Ekibimiz **OSCP ve CISSP
sertifikalı profesyoneller** içerir; her çalışmaya derin teknik uzmanlık ve sektör standardı içgörü getirir.

Otomatik taramaların ötesine geçerek yüksek riskli ortamlara özel **manuel, intelligence-driven testing** yaparız. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar,
kuruluşların en önemli olanı savunmasına yardımcı oluruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; biz anlayış yoluyla güvenlik sağlarız.”_

Siber güvenlikteki en son gelişmeleri öğrenmek ve güncel kalmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve developer'ların Kubernetes cluster'larını verimli şekilde yönetmesini, izlemesini ve güvence altına almasını sağlar. AI destekli içgörülerimizden, gelişmiş güvenlik çerçevemizden ve sezgisel CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle aksiyon alın.

Ayrıca K8Studio, **tüm büyük kubernetes dağıtımlarıyla uyumludur** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Şunları kontrol edin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
