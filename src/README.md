# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareket tasarımı_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks’i Yerel Olarak Çalıştırın
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
Yerel HackTricks kopyanız, <5 dakika sonra **[http://localhost:3337](http://localhost:3337)** adresinde **kullanılabilir olacak** (kitabın derlenmesi gerekiyor, sabırlı olun).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com), sloganı **HACK THE UNHACKABLE** olan harika bir siber güvenlik şirketidir. Kendi araştırmalarını yaparlar ve kendi hacking araçlarını geliştirirler; böylece **pentesting, Red teams ve training** gibi çeşitli değerli siber güvenlik hizmetleri sunarlar.

**Blog**'larını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden inceleyebilirsiniz

**STM Cyber**, HackTricks gibi açık kaynaklı siber güvenlik projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Avrupa'nın 1 numaralı** ethical hacking ve **bug bounty platformudur.**

**Bug bounty ipucu**: **Intigriti**'ye kaydolun, hackerlar tarafından hackerlar için oluşturulmuş premium bir **bug bounty platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **$100,000**'a kadar bounty kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty hunter'larla iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

- **Hacking Insights:** Hacking'in heyecanına ve zorluklarına derinlemesine inen içeriklerle etkileşime geçin
- **Real-Time Hack News:** Gerçek zamanlı haberler ve içgörülerle hızlı ilerleyen hacking dünyasını takip edin
- **Latest Announcements:** Yeni başlayan bug bounty'lerden ve önemli platform güncellemelerinden haberdar olun

Bugün üst düzey hackerlarla işbirliği yapmaya başlamak için [**Discord**](https://discord.com/invite/N3FrSbmwdy) üzerinden bize katılın!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security, **mühendislik öncelikli, uygulamalı laboratuvar yaklaşımıyla** pratik **AI Security training** sunar. Kurslarımız, gerçek AI/LLM destekli uygulamaları **oluşturmak, bozmak ve güvence altına almak** isteyen security engineer'lar, AppSec profesyonelleri ve geliştiriciler için hazırlanmıştır.

**AI Security Certification** şu alanlara odaklanır:
- LLM ve AI destekli uygulamaları güvence altına alma
- AI sistemleri için threat modeling
- Embeddings, vector databases ve RAG security
- LLM attacks, abuse senaryoları ve pratik savunmalar
- Güvenli tasarım kalıpları ve deployment değerlendirmeleri

Tüm kurslar **on-demand**, **lab odaklı**dır ve yalnızca teoriye değil, **gerçek dünya security tradeoff'larına** göre tasarlanmıştır.

👉 AI Security kursu hakkında daha fazla bilgi:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, **arama motoru sonuçlarına erişmek** için hızlı ve kolay gerçek zamanlı API'ler sunar. Arama motorlarını tarar, proxy'leri yönetir, captcha'ları çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

SerpApi planlarından birine yapılan abonelik, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını taramak için 50'den fazla farklı API'ye erişim içerir.\
Diğer sağlayıcıların aksine, **SerpApi yalnızca organic sonuçları taramaz**. SerpApi yanıtları tutarlı biçimde tüm reklamları, satır içi görselleri ve videoları, knowledge graph'leri ve arama sonuçlarında bulunan diğer öğe ve özellikleri içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** yer alır.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larına** göz atın veya [**playground**](https://serpapi.com/playground)**'larında** bir örneği deneyin.\
[**Burada**](https://serpapi.com/users/sign_up) **ücretsiz bir hesap** oluşturabilirsiniz.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Vulnerability research, penetration testing ve reverse engineering yapmak için gerekli teknolojileri ve becerileri öğrenerek mobil uygulamaları ve cihazları koruyun. **iOS ve Android security** alanında uzmanlaşın; on-demand kurslarımızla öğrenin ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**, saldırganlar bulmadan önce istismar edilebilir açıkları bulmak için AI-powered bir security platformudur.

**Code security ipucu**: Geliştiriciler ve security teams için oluşturulmuş akıllı bir vulnerability monitoring platformu olan NaxusAI'ye kaydolun! Bugün bize katılın ve **gerçek security risklerini production'a ulaşmadan önce tespit etmek, doğrulamak ve düzeltmek** için AI kullanmaya başlayın!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net), merkezi **Amsterdam**'da bulunan profesyonel bir siber güvenlik şirketidir ve **modern** bir yaklaşımla **offensive-security services** sunarak işletmeleri **dünya genelinde** en yeni siber güvenlik tehditlerine karşı **korumaya** yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri olan uluslararası bir güvenlik şirketidir. **Hepsi bir arada security services** sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında bir diğer güzel şey, sektör ortalamasının aksine becerilerine **çok güveniyor** olmalarıdır; o kadar ki **en iyi kalite sonuçları garanti ederler**. Web sitelerinde şu ifade yer alır: "**If we can't hack it, You don't pay it!**". Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/)'larına göz atın!

Buna ek olarak WebSec, HackTricks'in **kararlı bir destekçisidir**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Sahada kullanılmak üzere tasarlandı. Sizin etrafınızda şekillendirildi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), sektör uzmanları tarafından oluşturulan ve sunulan etkili siber güvenlik eğitimleri geliştirir ve sunar. Programları teorinin ötesine geçerek ekipleri derin anlayış ve uygulanabilir becerilerle donatır; gerçek dünya tehditlerini yansıtan özel ortamlar kullanır. Özel eğitim talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Eğitimlerini farklı kılan şeyler:**
* Özel olarak hazırlanmış içerik ve lab'lar
* Üst düzey araçlar ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve öğretilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumları için uzmanlaşmış siber güvenlik hizmetleri sunar; odak noktası **penetration testing, cloud security assessments** ve
**compliance readiness** (SOC 2, PCI-DSS, NIST)'tir. Ekibimiz, derin teknik uzmanlık ve sektör standardı içgörü sağlayan **OSCP ve CISSP sertifikalı profesyoneller** içerir.

Yüksek riskli ortamlar için uyarlanmış, **manuel ve intelligence-driven testing** ile otomatik taramaların ötesine geçiyoruz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, kuruluşların en önemli şeyleri savunmasına yardımcı oluyoruz.

_“Kaliteli bir savunma, saldırıyı bilmeyi gerektirir; biz anlayış yoluyla güvenlik sağlarız.”_

Siber güvenlikteki en son gelişmeleri öğrenmek ve güncel kalmak için [**blog**](https://www.lasttowersolutions.com/blog)'umuzu ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve geliştiricilerin Kubernetes cluster'larını verimli şekilde yönetmesini, izlemesini ve güvence altına almasını sağlar. AI-driven insights, gelişmiş security framework ve sezgisel CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle aksiyon alın.

Ayrıca K8Studio, **tüm büyük kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası) ile **uyumludur**.

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Bu, siber güvenlik ücretsiz wiki'sini sunmak için bir metindir: <b>Hacktricks Book </b>. Tüm hacking tricks türlerini şimdi buradan ücretsiz öğrenin!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Şurada kontrol edin:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
