# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareketli tasarım tarafından_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks'i yerel olarak çalıştır
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
Yerel HackTricks kopyanız **[http://localhost:3337](http://localhost:3337)** adresinde <5 dakika sonra kullanılabilir olacak (kitabı oluşturması gerekiyor, sabırlı olun).

## Kurumsal Sponsorlar

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) harika bir siber güvenlik şirketidir; sloganı **HACK THE UNHACKABLE**. Kendi araştırmalarını yapar ve kendi hacking araçlarını geliştirirler, böylece pentesting, Red teams ve eğitim gibi **birçok değerli siber güvenlik hizmeti sunarlar**.

Bloglarını [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden inceleyebilirsiniz.

**STM Cyber** ayrıca HackTricks gibi açık kaynak siber güvenlik projelerini destekliyor :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **Spain**'deki en önemli siber güvenlik etkinliğidir ve **Europe**'un en önemli etkinliklerinden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, teknoloji ve siber güvenlik profesyonelleri için her disipline yönelik kaynayan bir buluşma noktasıdır.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** Avrupa'nın #1 ethical hacking ve **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, hack'ler tarafından, hack'ler için oluşturulmuş premium bir **bug bounty platform**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen iş akışlarını kolayca oluşturup **otomatikleştirebilirsiniz**.

Hemen erişim alın:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın ve deneyimli hackers ve bug bounty hunters ile iletişim kurun!

- **Hacking Insights:** Hacking'in heyecanı ve zorluklarına dair içeriklerle etkileşime geçin
- **Real-Time Hack News:** Hızla değişen hacking dünyasındaki haberler ve bilgilerle güncel kalın
- **Latest Announcements:** En yeni bug bounty'lerin başlatılması ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackers ile iş birliği yapmaya başlayın!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

Gerçek iş etkisi olan kritik, exploit edilebilir güvenlik açıklarını bulun ve raporlayın. Saldırı yüzeyini haritalamak, ayrıcalık yükseltmeye izin veren güvenlik sorunlarını tespit etmek ve otomatik exploits kullanarak gerekli kanıtları toplamak için 20'den fazla özel aracımızı kullanın; böylece sıkı çalışmanızı ikna edici raporlara dönüştürün.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** arama motoru sonuçlarına hızlı ve kolay gerçek zamanlı API'lar sağlar. Arama motorlarını tarar, proxy'leri yönetir, captchas çözer ve tüm zengin yapılandırılmış verileri sizin için ayrıştırır.

Bir SerpApi aboneliği, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını kazımak için 50'den fazla farklı API'ya erişim sağlar.\
Diğer sağlayıcılardan farklı olarak, **SerpApi sadece organik sonuçları kazımaz**. SerpApi cevapları tutarlı olarak tüm reklamları, satır içi görüntüleri ve videoları, knowledge graph'ları ve arama sonuçlarında bulunan diğer öğe ve özellikleri içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunuyor.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)'larına bakın veya [**playground**](https://serpapi.com/playground)'larında bir örnek deneyin.\
Ücretsiz bir hesap [**oluşturabilirsiniz**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil uygulamaları ve cihazları korumak için gerekli olan güvenlik araştırması, penetration testing ve reverse engineering becerilerini öğrenin. **iOS ve Android security** üzerinde uzmanlaşın, on-demand kurslarımızla eğitim alın ve **sertifika** sahibi olun:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) Amsterdam merkezli profesyonel bir siber güvenlik şirketidir; modern bir yaklaşımla **offensive-security services** sağlayarak işletmelerin dünya çapında en son siber tehditlere karşı korunmasına yardımcı olur.

WebSec, Amsterdam ve Wyoming'de ofisleri olan uluslararası bir güvenlik şirketidir. Hepsi bir arada güvenlik hizmetleri sunar; yani hepsini yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve çok daha fazlası.

WebSec hakkında başka bir güzel şey, sektör ortalamasının aksine uzmanlıklarına **çok güvenmeleri**; öyle ki web sitelerinde "**If we can't hack it, You don't pay it!**" diyorlar. Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/)'larına göz atın!

Buna ek olarak WebSec, HackTricks'in de **bağlı destekçilerinden** biridir.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sektör uzmanları tarafından oluşturulan ve verilen etkili siber güvenlik eğitimleri geliştirir ve sunar. Programları teorinin ötesine geçer; ekipleri gerçek dünya tehditlerini yansıtan özel ortamlarla derin bir anlayış ve uygulanabilir becerilerle donatır. Özel eğitim talepleri için bize [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) ulaşın.

**Eğitimlerini farklı kılanlar:**
* Özel hazırlanmış içerik ve laboratuvarlar
* Üst düzey araçlar ve platformlarla desteklenmiş
* Uygulayıcılar tarafından tasarlanmış ve öğretilmiş

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** kurumlarına yönelik uzmanlaşmış siber güvenlik hizmetleri sunar; odak noktası penetration testing, cloud security assessments ve uyumluluk hazırlığıdır (SOC 2, PCI-DSS, NIST). Ekibimizde **OSCP ve CISSP** sertifikalı profesyoneller bulunmaktadır; her görevde derin teknik uzmanlık ve sektör standartlarında içgörü sağlarlar.

Otomatik taramaların ötesine geçiyoruz ve yüksek riskli ortamlara özel, manuel, istihbarat odaklı testler yapıyoruz. Öğrenci kayıtlarını güvence altına almaktan finansal işlemleri korumaya kadar, kuruluşların en değerli varlıklarını savunmalarına yardım ediyoruz.

_“Kaliteli bir savunma, taarruzu bilmeyi gerektirir; biz anlayış yoluyla güvenlik sağlıyoruz.”_

Güncel kalmak ve siber güvenlikteki en son gelişmeleri takip etmek için [**blog**](https://www.lasttowersolutions.com/blog)'larını ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve geliştiricilerin Kubernetes cluster'larını verimli şekilde yönetmeleri, izlemeleri ve güvence altına almaları için güç sağlar. AI-driven içgörülerimizden, gelişmiş güvenlik çerçevemizden ve CloudMaps GUI'mizden yararlanarak cluster'larınızı görselleştirin, durumlarını anlayın ve güvenle hareket edin.

Ayrıca, K8Studio tüm major kubernetes dağıtımları ile uyumludur (AWS, GCP, Azure, DO, Rancher, K3s, Openshift ve daha fazlası).

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
