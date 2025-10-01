# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareketli tasarım tarafından_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## Kurumsal Sponsorlar

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) harika bir siber güvenlik şirketidir; sloganı **HACK THE UNHACKABLE**. Kendi araştırmalarını yaparlar ve kendi hacking araçlarını geliştirirler; pentesting, Red teams ve eğitim gibi çeşitli değerli siber güvenlik hizmetleri sunarlar.

You can check their **blog** in [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** ayrıca HackTricks gibi siber güvenlik açık kaynak projelerini destekliyor :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **İspanya**'daki en önemli siber güvenlik etkinliğidir ve **Avrupa**'nın en önemli etkinliklerinden biridir. Teknik bilginin teşvik edilmesi misyonuyla bu kongre, her disiplininden teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** Avrupa'nın #1 ethical hacking ve **bug bounty platform**'udur.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen iş akışlarını kolayca oluşturun ve **otomatikleştirin**.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** hacking'in getirdiği heyecan ve zorlukları ele alan içeriklerle etkileşime girin
- **Real-Time Hack News:** gerçek zamanlı haberler ve içgörülerle hızlı değişen hacking dünyasından haberdar olun
- **Latest Announcements:** yeni başlayan bug bounty programları ve önemli platform güncellemeleri hakkında bilgi sahibi olun

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hızlı ve kolay gerçek zamanlı API'ler sunar; search engine results erişimi sağlar. Search engine'leri scrape ederler, proxy'lerle uğraşır, captcha çözerler ve tüm zengin yapılandırılmış verileri sizin için parse ederler.

SerpApi’nin planlarından birine abone olmak, Google, Bing, Baidu, Yahoo, Yandex ve daha fazlası dahil olmak üzere farklı arama motorlarını kazımak için 50'den fazla farklı API erişimini içerir.\
Diğer sağlayıcılardan farklı olarak, **SerpApi sadece organic results kazımaz**. SerpApi yanıtları tutarlı olarak tüm reklamları, inline görüntüleri ve videoları, bilgi grafikleri ve arama sonuçlarında bulunan diğer öğe ve özellikleri içerir.

Mevcut SerpApi müşterileri arasında **Apple, Shopify ve GrubHub** bulunuyor.\
Daha fazla bilgi için [**blog**](https://serpapi.com/blog/)**'larına** göz atın, veya örnek bir uygulamayı [**playground**](https://serpapi.com/playground)**'ta** deneyin.\
You can **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Mobil uygulamaları ve cihazları korumak için gerekli olan teknolojileri ve becerileri öğrenin: vulnerability research, penetration testing ve reverse engineering yapmayı öğrenin. **iOS ve Android güvenliğinde ustalaşın** on-demand kurslarımızla ve **sertifika alın**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** merkezli profesyonel bir siber güvenlik şirketidir ve **modern** bir yaklaşımla işletmeleri dünyadaki en son siber güvenlik tehditlerine karşı korumaya yardımcı olur; offensive-security services sağlar.

WebSec, Amsterdam ve Wyoming'de ofisleri olan uluslararası bir güvenlik şirketidir. Hepsi bir arada security services sunarlar; yani her şeyi yaparlar: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing ve daha fazlası.

WebSec hakkında başka güzel bir şey de, sektör ortalamasının aksine WebSec'in **becerilerine çok güvenmesi**; bu güven o kadar ileri gidiyor ki **en iyi kalite sonuçlarını garanti ediyorlar**, sitelerinde şöyle yazıyor: "**If we can't hack it, You don't pay it!**". Daha fazla bilgi için [**website**](https://websec.net/en/) ve [**blog**](https://websec.net/blog/)'larına bakın!

Bunun yanı sıra WebSec, HackTricks'in de **kararlı bir destekçisidir.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) bir data breach (leak) arama motorudur. \
Tüm türdeki data leaks üzerinde rasgele string araması (Google gibi) sağlıyoruz -- sadece büyükleri değil -- birden çok kaynaktan gelen veriler üzerinde. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, pentester'ın ihtiyaç duyduğu tüm özellikler.\
**HackTricks continues to be a great learning platform for us all and we're proud to be sponsoring it!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sektör uzmanları tarafından oluşturulan ve yönetilen etkili siber güvenlik eğitimleri geliştiren ve sunan bir kuruluştur. Programları teori ötesine geçer ve ekipleri gerçek dünyadaki tehditleri yansıtan özel ortamlar kullanarak derin anlayış ve uygulanabilir becerilerle donatır. Özel eğitim talepleri için bize [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) ulaşın.

**Eğitimlerini farklı kılanlar:**
* Özel hazırlanmış içerik ve lablar
* Üst düzey araçlar ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve öğretilir

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** kurumlarına yönelik uzmanlaşmış siber güvenlik hizmetleri sunar; odak noktası **penetration testing, cloud security assessments** ve **compliance readiness** (SOC 2, PCI-DSS, NIST) hizmetleridir. Ekibimizde **OSCP ve CISSP sertifikalı profesyoneller** bulunur ve her görevde derin teknik uzmanlık ve sektör standardı içgörüsü sağlar.

Otomatik taramaların ötesine geçiyoruz ve yüksek riskli ortamlara özel, istihbarat odaklı manuel testler gerçekleştiriyoruz. Öğrenci kayıtlarını güvence altına almadan finansal işlemleri korumaya kadar, kuruluşların en değerli varlıklarını savunmalarına yardımcı oluyoruz.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Siber güvenlikteki en son gelişmelerden haberdar olmak için [**blog**](https://www.lasttowersolutions.com/blog) sayfalarını ziyaret edin.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE, DevOps, DevSecOps ve geliştiricilerin Kubernetes kümelerini verimli şekilde yönetmelerini, izlemelerini ve güvenli hale getirmelerini sağlar. AI destekli içgörülerimizden, gelişmiş güvenlik çerçevemizden ve sezgisel CloudMaps GUI'mizden faydalanarak kümelerinizi görselleştirin, durumlarını anlayın ve güvenle işlem yapın.

Ayrıca K8Studio, **tüm ana kubernetes dağıtımlarıyla uyumludur** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Lisans & Feragat

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
