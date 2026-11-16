# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve hareketli tasarım_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ tarafından._

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
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

HackTricks'in yerel kopyası, kitabı derlemesi gerektiğinden biraz sabırlı olun; 5 dakikadan kısa süre sonra **[http://localhost:3337](http://localhost:3337)** adresinde kullanılabilir olacaktır.

Alternatif olarak, Docker Compose'unuz varsa depo kök dizininden aşağıdakini çalıştırabilirsiniz:

```bash
docker compose up
```

Bu, canlı yeniden yükleme özelliğiyle ana makinede şu anda checkout edilmiş branch'i [http://localhost:3337](http://localhost:3337) adresinde sunmak için birlikte gelen `docker-compose.yml` dosyasını kullanır. Compose kullanırken dili değiştirmek için servisi başlatmadan önce istediğiniz dilin branch'ini checkout edin.

## HackTricks İş Ortakları

---

## HackTricks Dostları

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber; sızma testleri, güvenlik denetimleri, exploit ve araştırma çalışmaları, araçlar ve güvenlik farkındalığı hizmetleri sunar. Web sitesinde, on yılı aşkın deneyime sahip sızma testi uzmanları, programcılar ve güvenlik araştırmacılarından oluşan bir ekip tanıtılmaktadır.<sup>[[1]](#references)</sup>

**Blog** sayfalarına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden ulaşabilirsiniz.

**STM Cyber**, HackTricks gibi siber güvenlik açık kaynak projelerini de destekliyor :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti, küresel bir araştırmacı topluluğu aracılığıyla bug bounty ve sızma testi hizmetleri sunan, topluluk kaynaklı bir güvenlik sağlayıcısıdır. Platformu, sürekli bug bounty kapsamını isteğe bağlı PTaaS ve yönetilen güvenlik açığı bildirim programlarıyla birleştirir.<sup>[[2]](#references)</sup>

**Bug bounty ipucu**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden Intigriti'ye katılın ve bug bounty programlarını keşfedin.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security; güvenlik mühendisleri, AppSec uzmanları ve geliştiriciler için kendi hızınızda ilerleyebileceğiniz, uygulamalı AI güvenliği eğitimleri sunar. AI Security Certification programı; LLM ve agent temellerini, RAG ve vektör veritabanlarını, tehdit modellemeyi, prompt injection ve MCP saldırılarını ve savunma mimarisini kapsar.<sup>[[3]](#references)</sup>

👉 AI Security kursu hakkında daha fazla bilgi:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, Google ve diğer arama motorları için API'ler sunar ve konuma duyarlı sonuçlar, Maps, Shopping ve Knowledge Graph sonuçları gibi özelliklerle yapılandırılmış SERP verileri döndürür.<sup>[[4]](#references)</sup>

Daha fazla bilgi için [**bloglarına**](https://serpapi.com/blog/) göz atın, [**playground**](https://serpapi.com/playground) üzerinden bir örnek deneyin veya [**ücretsiz hesap oluşturun**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, kendi hızınızda ilerleyebileceğiniz mobil ve AI güvenliği kursları sunar. Kurs kataloğunda Ghidra, Frida ve LLDB gibi araçlarla mobil uygulama denetimi ve tersine mühendisliğin yanı sıra AI/LLM saldırı ve savunma laboratuvarları yer alır.<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy kurs kataloğuna](https://academy.8ksec.io/) göz atın.

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus**, dış saldırı yüzeyinin tamamını taramak, mobil uygulamaları denetlemek, web uygulamalarında black-box testleri yapmak ve kaynak kodunu incelemek için AI destekli bir offensive security platformudur. Agent'ları istismar edilebilir bulguları doğrular ve izlenebilir kanıtlar, proof-of-concept exploit'ler ve uygulanabilir iyileştirme önerileri sunar.<sup>[[7]](#references)</sup>

**Güvenlik denetimi ipucu**: Dış varlıklar, mobil uygulamalar, web uygulamaları ve kaynak kodu genelinde uçtan uca otonom denetimler için Naxus'ı kullanın.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec; sızma testleri, güvenlik abonelikleri, personel desteği ve güvenlik açığı değerlendirme hizmetleri sunar. Web sitesinde, uluslararası alanda faaliyet gösterdiği ve offensive security, defensive security ile yönetişim, risk ve uyumluluk çalışmalarını kapsadığı belirtilir.<sup>[[8]](#references)</sup>

Daha fazla bilgi için [**web sitelerini**](https://websec.net/en/) veya [**bloglarını**](https://websec.net/blog/) ziyaret edin.

Yukarıdakilere ek olarak WebSec, **HackTricks'in de kararlı bir destekçisidir.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için tasarlandı. Size göre şekillendirildi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), gerçek altyapıları temel alan, özel hazırlanmış içerik ve laboratuvarlarla uzmanlar tarafından verilen siber güvenlik eğitimleri sunar. Programları kurumsal ihtiyaçlara göre uyarlanır ve değerlendirmeden uygulamaya kadar farklı aşamaları kapsar.<sup>[[9]](#references)</sup> Özel eğitim talepleriniz için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) bize ulaşın.

**Eğitimlerini farklı kılan özellikler:**
* Özel hazırlanmış içerik ve laboratuvarlar
* Üst düzey araçlar ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve verilir

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** alanlarında siber güvenlik danışmanlığına odaklanır. Hizmetleri arasında bulut değerlendirmeleri, iç ve dış sızma testleri, güvenlik açığı değerlendirmeleri ve uyumluluk desteği bulunur.<sup>[[10]](#references)</sup>

Siber güvenlik alanındaki en son gelişmelerden haberdar olmak için [**blogumuzu**](https://www.lasttowersolutions.com/blog) ziyaret edin.

---

### [Beaki — Food that fits you](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki**, kişiselleştirilmiş bir gıda tarayıcısı, kalori sayacı ve beslenme takipçisidir. Barkodları ve market raflarını tarayın, yemeklerin ve restoran menülerinin fotoğrafını çekin veya açıklamasını yazın; hedeflerinize, beslenme düzeninize, alerjilerinize ve sağlık profilinize göre şekillendirilmiş, açıklanabilir puanlar alın. Beaki ayrıca kalorileri ve makroları takip eder, alışveriş listeleriyle kişiselleştirilmiş yemek planları oluşturur.<sup>[[11]](#references)</sup>

Android veya iPhone için [**Beaki'yi ücretsiz indirin**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks).

---

## Lisans ve Sorumluluk Reddi

Aşağıdaki References bölümündeki HackTricks Değerleri ve SSS başlığına bakın.

## Github İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Güvenliği Sertifikasyonu – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Uygulamalı AI Güvenliği: Saldırılar, Savunmalar ve Uygulamalar](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti HackTricks yönlendirme bağlantısı](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorluk videosu](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets kursları](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Değerleri ve SSS](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
