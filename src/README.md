# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logo ve motion design: _[_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

HackTricks'in yerel kopyası, kitap oluşturulduktan sonra 5 dakikadan kısa süre içinde **[http://localhost:3337](http://localhost:3337)** adresinde kullanılabilir olacaktır (kitabın derlenmesi gerekir, lütfen sabırlı olun).

Alternatif olarak, Docker Compose'unuz varsa depo kök dizininden aşağıdakini çalıştırmanız yeterlidir:

```bash
docker compose up
```

Bu, live reload ile ana makinede şu anda checkout edilmiş branch’i [http://localhost:3337](http://localhost:3337) adresinde sunmak için birlikte gelen `docker-compose.yml` dosyasını kullanır. Compose kullanırken dili değiştirmek için servisi başlatmadan önce istediğiniz dilin branch’ini checkout edin.

## HackTricks İş Ortakları

---

## HackTricks Dostları

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber; sızma testleri, güvenlik denetimleri, exploit ve araştırma çalışmaları, araçlar ve güvenlik farkındalığı hizmetleri sunar. Web sitesinde, on yılı aşkın deneyime sahip sızma testi uzmanları, programcılar ve güvenlik araştırmacılarından oluşan bir ekip oldukları belirtiliyor.<sup>[[1]](#references)</sup>

**Blog** sayfalarına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden göz atabilirsiniz.

**STM Cyber**, HackTricks gibi siber güvenlik alanındaki açık kaynak projelerini de destekliyor :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti, küresel bir araştırmacı topluluğu aracılığıyla bug bounty ve sızma testi hizmetleri sunan, kitle kaynaklı bir güvenlik sağlayıcısıdır. Platformu, sürekli bug bounty kapsamını isteğe bağlı PTaaS ve yönetilen güvenlik açığı bildirim programlarıyla bir araya getirir.<sup>[[2]](#references)</sup>

**Bug bounty ipucu**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden Intigriti'ye katılın ve bug bounty programlarını keşfedin.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security; güvenlik mühendisleri, AppSec uzmanları ve geliştiriciler için kendi hızınızda ilerleyebileceğiniz, uygulamalı AI güvenliği eğitimi sunar. AI Security Certification; LLM ve agent temelleri, RAG ve vektör veritabanları, tehdit modelleme, prompt injection ve MCP saldırıları ile savunma mimarisini kapsar.<sup>[[3]](#references)</sup>

👉 AI Security kursu hakkında daha fazla bilgi:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, Google ve diğer arama motorları için API'ler sunarak konuma duyarlı sonuçlar, Maps, Shopping ve Knowledge Graph sonuçları gibi özelliklerle yapılandırılmış SERP verileri sağlar.<sup>[[4]](#references)</sup>

Daha fazla bilgi için [**blog**](https://serpapi.com/blog/) sayfalarına göz atın, [**playground**](https://serpapi.com/playground) üzerinde bir örnek deneyin veya [**ücretsiz hesap oluşturun**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, kendi hızınızda ilerleyebileceğiniz mobil ve AI güvenliği kursları sunar. Kataloğunda Ghidra, Frida ve LLDB gibi araçlarla mobil uygulama denetimi ve reverse engineering'in yanı sıra AI/LLM saldırı ve savunma laboratuvarları da yer alır.<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy kurs kataloğuna](https://academy.8ksec.io/) göz atın.

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus**, kodu ve altyapıyı haritalandıran; ardından statik ve dinamik agent'lar kullanarak exploit edilebilir zayıflıkları kanıt niteliğinde PoC'lerle ve düzeltme önerileriyle bulan ve doğrulayan bir offensive-AI platformu sunuyor.<sup>[[7]](#references)</sup>

**Kod güvenliği ipucu**: Kod ve altyapı odaklı güvenlik açığı keşfi için Naxus'u inceleyin.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec; sızma testi, güvenlik abonelikleri, personel temini ve güvenlik açığı değerlendirme hizmetleri sunar. Web sitesinde, uluslararası ölçekte faaliyet gösterdiği ve offensive security, defensive security ile yönetişim, risk ve uyumluluk çalışmalarını kapsadığı belirtiliyor.<sup>[[8]](#references)</sup>

Daha fazla bilgi için [**web sitelerini**](https://websec.net/en/) veya [**bloglarını**](https://websec.net/blog/) ziyaret edin.

Yukarıdakilere ek olarak WebSec, **HackTricks'in kararlı bir destekçisidir.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için tasarlandı. Size göre şekillendirildi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), gerçek altyapılara dayanan, özel olarak hazırlanmış içerik ve laboratuvarlarla uzmanlar tarafından verilen siber güvenlik eğitimleri sunar. Programları kurumsal ihtiyaçlara göre uyarlanır ve değerlendirmeden uygulamaya kadar çeşitli aşamaları kapsar.<sup>[[9]](#references)</sup> Özel eğitim talepleriniz için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) iletişime geçin.

**Eğitimlerini farklı kılanlar:**
* Özel olarak hazırlanmış içerik ve laboratuvarlar
* Üst düzey araç ve platformlarla desteklenir
* Uygulayıcılar tarafından tasarlanır ve verilir

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** alanlarında siber güvenlik danışmanlığına odaklanır. Hizmetleri arasında bulut değerlendirmeleri, kurum içi ve dışı sızma testleri, güvenlik açığı değerlendirmeleri ve uyumluluk desteği bulunur.<sup>[[10]](#references)</sup>

Siber güvenlikteki en yeni gelişmelerden haberdar olmak için [**blogumuzu**](https://www.lasttowersolutions.com/blog) ziyaret edin.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio; CloudMaps görselleştirmesi, çoklu cluster gezinme, RBAC, Helm, loglar, YAML ve terminal görünümleri sunan bir masaüstü Kubernetes IDE'sidir. Üretici, agent yüklemeden kubeconfig üzerinden bağlandığını ve macOS, Windows, Linux ile air-gapped cluster'ları desteklediğini belirtiyor.<sup>[[11]](#references)</sup>

---

## Lisans ve Sorumluluk Reddi

Aşağıdaki References bölümündeki HackTricks Values & FAQ girdisine bakın.

## GitHub İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Güvenliği Sertifikasyonu – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Pratik AI Güvenliği: Saldırılar, Savunmalar ve Uygulamalar](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks yönlendirmesi](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorluk videosu](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets kursları](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Değerleri ve SSS](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
