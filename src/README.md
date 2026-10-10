# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoları ve motion design:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

HackTricks'in yerel kopyası, kitabın derlenmesi gerektiğinden biraz sabrederseniz **5 dakikadan kısa süre içinde [http://localhost:3337](http://localhost:3337)** adresinde kullanılabilir olacaktır.

Alternatif olarak, Docker Compose yüklüyse depo kök dizininde aşağıdaki komutu çalıştırabilirsiniz:

```bash
docker compose up
```

Bu, paketle birlikte gelen `docker-compose.yml` dosyasını kullanarak ana makinede şu anda checkout edilmiş branch’i canlı yeniden yükleme ile [http://localhost:3337](http://localhost:3337) adresinde sunar. Compose kullanırken dili değiştirmek için hizmeti başlatmadan önce istediğiniz dilin branch’ini checkout edin.

## HackTricks İş Ortakları

---

## HackTricks Dostları

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber; penetration testing, güvenlik denetimleri, exploit ve araştırma çalışmaları, araçlar ve güvenlik farkındalığı hizmetleri sunar. Web sitesinde, on yılı aşkın deneyime sahip penetration tester’lardan, programcılardan ve güvenlik araştırmacılarından oluşan bir ekip tanıtılıyor.<sup>[[1]](#references)</sup>

**Blog** sayfalarına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden göz atabilirsiniz.

**STM Cyber**, HackTricks gibi siber güvenlik alanındaki açık kaynak projelerini de destekliyor :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti, küresel bir araştırmacı topluluğu aracılığıyla bug bounty ve penetration testing hizmetleri sunan, kitle kaynaklı bir güvenlik sağlayıcısıdır. Platformu, sürekli bug bounty kapsamını isteğe bağlı PTaaS ve yönetilen güvenlik açığı bildirim programlarıyla bir araya getirir.<sup>[[2]](#references)</sup>

**Bug bounty ipucu**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden Intigriti’ye katılın ve bug bounty programlarını inceleyin.

---

### [Modern Security – AI ve Uygulama Güvenliği Eğitim Platformu](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security; güvenlik mühendisleri, AppSec uzmanları ve geliştiriciler için kendi hızınızda ilerleyebileceğiniz, uygulamalı AI güvenlik eğitimleri sunar. AI Security Certification; LLM ve agent temellerini, RAG ve vector database’leri, threat modeling’i, prompt injection ve MCP saldırılarını ve savunma mimarisini kapsar.<sup>[[3]](#references)</sup>

👉 AI Security kursu hakkında daha fazla bilgi:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, Google ve diğer arama motorları için API’ler sunarak konuma duyarlı sonuçlar, Maps, Shopping ve Knowledge Graph sonuçları gibi özelliklerle yapılandırılmış SERP verileri sağlar.<sup>[[4]](#references)</sup>

Daha fazla bilgi için [**blog**](https://serpapi.com/blog/) sayfalarına göz atın, [**playground**](https://serpapi.com/playground) alanında bir örnek deneyin veya [**ücretsiz hesap oluşturun**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Kapsamlı Mobil ve AI Güvenlik Kursları](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, kendi hızınızda ilerleyebileceğiniz mobil ve AI güvenliği kursları sunar. Katalogda Ghidra, Frida ve LLDB gibi araçlarla mobil uygulama denetimi ve reverse engineering’in yanı sıra AI/LLM saldırı ve savunma laboratuvarları yer alır.<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy kurs kataloğuna](https://academy.8ksec.io/) göz atın.

---

### [NaxusAI – AI Destekli Güvenlik Tarayıcısı](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus**, kodu ve altyapıyı haritalayan, ardından statik ve dinamik agent’lar kullanarak istismar edilebilir zayıflıkları bulup kavram kanıtı niteliğinde kanıtlar ve düzeltme yönergeleriyle doğrulayan bir offensive AI platformu sunuyor.<sup>[[7]](#references)</sup>

**Kod güvenliği ipucu**: Kod ve altyapı odaklı güvenlik açığı tespiti için Naxus’u inceleyin.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec; penetration testing, güvenlik abonelikleri, personel temini ve güvenlik açığı değerlendirme hizmetleri sunar. Web sitesine göre şirket uluslararası ölçekte faaliyet gösteriyor ve offensive security, defensive security ile governance, risk ve compliance çalışmalarını kapsıyor.<sup>[[8]](#references)</sup>

Daha fazla bilgi için [**web sitesini**](https://websec.net/en/) veya [**blogunu**](https://websec.net/blog/) ziyaret edin.

Yukarıdakilere ek olarak WebSec, HackTricks’in **kararlı bir destekçisidir.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logosu"><figcaption></figcaption></figure>


**Saha için tasarlandı. Size göre tasarlandı.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), gerçek altyapılara dayanan, özel olarak hazırlanmış içerik ve laboratuvarlarla uzman eğitmenlerin verdiği siber güvenlik eğitimleri sunar. Programları kurumsal ihtiyaçlara göre uyarlanır ve değerlendirmeden uygulamaya kadar uzanır.<sup>[[9]](#references)</sup> Özel eğitim talepleriniz için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) iletişime geçin.

**Eğitimlerini farklı kılan özellikler:**
* Özel olarak hazırlanmış içerik ve laboratuvarlar
* Üst düzey araçlar ve platformlarla desteklenir
* Alanda çalışan uzmanlar tarafından tasarlanır ve verilir

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logosu"><figcaption></figcaption></figure>

Last Tower Solutions, **Eğitim** ve **FinTech** alanlarında siber güvenlik danışmanlığına odaklanır. Hizmetleri arasında cloud değerlendirmeleri, iç ve dış penetration testleri, güvenlik açığı değerlendirmeleri ve compliance desteği bulunur.<sup>[[10]](#references)</sup>

Siber güvenlik alanındaki en son gelişmelerden haberdar olmak için [**blogumuzu**](https://www.lasttowersolutions.com/blog) ziyaret edin.

---

### [Kubernetes Yönetimi için Daha Akıllı GUI - K8Studio](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logosu"><figcaption></figcaption></figure>

K8Studio; CloudMaps görselleştirmesi, çoklu cluster gezintisi, RBAC, Helm, loglar, YAML ve terminal görünümleri sunan bir masaüstü Kubernetes IDE’sidir. Sağlayıcı, agent yüklemeden kubeconfig üzerinden bağlandığını ve macOS, Windows, Linux ile air-gapped cluster’ları desteklediğini belirtiyor.<sup>[[11]](#references)</sup>

---

## Lisans ve Sorumluluk Reddi

Aşağıdaki References bölümündeki HackTricks Values & FAQ kaydına bakın.

## Github İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Güvenlik Sertifikasyonu – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Uygulamalı AI Güvenliği: Saldırılar, Savunmalar ve Uygulamalar](https://academy.8ksec.io/course/practical-ai-security)
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
