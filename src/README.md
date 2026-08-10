# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logo ve motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks'i Yerel Olarak Çalıştır
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
HackTricks'in yerel kopyasına, kitap oluşturulması gerektiğinden lütfen sabırlı olun, **5 dakikadan kısa bir süre sonra [http://localhost:3337](http://localhost:3337)** adresinden erişebilirsiniz.

Alternatif olarak Docker Compose'unuz varsa repo root dizininden aşağıdaki komutu çalıştırabilirsiniz:
```bash
docker compose up
```
Bu, şu anda host üzerinde checkout edilmiş branch'i [http://localhost:3337](http://localhost:3337) adresinde live reload ile sunmak için birlikte verilen `docker-compose.yml` dosyasını kullanır. Compose kullanırken dilleri değiştirmek için servisi başlatmadan önce istediğiniz dil branch'ini checkout edin.

## HackTricks İş Ortakları

---

## HackTricks Dostları

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber penetration testing, security audits, exploit ve research çalışmaları, araçlar ve security-awareness hizmetleri sunar. Sitesinde, on yılı aşkın deneyime sahip penetration tester, programmer ve security researcher'lardan oluşan bir ekip bulunduğu belirtilir.<sup>[[1]](#references)</sup>

**blog**'larına [**https://blog.stmcyber.com**](https://blog.stmcyber.com) adresinden göz atabilirsiniz.

**STM Cyber**, HackTricks gibi cybersecurity open source projelerini de destekler :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti, global bir researcher topluluğu aracılığıyla bug bounty ve penetration-testing hizmetleri sunan crowdsourced security sağlayıcısıdır. Platformu, sürekli bug bounty kapsamını on-demand PTaaS ve managed vulnerability disclosure programlarıyla birleştirir.<sup>[[2]](#references)</sup>

**Bug bounty ipucu**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) üzerinden Intigriti'ye katılın ve bug bounty programlarını inceleyin.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security; security engineer'lar, AppSec profesyonelleri ve developer'lar için kendi hızınızda ilerleyebileceğiniz, uygulamalı AI security training sunar. AI Security Certification; LLM ve agent temellerini, RAG ve vector database'leri, threat modeling'i, prompt-injection ve MCP attack'lerini ve defensive architecture'ı kapsar.<sup>[[3]](#references)</sup>

👉 AI Security course hakkında daha fazla bilgi:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**, Google ve diğer search engine'ler için API'ler sunar ve location-aware results, Maps, Shopping ve Knowledge Graph results gibi özelliklerle yapılandırılmış SERP verileri döndürür.<sup>[[4]](#references)</sup>

Daha fazla bilgi için [**blog**](https://serpapi.com/blog/) sayfalarına göz atın, [**playground**](https://serpapi.com/playground) üzerinde bir örnek deneyin veya [**ücretsiz bir hesap oluşturun**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**, kendi hızınızda ilerleyebileceğiniz mobile ve AI-security course'ları sunar. Kataloğu, Ghidra, Frida ve LLDB gibi araçlarla mobile application auditing ve reversing'in yanı sıra AI/LLM attack ve defense lab'lerini kapsar.<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy course kataloğuna](https://academy.8ksec.io/) göz atın.

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus**, code ve infrastructure'ı haritalayan, ardından proof-of-concept kanıtları ve remediation guidance ile exploitable weakness'leri bulup doğrulamak için static ve dynamic agent'lar kullanan offensive-AI platformunu pazara sunar.<sup>[[7]](#references)</sup>

**Code security ipucu**: Code ve infrastructure odaklı vulnerability discovery için Naxus'u inceleyin.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec penetration testing, security subscription, staffing ve vulnerability-assessment hizmetleri sunar. Sitesinde, uluslararası alanda faaliyet gösterdiği ve offensive security, defensive security ile governance, risk ve compliance çalışmalarını kapsadığı belirtilir.<sup>[[8]](#references)</sup>

Daha fazla bilgi için [**website**](https://websec.net/en/) veya [**blog**](https://websec.net/blog/) sayfalarını ziyaret edin.

Yukarıdakilere ek olarak WebSec, **HackTricks'in kararlı bir destekçisidir.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Saha için oluşturuldu. Size göre tasarlandı.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks), gerçek infrastructure'lara dayanan, uzmanlar tarafından verilen ve özel olarak oluşturulmuş içerik ve lab'lerle cybersecurity training sunar. Programları kurumsal ihtiyaçlara göre uyarlanır ve assessment'tan implementation'a kadar uzanır.<sup>[[9]](#references)</sup> Özel training talepleri için [**buradan**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) iletişime geçin.

**Training'lerini farklı kılan özellikler:**
* Özel olarak oluşturulmuş içerik ve lab'ler
* Üst düzey araçlar ve platformlarla desteklenir
* Practitioner'lar tarafından tasarlanır ve verilir

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions, **Education** ve **FinTech** için cybersecurity consulting'e odaklanır; cloud assessment'ları, internal ve external penetration test'leri, vulnerability assessment'ları ve compliance desteği sunar.<sup>[[10]](#references)</sup>

[**Blog**](https://www.lasttowersolutions.com/blog) sayfamızı ziyaret ederek cybersecurity alanındaki en son gelişmelerden haberdar olun.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio; CloudMaps visualization, multi-cluster navigation, RBAC, Helm, logs, YAML ve terminal görünümlerine sahip bir desktop Kubernetes IDE'sidir. Vendor, agent kurmadan kubeconfig üzerinden bağlandığını ve macOS, Windows, Linux ile air-gapped cluster'ları desteklediğini belirtir.<sup>[[11]](#references)</sup>

---

## Lisans ve Sorumluluk Reddi

Aşağıdaki References bölümündeki HackTricks Values & FAQ girdisine bakın.

## Github İstatistikleri

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Saldırılar, Savunmalar ve Uygulamalar](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
