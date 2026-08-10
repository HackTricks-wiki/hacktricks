# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's en motion design deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Run HackTricks Plaaslik
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
Jou plaaslike kopie van HackTricks sal **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** na <5 minutes (dit moet die boek bou, wees geduldig).

Alternatiewelik, indien jy Docker Compose het, kan jy eenvoudig die volgende vanaf die repo-hoofgids uitvoer:
```bash
docker compose up
```
Dit gebruik die gebundelde `docker-compose.yml` om die branch wat tans op die host uitgecheck is, by [http://localhost:3337](http://localhost:3337) met live reload te bedien. Om tale te verander wanneer Compose gebruik word, check die verlangde taalbranch uit voordat jy die diens begin.

## HackTricks-vennote

---

## HackTricks-vriende

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber verskaf penetration testing, security audits, exploit- en navorsingswerk, tools en security-awareness-dienste. Die webwerf beskryf ’n span penetration testers, programmeerders en security researchers met meer as ’n dekade se ervaring.<sup>[[1]](#references)</sup>

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besoek.

**STM Cyber** ondersteun ook cybersecurity open source-projekte soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti is ’n crowdsourced security-verskaffer wat bug bounty- en penetration-testing-dienste deur ’n wêreldwye researcher-gemeenskap aanbied. Sy platform kombineer deurlopende bug bounty-dekking met on-demand PTaaS en bestuurde vulnerability disclosure-programme.<sup>[[2]](#references)</sup>

**Bug bounty-wenk**: Sluit by Intigriti aan deur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en verken sy bug bounty-programme.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bied self-paced, praktiese AI security-training vir security engineers, AppSec-professionele persone en developers. Sy AI Security Certification dek LLM- en agent-grondbeginsels, RAG en vector databases, threat modeling, prompt-injection- en MCP-attacks, asook defensive architecture.<sup>[[3]](#references)</sup>

👉 Meer besonderhede oor die AI Security-kursus:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** verskaf APIs vir Google en ander search engines, en lewer gestruktureerde SERP-data met funksies soos liggingbewuste resultate, Maps, Shopping en Knowledge Graph-resultate.<sup>[[4]](#references)</sup>

Vir meer inligting, besoek hul [**blog**](https://serpapi.com/blog/), probeer ’n voorbeeld in hul [**playground**](https://serpapi.com/playground), of [**skep ’n gratis rekening**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bied self-paced mobile- en AI-security-kursusse aan. Sy katalogus dek mobile application auditing en reversing met tools soos Ghidra, Frida en LLDB, tesame met AI/LLM attack- en defense-labs.<sup>[[5]](#references)[[6]](#references)</sup>

Blaai deur die [8kSec Academy-kursuskatalogus](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** bemark ’n offensive-AI-platform wat code en infrastructure karteer, en dan static en dynamic agents gebruik om exploitable weaknesses met proof-of-concept-bewyse en remediation guidance te vind en te valideer.<sup>[[7]](#references)</sup>

**Code security-wenk**: Verken Naxus vir code- en infrastructure-gefokusde vulnerability discovery.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec verskaf penetration testing, security subscriptions, staffing en vulnerability-assessment-dienste. Die webwerf sê dat dit internasionaal werk en offensive security, defensive security, asook governance-, risk- en compliance-werk dek.<sup>[[8]](#references)</sup>

Vir meer inligting, besoek hul [**webwerf**](https://websec.net/en/) of [**blog**](https://websec.net/blog/).

Benewens bogenoemde is WebSec ook ’n **toegewyde ondersteuner van HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) verskaf cybersecurity-training onder leiding van kundiges, met pasgemaakte inhoud en labs wat op werklike infrastructures gegrond is. Sy programme word volgens organisatoriese behoeftes aangepas en strek van assessment tot implementation.<sup>[[9]](#references)</sup> Vir navrae oor pasgemaakte training, kontak hulle [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul training onderskei:**
* Pasgemaakte inhoud en labs
* Ondersteun deur topvlak-tools en platforms
* Ontwerp en aangebied deur praktisyns

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fokus op cybersecurity-consulting vir **Onderwys** en **FinTech**, insluitend cloud assessments, interne en eksterne penetration tests, vulnerability assessments en compliance-ondersteuning.<sup>[[10]](#references)</sup>

Bly ingelig en op hoogte van die jongste ontwikkelingen in cybersecurity deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio is ’n desktop Kubernetes IDE met CloudMaps-visualisering, multi-cluster-navigasie, RBAC, Helm, logs, YAML- en terminal views. Die vendor sê dit verbind deur kubeconfig sonder om agents te installeer en ondersteun macOS, Windows, Linux en air-gapped clusters.<sup>[[11]](#references)</sup>

---

## Lisensie en vrywaring

Sien die HackTricks Values & FAQ-inskrywing in References hieronder.

## Github-statistieke

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktiese AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks-verwysing](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec-borgskapvideo](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets-kursusse](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
