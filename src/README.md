# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인: _[_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks 로컬에서 실행하기
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
로컬 HackTricks 사본은 5분 이내에 [http://localhost:3337](http://localhost:3337)에서 사용할 수 있습니다(책을 빌드해야 하므로 잠시 기다려 주세요).

또는 Docker Compose가 있다면 repo root에서 다음 명령을 실행하면 됩니다:
```bash
docker compose up
```
이 기능은 포함된 `docker-compose.yml`을 사용하여 호스트에서 현재 checkout된 branch를 [http://localhost:3337](http://localhost:3337)에서 live reload와 함께 제공합니다. Compose를 사용할 때 언어를 변경하려면 service를 시작하기 전에 원하는 언어 branch를 checkout하세요.

## HackTricks 파트너

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber는 penetration testing, security audits, exploit 및 research 작업, tools, security-awareness 서비스를 제공합니다. 사이트에 따르면 10년 이상의 경험을 보유한 penetration testers, programmers, security researchers로 구성된 team입니다.<sup>[[1]](#references)</sup>

그들의 [**blog**](https://blog.stmcyber.com)에서 더 많은 내용을 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 cybersecurity open source projects도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti는 global researcher community를 통해 bug bounty 및 penetration-testing 서비스를 제공하는 crowdsourced security provider입니다. 이 platform은 지속적인 bug bounty coverage와 on-demand PTaaS 및 managed vulnerability disclosure programs를 결합합니다.<sup>[[2]](#references)</sup>

**Bug bounty tip**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)를 통해 Intigriti에 가입하고 bug bounty programs를 살펴보세요.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 security engineers, AppSec professionals 및 developers를 위한 self-paced, hands-on AI security training을 제공합니다. AI Security Certification은 LLM 및 agent fundamentals, RAG 및 vector databases, threat modeling, prompt-injection 및 MCP attacks, defensive architecture를 다룹니다.<sup>[[3]](#references)</sup>

👉 AI Security course에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 Google 및 기타 search engines를 위한 APIs를 제공하며, location-aware results, Maps, Shopping, Knowledge Graph results 등의 features를 포함한 구조화된 SERP data를 반환합니다.<sup>[[4]](#references)</sup>

자세한 내용은 [**blog**](https://serpapi.com/blog/)를 확인하거나, [**playground**](https://serpapi.com/playground)에서 example을 실행하거나, [**create a free account**](https://serpapi.com/users/sign_up)를 통해 무료 account를 생성해 보세요.

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**는 self-paced mobile 및 AI-security courses를 제공합니다. catalog에는 Ghidra, Frida, LLDB와 같은 tools를 사용한 mobile application auditing 및 reversing과 AI/LLM attack 및 defense labs가 포함되어 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy course catalog](https://academy.8ksec.io/)를 살펴보세요.

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus**는 code와 infrastructure를 mapping한 다음 static 및 dynamic agents를 사용하여 악용 가능한 weaknesses를 찾고 검증하는 offensive-AI platform을 제공합니다. 이 platform은 proof-of-concept evidence와 remediation guidance도 제공합니다.<sup>[[7]](#references)</sup>

**Code security tip**: code 및 infrastructure 중심의 vulnerability discovery를 위해 Naxus를 살펴보세요.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec는 penetration testing, security subscriptions, staffing 및 vulnerability-assessment services를 제공합니다. 사이트에 따르면 국제적으로 운영되며 offensive security, defensive security, governance, risk 및 compliance 작업을 다룹니다.<sup>[[8]](#references)</sup>

자세한 내용은 [**website**](https://websec.net/en/) 또는 [**blog**](https://websec.net/blog/)를 방문하세요.

위 내용 외에도 WebSec는 **HackTricks의 committed supporter**입니다.

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장을 위해 만들어졌습니다. 여러분을 중심으로 설계되었습니다.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 실제 infrastructures를 기반으로 custom-built content 및 labs를 제공하는 expert-led cybersecurity training을 운영합니다. programs는 조직의 needs에 맞게 구성되며 assessment부터 implementation까지 다룹니다.<sup>[[9]](#references)</sup> custom training 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**이들의 training이 차별화되는 점:**
* Custom-built content 및 labs
* Top-tier tools 및 platforms 기반
* Practitioners가 설계하고 교육

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech**를 위한 cybersecurity consulting에 주력하며, cloud assessments, internal 및 external penetration tests, vulnerability assessments 및 compliance support를 제공합니다.<sup>[[10]](#references)</sup>

[**blog**](https://www.lasttowersolutions.com/blog)를 방문하여 cybersecurity 최신 소식을 확인하고 최신 상태를 유지하세요.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio는 CloudMaps visualization, multi-cluster navigation, RBAC, Helm, logs, YAML 및 terminal views를 제공하는 desktop Kubernetes IDE입니다. vendor에 따르면 agents를 설치하지 않고 kubeconfig를 통해 연결하며 macOS, Windows, Linux 및 air-gapped clusters를 지원합니다.<sup>[[11]](#references)</sup>

---

## License & Disclaimer

아래 References의 HackTricks Values & FAQ 항목을 참조하세요.

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
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
