# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
로컬 HackTricks 사본은 책을 빌드해야 하므로 5분 이내에 **[http://localhost:3337](http://localhost:3337)** 에서 사용할 수 있습니다(잠시 기다려 주세요).

또는 Docker Compose가 있다면 repo root에서 다음을 실행하면 됩니다:
```bash
docker compose up
```
호스트에서 현재 checkout된 branch를 live reload와 함께 [http://localhost:3337](http://localhost:3337)에서 제공하기 위해 번들된 `docker-compose.yml`을 사용합니다. Compose 사용 중 언어를 변경하려면 service를 시작하기 전에 원하는 language branch를 checkout하세요.

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**을 slogan으로 내세우는 훌륭한 cybersecurity company입니다. 자체 research를 수행하고 자체 hacking tools를 개발하여 pentesting, Red teams 및 training과 같은 **여러 유용한 cybersecurity services를 제공합니다**.

그들의 **blog**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 cybersecurity open source projects도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽 1위** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **hackers가 hackers를 위해 만든** premium **bug bounty platform**인 **Intigriti**에 **sign up**하세요! 지금 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 함께하고 최대 **$100,000**의 bounties를 받기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **engineering-first, hands-on lab approach**를 통해 **실용적인 AI Security training**을 제공합니다. 저희 courses는 실제 AI/LLM 기반 applications를 **build, break 및 secure**하려는 security engineers, AppSec professionals 및 developers를 위해 제작되었습니다.

**AI Security Certification**은 다음을 포함한 real-world skills에 중점을 둡니다:
- LLM 및 AI 기반 applications 보안
- AI systems를 위한 threat modeling
- Embeddings, vector databases 및 RAG security
- LLM attacks, abuse scenarios 및 실용적인 defenses
- Secure design patterns 및 deployment considerations

모든 courses는 **on-demand**, **lab-driven** 방식이며 단순한 theory가 아니라 **실제 security tradeoffs**를 중심으로 설계되었습니다.

👉 AI Security course에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **search engine results에 액세스**할 수 있는 빠르고 간편한 real-time APIs를 제공합니다. search engines를 scrape하고, proxies를 처리하며, captchas를 해결하고, 모든 풍부한 structured data를 대신 parsing합니다.

SerpApi plans 중 하나를 구독하면 Google, Bing, Baidu, Yahoo, Yandex 등을 포함한 다양한 search engines를 scrape할 수 있는 50개 이상의 서로 다른 APIs에 액세스할 수 있습니다.\
다른 providers와 달리 **SerpApi는 organic results만 scrape하지 않습니다**. SerpApi responses에는 search results에 표시되는 모든 ads, inline images 및 videos, knowledge graphs와 기타 elements 및 features가 일관되게 포함됩니다.

현재 SerpApi customers로는 **Apple, Shopify 및 GrubHub**가 있습니다.\
자세한 내용은 [**blog**](https://serpapi.com/blog/)에서 확인하거나, [**playground**](https://serpapi.com/playground)에서 example을 사용해 보세요.\
[**여기**](https://serpapi.com/users/sign_up)에서 **무료 account를 생성**할 수 있습니다.

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**는 Black Hat, HITB 및 Zer0con에서 CVE writeups와 talks를 진행한 동일한 team의 active researchers가 가르치는 offensive mobile 및 AI security training을 제공합니다. Courses는 self-paced 방식이며 실제 targets를 대상으로 한 labs를 중심으로 구성되고 hands-on certification이 제공됩니다.

catalog는 두 가지 tracks로 운영됩니다:

**Mobile Security** – app layer부터 그 아래까지 iOS 및 Android를 다룹니다. Ghidra와 LLDB를 사용한 reverse engineering, ARM64 exploitation, kernel internals 및 최신 mitigations(PAC, MTE, SELinux), jailbreak 및 rooting mechanics를 포함합니다.

**AI Security** – 해당 분야를 다루는 두 개의 full courses입니다. Practical AI Security에서는 LLMs, RAG pipelines, AI agents 및 MCP의 작동 방식과 이를 attack 및 defend하는 방법을 다룹니다. Advanced AI Security는 frontier를 대상으로 build-heavy 방식으로 진행되며, Garak 및 PyRIT을 사용한 AI systems의 대규모 red teaming, MCP servers exploitation, model backdoors planting 및 detection, Apple Silicon에서의 fine-tuning attacks 및 defenses를 포함합니다.

Courses 및 certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**는 attackers보다 먼저 exploitable vulnerabilities를 찾을 수 있는 AI-powered security platform입니다.

**Code security tip**: developers와 security teams를 위해 구축된 smart vulnerability monitoring platform인 NaxusAI에 sign up하세요! 지금 함께하고 AI를 사용하여 **실제 security risks가 production에 도달하기 전에 이를 detecting, validating 및 fixing**하기 시작하세요!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)은 **Amsterdam**에 기반을 둔 professional cybersecurity company로, **modern** approach를 적용한 **offensive-security services**를 제공하여 **전 세계** businesses가 최신 cybersecurity threats로부터 **보호받도록 지원**합니다.

WebSec은 Amsterdam과 Wyoming에 offices를 둔 intenational security company입니다. **all-in-one security services**를 제공하며, 이는 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등을 모두 수행한다는 의미입니다.

WebSec의 또 다른 멋진 점은 industry average와 달리 WebSec이 **자신들의 skills에 매우 자신감을 가지고 있다**는 것입니다. 그 정도로 **최고 품질의 results를 보장**하며, website에는 "**If we can't hack it, You don't pay it!**"이라고 명시되어 있습니다. 자세한 내용은 [**website**](https://websec.net/en/)와 [**blog**](https://websec.net/blog/)를 확인하세요!

위의 내용 외에도 WebSec은 **HackTricks의 committed supporter**입니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장을 위해 만들어졌습니다. 당신을 중심으로 설계되었습니다.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 industry experts가 개발하고 주도하는 효과적인 cybersecurity training을 개발하고 제공합니다. 이들의 programs는 theory를 넘어 실제 환경의 threats를 반영한 custom environments를 사용하여 teams에 깊은 understanding과 actionable skills를 제공합니다. custom training 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**이들의 training이 차별화되는 점:**
* Custom-built content 및 labs
* 최고 수준의 tools 및 platforms 지원
* Practitioners가 설계하고 교육

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech** institutions를 위한 specialized cybersecurity services를 제공하며, **penetration testing, cloud security assessments** 및 **compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 저희 team에는 **OSCP 및 CISSP
certified professionals**가 포함되어 있으며, 모든 engagement에 deep technical expertise와 industry-standard insight를 제공합니다.

저희는 automated scans를 넘어 high-stakes environments에 맞춘 **manual, intelligence-driven testing**을 수행합니다. student records를 보호하는 것부터 financial transactions를 보호하는 것까지, organizations가 가장 중요한 자산을 방어할 수 있도록 지원합니다.

_“양질의 defense를 위해서는 offense를 알아야 하며, 저희는 understanding을 통해 security를 제공합니다.”_

[**blog**](https://www.lasttowersolutions.com/blog)를 방문하여 최신 cybersecurity 정보를 확인하고 최신 상태를 유지하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps 및 developers가 Kubernetes clusters를 효율적으로 manage, monitor 및 secure할 수 있도록 지원합니다. AI-driven insights, advanced security framework 및 직관적인 CloudMaps GUI를 활용하여 clusters를 visualize하고, 상태를 파악하며, 확신을 가지고 조치하세요.

또한 K8Studio는 **모든 주요 kubernetes distributions**(AWS, GCP, Azure, DO, Rancher, K3s, Openshift 등)과 **호환됩니다**.

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

다음에서 확인하세요:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
