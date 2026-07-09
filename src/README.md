# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인 by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks를 로컬에서 실행하기
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

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**을 슬로건으로 내세우는 훌륭한 cybersecurity 회사입니다. 이들은 자체 연구를 수행하고 자체 hacking tools를 개발하여 **pentesting, Red teams, training** 같은 여러 유용한 cybersecurity 서비스를 **제공**합니다.

자세한 내용은 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 **blog**를 확인할 수 있습니다.

**STM Cyber**는 HackTricks 같은 cybersecurity 오픈 소스 프로젝트도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **Europe's #1** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 참여하고, 최대 **$100,000**까지 bounty를 벌기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

숙련된 hackers와 bug bounty hunters와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

- **Hacking Insights:** hacking의 흥미와 도전 과제를 다루는 콘텐츠를 확인하세요
- **Real-Time Hack News:** 실시간 뉴스와 인사이트를 통해 빠르게 변하는 hacking world를 최신 상태로 유지하세요
- **Latest Announcements:** 새로 시작되는 bug bounties와 중요한 platform 업데이트를 확인하세요

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 **Join us on**해서 최고의 hackers와 협업을 시작하세요!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **engineering-first, hands-on lab approach**를 바탕으로 한 **실용적인 AI Security training**을 제공합니다. 우리의 courses는 security engineers, AppSec professionals, 그리고 실제 AI/LLM-powered applications를 **build, break, and secure**하고 싶은 developers를 위해 만들어졌습니다.

**AI Security Certification**은 다음을 포함한 실제 세계 기술에 초점을 맞춥니다:
- LLM 및 AI-powered applications 보호
- AI systems에 대한 Threat modeling
- Embeddings, vector databases, 그리고 RAG security
- LLM attacks, abuse scenarios, 그리고 실용적인 defenses
- Secure design patterns 및 deployment considerations

모든 courses는 **on-demand**, **lab-driven**이며, 단순한 이론이 아니라 **real-world security tradeoffs**를 중심으로 설계되었습니다.

👉 AI Security course에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **search engine results**에 접근하기 위한 빠르고 쉬운 real-time APIs를 제공합니다. 이들은 search engines를 scrape하고, proxies를 처리하며, captchas를 풀고, 모든 rich structured data를 파싱해 줍니다.

SerpApi의 플랜 하나를 구독하면 Google, Bing, Baidu, Yahoo, Yandex 등을 포함한 다양한 search engines를 scraping하는 50개 이상의 서로 다른 APIs에 접근할 수 있습니다.\
다른 provider와 달리, **SerpApi는 단순히 organic results만 scrape하지 않습니다**. SerpApi responses에는 광고, inline images와 videos, knowledge graphs, 그리고 search results에 포함된 다른 요소와 기능이 일관되게 모두 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, and GrubHub**가 포함됩니다.\
더 많은 정보는 [**blog**](https://serpapi.com/blog/)를 확인하거나, [**playground**](https://serpapi.com/playground)에서 예제를 사용해 보세요.\
[**here**](https://serpapi.com/users/sign_up)에서 **create a free account**할 수 있습니다.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**는 활동 중인 researchers가 가르치는 offensive mobile and AI security 교육을 제공합니다. 이들은 Black Hat, HITB, 그리고 Zer0con에서 CVE writeups와 talks를 담당한 동일한 팀입니다. Courses는 self-paced이며, 실제 targets에 대한 labs를 중심으로 구성되고, hands-on certification이 함께 제공됩니다.

카탈로그는 두 트랙으로 운영됩니다:

**Mobile Security** – app layer부터 아래까지의 iOS와 Android: Ghidra와 LLDB를 이용한 reverse engineering, ARM64 exploitation, kernel internals와 현대적 mitigation(PAC, MTE, SELinux), jailbreak 및 rooting mechanics.

**AI Security** – 분야 전반을 아우르는 두 개의 전체 courses. Practical AI Security는 LLMs, RAG pipelines, AI agents와 MCP가 어떻게 동작하는지, 그리고 그것들을 어떻게 attack하고 defend하는지 다룹니다. Advanced AI Security는 최전선에서 build-heavy하게 진행됩니다: Garak과 PyRIT으로 대규모 AI systems red teaming, MCP servers exploitation, model backdoors 심기 및 탐지, 그리고 Apple Silicon에서의 fine-tuning attacks와 defenses.

Courses and certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**는 공격자가 찾기 전에 exploit 가능한 vulnerabilities를 찾아내는 AI-powered security platform입니다.

**Code security tip**: 개발자와 security teams를 위해 만들어진 스마트 vulnerability monitoring platform인 NaxusAI에 sign up하세요! 오늘 가입하고 AI를 사용해 **production에 도달하기 전에 real security risks를 detect, validate, and fix**하기 시작하세요!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 기반을 둔 전문 cybersecurity 회사로, **modern**한 접근 방식의 **offensive-security services**를 제공하여 전 세계 기업을 최신 cybersecurity threats로부터 **보호**하는 데 도움을 줍니다.

WebSec는 Amsterdam과 Wyoming에 사무실을 둔 international security company입니다. 이들은 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 모든 것을 제공하는 **all-in-one security services**를 제공합니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 자신의 실력에 **매우 자신감이 있다**는 것이며, 그 정도가 너무 커서 **최고 품질의 결과를 보장**한다는 점입니다. 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 적혀 있습니다. 더 많은 정보는 [**website**](https://websec.net/en/)와 [**blog**](https://websec.net/blog/)를 확인하세요!

위 내용 외에도 WebSec는 HackTricks의 **헌신적인 supporter**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 만들고 이끄는 효과적인 cybersecurity training을 개발하고 제공합니다. 이들의 프로그램은 이론을 넘어, 실제 위협을 반영한 맞춤형 환경을 활용해 팀에 깊은 이해와 실행 가능한 기술을 제공합니다. 맞춤형 training 문의는 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech**
기관을 위한 전문 cybersecurity services를 제공하며, **penetration testing, cloud security assessments**, 그리고
**compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀에는 **OSCP 및 CISSP
certified professionals**가 포함되어 있으며, 모든 engagement에 깊은 기술 전문성과 업계 표준 인사이트를 제공합니다.

우리는 **manual, intelligence-driven testing**으로 자동화된 스캔을 넘어
고위험 환경에 맞춘 테스트를 수행합니다. 학생 기록 보호부터 금융 거래 보호까지,
가장 중요한 것을 지키도록 조직을 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 cybersecurity 소식을 확인하고 업데이트를 유지하려면 [**blog**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps, 그리고 developers가 Kubernetes clusters를 효율적으로 관리, 모니터링, 보호할 수 있도록 지원합니다. AI-driven insights, advanced security framework, 그리고 직관적인 CloudMaps GUI를 활용해 clusters를 시각화하고, 상태를 이해하며, 자신 있게 대응하세요.

또한 K8Studio는 **모든 주요 kubernetes distributions**(AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more)과 **호환됩니다**.

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

{{#include ./banners/hacktricks-training.md}}
